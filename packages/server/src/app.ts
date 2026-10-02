import express, { type Express, type Request, type Response } from 'express';
import {
  b64uEncode,
  verifyAuthentication,
  verifyRegistration,
  type AssertionResponseDTO,
  type AttestationResponseDTO,
  type AuthenticationOptionsDTO,
  type CeremonyStatus,
  type CheckResult,
  type CryptoProvider,
  type FailureCode,
  type RegistrationOptionsDTO,
} from '@lab/shared';
import { LabStore, type CeremonyState } from './store.js';

export interface ServerConfig {
  rpId: string;
  rpName: string;
  expectedOrigins: string[];
  defaultTtlMs: number;
  maxTtlMs: number;
}

export interface AppDeps {
  store: LabStore;
  crypto: CryptoProvider;
  config: ServerConfig;
}

const DEFAULT_TTL = 60_000;

function ceremonySummary(c: CeremonyState) {
  return {
    ceremonyId: c.id,
    kind: c.kind,
    status: c.status as CeremonyStatus,
    failureCode: c.failureCode,
    failureMessage: c.failureMessage,
    cloneWarning: c.cloneWarning,
    createdAt: new Date(c.createdAt).toISOString(),
    expiresAt: c.expiresAt,
    credentialId: c.credentialId,
    checks: c.checks,
  };
}

function clampTtl(requested: unknown, config: ServerConfig): number {
  const n = typeof requested === 'number' && Number.isFinite(requested) ? requested : config.defaultTtlMs;
  return Math.min(Math.max(250, n), config.maxTtlMs);
}

export function createApp(deps: AppDeps): Express {
  const { store, crypto, config } = deps;
  const app = express();
  app.use(express.json({ limit: '1mb' }));

  const asyncHandler =
    (fn: (req: Request, res: Response) => Promise<void>) =>
    (req: Request, res: Response, next: (err: unknown) => void) =>
      fn(req, res).catch(next);

  app.get('/api/config', (_req, res) => {
    res.json({
      rpId: config.rpId,
      rpName: config.rpName,
      expectedOrigins: config.expectedOrigins,
      defaultTtlMs: config.defaultTtlMs,
    });
  });

  // ---------- 注册：签发 options（challenge 一次性、带过期） ----------

  app.post(
    '/api/register/options',
    asyncHandler(async (req, res) => {
      const body = req.body as {
        userName?: string;
        displayName?: string;
        residentKey?: 'required' | 'preferred' | 'discouraged';
        userVerification?: 'required' | 'preferred' | 'discouraged';
        attestation?: 'none' | 'direct';
        ttlMs?: number;
        replacesCredentialId?: string | null;
      };
      const userName = body.userName?.trim();
      if (!userName) {
        res.status(400).json({ ok: false, code: 'bad_format', message: 'userName 必填' });
        return;
      }
      const user = store.getOrCreateUser(userName);
      const challenge = b64uEncode(crypto.randomBytes(32));
      const ttl = clampTtl(body.ttlMs, config);

      // excludeCredentials 覆盖该用户的全部凭据（含隔离/已撤销）：
      // 恢复也必须在一枚新的 authenticator 凭据上完成，不能复用旧 credential id
      const excludeCredentials = store
        .allCredentials()
        .filter((c) => c.userName === userName)
        .map((c) => ({
          type: 'public-key' as const,
          id: c.credentialId,
          transports: ['internal'],
        }));

      // 恢复注册：在签发阶段锁定替代目标与处置版本快照，
      // 提交时重新校验，杜绝 options 与处置动作交错后的覆盖
      let replacesCredentialId: string | null = null;
      let replacesVersion: number | undefined;
      if (body.replacesCredentialId) {
        const target = store.getCredential(body.replacesCredentialId);
        if (!target || target.userName !== userName) {
          res.status(400).json({
            ok: false,
            code: 'recovery_target_invalid',
            message: `恢复目标凭据 ${body.replacesCredentialId} 不存在或不属于用户 ${userName}`,
          });
          return;
        }
        if (target.disposition.state !== 'quarantined') {
          res.status(409).json({
            ok: false,
            code: 'recovery_target_invalid',
            message: `恢复目标凭据当前为 ${target.disposition.state} 状态，只有隔离中的凭据可发起恢复替代`,
            state: target.disposition.state,
            disposition: target.disposition,
          });
          return;
        }
        replacesCredentialId = target.credentialId;
        replacesVersion = target.disposition.version;
      }

      const options: RegistrationOptionsDTO = {
        ceremonyId: '',
        rp: { id: config.rpId, name: config.rpName },
        user: { id: user.id, name: user.name, displayName: body.displayName ?? user.displayName },
        challenge,
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        authenticatorSelection: {
          residentKey: body.residentKey ?? 'preferred',
          userVerification: body.userVerification ?? 'preferred',
        },
        attestation: body.attestation ?? 'none',
        excludeCredentials,
        expiresAt: 0,
        timeout: ttl,
        ...(replacesCredentialId ? { replacesCredentialId, replacesVersion } : {}),
      };
      const ceremony = store.createCeremony('registration', challenge, options, ttl);
      options.ceremonyId = ceremony.id;
      options.expiresAt = ceremony.expiresAt;
      res.json(options);
    }),
  );

  // ---------- 注册：校验 attestation ----------

  app.post(
    '/api/register/result',
    asyncHandler(async (req, res) => {
      const body = req.body as AttestationResponseDTO;
      const gate = consumeCeremony(store, body.ceremonyId, 'registration');
      if (!gate.ok) {
        res.status(gate.httpStatus).json(gate.body);
        return;
      }
      const ceremony = gate.ceremony;

      const result = await verifyRegistration({
        options: ceremony.options as RegistrationOptionsDTO,
        response: body,
        expectedOrigins: config.expectedOrigins,
        crypto,
        credentialIdExists: (id) => store.credentialExists(id),
      });

      if (!result.ok) {
        store.fail(ceremony.id, result.code, result.message, result.checks);
        res.status(422).json(result);
        return;
      }

      const options = ceremony.options as RegistrationOptionsDTO;

      // 恢复注册：密码学检查全部通过后，原子地把隔离中的旧凭据翻转为已撤销（替代）。
      // 若 options 签发后旧凭据已被另一页面处置（版本/状态变化），本次恢复作废，
      // 新凭据也不落库——恢复必须与当前服务端处置状态一致。
      if (options.replacesCredentialId) {
        const linked = store.linkRecovery({
          oldCredentialId: options.replacesCredentialId,
          expectedVersion: options.replacesVersion ?? 0,
          newCredentialId: result.credentialId,
          ceremonyId: ceremony.id,
        });
        if (!linked.ok) {
          const checks = [
            ...result.checks,
            {
              check: 'recovery.target',
              ok: false as const,
              detail: linked.message,
            },
          ];
          store.fail(ceremony.id, linked.code, linked.message, checks);
          res.status(409).json({
            ok: false,
            code: linked.code,
            message: linked.message,
            checks,
            ...(linked.state ? { state: linked.state } : {}),
            ...(linked.current ? { disposition: linked.current } : {}),
          });
          return;
        }
      }

      const nowIso = new Date().toISOString();
      store.saveCredential({
        credentialId: result.credentialId,
        publicKey: result.publicKey,
        counter: result.counter,
        userHandle: options.user.id,
        userName: options.user.name,
        rpId: config.rpId,
        resident: body.residentHint ?? options.authenticatorSelection.residentKey !== 'discouraged',
        createdAt: nowIso,
        disposition: store.initialDisposition(nowIso),
      });
      if (options.replacesCredentialId) {
        store.markReplacement(result.credentialId, options.replacesCredentialId);
      }
      store.complete(ceremony.id, { checks: result.checks, credentialId: result.credentialId });
      res.json({
        ...result,
        ceremonyId: ceremony.id,
        ...(options.replacesCredentialId
          ? {
              recovery: {
                replacedCredentialId: options.replacesCredentialId,
                newCredentialId: result.credentialId,
              },
            }
          : {}),
      });
    }),
  );

  // ---------- 认证：签发 options ----------

  app.post(
    '/api/authenticate/options',
    asyncHandler(async (req, res) => {
      const body = req.body as {
        userName?: string;
        userVerification?: 'required' | 'preferred' | 'discouraged';
        discoverable?: boolean;
        ttlMs?: number;
      };
      const challenge = b64uEncode(crypto.randomBytes(32));
      const ttl = clampTtl(body.ttlMs, config);

      let allowCredentials: AuthenticationOptionsDTO['allowCredentials'] = [];
      if (!body.discoverable) {
        // 只签发 active 凭据；隔离/撤销凭据不出现在 allowCredentials 中
        const creds = body.userName
          ? store.credentialsForUser(body.userName)
          : store.allCredentials().filter((c) => c.disposition.state === 'active');
        allowCredentials = creds.map((c) => ({
          type: 'public-key' as const,
          id: c.credentialId,
          transports: ['internal'],
        }));
      }

      const options: AuthenticationOptionsDTO = {
        ceremonyId: '',
        rpId: config.rpId,
        challenge,
        allowCredentials,
        userVerification: body.userVerification ?? 'preferred',
        expiresAt: 0,
        timeout: ttl,
      };
      const ceremony = store.createCeremony('authentication', challenge, options, ttl);
      options.ceremonyId = ceremony.id;
      options.expiresAt = ceremony.expiresAt;
      res.json(options);
    }),
  );

  // ---------- 认证：校验 assertion（计数器 / 克隆告警） ----------

  app.post(
    '/api/authenticate/result',
    asyncHandler(async (req, res) => {
      const body = req.body as AssertionResponseDTO;
      const gate = consumeCeremony(store, body.ceremonyId, 'authentication');
      if (!gate.ok) {
        res.status(gate.httpStatus).json(gate.body);
        return;
      }
      const ceremony = gate.ceremony;

      const stored = store.getCredential(body.credentialId);
      const result = await verifyAuthentication({
        options: ceremony.options as AuthenticationOptionsDTO,
        response: body,
        expectedOrigins: config.expectedOrigins,
        crypto,
        credential: stored
          ? {
              credentialId: stored.credentialId,
              publicKey: stored.publicKey,
              counter: stored.counter,
              userHandle: stored.userHandle,
              rpId: stored.rpId,
            }
          : undefined,
      });

      if (!result.ok) {
        store.fail(ceremony.id, result.code, result.message, result.checks);
        res.status(422).json(result);
        return;
      }

      // 处置门禁：即使断言密码学上有效（签名、origin、rpId、UV、challenge 全部通过），
      // 隔离/撤销中的凭据也不能被当作普通成功；更大的计数器也不能自行解除隔离。
      // 检查在验签之后执行，因此失败响应仍带完整检查链作为证据；计数器不推进（冻结证据）。
      if (stored && stored.disposition.state !== 'active') {
        const code: FailureCode =
          stored.disposition.state === 'quarantined' ? 'credential_quarantined' : 'credential_revoked';
        const label = stored.disposition.state === 'quarantined' ? '隔离中' : '已撤销';
        const detail =
          stored.disposition.state === 'quarantined'
            ? `凭据 ${result.credentialId.slice(0, 12)}… 因克隆告警被隔离，待操作员处理；本次断言密码学有效但拒绝认证（计数器 ${stored.counter} → ${result.counter} 不解除隔离）`
            : `凭据 ${result.credentialId.slice(0, 12)}… 已被撤销（${stored.disposition.history.at(-1)?.action ?? ''}），即使仍留在 authenticator 中也不能再认证`;
        const checks: CheckResult[] = [
          ...result.checks,
          { check: 'credential.disposition', ok: false, detail: `${label}：${detail}` },
        ];
        store.fail(ceremony.id, code, detail, checks);
        res.status(403).json({
          ok: false,
          code,
          message: detail,
          checks,
          disposition: stored.disposition,
        });
        return;
      }

      // 计数器：即使触发克隆告警也推进到已见最大值，保证终态可解释。
      store.updateCounter(result.credentialId, Math.max(result.counter, stored?.counter ?? 0));
      if (result.cloneWarning) {
        // 真实断言校验产生的告警 → 凭据原子进入隔离，仪式保留 completed_with_clone_warning 作为证据
        store.quarantineForCloneWarning(result.credentialId, ceremony.id);
      }
      store.complete(ceremony.id, {
        checks: result.checks,
        credentialId: result.credentialId,
        cloneWarning: result.cloneWarning,
      });
      res.json({
        ...result,
        ceremonyId: ceremony.id,
        disposition: store.getCredential(result.credentialId)?.disposition,
      });
    }),
  );

  // ---------- 仪式管理 ----------

  app.post('/api/ceremonies/:id/cancel', (req, res) => {
    const ceremony = store.cancel(req.params.id);
    if (!ceremony) {
      res.status(404).json({ ok: false, code: 'challenge_not_found', message: '仪式不存在' });
      return;
    }
    res.json({ ceremonyId: ceremony.id, status: ceremony.status });
  });

  app.get('/api/ceremonies', (_req, res) => {
    res.json(store.listCeremonies().map(ceremonySummary));
  });

  app.get('/api/ceremonies/:id', (req, res) => {
    const ceremony = store.getCeremony(req.params.id);
    if (!ceremony) {
      res.status(404).json({ ok: false, code: 'challenge_not_found', message: '仪式不存在' });
      return;
    }
    res.json({ ...ceremonySummary(ceremony), options: ceremony.options });
  });

  app.get('/api/credentials', (_req, res) => {
    res.json(store.listCredentials());
  });

  // ---------- 凭据处置：维持隔离 / 撤销（乐观版本，防旧视图覆盖新决定） ----------

  app.post('/api/credentials/:id/disposition', (req, res) => {
    const body = req.body as { action?: string; expectedVersion?: number; note?: string };
    if (body.action !== 'maintain_quarantine' && body.action !== 'revoke_operator') {
      res.status(400).json({
        ok: false,
        code: 'bad_format',
        message: 'action 必须是 maintain_quarantine 或 revoke_operator',
      });
      return;
    }
    if (typeof body.expectedVersion !== 'number') {
      res.status(400).json({
        ok: false,
        code: 'bad_format',
        message: 'expectedVersion 必填（页面看到的处置版本）',
      });
      return;
    }
    const outcome = store.applyDisposition({
      credentialId: req.params.id,
      action: body.action,
      expectedVersion: body.expectedVersion,
      note: typeof body.note === 'string' ? body.note : undefined,
    });
    if (!outcome.ok) {
      if (outcome.code === 'credential_not_found') {
        res.status(404).json({ ok: false, code: 'unknown_credential', message: '凭据不存在（可能已重置服务端）' });
        return;
      }
      res.status(409).json({
        ok: false,
        code: 'disposition_conflict',
        message: outcome.message,
        state: outcome.state,
        disposition: outcome.current,
      });
      return;
    }
    res.json({
      ok: true,
      credentialId: outcome.credential.credentialId,
      disposition: outcome.credential.disposition,
    });
  });

  app.post('/api/reset', (_req, res) => {
    store.reset();
    res.json({ ok: true });
  });

  app.use((err: unknown, _req: Request, res: Response, _next: unknown) => {
    const message = err instanceof Error ? err.message : String(err);
    res.status(500).json({ ok: false, code: 'bad_format', message });
  });

  return app;
}

type ConsumeGate =
  | { ok: true; ceremony: CeremonyState }
  | { ok: false; httpStatus: number; body: { ok: false; code: FailureCode; message: string; checks: CheckResult[] } };

/**
 * 同步消费 challenge：在任何 await 之前完成状态翻转，
 * 保证并发请求里只有一个能进入校验阶段（一次性语义）。
 */
function consumeCeremony(store: LabStore, ceremonyId: string, expectedKind: CeremonyState['kind']): ConsumeGate {
  const fail = (httpStatus: number, code: FailureCode, message: string): ConsumeGate => ({
    ok: false,
    httpStatus,
    body: { ok: false, code, message, checks: [{ check: 'challenge.consume', ok: false, detail: message }] },
  });

  if (!ceremonyId) return fail(400, 'bad_format', '缺少 ceremonyId');
  const outcome = store.consume(ceremonyId);
  switch (outcome.outcome) {
    case 'ok': {
      if (outcome.ceremony.kind !== expectedKind) {
        store.fail(outcome.ceremony.id, 'type_mismatch', `仪式类型不符：${outcome.ceremony.kind}`, []);
        return fail(422, 'type_mismatch', `仪式 ${ceremonyId} 是 ${outcome.ceremony.kind}，不能用于 ${expectedKind}`);
      }
      return { ok: true, ceremony: outcome.ceremony };
    }
    case 'not_found':
      return fail(404, 'challenge_not_found', `仪式 ${ceremonyId} 不存在（challenge 从未签发或已重置）`);
    case 'consumed':
      return fail(
        409,
        'challenge_consumed',
        '该 challenge 已被消费：同一 challenge 不能被两个页面/请求重复使用（并发消费或重放）',
      );
    case 'expired':
      return fail(410, 'challenge_expired', 'challenge 已过期（超过 expiresAt），请重新发起仪式');
    case 'cancelled':
      return fail(409, 'ceremony_cancelled', '仪式已被客户端取消，challenge 作废');
  }
}
