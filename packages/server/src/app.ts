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
  type CredentialDispositionAction,
  type CryptoProvider,
  type FailureCode,
  type RegistrationOptionsDTO,
} from '@lab/shared';
import { LabStore, type CeremonyState, type StoredCredential } from './store.js';

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

function credentialInfo(cred: StoredCredential) {
  return {
    credentialId: cred.credentialId,
    disposition: cred.disposition,
    dispositionVersion: cred.dispositionVersion,
    cloneWarningCeremonyId: cred.cloneWarningCeremonyId,
    replacedByCredentialId: cred.replacedByCredentialId,
    recoveryOfCredentialId: cred.recoveryOfCredentialId,
    recoveryCeremonyId: cred.recoveryCeremonyId,
  };
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
        /** 恢复注册：替代该用户名下处于隔离中的异常凭据 */
        recoveryOf?: string;
      };
      const userName = body.userName?.trim();
      if (!userName) {
        res.status(400).json({ ok: false, code: 'bad_format', message: 'userName 必填' });
        return;
      }
      const user = store.getOrCreateUser(userName);
      const challenge = b64uEncode(crypto.randomBytes(32));
      const ttl = clampTtl(body.ttlMs, config);

      const allForUser = store.credentialsForUser(userName);
      const excludeCredentials = allForUser.map((c) => ({
        type: 'public-key' as const,
        id: c.credentialId,
        transports: ['internal'],
      }));

      // 恢复注册：目标必须存在、属于同一用户、且当前处于隔离中；
      // 版本在签发时快照，提交时复检（completeRecovery）。
      let recoverySnapshot: { credentialId: string; dispositionVersion: number } | undefined;
      if (body.recoveryOf !== undefined && body.recoveryOf !== null && body.recoveryOf !== '') {
        const recoveryOf = String(body.recoveryOf);
        const target = store.getCredential(recoveryOf);
        if (!target || target.userName !== userName) {
          res.status(404).json({
            ok: false,
            code: 'recovery_target_invalid',
            message: `恢复目标凭据 ${recoveryOf} 不存在或不属于用户 ${userName}`,
          });
          return;
        }
        if (target.disposition !== 'quarantined') {
          res.status(409).json({
            ok: false,
            code: 'recovery_target_invalid',
            message: `恢复目标凭据当前处置状态为 ${target.disposition}，只有隔离中（quarantined）的凭据才能被新注册替代`,
            current: credentialInfo(target),
          });
          return;
        }
        recoverySnapshot = { credentialId: target.credentialId, dispositionVersion: target.dispositionVersion };
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
        recoveryOf: recoverySnapshot?.credentialId,
        expiresAt: 0,
        timeout: ttl,
      };
      const ceremony = store.createCeremony('registration', challenge, options, ttl);
      if (recoverySnapshot) store.attachRecovery(ceremony, recoverySnapshot.credentialId);
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
      const newCred: StoredCredential = {
        credentialId: result.credentialId,
        publicKey: result.publicKey,
        counter: result.counter,
        userHandle: options.user.id,
        userName: options.user.name,
        rpId: config.rpId,
        resident: body.residentHint ?? options.authenticatorSelection.residentKey !== 'discouraged',
        createdAt: new Date().toISOString(),
        disposition: 'active',
        dispositionVersion: 0,
        dispositionHistory: [
          {
            ceremonyId: ceremony.id,
            disposition: 'active',
            reason: 'enrolled',
            detail: ceremony.recovery
              ? '恢复注册：通过完整注册校验链后建立的替代凭据'
              : '注册校验链通过，凭据入库',
            at: new Date().toISOString(),
          },
        ],
      };

      if (ceremony.recovery) {
        const recovery = store.completeRecovery(newCred, ceremony.id);
        if (!recovery.ok) {
          store.fail(ceremony.id, recovery.code, recovery.message, [
            ...result.checks,
            {
              check: 'recovery.targetVersion',
              ok: false,
              detail: recovery.message,
            },
          ]);
          res.status(409).json({
            ok: false,
            code: recovery.code,
            message: recovery.message,
            current: recovery.current ? credentialInfo(recovery.current) : undefined,
            checks: result.checks,
          });
          return;
        }
        store.complete(ceremony.id, { checks: result.checks, credentialId: result.credentialId });
        res.json({
          ...result,
          ceremonyId: ceremony.id,
          credentialDisposition: 'active' as const,
          recovery: {
            recoveryOfCredentialId: recovery.oldCredential.credentialId,
            replacedByCredentialId: recovery.newCredential.credentialId,
            cloneWarningCeremonyId: recovery.oldCredential.cloneWarningCeremonyId,
          },
        });
        return;
      }

      store.saveCredential(newCred);
      store.complete(ceremony.id, { checks: result.checks, credentialId: result.credentialId });
      res.json({ ...result, ceremonyId: ceremony.id, credentialDisposition: 'active' as const });
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
        // 隔离中的凭据仍下发到 allowCredentials，让客户端能选中它、
        // 由服务端处置门禁产出可解释的被拦截终态；已撤销的凭据不再下发。
        const creds = store.authenticatableCredentials(body.userName);
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

  // ---------- 认证：校验 assertion（计数器 / 克隆告警 / 处置门禁） ----------

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

      // 处置门禁在密码学校验链之后判定：
      // 1) 必须确认这是一枚"真实断言"（签名等全部通过），隔离/撤销才有依据；
      // 2) options 可能在隔离生效前签发，提交时以服务端当前处置状态为准，
      //    已签发 options 不能绕过隔离，更大的计数器也不能自行解除隔离。
      if (result.ok && stored && stored.disposition !== 'active') {
        const blockedCheck: CheckResult =
          stored.disposition === 'quarantined'
            ? {
                check: 'credential.disposition',
                ok: false,
                detail:
                  `凭据处于隔离（quarantined，v${stored.dispositionVersion}，告警仪式 ${stored.cloneWarningCeremonyId ?? '?'}）：` +
                  '即使本次签名有效、计数器递增，也不能完成新认证；需操作员维持隔离/撤销并由用户重新注册恢复',
              }
            : {
                check: 'credential.disposition',
                ok: false,
                detail: stored.replacedByCredentialId
                  ? `凭据已被恢复注册替代并撤销（替代凭据 ${stored.replacedByCredentialId}），不得再次使用`
                  : '凭据已被操作员撤销（revoked），即使私钥仍留在软件 authenticator 中也不得再次使用',
              };
        const code: FailureCode =
          stored.disposition === 'quarantined' ? 'credential_quarantined' : 'credential_revoked';
        const message = blockedCheck.detail ?? '凭据当前处置状态不允许完成认证';
        store.fail(ceremony.id, code, message, [...result.checks, blockedCheck]);
        res.status(403).json({
          ok: false,
          code,
          message,
          checks: [...result.checks, blockedCheck],
          credential: credentialInfo(stored),
        });
        return;
      }

      if (!result.ok) {
        store.fail(ceremony.id, result.code, result.message, result.checks);
        res.status(422).json(result);
        return;
      }

      // 计数器：即使触发克隆告警也推进到已见最大值，保证终态可解释；
      // 同时把凭据置为隔离——这是服务端校验真实断言后产生的状态，而非前端标记。
      store.updateCounter(result.credentialId, Math.max(result.counter, stored?.counter ?? 0));
      const quarantined = result.cloneWarning
        ? store.quarantineOnCloneWarning(result.credentialId, ceremony.id)
        : false;
      store.complete(ceremony.id, {
        checks: result.checks,
        credentialId: result.credentialId,
        cloneWarning: result.cloneWarning,
      });
      const after = store.getCredential(result.credentialId);
      res.json({
        ...result,
        ceremonyId: ceremony.id,
        credentialDisposition: after?.disposition ?? 'active',
        dispositionVersion: after?.dispositionVersion,
        quarantined,
      });
    }),
  );

  // ---------- 凭据处置：维持隔离 / 撤销（乐观并发） ----------

  app.post(
    '/api/credentials/:id/disposition',
    (req, res) => {
      const action = req.body?.action as CredentialDispositionAction;
      const expectedVersion =
        typeof req.body?.expectedVersion === 'number' ? (req.body.expectedVersion as number) : undefined;
      if (action !== 'maintain_quarantine' && action !== 'revoke') {
        res.status(400).json({
          ok: false,
          code: 'invalid_disposition_action',
          message: `action 必须是 maintain_quarantine 或 revoke，收到 ${String(action)}`,
        });
        return;
      }
      const applied = store.applyDisposition(req.params.id, action, expectedVersion);
      if (!applied.ok) {
        const httpStatus =
          applied.code === 'unknown_credential'
            ? 404
            : applied.code === 'disposition_conflict'
              ? 409
              : 409;
        res.status(httpStatus).json({
          ok: false,
          code: applied.code,
          message: applied.message,
          current: applied.current ? store.toCredentialInfo(applied.current) : undefined,
        });
        return;
      }
      res.json({ ok: true, credential: store.toCredentialInfo(applied.credential) });
    },
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
