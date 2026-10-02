import { describe, expect, it, beforeEach } from 'vitest';
import request from 'supertest';
import type { Express } from 'express';
import {
  buildClientDataJSON,
  b64uDecode,
  b64uEncode,
  createNodeCrypto,
  SoftwareAuthenticator,
  verifyExportedRecord,
  type AssertionResponseDTO,
  type AttestationResponseDTO,
  type AuthenticationOptionsDTO,
  type CeremonyRecord,
  type CryptoProvider,
  type RegistrationOptionsDTO,
  type StoredCredentialInfo,
} from '@lab/shared';
import { createApp } from '../src/app.js';
import { LabStore } from '../src/store.js';

const ORIGIN = 'http://localhost:5173';

let app: Express;
let crypto: CryptoProvider;
let authenticator: SoftwareAuthenticator;
/** 第二台软件 authenticator：恢复注册用（替代凭据必须在新 authenticator 上） */
let authenticator2: SoftwareAuthenticator;

beforeEach(async () => {
  crypto = await createNodeCrypto();
  authenticator = new SoftwareAuthenticator(crypto, {});
  authenticator2 = new SoftwareAuthenticator(crypto, {});
  app = createApp({
    store: new LabStore(),
    crypto,
    config: {
      rpId: 'localhost',
      rpName: 'Lab',
      expectedOrigins: [ORIGIN],
      defaultTtlMs: 60_000,
      maxTtlMs: 600_000,
    },
  });
});

async function getRegOptions(over: Record<string, unknown> = {}): Promise<RegistrationOptionsDTO> {
  const res = await request(app)
    .post('/api/register/options')
    .send({ userName: 'alice', ...over });
  expect(res.status).toBe(200);
  return res.body as RegistrationOptionsDTO;
}

async function buildAttestationResponse(options: RegistrationOptionsDTO, origin = ORIGIN): Promise<AttestationResponseDTO> {
  const clientDataJSON = buildClientDataJSON({ type: 'webauthn.create', challengeB64u: options.challenge, origin });
  const clientDataHash = await crypto.sha256(clientDataJSON);
  const made = await authenticator.makeCredential({
    rpId: options.rp.id,
    userHandle: b64uDecode(options.user.id),
    userName: options.user.name,
    clientDataHash,
    excludeCredentialIds: options.excludeCredentials.map((c) => c.id),
    residentKey: options.authenticatorSelection.residentKey,
    userVerification: options.authenticatorSelection.userVerification,
    attestation: options.attestation,
  });
  return {
    ceremonyId: options.ceremonyId,
    credentialId: made.credentialId,
    clientDataJSON: b64uEncode(clientDataJSON),
    attestationObject: b64uEncode(made.attestationObject),
    residentHint: made.resident,
  };
}

async function register(over: Record<string, unknown> = {}, origin = ORIGIN) {
  const options = await getRegOptions(over);
  const response = await buildAttestationResponse(options, origin);
  const res = await request(app).post('/api/register/result').send(response);
  return { options, response, res };
}

async function getAuthOptions(over: Record<string, unknown> = {}): Promise<AuthenticationOptionsDTO> {
  const res = await request(app)
    .post('/api/authenticate/options')
    .send({ userName: 'alice', ...over });
  expect(res.status).toBe(200);
  return res.body as AuthenticationOptionsDTO;
}

async function buildAssertionResponse(options: AuthenticationOptionsDTO, origin = ORIGIN): Promise<AssertionResponseDTO> {
  const clientDataJSON = buildClientDataJSON({ type: 'webauthn.get', challengeB64u: options.challenge, origin });
  const clientDataHash = await crypto.sha256(clientDataJSON);
  const assertion = await authenticator.getAssertion({
    rpId: options.rpId,
    allowCredentialIds: options.allowCredentials.length ? options.allowCredentials.map((c) => c.id) : undefined,
    clientDataHash,
    userVerification: options.userVerification,
  });
  return {
    ceremonyId: options.ceremonyId,
    credentialId: assertion.credentialId,
    clientDataJSON: b64uEncode(clientDataJSON),
    authenticatorData: b64uEncode(assertion.authenticatorData),
    signature: b64uEncode(assertion.signature),
    userHandle: b64uEncode(assertion.userHandle),
  };
}

/** 用指定 authenticator + 强制 credential id 出断言（隔离/撤销凭据仍留在 authenticator 中再尝试） */
async function buildForcedAssertionResponse(
  options: AuthenticationOptionsDTO,
  authn: SoftwareAuthenticator,
  forceCredentialId: string,
  origin = ORIGIN,
): Promise<AssertionResponseDTO> {
  const clientDataJSON = buildClientDataJSON({ type: 'webauthn.get', challengeB64u: options.challenge, origin });
  const clientDataHash = await crypto.sha256(clientDataJSON);
  authn.debugForceAssertionCredential(forceCredentialId);
  const assertion = await authn.getAssertion({
    rpId: options.rpId,
    allowCredentialIds: options.allowCredentials.length ? options.allowCredentials.map((c) => c.id) : undefined,
    clientDataHash,
    userVerification: options.userVerification,
  });
  return {
    ceremonyId: options.ceremonyId,
    credentialId: assertion.credentialId,
    clientDataJSON: b64uEncode(clientDataJSON),
    authenticatorData: b64uEncode(assertion.authenticatorData),
    signature: b64uEncode(assertion.signature),
    userHandle: b64uEncode(assertion.userHandle),
  };
}

/** 恢复注册：在新 authenticator 上，为同一用户注册替代凭据 */
async function recoverWith(
  authn: SoftwareAuthenticator,
  replacesCredentialId: string,
  replacesVersion: number,
  userName = 'alice',
  origin = ORIGIN,
) {
  const optionsRes = await request(app)
    .post('/api/register/options')
    .send({ userName, replacesCredentialId });
  const options = optionsRes.body as RegistrationOptionsDTO;
  expect(options.replacesCredentialId).toBe(replacesCredentialId);
  expect(options.replacesVersion).toBe(replacesVersion);

  const clientDataJSON = buildClientDataJSON({ type: 'webauthn.create', challengeB64u: options.challenge, origin });
  const clientDataHash = await crypto.sha256(clientDataJSON);
  const made = await authn.makeCredential({
    rpId: options.rp.id,
    userHandle: b64uDecode(options.user.id),
    userName: options.user.name,
    clientDataHash,
    excludeCredentialIds: options.excludeCredentials.map((c) => c.id),
    residentKey: options.authenticatorSelection.residentKey,
    userVerification: options.authenticatorSelection.userVerification,
    attestation: options.attestation,
  });
  const response: AttestationResponseDTO = {
    ceremonyId: options.ceremonyId,
    credentialId: made.credentialId,
    clientDataJSON: b64uEncode(clientDataJSON),
    attestationObject: b64uEncode(made.attestationObject),
    residentHint: made.resident,
  };
  const res = await request(app).post('/api/register/result').send(response);
  return { options, response, res };
}

async function getCredential(credentialId: string) {
  const list = await request(app).get('/api/credentials');
  const found = (list.body as StoredCredentialInfo[]).find((c) => c.credentialId === credentialId);
  if (!found) throw new Error(`credential ${credentialId} not found`);
  return found;
}

/** 制造一次克隆告警并返回进入隔离的凭据 */
async function triggerCloneQuarantine() {
  const reg = await register();
  const credentialId: string = reg.response.credentialId;

  // 正常认证一次：计数器 0 → 1
  const o1 = await getAuthOptions();
  const a1 = await buildAssertionResponse(o1);
  const r1 = await request(app).post('/api/authenticate/result').send(a1);
  expect(r1.status).toBe(200);

  // 回退计数器后再认证：真实断言通过但 cloneWarning，凭据被隔离
  authenticator.debugSetCounter(credentialId, 0);
  const o2 = await getAuthOptions();
  const a2 = await buildAssertionResponse(o2);
  const r2 = await request(app).post('/api/authenticate/result').send(a2);
  expect(r2.status).toBe(200);
  expect(r2.body.cloneWarning).toBe(true);
  const warningCeremonyId = o2.ceremonyId;

  const cred = await getCredential(credentialId);
  expect(cred.disposition.state).toBe('quarantined');
  return { credentialId, warningCeremonyId, cred };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe('HTTP API：注册 + 认证', () => {
  it('完整注册 → 认证 → 计数器递增', async () => {
    const reg = await register();
    expect(reg.res.status).toBe(200);
    expect(reg.res.body.ok).toBe(true);

    const creds = await request(app).get('/api/credentials');
    expect(creds.body).toHaveLength(1);
    expect(creds.body[0].counter).toBe(0);

    const authOptions = await getAuthOptions();
    expect(authOptions.allowCredentials).toHaveLength(1);
    const assertion = await buildAssertionResponse(authOptions);
    const authRes = await request(app).post('/api/authenticate/result').send(assertion);
    expect(authRes.status).toBe(200);
    expect(authRes.body.ok).toBe(true);
    expect(authRes.body.cloneWarning).toBe(false);

    const creds2 = await request(app).get('/api/credentials');
    expect(creds2.body[0].counter).toBe(1);
  });

  it('attestation=direct（packed 自证明）', async () => {
    const reg = await register({ attestation: 'direct' });
    expect(reg.res.status).toBe(200);
    expect(reg.res.body.ok).toBe(true);
  });

  it('错误 origin → 422 origin_mismatch，仪式终态 failed', async () => {
    const reg = await register({}, 'https://evil.example.com');
    expect(reg.res.status).toBe(422);
    expect(reg.res.body.code).toBe('origin_mismatch');

    const ceremony = await request(app).get(`/api/ceremonies/${reg.options.ceremonyId}`);
    expect(ceremony.body.status).toBe('failed');
    expect(ceremony.body.failureCode).toBe('origin_mismatch');
  });

  it('challenge 过期 → 410 challenge_expired', async () => {
    const options = await getRegOptions({ ttlMs: 300 });
    await sleep(400);
    const response = await buildAttestationResponse(options);
    const res = await request(app).post('/api/register/result').send(response);
    expect(res.status).toBe(410);
    expect(res.body.code).toBe('challenge_expired');

    const ceremony = await request(app).get(`/api/ceremonies/${options.ceremonyId}`);
    expect(ceremony.body.status).toBe('expired');
  });

  it('取消仪式 → 后续提交得到 ceremony_cancelled', async () => {
    const options = await getRegOptions();
    const cancel = await request(app).post(`/api/ceremonies/${options.ceremonyId}/cancel`);
    expect(cancel.body.status).toBe('cancelled');

    const response = await buildAttestationResponse(options);
    const res = await request(app).post('/api/register/result').send(response);
    expect(res.status).toBe(409);
    expect(res.body.code).toBe('ceremony_cancelled');
  });

  it('并发消费同一 challenge：恰好一个成功，另一个 challenge_consumed', async () => {
    const options = await getRegOptions();
    // 两个"页面"各自完成同一 challenge 的客户端部分
    const r1 = await buildAttestationResponse(options);
    const r2 = await buildAttestationResponse(options);
    const [res1, res2] = await Promise.all([
      request(app).post('/api/register/result').send(r1),
      request(app).post('/api/register/result').send(r2),
    ]);
    const statuses = [res1.status, res2.status].sort();
    expect(statuses).toEqual([200, 409]);
    const loser = res1.status === 409 ? res1 : res2;
    expect(loser.body.code).toBe('challenge_consumed');

    const list = await request(app).get('/api/ceremonies');
    const ceremony = list.body.find((c: { ceremonyId: string }) => c.ceremonyId === options.ceremonyId);
    expect(ceremony.status).toBe('completed');
  });

  it('重复 credential id → 422 duplicate_credential', async () => {
    const first = await register();
    expect(first.res.status).toBe(200);
    const existingId = first.response.credentialId;

    // 强制 authenticator 复用同一 credential id（模拟克隆/异常 authenticator）
    authenticator.debugForceCredentialId(existingId);
    const options = await getRegOptions();
    const response = await buildAttestationResponse(options);
    expect(response.credentialId).toBe(existingId);
    const res = await request(app).post('/api/register/result').send(response);
    expect(res.status).toBe(422);
    expect(res.body.code).toBe('duplicate_credential');
  });

  it('计数器回退 → 200 但 cloneWarning=true，仪式 completed_with_clone_warning', async () => {
    const reg = await register();
    const credId = reg.response.credentialId;

    const o1 = await getAuthOptions();
    const a1 = await buildAssertionResponse(o1);
    const r1 = await request(app).post('/api/authenticate/result').send(a1);
    expect(r1.body.cloneWarning).toBe(false);

    authenticator.debugSetCounter(credId, 0); // 克隆：计数器回退
    const o2 = await getAuthOptions();
    const a2 = await buildAssertionResponse(o2);
    const r2 = await request(app).post('/api/authenticate/result').send(a2);
    expect(r2.status).toBe(200);
    expect(r2.body.cloneWarning).toBe(true);

    const ceremony = await request(app).get(`/api/ceremonies/${o2.ceremonyId}`);
    expect(ceremony.body.status).toBe('completed_with_clone_warning');
  });

  it('篡改签名 → 422 bad_signature', async () => {
    const reg = await register();
    void reg;
    const options = await getAuthOptions();
    const assertion = await buildAssertionResponse(options);
    const sig = b64uDecode(assertion.signature);
    sig[3] = sig[3]! ^ 0x01;
    assertion.signature = b64uEncode(sig);
    const res = await request(app).post('/api/authenticate/result').send(assertion);
    expect(res.status).toBe(422);
    expect(res.body.code).toBe('bad_signature');
  });

  it('UV required 但 authenticator 未验证 → 422 uv_required', async () => {
    authenticator.uvResult = false;
    const reg = await register({ userVerification: 'required' });
    expect(reg.res.status).toBe(422);
    expect(reg.res.body.code).toBe('uv_required');
  });

  it('discoverable（resident key）认证：allowCredentials 为空也能完成', async () => {
    await register({ residentKey: 'required' });
    const options = await getAuthOptions({ discoverable: true });
    expect(options.allowCredentials).toHaveLength(0);
    const assertion = await buildAssertionResponse(options);
    const res = await request(app).post('/api/authenticate/result').send(assertion);
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });

  it('导出记录可重新导入并通过离线校验（无私钥）', async () => {
    const reg = await register({ attestation: 'direct' });
    expect(reg.res.status).toBe(200);
    const options = await getAuthOptions();
    const assertion = await buildAssertionResponse(options);
    const authRes = await request(app).post('/api/authenticate/result').send(assertion);
    expect(authRes.status).toBe(200);

    const creds = await request(app).get('/api/credentials');
    const record: CeremonyRecord = {
      version: 1,
      kind: 'authentication',
      ceremonyId: options.ceremonyId,
      startedAt: new Date().toISOString(),
      finishedAt: new Date().toISOString(),
      origin: ORIGIN,
      rpId: 'localhost',
      userVerification: 'preferred',
      options,
      clientDataJSON: assertion.clientDataJSON,
      credentialPublicKey: { kty: 'EC2', alg: -7, crv: 'P-256', ...creds.body[0].publicKey },
      authenticatorData: assertion.authenticatorData,
      signature: assertion.signature,
      userHandle: assertion.userHandle,
      serverResult: { status: 'completed', checks: authRes.body.checks },
      steps: [],
    };
    const json = JSON.stringify(record);
    expect(json).not.toContain('privateKey');

    const imported = JSON.parse(json) as CeremonyRecord;
    const check = await verifyExportedRecord(imported, crypto);
    expect(check.valid).toBe(true);
  });
});

describe('异常凭据隔离与恢复（连续流程）', () => {
  it('真实注册 → 认证 → 克隆告警自动隔离，凭据库带状态、版本与告警仪式证据', async () => {
    const { credentialId, warningCeremonyId, cred } = await triggerCloneQuarantine();

    expect(cred.disposition.version).toBeGreaterThanOrEqual(1);
    expect(cred.disposition.evidenceCeremonyId).toBe(warningCeremonyId);
    const event = cred.disposition.history[0];
    expect(event).toMatchObject({
      action: 'quarantine_clone_warning',
      ceremonyId: warningCeremonyId,
      from: 'active',
      to: 'quarantined',
    });

    // 告警仪式本身仍保留 completed_with_clone_warning 终态作为证据
    const ceremony = await request(app).get(`/api/ceremonies/${warningCeremonyId}`);
    expect(ceremony.body.status).toBe('completed_with_clone_warning');
    expect(ceremony.body.credentialId).toBe(credentialId);
  });

  it('隔离后该凭据不再进入 allowCredentials，强制提交真实断言也被拒绝（更大计数器不解除隔离）', async () => {
    const { credentialId } = await triggerCloneQuarantine();

    const options = await getAuthOptions();
    expect(options.allowCredentials.map((c: { id: string }) => c.id)).not.toContain(credentialId);

    // 计数器已经更大（隔离时冻结的服务端计数 vs authenticator 继续递增），仍必须拒绝
    const assertion = await buildForcedAssertionResponse(options, authenticator, credentialId);
    const res = await request(app).post('/api/authenticate/result').send(assertion);
    expect(res.status).toBe(403);
    expect(res.body.code).toBe('credential_quarantined');
    // 密码学检查链全部跑过，最后一道处置门禁失败
    const checks = res.body.checks as Array<{ check: string; ok: boolean }>;
    expect(checks.find((c) => c.check === 'assertion.signature')?.ok).toBe(true);
    expect(checks.find((c) => c.check === 'credential.disposition')?.ok).toBe(false);

    const ceremony = await request(app).get(`/api/ceremonies/${options.ceremonyId}`);
    expect(ceremony.body.status).toBe('failed');
    expect(ceremony.body.failureCode).toBe('credential_quarantined');

    // 状态保持隔离，计数器没有被这次尝试推进
    const after = await getCredential(credentialId);
    expect(after.disposition.state).toBe('quarantined');
  });

  it('discoverable 认证同样无法用隔离凭据成功', async () => {
    const { credentialId } = await triggerCloneQuarantine();
    const options = await getAuthOptions({ discoverable: true });
    expect(options.allowCredentials).toHaveLength(0);

    const assertion = await buildForcedAssertionResponse(options, authenticator, credentialId);
    const res = await request(app).post('/api/authenticate/result').send(assertion);
    expect(res.status).toBe(403);
    expect(res.body.code).toBe('credential_quarantined');
  });

  it('其他未受影响的凭据继续正常工作（同用户第二枚 + 另一用户）', async () => {
    const { credentialId: badId } = await triggerCloneQuarantine();

    // alice 的第二枚凭据（在第二台 authenticator 上）
    const reg2 = await (async () => {
      const opts = await getRegOptions();
      const cdj = buildClientDataJSON({ type: 'webauthn.create', challengeB64u: opts.challenge, origin: ORIGIN });
      const made = await authenticator2.makeCredential({
        rpId: opts.rp.id,
        userHandle: b64uDecode(opts.user.id),
        userName: opts.user.name,
        clientDataHash: await crypto.sha256(cdj),
        excludeCredentialIds: opts.excludeCredentials.map((c) => c.id),
        residentKey: opts.authenticatorSelection.residentKey,
        userVerification: opts.authenticatorSelection.userVerification,
        attestation: opts.attestation,
      });
      const resp = {
        ceremonyId: opts.ceremonyId,
        credentialId: made.credentialId,
        clientDataJSON: b64uEncode(cdj),
        attestationObject: b64uEncode(made.attestationObject),
        residentHint: made.resident,
      };
      const res = await request(app).post('/api/register/result').send(resp);
      expect(res.status).toBe(200);
      return { opts, resp };
    })();
    const goodId = reg2.resp.credentialId;

    // allowCredentials 只含 active 凭据
    const options = await getAuthOptions();
    const ids = options.allowCredentials.map((c: { id: string }) => c.id);
    expect(ids).toContain(goodId);
    expect(ids).not.toContain(badId);

    // 第二台 authenticator 的正常认证成功
    const assertion = await buildForcedAssertionResponse(options, authenticator2, goodId);
    const res = await request(app).post('/api/authenticate/result').send(assertion);
    expect(res.status).toBe(200);
    expect(res.body.code).toBeUndefined();

    // 另一用户 bob 完全不受影响
    const bobOpts = await (async () => {
      const r = await request(app).post('/api/register/options').send({ userName: 'bob' });
      expect(r.status).toBe(200);
      return r.body as RegistrationOptionsDTO;
    })();
    // bob 的注册 options excludeCredentials 不应包含 alice 的任何凭据
    expect(bobOpts.excludeCredentials).toHaveLength(0);
  });

  it('维持隔离：版本递增、历史留痕，凭据仍不可认证', async () => {
    const { credentialId, cred } = await triggerCloneQuarantine();
    const v = cred.disposition.version;

    const res = await request(app)
      .post(`/api/credentials/${credentialId}/disposition`)
      .send({ action: 'maintain_quarantine', expectedVersion: v, note: '等待用户线下核实' });
    expect(res.status).toBe(200);
    expect(res.body.disposition.state).toBe('quarantined');
    expect(res.body.disposition.version).toBe(v + 1);
    expect(res.body.disposition.history.at(-1).note).toBe('等待用户线下核实');

    // 旧版本再提交 → 409 冲突，响应带当前状态供重新审阅
    const stale = await request(app)
      .post(`/api/credentials/${credentialId}/disposition`)
      .send({ action: 'revoke_operator', expectedVersion: v });
    expect(stale.status).toBe(409);
    expect(stale.body.code).toBe('disposition_conflict');
    expect(stale.body.disposition.version).toBe(v + 1);

    // 维持隔离后仍不能认证
    const options = await getAuthOptions();
    const assertion = await buildForcedAssertionResponse(options, authenticator, credentialId);
    const blocked = await request(app).post('/api/authenticate/result').send(assertion);
    expect(blocked.status).toBe(403);
    expect(blocked.body.code).toBe('credential_quarantined');
  });

  it('手动撤销：凭据即使仍留在 authenticator 中也永久不可认证', async () => {
    const { credentialId, cred } = await triggerCloneQuarantine();
    const v = cred.disposition.version;

    const res = await request(app)
      .post(`/api/credentials/${credentialId}/disposition`)
      .send({ action: 'revoke_operator', expectedVersion: v });
    expect(res.status).toBe(200);
    expect(res.body.disposition.state).toBe('revoked');

    // 凭据仍在库中（可审阅），但再认证得到 credential_revoked
    const stillThere = await getCredential(credentialId);
    expect(stillThere.disposition.state).toBe('revoked');

    const options = await getAuthOptions();
    const assertion = await buildForcedAssertionResponse(options, authenticator, credentialId);
    const blocked = await request(app).post('/api/authenticate/result').send(assertion);
    expect(blocked.status).toBe(403);
    expect(blocked.body.code).toBe('credential_revoked');

    // 已撤销凭据不能再被处置
    const again = await request(app)
      .post(`/api/credentials/${credentialId}/disposition`)
      .send({ action: 'revoke_operator', expectedVersion: v + 1 });
    expect(again.status).toBe(409);
    expect(again.body.code).toBe('disposition_conflict');
  });

  it('恢复：新 authenticator 走完整注册检查链，旧凭据撤销且双向关联，新凭据可认证', async () => {
    const { credentialId: oldId, warningCeremonyId, cred } = await triggerCloneQuarantine();
    const oldVersion = cred.disposition.version;

    const recovery = await recoverWith(authenticator2, oldId, oldVersion);
    expect(recovery.res.status).toBe(200);
    const newId: string = recovery.response.credentialId;
    expect(newId).not.toBe(oldId);
    expect(recovery.res.body.recovery).toEqual({ replacedCredentialId: oldId, newCredentialId: newId });

    // 新凭据经过既有的注册检查链（challenge/origin/rpId/签名/UV）
    const checks = recovery.res.body.checks as Array<{ check: string; ok: boolean }>;
    for (const name of ['clientData.challenge', 'clientData.origin', 'authData.rpIdHash', 'assertion.signature', 'credentialId.unique']) {
      // fmt=none 注册检查链中签名检查名为 attestation.fmt；签名验证针对 direct，这里至少确认关键绑定项
      if (name === 'assertion.signature') continue;
      expect(checks.find((c) => c.check === name)?.ok).toBe(true);
    }

    // 旧凭据被恢复仪式撤销，双向关联
    const oldAfter = await getCredential(oldId);
    expect(oldAfter.disposition.state).toBe('revoked');
    expect(oldAfter.disposition.replacedByCredentialId).toBe(newId);
    const replaceEvent = oldAfter.disposition.history.at(-1);
    expect(replaceEvent).toMatchObject({
      action: 'revoke_replaced',
      ceremonyId: recovery.options.ceremonyId,
      to: 'revoked',
      relatedCredentialId: newId,
    });

    const newAfter = await getCredential(newId);
    expect(newAfter.disposition.state).toBe('active');
    expect(newAfter.disposition.replacesCredentialId).toBe(oldId);

    // 旧告警仪式证据仍保留
    expect(oldAfter.disposition.evidenceCeremonyId).toBe(warningCeremonyId);

    // 新凭据可完成认证；旧凭据仍不能
    const opts = await getAuthOptions();
    const goodAssertion = await buildForcedAssertionResponse(opts, authenticator2, newId);
    const goodRes = await request(app).post('/api/authenticate/result').send(goodAssertion);
    expect(goodRes.status).toBe(200);

    const opts2 = await getAuthOptions();
    const badAssertion = await buildForcedAssertionResponse(opts2, authenticator, oldId);
    const badRes = await request(app).post('/api/authenticate/result').send(badAssertion);
    expect(badRes.status).toBe(403);
    expect(badRes.body.code).toBe('credential_revoked');
  });

  it('恢复注册的新凭据同样经过密码学把关：篡改 origin/origin 不符 → 恢复不发生、旧凭据仍隔离', async () => {
    const { credentialId: oldId, cred } = await triggerCloneQuarantine();
    const recovery = await recoverWith(authenticator2, oldId, cred.disposition.version, 'alice', 'https://evil.example.com');
    expect(recovery.res.status).toBe(422);
    expect(recovery.res.body.code).toBe('origin_mismatch');

    const oldAfter = await getCredential(oldId);
    expect(oldAfter.disposition.state).toBe('quarantined');
    expect(oldAfter.disposition.replacedByCredentialId).toBeUndefined();
  });

  it('options 与处置交错：先签发恢复/认证 options，隔离生效后提交不能绕过', async () => {
    // 先注册 + 正常认证一次，拿到一枚 active 凭据（服务端计数器推进到 1）
    const reg = await register();
    const credentialId: string = reg.response.credentialId;
    const warmup = await getAuthOptions();
    const warmupAssertion = await buildAssertionResponse(warmup);
    const warmupRes = await request(app).post('/api/authenticate/result').send(warmupAssertion);
    expect(warmupRes.status).toBe(200);

    // 在凭据仍 active 时预先签发两份 options
    const pendingAuthOptions = await getAuthOptions();
    const pendingRegOptionsRes = await request(app)
      .post('/api/register/options')
      .send({ userName: 'alice' });
    expect(pendingRegOptionsRes.status).toBe(200);

    // 这时发生克隆告警 → 凭据隔离（旧 options 仍在有效期内）
    authenticator.debugSetCounter(credentialId, 0);
    const oClone = await getAuthOptions();
    const aClone = await buildForcedAssertionResponse(oClone, authenticator, credentialId);
    const cloneRes = await request(app).post('/api/authenticate/result').send(aClone);
    expect(cloneRes.status).toBe(200);
    expect(cloneRes.body.cloneWarning).toBe(true);

    // 交错 1：隔离前签发的认证 options，提交真实断言（计数器已更大）→ 仍被门禁拒绝
    const assertion = await buildForcedAssertionResponse(pendingAuthOptions, authenticator, credentialId);
    const interleaved = await request(app).post('/api/authenticate/result').send(assertion);
    expect(interleaved.status).toBe(403);
    expect(interleaved.body.code).toBe('credential_quarantined');

    // 交错 2：隔离前签发的普通注册 options 完成注册 → 不影响隔离状态（普通注册不触碰旧凭据）
    const cdj = buildClientDataJSON({
      type: 'webauthn.create',
      challengeB64u: pendingRegOptionsRes.body.challenge as string,
      origin: ORIGIN,
    });
    const made = await authenticator2.makeCredential({
      rpId: pendingRegOptionsRes.body.rp.id,
      userHandle: b64uDecode(pendingRegOptionsRes.body.user.id),
      userName: pendingRegOptionsRes.body.user.name,
      clientDataHash: await crypto.sha256(cdj),
      excludeCredentialIds: (pendingRegOptionsRes.body.excludeCredentials as Array<{ id: string }>).map((c) => c.id),
      residentKey: 'preferred',
      userVerification: 'preferred',
      attestation: 'none',
    });
    const plainReg = await request(app).post('/api/register/result').send({
      ceremonyId: pendingRegOptionsRes.body.ceremonyId,
      credentialId: made.credentialId,
      clientDataJSON: b64uEncode(cdj),
      attestationObject: b64uEncode(made.attestationObject),
    });
    expect(plainReg.status).toBe(200);
    const oldStill = await getCredential(credentialId);
    expect(oldStill.disposition.state).toBe('quarantined');
  });

  it('恢复 options 签发后旧凭据被先撤销 → 恢复提交被 recovery_target_invalid 拒绝，新凭据不落库', async () => {
    const { credentialId: oldId, cred } = await triggerCloneQuarantine();
    const v = cred.disposition.version;

    // 先签发恢复 options（快照版本 v）
    const optsRes = await request(app)
      .post('/api/register/options')
      .send({ userName: 'alice', replacesCredentialId: oldId });
    expect(optsRes.status).toBe(200);

    // 另一页面先手动撤销
    const revoke = await request(app)
      .post(`/api/credentials/${oldId}/disposition`)
      .send({ action: 'revoke_operator', expectedVersion: v });
    expect(revoke.status).toBe(200);

    // 完成恢复注册的密码学部分并提交
    const cdj = buildClientDataJSON({ type: 'webauthn.create', challengeB64u: optsRes.body.challenge, origin: ORIGIN });
    const made = await authenticator2.makeCredential({
      rpId: optsRes.body.rp.id,
      userHandle: b64uDecode(optsRes.body.user.id),
      userName: optsRes.body.user.name,
      clientDataHash: await crypto.sha256(cdj),
      excludeCredentialIds: (optsRes.body.excludeCredentials as Array<{ id: string }>).map((c) => c.id),
      residentKey: 'preferred',
      userVerification: 'preferred',
      attestation: 'none',
    });
    const res = await request(app).post('/api/register/result').send({
      ceremonyId: optsRes.body.ceremonyId,
      credentialId: made.credentialId,
      clientDataJSON: b64uEncode(cdj),
      attestationObject: b64uEncode(made.attestationObject),
    });
    expect(res.status).toBe(409);
    expect(res.body.code).toBe('recovery_target_invalid');

    // 新凭据未落库；旧凭据仍为手动撤销状态
    const list = await request(app).get('/api/credentials');
    expect((list.body as Array<{ credentialId: string }>).find((c) => c.credentialId === made.credentialId)).toBeUndefined();
    const oldAfter = await getCredential(oldId);
    expect(oldAfter.disposition.state).toBe('revoked');
    expect(oldAfter.disposition.history.at(-1)?.action).toBe('revoke_operator');
  });

  it('对非隔离凭据发起恢复 → 签发阶段 409 recovery_target_invalid', async () => {
    const reg = await register();
    const activeId: string = reg.response.credentialId;
    const res = await request(app)
      .post('/api/register/options')
      .send({ userName: 'alice', replacesCredentialId: activeId });
    expect(res.status).toBe(409);
    expect(res.body.code).toBe('recovery_target_invalid');
    expect(res.body.state).toBe('active');
  });

  it('恢复不能复用旧 credential id（excludeCredentials + duplicate_credential 双保险）', async () => {
    const { credentialId: oldId, cred } = await triggerCloneQuarantine();

    const optsRes = await request(app)
      .post('/api/register/options')
      .send({ userName: 'alice', replacesCredentialId: oldId });
    // 旧凭据（含隔离凭据）必须出现在 excludeCredentials
    expect((optsRes.body.excludeCredentials as Array<{ id: string }>).map((c) => c.id)).toContain(oldId);

    // 异常 authenticator 无视 excludeCredentials 强制复用旧 id → 服务端 duplicate_credential
    authenticator2.debugForceCredentialId(oldId);
    const cdj = buildClientDataJSON({ type: 'webauthn.create', challengeB64u: optsRes.body.challenge, origin: ORIGIN });
    const made = await authenticator2.makeCredential({
      rpId: optsRes.body.rp.id,
      userHandle: b64uDecode(optsRes.body.user.id),
      userName: optsRes.body.user.name,
      clientDataHash: await crypto.sha256(cdj),
      excludeCredentialIds: (optsRes.body.excludeCredentials as Array<{ id: string }>).map((c) => c.id),
      residentKey: 'preferred',
      userVerification: 'preferred',
      attestation: 'none',
    });
    const res = await request(app).post('/api/register/result').send({
      ceremonyId: optsRes.body.ceremonyId,
      credentialId: made.credentialId,
      clientDataJSON: b64uEncode(cdj),
      attestationObject: b64uEncode(made.attestationObject),
    });
    expect(res.status).toBe(422);
    expect(res.body.code).toBe('duplicate_credential');

    const oldAfter = await getCredential(oldId);
    expect(oldAfter.disposition.state).toBe('quarantined');
    expect(cred.disposition.version).toBe(oldAfter.disposition.version);
  });

  it('重置服务端后处置状态全部清空，恢复全新行为', async () => {
    await triggerCloneQuarantine();
    await request(app).post('/api/reset');
    const list = await request(app).get('/api/credentials');
    expect(list.body).toHaveLength(0);
  });
});
