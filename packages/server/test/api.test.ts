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
} from '@lab/shared';
import { createApp } from '../src/app.js';
import { LabStore } from '../src/store.js';

const ORIGIN = 'http://localhost:5173';

let app: Express;
let crypto: CryptoProvider;
let authenticator: SoftwareAuthenticator;

beforeEach(async () => {
  crypto = await createNodeCrypto();
  authenticator = new SoftwareAuthenticator(crypto, {});
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
