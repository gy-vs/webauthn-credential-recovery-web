import { describe, expect, it } from 'vitest';
import {
  buildClientDataJSON,
  b64uDecode,
  b64uEncode,
  createNodeCrypto,
  SoftwareAuthenticator,
  verifyExportedRecord,
  type CeremonyRecord,
  type RegistrationOptionsDTO,
} from '../src/index.js';

const ORIGIN = 'https://app.example.com';
const RP_ID = 'app.example.com';

async function makeRegistrationRecord(attestation: 'none' | 'direct'): Promise<{ record: CeremonyRecord; crypto: Awaited<ReturnType<typeof createNodeCrypto>> }> {
  const crypto = await createNodeCrypto();
  const authn = new SoftwareAuthenticator(crypto, { clock: () => 1_700_000_000_000 });
  const options: RegistrationOptionsDTO = {
    ceremonyId: 'c1',
    rp: { id: RP_ID, name: 'Example' },
    user: { id: b64uEncode(new Uint8Array(16).fill(3)), name: 'bob', displayName: 'Bob' },
    challenge: b64uEncode(crypto.randomBytes(32)),
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
    attestation,
    excludeCredentials: [],
    expiresAt: Date.now() + 60_000,
    timeout: 60_000,
  };
  const clientDataJSON = buildClientDataJSON({ type: 'webauthn.create', challengeB64u: options.challenge, origin: ORIGIN });
  const made = await authn.makeCredential({
    rpId: RP_ID,
    userHandle: b64uDecode(options.user.id),
    userName: 'bob',
    clientDataHash: await crypto.sha256(clientDataJSON),
    excludeCredentialIds: [],
    residentKey: 'preferred',
    userVerification: 'preferred',
    attestation,
  });
  const record: CeremonyRecord = {
    version: 1,
    kind: 'registration',
    ceremonyId: 'c1',
    startedAt: new Date().toISOString(),
    finishedAt: new Date().toISOString(),
    origin: ORIGIN,
    rpId: RP_ID,
    userVerification: 'preferred',
    residentKey: 'preferred',
    attestation,
    options,
    clientDataJSON: b64uEncode(clientDataJSON),
    credentialPublicKey: { kty: 'EC2', alg: -7, crv: 'P-256', ...made.publicKey },
    attestationObject: b64uEncode(made.attestationObject),
    serverResult: { status: 'completed', checks: [] },
    steps: [],
  };
  return { record, crypto };
}

describe('仪式记录导出 / 重新导入检查', () => {
  it('fmt=none 注册记录通过离线复检', async () => {
    const { record, crypto } = await makeRegistrationRecord('none');
    const result = await verifyExportedRecord(record, crypto);
    expect(result.valid).toBe(true);
  });

  it('fmt=direct（packed 自证明）注册记录通过离线复检', async () => {
    const { record, crypto } = await makeRegistrationRecord('direct');
    const result = await verifyExportedRecord(record, crypto);
    expect(result.valid).toBe(true);
    expect(result.checks.find((c) => c.check === 'attestation.signature')?.ok).toBe(true);
  });

  it('challenge 被篡改 → 复检失败', async () => {
    const { record, crypto } = await makeRegistrationRecord('none');
    record.options = { ...record.options, challenge: b64uEncode(new Uint8Array(32).fill(9)) };
    const result = await verifyExportedRecord(record, crypto);
    expect(result.valid).toBe(false);
    expect(result.checks.at(-1)?.check).toBe('clientData.challenge');
  });

  it('非规范 base64url（带填充）→ 复检失败', async () => {
    const { record, crypto } = await makeRegistrationRecord('none');
    record.clientDataJSON = record.clientDataJSON + '=';
    const result = await verifyExportedRecord(record, crypto);
    expect(result.valid).toBe(false);
    expect(result.checks.at(-1)?.check).toBe('record.base64url');
  });

  it('记录中混入私钥材料 → 复检失败', async () => {
    const { record, crypto } = await makeRegistrationRecord('none');
    record.steps.push({
      name: 'leak',
      at: new Date().toISOString(),
      actor: 'authenticator',
      output: { privateKey: 'should-not-be-here' },
    });
    const result = await verifyExportedRecord(record, crypto);
    expect(result.valid).toBe(false);
    expect(result.checks.at(-1)?.check).toBe('record.noPrivateKey');
  });

  it('签名被篡改 → 复检失败', async () => {
    const { record, crypto } = await makeRegistrationRecord('direct');
    const obj = b64uDecode(record.attestationObject!);
    obj[obj.length - 40] = obj[obj.length - 40]! ^ 0xff; // 翻转签名区域一个字节
    record.attestationObject = b64uEncode(obj);
    const result = await verifyExportedRecord(record, crypto);
    expect(result.valid).toBe(false);
  });
});
