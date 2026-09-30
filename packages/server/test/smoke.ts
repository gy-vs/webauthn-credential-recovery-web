/** 对运行中的服务端做一次完整注册+认证冒烟测试 */
import {
  buildClientDataJSON,
  b64uDecode,
  b64uEncode,
  createNodeCrypto,
  SoftwareAuthenticator,
} from '@lab/shared';

const BASE = 'http://localhost:8787';
const ORIGIN = 'http://localhost:5173';

async function post(path: string, body: unknown) {
  const res = await fetch(BASE + path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, data: (await res.json()) as Record<string, unknown> };
}

const crypto = await createNodeCrypto();
const authn = new SoftwareAuthenticator(crypto, {});

// 注册
const regOptions = (await post('/api/register/options', { userName: 'smoke', attestation: 'direct' })).data as never as {
  ceremonyId: string; challenge: string; rp: { id: string }; user: { id: string; name: string };
  authenticatorSelection: { residentKey: 'preferred'; userVerification: 'preferred' }; attestation: 'direct';
  excludeCredentials: [];
};
const cdj = buildClientDataJSON({ type: 'webauthn.create', challengeB64u: regOptions.challenge, origin: ORIGIN });
const made = await authn.makeCredential({
  rpId: regOptions.rp.id,
  userHandle: b64uDecode(regOptions.user.id),
  userName: regOptions.user.name,
  clientDataHash: await crypto.sha256(cdj),
  excludeCredentialIds: [],
  residentKey: 'preferred',
  userVerification: 'preferred',
  attestation: 'direct',
});
const regRes = await post('/api/register/result', {
  ceremonyId: regOptions.ceremonyId,
  credentialId: made.credentialId,
  clientDataJSON: b64uEncode(cdj),
  attestationObject: b64uEncode(made.attestationObject),
});
console.log('register:', regRes.status, regRes.data.ok, 'fmt =', regRes.data.fmt);

// 认证
const authOptions = (await post('/api/authenticate/options', { userName: 'smoke' })).data as never as {
  ceremonyId: string; challenge: string; rpId: string; allowCredentials: Array<{ id: string }>; userVerification: 'preferred';
};
const cdj2 = buildClientDataJSON({ type: 'webauthn.get', challengeB64u: authOptions.challenge, origin: ORIGIN });
const assertion = await authn.getAssertion({
  rpId: authOptions.rpId,
  allowCredentialIds: authOptions.allowCredentials.map((c) => c.id),
  clientDataHash: await crypto.sha256(cdj2),
  userVerification: 'preferred',
});
const authRes = await post('/api/authenticate/result', {
  ceremonyId: authOptions.ceremonyId,
  credentialId: assertion.credentialId,
  clientDataJSON: b64uEncode(cdj2),
  authenticatorData: b64uEncode(assertion.authenticatorData),
  signature: b64uEncode(assertion.signature),
  userHandle: b64uEncode(assertion.userHandle),
});
console.log('authenticate:', authRes.status, authRes.data.ok, 'cloneWarning =', authRes.data.cloneWarning);

// 重放同一 challenge → 应被拒绝
const replay = await post('/api/authenticate/result', {
  ceremonyId: authOptions.ceremonyId,
  credentialId: assertion.credentialId,
  clientDataJSON: b64uEncode(cdj2),
  authenticatorData: b64uEncode(assertion.authenticatorData),
  signature: b64uEncode(assertion.signature),
  userHandle: b64uEncode(assertion.userHandle),
});
console.log('replay:', replay.status, replay.data.code);

if (regRes.data.ok !== true || authRes.data.ok !== true || replay.data.code !== 'challenge_consumed') {
  console.error('SMOKE FAILED');
  process.exit(1);
}
console.log('SMOKE OK');
