import { describe, expect, it } from 'vitest';
import {
  buildAuthData,
  buildClientDataJSON,
  b64uDecode,
  b64uEncode,
  createNodeCrypto,
  parseAuthData,
  SoftwareAuthenticator,
  verifyAuthentication,
  verifyRegistration,
  type AuthenticationOptionsDTO,
  type CryptoProvider,
  type RegistrationOptionsDTO,
} from '../src/index.js';

const ORIGINS = ['https://app.example.com'];
const RP_ID = 'app.example.com';

async function setup() {
  const crypto = await createNodeCrypto();
  const events: Array<[string, Record<string, unknown>]> = [];
  const authenticator = new SoftwareAuthenticator(crypto, {
    clock: () => 1_700_000_000_000, // 注入固定时钟
    onEvent: (name, detail) => events.push([name, detail]),
  });
  return { crypto, authenticator, events };
}

function regOptions(challenge: string, over: Partial<RegistrationOptionsDTO> = {}): RegistrationOptionsDTO {
  return {
    ceremonyId: 'c1',
    rp: { id: RP_ID, name: 'Example' },
    user: { id: b64uEncode(new Uint8Array(16).fill(7)), name: 'alice', displayName: 'Alice' },
    challenge,
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
    attestation: 'none',
    excludeCredentials: [],
    expiresAt: Date.now() + 60_000,
    timeout: 60_000,
    ...over,
  };
}

async function runMakeCredential(
  crypto: CryptoProvider,
  authenticator: SoftwareAuthenticator,
  options: RegistrationOptionsDTO,
  origin = ORIGINS[0]!,
) {
  const clientDataJSON = buildClientDataJSON({ type: 'webauthn.create', challengeB64u: options.challenge, origin });
  const clientDataHash = await crypto.sha256(clientDataJSON);
  const result = await authenticator.makeCredential({
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
    response: {
      ceremonyId: options.ceremonyId,
      credentialId: result.credentialId,
      clientDataJSON: b64uEncode(clientDataJSON),
      attestationObject: b64uEncode(result.attestationObject),
    },
    result,
  };
}

describe('注册仪式（attestation）', () => {
  it('fmt=none 全流程通过，检查链完整', async () => {
    const { crypto, authenticator } = await setup();
    const options = regOptions(b64uEncode(crypto.randomBytes(32)));
    const { response } = await runMakeCredential(crypto, authenticator, options);
    const verified = await verifyRegistration({
      options,
      response,
      expectedOrigins: ORIGINS,
      crypto,
      credentialIdExists: () => false,
    });
    expect(verified.ok).toBe(true);
    if (verified.ok) {
      expect(verified.fmt).toBe('none');
      expect(verified.checks.map((c) => c.check)).toEqual(
        expect.arrayContaining(['clientData.origin', 'authData.rpIdHash', 'authData.flags.UP', 'credentialId.unique']),
      );
    }
  });

  it('attestation=direct 走 packed 自证明并验签', async () => {
    const { crypto, authenticator } = await setup();
    const options = regOptions(b64uEncode(crypto.randomBytes(32)), { attestation: 'direct' });
    const { response } = await runMakeCredential(crypto, authenticator, options);
    const verified = await verifyRegistration({
      options,
      response,
      expectedOrigins: ORIGINS,
      crypto,
      credentialIdExists: () => false,
    });
    expect(verified.ok).toBe(true);
    if (verified.ok) expect(verified.fmt).toBe('packed');
  });

  it('错误 origin → origin_mismatch', async () => {
    const { crypto, authenticator } = await setup();
    const options = regOptions(b64uEncode(crypto.randomBytes(32)));
    const { response } = await runMakeCredential(crypto, authenticator, options, 'https://evil.example.com');
    const verified = await verifyRegistration({
      options,
      response,
      expectedOrigins: ORIGINS,
      crypto,
      credentialIdExists: () => false,
    });
    expect(verified.ok).toBe(false);
    if (!verified.ok) expect(verified.code).toBe('origin_mismatch');
  });

  it('UV required 但用户拒绝验证 → uv_required', async () => {
    const { crypto, authenticator } = await setup();
    authenticator.uvResult = false;
    const options = regOptions(b64uEncode(crypto.randomBytes(32)));
    options.authenticatorSelection.userVerification = 'required';
    const { response } = await runMakeCredential(crypto, authenticator, options);
    const verified = await verifyRegistration({
      options,
      response,
      expectedOrigins: ORIGINS,
      crypto,
      credentialIdExists: () => false,
    });
    expect(verified.ok).toBe(false);
    if (!verified.ok) expect(verified.code).toBe('uv_required');
  });

  it('重复 credential id → duplicate_credential', async () => {
    const { crypto, authenticator } = await setup();
    const options = regOptions(b64uEncode(crypto.randomBytes(32)));
    const { response } = await runMakeCredential(crypto, authenticator, options);
    const verified = await verifyRegistration({
      options,
      response,
      expectedOrigins: ORIGINS,
      crypto,
      credentialIdExists: () => true,
    });
    expect(verified.ok).toBe(false);
    if (!verified.ok) expect(verified.code).toBe('duplicate_credential');
  });

  it('excludeCredentials 命中 → authenticator 抛 NotAllowedError', async () => {
    const { crypto, authenticator } = await setup();
    const options = regOptions(b64uEncode(crypto.randomBytes(32)));
    const { result } = await runMakeCredential(crypto, authenticator, options);
    const options2 = regOptions(b64uEncode(crypto.randomBytes(32)), {
      excludeCredentials: [{ type: 'public-key', id: result.credentialId }],
    });
    await expect(runMakeCredential(crypto, authenticator, options2)).rejects.toMatchObject({
      code: 'NotAllowedError',
    });
  });
});

describe('认证仪式（assertion）', () => {
  async function registerOne(crypto: CryptoProvider, authenticator: SoftwareAuthenticator, residentKey: 'required' | 'discouraged' = 'required') {
    const options = regOptions(b64uEncode(crypto.randomBytes(32)));
    options.authenticatorSelection.residentKey = residentKey;
    const { response, result } = await runMakeCredential(crypto, authenticator, options);
    const verified = await verifyRegistration({
      options,
      response,
      expectedOrigins: ORIGINS,
      crypto,
      credentialIdExists: () => false,
    });
    if (!verified.ok) throw new Error('registration failed');
    return { credentialId: result.credentialId, publicKey: verified.publicKey, counter: verified.counter };
  }

  function authOptions(challenge: string, allow: string[] | undefined, over: Partial<AuthenticationOptionsDTO> = {}): AuthenticationOptionsDTO {
    return {
      ceremonyId: 'c2',
      rpId: RP_ID,
      challenge,
      allowCredentials: allow?.map((id) => ({ type: 'public-key' as const, id })) ?? [],
      userVerification: 'preferred',
      expiresAt: Date.now() + 60_000,
      timeout: 60_000,
      ...over,
    };
  }

  async function runGetAssertion(
    crypto: CryptoProvider,
    authenticator: SoftwareAuthenticator,
    options: AuthenticationOptionsDTO,
    origin = ORIGINS[0]!,
  ) {
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

  it('完整认证流程 + 计数器递增', async () => {
    const { crypto, authenticator } = await setup();
    const cred = await registerOne(crypto, authenticator);
    let storedCounter = cred.counter;
    for (let i = 0; i < 3; i++) {
      const options = authOptions(b64uEncode(crypto.randomBytes(32)), [cred.credentialId]);
      const response = await runGetAssertion(crypto, authenticator, options);
      const verified = await verifyAuthentication({
        options,
        response,
        expectedOrigins: ORIGINS,
        crypto,
        credential: {
          credentialId: cred.credentialId,
          publicKey: cred.publicKey,
          counter: storedCounter,
          userHandle: b64uEncode(new Uint8Array(16).fill(7)),
          rpId: RP_ID,
        },
      });
      expect(verified.ok).toBe(true);
      if (verified.ok) {
        expect(verified.cloneWarning).toBe(false);
        expect(verified.counter).toBe(storedCounter + 1);
        storedCounter = verified.counter;
      }
    }
  });

  it('计数器回退 → cloneWarning（克隆告警）', async () => {
    const { crypto, authenticator } = await setup();
    const cred = await registerOne(crypto, authenticator);
    const options1 = authOptions(b64uEncode(crypto.randomBytes(32)), [cred.credentialId]);
    const r1 = await runGetAssertion(crypto, authenticator, options1);
    const v1 = await verifyAuthentication({
      options: options1,
      response: r1,
      expectedOrigins: ORIGINS,
      crypto,
      credential: { credentialId: cred.credentialId, publicKey: cred.publicKey, counter: cred.counter, userHandle: b64uEncode(new Uint8Array(16).fill(7)), rpId: RP_ID },
    });
    expect(v1.ok && !v1.cloneWarning).toBe(true);

    // 模拟克隆：计数器回退到 0
    authenticator.debugSetCounter(cred.credentialId, 0);
    const options2 = authOptions(b64uEncode(crypto.randomBytes(32)), [cred.credentialId]);
    const r2 = await runGetAssertion(crypto, authenticator, options2);
    const v2 = await verifyAuthentication({
      options: options2,
      response: r2,
      expectedOrigins: ORIGINS,
      crypto,
      credential: { credentialId: cred.credentialId, publicKey: cred.publicKey, counter: v1.ok ? v1.counter : 0, userHandle: b64uEncode(new Uint8Array(16).fill(7)), rpId: RP_ID },
    });
    expect(v2.ok).toBe(true);
    if (v2.ok) {
      expect(v2.cloneWarning).toBe(true);
      const counterCheck = v2.checks.find((c) => c.check === 'counter.monotonic');
      expect(counterCheck?.ok).toBe(false);
    }
  });

  it('篡改签名 → bad_signature', async () => {
    const { crypto, authenticator } = await setup();
    const cred = await registerOne(crypto, authenticator);
    const options = authOptions(b64uEncode(crypto.randomBytes(32)), [cred.credentialId]);
    const response = await runGetAssertion(crypto, authenticator, options);
    const sig = b64uDecode(response.signature);
    sig[10] = sig[10]! ^ 0xff;
    response.signature = b64uEncode(sig);
    const verified = await verifyAuthentication({
      options,
      response,
      expectedOrigins: ORIGINS,
      crypto,
      credential: { credentialId: cred.credentialId, publicKey: cred.publicKey, counter: cred.counter, userHandle: b64uEncode(new Uint8Array(16).fill(7)), rpId: RP_ID },
    });
    expect(verified.ok).toBe(false);
    if (!verified.ok) expect(verified.code).toBe('bad_signature');
  });

  it('resident key：无 allowCredentials 可发现；非 resident 则拒绝', async () => {
    const { crypto, authenticator } = await setup();
    const cred = await registerOne(crypto, authenticator, 'required');
    const options = authOptions(b64uEncode(crypto.randomBytes(32)), undefined); // discoverable
    const response = await runGetAssertion(crypto, authenticator, options);
    expect(response.credentialId).toBe(cred.credentialId);

    const { crypto: crypto2, authenticator: auth2 } = await setup();
    const nonResident = await registerOne(crypto2, auth2, 'discouraged');
    expect(nonResident.credentialId).toBeTruthy();
    const options2 = authOptions(b64uEncode(crypto2.randomBytes(32)), undefined);
    await expect(runGetAssertion(crypto2, auth2, options2)).rejects.toMatchObject({ code: 'NotAllowedError' });
  });

  it('authData 构建/解析往返', async () => {
    const crypto = await createNodeCrypto();
    const rpIdHash = await crypto.sha256(new TextEncoder().encode(RP_ID));
    const authData = buildAuthData({
      rpIdHash,
      userPresent: true,
      userVerified: true,
      signCount: 0x01020304,
      attestedCredential: {
        aaguid: new Uint8Array(16).fill(1),
        credentialId: new Uint8Array([9, 8, 7]),
        publicKey: { x: b64uEncode(new Uint8Array(32).fill(2)), y: b64uEncode(new Uint8Array(32).fill(3)) },
      },
    });
    const parsed = parseAuthData(authData);
    expect(parsed.userPresent).toBe(true);
    expect(parsed.userVerified).toBe(true);
    expect(parsed.signCount).toBe(0x01020304);
    expect(parsed.attestedCredential?.credentialId).toEqual(new Uint8Array([9, 8, 7]));
    expect(parsed.attestedCredential?.publicKey.x).toBe(b64uEncode(new Uint8Array(32).fill(2)));
  });
});
