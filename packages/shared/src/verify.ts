/**
 * 服务端仪式校验：纯函数，输入已落库的 options 与客户端响应，
 * 输出带完整检查链（checks）的可解释结果。challenge 的一次性消费
 * 与过期判定在 store 层完成，这里只负责密码学与绑定校验。
 */
import { parseAuthData } from './authdata.js';
import { b64uDecode, b64uEncode, bytesEqual, concatBytes, utf8Decode } from './base64url.js';
import { cborDecode } from './cbor.js';
import type { CryptoProvider, EcPublicKey } from './crypto-provider.js';
import type {
  AssertionResponseDTO,
  AttestationResponseDTO,
  AuthenticationOptionsDTO,
  CheckResult,
  FailureCode,
  RegistrationOptionsDTO,
} from './types.js';

export interface VerifiedRegistration {
  ok: true;
  checks: CheckResult[];
  credentialId: string;
  publicKey: EcPublicKey;
  counter: number;
  userVerified: boolean;
  fmt: string;
}

export interface VerifiedAuthentication {
  ok: true;
  checks: CheckResult[];
  credentialId: string;
  counter: number;
  cloneWarning: boolean;
  userVerified: boolean;
}

export interface VerificationFailure {
  ok: false;
  code: FailureCode;
  message: string;
  checks: CheckResult[];
}

export type RegistrationVerification = VerifiedRegistration | VerificationFailure;
export type AuthenticationVerification = VerifiedAuthentication | VerificationFailure;

export interface StoredCredentialRecord {
  credentialId: string;
  publicKey: EcPublicKey;
  counter: number;
  userHandle: string;
  rpId: string;
}

interface ClientData {
  type: string;
  challenge: string;
  origin: string;
  crossOrigin?: boolean;
}

function failure(code: FailureCode, message: string, checks: CheckResult[]): VerificationFailure {
  return { ok: false, code, message, checks };
}

async function parseClientData(
  clientDataJSONB64: string,
  expectedType: 'webauthn.create' | 'webauthn.get',
  expectedChallenge: string,
  expectedOrigins: string[],
  checks: CheckResult[],
): Promise<ClientData | { code: FailureCode; message: string }> {
  let clientData: ClientData;
  try {
    clientData = JSON.parse(utf8Decode(b64uDecode(clientDataJSONB64))) as ClientData;
  } catch {
    return { code: 'bad_format', message: 'clientDataJSON 不是合法 JSON' };
  }
  if (clientData.type !== expectedType) {
    return { code: 'type_mismatch', message: `clientData.type=${clientData.type}，期望 ${expectedType}` };
  }
  checks.push({ check: 'clientData.type', ok: true, detail: clientData.type });
  if (clientData.challenge !== expectedChallenge) {
    return { code: 'challenge_mismatch', message: 'clientData.challenge 与服务端签发的不一致' };
  }
  checks.push({ check: 'clientData.challenge', ok: true, detail: '与签发 challenge 一致' });
  if (!expectedOrigins.includes(clientData.origin)) {
    return {
      code: 'origin_mismatch',
      message: `origin "${clientData.origin}" 不在服务端允许列表 [${expectedOrigins.join(', ')}]`,
    };
  }
  checks.push({ check: 'clientData.origin', ok: true, detail: clientData.origin });
  return clientData;
}

async function checkAuthDataCommon(
  authData: ReturnType<typeof parseAuthData>,
  rpId: string,
  userVerification: string,
  crypto: CryptoProvider,
  checks: CheckResult[],
): Promise<{ code: FailureCode; message: string } | null> {
  const expectedRpHash = await crypto.sha256(new TextEncoder().encode(rpId));
  if (!bytesEqual(authData.rpIdHash, expectedRpHash)) {
    return { code: 'rp_id_mismatch', message: `authData.rpIdHash 与 RP ID "${rpId}" 的 SHA-256 不匹配` };
  }
  checks.push({ check: 'authData.rpIdHash', ok: true, detail: `SHA-256(${rpId})` });
  if (!authData.userPresent) {
    return { code: 'up_flag_missing', message: 'UP（user present）标志位未设置' };
  }
  checks.push({ check: 'authData.flags.UP', ok: true });
  if (userVerification === 'required' && !authData.userVerified) {
    return { code: 'uv_required', message: '服务端要求 UV，但 authData 中 UV 标志位未设置' };
  }
  checks.push({
    check: 'authData.flags.UV',
    ok: true,
    detail: authData.userVerified ? 'UV 已设置' : `UV 未设置（策略 ${userVerification}，允许）`,
  });
  return null;
}

export async function verifyRegistration(params: {
  options: RegistrationOptionsDTO;
  response: AttestationResponseDTO;
  expectedOrigins: string[];
  crypto: CryptoProvider;
  credentialIdExists: (id: string) => boolean;
}): Promise<RegistrationVerification> {
  const { options, response, expectedOrigins, crypto } = params;
  const checks: CheckResult[] = [];

  const clientData = await parseClientData(response.clientDataJSON, 'webauthn.create', options.challenge, expectedOrigins, checks);
  if ('code' in clientData) return failure(clientData.code, clientData.message, checks);

  let attestation: Map<unknown, unknown>;
  try {
    const decoded = cborDecode(b64uDecode(response.attestationObject));
    if (!(decoded instanceof Map)) throw new Error('not a map');
    attestation = decoded as Map<unknown, unknown>;
  } catch {
    return failure('bad_format', 'attestationObject 不是合法 CBOR 映射', checks);
  }
  const fmt = attestation.get('fmt');
  const attStmt = attestation.get('attStmt');
  const authDataBytes = attestation.get('authData');
  if (typeof fmt !== 'string' || !(authDataBytes instanceof Uint8Array)) {
    return failure('bad_format', 'attestationObject 缺少 fmt/authData', checks);
  }

  let authData;
  try {
    authData = parseAuthData(authDataBytes);
  } catch (e) {
    return failure('bad_format', `authenticatorData 解析失败：${(e as Error).message}`, checks);
  }

  const common = await checkAuthDataCommon(authData, options.rp.id, options.authenticatorSelection.userVerification, crypto, checks);
  if (common) return failure(common.code, common.message, checks);

  if (!authData.hasAttestedCredential || !authData.attestedCredential) {
    return failure('bad_format', '注册响应缺少 attestedCredentialData（AT 标志位未设置）', checks);
  }
  checks.push({ check: 'authData.AT', ok: true, detail: '包含 attestedCredentialData' });

  const attestedId = b64uEncode(authData.attestedCredential.credentialId);
  if (attestedId !== response.credentialId) {
    return failure('bad_format', '响应 credentialId 与 attestedCredentialData 中的不一致', checks);
  }

  const clientDataHash = await crypto.sha256(b64uDecode(response.clientDataJSON));
  if (fmt === 'none') {
    if (attStmt instanceof Map && attStmt.size > 0) {
      return failure('attestation_verification_failed', 'fmt=none 但 attStmt 非空', checks);
    }
    checks.push({ check: 'attestation.fmt', ok: true, detail: 'none（无证明签名，按策略接受）' });
  } else if (fmt === 'packed') {
    if (!(attStmt instanceof Map)) return failure('bad_format', 'packed attestation 缺少 attStmt', checks);
    const alg = attStmt.get('alg');
    const sig = attStmt.get('sig');
    if (alg !== -7 || !(sig instanceof Uint8Array)) {
      return failure('attestation_verification_failed', 'packed attStmt 需要 alg=-7 且含 sig（当前仅支持 ES256 自证明）', checks);
    }
    const valid = await crypto.verify(
      authData.attestedCredential.publicKey,
      sig,
      concatBytes(authDataBytes, clientDataHash),
    );
    if (!valid) {
      return failure('attestation_verification_failed', 'packed 自证明签名验证失败', checks);
    }
    checks.push({ check: 'attestation.fmt', ok: true, detail: 'packed 自证明签名有效（ES256）' });
  } else {
    return failure('attestation_verification_failed', `不支持的 attestation fmt: ${fmt}`, checks);
  }

  if (params.credentialIdExists(response.credentialId)) {
    return failure(
      'duplicate_credential',
      `credential id ${response.credentialId} 已注册（对应 excludeCredentials / 重复注册场景）`,
      checks,
    );
  }
  checks.push({ check: 'credentialId.unique', ok: true, detail: '未与既有凭据冲突' });

  return {
    ok: true,
    checks,
    credentialId: response.credentialId,
    publicKey: authData.attestedCredential.publicKey,
    counter: authData.signCount,
    userVerified: authData.userVerified,
    fmt,
  };
}

export async function verifyAuthentication(params: {
  options: AuthenticationOptionsDTO;
  response: AssertionResponseDTO;
  expectedOrigins: string[];
  crypto: CryptoProvider;
  credential: StoredCredentialRecord | undefined;
}): Promise<AuthenticationVerification> {
  const { options, response, expectedOrigins, crypto, credential } = params;
  const checks: CheckResult[] = [];

  const clientData = await parseClientData(response.clientDataJSON, 'webauthn.get', options.challenge, expectedOrigins, checks);
  if ('code' in clientData) return failure(clientData.code, clientData.message, checks);

  if (!credential) {
    return failure('unknown_credential', `credential id ${response.credentialId} 未注册`, checks);
  }
  checks.push({ check: 'credential.known', ok: true, detail: `属于 RP ${credential.rpId}` });

  if (credential.rpId !== options.rpId) {
    return failure('rp_id_mismatch', `凭据属于 ${credential.rpId}，本次认证 rpId=${options.rpId}`, checks);
  }

  if (response.userHandle && response.userHandle !== credential.userHandle) {
    return failure('user_handle_mismatch', '断言 userHandle 与注册时不一致', checks);
  }
  checks.push({ check: 'assertion.userHandle', ok: true, detail: response.userHandle ?? '(空)' });

  let authData;
  try {
    authData = parseAuthData(b64uDecode(response.authenticatorData));
  } catch (e) {
    return failure('bad_format', `authenticatorData 解析失败：${(e as Error).message}`, checks);
  }

  const common = await checkAuthDataCommon(authData, options.rpId, options.userVerification, crypto, checks);
  if (common) return failure(common.code, common.message, checks);

  const clientDataHash = await crypto.sha256(b64uDecode(response.clientDataJSON));
  const sigBase = concatBytes(b64uDecode(response.authenticatorData), clientDataHash);
  const valid = await crypto.verify(credential.publicKey, b64uDecode(response.signature), sigBase);
  if (!valid) {
    return failure('bad_signature', '断言签名验证失败（authData ‖ clientDataHash，ES256）', checks);
  }
  checks.push({ check: 'assertion.signature', ok: true, detail: 'ES256 签名有效' });

  // 计数器：双方都为 0 表示 authenticator 不支持计数器；否则必须严格递增
  let cloneWarning = false;
  if (!(credential.counter === 0 && authData.signCount === 0)) {
    if (authData.signCount <= credential.counter) {
      cloneWarning = true;
      checks.push({
        check: 'counter.monotonic',
        ok: false,
        detail: `计数器回退：服务端记录 ${credential.counter}，本次 ${authData.signCount} → 疑似克隆 authenticator`,
      });
    } else {
      checks.push({
        check: 'counter.monotonic',
        ok: true,
        detail: `${credential.counter} → ${authData.signCount}`,
      });
    }
  } else {
    checks.push({ check: 'counter.monotonic', ok: true, detail: '双方计数器均为 0（未启用）' });
  }

  return {
    ok: true,
    checks,
    credentialId: response.credentialId,
    counter: authData.signCount,
    cloneWarning,
    userVerified: authData.userVerified,
  };
}
