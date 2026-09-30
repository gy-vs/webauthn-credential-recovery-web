/**
 * 仪式记录（CeremonyRecord）的导入校验：
 * 不依赖服务端状态，对记录本身重放全部可离线验证的检查——
 * base64url 规范性、challenge 绑定、rpIdHash、签名（用记录中的公钥）。
 */
import { parseAuthData } from './authdata.js';
import { b64uDecode, bytesEqual, concatBytes, isCanonicalB64u, utf8Decode } from './base64url.js';
import { cborDecode } from './cbor.js';
import type { CryptoProvider } from './crypto-provider.js';
import type { CeremonyRecord, CheckResult } from './types.js';

function b64uFields(r: CeremonyRecord): Array<[string, string | null | undefined]> {
  return [
    ['options.challenge', r.options.challenge],
    ['clientDataJSON', r.clientDataJSON],
    ['attestationObject', r.attestationObject],
    ['authenticatorData', r.authenticatorData],
    ['signature', r.signature],
    ['userHandle', r.userHandle],
    ['credentialPublicKey.x', r.credentialPublicKey?.x],
    ['credentialPublicKey.y', r.credentialPublicKey?.y],
  ];
}

export async function verifyExportedRecord(
  record: CeremonyRecord,
  crypto: CryptoProvider,
): Promise<{ valid: boolean; checks: CheckResult[] }> {
  const checks: CheckResult[] = [];
  const fail = (check: string, detail: string) => {
    checks.push({ check, ok: false, detail });
    return { valid: false, checks };
  };

  if (record.version !== 1) return fail('record.version', `不支持的版本 ${String(record.version)}`);
  if (record.kind !== 'registration' && record.kind !== 'authentication') {
    return fail('record.kind', `未知仪式类型 ${String(record.kind)}`);
  }
  checks.push({ check: 'record.shape', ok: true, detail: `${record.kind} / v${record.version}` });

  for (const [name, value] of b64uFields(record)) {
    if (value === undefined || value === null) continue;
    if (!isCanonicalB64u(value)) {
      return fail('record.base64url', `字段 ${name} 不是规范 base64url（无填充）编码`);
    }
  }
  checks.push({ check: 'record.base64url', ok: true, detail: '所有二进制字段均为规范 base64url（无填充）' });

  for (const step of record.steps ?? []) {
    const s = JSON.stringify(step);
    if (/privateKey|d":\s*"/.test(s)) {
      return fail('record.noPrivateKey', `步骤 "${step.name}" 疑似包含私钥材料`);
    }
  }
  checks.push({ check: 'record.noPrivateKey', ok: true, detail: '未发现私钥材料' });

  let clientData: { type?: string; challenge?: string; origin?: string };
  try {
    clientData = JSON.parse(utf8Decode(b64uDecode(record.clientDataJSON)));
  } catch {
    return fail('clientData.parse', 'clientDataJSON 无法解析');
  }
  if (clientData.challenge !== record.options.challenge) {
    return fail('clientData.challenge', 'clientDataJSON 中的 challenge 与 options 不一致');
  }
  checks.push({ check: 'clientData.challenge', ok: true, detail: '与 options.challenge 绑定一致' });
  if (clientData.origin !== record.origin) {
    return fail('clientData.origin', `记录 origin=${record.origin}，clientData origin=${clientData.origin}`);
  }
  checks.push({ check: 'clientData.origin', ok: true, detail: clientData.origin! });

  const clientDataHash = await crypto.sha256(b64uDecode(record.clientDataJSON));

  if (record.kind === 'registration') {
    if (!record.attestationObject) return fail('record.attestationObject', '注册记录缺少 attestationObject');
    let attestation: Map<unknown, unknown>;
    try {
      const decoded = cborDecode(b64uDecode(record.attestationObject));
      if (!(decoded instanceof Map)) throw new Error('not a map');
      attestation = decoded as Map<unknown, unknown>;
    } catch {
      return fail('attestationObject.parse', 'attestationObject 不是合法 CBOR');
    }
    const authDataBytes = attestation.get('authData');
    if (!(authDataBytes instanceof Uint8Array)) return fail('attestationObject.authData', '缺少 authData');
    const authData = parseAuthData(authDataBytes);
    const expectedRpHash = await crypto.sha256(new TextEncoder().encode(record.rpId));
    if (!bytesEqual(authData.rpIdHash, expectedRpHash)) {
      return fail('authData.rpIdHash', `与 rpId "${record.rpId}" 的 SHA-256 不匹配`);
    }
    checks.push({ check: 'authData.rpIdHash', ok: true, detail: `SHA-256(${record.rpId})` });
    if (!authData.attestedCredential) return fail('authData.AT', '缺少 attestedCredentialData');
    if (record.credentialPublicKey) {
      const { x, y } = authData.attestedCredential.publicKey;
      if (x !== record.credentialPublicKey.x || y !== record.credentialPublicKey.y) {
        return fail('credentialPublicKey.match', '记录中的公钥与 attestedCredentialData 不一致');
      }
      checks.push({ check: 'credentialPublicKey.match', ok: true });
    }
    const fmt = attestation.get('fmt');
    if (fmt === 'packed') {
      const attStmt = attestation.get('attStmt');
      if (!(attStmt instanceof Map)) return fail('attestation.attStmt', 'packed 缺少 attStmt');
      const sig = attStmt.get('sig');
      if (!(sig instanceof Uint8Array)) return fail('attestation.attStmt', '缺少 sig');
      const ok = await crypto.verify(
        authData.attestedCredential.publicKey,
        sig,
        concatBytes(authDataBytes, clientDataHash),
      );
      if (!ok) return fail('attestation.signature', 'packed 自证明签名重放验证失败');
      checks.push({ check: 'attestation.signature', ok: true, detail: 'packed 自证明签名有效' });
    } else {
      checks.push({ check: 'attestation.signature', ok: true, detail: `fmt=${String(fmt)}，无证明签名可验` });
    }
  } else {
    if (!record.authenticatorData || !record.signature || !record.credentialPublicKey) {
      return fail('record.fields', '认证记录缺少 authenticatorData / signature / credentialPublicKey');
    }
    const authData = parseAuthData(b64uDecode(record.authenticatorData));
    const expectedRpHash = await crypto.sha256(new TextEncoder().encode(record.rpId));
    if (!bytesEqual(authData.rpIdHash, expectedRpHash)) {
      return fail('authData.rpIdHash', `与 rpId "${record.rpId}" 的 SHA-256 不匹配`);
    }
    checks.push({ check: 'authData.rpIdHash', ok: true, detail: `SHA-256(${record.rpId})` });
    const ok = await crypto.verify(
      { x: record.credentialPublicKey.x, y: record.credentialPublicKey.y },
      b64uDecode(record.signature),
      concatBytes(b64uDecode(record.authenticatorData), clientDataHash),
    );
    if (!ok) return fail('assertion.signature', '断言签名重放验证失败');
    checks.push({ check: 'assertion.signature', ok: true, detail: 'ES256 签名有效' });
  }

  return { valid: true, checks };
}
