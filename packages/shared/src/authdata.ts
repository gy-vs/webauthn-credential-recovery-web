/**
 * authenticatorData 布局：
 *   rpIdHash(32) | flags(1) | signCount(4, BE) | [attestedCredentialData] | [extensions]
 * attestedCredentialData = aaguid(16) | credentialIdLength(2, BE) | credentialId | credentialPublicKey(COSE)
 */
import { b64uEncode } from './base64url.js';
import { cborDecodeFirst, cborEncode } from './cbor.js';
import { publicKeyFromCose, publicKeyToCose, type EcPublicKey } from './crypto-provider.js';

export const FLAG_UP = 0x01;
export const FLAG_UV = 0x04;
export const FLAG_AT = 0x40;
export const FLAG_ED = 0x80;

export interface AuthDataBuild {
  rpIdHash: Uint8Array;
  userPresent: boolean;
  userVerified: boolean;
  signCount: number;
  attestedCredential?: {
    aaguid: Uint8Array;
    credentialId: Uint8Array;
    publicKey: EcPublicKey;
  };
}

export function buildAuthData(input: AuthDataBuild): Uint8Array {
  let flags = 0;
  if (input.userPresent) flags |= FLAG_UP;
  if (input.userVerified) flags |= FLAG_UV;
  if (input.attestedCredential) flags |= FLAG_AT;

  const parts: Uint8Array[] = [
    input.rpIdHash,
    new Uint8Array([flags]),
    new Uint8Array([
      (input.signCount >>> 24) & 0xff,
      (input.signCount >>> 16) & 0xff,
      (input.signCount >>> 8) & 0xff,
      input.signCount & 0xff,
    ]),
  ];

  if (input.attestedCredential) {
    const { aaguid, credentialId, publicKey } = input.attestedCredential;
    if (aaguid.length !== 16) throw new Error('aaguid must be 16 bytes');
    const idLen = new Uint8Array([(credentialId.length >>> 8) & 0xff, credentialId.length & 0xff]);
    const cose = cborEncode(publicKeyToCose(publicKey));
    parts.push(aaguid, idLen, credentialId, cose);
  }

  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

export interface ParsedAuthData {
  rpIdHash: Uint8Array;
  flags: number;
  userPresent: boolean;
  userVerified: boolean;
  hasAttestedCredential: boolean;
  signCount: number;
  attestedCredential?: {
    aaguid: string; // base64url
    credentialId: Uint8Array;
    publicKey: EcPublicKey;
  };
}

export function parseAuthData(bytes: Uint8Array): ParsedAuthData {
  if (bytes.length < 37) throw new Error('authenticatorData too short');
  const rpIdHash = bytes.slice(0, 32);
  const flags = bytes[32]!;
  const signCount =
    ((bytes[33]! << 24) | (bytes[34]! << 16) | (bytes[35]! << 8) | bytes[36]!) >>> 0;

  const parsed: ParsedAuthData = {
    rpIdHash,
    flags,
    userPresent: (flags & FLAG_UP) !== 0,
    userVerified: (flags & FLAG_UV) !== 0,
    hasAttestedCredential: (flags & FLAG_AT) !== 0,
    signCount,
  };

  if (parsed.hasAttestedCredential) {
    if (bytes.length < 37 + 16 + 2) throw new Error('attestedCredentialData truncated');
    const aaguid = bytes.slice(37, 53);
    const idLen = (bytes[53]! << 8) | bytes[54]!;
    const idStart = 55;
    const idEnd = idStart + idLen;
    if (idEnd > bytes.length) throw new Error('credentialId truncated');
    const credentialId = bytes.slice(idStart, idEnd);
    const { value: cose, offset } = cborDecodeFirst(bytes, idEnd);
    if (!(cose instanceof Map)) throw new Error('credentialPublicKey is not a CBOR map');
    parsed.attestedCredential = {
      aaguid: b64uEncode(aaguid),
      credentialId,
      publicKey: publicKeyFromCose(cose as Map<unknown, unknown>),
    };
    if (offset > bytes.length) throw new Error('credentialPublicKey overruns authenticatorData');
  }

  return parsed;
}
