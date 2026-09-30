/**
 * 客户端（RP 页面模拟器）辅助：构造 clientDataJSON、把 authenticator
 * 输出装配成提交给服务端的 DTO。origin 由调用方指定——
 * 工作台借此重放"错误 origin"等客户端行为。
 */
import { b64uEncode, utf8Encode } from './base64url.js';
import type { CryptoProvider } from './crypto-provider.js';

export interface ClientDataInput {
  type: 'webauthn.create' | 'webauthn.get';
  challengeB64u: string;
  origin: string;
  crossOrigin?: boolean;
}

export function buildClientDataJSON(input: ClientDataInput): Uint8Array {
  return utf8Encode(
    JSON.stringify({
      type: input.type,
      challenge: input.challengeB64u,
      origin: input.origin,
      crossOrigin: input.crossOrigin ?? false,
    }),
  );
}

export async function hashClientData(
  crypto: CryptoProvider,
  clientDataJSON: Uint8Array,
): Promise<Uint8Array> {
  return crypto.sha256(clientDataJSON);
}

export function clientDataToB64u(clientDataJSON: Uint8Array): string {
  return b64uEncode(clientDataJSON);
}
