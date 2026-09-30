/**
 * 加密提供者抽象：authenticator 与校验逻辑不直接依赖 WebCrypto / node:crypto，
 * 便于在浏览器与 Node（测试、服务端）中复用同一套仪式代码。
 * ES256 签名一律使用 IEEE P1363 原始格式（r‖s，64 字节）。
 */
import { b64uDecode, b64uEncode } from './base64url.js';

export interface EcPublicKey {
  /** base64url 无填充，32 字节 */
  x: string;
  y: string;
}

export interface KeyPairHandle {
  /** 不透明私钥句柄（CryptoKey 或 node KeyObject），绝不序列化 */
  privateKey: unknown;
  publicKey: EcPublicKey;
}

export interface CryptoProvider {
  generateEcKeyPair(): Promise<KeyPairHandle>;
  sign(privateKey: unknown, data: Uint8Array): Promise<Uint8Array>;
  verify(publicKey: EcPublicKey, signature: Uint8Array, data: Uint8Array): Promise<boolean>;
  sha256(data: Uint8Array): Promise<Uint8Array>;
  randomBytes(length: number): Uint8Array;
}

/** Node 实现（node:crypto），供服务端与测试使用；浏览器中不会被调用 */
export async function createNodeCrypto(): Promise<CryptoProvider> {
  const nodeCrypto = await import(/* @vite-ignore */ 'node:crypto');
  return {
    async generateEcKeyPair(): Promise<KeyPairHandle> {
      const { privateKey, publicKey } = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
      const jwk = publicKey.export({ format: 'jwk' }) as { x: string; y: string };
      return { privateKey, publicKey: { x: jwk.x, y: jwk.y } };
    },
    async sign(privateKey: unknown, data: Uint8Array): Promise<Uint8Array> {
      const sig = nodeCrypto.sign('sha256', data, {
        key: privateKey as import('node:crypto').KeyObject,
        dsaEncoding: 'ieee-p1363',
      });
      return new Uint8Array(sig);
    },
    async verify(publicKey: EcPublicKey, signature: Uint8Array, data: Uint8Array): Promise<boolean> {
      try {
        const key = nodeCrypto.createPublicKey({
          key: { kty: 'EC', crv: 'P-256', x: publicKey.x, y: publicKey.y },
          format: 'jwk',
        });
        return nodeCrypto.verify('sha256', data, { key, dsaEncoding: 'ieee-p1363' }, signature);
      } catch {
        return false;
      }
    },
    async sha256(data: Uint8Array): Promise<Uint8Array> {
      return new Uint8Array(nodeCrypto.createHash('sha256').update(data).digest());
    },
    randomBytes(length: number): Uint8Array {
      return new Uint8Array(nodeCrypto.randomBytes(length));
    },
  };
}

/** 浏览器实现（WebCrypto） */
export function createWebCrypto(): CryptoProvider {
  const subtle = globalThis.crypto.subtle;
  return {
    async generateEcKeyPair(): Promise<KeyPairHandle> {
      const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
      const jwk = await subtle.exportKey('jwk', pair.publicKey);
      return { privateKey: pair.privateKey, publicKey: { x: jwk.x!, y: jwk.y! } };
    },
    async sign(privateKey: unknown, data: Uint8Array): Promise<Uint8Array> {
      const sig = await subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        privateKey as never, // CryptoKey，结构类型在 DOM/Node 类型间不一致，运行时均为合法句柄
        new Uint8Array(data), // 拷贝为 ArrayBuffer 支撑的视图，兼容 Node/DOM 的 BufferSource 定义
      );
      return new Uint8Array(sig);
    },
    async verify(publicKey: EcPublicKey, signature: Uint8Array, data: Uint8Array): Promise<boolean> {
      try {
        const key = await subtle.importKey(
          'jwk',
          { kty: 'EC', crv: 'P-256', x: publicKey.x, y: publicKey.y },
          { name: 'ECDSA', namedCurve: 'P-256' },
          false,
          ['verify'],
        );
        return await subtle.verify(
          { name: 'ECDSA', hash: 'SHA-256' },
          key,
          new Uint8Array(signature),
          new Uint8Array(data),
        );
      } catch {
        return false;
      }
    },
    async sha256(data: Uint8Array): Promise<Uint8Array> {
      return new Uint8Array(await subtle.digest('SHA-256', new Uint8Array(data)));
    },
    randomBytes(length: number): Uint8Array {
      const out = new Uint8Array(length);
      globalThis.crypto.getRandomValues(out);
      return out;
    },
  };
}

export function publicKeyToCose(pk: EcPublicKey): Map<number, import('./cbor.js').CborValue> {
  // COSE_Key: kty=EC2(2), alg=ES256(-7), crv=P-256(1), x, y
  return new Map<number, import('./cbor.js').CborValue>([
    [1, 2],
    [3, -7],
    [-1, 1],
    [-2, b64uDecode(pk.x)],
    [-3, b64uDecode(pk.y)],
  ]);
}

export function publicKeyFromCose(cose: Map<unknown, unknown>): EcPublicKey {
  const kty = cose.get(1);
  const alg = cose.get(3);
  const crv = cose.get(-1);
  const x = cose.get(-2);
  const y = cose.get(-3);
  if (kty !== 2 || alg !== -7 || crv !== 1) {
    throw new Error(`unsupported COSE key: kty=${String(kty)} alg=${String(alg)} crv=${String(crv)}`);
  }
  if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array) || x.length !== 32 || y.length !== 32) {
    throw new Error('malformed COSE EC2 key coordinates');
  }
  return { x: b64uEncode(x), y: b64uEncode(y) };
}
