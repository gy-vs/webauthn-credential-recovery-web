/**
 * 最小 CBOR（RFC 8949）编解码，覆盖 WebAuthn 需要的子集：
 * 定长无符号/负整数、字节串、文本串、数组、映射、true/false/null。
 * 映射编码接受 Map（键可为整数，COSE 密钥需要）或普通对象（键按文本串编码）。
 */

export type CborValue =
  | null
  | boolean
  | number
  | bigint
  | string
  | Uint8Array
  | CborValue[]
  | Map<CborValue, CborValue>
  | { [key: string]: CborValue };

function head(major: number, value: number | bigint, out: number[]): void {
  const m = major << 5;
  const v = typeof value === 'bigint' ? value : BigInt(value);
  if (v < 24n) {
    out.push(m | Number(v));
  } else if (v < 0x100n) {
    out.push(m | 24, Number(v));
  } else if (v < 0x10000n) {
    out.push(m | 25, Number(v >> 8n), Number(v & 0xffn));
  } else if (v < 0x100000000n) {
    out.push(m | 26, Number((v >> 24n) & 0xffn), Number((v >> 16n) & 0xffn), Number((v >> 8n) & 0xffn), Number(v & 0xffn));
  } else {
    out.push(
      m | 27,
      Number((v >> 56n) & 0xffn), Number((v >> 48n) & 0xffn), Number((v >> 40n) & 0xffn), Number((v >> 32n) & 0xffn),
      Number((v >> 24n) & 0xffn), Number((v >> 16n) & 0xffn), Number((v >> 8n) & 0xffn), Number(v & 0xffn),
    );
  }
}

function encodeInto(value: CborValue, out: number[]): void {
  if (value === null) {
    out.push(0xf6);
  } else if (typeof value === 'boolean') {
    out.push(value ? 0xf5 : 0xf4);
  } else if (typeof value === 'number' || typeof value === 'bigint') {
    const n = typeof value === 'number' ? BigInt(Math.trunc(value)) : value;
    if (!Number.isSafeInteger(Number(n)) && n > 0xffffffffffffffffn) throw new Error('cbor: integer too large');
    if (n >= 0n) head(0, n, out);
    else head(1, -1n - n, out);
  } else if (typeof value === 'string') {
    const bytes = new TextEncoder().encode(value);
    head(3, bytes.length, out);
    for (const b of bytes) out.push(b);
  } else if (value instanceof Uint8Array) {
    head(2, value.length, out);
    for (const b of value) out.push(b);
  } else if (Array.isArray(value)) {
    head(4, value.length, out);
    for (const item of value) encodeInto(item, out);
  } else if (value instanceof Map) {
    head(5, value.size, out);
    for (const [k, v] of value) {
      encodeInto(k, out);
      encodeInto(v, out);
    }
  } else if (typeof value === 'object') {
    const entries = Object.entries(value);
    head(5, entries.length, out);
    for (const [k, v] of entries) {
      encodeInto(k, out);
      encodeInto(v, out);
    }
  } else {
    throw new Error(`cbor: unsupported value ${String(value)}`);
  }
}

export function cborEncode(value: CborValue): Uint8Array {
  const out: number[] = [];
  encodeInto(value, out);
  return new Uint8Array(out);
}

export interface DecodeResult {
  value: CborValue;
  /** 解码结束位置（相对输入起点） */
  offset: number;
}

function readLength(bytes: Uint8Array, offset: number, info: number): { length: bigint; offset: number } {
  if (info < 24) return { length: BigInt(info), offset };
  if (info === 24) return { length: BigInt(bytes[offset]!), offset: offset + 1 };
  if (info === 25) return { length: BigInt((bytes[offset]! << 8) | bytes[offset + 1]!), offset: offset + 2 };
  if (info === 26) {
    return {
      length: BigInt(((bytes[offset]! << 24) | (bytes[offset + 1]! << 16) | (bytes[offset + 2]! << 8) | bytes[offset + 3]!) >>> 0),
      offset: offset + 4,
    };
  }
  if (info === 27) {
    let v = 0n;
    for (let i = 0; i < 8; i++) v = (v << 8n) | BigInt(bytes[offset + i]!);
    return { length: v, offset: offset + 8 };
  }
  throw new Error(`cbor: unsupported additional info ${info}`);
}

function decodeAt(bytes: Uint8Array, offset: number): DecodeResult {
  if (offset >= bytes.length) throw new Error('cbor: unexpected end of input');
  const initial = bytes[offset]!;
  const major = initial >> 5;
  const info = initial & 0x1f;
  offset += 1;

  switch (major) {
    case 0:
    case 1: {
      const { length, offset: next } = readLength(bytes, offset, info);
      const n = major === 0 ? length : -1n - length;
      const value = n <= BigInt(Number.MAX_SAFE_INTEGER) && n >= BigInt(Number.MIN_SAFE_INTEGER) ? Number(n) : n;
      return { value, offset: next };
    }
    case 2:
    case 3: {
      const { length, offset: start } = readLength(bytes, offset, info);
      const end = start + Number(length);
      if (end > bytes.length) throw new Error('cbor: truncated string');
      const slice = bytes.slice(start, end);
      return { value: major === 2 ? slice : new TextDecoder().decode(slice), offset: end };
    }
    case 4: {
      const { length, offset: start } = readLength(bytes, offset, info);
      const arr: CborValue[] = [];
      let cur = start;
      for (let i = 0; i < Number(length); i++) {
        const r = decodeAt(bytes, cur);
        arr.push(r.value);
        cur = r.offset;
      }
      return { value: arr, offset: cur };
    }
    case 5: {
      const { length, offset: start } = readLength(bytes, offset, info);
      const map = new Map<CborValue, CborValue>();
      let cur = start;
      for (let i = 0; i < Number(length); i++) {
        const k = decodeAt(bytes, cur);
        const v = decodeAt(bytes, k.offset);
        map.set(k.value, v.value);
        cur = v.offset;
      }
      return { value: map, offset: cur };
    }
    case 7: {
      if (info === 20) return { value: false, offset };
      if (info === 21) return { value: true, offset };
      if (info === 22) return { value: null, offset };
      throw new Error(`cbor: unsupported simple value ${info}`);
    }
    default:
      throw new Error(`cbor: unsupported major type ${major}`);
  }
}

/** 从 bytes[offset] 解码一个 CBOR 项，返回值与消费后的偏移（authData 变长部分需要）。 */
export function cborDecodeFirst(bytes: Uint8Array, offset = 0): DecodeResult {
  return decodeAt(bytes, offset);
}

export function cborDecode(bytes: Uint8Array): CborValue {
  const { value, offset } = decodeAt(bytes, 0);
  if (offset !== bytes.length) throw new Error('cbor: trailing bytes');
  return value;
}

/** 转成可 JSON 序列化的普通对象（Uint8Array → base64url），仅用于展示/日志。 */
export function cborToJs(value: CborValue, encodeBytes: (b: Uint8Array) => string): unknown {
  if (value instanceof Uint8Array) return encodeBytes(value);
  if (value instanceof Map) {
    const obj: Record<string, unknown> = {};
    for (const [k, v] of value) obj[String(k)] = cborToJs(v, encodeBytes);
    return obj;
  }
  if (Array.isArray(value)) return value.map((v) => cborToJs(v, encodeBytes));
  if (typeof value === 'bigint') return value.toString();
  if (typeof value === 'object' && value !== null) {
    const obj: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) obj[k] = cborToJs(v, encodeBytes);
    return obj;
  }
  return value;
}
