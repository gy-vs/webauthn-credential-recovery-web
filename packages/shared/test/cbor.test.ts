import { describe, expect, it } from 'vitest';
import { cborDecode, cborDecodeFirst, cborEncode, type CborValue } from '../src/cbor.js';

describe('CBOR 子集', () => {
  it('整数（含负数与边界）往返', () => {
    for (const n of [0, 1, 10, 23, 24, 255, 256, 65535, 65536, 4294967295, 4294967296, -1, -7, -24, -256, -65536, -4294967296]) {
      expect(cborDecode(cborEncode(n))).toBe(n);
    }
  });

  it('字符串 / 字节串 / 数组 / 布尔 / null 往返', () => {
    const value: CborValue = ['hello', new Uint8Array([1, 2, 3]), [true, false, null], 42];
    expect(cborDecode(cborEncode(value))).toEqual(value);
  });

  it('Map（整数键，COSE 形态）往返', () => {
    const cose = new Map<number, CborValue>([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, new Uint8Array(32).fill(0xaa)],
      [-3, new Uint8Array(32).fill(0xbb)],
    ]);
    const decoded = cborDecode(cborEncode(cose)) as Map<number, CborValue>;
    expect(decoded.get(1)).toBe(2);
    expect(decoded.get(3)).toBe(-7);
    expect(decoded.get(-1)).toBe(1);
    expect(decoded.get(-2)).toEqual(new Uint8Array(32).fill(0xaa));
  });

  it('普通对象按文本键编码', () => {
    const decoded = cborDecode(cborEncode({ fmt: 'none', attStmt: {} })) as Map<string, CborValue>;
    expect(decoded.get('fmt')).toBe('none');
    expect(decoded.get('attStmt')).toBeInstanceOf(Map);
  });

  it('decodeFirst 报告消费偏移', () => {
    const bytes = cborEncode([1, 2]);
    const extra = new Uint8Array([...bytes, 0xf6]);
    const { value, offset } = cborDecodeFirst(extra, 0);
    expect(value).toEqual([1, 2]);
    expect(offset).toBe(bytes.length);
  });

  it('拒绝尾随字节', () => {
    const bytes = new Uint8Array([...cborEncode(1), 0x01]);
    expect(() => cborDecode(bytes)).toThrow();
  });
});
