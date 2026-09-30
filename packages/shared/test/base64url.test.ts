import { describe, expect, it } from 'vitest';
import { b64uDecode, b64uEncode, isCanonicalB64u } from '../src/base64url.js';

describe('base64url（无填充）', () => {
  it('往返编码各种长度', () => {
    for (const len of [0, 1, 2, 3, 4, 31, 32, 33, 64, 65]) {
      const bytes = new Uint8Array(len).map((_, i) => (i * 37 + len) & 0xff);
      const encoded = b64uEncode(bytes);
      expect(encoded).not.toContain('=');
      expect(encoded).toMatch(/^[A-Za-z0-9_-]*$/);
      expect(b64uDecode(encoded)).toEqual(bytes);
    }
  });

  it('输出与 RFC 4648 测试向量一致', () => {
    expect(b64uEncode(new TextEncoder().encode('f'))).toBe('Zg');
    expect(b64uEncode(new TextEncoder().encode('fo'))).toBe('Zm8');
    expect(b64uEncode(new TextEncoder().encode('foo'))).toBe('Zm9v');
    expect(b64uEncode(new TextEncoder().encode('foob'))).toBe('Zm9vYg');
    // 0xfb 0xff 在标准 base64 中是 +/ ，base64url 中是 -_
    expect(b64uEncode(new Uint8Array([0xfb, 0xff]))).toBe('-_8');
  });

  it('isCanonicalB64u 拒绝填充与非法字符', () => {
    expect(isCanonicalB64u('Zm9v')).toBe(true);
    expect(isCanonicalB64u('Zm9v=')).toBe(false);
    expect(isCanonicalB64u('Zm9v+')).toBe(false);
    expect(isCanonicalB64u('')).toBe(true);
  });

  it('解码容忍带填充输入', () => {
    expect(b64uDecode('Zm8=')).toEqual(new TextEncoder().encode('fo'));
  });
});
