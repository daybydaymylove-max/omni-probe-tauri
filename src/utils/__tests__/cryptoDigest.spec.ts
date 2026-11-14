import { describe, it, expect } from 'vitest';
import { computeSm3Hex, computeSha256Hex, escapeHtml } from '../cryptoDigest';

describe('cryptoDigest 密码学杂凑算法引擎 (GM/T 0004-2012 & FIPS 180-4)', () => {
  it('SM3 算法必须精确匹配国家商用密码标准 GM/T 0004-2012 官方测试向量', () => {
    // 1. 空字符串标准向量
    expect(computeSm3Hex('')).toBe(
      '1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b'
    );
    // 2. "abc" 单分组测试向量 (GM/T 0004-2012 附录 A 示例1)
    expect(computeSm3Hex('abc')).toBe(
      '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0'
    );
    // 3. 512比特(64字节)跨多分组标准测试向量 "abcd" * 16 (GM/T 0004-2012 附录 A 示例2)
    expect(computeSm3Hex('abcd'.repeat(16))).toBe(
      'debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732'
    );
  });

  it('SHA-256 算法必须精确匹配 NIST FIPS 180-4 标准测试向量', () => {
    expect(computeSha256Hex('')).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    );
    expect(computeSha256Hex('abc')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    );
    expect(computeSha256Hex('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')).toBe(
      '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1'
    );
  });

  it('雪崩效应与中文 UTF-8 多字节报文抗篡改灵敏度测试', () => {
    const payloadA = '192.168.1.1|符合|实测未开放23端口';
    const payloadB = '192.168.1.1|符合|实测未开放22端口';
    expect(computeSm3Hex(payloadA)).not.toBe(computeSm3Hex(payloadB));
    expect(computeSha256Hex(payloadA)).not.toBe(computeSha256Hex(payloadB));
    expect(computeSm3Hex(payloadA).length).toBe(64);
    expect(computeSha256Hex(payloadA).length).toBe(64);
  });

  it('HTML 实体转义有效防御报告导出 XSS 注入', () => {
    const xss = '<script>alert("xss")</script>&\'';
    expect(escapeHtml(xss)).toBe('&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;&amp;&#39;');
  });
});
