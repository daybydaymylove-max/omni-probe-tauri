/**
 * 工业级密码学杂凑算法引擎 (零外部依赖纯 TypeScript 实现)
 * 1. 中华人民共和国商用密码标准 GM/T 0004-2012《SM3 密码杂凑算法》
 * 2. 美国国家标准技术研究院 FIPS 180-4 SHA-256 算法
 *
 * 算法复杂度：
 * - 时间复杂度：O(N)，其中 N 为输入 UTF-8 字节长度（按 64 字节分组压缩）
 * - 空间复杂度：O(1)，固定长度压缩工作向量与 68/64 字消息扩展缓冲区
 */

const utf8Encoder = new TextEncoder();

function rotl32(x: number, n: number): number {
  const s = n & 31;
  return s === 0 ? (x >>> 0) : (((x << s) | (x >>> (32 - s))) >>> 0);
}

function rotr32(x: number, n: number): number {
  const s = n & 31;
  return s === 0 ? (x >>> 0) : (((x >>> s) | (x << (32 - s))) >>> 0);
}

function bytesToHex(words: Uint32Array): string {
  let out = '';
  for (let i = 0; i < words.length; i++) {
    out += (words[i] >>> 0).toString(16).padStart(8, '0');
  }
  return out;
}

/**
 * 依据标准分组规则填充消息至 64 字节整数倍（大端 64 位总比特长度）
 */
function padMessageBlock64(input: Uint8Array): Uint8Array {
  const byteLen = input.length;
  // 至少追加 1 字节 (0x80) 与 8 字节长度字段
  const rem = (byteLen + 9) % 64;
  const padZeroLen = rem === 0 ? 0 : 64 - rem;
  const totalLen = byteLen + 1 + padZeroLen + 8;

  const padded = new Uint8Array(totalLen);
  padded.set(input, 0);
  padded[byteLen] = 0x80;

  // 写入 64-bit 大端比特长度 (支持大消息长度无溢出)
  const bitLen = byteLen * 8;
  const high = Math.floor(bitLen / 0x100000000);
  const low = bitLen >>> 0;
  const view = new DataView(padded.buffer);
  view.setUint32(totalLen - 8, high, false);
  view.setUint32(totalLen - 4, low, false);

  return padded;
}

function sm3P0(x: number): number {
  return (x ^ rotl32(x, 9) ^ rotl32(x, 17)) >>> 0;
}

function sm3P1(x: number): number {
  return (x ^ rotl32(x, 15) ^ rotl32(x, 23)) >>> 0;
}

/**
 * 计算输入字符串的国密 SM3 散列摘要（64 字符小写十六进制）
 * 严格遵循 GM/T 0004-2012 标准
 */
export function computeSm3Hex(message: string): string {
  const inputBytes = utf8Encoder.encode(message);
  const padded = padMessageBlock64(inputBytes);
  const view = new DataView(padded.buffer);

  const v = new Uint32Array([
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
    0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e,
  ]);
  const w = new Uint32Array(68);
  const w1 = new Uint32Array(64);

  for (let offset = 0; offset < padded.length; offset += 64) {
    for (let j = 0; j < 16; j++) {
      w[j] = view.getUint32(offset + j * 4, false);
    }
    for (let j = 16; j < 68; j++) {
      const term = (w[j - 16] ^ w[j - 9] ^ rotl32(w[j - 3], 15)) >>> 0;
      w[j] = (sm3P1(term) ^ rotl32(w[j - 13], 7) ^ w[j - 6]) >>> 0;
    }
    for (let j = 0; j < 64; j++) {
      w1[j] = (w[j] ^ w[j + 4]) >>> 0;
    }

    let a = v[0];
    let b = v[1];
    let c = v[2];
    let d = v[3];
    let e = v[4];
    let f = v[5];
    let g = v[6];
    let h = v[7];

    for (let j = 0; j < 64; j++) {
      const tj = j < 16 ? 0x79cc4519 : 0x7a879d8a;
      const a12 = rotl32(a, 12);
      const ss1 = rotl32((a12 + e + rotl32(tj, j)) >>> 0, 7);
      const ss2 = (ss1 ^ a12) >>> 0;

      const ff = j < 16
        ? (a ^ b ^ c) >>> 0
        : ((a & b) | (a & c) | (b & c)) >>> 0;
      const gg = j < 16
        ? (e ^ f ^ g) >>> 0
        : ((e & f) | (~e & g)) >>> 0;

      const tt1 = (ff + d + ss2 + w1[j]) >>> 0;
      const tt2 = (gg + h + ss1 + w[j]) >>> 0;

      d = c;
      c = rotl32(b, 9);
      b = a;
      a = tt1;
      h = g;
      g = rotl32(f, 19);
      f = e;
      e = sm3P0(tt2);
    }

    v[0] = (v[0] ^ a) >>> 0;
    v[1] = (v[1] ^ b) >>> 0;
    v[2] = (v[2] ^ c) >>> 0;
    v[3] = (v[3] ^ d) >>> 0;
    v[4] = (v[4] ^ e) >>> 0;
    v[5] = (v[5] ^ f) >>> 0;
    v[6] = (v[6] ^ g) >>> 0;
    v[7] = (v[7] ^ h) >>> 0;
  }

  return bytesToHex(v);
}

const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

/**
 * 计算输入字符串的 SHA-256 散列摘要（64 字符小写十六进制）
 * 严格遵循 NIST FIPS 180-4 标准
 */
export function computeSha256Hex(message: string): string {
  const inputBytes = utf8Encoder.encode(message);
  const padded = padMessageBlock64(inputBytes);
  const view = new DataView(padded.buffer);

  const hash = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);
  const w = new Uint32Array(64);

  for (let offset = 0; offset < padded.length; offset += 64) {
    for (let i = 0; i < 16; i++) {
      w[i] = view.getUint32(offset + i * 4, false);
    }
    for (let i = 16; i < 64; i++) {
      const s0 = (rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >>> 3)) >>> 0;
      const s1 = (rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >>> 10)) >>> 0;
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    let a = hash[0];
    let b = hash[1];
    let c = hash[2];
    let d = hash[3];
    let e = hash[4];
    let f = hash[5];
    let g = hash[6];
    let h = hash[7];

    for (let i = 0; i < 64; i++) {
      const S1 = (rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)) >>> 0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const temp1 = (h + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
      const S0 = (rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const temp2 = (S0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    hash[0] = (hash[0] + a) >>> 0;
    hash[1] = (hash[1] + b) >>> 0;
    hash[2] = (hash[2] + c) >>> 0;
    hash[3] = (hash[3] + d) >>> 0;
    hash[4] = (hash[4] + e) >>> 0;
    hash[5] = (hash[5] + f) >>> 0;
    hash[6] = (hash[6] + g) >>> 0;
    hash[7] = (hash[7] + h) >>> 0;
  }

  return bytesToHex(hash);
}

/**
 * 严格的 HTML 实体字符转义，防御报告导出跨站脚本 (XSS) 注入
 */
export function escapeHtml(raw: string): string {
  return raw
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
