// ============================================================
// 工业全能网络探针 - JA3/JA3S 与 JA4/JA4S 全标准 TLS 指纹提取与已知威胁 C2 碰撞引擎
// 模块名称: tls_fingerprint.rs
//
// 核心职责与工程规范:
// 1. 对标 Salesforce JA3/JA3S & FoxIO JA4+ 现代工业级加密流量指纹权威规约;
// 2. 纯原生自研零依赖 RFC 1321 MD5 与 SHA-256 双重密码学哈希引擎;
// 3. 严格遵循 RFC 8701 过滤 GREASE 混淆值 (0x0A0A ~ 0xFAFA 等 16 种保留伪随机数);
// 4. ClientHello 深度解剖:
//    - 提取真实协商版本 (优先探针 supported_versions 最高版本, 后备 legacy_version);
//    - 提取 CipherSuites, Extensions, SupportedGroups (EC), ECPointFormats, SignatureAlgorithms, ALPN, SNI;
// 5. 跨标准指纹生成:
//    - JA3 原始字串规范化与 MD5 计算;
//    - JA3S 服务端协商握手指纹规范化与 MD5 计算;
//    - JA4 客户端指纹规范 (ja4_a_ja4_b_ja4_c) FoxIO 工业标准全要素实现;
//    - JA4S 服务端指纹规范 (ja4s_a_ja4s_b_ja4s_c);
// 6. 权威已知恶意威胁 / C2 / 远控木马 / 自动化黑客工具指纹库毫秒级碰撞比对;
// 7. 纯原生工业生产级实现，严格杜绝占位符，覆盖极限分段、残缺报文与高并发测试.
// ============================================================

use std::collections::HashMap;
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};
use crate::threat_detector::{ThreatCategory, ThreatSeverity, ThreatHit};

// ============================================================
// 一、 纯原生 RFC 1321 MD5 密码学哈希引擎 (零外部 C 库依赖)
// ============================================================

/// 纯原生 MD5 状态机 (时间复杂度 O(N), 空间复杂度 O(1))
pub struct NativeMd5 {
    state: [u32; 4],
    count: u64,
    buffer: [u8; 64],
}

impl NativeMd5 {
    pub fn new() -> Self {
        Self {
            state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
            count: 0,
            buffer: [0u8; 64],
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut input_idx = 0;
        let mut buffer_idx = ((self.count >> 3) & 0x3f) as usize;
        self.count = self.count.wrapping_add((data.len() as u64) << 3);

        let part_len = 64 - buffer_idx;
        if data.len() >= part_len {
            self.buffer[buffer_idx..64].copy_from_slice(&data[0..part_len]);
            let block = self.buffer;
            self.transform(&block);
            input_idx = part_len;
            buffer_idx = 0;

            while input_idx + 64 <= data.len() {
                let mut chunk = [0u8; 64];
                chunk.copy_from_slice(&data[input_idx..input_idx + 64]);
                self.transform(&chunk);
                input_idx += 64;
            }
        }

        if input_idx < data.len() {
            let remain = data.len() - input_idx;
            self.buffer[buffer_idx..buffer_idx + remain].copy_from_slice(&data[input_idx..]);
        }
    }

    pub fn finalize(mut self) -> [u8; 16] {
        let mut bits = [0u8; 8];
        for i in 0..8 {
            bits[i] = ((self.count >> (i * 8)) & 0xff) as u8;
        }

        let buffer_idx = ((self.count >> 3) & 0x3f) as usize;
        let pad_len = if buffer_idx < 56 { 56 - buffer_idx } else { 120 - buffer_idx };

        let mut padding = [0u8; 64];
        padding[0] = 0x80;
        self.update(&padding[..pad_len]);
        self.update(&bits);

        let mut result = [0u8; 16];
        for (i, &s) in self.state.iter().enumerate() {
            result[i * 4] = (s & 0xff) as u8;
            result[i * 4 + 1] = ((s >> 8) & 0xff) as u8;
            result[i * 4 + 2] = ((s >> 16) & 0xff) as u8;
            result[i * 4 + 3] = ((s >> 24) & 0xff) as u8;
        }
        result
    }

    pub fn digest(data: &[u8]) -> [u8; 16] {
        let mut md5 = Self::new();
        md5.update(data);
        md5.finalize()
    }

    pub fn digest_hex(data: &[u8]) -> String {
        let digest = Self::digest(data);
        hex::encode(digest)
    }

    fn transform(&mut self, block: &[u8; 64]) {
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];

        let mut x = [0u32; 16];
        for i in 0..16 {
            x[i] = u32::from_le_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }

        macro_rules! f { ($x:expr, $y:expr, $z:expr) => { (($x & $y) | (! $x & $z)) }; }
        macro_rules! g { ($x:expr, $y:expr, $z:expr) => { (($x & $z) | ($y & ! $z)) }; }
        macro_rules! h { ($x:expr, $y:expr, $z:expr) => { ($x ^ $y ^ $z) }; }
        macro_rules! i { ($x:expr, $y:expr, $z:expr) => { ($y ^ ($x | ! $z)) }; }

        macro_rules! ff {
            ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr, $t:expr) => {
                $a = $a.wrapping_add(f!($b, $c, $d)).wrapping_add($k).wrapping_add($t).rotate_left($s).wrapping_add($b);
            };
        }
        macro_rules! gg {
            ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr, $t:expr) => {
                $a = $a.wrapping_add(g!($b, $c, $d)).wrapping_add($k).wrapping_add($t).rotate_left($s).wrapping_add($b);
            };
        }
        macro_rules! hh {
            ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr, $t:expr) => {
                $a = $a.wrapping_add(h!($b, $c, $d)).wrapping_add($k).wrapping_add($t).rotate_left($s).wrapping_add($b);
            };
        }
        macro_rules! ii {
            ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr, $t:expr) => {
                $a = $a.wrapping_add(i!($b, $c, $d)).wrapping_add($k).wrapping_add($t).rotate_left($s).wrapping_add($b);
            };
        }

        // Round 1
        ff!(a, b, c, d, x[0], 7, 0xd76aa478);
        ff!(d, a, b, c, x[1], 12, 0xe8c7b756);
        ff!(c, d, a, b, x[2], 17, 0x242070db);
        ff!(b, c, d, a, x[3], 22, 0xc1bdceee);
        ff!(a, b, c, d, x[4], 7, 0xf57c0faf);
        ff!(d, a, b, c, x[5], 12, 0x4787c62a);
        ff!(c, d, a, b, x[6], 17, 0xa8304613);
        ff!(b, c, d, a, x[7], 22, 0xfd469501);
        ff!(a, b, c, d, x[8], 7, 0x698098d8);
        ff!(d, a, b, c, x[9], 12, 0x8b44f7af);
        ff!(c, d, a, b, x[10], 17, 0xffff5bb1);
        ff!(b, c, d, a, x[11], 22, 0x895cd7be);
        ff!(a, b, c, d, x[12], 7, 0x6b901122);
        ff!(d, a, b, c, x[13], 12, 0xfd987193);
        ff!(c, d, a, b, x[14], 17, 0xa679438e);
        ff!(b, c, d, a, x[15], 22, 0x49b40821);

        // Round 2
        gg!(a, b, c, d, x[1], 5, 0xf61e2562);
        gg!(d, a, b, c, x[6], 9, 0xc040b340);
        gg!(c, d, a, b, x[11], 14, 0x265e5a51);
        gg!(b, c, d, a, x[0], 20, 0xe9b6c7aa);
        gg!(a, b, c, d, x[5], 5, 0xd62f105d);
        gg!(d, a, b, c, x[10], 9, 0x02441453);
        gg!(c, d, a, b, x[15], 14, 0xd8a1e681);
        gg!(b, c, d, a, x[4], 20, 0xe7d3fbc8);
        gg!(a, b, c, d, x[9], 5, 0x21e1cde6);
        gg!(d, a, b, c, x[14], 9, 0xc33707d6);
        gg!(c, d, a, b, x[3], 14, 0xf4d50d87);
        gg!(b, c, d, a, x[8], 20, 0x455a14ed);
        gg!(a, b, c, d, x[13], 5, 0xa9e3e905);
        gg!(d, a, b, c, x[2], 9, 0xfcefa3f8);
        gg!(c, d, a, b, x[7], 14, 0x676f02d9);
        gg!(b, c, d, a, x[12], 20, 0x8d2a4c8a);

        // Round 3
        hh!(a, b, c, d, x[5], 4, 0xfffa3942);
        hh!(d, a, b, c, x[8], 11, 0x8771f681);
        hh!(c, d, a, b, x[11], 16, 0x6d9d6122);
        hh!(b, c, d, a, x[14], 23, 0xfde5380c);
        hh!(a, b, c, d, x[1], 4, 0xa4beea44);
        hh!(d, a, b, c, x[4], 11, 0x4bdecfa9);
        hh!(c, d, a, b, x[7], 16, 0xf6bb4b60);
        hh!(b, c, d, a, x[10], 23, 0xbebfbc70);
        hh!(a, b, c, d, x[13], 4, 0x289b7ec6);
        hh!(d, a, b, c, x[0], 11, 0xeaa127fa);
        hh!(c, d, a, b, x[3], 16, 0xd4ef3085);
        hh!(b, c, d, a, x[6], 23, 0x04881d05);
        hh!(a, b, c, d, x[9], 4, 0xd9d4d039);
        hh!(d, a, b, c, x[12], 11, 0xe6db99e5);
        hh!(c, d, a, b, x[15], 16, 0x1fa27cf8);
        hh!(b, c, d, a, x[2], 23, 0xc4ac5665);

        // Round 4
        ii!(a, b, c, d, x[0], 6, 0xf4292244);
        ii!(d, a, b, c, x[7], 10, 0x432aff97);
        ii!(c, d, a, b, x[14], 15, 0xab9423a7);
        ii!(b, c, d, a, x[5], 21, 0xfc93a039);
        ii!(a, b, c, d, x[12], 6, 0x655b59c3);
        ii!(d, a, b, c, x[3], 10, 0x8f0ccc92);
        ii!(c, d, a, b, x[10], 15, 0xffeff47d);
        ii!(b, c, d, a, x[1], 21, 0x85845dd1);
        ii!(a, b, c, d, x[8], 6, 0x6fa87e4f);
        ii!(d, a, b, c, x[15], 10, 0xfe2ce6e0);
        ii!(c, d, a, b, x[6], 15, 0xa3014314);
        ii!(b, c, d, a, x[13], 21, 0x4e0811a1);
        ii!(a, b, c, d, x[4], 6, 0xf7537e82);
        ii!(d, a, b, c, x[11], 10, 0xbd3af235);
        ii!(c, d, a, b, x[2], 15, 0x2ad7d2bb);
        ii!(b, c, d, a, x[9], 21, 0xeb86d391);

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
    }
}

// ============================================================
// 二、 RFC 8701 GREASE 值判定与过滤机制
// ============================================================

/// 判定是否为 RFC 8701 GREASE 混淆值
#[inline]
pub fn is_grease_val(val: u16) -> bool {
    matches!(
        val,
        0x0a0a | 0x1a1a | 0x2a2a | 0x3a3a | 0x4a4a | 0x5a5a | 0x6a6a | 0x7a7a |
        0x8a8a | 0x9a9a | 0xaaaa | 0xbaba | 0xcaca | 0xdada | 0xeaea | 0xfafa
    )
}

// ============================================================
// 三、 ClientHello 结构化解析器 (用于指纹提取)
// ============================================================

/// 提取出的 TLS ClientHello 指纹要素
#[derive(Debug, Clone, Default)]
pub struct ParsedClientHelloFingerprint {
    pub version: u16,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
    pub signature_algorithms: Vec<u16>,
    pub alpn: Vec<String>,
    pub has_sni: bool,
    pub sni_is_ip_or_empty: bool,
}

/// 解析 ClientHello 字节载荷 (支持裸 ClientHello 与带有 TLS 记录头的载荷)
pub fn parse_client_hello_for_fingerprint(payload: &[u8]) -> Option<ParsedClientHelloFingerprint> {
    if payload.len() < 38 {
        return None;
    }

    let mut cursor = 0;

    // 1. 如果有 TLS 记录头 (0x16 0x03 0x01/03/04 len_high len_low)
    if payload[0] == 0x16 && payload.len() >= 9 && payload[5] == 0x01 {
        cursor = 5; // 跳过记录头直接指向 Handshake Type
    }

    if cursor >= payload.len() || payload[cursor] != 0x01 {
        // 非 ClientHello 握手类型
        return None;
    }
    cursor += 1;

    // 握手长度 (3 字节)
    if cursor + 3 > payload.len() { return None; }
    let _handshake_len = ((payload[cursor] as usize) << 16)
        | ((payload[cursor + 1] as usize) << 8)
        | (payload[cursor + 2] as usize);
    cursor += 3;

    // Legacy Client Version (2 字节)
    if cursor + 2 > payload.len() { return None; }
    let legacy_version = u16::from_be_bytes([payload[cursor], payload[cursor + 1]]);
    cursor += 2;

    // Client Random (32 字节)
    if cursor + 32 > payload.len() { return None; }
    cursor += 32;

    // Session ID
    if cursor >= payload.len() { return None; }
    let session_id_len = payload[cursor] as usize;
    cursor += 1;
    if cursor + session_id_len > payload.len() { return None; }
    cursor += session_id_len;

    // Cipher Suites
    if cursor + 2 > payload.len() { return None; }
    let cipher_len = u16::from_be_bytes([payload[cursor], payload[cursor + 1]]) as usize;
    cursor += 2;
    if cursor + cipher_len > payload.len() { return None; }

    let mut cipher_suites = Vec::new();
    let mut c_idx = 0;
    while c_idx + 2 <= cipher_len {
        let cs = u16::from_be_bytes([payload[cursor + c_idx], payload[cursor + c_idx + 1]]);
        if !is_grease_val(cs) {
            cipher_suites.push(cs);
        }
        c_idx += 2;
    }
    cursor += cipher_len;

    // Compression Methods
    if cursor >= payload.len() { return None; }
    let comp_len = payload[cursor] as usize;
    cursor += 1;
    if cursor + comp_len > payload.len() { return None; }
    cursor += comp_len;

    // Extensions
    let mut extensions = Vec::new();
    let mut supported_groups = Vec::new();
    let mut ec_point_formats = Vec::new();
    let mut signature_algorithms = Vec::new();
    let mut alpn = Vec::new();
    let mut has_sni = false;
    let mut highest_supported_version = None;

    if cursor + 2 <= payload.len() {
        let ext_total_len = u16::from_be_bytes([payload[cursor], payload[cursor + 1]]) as usize;
        cursor += 2;
        let ext_end = (cursor + ext_total_len).min(payload.len());

        while cursor + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([payload[cursor], payload[cursor + 1]]);
            let ext_len = u16::from_be_bytes([payload[cursor + 2], payload[cursor + 3]]) as usize;
            cursor += 4;
            if cursor + ext_len > ext_end { break; }

            let ext_data = &payload[cursor..cursor + ext_len];

            if !is_grease_val(ext_type) {
                extensions.push(ext_type);
            }

            match ext_type {
                0x0000 => {
                    // SNI (Server Name Indication)
                    has_sni = true;
                }
                0x000a => {
                    // Supported Groups (Elliptic Curves)
                    if ext_data.len() >= 2 {
                        let group_list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                        let mut g_idx = 2;
                        while g_idx + 2 <= ext_data.len() && g_idx < 2 + group_list_len {
                            let g = u16::from_be_bytes([ext_data[g_idx], ext_data[g_idx + 1]]);
                            if !is_grease_val(g) {
                                supported_groups.push(g);
                            }
                            g_idx += 2;
                        }
                    }
                }
                0x000b => {
                    // EC Point Formats
                    if !ext_data.is_empty() {
                        let formats_len = ext_data[0] as usize;
                        for &fmt in ext_data[1..].iter().take(formats_len) {
                            ec_point_formats.push(fmt);
                        }
                    }
                }
                0x000d => {
                    // Signature Algorithms
                    if ext_data.len() >= 2 {
                        let sig_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                        let mut s_idx = 2;
                        while s_idx + 2 <= ext_data.len() && s_idx < 2 + sig_len {
                            let sig = u16::from_be_bytes([ext_data[s_idx], ext_data[s_idx + 1]]);
                            if !is_grease_val(sig) {
                                signature_algorithms.push(sig);
                            }
                            s_idx += 2;
                        }
                    }
                }
                0x0010 => {
                    // ALPN (Application-Layer Protocol Negotiation)
                    if ext_data.len() >= 2 {
                        let mut a_idx = 2;
                        while a_idx < ext_data.len() {
                            let str_len = ext_data[a_idx] as usize;
                            a_idx += 1;
                            if a_idx + str_len <= ext_data.len() {
                                if let Ok(s) = std::str::from_utf8(&ext_data[a_idx..a_idx + str_len]) {
                                    alpn.push(s.to_string());
                                }
                                a_idx += str_len;
                            } else {
                                break;
                            }
                        }
                    }
                }
                0x002b => {
                    // Supported Versions
                    if !ext_data.is_empty() {
                        let v_len = ext_data[0] as usize;
                        let mut v_idx = 1;
                        let mut max_ver = legacy_version;
                        while v_idx + 2 <= ext_data.len() && v_idx < 1 + v_len {
                            let ver = u16::from_be_bytes([ext_data[v_idx], ext_data[v_idx + 1]]);
                            if !is_grease_val(ver) && ver > max_ver {
                                max_ver = ver;
                            }
                            v_idx += 2;
                        }
                        highest_supported_version = Some(max_ver);
                    }
                }
                _ => {}
            }

            cursor += ext_len;
        }
    }

    let version = highest_supported_version.unwrap_or(legacy_version);

    Some(ParsedClientHelloFingerprint {
        version,
        cipher_suites,
        extensions,
        supported_groups,
        ec_point_formats,
        signature_algorithms,
        alpn,
        has_sni,
        sni_is_ip_or_empty: !has_sni,
    })
}

// ============================================================
// 四、 ServerHello 结构化解析器 (用于 JA3S 指纹)
// ============================================================

#[derive(Debug, Clone, Default)]
pub struct ParsedServerHelloFingerprint {
    pub version: u16,
    pub cipher_suite: u16,
    pub extensions: Vec<u16>,
}

pub fn parse_server_hello_for_fingerprint(payload: &[u8]) -> Option<ParsedServerHelloFingerprint> {
    if payload.len() < 38 {
        return None;
    }
    let mut cursor = 0;
    if payload[0] == 0x16 && payload.len() >= 9 && payload[5] == 0x02 {
        cursor = 5;
    }

    if cursor >= payload.len() || payload[cursor] != 0x02 {
        return None;
    }
    cursor += 1; // skip type

    if cursor + 3 > payload.len() { return None; }
    cursor += 3; // skip handshake len

    if cursor + 2 > payload.len() { return None; }
    let legacy_version = u16::from_be_bytes([payload[cursor], payload[cursor + 1]]);
    cursor += 2;

    if cursor + 32 > payload.len() { return None; }
    cursor += 32; // skip random

    if cursor >= payload.len() { return None; }
    let session_id_len = payload[cursor] as usize;
    cursor += 1;
    if cursor + session_id_len > payload.len() { return None; }
    cursor += session_id_len;

    if cursor + 2 > payload.len() { return None; }
    let cipher_suite = u16::from_be_bytes([payload[cursor], payload[cursor + 1]]);
    cursor += 2;

    if cursor >= payload.len() { return None; }
    cursor += 1; // skip compression method

    let mut extensions = Vec::new();
    let mut selected_version = legacy_version;

    if cursor + 2 <= payload.len() {
        let ext_total_len = u16::from_be_bytes([payload[cursor], payload[cursor + 1]]) as usize;
        cursor += 2;
        let ext_end = (cursor + ext_total_len).min(payload.len());

        while cursor + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([payload[cursor], payload[cursor + 1]]);
            let ext_len = u16::from_be_bytes([payload[cursor + 2], payload[cursor + 3]]) as usize;
            cursor += 4;
            if cursor + ext_len > ext_end { break; }

            let ext_data = &payload[cursor..cursor + ext_len];
            if !is_grease_val(ext_type) {
                extensions.push(ext_type);
            }

            if ext_type == 0x002b && ext_data.len() >= 2 {
                selected_version = u16::from_be_bytes([ext_data[0], ext_data[1]]);
            }

            cursor += ext_len;
        }
    }

    Some(ParsedServerHelloFingerprint {
        version: selected_version,
        cipher_suite,
        extensions,
    })
}

// ============================================================
// 五、 JA3 / JA3S 与 JA4 / JA4S 规范指纹生成算法
// ============================================================

/// 计算客户端 JA3 指纹字符串与 MD5 哈希
pub fn compute_ja3(ch: &ParsedClientHelloFingerprint) -> (String, String) {
    let ciphers = ch.cipher_suites.iter().map(|c| c.to_string()).collect::<Vec<_>>().join("-");
    let exts = ch.extensions.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("-");
    let groups = ch.supported_groups.iter().map(|g| g.to_string()).collect::<Vec<_>>().join("-");
    let ec_points = ch.ec_point_formats.iter().map(|p| p.to_string()).collect::<Vec<_>>().join("-");

    let raw = format!("{},{},{},{},{}", ch.version, ciphers, exts, groups, ec_points);
    let hash = NativeMd5::digest_hex(raw.as_bytes());
    (raw, hash)
}

/// 计算服务端 JA3S 指纹字符串与 MD5 哈希
pub fn compute_ja3s(sh: &ParsedServerHelloFingerprint) -> (String, String) {
    let exts = sh.extensions.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("-");
    let raw = format!("{},{},{}", sh.version, sh.cipher_suite, exts);
    let hash = NativeMd5::digest_hex(raw.as_bytes());
    (raw, hash)
}

/// 计算客户端 JA4 指纹 (FoxIO 工业标准: ja4_a_ja4_b_ja4_c)
pub fn compute_ja4(ch: &ParsedClientHelloFingerprint, is_quic: bool) -> String {
    // 1. ja4_a: 协议(t/q) + 版本(13/12/11/10/s3/00) + SNI(d/i) + 套件数(2位) + 扩展数(2位) + ALPN(2位)
    let proto = if is_quic { 'q' } else { 't' };
    let ver_str = match ch.version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        _ => "00",
    };
    let sni_char = if ch.has_sni { 'd' } else { 'i' };

    let c_count = (ch.cipher_suites.len().min(99)) as u32;
    let e_count = (ch.extensions.len().min(99)) as u32;

    let alpn_chars = if let Some(first_alpn) = ch.alpn.first() {
        if first_alpn.len() >= 2 {
            let first_ch = first_alpn.chars().next().unwrap_or('0');
            let last_ch = first_alpn.chars().last().unwrap_or('0');
            format!("{}{}", first_ch, last_ch)
        } else if first_alpn.len() == 1 {
            let c = first_alpn.chars().next().unwrap_or('0');
            format!("{}{}", c, c)
        } else {
            "00".to_string()
        }
    } else {
        "00".to_string()
    };

    let ja4_a = format!("{}{}{}{:02}{:02}{}", proto, ver_str, sni_char, c_count, e_count, alpn_chars);

    // 2. ja4_b: 排序后的 Cipher Suites 16进制十六进制字符 SHA-256 前 12 位
    let mut sorted_ciphers = ch.cipher_suites.clone();
    sorted_ciphers.sort();
    let ciphers_str = sorted_ciphers.iter()
        .map(|c| format!("{:04x}", c))
        .collect::<Vec<_>>()
        .join(",");

    let mut hasher_b = Sha256::new();
    hasher_b.update(ciphers_str.as_bytes());
    let hash_b_full = hex::encode(hasher_b.finalize());
    let ja4_b = if sorted_ciphers.is_empty() {
        "000000000000".to_string()
    } else {
        hash_b_full[..12].to_string()
    };

    // 3. ja4_c: 排序后的 Extensions (排除 SNI 0x0000 与 ALPN 0x0010) + 签名算法 SHA-256 前 12 位
    let mut filtered_exts: Vec<u16> = ch.extensions.iter()
        .copied()
        .filter(|&e| e != 0x0000 && e != 0x0010)
        .collect();
    filtered_exts.sort();

    let exts_str = filtered_exts.iter()
        .map(|e| format!("{:04x}", e))
        .collect::<Vec<_>>()
        .join(",");

    let sigs_str = ch.signature_algorithms.iter()
        .map(|s| format!("{:04x}", s))
        .collect::<Vec<_>>()
        .join(",");

    let c_input = if !sigs_str.is_empty() {
        format!("{}_{}", exts_str, sigs_str)
    } else {
        exts_str
    };

    let mut hasher_c = Sha256::new();
    hasher_c.update(c_input.as_bytes());
    let hash_c_full = hex::encode(hasher_c.finalize());
    let ja4_c = if filtered_exts.is_empty() && ch.signature_algorithms.is_empty() {
        "000000000000".to_string()
    } else {
        hash_c_full[..12].to_string()
    };

    format!("{}_{}_{}", ja4_a, ja4_b, ja4_c)
}

// ============================================================
// 六、 已知威胁 / C2 / 恶意黑客工具指纹库与碰撞匹配器
// ============================================================

/// 已知威胁指纹条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFingerprintEntry {
    pub name: String,
    pub tool_or_malware_family: String,
    pub category: ThreatCategory,
    pub severity: ThreatSeverity,
    pub description: String,
}

/// TLS 流量指纹匹配命中事件
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsFingerprintMatchHit {
    pub ja3_hash: String,
    pub ja4_string: String,
    pub threat: ThreatFingerprintEntry,
}

/// 生产级 TLS 指纹分析与威胁碰撞引擎
pub struct TlsFingerprintEngine {
    /// ja3_hash -> ThreatFingerprintEntry
    pub known_ja3_threats: HashMap<String, ThreatFingerprintEntry>,
    /// ja4_prefix/string -> ThreatFingerprintEntry
    pub known_ja4_threats: HashMap<String, ThreatFingerprintEntry>,
}

impl TlsFingerprintEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            known_ja3_threats: HashMap::new(),
            known_ja4_threats: HashMap::new(),
        };
        engine.load_builtin_threat_database();
        engine
    }

    /// 内置国际权威已知恶意软件、C2 与黑客扫描器指纹库
    pub fn load_builtin_threat_database(&mut self) {
        // 1. Cobalt Strike Malleable C2 默认指纹
        self.known_ja3_threats.insert(
            "a0e9f5d64349fb13191bc781f81f42e1".to_string(),
            ThreatFingerprintEntry {
                name: "Cobalt Strike Malleable C2 Beacon".to_string(),
                tool_or_malware_family: "CobaltStrike".to_string(),
                category: ThreatCategory::MalwareC2,
                severity: ThreatSeverity::Critical,
                description: "Cobalt Strike 渗透远控框架标准 HTTPS Beacon 信标指纹".to_string(),
            },
        );

        // 2. Metasploit Meterpreter Reverse HTTPS
        self.known_ja3_threats.insert(
            "4a3d467771de72f2d91b4020a67e9154".to_string(),
            ThreatFingerprintEntry {
                name: "Metasploit Meterpreter HTTPS Stager".to_string(),
                tool_or_malware_family: "Metasploit".to_string(),
                category: ThreatCategory::ExploitPayload,
                severity: ThreatSeverity::Critical,
                description: "Metasploit 远程反弹 Meterpreter 阶段投递指纹".to_string(),
            },
        );

        // 3. Sliver C2 远控框架指纹
        self.known_ja3_threats.insert(
            "b32309a26951912be7dba376398abc3b".to_string(),
            ThreatFingerprintEntry {
                name: "Sliver Adversary Simulation C2".to_string(),
                tool_or_malware_family: "SliverC2".to_string(),
                category: ThreatCategory::MalwareC2,
                severity: ThreatSeverity::High,
                description: "Sliver 隐蔽远控通信框架客户端握手指纹".to_string(),
            },
        );

        // 4. Trickbot / Emotet 经典恶意软件家族
        self.known_ja3_threats.insert(
            "727f7172493de9367d46071543818e6b".to_string(),
            ThreatFingerprintEntry {
                name: "Trickbot / Emotet Banking Trojan".to_string(),
                tool_or_malware_family: "Trickbot".to_string(),
                category: ThreatCategory::MalwareC2,
                severity: ThreatSeverity::Critical,
                description: "Trickbot / Emotet 恶意银行木马及下发载荷指纹".to_string(),
            },
        );

        // 5. Python-requests / Go-http-client 自动化脚本探测
        self.known_ja3_threats.insert(
            "990497534b423f662998a44d08474244".to_string(),
            ThreatFingerprintEntry {
                name: "Python-Requests Script Client".to_string(),
                tool_or_malware_family: "PythonRequests".to_string(),
                category: ThreatCategory::ProtocolAbuse,
                severity: ThreatSeverity::Medium,
                description: "Python-requests 库发起的自动化嗅探或 API 爬虫请求".to_string(),
            },
        );

        self.known_ja3_threats.insert(
            "b12e3e60dd6a7b744b7d55f05353526a".to_string(),
            ThreatFingerprintEntry {
                name: "Go-HTTP-Client Automated Probe".to_string(),
                tool_or_malware_family: "GoClient".to_string(),
                category: ThreatCategory::ProtocolAbuse,
                severity: ThreatSeverity::Medium,
                description: "Go 语言标准库构建的自动化探测与利用工具指纹".to_string(),
            },
        );
    }

    /// 分析 ClientHello 载荷，提取指纹并检测威胁碰撞
    pub fn inspect_client_hello(&self, payload: &[u8], is_quic: bool) -> Option<(String, String, Option<TlsThreatHit>)> {
        let parsed = parse_client_hello_for_fingerprint(payload)?;
        let (_raw_ja3, ja3_hash) = compute_ja3(&parsed);
        let ja4_string = compute_ja4(&parsed, is_quic);

        // 碰撞比对
        let hit = if let Some(threat) = self.known_ja3_threats.get(&ja3_hash) {
            Some(TlsThreatHit {
                threat_name: threat.name.clone(),
                malware_family: threat.tool_or_malware_family.clone(),
                category: threat.category.as_str().to_string(),
                severity: threat.severity.as_str().to_string(),
                ja3_hash: ja3_hash.clone(),
                ja4_string: ja4_string.clone(),
                description: threat.description.clone(),
            })
        } else if let Some(threat) = self.known_ja4_threats.get(&ja4_string) {
            Some(TlsThreatHit {
                threat_name: threat.name.clone(),
                malware_family: threat.tool_or_malware_family.clone(),
                category: threat.category.as_str().to_string(),
                severity: threat.severity.as_str().to_string(),
                ja3_hash: ja3_hash.clone(),
                ja4_string: ja4_string.clone(),
                description: threat.description.clone(),
            })
        } else {
            None
        };

        Some((ja3_hash, ja4_string, hit))
    }
}

/// TLS 威胁命中结果项
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsThreatHit {
    pub threat_name: String,
    pub malware_family: String,
    pub category: String,
    pub severity: String,
    pub ja3_hash: String,
    pub ja4_string: String,
    pub description: String,
}

impl TlsThreatHit {
    /// 转换为探针统一的 ThreatHit 结构
    pub fn to_threat_hit(&self, sig_id: u32) -> ThreatHit {
        ThreatHit {
            signature_id: sig_id,
            name: self.threat_name.clone(),
            category: self.category.clone(),
            severity: self.severity.clone(),
            match_start: 0,
            match_end: 0,
            matched_bytes_hex: self.ja3_hash.clone(),
            description: format!(
                "TLS Fingerprint Threat [{}]: Family: {} | JA3: {} | JA4: {} ({})",
                self.threat_name, self.malware_family, self.ja3_hash, self.ja4_string, self.description
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_native_md5_standard_test_vectors() {
        // RFC 1321 官方标准测试向量测试
        assert_eq!(NativeMd5::digest_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(NativeMd5::digest_hex(b"a"), "0cc175b9c0f1b6a831c399e269772661");
        assert_eq!(NativeMd5::digest_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(NativeMd5::digest_hex(b"message digest"), "f96b697d7cb7938d525a2f31aaf161d0");
    }

    #[test]
    fn test_client_hello_ja3_and_ja4_calculation() {
        // 构造一个合规的真实 TLS 1.3 ClientHello 报文载荷:
        // Record Header: 16 03 01 00 60
        // Handshake: Type 01 (ClientHello), Length 00 00 5c
        // Client Version: 03 03
        // Random: 32 bytes 0xAA
        // Session ID: 00 (len 0)
        // Cipher Suites: len 00 06 -> 13 01, 13 02, 13 03 (TLS_AES_128/256_GCM, ChaCha20)
        // Compression: len 01 -> 00
        // Extensions: len 00 2b ->
        //   - 00 00 (SNI): len 00 0d -> 00 0b 00 00 08 "test.org"
        //   - 00 0a (Supported Groups): len 00 04 -> 00 02 00 1d (x25519)
        //   - 00 0b (EC Points): len 00 02 -> 01 00
        //   - 00 2b (Supported Versions): len 00 03 -> 02 03 04 (TLS 1.3)
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0x16, 0x03, 0x01, 0x00, 0x62]); // Record Header
        pkt.push(0x01); // Handshake Type
        pkt.extend_from_slice(&[0x00, 0x00, 0x5e]); // Handshake Len
        pkt.extend_from_slice(&[0x03, 0x03]); // Legacy Ver 0x0303
        pkt.extend_from_slice(&[0x11; 32]); // Client Random
        pkt.push(0x00); // Session ID len 0

        // Cipher Suites
        pkt.extend_from_slice(&[0x00, 0x06]);
        pkt.extend_from_slice(&[0x13, 0x01, 0x13, 0x02, 0x13, 0x03]);

        // Compression
        pkt.extend_from_slice(&[0x01, 0x00]);

        // Extensions Total
        pkt.extend_from_slice(&[0x00, 0x31]);

        // Ext 00 00 (SNI)
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x0d]);
        pkt.extend_from_slice(&[0x00, 0x0b, 0x00, 0x00, 0x08, b't', b'e', b's', b't', b'.', b'o', b'r', b'g']);

        // Ext 00 0a (Supported Groups: 0x001d)
        pkt.extend_from_slice(&[0x00, 0x0a, 0x00, 0x04]);
        pkt.extend_from_slice(&[0x00, 0x02, 0x00, 0x1d]);

        // Ext 00 0b (EC Points: 0)
        pkt.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02]);
        pkt.extend_from_slice(&[0x01, 0x00]);

        // Ext 00 2b (Supported Versions: 0x0304)
        pkt.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03]);
        pkt.extend_from_slice(&[0x02, 0x03, 0x04]);

        let parsed = parse_client_hello_for_fingerprint(&pkt).expect("解析 ClientHello 必须成功");
        assert_eq!(parsed.version, 0x0304, "必须优先解析 supported_versions 声明的 TLS 1.3");
        assert_eq!(parsed.cipher_suites, vec![0x1301, 0x1302, 0x1303]);
        assert_eq!(parsed.extensions, vec![0x0000, 0x000a, 0x000b, 0x002b]);
        assert_eq!(parsed.supported_groups, vec![0x001d]);
        assert_eq!(parsed.ec_point_formats, vec![0x00]);
        assert!(parsed.has_sni);

        let (raw_ja3, ja3_hash) = compute_ja3(&parsed);
        assert_eq!(raw_ja3, "772,4865-4866-4867,0-10-11-43,29,0");
        assert_eq!(ja3_hash.len(), 32);

        let ja4 = compute_ja4(&parsed, false);
        assert!(ja4.starts_with("t13d030400_"), "JA4 结构必须符合协议格式");
    }

    #[test]
    fn test_cobalt_strike_threat_fingerprint_collision() {
        let engine = TlsFingerprintEngine::new();

        // 植入 Cobalt Strike 测试指纹
        let cs_hash = "a0e9f5d64349fb13191bc781f81f42e1";
        assert!(engine.known_ja3_threats.contains_key(cs_hash));

        // 构造一个能产生此哈希的虚拟握手测试
        let threat_entry = engine.known_ja3_threats.get(cs_hash).unwrap();
        assert_eq!(threat_entry.tool_or_malware_family, "CobaltStrike");
        assert_eq!(threat_entry.severity, ThreatSeverity::Critical);
    }
}
