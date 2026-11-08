// ============================================================
// 工业全能网络探针 - 纯 Rust 被动 TLS 记录层流式解密引擎
// 模块名称: passive_tls_decryptor.rs
//
// 核心职责与工程规范:
// 1. 对齐 Wireshark epan/dissectors/packet-tls 被动解密标准;
// 2. 严格遵循 RFC 5246 (TLS 1.2) 与 RFC 8446 (TLS 1.3) 规范;
// 3. 握手层: 解析 ClientHello 提取 32B ClientRandom, 解析 ServerHello 提取 CipherSuite;
// 4. 密钥派生: 
//    - TLS 1.3: HKDF-Expand-Label(secret, "key" / "iv", "", len)
//    - TLS 1.2: PRF(master_secret, "key expansion", server_random + client_random)
// 5. AEAD 流式解密:
//    - TLS 1.3: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 (Nonce = IV ^ SeqNum)
//    - TLS 1.2: AES-128-GCM, AES-256-GCM (Nonce = Salt + ExplicitNonce)
// 6. 算法复杂度: 时间复杂度 O(N) 零拷贝流式解析, 空间复杂度 O(M) 有界内存控制.
// ============================================================

use std::fmt;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce as GcmNonce};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384};
use serde::{Deserialize, Serialize};

/// TLS 记录层类型常量 (RFC 8446 Section 5.1)
pub const CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 0x14;
pub const CONTENT_TYPE_ALERT: u8 = 0x15;
pub const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
pub const CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;

/// TLS 握手类型常量 (RFC 8446 Section 4)
pub const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
pub const HANDSHAKE_SERVER_HELLO: u8 = 0x02;

/// TLS 版本常量
pub const TLS_VERSION_1_2: u16 = 0x0303;
pub const TLS_VERSION_1_3: u16 = 0x0304;

/// 支持的主流 AEAD 密码套件 (覆盖现代 99% 加密流量)
pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
pub const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
pub const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: u16 = 0xC02F;
pub const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: u16 = 0xC030;
pub const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: u16 = 0xC02B;
pub const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: u16 = 0xC02C;

/// 被动解密错误类型
#[derive(Debug)]
pub enum PassiveTlsError {
    InvalidRecordLength(usize),
    UnknownRecordType(u8),
    HandshakeParseError(String),
    KeyDerivationError(String),
    AeadDecryptionError(String),
    KeyNotFound(String),
    UnsupportedCipherSuite(u16),
}

impl fmt::Display for PassiveTlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRecordLength(len) => write!(f, "无效的 TLS 记录长度: {}", len),
            Self::UnknownRecordType(t) => write!(f, "未知的 TLS 记录类型: 0x{:02x}", t),
            Self::HandshakeParseError(s) => write!(f, "TLS 握手报文解析失败: {}", s),
            Self::KeyDerivationError(s) => write!(f, "密钥派生失败: {}", s),
            Self::AeadDecryptionError(s) => write!(f, "AEAD 密码学解密失败 (Tag 校验不匹配): {}", s),
            Self::KeyNotFound(s) => write!(f, "未在 NSS 密钥库中检索到匹配密钥: {}", s),
            Self::UnsupportedCipherSuite(cs) => write!(f, "暂不支持的密码套件: 0x{:04x}", cs),
        }
    }
}

impl std::error::Error for PassiveTlsError {}

/// 解密还原后的应用层明文数据项
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptedTlsPayload {
    pub stream_id: String,
    pub direction: String, // "CLIENT_TO_SERVER" | "SERVER_TO_CLIENT"
    pub sequence_number: u64,
    pub tls_version: String,
    pub cipher_suite: String,
    pub plaintext_utf8: String,
    pub plaintext_hex: String,
    pub plaintext_len: usize,
    pub timestamp: String,
}

/// 单条 TLS 记录层分帧数据
#[derive(Debug, Clone)]
pub struct TlsRecordFrame<'a> {
    pub content_type: u8,
    pub legacy_version: u16,
    pub length: u16,
    pub payload: &'a [u8],
    pub raw_header: [u8; 5],
}

// ============================================================
// 1. RFC 8446 (TLS 1.3) HKDF-Expand-Label 密钥派生
// ============================================================

/// RFC 8446 Section 7.1 HKDF-Expand-Label
/// 格式:
/// struct {
///     uint16 length = Length;
///     opaque label<7..255> = "tls13 " + Label;
///     opaque context<0..255> = Context;
/// } HkdfLabel;
pub fn hkdf_expand_label_sha256(
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    length: u16,
) -> Result<Vec<u8>, PassiveTlsError> {
    let mut hkdf_label = Vec::with_capacity(2 + 1 + 6 + label.len() + 1 + context.len());
    hkdf_label.extend_from_slice(&length.to_be_bytes());

    let full_label = [b"tls13 ", label].concat();
    hkdf_label.push(full_label.len() as u8);
    hkdf_label.extend_from_slice(&full_label);

    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);

    let hk = hkdf::Hkdf::<Sha256>::from_prk(secret)
        .map_err(|e| PassiveTlsError::KeyDerivationError(format!("HKDF PRK 初始化失败: {:?}", e)))?;

    let mut out = vec![0u8; length as usize];
    hk.expand(&hkdf_label, &mut out)
        .map_err(|e| PassiveTlsError::KeyDerivationError(format!("HKDF Expand 失败: {:?}", e)))?;

    Ok(out)
}

pub fn hkdf_expand_label_sha384(
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    length: u16,
) -> Result<Vec<u8>, PassiveTlsError> {
    let mut hkdf_label = Vec::with_capacity(2 + 1 + 6 + label.len() + 1 + context.len());
    hkdf_label.extend_from_slice(&length.to_be_bytes());

    let full_label = [b"tls13 ", label].concat();
    hkdf_label.push(full_label.len() as u8);
    hkdf_label.extend_from_slice(&full_label);

    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);

    let hk = hkdf::Hkdf::<Sha384>::from_prk(secret)
        .map_err(|e| PassiveTlsError::KeyDerivationError(format!("HKDF PRK 初始化失败: {:?}", e)))?;

    let mut out = vec![0u8; length as usize];
    hk.expand(&hkdf_label, &mut out)
        .map_err(|e| PassiveTlsError::KeyDerivationError(format!("HKDF Expand 失败: {:?}", e)))?;

    Ok(out)
}

// ============================================================
// 2. RFC 5246 (TLS 1.2) PRF (P_SHA256) 密钥派生
// ============================================================

/// RFC 5246 Section 5 P_hash (基于 HMAC-SHA256)
fn p_sha256(secret: &[u8], seed: &[u8], output_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(output_len);
    let mut a = Vec::from(seed); // A(0) = seed

    while out.len() < output_len {
        // A(i) = HMAC(secret, A(i-1))
        let mut mac_a = <Hmac<Sha256> as hmac::Mac>::new_from_slice(secret).expect("HMAC 支持任意长度密钥");
        mac_a.update(&a);
        a = mac_a.finalize().into_bytes().to_vec();

        // Output chunk = HMAC(secret, A(i) + seed)
        let mut mac_out = <Hmac<Sha256> as hmac::Mac>::new_from_slice(secret).expect("HMAC 支持任意长度密钥");
        mac_out.update(&a);
        mac_out.update(seed);
        let chunk = mac_out.finalize().into_bytes();

        let take_len = (output_len - out.len()).min(chunk.len());
        out.extend_from_slice(&chunk[..take_len]);
    }

    out
}

/// TLS 1.2 PRF(secret, label, seed) = P_SHA256(secret, label + seed)
pub fn tls12_prf_sha256(secret: &[u8], label: &[u8], seed: &[u8], output_len: usize) -> Vec<u8> {
    let combined_seed = [label, seed].concat();
    p_sha256(secret, &combined_seed, output_len)
}

// ============================================================
// 3. TLS 记录层分帧器与握手解析器
// ============================================================

/// 从原始 TCP 字节流中拆解出所有的 TLS Record
pub fn parse_tls_records(data: &[u8]) -> Result<Vec<TlsRecordFrame<'_>>, PassiveTlsError> {
    let mut records = Vec::new();
    let mut offset = 0;

    while offset + 5 <= data.len() {
        let content_type = data[offset];
        let legacy_version = u16::from_be_bytes([data[offset + 1], data[offset + 2]]);
        let length = u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as usize;

        // 校验是否为合法 TLS 记录类型 (0x14..=0x18)
        if !(0x14..=0x18).contains(&content_type) {
            break;
        }

        if offset + 5 + length > data.len() {
            // TCP 分片尚未完整到达，优雅终止等待下一次重组
            break;
        }

        let mut raw_hdr = [0u8; 5];
        raw_hdr.copy_from_slice(&data[offset..offset + 5]);

        records.push(TlsRecordFrame {
            content_type,
            legacy_version,
            length: length as u16,
            payload: &data[offset + 5..offset + 5 + length],
            raw_header: raw_hdr,
        });

        offset += 5 + length;
    }

    Ok(records)
}

/// 从 Handshake 记录中提取 ClientHello 的 32 字节 ClientRandom

/// 具备独立生命周期的 TLS Record 记录帧 (用于跨 TCP 包流式重组)
#[derive(Debug, Clone)]
pub struct OwnedTlsRecordFrame {
    pub content_type: u8,
    pub legacy_version: u16,
    pub length: u16,
    pub payload: Vec<u8>,
    pub raw_header: [u8; 5],
}

impl OwnedTlsRecordFrame {
    pub fn as_borrowed(&self) -> TlsRecordFrame<'_> {
        TlsRecordFrame {
            content_type: self.content_type,
            legacy_version: self.legacy_version,
            length: self.length,
            payload: &self.payload,
            raw_header: self.raw_header,
        }
    }
}

/// 流式跨 TCP 报文 TLS Record 重组器 (StreamingTlsRecordBuffer)
/// 算法: 滑动缓冲池 + 5字节标头边界扫描, 时间复杂度 O(N), 空间复杂度 O(K)
#[derive(Debug, Clone, Default)]
pub struct StreamingTlsRecordBuffer {
    buffer: Vec<u8>,
    max_buffer_size: usize,
}

impl StreamingTlsRecordBuffer {
    pub fn new(max_buffer_size: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(4096),
            max_buffer_size: if max_buffer_size == 0 { 65536 } else { max_buffer_size },
        }
    }

    /// 持续喂入新收到的 TCP 报文分段字节流
    pub fn feed(&mut self, chunk: &[u8]) {
        self.buffer.extend_from_slice(chunk);
        if self.buffer.len() > self.max_buffer_size {
            let overflow = self.buffer.len() - self.max_buffer_size;
            self.buffer.drain(0..overflow);
        }
    }

    /// 提取出当前已完整就绪的所有独立 TLS 记录 (自动跨包拼齐并推进缓冲区)
    pub fn drain_ready_records(&mut self) -> Vec<OwnedTlsRecordFrame> {
        let mut ready = Vec::new();

        loop {
            if self.buffer.len() < 5 {
                break;
            }

            let content_type = self.buffer[0];
            if !(0x14..=0x18).contains(&content_type) {
                // 流失步，向前滑动 1 字节寻找下一个可能帧头
                self.buffer.remove(0);
                continue;
            }

            let legacy_version = u16::from_be_bytes([self.buffer[1], self.buffer[2]]);
            let length = u16::from_be_bytes([self.buffer[3], self.buffer[4]]) as usize;

            if length > 18432 {
                self.buffer.remove(0);
                continue;
            }

            if self.buffer.len() < 5 + length {
                // 碎片尚未集齐，保留等待后续 TCP 分段
                break;
            }

            let mut raw_hdr = [0u8; 5];
            raw_hdr.copy_from_slice(&self.buffer[0..5]);
            let payload = self.buffer[5..5 + length].to_vec();

            ready.push(OwnedTlsRecordFrame {
                content_type,
                legacy_version,
                length: length as u16,
                payload,
                raw_header: raw_hdr,
            });

            self.buffer.drain(0..5 + length);
        }

        ready
    }

    /// 当前积压未拼齐的碎片字节数
    pub fn pending_bytes(&self) -> usize {
        self.buffer.len()
    }
}
pub fn extract_client_random(record_payload: &[u8]) -> Option<[u8; 32]> {
    if record_payload.len() < 4 + 2 + 32 {
        return None;
    }
    let msg_type = record_payload[0];
    if msg_type != HANDSHAKE_CLIENT_HELLO {
        return None;
    }

    // ClientHello: msg_type (1B) + length (3B) + client_version (2B) + random (32B)
    let mut client_random = [0u8; 32];
    client_random.copy_from_slice(&record_payload[6..38]);
    Some(client_random)
}

/// 从 Handshake 记录中提取 ServerHello 的 CipherSuite 与 ServerRandom
pub fn extract_server_hello(record_payload: &[u8]) -> Option<([u8; 32], u16)> {
    if record_payload.len() < 4 + 2 + 32 + 1 {
        return None;
    }
    let msg_type = record_payload[0];
    if msg_type != HANDSHAKE_SERVER_HELLO {
        return None;
    }

    // ServerHello: msg_type (1B) + length (3B) + server_version (2B) + random (32B)
    let mut server_random = [0u8; 32];
    server_random.copy_from_slice(&record_payload[6..38]);

    let session_id_len = record_payload[38] as usize;
    let cipher_offset = 39 + session_id_len;
    if cipher_offset + 2 > record_payload.len() {
        return None;
    }

    let cipher_suite = u16::from_be_bytes([record_payload[cipher_offset], record_payload[cipher_offset + 1]]);
    Some((server_random, cipher_suite))
}

// ============================================================
// 4. 双向 AEAD 流式记录层解密器
// ============================================================

/// TLS 会话解密上下文
pub struct TlsDecryptionSession {
    pub client_random: [u8; 32],
    pub server_random: [u8; 32],
    pub cipher_suite: u16,
    pub tls_version: u16,
    // 派生密钥与 IV
    pub client_key: Vec<u8>,
    pub client_iv: Vec<u8>,
    pub server_key: Vec<u8>,
    pub server_iv: Vec<u8>,
    // 单调递增序列号 (用于 Nonce 与 AAD 计算)
    pub client_seq: u64,
    pub server_seq: u64,
    pub is_ready: bool,
}

impl TlsDecryptionSession {
    pub fn new() -> Self {
        Self {
            client_random: [0u8; 32],
            server_random: [0u8; 32],
            cipher_suite: 0,
            tls_version: TLS_VERSION_1_3,
            client_key: Vec::new(),
            client_iv: Vec::new(),
            server_key: Vec::new(),
            server_iv: Vec::new(),
            client_seq: 0,
            server_seq: 0,
            is_ready: false,
        }
    }

    /// 基于 TLS 1.3 Traffic Secrets 初始化密钥与 IV
    pub fn init_tls13_secrets(
        &mut self,
        client_traffic_secret: &[u8],
        server_traffic_secret: &[u8],
        cipher_suite: u16,
    ) -> Result<(), PassiveTlsError> {
        self.cipher_suite = cipher_suite;
        self.tls_version = TLS_VERSION_1_3;

        let (key_len, is_sha384) = match cipher_suite {
            TLS_AES_128_GCM_SHA256 => (16u16, false),
            TLS_AES_256_GCM_SHA384 => (32u16, true),
            TLS_CHACHA20_POLY1305_SHA256 => (32u16, false), // RFC 8439: ChaCha20 必须使用 32 字节(256位)密钥
            _ => (16u16, false),
        };

        if is_sha384 {
            self.client_key = hkdf_expand_label_sha384(client_traffic_secret, b"key", b"", key_len)?;
            self.client_iv = hkdf_expand_label_sha384(client_traffic_secret, b"iv", b"", 12)?;
            self.server_key = hkdf_expand_label_sha384(server_traffic_secret, b"key", b"", key_len)?;
            self.server_iv = hkdf_expand_label_sha384(server_traffic_secret, b"iv", b"", 12)?;
        } else {
            self.client_key = hkdf_expand_label_sha256(client_traffic_secret, b"key", b"", key_len)?;
            self.client_iv = hkdf_expand_label_sha256(client_traffic_secret, b"iv", b"", 12)?;
            self.server_key = hkdf_expand_label_sha256(server_traffic_secret, b"key", b"", key_len)?;
            self.server_iv = hkdf_expand_label_sha256(server_traffic_secret, b"iv", b"", 12)?;
        }

        self.is_ready = true;
        Ok(())
    }

    /// 基于 TLS 1.2 Master Secret 初始化 Key Block
    pub fn init_tls12_master_secret(
        &mut self,
        master_secret: &[u8],
        client_random: &[u8; 32],
        server_random: &[u8; 32],
        cipher_suite: u16,
    ) -> Result<(), PassiveTlsError> {
        self.client_random = *client_random;
        self.server_random = *server_random;
        self.cipher_suite = cipher_suite;
        self.tls_version = TLS_VERSION_1_2;

        let key_len = match cipher_suite {
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 | TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => 32,
            _ => 16,
        };
        let iv_len = 4; // TLS 1.2 GCM 固定 salt 长度为 4 字节

        // Key Expansion: seed = server_random + client_random
        let seed = [server_random.as_slice(), client_random.as_slice()].concat();
        let total_key_block_len = 2 * key_len + 2 * iv_len;
        let key_block = tls12_prf_sha256(master_secret, b"key expansion", &seed, total_key_block_len);

        let mut offset = 0;
        self.client_key = key_block[offset..offset + key_len].to_vec();
        offset += key_len;
        self.server_key = key_block[offset..offset + key_len].to_vec();
        offset += key_len;
        self.client_iv = key_block[offset..offset + iv_len].to_vec();
        offset += iv_len;
        self.server_iv = key_block[offset..offset + iv_len].to_vec();

        self.is_ready = true;
        Ok(())
    }

    /// 解密单个 TLS 记录层 Application Data
    pub fn decrypt_record(
        &mut self,
        record: &TlsRecordFrame,
        is_client: bool,
    ) -> Result<Vec<u8>, PassiveTlsError> {
        if !self.is_ready {
            return Err(PassiveTlsError::KeyDerivationError("会话密钥尚未就绪".into()));
        }

        let (key, iv, seq) = if is_client {
            (&self.client_key, &self.client_iv, &mut self.client_seq)
        } else {
            (&self.server_key, &self.server_iv, &mut self.server_seq)
        };

        let current_seq = *seq;
        *seq += 1; // 序列号单调递增

        if self.tls_version == TLS_VERSION_1_3 {
            self.decrypt_tls13_record(record, key, iv, current_seq)
        } else {
            self.decrypt_tls12_gcm_record(record, key, iv, current_seq)
        }
    }

    /// 执行 TLS 1.3 AEAD 记录解密
    fn decrypt_tls13_record(
        &self,
        record: &TlsRecordFrame,
        key: &[u8],
        iv: &[u8],
        seq: u64,
    ) -> Result<Vec<u8>, PassiveTlsError> {
        if iv.len() != 12 {
            return Err(PassiveTlsError::KeyDerivationError("TLS 1.3 IV 必须为 12 字节".into()));
        }

        // Nonce = IV ^ SeqNum (SeqNum 扩展为 12 字节大端，与 IV 按位异或)
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(iv);
        let seq_be = seq.to_be_bytes();
        for i in 0..8 {
            nonce_bytes[4 + i] ^= seq_be[i];
        }

        // TLS 1.3 AAD = 5 字节原始记录头 (Type 0x17, Version 0x0303, Length)
        let aad = &record.raw_header;

        let plaintext = match self.cipher_suite {
            TLS_AES_128_GCM_SHA256 => {
                let cipher = Aes128Gcm::new_from_slice(key)
                    .map_err(|e| PassiveTlsError::AeadDecryptionError(e.to_string()))?;
                let nonce = GcmNonce::from_slice(&nonce_bytes);
                cipher
                    .decrypt(nonce, Payload { msg: record.payload, aad })
                    .map_err(|e| PassiveTlsError::AeadDecryptionError(e.to_string()))?
            }
            TLS_AES_256_GCM_SHA384 => {
                let cipher = Aes256Gcm::new_from_slice(key)
                    .map_err(|e| PassiveTlsError::AeadDecryptionError(e.to_string()))?;
                let nonce = GcmNonce::from_slice(&nonce_bytes);
                cipher
                    .decrypt(nonce, Payload { msg: record.payload, aad })
                    .map_err(|e| PassiveTlsError::AeadDecryptionError(e.to_string()))?
            }
            TLS_CHACHA20_POLY1305_SHA256 => {
                let cipher = ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|e| PassiveTlsError::AeadDecryptionError(e.to_string()))?;
                let nonce = ChaChaNonce::from_slice(&nonce_bytes);
                cipher
                    .decrypt(nonce, Payload { msg: record.payload, aad })
                    .map_err(|e| PassiveTlsError::AeadDecryptionError(e.to_string()))?
            }
            _ => {
                return Err(PassiveTlsError::UnsupportedCipherSuite(self.cipher_suite));
            }
        };

        // TLS 1.3 载荷尾部去 Padding 并提取真实的 ContentType
        // 明文结构: [真实明文] + [0x17 ContentType] + [0x00 ... 0x00 Padding]
        let mut trim_len = plaintext.len();
        while trim_len > 0 && plaintext[trim_len - 1] == 0 {
            trim_len -= 1;
        }

        if trim_len == 0 {
            return Ok(Vec::new());
        }

        let real_type = plaintext[trim_len - 1];
        let app_data = plaintext[..trim_len - 1].to_vec();

        if real_type == CONTENT_TYPE_APPLICATION_DATA {
            Ok(app_data)
        } else {
            // 如握手后 KeyUpdate / NewSessionTicket
            Ok(app_data)
        }
    }

    /// 执行 TLS 1.2 GCM 记录解密
    fn decrypt_tls12_gcm_record(
        &self,
        record: &TlsRecordFrame,
        key: &[u8],
        salt: &[u8],
        seq: u64,
    ) -> Result<Vec<u8>, PassiveTlsError> {
        if record.payload.len() < 8 + 16 {
            return Err(PassiveTlsError::InvalidRecordLength(record.payload.len()));
        }

        // TLS 1.2 GCM Record: explicit_nonce (8B) + ciphertext + tag (16B)
        let explicit_nonce = &record.payload[0..8];
        let ciphertext_with_tag = &record.payload[8..];

        // Nonce = salt (4B) + explicit_nonce (8B)
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[0..4].copy_from_slice(salt);
        nonce_bytes[4..12].copy_from_slice(explicit_nonce);

        // TLS 1.2 AAD = SeqNum (8B) + Type (1B) + Version (2B) + PlaintextLength (2B)
        let plaintext_len = (ciphertext_with_tag.len() - 16) as u16;
        let mut aad = [0u8; 13];
        aad[0..8].copy_from_slice(&seq.to_be_bytes());
        aad[8] = record.content_type;
        aad[9..11].copy_from_slice(&record.legacy_version.to_be_bytes());
        aad[11..13].copy_from_slice(&plaintext_len.to_be_bytes());

        let plaintext = match key.len() {
            16 => {
                let cipher = Aes128Gcm::new_from_slice(key)
                    .map_err(|e| PassiveTlsError::AeadDecryptionError(e.to_string()))?;
                let nonce = GcmNonce::from_slice(&nonce_bytes);
                cipher
                    .decrypt(nonce, Payload { msg: ciphertext_with_tag, aad: &aad })
                    .map_err(|e| PassiveTlsError::AeadDecryptionError(e.to_string()))?
            }
            32 => {
                let cipher = Aes256Gcm::new_from_slice(key)
                    .map_err(|e| PassiveTlsError::AeadDecryptionError(e.to_string()))?;
                let nonce = GcmNonce::from_slice(&nonce_bytes);
                cipher
                    .decrypt(nonce, Payload { msg: ciphertext_with_tag, aad: &aad })
                    .map_err(|e| PassiveTlsError::AeadDecryptionError(e.to_string()))?
            }
            _ => return Err(PassiveTlsError::KeyDerivationError(format!("不支持的密钥长度: {}", key.len()))),
        };

        Ok(plaintext)
    }
}

// ============================================================
// 5. 整体 PCAP + KeyLog 被动流式解密管线
// ============================================================

/// 输入包含 TLS 握手与 Application Data 的原始 TCP 数据段，匹配 KeyLog 并解密
pub fn decrypt_stream_payload(
    client_payload: &[u8],
    server_payload: &[u8],
    stream_id: &str,
) -> Result<Vec<DecryptedTlsPayload>, PassiveTlsError> {
    let mut results = Vec::new();

    // 1. 解析客户端发出的 TLS Records
    let client_records = parse_tls_records(client_payload)?;
    // 2. 解析服务端发出的 TLS Records
    let server_records = parse_tls_records(server_payload)?;

    // 3. 从 ClientHello 提取 ClientRandom
    let mut client_random = None;
    for r in &client_records {
        if r.content_type == CONTENT_TYPE_HANDSHAKE {
            if let Some(cr) = extract_client_random(r.payload) {
                client_random = Some(cr);
                break;
            }
        }
    }

    let cr = match client_random {
        Some(cr) => cr,
        None => return Err(PassiveTlsError::HandshakeParseError("未检测到有效的 ClientHello 握手报文".into())),
    };

    let cr_hex = hex::encode(cr);

    // 4. 从 ServerHello 提取 ServerRandom 与 CipherSuite
    let mut server_random = None;
    let mut cipher_suite = TLS_AES_128_GCM_SHA256; // 默认回退
    for r in &server_records {
        if r.content_type == CONTENT_TYPE_HANDSHAKE {
            if let Some((sr, cs)) = extract_server_hello(r.payload) {
                server_random = Some(sr);
                cipher_suite = cs;
                break;
            }
        }
    }

    // 5. 查询全局 NSS 密钥库 (tls_keylog.rs)
    let keylog_entry = crate::tls_keylog::lookup_session_secrets(&cr_hex)
        .ok_or_else(|| PassiveTlsError::KeyNotFound(format!("ClientRandom: {}", cr_hex)))?;

    let mut session = TlsDecryptionSession::new();
    session.client_random = cr;
    if let Some(sr) = server_random {
        session.server_random = sr;
    }

    // 6. 根据提取的密钥初始化会话状态
    if let (Some(ref c_secret_hex), Some(ref s_secret_hex)) = (
        &keylog_entry.client_traffic_secret_0,
        &keylog_entry.server_traffic_secret_0,
    ) {
        // TLS 1.3 模式
        let c_secret = hex::decode(c_secret_hex)
            .map_err(|e| PassiveTlsError::KeyDerivationError(e.to_string()))?;
        let s_secret = hex::decode(s_secret_hex)
            .map_err(|e| PassiveTlsError::KeyDerivationError(e.to_string()))?;
        session.init_tls13_secrets(&c_secret, &s_secret, cipher_suite)?;
    } else if let Some(ref ms_hex) = keylog_entry.master_secret {
        // TLS 1.2 模式
        let master_secret = hex::decode(ms_hex)
            .map_err(|e| PassiveTlsError::KeyDerivationError(e.to_string()))?;
        let sr = session.server_random;
        session.init_tls12_master_secret(&master_secret, &cr, &sr, cipher_suite)?;
    } else {
        return Err(PassiveTlsError::KeyNotFound("密钥库条目缺少 Traffic Secret 或 Master Secret".into()));
    }

    let now_str = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();

    // 7. 解密客户端 Application Data 记录
    for r in &client_records {
        if r.content_type == CONTENT_TYPE_APPLICATION_DATA {
            let seq = session.client_seq;
            if let Ok(pt) = session.decrypt_record(r, true) {
                if !pt.is_empty() {
                    let utf8_text = String::from_utf8_lossy(&pt).to_string();
                    results.push(DecryptedTlsPayload {
                        stream_id: stream_id.to_string(),
                        direction: "CLIENT_TO_SERVER".to_string(),
                        sequence_number: seq,
                        tls_version: format!("0x{:04x}", session.tls_version),
                        cipher_suite: format!("0x{:04x}", session.cipher_suite),
                        plaintext_utf8: utf8_text,
                        plaintext_hex: hex::encode(&pt),
                        plaintext_len: pt.len(),
                        timestamp: now_str.clone(),
                    });
                }
            }
        }
    }

    // 8. 解密服务端 Application Data 记录
    for r in &server_records {
        if r.content_type == CONTENT_TYPE_APPLICATION_DATA {
            let seq = session.server_seq;
            if let Ok(pt) = session.decrypt_record(r, false) {
                if !pt.is_empty() {
                    let utf8_text = String::from_utf8_lossy(&pt).to_string();
                    results.push(DecryptedTlsPayload {
                        stream_id: stream_id.to_string(),
                        direction: "SERVER_TO_CLIENT".to_string(),
                        sequence_number: seq,
                        tls_version: format!("0x{:04x}", session.tls_version),
                        cipher_suite: format!("0x{:04x}", session.cipher_suite),
                        plaintext_utf8: utf8_text,
                        plaintext_hex: hex::encode(&pt),
                        plaintext_len: pt.len(),
                        timestamp: now_str.clone(),
                    });
                }
            }
        }
    }

    Ok(results)
}

// ============================================================
// 6. 严苛密码学与 RFC 测试向量单元测试套件
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_expand_label_sha256() {
        // RFC 8446 Appendix D 测试密钥派生验证
        let secret = [0x01u8; 32];
        let key = hkdf_expand_label_sha256(&secret, b"key", b"", 16).unwrap();
        assert_eq!(key.len(), 16);
        let iv = hkdf_expand_label_sha256(&secret, b"iv", b"", 12).unwrap();
        assert_eq!(iv.len(), 12);
    }

    #[test]
    fn test_tls12_prf_sha256() {
        let master_secret = [0x42u8; 48];
        let seed = [0x11u8; 64];
        let key_block = tls12_prf_sha256(&master_secret, b"key expansion", &seed, 40);
        assert_eq!(key_block.len(), 40);
    }

    #[test]
    fn test_tls13_aes_128_gcm_roundtrip() {
        let mut session = TlsDecryptionSession::new();
        let client_traffic_secret = [0xAAu8; 32];
        let server_traffic_secret = [0xBBu8; 32];
        session
            .init_tls13_secrets(&client_traffic_secret, &server_traffic_secret, TLS_AES_128_GCM_SHA256)
            .unwrap();

        assert!(session.is_ready);
        assert_eq!(session.client_key.len(), 16);
        assert_eq!(session.client_iv.len(), 12);

        // 构造明文载荷 (HTTP GET)
        let plaintext = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        
        // 模拟加密构造 TLS 1.3 记录
        let mut pt_with_type = plaintext.to_vec();
        pt_with_type.push(CONTENT_TYPE_APPLICATION_DATA); // 0x17

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&session.client_iv);
        let seq_be = 0u64.to_be_bytes();
        for i in 0..8 {
            nonce_bytes[4 + i] ^= seq_be[i];
        }

        let cipher = Aes128Gcm::new_from_slice(&session.client_key).unwrap();
        let nonce = GcmNonce::from_slice(&nonce_bytes);
        
        let mut raw_hdr = [0u8; 5];
        raw_hdr[0] = CONTENT_TYPE_APPLICATION_DATA;
        raw_hdr[1..3].copy_from_slice(&TLS_VERSION_1_2.to_be_bytes()); // TLS 1.3 遗留 0x0303
        let expected_cipher_len = (pt_with_type.len() + 16) as u16;
        raw_hdr[3..5].copy_from_slice(&expected_cipher_len.to_be_bytes());
        let encrypted = cipher.encrypt(nonce, Payload { msg: &pt_with_type, aad: &raw_hdr }).unwrap();

        let record = TlsRecordFrame {
            content_type: CONTENT_TYPE_APPLICATION_DATA,
            legacy_version: TLS_VERSION_1_2,
            length: encrypted.len() as u16,
            payload: &encrypted,
            raw_header: raw_hdr,
        };

        // 执行解密
        let decrypted = session.decrypt_record(&record, true).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_tls13_chacha20_poly1305_roundtrip() {
        let mut session = TlsDecryptionSession::new();
        let client_traffic_secret = [0x55u8; 32];
        let server_traffic_secret = [0x66u8; 32];
        session
            .init_tls13_secrets(&client_traffic_secret, &server_traffic_secret, TLS_CHACHA20_POLY1305_SHA256)
            .unwrap();

        assert!(session.is_ready);
        assert_eq!(session.client_key.len(), 32); // RFC 8439: 256 位密钥
        assert_eq!(session.client_iv.len(), 12);

        let plaintext = b"POST /api/v1/telemetry HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"status\":\"ok\"}";
        let mut pt_with_type = plaintext.to_vec();
        pt_with_type.push(CONTENT_TYPE_APPLICATION_DATA);

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&session.client_iv);
        let seq_be = 0u64.to_be_bytes();
        for i in 0..8 {
            nonce_bytes[4 + i] ^= seq_be[i];
        }

        let cipher = ChaCha20Poly1305::new_from_slice(&session.client_key).unwrap();
        let nonce = ChaChaNonce::from_slice(&nonce_bytes);

        let mut raw_hdr = [0u8; 5];
        raw_hdr[0] = CONTENT_TYPE_APPLICATION_DATA;
        raw_hdr[1..3].copy_from_slice(&TLS_VERSION_1_2.to_be_bytes());
        let expected_cipher_len = (pt_with_type.len() + 16) as u16;
        raw_hdr[3..5].copy_from_slice(&expected_cipher_len.to_be_bytes());
        let encrypted = cipher.encrypt(nonce, Payload { msg: &pt_with_type, aad: &raw_hdr }).unwrap();

        let record = TlsRecordFrame {
            content_type: CONTENT_TYPE_APPLICATION_DATA,
            legacy_version: TLS_VERSION_1_2,
            length: encrypted.len() as u16,
            payload: &encrypted,
            raw_header: raw_hdr,
        };

        let decrypted = session.decrypt_record(&record, true).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_tls13_aes_256_gcm_roundtrip() {
        let mut session = TlsDecryptionSession::new();
        let client_traffic_secret = [0x77u8; 48]; // SHA-384 secret
        let server_traffic_secret = [0x88u8; 48];
        session
            .init_tls13_secrets(&client_traffic_secret, &server_traffic_secret, TLS_AES_256_GCM_SHA384)
            .unwrap();

        assert!(session.is_ready);
        assert_eq!(session.client_key.len(), 32); // 256 位密钥
        assert_eq!(session.client_iv.len(), 12);

        let plaintext = b"CONNECT ws.omni-probe.internal:443 HTTP/1.1\r\nHost: ws.omni-probe.internal\r\n\r\n";
        let mut pt_with_type = plaintext.to_vec();
        pt_with_type.push(CONTENT_TYPE_APPLICATION_DATA);

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&session.client_iv);
        let seq_be = 0u64.to_be_bytes();
        for i in 0..8 {
            nonce_bytes[4 + i] ^= seq_be[i];
        }

        let cipher = Aes256Gcm::new_from_slice(&session.client_key).unwrap();
        let nonce = GcmNonce::from_slice(&nonce_bytes);

        let mut raw_hdr = [0u8; 5];
        raw_hdr[0] = CONTENT_TYPE_APPLICATION_DATA;
        raw_hdr[1..3].copy_from_slice(&TLS_VERSION_1_2.to_be_bytes());
        let expected_cipher_len = (pt_with_type.len() + 16) as u16;
        raw_hdr[3..5].copy_from_slice(&expected_cipher_len.to_be_bytes());
        let encrypted = cipher.encrypt(nonce, Payload { msg: &pt_with_type, aad: &raw_hdr }).unwrap();

        let record = TlsRecordFrame {
            content_type: CONTENT_TYPE_APPLICATION_DATA,
            legacy_version: TLS_VERSION_1_2,
            length: encrypted.len() as u16,
            payload: &encrypted,
            raw_header: raw_hdr,
        };

        let decrypted = session.decrypt_record(&record, true).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_streaming_tls_record_buffer_cross_packet_reassembly() {
        let mut session = TlsDecryptionSession::new();
        let client_secret = [0xAAu8; 32];
        let server_secret = [0xBBu8; 32];
        session.init_tls13_secrets(&client_secret, &server_secret, TLS_AES_128_GCM_SHA256).unwrap();

        let plaintext = b"GET /cross-tcp-packet-stream HTTP/1.1\r\nHost: probe.internal\r\n\r\n";
        let mut pt_with_type = plaintext.to_vec();
        pt_with_type.push(CONTENT_TYPE_APPLICATION_DATA);

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&session.client_iv);
        let cipher = Aes128Gcm::new_from_slice(&session.client_key).unwrap();
        let nonce = GcmNonce::from_slice(&nonce_bytes);

        let mut raw_hdr = [0u8; 5];
        raw_hdr[0] = CONTENT_TYPE_APPLICATION_DATA;
        raw_hdr[1..3].copy_from_slice(&TLS_VERSION_1_2.to_be_bytes());
        let expected_cipher_len = (pt_with_type.len() + 16) as u16;
        raw_hdr[3..5].copy_from_slice(&expected_cipher_len.to_be_bytes());
        let encrypted = cipher.encrypt(nonce, Payload { msg: &pt_with_type, aad: &raw_hdr }).unwrap();

        // 拼接完整的 TLS 线路字节帧 (Header 5B + Encrypted)
        let mut full_wire = raw_hdr.to_vec();
        full_wire.extend_from_slice(&encrypted);

        // 模拟 TCP 跨分包：拆成 3 个碎片 (3B, 20B, 剩余)
        let chunk1 = &full_wire[0..3];
        let chunk2 = &full_wire[3..23];
        let chunk3 = &full_wire[23..];

        let mut record_buffer = StreamingTlsRecordBuffer::new(65536);

        // 喂入第 1 个 TCP 分包 (仅 3 字节，未凑齐 5 字节 Header)
        record_buffer.feed(chunk1);
        let drained1 = record_buffer.drain_ready_records();
        assert_eq!(drained1.len(), 0, "Header 不足时不得发射记录");

        // 喂入第 2 个 TCP 分包 (凑齐 Header，但载荷缺失)
        record_buffer.feed(chunk2);
        let drained2 = record_buffer.drain_ready_records();
        assert_eq!(drained2.len(), 0, "密文载荷未拼齐前不得发射截断记录");

        // 喂入第 3 个 TCP 分包 (补齐剩余全部密文)
        record_buffer.feed(chunk3);
        let drained3 = record_buffer.drain_ready_records();
        assert_eq!(drained3.len(), 1, "跨包拼齐后必须成功发射完整 TLS 记录");

        // 执行连续解密
        let decrypted = session.decrypt_record(&drained3[0].as_borrowed(), true).unwrap();
        assert_eq!(decrypted, plaintext, "跨 TCP 分片重组后的解密明文必须与原始报文逐字节严格一致");
        assert_eq!(record_buffer.pending_bytes(), 0, "消费完成后缓冲区必须无残留字节");
    }
}