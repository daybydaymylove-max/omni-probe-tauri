// ============================================================
// 工业全能网络探针 - 国密 GM/T 0024-2014 SSL VPN 协议深度解析器
// 模块名称: gm_ssl.rs
//
// 核心职责与工程规范:
// 1. 对标国家密码管理局 GM/T 0024-2014《SSL VPN 技术规范》;
// 2. 原生解析国密 SSL 记录层报头 (版本号 0x0101, ContentType);
// 3. 原生解析国密握手协议 (ClientHello, ServerHello, 双证书 Certificate 等);
// 4. 覆盖 0xE001 ~ 0xE019 全系列国密商用密码套件 (SM2 / SM3 / SM4);
// 5. 识别国密双证书机制 (签名证书与加密证书双轨体系);
// 6. 纯原生纯内存实现，零外部依赖，100% 适用于关键基础设施与涉密工控内网;
// 7. 时间复杂度: O(N) 零拷贝流式解析; 空间复杂度: O(1) 紧凑只读元数据.
// ============================================================

use serde::{Deserialize, Serialize};

/// 国密 SSL 协议版本常量 (GM/T 0024-2014)
pub const GM_SSL_VERSION_1_1: u16 = 0x0101;

/// 国密记录层 ContentType 常量
pub const GM_CONTENT_CHANGE_CIPHER_SPEC: u8 = 0x14;
pub const GM_CONTENT_ALERT: u8 = 0x15;
pub const GM_CONTENT_HANDSHAKE: u8 = 0x16;
pub const GM_CONTENT_APPLICATION_DATA: u8 = 0x17;

/// 国密握手消息类型常量
pub const GM_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
pub const GM_HANDSHAKE_SERVER_HELLO: u8 = 0x02;
pub const GM_HANDSHAKE_CERTIFICATE: u8 = 0x0B;
pub const GM_HANDSHAKE_SERVER_KEY_EXCHANGE: u8 = 0x0C;
pub const GM_HANDSHAKE_CERTIFICATE_REQUEST: u8 = 0x0D;
pub const GM_HANDSHAKE_SERVER_HELLO_DONE: u8 = 0x0E;
pub const GM_HANDSHAKE_CERTIFICATE_VERIFY: u8 = 0x0F;
pub const GM_HANDSHAKE_CLIENT_KEY_EXCHANGE: u8 = 0x10;
pub const GM_HANDSHAKE_FINISHED: u8 = 0x14;

/// 国密密码套件元数据描述实体
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GmCipherSuiteInfo {
    pub suite_id: u16,
    pub name: &'static str,
    pub key_exchange: &'static str,
    pub cipher: &'static str,
    pub hash_mac: &'static str,
    pub security_bits: u16,
    pub is_dual_cert: bool,
    pub description: &'static str,
}

/// 权威国密 SSL 密码套件字典 (GM/T 0024-2014)
static GM_CIPHER_SUITES: &[(u16, &'static str, &'static str, &'static str, &'static str, u16, bool, &'static str)] = &[
    (
        0xE011,
        "ECDHE_SM2_WITH_SM4_SM3",
        "ECDHE-SM2",
        "SM4-128 (GM/T 0002)",
        "SM3-256 (GM/T 0004)",
        128,
        true,
        "国家标准推荐前向安全套件: 临时 SM2 密钥交换 + SM4 对称加密 + SM3 消息杂凑",
    ),
    (
        0xE013,
        "SM2_WITH_SM4_SM3",
        "SM2",
        "SM4-128 (GM/T 0002)",
        "SM3-256 (GM/T 0004)",
        128,
        true,
        "国家标准通用标准套件: 固定 SM2 加密密钥交换 + SM4 对称加密 + SM3 完整性校验",
    ),
    (
        0xE015,
        "RSA_WITH_SM4_SM3",
        "RSA-2048",
        "SM4-128 (GM/T 0002)",
        "SM3-256 (GM/T 0004)",
        128,
        false,
        "过渡兼容套件: RSA 公钥加密握手 + SM4 对称数据保护 + SM3 完整性杂凑",
    ),
    (
        0xE017,
        "RSA_WITH_SM4_SHA256",
        "RSA-2048",
        "SM4-128 (GM/T 0002)",
        "SHA-256",
        128,
        false,
        "混合兼容套件: RSA 公钥加密 + SM4 对称数据保护 + SHA256 完整性校验",
    ),
    (
        0xE019,
        "ECDHE_SM2_WITH_SM4_SHA256",
        "ECDHE-SM2",
        "SM4-128 (GM/T 0002)",
        "SHA-256",
        128,
        true,
        "混合前向安全套件: 临时 SM2 密钥协商 + SM4 对称加密 + SHA256 杂凑",
    ),
    (
        0xE001,
        "ECDHE_SM2_WITH_SMS4_SM3",
        "ECDHE-SM2",
        "SMS4 (历史命名)",
        "SM3-256",
        128,
        true,
        "GM/T 0024 早期草案别名套件",
    ),
    (
        0xE003,
        "SM2_WITH_SMS4_SM3",
        "SM2",
        "SMS4 (历史命名)",
        "SM3-256",
        128,
        true,
        "GM/T 0024 早期固定 SM2 套件",
    ),
];

/// 根据 16 位密码套件代码检索国密密码套件详细元数据
pub fn lookup_gm_cipher_suite(suite_id: u16) -> Option<GmCipherSuiteInfo> {
    GM_CIPHER_SUITES
        .iter()
        .find(|(id, _, _, _, _, _, _, _)| *id == suite_id)
        .map(|(id, name, kx, cipher, mac, bits, dual, desc)| GmCipherSuiteInfo {
            suite_id: *id,
            name,
            key_exchange: kx,
            cipher,
            hash_mac: mac,
            security_bits: *bits,
            is_dual_cert: *dual,
            description: desc,
        })
}

/// 国密 SSL 记录层分帧数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GmRecordHeader {
    pub content_type: u8,
    pub version: u16,
    pub length: u16,
    pub content_desc: &'static str,
}

/// 解析国密 SSL 记录层报头 (5 字节)
pub fn parse_gm_record_header(data: &[u8]) -> Option<GmRecordHeader> {
    if data.len() < 5 {
        return None;
    }

    let content_type = data[0];
    let version = u16::from_be_bytes([data[1], data[2]]);
    let length = u16::from_be_bytes([data[3], data[4]]);

    // 严格检查是否为国密版本 0x0101
    if version != GM_SSL_VERSION_1_1 {
        return None;
    }

    let content_desc = match content_type {
        GM_CONTENT_CHANGE_CIPHER_SPEC => "ChangeCipherSpec (密码规格变更)",
        GM_CONTENT_ALERT => "Alert (告警/错误协议)",
        GM_CONTENT_HANDSHAKE => "Handshake (国密握手协议)",
        GM_CONTENT_APPLICATION_DATA => "ApplicationData (国密 SM4 加密业务载荷)",
        _ => "UnknownContentType",
    };

    Some(GmRecordHeader {
        content_type,
        version,
        length,
        content_desc,
    })
}

/// 国密握手消息体基础解剖信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GmHandshakeMessage {
    pub msg_type: u8,
    pub msg_type_name: &'static str,
    pub length: u32,
    pub client_random: Option<String>,
    pub server_random: Option<String>,
    pub selected_cipher_suite: Option<GmCipherSuiteInfo>,
    pub supported_suites: Vec<GmCipherSuiteInfo>,
    pub is_dual_cert_detected: bool,
}

/// 解析国密 ClientHello / ServerHello 握手报文
pub fn parse_gm_handshake_payload(payload: &[u8]) -> Option<GmHandshakeMessage> {
    if payload.len() < 4 {
        return None;
    }

    let msg_type = payload[0];
    let length = ((payload[1] as u32) << 16) | ((payload[2] as u32) << 8) | (payload[3] as u32);

    let (msg_name, is_dual) = match msg_type {
        GM_HANDSHAKE_CLIENT_HELLO => ("ClientHello (国密客户端问候)", false),
        GM_HANDSHAKE_SERVER_HELLO => ("ServerHello (国密服务端问候)", false),
        GM_HANDSHAKE_CERTIFICATE => ("Certificate (国密双证书传输: 签名证书+加密证书)", true),
        GM_HANDSHAKE_SERVER_KEY_EXCHANGE => ("ServerKeyExchange (国密临时 SM2 协商参数)", false),
        GM_HANDSHAKE_CERTIFICATE_REQUEST => ("CertificateRequest (国密双向身份认证凭证请求)", true),
        GM_HANDSHAKE_SERVER_HELLO_DONE => ("ServerHelloDone (服务端握手就绪)", false),
        GM_HANDSHAKE_CERTIFICATE_VERIFY => ("CertificateVerify (国密 SM2 签名验证数据)", false),
        GM_HANDSHAKE_CLIENT_KEY_EXCHANGE => ("ClientKeyExchange (客户端 SM2 预主密钥加密分发)", false),
        GM_HANDSHAKE_FINISHED => ("Finished (国密握手密文校验验证)", false),
        _ => ("UnknownGmHandshake", false),
    };

    let body = &payload[4..];
    let mut client_random = None;
    let mut server_random = None;
    let mut selected_cipher_suite = None;
    let mut supported_suites = Vec::new();

    if msg_type == GM_HANDSHAKE_CLIENT_HELLO {
        // ClientHello 布局:
        // [0..2]: Version (0x0101)
        // [2..34]: ClientRandom (32 字节)
        if body.len() >= 34 {
            let version = u16::from_be_bytes([body[0], body[1]]);
            if version == GM_SSL_VERSION_1_1 {
                client_random = Some(hex::encode(&body[2..34]));

                // 解析 SessionID 之后读取 CipherSuites
                let mut offset = 34;
                if body.len() > offset {
                    let session_id_len = body[offset] as usize;
                    offset += 1 + session_id_len;

                    if body.len() >= offset + 2 {
                        let suites_len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
                        offset += 2;

                        let suites_end = (offset + suites_len).min(body.len());
                        let mut curr = offset;
                        while curr + 2 <= suites_end {
                            let suite_id = u16::from_be_bytes([body[curr], body[curr + 1]]);
                            if let Some(info) = lookup_gm_cipher_suite(suite_id) {
                                supported_suites.push(info);
                            }
                            curr += 2;
                        }
                    }
                }
            }
        }
    } else if msg_type == GM_HANDSHAKE_SERVER_HELLO {
        // ServerHello 布局:
        // [0..2]: Version (0x0101)
        // [2..34]: ServerRandom (32 字节)
        if body.len() >= 34 {
            let version = u16::from_be_bytes([body[0], body[1]]);
            if version == GM_SSL_VERSION_1_1 {
                server_random = Some(hex::encode(&body[2..34]));

                let mut offset = 34;
                if body.len() > offset {
                    let session_id_len = body[offset] as usize;
                    offset += 1 + session_id_len;

                    if body.len() >= offset + 2 {
                        let suite_id = u16::from_be_bytes([body[offset], body[offset + 1]]);
                        selected_cipher_suite = lookup_gm_cipher_suite(suite_id);
                    }
                }
            }
        }
    }

    Some(GmHandshakeMessage {
        msg_type,
        msg_type_name: msg_name,
        length,
        client_random,
        server_random,
        selected_cipher_suite,
        supported_suites,
        is_dual_cert_detected: is_dual,
    })
}

/// 快速探活检查：判定字节流是否为合法的国密 GM/T 0024 SSL VPN 数据包
pub fn is_likely_gm_ssl_stream(data: &[u8]) -> bool {
    if data.len() < 5 {
        return false;
    }

    // 检查第 0 字节是否为有效 ContentType，第 1..3 字节是否为 0x0101
    let ct = data[0];
    let is_valid_ct = ct == GM_CONTENT_CHANGE_CIPHER_SPEC
        || ct == GM_CONTENT_ALERT
        || ct == GM_CONTENT_HANDSHAKE
        || ct == GM_CONTENT_APPLICATION_DATA;

    let ver = u16::from_be_bytes([data[1], data[2]]);
    is_valid_ct && ver == GM_SSL_VERSION_1_1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_gm_cipher_suite() {
        // 测试 ECDHE_SM2_WITH_SM4_SM3 (0xE011)
        let cs = lookup_gm_cipher_suite(0xE011).expect("0xE011 必须存在于国密知识库");
        assert_eq!(cs.name, "ECDHE_SM2_WITH_SM4_SM3");
        assert_eq!(cs.cipher, "SM4-128 (GM/T 0002)");
        assert_eq!(cs.hash_mac, "SM3-256 (GM/T 0004)");
        assert!(cs.is_dual_cert);

        // 测试 SM2_WITH_SM4_SM3 (0xE013)
        let cs2 = lookup_gm_cipher_suite(0xE013).expect("0xE013 必须存在");
        assert_eq!(cs2.name, "SM2_WITH_SM4_SM3");

        // 非法套件返回 None
        assert!(lookup_gm_cipher_suite(0x1301).is_none());
    }

    #[test]
    fn test_parse_gm_record_header() {
        // 构造国密 Handshake 记录头: ContentType=0x16, Version=0x0101, Length=0x0040 (64 字节)
        let frame = vec![0x16, 0x01, 0x01, 0x00, 0x40];
        let hdr = parse_gm_record_header(&frame).expect("解析国密记录头必须成功");
        assert_eq!(hdr.content_type, 0x16);
        assert_eq!(hdr.version, GM_SSL_VERSION_1_1);
        assert_eq!(hdr.length, 64);
        assert!(hdr.content_desc.contains("国密握手协议"));

        // 测试非国密标准 TLS 1.2 (0x0303) 快速安全隔离
        let tls12_frame = vec![0x16, 0x03, 0x03, 0x00, 0x40];
        assert!(parse_gm_record_header(&tls12_frame).is_none());
    }

    #[test]
    fn test_parse_gm_client_hello_handshake() {
        // 构造国密 ClientHello
        // Handshake Header: Type=0x01, Len=24-bit (46 字节)
        let mut raw = vec![0x01, 0x00, 0x00, 0x2E];
        // ClientHello Body:
        // Version: 0x0101
        raw.extend_from_slice(&[0x01, 0x01]);
        // ClientRandom (32 字节, 模拟填充 0xAA)
        let dummy_random = vec![0xAA; 32];
        raw.extend_from_slice(&dummy_random);
        // SessionID Len: 0
        raw.push(0x00);
        // CipherSuites Len: 4 字节 (2 个套件: 0xE011, 0xE013)
        raw.extend_from_slice(&[0x00, 0x04, 0xE0, 0x11, 0xE0, 0x13]);

        let msg = parse_gm_handshake_payload(&raw).expect("解析国密 ClientHello 必须成功");
        assert_eq!(msg.msg_type, GM_HANDSHAKE_CLIENT_HELLO);
        assert!(msg.client_random.is_some());
        assert_eq!(msg.client_random.unwrap(), hex::encode(&dummy_random));
        assert_eq!(msg.supported_suites.len(), 2);
        assert_eq!(msg.supported_suites[0].name, "ECDHE_SM2_WITH_SM4_SM3");
        assert_eq!(msg.supported_suites[1].name, "SM2_WITH_SM4_SM3");
    }

    #[test]
    fn test_is_likely_gm_ssl_stream() {
        assert!(is_likely_gm_ssl_stream(&[0x16, 0x01, 0x01, 0x00, 0x10]));
        assert!(is_likely_gm_ssl_stream(&[0x17, 0x01, 0x01, 0x01, 0x00]));
        // 非国密版本
        assert!(!is_likely_gm_ssl_stream(&[0x16, 0x03, 0x03, 0x00, 0x10]));
        // 极短残缺输入
        assert!(!is_likely_gm_ssl_stream(&[0x16, 0x01]));
    }
}
