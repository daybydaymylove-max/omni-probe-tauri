use once_cell::sync::Lazy;
use regex::Regex;
use serde::Deserialize;
use std::sync::{Arc, RwLock};

// ============================================================
// 深度包检测引擎 v2.1 (DPI Engine with Dynamic Dictionary)
// 优先级：动态JSON字典(热加载) > 端口精确匹配 > 载荷魔数 > 正则文本
// 协议库：35+ 协议（工业控制 + 标准应用层 + 水文环保协议）
// 时间复杂度: O(D+P) D=动态规则数, P=静态规则数（均为小常数）
// ============================================================

// ---- 动态字典数据结构 ----

#[derive(Debug, Deserialize, Clone)]
pub struct PortRule {
    pub port:  u16,
    pub proto: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct MagicRule {
    pub offset: usize,
    pub bytes:  String,  // hex 字符串，如 "1603"
    pub length: usize,
    pub proto:  String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RegexRule {
    pub pattern: String,
    pub proto:   String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DissectorField {
    pub field:     String,
    pub offset:    usize,
    pub length:    usize,
    #[serde(default = "default_data_type")]
    pub data_type: String, // "uint", "hex", "string"
    #[serde(default)]
    pub note:      String,
}

fn default_data_type() -> String {
    "uint".to_string()
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct DynSignatures {
    #[serde(default)]
    pub port_rules:       Vec<PortRule>,
    #[serde(default)]
    pub magic_rules:      Vec<MagicRule>,
    #[serde(default)]
    pub regex_rules:      Vec<RegexRule>,
    #[serde(default)]
    pub dissector_rules:  std::collections::HashMap<String, Vec<DissectorField>>,
}

/// 全局动态字典（RwLock 保证多线程安全的读写分离）
/// 写操作：文件热加载时独占写锁（极低频率，毫秒级）
/// 读操作：每帧 DPI 调用时共享读锁（高频，接近零开销）
static DYN_DICT: Lazy<Arc<RwLock<DynSignatures>>> =
    Lazy::new(|| Arc::new(RwLock::new(DynSignatures::default())));

/// 全局动态正则缓存（避免每次 DPI 调用时重复编译 Regex）
static DYN_REGEX_CACHE: Lazy<Arc<RwLock<Vec<(Regex, String)>>>> =
    Lazy::new(|| Arc::new(RwLock::new(Vec::new())));

/// 业务数据字典解码器 (Dictionary Dissector)
/// 时间复杂度: O(K), K 为协议定义的字段数 (小常数 <= 10)
/// 空间复杂度: O(K)
pub fn dissect_payload(protocol: &str, payload: &[u8]) -> std::collections::HashMap<String, serde_json::Value> {
    let mut result = std::collections::HashMap::new();

    // 国密 GM/T 0024-2014 SSL VPN 协议深度解剖 (对标商用密码国家标准)
    if protocol.to_uppercase() == "GM_SSL" || (payload.len() >= 5 && crate::gm_ssl::is_likely_gm_ssl_stream(payload)) {
        if let Some(hdr) = crate::gm_ssl::parse_gm_record_header(payload) {
            result.insert("gm_ssl_content_type".into(), serde_json::json!(hdr.content_type));
            result.insert("gm_ssl_content_desc".into(), serde_json::json!(hdr.content_desc));
            result.insert("gm_ssl_version".into(), serde_json::json!("GM/T 0024-2014 (0x0101)"));
            result.insert("gm_ssl_record_length".into(), serde_json::json!(hdr.length));

            if hdr.content_type == crate::gm_ssl::GM_CONTENT_HANDSHAKE && payload.len() >= 9 {
                if let Some(handshake) = crate::gm_ssl::parse_gm_handshake_payload(&payload[5..]) {
                    result.insert("gm_handshake_type".into(), serde_json::json!(handshake.msg_type));
                    result.insert("gm_handshake_name".into(), serde_json::json!(handshake.msg_type_name));
                    result.insert("gm_is_dual_cert".into(), serde_json::json!(handshake.is_dual_cert_detected));

                    if let Some(cr) = handshake.client_random {
                        result.insert("gm_client_random".into(), serde_json::json!(cr));
                    }
                    if let Some(sr) = handshake.server_random {
                        result.insert("gm_server_random".into(), serde_json::json!(sr));
                    }
                    if let Some(suite) = handshake.selected_cipher_suite {
                        result.insert("gm_selected_cipher_suite".into(), serde_json::json!(suite.name));
                        result.insert("gm_cipher_desc".into(), serde_json::json!(suite.description));
                    }
                }
            }

            result.insert("summary".into(), serde_json::json!(format!("国密 GM/T 0024 SSL VPN: {}", hdr.content_desc)));
            return result;
        }
    }
    if payload.is_empty() {
        return result;
    }
    // DL/T 698.45-2017 面向对象电能信息采集规约 (智能电网国标)
    if protocol.to_uppercase().contains("698") || (payload.len() >= 12 && payload[0] == 0x68 && *payload.last().unwrap_or(&0) == 0x16) {
        if let Some(dlt) = crate::industrial_gb_dissector::dissect_dlt698_45(payload) {
            result.insert("dlt698_45".into(), serde_json::to_value(&dlt).unwrap_or_default());
            result.insert("summary".into(), serde_json::json!(dlt.summary));
        }
    }

    // HJ 212-2017 生态环境污染源在线监控规约 (环保国标)
    if protocol.to_uppercase().contains("HJ212") || (payload.len() >= 12 && payload.starts_with(b"##")) {
        if let Some(hj) = crate::industrial_gb_dissector::dissect_hj212(payload) {
            result.insert("hj212".into(), serde_json::to_value(&hj).unwrap_or_default());
            result.insert("summary".into(), serde_json::json!(hj.summary));
        }
    }

    // IEC 60870-5-104 ASDU 全类型与 CP56Time2a 深度展开 (电力远动国标)
    if protocol.to_uppercase().contains("104") || (payload.len() >= 6 && payload[0] == 0x68) {
        if let Some(iec_deep) = crate::industrial_gb_dissector::dissect_iec104_deep(payload) {
            result.insert("iec104_deep".into(), serde_json::to_value(&iec_deep).unwrap_or_default());
        }
    }


    // DNP3 (Distributed Network Protocol 3.0 / IEEE 1815) 工业电力解构
    if protocol.to_uppercase().contains("DNP3") || (payload.len() >= 10 && payload[0] == 0x05 && payload[1] == 0x64) {
    result.insert("dnp3_start_bytes".into(), serde_json::json!("0x0564"));
        let length = payload[2];
    result.insert("dnp3_length".into(), serde_json::json!(length));
        let ctrl = payload[3];
    result.insert("dnp3_ctrl_hex".into(), serde_json::json!(format!("0x{:02X}", ctrl)));
    result.insert("dnp3_ctrl_dir".into(), serde_json::json!((ctrl & 0x80) != 0));
    result.insert("dnp3_ctrl_prm".into(), serde_json::json!((ctrl & 0x40) != 0));

        let dst = u16::from_le_bytes([payload[4], payload[5]]);
        let src = u16::from_le_bytes([payload[6], payload[7]]);
    result.insert("dnp3_dst".into(), serde_json::json!(dst));
    result.insert("dnp3_src".into(), serde_json::json!(src));

        if payload.len() >= 13 {
            let app_ctrl = payload[11];
            let func_code = payload[12];
        result.insert("dnp3_app_ctrl_hex".into(), serde_json::json!(format!("0x{:02X}", app_ctrl)));
        result.insert("dnp3_func_code".into(), serde_json::json!(func_code));

            let func_name = match func_code {
                0x01 => "READ",
                0x02 => "WRITE",
                0x03 => "SELECT",
                0x04 => "OPERATE",
                0x05 => "DIRECT_OPERATE",
                0x06 => "DIRECT_OPERATE_NR",
                0x0D => "COLD_RESTART",
                0x0E => "WARM_RESTART",
                0x81 => "RESPONSE",
                0x82 => "UNSOLICITED_RESPONSE",
                _ => "CUSTOM_FUNCTION",
            };
        result.insert("dnp3_func_name".into(), serde_json::json!(func_name));
        result.insert("summary".into(), serde_json::json!(format!("DNP3 {} (Src: {}, Dst: {})", func_name, src, dst)));
        } else {
        result.insert("summary".into(), serde_json::json!(format!("DNP3 Link Frame (Src: {}, Dst: {})", src, dst)));
        }
        return result;
    }

    // BACnet/IP (Building Automation and Control Networks / ISO 16484-5) 楼宇智控解构
    if protocol.to_uppercase().contains("BACNET") || (payload.len() >= 4 && payload[0] == 0x81) {
    result.insert("bacnet_bvll_type".into(), serde_json::json!(payload[0]));
        let bvll_fn = payload[1];
    result.insert("bacnet_bvll_function".into(), serde_json::json!(bvll_fn));
        let bvll_fn_name = match bvll_fn {
            0x04 => "Forwarded-NPDU",
            0x0A => "BACnet-Unicast-NPDU",
            0x0B => "BACnet-Broadcast-NPDU",
            _ => "BACnet-BVLL-Other",
        };
    result.insert("bacnet_bvll_func_name".into(), serde_json::json!(bvll_fn_name));
        let bvll_len = u16::from_be_bytes([payload[2], payload[3]]);
    result.insert("bacnet_bvll_length".into(), serde_json::json!(bvll_len));

        if payload.len() >= 6 {
        result.insert("bacnet_npdu_version".into(), serde_json::json!(payload[4]));
        result.insert("bacnet_npdu_control".into(), serde_json::json!(payload[5]));
        }

        if payload.len() >= 8 {
            let apdu_type = payload[6] >> 4;
            let service_choice = payload[7];
        result.insert("bacnet_apdu_type".into(), serde_json::json!(apdu_type));
        result.insert("bacnet_service_choice".into(), serde_json::json!(service_choice));

            let service_name = match (apdu_type, service_choice) {
                (0, 0x0C) => "ReadProperty",
                (0, 0x0E) => "ReadPropertyMultiple",
                (0, 0x0F) => "WriteProperty",
                (0, 0x10) => "WritePropertyMultiple",
                (1, 0x08) => "Who-Is",
                (1, 0x00) => "I-Am",
                (1, 0x01) => "I-Have",
                _ => "BACnet-Service",
            };
        result.insert("bacnet_service_name".into(), serde_json::json!(service_name));
        result.insert("summary".into(), serde_json::json!(format!("BACnet/IP {} - {}", bvll_fn_name, service_name)));
        } else {
        result.insert("summary".into(), serde_json::json!(format!("BACnet/IP {}", bvll_fn_name)));
        }
        return result;
    }

    // 优先尝试工控插件化解包器扩展（SEMI HSMS/SECS, Honeywell FTE, Yokogawa Vnet/IP, Schneider UMAS, Beckhoff ADS 及声明式长尾协议）
    {
        let reg = crate::lock_guard::read_rwlock(
            &crate::industrial_plugin::INDUSTRIAL_PLUGIN_REGISTRY,
            "dpi::dissect_payload_plugin",
        );
        if let Some(out) = reg.dissect_by_protocol_id(protocol, payload) {
            for (k, v) in out.fields {
            result.insert(k, v);
            }
        result.insert("plugin_protocol_id".into(), serde_json::json!(out.protocol_id));
        result.insert("plugin_vendor".into(), serde_json::json!(out.vendor));
        result.insert("plugin_operation_type".into(), serde_json::json!(out.operation_type));
        result.insert("plugin_is_dangerous_write".into(), serde_json::json!(out.is_dangerous_write));
        result.insert("plugin_summary".into(), serde_json::json!(out.summary));
            return result;
        }
    }

    // 优先尝试工业水利规约 SL651-2014 专业拆解（支持 0x7E 0x7E 或 0x01 起始帧）
    if protocol == "SL651_WATER" || (payload.len() >= 10 && (payload.starts_with(&[0x7E, 0x7E]) || payload[0] == 0x01)) {
        let start_offset = if payload.starts_with(&[0x7E, 0x7E]) { 2 } else { 1 };
        if payload.len() >= start_offset + 1 {
        result.insert("center_address".into(), serde_json::Value::Number(serde_json::Number::from(payload[start_offset])));
        }
        if payload.len() >= start_offset + 6 {
            let addr_bytes = &payload[start_offset + 1..start_offset + 6];
            let addr_bcd: String = addr_bytes.iter().map(|b| format!("{:02X}", b)).collect();
        result.insert("telemetry_station_bcd".into(), serde_json::Value::String(addr_bcd));
        }
        if payload.len() >= start_offset + 8 {
            let pwd_bytes = &payload[start_offset + 6..start_offset + 8];
            let pwd_hex = format!("{:02X}{:02X}", pwd_bytes[0], pwd_bytes[1]);
        result.insert("center_password_hex".into(), serde_json::Value::String(pwd_hex));
        }
        if payload.len() >= start_offset + 9 {
            let fn_code = payload[start_offset + 8];
            let fn_desc = match fn_code {
                0x2F => "链路维持报 (心跳)",
                0x30 => "测试报",
                0x31 => "均匀时段水文信息报",
                0x32 => "遥测站定时报",
                0x33 => "遥测站加报报",
                0x34 => "遥测站小时报",
                0x35 => "人工置数报",
                0x36 => "图片报",
                0x40 => "修改基本配置",
                0x41 => "读取/自报基本配置",
                _other => "自定义/其他水利功能码",
            };
        result.insert("function_code".into(), serde_json::Value::String(format!("0x{:02X}", fn_code)));
        result.insert("function_name".into(), serde_json::Value::String(fn_desc.into()));
        }
        if payload.len() >= 16 {
            let crc_bytes = &payload[payload.len() - 2..];
            let crc_val = ((crc_bytes[0] as u16) << 8) | (crc_bytes[1] as u16);
        result.insert("crc16".into(), serde_json::Value::String(format!("0x{:04X}", crc_val)));
        }
    result.insert("sl651_frame_bytes".into(), serde_json::Value::Number(serde_json::Number::from(payload.len())));
    }

    // 工业控制 Modbus-TCP 规约功能码深度拆解 (等保三级工控指令级审计)
    if protocol.starts_with("MODBUS") || (payload.len() >= 8 && payload[2] == 0x00 && payload[3] == 0x00) {
        if payload.len() >= 8 {
            let trans_id = u16::from_be_bytes([payload[0], payload[1]]);
            let proto_id = u16::from_be_bytes([payload[2], payload[3]]);
            let length = u16::from_be_bytes([payload[4], payload[5]]);
            let unit_id = payload[6];
            let fc = payload[7];

            let (fc_name, is_write) = match fc {
                0x01 => ("Read Coils (读线圈)", false),
                0x02 => ("Read Discrete Inputs (读离散输入)", false),
                0x03 => ("Read Holding Registers (读保持寄存器)", false),
                0x04 => ("Read Input Registers (读输入寄存器)", false),
                0x05 => ("Write Single Coil (写单个线圈)", true),
                0x06 => ("Write Single Register (写单个寄存器)", true),
                0x07 => ("Read Exception Status (读异常状态)", false),
                0x08 => ("Diagnostics (诊断测试)", false),
                0x0B => ("Get Comm Event Counter", false),
                0x0C => ("Get Comm Event Log", false),
                0x0F => ("Write Multiple Coils (写多个线圈)", true),
                0x10 => ("Write Multiple Registers (写多个寄存器)", true),
                0x11 => ("Report Slave ID", false),
                0x14 => ("Read File Record", false),
                0x15 => ("Write File Record", true),
                0x16 => ("Mask Write Register", true),
                0x17 => ("Read/Write Multiple Registers", true),
                0x2B => ("Encapsulated Interface Transport", false),
                _ => ("Unknown Function Code (异常未知功能码)", false),
            };

        result.insert("modbus_trans_id".into(), serde_json::Value::Number(serde_json::Number::from(trans_id)));
        result.insert("modbus_proto_id".into(), serde_json::Value::Number(serde_json::Number::from(proto_id)));
        result.insert("modbus_length".into(), serde_json::Value::Number(serde_json::Number::from(length)));
        result.insert("modbus_unit_id".into(), serde_json::Value::Number(serde_json::Number::from(unit_id)));
        result.insert("modbus_function_code".into(), serde_json::Value::String(format!("0x{:02X}", fc)));
        result.insert("modbus_function_name".into(), serde_json::Value::String(fc_name.into()));
        result.insert("modbus_is_write_command".into(), serde_json::Value::Bool(is_write));
        result.insert("modbus_action_type".into(), serde_json::Value::String(
                if is_write { "WRITE_CONTROL" } else { "READ_QUERY" }.into()
            ));

            // 若包含起始寄存器地址 (FC 01, 02, 03, 04, 05, 06, 0F, 10 均在偏移 8-9)
            if payload.len() >= 10 {
                let start_addr = u16::from_be_bytes([payload[8], payload[9]]);
            result.insert("modbus_start_address".into(), serde_json::Value::Number(serde_json::Number::from(start_addr)));
            }
        }
    }

    // 电力自动化 IEC 60870-5-104 远动通信规约深度剖析
    if protocol.contains("104") || (payload.len() >= 6 && payload[0] == 0x68) {
        let apdu_len = payload[1] as usize;
    result.insert("iec104_apdu_length".into(), serde_json::json!(apdu_len));

        let ctrl0 = payload[2];
        let ctrl1 = payload[3];
        let ctrl2 = payload[4];
        let ctrl3 = payload[5];

        if (ctrl0 & 0x01) == 0 {
            // I 格式 (编号信息传输)
            let send_seq = (u16::from_le_bytes([ctrl0, ctrl1]) >> 1) as u32;
            let recv_seq = (u16::from_le_bytes([ctrl2, ctrl3]) >> 1) as u32;
        result.insert("iec104_frame_format".into(), serde_json::json!("I-Format (编号信息传输)"));
        result.insert("iec104_send_seq_ns".into(), serde_json::json!(send_seq));
        result.insert("iec104_recv_seq_nr".into(), serde_json::json!(recv_seq));

            // 剖析 ASDU 应用服务数据单元
            if payload.len() >= 12 {
                let type_id = payload[6];
                let vsq = payload[7];
                let num_objects = (vsq & 0x7F) as usize;
                let is_sequence = (vsq & 0x80) != 0;
                let cot = u16::from_le_bytes([payload[8], payload[9]]);
                let ca = u16::from_le_bytes([payload[10], payload[11]]);

                let type_desc = match type_id {
                    1 => "M_SP_NA_1 (单点遥信)",
                    3 => "M_DP_NA_1 (双点遥信)",
                    9 => "M_ME_NA_1 (测量值遥测-归一化值)",
                    11 => "M_ME_NB_1 (测量值遥测-标度化值)",
                    13 => "M_ME_NC_1 (测量值遥测-短浮点数)",
                    45 => "C_SC_NA_1 (单点遥控命令)",
                    46 => "C_DC_NA_1 (双点遥控命令)",
                    100 => "C_IC_NA_1 (总召唤命令)",
                    103 => "C_CS_NA_1 (时钟同步命令)",
                    _ => "其他应用数据单元",
                };

                let cot_desc = match cot & 0x3F {
                    1 => "周期/循环 (Periodic)",
                    2 => "背景扫描 (Background)",
                    3 => "突发/自发 (Spontaneous)",
                    6 => "激活 (Activation)",
                    7 => "激活确认 (Activation Con)",
                    8 => "停止激活 (Deactivation)",
                    20 => "响应总召唤 (Interrogated)",
                    _ => "其他传送原因",
                };

            result.insert("iec104_asdu_type_id".into(), serde_json::json!(type_id));
            result.insert("iec104_asdu_type_desc".into(), serde_json::json!(type_desc));
            result.insert("iec104_asdu_vsq_objects".into(), serde_json::json!(num_objects));
            result.insert("iec104_asdu_is_sequence".into(), serde_json::json!(is_sequence));
            result.insert("iec104_asdu_cot".into(), serde_json::json!(cot));
            result.insert("iec104_asdu_cot_desc".into(), serde_json::json!(cot_desc));
            result.insert("iec104_asdu_common_addr".into(), serde_json::json!(ca));

                if payload.len() >= 15 {
                    let ioa = (payload[12] as u32) | ((payload[13] as u32) << 8) | ((payload[14] as u32) << 16);
                result.insert("iec104_asdu_ioa".into(), serde_json::json!(ioa));
                }
            }
        } else if (ctrl0 & 0x03) == 0x01 {
            // S 格式 (编号监视功能)
            let recv_seq = (u16::from_le_bytes([ctrl2, ctrl3]) >> 1) as u32;
        result.insert("iec104_frame_format".into(), serde_json::json!("S-Format (编号监视功能)"));
        result.insert("iec104_recv_seq_nr".into(), serde_json::json!(recv_seq));
        } else {
            // U 格式 (未编号控制功能)
            let u_desc = match ctrl0 {
                0x07 => "STARTDT 激活 (启动传输)",
                0x0B => "STARTDT 确认",
                0x13 => "STOPDT 激活 (停止传输)",
                0x23 => "STOPDT 确认",
                0x43 => "TESTFR 激活 (测试连接)",
                0x83 => "TESTFR 确认",
                _ => "U-Format 控制帧",
            };
        result.insert("iec104_frame_format".into(), serde_json::json!("U-Format (未编号控制功能)"));
        result.insert("iec104_u_command".into(), serde_json::json!(u_desc));
        }
    }

    // 智能变电站 IEC 61850 MMS 规约深度剖析 (ISO 9506 制造报文规范)
    if protocol.contains("61850") || protocol.contains("MMS") || (payload.len() >= 7 && payload[0] == 0x03 && payload[1] == 0x00) {
        let tpkt_len = u16::from_be_bytes([payload[2], payload[3]]);
    result.insert("mms_tpkt_length".into(), serde_json::json!(tpkt_len));

        let cotp_len = payload[4] as usize;
        let cotp_type = payload[5];
        let cotp_desc = match cotp_type {
            0xE0 => "CR (连接请求)",
            0xD0 => "CC (连接确认)",
            0xF0 => "DT (数据传输)",
            _ => "其他 COTP PDU",
        };
    result.insert("mms_cotp_type".into(), serde_json::json!(cotp_desc));

        let mms_offset = 4 + cotp_len + 1;
        if payload.len() > mms_offset {
            let mms_tag = payload[mms_offset];
            let (mms_pdu_desc, mms_service) = match mms_tag {
                0xA0 => ("confirmed-RequestPDU", "确认请求"),
                0xA1 => ("confirmed-ResponsePDU", "确认响应"),
                0xA8 => ("initiate-RequestPDU", "MMS 握手发起"),
                0xA9 => ("initiate-ResponsePDU", "MMS 握手应答"),
                0x87 => ("unconfirmed-PDU", "信息报告 (InformationReport)"),
                _ => ("MMS-PDU", "未知服务"),
            };
        result.insert("mms_pdu_type".into(), serde_json::json!(mms_pdu_desc));
        result.insert("mms_service_category".into(), serde_json::json!(mms_service));
        }
    }

    {
        let dict = crate::lock_guard::read_rwlock(&DYN_DICT, "dpi::dissect_payload_dict");
        if let Some(rules) = dict.dissector_rules.get(protocol) {
            for rule in rules {
                let end = rule.offset + rule.length;
                if payload.len() >= end {
                    let chunk = &payload[rule.offset..end];
                    match rule.data_type.as_str() {
                        "hex" => {
                        result.insert(rule.field.clone(), serde_json::Value::String(hex::encode(chunk)));
                        }
                        "string" => {
                            let s = String::from_utf8_lossy(chunk).to_string();
                        result.insert(rule.field.clone(), serde_json::Value::String(s));
                        }
                        "float" | "float32" if chunk.len() >= 4 => {
                            let val = f32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                            if let Some(n) = serde_json::Number::from_f64((val as f64 * 1000.0).round() / 1000.0) {
                            result.insert(rule.field.clone(), serde_json::Value::Number(n));
                            }
                        }
                        "float_le" | "float32_le" if chunk.len() >= 4 => {
                            let val = f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                            if let Some(n) = serde_json::Number::from_f64((val as f64 * 1000.0).round() / 1000.0) {
                            result.insert(rule.field.clone(), serde_json::Value::Number(n));
                            }
                        }
                        "double" | "float64" if chunk.len() >= 8 => {
                            let mut b = [0u8; 8];
                            b.copy_from_slice(&chunk[..8]);
                            let val = f64::from_be_bytes(b);
                            if let Some(n) = serde_json::Number::from_f64((val * 1000.0).round() / 1000.0) {
                            result.insert(rule.field.clone(), serde_json::Value::Number(n));
                            }
                        }
                        "double_le" | "float64_le" if chunk.len() >= 8 => {
                            let mut b = [0u8; 8];
                            b.copy_from_slice(&chunk[..8]);
                            let val = f64::from_le_bytes(b);
                            if let Some(n) = serde_json::Number::from_f64((val * 1000.0).round() / 1000.0) {
                            result.insert(rule.field.clone(), serde_json::Value::Number(n));
                            }
                        }
                        "uint_le" => {
                            let val: u64 = chunk.iter().rev().fold(0u64, |acc, &b| (acc << 8) | b as u64);
                        result.insert(rule.field.clone(), serde_json::Value::Number(serde_json::Number::from(val)));
                        }
                        _ => {
                            // "uint" 大端解码
                            let val: u64 = chunk.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64);
                        result.insert(rule.field.clone(), serde_json::Value::Number(serde_json::Number::from(val)));
                        }
                    }
                }
            }
        }
    }
    // 若尚未匹配到任何静态专有字段，调用全协议原生解剖器集与通用自省展开引擎 (对标 Wireshark 3000+ 规约)
    if result.is_empty() {
        let uni_fields = crate::protocol_dissectors::dissect_universal_protocol(protocol, payload);
        for (k, v) in uni_fields {
            result.insert(k, v);
        }
    }

    // 若依然未生成足够字段，尝试通用 TLV / ASN.1 递归展开
    if result.is_empty() || result.len() <= 2 {
        if let Some(tlv_tree) = crate::dpi_heuristic::HeuristicDissectorEngine::parse_tlv_tree(payload, 0) {
            result.insert("tlv_root_tag".into(), serde_json::json!(tlv_tree.tag_hex));
            result.insert("tlv_node_count".into(), serde_json::json!(tlv_tree.children.len()));
            for (idx, child) in tlv_tree.children.iter().enumerate() {
                let key = format!("tlv_item_{}_{}", idx + 1, child.tag_hex);
                let val_str = child.value_text.as_deref().unwrap_or(&child.value_hex);
                result.insert(key, serde_json::json!(format!("Len={} Val={}", child.length, val_str)));
            }
        }
    }

    result
}

/// 从磁盘加载并解析 `protocol_signatures.json`，原子替换全局字典
/// 成功返回加载的规则数量，失败返回错误描述
pub fn reload_signatures(path: &str) -> Result<usize, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("读取 {} 失败: {}", path, e))?;

    // 允许 JSON 中包含注释字段（serde_json 默认不支持，用 Value 先解析再转）
    let raw: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("JSON 解析失败: {}", e))?;

    let sigs: DynSignatures = serde_json::from_value(raw)
        .map_err(|e| format!("签名结构映射失败: {}", e))?;

    let total = sigs.port_rules.len() + sigs.magic_rules.len() + sigs.regex_rules.len() + sigs.dissector_rules.len();

    // 预编译动态正则，写入缓存
    let compiled: Vec<(Regex, String)> = sigs
        .regex_rules
        .iter()
        .filter_map(|r| {
            Regex::new(&r.pattern)
                .ok()
                .map(|rx| (rx, r.proto.clone()))
        })
        .collect();

    // 原子写入（写锁极短暂，不阻塞读路径）
    {
        let mut w = crate::lock_guard::write_rwlock(&DYN_DICT, "dpi::reload_signatures_dict");
        *w = sigs;
    }
    {
        let mut w = crate::lock_guard::write_rwlock(&DYN_REGEX_CACHE, "dpi::reload_signatures_regex");
        *w = compiled;
    }

    Ok(total)
}

/// 启动文件系统热监听：当 `protocol_signatures.json` 变更时自动重载
/// 在独立线程内运行，不阻塞主引擎
pub fn start_hot_reload_watcher(path: String, app: tauri::AppHandle) {
    use notify::{EventKind, RecursiveMode, Watcher};
    use tauri::Emitter;

    // 首次加载
    match reload_signatures(&path) {
        Ok(n) => {
            let _ = app.emit(
                "system-log",
                format!("[DPI] ✅ 动态协议字典已加载: {} 条规则 <- {}", n, path),
            );
        }
        Err(e) => {
            let _ = app.emit("system-log", format!("[DPI] ⚠️ 动态字典加载失败: {}", e));
        }
    }

    let path_clone = path.clone();
    std::thread::spawn(move || {
        let (tx, rx) = std::sync::mpsc::channel();

        let mut watcher = match notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            if let Ok(event) = res {
                let _ = tx.send(event);
            }
        }) {
            Ok(w) => w,
            Err(e) => {
                let _ = app.emit("system-log", format!("[DPI] ❌ 文件热监听初始化失败: {}", e));
                return;
            }
        };

        let watch_path = std::path::Path::new(&path_clone);
        if let Err(e) = watcher.watch(watch_path, RecursiveMode::NonRecursive) {
            let _ = app.emit("system-log", format!("[DPI] ❌ 无法监听文件 {}: {}", path_clone, e));
            return;
        }

        for event in rx {
            // 仅响应内容修改事件，忽略访问/元数据变更
            if matches!(
                event.kind,
                EventKind::Modify(_) | EventKind::Create(_)
            ) {
                // 延迟 200ms 等待文件写入完成（编辑器可能先 truncate 再写）
                std::thread::sleep(std::time::Duration::from_millis(200));

                match reload_signatures(&path_clone) {
                    Ok(n) => {
                        let _ = app.emit(
                            "system-log",
                            format!("[DPI] 🔄 动态字典热重载成功: {} 条规则", n),
                        );
                    }
                    Err(e) => {
                        let _ = app.emit(
                            "system-log",
                            format!("[DPI] ❌ 热重载失败（旧字典保持生效）: {}", e),
                        );
                    }
                }
            }
        }
    });
}


/// 编译期一次性构建的正则表达式池（避免运行时重复编译）
struct RegexPool {
    http_req:  Regex,
    http_res:  Regex,
    ftp_cmd:   Regex,
    smtp_cmd:  Regex,
    redis_cmd: Regex,
    hj212:     Regex,
}

static REGEX_POOL: Lazy<RegexPool> = Lazy::new(|| RegexPool {
    http_req:  Regex::new(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|CONNECT|TRACE|PATCH) .+ HTTP/1\.[01]").unwrap(),
    http_res:  Regex::new(r"^HTTP/1\.[01] \d{3}").unwrap(),
    ftp_cmd:   Regex::new(r"(?i)^(USER|PASS|SYST|FEAT|PWD|CWD|QUIT|RETR|STOR|LIST|PASV|PORT) ").unwrap(),
    smtp_cmd:  Regex::new(r"(?i)^(EHLO|HELO|MAIL FROM:|RCPT TO:|DATA|QUIT|AUTH|STARTTLS)").unwrap(),
    redis_cmd: Regex::new(r"^(\*[0-9]+|\+[^\r\n]+|-[^\r\n]+)\r\n").unwrap(),
    hj212:     Regex::new(r"^##\d{4}(ST=|CN=|QN=)").unwrap(),
});

/// DPI 主入口函数
/// 优先级：动态JSON字典 > 端口精确匹配 > 载荷魔数 > 正则文本
///
/// # Arguments
/// * `src_port` - 源端口
/// * `dst_port` - 目的端口
/// * `payload`  - 应用层裸载荷字节切片
///
/// # Returns
/// 协议名称字符串（如 "MODBUS_TCP", "HTTP_REQ", "TLS_HANDSHAKE"）
pub fn identify_protocol(src_port: u16, dst_port: u16, payload: &[u8]) -> String {
    if payload.is_empty() {
        return "EMPTY".to_string();
    }

    // ---- 阶段零：动态 JSON 字典匹配（最高优先级，热加载规则优先于内置）----
    {
        let dict = crate::lock_guard::read_rwlock(&DYN_DICT, "dpi::dissect_payload_dict");
        // 0a. 动态端口规则
        for rule in &dict.port_rules {
            if dst_port == rule.port || src_port == rule.port {
                return rule.proto.clone();
            }
        }
        // 0b. 动态魔数规则（Hex 偏移匹配）
        for rule in &dict.magic_rules {
            if let Ok(expected) = hex::decode(&rule.bytes) {
                let end = rule.offset + expected.len();
                if payload.len() >= end && &payload[rule.offset..end] == expected.as_slice() {
                    return rule.proto.clone();
                }
            }
        }
    }
    // 0c. 动态正则规则（使用预编译缓存）
    {
        let cache = crate::lock_guard::read_rwlock(&DYN_REGEX_CACHE, "dpi::identify_protocol_regex");
        if !cache.is_empty() {
            if let Ok(text) = std::str::from_utf8(payload) {
                for (regex, proto) in cache.iter() {
                    if regex.is_match(text) {
                        return proto.clone();
                    }
                }
            }
        }
    }

    // ---- 阶段 0.5：工控专有与长尾解包插件（HSMS/SECS, FTE, Vnet/IP, UMAS, ADS 及自定义规则）----
    {
        let reg = crate::lock_guard::read_rwlock(
            &crate::industrial_plugin::INDUSTRIAL_PLUGIN_REGISTRY,
            "dpi::dissect_payload_plugin",
        );
        if let Some(out) = reg.inspect(src_port, dst_port, payload) {
            return out.protocol_id;
        }
    }

    // ---- 阶段一：端口精确匹配（最高优先级，O(1)）----
    // 国密 GM/T 0024-2014 SSL VPN 专属魔数嗅探 (Version: 0x0101)
    if crate::gm_ssl::is_likely_gm_ssl_stream(payload) {
        return "GM_SSL".to_string();
    }

    let port_result = match_by_port(src_port, dst_port, payload);
    if !port_result.is_empty() {
        return port_result;
    }

    // ---- 阶段二：载荷魔数（Hex 字节偏移）匹配 ----
    let magic_result = match_by_magic(payload);
    if !magic_result.is_empty() {
        return magic_result;
    }

    // ---- 阶段三：文本正则匹配（最低优先级）----
    let text_result = match_by_regex(payload);
    if !text_result.is_empty() {
        return text_result;
    }

    // ---- 阶段四：启发式盲探流水线 (对标 Wireshark Heuristic Dissector，端口漂移与长尾规约自适应) ----
    if let Some(heuristic_res) = crate::dpi_heuristic::HeuristicDissectorEngine::inspect_heuristic(payload, src_port, dst_port) {
        return heuristic_res.protocol;
    }

    format!("UNKNOWN:{}", dst_port)
}


/// 校验 DNP3 (IEEE 1815) 报文
fn validate_dnp3(payload: &[u8]) -> String {
    if payload.len() >= 10 && payload[0] == 0x05 && payload[1] == 0x64 {
        "DNP3".to_string()
    } else {
        "DNP3_INVALID".to_string()
    }
}

/// 校验 BACnet/IP (ISO 16484-5) 报文
fn validate_bacnet(payload: &[u8]) -> String {
    if payload.len() >= 4 && payload[0] == 0x81 {
        let bvll_fn = payload[1];
        if bvll_fn == 0x0A || bvll_fn == 0x0B || bvll_fn == 0x04 {
            return "BACNET".to_string();
        }
    }
    "BACNET_INVALID".to_string()
}

/// 阶段一：基于众所周知端口（IANA Well-Known Ports）的精确匹配
fn match_by_port(src_port: u16, dst_port: u16, payload: &[u8]) -> String {
    let p = |port: u16| -> bool { dst_port == port || src_port == port };

    // 工业控制协议（ICS/SCADA）
    if p(502)  { return validate_modbus_tcp(payload); }
    if p(102)  { return validate_iec61850_or_s7(payload); }
    if p(2404) { return validate_iec104(payload); }
    if p(44818) || p(2222) { return "ENIP".to_string(); }   // EtherNet/IP
    if p(47808) { return validate_bacnet(payload); }          // BACnet/IP
    if p(20000) { return validate_dnp3(payload); }            // DNP3
    if p(4840)  { return "OPC-UA".to_string(); }              // OPC Unified Architecture
    if p(9600)  { return "OMRON-FINS".to_string(); }          // Omron FINS
    if p(789)   { return "MITSUBISHI-MC".to_string(); }       // Mitsubishi MELSEC

    // 物联网消息协议
    if p(1883) || p(8883) { return validate_mqtt(payload); }
    if p(5672)  { return "AMQP".to_string(); }

    // 标准应用层协议
    if p(80) || p(8080) || p(8000) || p(8888) {
        if payload.starts_with(b"GET ")  || payload.starts_with(b"POST ")
        || payload.starts_with(b"HTTP") || payload.starts_with(b"PUT ")
        || payload.starts_with(b"DELETE ") || payload.starts_with(b"HEAD ") {
            return "HTTP".to_string();
        }
    }
    if p(443) || p(8443) {
        return match_tls(payload);
    }
    if p(53)  { return "DNS".to_string(); }
    if p(22)  { if payload.starts_with(b"SSH-") { return "SSH".to_string(); } }
    if p(21)  { return "FTP".to_string(); }
    if p(25) || p(587) || p(465) { return "SMTP".to_string(); }
    if p(110) { return "POP3".to_string(); }
    if p(143) { return "IMAP".to_string(); }
    if p(3306) { return "MYSQL".to_string(); }
    if p(5432) { return "POSTGRESQL".to_string(); }
    if p(6379) { return "REDIS".to_string(); }
    if p(27017) { return "MONGODB".to_string(); }
    if p(5900) { return "VNC".to_string(); }
    if p(3389) { return "RDP".to_string(); }
    if p(161) || p(162) { return "SNMP".to_string(); }
    if p(123) { return "NTP".to_string(); }
    if p(67) || p(68) { return "DHCP".to_string(); }
    if p(5683) { return "COAP".to_string(); }               // CoAP (IoT)

    // 水文/环保行业标准端口（行业标准規约）
    if p(5003) || p(6501) || p(6502) || p(6503) { return "SL651_WATER".to_string(); }
    if p(212)  { return "HJ212".to_string(); }

    String::new()
}

/// 阶段二：基于载荷字节魔数的精确指纹匹配
fn match_by_magic(payload: &[u8]) -> String {
    let len = payload.len();

    // TLS 握手（优先于其他匹配）
    if len >= 3 && payload[0] == 0x16 && payload[1] == 0x03 { return "TLS_HANDSHAKE".to_string(); }
    if len >= 3 && payload[0] == 0x17 && payload[1] == 0x03 { return "TLS_APP_DATA".to_string(); }
    if len >= 3 && payload[0] == 0x15 && payload[1] == 0x03 { return "TLS_ALERT".to_string(); }

    // MODBUS TCP (工业标准)
    // 偏移 2-3: 0x00 0x00 (协议标识符=0, MODBUS), 偏移 4-5: 数据长度
    if len >= 8 && payload[2] == 0x00 && payload[3] == 0x00 {
        let data_len = u16::from_be_bytes([payload[4], payload[5]]) as usize;
        if data_len > 0 && data_len + 6 == len {
            return "MODBUS_TCP".to_string();
        }
    }

    // S7 Comm (西门子 PLC)
    // 头部: 0x03 0x00, 字节2-3为总长度
    if len >= 4 && payload[0] == 0x03 && payload[1] == 0x00 {
        let total_len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
        if total_len == len {
            return "S7_COMM".to_string();
        }
    }

    // IEC 60870-5-104 (电力自动化，0x68 起始 + APDU 长度 + 4 字节控制域)
    if len >= 6 && payload[0] == 0x68 && (payload[1] as usize) <= len - 2 {
        let ctrl0 = payload[2];
        if (ctrl0 & 0x01) == 0 || (ctrl0 & 0x03) == 0x01 || (ctrl0 & 0x03) == 0x03 {
            return "IEC-104".to_string();
        }
    }

    // IEC 61850 MMS (TPKT + COTP + MMS PDU)
    if len >= 7 && payload[0] == 0x03 && payload[1] == 0x00 {
        let cotp_len = payload[4] as usize;
        if len >= 4 + cotp_len + 1 {
            let mms_tag = payload[4 + cotp_len + 1];
            if matches!(mms_tag, 0xA0 | 0xA1 | 0xA8 | 0xA9 | 0x87) {
                return "IEC-61850-MMS".to_string();
            }
        }
    }

    // HJ212 环保数据采集传输协议 (中国国标 HJ/T 212-2005 / HJ 212-2017)
    // 帧头固定为 "##" (0x23 0x23)
    if len >= 4 && payload[0] == 0x23 && payload[1] == 0x23 {
        return "HJ212".to_string();
    }

    // SL651 水文遥测协议（中国水利部标准）
    // 帧头: 0x7E 0x7E
    if len >= 10 && payload[0] == 0x7E && payload[1] == 0x7E { return "SL651_WATER".to_string(); }

    // MODBUS RTU (串口)
    // 功能码范围: 01-06, 0F, 10 (常见读写功能码)
    if len >= 4 {
        let fc = payload[1];
        if matches!(fc, 0x01..=0x06 | 0x0F | 0x10 | 0x11 | 0x17) {
            return "MODBUS_RTU".to_string();
        }
    }

    // MQTT (物联网消息协议，严格遵循 OASIS 规范)
    if len >= 2 {
        let first = payload[0];
        let msg_type = (first >> 4) & 0x0F;
        match msg_type {
            1 => {
                // CONNECT: 验证协议名
                if len >= 10 && (payload[4..10].windows(4).any(|w| w == b"MQTT") || payload[4..10].windows(6).any(|w| w == b"MQIsdp")) {
                    return "MQTT".to_string();
                }
            }
            2 => {
                // CONNACK: 首字节严格为 0x20，长度为 4 且剩余长度字节为 2
                if first == 0x20 && len == 4 && payload[1] == 2 {
                    return "MQTT".to_string();
                }
            }
            3 => {
                // PUBLISH: 0x30..=0x3F
                if (0x30..=0x3F).contains(&first) && len >= 5 {
                    return "MQTT".to_string();
                }
            }
            4..=14 => {
                let flags = first & 0x0F;
                let valid = match msg_type {
                    4 | 5 | 7 | 9 | 11 | 13 => flags == 0,
                    6 | 8 | 10 => flags == 2,
                    12 | 14 => flags == 0,
                    _ => false,
                };
                if valid {
                    return "MQTT".to_string();
                }
            }
            _ => {}
        }
    }

    // SMB2 (文件共享)
    if len >= 4 && &payload[..4] == b"\xfeSMB" { return "SMB2".to_string(); }
    if len >= 4 && &payload[..4] == b"\xffSMB" { return "SMB1".to_string(); }

    // RFB (VNC 协议握手)
    if payload.starts_with(b"RFB ") { return "VNC".to_string(); }

    // DNS (UDP)
    if len >= 12 {
        let flags = u16::from_be_bytes([payload[2], payload[3]]);
        let qr = (flags >> 15) & 0x01;
        let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
        if qdcount > 0 && qdcount < 20 {
            if qr == 0 { return "DNS_QUERY".to_string(); }
            if qr == 1 { return "DNS_RESP".to_string(); }
        }
    }

    // NTP (UDP)
    if len >= 48 {
        let li_vn_mode = payload[0];
        let mode = li_vn_mode & 0x07;
        let version = (li_vn_mode >> 3) & 0x07;
        if matches!(mode, 3 | 4) && matches!(version, 3 | 4) { return "NTP".to_string(); }
    }

    // DHCP (UDP) - Magic Cookie: 0x63825363
    if len >= 236 && len >= 240 && &payload[236..240] == &[0x63, 0x82, 0x53, 0x63] {
        return "DHCP".to_string();
    }

    // SSDP (UPnP 组播)
    if payload.starts_with(b"M-SEARCH * HTTP") || payload.starts_with(b"NOTIFY * HTTP") || payload.starts_with(b"HTTP/1.1 200 OK") {
        if payload.windows(4).any(|w| w == b"uuid" || w == b"USN:") {
            return "SSDP_MULTICAST".to_string();
        }
    }

    String::new()
}

/// 阶段三：正则文本匹配（仅在前两阶段均未识别时调用）
fn match_by_regex(payload: &[u8]) -> String {
    // 只对可打印 ASCII 进行文本解析，避免乱码误匹配
    // 先尝试合法 UTF-8；失败则直接返回空（非文本载荷由魔数阶段处理）
    let text: &str = match std::str::from_utf8(payload) {
        Ok(t) => t,
        Err(_) => return String::new(),
    };

    let pool = &*REGEX_POOL;

    if pool.hj212.is_match(text)    { return "HJ212".to_string(); }
    if pool.http_req.is_match(text)  { return "HTTP_REQ".to_string(); }
    if pool.http_res.is_match(text)  { return "HTTP_RES".to_string(); }
    if pool.redis_cmd.is_match(text) { return "REDIS".to_string(); }
    if pool.ftp_cmd.is_match(text)   { return "FTP_CMD".to_string(); }
    if pool.smtp_cmd.is_match(text)  { return "SMTP_CMD".to_string(); }

    if text.starts_with("SSH-")  { return "SSH".to_string(); }
    if text.starts_with("##") && (text.contains("ST=") || text.contains("CN=")) {
        return "HJ212".to_string();
    }
    if text.contains("NOTIFY * HTTP/1.1") || text.contains("M-SEARCH * HTTP/1.1") {
        return "SSDP_MULTICAST".to_string();
    }

    String::new()
}

// ============================================================
// 协议深度验证辅助函数
// ============================================================

fn validate_modbus_tcp(payload: &[u8]) -> String {
    if payload.len() >= 8 && payload[2] == 0x00 && payload[3] == 0x00 {
        "MODBUS_TCP".to_string()
    } else if payload.len() >= 4 {
        let fc = payload[1];
        if matches!(fc, 0x01..=0x06 | 0x0F | 0x10) {
            return "MODBUS_RTU".to_string();
        }
        "MODBUS_TCP".to_string()
    } else {
        "MODBUS_TCP".to_string()
    }
}

fn validate_s7comm(payload: &[u8]) -> String {
    if payload.len() >= 4 && payload[0] == 0x03 && payload[1] == 0x00 {
        "S7_COMM".to_string()
    } else {
        "S7_COMM".to_string()
    }
}

fn validate_iec104(payload: &[u8]) -> String {
    if payload.len() >= 6 && payload[0] == 0x68 {
        "IEC-104".to_string()
    } else {
        "IEC-104".to_string()
    }
}

fn validate_iec61850_or_s7(payload: &[u8]) -> String {
    if payload.len() >= 7 && payload[0] == 0x03 && payload[1] == 0x00 {
        let cotp_len = payload[4] as usize;
        if payload.len() >= 4 + cotp_len + 1 {
            let mms_tag = payload[4 + cotp_len + 1];
            if matches!(mms_tag, 0xA0 | 0xA1 | 0xA8 | 0xA9 | 0x87) {
                return "IEC-61850-MMS".to_string();
            }
        }
    }
    validate_s7comm(payload)
}

fn validate_mqtt(payload: &[u8]) -> String {
    if payload.len() >= 2 {
        let msg_type = (payload[0] >> 4) & 0x0F;
        if matches!(msg_type, 1..=14) { return "MQTT".to_string(); }
    }
    "MQTT".to_string()
}

fn match_tls(payload: &[u8]) -> String {
    if payload.is_empty() { return "TLS".to_string(); }
    match payload[0] {
        0x16 => "TLS_HANDSHAKE".to_string(),
        0x17 => "TLS_APP_DATA".to_string(),
        0x15 => "TLS_ALERT".to_string(),
        0x14 => "TLS_CHANGE_CIPHER".to_string(),
        _    => "TLS".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identify_modbus_tcp() {
        // Transaction ID (2B) + Protocol ID (2B = 0) + Length (2B) + Unit ID (1B) + FC (1B)
        let payload = [0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0A];
        let proto = identify_protocol(502, 502, &payload);
        assert_eq!(proto, "MODBUS_TCP");
    }

    #[test]
    fn test_identify_s7comm() {
        let payload = [0x03, 0x00, 0x00, 0x16, 0x11, 0xE0];
        let proto = identify_protocol(102, 102, &payload);
        assert_eq!(proto, "S7_COMM");
    }

    #[test]
    fn test_identify_hj212() {
        let payload = b"##0120ST=32;CN=2011;PW=123456;MN=8888888;CP=&&DataTime=20260920000000;B01=12.5&&0305\r\n";
        let proto = identify_protocol(9000, 9000, payload);
        assert_eq!(proto, "HJ212");
    }

    #[test]
    fn test_identify_http_well_known_port() {
        let payload = b"GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let proto = identify_protocol(8080, 8080, payload);
        assert_eq!(proto, "HTTP");
    }

    #[test]
    fn test_identify_http_blind_port_regex() {
        let payload = b"GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let proto = identify_protocol(19999, 19999, payload);
        assert_eq!(proto, "HTTP_REQ");
    }

    #[test]
    fn test_dissect_payload_mock() {
        // 动态注册一条测试规则
        let mut dissector_rules = std::collections::HashMap::new();
        dissector_rules.insert("TEST_PROTO".to_string(), vec![
            DissectorField {
                field: "station_id".into(),
                offset: 0,
                length: 2,
                data_type: "uint".into(),
                note: "".into(),
            },
            DissectorField {
                field: "signature_hex".into(),
                offset: 2,
                length: 4,
                data_type: "hex".into(),
                note: "".into(),
            }
        ]);
        if let Ok(mut dict) = DYN_DICT.write() {
            dict.dissector_rules.extend(dissector_rules);
        }

        let payload = [0x01, 0x00, 0xAA, 0xBB, 0xCC, 0xDD];
        let map = dissect_payload("TEST_PROTO", &payload);
        assert_eq!(map.get("station_id").unwrap().as_u64().unwrap(), 256);
        assert_eq!(map.get("signature_hex").unwrap().as_str().unwrap(), "aabbccdd");
    }

    #[test]
    fn test_dissect_ieee754_float() {
        let mut dissector_rules = std::collections::HashMap::new();
        dissector_rules.insert("SENSOR_PROTO".to_string(), vec![
            DissectorField {
                field: "water_level".into(),
                offset: 0,
                length: 4,
                data_type: "float".into(),
                note: "水位(米)".into(),
            },
            DissectorField {
                field: "water_temp".into(),
                offset: 4,
                length: 4,
                data_type: "float_le".into(),
                note: "水温(摄氏度)".into(),
            }
        ]);
        if let Ok(mut dict) = DYN_DICT.write() {
            dict.dissector_rules.extend(dissector_rules);
        }

        let be_bytes = 123.456f32.to_be_bytes();
        let le_bytes = 25.5f32.to_le_bytes();
        let mut payload = Vec::new();
        payload.extend_from_slice(&be_bytes);
        payload.extend_from_slice(&le_bytes);

        let map = dissect_payload("SENSOR_PROTO", &payload);
        let level = map.get("water_level").unwrap().as_f64().unwrap();
        let temp = map.get("water_temp").unwrap().as_f64().unwrap();
        assert!((level - 123.456).abs() < 0.01, "大端浮点数解码误差超限: {}", level);
        assert!((temp - 25.5).abs() < 0.01, "小端浮点数解码误差超限: {}", temp);
    }

    #[test]
    fn test_iec104_dissection() {
        // 构造 IEC 104 I-Format 报文 (总召唤命令 C_IC_NA_1, TypeID 100, COT 6 激活, CommonAddr 1)
        // 68 0E 00 00 00 00 64 01 06 00 01 00 00 00 00 14
        let raw_104 = vec![
            0x68, 0x0E, // Start 0x68, Length 14
            0x00, 0x00, 0x00, 0x00, // I-Format N(S)=0, N(R)=0
            100, 0x01, // TypeID 100 (C_IC_NA_1), VSQ 1
            0x06, 0x00, // COT 6 (Activation)
            0x01, 0x00, // Common Address 1
            0x00, 0x00, 0x00, // IOA 0
            0x14, // QOI 20 (Station interrogation)
        ];

        let proto = identify_protocol(2404, 55555, &raw_104);
        assert_eq!(proto, "IEC-104");

        let dissected = dissect_payload(&proto, &raw_104);
        assert_eq!(dissected.get("iec104_frame_format").unwrap().as_str().unwrap(), "I-Format (编号信息传输)");
        assert_eq!(dissected.get("iec104_asdu_type_id").unwrap().as_u64().unwrap(), 100);
        assert!(dissected.get("iec104_asdu_type_desc").unwrap().as_str().unwrap().contains("总召唤"));
        assert_eq!(dissected.get("iec104_asdu_cot").unwrap().as_u64().unwrap(), 6);
    }

    #[test]
    fn test_iec61850_mms_dissection() {
        // 构造 TPKT (4B) + COTP DT (3B) + MMS confirmed-RequestPDU (0xA0)
        // 03 00 00 0B 02 F0 80 A0 03 02 01 01
        let raw_mms = vec![
            0x03, 0x00, 0x00, 0x0C, // TPKT v3, len 12
            0x02, 0xF0, 0x80,       // COTP: len 2, type 0xF0 (DT), EOT 0x80
            0xA0, 0x05,             // MMS confirmed-RequestPDU (tag 0xA0, len 5)
            0x02, 0x01, 0x01,       // invokeID = 1
            0xA4, 0x00,             // read service (tag 0xA4)
        ];

        let proto = identify_protocol(102, 60000, &raw_mms);
        assert_eq!(proto, "IEC-61850-MMS");

        let dissected = dissect_payload(&proto, &raw_mms);
        assert_eq!(dissected.get("mms_cotp_type").unwrap().as_str().unwrap(), "DT (数据传输)");
        assert_eq!(dissected.get("mms_pdu_type").unwrap().as_str().unwrap(), "confirmed-RequestPDU");
    }

    #[test]
    fn test_industrial_plugin_dpi_integration() {
        // 构造横河 Vnet/IP 报文并在端口 51100 触发 DPI 识别
        let vnet_packet = vec![
            b'V', b'N', b'E', b'T',
            0x01, 0x02, 0x05, 0x01,
            0x00, 0x00, 0x01, 0x00,
        ];
        let proto = identify_protocol(51100, 51100, &vnet_packet);
        assert_eq!(proto, "YOKOGAWA_VNET_IP", "DPI 必须优先命中工控插件识别出横河 Vnet/IP");

        let dissected = dissect_payload(&proto, &vnet_packet);
        assert_eq!(dissected.get("plugin_protocol_id").unwrap().as_str().unwrap(), "YOKOGAWA_VNET_IP");
        assert_eq!(dissected.get("plugin_vendor").unwrap().as_str().unwrap(), "Yokogawa Electric");
        assert_eq!(dissected.get("plugin_is_dangerous_write").unwrap().as_bool().unwrap(), true);
    }

    #[test]
    fn test_dnp3_and_bacnet_dpi_dissection() {
        // 1. DNP3 Direct Operate 指令测试
        let dnp3_payload = vec![
            0x05, 0x64, // Start
            0x0B,       // Length
            0xC4,       // Control: DIR=1, PRM=1, FCB=0, FCV=0, Func=4
            0x01, 0x00, // Dst = 1
            0x02, 0x00, // Src = 2
            0xAA, 0xBB, // CRC
            0xC0,       // Transport Header
            0xC0,       // App Control
            0x05,       // Func = DIRECT_OPERATE (0x05)
        ];
        let dnp3_res = dissect_payload("DNP3", &dnp3_payload);
        assert_eq!(dnp3_res.get("dnp3_src").unwrap(), &serde_json::json!(2));
        assert_eq!(dnp3_res.get("dnp3_dst").unwrap(), &serde_json::json!(1));
        assert_eq!(dnp3_res.get("dnp3_func_code").unwrap(), &serde_json::json!(5));
        assert_eq!(dnp3_res.get("dnp3_func_name").unwrap(), &serde_json::json!("DIRECT_OPERATE"));

        // 2. BACnet/IP Unicast ReadProperty 测试
        let bacnet_payload = vec![
            0x81,       // BVLL Type
            0x0A,       // Function: BACnet-Unicast-NPDU
            0x00, 0x08, // Length: 8
            0x01,       // NPDU Version: 1
            0x00,       // NPDU Control: normal priority
            0x00,       // APDU Type: Confirmed-Request (0)
            0x0C,       // Service Choice: ReadProperty (0x0C)
        ];
        let bacnet_res = dissect_payload("BACNET", &bacnet_payload);
        assert_eq!(bacnet_res.get("bacnet_bvll_function").unwrap(), &serde_json::json!(0x0A));
        assert_eq!(bacnet_res.get("bacnet_service_name").unwrap(), &serde_json::json!("ReadProperty"));
        let summary = bacnet_res.get("summary").unwrap().as_str().unwrap();
        assert!(summary.contains("ReadProperty"));
    }

}
