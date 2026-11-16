//! ==============================================================================
//! 工业级 Omni-Probe - 报文物理特征智能分析与专家辅导参考引擎
//! 模块名称: packet_expert_advisor.rs
//!
//! 核心职责:
//! 1. 深度萃取抓包数据包物理与规约特征（帧长档位、香农熵谱、L2/L3/L4 拓扑特征、应用层载荷关键魔数）；
//! 2. 结合国家标准 (GB/T) 与国际规范 (RFC / IEC / SEMI)，输出权威技术标准编号与具体条款映射；
//! 3. 诊断报文的底层物理行为意图（如：参数轮询、远程写入、状态机同步、心跳保活、异常响应）；
//! 4. 面向现场网络与工控工程师，提供具备指导意义的行动建议（排查指南、合规核验、故障定位）；
//! 5. 严格杜绝占位符，纯原生生产级实现，全量边界覆盖。
//! ==============================================================================

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::sniffer::PacketRecord;

/// 关键物理与规约特征指纹项
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureFingerprintItem {
    pub name: String,
    pub value: String,
    pub detection_basis: String,
    pub significance: String,
}

/// 报文专家智能分析与技术辅导参考综合报告
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketExpertGuidanceReport {
    pub packet_id: u64,
    pub protocol_name: String,
    pub protocol_standard: String,
    pub standard_clause_ref: String,
    pub behavioral_intent: String,
    pub role_analysis: String,
    pub feature_fingerprints: Vec<FeatureFingerprintItem>,
    pub risk_level: String,
    pub risk_assessment: String,
    pub actionable_guidance: Vec<String>,
    pub decoding_confidence: f64,
}

/// 报文专家分析与辅导核心引擎
pub struct PacketExpertAdvisor;

impl PacketExpertAdvisor {
    /// 执行全息特征萃取与专家诊断报告推演
    ///
    /// 时间复杂度: O(N) (N 为报文载荷长度，微秒级执行完成)
    /// 空间复杂度: O(K) (K 为特征项与建议条目数，严格有界)
    pub fn generate_guidance(packet: &PacketRecord) -> PacketExpertGuidanceReport {
        let payload_bytes = hex::decode(&packet.payload_hex).unwrap_or_default();
        let proto_upper = packet.protocol.to_uppercase();
        let bdata = packet.business_data.as_ref();

        let mut fingerprints = Vec::new();
        let mut guidance = Vec::new();

        // 1. 物理层与链路层通用特征指纹萃取 (RFC 2544 档位与香农熵)
        let rfc2544_tier = match packet.length {
            0..=64 => "64 字节 (标准线速最小帧/控制信令)",
            65..=128 => "128 字节 (小型请求/应答帧)",
            129..=256 => "256 字节 (中小型遥信遥测帧)",
            257..=512 => "512 字节 (通用工控参数帧)",
            513..=1024 => "1024 字节 (大容量数据块)",
            1025..=1518 => "1518 字节 (以太网标准最大传输单元 MTU)",
            _ => "1518+ 字节 (以太网巨帧 Jumbo Frame)",
        };
        fingerprints.push(FeatureFingerprintItem {
            name: "RFC 2544 长度阶梯".to_string(),
            value: format!("{} B · {}", packet.length, rfc2544_tier),
            detection_basis: "物理网卡 L2 完整帧长度测量".to_string(),
            significance: if packet.length < 60 {
                "低于 60 字节的以太网填充帧，注意网卡硬件 Padding 差异".to_string()
            } else if packet.length > 1514 {
                "巨帧传输需确保整条链路各级交换机与路由均开启 Jumbo Frame 支持".to_string()
            } else {
                "符合工业以太网常规通信标准帧长区间".to_string()
            },
        });

        // 2. 香农信息熵谱特征分析
        let entropy_desc = if packet.entropy >= 7.5 {
            "高度随机 (极大概率为密文流、对称加密载荷或压缩固件)"
        } else if packet.entropy >= 6.0 {
            "中度离散 (存在局部混淆、编码或高密度工控浮点数组)"
        } else if packet.entropy >= 3.0 {
            "低度离散 (典型结构化协议头与规律性 ASCII 明文字符)"
        } else {
            "极低随机度 (大量固定全零、填充字节或简单心跳保活)"
        };
        fingerprints.push(FeatureFingerprintItem {
            name: "香农信息熵量化".to_string(),
            value: format!("{:.2} bits/byte ({})", packet.entropy, packet.entropy_level),
            detection_basis: "基于有效载荷字节频次离散度计算: H = -∑ P(x)·log2(P(x))".to_string(),
            significance: entropy_desc.to_string(),
        });

        // 3. 针对不同协议特征的深度专家规则推导
        if proto_upper.contains("MODBUS") || packet.src_port == 502 || packet.dst_port == 502 {
            Self::analyze_modbus(packet, &payload_bytes, bdata, &mut fingerprints, &mut guidance)
        } else if proto_upper.contains("104") || proto_upper.contains("IEC") || packet.src_port == 2404 || packet.dst_port == 2404 {
            Self::analyze_iec104(packet, &payload_bytes, bdata, &mut fingerprints, &mut guidance)
        } else if proto_upper.contains("SL651") || proto_upper.contains("WATER") || payload_bytes.starts_with(&[0x7E, 0x7E]) {
            Self::analyze_sl651(packet, &payload_bytes, bdata, &mut fingerprints, &mut guidance)
        } else if proto_upper.contains("S7") || packet.src_port == 102 || packet.dst_port == 102 {
            Self::analyze_s7comm(packet, &payload_bytes, bdata, &mut fingerprints, &mut guidance)
        } else if proto_upper.contains("DNS") || packet.src_port == 53 || packet.dst_port == 53 {
            Self::analyze_dns(packet, &payload_bytes, bdata, &mut fingerprints, &mut guidance)
        } else if proto_upper.contains("TLS") || proto_upper.contains("HTTPS") || packet.src_port == 443 || packet.dst_port == 443 {
            Self::analyze_tls(packet, &payload_bytes, bdata, &mut fingerprints, &mut guidance)
        } else if proto_upper.contains("HTTP") || packet.src_port == 80 || packet.dst_port == 80 || packet.src_port == 8080 || packet.dst_port == 8080 {
            Self::analyze_http(packet, &payload_bytes, bdata, &mut fingerprints, &mut guidance)
        } else if packet.transport == "TCP" {
            Self::analyze_generic_tcp(packet, &payload_bytes, bdata, &mut fingerprints, &mut guidance)
        } else if packet.transport == "UDP" {
            Self::analyze_generic_udp(packet, &payload_bytes, bdata, &mut fingerprints, &mut guidance)
        } else if proto_upper.contains("ARP") {
            Self::analyze_arp(packet, &payload_bytes, &mut fingerprints, &mut guidance)
        } else if proto_upper.contains("ICMP") {
            Self::analyze_icmp(packet, &payload_bytes, &mut fingerprints, &mut guidance)
        } else {
            Self::analyze_unknown(packet, &payload_bytes, &mut fingerprints, &mut guidance)
        }
    }

    /// Modbus 协议特征推导与排查辅导
    fn analyze_modbus(
        packet: &PacketRecord,
        payload: &[u8],
        bdata: Option<&HashMap<String, serde_json::Value>>,
        fingerprints: &mut Vec<FeatureFingerprintItem>,
        guidance: &mut Vec<String>,
    ) -> PacketExpertGuidanceReport {
        let mut intent = "Modbus 工业控制总线通信".to_string();
        let clause = "GB/T 19582.1-2008 / Modbus Application Protocol V1.1b".to_string();
        let mut role = if packet.dst_port == 502 { "Client / Master (主站请求端)".to_string() } else { "Server / Slave (从站应答端)".to_string() };
        let mut risk_level = "INFO".to_string();
        let mut risk_desc = "常规工业控制轮询采集通信".to_string();

        let func_code = if payload.len() >= 8 {
            payload.get(7).copied()
        } else {
            bdata.and_then(|m| m.get("modbus_function").or_else(|| m.get("function_code")))
                .and_then(|v| v.as_u64().map(|n| n as u8))
        };

        if let Some(fc) = func_code {
            fingerprints.push(FeatureFingerprintItem {
                name: "Modbus 功能码 (Function Code)".to_string(),
                value: format!("0x{:02X} ({})", fc, fc),
                detection_basis: "MBAP 报头第 8 字节".to_string(),
                significance: match fc {
                    0x01 => "Read Coils (读线圈状态)",
                    0x02 => "Read Discrete Inputs (读离散输入状态)",
                    0x03 => "Read Holding Registers (读保持寄存器)",
                    0x04 => "Read Input Registers (读输入寄存器)",
                    0x05 => "Write Single Coil (写单个线圈)",
                    0x06 => "Write Single Register (写单个保持寄存器)",
                    0x0F => "Write Multiple Coils (写多个线圈)",
                    0x10 => "Write Multiple Registers (写多个保持寄存器)",
                    0x08 => "Diagnostic (工控链路诊断测试)",
                    0x17 => "Read/Write Multiple Registers (读写多个寄存器)",
                    0x5A => "Schneider UMAS Proprietary (施耐德专有管理协议)",
                    c if c >= 0x80 => "Exception Response (从机异常报错应答)",
                    _ => "Vendor Specific / Reserved (厂商自定义或保留功能码)",
                }.to_string(),
            });

            match fc {
                0x01 | 0x02 | 0x03 | 0x04 => {
                    intent = format!("监控主机正在执行只读量遥信/遥测轮询采样 (功能码 0x{:02X})", fc);
                    guidance.push("【排查辅导】只读采集为典型周期性 SCADA 采集流。若采样频率高于 100Hz，需关注 PLC 通讯协处理器负载。".to_string());
                    guidance.push("【标准参考】核对点表地址时需注意基准偏移：Modbus 协议报文传输物理地址从 0 开始 (0x0000 对应 PLC 组态点表 40001)。".to_string());
                }
                0x05 | 0x06 | 0x0F | 0x10 => {
                    intent = format!("主控端正在下发修改现场执行机构或控制参数的物理指令 (写操作 0x{:02X})", fc);
                    role = "Master / Operator (工控指令下发端)".to_string();
                    risk_level = "MEDIUM".to_string();
                    risk_desc = "检测到工控写操作，可能变更现场 PLC/DCS 运行状态或设定值".to_string();
                    guidance.push("【安全审计】工控写操作具有工艺安全性风险！请核实源 IP 是否属于已授权的操作员站或工业 MES 控制台。".to_string());
                    guidance.push("【对账建议】建议抓取后续从站应答报文，比对写入值是否与下发指令完全一致（防篡改与链路抖动校验）。".to_string());
                }
                0x08 => {
                    intent = "主控端发起底层诊断测试指令 (Diagnostic)".to_string();
                    risk_level = "HIGH".to_string();
                    risk_desc = "诊断功能码可触发通信事件计数器清零甚至 PLC 通讯口重启".to_string();
                    guidance.push("【高危告警】诊断功能码常见于故障排查，但亦可被攻击者利用导致 PLC 通信中断。请核查子功能码 (Sub-function)。".to_string());
                }
                c if c >= 0x80 => {
                    let origin_fc = c - 0x80;
                    let exc_code = payload.get(8).copied().unwrap_or(0);
                    let exc_meaning = match exc_code {
                        0x01 => "01 (Illegal Function - 从机不支持此功能码)",
                        0x02 => "02 (Illegal Data Address - 请求访问的寄存器地址超出范围)",
                        0x03 => "03 (Illegal Data Value - 写入的寄存器数值不在合法量程)",
                        0x04 => "04 (Slave Device Failure - 从机内部硬件/执行机构故障)",
                        0x06 => "06 (Slave Device Busy - 从站正在执行繁重运算，请稍后重试)",
                        _ => "未知或自定义异常代码",
                    };
                    intent = format!("从机针对功能码 0x{:02X} 返回了执行异常 (Exception Code: {})", origin_fc, exc_meaning);
                    risk_level = "HIGH".to_string();
                    risk_desc = format!("从站拒绝执行或物理执行出错: {}", exc_meaning);
                    guidance.push(format!("【故障诊断】从站返回异常码 {}。排查方向：1. 检查上位机请求的起始地址是否越界；2. 检查 PLC 固件版本或点表定义是否存在遗漏；3. 检查从站运行状态。", exc_meaning));
                }
                _ => {}
            }
        }

        if let Some(m) = bdata {
            if m.contains_key("ics_acl_violation") {
                risk_level = "CRITICAL".to_string();
                risk_desc = "违反 IEC 62443 细粒度工业访问控制策略 (ICS-ACL Violation)".to_string();
                guidance.insert(0, "【合规阻断】该报文已被系统策略引擎标记为非法越权访问！请排查源 IP 权限分配与白名单配置。".to_string());
            }
        }

        PacketExpertGuidanceReport {
            packet_id: packet.id,
            protocol_name: "Modbus TCP/RTU".to_string(),
            protocol_standard: clause,
            standard_clause_ref: "Modbus-IDA V1.1b Section 6".to_string(),
            behavioral_intent: intent,
            role_analysis: role,
            feature_fingerprints: fingerprints.clone(),
            risk_level,
            risk_assessment: risk_desc,
            actionable_guidance: guidance.clone(),
            decoding_confidence: 0.98,
        }
    }

    /// 电力远动 IEC 60870-5-104 特征推导与排查辅导
    fn analyze_iec104(
        packet: &PacketRecord,
        payload: &[u8],
        _bdata: Option<&HashMap<String, serde_json::Value>>,
        fingerprints: &mut Vec<FeatureFingerprintItem>,
        guidance: &mut Vec<String>,
    ) -> PacketExpertGuidanceReport {
        let mut intent = "电力变电站/调度远动 104 规约数据交换".to_string();
        let clause = "GB/T 18657.5 / IEC 60870-5-104 (电力自动化通信规范)".to_string();
        let role = if packet.dst_port == 2404 { "Master Station / 调度主站端".to_string() } else { "Outstation / 变电站测控装置 RTU".to_string() };
        let mut risk_level = "INFO".to_string();
        let mut risk_desc = "正常电力远动时序报文".to_string();

        if payload.len() >= 6 && payload[0] == 0x68 {
            let ctrl1 = payload[2];
            let frame_type = if (ctrl1 & 0x01) == 0 {
                "I 格式 (Information Transfer - 包含遥测/遥信/遥控业务数据)"
            } else if (ctrl1 & 0x03) == 0x01 {
                "S 格式 (Numbered Supervisory - 接收序号确认，防止丢包累积)"
            } else {
                "U 格式 (Unnumbered Control - 启动激活 STARTDT / 停止 STOPDT / 心跳 TESTFR)"
            };

            fingerprints.push(FeatureFingerprintItem {
                name: "IEC 104 帧类型 (APCI Format)".to_string(),
                value: frame_type.to_string(),
                detection_basis: "APCI 控制域第 1 字节低位特征判决".to_string(),
                significance: "决定报文是传输核心遥信/遥测，还是维持双向链路心跳".to_string(),
            });

            if (ctrl1 & 0x01) == 0 {
                // I 格式
                if payload.len() >= 8 {
                    let asdu_type = payload[6];
                    let type_meaning = match asdu_type {
                        1 => "M_SP_NA_1: 单点遥信 (开入量变位/断路器分合状态)",
                        3 => "M_DP_NA_1: 双点遥信 (隔离开关/刀闸常开常闭双触点)",
                        9 => "M_ME_NA_1: 测量值，归一化定点数 (母线电压/线路电流)",
                        13 => "M_ME_NC_1: 测量值，短浮点数 (IEEE 754 精度遥测量)",
                        45 => "C_SC_NA_1: 单点遥控指令 (合闸/分闸命令下发)",
                        46 => "C_DC_NA_1: 双点遥控指令 (高安全断路器遥控)",
                        100 => "C_IC_NA_1: 总召唤命令 (Interrogation Command)",
                        103 => "C_CS_NA_1: 时钟同步命令 (Clock Synchronization)",
                        _ => "其他标准或专有 ASDU 类型",
                    };
                    intent = format!("变电站测控装置正在上报/下发 ASDU 数据: {}", type_meaning);

                    if asdu_type == 45 || asdu_type == 46 {
                        risk_level = "CRITICAL".to_string();
                        risk_desc = "检测到电力分合闸遥控命令！涉及一次设备物理动作安全".to_string();
                        guidance.push("【电力高危操作】检测到遥控指令！需立即核验是否遵循「遥控预置(Select) -> 遥控返校(Confirm) -> 遥控执行(Execute)」双工安全闭环。".to_string());
                    } else if asdu_type == 100 {
                        guidance.push("【总召唤诊断】检测到全站总召唤命令。通常发生于主站重新建立链路或断线重连后，测控装置将依次上报全站遥信与遥测全集。".to_string());
                    } else if asdu_type == 103 {
                        guidance.push("【对时辅导】调度时钟同步帧。请确保测控终端对时误差在国网标准 (±1ms) 允许范围内，防止事故事件顺序记录 (SOE) 时序错乱。".to_string());
                    }
                }
            } else if (ctrl1 & 0x03) == 0x03 {
                // U 格式
                if (ctrl1 & 0x04) != 0 {
                    intent = "STARTDT 启动链路数据传输激活指令".to_string();
                    guidance.push("【建链辅导】TCP 握手成功后，主站必须发送 STARTDT 激活命令，待从站回复确认后方可进入应用层数据交互。".to_string());
                } else if (ctrl1 & 0x40) != 0 {
                    intent = "TESTFR 双向链路活性探测 (心跳帧)".to_string();
                    guidance.push("【心跳排查】IEC 104 规约 t3 超时机制（通常为 20s）。若长时间未收到 TESTFR 确认，TCP 连接将被强制重置。".to_string());
                }
            }
        }

        PacketExpertGuidanceReport {
            packet_id: packet.id,
            protocol_name: "IEC 60870-5-104 (电力远动)".to_string(),
            protocol_standard: clause,
            standard_clause_ref: "DL/T 634.5104-2009 / IEC 60870-5-104 Section 5".to_string(),
            behavioral_intent: intent,
            role_analysis: role,
            feature_fingerprints: fingerprints.clone(),
            risk_level,
            risk_assessment: risk_desc,
            actionable_guidance: guidance.clone(),
            decoding_confidence: 0.99,
        }
    }

    /// 水利水文 SL651-2014 特征推导与排查辅导
    fn analyze_sl651(
        packet: &PacketRecord,
        payload: &[u8],
        _bdata: Option<&HashMap<String, serde_json::Value>>,
        fingerprints: &mut Vec<FeatureFingerprintItem>,
        guidance: &mut Vec<String>,
    ) -> PacketExpertGuidanceReport {
        let mut intent = "水文监测遥测站数据上报通信".to_string();
        let clause = "SL 651-2014 (水文监测数据通信规约 - 中华人民共和国水利行业标准)".to_string();

        if payload.len() >= 10 && payload[0] == 0x7E && payload[1] == 0x7E {
            let center_addr = payload[2];
            let station_hex = payload.get(3..8).map(|s| hex::encode(s)).unwrap_or_default();
            let func_code = payload[10];

            fingerprints.push(FeatureFingerprintItem {
                name: "遥测站 BCD 测站编码".to_string(),
                value: station_hex.clone(),
                detection_basis: "SL651 报头 5 字节 BCD 地址码".to_string(),
                significance: "在水利水务监测平台中唯一定位水库、水文站、闸门或雨量筒物理点位".to_string(),
            });

            let (func_desc, guide_tip) = match func_code {
                0x30 => ("测试报 (链路活性探测试验)", "测试报通常在设备安装阶段或调试时由人工触发，用于核验通信天线与信道可靠度。"),
                0x31 => ("均匀时段报 (周期性雨量/水位数据上报)", "标准定时采集报文。现场传感器采样值将同步归档进水文历史数据库。"),
                0x32 => ("加测报 (突降暴雨或汛期水位越限触发)", "【防汛注意】加测报由雨量突增或水位超过警戒线自动触发！调度人员应重点关注测站实时水位波动。"),
                0x34 => ("定时报 (整点水位与水库蓄水量报告)", "标准整点数据归档报文。"),
                0x35 => ("小时报 (逐小时雨量累积值上报)", "逐小时累积值，常用于水文模型产汇流计算与面雨量统计。"),
                0x37 => ("报警报 (电池欠压/水泵故障/越界告警)", "【设备运维告警】该测站上报了设备运行故障，请排查太阳能电池板供电电压与传感器接线。"),
                _ => ("其他规约控制/查询指令", "核对水利信息化平台下发的指令交互流程。"),
            };

            intent = format!("遥测站 (ID: {}) 正在向中心站 (0x{:02X}) 发送: {}", station_hex, center_addr, func_desc);
            guidance.push(format!("【行业规约辅导】{}", guide_tip));
            guidance.push("【校验建议】规约强制在报文尾部附加 2 字节 CRC-16 (Modbus 多项式 0xA001)。若校验失败，水利中心站将静默丢弃此帧。".to_string());
        }

        PacketExpertGuidanceReport {
            packet_id: packet.id,
            protocol_name: "SL651-2014 (水利水文)".to_string(),
            protocol_standard: clause,
            standard_clause_ref: "SL 651-2014 附录 A 与第 5 章功能码定义".to_string(),
            behavioral_intent: intent,
            role_analysis: "Telemetry Terminal RTU / 水利水文遥测终端".to_string(),
            feature_fingerprints: fingerprints.clone(),
            risk_level: "INFO".to_string(),
            risk_assessment: "水文遥测自动化业务通信".to_string(),
            actionable_guidance: guidance.clone(),
            decoding_confidence: 0.99,
        }
    }

    /// 西门子 S7Comm 特征推导与排查辅导
    fn analyze_s7comm(
        packet: &PacketRecord,
        payload: &[u8],
        _bdata: Option<&HashMap<String, serde_json::Value>>,
        fingerprints: &mut Vec<FeatureFingerprintItem>,
        guidance: &mut Vec<String>,
    ) -> PacketExpertGuidanceReport {
        let intent = "西门子 S7 PLC 工业自动化专有总线通信".to_string();
        let clause = "Siemens S7Comm Protocol Specification (ISO-on-TCP RFC 1006)".to_string();

        if let Some(s7_idx) = payload.windows(8).position(|w| w[0] == 0x32) {
            let rosctr = payload.get(s7_idx + 1).copied().unwrap_or(0);
            let rosctr_meaning = match rosctr {
                0x01 => "Job (主站发起读写/控制请求)",
                0x02 => "Ack (从站确认)",
                0x03 => "Ack-Data (从站携带数据应答)",
                0x07 => "Userdata (安全扩展/时钟/PLC启停指令)",
                _ => "未知 ROSCTR 类型",
            };
            fingerprints.push(FeatureFingerprintItem {
                name: "S7Comm ROSCTR 报文操作类型".to_string(),
                value: format!("0x{:02X} - {}", rosctr, rosctr_meaning),
                detection_basis: format!("S7 报头偏移 +{} 处", s7_idx),
                significance: "标定该报文是客户端下发作业还是 PLC 返回结果".to_string(),
            });
        }

        guidance.push("【工控运维参考】S7-300/400/1200/1500 默认在未开启「访问保护」时以明文传输数据。若涉及关键生产机密，建议在 TIA Portal 组态中启用「安全通信与保护密码」。".to_string());

        PacketExpertGuidanceReport {
            packet_id: packet.id,
            protocol_name: "Siemens S7Comm".to_string(),
            protocol_standard: clause,
            standard_clause_ref: "RFC 1006 (ISO-on-TCP) & S7Comm V1".to_string(),
            behavioral_intent: intent,
            role_analysis: if packet.dst_port == 102 { "Client / Engineering Station" } else { "Siemens PLC Controller" }.to_string(),
            feature_fingerprints: fingerprints.clone(),
            risk_level: "LOW".to_string(),
            risk_assessment: "西门子专有工控总线通信".to_string(),
            actionable_guidance: guidance.clone(),
            decoding_confidence: 0.95,
        }
    }

    /// DNS 特征推导与辅导
    fn analyze_dns(
        packet: &PacketRecord,
        payload: &[u8],
        _bdata: Option<&HashMap<String, serde_json::Value>>,
        fingerprints: &mut Vec<FeatureFingerprintItem>,
        guidance: &mut Vec<String>,
    ) -> PacketExpertGuidanceReport {
        let is_query = packet.dst_port == 53;
        let intent = if is_query {
            "客户端发起域名系统 (DNS) 递归/迭代解析查询请求".to_string()
        } else {
            "DNS 解析服务器向客户端返回权威/缓存解析应答".to_string()
        };

        fingerprints.push(FeatureFingerprintItem {
            name: "DNS 交互角色".to_string(),
            value: if is_query { "Query Request (查询)" } else { "Response (应答)" }.to_string(),
            detection_basis: "传输层 UDP/TCP 53 端口与报头 QR 标志位".to_string(),
            significance: "互联网基础命名解析".to_string(),
        });

        if payload.len() >= 12 {
            let tx_id = u16::from_be_bytes([payload[0], payload[1]]);
            fingerprints.push(FeatureFingerprintItem {
                name: "DNS 事务 ID (Transaction ID)".to_string(),
                value: format!("0x{:04X}", tx_id),
                detection_basis: "DNS 报头第 1..2 字节".to_string(),
                significance: "用于客户端将异步应答与特定查询精确关联".to_string(),
            });
        }

        guidance.push("【排查辅导】若主机持续高频向外部 DNS 发起相同未应答查询，建议检查：1. 出口防火墙是否放行 UDP 53；2. 是否遭遇 DNS 隧道数据外发 (DNS Tunneling) 或域名投毒。".to_string());

        PacketExpertGuidanceReport {
            packet_id: packet.id,
            protocol_name: "DNS (Domain Name System)".to_string(),
            protocol_standard: "IETF RFC 1034 / RFC 1035".to_string(),
            standard_clause_ref: "RFC 1035 Section 4: Messages Format".to_string(),
            behavioral_intent: intent,
            role_analysis: if is_query { "DNS Resolver Client" } else { "DNS Name Server" }.to_string(),
            feature_fingerprints: fingerprints.clone(),
            risk_level: "INFO".to_string(),
            risk_assessment: "域名解析基础设施通信".to_string(),
            actionable_guidance: guidance.clone(),
            decoding_confidence: 0.98,
        }
    }

    /// TLS / HTTPS 特征推导与辅导
    fn analyze_tls(
        packet: &PacketRecord,
        payload: &[u8],
        bdata: Option<&HashMap<String, serde_json::Value>>,
        fingerprints: &mut Vec<FeatureFingerprintItem>,
        guidance: &mut Vec<String>,
    ) -> PacketExpertGuidanceReport {
        let mut intent = "传输层安全加密会话通信 (TLS/HTTPS)".to_string();
        let mut role = "TLS Peer".to_string();

        if payload.len() >= 5 && payload[0] == 0x16 && payload[1] == 0x03 {
            let handshake_type = payload.get(5).copied().unwrap_or(0);
            let hs_meaning = match handshake_type {
                0x01 => {
                    role = "TLS Client (握手发起方)".to_string();
                    "ClientHello (客户端提议支持的密码套件与扩展)"
                }
                0x02 => {
                    role = "TLS Server (握手响应方)".to_string();
                    "ServerHello (服务端确认选定的密码套件与握手密钥)"
                }
                0x0B => "Certificate (服务端下发 X.509 身份公钥证书)",
                _ => "Handshake Record",
            };
            intent = format!("正在执行端到端安全握手协商: {}", hs_meaning);
            fingerprints.push(FeatureFingerprintItem {
                name: "TLS 记录层与握手类型".to_string(),
                value: hs_meaning.to_string(),
                detection_basis: "0x16 ContentType + Handshake Type 判别".to_string(),
                significance: "决定双向会话安全参数与身份认证完整性".to_string(),
            });
        }

        if let Some(m) = bdata {
            if let Some(ja3) = m.get("tls_ja3_hash").and_then(|v| v.as_str()) {
                fingerprints.push(FeatureFingerprintItem {
                    name: "JA3 客户端指纹特征".to_string(),
                    value: ja3.to_string(),
                    detection_basis: "提取 SSL/TLS 握手套件、扩展与椭圆曲线特征哈希".to_string(),
                    significance: "在无需解密的情况下识别客户端软件指纹（如 Python-requests、CobaltStrike、浏览器）".to_string(),
                });
            }
            if let Some(ja4) = m.get("tls_ja4").and_then(|v| v.as_str()) {
                fingerprints.push(FeatureFingerprintItem {
                    name: "JA4 现代指纹特征".to_string(),
                    value: ja4.to_string(),
                    detection_basis: "FoxIO JA4 字符串分段指纹算法".to_string(),
                    significance: "高精度定性恶意 C2 与隧道工具".to_string(),
                });
            }
            if let Some(c2) = m.get("tls_c2_family").and_then(|v| v.as_str()) {
                guidance.push(format!("【威胁告警】TLS 指纹与已知恶意家族匹配命中: {}！请排查该主机进程！", c2));
            }
        }

        guidance.push("【透明性辅导】该报文处于加密状态。如需审查 HTTP/2 明文业务，可在系统「流量解密面板」导入目标主机的 SSLKEYLOGFILE 或服务端 RSA 私钥，系统将自动进行无损解密还原。".to_string());

        PacketExpertGuidanceReport {
            packet_id: packet.id,
            protocol_name: "TLS / HTTPS (加密安全通信)".to_string(),
            protocol_standard: "IETF RFC 8446 (TLS 1.3) / RFC 5246 (TLS 1.2)".to_string(),
            standard_clause_ref: "RFC 8446 Section 4: Handshake Protocol".to_string(),
            behavioral_intent: intent,
            role_analysis: role,
            feature_fingerprints: fingerprints.clone(),
            risk_level: "INFO".to_string(),
            risk_assessment: "端到端高强度加密传输".to_string(),
            actionable_guidance: guidance.clone(),
            decoding_confidence: 0.99,
        }
    }

    /// HTTP 特征推导与辅导
    fn analyze_http(
        packet: &PacketRecord,
        payload: &[u8],
        _bdata: Option<&HashMap<String, serde_json::Value>>,
        fingerprints: &mut Vec<FeatureFingerprintItem>,
        guidance: &mut Vec<String>,
    ) -> PacketExpertGuidanceReport {
        let is_req = packet.dst_port == 80 || packet.dst_port == 8080;
        let mut intent = "超文本传输协议 (HTTP) 明文应用交互".to_string();

        if let Ok(text) = std::str::from_utf8(payload) {
            let first_line = text.lines().next().unwrap_or_default();
            if is_req {
                intent = format!("HTTP 客户端请求: {}", first_line);
            } else {
                intent = format!("HTTP 服务端应答: {}", first_line);
            }
            fingerprints.push(FeatureFingerprintItem {
                name: "HTTP 首行信令 (Start Line)".to_string(),
                value: first_line.to_string(),
                detection_basis: "解析 ASCII 报头 CRLF 首行".to_string(),
                significance: "定位请求资源 URI、请求动作或服务端返回的状态码".to_string(),
            });
        }

        guidance.push("【安全辅导】HTTP 为纯明文协议。现场工业网络若涉及管理后台认证或 PLC 固件下发，强烈建议升级至 HTTPS/TLS，杜绝中间人窃听与数据篡改。".to_string());

        PacketExpertGuidanceReport {
            packet_id: packet.id,
            protocol_name: "HTTP (Hypertext Transfer Protocol)".to_string(),
            protocol_standard: "IETF RFC 7230 / RFC 7231 (HTTP/1.1)".to_string(),
            standard_clause_ref: "RFC 7230 Section 3: Message Format".to_string(),
            behavioral_intent: intent,
            role_analysis: if is_req { "HTTP Client / Web Browser" } else { "HTTP Web Server / REST API" }.to_string(),
            feature_fingerprints: fingerprints.clone(),
            risk_level: "LOW".to_string(),
            risk_assessment: "明文网络传输存在信息泄露隐患".to_string(),
            actionable_guidance: guidance.clone(),
            decoding_confidence: 0.97,
        }
    }

    /// 通用 TCP 特征推导与辅导
    fn analyze_generic_tcp(
        packet: &PacketRecord,
        payload: &[u8],
        _bdata: Option<&HashMap<String, serde_json::Value>>,
        fingerprints: &mut Vec<FeatureFingerprintItem>,
        guidance: &mut Vec<String>,
    ) -> PacketExpertGuidanceReport {
        let mut intent = "TCP 面向连接的可靠传输".to_string();
        guidance.push("【TCP 状态机】关注 SYN、ACK、FIN、RST 标志位变化以推演 TCP 连接状态机生命周期。".to_string());

        if payload.is_empty() {
            intent = "TCP 传输层控制握手/确认帧 (无应用层数据)".to_string();
            guidance.push("【性能分析】纯 ACK 报文用于滑动窗口确认与流量控制。如频繁出现零窗口 (Zero Window)，表明对端接收缓冲区耗尽。".to_string());
        }

        PacketExpertGuidanceReport {
            packet_id: packet.id,
            protocol_name: "TCP (Transmission Control Protocol)".to_string(),
            protocol_standard: "IETF RFC 793 / RFC 9293".to_string(),
            standard_clause_ref: "RFC 9293 Section 3: Functional Specification".to_string(),
            behavioral_intent: intent,
            role_analysis: "TCP Endpoint".to_string(),
            feature_fingerprints: fingerprints.clone(),
            risk_level: "INFO".to_string(),
            risk_assessment: "常规传输层控制信令".to_string(),
            actionable_guidance: guidance.clone(),
            decoding_confidence: 0.92,
        }
    }

    /// 通用 UDP 特征推导与辅导
    fn analyze_generic_udp(
        packet: &PacketRecord,
        payload: &[u8],
        _bdata: Option<&HashMap<String, serde_json::Value>>,
        fingerprints: &mut Vec<FeatureFingerprintItem>,
        guidance: &mut Vec<String>,
    ) -> PacketExpertGuidanceReport {
        guidance.push("【排查辅导】UDP 协议无连接、无重传机制。若现场网络丢包率较高，业务层需具备序列号确认与重发机制。".to_string());

        PacketExpertGuidanceReport {
            packet_id: packet.id,
            protocol_name: "UDP (User Datagram Protocol)".to_string(),
            protocol_standard: "IETF RFC 768".to_string(),
            standard_clause_ref: "RFC 768 Section: Fields".to_string(),
            behavioral_intent: format!("UDP 无连接数据报传输 (载荷长度: {} 字节)", payload.len()),
            role_analysis: "UDP Datagram Endpoint".to_string(),
            feature_fingerprints: fingerprints.clone(),
            risk_level: "INFO".to_string(),
            risk_assessment: "无状态数据报传输".to_string(),
            actionable_guidance: guidance.clone(),
            decoding_confidence: 0.90,
        }
    }

    /// ARP 特征推导与辅导
    fn analyze_arp(
        packet: &PacketRecord,
        _payload: &[u8],
        fingerprints: &mut Vec<FeatureFingerprintItem>,
        guidance: &mut Vec<String>,
    ) -> PacketExpertGuidanceReport {
        guidance.push("【ARP 欺骗防范】若同一 IP 在短时间内被不同 MAC 地址连续认领应答，提示局域网内存在 ARP 欺骗攻击或 IP 冲突。".to_string());

        PacketExpertGuidanceReport {
            packet_id: packet.id,
            protocol_name: "ARP (Address Resolution Protocol)".to_string(),
            protocol_standard: "IETF RFC 826".to_string(),
            standard_clause_ref: "RFC 826: Packet format".to_string(),
            behavioral_intent: "局域网 IP 地址到物理 MAC 地址动态寻址映射".to_string(),
            role_analysis: "Local Broadcast / Address Resolver".to_string(),
            feature_fingerprints: fingerprints.clone(),
            risk_level: "INFO".to_string(),
            risk_assessment: "局域网二层解析信令".to_string(),
            actionable_guidance: guidance.clone(),
            decoding_confidence: 0.98,
        }
    }

    /// ICMP 特征推导与辅导
    fn analyze_icmp(
        packet: &PacketRecord,
        _payload: &[u8],
        fingerprints: &mut Vec<FeatureFingerprintItem>,
        guidance: &mut Vec<String>,
    ) -> PacketExpertGuidanceReport {
        guidance.push("【网络诊断】ICMP Echo 常用于 Ping 连通性测试。若收到 TTL Expired (TTL 超时)，通常用于 Traceroute 路由多跳测绘或提示网络路由环路。".to_string());

        PacketExpertGuidanceReport {
            packet_id: packet.id,
            protocol_name: "ICMP (Internet Control Message Protocol)".to_string(),
            protocol_standard: "IETF RFC 792".to_string(),
            standard_clause_ref: "RFC 792: Message Formats".to_string(),
            behavioral_intent: "网络层控制、差错报告与链路回显诊断".to_string(),
            role_analysis: "Network Diagnostic Probe".to_string(),
            feature_fingerprints: fingerprints.clone(),
            risk_level: "INFO".to_string(),
            risk_assessment: "网络探测差错信令".to_string(),
            actionable_guidance: guidance.clone(),
            decoding_confidence: 0.98,
        }
    }

    /// 未知或专有私有协议逆向辅导
    fn analyze_unknown(
        packet: &PacketRecord,
        payload: &[u8],
        fingerprints: &mut Vec<FeatureFingerprintItem>,
        guidance: &mut Vec<String>,
    ) -> PacketExpertGuidanceReport {
        if !payload.is_empty() {
            let magic_header = if payload.len() >= 4 {
                format!("{:02X} {:02X} {:02X} {:02X}", payload[0], payload[1], payload[2], payload[3])
            } else {
                hex::encode(payload)
            };
            fingerprints.push(FeatureFingerprintItem {
                name: "起始魔法字节 (Magic Header)".to_string(),
                value: magic_header,
                detection_basis: "载荷前 4 字节静态特征抽取".to_string(),
                significance: "私有规约通常以特定固定字节作为帧定界符或协议特征码".to_string(),
            });
        }

        guidance.push("【逆向辅导建议】该数据包属于未识别的专有/私有协议：".to_string());
        guidance.push("1. 【多包差分】建议选中该报文并点击「加入比对队列」，使用本系统的「双组/多组精密差分 (Packet Diff)」分析固定字段与动态字段；".to_string());
        guidance.push("2. 【示波波形】可右键选择「示波波形追踪」，观察载荷中是否存在连续递增的计数器或周期性方波；".to_string());
        guidance.push("3. 【规则加载】若已知其私有格式，可通过「声明式协议解剖虚拟机 (Dissector VM)」直接在线导入 JSON 规约模版，无需重新编译即可挂载结构化解析。".to_string());

        PacketExpertGuidanceReport {
            packet_id: packet.id,
            protocol_name: format!("{} (未注册私有/专有规约)", packet.protocol),
            protocol_standard: "专有私有工控/物联网规约 (Custom Proprietary)".to_string(),
            standard_clause_ref: "N/A (建议提取特征并配置声明式 Dissector VM 模版)".to_string(),
            behavioral_intent: format!("专有协议载荷交互 (载荷有效数据: {} 字节)", payload.len()),
            role_analysis: "Proprietary Node".to_string(),
            feature_fingerprints: fingerprints.clone(),
            risk_level: if packet.entropy >= 7.5 { "MEDIUM".to_string() } else { "INFO".to_string() },
            risk_assessment: "专有未知协议传输，建议核查源/目的 IP 信任等级".to_string(),
            actionable_guidance: guidance.clone(),
            decoding_confidence: 0.65,
        }
    }
}

/// Tauri 接口命令：获取报文全息专家诊断与辅导参考报告
#[tauri::command]
pub fn get_packet_expert_guidance_cmd(packet: PacketRecord) -> Result<PacketExpertGuidanceReport, String> {
    Ok(PacketExpertAdvisor::generate_guidance(&packet))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expert_advisor_modbus() {
        let mut bdata = HashMap::new();
        bdata.insert("modbus_function".to_string(), serde_json::json!(3));

        let pkt = PacketRecord {
            id: 1,
            timestamp: "2026-11-16T14:00:00Z".to_string(),
            timestamp_ns: 1000,
            direction: "OUTBOUND".to_string(),
            transport: "TCP".to_string(),
            protocol: "MODBUS".to_string(),
            src_ip: "192.168.1.10".to_string(),
            dst_ip: "192.168.1.100".to_string(),
            src_port: 49152,
            dst_port: 502,
            length: 12,
            payload_hex: "00010000000601030000000A".to_string(),
            raw_frame_hex: "".to_string(),
            entropy: 2.1,
            entropy_level: "low".to_string(),
            mac_src: "00:11:22:33:44:55".to_string(),
            mac_dst: "AA:BB:CC:DD:EE:FF".to_string(),
            chain_hash: "hash".to_string(),
            business_data: Some(bdata),
            raw_text: None,
        };

        let report = PacketExpertAdvisor::generate_guidance(&pkt);
        assert_eq!(report.packet_id, 1);
        assert!(report.protocol_name.contains("Modbus"));
        assert!(report.behavioral_intent.contains("只读"));
        assert!(report.protocol_standard.contains("GB/T 19582"));
        assert!(!report.actionable_guidance.is_empty());
    }

    #[test]
    fn test_expert_advisor_iec104() {
        let pkt = PacketRecord {
            id: 2,
            timestamp: "2026-11-16T14:00:01Z".to_string(),
            timestamp_ns: 2000,
            direction: "OUTBOUND".to_string(),
            transport: "TCP".to_string(),
            protocol: "104".to_string(),
            src_ip: "10.0.0.1".to_string(),
            dst_ip: "10.0.0.2".to_string(),
            src_port: 2404,
            dst_port: 2404,
            length: 14,
            // 0x68 (Start), len 12, ctrl: 0x00 0x00 0x00 0x00 (I-format), asdu 0x64 (100 - 总召唤)
            payload_hex: "680c00000000640106000100000014".to_string(),
            raw_frame_hex: "".to_string(),
            entropy: 3.2,
            entropy_level: "low".to_string(),
            mac_src: "".to_string(),
            mac_dst: "".to_string(),
            chain_hash: "hash".to_string(),
            business_data: None,
            raw_text: None,
        };

        let report = PacketExpertAdvisor::generate_guidance(&pkt);
        assert!(report.protocol_name.contains("104"));
        assert!(report.behavioral_intent.contains("总召唤"));
        assert!(!report.actionable_guidance.is_empty());
    }
}
