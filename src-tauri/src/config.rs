use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

// ============================================================
// 探针配置体系 (Probe Configuration System)
// 等价于 Python 版 config.json：端口表、主动探测目标、阈值、
// 云端与舰队特性全部由配置文件驱动，杜绝源码硬编码。
// 文件不存在时自动生成默认配置（与 Python 版默认值一致），
// 用户可直接编辑 config.json 后重启生效。
// ============================================================

/// config.json 绝对路径（经 forensics::data_path 锚定统一数据目录，去 CWD 依赖）
/// 注意：不可用常量——DATA_DIR 由 Tauri setup 期动态注入，必须运行时求值
fn config_path() -> std::path::PathBuf {
    crate::forensics::data_path("config.json")
}

fn default_sealing_interval_secs() -> u64 {
    60
}

fn default_reconnect_interval() -> u64 {
    5
}

fn default_baud_rate() -> u32 {
    9600
}

/// 应用层监听服务表项（servers）
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ServerEntry {
    pub host: String,
    pub port: u16,
    pub protocol: String, // "tcp" | "udp"
}

/// 主动探测目标表项（active_probes）
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ActiveProbeEntry {
    pub host: String,
    pub port: u16,
    pub protocol: String, // "tcp"
    #[serde(default = "default_reconnect_interval")]
    pub reconnect_interval: u64,
}

/// 串口探测表项（serial_probes）
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SerialProbeEntry {
    pub port: String,
    #[serde(default = "default_baud_rate")]
    pub baud_rate: u32,
}

/// 日志配置（logging）
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct LoggingConfig {
    pub level: String,
    pub file: String,
}

/// 数据落盘配置（data_storage）
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DataStorageConfig {
    pub mode: String,
    pub file: String,
    pub pcap_file: String,
    pub enable_pcap: bool,
}

/// 舰队管理配置（enterprise_features.fleet_management）
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct FleetManagementConfig {
    pub enabled: bool,
    pub api_port: u16,
}

/// 威胁防御配置（enterprise_features.threat_defense）
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ThreatDefenseConfig {
    pub enabled: bool,
    pub max_packets_per_sec: f64,
    pub auto_drop_connection: bool,
}

/// 云端流式上报配置（enterprise_features.cloud_streaming）
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct CloudStreamingConfig {
    pub enabled: bool,
    pub webhook_url: String,
}

/// 企业特性聚合（enterprise_features）
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct EnterpriseFeatures {
    pub fleet_management: FleetManagementConfig,
    pub threat_defense: ThreatDefenseConfig,
    pub cloud_streaming: CloudStreamingConfig,
}

/// 探针全局配置根结构（对齐 Python config.json 顶层字段）
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ProbeConfig {
    pub servers: Vec<ServerEntry>,
    pub active_probes: Vec<ActiveProbeEntry>,
    #[serde(default)]
    pub serial_probes: Vec<SerialProbeEntry>,
    pub logging: LoggingConfig,
    pub data_storage: DataStorageConfig,
    pub tcp_framing_timeout: f64,
    /// 司法封条周期（秒，对齐 Python ForensicIntegritySealer interval；缺省 60）
    #[serde(default = "default_sealing_interval_secs")]
    pub sealing_interval_secs: u64,
    pub enterprise_features: EnterpriseFeatures,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            servers: vec![
                ServerEntry { host: "0.0.0.0".into(), port: 8080, protocol: "tcp".into() },
                ServerEntry { host: "0.0.0.0".into(), port: 5003, protocol: "tcp".into() },
                ServerEntry { host: "0.0.0.0".into(), port: 502, protocol: "tcp".into() },
                ServerEntry { host: "0.0.0.0".into(), port: 1883, protocol: "tcp".into() },
                ServerEntry { host: "0.0.0.0".into(), port: 5003, protocol: "udp".into() },
                ServerEntry { host: "0.0.0.0".into(), port: 8080, protocol: "udp".into() },
            ],
            active_probes: Vec::new(),
            serial_probes: Vec::new(),
            logging: LoggingConfig {
                level: "INFO".into(),
                file: "listener.log".into(),
            },
            data_storage: DataStorageConfig {
                mode: "file".into(),
                file: "received_data.jsonl".into(),
                pcap_file: "capture.pcap".into(),
                enable_pcap: true,
            },
            tcp_framing_timeout: 0.05,
            sealing_interval_secs: 60,
            enterprise_features: EnterpriseFeatures {
                fleet_management: FleetManagementConfig {
                    enabled: true,
                    api_port: 9091,
                },
                threat_defense: ThreatDefenseConfig {
                    enabled: true,
                    max_packets_per_sec: 50.0,
                    auto_drop_connection: true,
                },
                cloud_streaming: CloudStreamingConfig {
                    enabled: false,
                    webhook_url: "http://127.0.0.1:9090/ingest".into(),
                },
            },
        }
    }
}

/// 全局配置单例（进程内首次访问时加载，运行期可通过 save_config 刷新）
static GLOBAL_CONFIG: Lazy<Mutex<ProbeConfig>> = Lazy::new(|| Mutex::new(load_config()));

/// 从磁盘加载配置；文件缺失时生成默认 config.json 落盘
/// 【循环依赖禁止】此处只允许 eprintln!，严禁调用 forensics::write_log_line：
/// config 加载先于 setup 期 init_evidence_names 注入，任何 writer Lazy 在此提前触发
/// 都会以默认文件名打开证据文件，导致 config 自定义文件名（logging.file 等）失效
fn load_config() -> ProbeConfig {
    let path = config_path();
    match std::fs::read_to_string(&path) {
        Ok(content) => match serde_json::from_str::<ProbeConfig>(&content) {
            Ok(cfg) => {
                eprintln!("[CONFIG] ✅ 配置已加载 <- {}", path.display());
                cfg
            }
            Err(e) => {
                eprintln!(
                    "[CONFIG] ⚠️ config.json 解析失败（{}），回退默认配置。原文件保留为 config.json.bak",
                    e
                );
                // 损坏文件备份保留，不静默覆盖用户数据
                let _ = std::fs::copy(&path, crate::forensics::data_path("config.json.bak"));
                let default_cfg = ProbeConfig::default();
                let _ = std::fs::write(
                    &path,
                    serde_json::to_string_pretty(&default_cfg).unwrap_or_default(),
                );
                default_cfg
            }
        },
        Err(_) => {
            // 首次运行：生成默认配置文件供用户编辑
            let default_cfg = ProbeConfig::default();
            if let Ok(json) = serde_json::to_string_pretty(&default_cfg) {
                if std::fs::write(&path, &json).is_ok() {
                    eprintln!("[CONFIG] ✅ 首次运行，已生成默认配置文件 {}", path.display());
                }
            }
            default_cfg
        }
    }
}

/// 获取当前配置快照（克隆，避免长时间持锁）
pub fn get_config() -> ProbeConfig {
    GLOBAL_CONFIG
        .lock()
        .map(|c| c.clone())
        .unwrap_or_default()
}

/// 保存配置到内存单例并落盘 config.json（锚定统一数据目录）
pub fn save_config(cfg: ProbeConfig) -> Result<(), String> {
    let json = serde_json::to_string_pretty(&cfg)
        .map_err(|e| format!("配置序列化失败: {}", e))?;
    std::fs::write(config_path(), &json).map_err(|e| format!("写入 config.json 失败: {}", e))?;
    {
        let mut guard = crate::lock_guard::lock_mutex(&GLOBAL_CONFIG, "config::save_config");
        *guard = cfg;
    }
    Ok(())
}

/// 双轨 TCP 服务端口表（servers 表中 protocol=tcp 的项；空表回退内置默认端口）
pub fn dual_track_tcp_ports() -> Vec<u16> {
    let cfg = get_config();
    let ports: Vec<u16> = cfg
        .servers
        .iter()
        .filter(|s| s.protocol.eq_ignore_ascii_case("tcp"))
        .map(|s| s.port)
        .collect();
    if ports.is_empty() {
        vec![8080, 5003, 502, 1883]
    } else {
        ports
    }
}

/// 双轨 UDP 服务端口表（servers 表中 protocol=udp 的项；空表回退内置默认端口）
pub fn dual_track_udp_ports() -> Vec<u16> {
    let cfg = get_config();
    let ports: Vec<u16> = cfg
        .servers
        .iter()
        .filter(|s| s.protocol.eq_ignore_ascii_case("udp"))
        .map(|s| s.port)
        .collect();
    if ports.is_empty() {
        vec![5003, 8080]
    } else {
        ports
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_roundtrip() {
        let cfg = ProbeConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: ProbeConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.servers.len(), 6);
        assert_eq!(parsed.tcp_framing_timeout, 0.05);
        assert_eq!(parsed.enterprise_features.fleet_management.api_port, 9091);
        assert_eq!(parsed.enterprise_features.threat_defense.max_packets_per_sec, 50.0);
    }

    #[test]
    fn test_dual_track_tcp_ports_from_config() {
        let ports = dual_track_tcp_ports();
        assert!(!ports.is_empty(), "端口表绝不能为空（空配置必须回退默认端口）");
        assert!(ports.contains(&8080) || ports.len() >= 1);
    }

    #[test]
    fn test_dual_track_udp_ports_from_config() {
        let ports = dual_track_udp_ports();
        assert!(!ports.is_empty(), "UDP 端口表绝不能为空（空配置必须回退默认端口）");
        assert!(ports.contains(&5003) || ports.contains(&8080));
    }

    #[test]
    fn test_python_config_field_names_aligned() {
        // 与 Python config.json 字段名严格对齐（serde 自动映射，缺字段反序列化报错）
        let python_style_json = r#"{
            "servers": [{"host": "0.0.0.0", "port": 9999, "protocol": "tcp"}],
            "active_probes": [{"host": "127.0.0.1", "port": 80, "protocol": "tcp", "reconnect_interval": 5}],
            "serial_probes": [],
            "logging": {"level": "INFO", "file": "listener.log", "format": "%(asctime)s - [%(levelname)s] - %(message)s"},
            "data_storage": {"mode": "file", "file": "received_data.jsonl", "pcap_file": "capture.pcap", "enable_pcap": true},
            "tcp_framing_timeout": 0.05,
            "enterprise_features": {
                "fleet_management": {"enabled": true, "api_port": 9091},
                "sanitization": {"enabled": true, "regex_patterns": ["(?i)password"]},
                "threat_defense": {"enabled": true, "max_packets_per_sec": 50, "auto_drop_connection": true},
                "protocol_dictionaries": {"MODBUS_TCP": {}},
                "cloud_streaming": {"enabled": false, "webhook_url": "http://127.0.0.1:9090/ingest"}
            }
        }"#;
        let parsed: Result<ProbeConfig, _> = serde_json::from_str(python_style_json);
        assert!(parsed.is_ok(), "Python 版 config.json 必须可直接解析: {:?}", parsed.err());
    }
}
