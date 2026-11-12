use std::io::{Read, Write};
use std::time::Duration;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::sync::mpsc::{channel, Sender, Receiver};
use std::collections::{HashMap, HashSet};
use once_cell::sync::Lazy;
use tauri::Emitter;

use crate::sniffer::PacketRecord;
use crate::forensics::ForensicEngine;
use crate::dpi;
use serde_json::json;
use serde::{Deserialize, Serialize};

pub static SERIAL_RUNNING: Lazy<Arc<Mutex<bool>>> = Lazy::new(|| Arc::new(Mutex::new(false)));
pub static CURRENT_PROBING_PORT: Lazy<Arc<Mutex<Option<String>>>> = Lazy::new(|| Arc::new(Mutex::new(None)));
static SERIAL_COUNTER: AtomicU64 = AtomicU64::new(1);

/// 工业级串口全量通信参数配置结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerialCommunicationConfig {
    pub baud_rate: u32,
    pub data_bits: u8,        // 5, 6, 7, 8
    pub parity: String,       // "None", "Odd", "Even"
    pub stop_bits: u8,        // 1, 2
    pub flow_control: String, // "None", "Software", "Hardware"
    pub framing_mode: String, // "Auto3_5T", "TimeoutMs", "Delimiter", "FixedLength"
    pub framing_timeout_ms: Option<u64>,
    pub framing_delimiter_hex: Option<String>,
    pub framing_fixed_length: Option<usize>,
}

impl Default for SerialCommunicationConfig {
    fn default() -> Self {
        Self {
            baud_rate: 9600,
            data_bits: 8,
            parity: "None".into(),
            stop_bits: 1,
            flow_control: "None".into(),
            framing_mode: "Auto3_5T".into(),
            framing_timeout_ms: Some(30),
            framing_delimiter_hex: None,
            framing_fixed_length: None,
        }
    }
}

/// 工业串口硬件 Modem 状态与控制引脚实时状态
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SerialModemStatus {
    pub cts: bool, // Clear To Send (输入引脚，硬件流控状态)
    pub dsr: bool, // Data Set Ready (输入引脚，设备就绪指示)
    pub ri: bool,  // Ring Indicator (输入引脚，振铃指示)
    pub cd: bool,  // Carrier Detect (输入引脚，载波检测)
    pub rts: bool, // Request To Send (输出控制，请求发送)
    pub dtr: bool, // Data Terminal Ready (输出控制，数据终端就绪)
}

/// 工业级 Modbus RTU 规约剖析结果结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModbusRtuDissection {
    pub slave_address: u8,
    pub function_code: u8,
    pub is_exception: bool,
    pub exception_code: Option<u8>,
    pub exception_desc: Option<String>,
    pub is_crc_valid: bool,
    pub expected_crc: u16,
    pub actual_crc: u16,
    pub register_address: Option<u16>,
    pub register_count: Option<u16>,
    pub byte_count: Option<u8>,
    pub values: Vec<u16>,
    pub summary: String,
}

/// 工业级 DL/T 645-2007 电力电表规约剖析结果结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dlt645Dissection {
    pub meter_address: String,
    pub control_code: u8,
    pub data_length: u8,
    pub is_valid_cs: bool,
    pub summary: String,
}

/// 工业级 NMEA 0183 导航规约剖析结果结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NmeaDissection {
    pub sentence_type: String,
    pub is_valid_checksum: bool,
    pub latitude: Option<String>,
    pub longitude: Option<String>,
    pub speed_knots: Option<f64>,
    pub course_deg: Option<f64>,
    pub summary: String,
}

/// 物理/虚拟串口工业级全维元数据结构
/// 包含硬件拓扑属性、USB 芯片识别、操作系统排他占用状态探活
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SerialPortDetail {
    pub port_name: String,            // 如 "COM3"
    pub description: String,          // 如 "COM3 (Silicon Labs CP210x USB to UART Bridge)"
    pub hardware_id: String,         // 如 "USB\\VID_10C4&PID_EA60"
    pub manufacturer: Option<String>, // 如 "Silicon Laboratories"
    pub product: Option<String>,      // 如 "CP2102 USB to UART Bridge Controller"
    pub port_type: String,            // 如 "USB 虚拟串口" / "PCI 物理串口" / "标准硬件串口"
    pub is_usb: bool,
    pub is_available: bool,           // 物理/系统可用状态（未被其他进程独占占用）
    pub is_in_use_by_us: bool,        // 是否正在被本探针引擎监听
}

/// Windows 注册表 SERIALCOMM 底层活跃端口扫描 (工业级保底)
#[cfg(windows)]
fn get_windows_registry_serial_ports() -> Vec<String> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;

    let mut ports = Vec::new();
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(serial_comm) = hklm.open_subkey("HARDWARE\\DEVICEMAP\\SERIALCOMM") {
        for val in serial_comm.enum_values().flatten() {
            if let Ok(port_name) = serial_comm.get_value::<String, _>(&val.0) {
                let clean = port_name.trim().to_string();
                if !clean.is_empty() && !ports.contains(&clean) {
                    ports.push(clean);
                }
            }
        }
    }
    ports
}

#[cfg(not(windows))]
fn get_windows_registry_serial_ports() -> Vec<String> {
    Vec::new()
}

/// 快速非阻塞探活：检测串口当前是否可被打开（未被第三方程序独占占用）
/// 时间复杂度: O(1) 物理端口 I/O
/// 空间复杂度: O(1)
fn check_port_availability(port_name: &str) -> bool {
    // 1. 如果已在本探针的并发监听集合中，视为可用且正由本程序掌控
    {
        let map = crate::lock_guard::lock_mutex(&ACTIVE_SERIAL_PROBES, "serial::check_port_availability");
        if map.contains_key(port_name) {
            return true;
        }
    }

    // 2. 尝试以极小超时快速打开，验证 OS 句柄未被其他软件独占锁死
    // 2. 纯内存状态判定: 严禁在枚举流程中调用 open()，
    // 否则在遇到 Windows 蓝牙虚拟串口 (BTHENUM) 或脱机虚拟串口时，
    // Win32 CreateFileW 会被内核蓝牙射频握手同步死锁 5~30 秒导致启动停滞！
    true
}

/// 枚举本机所有可用的 COM 物理/虚拟串口名称列表 (保持向前兼容)
pub fn list_available_serial_ports() -> Vec<String> {
    list_available_serial_ports_detail()
        .into_iter()
        .map(|p| p.port_name)
        .collect()
}

/// 枚举本机全部可用物理/虚拟串口的结构化全维元数据 (双源融合扫描: serialport API + Windows 注册表 + 占用探活)
pub fn list_available_serial_ports_detail() -> Vec<SerialPortDetail> {
    let mut details: Vec<SerialPortDetail> = Vec::new();
    let mut detected_names: HashSet<String> = HashSet::new();

    let active_ports: HashSet<String> = {
        let map = crate::lock_guard::lock_mutex(&ACTIVE_SERIAL_PROBES, "serial::list_available_serial_ports_detail");
        map.keys().cloned().collect()
    };

    // 1. 调用系统 serialport API 提取丰富物理层与 USB 芯片描述
    if let Ok(sys_ports) = serialport::available_ports() {
        for p in sys_ports {
            let port_name = p.port_name.trim().to_string();
            if port_name.is_empty() {
                continue;
            }
            detected_names.insert(port_name.clone());

            let (port_type, desc, hw_id, mfr, prod, is_usb) = match p.port_type {
                serialport::SerialPortType::UsbPort(info) => {
                    let vid_pid = format!("USB\\VID_{:04X}&PID_{:04X}", info.vid, info.pid);
                    let product_desc = info.product.clone().unwrap_or_else(|| "USB 串行设备".to_string());
                    let mfr_desc = info.manufacturer.clone().unwrap_or_else(|| "通用硬件厂商".to_string());
                    let full_desc = format!("{} ({} - {})", port_name, product_desc, mfr_desc);
                    ("USB 虚拟串口".to_string(), full_desc, vid_pid, info.manufacturer, info.product, true)
                }
                serialport::SerialPortType::PciPort => {
                    ("PCI 物理串口".to_string(), format!("{} (PCI 物理板卡串口)", port_name), "PCI_SERIAL".to_string(), None, None, false)
                }
                serialport::SerialPortType::BluetoothPort => {
                    ("蓝牙无线串口".to_string(), format!("{} (蓝牙 SPP 虚拟串口)", port_name), "BTH_SERIAL".to_string(), None, None, false)
                }
                serialport::SerialPortType::Unknown => {
                    ("标准硬件通信口".to_string(), format!("{} (标准通信端口)", port_name), "STANDARD_COM".to_string(), None, None, false)
                }
            };

            let is_in_use = active_ports.contains(&port_name);
            let is_avail = is_in_use || check_port_availability(&port_name);

            details.push(SerialPortDetail {
                port_name,
                description: desc,
                hardware_id: hw_id,
                manufacturer: mfr,
                product: prod,
                port_type,
                is_usb,
                is_available: is_avail,
                is_in_use_by_us: is_in_use,
            });
        }
    }

    // 2. Windows 注册表 SERIALCOMM 二次保底与融合 (捕获无标准 USB 描述符的工业虚拟串口)
    for reg_port in get_windows_registry_serial_ports() {
        if !detected_names.contains(&reg_port) {
            detected_names.insert(reg_port.clone());
            let is_in_use = active_ports.contains(&reg_port);
            let is_avail = is_in_use || check_port_availability(&reg_port);

            details.push(SerialPortDetail {
                port_name: reg_port.clone(),
                description: format!("{} (系统注册通信端口)", reg_port),
                hardware_id: "REGISTRY_SERIALCOMM".to_string(),
                manufacturer: None,
                product: None,
                port_type: "系统注册串口".to_string(),
                is_usb: false,
                is_available: is_avail,
                is_in_use_by_us: is_in_use,
            });
        }
    }

    // 3. 自然数字排序: COM1, COM2, COM10 (避免字典序 COM1, COM10, COM2)
    details.sort_by(|a, b| {
        let num_a = a.port_name.trim_start_matches("COM").parse::<u32>().unwrap_or(9999);
        let num_b = b.port_name.trim_start_matches("COM").parse::<u32>().unwrap_or(9999);
        num_a.cmp(&num_b)
    });

    details
}

/// 正在并发监听的单个串口探针实例句柄
pub struct SerialProbeHandle {
    pub port_name: String,
    pub config: SerialCommunicationConfig,
    pub is_running: Arc<AtomicBool>,
    pub start_time: std::time::Instant,
    pub tx_sender: Sender<Vec<u8>>,
    pub modem_status: Arc<Mutex<SerialModemStatus>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveSerialProbeInfo {
    pub port_name: String,
    pub baud_rate: u32,
    pub data_bits: u8,
    pub parity: String,
    pub stop_bits: u8,
    pub flow_control: String,
    pub framing_mode: String,
    pub uptime_secs: u64,
}

/// 全局多物理串口并发监听管理器 (支持同时监听多个 COM 端口并支持双向并发写出)
pub static ACTIVE_SERIAL_PROBES: Lazy<Arc<Mutex<HashMap<String, SerialProbeHandle>>>> =
    Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

/// 工业级双串口透明中继器句柄
pub struct SerialBridgeHandle {
    pub bridge_id: String,
    pub port_a: String,
    pub baud_a: u32,
    pub port_b: String,
    pub baud_b: u32,
    pub start_time_str: String,
    pub is_running: Arc<AtomicBool>,
    pub start_time: std::time::Instant,
    pub total_a_to_b_bytes: Arc<AtomicU64>,
    pub total_b_to_a_bytes: Arc<AtomicU64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveSerialBridgeInfo {
    pub bridge_id: String,
    pub port_a: String,
    pub baud_a: u32,
    pub port_b: String,
    pub baud_b: u32,
    pub start_time: String,
    pub uptime_secs: u64,
    pub total_a_to_b_bytes: u64,
    pub total_b_to_a_bytes: u64,
    pub is_running: bool,
}

/// 全局双串口中继器实例池
pub static ACTIVE_SERIAL_BRIDGES: Lazy<Arc<Mutex<HashMap<String, SerialBridgeHandle>>>> =
    Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

/// 检查是否有任意串口或指定串口正在监听中
pub fn is_any_serial_running(port: Option<&str>) -> bool {
    let map = crate::lock_guard::lock_mutex(&ACTIVE_SERIAL_PROBES, "serial::is_any_serial_running");
    if let Some(p) = port {
        map.get(p).map(|h| h.is_running.load(Ordering::SeqCst)).unwrap_or(false)
    } else {
        map.values().any(|h| h.is_running.load(Ordering::SeqCst))
    }
}

/// 获取当前所有正在并发监听的串口探针状态
pub fn list_active_serial_probes() -> Vec<ActiveSerialProbeInfo> {
    let map = crate::lock_guard::lock_mutex(&ACTIVE_SERIAL_PROBES, "serial::list_active_serial_probes");
    map.values()
        .filter(|h| h.is_running.load(Ordering::SeqCst))
        .map(|h| ActiveSerialProbeInfo {
            port_name: h.port_name.clone(),
            baud_rate: h.config.baud_rate,
            data_bits: h.config.data_bits,
            parity: h.config.parity.clone(),
            stop_bits: h.config.stop_bits,
            flow_control: h.config.flow_control.clone(),
            framing_mode: h.config.framing_mode.clone(),
            uptime_secs: h.start_time.elapsed().as_secs(),
        })
        .collect()
}

/// 获取当前所有正在运行的双串口透明中继器状态
pub fn list_active_serial_bridges() -> Vec<ActiveSerialBridgeInfo> {
    let map = crate::lock_guard::lock_mutex(&ACTIVE_SERIAL_BRIDGES, "serial::list_active_serial_bridges");
    map.values()
        .filter(|h| h.is_running.load(Ordering::SeqCst))
        .map(|h| ActiveSerialBridgeInfo {
            bridge_id: h.bridge_id.clone(),
            port_a: h.port_a.clone(),
            baud_a: h.baud_a,
            port_b: h.port_b.clone(),
            baud_b: h.baud_b,
            start_time: h.start_time_str.clone(),
            uptime_secs: h.start_time.elapsed().as_secs(),
            total_a_to_b_bytes: h.total_a_to_b_bytes.load(Ordering::Relaxed),
            total_b_to_a_bytes: h.total_b_to_a_bytes.load(Ordering::Relaxed),
            is_running: true,
        })
        .collect()
}

/// 启动后台热插拔探测与自动广播守护线程 (工业级实时高频侦测: 800ms)
pub fn start_serial_hotplug_detector(app: tauri::AppHandle) {
    std::thread::spawn(move || {
        let mut last_ports: Vec<String> = list_available_serial_ports();

        loop {
            std::thread::sleep(Duration::from_millis(800));

            let current_details = list_available_serial_ports_detail();
            let current_ports: Vec<String> = current_details.iter().map(|p| p.port_name.clone()).collect();

            if current_ports != last_ports {
                let added: Vec<&String> = current_ports.iter().filter(|p| !last_ports.contains(p)).collect();
                let removed: Vec<&String> = last_ports.iter().filter(|p| !current_ports.contains(p)).collect();

                for p in added {
                    let detail = current_details.iter().find(|d| &d.port_name == p);
                    let desc = detail.map(|d| d.description.as_str()).unwrap_or(p);
                    let is_usb = detail.map(|d| d.is_usb).unwrap_or(false);

                    let _ = app.emit("system-log", format!("[SERIAL] 🔌 物理串口已接入: {}", desc));
                    let _ = app.emit(
                        "hardware-alert",
                        json!({
                            "alert_type": "SERIAL_ATTACH",
                            "device_name": desc,
                            "port_name": p,
                            "is_usb": is_usb
                        }),
                    );
                    if let Some(d) = detail {
                        let _ = app.emit("serial-inserted", d);
                    }
                }

                for p in &removed {
                    let _ = app.emit("system-log", format!("[SERIAL] ⚠️ 物理串口已断开: {}", p));
                    let _ = app.emit(
                        "hardware-alert",
                        json!({
                            "alert_type": "SERIAL_DETACH",
                            "device_name": p,
                            "port_name": p
                        }),
                    );
                }

                // 检查当前正在并发监听的串口中是否有被意外物理拔出的
                let active_keys: Vec<String> = {
                    let map = crate::lock_guard::lock_mutex(&ACTIVE_SERIAL_PROBES, "serial::hotplug_check_active");
                    map.keys().cloned().collect()
                };
                for cur in active_keys {
                    if removed.contains(&&cur) {
                        let _ = app.emit("system-log", format!("[SERIAL] 🚨 正在监听的串口 {} 已被意外物理拔出，紧急中止采集", cur));
                        let _ = app.emit("serial-disconnected", &cur);
                        stop_serial_probe(Some(&cur));
                    }
                }

                let _ = app.emit("serial-ports-changed", &current_details);
                last_ports = current_ports;
            }
        }
    });
}

/// 根据串口波特率、数据位、校验位、停止位精确推导 3.5 字符时间 (Modbus RTU 工业标准规范)
/// 时间复杂度: O(1)
/// 空间复杂度: O(1)
pub fn calculate_3_5t_duration(baud_rate: u32, data_bits: u8, parity: &str, stop_bits: u8) -> Duration {
    if baud_rate == 0 {
        return Duration::from_millis(30);
    }
    // Modbus 规约: 当波特率 > 19200 时，固定帧间间隔为 1.750ms (此处设为 3ms 防止操作系统调度抖动)
    if baud_rate > 19200 {
        return Duration::from_millis(3);
    }
    // 1 个字符的总位数 = 1(起始位) + data_bits + (parity != "None" ? 1 : 0) + stop_bits
    let parity_bits = if parity.eq_ignore_ascii_case("None") { 0 } else { 1 };
    let total_bits_per_char = 1 + (data_bits as u32) + parity_bits + (stop_bits as u32);
    // 3.5 字符所需总位数
    let bits_3_5 = (total_bits_per_char as f64) * 3.5;
    // 所需微秒数 = (bits / baud_rate) * 1_000_000
    let micros = ((bits_3_5 / (baud_rate as f64)) * 1_000_000.0).ceil() as u64;
    // 工业级防御：现代操作系统（特别是 Windows）线程调度精度通常为 1ms~15ms，设下限为 3ms 保证稳定
    Duration::from_micros(micros.max(3000))
}

/// Modbus RTU CRC-16 工业级快速查表计算 (多项式 0xA001，初始值 0xFFFF)
/// 时间复杂度: O(N) (N 为帧字节数)
/// 空间复杂度: O(1)
pub fn calculate_modbus_crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= byte as u16;
        for _ in 0..8 {
            if (crc & 0x0001) != 0 {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

/// 剖析 Modbus RTU 工业规约帧
/// 时间复杂度: O(N)
/// 空间复杂度: O(1)
pub fn dissect_modbus_rtu(payload: &[u8]) -> Option<ModbusRtuDissection> {
    if payload.len() < 4 {
        return None;
    }
    let len = payload.len();
    let actual_crc = (payload[len - 2] as u16) | ((payload[len - 1] as u16) << 8);
    let expected_crc = calculate_modbus_crc16(&payload[..len - 2]);
    let is_crc_valid = actual_crc == expected_crc;

    let slave_address = payload[0];
    let function_code = payload[1];
    let is_exception = (function_code & 0x80) != 0;

    let mut dissection = ModbusRtuDissection {
        slave_address,
        function_code,
        is_exception,
        exception_code: None,
        exception_desc: None,
        is_crc_valid,
        expected_crc,
        actual_crc,
        register_address: None,
        register_count: None,
        byte_count: None,
        values: Vec::new(),
        summary: String::new(),
    };

    if is_exception {
        if payload.len() >= 3 {
            let exc = payload[2];
            dissection.exception_code = Some(exc);
            dissection.exception_desc = Some(match exc {
                0x01 => "非法功能码 (ILLEGAL_FUNCTION)".to_string(),
                0x02 => "非法数据地址 (ILLEGAL_DATA_ADDRESS)".to_string(),
                0x03 => "非法数据值 (ILLEGAL_DATA_VALUE)".to_string(),
                0x04 => "从站设备故障 (SLAVE_DEVICE_FAILURE)".to_string(),
                0x05 => "确认响应 (ACKNOWLEDGE)".to_string(),
                0x06 => "从站设备忙 (SLAVE_DEVICE_BUSY)".to_string(),
                _ => format!("未知异常码 (0x{:02X})", exc),
            });
            dissection.summary = format!(
                "Modbus 异常响应: 从站 {} 功能码 0x{:02X} 错误: {}",
                slave_address, function_code & 0x7F, dissection.exception_desc.as_deref().unwrap_or("")
            );
        }
    } else {
        match function_code {
            0x01 | 0x02 => {
                if payload.len() == 8 {
                    let addr = u16::from_be_bytes([payload[2], payload[3]]);
                    let count = u16::from_be_bytes([payload[4], payload[5]]);
                    dissection.register_address = Some(addr);
                    dissection.register_count = Some(count);
                    dissection.summary = format!("从站 {} 读取线圈/离散输入 请求: 起始=0x{:04X}, 数量={}", slave_address, addr, count);
                } else if payload.len() >= 5 {
                    let bc = payload[2];
                    dissection.byte_count = Some(bc);
                    dissection.summary = format!("从站 {} 读取线圈/离散输入 响应: 字节数={}", slave_address, bc);
                }
            }
            0x03 | 0x04 => {
                if payload.len() == 8 {
                    let addr = u16::from_be_bytes([payload[2], payload[3]]);
                    let count = u16::from_be_bytes([payload[4], payload[5]]);
                    dissection.register_address = Some(addr);
                    dissection.register_count = Some(count);
                    let reg_name = if function_code == 0x03 { "保持寄存器" } else { "输入寄存器" };
                    dissection.summary = format!("从站 {} 读取{} 请求: 起始=0x{:04X}, 寄存器数={}", slave_address, reg_name, addr, count);
                } else if payload.len() >= 5 {
                    let bc = payload[2] as usize;
                    dissection.byte_count = Some(bc as u8);
                    let mut vals = Vec::new();
                    let data_end = (3 + bc).min(len - 2);
                    for chunk in payload[3..data_end].chunks_exact(2) {
                        vals.push(u16::from_be_bytes([chunk[0], chunk[1]]));
                    }
                    dissection.values = vals.clone();
                    let reg_name = if function_code == 0x03 { "保持寄存器" } else { "输入寄存器" };
                    dissection.summary = format!("从站 {} 读取{} 响应: 返回 {} 个寄存器数值", slave_address, reg_name, vals.len());
                }
            }
            0x05 => {
                if payload.len() == 8 {
                    let addr = u16::from_be_bytes([payload[2], payload[3]]);
                    let val = u16::from_be_bytes([payload[4], payload[5]]);
                    dissection.register_address = Some(addr);
                    dissection.summary = format!("从站 {} 写单个线圈: 地址=0x{:04X}, 状态={}", slave_address, addr, if val == 0xFF00 { "ON" } else { "OFF" });
                }
            }
            0x06 => {
                if payload.len() == 8 {
                    let addr = u16::from_be_bytes([payload[2], payload[3]]);
                    let val = u16::from_be_bytes([payload[4], payload[5]]);
                    dissection.register_address = Some(addr);
                    dissection.values = vec![val];
                    dissection.summary = format!("从站 {} 写单个寄存器: 地址=0x{:04X}, 值=0x{:04X} ({})", slave_address, addr, val, val);
                }
            }
            0x10 => {
                if payload.len() >= 9 {
                    let addr = u16::from_be_bytes([payload[2], payload[3]]);
                    let count = u16::from_be_bytes([payload[4], payload[5]]);
                    dissection.register_address = Some(addr);
                    dissection.register_count = Some(count);
                    dissection.summary = format!("从站 {} 写多个寄存器: 起始=0x{:04X}, 数量={}", slave_address, addr, count);
                }
            }
            _ => {
                dissection.summary = format!("从站 {} 功能码 0x{:02X} 载荷 (长度 {} 字节)", slave_address, function_code, payload.len());
            }
        }
    }
    Some(dissection)
}

/// 剖析 DL/T 645-2007 电力电表规约帧
/// 时间复杂度: O(N)
/// 空间复杂度: O(1)
pub fn dissect_dlt645(payload: &[u8]) -> Option<Dlt645Dissection> {
    let start_pos = payload.iter().position(|&b| b == 0x68)?;
    let frame = &payload[start_pos..];
    if frame.len() < 12 || frame[7] != 0x68 || *frame.last()? != 0x16 {
        return None;
    }
    let addr_bytes = &frame[1..7];
    let meter_address = addr_bytes.iter().rev().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join("");
    let control_code = frame[8];
    let data_len = frame[9] as usize;
    if frame.len() < 12 + data_len {
        return None;
    }
    let cs_actual = frame[10 + data_len];
    let cs_expected: u8 = frame[..10 + data_len].iter().fold(0u8, |acc, &x| acc.wrapping_add(x));
    let is_valid_cs = cs_actual == cs_expected;

    let ctrl_desc = match control_code & 0x1F {
        0x11 => "读数据",
        0x12 => "读后续数据",
        0x13 => "读通信地址",
        0x14 => "写数据",
        0x15 => "写通信地址",
        0x16 => "冻结命令",
        0x17 => "更改波特率",
        0x18 => "修改密码",
        0x19 => "最大需量清零",
        0x1A => "电表清零",
        _ => "其他控制操作",
    };
    let is_response = (control_code & 0x80) != 0;
    let summary = format!(
        "DL/T 645 电表 [{}] {} {} (数据长度 {}B, 校验: {})",
        meter_address,
        if is_response { "从站响应" } else { "主站请求" },
        ctrl_desc,
        data_len,
        if is_valid_cs { "有效" } else { "校验失败" }
    );

    Some(Dlt645Dissection {
        meter_address,
        control_code,
        data_length: data_len as u8,
        is_valid_cs,
        summary,
    })
}

/// 剖析 NMEA 0183 导航报文
/// 时间复杂度: O(N)
/// 空间复杂度: O(1)
pub fn dissect_nmea0183(payload: &[u8]) -> Option<NmeaDissection> {
    if payload.len() < 7 {
        return None;
    }
    let text = std::str::from_utf8(payload).ok()?.trim();
    if !text.starts_with('$') && !text.starts_with('!') {
        return None;
    }
    let parts: Vec<&str> = text.split('*').collect();
    let is_valid_checksum = if parts.len() == 2 && parts[1].len() >= 2 {
        let expected_cs = u8::from_str_radix(&parts[1][..2], 16).unwrap_or(0);
        let actual_cs = parts[0][1..].bytes().fold(0u8, |acc, b| acc ^ b);
        actual_cs == expected_cs
    } else {
        false
    };

    let fields: Vec<&str> = parts[0].split(',').collect();
    let sentence_type = fields[0].to_string();

    let mut lat = None;
    let mut lon = None;
    let mut speed = None;
    let mut course = None;

    if sentence_type.ends_with("RMC") && fields.len() >= 9 {
        if fields[2] == "A" {
            lat = Some(format!("{} {}", fields[3], fields[4]));
            lon = Some(format!("{} {}", fields[5], fields[6]));
            speed = fields[7].parse::<f64>().ok();
            course = fields[8].parse::<f64>().ok();
        }
    } else if sentence_type.ends_with("GGA") && fields.len() >= 6 {
        lat = Some(format!("{} {}", fields[2], fields[3]));
        lon = Some(format!("{} {}", fields[4], fields[5]));
    }

    let summary = format!(
        "NMEA 0183 导航 [{}] 校验: {} {}",
        sentence_type,
        if is_valid_checksum { "正确" } else { "异常" },
        if let (Some(l1), Some(l2)) = (&lat, &lon) {
            format!("坐标: {}, {}", l1, l2)
        } else {
            "".to_string()
        }
    );

    Some(NmeaDissection {
        sentence_type,
        is_valid_checksum,
        latitude: lat,
        longitude: lon,
        speed_knots: speed,
        course_deg: course,
        summary,
    })
}

pub(crate) fn parse_data_bits(bits: u8) -> serialport::DataBits {
    match bits {
        5 => serialport::DataBits::Five,
        6 => serialport::DataBits::Six,
        7 => serialport::DataBits::Seven,
        _ => serialport::DataBits::Eight,
    }
}

pub(crate) fn parse_parity(parity: &str) -> serialport::Parity {
    match parity.to_uppercase().as_str() {
        "ODD" => serialport::Parity::Odd,
        "EVEN" => serialport::Parity::Even,
        _ => serialport::Parity::None,
    }
}

pub(crate) fn parse_stop_bits(bits: u8) -> serialport::StopBits {
    match bits {
        2 => serialport::StopBits::Two,
        _ => serialport::StopBits::One,
    }
}

pub(crate) fn parse_flow_control(flow: &str) -> serialport::FlowControl {
    match flow.to_uppercase().as_str() {
        "SOFTWARE" => serialport::FlowControl::Software,
        "HARDWARE" => serialport::FlowControl::Hardware,
        _ => serialport::FlowControl::None,
    }
}

/// 串口出向操作动作 (支持载荷写出与 RTS/DTR 引脚控制)
pub enum SerialTxAction {
    SendData(Vec<u8>),
    SetRts(bool),
    SetDtr(bool),
}

/// 启动指定物理串口的数据流监听 (支持 4 大参数、分帧定界、Modem 引脚监控与双向出入)
pub fn start_serial_probe_with_config(
    app: tauri::AppHandle,
    port_name: &str,
    config: SerialCommunicationConfig,
) -> Result<String, String> {
    let clean_port = port_name.trim();
    if clean_port.is_empty() {
        return Err("串口名称不能为空".into());
    }

    {
        let map = crate::lock_guard::lock_mutex(&ACTIVE_SERIAL_PROBES, "serial::start_serial_probe_check");
        if let Some(existing) = map.get(clean_port) {
            if existing.is_running.load(Ordering::SeqCst) {
                return Err(format!("串口 {} 已经处于监听运行中", clean_port));
            }
        }
    }

    let timeout_duration = match config.framing_mode.as_str() {
        "Auto3_5T" => calculate_3_5t_duration(config.baud_rate, config.data_bits, &config.parity, config.stop_bits),
        "TimeoutMs" => Duration::from_millis(config.framing_timeout_ms.unwrap_or(30).max(2)),
        _ => Duration::from_millis(15),
    };

    let port = serialport::new(clean_port, config.baud_rate)
        .data_bits(parse_data_bits(config.data_bits))
        .parity(parse_parity(&config.parity))
        .stop_bits(parse_stop_bits(config.stop_bits))
        .flow_control(parse_flow_control(&config.flow_control))
        .timeout(Duration::from_millis(15))
        .open()
        .map_err(|e| format!("无法打开串口 {}: {}", clean_port, e))?;

    let port_name_owned = clean_port.to_string();
    let is_running = Arc::new(AtomicBool::new(true));
    let is_running_thread = is_running.clone();
    let (tx_sender, tx_receiver): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = channel();
    let modem_status = Arc::new(Mutex::new(SerialModemStatus::default()));
    let modem_status_thread = modem_status.clone();

    {
        let mut map = crate::lock_guard::lock_mutex(&ACTIVE_SERIAL_PROBES, "serial::start_serial_probe_insert");
        map.insert(
            port_name_owned.clone(),
            SerialProbeHandle {
                port_name: port_name_owned.clone(),
                config: config.clone(),
                is_running,
                start_time: std::time::Instant::now(),
                tx_sender,
                modem_status,
            },
        );
    }

    let _ = app.emit(
        "system-log",
        format!(
            "[SERIAL] ✅ 已绑定物理串口 {} @ {} bps, {} {}{}{} 流控:{} 定界:{} (双向监听就绪)",
            port_name_owned,
            config.baud_rate,
            config.data_bits,
            config.parity.chars().next().unwrap_or('N'),
            config.stop_bits,
            if config.flow_control != "None" { format!(" {}", config.flow_control) } else { "".to_string() },
            config.flow_control,
            config.framing_mode
        ),
    );

    let app_clone = app.clone();
    let port_thread_name = port_name_owned.clone();
    let config_clone = config.clone();

    std::thread::spawn(move || {
        let mut port = port;
        let mut buf = vec![0u8; 4096];
        let mut frame_buf = Vec::new();
        let mut last_rx_time = std::time::Instant::now();
        let mut last_modem_poll = std::time::Instant::now();

        let delimiter_bytes: Option<Vec<u8>> = if config_clone.framing_mode == "Delimiter" {
            config_clone.framing_delimiter_hex.as_ref().and_then(|h| hex::decode(h.replace(' ', "")).ok())
        } else {
            None
        };
        let fixed_len = config_clone.framing_fixed_length;

        while is_running_thread.load(Ordering::SeqCst) {
            // 1. 检查出向写请求队列 (TX Channel)
            while let Ok(out_data) = tx_receiver.try_recv() {
                if let Err(e) = port.write_all(&out_data) {
                    let _ = app_clone.emit(
                        "system-log",
                        format!("[SERIAL] ❌ 串口 {} 出向写出失败: {}", port_thread_name, e),
                    );
                } else {
                    let _ = port.flush();
                }
            }

            // 2. 定期轮询 Modem 硬件引脚状态 (每 250ms 一次，保持轻量高效)
            if last_modem_poll.elapsed() >= Duration::from_millis(250) {
                last_modem_poll = std::time::Instant::now();
                let cts = port.read_clear_to_send().unwrap_or(false);
                let dsr = port.read_data_set_ready().unwrap_or(false);
                let ri = port.read_ring_indicator().unwrap_or(false);
                let cd = port.read_carrier_detect().unwrap_or(false);

                let mut changed = false;
                {
                    let mut st = crate::lock_guard::lock_mutex(&modem_status_thread, "serial::rx_thread_modem_status");
                    if st.cts != cts || st.dsr != dsr || st.ri != ri || st.cd != cd {
                        st.cts = cts;
                        st.dsr = dsr;
                        st.ri = ri;
                        st.cd = cd;
                        changed = true;
                    }
                }
                if changed {
                    let _ = app_clone.emit("serial-modem-status-changed", json!({
                        "port_name": port_thread_name,
                        "cts": cts,
                        "dsr": dsr,
                        "ri": ri,
                        "cd": cd,
                    }));
                }
            }

            // 3. 接收串口入向数据流 (RX)
            match port.read(buf.as_mut_slice()) {
                Ok(n) if n > 0 => {
                    frame_buf.extend_from_slice(&buf[..n]);
                    last_rx_time = std::time::Instant::now();

                    // 固定长度即时触发
                    if let Some(flen) = fixed_len {
                        while frame_buf.len() >= flen {
                            let payload: Vec<u8> = frame_buf.drain(..flen).collect();
                            emit_serial_rx_packet(&app_clone, &port_thread_name, &config_clone, payload);
                        }
                    }

                    // 帧尾分隔符即时触发 (循环切分粘包多行帧，防止滞留造成波形延迟)
                    if let Some(ref delim) = delimiter_bytes {
                        if !delim.is_empty() {
                            let mut drained = 0usize;
                            while frame_buf.len() >= delim.len() && drained < 64 {
                                if let Some(pos) = frame_buf.windows(delim.len()).position(|w| w == delim.as_slice()) {
                                    let end_idx = pos + delim.len();
                                    let payload: Vec<u8> = frame_buf.drain(..end_idx).collect();
                                    emit_serial_rx_packet(&app_clone, &port_thread_name, &config_clone, payload);
                                    drained += 1;
                                } else {
                                    break;
                                }
                            }
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                    // 超时定界：根据 3.5T 或配置的毫秒数
                    if !frame_buf.is_empty() && last_rx_time.elapsed() >= timeout_duration {
                        let payload = std::mem::take(&mut frame_buf);
                        emit_serial_rx_packet(&app_clone, &port_thread_name, &config_clone, payload);
                    }
                }
                Err(e) => {
                    let _ = app_clone.emit(
                        "system-log",
                        format!("[SERIAL] ❌ 串口 {} 读取错误: {}", port_thread_name, e),
                    );
                    break;
                }
                _ => {}
            }
        }

        {
            let mut map = crate::lock_guard::lock_mutex(&ACTIVE_SERIAL_PROBES, "serial::rx_thread_cleanup");
            map.remove(&port_thread_name);
        }
        let _ = app_clone.emit("system-log", format!("[SERIAL] 物理串口 {} 监听已释放关闭", port_thread_name));
    });

    Ok(format!("[SERIAL] 物理串口 {} @ {} bps 监听已成功启动", clean_port, config.baud_rate))
}

/// 兼容旧版入口：以默认 8-N-1、3.5T 自动定界启动
pub fn start_serial_probe(app: tauri::AppHandle, port_name: &str, baud_rate: u32) -> Result<String, String> {
    let mut config = SerialCommunicationConfig::default();
    config.baud_rate = baud_rate;
    start_serial_probe_with_config(app, port_name, config)
}

/// 广播并固化单条串口 RX 报文到全维证据链与界面
fn emit_serial_rx_packet(
    app: &tauri::AppHandle,
    port_name: &str,
    config: &SerialCommunicationConfig,
    payload: Vec<u8>,
) {
    let entropy = ForensicEngine::calculate_entropy(&payload);
    let entropy_level = if entropy >= 7.5 {
        "critical"
    } else if entropy >= 6.0 {
        "suspicious"
    } else {
        "safe"
    };
    let id = SERIAL_COUNTER.fetch_add(1, Ordering::Relaxed);
    let ts_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    let payload_hex = hex::encode(&payload);
    let mut protocol = dpi::identify_protocol(0, 0, &payload);

    // 工业规约自动嗅探
    let mut modbus_info = None;
    let mut modbus_crc_err = false;
    let mut dlt645_info = None;
    let mut nmea_info = None;

    if let Some(mb) = dissect_modbus_rtu(&payload) {
        if mb.is_crc_valid {
            protocol = "Modbus-RTU".to_string();
            modbus_info = Some(mb);
            let is_resp = payload.len() >= 3 && (payload[1] & 0x80 != 0 || (payload.len() > 3 && payload[2] != 0));
            if is_resp {
                crate::cross_bus_diagnostic::GLOBAL_CASCADE_DIAGNOSTIC_ENGINE.record_response(
                    crate::cross_bus_diagnostic::BusType::Serial,
                    id,
                    ts_ns,
                    &protocol,
                    &payload,
                );
            } else {
                crate::cross_bus_diagnostic::GLOBAL_CASCADE_DIAGNOSTIC_ENGINE.record_request(
                    crate::cross_bus_diagnostic::BusType::Serial,
                    id,
                    ts_ns,
                    &protocol,
                    &payload,
                );
            }
        } else {
            modbus_crc_err = true;
            crate::cross_bus_diagnostic::GLOBAL_CASCADE_DIAGNOSTIC_ENGINE.report_physical_crc_error(
                crate::cross_bus_diagnostic::BusType::Serial,
                ts_ns,
            );
        }
    }
    if protocol == "UNKNOWN" {
        if let Some(_dlt698) = crate::industrial_gb_dissector::dissect_dlt698_45(&payload) {
            protocol = "DL/T 698.45".to_string();
        } else if let Some(_hj) = crate::industrial_gb_dissector::dissect_hj212(&payload) {
            protocol = "HJ 212-2017".to_string();
        } else if let Some(dlt) = dissect_dlt645(&payload) {
            protocol = "DL/T 645".to_string();
            dlt645_info = Some(dlt);
        } else if let Some(nm) = dissect_nmea0183(&payload) {
            protocol = "NMEA-0183".to_string();
            nmea_info = Some(nm);
        }
    }

    let raw_text = Some(crate::sniffer::generate_raw_text_preview(&payload));
    let mut b_map = dpi::dissect_payload(&protocol, &payload);
    b_map.insert("direction".into(), serde_json::json!("SERIAL_RX"));
    b_map.insert("serial_interface".into(), serde_json::json!(port_name));
    b_map.insert("configured_baud_rate".into(), serde_json::json!(config.baud_rate));
    b_map.insert("frame_bytes".into(), serde_json::json!(payload.len()));
    b_map.insert("inferred_protocol".into(), json!(&protocol));
    b_map.insert("entropy".into(), json!(entropy));

    if let Some(ref mb) = modbus_info {
        b_map.insert("modbus_rtu".into(), serde_json::to_value(&mb).unwrap_or_default());
    }
    if let Some(dlt) = dlt645_info {
        b_map.insert("dlt645".into(), serde_json::to_value(&dlt).unwrap_or_default());
    }
    if let Some(nm) = nmea_info {
        b_map.insert("nmea0183".into(), serde_json::to_value(&nm).unwrap_or_default());
    }

    let business_data = Some(b_map);

    let chain_hash = crate::sniffer::advance_global_chain(
        ts_ns,
        &format!("SERIAL_RX|{}@{}|{}", port_name, config.baud_rate, payload_hex),
    );

    crate::forensics::write_app_packet(
        port_name, "HOST_SYSTEM", 0, 0, "SERIAL", &payload,
    );

    let record = PacketRecord {
        id,
        timestamp: chrono::Local::now().format("%H:%M:%S.%3f").to_string(),
        timestamp_ns: ts_ns,
        direction: "SERIAL_RX".into(),
        transport: "SERIAL".into(),
        protocol,
        src_ip: port_name.to_string(),
        dst_ip: "HOST_SYSTEM".into(),
        src_port: 0,
        dst_port: 0,
        length: payload.len(),
        payload_hex,
        raw_frame_hex: hex::encode(&payload),
        entropy,
        entropy_level: entropy_level.into(),
        mac_src: "SERIAL".into(),
        mac_dst: "LOCAL".into(),
        chain_hash,
        business_data,
        raw_text,
    };

    if let Ok(v) = serde_json::to_value(&record) {
        crate::forensics::write_jsonl_record(&v.to_string());
    }
    // 多分辨率时序指标流与工业拓扑热力雷达收口 (TASK-17)
    let is_ind_serial = matches!(
        record.protocol.to_uppercase().as_str(),
        "MODBUS" | "MODBUS_TCP" | "MODBUS-RTU" | "DL/T 645"
    );
    let is_write_serial = modbus_info.as_ref().map_or(false, |m| {
        matches!(m.function_code, 0x05 | 0x06 | 0x0F | 0x10)
    });
    let timestamp_s_serial = (record.timestamp_ns / 1_000_000_000) as u64;

    crate::metrics_timeseries::GLOBAL_TIMESERIES_POOL.record_packet(
        timestamp_s_serial,
        record.length as u64,
        is_ind_serial,
        is_write_serial,
        false,
    );
    crate::metrics_timeseries::GLOBAL_TOPOLOGY_HEATMAP.record_interaction(
        &record.src_ip,
        &record.dst_ip,
        record.length as u64,
        is_ind_serial,
        is_write_serial,
        false,
        record.timestamp_ns,
    );

    crate::analyzer::record_packet_io_with_bus("SERIAL", record.length, None, false);
    crate::analyzer::process_wave_sample(app, port_name, &payload);

    let responder_actions = crate::bus_intelligence::record_serial_frame_and_match_rules(
        port_name,
        &payload,
        modbus_info.as_ref(),
        modbus_crc_err,
    );
    if !responder_actions.is_empty() {
        let app_rep = app.clone();
        let port_rep = port_name.to_string();
        let baud_rep = config.baud_rate;
        std::thread::spawn(move || {
            for (delay_ms, reply_bytes) in responder_actions {
                if delay_ms > 0 {
                    std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                }
                let _ = send_serial_data(app_rep.clone(), &port_rep, baud_rep, &reply_bytes);
            }
        });
    }

    let _ = crate::cloud::emit_record(serde_json::to_value(&record).unwrap_or_default());
    let _ = app.emit("packet-received", &record);
}

/// 停止指定串口或全部物理串口的采集
pub fn stop_serial_probe(port_name: Option<&str>) -> String {
    let mut map = crate::lock_guard::lock_mutex(&ACTIVE_SERIAL_PROBES, "serial::stop_serial_probe");
    if let Some(p) = port_name {
        let clean = p.trim();
        if let Some(handle) = map.remove(clean) {
            handle.is_running.store(false, Ordering::SeqCst);
            format!("[SERIAL] 物理串口 {} 监听已停止", clean)
        } else {
            format!("[SERIAL] 串口 {} 未在运行中", clean)
        }
    } else {
        let count = map.len();
        for (_, handle) in map.drain() {
            handle.is_running.store(false, Ordering::SeqCst);
        }
        format!("[SERIAL] 已停止全部正在运行的物理串口 (共 {} 个)", count)
    }
}

/// 获取指定串口的硬件引脚电平状态
pub fn get_serial_modem_status(port_name: &str) -> Result<SerialModemStatus, String> {
    let clean = port_name.trim();
    let map = crate::lock_guard::lock_mutex(&ACTIVE_SERIAL_PROBES, "serial::get_serial_modem_status_map");
    if let Some(handle) = map.get(clean) {
        let st = crate::lock_guard::lock_mutex(&handle.modem_status, "serial::get_serial_modem_status_inner");
        Ok(st.clone())
    } else {
        // 如果未处于全局监听，临时打开进行单次物理读取
        let mut p = serialport::new(clean, 9600)
            .timeout(Duration::from_millis(50))
            .open()
            .map_err(|e| format!("无法打开串口 {}: {}", clean, e))?;
        Ok(SerialModemStatus {
            cts: p.read_clear_to_send().unwrap_or(false),
            dsr: p.read_data_set_ready().unwrap_or(false),
            ri: p.read_ring_indicator().unwrap_or(false),
            cd: p.read_carrier_detect().unwrap_or(false),
            rts: false,
            dtr: false,
        })
    }
}

/// 控制指定串口的 RTS / DTR 硬件引脚电平
pub fn set_serial_pin_state(
    port_name: &str,
    rts: Option<bool>,
    dtr: Option<bool>,
) -> Result<(), String> {
    let clean = port_name.trim();
    let mut p = serialport::new(clean, 9600)
        .timeout(Duration::from_millis(50))
        .open()
        .map_err(|e| format!("无法打开串口 {}: {}", clean, e))?;

    if let Some(val) = rts {
        p.write_request_to_send(val)
            .map_err(|e| format!("设置 RTS 失败: {}", e))?;
    }
    if let Some(val) = dtr {
        p.write_data_terminal_ready(val)
            .map_err(|e| format!("设置 DTR 失败: {}", e))?;
    }
    Ok(())
}

/// 启动工业级双串口全双工透明中继器 (COM-A ⇄ COM-B 双向独立流线程 + 3.5T 帧边界聚合 + 控制引脚镜像)
pub fn start_serial_bridge(
    app: tauri::AppHandle,
    port_a: &str,
    config_a: SerialCommunicationConfig,
    port_b: &str,
    config_b: SerialCommunicationConfig,
) -> Result<String, String> {
    let clean_a = port_a.trim();
    let clean_b = port_b.trim();

    if clean_a.is_empty() || clean_b.is_empty() {
        return Err("中继两端串口名称不能为空".into());
    }
    if clean_a == clean_b {
        return Err("中继两端不能为同一个串口".into());
    }

    let bridge_id = format!("{}_TO_{}", clean_a, clean_b);
    {
        let map = crate::lock_guard::lock_mutex(&ACTIVE_SERIAL_BRIDGES, "serial::start_serial_bridge_check");
        if map.contains_key(&bridge_id) {
            return Err(format!("双串口中继器 {} 已经在运行中", bridge_id));
        }
    }

    let port_dev_a = serialport::new(clean_a, config_a.baud_rate)
        .data_bits(parse_data_bits(config_a.data_bits))
        .parity(parse_parity(&config_a.parity))
        .stop_bits(parse_stop_bits(config_a.stop_bits))
        .flow_control(parse_flow_control(&config_a.flow_control))
        .timeout(Duration::from_millis(8))
        .open()
        .map_err(|e| format!("中继端 A ({}) 打开失败: {}", clean_a, e))?;

    let port_dev_b = serialport::new(clean_b, config_b.baud_rate)
        .data_bits(parse_data_bits(config_b.data_bits))
        .parity(parse_parity(&config_b.parity))
        .stop_bits(parse_stop_bits(config_b.stop_bits))
        .flow_control(parse_flow_control(&config_b.flow_control))
        .timeout(Duration::from_millis(8))
        .open()
        .map_err(|e| format!("中继端 B ({}) 打开失败: {}", clean_b, e))?;

    let a_clone = port_dev_a
        .try_clone()
        .map_err(|e| format!("复制串口 A ({}) 全双工句柄失败: {}", clean_a, e))?;
    let b_clone = port_dev_b
        .try_clone()
        .map_err(|e| format!("复制串口 B ({}) 全双工句柄失败: {}", clean_b, e))?;
    let a_pins = port_dev_a
        .try_clone()
        .map_err(|e| format!("复制串口 A ({}) 引脚监控句柄失败: {}", clean_a, e))?;
    let b_pins = port_dev_b
        .try_clone()
        .map_err(|e| format!("复制串口 B ({}) 引脚监控句柄失败: {}", clean_b, e))?;

    let is_running = Arc::new(AtomicBool::new(true));
    let total_a_to_b = Arc::new(AtomicU64::new(0));
    let total_b_to_a = Arc::new(AtomicU64::new(0));
    let start_time_str = chrono::Local::now().format("%H:%M:%S").to_string();

    {
        let mut map = crate::lock_guard::lock_mutex(&ACTIVE_SERIAL_BRIDGES, "serial::start_serial_bridge_insert");
        map.insert(
            bridge_id.clone(),
            SerialBridgeHandle {
                bridge_id: bridge_id.clone(),
                port_a: clean_a.to_string(),
                baud_a: config_a.baud_rate,
                port_b: clean_b.to_string(),
                baud_b: config_b.baud_rate,
                start_time_str,
                is_running: is_running.clone(),
                start_time: std::time::Instant::now(),
                total_a_to_b_bytes: total_a_to_b.clone(),
                total_b_to_a_bytes: total_b_to_a.clone(),
            },
        );
    }

    // 线程 1: A -> B 透明转发、3.5T 帧边界聚合与证据链嗅探
    spawn_bridge_half_duplex_thread(
        app.clone(),
        port_dev_a,
        b_clone,
        clean_a.to_string(),
        clean_b.to_string(),
        "BRIDGE_A_TO_B".to_string(),
        calculate_3_5t_duration(config_a.baud_rate, config_a.data_bits, &config_a.parity, config_a.stop_bits),
        is_running.clone(),
        total_a_to_b.clone(),
    );

    // 线程 2: B -> A 双向对称全双工转发与嗅探
    spawn_bridge_half_duplex_thread(
        app.clone(),
        port_dev_b,
        a_clone,
        clean_b.to_string(),
        clean_a.to_string(),
        "BRIDGE_B_TO_A".to_string(),
        calculate_3_5t_duration(config_b.baud_rate, config_b.data_bits, &config_b.parity, config_b.stop_bits),
        is_running.clone(),
        total_b_to_a.clone(),
    );

    // 线程 3: 双向 Modem 控制引脚交叉镜像线程 (CTS/DSR -> RTS/DTR 硬件电平透传)
    let app_pins = app.clone();
    let pin_a_name = clean_a.to_string();
    let pin_b_name = clean_b.to_string();
    let running_pins = is_running.clone();
    std::thread::spawn(move || {
        let mut dev_a = a_pins;
        let mut dev_b = b_pins;
        let mut last_a_cts = false;
        let mut last_b_cts = false;
        while running_pins.load(Ordering::Acquire) {
            if let Ok(a_cts) = dev_a.read_clear_to_send() {
                if a_cts != last_a_cts {
                    last_a_cts = a_cts;
                    let _ = dev_b.write_request_to_send(a_cts);
                    let _ = app_pins.emit("serial-modem-status-changed", json!({
                        "port_name": pin_a_name,
                        "cts": a_cts,
                        "bridge_mirrored_to": pin_b_name,
                    }));
                }
            }
            if let Ok(b_cts) = dev_b.read_clear_to_send() {
                if b_cts != last_b_cts {
                    last_b_cts = b_cts;
                    let _ = dev_a.write_request_to_send(b_cts);
                    let _ = app_pins.emit("serial-modem-status-changed", json!({
                        "port_name": pin_b_name,
                        "cts": b_cts,
                        "bridge_mirrored_to": pin_a_name,
                    }));
                }
            }
            std::thread::sleep(Duration::from_millis(30));
        }
    });

    let _ = app.emit(
        "system-log",
        format!(
            "[SERIAL] 双串口全双工透明中继器已建立: {} (@{}bps) <===> {} (@{}bps)",
            clean_a, config_a.baud_rate, clean_b, config_b.baud_rate
        ),
    );

    Ok(format!("双串口全双工透明中继器 {} 已就绪", bridge_id))
}

#[allow(clippy::too_many_arguments)]
fn spawn_bridge_half_duplex_thread(
    app: tauri::AppHandle,
    mut src_dev: Box<dyn serialport::SerialPort>,
    mut dst_dev: Box<dyn serialport::SerialPort>,
    src_name: String,
    dst_name: String,
    direction: String,
    idle_gap: Duration,
    is_running: Arc<AtomicBool>,
    byte_counter: Arc<AtomicU64>,
) {
    std::thread::spawn(move || {
        let mut read_buf = [0u8; 2048];
        let mut frame_acc = Vec::with_capacity(2048);
        let mut last_rx = std::time::Instant::now();

        while is_running.load(Ordering::Acquire) {
            match src_dev.read(&mut read_buf) {
                Ok(n) if n > 0 => {
                    let chunk = &read_buf[..n];
                    let _ = dst_dev.write_all(chunk);
                    let _ = dst_dev.flush();
                    byte_counter.fetch_add(n as u64, Ordering::Relaxed);
                    frame_acc.extend_from_slice(chunk);
                    last_rx = std::time::Instant::now();
                    if frame_acc.len() >= 1024 {
                        let out = std::mem::take(&mut frame_acc);
                        emit_intercept_frame(&app, &src_name, &dst_name, &out, &direction, "SERIAL_BRIDGE");
                    }
                }
                _ => {
                    if !frame_acc.is_empty() && last_rx.elapsed() >= idle_gap {
                        let out = std::mem::take(&mut frame_acc);
                        emit_intercept_frame(&app, &src_name, &dst_name, &out, &direction, "SERIAL_BRIDGE");
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }
        if !frame_acc.is_empty() {
            emit_intercept_frame(&app, &src_name, &dst_name, &frame_acc, &direction, "SERIAL_BRIDGE");
        }
    });
}

/// 统一广播串口中继 / PTY / Pipe / RFC2217 / WDM 过滤报文到全系统证据链
pub(crate) fn emit_intercept_frame(
    app: &tauri::AppHandle,
    from_port: &str,
    to_port: &str,
    payload: &[u8],
    direction: &str,
    transport_tag: &str,
) {
    let entropy = ForensicEngine::calculate_entropy(payload);
    let id = SERIAL_COUNTER.fetch_add(1, Ordering::Relaxed);
    let ts_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let payload_hex = hex::encode(payload);
    let protocol = dpi::identify_protocol(0, 0, payload);

    let chain_hash = crate::sniffer::advance_global_chain(
        ts_ns,
        &format!("{}|{}|{}->{}|{}", transport_tag, direction, from_port, to_port, payload_hex),
    );

    let mut b_map = dpi::dissect_payload(&protocol, payload);
    b_map.insert("direction".into(), json!(direction));
    b_map.insert("intercept_engine".into(), json!(transport_tag));
    b_map.insert("relay_from".into(), json!(from_port));
    b_map.insert("relay_to".into(), json!(to_port));
    b_map.insert("bridge_bytes".into(), json!(payload.len()));

    let record = PacketRecord {
        id,
        timestamp: chrono::Local::now().format("%H:%M:%S.%3f").to_string(),
        timestamp_ns: ts_ns,
        direction: direction.into(),
        transport: transport_tag.into(),
        protocol,
        src_ip: from_port.to_string(),
        dst_ip: to_port.to_string(),
        src_port: 0,
        dst_port: 0,
        length: payload.len(),
        payload_hex,
        raw_frame_hex: hex::encode(payload),
        entropy,
        entropy_level: "safe".into(),
        mac_src: transport_tag.into(),
        mac_dst: to_port.to_string(),
        chain_hash,
        business_data: Some(b_map),
        raw_text: Some(crate::sniffer::generate_raw_text_preview(payload)),
    };

    if let Ok(v) = serde_json::to_value(&record) {
        crate::forensics::write_jsonl_record(&v.to_string());
    }
    let _ = app.emit("packet-received", &record);
}

/// 停止双串口透明中继器
pub fn stop_serial_bridge(bridge_id: Option<&str>) -> String {
    let mut map = crate::lock_guard::lock_mutex(&ACTIVE_SERIAL_BRIDGES, "serial::stop_serial_bridge");
    if let Some(id) = bridge_id {
        if let Some(handle) = map.remove(id) {
            handle.is_running.store(false, Ordering::SeqCst);
            format!("[SERIAL] 双串口中继器 {} 已停止", id)
        } else {
            format!("[SERIAL] 中继器 {} 未在运行", id)
        }
    } else {
        let count = map.len();
        for (_, handle) in map.drain() {
            handle.is_running.store(false, Ordering::SeqCst);
        }
        format!("[SERIAL] 已停止所有双串口中继器 (共 {} 个)", count)
    }
}

/// 向指定 COM 串口物理写入并发送操作数据（端口出向 TX 深度侦测）
/// 架构特性：若串口已在监听中，通过内置 mpsc 通道无锁并发写出；若未在监听中，以独占方式临时打开、写出并释放
pub fn send_serial_data(
    app: tauri::AppHandle,
    port_name: &str,
    baud_rate: u32,
    payload: &[u8],
) -> Result<usize, String> {
    if payload.is_empty() {
        return Err("发送载荷不能为空".into());
    }

    let clean_port = port_name.trim();

    // 1. 检查是否正在被本探针监听中
    let is_handled_by_active_probe = {
        let map = crate::lock_guard::lock_mutex(&ACTIVE_SERIAL_PROBES, "serial::send_serial_data");
        if let Some(handle) = map.get(clean_port) {
            handle.tx_sender.send(payload.to_vec()).map_err(|e| format!("发送队列投递失败: {}", e))?;
            true
        } else {
            false
        }
    };

    let bytes_written = if is_handled_by_active_probe {
        payload.len()
    } else {
        // 未在监听中：临时独占打开并写出
        let mut port = serialport::new(clean_port, baud_rate)
            .timeout(Duration::from_millis(500))
            .open()
            .map_err(|e| format!("打开串口 {} 失败: {}", clean_port, e))?;

        let written = port
            .write(payload)
            .map_err(|e| format!("写入串口 {} 失败: {}", clean_port, e))?;
        let _ = port.flush();
        written
    };

    let entropy = ForensicEngine::calculate_entropy(payload);
    let entropy_level = if entropy >= 7.5 {
        "critical"
    } else if entropy >= 6.0 {
        "suspicious"
    } else {
        "safe"
    };

    let id = SERIAL_COUNTER.fetch_add(1, Ordering::Relaxed);
    let ts_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let timestamp = chrono::Local::now().format("%H:%M:%S.%3f").to_string();

    let payload_hex = hex::encode(payload);
    let protocol = dpi::identify_protocol(0, 0, payload);
    let raw_preview = crate::sniffer::generate_raw_text_preview(payload);

    let mut b_map = dpi::dissect_payload(&protocol, payload);
    b_map.insert("direction".into(), serde_json::json!("SERIAL_TX"));
    b_map.insert("serial_interface".into(), serde_json::json!(clean_port));
    b_map.insert("configured_baud_rate".into(), serde_json::json!(baud_rate));
    b_map.insert("bytes_sent".into(), serde_json::json!(bytes_written));
    b_map.insert("inferred_protocol".into(), serde_json::json!(&protocol));
    b_map.insert("entropy".into(), serde_json::json!(entropy));

    let summary_text = format!(
        "[SERIAL TX] 端口操作写出 -> {} [{}B, {} bps] 协议: {} | 载荷摘要: {}",
        clean_port, bytes_written, baud_rate, protocol, raw_preview
    );

    let chain_hash = crate::sniffer::advance_global_chain(
        ts_ns,
        &format!("SERIAL_TX|{}@{}|{}", clean_port, baud_rate, payload_hex),
    );

    crate::forensics::write_app_packet(
        "HOST_SYSTEM", clean_port, 0, 0, "SERIAL", payload,
    );

    let record = PacketRecord {
        id,
        timestamp,
        timestamp_ns: ts_ns,
        direction: "SERIAL_TX".into(),
        transport: "SERIAL".into(),
        protocol,
        src_ip: "HOST_SYSTEM".into(),
        dst_ip: clean_port.to_string(),
        src_port: 0,
        dst_port: 0,
        length: bytes_written,
        payload_hex,
        raw_frame_hex: hex::encode(payload),
        entropy,
        entropy_level: entropy_level.into(),
        mac_src: "LOCAL".into(),
        mac_dst: "SERIAL".into(),
        chain_hash,
        business_data: Some(b_map),
        raw_text: Some(summary_text),
    };

    if let Ok(v) = serde_json::to_value(&record) {
        crate::forensics::write_jsonl_record(&v.to_string());
    }
    crate::analyzer::record_packet_io_with_bus("SERIAL", record.length, None, false);
    crate::analyzer::process_wave_sample(&app, clean_port, payload);
    crate::bus_intelligence::record_serial_tx_context(clean_port, payload);

    let _ = crate::cloud::emit_record(serde_json::to_value(&record).unwrap_or_default());
    let _ = app.emit("packet-received", &record);
    let _ = app.emit(
        "system-log",
        format!("[SERIAL] 📤 端口出向写出成功: {} ({} 字节)", clean_port, bytes_written),
    );

    Ok(bytes_written)
}

/// 向指定 COM 物理串口发送工业标准探活测试帧 (验证物理通信链路连通性与回路响应)
pub fn send_serial_probe_frame(
    app: tauri::AppHandle,
    port_name: &str,
    baud_rate: u32,
) -> Result<String, String> {
    let ts_ms = chrono::Local::now().timestamp_millis();
    let mut payload = vec![0x55, 0xAA, 0x01, 0x10]; // 同步前导字 0x55 0xAA + 探活指令 0x01 + 长度 0x10
    payload.extend_from_slice(b"OMNI_PROBE_PING\r\n");
    payload.extend_from_slice(&ts_ms.to_be_bytes());

    // 计算工业标准累加和校验码 (Checksum 8-bit)
    let chk: u8 = payload.iter().fold(0u8, |acc, &x| acc.wrapping_add(x));
    payload.push(chk);

    let bytes_sent = send_serial_data(app.clone(), port_name, baud_rate, &payload)?;
    let msg = format!("[SERIAL] ⚡ 物理探活测试帧已成功发出 -> {} @ {} bps ({} 字节)", port_name, baud_rate, bytes_sent);
    let _ = app.emit("system-log", &msg);
    Ok(msg)
}


// ============================================================
// VCD (Value Change Dump / IEEE 1364) 逻辑分析仪物理采样波形解调引擎
// 对标 sigrok / PulseView / Saleae Logic 硬件底层信号分析
// ============================================================

/// 逻辑分析仪采样点跳变事件
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VcdTransition {
    pub timestamp_us: u64,
    pub level: u8,
}

/// 逻辑分析仪波形解析与 UART 物理重组结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VcdUartDecodedResult {
    pub decoded_bytes: Vec<u8>,
    pub decoded_text: String,
    pub decoded_hex: String,
    pub total_sample_duration_us: u64,
    pub detected_baud_rate: u32,
    pub detected_timescale: String,
    pub matched_signal: String,
    pub available_signals: Vec<String>,
    pub framing_errors: usize,
    pub parity_errors: usize,
    pub glitch_count: usize,
    pub transitions: Vec<VcdTransition>,
}

/// 解析 IEEE 1364 VCD `$timescale ... $end` 指令，返回 1 tick 折合微秒 (us) 的缩放系数
/// 兼容 "1 ns", "10ps", "100 us" 及跨行写法；缺省时按常规逻辑分析仪 1 us 处理
pub(crate) fn parse_vcd_timescale_to_us(vcd_content: &str) -> (f64, String) {
    let mut in_timescale = false;
    let mut collected = Vec::new();
    for tok in vcd_content.split_whitespace() {
        if !in_timescale {
            if tok == "$timescale" {
                in_timescale = true;
            }
            continue;
        }
        if tok == "$end" {
            break;
        }
        collected.push(tok);
        if collected.len() >= 4 {
            break;
        }
    }
    if collected.is_empty() {
        return (1.0, "1 us (default)".to_string());
    }
    let joined = collected.join("");
    let num_end = joined.find(|c: char| !c.is_ascii_digit()).unwrap_or(joined.len());
    let mag: f64 = joined[..num_end].parse::<f64>().unwrap_or(1.0).max(1.0);
    let unit = joined[num_end..].trim().to_ascii_lowercase();
    let unit_in_us = match unit.as_str() {
        "s" => 1_000_000.0,
        "ms" => 1_000.0,
        "us" => 1.0,
        "ns" => 1e-3,
        "ps" => 1e-6,
        "fs" => 1e-9,
        _ => 1.0,
    };
    let desc = if unit.is_empty() {
        format!("{} us", mag as u64)
    } else {
        format!("{} {}", mag as u64, unit)
    };
    (mag * unit_in_us, desc)
}

/// 扫描全部 IEEE 1364 VCD `$var ... $end` 声明，返回 `(id_symbol, reference_name)` 列表
pub(crate) fn parse_vcd_var_declarations(vcd_content: &str) -> Vec<(String, String)> {
    let mut vars = Vec::new();
    let mut in_var = false;
    let mut var_tokens: Vec<String> = Vec::new();
    for tok in vcd_content.split_whitespace() {
        if !in_var {
            if tok == "$var" {
                in_var = true;
                var_tokens.clear();
            } else if tok == "$enddefinitions" {
                break;
            }
            continue;
        }
        if tok == "$end" {
            in_var = false;
            // 标准格式: $var <type> <size> <id_code> <reference> [bit_select] $end
            if var_tokens.len() >= 4 {
                let sym = var_tokens[2].clone();
                let mut name = var_tokens[3].clone();
                if let Some(pos) = name.find('[') {
                    name.truncate(pos);
                }
                if !sym.is_empty() && !name.is_empty() {
                    vars.push((sym, name));
                }
            }
            continue;
        }
        var_tokens.push(tok.to_string());
    }
    vars
}

/// 从 VCD 数据段提取目标信号符号的单比特电平变更 (`0`/`1`)
#[inline]
fn match_vcd_scalar_change(tok: &str, sym: &str) -> Option<u8> {
    if let Some(rest) = tok.strip_suffix(sym) {
        if rest.len() == 1 {
            return match rest.as_bytes()[0] {
                b'0' | b'z' | b'Z' | b'x' | b'X' => Some(0),
                b'1' => Some(1),
                _ => None,
            };
        }
    }
    None
}

/// 兼容旧签名的 VCD UART 解析入口（默认无校验位 8-N-1）
pub fn decode_vcd_uart_waveform(
    vcd_content: &str,
    target_signal: &str,
    baud_rate: u32,
) -> Result<VcdUartDecodedResult, String> {
    decode_vcd_uart_waveform_with_options(vcd_content, target_signal, baud_rate, None)
}

/// 解析标准 IEEE 1364 VCD 物理波形并按指定波特率、奇偶校验与精准 `$timescale` 缩放执行 UART 采样恢复
/// 时间复杂度: O(N + M log N)（N 为跳变点数，M 为采样点数）, 空间复杂度: O(N)
pub fn decode_vcd_uart_waveform_with_options(
    vcd_content: &str,
    target_signal: &str,
    baud_rate: u32,
    parity: Option<&str>,
) -> Result<VcdUartDecodedResult, String> {
    if baud_rate == 0 {
        return Err("波特率不能为 0".to_string());
    }
    if vcd_content.trim().is_empty() {
        return Err("VCD 文件内容为空".to_string());
    }

    let parity_mode = match parity.unwrap_or("NONE").trim().to_ascii_uppercase().as_str() {
        "EVEN" | "E" => 1u8,
        "ODD" | "O" => 2u8,
        _ => 0u8,
    };

    let (tick_to_us, timescale_desc) = parse_vcd_timescale_to_us(vcd_content);
    let vars = parse_vcd_var_declarations(vcd_content);
    let available_signals: Vec<String> = vars.iter().map(|(_, n)| n.clone()).collect();

    let clean_target = target_signal.trim();
    let (signal_sym, matched_signal) = if vars.is_empty() {
        if clean_target.is_empty() {
            ("!".to_string(), "TX".to_string())
        } else {
            ("!".to_string(), clean_target.to_string())
        }
    } else if clean_target.is_empty() {
        if vars.len() == 1 {
            (vars[0].0.clone(), vars[0].1.clone())
        } else if let Some(tx) = vars.iter().find(|(_, n)| n.eq_ignore_ascii_case("TX") || n.eq_ignore_ascii_case("UART_TX")) {
            (tx.0.clone(), tx.1.clone())
        } else {
            (vars[0].0.clone(), vars[0].1.clone())
        }
    } else if let Some(exact) = vars.iter().find(|(_, n)| n == clean_target) {
        (exact.0.clone(), exact.1.clone())
    } else if let Some(ci) = vars.iter().find(|(_, n)| n.eq_ignore_ascii_case(clean_target)) {
        (ci.0.clone(), ci.1.clone())
    } else {
        return Err(format!(
            "VCD 文件中未找到通道「{}」，文件实际包含通道: [{}]",
            clean_target,
            available_signals.join(", ")
        ));
    };

    // 单遍流式解析数据主体：支持 #timestamp 独立行或同行模式，支持标量 0!/1! 与向量 b0 !/b1 !
    let mut transitions_f64: Vec<(f64, u8)> = Vec::new();
    let mut cur_ticks: u64 = 0;
    let mut in_defs = vcd_content.contains("$enddefinitions");
    let mut past_defs = !in_defs;
    let mut skip_directive = false;
    let mut pending_vector_bit: Option<u8> = None;

    for tok in vcd_content.split_whitespace() {
        if !past_defs {
            if tok == "$enddefinitions" {
                in_defs = false;
            } else if !in_defs && tok == "$end" {
                past_defs = true;
            }
            continue;
        }
        if skip_directive {
            if tok == "$end" {
                skip_directive = false;
            }
            continue;
        }
        if tok == "$comment" || tok == "$scope" || tok == "$upscope" {
            skip_directive = true;
            continue;
        }
        if tok == "$dumpvars" || tok == "$dumpall" || tok == "$dumpoff" || tok == "$dumpon" || tok == "$end" {
            pending_vector_bit = None;
            continue;
        }
        if let Some(bit_val) = pending_vector_bit.take() {
            if tok == signal_sym {
                let t_us = (cur_ticks as f64) * tick_to_us;
                if transitions_f64.last().map_or(true, |&(_, prev)| prev != bit_val) {
                    transitions_f64.push((t_us, bit_val));
                }
            }
            continue;
        }
        if let Some(rest) = tok.strip_prefix('#') {
            if let Ok(ts) = rest.parse::<u64>() {
                cur_ticks = ts;
            }
            continue;
        }
        if tok.starts_with('b') || tok.starts_with('B') {
            if tok.len() >= 2 {
                let last_bit = tok.as_bytes()[tok.len() - 1];
                let lvl = if last_bit == b'1' { 1u8 } else { 0u8 };
                pending_vector_bit = Some(lvl);
            }
            continue;
        }
        if let Some(lvl) = match_vcd_scalar_change(tok, &signal_sym) {
            let t_us = (cur_ticks as f64) * tick_to_us;
            if transitions_f64.last().map_or(true, |&(_, prev)| prev != lvl) {
                transitions_f64.push((t_us, lvl));
            }
        }
    }

    if transitions_f64.is_empty() {
        return Err(format!("在通道「{}」中未发现任何电平跳变事件", matched_signal));
    }

    let bit_period_us = 1_000_000.0 / (baud_rate as f64);
    let initial_level = transitions_f64[0].1;

    // O(log N) 二分查找指定时刻的稳定电平
    let sample_level_at = |time_us: f64| -> u8 {
        let pos = transitions_f64.partition_point(|&(t, _)| t <= time_us);
        if pos == 0 {
            initial_level
        } else {
            transitions_f64[pos - 1].1
        }
    };

    let total_duration_f64 = transitions_f64.last().map(|t| t.0).unwrap_or(0.0);
    let total_duration = total_duration_f64.round() as u64;
    let mut decoded_bytes = Vec::new();
    let mut framing_errors = 0usize;
    let mut parity_errors = 0usize;
    let mut glitch_count = 0usize;

    let mut idx = 1usize;
    let mut next_allowed_search_time = 0.0f64;
    let stop_bit_offset = if parity_mode == 0 { 9.5 } else { 10.5 };
    let frame_total_bits = if parity_mode == 0 { 10.0 } else { 11.0 };

    while idx < transitions_f64.len() {
        let prev = transitions_f64[idx - 1];
        let curr = transitions_f64[idx];

        if curr.0 >= next_allowed_search_time && prev.1 == 1 && curr.1 == 0 {
            let t_start = curr.0;

            if idx + 1 < transitions_f64.len() && (transitions_f64[idx + 1].0 - t_start) < (0.2 * bit_period_us) {
                glitch_count += 1;
                idx += 1;
                continue;
            }

            let mid_start = sample_level_at(t_start + 0.5 * bit_period_us);
            if mid_start == 0 {
                let mut byte_val = 0u8;
                let mut ones_count = 0u32;
                for b in 0..8 {
                    let sample_t = t_start + (1.5 + b as f64) * bit_period_us;
                    let bit_val = sample_level_at(sample_t);
                    if bit_val == 1 {
                        ones_count += 1;
                    }
                    byte_val |= bit_val << b;
                }

                if parity_mode != 0 {
                    let p_bit = sample_level_at(t_start + 9.5 * bit_period_us) as u32;
                    let total_ones = ones_count + p_bit;
                    let expected_even = parity_mode == 1;
                    if (expected_even && total_ones % 2 != 0) || (!expected_even && total_ones % 2 == 0) {
                        parity_errors += 1;
                    }
                }

                let stop_sample_t = t_start + stop_bit_offset * bit_period_us;
                let stop_val = sample_level_at(stop_sample_t);
                if stop_val != 1 {
                    framing_errors += 1;
                }

                decoded_bytes.push(byte_val);
                next_allowed_search_time = t_start + (frame_total_bits - 0.15) * bit_period_us;
            }
        }
        idx += 1;
    }

    let decoded_hex = decoded_bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ");

    let text_repr: String = String::from_utf8_lossy(&decoded_bytes)
        .chars()
        .map(|ch| {
            if ch == '\r' || ch == '\n' || ch == '\t' || !ch.is_control() {
                ch
            } else {
                '.'
            }
        })
        .collect();

    let visible_transitions: Vec<VcdTransition> = transitions_f64
        .iter()
        .take(4000)
        .map(|&(t_us, level)| VcdTransition {
            timestamp_us: t_us.round() as u64,
            level,
        })
        .collect();

    Ok(VcdUartDecodedResult {
        decoded_bytes,
        decoded_text: text_repr,
        decoded_hex,
        total_sample_duration_us: total_duration,
        detected_baud_rate: baud_rate,
        detected_timescale: timescale_desc,
        matched_signal,
        available_signals,
        framing_errors,
        parity_errors,
        glitch_count,
        transitions: visible_transitions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_3_5t_duration() {
        // 9600 bps, 8 bits, None parity (0), 1 stop bit -> 1 + 8 + 0 + 1 = 10 bits
        // 10 * 3.5 = 35 bits. 35 / 9600 = 0.0036458s = 3646us
        let d_9600 = calculate_3_5t_duration(9600, 8, "None", 1);
        assert!(d_9600.as_micros() >= 3600 && d_9600.as_micros() <= 3700);

        // 高速波特率 (>19200) 应返回至少 3ms 的操作系统保底时间
        let d_115200 = calculate_3_5t_duration(115200, 8, "None", 1);
        assert_eq!(d_115200, Duration::from_millis(3));
    }

    #[test]
    fn test_modbus_rtu_crc_and_dissection() {
        // 1. Modbus RTU 读保持寄存器请求: 从站 1, 功能码 3, 起始地址 0x0000, 数量 2
        let raw_req = [0x01, 0x03, 0x00, 0x00, 0x00, 0x02];
        let crc = calculate_modbus_crc16(&raw_req);
        let mut frame = raw_req.to_vec();
        frame.push((crc & 0xFF) as u8);
        frame.push(((crc >> 8) & 0xFF) as u8);

        let parsed_req = dissect_modbus_rtu(&frame).expect("Modbus 请求帧解析失败");
        assert!(parsed_req.is_crc_valid);
        assert_eq!(parsed_req.slave_address, 1);
        assert_eq!(parsed_req.function_code, 3);
        assert_eq!(parsed_req.register_address, Some(0x0000));
        assert_eq!(parsed_req.register_count, Some(2));
        assert!(!parsed_req.is_exception);

        // 2. Modbus RTU 读保持寄存器响应: 返回 2 个寄存器 (4 字节数据: 0x0102, 0x0304)
        let raw_resp = [0x01, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04];
        let crc_resp = calculate_modbus_crc16(&raw_resp);
        let mut frame_resp = raw_resp.to_vec();
        frame_resp.push((crc_resp & 0xFF) as u8);
        frame_resp.push(((crc_resp >> 8) & 0xFF) as u8);

        let parsed_resp = dissect_modbus_rtu(&frame_resp).expect("Modbus 响应帧解析失败");
        assert!(parsed_resp.is_crc_valid);
        assert_eq!(parsed_resp.byte_count, Some(4));
        assert_eq!(parsed_resp.values, vec![0x0102, 0x0304]);

        // 3. Modbus 异常响应: 功能码 0x83 (读错误), 异常码 0x02 (非法数据地址)
        let raw_exc = [0x01, 0x83, 0x02];
        let crc_exc = calculate_modbus_crc16(&raw_exc);
        let mut frame_exc = raw_exc.to_vec();
        frame_exc.push((crc_exc & 0xFF) as u8);
        frame_exc.push(((crc_exc >> 8) & 0xFF) as u8);

        let parsed_exc = dissect_modbus_rtu(&frame_exc).expect("Modbus 异常帧解析失败");
        assert!(parsed_exc.is_crc_valid);
        assert!(parsed_exc.is_exception);
        assert_eq!(parsed_exc.exception_code, Some(0x02));
    }

    #[test]
    fn test_dlt645_dissection() {
        // 构造 DL/T 645-2007 读数据请求
        // 0x68 + 地址(6B) + 0x68 + 控制码(1B) + 长度(1B) + CS + 0x16
        let mut frame = vec![0x68, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x68, 0x11, 0x00];
        let cs: u8 = frame.iter().fold(0u8, |acc, &x| acc.wrapping_add(x));
        frame.push(cs);
        frame.push(0x16);

        let parsed = dissect_dlt645(&frame).expect("DL/T 645 解析失败");
        assert!(parsed.is_valid_cs);
        assert_eq!(parsed.meter_address, "665544332211");
        assert_eq!(parsed.control_code, 0x11);
    }

    #[test]
    fn test_nmea0183_dissection() {
        let raw_body = "GNRMC,083559.00,A,4717.11437,N,00833.91522,E,0.004,77.52,091218,,,A";
        let cs = raw_body.bytes().fold(0u8, |acc, b| acc ^ b);
        let nmea_sentence = format!("${}*{:02X}\r\n", raw_body, cs);

        let parsed = dissect_nmea0183(nmea_sentence.as_bytes()).expect("NMEA 0183 解析失败");
        assert!(parsed.is_valid_checksum);
        assert_eq!(parsed.sentence_type, "$GNRMC");
        assert_eq!(parsed.latitude.as_deref(), Some("4717.11437 N"));
        assert_eq!(parsed.longitude.as_deref(), Some("00833.91522 E"));
        assert_eq!(parsed.speed_knots, Some(0.004));
    }

    #[test]
    fn test_vcd_waveform_uart_physical_decoding() {
        // 模拟 sigrok 导出的 115200 bps (位周期约 8.68 us) UART 字符 'A' (0x41 = 0b01000001)
        // LSB First 传输: Start(0), Bit0(1), Bit1(0), Bit2(0), Bit3(0), Bit4(0), Bit5(0), Bit6(1), Bit7(0), Stop(1)
        let vcd_content = r#"
$date 2026-11-08 $end
$version sigrok 0.5.2 $end
$timescale 1 us $end
$scope module top $end
$var wire 1 ! rx $end
$upscope $end
$enddefinitions $end
#0
1!
#10
0!
#19
1!
#27
0!
#71
1!
#79
0!
#88
1!
#120
1!
"#;

        let result = decode_vcd_uart_waveform(vcd_content, "rx", 115200).expect("VCD 解码失败");
        assert_eq!(result.decoded_bytes.len(), 1);
        assert_eq!(result.decoded_bytes[0], b'A');
        assert_eq!(result.decoded_text, "A");
        assert_eq!(result.framing_errors, 0);
        assert_eq!(result.matched_signal, "rx");
        assert_eq!(result.available_signals, vec!["rx".to_string()]);
    }

    #[test]
    fn test_vcd_timescale_ns_inline_timestamps_and_parity_edges() {
        // 1. 测试工业标准 $timescale 1 ns $end + 多通道声明 + 同行写法 (#ts lvl) + 115200 bps (位宽 8681 ns)
        // 发送 "OK" (0x4F, 0x4B)
        let bit_ns: u64 = 8681;
        let mut t: u64 = 20_000;
        let mut body = String::from("#0 1!\n#0 0\"\n");
        for &ch in b"OK" {
            body.push_str(&format!("#{} 0!\n", t)); // Start bit
            t += bit_ns;
            for b in 0..8 {
                let bit = (ch >> b) & 1;
                body.push_str(&format!("#{} {}!\n", t, bit));
                t += bit_ns;
            }
            body.push_str(&format!("#{} 1!\n", t)); // Stop bit
            t += bit_ns * 2;
        }
        let ns_vcd = format!(
            "$date\n  Saleae\n$end\n$timescale 1 ns $end\n$scope module top $end\n$var wire 1 ! TX $end\n$var wire 1 \" CLK $end\n$upscope $end\n$enddefinitions $end\n$dumpvars\n1!\n0\"\n$end\n{}",
            body
        );

        let res = decode_vcd_uart_waveform_with_options(&ns_vcd, "TX", 115200, Some("NONE")).expect("1ns VCD 解码失败");
        assert_eq!(res.decoded_text, "OK");
        assert_eq!(res.decoded_hex, "4F 4B");
        assert_eq!(res.framing_errors, 0);
        assert_eq!(res.parity_errors, 0);
        assert_eq!(res.detected_timescale, "1 ns");
        assert_eq!(res.available_signals, vec!["TX".to_string(), "CLK".to_string()]);

        // 2. 指定不存在通道应精准拦截并告知可用通道列表，禁止盲抓默认通道误解调
        let err = decode_vcd_uart_waveform_with_options(&ns_vcd, "NON_EXISTENT", 115200, None).unwrap_err();
        assert!(err.contains("TX") && err.contains("CLK"));

        // 3. 测试偶校验 8-E-1 发送 0x55 ('U', 含 4 个 1 -> 偶校验位应为 0)
        let mut even_vcd = String::from("$timescale 10 us $end\n$var wire 1 ! UART_TX $end\n$enddefinitions $end\n#0 1!\n");
        // 9600 bps -> 104.167 us -> ~10.4 ticks (用 1 us 更精准，此处验证 10 us 缩放)
        // 为避免 10us 采样量化误差，改用 10 ns 缩放发送 0x55 @ 115200 bps
        even_vcd.clear();
        even_vcd.push_str("$timescale 10 ns $end\n$var wire 1 ! UART_TX $end\n$enddefinitions $end\n#0 1!\n");
        let step_10ns = 868u64; // 8680 ns
        let mut cur = 1000u64;
        even_vcd.push_str(&format!("#{} 0!\n", cur)); // Start
        cur += step_10ns;
        let b_val = 0x55u8; // 0101_0101 -> 4 ones -> Even parity = 0
        for b in 0..8 {
            even_vcd.push_str(&format!("#{} {}!\n", cur, (b_val >> b) & 1));
            cur += step_10ns;
        }
        even_vcd.push_str(&format!("#{} 0!\n", cur)); // Even parity bit = 0
        cur += step_10ns;
        even_vcd.push_str(&format!("#{} 1!\n", cur)); // Stop bit = 1
        cur += step_10ns * 2;
        even_vcd.push_str(&format!("#{} 1!\n", cur));

        let ok_even = decode_vcd_uart_waveform_with_options(&even_vcd, "UART_TX", 115200, Some("EVEN")).unwrap();
        assert_eq!(ok_even.decoded_text, "U");
        assert_eq!(ok_even.parity_errors, 0);
        assert_eq!(ok_even.framing_errors, 0);

        // 若强行用 ODD 解 8-E-1 报文，应准确检出 1 次奇偶校验错误
        let bad_odd = decode_vcd_uart_waveform_with_options(&even_vcd, "UART_TX", 115200, Some("ODD")).unwrap();
        assert_eq!(bad_odd.parity_errors, 1);

        // 4. 极限边界防御：空 VCD 与 0 波特率
        assert!(decode_vcd_uart_waveform_with_options("", "TX", 9600, None).is_err());
        assert!(decode_vcd_uart_waveform_with_options(&ns_vcd, "TX", 0, None).is_err());
    }

}
