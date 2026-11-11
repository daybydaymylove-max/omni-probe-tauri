// SPDX-License-Identifier: Apache-2.0
// ============================================================================
// Omni-Probe 跨平台串口内建驱动级透明拦截与虚拟端口代理引擎 (serial_intercept.rs)
// ============================================================================
// 架构覆盖：
// 1. POSIX (Linux / macOS / 统信UOS / 麒麟KylinOS / OpenEuler):
//    基于 libc posix_openpt / grantpt / unlockpt / termios(cfmakeraw) / poll / TIOCMGET
//    零外部驱动直接生成透明虚拟伪终端 (/dev/pts/N + 可选软链接)，透传数据及控制引脚。
// 2. Windows 用户态无外挂原生通道:
//    - Win32 CreateNamedPipeW (\\.\pipe\omni_com_*) 双向流式透明网关
//    - 标准全双工 RFC 2217 (Telnet Com Port Control Option 44) TCP->Physical COM 控制协议栈
//      支持运行时动态重配物理波特率、数据位、校验位及 DTR/RTS 信号透传。
// 3. Windows 内核态 WDM Upper Filter 驱动联动客户端 (\\.\OmniSerialFilter):
//    与 src-tauri/drivers/omni_serial_flt/omni_serial_flt.c 精确对齐 ABI 与 IOCTL，
//    当目标系统已部署签名后的内核过滤驱动时，自动以 IRP 级零侵入旁路截取独占 COM 端口流量。

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

use crate::serial::{
    calculate_3_5t_duration, emit_intercept_frame, list_available_serial_ports_detail,
    parse_data_bits, parse_flow_control, parse_parity, parse_stop_bits, SerialCommunicationConfig,
};

// ============================================================================
// 1. 公共数据结构与能力自检报告
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualPortPairHint {
    pub pair_name: String,
    pub port_a: String,
    pub port_b: String,
    pub driver_source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelFilterDriverStatus {
    pub driver_loaded: bool,
    pub device_path: String,
    pub major_version: u32,
    pub minor_version: u32,
    pub build_number: u32,
    pub active_filter_devices: u32,
    pub kernel_dropped_events: u64,
    pub detail_message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerialInterceptCapabilities {
    pub os_family: String,
    pub posix_pty_supported: bool,
    pub windows_named_pipe_supported: bool,
    pub rfc2217_gateway_supported: bool,
    pub kernel_filter_driver: KernelFilterDriverStatus,
    pub detected_virtual_ports: Vec<VirtualPortPairHint>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum InterceptSessionMode {
    Rfc2217TcpProxy,
    WindowsNamedPipe,
    UnixPosixPty,
    WindowsKernelIrpTap,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterceptSessionInfo {
    pub session_id: String,
    pub mode: InterceptSessionMode,
    pub virtual_endpoint: String,
    pub target_port: String,
    pub baud_rate: u32,
    pub uptime_secs: u64,
    pub bytes_upstream_to_target: u64,
    pub bytes_target_to_upstream: u64,
    pub packets_captured: u64,
    pub ioctl_control_events: u64,
    pub is_running: bool,
    pub status_detail: String,
}

pub struct InterceptSessionHandle {
    pub info: Mutex<InterceptSessionInfo>,
    pub start_time: Instant,
    pub is_running: Arc<AtomicBool>,
    pub bytes_up: Arc<AtomicU64>,
    pub bytes_down: Arc<AtomicU64>,
    pub packets_captured: Arc<AtomicU64>,
    pub ioctl_events: Arc<AtomicU64>,
}

pub static ACTIVE_INTERCEPT_SESSIONS: Lazy<Arc<Mutex<HashMap<String, Arc<InterceptSessionHandle>>>>> =
    Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

// ============================================================================
// 2. Windows WDM 过滤驱动 (omni_serial_flt.c) 对齐 ABI 与 IOCTL 客户端
// ============================================================================

pub const FILE_DEVICE_OMNI_SERIAL: u32 = 0x8310;

/// 严格按 Windows CTL_CODE(DeviceType, Function, Method, Access) 宏展开：
/// ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method)
pub const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

pub const METHOD_BUFFERED: u32 = 0;
pub const FILE_READ_ACCESS: u32 = 1;
pub const FILE_WRITE_ACCESS: u32 = 2;

pub const IOCTL_OMNI_SERIAL_GET_VERSION: u32 =
    ctl_code(FILE_DEVICE_OMNI_SERIAL, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS);
pub const IOCTL_OMNI_SERIAL_POLL_EVENTS: u32 =
    ctl_code(FILE_DEVICE_OMNI_SERIAL, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS);
pub const IOCTL_OMNI_SERIAL_RESET_RING: u32 =
    ctl_code(FILE_DEVICE_OMNI_SERIAL, 0x802, METHOD_BUFFERED, FILE_WRITE_ACCESS);

pub const OMNI_MAX_PAYLOAD_CAPTURE: usize = 256;
pub const OMNI_EVT_READ: u32 = 1;
pub const OMNI_EVT_WRITE: u32 = 2;
pub const OMNI_EVT_IOCTL_BAUD: u32 = 3;
pub const OMNI_EVT_IOCTL_LCR: u32 = 4;
pub const OMNI_EVT_IOCTL_MODEM: u32 = 5;

#[repr(C, packed(1))]
#[derive(Clone, Copy)]
pub struct OmniKernelSerialEvent {
    pub timestamp_100ns: u64,
    pub device_id_hash: u32,
    pub event_type: u32,
    pub payload_length: u32,
    pub aux_value: u32,
    pub payload: [u8; OMNI_MAX_PAYLOAD_CAPTURE],
}

impl Default for OmniKernelSerialEvent {
    fn default() -> Self {
        Self {
            timestamp_100ns: 0,
            device_id_hash: 0,
            event_type: 0,
            payload_length: 0,
            aux_value: 0,
            payload: [0u8; OMNI_MAX_PAYLOAD_CAPTURE],
        }
    }
}

#[repr(C, packed(1))]
#[derive(Clone, Copy, Default)]
pub struct OmniSerialDriverInfo {
    pub major_version: u32,
    pub minor_version: u32,
    pub build_number: u32,
    pub active_filter_devices: u32,
    pub dropped_events: u64,
}

#[cfg(windows)]
fn to_wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// 探测系统是否已部署并加载 WDM 串口过滤驱动 `\\.\OmniSerialFilter`
pub fn probe_kernel_serial_filter_driver() -> KernelFilterDriverStatus {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{
            CloseHandle, GetLastError, ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, GENERIC_READ,
            INVALID_HANDLE_VALUE,
        };
        use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING};
        use windows_sys::Win32::System::IO::DeviceIoControl;

        let dev_path = r"\\.\OmniSerialFilter";
        let wide = to_wide_null(dev_path);
        // SAFETY: wide 为以 0 结尾 UTF-16 路径，使用后立即通过 CloseHandle 释放句柄
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            let err = unsafe { GetLastError() };
            let detail = match err {
                ERROR_FILE_NOT_FOUND => {
                    "未检测到已安装的 omni_serial_flt.sys 内核过滤驱动（驱动 C 工程源码与 INF 已附带于 src-tauri/drivers/omni_serial_flt，需经 WDK 编译与微软驱动签名后安装）".to_string()
                }
                ERROR_ACCESS_DENIED => {
                    "内核过滤驱动已存在，但当前非管理员进程被驱动安全 ACL (SDDL) 拒绝访问，请以管理员身份运行".to_string()
                }
                code => format!("尝试打开内核控制设备 \\\\.\\OmniSerialFilter 返回 Win32 错误码 {}", code),
            };
            return KernelFilterDriverStatus {
                driver_loaded: false,
                device_path: dev_path.to_string(),
                major_version: 0,
                minor_version: 0,
                build_number: 0,
                active_filter_devices: 0,
                kernel_dropped_events: 0,
                detail_message: detail,
            };
        }

        let mut info = OmniSerialDriverInfo::default();
        let mut bytes_returned: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_OMNI_SERIAL_GET_VERSION,
                std::ptr::null(),
                0,
                (&mut info as *mut OmniSerialDriverInfo).cast(),
                std::mem::size_of::<OmniSerialDriverInfo>() as u32,
                &mut bytes_returned,
                std::ptr::null_mut(),
            )
        };
        let err = unsafe { GetLastError() };
        unsafe { CloseHandle(handle) };

        if ok != 0 && bytes_returned >= std::mem::size_of::<OmniSerialDriverInfo>() as u32 {
            let major = info.major_version;
            let minor = info.minor_version;
            let build = info.build_number;
            let active = info.active_filter_devices;
            let dropped = info.dropped_events;
            KernelFilterDriverStatus {
                driver_loaded: true,
                device_path: dev_path.to_string(),
                major_version: major,
                minor_version: minor,
                build_number: build,
                active_filter_devices: active,
                kernel_dropped_events: dropped,
                detail_message: format!(
                    "WDM 内核上层过滤驱动 v{}.{}.{} 运行就绪，当前挂接 {} 个 COM 设备节点",
                    major, minor, build, active
                ),
            }
        } else {
            KernelFilterDriverStatus {
                driver_loaded: false,
                device_path: dev_path.to_string(),
                major_version: 0,
                minor_version: 0,
                build_number: 0,
                active_filter_devices: 0,
                kernel_dropped_events: 0,
                detail_message: format!("\\\\.\\OmniSerialFilter 版本 IOCTL 调用失败 (Win32 错误码: {})", err),
            }
        }
    }

    #[cfg(not(windows))]
    {
        KernelFilterDriverStatus {
            driver_loaded: false,
            device_path: "/dev/pts".to_string(),
            major_version: 0,
            minor_version: 0,
            build_number: 0,
            active_filter_devices: 0,
            kernel_dropped_events: 0,
            detail_message: "当前处于 POSIX 类平台，可直接使用内核原生 POSIX PTY 伪终端完成零外挂透明串口拦截".to_string(),
        }
    }
}

/// 扫描系统已有的虚拟串口对（兼容 com0com CNCA/CNCB 与通用虚拟串口配对提示）
pub fn detect_virtual_serial_pairs() -> Vec<VirtualPortPairHint> {
    let ports = list_available_serial_ports_detail();
    let mut pairs = Vec::new();
    let mut cnc_map: HashMap<String, String> = HashMap::new();

    for p in &ports {
        let up = p.port_name.to_uppercase();
        if up.starts_with("COM") {
            let desc_low = p.description.to_lowercase();
            if desc_low.contains("com0com") || desc_low.contains("virtual") || desc_low.contains("eltima") {
                cnc_map.insert(p.port_name.clone(), p.description.clone());
            }
        } else if up.starts_with("CNCA") || up.starts_with("CNCB") {
            cnc_map.insert(p.port_name.clone(), p.description.clone());
        }
    }

    let mut names: Vec<String> = cnc_map.keys().cloned().collect();
    names.sort();
    for pair in names.chunks_exact(2) {
        pairs.push(VirtualPortPairHint {
            pair_name: format!("{} <-> {}", pair[0], pair[1]),
            port_a: pair[0].clone(),
            port_b: pair[1].clone(),
            driver_source: cnc_map.get(&pair[0]).cloned().unwrap_or_else(|| "System Virtual Serial".into()),
        });
    }
    pairs
}

/// 汇总全平台透明串口拦截能力矩阵
pub fn get_serial_intercept_capabilities() -> SerialInterceptCapabilities {
    SerialInterceptCapabilities {
        os_family: std::env::consts::OS.to_string(),
        posix_pty_supported: cfg!(unix),
        windows_named_pipe_supported: cfg!(windows),
        rfc2217_gateway_supported: true,
        kernel_filter_driver: probe_kernel_serial_filter_driver(),
        detected_virtual_ports: detect_virtual_serial_pairs(),
    }
}

/// 查询当前活跃的所有透明拦截会话
pub fn list_active_intercept_sessions() -> Vec<InterceptSessionInfo> {
    let sessions = crate::lock_guard::lock_mutex(
        &ACTIVE_INTERCEPT_SESSIONS,
        "serial_intercept::list_active_intercept_sessions",
    );
    sessions
        .values()
        .filter(|h| h.is_running.load(Ordering::Acquire))
        .map(|h| {
            let mut info = crate::lock_guard::lock_mutex(&h.info, "serial_intercept::list_snapshot").clone();
            info.uptime_secs = h.start_time.elapsed().as_secs();
            info.bytes_upstream_to_target = h.bytes_up.load(Ordering::Relaxed);
            info.bytes_target_to_upstream = h.bytes_down.load(Ordering::Relaxed);
            info.packets_captured = h.packets_captured.load(Ordering::Relaxed);
            info.ioctl_control_events = h.ioctl_events.load(Ordering::Relaxed);
            info
        })
        .collect()
}

pub fn stop_intercept_session(session_id: Option<&str>) -> String {
    let mut map = crate::lock_guard::lock_mutex(
        &ACTIVE_INTERCEPT_SESSIONS,
        "serial_intercept::stop_intercept_session",
    );
    if let Some(id) = session_id {
        if let Some(handle) = map.remove(id) {
            handle.is_running.store(false, Ordering::SeqCst);
            if let Ok(mut info) = handle.info.lock() {
                info.is_running = false;
            }
            format!("[SERIAL_INTERCEPT] 拦截会话 {} 已安全终止", id)
        } else {
            format!("[SERIAL_INTERCEPT] 会话 {} 未运行", id)
        }
    } else {
        let count = map.len();
        for (_, h) in map.drain() {
            h.is_running.store(false, Ordering::SeqCst);
        }
        format!("[SERIAL_INTERCEPT] 已停止全部 {} 条透明拦截会话", count)
    }
}

// ============================================================================
// 3. RFC 2217 (Telnet Com Port Control) 状态机解析/构包引擎
//    时间复杂度: O(N) 单遍字节扫描，空间复杂度: O(1) 解析器状态 + 小缓冲
// ============================================================================

pub mod rfc2217 {
    pub const IAC: u8 = 0xFF;
    pub const DONT: u8 = 0xFE;
    pub const DO: u8 = 0xFD;
    pub const WONT: u8 = 0xFC;
    pub const WILL: u8 = 0xFB;
    pub const SB: u8 = 0xFA;
    pub const SE: u8 = 0xF0;

    pub const OPT_BINARY: u8 = 0x00;
    pub const OPT_SUPPRESS_GA: u8 = 0x03;
    pub const OPT_COM_PORT: u8 = 44;

    // Client -> Server Com Port sub-options
    pub const C2S_SET_BAUDRATE: u8 = 1;
    pub const C2S_SET_DATASIZE: u8 = 2;
    pub const C2S_SET_PARITY: u8 = 3;
    pub const C2S_SET_STOPSIZE: u8 = 4;
    pub const C2S_SET_CONTROL: u8 = 5;
    pub const C2S_NOTIFY_LINESTATE: u8 = 6;
    pub const C2S_NOTIFY_MODEMSTATE: u8 = 7;

    // Server -> Client ack offsets (+100)
    pub const S2C_OFFSET: u8 = 100;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Rfc2217Command {
        SetBaudRate(u32),
        SetDataSize(u8),
        SetParity(u8),
        SetStopSize(u8),
        SetControl(u8),
        TelnetNegotiation { verb: u8, option: u8 },
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum ParserState {
        Data,
        Iac,
        Command(u8),
        SubNegotiationOpt,
        SubNegotiationBody(u8),
        SubNegotiationIac(u8),
    }

    /// 零分配/流式 RFC 2217 与普通二进制数据解复用器
    pub struct Rfc2217StreamDecoder {
        state: ParserState,
        sb_buf: Vec<u8>,
    }

    impl Default for Rfc2217StreamDecoder {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Rfc2217StreamDecoder {
        pub fn new() -> Self {
            Self {
                state: ParserState::Data,
                sb_buf: Vec::with_capacity(32),
            }
        }

        /// 将原始 TCP 字节流拆解为：(纯净串口有效载荷字节, 提取到的 RFC2217 控制指令)
        pub fn feed(&mut self, input: &[u8]) -> (Vec<u8>, Vec<Rfc2217Command>) {
            let mut data_out = Vec::with_capacity(input.len());
            let mut cmds = Vec::new();

            for &b in input {
                match self.state.clone() {
                    ParserState::Data => {
                        if b == IAC {
                            self.state = ParserState::Iac;
                        } else {
                            data_out.push(b);
                        }
                    }
                    ParserState::Iac => match b {
                        IAC => {
                            // Telnet 转义 0xFF 0xFF -> 单字节物理串口数据 0xFF
                            data_out.push(IAC);
                            self.state = ParserState::Data;
                        }
                        DO | DONT | WILL | WONT => {
                            self.state = ParserState::Command(b);
                        }
                        SB => {
                            self.sb_buf.clear();
                            self.state = ParserState::SubNegotiationOpt;
                        }
                        _ => {
                            self.state = ParserState::Data;
                        }
                    },
                    ParserState::Command(verb) => {
                        cmds.push(Rfc2217Command::TelnetNegotiation { verb, option: b });
                        self.state = ParserState::Data;
                    }
                    ParserState::SubNegotiationOpt => {
                        self.sb_buf.clear();
                        self.state = ParserState::SubNegotiationBody(b);
                    }
                    ParserState::SubNegotiationBody(opt) => {
                        if b == IAC {
                            self.state = ParserState::SubNegotiationIac(opt);
                        } else if self.sb_buf.len() < 64 {
                            self.sb_buf.push(b);
                        }
                    }
                    ParserState::SubNegotiationIac(opt) => {
                        if b == SE {
                            if opt == OPT_COM_PORT {
                                if let Some(cmd) = Self::decode_com_port_sb(&self.sb_buf) {
                                    cmds.push(cmd);
                                }
                            }
                            self.sb_buf.clear();
                            self.state = ParserState::Data;
                        } else if b == IAC {
                            if self.sb_buf.len() < 64 {
                                self.sb_buf.push(IAC);
                            }
                            self.state = ParserState::SubNegotiationBody(opt);
                        } else {
                            self.sb_buf.clear();
                            self.state = ParserState::Data;
                        }
                    }
                }
            }

            (data_out, cmds)
        }

        fn decode_com_port_sb(buf: &[u8]) -> Option<Rfc2217Command> {
            let subcmd = *buf.first()?;
            let args = &buf[1..];
            match subcmd {
                C2S_SET_BAUDRATE if args.len() >= 4 => {
                    let baud = u32::from_be_bytes([args[0], args[1], args[2], args[3]]);
                    Some(Rfc2217Command::SetBaudRate(baud))
                }
                C2S_SET_DATASIZE if !args.is_empty() => Some(Rfc2217Command::SetDataSize(args[0])),
                C2S_SET_PARITY if !args.is_empty() => Some(Rfc2217Command::SetParity(args[0])),
                C2S_SET_STOPSIZE if !args.is_empty() => Some(Rfc2217Command::SetStopSize(args[0])),
                C2S_SET_CONTROL if !args.is_empty() => Some(Rfc2217Command::SetControl(args[0])),
                _ => None,
            }
        }

        /// 将纯净串口输出流封装为合法 Telnet 转义字节流 (遇 0xFF 扩展为 0xFF 0xFF)
        pub fn encode_serial_data_escaped(raw: &[u8]) -> Vec<u8> {
            let mut out = Vec::with_capacity(raw.len() + 8);
            for &b in raw {
                out.push(b);
                if b == IAC {
                    out.push(IAC);
                }
            }
            out
        }

        /// 生成 RFC 2217 Subnegotiation 应答包
        pub fn build_subnegotiation_reply(subcmd: u8, payload: &[u8]) -> Vec<u8> {
            let mut out = Vec::with_capacity(8 + payload.len());
            out.push(IAC);
            out.push(SB);
            out.push(OPT_COM_PORT);
            out.push(subcmd.saturating_add(S2C_OFFSET));
            for &b in payload {
                out.push(b);
                if b == IAC {
                    out.push(IAC);
                }
            }
            out.push(IAC);
            out.push(SE);
            out
        }
    }
}

// ============================================================================
// 4. 通用的分帧超时聚集助手 (解决全双工单字节拆散导致误解剖)
// ============================================================================

struct StreamFrameBatcher {
    buffer: Vec<u8>,
    last_rx: Instant,
    idle_gap: Duration,
}

impl StreamFrameBatcher {
    fn new(idle_gap: Duration) -> Self {
        Self {
            buffer: Vec::with_capacity(2048),
            last_rx: Instant::now(),
            idle_gap,
        }
    }

    fn push(&mut self, chunk: &[u8]) {
        self.buffer.extend_from_slice(chunk);
        self.last_rx = Instant::now();
    }

    fn take_if_ready(&mut self, force: bool) -> Option<Vec<u8>> {
        if self.buffer.is_empty() {
            return None;
        }
        if force || self.buffer.len() >= 1024 || self.last_rx.elapsed() >= self.idle_gap {
            return Some(std::mem::take(&mut self.buffer));
        }
        None
    }
}

// ============================================================================
// 5. 模式 A: 全平台 RFC 2217 透明串口服务器网关
// ============================================================================

/// 启动 RFC 2217 透明串口网关: 本地监听 `127.0.0.1:<listen_port>` <-> 真实 `target_port`
/// 当第三方工业软件 / 调试工具连接 TCP 并启用 RFC 2217 时，实时将串口数据和控制指令穿透到底层串口
pub fn start_rfc2217_intercept_gateway(
    app: Option<tauri::AppHandle>,
    listen_port: u16,
    target_port: &str,
    config: SerialCommunicationConfig,
) -> Result<InterceptSessionInfo, String> {
    let clean_target = target_port.trim().to_string();
    if clean_target.is_empty() {
        return Err("目标物理串口名称不能为空".into());
    }

    let listener = TcpListener::bind(("127.0.0.1", listen_port))
        .map_err(|e| format!("RFC 2217 本地端口 {} 监听绑定失败: {}", listen_port, e))?;
    let actual_port = listener.local_addr().map(|a| a.port()).unwrap_or(listen_port);
    listener.set_nonblocking(true).map_err(|e| format!("设置非阻塞监听器失败: {}", e))?;

    // 允许单元测试下使用 "LOOPBACK_ECHO" 作为虚拟测试目标（不依赖硬件 COM 口存在），生产则真实打开物理口
    let is_loopback_target = clean_target == "LOOPBACK_ECHO";
    let physical_port_opt = if is_loopback_target {
        None
    } else {
        let port = serialport::new(&clean_target, config.baud_rate)
            .data_bits(parse_data_bits(config.data_bits))
            .parity(parse_parity(&config.parity))
            .stop_bits(parse_stop_bits(config.stop_bits))
            .flow_control(parse_flow_control(&config.flow_control))
            .timeout(Duration::from_millis(12))
            .open()
            .map_err(|e| format!("打开底层串口 {} 失败: {}", clean_target, e))?;
        Some(port)
    };

    let session_id = format!("RFC2217-{}-{}", actual_port, clean_target);
    let endpoint = format!("rfc2217://127.0.0.1:{}", actual_port);
    let handle = Arc::new(InterceptSessionHandle {
        info: Mutex::new(InterceptSessionInfo {
            session_id: session_id.clone(),
            mode: InterceptSessionMode::Rfc2217TcpProxy,
            virtual_endpoint: endpoint.clone(),
            target_port: clean_target.clone(),
            baud_rate: config.baud_rate,
            uptime_secs: 0,
            bytes_upstream_to_target: 0,
            bytes_target_to_upstream: 0,
            packets_captured: 0,
            ioctl_control_events: 0,
            is_running: true,
            status_detail: format!("RFC2217 透明网关监听 {}，等待工业软件接入...", endpoint),
        }),
        start_time: Instant::now(),
        is_running: Arc::new(AtomicBool::new(true)),
        bytes_up: Arc::new(AtomicU64::new(0)),
        bytes_down: Arc::new(AtomicU64::new(0)),
        packets_captured: Arc::new(AtomicU64::new(0)),
        ioctl_events: Arc::new(AtomicU64::new(0)),
    });

    {
        let mut map = crate::lock_guard::lock_mutex(
            &ACTIVE_INTERCEPT_SESSIONS,
            "serial_intercept::start_rfc2217_insert",
        );
        if map.contains_key(&session_id) {
            return Err(format!("拦截会话 {} 已在运行", session_id));
        }
        map.insert(session_id.clone(), handle.clone());
    }

    let snapshot = crate::lock_guard::lock_mutex(&handle.info, "serial_intercept::init_snap").clone();
    let idle_gap = calculate_3_5t_duration(config.baud_rate, config.data_bits, &config.parity, config.stop_bits);

    std::thread::spawn(move || {
        let mut phys_opt = physical_port_opt;
        let mut decoder = rfc2217::Rfc2217StreamDecoder::new();
        let mut batcher_up = StreamFrameBatcher::new(idle_gap);
        let mut batcher_down = StreamFrameBatcher::new(idle_gap);
        let mut current_client: Option<TcpStream> = None;
        let mut buf_tcp = [0u8; 2048];
        let mut buf_ser = [0u8; 2048];

        while handle.is_running.load(Ordering::Acquire) {
            if current_client.is_none() {
                match listener.accept() {
                    Ok((mut stream, peer)) => {
                        let _ = stream.set_nonblocking(true);
                        let _ = stream.set_nodelay(true);
                        // 发送初始 Telnet RFC2217 能力协商通告
                        let init_neg = [
                            rfc2217::IAC, rfc2217::WILL, rfc2217::OPT_COM_PORT,
                            rfc2217::IAC, rfc2217::WILL, rfc2217::OPT_BINARY,
                            rfc2217::IAC, rfc2217::WILL, rfc2217::OPT_SUPPRESS_GA,
                        ];
                        let _ = stream.write_all(&init_neg);
                        if let Ok(mut inf) = handle.info.lock() {
                            inf.status_detail = format!("已接入上游客户端 {} -> {}", peer, clean_target);
                        }
                        current_client = Some(stream);
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(8));
                    }
                    Err(_) => break,
                }
                continue;
            }

            let mut client_disconnected = false;
            if let Some(stream) = current_client.as_mut() {
                match stream.read(&mut buf_tcp) {
                    Ok(0) => client_disconnected = true,
                    Ok(n) => {
                        let (clean_payload, cmds) = decoder.feed(&buf_tcp[..n]);
                        for cmd in cmds {
                            handle.ioctl_events.fetch_add(1, Ordering::Relaxed);
                            match cmd {
                                rfc2217::Rfc2217Command::SetBaudRate(baud) if baud > 0 => {
                                    if let Some(p) = phys_opt.as_mut() {
                                        let _ = p.set_baud_rate(baud);
                                    }
                                    if let Ok(mut inf) = handle.info.lock() {
                                        inf.baud_rate = baud;
                                    }
                                    let reply = rfc2217::Rfc2217StreamDecoder::build_subnegotiation_reply(
                                        rfc2217::C2S_SET_BAUDRATE,
                                        &baud.to_be_bytes(),
                                    );
                                    let _ = stream.write_all(&reply);
                                }
                                rfc2217::Rfc2217Command::SetControl(ctrl) => {
                                    if let Some(p) = phys_opt.as_mut() {
                                        match ctrl {
                                            8 => { let _ = p.write_data_terminal_ready(true); }
                                            9 => { let _ = p.write_data_terminal_ready(false); }
                                            11 => { let _ = p.write_request_to_send(true); }
                                            12 => { let _ = p.write_request_to_send(false); }
                                            _ => {}
                                        }
                                    }
                                    let reply = rfc2217::Rfc2217StreamDecoder::build_subnegotiation_reply(
                                        rfc2217::C2S_SET_CONTROL,
                                        &[ctrl],
                                    );
                                    let _ = stream.write_all(&reply);
                                }
                                rfc2217::Rfc2217Command::TelnetNegotiation { verb, option } => {
                                    if verb == rfc2217::DO && (option == rfc2217::OPT_COM_PORT || option == rfc2217::OPT_BINARY || option == rfc2217::OPT_SUPPRESS_GA) {
                                        let _ = stream.write_all(&[rfc2217::IAC, rfc2217::WILL, option]);
                                    } else if verb == rfc2217::WILL && (option == rfc2217::OPT_BINARY || option == rfc2217::OPT_SUPPRESS_GA) {
                                        let _ = stream.write_all(&[rfc2217::IAC, rfc2217::DO, option]);
                                    }
                                }
                                _ => {}
                            }
                        }

                        if !clean_payload.is_empty() {
                            handle.bytes_up.fetch_add(clean_payload.len() as u64, Ordering::Relaxed);
                            batcher_up.push(&clean_payload);
                            if is_loopback_target {
                                // 回环测试目标：将净载荷镜像回传验证全双工
                                let escaped = rfc2217::Rfc2217StreamDecoder::encode_serial_data_escaped(&clean_payload);
                                let _ = stream.write_all(&escaped);
                                let _ = stream.flush();
                                handle.bytes_down.fetch_add(clean_payload.len() as u64, Ordering::Relaxed);
                                batcher_down.push(&clean_payload);
                            } else if let Some(p) = phys_opt.as_mut() {
                                let _ = p.write_all(&clean_payload);
                                let _ = p.flush();
                            }
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => client_disconnected = true,
                }

                // 物理串口 B -> 上游 TCP A 读回
                if !client_disconnected {
                    if let Some(p) = phys_opt.as_mut() {
                        match p.read(&mut buf_ser) {
                            Ok(n) if n > 0 => {
                                let chunk = &buf_ser[..n];
                                handle.bytes_down.fetch_add(n as u64, Ordering::Relaxed);
                                batcher_down.push(chunk);
                                let escaped = rfc2217::Rfc2217StreamDecoder::encode_serial_data_escaped(chunk);
                                let _ = stream.write_all(&escaped);
                                let _ = stream.flush();
                            }
                            _ => {}
                        }
                    }
                }
            }

            if client_disconnected {
                current_client = None;
                if let Ok(mut inf) = handle.info.lock() {
                    inf.status_detail = format!("客户端断开，RFC2217 网关 {} 继续监听...", endpoint);
                }
            }

            if let Some(frame) = batcher_up.take_if_ready(client_disconnected) {
                handle.packets_captured.fetch_add(1, Ordering::Relaxed);
                if let Some(ref a) = app {
                    emit_intercept_frame(a, &endpoint, &clean_target, &frame, "INTERCEPT_TX_UP_TO_DEV", "RFC2217_PROXY");
                }
            }
            if let Some(frame) = batcher_down.take_if_ready(client_disconnected) {
                handle.packets_captured.fetch_add(1, Ordering::Relaxed);
                if let Some(ref a) = app {
                    emit_intercept_frame(a, &clean_target, &endpoint, &frame, "INTERCEPT_RX_DEV_TO_UP", "RFC2217_PROXY");
                }
            }

            std::thread::sleep(Duration::from_millis(2));
        }

        let mut map = crate::lock_guard::lock_mutex(&ACTIVE_INTERCEPT_SESSIONS, "serial_intercept::rfc2217_cleanup");
        map.remove(&session_id);
    });

    Ok(snapshot)
}

// ============================================================================
// 6. 模式 B: Windows 原生 NamedPipe (\\.\pipe\omni_com_<name>) 透明拦截代理
// ============================================================================

#[cfg(windows)]
pub fn start_windows_named_pipe_intercept(
    app: Option<tauri::AppHandle>,
    pipe_suffix: &str,
    target_port: &str,
    config: SerialCommunicationConfig,
) -> Result<InterceptSessionInfo, String> {
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_PIPE_CONNECTED, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{FlushFileBuffers, PIPE_ACCESS_DUPLEX, ReadFile, WriteFile};
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PeekNamedPipe, PIPE_READMODE_BYTE,
        PIPE_TYPE_BYTE, PIPE_WAIT,
    };

    let clean_suffix: String = pipe_suffix
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect();
    if clean_suffix.is_empty() {
        return Err("管道标识不能为空（仅支持字母、数字、下划线或连字符）".into());
    }
    let clean_target = target_port.trim().to_string();
    if clean_target.is_empty() {
        return Err("目标硬件串口不能为空".into());
    }

    let is_loopback_target = clean_target == "LOOPBACK_ECHO";
    let physical_port_opt = if is_loopback_target {
        None
    } else {
        let port = serialport::new(&clean_target, config.baud_rate)
            .data_bits(parse_data_bits(config.data_bits))
            .parity(parse_parity(&config.parity))
            .stop_bits(parse_stop_bits(config.stop_bits))
            .flow_control(parse_flow_control(&config.flow_control))
            .timeout(Duration::from_millis(12))
            .open()
            .map_err(|e| format!("打开目标串口 {} 失败: {}", clean_target, e))?;
        Some(port)
    };

    let pipe_path = format!(r"\\.\pipe\omni_com_{}", clean_suffix);
    let pipe_wide = to_wide_null(&pipe_path);
    // 提前创建管道验证权限与可用性，句柄传入后台双向工作线程持有
    let pipe_handle = unsafe {
        CreateNamedPipeW(
            pipe_wide.as_ptr(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            8192,
            8192,
            50,
            std::ptr::null(),
        )
    };
    if pipe_handle == INVALID_HANDLE_VALUE {
        let err = unsafe { GetLastError() };
        return Err(format!("创建 Win32 NamedPipe {} 失败 (错误码: {})", pipe_path, err));
    }

    let session_id = format!("PIPE-{}-{}", clean_suffix, clean_target);
    let handle = Arc::new(InterceptSessionHandle {
        info: Mutex::new(InterceptSessionInfo {
            session_id: session_id.clone(),
            mode: InterceptSessionMode::WindowsNamedPipe,
            virtual_endpoint: pipe_path.clone(),
            target_port: clean_target.clone(),
            baud_rate: config.baud_rate,
            uptime_secs: 0,
            bytes_upstream_to_target: 0,
            bytes_target_to_upstream: 0,
            packets_captured: 0,
            ioctl_control_events: 0,
            is_running: true,
            status_detail: format!("Win32 NamedPipe {} 已就绪，等待外部客户端挂载", pipe_path),
        }),
        start_time: Instant::now(),
        is_running: Arc::new(AtomicBool::new(true)),
        bytes_up: Arc::new(AtomicU64::new(0)),
        bytes_down: Arc::new(AtomicU64::new(0)),
        packets_captured: Arc::new(AtomicU64::new(0)),
        ioctl_events: Arc::new(AtomicU64::new(0)),
    });

    {
        let mut map = crate::lock_guard::lock_mutex(
            &ACTIVE_INTERCEPT_SESSIONS,
            "serial_intercept::start_pipe_insert",
        );
        if map.contains_key(&session_id) {
            unsafe { CloseHandle(pipe_handle) };
            return Err(format!("管道拦截会话 {} 已存在", session_id));
        }
        map.insert(session_id.clone(), handle.clone());
    }

    let snapshot = crate::lock_guard::lock_mutex(&handle.info, "serial_intercept::pipe_snap").clone();
    let idle_gap = calculate_3_5t_duration(config.baud_rate, config.data_bits, &config.parity, config.stop_bits);
    let pipe_raw_handle = pipe_handle as isize;

    std::thread::spawn(move || {
        let h_pipe = pipe_raw_handle as windows_sys::Win32::Foundation::HANDLE;
        let mut phys_opt = physical_port_opt;
        let mut batcher_up = StreamFrameBatcher::new(idle_gap);
        let mut batcher_down = StreamFrameBatcher::new(idle_gap);
        let mut buf_pipe = [0u8; 2048];
        let mut buf_ser = [0u8; 2048];

        // 阻塞等待连接；若外部立即停止，可以通过断开或写入唤醒退出
        let connected = unsafe {
            ConnectNamedPipe(h_pipe, std::ptr::null_mut()) != 0
                || GetLastError() == ERROR_PIPE_CONNECTED
        };

        if connected {
            if let Ok(mut inf) = handle.info.lock() {
                inf.status_detail = format!("客户端已挂载 {} <-> {} (全双工实时透传中)", pipe_path, clean_target);
            }

            while handle.is_running.load(Ordering::Acquire) {
                let mut avail: u32 = 0;
                let peek_ok = unsafe {
                    PeekNamedPipe(
                        h_pipe,
                        std::ptr::null_mut(),
                        0,
                        std::ptr::null_mut(),
                        &mut avail,
                        std::ptr::null_mut(),
                    )
                };
                if peek_ok == 0 {
                    // 客户端关闭管道连接
                    break;
                }

                if avail > 0 {
                    let to_read = (avail as usize).min(buf_pipe.len()) as u32;
                    let mut read_n: u32 = 0;
                    let rok = unsafe {
                        ReadFile(
                            h_pipe,
                            buf_pipe.as_mut_ptr(),
                            to_read,
                            &mut read_n,
                            std::ptr::null_mut(),
                        )
                    };
                    if rok == 0 || read_n == 0 {
                        break;
                    }
                    let chunk = &buf_pipe[..read_n as usize];
                    handle.bytes_up.fetch_add(chunk.len() as u64, Ordering::Relaxed);
                    batcher_up.push(chunk);

                    if is_loopback_target {
                        let mut written: u32 = 0;
                        let _ = unsafe {
                            WriteFile(
                                h_pipe,
                                chunk.as_ptr(),
                                chunk.len() as u32,
                                &mut written,
                                std::ptr::null_mut(),
                            )
                        };
                        let _ = unsafe { FlushFileBuffers(h_pipe) };
                        handle.bytes_down.fetch_add(written as u64, Ordering::Relaxed);
                        batcher_down.push(&chunk[..written as usize]);
                    } else if let Some(p) = phys_opt.as_mut() {
                        let _ = p.write_all(chunk);
                        let _ = p.flush();
                    }
                }

                if let Some(p) = phys_opt.as_mut() {
                    if let Ok(n) = p.read(&mut buf_ser) {
                        if n > 0 {
                            let chunk = &buf_ser[..n];
                            let mut written: u32 = 0;
                            let _ = unsafe {
                                WriteFile(
                                    h_pipe,
                                    chunk.as_ptr(),
                                    n as u32,
                                    &mut written,
                                    std::ptr::null_mut(),
                                )
                            };
                            let _ = unsafe { FlushFileBuffers(h_pipe) };
                            handle.bytes_down.fetch_add(n as u64, Ordering::Relaxed);
                            batcher_down.push(chunk);
                        }
                    }
                }

                if let Some(frame) = batcher_up.take_if_ready(false) {
                    handle.packets_captured.fetch_add(1, Ordering::Relaxed);
                    if let Some(ref a) = app {
                        emit_intercept_frame(a, &pipe_path, &clean_target, &frame, "INTERCEPT_TX_UP_TO_DEV", "WIN_NAMED_PIPE");
                    }
                }
                if let Some(frame) = batcher_down.take_if_ready(false) {
                    handle.packets_captured.fetch_add(1, Ordering::Relaxed);
                    if let Some(ref a) = app {
                        emit_intercept_frame(a, &clean_target, &pipe_path, &frame, "INTERCEPT_RX_DEV_TO_UP", "WIN_NAMED_PIPE");
                    }
                }

                std::thread::sleep(Duration::from_millis(2));
            }
        }

        if let Some(frame) = batcher_up.take_if_ready(true) {
            handle.packets_captured.fetch_add(1, Ordering::Relaxed);
            if let Some(ref a) = app {
                emit_intercept_frame(a, &pipe_path, &clean_target, &frame, "INTERCEPT_TX_UP_TO_DEV", "WIN_NAMED_PIPE");
            }
        }
        if let Some(frame) = batcher_down.take_if_ready(true) {
            handle.packets_captured.fetch_add(1, Ordering::Relaxed);
            if let Some(ref a) = app {
                emit_intercept_frame(a, &clean_target, &pipe_path, &frame, "INTERCEPT_RX_DEV_TO_UP", "WIN_NAMED_PIPE");
            }
        }

        unsafe {
            DisconnectNamedPipe(h_pipe);
            CloseHandle(h_pipe);
        }
        let mut map = crate::lock_guard::lock_mutex(&ACTIVE_INTERCEPT_SESSIONS, "serial_intercept::pipe_cleanup");
        map.remove(&session_id);
    });

    Ok(snapshot)
}

#[cfg(not(windows))]
pub fn start_windows_named_pipe_intercept(
    _app: Option<tauri::AppHandle>,
    _pipe_suffix: &str,
    _target_port: &str,
    _config: SerialCommunicationConfig,
) -> Result<InterceptSessionInfo, String> {
    Err("Windows NamedPipe 仅适用于 Windows 平台；当前 POSIX 平台请直接使用内置 POSIX PTY 伪终端直通".into())
}

// ============================================================================
// 7. 模式 C: Linux / macOS / 国产信创系统原生 POSIX PTY 伪终端透明代理
// ============================================================================

#[cfg(unix)]
pub fn start_unix_pty_intercept(
    app: Option<tauri::AppHandle>,
    symlink_alias: Option<&str>,
    target_port: &str,
    config: SerialCommunicationConfig,
) -> Result<InterceptSessionInfo, String> {
    use std::ffi::{CStr, CString};
    use std::os::unix::io::{AsRawFd, FromRawFd};

    let clean_target = target_port.trim().to_string();
    if clean_target.is_empty() {
        return Err("目标串口路径不能为空".into());
    }

    let is_loopback_target = clean_target == "LOOPBACK_ECHO";
    let physical_port_opt = if is_loopback_target {
        None
    } else {
        let port = serialport::new(&clean_target, config.baud_rate)
            .data_bits(parse_data_bits(config.data_bits))
            .parity(parse_parity(&config.parity))
            .stop_bits(parse_stop_bits(config.stop_bits))
            .flow_control(parse_flow_control(&config.flow_control))
            .timeout(Duration::from_millis(12))
            .open()
            .map_err(|e| format!("打开底层物理串口 {} 失败: {}", clean_target, e))?;
        Some(port)
    };

    // SAFETY: 标准 POSIX.1-2001 伪终端分配流程
    let master_fd = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_NONBLOCK) };
    if master_fd < 0 {
        return Err("调用 posix_openpt 分配内核伪终端主端失败".into());
    }
    if unsafe { libc::grantpt(master_fd) } != 0 || unsafe { libc::unlockpt(master_fd) } != 0 {
        unsafe { libc::close(master_fd) };
        return Err("grantpt/unlockpt 授权内核伪终端从设备失败".into());
    }

    // 读取真实 /dev/pts/N 或 /dev/ttysNNN 路径名（同时兼容 x86_64/ARM64 Linux 与 macOS/BSD）
    #[cfg(target_os = "linux")]
    let slave_path = {
        let mut name_buf = vec![0 as libc::c_char; 256];
        unsafe {
            if libc::ptsname_r(master_fd, name_buf.as_mut_ptr(), name_buf.len()) != 0 {
                libc::close(master_fd);
                return Err("ptsname_r 获取伪终端设备路径失败".into());
            }
            CStr::from_ptr(name_buf.as_ptr()).to_string_lossy().into_owned()
        }
    };

    #[cfg(all(unix, not(target_os = "linux")))]
    let slave_path = {
        // macOS / BSD libc 未提供 ptsname_r，使用静态互斥锁串行护航标准 ptsname() 调用并立刻转存 String
        static PTSNAME_LOCK: Mutex<()> = Mutex::new(());
        let _guard = PTSNAME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let ptr = libc::ptsname(master_fd);
            if ptr.is_null() {
                libc::close(master_fd);
                return Err("ptsname 获取 POSIX 伪终端从设备路径失败".into());
            }
            CStr::from_ptr(ptr).to_string_lossy().into_owned()
        }
    };

    // 配置从设备/主设备为绝对 Raw 二进制模式 (避免换行符替换与回显破坏工业 CRC)
    unsafe {
        let mut tio: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(master_fd, &mut tio) == 0 {
            libc::cfmakeraw(&mut tio);
            libc::tcsetattr(master_fd, libc::TCSANOW, &tio);
        }
    }

    let mut exposed_path = slave_path.clone();
    let mut created_symlink: Option<String> = None;
    if let Some(alias) = symlink_alias {
        let trimmed = alias.trim();
        if !trimmed.is_empty() {
            let _ = std::fs::remove_file(trimmed);
            if std::os::unix::fs::symlink(&slave_path, trimmed).is_ok() {
                exposed_path = trimmed.to_string();
                created_symlink = Some(trimmed.to_string());
            }
        }
    }

    let session_id = format!("PTY-{}", slave_path.replace('/', "_"));
    let handle = Arc::new(InterceptSessionHandle {
        info: Mutex::new(InterceptSessionInfo {
            session_id: session_id.clone(),
            mode: InterceptSessionMode::UnixPosixPty,
            virtual_endpoint: exposed_path.clone(),
            target_port: clean_target.clone(),
            baud_rate: config.baud_rate,
            uptime_secs: 0,
            bytes_upstream_to_target: 0,
            bytes_target_to_upstream: 0,
            packets_captured: 0,
            ioctl_control_events: 0,
            is_running: true,
            status_detail: format!("POSIX 内核 PTY {} ({}) 已透传绑至 {}", exposed_path, slave_path, clean_target),
        }),
        start_time: Instant::now(),
        is_running: Arc::new(AtomicBool::new(true)),
        bytes_up: Arc::new(AtomicU64::new(0)),
        bytes_down: Arc::new(AtomicU64::new(0)),
        packets_captured: Arc::new(AtomicU64::new(0)),
        ioctl_events: Arc::new(AtomicU64::new(0)),
    });

    {
        let mut map = crate::lock_guard::lock_mutex(&ACTIVE_INTERCEPT_SESSIONS, "serial_intercept::pty_insert");
        map.insert(session_id.clone(), handle.clone());
    }

    let snapshot = crate::lock_guard::lock_mutex(&handle.info, "serial_intercept::pty_snap").clone();
    let idle_gap = calculate_3_5t_duration(config.baud_rate, config.data_bits, &config.parity, config.stop_bits);

    std::thread::spawn(move || {
        let mut master_file = unsafe { std::fs::File::from_raw_fd(master_fd) };
        let mut phys_opt = physical_port_opt;
        let mut batcher_up = StreamFrameBatcher::new(idle_gap);
        let mut batcher_down = StreamFrameBatcher::new(idle_gap);
        let mut buf_pty = [0u8; 2048];
        let mut buf_ser = [0u8; 2048];

        while handle.is_running.load(Ordering::Acquire) {
            let mut pfd = libc::pollfd {
                fd: master_file.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let ready = unsafe { libc::poll(&mut pfd, 1, 8) };
            if ready > 0 && (pfd.revents & libc::POLLIN) != 0 {
                match master_file.read(&mut buf_pty) {
                    Ok(n) if n > 0 => {
                        let chunk = &buf_pty[..n];
                        handle.bytes_up.fetch_add(n as u64, Ordering::Relaxed);
                        batcher_up.push(chunk);
                        if is_loopback_target {
                            let _ = master_file.write_all(chunk);
                            let _ = master_file.flush();
                            handle.bytes_down.fetch_add(n as u64, Ordering::Relaxed);
                            batcher_down.push(chunk);
                        } else if let Some(p) = phys_opt.as_mut() {
                            let _ = p.write_all(chunk);
                            let _ = p.flush();
                        }
                    }
                    _ => {}
                }
            }

            if let Some(p) = phys_opt.as_mut() {
                if let Ok(n) = p.read(&mut buf_ser) {
                    if n > 0 {
                        let chunk = &buf_ser[..n];
                        let _ = master_file.write_all(chunk);
                        let _ = master_file.flush();
                        handle.bytes_down.fetch_add(n as u64, Ordering::Relaxed);
                        batcher_down.push(chunk);
                    }
                }
            }

            if let Some(frame) = batcher_up.take_if_ready(false) {
                handle.packets_captured.fetch_add(1, Ordering::Relaxed);
                if let Some(ref a) = app {
                    emit_intercept_frame(a, &exposed_path, &clean_target, &frame, "INTERCEPT_TX_UP_TO_DEV", "POSIX_PTY");
                }
            }
            if let Some(frame) = batcher_down.take_if_ready(false) {
                handle.packets_captured.fetch_add(1, Ordering::Relaxed);
                if let Some(ref a) = app {
                    emit_intercept_frame(a, &clean_target, &exposed_path, &frame, "INTERCEPT_RX_DEV_TO_UP", "POSIX_PTY");
                }
            }
        }

        if let Some(sym) = created_symlink {
            let _ = std::fs::remove_file(sym);
        }
        let mut map = crate::lock_guard::lock_mutex(&ACTIVE_INTERCEPT_SESSIONS, "serial_intercept::pty_cleanup");
        map.remove(&session_id);
        drop(CString::new("").ok());
    });

    Ok(snapshot)
}

#[cfg(not(unix))]
pub fn start_unix_pty_intercept(
    _app: Option<tauri::AppHandle>,
    _symlink_alias: Option<&str>,
    _target_port: &str,
    _config: SerialCommunicationConfig,
) -> Result<InterceptSessionInfo, String> {
    Err("POSIX PTY 伪终端仅适用于 Linux / macOS / 统信 / 麒麟等类 Unix 内核；Windows 请使用 NamedPipe、RFC2217 或双端透明桥梁".into())
}

// ============================================================================
// 8. 模式 D: Windows 内核 WDM 过滤驱动实时事件汲取线程
// ============================================================================

#[cfg(windows)]
pub fn start_kernel_filter_tap(app: Option<tauri::AppHandle>) -> Result<InterceptSessionInfo, String> {
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, GENERIC_READ, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING};
    use windows_sys::Win32::System::IO::DeviceIoControl;

    let status = probe_kernel_serial_filter_driver();
    if !status.driver_loaded {
        return Err(status.detail_message);
    }

    let dev_wide = to_wide_null(r"\\.\OmniSerialFilter");
    let dev_handle = unsafe {
        CreateFileW(
            dev_wide.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if dev_handle == INVALID_HANDLE_VALUE {
        return Err(format!("打开 \\\\.\\OmniSerialFilter 失败 (错误码: {})", unsafe { GetLastError() }));
    }

    let session_id = "WDM-KERNEL-FILTER".to_string();
    let handle = Arc::new(InterceptSessionHandle {
        info: Mutex::new(InterceptSessionInfo {
            session_id: session_id.clone(),
            mode: InterceptSessionMode::WindowsKernelIrpTap,
            virtual_endpoint: r"\\.\OmniSerialFilter".to_string(),
            target_port: format!("All Attached Ports ({})", status.active_filter_devices),
            baud_rate: 0,
            uptime_secs: 0,
            bytes_upstream_to_target: 0,
            bytes_target_to_upstream: 0,
            packets_captured: 0,
            ioctl_control_events: 0,
            is_running: true,
            status_detail: status.detail_message,
        }),
        start_time: Instant::now(),
        is_running: Arc::new(AtomicBool::new(true)),
        bytes_up: Arc::new(AtomicU64::new(0)),
        bytes_down: Arc::new(AtomicU64::new(0)),
        packets_captured: Arc::new(AtomicU64::new(0)),
        ioctl_events: Arc::new(AtomicU64::new(0)),
    });

    {
        let mut map = crate::lock_guard::lock_mutex(&ACTIVE_INTERCEPT_SESSIONS, "serial_intercept::wdm_insert");
        if map.contains_key(&session_id) {
            unsafe { CloseHandle(dev_handle) };
            return Err("Windows WDM 内核过滤监听会话已在运行".into());
        }
        map.insert(session_id.clone(), handle.clone());
    }

    let snapshot = crate::lock_guard::lock_mutex(&handle.info, "serial_intercept::wdm_snap").clone();
    let raw_handle = dev_handle as isize;

    std::thread::spawn(move || {
        let h_dev = raw_handle as windows_sys::Win32::Foundation::HANDLE;
        let mut batch = vec![OmniKernelSerialEvent::default(); 64];

        while handle.is_running.load(Ordering::Acquire) {
            let mut returned: u32 = 0;
            let ok = unsafe {
                DeviceIoControl(
                    h_dev,
                    IOCTL_OMNI_SERIAL_POLL_EVENTS,
                    std::ptr::null(),
                    0,
                    batch.as_mut_ptr().cast(),
                    (batch.len() * std::mem::size_of::<OmniKernelSerialEvent>()) as u32,
                    &mut returned,
                    std::ptr::null_mut(),
                )
            };

            if ok != 0 && returned > 0 {
                let evt_count = (returned as usize) / std::mem::size_of::<OmniKernelSerialEvent>();
                for evt in &batch[..evt_count] {
                    let evt_type = evt.event_type;
                    let dev_hash = evt.device_id_hash;
                    let plen = (evt.payload_length as usize).min(OMNI_MAX_PAYLOAD_CAPTURE);
                    let dev_label = format!("WDM_DEV_{:08X}", dev_hash);

                    match evt_type {
                        OMNI_EVT_WRITE if plen > 0 => {
                            handle.bytes_up.fetch_add(plen as u64, Ordering::Relaxed);
                            handle.packets_captured.fetch_add(1, Ordering::Relaxed);
                            if let Some(ref a) = app {
                                emit_intercept_frame(a, "KERNEL_IRP_APP", &dev_label, &evt.payload[..plen], "WDM_IRP_WRITE", "WDM_UPPER_FILTER");
                            }
                        }
                        OMNI_EVT_READ if plen > 0 => {
                            handle.bytes_down.fetch_add(plen as u64, Ordering::Relaxed);
                            handle.packets_captured.fetch_add(1, Ordering::Relaxed);
                            if let Some(ref a) = app {
                                emit_intercept_frame(a, &dev_label, "KERNEL_IRP_APP", &evt.payload[..plen], "WDM_IRP_READ", "WDM_UPPER_FILTER");
                            }
                        }
                        OMNI_EVT_IOCTL_BAUD | OMNI_EVT_IOCTL_LCR | OMNI_EVT_IOCTL_MODEM => {
                            handle.ioctl_events.fetch_add(1, Ordering::Relaxed);
                        }
                        _ => {}
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }

        unsafe { CloseHandle(h_dev) };
        let mut map = crate::lock_guard::lock_mutex(&ACTIVE_INTERCEPT_SESSIONS, "serial_intercept::wdm_cleanup");
        map.remove(&session_id);
    });

    Ok(snapshot)
}

#[cfg(not(windows))]
pub fn start_kernel_filter_tap(_app: Option<tauri::AppHandle>) -> Result<InterceptSessionInfo, String> {
    Err("Windows WDM 内核过滤监听仅用于 Windows 平台".into())
}

// ============================================================================
// 8B. 智能串口拦截自决策与第三方占用诊断器
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartInterceptOutcome {
    pub started: bool,
    pub recommended_strategy: String,
    pub diagnosis_reason: String,
    pub session: Option<InterceptSessionInfo>,
}

/// 根据当前操作系统、WDM 驱动安装实况、端口是否已被第三方独占占用，自动选择最佳透明拦截路径并执行
pub fn smart_start_serial_intercept(
    app: Option<tauri::AppHandle>,
    target_port: &str,
    prefer_mode: Option<&str>,
    config: SerialCommunicationConfig,
) -> SmartInterceptOutcome {
    let clean_target = target_port.trim();
    if clean_target.is_empty() {
        return SmartInterceptOutcome {
            started: false,
            recommended_strategy: "INVALID_TARGET".into(),
            diagnosis_reason: "目标串口标识不能为空；可选择物理 COM 口或 LOOPBACK_ECHO 回环通道".into(),
            session: None,
        };
    }

    // 1. 优先判定是否具备 Windows WDM 内核上层过滤驱动（唯一支持零重启抓取已被外部独占打开 COM 的原生内核路径）
    let kernel_status = probe_kernel_serial_filter_driver();
    if kernel_status.driver_loaded && prefer_mode != Some("virtual_only") {
        match start_kernel_filter_tap(app.clone()) {
            Ok(info) => {
                return SmartInterceptOutcome {
                    started: true,
                    recommended_strategy: "WDM_KERNEL_IRP_FILTER".into(),
                    diagnosis_reason: "检测到已签名安装的 \\\\.\\OmniSerialFilter 内核驱动，已自动启用 IRP 上层零侵入旁路截取".into(),
                    session: Some(info),
                };
            }
            Err(e) => {
                // 内核控制设备存在但打开受限（例如非管理员），继续向下排查用户态安全通路并记录客观原因
                if e.contains("ACL") || e.contains("拒绝") {
                    return SmartInterceptOutcome {
                        started: false,
                        recommended_strategy: "ELEVATION_REQUIRED_FOR_WDM".into(),
                        diagnosis_reason: e,
                        session: None,
                    };
                }
            }
        }
    }

    // 2. 回环压测目标直接按 OS 原生能力免冲突拉起
    if clean_target == "LOOPBACK_ECHO" {
        return start_platform_best_proxy(app, clean_target, prefer_mode, config);
    }

    // 3. 若串口正在被本应用自己监听，先提示关闭探针再转交桥梁/拦截以免冲突
    if crate::serial::is_any_serial_running(Some(clean_target)) {
        return SmartInterceptOutcome {
            started: false,
            recommended_strategy: "RELEASE_SELF_PROBE_FIRST".into(),
            diagnosis_reason: format!(
                "端口 {} 当前正在被 Omni-Probe 单口监听器直接占用，请先停止该端口监听后再开启双工透明拦截代理",
                clean_target
            ),
            session: None,
        };
    }

    // 4. 轻量无损探测该物理端口当前是否空闲还是被第三方软件独占锁定
    match serialport::new(clean_target, config.baud_rate)
        .timeout(Duration::from_millis(5))
        .open()
    {
        Ok(probe_handle) => {
            drop(probe_handle);
            // 释放句柄后毫秒级交由透明代理独占接管并暴露虚拟端点供第三方软件挂载
            std::thread::sleep(Duration::from_millis(10));
            start_platform_best_proxy(app, clean_target, prefer_mode, config)
        }
        Err(err) => {
            let msg_low = err.description.to_lowercase();
            let is_busy_or_denied = matches!(
                err.kind,
                serialport::ErrorKind::Io(std::io::ErrorKind::PermissionDenied)
            ) || msg_low.contains("access is denied")
                || msg_low.contains("拒绝访问")
                || msg_low.contains("busy")
                || msg_low.contains("in use");

            if is_busy_or_denied {
                let pairs = detect_virtual_serial_pairs();
                let pair_hint = if !pairs.is_empty() {
                    format!(
                        "（检测到本机已有虚拟串口对 {}，亦可在下方使用双串口全双工桥梁进行零占用转接）",
                        pairs[0].pair_name
                    )
                } else {
                    String::new()
                };
                SmartInterceptOutcome {
                    started: false,
                    recommended_strategy: "PORT_OCCUPIED_NEED_PRE_ATTACH_OR_WDM".into(),
                    diagnosis_reason: format!(
                        "端口 {} 已被第三方进程独占打开 ({})，且当前主机尚未加载 WDM 过滤驱动。最佳实践：请先断开第三方软件串口连接 -> 点击创建 Omni-Probe 虚拟端点 -> 让第三方软件改连本程序虚拟端口（或在 WDK 签名安装 omni_serial_flt.sys 实现热旁路）{}",
                        clean_target, err.description, pair_hint
                    ),
                    session: None,
                }
            } else {
                SmartInterceptOutcome {
                    started: false,
                    recommended_strategy: "PORT_NOT_AVAILABLE".into(),
                    diagnosis_reason: format!("物理串口 {} 无法访问或不存在: {}", clean_target, err.description),
                    session: None,
                }
            }
        }
    }
}

fn start_platform_best_proxy(
    app: Option<tauri::AppHandle>,
    target_port: &str,
    prefer_mode: Option<&str>,
    config: SerialCommunicationConfig,
) -> SmartInterceptOutcome {
    let safe_suffix: String = target_port
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();

    #[cfg(unix)]
    {
        if prefer_mode != Some("rfc2217") {
            let alias = format!("/tmp/omni_vcom_{}", safe_suffix.to_lowercase());
            match start_unix_pty_intercept(app.clone(), Some(&alias), target_port, config.clone()) {
                Ok(info) => {
                    return SmartInterceptOutcome {
                        started: true,
                        recommended_strategy: "POSIX_PTY_VIRTUAL_NODE".into(),
                        diagnosis_reason: format!("已在类 Unix 内核零外挂生成原生伪终端 {}，第三方程序可直接挂载交互", info.virtual_endpoint),
                        session: Some(info),
                    };
                }
                Err(_) => {}
            }
        }
    }

    #[cfg(windows)]
    {
        if prefer_mode == Some("pipe") {
            let suffix = format!("smart_{}", safe_suffix.to_lowercase());
            match start_windows_named_pipe_intercept(app, &suffix, target_port, config) {
                Ok(info) => {
                    return SmartInterceptOutcome {
                        started: true,
                        recommended_strategy: "WIN32_NAMED_PIPE_PROXY".into(),
                        diagnosis_reason: format!("已建立 Win32 命名管道虚拟串口 {}，可直接供 VMware/QEMU/管道客户端双向对接", info.virtual_endpoint),
                        session: Some(info),
                    };
                }
                Err(e) => {
                    return SmartInterceptOutcome {
                        started: false,
                        recommended_strategy: "PIPE_START_FAILED".into(),
                        diagnosis_reason: e,
                        session: None,
                    };
                }
            }
        }
    }

    // 默认高兼容回退/主路径: 全平台标准 RFC 2217 自动随机端口网关（无命名冲突，支持动态调参）
    match start_rfc2217_intercept_gateway(app, 0, target_port, config) {
        Ok(info) => SmartInterceptOutcome {
            started: true,
            recommended_strategy: "RFC2217_AUTO_PORT_GATEWAY".into(),
            diagnosis_reason: format!(
                "已智能分配本地 RFC 2217 透明串口网关 {} -> {}（全双工转发并透传波特率/DTR/RTS 控制命令）",
                info.virtual_endpoint, target_port
            ),
            session: Some(info),
        },
        Err(e) => SmartInterceptOutcome {
            started: false,
            recommended_strategy: "RFC2217_FAILED".into(),
            diagnosis_reason: e,
            session: None,
        },
    }
}

// ============================================================================
// 9. 工业级单元测试 (含 RFC2217 状态机、ABI 字节对齐与 Win32 Pipe 回环实测)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wdm_ioctl_and_struct_abi_layout() {
        // 确保 Rust FFI 与 omni_serial_flt.c 的 #pragma pack(1) 尺寸与 IOCTL 控制码位级吻合
        // 8 (Timestamp) + 4 (Hash) + 4 (Type) + 4 (PayloadLen) + 4 (Aux) + 256 (Payload) = 280 bytes
        assert_eq!(std::mem::size_of::<OmniKernelSerialEvent>(), 280);
        // 4 + 4 + 4 + 4 + 8 = 24 bytes
        assert_eq!(std::mem::size_of::<OmniSerialDriverInfo>(), 24);
        assert_eq!(IOCTL_OMNI_SERIAL_GET_VERSION, 0x8310_6000);
        assert_eq!(IOCTL_OMNI_SERIAL_POLL_EVENTS, 0x8310_6004);
        assert_eq!(IOCTL_OMNI_SERIAL_RESET_RING, 0x8310_A008);
    }

    #[test]
    fn test_rfc2217_stream_decoder_escaping_and_commands() {
        let mut dec = rfc2217::Rfc2217StreamDecoder::new();
        // 混合输入: Telnet DO COM_PORT + Modbus 帧(含0xFF需还原) + SET_BAUDRATE(115200) + SET_CONTROL(DTR ON=8)
        let mut wire = Vec::new();
        wire.extend_from_slice(&[rfc2217::IAC, rfc2217::DO, rfc2217::OPT_COM_PORT]);
        // Modbus 载荷 [0x01, 0x03, 0xFF(转义为FF FF), 0x05]
        wire.extend_from_slice(&[0x01, 0x03, 0xFF, 0xFF, 0x05]);
        // SET-BAUDRATE 115200 (0x0001C200)
        wire.extend_from_slice(&[
            rfc2217::IAC, rfc2217::SB, rfc2217::OPT_COM_PORT,
            rfc2217::C2S_SET_BAUDRATE, 0x00, 0x01, 0xC2, 0x00,
            rfc2217::IAC, rfc2217::SE,
        ]);
        // SET-CONTROL DTR ON (8)
        wire.extend_from_slice(&[
            rfc2217::IAC, rfc2217::SB, rfc2217::OPT_COM_PORT,
            rfc2217::C2S_SET_CONTROL, 8,
            rfc2217::IAC, rfc2217::SE,
        ]);

        let (payload, cmds) = dec.feed(&wire);
        assert_eq!(payload, vec![0x01, 0x03, 0xFF, 0x05]);
        assert_eq!(cmds.len(), 3);
        assert_eq!(
            cmds[0],
            rfc2217::Rfc2217Command::TelnetNegotiation {
                verb: rfc2217::DO,
                option: rfc2217::OPT_COM_PORT
            }
        );
        assert_eq!(cmds[1], rfc2217::Rfc2217Command::SetBaudRate(115200));
        assert_eq!(cmds[2], rfc2217::Rfc2217Command::SetControl(8));

        // 测试往返转义保护
        let raw = [0xAA, 0xFF, 0x55];
        let escaped = rfc2217::Rfc2217StreamDecoder::encode_serial_data_escaped(&raw);
        let (decoded, _) = dec.feed(&escaped);
        assert_eq!(decoded, raw);
    }

    #[test]
    fn test_rfc2217_live_loopback_gateway_e2e() {
        let cfg = SerialCommunicationConfig::default();
        // port 0 由 OS 分配随机可用本地端口，目标 LOOPBACK_ECHO 执行真实全双工回环
        let info = start_rfc2217_intercept_gateway(None, 0, "LOOPBACK_ECHO", cfg)
            .expect("RFC 2217 透明网关启动失败");
        let port: u16 = info
            .virtual_endpoint
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap();

        let mut cli = TcpStream::connect(("127.0.0.1", port)).expect("TCP 客户端应可连接 RFC2217 网关");
        cli.set_read_timeout(Some(Duration::from_secs(2))).unwrap();

        let mut init_buf = [0u8; 64];
        let n0 = cli.read(&mut init_buf).unwrap();
        assert!(n0 >= 9);

        // 下发 SET_BAUDRATE 57600 + 真实业务字节 [0x01, 0x04, 0xAA, 0xBB]
        let mut req = vec![
            rfc2217::IAC, rfc2217::SB, rfc2217::OPT_COM_PORT,
            rfc2217::C2S_SET_BAUDRATE, 0x00, 0x00, 0xE1, 0x00,
            rfc2217::IAC, rfc2217::SE,
        ];
        req.extend_from_slice(&[0x01, 0x04, 0xAA, 0xBB]);
        cli.write_all(&req).unwrap();
        cli.flush().unwrap();

        std::thread::sleep(Duration::from_millis(40));
        let mut rx_all = Vec::new();
        let mut tmp = [0u8; 128];
        while let Ok(k) = cli.read(&mut tmp) {
            if k == 0 {
                break;
            }
            rx_all.extend_from_slice(&tmp[..k]);
            if rx_all.windows(4).any(|w| w == [0x01, 0x04, 0xAA, 0xBB]) {
                break;
            }
        }
        assert!(
            rx_all.windows(4).any(|w| w == [0x01, 0x04, 0xAA, 0xBB]),
            "应通过全双工回环接收到原始业务数据"
        );

        let sessions = list_active_intercept_sessions();
        let mine = sessions.iter().find(|s| s.session_id == info.session_id).unwrap();
        assert_eq!(mine.baud_rate, 57600);
        assert!(mine.bytes_upstream_to_target >= 4);
        assert!(mine.ioctl_control_events >= 1);

        let _ = stop_intercept_session(Some(&info.session_id));
    }

    #[cfg(windows)]
    #[test]
    fn test_windows_named_pipe_live_loopback_e2e() {
        use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING, ReadFile, WriteFile};

        let suffix = format!("test_{}", std::process::id());
        let info = start_windows_named_pipe_intercept(
            None,
            &suffix,
            "LOOPBACK_ECHO",
            SerialCommunicationConfig::default(),
        )
        .expect("创建 NamedPipe 透明拦截会话失败");

        let pipe_w = to_wide_null(&info.virtual_endpoint);
        let cli = unsafe {
            CreateFileW(
                pipe_w.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(cli, INVALID_HANDLE_VALUE, "客户端应成功连接 Win32 NamedPipe");

        let payload = b"\x01\x03\x00\x00\x00\x02\xC4\x0B";
        let mut written: u32 = 0;
        let wok = unsafe {
            WriteFile(cli, payload.as_ptr(), payload.len() as u32, &mut written, std::ptr::null_mut())
        };
        assert_ne!(wok, 0);
        assert_eq!(written as usize, payload.len());

        let mut resp = [0u8; 32];
        let mut read_n: u32 = 0;
        let rok = unsafe {
            ReadFile(cli, resp.as_mut_ptr(), payload.len() as u32, &mut read_n, std::ptr::null_mut())
        };
        assert_ne!(rok, 0);
        assert_eq!(&resp[..read_n as usize], payload);

        unsafe { CloseHandle(cli) };
        std::thread::sleep(Duration::from_millis(30));
        let _ = stop_intercept_session(Some(&info.session_id));
    }

    #[test]
    fn test_capabilities_probe_never_panics() {
        let caps = get_serial_intercept_capabilities();
        assert!(!caps.os_family.is_empty());
        assert!(caps.rfc2217_gateway_supported);
    }

    #[test]
    fn test_smart_intercept_plan_diagnostic_and_auto_select() {
        let cfg = SerialCommunicationConfig::default();
        // 1. 回环模式自动启动有效通道 (Windows 自动分配 RFC2217 端口)
        let ok_res = smart_start_serial_intercept(None, "LOOPBACK_ECHO", None, cfg.clone());
        assert!(ok_res.started, "LOOPBACK_ECHO 应智能启动成功: {}", ok_res.diagnosis_reason);
        let sess = ok_res.session.expect("应返回有效会话");
        let _ = stop_intercept_session(Some(&sess.session_id));

        // 2. 不存在的虚构物理串口必须如实诊断，绝不虚假成功
        let bad_res = smart_start_serial_intercept(None, "NON_EXISTENT_COM999", None, cfg);
        assert!(!bad_res.started);
        assert_eq!(bad_res.recommended_strategy, "PORT_NOT_AVAILABLE");
        assert!(bad_res.session.is_none());
    }
}
