// ============================================================
// Omni-Probe: Windows 原生内置 NDIS ETW L2 数据链路层捕获引擎
// 模块名称: win_ndis_capture.rs
//
// 核心设计价值:
// 1. 无需额外安装第三方 Npcap / WinPcap 驱动，直接通过 Win32 原生 ETW API 订阅系统自带
//    `Microsoft-Windows-NDIS-PacketCapture` ({2ED6006E-4729-4609-B423-3EE7BCD678EF}) Provider；
// 2. 在具备管理员权限的 Windows 10/11 主机上即可真实截获双向进出的完整 L2 Ethernet II 帧
//    (包含目的/源 MAC、802.1Q VLAN、ARP、IPv4/IPv6、TCP/UDP 与工控应用层负载)；
// 3. 在非特权普通用户权限下，立即精准识别 ERROR_ACCESS_DENIED (5) 并在毫秒级无阻塞回退至
//    应用层双轨 + Raw Socket 监听通道；
// 4. 在 ETW ProcessTrace 回调内仅作最小切片校验与非阻塞 `try_send`，由独立消费线程解码，
//    彻底避免阻塞系统级 ETW 实时流缓冲。
// ============================================================

use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// NDIS ETW 原始分片数据解码输出
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedNdisEtwFragment {
    pub miniport_if_index: u32,
    pub lower_if_index: u32,
    pub fragment_size: u32,
    pub ethernet_frame: Vec<u8>,
}

/// 从 `Microsoft-Windows-NDIS-PacketCapture` Event 1001 (`PacketFragment`) 的 UserData 字节块提取真实 L2 帧
/// 微软 NDIS ETW Manifest 固定二进制布局:
/// - `[0..4]`   MiniportIfIndex (u32 LE)
/// - `[4..8]`   LowerIfIndex    (u32 LE)
/// - `[8..12]`  FragmentSize    (u32 LE)
/// - `[12..12+FragmentSize]`    原始以太网 II / 802.3 帧字节
/// 时间复杂度: O(L) (L 为单帧载荷拷贝长度)
pub fn decode_ndis_etw_packet_fragment(user_data: &[u8]) -> Option<DecodedNdisEtwFragment> {
    if user_data.len() < 12 {
        return None;
    }
    let miniport_if_index = u32::from_le_bytes([user_data[0], user_data[1], user_data[2], user_data[3]]);
    let lower_if_index = u32::from_le_bytes([user_data[4], user_data[5], user_data[6], user_data[7]]);
    let fragment_size = u32::from_le_bytes([user_data[8], user_data[9], user_data[10], user_data[11]]);

    let frag_len = fragment_size as usize;
    if frag_len < 14 || frag_len > 65536 {
        return None;
    }
    if user_data.len() < 12 + frag_len {
        return None;
    }

    Some(DecodedNdisEtwFragment {
        miniport_if_index,
        lower_if_index,
        fragment_size,
        ethernet_frame: user_data[12..12 + frag_len].to_vec(),
    })
}

/// 全局 NDIS-ETW 运行统计
pub static NDIS_ETW_ACTIVE: AtomicBool = AtomicBool::new(false);
pub static NDIS_ETW_CAPTURED_FRAMES: AtomicU64 = AtomicU64::new(0);
pub static NDIS_ETW_DROPPED_FRAMES: AtomicU64 = AtomicU64::new(0);

#[cfg(windows)]
mod win_etw_impl {
    use super::*;
    use std::ffi::c_void;
    use std::sync::mpsc;
    use tauri::Emitter;
    use windows_sys::core::GUID;
    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_SUCCESS, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::Etw::{
        CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW,
        CONTROLTRACE_HANDLE, ENABLE_TRACE_PARAMETERS, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_RECORD,
        EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
        EVENT_TRACE_REAL_TIME_MODE, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME,
        TRACE_LEVEL_VERBOSE, WNODE_FLAG_TRACED_GUID,
    };

    const SESSION_NAME: &str = "OmniProbe_NdisPacketCapture_Live";
    const NDIS_PACKET_CAPTURE_EVENT_FRAGMENT: u16 = 1001;

    // {2ED6006E-4729-4609-B423-3EE7BCD678EF}
    const GUID_NDIS_PACKET_CAPTURE: GUID = GUID {
        data1: 0x2ED6006E,
        data2: 0x4729,
        data3: 0x4609,
        data4: [0xB4, 0x23, 0x3E, 0xE7, 0xBC, 0xD6, 0x78, 0xEF],
    };

    // 捕获标准 Ethernet 802.3 与 Native 802.11 路径帧 (Keyword bits 0 | 16)
    const KEYWORD_NDIS_L2_FRAMES: u64 = 0x0000_0000_0001_0001;

    #[repr(C)]
    struct TracePropertiesWithName {
        props: EVENT_TRACE_PROPERTIES,
        session_name_buf: [u16; 128],
    }

    impl TracePropertiesWithName {
        fn new() -> Self {
            let props_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
            let total_size = std::mem::size_of::<Self>() as u32;
            // SAFETY: 纯 POD C 结构体零初始化
            let mut props: EVENT_TRACE_PROPERTIES = unsafe { std::mem::zeroed() };
            props.Wnode.BufferSize = total_size;
            props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            props.Wnode.ClientContext = 1; // QPC 高精度时钟
            props.BufferSize = 64; // KB per buffer
            props.MinimumBuffers = 8;
            props.MaximumBuffers = 32;
            props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            props.FlushTimer = 1;
            props.LoggerNameOffset = props_size as u32;
            Self {
                props,
                session_name_buf: [0u16; 128],
            }
        }
    }

    struct CallbackContext {
        tx: mpsc::SyncSender<Vec<u8>>,
        running: Arc<Mutex<bool>>,
    }

    unsafe extern "system" fn event_record_callback(record: *mut EVENT_RECORD) {
        if record.is_null() {
            return;
        }
        let rec = unsafe { &*record };
        if rec.EventHeader.EventDescriptor.Id != NDIS_PACKET_CAPTURE_EVENT_FRAGMENT {
            return;
        }
        if rec.UserData.is_null() || rec.UserDataLength < 12 {
            return;
        }
        let ctx_ptr = rec.UserContext as *const CallbackContext;
        if ctx_ptr.is_null() {
            return;
        }
        let ctx = unsafe { &*ctx_ptr };
        let user_bytes = unsafe {
            std::slice::from_raw_parts(rec.UserData as *const u8, rec.UserDataLength as usize)
        };
        if let Some(frag) = decode_ndis_etw_packet_fragment(user_bytes) {
            if ctx.tx.try_send(frag.ethernet_frame).is_err() {
                NDIS_ETW_DROPPED_FRAMES.fetch_add(1, Ordering::Relaxed);
            } else {
                NDIS_ETW_CAPTURED_FRAMES.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    unsafe extern "system" fn buffer_callback(logfile: *mut EVENT_TRACE_LOGFILEW) -> u32 {
        if logfile.is_null() {
            return 0;
        }
        let ctx_ptr = unsafe { (*logfile).Context } as *const CallbackContext;
        if ctx_ptr.is_null() {
            return 1;
        }
        let ctx = unsafe { &*ctx_ptr };
        let is_running = *crate::lock_guard::lock_mutex(&ctx.running, "win_ndis_capture::buffer_cb");
        if is_running { 1 } else { 0 }
    }

    fn stop_existing_session(session_utf16: &[u16]) {
        let mut stop_props = TracePropertiesWithName::new();
        unsafe {
            ControlTraceW(
                CONTROLTRACE_HANDLE { Value: 0 },
                session_utf16.as_ptr(),
                &mut stop_props.props as *mut EVENT_TRACE_PROPERTIES,
                EVENT_TRACE_CONTROL_STOP,
            );
        }
    }

    /// 尝试启动无 Npcap 的 Windows 原生 NDIS ETW L2 抓包管道
    /// - 成功时在后台启动实时消费线程并返回 Ok(())
    /// - 若非管理员权限拒绝访问或环境不支持时，秒级安全退出并返回明确的诊断原因 Err(msg)
    pub fn try_start_native_ndis_etw_pipeline(
        app: tauri::AppHandle,
        running: Arc<Mutex<bool>>,
    ) -> Result<(), String> {
        let mut session_utf16: Vec<u16> = SESSION_NAME.encode_utf16().collect();
        session_utf16.push(0);

        // 先停止任何上次遗留会话
        stop_existing_session(&session_utf16);

        let mut props_wrap = TracePropertiesWithName::new();
        let copy_len = session_utf16.len().min(props_wrap.session_name_buf.len());
        props_wrap.session_name_buf[..copy_len].copy_from_slice(&session_utf16[..copy_len]);

        let mut trace_handle = CONTROLTRACE_HANDLE { Value: 0 };
        let rc_start = unsafe {
            StartTraceW(
                &mut trace_handle,
                session_utf16.as_ptr(),
                &mut props_wrap.props as *mut EVENT_TRACE_PROPERTIES,
            )
        };

        if rc_start == ERROR_ACCESS_DENIED {
            return Err("系统拒绝对话建立 (ERROR_ACCESS_DENIED=5): Windows 内置 NDIS-PacketCapture 需要管理员权限；当前进程已自动交由双轨与普通监听承接。".to_string());
        }
        if rc_start != ERROR_SUCCESS && rc_start != ERROR_ALREADY_EXISTS {
            return Err(format!("StartTraceW 启动 NDIS-ETW 实时会话失败，Win32 错误码: {}", rc_start));
        }

        let mut enable_params: ENABLE_TRACE_PARAMETERS = unsafe { std::mem::zeroed() };
        enable_params.Version = 2; // ENABLE_TRACE_PARAMETERS_VERSION_2

        let rc_enable = unsafe {
            EnableTraceEx2(
                trace_handle,
                &GUID_NDIS_PACKET_CAPTURE,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                TRACE_LEVEL_VERBOSE as u8,
                KEYWORD_NDIS_L2_FRAMES,
                0,
                0,
                &enable_params,
            )
        };
        if rc_enable != ERROR_SUCCESS {
            stop_existing_session(&session_utf16);
            return Err(format!("EnableTraceEx2 绑定 NDIS-PacketCapture 失败，Win32 错误码: {}", rc_enable));
        }

        let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(4096);
        let ctx_box = Box::new(CallbackContext {
            tx,
            running: running.clone(),
        });
        let ctx_raw = Box::into_raw(ctx_box);

        let mut logfile: EVENT_TRACE_LOGFILEW = unsafe { std::mem::zeroed() };
        logfile.LoggerName = session_utf16.as_ptr() as *mut u16;
        logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(event_record_callback);
        logfile.BufferCallback = Some(buffer_callback);
        logfile.Context = ctx_raw as *mut c_void;

        let consumer_handle = unsafe { OpenTraceW(&mut logfile) };
        if consumer_handle.Value == INVALID_HANDLE_VALUE as u64 || consumer_handle.Value == 0 {
            let _ = unsafe { Box::from_raw(ctx_raw) };
            stop_existing_session(&session_utf16);
            return Err("OpenTraceW 打开 NDIS-ETW 实时日志流失败".to_string());
        }

        NDIS_ETW_ACTIVE.store(true, Ordering::SeqCst);
        NDIS_ETW_CAPTURED_FRAMES.store(0, Ordering::Relaxed);
        NDIS_ETW_DROPPED_FRAMES.store(0, Ordering::Relaxed);

        let _ = app.emit(
            "system-log",
            "[NATIVE-NDIS] ✅ Windows 内置 NDIS-PacketCapture (ETW) 免 Npcap L2 以太网抓包引擎已激活！".to_string(),
        );

        // 工作线程 1：解码消费以太网 II 帧，送入统一审计管线
        let app_worker = app.clone();
        let run_worker = running.clone();
        std::thread::spawn(move || {
            let mut last_hash = String::new();
            while *crate::lock_guard::lock_mutex(&run_worker, "win_ndis_capture::worker_loop") {
                match rx.recv_timeout(std::time::Duration::from_millis(120)) {
                    Ok(frame) => {
                        if let Some(rec) = crate::sniffer::parse_ethernet_frame(&frame, &mut last_hash) {
                            crate::sniffer::process_incoming_record(&app_worker, rec);
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        });

        // 工作线程 2：ETW 实时消费阻塞循环 + 监听关闭信号安全停止
        let run_monitor = running.clone();
        let sess_copy = session_utf16.clone();
        std::thread::spawn(move || {
            while *crate::lock_guard::lock_mutex(&run_monitor, "win_ndis_capture::stop_watch") {
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            stop_existing_session(&sess_copy);
        });

        let ctx_addr = ctx_raw as usize;

        std::thread::spawn(move || {
            let mut handles = [consumer_handle];
            unsafe {
                ProcessTrace(handles.as_mut_ptr(), 1, std::ptr::null(), std::ptr::null());
                CloseTrace(consumer_handle);
            }
            stop_existing_session(&session_utf16);
            let _ = unsafe { Box::from_raw(ctx_addr as *mut CallbackContext) };
            NDIS_ETW_ACTIVE.store(false, Ordering::SeqCst);
        });

        Ok(())
    }
}

/// 统一公开入口：尝试在 Windows 平台免 Npcap 启动 NDIS ETW L2 捕获引擎
pub fn start_native_ndis_capture(app: tauri::AppHandle, running: Arc<Mutex<bool>>) -> Result<(), String> {
    #[cfg(windows)]
    {
        win_etw_impl::try_start_native_ndis_etw_pipeline(app, running)
    }
    #[cfg(not(windows))]
    {
        let _ = (app, running);
        Err("Windows NDIS-ETW 引擎仅适用于 Windows 平台".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::packet::arp::MutableArpPacket;
    use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};

    #[test]
    fn test_decode_ndis_etw_packet_fragment_and_l2_handoff() {
        // 1. 构造标准 42 字节 ARP 请求以太网帧
        let mut eth_frame = vec![0u8; 14 + 28];
        {
            let mut eth = MutableEthernetPacket::new(&mut eth_frame).unwrap();
            eth.set_destination(pnet::util::MacAddr::broadcast());
            eth.set_source(pnet::util::MacAddr::new(0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33));
            eth.set_ethertype(EtherTypes::Arp);
        }
        {
            let mut arp = MutableArpPacket::new(&mut eth_frame[14..]).unwrap();
            arp.set_hardware_type(pnet::packet::arp::ArpHardwareTypes::Ethernet);
            arp.set_protocol_type(EtherTypes::Ipv4);
            arp.set_hw_addr_len(6);
            arp.set_proto_addr_len(4);
            arp.set_operation(pnet::packet::arp::ArpOperations::Request);
            arp.set_sender_proto_addr(std::net::Ipv4Addr::new(192, 168, 50, 10));
            arp.set_target_proto_addr(std::net::Ipv4Addr::new(192, 168, 50, 1));
        }

        // 2. 封入微软 NDIS ETW Event 1001 二进制负载头
        let mut etw_payload = Vec::new();
        etw_payload.extend_from_slice(&12u32.to_le_bytes()); // MiniportIfIndex = 12
        etw_payload.extend_from_slice(&12u32.to_le_bytes()); // LowerIfIndex = 12
        etw_payload.extend_from_slice(&(eth_frame.len() as u32).to_le_bytes());
        etw_payload.extend_from_slice(&eth_frame);

        let decoded = decode_ndis_etw_packet_fragment(&etw_payload).expect("ETW L2 载荷提取失败");
        assert_eq!(decoded.miniport_if_index, 12);
        assert_eq!(decoded.fragment_size as usize, eth_frame.len());
        assert_eq!(decoded.ethernet_frame, eth_frame);

        // 3. 验证与 sniffer::parse_ethernet_frame 无缝解析成完整 PacketRecord
        let mut last_hash = "GENESIS".to_string();
        let rec = crate::sniffer::parse_ethernet_frame(&decoded.ethernet_frame, &mut last_hash)
            .expect("原生 NDIS 帧应被正常解构");
        assert_eq!(rec.protocol, "ARP");
        assert!(rec.raw_text.unwrap().contains("192.168.50.10"));

        // 4. 极限异常防御：过短头部、虚假超大帧长度、截断负载全部安全拒绝
        assert!(decode_ndis_etw_packet_fragment(&[0u8; 8]).is_none());
        let mut oversized = vec![0u8; 28];
        oversized[8..12].copy_from_slice(&99999u32.to_le_bytes());
        assert!(decode_ndis_etw_packet_fragment(&oversized).is_none());
    }
}
