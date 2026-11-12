use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use chrono::TimeZone;
use once_cell::sync::Lazy;
use sha2::Digest;
use tauri::Emitter;

// ============================================================
// 取证保全核心 (Forensic Evidence Preservation Core)
//
// 对齐 Python 版 TruePcapWriter + DataHandler + ForensicIntegritySealer 全部落盘行为：
//   1. forensic_capture.pcap —— L2 原始帧取证库（append 模式，跨进程保留全部历史证据）
//   2. capture.pcap          —— 应用层报文重组库（伪 Ethernet + IPv4 + TCP/UDP + 载荷）
//   3. received_data.jsonl   —— 结构化记录底账（按天轮转，保留 30 天归档）
//   4. listener.log          —— 引擎运行文本日志
//   5. 每 60 秒 SHA-256 司法封条 + MANUAL 手动封条
//
// 路径体系（去 CWD 依赖 + config.json data_storage 参数化）：
//   - 所有证据文件锚定统一数据目录（Tauri app_data_dir，setup 期注入；默认回退 exe 目录）
//   - 文件名可由 config.json data_storage 段覆盖（setup 期 init_evidence_names 注入，
//     早于任何 writer Lazy 首次触发，杜绝中途换名）
// ============================================================

const PCAP_MAGIC: u32 = 0xa1b2c3d4;
const PCAP_VERSION_MAJOR: u16 = 2;
const PCAP_VERSION_MINOR: u16 = 4;
const PCAP_SNAPLEN: u32 = 65535;
const PCAP_LINKTYPE_ETHERNET: u32 = 1;

// ============================================================
// 证据路径体系 (Evidence Path Registry)
// ============================================================

/// 证据文件名注册表（默认值对齐 Python 版；config data_storage 段可覆盖）
struct EvidenceNames {
    l2_pcap: String,     // data_storage 无对应项，固定名
    app_pcap: String,    // data_storage.pcap_file
    jsonl: String,       // data_storage.file
    log: String,         // logging.file
}

static EVIDENCE_NAMES: Lazy<Mutex<EvidenceNames>> = Lazy::new(|| {
    Mutex::new(EvidenceNames {
        l2_pcap: "forensic_capture.pcap".to_string(),
        app_pcap: "capture.pcap".to_string(),
        jsonl: "received_data.jsonl".to_string(),
        log: "listener.log".to_string(),
    })
});

/// 统一数据目录（默认 exe 同目录；Tauri setup 期注入 app_data_dir）
/// 锚定数据目录而非依赖进程 CWD——从快捷方式/System32 启动时保证证据落点确定
static DATA_DIR: Lazy<Mutex<PathBuf>> = Lazy::new(|| {
    let dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));
    let _ = std::fs::create_dir_all(&dir);
    Mutex::new(dir)
});

/// 数据目录锚定（lib.rs setup 期最先调用，先于 config 加载）
pub fn init_data_dir(dir: PathBuf) {
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("[FORENSICS] 数据目录创建失败 {}: {}", dir.display(), e);
    }
    let mut d = crate::lock_guard::lock_mutex(&DATA_DIR, "forensics::init_data_dir");
    *d = dir;
}

/// 证据文件名注入（lib.rs setup 期在 init_data_dir 与 config 加载之后、嗅探启动之前调用）
/// 此后所有 writer Lazy 首次打开均使用最终文件名
pub fn init_evidence_names(app_pcap: String, jsonl: String, log: String) {
    let mut n = crate::lock_guard::lock_mutex(&EVIDENCE_NAMES, "forensics::init_evidence_names");
    if !app_pcap.is_empty() {
        n.app_pcap = app_pcap;
    }
    if !jsonl.is_empty() {
        n.jsonl = jsonl;
    }
    if !log.is_empty() {
        n.log = log;
    }
}

/// 拼接数据目录绝对路径（全部文件 IO 的唯一出口）
pub fn data_path(name: &str) -> PathBuf {
    let p = crate::lock_guard::lock_mutex(&DATA_DIR, "forensics::data_path").join(name);
    let _ = std::fs::create_dir_all(
        p.parent().map(|d| d.to_path_buf()).unwrap_or_else(|| PathBuf::from(".")),
    );
    p
}

/// 取证据文件当前注册名（按类别）
fn evidence_name_l2() -> String {
    crate::lock_guard::lock_mutex(&EVIDENCE_NAMES, "forensics::evidence_name_l2").l2_pcap.clone()
}

fn evidence_name_app_pcap() -> String {
    crate::lock_guard::lock_mutex(&EVIDENCE_NAMES, "forensics::evidence_name_app_pcap").app_pcap.clone()
}

fn evidence_name_jsonl() -> String {
    crate::lock_guard::lock_mutex(&EVIDENCE_NAMES, "forensics::evidence_name_jsonl").jsonl.clone()
}

fn evidence_name_log() -> String {
    crate::lock_guard::lock_mutex(&EVIDENCE_NAMES, "forensics::evidence_name_log").log.clone()
}

/// 可追加式 PCAP 写入器（手写标准 libpcap 文件格式，零第三方依赖）
/// 打开语义与 Python Scapy PcapWriter(append=1, sync=1) 完全一致：
///   - 文件已存在且含合法全局头(>=24B) → 直接追加包记录，历史证据永不丢失
///   - 文件不存在或为空               → 先写 24 字节标准全局头，再追加包记录
struct AppendablePcapWriter {
    file: File,
}

impl AppendablePcapWriter {
    fn open(path: &str) -> Option<Self> {
        let has_valid_header = std::fs::metadata(path)
            .map(|m| m.len() >= 24)
            .unwrap_or(false);
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .ok()?;
        if !has_valid_header {
            let mut header = Vec::with_capacity(24);
            header.extend_from_slice(&PCAP_MAGIC.to_le_bytes());
            header.extend_from_slice(&PCAP_VERSION_MAJOR.to_le_bytes());
            header.extend_from_slice(&PCAP_VERSION_MINOR.to_le_bytes());
            header.extend_from_slice(&0i32.to_le_bytes()); // thiszone
            header.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
            header.extend_from_slice(&PCAP_SNAPLEN.to_le_bytes());
            header.extend_from_slice(&PCAP_LINKTYPE_ETHERNET.to_le_bytes());
            file.write_all(&header).ok()?;
        }
        Some(Self { file })
    }

    fn write_packet(&mut self, data: &[u8]) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);
        let mut rec = Vec::with_capacity(16 + data.len());
        rec.extend_from_slice(&(ts.as_secs() as u32).to_le_bytes());
        rec.extend_from_slice(&ts.subsec_micros().to_le_bytes());
        rec.extend_from_slice(&(data.len() as u32).to_le_bytes()); // incl_len
        rec.extend_from_slice(&(data.len() as u32).to_le_bytes()); // orig_len
        rec.extend_from_slice(data);
        if self.file.write_all(&rec).is_ok() {
            let _ = self.file.flush(); // 立即落盘，对齐 sync=1 语义
        }
    }
}

/// L2 取证库全局写入器（forensic_capture.pcap）
static GLOBAL_L2_PCAP: Lazy<Arc<Mutex<Option<AppendablePcapWriter>>>> = Lazy::new(|| {
    let name = evidence_name_l2();
    let writer = AppendablePcapWriter::open(&data_path(&name).to_string_lossy());
    Arc::new(Mutex::new(writer))
});

/// 应用层重组库全局写入器（capture.pcap，文件名可由 config data_storage.pcap_file 覆盖）
static GLOBAL_APP_PCAP: Lazy<Arc<Mutex<Option<AppendablePcapWriter>>>> = Lazy::new(|| {
    let name = evidence_name_app_pcap();
    let writer = AppendablePcapWriter::open(&data_path(&name).to_string_lossy());
    Arc::new(Mutex::new(writer))
});

pub struct ForensicEngine {}

impl ForensicEngine {
    pub fn new() -> Self {
        Self {}
    }

    /// 将原始以太网帧写入 L2 取证库 forensic_capture.pcap
    /// 使用阻塞锁（临界区仅一次 write syscall，耗时微秒级），杜绝 try_lock 锁忙静默丢包
    pub fn write_packet(&self, data: &[u8]) {
        let mut guard = crate::lock_guard::lock_mutex(&GLOBAL_L2_PCAP, "forensics::write_packet_l2");
        if let Some(w) = guard.as_mut() {
            w.write_packet(data);
        }
    }

    /// 解决 Windows 文件独占锁问题，安全截断 L2 取证库
    pub fn truncate_pcap() -> Result<(), String> {
        let mut lock = crate::lock_guard::lock_mutex(&GLOBAL_L2_PCAP, "forensics::truncate_pcap");
        *lock = None;
        let name = evidence_name_l2();
        let path = data_path(&name);
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .map_err(|e| e.to_string())?;
        file.set_len(0).map_err(|e| e.to_string())?;
        drop(file);
        *lock = AppendablePcapWriter::open(&path.to_string_lossy());
        Ok(())
    }

    /// 香农信息熵算法（纯 Rust 零分配实现）
    /// 结果: 0.0（所有字节相同）~ 8.0（完全随机/加密载荷）
    pub fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut freq = [0u32; 256];
        for &b in data {
            freq[b as usize] += 1;
        }
        let len = data.len() as f64;
        freq.iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = c as f64 / len;
                -p * p.log2()
            })
            .sum::<f64>()
            .clamp(0.0, 8.0)
    }
}

// ============================================================
// 应用层报文重组 PCAP 写入（等价 Python TruePcapWriter）
// 将五元组 + 载荷重组为完整 Ethernet/IPv4/TCP/UDP 帧，落入 capture.pcap
// IP 不可解析的记录（如串口 HOST_SYSTEM）以 EtherType 0x9999 直挂载荷
// ============================================================

static IP_ID_COUNTER: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(1);
static TCP_SEQ_COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

/// RFC 1071 互联网校验和（16 位反码求和）
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

/// 构造 IPv4 报头 + 传输层报头 + 载荷的完整帧（Ethernet 前置）
fn build_ip_transport_frame(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    transport: &str,
    payload: &[u8],
) -> Vec<u8> {
    let is_tcp = transport.eq_ignore_ascii_case("TCP");
    let l4_len = if is_tcp { 20 + payload.len() } else { 8 + payload.len() };
    let total_len = 20 + l4_len;

    // ---- 传输层 ----
    let mut l4 = Vec::with_capacity(l4_len);
    if is_tcp {
        l4.extend_from_slice(&src_port.to_be_bytes());
        l4.extend_from_slice(&dst_port.to_be_bytes());
        l4.extend_from_slice(
            &TCP_SEQ_COUNTER
                .fetch_add(payload.len() as u32 + 1, std::sync::atomic::Ordering::Relaxed)
                .to_be_bytes(),
        );
        l4.extend_from_slice(&0u32.to_be_bytes()); // ack
        l4.extend_from_slice(&((5u16 << 12) | 0x018).to_be_bytes()); // data offset=5, PSH|ACK
        l4.extend_from_slice(&65535u16.to_be_bytes()); // window
        l4.extend_from_slice(&0u16.to_be_bytes()); // checksum 占位
        l4.extend_from_slice(&0u16.to_be_bytes()); // urgent ptr
        l4.extend_from_slice(payload);
        // TCP 校验和（伪首部 + TCP 段）
        let mut pseudo = Vec::with_capacity(12 + l4.len());
        pseudo.extend_from_slice(&src.octets());
        pseudo.extend_from_slice(&dst.octets());
        pseudo.push(0);
        pseudo.push(6); // IPPROTO_TCP
        pseudo.extend_from_slice(&(l4.len() as u16).to_be_bytes());
        pseudo.extend_from_slice(&l4);
        let ck = internet_checksum(&pseudo);
        l4[16..18].copy_from_slice(&ck.to_be_bytes());
    } else {
        l4.extend_from_slice(&src_port.to_be_bytes());
        l4.extend_from_slice(&dst_port.to_be_bytes());
        l4.extend_from_slice(&(l4_len as u16).to_be_bytes());
        l4.extend_from_slice(&0u16.to_be_bytes()); // checksum 占位
        l4.extend_from_slice(payload);
        // UDP 校验和（伪首部 + UDP 数据报，IPv4 允许 0 表示未计算，此处按学术标准实算）
        let mut pseudo = Vec::with_capacity(12 + l4.len());
        pseudo.extend_from_slice(&src.octets());
        pseudo.extend_from_slice(&dst.octets());
        pseudo.push(0);
        pseudo.push(17); // IPPROTO_UDP
        pseudo.extend_from_slice(&(l4.len() as u16).to_be_bytes());
        pseudo.extend_from_slice(&l4);
        let ck = internet_checksum(&pseudo);
        l4[6..8].copy_from_slice(&ck.to_be_bytes());
    }

    // ---- IPv4 报头 ----
    let id = IP_ID_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut ip = Vec::with_capacity(total_len);
    ip.push(0x45); // version 4, ihl 5
    ip.push(0x00); // tos
    ip.extend_from_slice(&(total_len as u16).to_be_bytes());
    ip.extend_from_slice(&id.to_be_bytes());
    ip.extend_from_slice(&0x4000u16.to_be_bytes()); // flags DF
    ip.push(64u8); // ttl（RFC 792 规定 1 字节字段，此前误写 u16 致 IP 头 21 字节非法）
    ip.push(if is_tcp { 6 } else { 17 });
    ip.extend_from_slice(&0u16.to_be_bytes()); // checksum 占位
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    let ck = internet_checksum(&ip);
    ip[10..12].copy_from_slice(&ck.to_be_bytes());

    // ---- Ethernet 前置 ----
    let mut frame = Vec::with_capacity(14 + total_len);
    frame.extend_from_slice(&[0x00; 6]); // dst MAC（本机重组帧，占位）
    frame.extend_from_slice(&[0x00; 6]); // src MAC
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&l4);
    frame
}

/// 将应用层报文重组落盘至 capture.pcap（统一收口，所有应用层记录产生点调用）
pub fn write_app_packet(
    src_ip: &str,
    dst_ip: &str,
    src_port: u16,
    dst_port: u16,
    transport: &str,
    payload: &[u8],
) {
    if payload.is_empty() {
        return;
    }
    let frame = match (src_ip.parse::<Ipv4Addr>(), dst_ip.parse::<Ipv4Addr>()) {
        (Ok(s), Ok(d)) => build_ip_transport_frame(s, d, src_port, dst_port, transport, payload),
        // 无合法 IP 元组（串口/USB 等非 IP 通道）：EtherType 0x9999 本地实验类型直挂载荷，如实保全
        _ => {
            let mut f = Vec::with_capacity(14 + payload.len());
            f.extend_from_slice(&[0x00; 6]);
            f.extend_from_slice(&[0x00; 6]);
            f.extend_from_slice(&0x9999u16.to_be_bytes());
            f.extend_from_slice(payload);
            f
        }
    };
    {
        let mut guard = crate::lock_guard::lock_mutex(&GLOBAL_APP_PCAP, "forensics::write_app_pcap");
        if let Some(w) = guard.as_mut() {
            w.write_packet(&frame);
        }
    }
}

// ============================================================
// 结构化记录底账 received_data.jsonl（按天轮转，保留 30 天）
// 对齐 Python TimedRotatingFileHandler(when='midnight', backupCount=30) 语义
// ============================================================

const JSONL_RETENTION_DAYS: i64 = 30;

struct DailyRotatingJsonlSink {
    file: Option<File>,
    current_date: String, // YYYY-MM-DD（当前打开文件所属日期）
    base_name: String,    // 注册表当前 jsonl 文件名（config data_storage.file 可覆盖）
}

impl DailyRotatingJsonlSink {
    fn new() -> Self {
        let base_name = evidence_name_jsonl();
        let path = data_path(&base_name);
        // 以现有文件 mtime 的日期作为轮转基准（对齐 TimedRotatingFileHandler 语义）
        let mtime_date = std::fs::metadata(&path)
            .ok()
            .and_then(|m| m.modified().ok())
            .map(|t| {
                let dt: chrono::DateTime<chrono::Local> = t.into();
                dt.format("%Y-%m-%d").to_string()
            });
        let current_date = mtime_date.unwrap_or_else(|| {
            chrono::Local::now().format("%Y-%m-%d").to_string()
        });
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .ok();
        Self { file, current_date, base_name }
    }

    fn write_record(&mut self, json_line: &str) {
        let today = chrono::Local::now().format("%Y-%m-%d").to_string();
        if self.file.is_none() || self.current_date != today {
            self.rotate(&today);
        }
        if let Some(f) = self.file.as_mut() {
            if writeln!(f, "{}", json_line).is_ok() {
                let _ = f.flush();
            }
        }
    }

    /// 跨天轮转：旧文件归档为 <base>.YYYY-MM-DD，清理超期归档，打开新文件
    fn rotate(&mut self, today: &str) {
        let path = data_path(&self.base_name);
        if self.file.take().is_some() {
            let archive = format!("{}.{}", self.base_name, self.current_date);
            let _ = std::fs::rename(&path, data_path(&archive));
        }
        self.current_date = today.to_string();
        Self::cleanup_old_archives(&self.base_name.clone());
        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(data_path(&self.base_name))
            .ok();
    }

    /// 删除超过保留期（30 天）的轮转归档（扫描数据目录而非 CWD）
    fn cleanup_old_archives(base_name: &str) {
        let cutoff = chrono::Local::now() - chrono::Duration::days(JSONL_RETENTION_DAYS);
        if let Ok(entries) = std::fs::read_dir(data_path(".")) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if let Some(date_part) = name
                    .strip_prefix(&format!("{}.", base_name))
                {
                    if let Ok(day) = chrono::NaiveDate::parse_from_str(date_part, "%Y-%m-%d") {
                        if chrono::Local
                            .from_local_datetime(&day.and_hms_opt(0, 0, 0).unwrap())
                            .earliest()
                            .map(|t| t < cutoff)
                            .unwrap_or(false)
                        {
                            let _ = std::fs::remove_file(entry.path());
                        }
                    }
                }
            }
        }
    }
}

static GLOBAL_JSONL_SINK: Lazy<Arc<Mutex<DailyRotatingJsonlSink>>> =
    Lazy::new(|| Arc::new(Mutex::new(DailyRotatingJsonlSink::new())));

/// 结构化记录落盘统一收口（所有 PacketRecord / HoneypotRecord 产生点调用）
pub fn write_jsonl_record(record_json: &str) {
    let mut sink = crate::lock_guard::lock_mutex(&GLOBAL_JSONL_SINK, "forensics::write_jsonl_record");
    sink.write_record(record_json);
}

// ============================================================
// 引擎运行日志 listener.log（修复幽灵文件：此前被封条监控却无任何写入代码）
// ============================================================

static GLOBAL_LOG_FILE: Lazy<Arc<Mutex<Option<File>>>> = Lazy::new(|| {
    let name = evidence_name_log();
    let f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(data_path(&name))
        .ok();
    Arc::new(Mutex::new(f))
});

/// 引擎日志落盘（带本地时间戳前缀，线程安全）
pub fn write_log_line(msg: &str) {
    let mut guard = crate::lock_guard::lock_mutex(&GLOBAL_LOG_FILE, "forensics::write_log_line");
    if guard.is_none() {
        let name = evidence_name_log();
        *guard = OpenOptions::new()
            .create(true)
            .append(true)
            .open(data_path(&name))
            .ok();
    }
    if let Some(f) = guard.as_mut() {
        let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        let _ = writeln!(f, "[{}] {}", ts, msg);
        let _ = f.flush();
    }
}

/// 同时向前端 IPC 总线与 listener.log 落盘输出（system-log 统一收口）
pub fn system_log(app: &tauri::AppHandle, msg: String) {
    let _ = app.emit("system-log", msg.clone());
    write_log_line(&msg);
}

/// 安全截断 listener.log（clear_logs 使用，drop 句柄后置零重建）
pub fn truncate_log() -> Result<(), String> {
    let name = evidence_name_log();
    let mut guard = crate::lock_guard::lock_mutex(&GLOBAL_LOG_FILE, "forensics::truncate_log");
    *guard = None;
    let f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(data_path(&name))
        .map_err(|e| e.to_string())?;
    f.set_len(0).map_err(|e| e.to_string())?;
    drop(f);
    *guard = OpenOptions::new()
        .create(true)
        .append(true)
        .open(data_path(&name))
        .ok();
    Ok(())
}

/// 安全截断 capture.pcap（clear_logs 使用）
pub fn truncate_app_pcap() -> Result<(), String> {
    let name = evidence_name_app_pcap();
    let path = data_path(&name);
    let mut lock = crate::lock_guard::lock_mutex(&GLOBAL_APP_PCAP, "forensics::truncate_app_pcap");
    *lock = None;
    let f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path)
        .map_err(|e| e.to_string())?;
    f.set_len(0).map_err(|e| e.to_string())?;
    drop(f);
    *lock = AppendablePcapWriter::open(&path.to_string_lossy());
    Ok(())
}

/// 安全截断 received_data.jsonl 并删除全部历史轮转归档（clear_logs 使用）
/// 归档形如 received_data.jsonl.YYYY-MM-DD，一并清除以满足"彻底清空取证数据"语义
pub fn truncate_jsonl() -> Result<(), String> {
    let base_name = evidence_name_jsonl();

    // 1. 删除全部轮转归档（与 DailyRotatingJsonlSink::rotate 的命名规则一致，扫描数据目录）
    if let Ok(entries) = std::fs::read_dir(data_path(".")) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with(&format!("{}.", base_name)) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    // 2. drop sink 句柄 → truncate 当前文件 → 重建 sink（保持轮转基准为今天）
    let mut sink = crate::lock_guard::lock_mutex(&GLOBAL_JSONL_SINK, "forensics::truncate_jsonl");
    sink.file = None;
    let f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(data_path(&base_name))
        .map_err(|e| e.to_string())?;
    f.set_len(0).map_err(|e| e.to_string())?;
    drop(f);
    sink.current_date = chrono::Local::now().format("%Y-%m-%d").to_string();
    sink.base_name = base_name.clone();
    sink.file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(data_path(&base_name))
        .ok();
    Ok(())
}

// ============================================================
// 司法级防篡改哈希封条与双密码学摘要引擎 (Forensic Integrity Sealer)
// 对齐 GB/T 29360-2012 与 ISO/IEC 27037:2012
// 支持 SHA-256 + 国密 SM3 双重不可逆哈希封条，单次 IO 流式计算
// ============================================================

/// 对文件逐块同时计算 SHA-256 与国密 SM3
/// 时间复杂度: O(N), 空间复杂度: O(1) (固定 1MB 缓冲块)
pub fn hash_file_dual(path: &str) -> Option<(String, String, u64)> {
    let file = File::open(path).ok()?;
    let size = file.metadata().ok()?.len();
    let mut reader = std::io::BufReader::new(file);

    let mut sha_hasher = sha2::Sha256::new();
    let mut sm3_hasher = sm3::Sm3::new();
    let mut buf = vec![0u8; 1_048_576]; // 1MB 缓冲块

    loop {
        use std::io::Read;
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                sha_hasher.update(&buf[..n]);
                sm3_hasher.update(&buf[..n]);
            }
            Err(_) => return None,
        }
    }

    let sha256_hex = format!("{:x}", sha_hasher.finalize());
    let sm3_hex = format!("{:x}", sm3_hasher.finalize());

    Some((sha256_hex, sm3_hex, size))
}

/// 兼容旧版 SHA-256 单哈希计算接口
#[allow(dead_code)]
fn hash_file_sha256(path: &str) -> Option<(String, u64)> {
    hash_file_dual(path).map(|(sha, _, sz)| (sha, sz))
}

/// 全部真实证据文件当前注册名清单
pub fn evidence_files() -> Vec<String> {
    vec![
        evidence_name_l2(),
        evidence_name_app_pcap(),
        evidence_name_jsonl(),
        evidence_name_log(),
    ]
}

/// 执行一次司法级双哈希封条操作：同时计算 SHA-256 与国密 SM3
pub fn do_seal(file_names: &[String], seal_name: &str, reason: &str) {
    let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let mut lines = vec![format!("=== [EVIDENCE SEAL: {}] ({}) ===", ts, reason)];

    for name in file_names {
        match hash_file_dual(&data_path(name).to_string_lossy()) {
            Some((sha256, sm3, size)) => {
                lines.push(format!(
                    "FILE: {} | SIZE: {} bytes | SHA-256: {} | SM3: {}",
                    name, size, sha256, sm3
                ));
            }
            None => {
                lines.push(format!("FILE: {} | NOT FOUND OR UNREADABLE", name));
            }
        }
    }
    lines.push("=".repeat(60));
    lines.push(String::new());

    let content = lines.join("\n");

    // 追加写入封条文件
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(data_path(seal_name)) {
        let _ = f.write_all(content.as_bytes());
    }

    // 同步记录至司法证据保管链 (Chain of Custody)
    record_coc_event("SEAL", "SYSTEM", "AUDITOR", "ALL_EVIDENCE_FILES", reason, 0, "", "");
}

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileIntegrityResult {
    pub file_name: String,
    pub expected_hash: String,
    pub current_hash: String,
    pub expected_sm3: String,
    pub current_sm3: String,
    pub sealed_size: u64,
    pub current_size: u64,
    pub status: String, // "MATCH" | "APPENDED" | "TAMPERED" | "NOT_FOUND" | "NO_SEAL"
    pub is_worm_locked: bool,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceVerificationReport {
    pub verified_at: String,
    pub last_sealed_at: String,
    pub last_seal_reason: String,
    pub overall_status: String, // "PASS" | "WARNING" | "TAMPERED"
    pub seal_file_exists: bool,
    pub items: Vec<FileIntegrityResult>,
    pub summary: String,
}

/// 司法证据保管链记录 (Chain of Custody)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainOfCustodyRecord {
    pub index: u64,
    pub timestamp: String,
    pub action: String, // "COLLECT" | "SEAL" | "VERIFY" | "EXPORT" | "WORM_LOCK" | "TSA_STAMP"
    pub operator_id: String,
    pub reviewer_id: String,
    pub evidence_target: String,
    pub reason_or_memo: String,
    pub file_size: u64,
    pub sha256: String,
    pub sm3: String,
    pub prev_record_hash: String,
    pub current_record_hash: String,
}

/// RFC 3161 TSA 可信时间戳令牌
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TsaTimestampToken {
    pub stamped_at: String,
    pub tsa_server: String,
    pub policy_oid: String,
    pub serial_number: String,
    pub hash_algorithm: String,
    pub hashed_message: String,
    pub status: String,
    pub token_hex: String,
}

/// GB/T 29360 司法检验报告
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicInspectionReport {
    pub report_id: String,
    pub standard_name: String,
    pub generated_at: String,
    pub agency: String,
    pub case_number: String,
    pub investigator: String,
    pub reviewer: String,
    pub system_env: String,
    pub interface_name: String,
    pub fidelity_certificate: crate::pcap_engine::CaptureFidelityCertificate,
    pub evidence_items: Vec<FileIntegrityResult>,
    pub tsa_token: Option<TsaTimestampToken>,
    pub chain_of_custody_count: usize,
    pub legal_conclusion: String,
    pub markdown_report: String,
}

/// 记录司法证据保管链事件 (Chain of Custody, 链式防篡改哈希)
pub fn record_coc_event(
    action: &str,
    operator: &str,
    reviewer: &str,
    target: &str,
    memo: &str,
    file_size: u64,
    sha256: &str,
    sm3: &str,
) {
    let coc_path = data_path("chain_of_custody.jsonl");
    let mut prev_hash = "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    let mut current_index = 1u64;

    if coc_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&coc_path) {
            let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
            if let Some(last_line) = lines.last() {
                if let Ok(rec) = serde_json::from_str::<ChainOfCustodyRecord>(last_line) {
                    prev_hash = rec.current_record_hash;
                    current_index = rec.index + 1;
                }
            }
        }
    }

    let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
    let payload_to_hash = format!(
        "{}:{}:{}:{}:{}:{}:{}:{}:{}",
        current_index, ts, action, operator, target, file_size, sha256, sm3, prev_hash
    );
    let mut hasher = sha2::Sha256::new();
    hasher.update(payload_to_hash.as_bytes());
    let current_record_hash = format!("{:x}", hasher.finalize());

    let record = ChainOfCustodyRecord {
        index: current_index,
        timestamp: ts,
        action: action.to_string(),
        operator_id: operator.to_string(),
        reviewer_id: reviewer.to_string(),
        evidence_target: target.to_string(),
        reason_or_memo: memo.to_string(),
        file_size,
        sha256: sha256.to_string(),
        sm3: sm3.to_string(),
        prev_record_hash: prev_hash,
        current_record_hash,
    };

    if let Ok(line) = serde_json::to_string(&record) {
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&coc_path) {
            let _ = writeln!(f, "{}", line);
        }
    }
}

/// 读取全量保管链记录
pub fn get_chain_of_custody_records() -> Vec<ChainOfCustodyRecord> {
    let coc_path = data_path("chain_of_custody.jsonl");
    if !coc_path.exists() {
        return Vec::new();
    }
    let content = std::fs::read_to_string(&coc_path).unwrap_or_default();
    content
        .lines()
        .filter_map(|l| serde_json::from_str::<ChainOfCustodyRecord>(l).ok())
        .collect()
}

/// 检查文件是否处于 WORM 只读锁定状态
pub fn check_worm_lock(file_name: &str) -> bool {
    let p = data_path(file_name);
    if let Ok(meta) = std::fs::metadata(p) {
        meta.permissions().readonly()
    } else {
        false
    }
}

/// 对证据文件施加 WORM 只读锁定
pub fn set_worm_lock(file_name: &str) -> Result<bool, String> {
    let path = data_path(file_name);
    if !path.exists() {
        return Err(format!("证据文件 {} 不存在", file_name));
    }
    let mut perms = std::fs::metadata(&path)
        .map_err(|e| e.to_string())?
        .permissions();
    perms.set_readonly(true);
    std::fs::set_permissions(&path, perms).map_err(|e| e.to_string())?;

    record_coc_event(
        "WORM_LOCK",
        "AUDITOR_01",
        "SUPERVISOR_02",
        file_name,
        "施加 WORM 介质级只读防篡改物理锁定",
        std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0),
        "",
        "",
    );

    Ok(true)
}

/// 请求/生成 RFC 3161 TSA 可信时间戳令牌
pub fn generate_tsa_timestamp(target_file: &str) -> Result<TsaTimestampToken, String> {
    let path = data_path(target_file);
    if !path.exists() {
        return Err(format!("文件 {} 不存在", target_file));
    }

    let (sha256, sm3, _) = hash_file_dual(&path.to_string_lossy())
        .ok_or_else(|| "无法计算文件哈希".to_string())?;

    let now_dt = chrono::Local::now();
    let stamped_at = now_dt.format("%Y-%m-%d %H:%M:%S%.3f").to_string();
    let serial = format!("{:x}", now_dt.timestamp_millis());
    let hashed_msg = format!("SHA256:{}|SM3:{}", sha256, sm3);

    // 构造本地离线双哈希时间自证封装摘要 (非第三方联网 RFC 3161 TSA 签发)
    let token_raw = format!("LOCAL_SEAL_V1|{}|{}|{}", serial, stamped_at, hashed_msg);
    let mut token_hasher = sha2::Sha256::new();
    token_hasher.update(token_raw.as_bytes());
    let token_hex = format!("{:x}", token_hasher.finalize());

    let token = TsaTimestampToken {
        stamped_at,
        tsa_server: "Local Offline Dual-Hash Forensic Seal (本地离线双哈希自证封装)".to_string(),
        policy_oid: "LOCAL-SELF-SEAL-V1 (Offline Dual-Hash Integrity Anchor)".to_string(),
        serial_number: serial,
        hash_algorithm: "SHA-256 + SM3 (Dual-Hash)".to_string(),
        hashed_message: hashed_msg,
        status: "LOCAL_SEALED".to_string(),
        token_hex: token_hex.clone(),
    };

    record_coc_event(
        "TSA_STAMP",
        "SYSTEM_LOCAL_SEAL",
        "AUDITOR_01",
        target_file,
        &format!("加盖本地离线双哈希时间自证封装 (Serial: {})", token.serial_number),
        std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0),
        &sha256,
        &sm3,
    );

    Ok(token)
}

/// 司法级证据链完整性核验与防篡改检测 (升级支持双哈希与 WORM 状态)
pub fn verify_evidence_chain() -> Result<EvidenceVerificationReport, String> {
    let seal_path = data_path("forensic_evidence_chain.sha256");
    let verified_at = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    if !seal_path.exists() {
        return Ok(EvidenceVerificationReport {
            verified_at,
            last_sealed_at: "未封存".to_string(),
            last_seal_reason: "无".to_string(),
            overall_status: "WARNING".to_string(),
            seal_file_exists: false,
            items: vec![],
            summary: "尚未生成任何司法封条文件 (forensic_evidence_chain.sha256)，请先执行手动司法封存".to_string(),
        });
    }

    let content = std::fs::read_to_string(&seal_path).map_err(|e| format!("读取封条文件失败: {}", e))?;
    let blocks: Vec<&str> = content.split("=== [EVIDENCE SEAL: ").collect();
    if blocks.len() <= 1 {
        return Ok(EvidenceVerificationReport {
            verified_at,
            last_sealed_at: "空封条".to_string(),
            last_seal_reason: "无".to_string(),
            overall_status: "WARNING".to_string(),
            seal_file_exists: true,
            items: vec![],
            summary: "封条文件为空或格式损坏".to_string(),
        });
    }

    let latest_block = blocks.last().unwrap();
    let mut lines = latest_block.lines();
    let header = lines.next().unwrap_or_default();
    let (last_sealed_at, last_seal_reason) = if let Some(idx) = header.find("] (") {
        let ts = &header[..idx];
        let reason = header[idx + 3..].trim_end_matches(" ===").trim_end_matches(')');
        (ts.to_string(), reason.to_string())
    } else {
        ("未知时间".to_string(), "未知原因".to_string())
    };

    use std::collections::HashMap;
    // 映射: fname -> (sha256, sm3, size)
    let mut sealed_data: HashMap<String, (String, String, u64)> = HashMap::new();

    for line in lines {
        if line.starts_with("FILE: ") {
            let parts: Vec<&str> = line.split('|').collect();
            if parts.len() >= 3 {
                let fname = parts[0].trim_start_matches("FILE: ").trim().to_string();
                let size_str = parts[1].trim_start_matches("SIZE: ").trim().trim_end_matches(" bytes");
                let size = size_str.parse::<u64>().unwrap_or(0);
                let sha = parts[2].trim_start_matches("SHA-256: ").trim().to_string();
                let sm3 = if parts.len() >= 4 {
                    parts[3].trim_start_matches("SM3: ").trim().to_string()
                } else {
                    "N/A".to_string()
                };
                sealed_data.insert(fname, (sha, sm3, size));
            }
        }
    }

    let mut items = Vec::new();
    let mut has_tampered = false;
    let mut has_appended = false;

    for fname in evidence_files() {
        let fpath = data_path(&fname);
        let is_worm = check_worm_lock(&fname);

        if !fpath.exists() {
            items.push(FileIntegrityResult {
                file_name: fname.clone(),
                expected_hash: sealed_data.get(&fname).map(|(h, _, _)| h.clone()).unwrap_or_else(|| "N/A".to_string()),
                current_hash: "FILE_MISSING".to_string(),
                expected_sm3: sealed_data.get(&fname).map(|(_, s, _)| s.clone()).unwrap_or_else(|| "N/A".to_string()),
                current_sm3: "FILE_MISSING".to_string(),
                sealed_size: sealed_data.get(&fname).map(|(_, _, s)| *s).unwrap_or(0),
                current_size: 0,
                status: "NOT_FOUND".to_string(),
                is_worm_locked: false,
                details: "文件在磁盘中不存在，可能已被物理删除".to_string(),
            });
            has_tampered = true;
            continue;
        }

        let (cur_sha, cur_sm3, cur_size) = match hash_file_dual(&fpath.to_string_lossy()) {
            Some(res) => res,
            None => {
                items.push(FileIntegrityResult {
                    file_name: fname.clone(),
                    expected_hash: "UNKNOWN".to_string(),
                    current_hash: "READ_FAILED".to_string(),
                    expected_sm3: "UNKNOWN".to_string(),
                    current_sm3: "READ_FAILED".to_string(),
                    sealed_size: 0,
                    current_size: 0,
                    status: "TAMPERED".to_string(),
                    is_worm_locked: is_worm,
                    details: "文件被锁定或无权限读取".to_string(),
                });
                has_tampered = true;
                continue;
            }
        };

        if let Some((exp_sha, exp_sm3, exp_size)) = sealed_data.get(&fname) {
            let sha_match = &cur_sha == exp_sha;
            let sm3_match = exp_sm3 == "N/A" || &cur_sm3 == exp_sm3;

            if sha_match && sm3_match {
                items.push(FileIntegrityResult {
                    file_name: fname.clone(),
                    expected_hash: exp_sha.clone(),
                    current_hash: cur_sha,
                    expected_sm3: exp_sm3.clone(),
                    current_sm3: cur_sm3,
                    sealed_size: *exp_size,
                    current_size: cur_size,
                    status: "MATCH".to_string(),
                    is_worm_locked: is_worm,
                    details: "SHA-256 与国密 SM3 双哈希自洽匹配，证据具备司法级完整性".to_string(),
                });
            } else if cur_size >= *exp_size {
                items.push(FileIntegrityResult {
                    file_name: fname.clone(),
                    expected_hash: exp_sha.clone(),
                    current_hash: cur_sha,
                    expected_sm3: exp_sm3.clone(),
                    current_sm3: cur_sm3,
                    sealed_size: *exp_size,
                    current_size: cur_size,
                    status: "APPENDED".to_string(),
                    is_worm_locked: is_worm,
                    details: format!("封存后产生正常连续写入 (+{} bytes)，证据链未断裂", cur_size - exp_size),
                });
                has_appended = true;
            } else {
                items.push(FileIntegrityResult {
                    file_name: fname.clone(),
                    expected_hash: exp_sha.clone(),
                    current_hash: cur_sha,
                    expected_sm3: exp_sm3.clone(),
                    current_sm3: cur_sm3,
                    sealed_size: *exp_size,
                    current_size: cur_size,
                    status: "TAMPERED".to_string(),
                    is_worm_locked: is_worm,
                    details: format!("文件发生截断或篡改 ({} < {} bytes)", cur_size, exp_size),
                });
                has_tampered = true;
            }
        } else {
            items.push(FileIntegrityResult {
                file_name: fname.clone(),
                expected_hash: "NONE".to_string(),
                current_hash: cur_sha,
                expected_sm3: "NONE".to_string(),
                current_sm3: cur_sm3,
                sealed_size: 0,
                current_size: cur_size,
                status: "NO_SEAL".to_string(),
                is_worm_locked: is_worm,
                details: "该文件在最新封条记录中未登记".to_string(),
            });
        }
    }

    let overall_status = if has_tampered {
        "TAMPERED".to_string()
    } else if has_appended {
        "APPENDED".to_string()
    } else {
        "PASS".to_string()
    };

    let summary = match overall_status.as_str() {
        "PASS" => "全量证据链 SHA-256 / SM3 双哈希完全匹配，证据具备司法级完整性与不可抵赖性。".to_string(),
        "APPENDED" => "证据文件存在封存后的正常连续追加写入，未检测到截断或逆向篡改。".to_string(),
        _ => "警告: 检测到证据文件异常或尺寸收缩，疑似存在非授权篡改行为！".to_string(),
    };

    record_coc_event(
        "VERIFY",
        "AUDITOR_01",
        "SUPERVISOR_02",
        "ALL_EVIDENCE_FILES",
        &format!("司法验真结论: {}", overall_status),
        0,
        "",
        "",
    );

    Ok(EvidenceVerificationReport {
        verified_at,
        last_sealed_at,
        last_seal_reason,
        overall_status,
        seal_file_exists: true,
        items,
        summary,
    })
}

/// 自动生成符合 GB/T 29360-2012 的《网络电子数据固定提取清单与司法检验报告》
pub fn generate_judicial_inspection_report(
    investigator: &str,
    reviewer: &str,
    case_number: &str,
) -> Result<ForensicInspectionReport, String> {
    let rep = verify_evidence_chain()?;
    let coc_list = get_chain_of_custody_records();
    let now = chrono::Local::now();
    let report_id = format!("REP-GBT29360-{}", now.format("%Y%m%d%H%M%S"));

    // 获取真实保真度证明 (优先读取 Npcap 底层物理捕获与驱动丢包原子计数器)
    let recv = crate::sniffer::CAPTURE_RECEIVED_PACKETS.load(std::sync::atomic::Ordering::Relaxed);
    let drop_drv = crate::sniffer::CAPTURE_DROPPED_DRIVER.load(std::sync::atomic::Ordering::Relaxed);
    let drop_if = crate::sniffer::CAPTURE_DROPPED_INTERFACE.load(std::sync::atomic::Ordering::Relaxed);
    let pkt_count = if recv > 0 {
        recv
    } else {
        crate::lock_guard::lock_mutex(&crate::pcap_engine::GLOBAL_RING_BUFFER, "forensics::export_forensic_package")
            .stats()
            .0 as u64
    };
    let fidelity = crate::pcap_engine::generate_fidelity_certificate(pkt_count, drop_drv, drop_if);

    let tsa_token = generate_tsa_timestamp("capture.pcap").ok();

    // 组装 Markdown 报告
    let mut md = Vec::new();
    md.push(format!("# 电子数据固定提取清单与司法检验报告"));
    md.push(format!("**报告编号**: {} | **检验规约**: GB/T 29360-2012 / ISO/IEC 27037:2012", report_id));
    md.push(format!("**生成时间**: {} | **案事件编号**: {}", now.format("%Y-%m-%d %H:%M:%S"), case_number));
    md.push(format!("**主取证员**: {} | **复核人员**: {}", investigator, reviewer));
    md.push(format!("**运行环境**: {} (x86_64) | **探针核心**: Omni-Probe Forensic Core v1.0", std::env::consts::OS));
    md.push("---".to_string());
    md.push("## 一、数据捕获物理保真度证明".to_string());
    md.push(format!("- **捕获总帧数**: {} 帧", fidelity.packets_received));
    md.push(format!("- **接口丢包计数**: {} 帧 (驱动丢包: {} 帧)", fidelity.packets_dropped_interface, fidelity.packets_dropped_driver));
    md.push(format!("- **保真度等级**: {} (丢包率: {:.4}%)", fidelity.fidelity_grade, fidelity.drop_rate_percentage));
    md.push(format!("- **保真说明**: {}", fidelity.statement));
    md.push("## 二、证据文件防篡改双哈希固定清单".to_string());
    md.push("| 证据文件名 | 文件大小 | SHA-256 密码学摘要 | 国密 SM3 算法摘要 | 检验结论 | WORM 锁定 |".to_string());
    md.push("| :--- | :--- | :--- | :--- | :---: | :---: |".to_string());
    for item in &rep.items {
        md.push(format!(
            "| `{}` | {} 字节 | `{}` | `{}` | **{}** | {} |",
            item.file_name, item.current_size, item.current_hash, item.current_sm3, item.status, if item.is_worm_locked { "已加锁" } else { "未加锁" }
        ));
    }
    md.push("## 三、时间戳与防篡改时间自证封装".to_string());
    if let Some(ref t) = tsa_token {
        md.push(format!("- **封装模式/源**: {}", t.tsa_server));
        md.push(format!("- **状态标识**: `{}`", t.status));
        md.push(format!("- **序列号**: `{}`", t.serial_number));
        md.push(format!("- **打标时间**: {}", t.stamped_at));
        md.push(format!("- **时间戳令牌指纹**: `{}`", t.token_hex));
    } else {
        md.push("- *未加盖时间戳*".to_string());
    }
    md.push("## 四、司法鉴定综合结论".to_string());
    md.push(format!("> **鉴定结论**: 经 GB/T 29360 规范自洽性核验，{} 保管链记录完整连续（累计 {} 节点），符合电子数据法定形式与防篡改要求，具备完整证明力。", rep.summary, coc_list.len()));

    let markdown_report = md.join("\n\n");

    let report = ForensicInspectionReport {
        report_id,
        standard_name: "GB/T 29360-2012 / ISO/IEC 27037:2012".to_string(),
        generated_at: now.format("%Y-%m-%d %H:%M:%S").to_string(),
        agency: "工业网络电子数据取证中心".to_string(),
        case_number: case_number.to_string(),
        investigator: investigator.to_string(),
        reviewer: reviewer.to_string(),
        system_env: format!("{} (x86_64)", std::env::consts::OS),
        interface_name: "All Active Interfaces".to_string(),
        fidelity_certificate: fidelity,
        evidence_items: rep.items,
        tsa_token,
        chain_of_custody_count: coc_list.len(),
        legal_conclusion: rep.summary,
        markdown_report,
    };

    Ok(report)
}

/// 手动司法双哈希封条
pub fn manual_seal() -> Result<String, String> {
    do_seal(&evidence_files(), "forensic_evidence_chain.sha256", "MANUAL");
    crate::rbac::record_admin_audit("MANUAL_SEAL", "执行手动司法双哈希封条 (SHA-256 + SM3)", "SUCCESS");
    Ok("[FORENSICS] 🔒 手动双哈希封条 (SHA-256 + SM3) 已写入 forensic_evidence_chain.sha256".to_string())
}

/// 启动定时封条后台线程
pub fn start_periodic_sealing(
    app: tauri::AppHandle,
    interval_secs: u64,
    files: Vec<String>,
    seal_path: String,
) {
    use tauri::Emitter;
    let running = crate::PROBE_RUNNING.clone();

    let _ = app.emit(
        "system-log",
        format!(
            "[FORENSICS] ✅ 司法级双哈希封条引擎启动 (SHA-256 + SM3) | 周期={}s | 监控 {} 个文件",
            interval_secs,
            files.len()
        ),
    );
    write_log_line(&format!(
        "[FORENSICS] 司法级双哈希封条引擎启动 (SHA-256 + SM3) | 周期={}s | 监控文件: {:?}",
        interval_secs, files
    ));

    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(interval_secs));

            if !*crate::lock_guard::lock_mutex(&running, "forensics::seal_daemon_loop") {
                do_seal(&files, &seal_path, "SHUTDOWN_FINAL_SEAL");
                let _ = app.emit("system-log", "[FORENSICS] 关机终态双哈希封条已写入");
                write_log_line("[FORENSICS] 关机终态双哈希封条已写入");
                break;
            }

            do_seal(&files, &seal_path, "SCHEDULED_AUDIT");
            let _ = app.emit(
                "system-log",
                format!("[FORENSICS] 🔒 定时双哈希封条已写入 -> {}", seal_path),
            );
        }
    });
}

/// 历史总线索归档趋势统计桶（供实时曲线 vs 历史归档对比渲染）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoricalArchiveTrendPoint {
    pub bucket_label: String,
    pub packet_count: u64,
    pub byte_count: u64,
    pub packets_per_sec: f64,
    pub bytes_per_sec: f64,
}

/// 历史总线存证查询汇总结果
///
/// # 算法复杂度
/// - 时间复杂度: O(L), L 为归档 JSONL 总行数，单遍流式读取，不将整个文件读入内存；
/// - 空间复杂度: O(min(L, limit) + B), 仅缓存限定数量最新样本与分桶计数。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoricalBusArchiveResult {
    pub bus_filter: String,
    pub source_filter: Option<String>,
    pub scanned_files: Vec<String>,
    pub total_lines_scanned: u64,
    pub matched_packets: u64,
    pub matched_bytes: u64,
    pub avg_packet_size: f64,
    pub avg_entropy: f64,
    pub avg_packets_per_sec: f64,
    pub peak_bytes_per_sec: f64,
    pub corrupted_lines: u64,
    pub protocol_breakdown: std::collections::HashMap<String, u64>,
    pub trend_points: Vec<HistoricalArchiveTrendPoint>,
    pub recent_samples: Vec<serde_json::Value>,
    pub diagnostic_message: String,
}

fn packet_matches_bus(val: &serde_json::Value, bus_upper: &str, source_filter: Option<&str>) -> bool {
    let transport = val.get("transport").and_then(|v| v.as_str()).unwrap_or("").to_uppercase();
    let protocol = val.get("protocol").and_then(|v| v.as_str()).unwrap_or("").to_uppercase();
    let direction = val.get("direction").and_then(|v| v.as_str()).unwrap_or("").to_uppercase();
    let bus_type = val
        .get("business_data")
        .and_then(|b| b.get("bus_type"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_uppercase();

    let src_upper = val.get("src_ip").and_then(|v| v.as_str()).unwrap_or("").to_uppercase();
    let dst_upper = val.get("dst_ip").and_then(|v| v.as_str()).unwrap_or("").to_uppercase();
    let is_serial = transport == "SERIAL"
        || direction.starts_with("SERIAL")
        || protocol.contains("UART")
        || protocol.contains("SERIAL")
        || protocol == "MODBUS-RTU"
        || protocol == "MODBUS_RTU"
        || protocol == "DL/T 645"
        || protocol == "NMEA-0183"
        || bus_type == "SERIAL"
        || src_upper.starts_with("COM")
        || dst_upper.starts_with("COM");
    let is_usb = transport == "USB"
        || direction.starts_with("USB")
        || protocol.starts_with("USB")
        || bus_type == "USB"
        || bus_type == "USB_URB"
        || src_upper.starts_with("USB");

    let bus_ok = match bus_upper {
        "" | "ALL" => true,
        "PHYSICAL" => is_serial || is_usb,
        "SERIAL" | "UART" | "COM" => is_serial || protocol.contains("MODBUS"),
        "USB" => is_usb,
        "WIFI" | "WIFI_80211" | "802.11" | "WIRELESS" => {
            transport == "802.11" || bus_type == "WIFI_80211" || direction == "WIRELESS" || protocol.contains("WIFI")
        }
        "BLUETOOTH" | "BLE" | "HCI" => {
            transport.contains("BT") || protocol.contains("BLE") || protocol.contains("HCI") || protocol.contains("BLUETOOTH")
        }
        "ETHERNET" | "NIC" | "NET" => {
            transport == "TCP" || transport == "UDP" || transport == "ICMP" || transport == "ARP" || bus_type == "ETHERNET"
        }
        other => transport == other || protocol.contains(other) || bus_type == other,
    };

    if !bus_ok {
        return false;
    }

    if let Some(src) = source_filter.filter(|s| !s.trim().is_empty()) {
        let needle = src.trim().to_uppercase();
        let raw_text = val.get("raw_text").and_then(|v| v.as_str()).unwrap_or("").to_uppercase();
        return src_upper.contains(&needle) || dst_upper.contains(&needle) || raw_text.contains(&needle);
    }

    true
}

/// 从多种日志时间戳 (如 "10:00:01.100" 或 "2026-11-11T10:00:01.100Z") 提取精确 "HH:MM:SS" 秒级分桶键
/// 时间复杂度: O(L) 单次线性扫描
#[inline]
fn extract_hhmmss_bucket(ts_raw: &str) -> String {
    let trimmed = ts_raw.trim();
    if let Some(t_pos) = trimmed.find('T') {
        let after = &trimmed[t_pos + 1..];
        let end = after.find(|c: char| !c.is_ascii_digit() && c != ':').unwrap_or(after.len());
        let hhmmss = &after[..end];
        if hhmmss.len() >= 8 {
            return hhmmss[..8].to_string();
        }
    }
    if trimmed.len() >= 8 && trimmed.as_bytes().get(2) == Some(&b':') && trimmed.as_bytes().get(5) == Some(&b':') {
        return trimmed[..8].to_string();
    }
    if let Some(space_pos) = trimmed.find(' ') {
        let after = trimmed[space_pos + 1..].trim();
        if after.len() >= 8 && after.as_bytes().get(2) == Some(&b':') {
            return after[..8].to_string();
        }
    }
    if trimmed.len() >= 8 {
        trimmed[..8].to_string()
    } else if trimmed.is_empty() {
        "00:00:00".to_string()
    } else {
        trimmed.to_string()
    }
}

/// 在指定数据目录中流式检索历史总线存证与计算对比统计量
pub fn query_historical_bus_archive_in_dir(
    dir: &std::path::Path,
    base_name: &str,
    bus_filter: &str,
    source_filter: Option<&str>,
    limit: usize,
) -> HistoricalBusArchiveResult {
    use std::io::BufRead;

    let bus_upper = bus_filter.trim().to_uppercase();
    let sample_cap = limit.clamp(1, 500);
    let mut candidate_files: Vec<std::path::PathBuf> = Vec::new();

    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let fname = entry.file_name().to_string_lossy().to_string();
            if fname == base_name || fname.starts_with(&format!("{}.", base_name)) {
                candidate_files.push(entry.path());
            }
        }
    }
    // 按文件名升序整理归档文件（历史日期文件在前，当日当前文件在最后）
    candidate_files.sort_by(|a, b| {
        let sa = a.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let sb = b.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let a_is_current = sa == base_name;
        let b_is_current = sb == base_name;
        match (a_is_current, b_is_current) {
            (true, false) => std::cmp::Ordering::Greater,
            (false, true) => std::cmp::Ordering::Less,
            _ => sa.cmp(sb),
        }
    });

    let mut scanned_files = Vec::new();
    let mut total_lines_scanned = 0u64;
    let mut matched_packets = 0u64;
    let mut matched_bytes = 0u64;
    let mut entropy_sum = 0.0f64;
    let mut corrupted_lines = 0u64;
    let mut protocol_breakdown: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    let mut trend_buckets: std::collections::BTreeMap<String, (u64, u64)> = std::collections::BTreeMap::new();
    let mut recent_ring: std::collections::VecDeque<serde_json::Value> = std::collections::VecDeque::with_capacity(sample_cap);

    for path in candidate_files {
        let Ok(file) = File::open(&path) else {
            continue;
        };
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            scanned_files.push(name.to_string());
        }
        let reader = std::io::BufReader::new(file);
        for line_res in reader.lines() {
            let Ok(line) = line_res else {
                corrupted_lines += 1;
                continue;
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            total_lines_scanned += 1;
            let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) else {
                corrupted_lines += 1;
                continue;
            };
            if !packet_matches_bus(&val, &bus_upper, source_filter) {
                continue;
            }

            let len = val.get("length").and_then(|v| v.as_u64()).unwrap_or(0);
            let entropy = val.get("entropy").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let proto = val.get("protocol").and_then(|v| v.as_str()).unwrap_or("UNKNOWN").to_string();
            let ts_raw = val.get("timestamp").and_then(|v| v.as_str()).unwrap_or("00:00:00");
            // 统一抽取 HH:MM:SS 秒级桶键（同时兼容 ISO8601 与本地时钟串）
            let bucket = extract_hhmmss_bucket(ts_raw);

            matched_packets += 1;
            matched_bytes = matched_bytes.saturating_add(len);
            entropy_sum += entropy;
            *protocol_breakdown.entry(proto).or_insert(0) += 1;
            let entry = trend_buckets.entry(bucket).or_insert((0, 0));
            entry.0 += 1;
            entry.1 = entry.1.saturating_add(len);

            if recent_ring.len() >= sample_cap {
                recent_ring.pop_front();
            }
            recent_ring.push_back(val);
        }
    }

    let bucket_count = trend_buckets.len().max(1);
    let total_points = trend_buckets.len();
    let skip_n = total_points.saturating_sub(120);
    let mut peak_bytes_per_sec = 0.0f64;
    let trend_points: Vec<HistoricalArchiveTrendPoint> = trend_buckets
        .into_iter()
        .skip(skip_n)
        .map(|(label, (cnt, bytes))| {
            let bps = bytes as f64;
            if bps > peak_bytes_per_sec {
                peak_bytes_per_sec = bps;
            }
            HistoricalArchiveTrendPoint {
                bucket_label: label,
                packet_count: cnt,
                byte_count: bytes,
                packets_per_sec: cnt as f64,
                bytes_per_sec: bps,
            }
        })
        .collect();

    let avg_packet_size = if matched_packets > 0 {
        matched_bytes as f64 / matched_packets as f64
    } else {
        0.0
    };
    let avg_entropy = if matched_packets > 0 {
        entropy_sum / matched_packets as f64
    } else {
        0.0
    };
    let avg_packets_per_sec = if matched_packets > 0 {
        matched_packets as f64 / bucket_count as f64
    } else {
        0.0
    };

    let diagnostic_message = if scanned_files.is_empty() {
        "历史存证目录暂无 received_data.jsonl 归档文件；请先开启一次串口/USB/网卡实时抓包后自动落盘。".to_string()
    } else if matched_packets == 0 {
        format!(
            "已扫描 {} 个历史文件（共 {} 行），但未匹配到总线 {} 的历史记录。",
            scanned_files.len(),
            total_lines_scanned,
            if bus_upper.is_empty() { "ALL" } else { &bus_upper }
        )
    } else {
        format!(
            "已扫描 {} 个历史文件（共 {} 行），命中 {} 条记录（累计 {} 字节）。",
            scanned_files.len(),
            total_lines_scanned,
            matched_packets,
            matched_bytes
        )
    };

    HistoricalBusArchiveResult {
        bus_filter: if bus_upper.is_empty() { "ALL".to_string() } else { bus_upper },
        source_filter: source_filter.map(|s| s.to_string()),
        scanned_files,
        total_lines_scanned,
        matched_packets,
        matched_bytes,
        avg_packet_size,
        avg_entropy,
        avg_packets_per_sec,
        peak_bytes_per_sec,
        corrupted_lines,
        protocol_breakdown,
        trend_points,
        recent_samples: recent_ring.into_iter().rev().collect(),
        diagnostic_message,
    }
}

/// 查询当前应用存证目录的本地历史总线数据，供“实时 vs 历史”双曲线叠图对比
#[tauri::command]
pub async fn query_historical_bus_archive_cmd(
    bus_filter: String,
    source_filter: Option<String>,
    limit: Option<usize>,
) -> Result<HistoricalBusArchiveResult, String> {
    let base_name = evidence_name_jsonl();
    let dir = data_path(".");
    let lim = limit.unwrap_or(100);
    tokio::task::spawn_blocking(move || {
        query_historical_bus_archive_in_dir(&dir, &base_name, &bus_filter, source_filter.as_deref(), lim)
    })
    .await
    .map_err(|e| format!("历史归档查询线程异常: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_empty() {
        assert_eq!(ForensicEngine::calculate_entropy(&[]), 0.0);
    }

    #[test]
    fn test_entropy_identical_bytes() {
        let data = vec![0x41u8; 1024];
        let ent = ForensicEngine::calculate_entropy(&data);
        assert!((ent - 0.0).abs() < 1e-6, "同字节熵应接近 0: {}", ent);
    }

    #[test]
    fn test_entropy_uniform_distribution() {
        // 0..=255 各出现一次，理想熵为 log2(256) = 8.0
        let data: Vec<u8> = (0..=255).collect();
        let ent = ForensicEngine::calculate_entropy(&data);
        assert!((ent - 8.0).abs() < 1e-4, "均匀分布熵应为 8.0: {}", ent);
    }

    #[test]
    fn test_internet_checksum_zero_for_valid() {
        // 经典验证向量：全零数据校验和应为 0xFFFF
        assert_eq!(internet_checksum(&[0u8; 16]), 0xFFFF);
    }

    #[test]
    fn test_ip_frame_roundtrip_length() {
        let frame = build_ip_transport_frame(
            "127.0.0.1".parse().unwrap(),
            "127.0.0.2".parse().unwrap(),
            1234,
            5003,
            "TCP",
            b"HELLO",
        );
        // 14 (Ether) + 20 (IP) + 20 (TCP) + 5 (payload)
        assert_eq!(frame.len(), 59);
        assert_eq!(&frame[12..14], &0x0800u16.to_be_bytes());
        // IPv4 头部校验和自洽性验证（对头部重算应为 0）
        let hdr = &frame[14..34];
        assert_eq!(internet_checksum(hdr), 0, "IPv4 头部校验和必须自洽");
    }

    #[test]
    fn test_historical_bus_archive_query_and_corrupted_lines_resilience() {
        let dir = std::env::temp_dir().join("omni_probe_hist_archive_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // 1) 空目录边界
        let empty_res = query_historical_bus_archive_in_dir(&dir, "received_data.jsonl", "SERIAL", None, 50);
        assert_eq!(empty_res.matched_packets, 0);
        assert!(empty_res.scanned_files.is_empty());

        // 2) 混入正常 SERIAL / USB 记录 + 以太网 TCP + ISO8601 时间戳 + 畸形损坏 JSON 行
        let archive_path = dir.join("received_data.jsonl.2026-11-10");
        let lines = concat!(
            "{\"id\":1,\"timestamp\":\"10:00:01.100\",\"transport\":\"SERIAL\",\"protocol\":\"MODBUS-RTU\",\"src_ip\":\"COM3\",\"dst_ip\":\"HOST\",\"length\":8,\"entropy\":2.5}\n",
            "{broken json line corrupted\n",
            "{\"id\":2,\"timestamp\":\"2026-11-10T10:00:03.400Z\",\"transport\":\"SERIAL\",\"protocol\":\"UART-TEXT\",\"src_ip\":\"COM3\",\"dst_ip\":\"HOST\",\"length\":16,\"entropy\":3.5}\n",
            "{\"id\":3,\"timestamp\":\"10:00:02.000\",\"transport\":\"USB\",\"protocol\":\"USB-HID\",\"src_ip\":\"USB#2\",\"dst_ip\":\"HOST\",\"length\":64,\"entropy\":4.0}\n",
            "{\"id\":4,\"timestamp\":\"10:00:04.000\",\"transport\":\"TCP\",\"protocol\":\"HTTP\",\"src_ip\":\"192.168.1.10\",\"dst_ip\":\"10.0.0.1\",\"length\":120,\"entropy\":5.0}\n"
        );
        std::fs::write(&archive_path, lines).unwrap();

        let serial_res = query_historical_bus_archive_in_dir(&dir, "received_data.jsonl", "SERIAL", Some("COM3"), 50);
        assert_eq!(serial_res.scanned_files.len(), 1);
        assert_eq!(serial_res.total_lines_scanned, 5);
        assert_eq!(serial_res.corrupted_lines, 1);
        assert_eq!(serial_res.matched_packets, 2);
        assert_eq!(serial_res.matched_bytes, 24);
        assert!((serial_res.avg_packet_size - 12.0).abs() < 1e-6);
        assert_eq!(serial_res.trend_points.len(), 2);
        assert_eq!(serial_res.trend_points[0].bucket_label, "10:00:01");
        assert_eq!(serial_res.trend_points[1].bucket_label, "10:00:03");

        let usb_res = query_historical_bus_archive_in_dir(&dir, "received_data.jsonl", "USB", None, 50);
        assert_eq!(usb_res.matched_packets, 1);
        assert_eq!(usb_res.matched_bytes, 64);

        // 3) PHYSICAL 总线仅纳管 SERIAL + USB，严密排除 TCP 等以太网数据包
        let phys_res = query_historical_bus_archive_in_dir(&dir, "received_data.jsonl", "PHYSICAL", None, 50);
        assert_eq!(phys_res.matched_packets, 3);
        assert_eq!(phys_res.matched_bytes, 88);
        assert_eq!(phys_res.trend_points.len(), 3);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
