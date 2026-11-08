use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

// ============================================================
// O(1) 令牌桶 IP 级限速引擎 (Token Bucket Per-IP Rate Limiter)
// 时间复杂度: O(1) amortized per call
// 空间复杂度: O(M), M = 历史唯一 IP 数量
// ============================================================

/// 单个 IP 的令牌桶状态
struct Bucket {
    tokens: f64,
    capacity: f64,
    fill_rate: f64, // tokens/second
    last_refill: Instant,
}

impl Bucket {
    fn new(capacity: f64, fill_rate: f64) -> Self {
        Self {
            tokens: capacity,
            capacity,
            fill_rate,
            last_refill: Instant::now(),
        }
    }

    /// 尝试消费一个令牌。若令牌耗尽，返回 false（表示该 IP 超频，应阻断）。
    /// 每次调用前自动按时间差补充令牌（Lazy Refill，避免全局扫描开销）。
    fn consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.fill_rate).min(self.capacity);
        self.last_refill = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true  // 有令牌，放行
        } else {
            false // 无令牌，阻断
        }
    }
}

/// 全局限速引擎（线程安全单例）
pub struct TokenBucketIpFilter {
    buckets: HashMap<IpAddr, Bucket>,
    capacity: f64,
    fill_rate: f64,
}

impl TokenBucketIpFilter {
    pub fn new(capacity: f64, fill_rate: f64) -> Self {
        Self {
            buckets: HashMap::new(),
            capacity,
            fill_rate,
        }
    }

    /// 对指定 IP 消费令牌。返回 true 表示该 IP 已超频（应阻断/丢弃该帧）。
    pub fn is_throttled(&mut self, ip: &str) -> bool {
        let addr: IpAddr = match ip.parse() {
            Ok(a) => a,
            Err(_) => return false, // 无法解析的 IP 默认放行（如 LOCAL_SERIAL）
        };

        let (cap, rate) = (self.capacity, self.fill_rate);
        let bucket = self.buckets.entry(addr).or_insert_with(|| Bucket::new(cap, rate));
        !bucket.consume() // consume 返回 true 表示放行，取反表示阻断
    }

    /// 清理长时间未活跃的 IP 桶（防止 HashMap 无限膨胀，建议每 300 秒调用一次）
    pub fn gc(&mut self) {
        self.buckets.retain(|_, b| {
            b.last_refill.elapsed().as_secs() < 300
        });
    }
}

/// 全局令牌桶单例（默认容量 50 包，每秒补充 50 令牌）
/// 可通过 Tauri Command 动态更新阈值
pub static GLOBAL_THROTTLE: Lazy<Arc<Mutex<TokenBucketIpFilter>>> = Lazy::new(|| {
    Arc::new(Mutex::new(TokenBucketIpFilter::new(50.0, 50.0)))
});

/// 全局威胁阻断计数（用于 metrics 暴露）
pub static THREATS_BLOCKED: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// 上次 GC 时间戳（周期清理不活跃 IP 桶，防止 HashMap 无限膨胀）
static LAST_GC: Lazy<Mutex<Instant>> = Lazy::new(|| Mutex::new(Instant::now()));

/// 对外接口：判断是否应阻断来自该 IP 的数据包
/// 返回 true = 超频阻断，返回 false = 正常放行
pub fn check_and_throttle(src_ip: &str) -> bool {
    if src_ip.is_empty() || src_ip == "LOCAL_SERIAL" || src_ip == "USB_CONTROLLER" {
        return false;
    }
    let throttled = GLOBAL_THROTTLE
        .lock()
        .map(|mut t| t.is_throttled(src_ip))
        .unwrap_or(false);

    // 周期 GC 接线：每 300 秒清理一次超过 300 秒未活跃的 IP 桶
    // （修复原缺陷：gc() 从未被任何调用方触发，扫描源 IP 数量大时内存无限增长）
    if let Ok(mut last) = LAST_GC.lock() {
        if last.elapsed().as_secs() >= 300 {
            *last = Instant::now();
            if let Ok(mut t) = GLOBAL_THROTTLE.lock() {
                t.gc();
            }
        }
    }

    if throttled {
        THREATS_BLOCKED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    throttled
}

/// 动态更新全局限速阈值（通过 Tauri Command 下发）
pub fn update_throttle_config(capacity: f64, fill_rate: f64) {
    if let Ok(mut t) = GLOBAL_THROTTLE.lock() {
        t.capacity = capacity;
        t.fill_rate = fill_rate;
        // 清空旧桶，以新阈值重新开始
        t.buckets.clear();
    }
}
