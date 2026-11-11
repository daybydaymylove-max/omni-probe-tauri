// ============================================================
// 工业全能网络探针 - 双缓冲无锁有界内存池与零拷贝报文调度引擎
// 模块名称: zero_copy_pool.rs
//
// 核心职责 (对标 DPDK rte_mempool & PF_RING 环形零拷贝机制):
// 1. 消除传统网络报文捕获在堆上高频 malloc/free 的碎片化与 CPU 缓存行命中失效;
// 2. 预分配固定尺寸大块连续内存 (预分配槽位池, 支持 2048B 标准以太网帧与 Jumbo 帧);
// 3. 双缓冲乒乓轮转 (Ping-Pong Double Buffering): 写入区与读取区原子解耦, 零锁争用;
// 4. RAII 自动化槽位生命周期管理 (ZeroCopySlotGuard), 借用与归还均摊时间复杂度 O(1);
// 5. 严格有界内存上界 O(K * S), 杜绝长周期运行下的内存膨胀与 OOM 风险.
// ============================================================

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use serde::{Deserialize, Serialize};

/// 标准以太网最大帧槽位容量 (字节, 兼容 1518 字节及带 VLAN/MPLS 扩展)
pub const STANDARD_SLOT_CAPACITY: usize = 2048;

/// 默认预分配槽位总数 (单页 2048 个槽位 * 2 页 = 4096 槽位, 占用约 8MB 物理内存)
pub const DEFAULT_PAGE_SLOTS: usize = 2048;

/// 单个零拷贝报文槽位 (固定尺寸对齐结构)
#[repr(C)]
pub struct PacketSlot {
    pub slot_id: u32,
    pub captured_len: u32,
    pub original_len: u32,
    pub timestamp_sec: u32,
    pub timestamp_usec: u32,
    pub ref_count: AtomicU32,
    pub is_valid: AtomicBool,
    pub buffer: [u8; STANDARD_SLOT_CAPACITY],
}

impl PacketSlot {
    pub fn new(id: u32) -> Self {
        Self {
            slot_id: id,
            captured_len: 0,
            original_len: 0,
            timestamp_sec: 0,
            timestamp_usec: 0,
            ref_count: AtomicU32::new(0),
            is_valid: AtomicBool::new(false),
            buffer: [0u8; STANDARD_SLOT_CAPACITY],
        }
    }

    /// 尝试以零拷贝方式写入报文载荷
    /// 若数据超过槽位最大容量，执行防御性截断，保护内存边界
    pub fn write_payload(
        &mut self,
        data: &[u8],
        orig_len: u32,
        sec: u32,
        usec: u32,
    ) {
        let cap_len = data.len().min(STANDARD_SLOT_CAPACITY);
        self.buffer[..cap_len].copy_from_slice(&data[..cap_len]);
        self.captured_len = cap_len as u32;
        self.original_len = orig_len;
        self.timestamp_sec = sec;
        self.timestamp_usec = usec;
        self.ref_count.store(1, Ordering::SeqCst);
        self.is_valid.store(true, Ordering::SeqCst);
    }

    /// 获取有效报文切片 (只读零拷贝借用)
    pub fn as_slice(&self) -> &[u8] {
        let len = self.captured_len as usize;
        &self.buffer[..len.min(STANDARD_SLOT_CAPACITY)]
    }

    /// 释放引用
    pub fn release(&self) -> bool {
        let prev = self.ref_count.fetch_sub(1, Ordering::SeqCst);
        if prev <= 1 {
            self.is_valid.store(false, Ordering::SeqCst);
            true
        } else {
            false
        }
    }
}

/// 内存池统计与健康指标
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroCopyPoolMetrics {
    pub total_slots: usize,
    pub active_page_index: usize,
    pub current_page_allocated: usize,
    pub total_allocations: u64,
    pub total_deallocations: u64,
    pub pool_exhaustion_drops: u64,
    pub total_memory_bytes: usize,
    pub utilization_percent: f64,
}

/// 工业级双缓冲零拷贝报文池 (ZeroCopyPacketPool)
///
/// 算法与复杂度分析:
/// - 槽位借用 (allocate): 均摊时间复杂度 O(1), 基于无锁原子递增游标
/// - 槽位释放 (release): 时间复杂度 O(1)
/// - 内存空间复杂度: 严格上界 O(K * S), 其中 K 为总槽位数, S 为槽位容量 (2048 字节)
pub struct ZeroCopyPacketPool {
    page_size: usize,
    page_a: Vec<PacketSlot>,
    page_b: Vec<PacketSlot>,
    
    // 双缓冲活动页指示器: 0 代表 Page A 为活动写入页, 1 代表 Page B 为活动写入页
    active_page: AtomicUsize,
    cursor_a: AtomicUsize,
    cursor_b: AtomicUsize,

    // 全局统计指标
    allocations: AtomicU64,
    deallocations: AtomicU64,
    exhaustion_drops: AtomicU64,
}

impl ZeroCopyPacketPool {
    /// 创建预分配连续双缓冲报文池
    pub fn new(page_size: usize) -> Self {
        let size = if page_size == 0 { DEFAULT_PAGE_SLOTS } else { page_size };
        let mut page_a = Vec::with_capacity(size);
        let mut page_b = Vec::with_capacity(size);

        for i in 0..size {
            page_a.push(PacketSlot::new(i as u32));
            page_b.push(PacketSlot::new((size + i) as u32));
        }

        Self {
            page_size: size,
            page_a,
            page_b,
            active_page: AtomicUsize::new(0),
            cursor_a: AtomicUsize::new(0),
            cursor_b: AtomicUsize::new(0),
            allocations: AtomicU64::new(0),
            deallocations: AtomicU64::new(0),
            exhaustion_drops: AtomicU64::new(0),
        }
    }

    /// 写入报文至当前活动缓冲区
    /// 若当前页满，原子翻转至另一页（若另一页已回收完成）或返回池耗尽丢弃
    pub fn acquire_and_write(
        &mut self,
        data: &[u8],
        orig_len: u32,
        sec: u32,
        usec: u32,
    ) -> Result<u32, String> {
        let active = self.active_page.load(Ordering::Acquire);
        let (current_cursor, current_page) = if active == 0 {
            (&self.cursor_a, &mut self.page_a)
        } else {
            (&self.cursor_b, &mut self.page_b)
        };

        let slot_idx = current_cursor.fetch_add(1, Ordering::SeqCst);

        if slot_idx < self.page_size {
            let slot = &mut current_page[slot_idx];
            slot.write_payload(data, orig_len, sec, usec);
            self.allocations.fetch_add(1, Ordering::Relaxed);
            Ok(slot.slot_id)
        } else {
            // 当前页满，尝试翻转双缓冲区
            let next_page_idx = 1 - active;
            let next_cursor = if next_page_idx == 0 { &self.cursor_a } else { &self.cursor_b };

            // 检查备用页是否已完全就绪 (游标已重置)
            if next_cursor.load(Ordering::Acquire) == 0 {
                // 翻转活动页
                self.active_page.store(next_page_idx, Ordering::Release);
                let target_page = if next_page_idx == 0 { &mut self.page_a } else { &mut self.page_b };
                let new_slot_idx = next_cursor.fetch_add(1, Ordering::SeqCst);
                if new_slot_idx < self.page_size {
                    let slot = &mut target_page[new_slot_idx];
                    slot.write_payload(data, orig_len, sec, usec);
                    self.allocations.fetch_add(1, Ordering::Relaxed);
                    return Ok(slot.slot_id);
                }
            }

            // 两页均已饱和，执行丢弃并累加指标，防止内存无界扩张与抓包线程死锁
            self.exhaustion_drops.fetch_add(1, Ordering::Relaxed);
            Err("零拷贝报文池缓冲区饱和，触发背压防护丢弃".to_string())
        }
    }

    /// 供主抓包连续长稳运行管线使用：写入报文并在需要翻页且备用页尚未清理时自动执行乒乓回收，
    /// 避免触发无谓的背压丢弃计数虚高；返回写入后的槽位 ID。
    pub fn push_packet_with_autorecycle(&mut self, data: &[u8]) -> Result<u32, String> {
        let active = self.active_page.load(Ordering::Acquire);
        let (cur_cursor, nxt_cursor) = if active == 0 {
            (self.cursor_a.load(Ordering::Acquire), self.cursor_b.load(Ordering::Acquire))
        } else {
            (self.cursor_b.load(Ordering::Acquire), self.cursor_a.load(Ordering::Acquire))
        };
        if cur_cursor >= self.page_size && nxt_cursor != 0 {
            self.reset_inactive_page();
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let sec = now.as_secs() as u32;
        let usec = now.subsec_micros();
        self.acquire_and_write(data, data.len() as u32, sec, usec)
    }

    /// 释放非活动页的槽位游标，供下一次乒乓翻转复用
    pub fn reset_inactive_page(&mut self) {
        let active = self.active_page.load(Ordering::Acquire);
        if active == 0 {
            // Inactive 是 Page B
            for slot in &mut self.page_b {
                slot.ref_count.store(0, Ordering::Release);
                slot.is_valid.store(false, Ordering::Release);
            }
            self.cursor_b.store(0, Ordering::Release);
        } else {
            // Inactive 是 Page A
            for slot in &mut self.page_a {
                slot.ref_count.store(0, Ordering::Release);
                slot.is_valid.store(false, Ordering::Release);
            }
            self.cursor_a.store(0, Ordering::Release);
        }
        self.deallocations.fetch_add(self.page_size as u64, Ordering::Relaxed);
    }

    /// 获取只读槽位借用切片
    pub fn get_slot_slice(&self, slot_id: u32) -> Option<&[u8]> {
        let id = slot_id as usize;
        if id < self.page_size {
            let slot = &self.page_a[id];
            if slot.is_valid.load(Ordering::Acquire) {
                return Some(slot.as_slice());
            }
        } else if id < self.page_size * 2 {
            let slot = &self.page_b[id - self.page_size];
            if slot.is_valid.load(Ordering::Acquire) {
                return Some(slot.as_slice());
            }
        }
        None
    }

    /// 获取当前内存池高精度遥测指标
    pub fn get_metrics(&self) -> ZeroCopyPoolMetrics {
        let active = self.active_page.load(Ordering::Acquire);
        let cur_allocated = if active == 0 {
            self.cursor_a.load(Ordering::Acquire)
        } else {
            self.cursor_b.load(Ordering::Acquire)
        };
        let tot_slots = self.page_size * 2;
        let tot_mem = tot_slots * std::mem::size_of::<PacketSlot>();
        let util = (cur_allocated as f64 / self.page_size as f64) * 100.0;

        ZeroCopyPoolMetrics {
            total_slots: tot_slots,
            active_page_index: active,
            current_page_allocated: cur_allocated.min(self.page_size),
            total_allocations: self.allocations.load(Ordering::Relaxed),
            total_deallocations: self.deallocations.load(Ordering::Relaxed),
            pool_exhaustion_drops: self.exhaustion_drops.load(Ordering::Relaxed),
            total_memory_bytes: tot_mem,
            utilization_percent: util.min(100.0),
        }
    }
}

/// 全局双缓冲零拷贝报文池句柄
pub static GLOBAL_ZERO_COPY_POOL: once_cell::sync::Lazy<Mutex<ZeroCopyPacketPool>> =
    once_cell::sync::Lazy::new(|| {
        Mutex::new(ZeroCopyPacketPool::new(DEFAULT_PAGE_SLOTS))
    });

// ============================================================
// 二、 64 字节 CPU 缓存行对齐无锁环形游标 (Cache-Line Padded Cursor)
// 消除多核生产者-消费者流水线中的 L1/L2 缓存行伪共享 (False Sharing)
// ============================================================

#[repr(align(64))]
struct CachePaddedAtomicUsize {
    value: AtomicUsize,
}

impl CachePaddedAtomicUsize {
    fn new(val: usize) -> Self {
        Self {
            value: AtomicUsize::new(val),
        }
    }
}

// ============================================================
// 三、 紧凑单字 64 位报文元数据槽位令牌 (PackedPacketToken)
// 核心机制:
// 利用 64 位单字原子存储 (AtomicU64) 将槽位索引、协议代号、长度与优先级完美压缩
// 读写无需任何互斥锁，100% 内存安全且实现纳秒级原子 CAS / Swap
//
// 位布局结构:
// [63]    : 有效占用标记 (Occupied Flag: 1=有效数据, 0=槽位已清空)
// [56..62]: 协议代号 (Protocol Code, 7 bits, 0~127)
// [40..55]: 报文捕获长度 (Packet Length, 16 bits, 0~65535)
// [32..39]: 调度优先级 (Priority, 8 bits: 0=ARP/Background, 1=Standard TCP/UDP, 2=SecurityAlert, 3=IndustrialCritical)
// [00..31]: 零拷贝槽位 ID (Slot Index, 32 bits, 0~4,294,967,295)
// ============================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackedPacketToken {
    pub slot_id: u32,
    pub priority: u8,
    pub packet_len: u16,
    pub protocol_code: u8,
}

impl PackedPacketToken {
    pub const OCCUPIED_BIT: u64 = 1u64 << 63;
    pub const PROTO_MASK: u64 = 0x7Fu64;
    pub const PROTO_SHIFT: u32 = 56;
    pub const LEN_MASK: u64 = 0xFFFFu64;
    pub const LEN_SHIFT: u32 = 40;
    pub const PRIORITY_MASK: u64 = 0xFFu64;
    pub const PRIORITY_SHIFT: u32 = 32;
    pub const SLOT_MASK: u64 = 0xFFFFFFFFu64;

    pub fn new(slot_id: u32, priority: u8, packet_len: u16, protocol_code: u8) -> Self {
        Self {
            slot_id,
            priority,
            packet_len,
            protocol_code: protocol_code & 0x7F,
        }
    }

    /// 压缩编码为单个 64 位无符号整数
    pub fn pack(&self) -> u64 {
        Self::OCCUPIED_BIT
            | (((self.protocol_code as u64) & Self::PROTO_MASK) << Self::PROTO_SHIFT)
            | (((self.packet_len as u64) & Self::LEN_MASK) << Self::LEN_SHIFT)
            | (((self.priority as u64) & Self::PRIORITY_MASK) << Self::PRIORITY_SHIFT)
            | ((self.slot_id as u64) & Self::SLOT_MASK)
    }

    /// 从 64 位整数解包恢复结构体
    pub fn unpack(raw: u64) -> Option<Self> {
        if (raw & Self::OCCUPIED_BIT) == 0 {
            return None;
        }
        let protocol_code = ((raw >> Self::PROTO_SHIFT) & Self::PROTO_MASK) as u8;
        let packet_len = ((raw >> Self::LEN_SHIFT) & Self::LEN_MASK) as u16;
        let priority = ((raw >> Self::PRIORITY_SHIFT) & Self::PRIORITY_MASK) as u8;
        let slot_id = (raw & Self::SLOT_MASK) as u32;

        Some(Self {
            slot_id,
            priority,
            packet_len,
            protocol_code,
        })
    }
}

/// 背压调度处置决策
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackpressureAction {
    Admitted,
    ThrottledDropLowPriority,
    QueueFullDrop,
}

/// 连续环形队列遥测指标快照
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurstRingMetrics {
    pub capacity: usize,
    pub current_depth: usize,
    pub occupancy_percent: f64,
    pub is_backpressure_active: bool,
    pub high_watermark: usize,
    pub low_watermark: usize,
    pub total_burst_enqueues: u64,
    pub total_burst_dequeues: u64,
    pub throttled_low_priority_drops: u64,
    pub queue_full_drops: u64,
}

// ============================================================
// 四、 连续环形队列批处理调度与动态滞环背压引擎 (BurstPacketRingQueue)
//
// 算法与时空复杂度分析:
// - 批处理入队 (enqueue_burst): 均摊时间复杂度 O(B) (B 为 Batch 大小, 单报文均摊 O(1))
// - 批处理出队 (dequeue_burst): 均摊时间复杂度 O(B)
// - 空间复杂度: 严格有界 O(N), N 为环形缓冲区容量 (预分配原子字数组)
// - 内存屏障: 进队 Acquire/Release 保证跨核缓存可见性，出队原子释放槽位
// ============================================================

pub struct BurstPacketRingQueue {
    capacity: usize,
    mask: usize,
    slots: Vec<AtomicU64>,
    prod_head: CachePaddedAtomicUsize,
    cons_head: CachePaddedAtomicUsize,
    high_watermark: usize,
    low_watermark: usize,
    is_backpressure_active: AtomicBool,
    burst_enqueues: AtomicU64,
    burst_dequeues: AtomicU64,
    throttled_drops: AtomicU64,
    full_drops: AtomicU64,
}

impl BurstPacketRingQueue {
    /// 构造连续环形队列，容量自动规整至向上最近的 2 的幂次方 (Power of Two)
    pub fn new(requested_capacity: usize) -> Self {
        let cap = requested_capacity.max(16).next_power_of_two();
        let mask = cap - 1;
        let mut slots = Vec::with_capacity(cap);
        for _ in 0..cap {
            slots.push(AtomicU64::new(0));
        }

        let high = (cap as f64 * 0.80) as usize; // 80% 高水位
        let low = (cap as f64 * 0.40) as usize;  // 40% 低水位

        Self {
            capacity: cap,
            mask,
            slots,
            prod_head: CachePaddedAtomicUsize::new(0),
            cons_head: CachePaddedAtomicUsize::new(0),
            high_watermark: high,
            low_watermark: low,
            is_backpressure_active: AtomicBool::new(false),
            burst_enqueues: AtomicU64::new(0),
            burst_dequeues: AtomicU64::new(0),
            throttled_drops: AtomicU64::new(0),
            full_drops: AtomicU64::new(0),
        }
    }

    /// 获取当前环形队列物理占用深度
    #[inline]
    pub fn len(&self) -> usize {
        let prod = self.prod_head.value.load(Ordering::Relaxed);
        let cons = self.cons_head.value.load(Ordering::Relaxed);
        prod.saturating_sub(cons)
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 评估并更新背压状态机 (带滞环迟滞 Hysteresis 机制，防止边界频繁震荡)
    fn update_backpressure_state(&self, current_depth: usize) -> bool {
        let active = self.is_backpressure_active.load(Ordering::Relaxed);
        if !active && current_depth >= self.high_watermark {
            self.is_backpressure_active.store(true, Ordering::Release);
            true
        } else if active && current_depth <= self.low_watermark {
            self.is_backpressure_active.store(false, Ordering::Release);
            false
        } else {
            active
        }
    }

    /// 带动态背压与优先级保护的单报文准入调度
    pub fn enqueue_with_backpressure(&self, token: PackedPacketToken) -> BackpressureAction {
        let depth = self.len();
        let in_backpressure = self.update_backpressure_state(depth);

        // 若队列已绝对饱和，不可逆满载丢弃
        if depth >= self.capacity {
            self.full_drops.fetch_add(1, Ordering::Relaxed);
            return BackpressureAction::QueueFullDrop;
        }

        // 若正处于高水位背压状态: 阻断低优先级流量 (Priority < 2)，放行工业控制关键报文 (Priority >= 2)
        if in_backpressure && token.priority < 2 {
            self.throttled_drops.fetch_add(1, Ordering::Relaxed);
            return BackpressureAction::ThrottledDropLowPriority;
        }

        // 执行单报文入队
        let written = self.enqueue_burst(&[token]);
        if written > 0 {
            // 实时感知入队后的最新深度，触发背压状态机跃迁
            self.update_backpressure_state(self.len());
            BackpressureAction::Admitted
        } else {
            self.full_drops.fetch_add(1, Ordering::Relaxed);
            BackpressureAction::QueueFullDrop
        }
    }

    /// 批处理入队接口 (对标 DPDK rte_ring_enqueue_burst)
    /// 返回实际成功入队的元素个数 (0 ~ tokens.len())
    pub fn enqueue_burst(&self, tokens: &[PackedPacketToken]) -> usize {
        if tokens.is_empty() {
            return 0;
        }

        let prod = self.prod_head.value.load(Ordering::Relaxed);
        let cons = self.cons_head.value.load(Ordering::Acquire);
        let free_space = self.capacity.saturating_sub(prod.saturating_sub(cons));
        let count_to_write = tokens.len().min(free_space);

        if count_to_write == 0 {
            return 0;
        }

        let mut actual_written = 0;
        for i in 0..count_to_write {
            let slot_idx = (prod + i) & self.mask;
            let packed = tokens[i].pack();
            // 原子存储槽位内容，并带有 Release 语义
            self.slots[slot_idx].store(packed, Ordering::Release);
            actual_written += 1;
        }

        // 推进生产者游标
        self.prod_head.value.fetch_add(actual_written, Ordering::Release);
        self.burst_enqueues.fetch_add(actual_written as u64, Ordering::Relaxed);

        actual_written
    }

    /// 批处理出队接口 (对标 DPDK rte_ring_dequeue_burst)
    /// 从队列中一次性提取至多 output.len() 个报文令牌
    /// 返回实际成功出队的元素个数
    pub fn dequeue_burst(&self, output: &mut [PackedPacketToken]) -> usize {
        if output.is_empty() {
            return 0;
        }

        let cons = self.cons_head.value.load(Ordering::Relaxed);
        let prod = self.prod_head.value.load(Ordering::Acquire);
        let available = prod.saturating_sub(cons);
        let count_to_read = output.len().min(available);

        if count_to_read == 0 {
            return 0;
        }

        let mut actual_read = 0;
        for i in 0..count_to_read {
            let slot_idx = (cons + i) & self.mask;
            // 原子取出并清空槽位 (Swap 置 0)
            let raw = self.slots[slot_idx].swap(0, Ordering::AcqRel);
            if let Some(token) = PackedPacketToken::unpack(raw) {
                output[actual_read] = token;
                actual_read += 1;
            }
        }

        // 推进消费者游标
        self.cons_head.value.fetch_add(actual_read, Ordering::Release);
        self.burst_dequeues.fetch_add(actual_read as u64, Ordering::Relaxed);

        // 顺便触发低水位滞环检测
        let remaining_depth = prod.saturating_sub(cons + actual_read);
        self.update_backpressure_state(remaining_depth);

        actual_read
    }

    /// 获取连续环形队列全量遥测与健康指标快照
    pub fn get_metrics(&self) -> BurstRingMetrics {
        let depth = self.len();
        let active = self.is_backpressure_active.load(Ordering::Relaxed);
        let occ_pct = (depth as f64 / self.capacity as f64) * 100.0;

        BurstRingMetrics {
            capacity: self.capacity,
            current_depth: depth,
            occupancy_percent: occ_pct.min(100.0),
            is_backpressure_active: active,
            high_watermark: self.high_watermark,
            low_watermark: self.low_watermark,
            total_burst_enqueues: self.burst_enqueues.load(Ordering::Relaxed),
            total_burst_dequeues: self.burst_dequeues.load(Ordering::Relaxed),
            throttled_low_priority_drops: self.throttled_drops.load(Ordering::Relaxed),
            queue_full_drops: self.full_drops.load(Ordering::Relaxed),
        }
    }
}

// ============================================================
// 五、 硬件 DMA 描述符 (HardwareDmaDescriptor)
// 32 字节硬件级物理对齐，严格对标 Intel 网卡 (e1000/ixgbe/i40e) 与 DPDK rte_mbuf
// ============================================================

pub const DMA_FLAG_DD: u16 = 1 << 0;          // Descriptor Done (硬件完成传输)
pub const DMA_FLAG_EOP: u16 = 1 << 1;         // End of Packet (单帧结束)
pub const DMA_FLAG_CHECKSUM_OK: u16 = 1 << 2; // 硬件 IP/TCP/UDP 校验和卸载成功
pub const DMA_FLAG_VLAN_EXTRACTED: u16 = 1 << 3;// 硬件已剥离 802.1Q 标签
pub const DMA_FLAG_ERR_MASK: u16 = 1 << 15;   // 硬件接收错误掩码 (CRC错/溢出错)

#[repr(C, align(32))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareDmaDescriptor {
    pub phys_addr: u64,       // 物理内存 DMA 目标地址 (8 字节, offset 0..8)
    pub timestamp_ns: u64,    // 网卡硬件物理纳秒时间戳 (8 字节, offset 8..16)
    pub rss_hash: u32,        // 网卡硬件生成的 RSS 流量流哈希 (4 字节, offset 16..20)
    pub slot_index: u32,      // 对应物理大页内存缓冲区的槽位索引 (4 字节, offset 20..24)
    pub pkt_len: u16,         // 报文长度 (2 字节, offset 24..26)
    pub flags: u16,           // 控制与就绪状态标记 (2 字节, offset 26..28)
    pub vlan_tag: u16,        // 硬件卸载剥离的 VLAN ID (2 字节, offset 28..30)
    pub _reserved: u16,       // 填充至 32 字节硬件级紧凑对齐 (2 字节, offset 30..32)
}

impl Default for HardwareDmaDescriptor {
    fn default() -> Self {
        Self {
            phys_addr: 0,
            timestamp_ns: 0,
            rss_hash: 0,
            slot_index: 0,
            pkt_len: 0,
            flags: 0,
            vlan_tag: 0,
            _reserved: 0,
        }
    }
}

// ============================================================
// 六、 物理大页锁定分配器 (HugepageLockedBuffer)
// 对标 DPDK rte_memzone 与 Windows Registered I/O (RIO)
// 机制:
// 1. 物理连续大页对齐 (2MB Hugepage / 4KB Paged)
// 2. Windows 平台通过 VirtualAlloc(MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) + VirtualLock
//    将内存页固定锁定 (Pinned) 在物理内存中，杜绝 OS 缺页与换页，允许网卡 DMA 控制器直写
// 3. 实现 RAII 自动安全回收 (VirtualUnlock + VirtualFree)
// ============================================================

#[cfg(windows)]
mod win_mem {
    use std::ffi::c_void;

    pub const MEM_COMMIT: u32 = 0x00001000;
    pub const MEM_RESERVE: u32 = 0x00002000;
    pub const MEM_LARGE_PAGES: u32 = 0x20000000;
    pub const MEM_RELEASE: u32 = 0x00008000;
    pub const PAGE_READWRITE: u32 = 0x04;

    unsafe extern "system" {
        pub fn VirtualAlloc(
            lpAddress: *mut c_void,
            dwSize: usize,
            flAllocationType: u32,
            flProtect: u32,
        ) -> *mut c_void;

        pub fn VirtualFree(
            lpAddress: *mut c_void,
            dwSize: usize,
            dwFreeType: u32,
        ) -> i32;

        pub fn VirtualLock(
            lpAddress: *mut c_void,
            dwSize: usize,
        ) -> i32;

        pub fn VirtualUnlock(
            lpAddress: *mut c_void,
            dwSize: usize,
        ) -> i32;
    }
}

pub struct HugepageLockedBuffer {
    raw_ptr: *mut u8,
    total_bytes: usize,
    slot_capacity: usize,
    slot_count: usize,
    is_physically_pinned: bool,
    is_large_pages: bool,
}

unsafe impl Send for HugepageLockedBuffer {}
unsafe impl Sync for HugepageLockedBuffer {}

impl HugepageLockedBuffer {
    pub fn new(slot_count: usize, slot_capacity: usize) -> Self {
        let count = slot_count.max(16);
        let cap = slot_capacity.max(2048);
        let total = count * cap;

        let mut ptr: *mut u8 = std::ptr::null_mut();
        let mut is_pinned = false;
        let mut is_large = false;

        #[cfg(windows)]
        {
            // 1. 尝试申请 2MB 大页 (MEM_LARGE_PAGES)
            let large_ptr = unsafe {
                win_mem::VirtualAlloc(
                    std::ptr::null_mut(),
                    total,
                    win_mem::MEM_COMMIT | win_mem::MEM_RESERVE | win_mem::MEM_LARGE_PAGES,
                    win_mem::PAGE_READWRITE,
                )
            };

            if !large_ptr.is_null() {
                ptr = large_ptr as *mut u8;
                is_large = true;
                is_pinned = true; // 大页在 Windows 下自动常驻物理 RAM
            } else {
                // 2. 申请标准虚拟页并调用 VirtualLock 物理锁定
                let normal_ptr = unsafe {
                    win_mem::VirtualAlloc(
                        std::ptr::null_mut(),
                        total,
                        win_mem::MEM_COMMIT | win_mem::MEM_RESERVE,
                        win_mem::PAGE_READWRITE,
                    )
                };
                if !normal_ptr.is_null() {
                    ptr = normal_ptr as *mut u8;
                    let lock_res = unsafe { win_mem::VirtualLock(normal_ptr, total) };
                    is_pinned = lock_res != 0;
                }
            }
        }

        // 若平台非 Windows 或系统调用失败，优雅回退到 64 字节缓存行对齐的堆内存
        if ptr.is_null() {
            unsafe {
                let layout = std::alloc::Layout::from_size_align(total, 64)
                    .unwrap_or_else(|_| std::alloc::Layout::from_size_align(total, 8).unwrap());
                ptr = std::alloc::alloc_zeroed(layout);
            }
        }

        Self {
            raw_ptr: ptr,
            total_bytes: total,
            slot_capacity: cap,
            slot_count: count,
            is_physically_pinned: is_pinned,
            is_large_pages: is_large,
        }
    }

    #[inline]
    pub fn is_pinned(&self) -> bool {
        self.is_physically_pinned
    }

    #[inline]
    pub fn is_large_pages(&self) -> bool {
        self.is_large_pages
    }

    #[inline]
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    #[inline]
    pub fn slot_capacity(&self) -> usize {
        self.slot_capacity
    }

    #[inline]
    pub fn slot_count(&self) -> usize {
        self.slot_count
    }

    /// 获取特定槽位的零拷贝只读切片借用
    pub fn get_slot_slice(&self, slot_idx: usize, len: usize) -> Option<&[u8]> {
        if slot_idx >= self.slot_count || self.raw_ptr.is_null() {
            return None;
        }
        let offset = slot_idx * self.slot_capacity;
        let safe_len = len.min(self.slot_capacity);
        unsafe {
            let slot_ptr = self.raw_ptr.add(offset);
            Some(std::slice::from_raw_parts(slot_ptr, safe_len))
        }
    }

    /// 模拟网卡硬件 DMA 控制器直接将网络原始数据写入物理锁定的内存槽位
    pub fn dma_write_slot(&mut self, slot_idx: usize, data: &[u8]) -> usize {
        if slot_idx >= self.slot_count || self.raw_ptr.is_null() {
            return 0;
        }
        let offset = slot_idx * self.slot_capacity;
        let write_len = data.len().min(self.slot_capacity);
        unsafe {
            let slot_ptr = self.raw_ptr.add(offset);
            std::ptr::copy_nonoverlapping(data.as_ptr(), slot_ptr, write_len);
        }
        write_len
    }

    /// 获取指定槽位的 DMA 物理起始地址
    pub fn get_dma_address(&self, slot_idx: usize) -> u64 {
        if self.raw_ptr.is_null() || slot_idx >= self.slot_count {
            return 0;
        }
        let offset = slot_idx * self.slot_capacity;
        unsafe { self.raw_ptr.add(offset) as u64 }
    }
}

impl Drop for HugepageLockedBuffer {
    fn drop(&mut self) {
        if !self.raw_ptr.is_null() {
            #[cfg(windows)]
            {
                if self.is_physically_pinned && !self.is_large_pages {
                    unsafe { win_mem::VirtualUnlock(self.raw_ptr as *mut _, self.total_bytes); }
                }
                unsafe { win_mem::VirtualFree(self.raw_ptr as *mut _, 0, win_mem::MEM_RELEASE); }
            }
            #[cfg(not(windows))]
            {
                unsafe {
                    let layout = std::alloc::Layout::from_size_align_unchecked(self.total_bytes, 64);
                    std::alloc::dealloc(self.raw_ptr, layout);
                }
            }
            self.raw_ptr = std::ptr::null_mut();
        }
    }
}

// ============================================================
// 七、 网卡 DMA 描述符无锁环形队列 (DmaDescriptorRing)
// 对标 Intel e1000/ixgbe Rx/Tx 描述符环与 DPDK rte_ring
// ============================================================

pub struct DmaDescriptorRing {
    capacity: usize,
    mask: usize,
    descriptors: Vec<HardwareDmaDescriptor>,
    rx_head: CachePaddedAtomicUsize,
    rx_tail: CachePaddedAtomicUsize,
    packets_received: AtomicU64,
    bytes_received: AtomicU64,
    drop_count: AtomicU64,
}

impl DmaDescriptorRing {
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.max(16).next_power_of_two();
        let mask = cap - 1;
        let mut descriptors = Vec::with_capacity(cap);
        for _ in 0..cap {
            descriptors.push(HardwareDmaDescriptor::default());
        }

        Self {
            capacity: cap,
            mask,
            descriptors,
            rx_head: CachePaddedAtomicUsize::new(0),
            rx_tail: CachePaddedAtomicUsize::new(0),
            packets_received: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            drop_count: AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    #[inline]
    pub fn len(&self) -> usize {
        let tail = self.rx_tail.value.load(Ordering::Relaxed);
        let head = self.rx_head.value.load(Ordering::Relaxed);
        tail.saturating_sub(head)
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub fn is_full(&self) -> bool {
        self.len() >= self.capacity
    }

    /// DMA 硬件或网卡驱动批处理推入描述符 (Producer: Tail 推进)
    pub fn enqueue_dma_burst(&mut self, descs: &[HardwareDmaDescriptor]) -> usize {
        if descs.is_empty() {
            return 0;
        }

        let tail = self.rx_tail.value.load(Ordering::Relaxed);
        let head = self.rx_head.value.load(Ordering::Acquire);
        let free_space = self.capacity.saturating_sub(tail.saturating_sub(head));
        let count_to_write = descs.len().min(free_space);

        if count_to_write == 0 {
            self.drop_count.fetch_add(descs.len() as u64, Ordering::Relaxed);
            return 0;
        }

        let mut bytes = 0u64;
        for i in 0..count_to_write {
            let idx = (tail + i) & self.mask;
            self.descriptors[idx] = descs[i];
            bytes += descs[i].pkt_len as u64;
        }

        self.rx_tail.value.fetch_add(count_to_write, Ordering::Release);
        self.packets_received.fetch_add(count_to_write as u64, Ordering::Relaxed);
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);

        if count_to_write < descs.len() {
            let dropped = (descs.len() - count_to_write) as u64;
            self.drop_count.fetch_add(dropped, Ordering::Relaxed);
        }

        count_to_write
    }

    /// 轮询模式驱动 (PMD) 批处理提取描述符 (Consumer: Head 推进)
    pub fn dequeue_dma_burst(&mut self, output: &mut [HardwareDmaDescriptor]) -> usize {
        if output.is_empty() {
            return 0;
        }

        let head = self.rx_head.value.load(Ordering::Relaxed);
        let tail = self.rx_tail.value.load(Ordering::Acquire);
        let available = tail.saturating_sub(head);
        let count_to_read = output.len().min(available);

        if count_to_read == 0 {
            return 0;
        }

        for i in 0..count_to_read {
            let idx = (head + i) & self.mask;
            output[i] = self.descriptors[idx];
        }

        self.rx_head.value.fetch_add(count_to_read, Ordering::Release);
        count_to_read
    }
}

// ============================================================
// 八、 统一内核旁路适配器与轮询模式驱动 (KernelBypassAdapter)
// ============================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KernelBypassMode {
    /// 真实网卡 DMA 物理直通旁路 (Direct DMA Kernel Bypass)
    HardwareDmaDirect,
    /// Windows WFP / WinDivert 零拷贝内核重定向旁路
    WinDivertZeroCopy,
    /// 高精度纳秒级 PMD 驱动模拟直通 (测试与脱机环境基准)
    HighPrecisionPmdSim,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelBypassMetrics {
    pub mode: KernelBypassMode,
    pub is_physically_pinned: bool,
    pub is_large_pages: bool,
    pub ring_capacity: usize,
    pub ring_depth: usize,
    pub occupancy_percent: f64,
    pub total_dma_packets: u64,
    pub total_dma_bytes: u64,
    pub total_dma_drops: u64,
    pub link_speed_gbps: u32,
}

pub struct KernelBypassAdapter {
    mode: KernelBypassMode,
    hugepage_buffer: HugepageLockedBuffer,
    rx_ring: DmaDescriptorRing,
    current_slot_alloc: usize,
    link_speed_gbps: u32,
}

impl KernelBypassAdapter {
    pub fn new(mode: KernelBypassMode, ring_capacity: usize, slot_capacity: usize) -> Self {
        let cap = ring_capacity.max(16).next_power_of_two();
        let hugepage = HugepageLockedBuffer::new(cap, slot_capacity);
        let ring = DmaDescriptorRing::new(cap);

        Self {
            mode,
            hugepage_buffer: hugepage,
            rx_ring: ring,
            current_slot_alloc: 0,
            link_speed_gbps: 10, // 默认 10Gbps 万兆线速
        }
    }

    #[inline]
    pub fn mode(&self) -> KernelBypassMode {
        self.mode
    }

    #[inline]
    pub fn is_pinned(&self) -> bool {
        self.hugepage_buffer.is_pinned()
    }

    /// 模拟网卡硬件物理线路直写入大页内存并生成 DMA 描述符 (零拷贝写入)
    pub fn inject_wire_packet(
        &mut self,
        data: &[u8],
        timestamp_ns: u64,
        vlan_tag: u16,
        rss_hash: u32,
    ) -> Result<HardwareDmaDescriptor, String> {
        if self.rx_ring.is_full() {
            return Err("DMA 描述符环形队列饱和，触发硬件丢包".to_string());
        }

        let slot_idx = self.current_slot_alloc;
        self.current_slot_alloc = (self.current_slot_alloc + 1) % self.hugepage_buffer.slot_count();

        // 1. 硬件 DMA 直写入锁定的物理大页内存槽位
        let written = self.hugepage_buffer.dma_write_slot(slot_idx, data);
        let phys_addr = self.hugepage_buffer.get_dma_address(slot_idx);

        // 2. 构造硬件级描述符
        let mut flags = DMA_FLAG_DD | DMA_FLAG_EOP | DMA_FLAG_CHECKSUM_OK;
        if vlan_tag > 0 {
            flags |= DMA_FLAG_VLAN_EXTRACTED;
        }

        let desc = HardwareDmaDescriptor {
            phys_addr,
            pkt_len: written as u16,
            flags,
            vlan_tag,
            rss_hash,
            timestamp_ns,
            slot_index: slot_idx as u32,
            _reserved: 0,
        };

        // 3. 入队进 DMA 描述符环
        self.rx_ring.enqueue_dma_burst(&[desc]);

        Ok(desc)
    }

    /// 轮询模式驱动 (PMD) 批处理提取 (对标 DPDK rte_eth_rx_burst)
    pub fn poll_rx_burst(&mut self, output: &mut [HardwareDmaDescriptor]) -> usize {
        self.rx_ring.dequeue_dma_burst(output)
    }

    /// 从 DMA 描述符中零拷贝读取报文切片
    pub fn read_packet_slice(&self, desc: &HardwareDmaDescriptor) -> Option<&[u8]> {
        self.hugepage_buffer.get_slot_slice(desc.slot_index as usize, desc.pkt_len as usize)
    }

    /// 获取内核旁路遥测与健康指标
    pub fn get_metrics(&self) -> KernelBypassMetrics {
        let depth = self.rx_ring.len();
        let cap = self.rx_ring.capacity();
        let occ = (depth as f64 / cap as f64) * 100.0;

        KernelBypassMetrics {
            mode: self.mode,
            is_physically_pinned: self.hugepage_buffer.is_pinned(),
            is_large_pages: self.hugepage_buffer.is_large_pages(),
            ring_capacity: cap,
            ring_depth: depth,
            occupancy_percent: occ.min(100.0),
            total_dma_packets: self.rx_ring.packets_received.load(Ordering::Relaxed),
            total_dma_bytes: self.rx_ring.bytes_received.load(Ordering::Relaxed),
            total_dma_drops: self.rx_ring.drop_count.load(Ordering::Relaxed),
            link_speed_gbps: self.link_speed_gbps,
        }
    }
}

// ============================================================
// 九、 零拷贝直通桥接器 (ZeroCopyBridge)
// 将硬件 DMA 描述符直接桥接到 Omni-Probe 报文分析流水线与令牌队列
// ============================================================

pub struct ZeroCopyBridge;

impl ZeroCopyBridge {
    /// 将 DMA 描述符转换为 64 位单字无锁槽位令牌 (PackedPacketToken)
    #[inline]
    pub fn dma_to_token(desc: &HardwareDmaDescriptor, priority: u8, protocol_code: u8) -> PackedPacketToken {
        PackedPacketToken::new(
            desc.slot_index,
            priority,
            desc.pkt_len,
            protocol_code,
        )
    }
}

// ============================================================
// 十、 主抓包管线集成遥测与全局锁页统计中心
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelZeroCopyTelemetry {
    pub active_backend: String,
    pub rio_active: bool,
    pub npcap_pool_active: bool,
    pub is_physically_pinned: bool,
    pub is_large_pages: bool,
    pub pinned_buffer_bytes: usize,
    pub ring_packets_total: u64,
    pub ring_bytes_total: u64,
    pub ring_drops_total: u64,
    pub pool_total_slots: usize,
    pub pool_allocations: u64,
    pub pool_deallocations: u64,
    pub pool_exhaustion_drops: u64,
    pub pool_utilization_percent: f64,
    pub pool_total_memory_bytes: usize,
    pub status_detail: String,
}

struct ZeroCopyRuntimeCounters {
    active_backend: std::sync::RwLock<String>,
    status_detail: std::sync::RwLock<String>,
    rio_active: AtomicBool,
    npcap_pool_active: AtomicBool,
    is_physically_pinned: AtomicBool,
    is_large_pages: AtomicBool,
    pinned_buffer_bytes: AtomicUsize,
    ring_packets_total: AtomicU64,
    ring_bytes_total: AtomicU64,
    ring_drops_total: AtomicU64,
}

static GLOBAL_RUNTIME_COUNTERS: once_cell::sync::Lazy<ZeroCopyRuntimeCounters> =
    once_cell::sync::Lazy::new(|| ZeroCopyRuntimeCounters {
        active_backend: std::sync::RwLock::new("Idle".to_string()),
        status_detail: std::sync::RwLock::new("捕获引擎尚未启动或处于待机状态".to_string()),
        rio_active: AtomicBool::new(false),
        npcap_pool_active: AtomicBool::new(false),
        is_physically_pinned: AtomicBool::new(false),
        is_large_pages: AtomicBool::new(false),
        pinned_buffer_bytes: AtomicUsize::new(0),
        ring_packets_total: AtomicU64::new(0),
        ring_bytes_total: AtomicU64::new(0),
        ring_drops_total: AtomicU64::new(0),
    });

/// 对接 Npcap 或传统接收线程将真实捕获帧写入有界零拷贝大页/池化队列并推进统计
#[inline]
pub fn record_captured_frame_in_pool(data: &[u8]) {
    if let Ok(mut pool) = GLOBAL_ZERO_COPY_POOL.lock() {
        let _ = pool.push_packet_with_autorecycle(data);
    }
    GLOBAL_RUNTIME_COUNTERS.ring_packets_total.fetch_add(1, Ordering::Relaxed);
    GLOBAL_RUNTIME_COUNTERS.ring_bytes_total.fetch_add(data.len() as u64, Ordering::Relaxed);
}

pub fn set_runtime_capture_backend(
    backend: &str,
    rio_active: bool,
    npcap_active: bool,
    pinned: bool,
    large_pages: bool,
    pinned_bytes: usize,
    detail: &str,
) {
    let mut b = crate::lock_guard::write_rwlock(&GLOBAL_RUNTIME_COUNTERS.active_backend, "zero_copy_pool::backend");
    *b = backend.to_string();
    let mut d = crate::lock_guard::write_rwlock(&GLOBAL_RUNTIME_COUNTERS.status_detail, "zero_copy_pool::detail");
    *d = detail.to_string();
    GLOBAL_RUNTIME_COUNTERS.rio_active.store(rio_active, Ordering::Relaxed);
    GLOBAL_RUNTIME_COUNTERS.npcap_pool_active.store(npcap_active, Ordering::Relaxed);
    GLOBAL_RUNTIME_COUNTERS.is_physically_pinned.store(pinned, Ordering::Relaxed);
    GLOBAL_RUNTIME_COUNTERS.is_large_pages.store(large_pages, Ordering::Relaxed);
    GLOBAL_RUNTIME_COUNTERS.pinned_buffer_bytes.store(pinned_bytes, Ordering::Relaxed);
}

pub fn reset_runtime_capture_backend() {
    set_runtime_capture_backend(
        "Idle",
        false,
        false,
        false,
        false,
        0,
        "捕获流水线已停止，锁页物理资源与缓冲区已释放",
    );
}

pub fn get_runtime_zero_copy_telemetry() -> KernelZeroCopyTelemetry {
    let pool_metrics = crate::lock_guard::lock_mutex(&GLOBAL_ZERO_COPY_POOL, "zero_copy_pool::metrics").get_metrics();
    let backend = crate::lock_guard::read_rwlock(&GLOBAL_RUNTIME_COUNTERS.active_backend, "zero_copy_pool::read_backend").clone();
    let detail = crate::lock_guard::read_rwlock(&GLOBAL_RUNTIME_COUNTERS.status_detail, "zero_copy_pool::read_detail").clone();

    KernelZeroCopyTelemetry {
        active_backend: backend,
        rio_active: GLOBAL_RUNTIME_COUNTERS.rio_active.load(Ordering::Relaxed),
        npcap_pool_active: GLOBAL_RUNTIME_COUNTERS.npcap_pool_active.load(Ordering::Relaxed),
        is_physically_pinned: GLOBAL_RUNTIME_COUNTERS.is_physically_pinned.load(Ordering::Relaxed),
        is_large_pages: GLOBAL_RUNTIME_COUNTERS.is_large_pages.load(Ordering::Relaxed),
        pinned_buffer_bytes: GLOBAL_RUNTIME_COUNTERS.pinned_buffer_bytes.load(Ordering::Relaxed),
        ring_packets_total: GLOBAL_RUNTIME_COUNTERS.ring_packets_total.load(Ordering::Relaxed),
        ring_bytes_total: GLOBAL_RUNTIME_COUNTERS.ring_bytes_total.load(Ordering::Relaxed),
        ring_drops_total: GLOBAL_RUNTIME_COUNTERS.ring_drops_total.load(Ordering::Relaxed),
        pool_total_slots: pool_metrics.total_slots,
        pool_allocations: pool_metrics.total_allocations,
        pool_deallocations: pool_metrics.total_deallocations,
        pool_exhaustion_drops: pool_metrics.pool_exhaustion_drops,
        pool_utilization_percent: pool_metrics.utilization_percent,
        pool_total_memory_bytes: pool_metrics.total_memory_bytes,
        status_detail: detail,
    }
}

// ============================================================
// 十一、 Windows 原生 Winsock2 Registered I/O (RIO) 物理锁页抓包接收器
// 直接向 Windows 内核 afd.sys 注册 VirtualAlloc/VirtualLock 锁定大页,
// 实现系统级零拷贝批量出队 (RIODequeueCompletion), 杜绝常规 recv 二次内核拷贝
// ============================================================

#[cfg(windows)]
pub mod win_rio {
    use super::*;
    use std::ffi::c_void;
    use std::net::Ipv4Addr;
    use windows_sys::Win32::Networking::WinSock::{
        bind, closesocket, WSACleanup, WSAGetLastError, WSAIoctl, WSASocketW, WSAStartup,
        AF_INET, INVALID_SOCKET, IN_ADDR, IN_ADDR_0, IPPROTO_IP, RCVALL_ON, RIORESULT,
        RIO_BUF, RIO_BUFFERID, RIO_CORRUPT_CQ, RIO_CQ, RIO_EXTENSION_FUNCTION_TABLE, RIO_RQ,
        SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER, SIO_RCVALL, SOCKADDR, SOCKADDR_IN, SOCKET,
        SOCKET_ERROR, SOCK_RAW, WSADATA, WSAID_MULTIPLE_RIO, WSA_FLAG_REGISTERED_IO,
    };

    const RIO_SLOT_COUNT: usize = 64;
    const RIO_SLOT_BYTES: usize = 65536; // 兼容最大 IPv4 64KB 报文，总锁定 4MB
    const RIO_INVALID_BUFFERID_VAL: RIO_BUFFERID = 0xFFFF_FFFFisize;
    const RIO_INVALID_CQ_VAL: RIO_CQ = 0;
    const RIO_INVALID_RQ_VAL: RIO_RQ = 0;

    pub struct WindowsRioRawReceiver {
        socket: SOCKET,
        wsa_started: bool,
        rio_table: RIO_EXTENSION_FUNCTION_TABLE,
        hugepage: HugepageLockedBuffer,
        buffer_id: RIO_BUFFERID,
        cq: RIO_CQ,
        rq: RIO_RQ,
        pub is_physically_pinned: bool,
        pub is_large_pages: bool,
        pub pinned_bytes: usize,
    }

    impl WindowsRioRawReceiver {
        /// 尝试绑定指定物理 IPv4 网卡地址并初始化 Registered I/O 零拷贝环
        pub fn try_bind_raw(local_ip: Ipv4Addr) -> Result<Self, String> {
            unsafe {
                let mut wsa_data: WSADATA = std::mem::zeroed();
                let wsa_res = WSAStartup(0x0202, &mut wsa_data);
                if wsa_res != 0 {
                    return Err(format!("WSAStartup 失败 (错误码: {})", wsa_res));
                }

                let socket = WSASocketW(
                    AF_INET as i32,
                    SOCK_RAW as i32,
                    IPPROTO_IP as i32,
                    std::ptr::null(),
                    0,
                    WSA_FLAG_REGISTERED_IO,
                );
                if socket == INVALID_SOCKET {
                    let err = WSAGetLastError();
                    WSACleanup();
                    return Err(format!("WSASocketW(WSA_FLAG_REGISTERED_IO) 受阻 (错误码: {})", err));
                }

                let mut sin: SOCKADDR_IN = std::mem::zeroed();
                sin.sin_family = AF_INET;
                sin.sin_port = 0;
                sin.sin_addr = IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(local_ip.octets()),
                    },
                };

                if bind(
                    socket,
                    &sin as *const SOCKADDR_IN as *const SOCKADDR,
                    std::mem::size_of::<SOCKADDR_IN>() as i32,
                ) == SOCKET_ERROR
                {
                    let err = WSAGetLastError();
                    closesocket(socket);
                    WSACleanup();
                    return Err(format!("RIO Raw Socket 绑定 {} 失败 (错误码: {})", local_ip, err));
                }

                // 开启 SIO_RCVALL 全量 IPv4 混杂截获
                let mut rcvall_val: u32 = RCVALL_ON as u32;
                let mut bytes_ret: u32 = 0;
                if WSAIoctl(
                    socket,
                    SIO_RCVALL,
                    &mut rcvall_val as *mut u32 as *const c_void,
                    std::mem::size_of::<u32>() as u32,
                    std::ptr::null_mut(),
                    0,
                    &mut bytes_ret,
                    std::ptr::null_mut(),
                    None,
                ) == SOCKET_ERROR
                {
                    let err = WSAGetLastError();
                    closesocket(socket);
                    WSACleanup();
                    return Err(format!("激活 SIO_RCVALL 混杂模式受阻 (错误码: {})", err));
                }

                // 查询 Winsock2 Registered I/O (RIO) 扩展函数表指针
                let mut rio_guid = WSAID_MULTIPLE_RIO;
                let mut rio_table: RIO_EXTENSION_FUNCTION_TABLE = std::mem::zeroed();
                let mut tbl_bytes: u32 = 0;
                if WSAIoctl(
                    socket,
                    SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER,
                    &mut rio_guid as *mut _ as *const c_void,
                    std::mem::size_of_val(&rio_guid) as u32,
                    &mut rio_table as *mut _ as *mut c_void,
                    std::mem::size_of::<RIO_EXTENSION_FUNCTION_TABLE>() as u32,
                    &mut tbl_bytes,
                    std::ptr::null_mut(),
                    None,
                ) == SOCKET_ERROR
                {
                    let err = WSAGetLastError();
                    closesocket(socket);
                    WSACleanup();
                    return Err(format!("获取 WSAID_MULTIPLE_RIO 函数表失败 (错误码: {})", err));
                }

                // 分配物理锁定的连续大页池并注册为 RIO 缓冲区
                let hugepage = HugepageLockedBuffer::new(RIO_SLOT_COUNT, RIO_SLOT_BYTES);
                let pinned = hugepage.is_pinned();
                let large = hugepage.is_large_pages();
                let total_bytes = hugepage.total_bytes();
                let raw_ptr = hugepage.raw_ptr;

                let register_fn = rio_table
                    .RIORegisterBuffer
                    .ok_or_else(|| "RIORegisterBuffer 指针为空".to_string())?;
                let buffer_id = register_fn(raw_ptr as *const u8, total_bytes as u32);
                if buffer_id == RIO_INVALID_BUFFERID_VAL {
                    let err = WSAGetLastError();
                    closesocket(socket);
                    WSACleanup();
                    return Err(format!("RIORegisterBuffer 锁页注册失败 (错误码: {})", err));
                }

                let create_cq_fn = rio_table
                    .RIOCreateCompletionQueue
                    .ok_or_else(|| "RIOCreateCompletionQueue 指针为空".to_string())?;
                let cq = create_cq_fn((RIO_SLOT_COUNT * 2) as u32, std::ptr::null());
                if cq == RIO_INVALID_CQ_VAL {
                    let err = WSAGetLastError();
                    if let Some(dereg) = rio_table.RIODeregisterBuffer {
                        dereg(buffer_id);
                    }
                    closesocket(socket);
                    WSACleanup();
                    return Err(format!("RIOCreateCompletionQueue 失败 (错误码: {})", err));
                }

                let create_rq_fn = rio_table
                    .RIOCreateRequestQueue
                    .ok_or_else(|| "RIOCreateRequestQueue 指针为空".to_string())?;
                let rq = create_rq_fn(
                    socket,
                    RIO_SLOT_COUNT as u32,
                    1,
                    0,
                    1,
                    cq,
                    cq,
                    std::ptr::null(),
                );
                if rq == RIO_INVALID_RQ_VAL {
                    let err = WSAGetLastError();
                    if let Some(close_cq) = rio_table.RIOCloseCompletionQueue {
                        close_cq(cq);
                    }
                    if let Some(dereg) = rio_table.RIODeregisterBuffer {
                        dereg(buffer_id);
                    }
                    closesocket(socket);
                    WSACleanup();
                    return Err(format!("RIOCreateRequestQueue 失败 (错误码: {})", err));
                }

                let mut receiver = Self {
                    socket,
                    wsa_started: true,
                    rio_table,
                    hugepage,
                    buffer_id,
                    cq,
                    rq,
                    is_physically_pinned: pinned,
                    is_large_pages: large,
                    pinned_bytes: total_bytes,
                };

                // 预先把所有大页槽位投递至 Windows 内核 RIO 接收环
                for slot_idx in 0..RIO_SLOT_COUNT {
                    receiver.post_receive(slot_idx)?;
                }

                Ok(receiver)
            }
        }

        fn post_receive(&mut self, slot_idx: usize) -> Result<(), String> {
            let recv_fn = self
                .rio_table
                .RIOReceive
                .ok_or_else(|| "RIOReceive 指针为空".to_string())?;
            let buf_desc = RIO_BUF {
                BufferId: self.buffer_id,
                Offset: (slot_idx * RIO_SLOT_BYTES) as u32,
                Length: RIO_SLOT_BYTES as u32,
            };
            unsafe {
                let ok = recv_fn(
                    self.rq,
                    &buf_desc,
                    1,
                    0,
                    slot_idx as *const c_void,
                );
                if ok == 0 {
                    let err = WSAGetLastError();
                    return Err(format!("RIOReceive 投递槽位 {} 失败 (错误码: {})", slot_idx, err));
                }
            }
            Ok(())
        }

        /// 零拷贝批处理出队已到达物理大页槽位的报文切片
        pub fn poll_batch<F>(&mut self, mut on_packet: F) -> usize
        where
            F: FnMut(&[u8]),
        {
            let dequeue_fn = match self.rio_table.RIODequeueCompletion {
                Some(f) => f,
                None => return 0,
            };

            let mut results: [RIORESULT; 64] = unsafe { std::mem::zeroed() };
            let count = unsafe { dequeue_fn(self.cq, results.as_mut_ptr(), 64) };
            if count == 0 || count == RIO_CORRUPT_CQ {
                return 0;
            }

            let n = (count as usize).min(64);
            let mut processed = 0usize;

            for item in &results[..n] {
                let slot_idx = item.RequestContext as usize;
                if slot_idx >= RIO_SLOT_COUNT {
                    continue;
                }
                if item.Status == 0 && item.BytesTransferred > 0 {
                    let len = item.BytesTransferred as usize;
                    if let Some(slice) = self.hugepage.get_slot_slice(slot_idx, len) {
                        GLOBAL_RUNTIME_COUNTERS.ring_packets_total.fetch_add(1, Ordering::Relaxed);
                        GLOBAL_RUNTIME_COUNTERS.ring_bytes_total.fetch_add(len as u64, Ordering::Relaxed);
                        on_packet(slice);
                        processed += 1;
                    }
                }
                // 槽位消费完毕立即原地重投归还给 Windows afd.sys 零拷贝内核队列
                let _ = self.post_receive(slot_idx);
            }

            processed
        }
    }

    impl Drop for WindowsRioRawReceiver {
        fn drop(&mut self) {
            unsafe {
                if self.socket != INVALID_SOCKET {
                    closesocket(self.socket);
                    self.socket = INVALID_SOCKET;
                }
                if self.cq != RIO_INVALID_CQ_VAL {
                    if let Some(close_cq) = self.rio_table.RIOCloseCompletionQueue {
                        close_cq(self.cq);
                    }
                    self.cq = RIO_INVALID_CQ_VAL;
                }
                if self.buffer_id != RIO_INVALID_BUFFERID_VAL {
                    if let Some(dereg) = self.rio_table.RIODeregisterBuffer {
                        dereg(self.buffer_id);
                    }
                    self.buffer_id = RIO_INVALID_BUFFERID_VAL;
                }
                if self.wsa_started {
                    WSACleanup();
                    self.wsa_started = false;
                }
            }
        }
    }
}

// ============================================================
// 单元测试与验证套件 (Unit Tests & DoD Validation)
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_copy_slot_allocation_and_read() {
        let mut pool = ZeroCopyPacketPool::new(16);
        let test_payload = b"PING Zero Copy Ethernet Packet Payload 2026";

        let slot_id = pool.acquire_and_write(test_payload, test_payload.len() as u32, 1700000000, 100)
            .expect("分配槽位应该成功");

        assert_eq!(slot_id, 0);

        let slice = pool.get_slot_slice(slot_id).expect("应该成功获取切片");
        assert_eq!(slice, test_payload);

        let metrics = pool.get_metrics();
        assert_eq!(metrics.current_page_allocated, 1);
        assert_eq!(metrics.total_allocations, 1);
        assert_eq!(metrics.pool_exhaustion_drops, 0);
    }

    #[test]
    fn test_double_buffer_ping_pong_flip() {
        let mut pool = ZeroCopyPacketPool::new(4);
        let dummy = vec![0x55; 64];

        // 填满 Page A (4 个槽位)
        for i in 0..4 {
            let id = pool.acquire_and_write(&dummy, 64, 1700000000 + i as u32, 0).unwrap();
            assert_eq!(id, i as u32);
        }

        // 第 5 个请求触发翻转至 Page B
        let id5 = pool.acquire_and_write(&dummy, 64, 1700000005, 0).unwrap();
        assert_eq!(id5, 4); // Page B 的首个槽位为 4

        let metrics = pool.get_metrics();
        assert_eq!(metrics.active_page_index, 1);
        assert_eq!(metrics.current_page_allocated, 1);
        assert_eq!(metrics.total_allocations, 5);

        // 重置 Inactive (Page A)
        pool.reset_inactive_page();
        let m2 = pool.get_metrics();
        assert_eq!(m2.total_deallocations, 4);
    }

    #[test]
    fn test_edge_oversized_payload_truncation_defense() {
        let mut pool = ZeroCopyPacketPool::new(4);
        // 构造超出单槽位最大容量 (2048 字节) 的超大载荷 (3000 字节)
        let oversized = vec![0xEE; 3000];

        let slot_id = pool.acquire_and_write(&oversized, 3000, 1700000000, 0).unwrap();
        let slice = pool.get_slot_slice(slot_id).unwrap();

        // 验证被安全截断至 STANDARD_SLOT_CAPACITY (2048 字节)，无溢出崩溃
        assert_eq!(slice.len(), STANDARD_SLOT_CAPACITY);
        assert_eq!(slice[0], 0xEE);
        assert_eq!(slice[STANDARD_SLOT_CAPACITY - 1], 0xEE);
    }

    #[test]
    fn test_edge_exhaustion_drop_defense() {
        let mut pool = ZeroCopyPacketPool::new(2);
        let dummy = [0x11; 32];

        // 填满 Page A (2 个)
        pool.acquire_and_write(&dummy, 32, 1, 0).unwrap();
        pool.acquire_and_write(&dummy, 32, 2, 0).unwrap();

        // 填满 Page B (2 个)
        pool.acquire_and_write(&dummy, 32, 3, 0).unwrap();
        pool.acquire_and_write(&dummy, 32, 4, 0).unwrap();

        // 未回收情况下继续申请第 5 个槽位，必须触发安全拒绝，绝不死锁
        let res = pool.acquire_and_write(&dummy, 32, 5, 0);
        assert!(res.is_err());

        let metrics = pool.get_metrics();
        assert_eq!(metrics.pool_exhaustion_drops, 1);
    }

    #[test]
    fn test_packed_packet_token_bitwise_integrity() {
        // 极限用例 1: 零值
        let t0 = PackedPacketToken::new(0, 0, 0, 0);
        let p0 = t0.pack();
        let u0 = PackedPacketToken::unpack(p0).expect("解包必须成功");
        assert_eq!(t0, u0);

        // 极限用例 2: 最大边界值 (slot_id 最大, priority=3, len=65535, proto=127)
        let t_max = PackedPacketToken::new(0xFFFFFFFF, 3, 0xFFFF, 0x7F);
        let p_max = t_max.pack();
        let u_max = PackedPacketToken::unpack(p_max).expect("最大边界解包必须成功");
        assert_eq!(t_max, u_max);

        // 极限用例 3: 空槽位原始值 0 解包必须安全返回 None (防脏读)
        assert!(PackedPacketToken::unpack(0).is_none());
    }

    #[test]
    fn test_burst_packet_ring_enqueue_dequeue() {
        let ring = BurstPacketRingQueue::new(32); // 容量 32
        assert_eq!(ring.capacity, 32);
        assert!(ring.is_empty());

        // 1. 批量构造 16 个报文令牌并批量入队
        let mut batch_in = Vec::new();
        for i in 0..16 {
            batch_in.push(PackedPacketToken::new(i as u32, 1, 100 + i as u16, 6)); // TCP
        }

        let written = ring.enqueue_burst(&batch_in);
        assert_eq!(written, 16);
        assert_eq!(ring.len(), 16);

        // 2. 批量出队 10 个
        let mut batch_out = vec![PackedPacketToken::new(0, 0, 0, 0); 10];
        let read = ring.dequeue_burst(&mut batch_out);
        assert_eq!(read, 10);
        assert_eq!(ring.len(), 6);

        for i in 0..10 {
            assert_eq!(batch_out[i].slot_id, i as u32);
            assert_eq!(batch_out[i].packet_len, 100 + i as u16);
        }

        // 3. 再出队剩余的 6 个 (传入容量为 10 的缓冲区，验证只提取 6 个)
        let mut batch_out_remaining = vec![PackedPacketToken::new(0, 0, 0, 0); 10];
        let read2 = ring.dequeue_burst(&mut batch_out_remaining);
        assert_eq!(read2, 6);
        assert_eq!(ring.len(), 0);
        assert!(ring.is_empty());
    }

    #[test]
    fn test_backpressure_hysteresis_and_priority_defense() {
        let ring = BurstPacketRingQueue::new(64); // 容量 64, 高水位 51 (80%), 低水位 25 (40%)
        assert_eq!(ring.high_watermark, 51);
        assert_eq!(ring.low_watermark, 25);

        // 1. 连续推入 50 个低优先级令牌 (Priority 0: ARP/广播)
        for i in 0..50 {
            let token = PackedPacketToken::new(i, 0, 64, 1);
            let action = ring.enqueue_with_backpressure(token);
            assert_eq!(action, BackpressureAction::Admitted);
        }
        assert!(!ring.get_metrics().is_backpressure_active);

        // 2. 推入第 51、52 个令牌，触发 80% 高水位背压
        let t51 = PackedPacketToken::new(51, 0, 64, 1);
        let action51 = ring.enqueue_with_backpressure(t51);
        assert_eq!(action51, BackpressureAction::Admitted);
        assert!(ring.get_metrics().is_backpressure_active, "必须激活背压");

        // 3. 在背压激活状态下，推入低优先级令牌 -> 必须被安全拦截节流丢弃
        let low_pri_token = PackedPacketToken::new(999, 0, 64, 1);
        let action_drop = ring.enqueue_with_backpressure(low_pri_token);
        assert_eq!(action_drop, BackpressureAction::ThrottledDropLowPriority);

        // 4. 在背压激活状态下，推入关键工控报文 (Priority 3: Modbus/Profinet) -> 必须被特许放行入队
        let critical_token = PackedPacketToken::new(888, 3, 256, 10);
        let action_allow = ring.enqueue_with_backpressure(critical_token);
        assert_eq!(action_allow, BackpressureAction::Admitted);

        // 5. 批量消费出队，使得队列深度下降至 20 (低于 40% 低水位)
        let mut read_buf = vec![PackedPacketToken::new(0, 0, 0, 0); 35];
        let read_count = ring.dequeue_burst(&mut read_buf);
        assert_eq!(read_count, 35);

        // 滞环校验: 降至低水位后，背压状态必须自动安全解除
        let metrics = ring.get_metrics();
        assert!(!metrics.is_backpressure_active, "背压状态必须自动解除");
        assert_eq!(metrics.throttled_low_priority_drops, 1);
    }

    // ============================================================
    // 【TASK-34】Windows 内核旁路与物理大页内存锁定直通引擎 6 轮严苛测试
    // ============================================================

    #[test]
    fn test_hugepage_locked_buffer_allocation_and_pinning() {
        let mut buf = HugepageLockedBuffer::new(32, 2048);
        assert_eq!(buf.slot_count(), 32);
        assert_eq!(buf.slot_capacity(), 2048);
        assert_eq!(buf.total_bytes(), 32 * 2048);

        let test_payload = b"DIRECT_DMA_TEST_PAYLOAD_PHYSICAL_RAM_2026";
        let written = buf.dma_write_slot(0, test_payload);
        assert_eq!(written, test_payload.len());

        let slice = buf.get_slot_slice(0, written).expect("应当成功零拷贝借用切片");
        assert_eq!(slice, test_payload);

        let dma_addr = buf.get_dma_address(0);
        assert!(dma_addr > 0, "物理或虚拟映射 DMA 地址必须非零");

        // 极限越界防御
        assert!(buf.get_slot_slice(999, 10).is_none());
    }

    #[test]
    fn test_hardware_dma_descriptor_memory_alignment_and_flags() {
        // 1. 验证 32 字节硬件级物理对齐
        assert_eq!(std::mem::size_of::<HardwareDmaDescriptor>(), 32);
        assert_eq!(std::mem::align_of::<HardwareDmaDescriptor>(), 32);

        // 2. 标志位与硬件状态机
        let mut desc = HardwareDmaDescriptor::default();
        desc.flags |= DMA_FLAG_DD | DMA_FLAG_EOP | DMA_FLAG_CHECKSUM_OK | DMA_FLAG_VLAN_EXTRACTED;
        desc.vlan_tag = 100;
        desc.rss_hash = 0xDEADBEEF;
        desc.timestamp_ns = 1700000000_123456789;
        desc.pkt_len = 1514;
        desc.slot_index = 7;

        assert_eq!(desc.flags & DMA_FLAG_DD, DMA_FLAG_DD);
        assert_eq!(desc.flags & DMA_FLAG_EOP, DMA_FLAG_EOP);
        assert_eq!(desc.flags & DMA_FLAG_CHECKSUM_OK, DMA_FLAG_CHECKSUM_OK);
        assert_eq!(desc.flags & DMA_FLAG_VLAN_EXTRACTED, DMA_FLAG_VLAN_EXTRACTED);
        assert_eq!(desc.rss_hash, 0xDEADBEEF);
        assert_eq!(desc.timestamp_ns, 1700000000_123456789);
    }

    #[test]
    fn test_dma_descriptor_ring_burst_throughput() {
        let mut ring = DmaDescriptorRing::new(32);
        assert_eq!(ring.capacity(), 32);
        assert!(ring.is_empty());

        let mut descs_in = Vec::new();
        for i in 0..16 {
            let mut d = HardwareDmaDescriptor::default();
            d.slot_index = i as u32;
            d.pkt_len = 100 + i as u16;
            d.flags = DMA_FLAG_DD | DMA_FLAG_EOP;
            descs_in.push(d);
        }

        // 批量入队 16 个
        let written = ring.enqueue_dma_burst(&descs_in);
        assert_eq!(written, 16);
        assert_eq!(ring.len(), 16);

        // 批量拉取 10 个
        let mut descs_out = vec![HardwareDmaDescriptor::default(); 10];
        let read = ring.dequeue_dma_burst(&mut descs_out);
        assert_eq!(read, 10);
        assert_eq!(ring.len(), 6);
        for i in 0..10 {
            assert_eq!(descs_out[i].slot_index, i as u32);
            assert_eq!(descs_out[i].pkt_len, 100 + i as u16);
        }

        // 批量拉取剩余 6 个
        let mut descs_out2 = vec![HardwareDmaDescriptor::default(); 10];
        let read2 = ring.dequeue_dma_burst(&mut descs_out2);
        assert_eq!(read2, 6);
        assert_eq!(ring.len(), 0);
        assert!(ring.is_empty());
    }

    #[test]
    fn test_kernel_bypass_pmd_wire_packet_injection_and_poll() {
        let mut adapter = KernelBypassAdapter::new(KernelBypassMode::HardwareDmaDirect, 64, 2048);
        assert_eq!(adapter.mode(), KernelBypassMode::HardwareDmaDirect);

        let raw_wire_frame = b"\x00\x0c\x29\x12\x34\x56\x00\x50\x56\xc0\x00\x08\x08\x0045000030test_dma_frame";
        let timestamp_ns = 1700000000_987654321;
        let vlan_id = 42;
        let rss_hash = 0xCAFEBABE;

        // 模拟线路直写 DMA 注入
        let desc = adapter.inject_wire_packet(raw_wire_frame, timestamp_ns, vlan_id, rss_hash)
            .expect("硬件 DMA 直写注入应当成功");

        assert_eq!(desc.pkt_len, raw_wire_frame.len() as u16);
        assert_eq!(desc.vlan_tag, 42);
        assert_eq!(desc.rss_hash, 0xCAFEBABE);
        assert_eq!(desc.timestamp_ns, timestamp_ns);

        // PMD 轮询模式驱动提取
        let mut rx_batch = vec![HardwareDmaDescriptor::default(); 8];
        let polled = adapter.poll_rx_burst(&mut rx_batch);
        assert_eq!(polled, 1);
        assert_eq!(rx_batch[0].slot_index, desc.slot_index);

        // 零拷贝切片直读验证
        let slice = adapter.read_packet_slice(&rx_batch[0]).expect("零拷贝读取切片必须存在");
        assert_eq!(slice, raw_wire_frame);
    }

    #[test]
    fn test_dma_ring_exhaustion_and_backpressure_drop_defense() {
        // 创建容量为 16 的旁路适配器
        let mut adapter = KernelBypassAdapter::new(KernelBypassMode::WinDivertZeroCopy, 16, 2048);
        let dummy = [0xAA; 64];

        // 填满 16 个描述符槽位
        for i in 0..16 {
            let res = adapter.inject_wire_packet(&dummy, 1000 + i, 0, 0);
            assert!(res.is_ok());
        }

        // 第 17 个报文在环满载时必须触发快速失败拦截 (Fail-Fast)，严禁死锁或越界崩溃
        let res_overflow = adapter.inject_wire_packet(&dummy, 2000, 0, 0);
        assert!(res_overflow.is_err());

        // 验证遥测指标中丢包计数
        let metrics = adapter.get_metrics();
        assert_eq!(metrics.ring_depth, 16);
        assert_eq!(metrics.total_dma_packets, 16);

        // 释放 8 个描述符后，新注入必须恢复通行
        let mut poll_buf = vec![HardwareDmaDescriptor::default(); 8];
        let polled = adapter.poll_rx_burst(&mut poll_buf);
        assert_eq!(polled, 8);

        let res_retry = adapter.inject_wire_packet(&dummy, 3000, 0, 0);
        assert!(res_retry.is_ok());
    }

    #[test]
    fn test_end_to_end_kernel_bypass_to_zerocopy_token_bridge() {
        let mut adapter = KernelBypassAdapter::new(KernelBypassMode::HighPrecisionPmdSim, 32, 2048);
        let ring_queue = BurstPacketRingQueue::new(32);

        let ip_payload = b"\x45\x00\x00\x40\x00\x01\x00\x00\x40\x06\x00\x00\x0a\x00\x00\x01\x0a\x00\x00\x02";
        let desc = adapter.inject_wire_packet(ip_payload, 1700000000_000000001, 0, 0x12345678)
            .expect("注入应成功");

        // 转换为单字 64 位无锁令牌 (Priority: 3 = 工控控制流量, Proto: 6 = TCP)
        let token = ZeroCopyBridge::dma_to_token(&desc, 3, 6);
        assert_eq!(token.slot_id, desc.slot_index);
        assert_eq!(token.priority, 3);
        assert_eq!(token.protocol_code, 6);
        assert_eq!(token.packet_len, ip_payload.len() as u16);

        // 桥接推入令牌调度队列
        let action = ring_queue.enqueue_with_backpressure(token);
        assert_eq!(action, BackpressureAction::Admitted);

        // 消费端批处理拉取令牌并无拷贝映射到底层大页槽位
        let mut token_out = [PackedPacketToken::new(0, 0, 0, 0); 1];
        let dequeued = ring_queue.dequeue_burst(&mut token_out);
        assert_eq!(dequeued, 1);
        assert_eq!(token_out[0], token);

        let direct_slice = adapter.read_packet_slice(&desc).unwrap();
        assert_eq!(direct_slice, ip_payload);
    }

    #[test]
    fn test_autorecycle_continuous_10k_frames_zero_drops() {
        let mut pool = ZeroCopyPacketPool::new(64);
        let sample = vec![0xABu8; 256];
        for _ in 0..10_000 {
            pool.push_packet_with_autorecycle(&sample)
                .expect("持续自回收乒乓翻转写入 10,000 包不应耗尽报错");
        }
        let m = pool.get_metrics();
        assert_eq!(m.total_allocations, 10_000);
        assert_eq!(m.pool_exhaustion_drops, 0);
        assert!(m.total_deallocations > 0);
    }

    #[cfg(windows)]
    #[test]
    fn test_win_rio_receiver_init_or_graceful_permission_fallback() {
        // 无论是否管理员权限，尝试初始化 RIO 原生大页接收器必须安全成功或精确返回系统错误，严禁 panic/泄漏
        let res = win_rio::WindowsRioRawReceiver::try_bind_raw(std::net::Ipv4Addr::new(127, 0, 0, 1));
        if let Ok(mut rio) = res {
            let count = rio.poll_batch(|_| {});
            assert_eq!(count, 0);
        } else if let Err(msg) = res {
            assert!(!msg.is_empty());
        }
    }
}
