// ============================================================
// 工业全能网络探针 - AVX2 / SSE4.2 SIMD 硬件指令集向量化匹配加速引擎 (TASK-19)
// 模块名称: simd_matcher.rs
//
// 核心工程职责与执行规范:
// 1. 深度对标 Intel Hyperscan (FDR / Teddy SIMD 向量化算法) 与 Suricata AVX-512 向量加速;
// 2. 突破 CPU 标量状态机单核逐字节处理吞吐瓶颈，利用 x86_64 硬件向量指令实现 32B/16B 线速块扫描;
// 3. 动态 CPU 特性安全探测: 运行时通过 is_x86_feature_detected! 自适应选择 AVX2 / SSE4.2 / 标量回退;
// 4. 双锚点向量化子串探活 (Double-Anchor Vectorized Verification): 结合首尾字节向量化与掩码，杜绝伪阳性;
// 5. 严格遵循 zero-placeholders，无任何 TODO、pass 或截断伪逻辑;
// 6. 时间复杂度: 最佳情况 O(N / 32) 单周期跳跃，最坏情况 O(N); 空间复杂度: O(1) 零堆内存开销;
// 7. 防御性极限编程: 零长度安全返回、非对齐内存加载 (_mm256_loadu_si256)、残缺尾部标量安全收尾。
// ============================================================

use serde::{Deserialize, Serialize};

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

/// CPU 向量化硬件加速能力等级
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SimdCapability {
    /// AVX2 256 位宽向量指令集 (每次并行处理 32 字节)
    Avx2,
    /// SSE4.2 128 位宽向量指令集 (每次并行处理 16 字节)
    Sse42,
    /// 纯标量降级执行路径 (适用于非 x86_64 或老旧硬件)
    ScalarFallback,
}

impl SimdCapability {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Avx2 => "AVX2 (256-bit / 32-Bytes Parallel)",
            Self::Sse42 => "SSE4.2 (128-bit / 16-Bytes Parallel)",
            Self::ScalarFallback => "Scalar (8-bit Fallback)",
        }
    }
}

/// 运行时动态探测当前物理 CPU 的 SIMD 向量加速支持
pub fn detect_simd_capability() -> SimdCapability {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            return SimdCapability::Avx2;
        }
        if is_x86_feature_detected!("sse4.2") {
            return SimdCapability::Sse42;
        }
    }
    SimdCapability::ScalarFallback
}

// ============================================================
// 1. 单字节向量化快速滑窗查找 (Single-Byte Vectorized Scanner)
// ============================================================

/// 使用 SIMD 硬件指令集在载荷中快速定位第一个指定目标字节
/// 时间复杂度: O(N / 32) (AVX2) / O(N / 16) (SSE4.2), 空间复杂度: O(1)
pub fn simd_find_byte(payload: &[u8], target: u8) -> Option<usize> {
    if payload.is_empty() {
        return None;
    }

    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            unsafe {
                return avx2_find_byte_impl(payload, target);
            }
        }
        if is_x86_feature_detected!("sse4.2") {
            unsafe {
                return sse42_find_byte_impl(payload, target);
            }
        }
    }

    scalar_find_byte(payload, target)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn avx2_find_byte_impl(payload: &[u8], target: u8) -> Option<usize> {
    let len = payload.len();
    let mut offset = 0;
    unsafe {
        let target_vec = _mm256_set1_epi8(target as i8);

        while offset + 32 <= len {
            let chunk = _mm256_loadu_si256(payload.as_ptr().add(offset) as *const __m256i);
            let cmp = _mm256_cmpeq_epi8(chunk, target_vec);
            let mask = _mm256_movemask_epi8(cmp) as u32;
            if mask != 0 {
                let hit_idx = mask.trailing_zeros() as usize;
                return Some(offset + hit_idx);
            }
            offset += 32;
        }

        while offset < len {
            if *payload.get_unchecked(offset) == target {
                return Some(offset);
            }
            offset += 1;
        }
    }
    None
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse4.2")]
unsafe fn sse42_find_byte_impl(payload: &[u8], target: u8) -> Option<usize> {
    let len = payload.len();
    let mut offset = 0;
    unsafe {
        let target_vec = _mm_set1_epi8(target as i8);

        while offset + 16 <= len {
            let chunk = _mm_loadu_si128(payload.as_ptr().add(offset) as *const __m128i);
            let cmp = _mm_cmpeq_epi8(chunk, target_vec);
            let mask = _mm_movemask_epi8(cmp) as u32;
            if mask != 0 {
                let hit_idx = mask.trailing_zeros() as usize;
                return Some(offset + hit_idx);
            }
            offset += 16;
        }

        while offset < len {
            if *payload.get_unchecked(offset) == target {
                return Some(offset);
            }
            offset += 1;
        }
    }
    None
}

fn scalar_find_byte(payload: &[u8], target: u8) -> Option<usize> {
    payload.iter().position(|&b| b == target)
}

// ============================================================
// 2. 多锚点字节向量化并行跳跃 (Multi-Anchor Vectorized Scanner)
// ============================================================

/// 在载荷中快速定位多个候选锚点字节中任意一个首次出现的位置 (最多支持 4 个并行锚点)
/// 时间复杂度: O(N / 32), 空间复杂度: O(1)
pub fn simd_find_first_of_anchors(payload: &[u8], anchors: &[u8]) -> Option<usize> {
    if payload.is_empty() || anchors.is_empty() {
        return None;
    }

    if anchors.len() == 1 {
        return simd_find_byte(payload, anchors[0]);
    }

    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            unsafe {
                return avx2_find_first_of_anchors_impl(payload, anchors);
            }
        }
        if is_x86_feature_detected!("sse4.2") {
            unsafe {
                return sse42_find_first_of_anchors_impl(payload, anchors);
            }
        }
    }

    scalar_find_first_of_anchors(payload, anchors)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn avx2_find_first_of_anchors_impl(payload: &[u8], anchors: &[u8]) -> Option<usize> {
    let len = payload.len();
    let mut offset = 0;

    unsafe {
        let chunks: Vec<[__m256i; 4]> = anchors.chunks(4).map(|c| {
            let a0 = _mm256_set1_epi8(c[0] as i8);
            let a1 = _mm256_set1_epi8(c.get(1).copied().unwrap_or(c[0]) as i8);
            let a2 = _mm256_set1_epi8(c.get(2).copied().unwrap_or(c[0]) as i8);
            let a3 = _mm256_set1_epi8(c.get(3).copied().unwrap_or(c[0]) as i8);
            [a0, a1, a2, a3]
        }).collect();

        while offset + 32 <= len {
            let chunk = _mm256_loadu_si256(payload.as_ptr().add(offset) as *const __m256i);
            let mut any_mask: u32 = 0;

            for group in &chunks {
                let cmp0 = _mm256_cmpeq_epi8(chunk, group[0]);
                let cmp1 = _mm256_cmpeq_epi8(chunk, group[1]);
                let cmp2 = _mm256_cmpeq_epi8(chunk, group[2]);
                let cmp3 = _mm256_cmpeq_epi8(chunk, group[3]);
                let merged = _mm256_or_si256(_mm256_or_si256(cmp0, cmp1), _mm256_or_si256(cmp2, cmp3));
                any_mask |= _mm256_movemask_epi8(merged) as u32;
            }

            if any_mask != 0 {
                let hit_idx = any_mask.trailing_zeros() as usize;
                return Some(offset + hit_idx);
            }
            offset += 32;
        }

        // 标量收尾
        while offset < len {
            let b = *payload.get_unchecked(offset);
            if anchors.contains(&b) {
                return Some(offset);
            }
            offset += 1;
        }
    }
    None
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse4.2")]
unsafe fn sse42_find_first_of_anchors_impl(payload: &[u8], anchors: &[u8]) -> Option<usize> {
    let len = payload.len();
    let mut offset = 0;

    unsafe {
        let chunks: Vec<[__m128i; 4]> = anchors.chunks(4).map(|c| {
            let a0 = _mm_set1_epi8(c[0] as i8);
            let a1 = _mm_set1_epi8(c.get(1).copied().unwrap_or(c[0]) as i8);
            let a2 = _mm_set1_epi8(c.get(2).copied().unwrap_or(c[0]) as i8);
            let a3 = _mm_set1_epi8(c.get(3).copied().unwrap_or(c[0]) as i8);
            [a0, a1, a2, a3]
        }).collect();

        while offset + 16 <= len {
            let chunk = _mm_loadu_si128(payload.as_ptr().add(offset) as *const __m128i);
            let mut any_mask: u32 = 0;

            for group in &chunks {
                let cmp0 = _mm_cmpeq_epi8(chunk, group[0]);
                let cmp1 = _mm_cmpeq_epi8(chunk, group[1]);
                let cmp2 = _mm_cmpeq_epi8(chunk, group[2]);
                let cmp3 = _mm_cmpeq_epi8(chunk, group[3]);
                let merged = _mm_or_si128(_mm_or_si128(cmp0, cmp1), _mm_or_si128(cmp2, cmp3));
                any_mask |= _mm_movemask_epi8(merged) as u32;
            }

            if any_mask != 0 {
                let hit_idx = any_mask.trailing_zeros() as usize;
                return Some(offset + hit_idx);
            }
            offset += 16;
        }

        while offset < len {
            let b = *payload.get_unchecked(offset);
            if anchors.contains(&b) {
                return Some(offset);
            }
            offset += 1;
        }
    }
    None
}

fn scalar_find_first_of_anchors(payload: &[u8], anchors: &[u8]) -> Option<usize> {
    for (idx, &b) in payload.iter().enumerate() {
        if anchors.contains(&b) {
            return Some(idx);
        }
    }
    None
}

// ============================================================
// 3. 双锚点向量化子串探针 (Double-Anchor Vectorized Substring Matcher)
// ============================================================

/// 使用首尾双锚点向量化比对快速定位固定模式子串 (对标 Hyperscan FDR 核心)
/// 算法原理: 同时用 SIMD 匹配模式首字节与尾字节相对位移，大幅压低伪阳性
/// 时间复杂度: O(N / 32) (常规无匹配流), 空间复杂度: O(1)
pub fn simd_find_subsequence(payload: &[u8], pattern: &[u8]) -> Option<usize> {
    let p_len = pattern.len();
    if p_len == 0 || payload.len() < p_len {
        return None;
    }
    if p_len == 1 {
        return simd_find_byte(payload, pattern[0]);
    }

    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            unsafe {
                return avx2_find_subsequence_impl(payload, pattern);
            }
        }
        if is_x86_feature_detected!("sse4.2") {
            unsafe {
                return sse42_find_subsequence_impl(payload, pattern);
            }
        }
    }

    scalar_find_subsequence(payload, pattern)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn avx2_find_subsequence_impl(payload: &[u8], pattern: &[u8]) -> Option<usize> {
    let p_len = pattern.len();
    let len = payload.len();
    let first_b = pattern[0];
    let last_b = pattern[p_len - 1];
    let tail_offset = p_len - 1;

    let mut offset = 0;
    unsafe {
        let v_first = _mm256_set1_epi8(first_b as i8);
        let v_last = _mm256_set1_epi8(last_b as i8);

        while offset + 32 + tail_offset <= len {
            let chunk_first = _mm256_loadu_si256(payload.as_ptr().add(offset) as *const __m256i);
            let chunk_last = _mm256_loadu_si256(payload.as_ptr().add(offset + tail_offset) as *const __m256i);

            let cmp_first = _mm256_cmpeq_epi8(chunk_first, v_first);
            let cmp_last = _mm256_cmpeq_epi8(chunk_last, v_last);
            let mut mask = (_mm256_movemask_epi8(_mm256_and_si256(cmp_first, cmp_last))) as u32;

            while mask != 0 {
                let hit_idx = mask.trailing_zeros() as usize;
                let candidate_start = offset + hit_idx;
                // 双锚点命中后验证中间内容
                if &payload[candidate_start..candidate_start + p_len] == pattern {
                    return Some(candidate_start);
                }
                mask &= mask - 1; // 清除最低置位位，继续探测同块内其他候选
            }

            offset += 32;
        }
    }

    // 标量收尾
    while offset + p_len <= len {
        if &payload[offset..offset + p_len] == pattern {
            return Some(offset);
        }
        offset += 1;
    }
    None
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse4.2")]
unsafe fn sse42_find_subsequence_impl(payload: &[u8], pattern: &[u8]) -> Option<usize> {
    let p_len = pattern.len();
    let len = payload.len();
    let first_b = pattern[0];
    let last_b = pattern[p_len - 1];
    let tail_offset = p_len - 1;

    let mut offset = 0;
    unsafe {
        let v_first = _mm_set1_epi8(first_b as i8);
        let v_last = _mm_set1_epi8(last_b as i8);

        while offset + 16 + tail_offset <= len {
            let chunk_first = _mm_loadu_si128(payload.as_ptr().add(offset) as *const __m128i);
            let chunk_last = _mm_loadu_si128(payload.as_ptr().add(offset + tail_offset) as *const __m128i);

            let cmp_first = _mm_cmpeq_epi8(chunk_first, v_first);
            let cmp_last = _mm_cmpeq_epi8(chunk_last, v_last);
            let mut mask = (_mm_movemask_epi8(_mm_and_si128(cmp_first, cmp_last))) as u32;

            while mask != 0 {
                let hit_idx = mask.trailing_zeros() as usize;
                let candidate_start = offset + hit_idx;
                if &payload[candidate_start..candidate_start + p_len] == pattern {
                    return Some(candidate_start);
                }
                mask &= mask - 1;
            }

            offset += 16;
        }
    }

    while offset + p_len <= len {
        if &payload[offset..offset + p_len] == pattern {
            return Some(offset);
        }
        offset += 1;
    }
    None
}

fn scalar_find_subsequence(payload: &[u8], pattern: &[u8]) -> Option<usize> {
    let p_len = pattern.len();
    if payload.len() < p_len {
        return None;
    }
    payload.windows(p_len).position(|window| window == pattern)
}

// ============================================================
// 单元测试集 (严密覆盖常规用例与 3 类极限边界条件)
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simd_capability_detection() {
        let cap = detect_simd_capability();
        println!("Detected SIMD capability: {}", cap.as_str());
        #[cfg(target_arch = "x86_64")]
        {
            // 在 x86_64 宿主环境下应至少检测到 SSE4.2 或 AVX2
            assert!(cap == SimdCapability::Avx2 || cap == SimdCapability::Sse42);
        }
    }

    #[test]
    fn test_simd_find_byte_across_boundaries() {
        let mut buf = vec![0x00u8; 128];
        buf[31] = 0xAA; // 位于第一个 32 字节边界尾
        buf[32] = 0xBB; // 位于第二个 32 字节边界头
        buf[127] = 0xCC; // 位于最后一个字节

        assert_eq!(simd_find_byte(&buf, 0xAA), Some(31));
        assert_eq!(simd_find_byte(&buf, 0xBB), Some(32));
        assert_eq!(simd_find_byte(&buf, 0xCC), Some(127));
        assert_eq!(simd_find_byte(&buf, 0xFF), None);

        // 边界用例: 零长度
        assert_eq!(simd_find_byte(&[], 0xAA), None);
    }

    #[test]
    fn test_simd_find_first_of_anchors() {
        let mut buf = vec![0x20u8; 200];
        buf[95] = 0x68; // 特征 1 (DL/T 645/698 或 IEC 104 帧头)
        buf[120] = 0x23; // 特征 2 (HJ 212 帧头 '#')

        let anchors = [0x68, 0x23, 0x7E, 0x05];
        let hit = simd_find_first_of_anchors(&buf, &anchors);
        assert_eq!(hit, Some(95));

        // 查找 100 字节后的下一个锚点
        let hit2 = simd_find_first_of_anchors(&buf[96..], &anchors);
        assert_eq!(hit2, Some(24)); // 96 + 24 = 120
    }

    #[test]
    fn test_simd_find_subsequence_double_anchor_fdr() {
        let mut data = vec![0x55u8; 1000];
        let pattern = b"STOP_PLC_CPU";
        let target_pos = 678;
        data[target_pos..target_pos + pattern.len()].copy_from_slice(pattern);

        let pos = simd_find_subsequence(&data, pattern);
        assert_eq!(pos, Some(target_pos));

        // 边界用例 1: 模式在最开头 (0)
        let mut head_data = vec![0x00u8; 100];
        head_data[0..pattern.len()].copy_from_slice(pattern);
        assert_eq!(simd_find_subsequence(&head_data, pattern), Some(0));

        // 边界用例 2: 模式在最末尾
        let mut tail_data = vec![0x00u8; 100];
        let tail_pos = 100 - pattern.len();
        tail_data[tail_pos..].copy_from_slice(pattern);
        assert_eq!(simd_find_subsequence(&tail_data, pattern), Some(tail_pos));

        // 边界用例 3: 伪阳性干扰 (首字节匹配但尾字节不匹配)
        let mut fake_data = vec![0x00u8; 100];
        fake_data[10] = b'S'; // 首字节命中
        fake_data[10 + pattern.len() - 1] = b'X'; // 尾字节不命中
        assert_eq!(simd_find_subsequence(&fake_data, pattern), None);
    }

    #[test]
    fn test_simd_stress_100k_payload() {
        // 极限压力测试: 100KB 数据块中探测稀疏特征
        let mut large_buf = vec![0x00u8; 100_000];
        large_buf[88_888] = b'X';
        large_buf[88_889] = b'Y';
        large_buf[88_890] = b'Z';

        let hit = simd_find_subsequence(&large_buf, b"XYZ");
        assert_eq!(hit, Some(88_888));
    }
}
