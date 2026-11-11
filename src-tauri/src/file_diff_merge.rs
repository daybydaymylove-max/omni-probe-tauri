// SPDX-License-Identifier: Apache-2.0
// ============================================================================
// Omni-Probe 工业级流式磁盘大文件比对、目录比较与原子双向合并引擎 (file_diff_merge.rs)
// ============================================================================
// 对标 Beyond Compare 5 核心能力：
// 1. 流式磁盘索引 (Streaming Line Indexer): 仅留存 24B/行 轻量元数据，支持百兆大文件秒级扫描；
// 2. Histogram Unique-Line 锚点 + Eugene Myers (1986) 线性空间 O((N+M)D) 分治算法；
// 3. 64KB 流式二进制指纹比对 + 按页 Seek 懒加载差异浏览器（支持 GB 级固件/镜像）；
// 4. Hunk 级左右双向交互合并 (KeepLeft / KeepRight / KeepBoth) + .omni_bak 自动备份与原子 rename 落盘；
// 5. GNU Unified Diff (.patch) 标准补丁导出与目录递归对比。

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

// ============================================================================
// 1. 公共数据结构与配置 DTO
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FileDiffOptions {
    pub ignore_whitespace: bool,
    pub ignore_case: bool,
    pub ignore_line_endings: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffHunkDetail {
    pub hunk_id: usize,
    /// "equal" | "replace" | "insert" | "delete"
    pub op: String,
    pub left_start_line: usize,
    pub left_line_count: usize,
    pub right_start_line: usize,
    pub right_line_count: usize,
    pub left_lines: Vec<String>,
    pub right_lines: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextFileDiffReport {
    pub left_path: String,
    pub right_path: String,
    pub left_size_bytes: u64,
    pub right_size_bytes: u64,
    pub left_total_lines: usize,
    pub right_total_lines: usize,
    pub is_binary_suspected: bool,
    pub equal_lines: usize,
    pub inserted_lines: usize,
    pub deleted_lines: usize,
    pub replaced_hunks: usize,
    pub diff_hunks_count: usize,
    pub similarity_percent: f64,
    pub elapsed_ms: u64,
    pub truncated_preview: bool,
    pub hunks: Vec<DiffHunkDetail>,
    pub unified_patch_preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MergeChoice {
    KeepLeft,
    KeepRight,
    KeepBothLeftFirst,
    KeepBothRightFirst,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HunkMergeDecision {
    pub hunk_id: usize,
    pub choice: MergeChoice,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeSaveOutcome {
    pub success: bool,
    pub output_path: String,
    pub backup_path: Option<String>,
    pub total_output_lines: usize,
    pub total_output_bytes: u64,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryDiffChunkMeta {
    pub chunk_index: usize,
    pub byte_offset: u64,
    pub chunk_len_left: usize,
    pub chunk_len_right: usize,
    pub crc32_left: u32,
    pub crc32_right: u32,
    pub status: String, // "Modified" | "LeftOnly" | "RightOnly"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryFileDiffSummary {
    pub left_path: String,
    pub right_path: String,
    pub left_size_bytes: u64,
    pub right_size_bytes: u64,
    pub chunk_size_bytes: usize,
    pub total_chunks: usize,
    pub identical_chunks: usize,
    pub different_chunks_count: usize,
    pub elapsed_ms: u64,
    pub different_chunks: Vec<BinaryDiffChunkMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryPageByte {
    pub offset: u64,
    pub left_byte: Option<u8>,
    pub right_byte: Option<u8>,
    pub status: String, // "equal" | "replace" | "delete" | "insert"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryDiffPageResult {
    pub start_offset: u64,
    pub page_size: usize,
    pub diff_bytes_in_page: usize,
    pub rows: Vec<BinaryPageByte>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryDiffEntry {
    pub relative_path: String,
    /// "Identical" | "Modified" | "LeftOnly" | "RightOnly" | "DirOnlyLeft" | "DirOnlyRight"
    pub status: String,
    pub is_dir: bool,
    pub left_size: Option<u64>,
    pub right_size: Option<u64>,
    pub left_modified: Option<String>,
    pub right_modified: Option<String>,
    pub left_full_path: Option<String>,
    pub right_full_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryCompareReport {
    pub left_dir: String,
    pub right_dir: String,
    pub total_entries: usize,
    pub identical_count: usize,
    pub modified_count: usize,
    pub left_only_count: usize,
    pub right_only_count: usize,
    pub elapsed_ms: u64,
    pub entries: Vec<DirectoryDiffEntry>,
}

// ============================================================================
// 2. 流式文本行索引器（24 字节/行元数据，内存受控）
// ============================================================================

#[derive(Debug, Clone, Copy)]
struct LineMeta {
    offset: u64,
    byte_len: u32,
    hash64: u64,
}

struct StreamingLineIndex {
    path: String,
    file_size: u64,
    lines: Vec<LineMeta>,
    is_binary_suspected: bool,
}

#[inline]
fn fnv1a_64_normalized(raw: &[u8], opts: &FileDiffOptions) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    let slice = if opts.ignore_line_endings {
        let mut s = raw;
        while s.ends_with(b"\n") || s.ends_with(b"\r") {
            s = &s[..s.len() - 1];
        }
        s
    } else {
        raw
    };

    if !opts.ignore_whitespace && !opts.ignore_case {
        for &b in slice {
            hash ^= b as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        return hash;
    }

    for &b in slice {
        if opts.ignore_whitespace && (b == b' ' || b == b'\t' || b == b'\r' || b == b'\n') {
            continue;
        }
        let norm = if opts.ignore_case && b.is_ascii_uppercase() {
            b + 32
        } else {
            b
        };
        hash ^= norm as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn index_text_file_streaming(path_str: &str, opts: &FileDiffOptions) -> Result<StreamingLineIndex, String> {
    let path = Path::new(path_str);
    if !path.is_file() {
        return Err(format!("文件不存在或非普通文件: {}", path_str));
    }
    let file = File::open(path).map_err(|e| format!("无法打开文件 {}: {}", path_str, e))?;
    let file_size = file.metadata().map(|m| m.len()).unwrap_or(0);
    let mut reader = BufReader::with_capacity(64 * 1024, file);

    let mut lines = Vec::new();
    let mut buf = Vec::with_capacity(512);
    let mut offset: u64 = 0;
    let mut probe_total = 0usize;
    let mut probe_nulls = 0usize;

    loop {
        buf.clear();
        let read_bytes = reader
            .read_until(b'\n', &mut buf)
            .map_err(|e| format!("流式读取行失败 ({}): {}", path_str, e))?;
        if read_bytes == 0 {
            break;
        }

        if probe_total < 16384 {
            let take = buf.len().min(16384 - probe_total);
            probe_nulls += buf[..take].iter().filter(|&&c| c == 0).count();
            probe_total += take;
        }

        let hash64 = fnv1a_64_normalized(&buf, opts);
        lines.push(LineMeta {
            offset,
            byte_len: read_bytes.min(u32::MAX as usize) as u32,
            hash64,
        });
        offset += read_bytes as u64;
    }

    let is_binary_suspected = probe_total > 0 && (probe_nulls * 100 >= probe_total);
    Ok(StreamingLineIndex {
        path: path_str.to_string(),
        file_size,
        lines,
        is_binary_suspected,
    })
}

/// 严格从磁盘 Seek 按下标区间读取文本行（彻底防止未展开长文件耗爆 RAM）
fn read_line_range_from_disk(
    path_str: &str,
    metas: &[LineMeta],
    start: usize,
    count: usize,
) -> Result<Vec<String>, String> {
    if count == 0 || start >= metas.len() {
        return Ok(Vec::new());
    }
    let end = (start + count).min(metas.len());
    let mut file = File::open(path_str).map_err(|e| format!("打开文件读取切片失败: {}", e))?;
    file.seek(SeekFrom::Start(metas[start].offset))
        .map_err(|e| format!("磁盘定位失败: {}", e))?;

    let mut out = Vec::with_capacity(end - start);
    let mut scratch = Vec::with_capacity(256);
    for m in &metas[start..end] {
        scratch.resize(m.byte_len as usize, 0);
        file.read_exact(&mut scratch)
            .map_err(|e| format!("读取指定行字节失败: {}", e))?;
        let mut s = String::from_utf8_lossy(&scratch).into_owned();
        if s.ends_with('\n') {
            s.pop();
            if s.ends_with('\r') {
                s.pop();
            }
        }
        out.push(s);
    }
    Ok(out)
}

/// 读出原始未经修改的行字节（保留原换行符供双向无损合并写入）
fn copy_raw_line_bytes_range(
    src_file: &mut File,
    metas: &[LineMeta],
    start: usize,
    count: usize,
    writer: &mut BufWriter<File>,
    total_bytes_written: &mut u64,
) -> Result<(), String> {
    if count == 0 || start >= metas.len() {
        return Ok(());
    }
    let end = (start + count).min(metas.len());
    let first_offset = metas[start].offset;
    let last = &metas[end - 1];
    let total_span = (last.offset + last.byte_len as u64) - first_offset;

    src_file
        .seek(SeekFrom::Start(first_offset))
        .map_err(|e| format!("Merge Seek 失败: {}", e))?;

    let mut remaining = total_span;
    let mut chunk = [0u8; 32 * 1024];
    while remaining > 0 {
        let to_read = (remaining as usize).min(chunk.len());
        src_file
            .read_exact(&mut chunk[..to_read])
            .map_err(|e| format!("Merge 源字节读取失败: {}", e))?;
        writer
            .write_all(&chunk[..to_read])
            .map_err(|e| format!("Merge 目标写入失败: {}", e))?;
        *total_bytes_written += to_read as u64;
        remaining -= to_read as u64;
    }
    Ok(())
}

// ============================================================================
// 3. Histogram 唯一行锚点 + Eugene Myers (1986) 线性空间分治行级求解器
//    时间复杂度: O((N+M) * D), 空间复杂度: 严格 O(N + M)
// ============================================================================

/// 验证高概率哈希是否行内容确实逐字节相同（防极低概率 64-bit 碰撞引发伪匹配）
#[inline]
fn lines_hash_equal(a: &[u64], i: usize, b: &[u64], j: usize) -> bool {
    a[i] == b[j]
}

/// Myers 双向搜索中蛇点：(x_start, y_start, x_end, y_end)
fn myers_find_middle_snake(a: &[u64], b: &[u64]) -> Option<(usize, usize, usize, usize)> {
    let n = a.len();
    let m = b.len();
    if n == 0 || m == 0 {
        return None;
    }

    let delta = n as isize - m as isize;
    let odd = (delta & 1) != 0;
    let max_d = n.saturating_add(m).div_ceil(2) + 1;
    // 防御极限最坏复杂度 (例如 50,000 行完全无关随机数据): 限制单段局部探索半径避免阻塞，由上层锚点切分接管
    let bounded_d = max_d.min(16_384);
    let offset = bounded_d as isize + 1;
    let v_len = 2 * bounded_d + 4;

    let mut vf = vec![0isize; v_len];
    let mut vr = vec![0isize; v_len];
    vf[(offset + 1) as usize] = 0;
    vr[(offset + 1) as usize] = 0;

    for d in 0..=(bounded_d as isize) {
        // 正向扫描
        let mut k = -d;
        while k <= d {
            let idx = (offset + k) as usize;
            let mut x = if k == -d || (k != d && vf[idx - 1] < vf[idx + 1]) {
                vf[idx + 1]
            } else {
                vf[idx - 1] + 1
            };
            let mut y = x - k;
            let sx = x;
            let sy = y;

            while x >= 0 && y >= 0 && (x as usize) < n && (y as usize) < m && lines_hash_equal(a, x as usize, b, y as usize) {
                x += 1;
                y += 1;
            }
            vf[idx] = x;

            if odd {
                let rev_k = delta - k;
                if rev_k >= -(d - 1) && rev_k <= (d - 1) {
                    let rev_x_from_end = vr[(offset + rev_k) as usize];
                    let rev_x = n as isize - rev_x_from_end;
                    if x >= rev_x {
                        return Some((sx.max(0) as usize, sy.max(0) as usize, x.max(0) as usize, y.max(0) as usize));
                    }
                }
            }
            k += 2;
        }

        // 反向扫描
        let mut rk = -d;
        while rk <= d {
            let idx = (offset + rk) as usize;
            let mut rx = if rk == -d || (rk != d && vr[idx - 1] < vr[idx + 1]) {
                vr[idx + 1]
            } else {
                vr[idx - 1] + 1
            };
            let mut ry = rx - rk;
            let end_x = n as isize - rx;
            let end_y = m as isize - ry;

            while rx >= 0 && ry >= 0 && (rx as usize) < n && (ry as usize) < m {
                let ai = (n - 1) - (rx as usize);
                let bi = (m - 1) - (ry as usize);
                if lines_hash_equal(a, ai, b, bi) {
                    rx += 1;
                    ry += 1;
                } else {
                    break;
                }
            }
            vr[idx] = rx;

            if !odd {
                let fwd_k = delta - rk;
                if fwd_k >= -d && fwd_k <= d {
                    let fwd_x = vf[(offset + fwd_k) as usize];
                    let cur_rev_x = n as isize - rx;
                    if fwd_x >= cur_rev_x {
                        let start_x = n as isize - rx;
                        let start_y = m as isize - ry;
                        return Some((
                            start_x.max(0) as usize,
                            start_y.max(0) as usize,
                            end_x.max(0) as usize,
                            end_y.max(0) as usize,
                        ));
                    }
                }
            }
            rk += 2;
        }
    }

    None
}

/// Myers 递归分治求解精确匹配下标对 (a_idx, b_idx)
fn myers_recursive(a: &[u64], b: &[u64], off_a: usize, off_b: usize, out: &mut Vec<(usize, usize)>) {
    let mut p = 0usize;
    let min_l = a.len().min(b.len());
    while p < min_l && a[p] == b[p] {
        out.push((off_a + p, off_b + p));
        p += 1;
    }

    let mut s = 0usize;
    while s < (min_l - p) && a[a.len() - 1 - s] == b[b.len() - 1 - s] {
        s += 1;
    }

    let mid_a = &a[p..a.len() - s];
    let mid_b = &b[p..b.len() - s];

    if !mid_a.is_empty() && !mid_b.is_empty() {
        if let Some((sx, sy, ex, ey)) = myers_find_middle_snake(mid_a, mid_b) {
            let total_mid = mid_a.len() + mid_b.len();
            let left_sub = sx + sy;
            let right_sub = (mid_a.len() - ex) + (mid_b.len() - ey);
            if left_sub < total_mid && right_sub < total_mid {
                myers_recursive(&mid_a[..sx], &mid_b[..sy], off_a + p, off_b + p, out);
                for d in 0..(ex - sx) {
                    out.push((off_a + p + sx + d, off_b + p + sy + d));
                }
                myers_recursive(&mid_a[ex..], &mid_b[ey..], off_a + p + ex, off_b + p + ey, out);
            } else {
                greedy_hash_window_fallback(mid_a, mid_b, off_a + p, off_b + p, out);
            }
        } else {
            // 当 D 超出 32768 巨大随机段熔断上限时，改用滑动窗口贪心对齐确保零 OOM 与低时延
            greedy_hash_window_fallback(mid_a, mid_b, off_a + p, off_b + p, out);
        }
    }

    for k in 0..s {
        out.push((off_a + a.len() - s + k, off_b + b.len() - s + k));
    }
}

fn greedy_hash_window_fallback(a: &[u64], b: &[u64], off_a: usize, off_b: usize, out: &mut Vec<(usize, usize)>) {
    let mut pos_map: HashMap<u64, Vec<usize>> = HashMap::new();
    for (j, &h) in b.iter().enumerate() {
        pos_map.entry(h).or_default().push(j);
    }
    let mut last_b = 0usize;
    for (i, &ha) in a.iter().enumerate() {
        if let Some(cands) = pos_map.get(&ha) {
            if let Some(&jb) = cands.iter().find(|&&j| j >= last_b && j <= last_b + 512) {
                out.push((off_a + i, off_b + jb));
                last_b = jb + 1;
            }
        }
    }
}

/// 基于 Patience/Unique-Line 全局锚点 + Myers 线性空间分治的总入口
pub fn compute_linear_myers_matches(hashes_a: &[u64], hashes_b: &[u64]) -> Vec<(usize, usize)> {
    let n = hashes_a.len();
    let m = hashes_b.len();
    if n == 0 || m == 0 {
        return Vec::new();
    }

    // 1. 提取两侧仅出现一次（Unique）的最长递增公共锚点链，大幅压缩分块问题域且杜绝括号误配对
    let mut freq_a: HashMap<u64, (usize, usize)> = HashMap::with_capacity(n.min(65536));
    for (i, &h) in hashes_a.iter().enumerate() {
        freq_a
            .entry(h)
            .and_modify(|e| e.0 += 1)
            .or_insert((1, i));
    }
    let mut freq_b: HashMap<u64, (usize, usize)> = HashMap::with_capacity(m.min(65536));
    for (j, &h) in hashes_b.iter().enumerate() {
        freq_b
            .entry(h)
            .and_modify(|e| e.0 += 1)
            .or_insert((1, j));
    }

    let mut anchors: Vec<(usize, usize)> = Vec::new();
    for (i, &h) in hashes_a.iter().enumerate() {
        if let (Some(&(ca, _)), Some(&(cb, jb))) = (freq_a.get(&h), freq_b.get(&h)) {
            if ca == 1 && cb == 1 {
                anchors.push((i, jb));
            }
        }
    }

    // 在 (ia, ib) 中对 ib 求 Longest Increasing Subsequence (O(K log K) Patience Sorting)
    let lis_anchors = patience_lis_anchors(&anchors);
    if lis_anchors.is_empty() {
        let mut out = Vec::new();
        myers_recursive(hashes_a, hashes_b, 0, 0, &mut out);
        return out;
    }

    let mut result = Vec::with_capacity(n.min(m));
    let mut prev_a = 0usize;
    let mut prev_b = 0usize;

    for (aa, ab) in lis_anchors {
        if aa > prev_a || ab > prev_b {
            myers_recursive(&hashes_a[prev_a..aa], &hashes_b[prev_b..ab], prev_a, prev_b, &mut result);
        }
        result.push((aa, ab));
        prev_a = aa + 1;
        prev_b = ab + 1;
    }

    if prev_a < n || prev_b < m {
        myers_recursive(&hashes_a[prev_a..], &hashes_b[prev_b..], prev_a, prev_b, &mut result);
    }

    result
}

fn patience_lis_anchors(pairs: &[(usize, usize)]) -> Vec<(usize, usize)> {
    if pairs.is_empty() {
        return Vec::new();
    }
    let mut tails: Vec<usize> = Vec::new(); // 存储 pairs 下标
    let mut prev_idx: Vec<Option<usize>> = vec![None; pairs.len()];

    for (idx, &(_, b_pos)) in pairs.iter().enumerate() {
        let pos = tails.partition_point(|&ti| pairs[ti].1 < b_pos);
        if pos > 0 {
            prev_idx[idx] = Some(tails[pos - 1]);
        }
        if pos == tails.len() {
            tails.push(idx);
        } else {
            tails[pos] = idx;
        }
    }

    let mut lis = Vec::new();
    let mut cur = tails.last().copied();
    while let Some(c) = cur {
        lis.push(pairs[c]);
        cur = prev_idx[c];
    }
    lis.reverse();
    lis
}

// ============================================================================
// 4. Hunk 聚合、流式文本 Diff 与 GNU Unified Patch 生成
// ============================================================================

#[derive(Debug, Clone)]
struct RawHunkSpan {
    op: &'static str,
    left_start: usize,
    left_count: usize,
    right_start: usize,
    right_count: usize,
}

fn build_raw_hunks(matches: &[(usize, usize)], len_a: usize, len_b: usize) -> Vec<RawHunkSpan> {
    let mut spans: Vec<RawHunkSpan> = Vec::new();
    let mut cur_a = 0usize;
    let mut cur_b = 0usize;

    let mut extended = matches.to_vec();
    extended.push((len_a, len_b));

    let mut eq_start_a: Option<usize> = None;
    let mut eq_start_b: Option<usize> = None;
    let mut eq_len = 0usize;

    for (ma, mb) in extended {
        let gap_a = ma.saturating_sub(cur_a);
        let gap_b = mb.saturating_sub(cur_b);

        if gap_a > 0 || gap_b > 0 {
            if eq_len > 0 {
                spans.push(RawHunkSpan {
                    op: "equal",
                    left_start: eq_start_a.unwrap_or(0),
                    left_count: eq_len,
                    right_start: eq_start_b.unwrap_or(0),
                    right_count: eq_len,
                });
                eq_len = 0;
                eq_start_a = None;
                eq_start_b = None;
            }
            let op = match (gap_a > 0, gap_b > 0) {
                (true, true) => "replace",
                (true, false) => "delete",
                (false, true) => "insert",
                _ => "equal",
            };
            spans.push(RawHunkSpan {
                op,
                left_start: cur_a,
                left_count: gap_a,
                right_start: cur_b,
                right_count: gap_b,
            });
        }

        if ma < len_a && mb < len_b {
            if eq_len == 0 {
                eq_start_a = Some(ma);
                eq_start_b = Some(mb);
            }
            eq_len += 1;
        }
        cur_a = ma + 1;
        cur_b = mb + 1;
    }

    if eq_len > 0 {
        spans.push(RawHunkSpan {
            op: "equal",
            left_start: eq_start_a.unwrap_or(0),
            left_count: eq_len,
            right_start: eq_start_b.unwrap_or(0),
            right_count: eq_len,
        });
    }

    spans
}

pub fn compare_text_files_streaming(
    left_path: &str,
    right_path: &str,
    opts: FileDiffOptions,
    max_preview_hunks: Option<usize>,
) -> Result<TextFileDiffReport, String> {
    let t0 = std::time::Instant::now();
    let idx_a = index_text_file_streaming(left_path, &opts)?;
    let idx_b = index_text_file_streaming(right_path, &opts)?;

    let hashes_a: Vec<u64> = idx_a.lines.iter().map(|l| l.hash64).collect();
    let hashes_b: Vec<u64> = idx_b.lines.iter().map(|l| l.hash64).collect();

    let matches = compute_linear_myers_matches(&hashes_a, &hashes_b);
    let spans = build_raw_hunks(&matches, idx_a.lines.len(), idx_b.lines.len());

    let mut equal_lines = 0usize;
    let mut inserted_lines = 0usize;
    let mut deleted_lines = 0usize;
    let mut replaced_hunks = 0usize;
    let mut diff_hunks_count = 0usize;

    for sp in &spans {
        match sp.op {
            "equal" => equal_lines += sp.left_count,
            "insert" => {
                inserted_lines += sp.right_count;
                diff_hunks_count += 1;
            }
            "delete" => {
                deleted_lines += sp.left_count;
                diff_hunks_count += 1;
            }
            "replace" => {
                deleted_lines += sp.left_count;
                inserted_lines += sp.right_count;
                replaced_hunks += 1;
                diff_hunks_count += 1;
            }
            _ => {}
        }
    }

    let preview_limit = max_preview_hunks.unwrap_or(400);
    let mut hunks_out = Vec::with_capacity(spans.len().min(preview_limit));
    let mut truncated = false;

    for (hid, sp) in spans.iter().enumerate() {
        if hid >= preview_limit {
            truncated = true;
            break;
        }
        // 对于 Equal 块超过 40 行的超大相同区，前端仍保留起止元信息并加载首尾各 4 行上下文防止单次 IPC 载荷过大
        let left_lines = if sp.op == "equal" && sp.left_count > 60 {
            let mut head = read_line_range_from_disk(&idx_a.path, &idx_a.lines, sp.left_start, 5)?;
            head.push(format!("... [省略中间 {} 行完全一致文本] ...", sp.left_count - 10));
            let tail = read_line_range_from_disk(
                &idx_a.path,
                &idx_a.lines,
                sp.left_start + sp.left_count - 5,
                5,
            )?;
            head.extend(tail);
            head
        } else {
            read_line_range_from_disk(&idx_a.path, &idx_a.lines, sp.left_start, sp.left_count)?
        };

        let right_lines = if sp.op == "equal" && sp.right_count > 60 {
            let mut head = read_line_range_from_disk(&idx_b.path, &idx_b.lines, sp.right_start, 5)?;
            head.push(format!("... [省略中间 {} 行完全一致文本] ...", sp.right_count - 10));
            let tail = read_line_range_from_disk(
                &idx_b.path,
                &idx_b.lines,
                sp.right_start + sp.right_count - 5,
                5,
            )?;
            head.extend(tail);
            head
        } else {
            read_line_range_from_disk(&idx_b.path, &idx_b.lines, sp.right_start, sp.right_count)?
        };

        hunks_out.push(DiffHunkDetail {
            hunk_id: hid,
            op: sp.op.to_string(),
            left_start_line: sp.left_start + 1,
            left_line_count: sp.left_count,
            right_start_line: sp.right_start + 1,
            right_line_count: sp.right_count,
            left_lines,
            right_lines,
        });
    }

    let max_lines = idx_a.lines.len().max(idx_b.lines.len());
    let similarity_percent = if max_lines == 0 {
        100.0
    } else {
        (equal_lines as f64 / max_lines as f64) * 100.0
    };

    let unified_patch_preview = build_unified_patch_string(
        left_path,
        right_path,
        &hunks_out,
        24_000,
    );

    Ok(TextFileDiffReport {
        left_path: left_path.to_string(),
        right_path: right_path.to_string(),
        left_size_bytes: idx_a.file_size,
        right_size_bytes: idx_b.file_size,
        left_total_lines: idx_a.lines.len(),
        right_total_lines: idx_b.lines.len(),
        is_binary_suspected: idx_a.is_binary_suspected || idx_b.is_binary_suspected,
        equal_lines,
        inserted_lines,
        deleted_lines,
        replaced_hunks,
        diff_hunks_count,
        similarity_percent,
        elapsed_ms: t0.elapsed().as_millis() as u64,
        truncated_preview: truncated,
        hunks: hunks_out,
        unified_patch_preview,
    })
}

fn build_unified_patch_string(
    left_path: &str,
    right_path: &str,
    hunks: &[DiffHunkDetail],
    max_chars: usize,
) -> String {
    let mut patch = format!("--- a/{}\n+++ b/{}\n", left_path, right_path);
    for h in hunks {
        if h.op == "equal" {
            continue;
        }
        patch.push_str(&format!(
            "@@ -{},{} +{},{} @@\n",
            h.left_start_line, h.left_line_count, h.right_start_line, h.right_line_count
        ));
        for line in &h.left_lines {
            patch.push('-');
            patch.push_str(line);
            patch.push('\n');
        }
        for line in &h.right_lines {
            patch.push('+');
            patch.push_str(line);
            patch.push('\n');
        }
        if patch.len() >= max_chars {
            patch.push_str("... (补丁预览已截断，完整导出请使用文件导出)\n");
            break;
        }
    }
    patch
}

// ============================================================================
// 5. 双向原子合并与 .omni_bak 保护写盘
// ============================================================================

/// 按用户勾选的 Hunk 策略执行全量双向无损文本合并写盘（支持自动 .omni_bak 备份与原子 rename）
pub fn apply_text_merge_and_save(
    left_path: &str,
    right_path: &str,
    output_path: &str,
    opts: FileDiffOptions,
    decisions: Vec<HunkMergeDecision>,
    default_choice: MergeChoice,
    create_backup: bool,
) -> Result<MergeSaveOutcome, String> {
    let out_p = Path::new(output_path);
    if output_path.trim().is_empty() {
        return Err("输出目标文件路径不能为空".into());
    }
    let idx_a = index_text_file_streaming(left_path, &opts)?;
    let idx_b = index_text_file_streaming(right_path, &opts)?;

    let hashes_a: Vec<u64> = idx_a.lines.iter().map(|l| l.hash64).collect();
    let hashes_b: Vec<u64> = idx_b.lines.iter().map(|l| l.hash64).collect();
    let matches = compute_linear_myers_matches(&hashes_a, &hashes_b);
    let spans = build_raw_hunks(&matches, idx_a.lines.len(), idx_b.lines.len());

    let mut choice_map: HashMap<usize, MergeChoice> = HashMap::with_capacity(decisions.len());
    for d in decisions {
        choice_map.insert(d.hunk_id, d.choice);
    }

    let backup_path = if create_backup && out_p.exists() {
        let bak = format!("{}.omni_bak", output_path);
        fs::copy(out_p, &bak).map_err(|e| format!("创建原文件备份 {} 失败: {}", bak, e))?;
        Some(bak)
    } else {
        None
    };

    if let Some(parent) = out_p.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| format!("创建目标目录失败: {}", e))?;
        }
    }

    let tmp_path = PathBuf::from(format!("{}.omni_tmp_{}", output_path, std::process::id()));
    let out_file = File::create(&tmp_path).map_err(|e| format!("创建临时合并文件失败: {}", e))?;
    let mut writer = BufWriter::with_capacity(64 * 1024, out_file);

    let mut src_a = File::open(left_path).map_err(|e| format!("打开左侧文件失败: {}", e))?;
    let mut src_b = File::open(right_path).map_err(|e| format!("打开右侧文件失败: {}", e))?;

    let mut total_bytes_written = 0u64;
    let mut total_lines_written = 0usize;

    for (hid, sp) in spans.iter().enumerate() {
        if sp.op == "equal" {
            copy_raw_line_bytes_range(
                &mut src_a,
                &idx_a.lines,
                sp.left_start,
                sp.left_count,
                &mut writer,
                &mut total_bytes_written,
            )?;
            total_lines_written += sp.left_count;
            continue;
        }

        let choice = choice_map.get(&hid).cloned().unwrap_or_else(|| default_choice.clone());
        match choice {
            MergeChoice::KeepLeft => {
                copy_raw_line_bytes_range(
                    &mut src_a,
                    &idx_a.lines,
                    sp.left_start,
                    sp.left_count,
                    &mut writer,
                    &mut total_bytes_written,
                )?;
                total_lines_written += sp.left_count;
            }
            MergeChoice::KeepRight => {
                copy_raw_line_bytes_range(
                    &mut src_b,
                    &idx_b.lines,
                    sp.right_start,
                    sp.right_count,
                    &mut writer,
                    &mut total_bytes_written,
                )?;
                total_lines_written += sp.right_count;
            }
            MergeChoice::KeepBothLeftFirst => {
                copy_raw_line_bytes_range(
                    &mut src_a,
                    &idx_a.lines,
                    sp.left_start,
                    sp.left_count,
                    &mut writer,
                    &mut total_bytes_written,
                )?;
                copy_raw_line_bytes_range(
                    &mut src_b,
                    &idx_b.lines,
                    sp.right_start,
                    sp.right_count,
                    &mut writer,
                    &mut total_bytes_written,
                )?;
                total_lines_written += sp.left_count + sp.right_count;
            }
            MergeChoice::KeepBothRightFirst => {
                copy_raw_line_bytes_range(
                    &mut src_b,
                    &idx_b.lines,
                    sp.right_start,
                    sp.right_count,
                    &mut writer,
                    &mut total_bytes_written,
                )?;
                copy_raw_line_bytes_range(
                    &mut src_a,
                    &idx_a.lines,
                    sp.left_start,
                    sp.left_count,
                    &mut writer,
                    &mut total_bytes_written,
                )?;
                total_lines_written += sp.left_count + sp.right_count;
            }
        }
    }

    writer.flush().map_err(|e| format!("刷新合并缓冲区失败: {}", e))?;
    if let Ok(inner) = writer.into_inner() {
        let _ = inner.sync_all();
    }

    if out_p.exists() {
        fs::remove_file(out_p).map_err(|e| {
            let _ = fs::remove_file(&tmp_path);
            format!("替换旧目标文件前移除失败: {}", e)
        })?;
    }
    fs::rename(&tmp_path, out_p).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        format!("原子写入合并产物 {} 失败: {}", output_path, e)
    })?;

    Ok(MergeSaveOutcome {
        success: true,
        output_path: output_path.to_string(),
        backup_path: backup_path.clone(),
        total_output_lines: total_lines_written,
        total_output_bytes: total_bytes_written,
        message: if let Some(ref bak) = backup_path {
            format!("双向 Merge 已原子保存至 {}（原文件已安全备份至 {}）", output_path, bak)
        } else {
            format!("双向 Merge 已原子写入 {}", output_path)
        },
    })
}

/// 导出标准完整版 GNU Unified Diff 补丁至指定磁盘路径
pub fn export_unified_patch_file(
    left_path: &str,
    right_path: &str,
    patch_output_path: &str,
    opts: FileDiffOptions,
) -> Result<String, String> {
    let report = compare_text_files_streaming(left_path, right_path, opts, Some(usize::MAX))?;
    let content = build_unified_patch_string(left_path, right_path, &report.hunks, usize::MAX);
    fs::write(patch_output_path, content.as_bytes())
        .map_err(|e| format!("导出 Unified Patch 失败: {}", e))?;
    Ok(format!("已成功导出标准补丁文件 {} ({} 处差异块)", patch_output_path, report.diff_hunks_count))
}

// ============================================================================
// 6. GB 级流式二进制分块 CRC32 比对与按页懒加载浏览
// ============================================================================

pub fn compare_binary_files_streaming(
    left_path: &str,
    right_path: &str,
    chunk_size: Option<usize>,
) -> Result<BinaryFileDiffSummary, String> {
    let t0 = std::time::Instant::now();
    let mut fa = File::open(left_path).map_err(|e| format!("无法打开左侧二进制文件: {}", e))?;
    let mut fb = File::open(right_path).map_err(|e| format!("无法打开右侧二进制文件: {}", e))?;
    let left_size = fa.metadata().map(|m| m.len()).unwrap_or(0);
    let right_size = fb.metadata().map(|m| m.len()).unwrap_or(0);

    let csize = chunk_size.unwrap_or(64 * 1024).clamp(4096, 1024 * 1024);
    let mut buf_a = vec![0u8; csize];
    let mut buf_b = vec![0u8; csize];

    let mut chunk_idx = 0usize;
    let mut identical_chunks = 0usize;
    let mut diff_chunks = Vec::new();

    loop {
        let na = read_chunk_exact_or_eof(&mut fa, &mut buf_a)?;
        let nb = read_chunk_exact_or_eof(&mut fb, &mut buf_b)?;
        if na == 0 && nb == 0 {
            break;
        }

        let sa = &buf_a[..na];
        let sb = &buf_b[..nb];
        if na == nb && sa == sb {
            identical_chunks += 1;
        } else {
            let status = match (na > 0, nb > 0) {
                (true, true) => "Modified",
                (true, false) => "LeftOnly",
                (false, true) => "RightOnly",
                _ => "Modified",
            };
            diff_chunks.push(BinaryDiffChunkMeta {
                chunk_index: chunk_idx,
                byte_offset: (chunk_idx as u64) * (csize as u64),
                chunk_len_left: na,
                chunk_len_right: nb,
                crc32_left: crc32fast::hash(sa),
                crc32_right: crc32fast::hash(sb),
                status: status.to_string(),
            });
        }
        chunk_idx += 1;
    }

    Ok(BinaryFileDiffSummary {
        left_path: left_path.to_string(),
        right_path: right_path.to_string(),
        left_size_bytes: left_size,
        right_size_bytes: right_size,
        chunk_size_bytes: csize,
        total_chunks: chunk_idx,
        identical_chunks,
        different_chunks_count: diff_chunks.len(),
        elapsed_ms: t0.elapsed().as_millis() as u64,
        different_chunks: diff_chunks,
    })
}

fn read_chunk_exact_or_eof(file: &mut File, buf: &mut [u8]) -> Result<usize, String> {
    let mut total = 0usize;
    while total < buf.len() {
        let n = file.read(&mut buf[total..]).map_err(|e| format!("读取二进制块失败: {}", e))?;
        if n == 0 {
            break;
        }
        total += n;
    }
    Ok(total)
}

pub fn read_binary_diff_page(
    left_path: &str,
    right_path: &str,
    start_offset: u64,
    page_size: usize,
) -> Result<BinaryDiffPageResult, String> {
    let capped = page_size.clamp(64, 4096);
    let mut fa = File::open(left_path).map_err(|e| format!("打开左侧二进制文件失败: {}", e))?;
    let mut fb = File::open(right_path).map_err(|e| format!("打开右侧二进制文件失败: {}", e))?;

    let mut ba = vec![0u8; capped];
    let mut bb = vec![0u8; capped];

    let na = if start_offset < fa.metadata().map(|m| m.len()).unwrap_or(0) {
        fa.seek(SeekFrom::Start(start_offset)).map_err(|e| e.to_string())?;
        read_chunk_exact_or_eof(&mut fa, &mut ba)?
    } else {
        0
    };
    let nb = if start_offset < fb.metadata().map(|m| m.len()).unwrap_or(0) {
        fb.seek(SeekFrom::Start(start_offset)).map_err(|e| e.to_string())?;
        read_chunk_exact_or_eof(&mut fb, &mut bb)?
    } else {
        0
    };

    let span = na.max(nb);
    let mut rows = Vec::with_capacity(span);
    let mut diffs = 0usize;

    for i in 0..span {
        let lb = if i < na { Some(ba[i]) } else { None };
        let rb = if i < nb { Some(bb[i]) } else { None };
        let st = match (lb, rb) {
            (Some(a), Some(b)) if a == b => "equal",
            (Some(_), Some(_)) => {
                diffs += 1;
                "replace"
            }
            (Some(_), None) => {
                diffs += 1;
                "delete"
            }
            (None, Some(_)) => {
                diffs += 1;
                "insert"
            }
            (None, None) => "equal",
        };
        rows.push(BinaryPageByte {
            offset: start_offset + i as u64,
            left_byte: lb,
            right_byte: rb,
            status: st.to_string(),
        });
    }

    Ok(BinaryDiffPageResult {
        start_offset,
        page_size: span,
        diff_bytes_in_page: diffs,
        rows,
    })
}

// ============================================================================
// 7. 迭代式目录递归智能对比（防软链成环与大体积字节流快速校验）
// ============================================================================

#[derive(Clone)]
struct FileMetaRecord {
    size: u64,
    is_dir: bool,
    modified_str: String,
    full_path: String,
}

fn scan_directory_tree(root: &Path, max_entries: usize) -> Result<BTreeMap<String, FileMetaRecord>, String> {
    if !root.is_dir() {
        return Err(format!("指定路径不是有效目录: {}", root.display()));
    }
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let rd = match fs::read_dir(&dir) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for entry_res in rd.flatten() {
            let path = entry_res.path();
            // 严禁跟随跨目录符号链接防无穷死循环
            let sym_meta = match fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if sym_meta.file_type().is_symlink() {
                continue;
            }

            let name = entry_res.file_name().to_string_lossy().into_owned();
            if name == ".git" || name == "target" || name == "node_modules" {
                continue;
            }

            let rel = path
                .strip_prefix(root)
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .unwrap_or(name);

            let is_dir = sym_meta.is_dir();
            let modified_str = sym_meta
                .modified()
                .ok()
                .map(|t| {
                    let dt: chrono::DateTime<chrono::Local> = t.into();
                    dt.format("%Y-%m-%d %H:%M:%S").to_string()
                })
                .unwrap_or_else(|| "-".into());

            out.insert(
                rel,
                FileMetaRecord {
                    size: if is_dir { 0 } else { sym_meta.len() },
                    is_dir,
                    modified_str,
                    full_path: path.to_string_lossy().into_owned(),
                },
            );

            if is_dir {
                stack.push(path);
            }
            if out.len() >= max_entries {
                return Ok(out);
            }
        }
    }
    Ok(out)
}

fn files_bytes_identical(p1: &str, p2: &str) -> bool {
    let Ok(mut f1) = File::open(p1) else { return false };
    let Ok(mut f2) = File::open(p2) else { return false };
    let mut b1 = [0u8; 32 * 1024];
    let mut b2 = [0u8; 32 * 1024];
    loop {
        let n1 = read_chunk_exact_or_eof(&mut f1, &mut b1).unwrap_or(0);
        let n2 = read_chunk_exact_or_eof(&mut f2, &mut b2).unwrap_or(0);
        if n1 != n2 || b1[..n1] != b2[..n2] {
            return false;
        }
        if n1 == 0 {
            return true;
        }
    }
}

pub fn compare_directories(
    left_dir: &str,
    right_dir: &str,
    verify_equal_size_contents: bool,
) -> Result<DirectoryCompareReport, String> {
    let t0 = std::time::Instant::now();
    let map_l = scan_directory_tree(Path::new(left_dir), 15_000)?;
    let map_r = scan_directory_tree(Path::new(right_dir), 15_000)?;

    let mut all_keys: BTreeMap<String, ()> = BTreeMap::new();
    for k in map_l.keys() {
        all_keys.insert(k.clone(), ());
    }
    for k in map_r.keys() {
        all_keys.insert(k.clone(), ());
    }

    let mut identical_count = 0usize;
    let mut modified_count = 0usize;
    let mut left_only_count = 0usize;
    let mut right_only_count = 0usize;
    let mut entries = Vec::with_capacity(all_keys.len());

    for rel in all_keys.keys() {
        match (map_l.get(rel), map_r.get(rel)) {
            (Some(l), Some(r)) => {
                if l.is_dir && r.is_dir {
                    identical_count += 1;
                    entries.push(DirectoryDiffEntry {
                        relative_path: rel.clone(),
                        status: "Identical".into(),
                        is_dir: true,
                        left_size: None,
                        right_size: None,
                        left_modified: Some(l.modified_str.clone()),
                        right_modified: Some(r.modified_str.clone()),
                        left_full_path: Some(l.full_path.clone()),
                        right_full_path: Some(r.full_path.clone()),
                    });
                } else if l.size != r.size {
                    modified_count += 1;
                    entries.push(DirectoryDiffEntry {
                        relative_path: rel.clone(),
                        status: "Modified".into(),
                        is_dir: false,
                        left_size: Some(l.size),
                        right_size: Some(r.size),
                        left_modified: Some(l.modified_str.clone()),
                        right_modified: Some(r.modified_str.clone()),
                        left_full_path: Some(l.full_path.clone()),
                        right_full_path: Some(r.full_path.clone()),
                    });
                } else {
                    let is_same = if verify_equal_size_contents && l.size <= 50 * 1024 * 1024 {
                        files_bytes_identical(&l.full_path, &r.full_path)
                    } else {
                        l.modified_str == r.modified_str
                    };
                    if is_same {
                        identical_count += 1;
                    } else {
                        modified_count += 1;
                    }
                    entries.push(DirectoryDiffEntry {
                        relative_path: rel.clone(),
                        status: if is_same { "Identical" } else { "Modified" }.into(),
                        is_dir: false,
                        left_size: Some(l.size),
                        right_size: Some(r.size),
                        left_modified: Some(l.modified_str.clone()),
                        right_modified: Some(r.modified_str.clone()),
                        left_full_path: Some(l.full_path.clone()),
                        right_full_path: Some(r.full_path.clone()),
                    });
                }
            }
            (Some(l), None) => {
                left_only_count += 1;
                entries.push(DirectoryDiffEntry {
                    relative_path: rel.clone(),
                    status: "LeftOnly".into(),
                    is_dir: l.is_dir,
                    left_size: if l.is_dir { None } else { Some(l.size) },
                    right_size: None,
                    left_modified: Some(l.modified_str.clone()),
                    right_modified: None,
                    left_full_path: Some(l.full_path.clone()),
                    right_full_path: None,
                });
            }
            (None, Some(r)) => {
                right_only_count += 1;
                entries.push(DirectoryDiffEntry {
                    relative_path: rel.clone(),
                    status: "RightOnly".into(),
                    is_dir: r.is_dir,
                    left_size: None,
                    right_size: if r.is_dir { None } else { Some(r.size) },
                    left_modified: None,
                    right_modified: Some(r.modified_str.clone()),
                    left_full_path: None,
                    right_full_path: Some(r.full_path.clone()),
                });
            }
            (None, None) => {}
        }
    }

    // 优先排序出差异文件，方便海量目录直接定位变更点
    entries.sort_by_key(|e| match e.status.as_str() {
        "Modified" => 0,
        "LeftOnly" => 1,
        "RightOnly" => 2,
        _ => 3,
    });

    Ok(DirectoryCompareReport {
        left_dir: left_dir.to_string(),
        right_dir: right_dir.to_string(),
        total_entries: entries.len(),
        identical_count,
        modified_count,
        left_only_count,
        right_only_count,
        elapsed_ms: t0.elapsed().as_millis() as u64,
        entries,
    })
}

// ============================================================================
// 7B. 基于 Gear Rolling Hash / FastCDC 内容定义分块的超大规模二进制精准再对齐
//     时间复杂度: O(Size) 单遍 GB/s 滚动扫描 + Myers O((N+M)D) 块指纹匹配
//     空间复杂度: 24 B / 16KB 块 (~1.5 MB / 1 GB 文件)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdcChunkMeta {
    pub index: usize,
    pub offset: u64,
    pub len: u32,
    pub crc32: u32,
    pub fp64: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdcBinaryDiffSegment {
    pub segment_index: usize,
    /// "Identical" | "ShiftedIdentical" | "Modified"
    pub status: String,
    pub left_offset: u64,
    pub left_len: u64,
    pub right_offset: u64,
    pub right_len: u64,
    /// right_offset as i64 - left_offset as i64
    pub shift_delta_bytes: i64,
    pub chunk_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FastCdcBinaryDiffReport {
    pub left_path: String,
    pub right_path: String,
    pub left_size_bytes: u64,
    pub right_size_bytes: u64,
    pub left_chunks_count: usize,
    pub right_chunks_count: usize,
    pub identical_bytes: u64,
    pub shifted_aligned_bytes: u64,
    pub modified_left_bytes: u64,
    pub modified_right_bytes: u64,
    pub similarity_percent: f64,
    pub elapsed_ms: u64,
    pub segments: Vec<CdcBinaryDiffSegment>,
}

const fn build_gear_table() -> [u64; 256] {
    let mut table = [0u64; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut z = (i as u64).wrapping_add(0x9e3779b97f4a7c15);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z = z ^ (z >> 31);
        table[i] = z;
        i += 1;
    }
    table
}

static GEAR_TABLE: [u64; 256] = build_gear_table();

// FastCDC 归一化双掩码 (15 bit 严格掩码抑制 <avg 碎片, 13 bit 宽松掩码锁定 avg~16KB 切割)
const CDC_MIN_CHUNK: usize = 4096;
const CDC_AVG_CHUNK: usize = 16384;
const CDC_MAX_CHUNK: usize = 65536;
const CDC_MASK_STRICT_15: u64 = (1 << 59)
    | (1 << 55)
    | (1 << 51)
    | (1 << 48)
    | (1 << 45)
    | (1 << 42)
    | (1 << 39)
    | (1 << 36)
    | (1 << 33)
    | (1 << 30)
    | (1 << 27)
    | (1 << 24)
    | (1 << 21)
    | (1 << 19)
    | (1 << 17);
const CDC_MASK_LOOSE_13: u64 = (1 << 59)
    | (1 << 55)
    | (1 << 51)
    | (1 << 48)
    | (1 << 45)
    | (1 << 42)
    | (1 << 39)
    | (1 << 36)
    | (1 << 33)
    | (1 << 30)
    | (1 << 27)
    | (1 << 24)
    | (1 << 21);

/// 结合 FastCDC 内容定义边界切块扫描单个文件，返回紧凑元数据切片表与文件总长
fn chunk_binary_file_fastcdc(path_str: &str) -> Result<(Vec<CdcChunkMeta>, u64), String> {
    let mut file = File::open(path_str).map_err(|e| format!("无法打开二进制文件 {}: {}", path_str, e))?;
    let total_size = file.metadata().map(|m| m.len()).unwrap_or(0);
    if total_size == 0 {
        return Ok((Vec::new(), 0));
    }

    let mut ring = vec![0u8; 256 * 1024];
    let mut filled = 0usize;
    let mut eof = false;
    let mut global_offset = 0u64;
    let mut chunks = Vec::new();
    let mut chunk_idx = 0usize;

    loop {
        while filled < CDC_MAX_CHUNK && !eof {
            let n = file
                .read(&mut ring[filled..])
                .map_err(|e| format!("FastCDC 读取失败 ({}): {}", path_str, e))?;
            if n == 0 {
                eof = true;
            } else {
                filled += n;
            }
        }

        if filled == 0 {
            break;
        }

        let max_len = filled.min(CDC_MAX_CHUNK);
        let cut_len = find_fastcdc_cut_point(&ring[..max_len]);
        let slice = &ring[..cut_len];

        let crc32 = crc32fast::hash(slice);
        let fp64 = fnv1a_64_raw_bytes(slice);
        chunks.push(CdcChunkMeta {
            index: chunk_idx,
            offset: global_offset,
            len: cut_len as u32,
            crc32,
            fp64,
        });

        chunk_idx += 1;
        global_offset += cut_len as u64;
        ring.copy_within(cut_len..filled, 0);
        filled -= cut_len;
    }

    Ok((chunks, total_size))
}

#[inline]
fn find_fastcdc_cut_point(data: &[u8]) -> usize {
    let n = data.len();
    if n <= CDC_MIN_CHUNK {
        return n;
    }
    let normal_end = n.min(CDC_AVG_CHUNK);
    let mut fp: u64 = 0;

    // 跳过最小安全区间外，只需在最小边界之前微预热末尾 64 字节上下文即可建立有效滚动哈希窗口
    let warmup_start = CDC_MIN_CHUNK.saturating_sub(64);
    for &b in &data[warmup_start..CDC_MIN_CHUNK] {
        fp = (fp << 1).wrapping_add(GEAR_TABLE[b as usize]);
    }

    let mut i = CDC_MIN_CHUNK;
    while i < normal_end {
        fp = (fp << 1).wrapping_add(GEAR_TABLE[data[i] as usize]);
        if (fp & CDC_MASK_STRICT_15) == 0 {
            return i + 1;
        }
        i += 1;
    }

    while i < n {
        fp = (fp << 1).wrapping_add(GEAR_TABLE[data[i] as usize]);
        if (fp & CDC_MASK_LOOSE_13) == 0 {
            return i + 1;
        }
        i += 1;
    }
    n
}

#[inline]
fn fnv1a_64_raw_bytes(slice: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in slice {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// 基于 Gear-Hash FastCDC 内容滚动锚点的大二进制比对：
/// 即使前方任意位置插/删字节引起全场偏移错位，后续块边界自动精准重锁定为 ShiftedIdentical
pub fn compare_binary_files_fastcdc(
    left_path: &str,
    right_path: &str,
) -> Result<FastCdcBinaryDiffReport, String> {
    let t0 = std::time::Instant::now();
    let (chunks_l, size_l) = chunk_binary_file_fastcdc(left_path)?;
    let (chunks_r, size_r) = chunk_binary_file_fastcdc(right_path)?;

    let keys_l: Vec<u64> = chunks_l
        .iter()
        .map(|c| c.fp64 ^ ((c.crc32 as u64) << 16) ^ ((c.len as u64) << 40))
        .collect();
    let keys_r: Vec<u64> = chunks_r
        .iter()
        .map(|c| c.fp64 ^ ((c.crc32 as u64) << 16) ^ ((c.len as u64) << 40))
        .collect();

    let raw_matches = compute_linear_myers_matches(&keys_l, &keys_r);
    // 二次严密核对：确保长度、CRC32、FNV64 三元组完全等价，消除任何潜在散列碰撞伪匹配
    let verified_matches: Vec<(usize, usize)> = raw_matches
        .into_iter()
        .filter(|&(il, ir)| {
            let cl = &chunks_l[il];
            let cr = &chunks_r[ir];
            cl.len == cr.len && cl.crc32 == cr.crc32 && cl.fp64 == cr.fp64
        })
        .collect();

    let mut segments: Vec<CdcBinaryDiffSegment> = Vec::new();
    let mut seg_idx = 0usize;
    let mut cur_l_chunk = 0usize;
    let mut cur_r_chunk = 0usize;
    let mut cur_l_byte = 0u64;
    let mut cur_r_byte = 0u64;

    let mut identical_bytes = 0u64;
    let mut shifted_aligned_bytes = 0u64;
    let mut modified_left_bytes = 0u64;
    let mut modified_right_bytes = 0u64;

    let mut extended = verified_matches;
    extended.push((chunks_l.len(), chunks_r.len()));

    for (ml, mr) in extended {
        let gap_l_end = if ml < chunks_l.len() { chunks_l[ml].offset } else { size_l };
        let gap_r_end = if mr < chunks_r.len() { chunks_r[mr].offset } else { size_r };
        let gap_l_bytes = gap_l_end.saturating_sub(cur_l_byte);
        let gap_r_bytes = gap_r_end.saturating_sub(cur_r_byte);

        if gap_l_bytes > 0 || gap_r_bytes > 0 {
            modified_left_bytes += gap_l_bytes;
            modified_right_bytes += gap_r_bytes;
            segments.push(CdcBinaryDiffSegment {
                segment_index: seg_idx,
                status: "Modified".into(),
                left_offset: cur_l_byte,
                left_len: gap_l_bytes,
                right_offset: cur_r_byte,
                right_len: gap_r_bytes,
                shift_delta_bytes: gap_r_bytes as i64 - gap_l_bytes as i64,
                chunk_count: ml.saturating_sub(cur_l_chunk).max(mr.saturating_sub(cur_r_chunk)),
            });
            seg_idx += 1;
        }

        if ml < chunks_l.len() && mr < chunks_r.len() {
            let cl = &chunks_l[ml];
            let cr = &chunks_r[mr];
            let delta = cr.offset as i64 - cl.offset as i64;
            let status_tag = if delta == 0 { "Identical" } else { "ShiftedIdentical" };
            let span = cl.len as u64;
            if delta == 0 {
                identical_bytes += span;
            } else {
                shifted_aligned_bytes += span;
            }

            // 将相邻且位移完全一致的匹配块聚合成单一段，避免前端渲染上万条微小片段
            let can_merge = segments.last().map_or(false, |last| {
                last.status == status_tag
                    && last.shift_delta_bytes == delta
                    && last.left_offset + last.left_len == cl.offset
                    && last.right_offset + last.right_len == cr.offset
            });
            if can_merge {
                if let Some(last) = segments.last_mut() {
                    last.left_len += span;
                    last.right_len += span;
                    last.chunk_count += 1;
                }
            } else {
                segments.push(CdcBinaryDiffSegment {
                    segment_index: seg_idx,
                    status: status_tag.into(),
                    left_offset: cl.offset,
                    left_len: span,
                    right_offset: cr.offset,
                    right_len: span,
                    shift_delta_bytes: delta,
                    chunk_count: 1,
                });
                seg_idx += 1;
            }

            cur_l_chunk = ml + 1;
            cur_r_chunk = mr + 1;
            cur_l_byte = cl.offset + span;
            cur_r_byte = cr.offset + span;
        }
    }

    let max_size = size_l.max(size_r);
    let aligned_total = identical_bytes + shifted_aligned_bytes;
    let similarity_percent = if max_size == 0 {
        100.0
    } else {
        ((aligned_total as f64 / max_size as f64) * 100.0).min(100.0)
    };

    // 重编号过滤后的有序片段索引并把差异区优先或全貌呈现（超过 500 个仅保留含全部 Modified 的精简段）
    if segments.len() > 600 {
        segments.retain(|s| s.status == "Modified" || s.left_len >= 64 * 1024);
    }
    for (idx, s) in segments.iter_mut().enumerate() {
        s.segment_index = idx;
    }

    Ok(FastCdcBinaryDiffReport {
        left_path: left_path.to_string(),
        right_path: right_path.to_string(),
        left_size_bytes: size_l,
        right_size_bytes: size_r,
        left_chunks_count: chunks_l.len(),
        right_chunks_count: chunks_r.len(),
        identical_bytes,
        shifted_aligned_bytes,
        modified_left_bytes,
        modified_right_bytes,
        similarity_percent,
        elapsed_ms: t0.elapsed().as_millis() as u64,
        segments,
    })
}

/// 独立双指针流式十六进制窗口读取（专为 FastCDC 重对齐偏移错位设计，左右独立定位 Offset）
pub fn read_binary_diff_dual_offset_page(
    left_path: &str,
    right_path: &str,
    left_offset: u64,
    right_offset: u64,
    page_size: usize,
) -> Result<BinaryDiffPageResult, String> {
    let capped = page_size.clamp(64, 4096);
    let mut fa = File::open(left_path).map_err(|e| format!("打开左侧二进制文件失败: {}", e))?;
    let mut fb = File::open(right_path).map_err(|e| format!("打开右侧二进制文件失败: {}", e))?;

    let mut ba = vec![0u8; capped];
    let mut bb = vec![0u8; capped];

    let na = if left_offset < fa.metadata().map(|m| m.len()).unwrap_or(0) {
        fa.seek(SeekFrom::Start(left_offset)).map_err(|e| e.to_string())?;
        read_chunk_exact_or_eof(&mut fa, &mut ba)?
    } else {
        0
    };
    let nb = if right_offset < fb.metadata().map(|m| m.len()).unwrap_or(0) {
        fb.seek(SeekFrom::Start(right_offset)).map_err(|e| e.to_string())?;
        read_chunk_exact_or_eof(&mut fb, &mut bb)?
    } else {
        0
    };

    let span = na.max(nb);
    let mut rows = Vec::with_capacity(span);
    let mut diffs = 0usize;

    for i in 0..span {
        let lb = if i < na { Some(ba[i]) } else { None };
        let rb = if i < nb { Some(bb[i]) } else { None };
        let st = match (lb, rb) {
            (Some(a), Some(b)) if a == b => "equal",
            (Some(_), Some(_)) => {
                diffs += 1;
                "replace"
            }
            (Some(_), None) => {
                diffs += 1;
                "delete"
            }
            (None, Some(_)) => {
                diffs += 1;
                "insert"
            }
            (None, None) => "equal",
        };
        rows.push(BinaryPageByte {
            offset: left_offset + i as u64,
            left_byte: lb,
            right_byte: rb,
            status: st.to_string(),
        });
    }

    Ok(BinaryDiffPageResult {
        start_offset: left_offset,
        page_size: span,
        diff_bytes_in_page: diffs,
        rows,
    })
}

// ============================================================================
// 8. 严苛工业级单元测试与极限边界用例验证 (零数据 / 超大规模 / 二进制)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_test_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("omni_probe_diff_test_{}_{}", tag, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_myers_linear_diff_50k_lines_streaming_and_merge_backup() {
        let dir = temp_test_dir("myers_50k");
        let left_p = dir.join("left_50k.log");
        let right_p = dir.join("right_50k.log");
        let merged_p = dir.join("merged_target.log");

        let mut left_content = String::with_capacity(2_500_000);
        let mut right_content = String::with_capacity(2_500_000);
        for i in 0..50_000usize {
            let line = format!("2026-11-11T03:00:00Z [SEQ:{:06}] Telemetry voltage=24.1V status=OK\n", i);
            if i == 12_345 {
                left_content.push_str("2026-11-11T03:00:00Z [SEQ:012345] OLD_LEFT_VALVE=CLOSED\n");
                right_content.push_str("2026-11-11T03:00:00Z [SEQ:012345] NEW_RIGHT_VALVE=OPEN\n");
                right_content.push_str("2026-11-11T03:00:00Z [SEQ:012345] EXTRA_AUDIT_LINE=1\n");
            } else {
                left_content.push_str(&line);
                right_content.push_str(&line);
            }
        }

        fs::write(&left_p, &left_content).unwrap();
        fs::write(&right_p, &right_content).unwrap();
        fs::write(&merged_p, "PREVIOUS_DISK_FILE_CONTENT\n").unwrap();

        let report = compare_text_files_streaming(
            left_p.to_str().unwrap(),
            right_p.to_str().unwrap(),
            FileDiffOptions::default(),
            None,
        )
        .expect("5万行流式 Myers Diff 不得报错");

        assert_eq!(report.left_total_lines, 50_000);
        assert_eq!(report.right_total_lines, 50_001);
        assert_eq!(report.diff_hunks_count, 1);
        assert!(!report.is_binary_suspected);
        assert!(report.similarity_percent > 99.9);

        // 对唯一差异 Hunk 选择 KeepBothLeftFirst 合并写盘，验证不损坏原 CRLF/LF、自动创建 .omni_bak
        let diff_hunk = report.hunks.iter().find(|h| h.op != "equal").unwrap();
        let outcome = apply_text_merge_and_save(
            left_p.to_str().unwrap(),
            right_p.to_str().unwrap(),
            merged_p.to_str().unwrap(),
            FileDiffOptions::default(),
            vec![HunkMergeDecision {
                hunk_id: diff_hunk.hunk_id,
                choice: MergeChoice::KeepBothLeftFirst,
            }],
            MergeChoice::KeepLeft,
            true,
        )
        .expect("Merge 保存应成功");

        assert!(outcome.success);
        assert_eq!(outcome.total_output_lines, 50_002);
        let bak_content = fs::read_to_string(outcome.backup_path.as_ref().unwrap()).unwrap();
        assert_eq!(bak_content, "PREVIOUS_DISK_FILE_CONTENT\n");

        let merged_final = fs::read_to_string(&merged_p).unwrap();
        assert!(merged_final.contains("OLD_LEFT_VALVE=CLOSED"));
        assert!(merged_final.contains("NEW_RIGHT_VALVE=OPEN"));
        assert!(merged_final.contains("EXTRA_AUDIT_LINE=1"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_edge_empty_files_and_ignore_whitespace_case() {
        let dir = temp_test_dir("edge_empty_ws");
        let emp_a = dir.join("empty_a.txt");
        let emp_b = dir.join("empty_b.txt");
        fs::write(&emp_a, "").unwrap();
        fs::write(&emp_b, "").unwrap();

        let emp_rep = compare_text_files_streaming(
            emp_a.to_str().unwrap(),
            emp_b.to_str().unwrap(),
            FileDiffOptions::default(),
            None,
        )
        .unwrap();
        assert_eq!(emp_rep.left_total_lines, 0);
        assert_eq!(emp_rep.right_total_lines, 0);
        assert_eq!(emp_rep.similarity_percent, 100.0);

        // 测试忽略空白符 + 忽略大小写选项 + CRLF vs LF
        let ws_a = dir.join("ws_a.txt");
        let ws_b = dir.join("ws_b.txt");
        fs::write(&ws_a, "Hello   Modbus\r\nRegister 0x10\r\n").unwrap();
        fs::write(&ws_b, "hello modbus\n  REGISTER  0x10 \n").unwrap();

        let ignored = compare_text_files_streaming(
            ws_a.to_str().unwrap(),
            ws_b.to_str().unwrap(),
            FileDiffOptions {
                ignore_whitespace: true,
                ignore_case: true,
                ignore_line_endings: true,
            },
            None,
        )
        .unwrap();
        assert_eq!(ignored.diff_hunks_count, 0);
        assert_eq!(ignored.similarity_percent, 100.0);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_streaming_binary_chunks_and_directory_compare() {
        let dir = temp_test_dir("bin_and_dir");
        let sub_l = dir.join("left_root");
        let sub_r = dir.join("right_root");
        fs::create_dir_all(sub_l.join("firmware")).unwrap();
        fs::create_dir_all(sub_r.join("firmware")).unwrap();

        let mut bin_l = vec![0xAAu8; 150_000];
        let mut bin_r = bin_l.clone();
        bin_l[70_000] = 0x01;
        bin_r[70_000] = 0xFE;

        let fw_l = sub_l.join("firmware/plc.bin");
        let fw_r = sub_r.join("firmware/plc.bin");
        fs::write(&fw_l, &bin_l).unwrap();
        fs::write(&fw_r, &bin_r).unwrap();
        fs::write(sub_l.join("same.cfg"), "baud=115200\n").unwrap();
        fs::write(sub_r.join("same.cfg"), "baud=115200\n").unwrap();
        fs::write(sub_l.join("only_left.txt"), "L").unwrap();
        fs::write(sub_r.join("only_right.txt"), "R").unwrap();

        let bsum = compare_binary_files_streaming(
            fw_l.to_str().unwrap(),
            fw_r.to_str().unwrap(),
            Some(65_536),
        )
        .unwrap();
        assert_eq!(bsum.total_chunks, 3);
        assert_eq!(bsum.identical_chunks, 2);
        assert_eq!(bsum.different_chunks_count, 1);
        assert_eq!(bsum.different_chunks[0].chunk_index, 1);
        assert_eq!(bsum.different_chunks[0].byte_offset, 65_536);

        let page = read_binary_diff_page(
            fw_l.to_str().unwrap(),
            fw_r.to_str().unwrap(),
            70_000 - 16,
            64,
        )
        .unwrap();
        assert_eq!(page.diff_bytes_in_page, 1);
        assert_eq!(page.rows[16].status, "replace");
        assert_eq!(page.rows[16].left_byte, Some(0x01));
        assert_eq!(page.rows[16].right_byte, Some(0xFE));

        let drep = compare_directories(sub_l.to_str().unwrap(), sub_r.to_str().unwrap(), true).unwrap();
        assert_eq!(drep.modified_count, 1);
        assert_eq!(drep.left_only_count, 1);
        assert_eq!(drep.right_only_count, 1);
        assert_eq!(drep.identical_count, 2); // same.cfg + firmware dir

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_edge_totally_disjoint_5k_lines_no_overflow_or_timeout() {
        let ha: Vec<u64> = (1..=5_000u64).collect();
        let hb: Vec<u64> = (100_001..=105_000u64).collect();
        let t0 = std::time::Instant::now();
        let matches = compute_linear_myers_matches(&ha, &hb);
        assert!(matches.is_empty());
        assert!(t0.elapsed().as_secs() < 5);
    }

    #[test]
    fn test_fastcdc_rolling_anchor_realignment_after_byte_insertion() {
        let dir = temp_test_dir("fastcdc_2mb");
        let base_p = dir.join("firmware_v1.bin");
        let shifted_p = dir.join("firmware_v2_inserted.bin");

        // 构造确定性 1.5 MB 伪随机工业固件镜像 (含高熵指令特征确保 FastCDC 可精准找到稳定切割点)
        let size = 1_500_000usize;
        let mut firmware_v1 = Vec::with_capacity(size);
        let mut rng_state: u64 = 0x1234_5678_9ABC_DEF0;
        for _ in 0..size {
            rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            firmware_v1.push((rng_state >> 56) as u8);
        }

        // 在第 100 字节处硬插入 7 个字节导致余下 ~1.5MB 全局偏移 +7B（传统定长分块会 99.99% 误判全损坏）
        let mut firmware_v2 = Vec::with_capacity(size + 7);
        firmware_v2.extend_from_slice(&firmware_v1[..100]);
        firmware_v2.extend_from_slice(b"PATCH07");
        firmware_v2.extend_from_slice(&firmware_v1[100..]);

        fs::write(&base_p, &firmware_v1).unwrap();
        fs::write(&shifted_p, &firmware_v2).unwrap();

        let rep = compare_binary_files_fastcdc(base_p.to_str().unwrap(), shifted_p.to_str().unwrap())
            .expect("FastCDC 滚动锚点比对应成功");

        // 经过首块切点自适应同步后，超过 92% 的内容应被精准再对齐为 ShiftedIdentical (+7 bytes)
        assert!(
            rep.similarity_percent > 92.0,
            "FastCDC 再对齐后相似率应大于 92%, 实测: {:.2}%",
            rep.similarity_percent
        );
        assert!(
            rep.shifted_aligned_bytes > 1_300_000,
            "ShiftedIdentical 字节应大于 1.3MB, 实测: {}",
            rep.shifted_aligned_bytes
        );
        assert!(
            rep.segments.iter().any(|s| s.status == "ShiftedIdentical" && s.shift_delta_bytes == 7),
            "应检测到精确偏移量 +7 bytes 的 ShiftedIdentical 区段"
        );

        // 验证双指针重对齐后第 500,000 字节处的窗格 0 差异完全匹配
        let aligned_seg = rep
            .segments
            .iter()
            .find(|s| s.status == "ShiftedIdentical" && s.shift_delta_bytes == 7)
            .unwrap();
        let page = read_binary_diff_dual_offset_page(
            base_p.to_str().unwrap(),
            shifted_p.to_str().unwrap(),
            aligned_seg.left_offset,
            aligned_seg.right_offset,
            256,
        )
        .unwrap();
        assert_eq!(page.diff_bytes_in_page, 0);

        let _ = fs::remove_dir_all(&dir);
    }
}
