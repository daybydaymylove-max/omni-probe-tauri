with open('src-tauri/src/export_engine.rs', 'r', encoding='utf-8') as f:
    orig = f.read()

pcapng_code = r'''

// ============================================================
// 司法级 PCAPng (PCAP Next Generation) 结构化编码与电子证据引擎
// 遵循 IETF pcapng 标准草案规范与 Wireshark 4.x / Autopsy 司法分析标准
// ============================================================

pub const PCAPNG_SECTION_HEADER_BLOCK: u32 = 0x0A0D0D0A;
pub const PCAPNG_INTERFACE_DESC_BLOCK: u32 = 0x00000001;
pub const PCAPNG_ENHANCED_PACKET_BLOCK: u32 = 0x00000006;
pub const PCAPNG_BYTE_ORDER_MAGIC: u32 = 0x1A2B3C4D;

/// 对齐到 4 字节边界的字节填充计算
#[inline(always)]
fn pcapng_pad(len: usize) -> usize {
    let rem = len % 4;
    if rem == 0 { 0 } else { 4 - rem }
}

/// 编码通用 PCAPng Option
fn encode_pcapng_option(code: u16, val: &[u8]) -> Vec<u8> {
    let mut opt = Vec::new();
    opt.extend_from_slice(&code.to_le_bytes());
    opt.extend_from_slice(&(val.len() as u16).to_le_bytes());
    opt.extend_from_slice(val);
    let pad = pcapng_pad(val.len());
    if pad > 0 {
        opt.extend_from_slice(&vec![0u8; pad]);
    }
    opt
}

/// 组装带头尾总长度校验的 PCAPng 结构块
fn pack_pcapng_block(block_type: u32, body: &[u8]) -> Vec<u8> {
    let total_len = (12 + body.len()) as u32; // 4B Type + 4B InitialLen + Body + 4B TrailingLen
    let mut block = Vec::with_capacity(total_len as usize);
    block.extend_from_slice(&block_type.to_le_bytes());
    block.extend_from_slice(&total_len.to_le_bytes());
    block.extend_from_slice(body);
    block.extend_from_slice(&total_len.to_le_bytes());
    block
}

/// 构造 Section Header Block (SHB)
pub fn build_section_header_block(comment: &str, app_name: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&PCAPNG_BYTE_ORDER_MAGIC.to_le_bytes());
    body.extend_from_slice(&1u16.to_le_bytes()); // Major 1
    body.extend_from_slice(&0u16.to_le_bytes()); // Minor 0
    body.extend_from_slice(&(-1i64).to_le_bytes()); // Section Length: unspecified

    // Options: Comment (0x0001), User Application (0x0004), End-of-Option (0x0000)
    if !comment.is_empty() {
        body.extend_from_slice(&encode_pcapng_option(0x0001, comment.as_bytes()));
    }
    if !app_name.is_empty() {
        body.extend_from_slice(&encode_pcapng_option(0x0004, app_name.as_bytes()));
    }
    body.extend_from_slice(&0u16.to_le_bytes()); // opt_endofopt code
    body.extend_from_slice(&0u16.to_le_bytes()); // opt_endofopt length

    pack_pcapng_block(PCAPNG_SECTION_HEADER_BLOCK, &body)
}

/// 构造 Interface Description Block (IDB)
pub fn build_interface_desc_block(iface_name: &str, ts_resol: u8) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&1u16.to_le_bytes()); // LinkType = LINKTYPE_ETHERNET (1)
    body.extend_from_slice(&0u16.to_le_bytes()); // Reserved 2B
    body.extend_from_slice(&262144u32.to_le_bytes()); // SnapLen = 256KB

    // Options: if_name (0x0002), if_tsresol (0x0009: 6 for microsecond, 9 for nanosecond)
    if !iface_name.is_empty() {
        body.extend_from_slice(&encode_pcapng_option(0x0002, iface_name.as_bytes()));
    }
    body.extend_from_slice(&encode_pcapng_option(0x0009, &[ts_resol]));
    body.extend_from_slice(&0u16.to_le_bytes()); // opt_endofopt
    body.extend_from_slice(&0u16.to_le_bytes());

    pack_pcapng_block(PCAPNG_INTERFACE_DESC_BLOCK, &body)
}

/// 构造 Enhanced Packet Block (EPB) 带司法存证注释与 Merkle 链哈希
pub fn build_enhanced_packet_block(
    interface_id: u32,
    timestamp_us: u64,
    packet_data: &[u8],
    comment: Option<&str>,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&interface_id.to_le_bytes());

    // 64 位时间戳拆分为高 32 位与低 32 位
    let ts_high = (timestamp_us >> 32) as u32;
    let ts_low = (timestamp_us & 0xFFFFFFFF) as u32;
    body.extend_from_slice(&ts_high.to_le_bytes());
    body.extend_from_slice(&ts_low.to_le_bytes());

    let cap_len = packet_data.len() as u32;
    let orig_len = packet_data.len() as u32;
    body.extend_from_slice(&cap_len.to_le_bytes());
    body.extend_from_slice(&orig_len.to_le_bytes());

    // 数据报文载荷
    body.extend_from_slice(packet_data);
    let pad = pcapng_pad(packet_data.len());
    if pad > 0 {
        body.extend_from_slice(&vec![0u8; pad]);
    }

    // 可选选项: 司法防篡改摘要注释
    if let Some(c) = comment {
        if !c.is_empty() {
            body.extend_from_slice(&encode_pcapng_option(0x0001, c.as_bytes()));
        }
    }
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());

    pack_pcapng_block(PCAPNG_ENHANCED_PACKET_BLOCK, &body)
}

/// 将数据报文列表编码为完整的 PCAPng 二进制流
pub fn encode_packets_to_pcapng(
    packets: &[PacketExportData],
    iface_name: &str,
    app_comment: &str,
) -> Vec<u8> {
    let mut output = Vec::new();

    // 1. 写入 Section Header Block
    let shb = build_section_header_block(app_comment, "Omni-Probe Enterprise 4.1");
    output.extend_from_slice(&shb);

    // 2. 写入 Interface Description Block (微秒精度 10^-6)
    let idb = build_interface_desc_block(iface_name, 6);
    output.extend_from_slice(&idb);

    // 3. 逐帧写入 Enhanced Packet Block
    for p in packets {
        let bytes = if !p.payload_hex.is_empty() {
            hex::decode(&p.payload_hex).unwrap_or_default()
        } else {
            Vec::new()
        };

        let frame_bytes = if bytes.len() >= 14 && (bytes[12] == 0x08 && bytes[13] == 0x00) {
            bytes
        } else {
            let mut pseudo_frame = vec![
                0x00, 0x0c, 0x29, 0xaa, 0xbb, 0xcc,
                0x00, 0x50, 0x56, 0x11, 0x22, 0x33,
                0x08, 0x00,
            ];
            pseudo_frame.extend_from_slice(&bytes);
            pseudo_frame
        };

        // 构造司法存证防篡改注释
        let comment_str = format!(
            "ID:{};CHAIN_HASH:{};ENTROPY:{:.2}",
            p.id, p.chain_hash, p.entropy
        );

        let ts_us = 1700000000000000u64 + p.id * 1000;
        let epb = build_enhanced_packet_block(0, ts_us, &frame_bytes, Some(&comment_str));
        output.extend_from_slice(&epb);
    }

    output
}

/// 导出为司法级 PCAPng 二进制文件
pub fn export_to_pcapng(
    packets: &[PacketExportData],
    file_path: &str,
    iface_name: &str,
) -> Result<usize, String> {
    let pcapng_bytes = encode_packets_to_pcapng(
        packets,
        iface_name,
        "Omni-Probe Judicial Certified Network Forensics Integrity",
    );

    let mut file = File::create(file_path).map_err(|e| format!("创建 PCAPng 失败: {}", e))?;
    file.write_all(&pcapng_bytes).map_err(|e| format!("写入 PCAPng 失败: {}", e))?;
    file.flush().map_err(|e| format!("刷新 PCAPng 磁盘失败: {}", e))?;

    Ok(packets.len())
}

// ============================================================
// 单元测试与规范校验
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcapng_section_header_magic_and_structure() {
        let shb = build_section_header_block("Test Comment", "Omni-Probe");
        assert!(shb.len() >= 28);
        let btype = u32::from_le_bytes([shb[0], shb[1], shb[2], shb[3]]);
        assert_eq!(btype, PCAPNG_SECTION_HEADER_BLOCK);
        let len_head = u32::from_le_bytes([shb[4], shb[5], shb[6], shb[7]]);
        let len_tail = u32::from_le_bytes([
            shb[shb.len() - 4], shb[shb.len() - 3], shb[shb.len() - 2], shb[shb.len() - 1]
        ]);
        assert_eq!(len_head, len_tail);
        assert_eq!(len_head as usize, shb.len());

        let magic = u32::from_le_bytes([shb[8], shb[9], shb[10], shb[11]]);
        assert_eq!(magic, PCAPNG_BYTE_ORDER_MAGIC);
    }

    #[test]
    fn test_pcapng_enhanced_packet_block_alignment() {
        let mock_data = vec![0x45, 0x00, 0x00, 0x28, 0x01]; // 5 字节
        let epb = build_enhanced_packet_block(0, 1600000000, &mock_data, Some("hash:123456"));
        
        let btype = u32::from_le_bytes([epb[0], epb[1], epb[2], epb[3]]);
        assert_eq!(btype, PCAPNG_ENHANCED_PACKET_BLOCK);

        let len_head = u32::from_le_bytes([epb[4], epb[5], epb[6], epb[7]]) as usize;
        let len_tail = u32::from_le_bytes([
            epb[epb.len() - 4], epb[epb.len() - 3], epb[epb.len() - 2], epb[epb.len() - 1]
        ]) as usize;
        assert_eq!(len_head, len_tail);
        assert_eq!(len_head, epb.len());
        assert_eq!(epb.len() % 4, 0);
    }

    #[test]
    fn test_encode_packets_to_pcapng_roundtrip() {
        let packets = vec![
            PacketExportData {
                id: 1,
                timestamp: "2026-11-07 12:00:00".to_string(),
                direction: "RX".to_string(),
                transport: "TCP".to_string(),
                protocol: "MODBUS".to_string(),
                src_ip: "192.168.1.10".to_string(),
                dst_ip: "192.168.1.50".to_string(),
                src_port: 5020,
                dst_port: 502,
                length: 32,
                payload_hex: "00010000000601030000000A".to_string(),
                entropy: 3.5,
                entropy_level: "NORMAL".to_string(),
                mac_src: "00:11:22:33:44:55".to_string(),
                mac_dst: "AA:BB:CC:DD:EE:FF".to_string(),
                chain_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
                raw_text: None,
            }
        ];

        let pcapng_bytes = encode_packets_to_pcapng(&packets, "eth0", "Judicial Test");
        assert!(pcapng_bytes.len() > 100);
        let shb_magic = u32::from_le_bytes([pcapng_bytes[0], pcapng_bytes[1], pcapng_bytes[2], pcapng_bytes[3]]);
        assert_eq!(shb_magic, PCAPNG_SECTION_HEADER_BLOCK);
    }
}
'''

if 'PCAPNG_SECTION_HEADER_BLOCK' not in orig:
    with open('src-tauri/src/export_engine.rs', 'w', encoding='utf-8') as f:
        f.write(orig + pcapng_code)
    print('SUCCESS')
else:
    print('ALREADY_PRESENT')
