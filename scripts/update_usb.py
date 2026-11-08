with open('src-tauri/src/usb.rs', 'r', encoding='utf-8') as f:
    content = f.read()

code_to_insert = r'''
/// USBPcap 原始报头剖析结构体 (RFC / USBPcap 驱动规范)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbPcapHeaderInfo {
    pub header_len: u16,
    pub irp_id: u64,
    pub usbd_status: u32,
    pub function: u16,
    pub is_in: bool,
    pub bus: u16,
    pub device: u16,
    pub endpoint: u8,
    pub transfer_type: String, // "Isochronous" | "Interrupt" | "Control" | "Bulk"
    pub data_length: u32,
}

/// 解析 USBPcap 内核驱动层 URB 数据包头
/// 时间复杂度: O(1), 空间复杂度: O(1)
pub fn parse_usbpcap_header(data: &[u8]) -> Option<(UsbPcapHeaderInfo, &[u8])> {
    if data.len() < 27 {
        return None;
    }
    let header_len = u16::from_le_bytes([data[0], data[1]]) as usize;
    if header_len < 27 || data.len() < header_len {
        return None;
    }

    let irp_id = u64::from_le_bytes([
        data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9],
    ]);
    let usbd_status = u32::from_le_bytes([data[10], data[11], data[12], data[13]]);
    let function = u16::from_le_bytes([data[14], data[15]]);
    let info = data[16];
    let is_in = (info & 0x01) != 0;
    let bus = u16::from_le_bytes([data[17], data[18]]);
    let device = u16::from_le_bytes([data[19], data[20]]);
    let endpoint = data[21];
    let transfer_type_code = data[22];
    let transfer_type = match transfer_type_code {
        0 => "Isochronous",
        1 => "Interrupt",
        2 => "Control",
        3 => "Bulk",
        _ => "Unknown",
    }.to_string();
    let data_len = u32::from_le_bytes([data[23], data[24], data[25], data[26]]) as usize;

    let payload_end = (header_len + data_len).min(data.len());
    let payload = &data[header_len..payload_end];

    Some((
        UsbPcapHeaderInfo {
            header_len: header_len as u16,
            irp_id,
            usbd_status,
            function,
            is_in,
            bus,
            device,
            endpoint,
            transfer_type,
            data_length: data_len as u32,
        },
        payload,
    ))
}
'''

test_to_insert = r'''
    #[test]
    fn test_usbpcap_header_dissection() {
        // 构造标准 27 字节 USBPcap 报头 + 4 字节载荷
        let mut frame = vec![0u8; 27 + 4];
        frame[0..2].copy_from_slice(&27u16.to_le_bytes()); // header_len = 27
        frame[2..10].copy_from_slice(&0x1122334455667788u64.to_le_bytes()); // irp_id
        frame[10..14].copy_from_slice(&0u32.to_le_bytes()); // status = success
        frame[14..16].copy_from_slice(&0x0008u16.to_le_bytes()); // function
        frame[16] = 0x01; // info: IN (Device to Host)
        frame[17..19].copy_from_slice(&1u16.to_le_bytes()); // bus 1
        frame[19..21].copy_from_slice(&3u16.to_le_bytes()); // device 3
        frame[21] = 0x81; // endpoint 1 IN
        frame[22] = 3; // transfer_type = Bulk
        frame[23..27].copy_from_slice(&4u32.to_le_bytes()); // data_length = 4
        frame[27..31].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // payload

        let (hdr, payload) = parse_usbpcap_header(&frame).expect("解析 USBPcap 报头失败");
        assert_eq!(hdr.header_len, 27);
        assert_eq!(hdr.irp_id, 0x1122334455667788);
        assert!(hdr.is_in);
        assert_eq!(hdr.bus, 1);
        assert_eq!(hdr.device, 3);
        assert_eq!(hdr.endpoint, 0x81);
        assert_eq!(hdr.transfer_type, "Bulk");
        assert_eq!(hdr.data_length, 4);
        assert_eq!(payload, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }
'''

# 插入到 #[cfg(test)] 之前
if 'pub fn parse_usbpcap_header' not in content:
    idx = content.find('#[cfg(test)]')
    if idx != -1:
        content = content[:idx] + code_to_insert + "\n" + content[idx:]
    else:
        content += code_to_insert

# 插入单测到结尾之前
if 'test_usbpcap_header_dissection' not in content:
    last_brace = content.rfind('}')
    if last_brace != -1:
        content = content[:last_brace] + test_to_insert + "\n}\n"

with open('src-tauri/src/usb.rs', 'w', encoding='utf-8') as f:
    f.write(content)

print("USB_UPDATE_SUCCESS")
