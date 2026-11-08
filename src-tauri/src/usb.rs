use std::collections::HashMap;
use std::io::{BufReader, Read};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use tauri::Emitter;

use crate::forensics::ForensicEngine;
use crate::sniffer::PacketRecord;

pub static USB_RUNNING: Lazy<Arc<Mutex<bool>>> = Lazy::new(|| Arc::new(Mutex::new(false)));
static USB_CHILD: Lazy<Arc<Mutex<Option<Child>>>> = Lazy::new(|| Arc::new(Mutex::new(None)));
static USB_PACKET_COUNTER: AtomicU64 = AtomicU64::new(1);

/// 物理 USB 设备完整属性画像结构体
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbDeviceInfo {
    pub instance_id: String,
    pub vid: String,
    pub pid: String,
    pub device_name: String,
    pub friendly_name: String,
    pub manufacturer: String,
    pub service: String,
    pub class_desc: String,
    pub location_info: String,
    pub is_connected: bool,
}

/// 停止 USB 嗅探引擎
pub fn stop_usb_sniffer() {
    if let Ok(mut r) = USB_RUNNING.lock() {
        *r = false;
    }
    if let Ok(mut child_opt) = USB_CHILD.lock() {
        if let Some(mut child) = child_opt.take() {
            let _ = child.kill();
        }
    }
}

/// 探测系统中可用的 USBPcapCMD 可执行文件路径
pub fn find_usbpcap_executable() -> Option<std::path::PathBuf> {
    let candidates = [
        r"C:\Program Files\USBPcap\USBPcapCMD.exe",
        r"C:\Program Files (x86)\USBPcap\USBPcapCMD.exe",
    ];
    for p in &candidates {
        let path = std::path::Path::new(p);
        if path.exists() {
            return Some(path.to_path_buf());
        }
    }
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let full = dir.join("USBPcapCMD.exe");
            if full.exists() {
                return Some(full);
            }
        }
    }
    None
}

#[cfg(windows)]
mod win_setupapi {
    use std::ffi::c_void;

    pub type HDEVINFO = *mut c_void;
    pub const INVALID_HANDLE_VALUE: HDEVINFO = -1isize as HDEVINFO;

    pub const DIGCF_PRESENT: u32 = 0x00000002;
    pub const DIGCF_ALLCLASSES: u32 = 0x00000004;

    pub const SPDRP_DEVICEDESC: u32 = 0x00000000;
    pub const SPDRP_HARDWAREID: u32 = 0x00000001;
    pub const SPDRP_SERVICE: u32 = 0x00000004;
    pub const SPDRP_MFG: u32 = 0x0000000B;
    pub const SPDRP_FRIENDLYNAME: u32 = 0x0000000C;
    pub const SPDRP_LOCATION_INFORMATION: u32 = 0x0000000D;

    #[repr(C)]
    pub struct SP_DEVINFO_DATA {
        pub cb_size: u32,
        pub class_guid: [u8; 16],
        pub dev_inst: u32,
        pub reserved: usize,
    }

    #[link(name = "setupapi")]
    extern "system" {
        pub fn SetupDiGetClassDevsW(
            class_guid: *const c_void,
            enumerator: *const u16,
            hwnd_parent: *mut c_void,
            flags: u32,
        ) -> HDEVINFO;

        pub fn SetupDiEnumDeviceInfo(
            device_info_set: HDEVINFO,
            member_index: u32,
            device_info_data: *mut SP_DEVINFO_DATA,
        ) -> i32;

        pub fn SetupDiGetDeviceRegistryPropertyW(
            device_info_set: HDEVINFO,
            device_info_data: *const SP_DEVINFO_DATA,
            property: u32,
            property_reg_data_type: *mut u32,
            property_buffer: *mut u8,
            property_buffer_size: u32,
            required_size: *mut u32,
        ) -> i32;

        pub fn SetupDiGetDeviceInstanceIdW(
            device_info_set: HDEVINFO,
            device_info_data: *const SP_DEVINFO_DATA,
            device_instance_id: *mut u16,
            device_instance_id_size: u32,
            required_size: *mut u32,
        ) -> i32;

        pub fn SetupDiDestroyDeviceInfoList(
            device_info_set: HDEVINFO,
        ) -> i32;
    }

    pub unsafe fn get_device_property_string(
        hdev: HDEVINFO,
        dev_data: &SP_DEVINFO_DATA,
        prop: u32,
    ) -> String {
        let mut buf = [0u8; 1024];
        let mut req_size = 0u32;
        let mut reg_type = 0u32;
        let res = SetupDiGetDeviceRegistryPropertyW(
            hdev,
            dev_data,
            prop,
            &mut reg_type,
            buf.as_mut_ptr(),
            buf.len() as u32,
            &mut req_size,
        );
        if res != 0 && req_size > 0 {
            let u16_len = req_size as usize / 2;
            let u16_slice = std::slice::from_raw_parts(buf.as_ptr() as *const u16, u16_len);
            let end = u16_slice.iter().position(|&c| c == 0).unwrap_or(u16_len);
            String::from_utf16_lossy(&u16_slice[..end]).trim().to_string()
        } else {
            String::new()
        }
    }
}

/// Windows 原生 SetupAPI 枚举当前真实物理在线 (DIGCF_PRESENT) 的 USB 设备
#[cfg(windows)]
fn get_present_usb_devices_windows() -> Vec<UsbDeviceInfo> {
    use win_setupapi::*;

    let mut devices = Vec::new();
    let enumerator: Vec<u16> = "USB\0".encode_utf16().collect();

    unsafe {
        let hdev = SetupDiGetClassDevsW(
            std::ptr::null(),
            enumerator.as_ptr(),
            std::ptr::null_mut(),
            DIGCF_ALLCLASSES | DIGCF_PRESENT,
        );

        if hdev == INVALID_HANDLE_VALUE {
            return devices;
        }

        let mut dev_data = SP_DEVINFO_DATA {
            cb_size: std::mem::size_of::<SP_DEVINFO_DATA>() as u32,
            class_guid: [0u8; 16],
            dev_inst: 0,
            reserved: 0,
        };

        let mut index = 0;
        while SetupDiEnumDeviceInfo(hdev, index, &mut dev_data) != 0 {
            index += 1;

            // 1. 获取当前在线设备的物理实例 ID
            let mut id_buf = [0u16; 512];
            let mut req_size = 0u32;
            let inst_id = if SetupDiGetDeviceInstanceIdW(
                hdev,
                &dev_data,
                id_buf.as_mut_ptr(),
                id_buf.len() as u32,
                &mut req_size,
            ) != 0 && req_size > 0 {
                let u16_len = (req_size as usize).saturating_sub(1);
                String::from_utf16_lossy(&id_buf[..u16_len]).trim().to_string()
            } else {
                continue;
            };

            // 2. 提取各项描述符与驱动服务属性
            let friendly = get_device_property_string(hdev, &dev_data, SPDRP_FRIENDLYNAME);
            let dev_desc = get_device_property_string(hdev, &dev_data, SPDRP_DEVICEDESC);
            let mfg = get_device_property_string(hdev, &dev_data, SPDRP_MFG);
            let service = get_device_property_string(hdev, &dev_data, SPDRP_SERVICE);
            let location = get_device_property_string(hdev, &dev_data, SPDRP_LOCATION_INFORMATION);
            let hw_id = get_device_property_string(hdev, &dev_data, SPDRP_HARDWAREID);

            let (vid, pid) = parse_vid_pid(&format!("{} {}", inst_id, hw_id));

            let clean_friendly = clean_inf_string(&friendly);
            let clean_desc = clean_inf_string(&dev_desc);
            let clean_mfg = clean_inf_string(&mfg);

            let display_name = if !clean_friendly.is_empty() {
                clean_friendly.clone()
            } else if !clean_desc.is_empty() {
                clean_desc.clone()
            } else {
                format!("USB 设备 [{}:{}]", vid, pid)
            };

            let class_desc = classify_usb_service(&service, &display_name);

            devices.push(UsbDeviceInfo {
                instance_id: inst_id,
                vid,
                pid,
                device_name: display_name,
                friendly_name: clean_friendly,
                manufacturer: clean_mfg,
                service,
                class_desc,
                location_info: location,
                is_connected: true,
            });
        }

        SetupDiDestroyDeviceInfoList(hdev);
    }

    devices
}

/// 物理 USB 设备全量枚举 (当前真正处于连接状态的设备)
/// 时间复杂度: O(N), 空间复杂度: O(N)
pub fn scan_connected_usb_devices() -> Vec<UsbDeviceInfo> {
    #[cfg(windows)]
    let mut devices = get_present_usb_devices_windows();

    #[cfg(not(windows))]
    let mut devices = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // 深度读取 Linux 内核 sysfs USB 总线接口 (/sys/bus/usb/devices/*)
        if let Ok(entries) = std::fs::read_dir("/sys/bus/usb/devices") {
            for entry in entries.flatten() {
                let path = entry.path();
                let id_vendor_file = path.join("idVendor");
                let id_product_file = path.join("idProduct");

                if id_vendor_file.exists() && id_product_file.exists() {
                    let vid = std::fs::read_to_string(&id_vendor_file).unwrap_or_default().trim().to_uppercase();
                    let pid = std::fs::read_to_string(&id_product_file).unwrap_or_default().trim().to_uppercase();
                    let product = std::fs::read_to_string(path.join("product")).unwrap_or_default().trim().to_string();
                    let manufacturer = std::fs::read_to_string(path.join("manufacturer")).unwrap_or_default().trim().to_string();
                    let dev_name = if !product.is_empty() {
                        product.clone()
                    } else {
                        format!("Linux USB Device [{}:{}]", vid, pid)
                    };
                    let location = entry.file_name().to_string_lossy().to_string();
                    let inst_id = format!("LinuxUSB/{}/{}/{}", vid, pid, location);
                    let class_desc = classify_usb_service("", &dev_name);

                    devices.push(UsbDeviceInfo {
                        instance_id: inst_id,
                        vid,
                        pid,
                        device_name: dev_name,
                        friendly_name: product,
                        manufacturer,
                        service: "sysfs_usb".into(),
                        class_desc,
                        location_info: location,
                        is_connected: true,
                    });
                }
            }
        }
    }

    // 跨平台通用补充：从可用串口总线中捕获 USB-Serial/CDC 物理适配器
    if let Ok(ports) = serialport::available_ports() {
        for p in ports {
            if let serialport::SerialPortType::UsbPort(usb) = p.port_type {
                let vid = format!("{:04X}", usb.vid);
                let pid = format!("{:04X}", usb.pid);
                let inst_id = format!("USB_SERIAL/{}/{}/{}", vid, pid, p.port_name);
                if !devices.iter().any(|d| d.instance_id == inst_id || (d.vid == vid && d.pid == pid)) {
                    let name = usb.product.clone().unwrap_or_else(|| format!("USB Serial ({})", p.port_name));
                    let mfg = usb.manufacturer.unwrap_or_default();
                    devices.push(UsbDeviceInfo {
                        instance_id: inst_id,
                        vid,
                        pid,
                        device_name: name.clone(),
                        friendly_name: name,
                        manufacturer: mfg,
                        service: "usb_serial".into(),
                        class_desc: "工业通信与串口 (CDC/ACM/RS485)".into(),
                        location_info: p.port_name,
                        is_connected: true,
                    });
                }
            }
        }
    }

    devices
}

fn parse_vid_pid(s: &str) -> (String, String) {
    let upper = s.to_uppercase();
    let mut vid = "UNKNOWN".to_string();
    let mut pid = "UNKNOWN".to_string();

    if let Some(vid_idx) = upper.find("VID_") {
        let after_vid = &upper[vid_idx + 4..];
        let v_end = after_vid.find('&').unwrap_or(after_vid.len().min(4));
        vid = after_vid[..v_end].to_string();
    }
    if let Some(pid_idx) = upper.find("PID_") {
        let after_pid = &upper[pid_idx + 4..];
        let p_end = after_pid.find('&').unwrap_or(after_pid.len().min(4));
        pid = after_pid[..p_end].to_string();
    }
    (vid, pid)
}

fn clean_inf_string(raw: &str) -> String {
    if let Some(pos) = raw.rfind(';') {
        raw[pos + 1..].trim().to_string()
    } else {
        raw.trim().to_string()
    }
}

/// USB 标准设备描述符 (USB 2.0 / 3.0 Standard Device Descriptor)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbDeviceDescriptor {
    pub b_length: u8,
    pub b_descriptor_type: u8, // 0x01
    pub bcd_usb: String,        // 如 "2.00", "3.00"
    pub b_device_class: u8,
    pub b_device_sub_class: u8,
    pub b_device_protocol: u8,
    pub b_max_packet_size0: u8,
    pub id_vendor: u16,
    pub id_product: u16,
    pub bcd_device: String,
    pub i_manufacturer: u8,
    pub i_product: u8,
    pub i_serial_number: u8,
    pub b_num_configurations: u8,
}

/// USB 端点描述符 (Standard Endpoint Descriptor)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbEndpointDescriptor {
    pub b_length: u8,
    pub b_descriptor_type: u8, // 0x05
    pub endpoint_address: u8,  // bit 7: 方向 (1=IN, 0=OUT), bit 3..0: 端点号
    pub direction: String,     // "IN" 或 "OUT"
    pub endpoint_number: u8,
    pub transfer_type: String, // "Control", "Isochronous", "Bulk", "Interrupt"
    pub max_packet_size: u16,
    pub interval: u8,
}

/// USB 接口描述符 (Standard Interface Descriptor)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbInterfaceDescriptor {
    pub b_length: u8,
    pub b_descriptor_type: u8, // 0x04
    pub interface_number: u8,
    pub alternate_setting: u8,
    pub num_endpoints: u8,
    pub interface_class: u8,
    pub interface_class_desc: String,
    pub interface_sub_class: u8,
    pub interface_protocol: u8,
    pub i_interface: u8,
    pub endpoints: Vec<UsbEndpointDescriptor>,
}

/// USB 配置描述符 (Standard Configuration Descriptor)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbConfigurationDescriptor {
    pub b_length: u8,
    pub b_descriptor_type: u8, // 0x02
    pub total_length: u16,
    pub num_interfaces: u8,
    pub configuration_value: u8,
    pub i_configuration: u8,
    pub attributes: u8,
    pub is_self_powered: bool,
    pub is_remote_wakeup: bool,
    pub max_power_ma: u16,
    pub interfaces: Vec<UsbInterfaceDescriptor>,
}

/// USB 描述符整树画像
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbDescriptorTree {
    pub device: Option<UsbDeviceDescriptor>,
    pub configurations: Vec<UsbConfigurationDescriptor>,
}

/// 解析 USB 接口类别的标准名称
fn parse_usb_class_desc(class_code: u8) -> String {
    match class_code {
        0x01 => "音频设备 (Audio)".into(),
        0x02 => "通讯与 CDC 控制 (CDC-Control)".into(),
        0x03 => "人机交互设备 (HID - 键盘/鼠标/触控)".into(),
        0x05 => "物理反馈设备 (Physical)".into(),
        0x06 => "图像采集设备 (Image / Still Camera)".into(),
        0x07 => "打印机设备 (Printer)".into(),
        0x08 => "大容量存储设备 (Mass Storage - U盘/移动硬盘)".into(),
        0x09 => "USB 集线器 (Hub)".into(),
        0x0A => "CDC 数据接口 (CDC-Data)".into(),
        0x0B => "智能卡读取器 (Smart Card)".into(),
        0x0E => "视频采集设备 (Video / UVC 摄像头)".into(),
        0xE0 => "无线控制器 (Wireless / Bluetooth)".into(),
        0xFE => "特定应用外设 (Application Specific)".into(),
        0xFF => "厂商自定义接口 (Vendor Specific)".into(),
        _ => format!("标准接口类 (0x{:02X})", class_code),
    }
}

/// 递归解析 USB 描述符二进制流为结构化整树
/// 时间复杂度: O(N) (N 为描述符二进制字节数)
/// 空间复杂度: O(N)
pub fn parse_usb_descriptor_tree(raw_bytes: &[u8]) -> Result<UsbDescriptorTree, String> {
    if raw_bytes.is_empty() {
        return Err("描述符字节流为空".into());
    }

    let mut tree = UsbDescriptorTree {
        device: None,
        configurations: Vec::new(),
    };

    let mut cursor = 0;
    let total_len = raw_bytes.len();

    while cursor + 2 <= total_len {
        let b_length = raw_bytes[cursor] as usize;
        if b_length < 2 || cursor + b_length > total_len {
            break;
        }

        let b_type = raw_bytes[cursor + 1];
        let desc_slice = &raw_bytes[cursor..cursor + b_length];

        match b_type {
            0x01 => {
                // Device Descriptor (18 字节)
                if b_length >= 18 {
                    let bcd_usb_raw = u16::from_le_bytes([desc_slice[2], desc_slice[3]]);
                    let bcd_dev_raw = u16::from_le_bytes([desc_slice[12], desc_slice[13]]);
                    tree.device = Some(UsbDeviceDescriptor {
                        b_length: desc_slice[0],
                        b_descriptor_type: desc_slice[1],
                        bcd_usb: format!("{:X}.{:02X}", bcd_usb_raw >> 8, bcd_usb_raw & 0xFF),
                        b_device_class: desc_slice[4],
                        b_device_sub_class: desc_slice[5],
                        b_device_protocol: desc_slice[6],
                        b_max_packet_size0: desc_slice[7],
                        id_vendor: u16::from_le_bytes([desc_slice[8], desc_slice[9]]),
                        id_product: u16::from_le_bytes([desc_slice[10], desc_slice[11]]),
                        bcd_device: format!("{:X}.{:02X}", bcd_dev_raw >> 8, bcd_dev_raw & 0xFF),
                        i_manufacturer: desc_slice[14],
                        i_product: desc_slice[15],
                        i_serial_number: desc_slice[16],
                        b_num_configurations: desc_slice[17],
                    });
                }
            }
            0x02 => {
                // Configuration Descriptor (9 字节)
                if b_length >= 9 {
                    let w_total = u16::from_le_bytes([desc_slice[2], desc_slice[3]]);
                    let attrs = desc_slice[7];
                    tree.configurations.push(UsbConfigurationDescriptor {
                        b_length: desc_slice[0],
                        b_descriptor_type: desc_slice[1],
                        total_length: w_total,
                        num_interfaces: desc_slice[4],
                        configuration_value: desc_slice[5],
                        i_configuration: desc_slice[6],
                        attributes: attrs,
                        is_self_powered: (attrs & 0x40) != 0,
                        is_remote_wakeup: (attrs & 0x20) != 0,
                        max_power_ma: (desc_slice[8] as u16) * 2,
                        interfaces: Vec::new(),
                    });
                }
            }
            0x04 => {
                // Interface Descriptor (9 字节)
                if b_length >= 9 {
                    let iface_class = desc_slice[5];
                    let iface = UsbInterfaceDescriptor {
                        b_length: desc_slice[0],
                        b_descriptor_type: desc_slice[1],
                        interface_number: desc_slice[2],
                        alternate_setting: desc_slice[3],
                        num_endpoints: desc_slice[4],
                        interface_class: iface_class,
                        interface_class_desc: parse_usb_class_desc(iface_class),
                        interface_sub_class: desc_slice[6],
                        interface_protocol: desc_slice[7],
                        i_interface: desc_slice[8],
                        endpoints: Vec::new(),
                    };
                    if let Some(cfg) = tree.configurations.last_mut() {
                        cfg.interfaces.push(iface);
                    }
                }
            }
            0x05 => {
                // Endpoint Descriptor (7 字节)
                if b_length >= 7 {
                    let ep_addr = desc_slice[2];
                    let is_in = (ep_addr & 0x80) != 0;
                    let ep_num = ep_addr & 0x0F;
                    let ep_attr = desc_slice[3] & 0x03;
                    let trans_type = match ep_attr {
                        0 => "Control",
                        1 => "Isochronous",
                        2 => "Bulk",
                        3 => "Interrupt",
                        _ => "Unknown",
                    };
                    let max_pk = u16::from_le_bytes([desc_slice[4], desc_slice[5]]);
                    let ep = UsbEndpointDescriptor {
                        b_length: desc_slice[0],
                        b_descriptor_type: desc_slice[1],
                        endpoint_address: ep_addr,
                        direction: if is_in { "IN".into() } else { "OUT".into() },
                        endpoint_number: ep_num,
                        transfer_type: trans_type.into(),
                        max_packet_size: max_pk,
                        interval: desc_slice[6],
                    };
                    if let Some(cfg) = tree.configurations.last_mut() {
                        if let Some(iface) = cfg.interfaces.last_mut() {
                            iface.endpoints.push(ep);
                        }
                    }
                }
            }
            _ => {
                // 其他类型如 HID (0x21), Hub (0x29) 等按标准跳过
            }
        }

        cursor += b_length;
    }

    Ok(tree)
}

/// USB Mass Storage SCSI 命令块包装器 (CBW) 与状态包装器 (CSW) 结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbScsiDissection {
    pub is_cbw: bool,
    pub tag: u32,
    pub data_transfer_length: u32,
    pub direction: String,
    pub lun: u8,
    pub scsi_opcode: u8,
    pub scsi_command_name: String,
    pub lba: Option<u64>,
    pub transfer_blocks: Option<u32>,
    pub status: Option<u8>,
    pub status_desc: Option<String>,
    pub summary: String,
}

/// 解析 USB Mass Storage 载荷 (SCSI CBW / CSW)
/// 时间复杂度: O(1)
/// 空间复杂度: O(1)
pub fn dissect_usb_mass_storage(payload: &[u8]) -> Option<UsbScsiDissection> {
    if payload.len() >= 31 && &payload[0..4] == b"USBC" {
        // CBW: 31 字节
        let tag = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let xfer_len = u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]);
        let flags = payload[12];
        let is_in = (flags & 0x80) != 0;
        let lun = payload[13] & 0x0F;
        let scsi_op = payload[15];

        let (scsi_name, lba, blocks) = match scsi_op {
            0x00 => ("TEST UNIT READY".to_string(), None, None),
            0x12 => ("INQUIRY (设备厂商型号查询)".to_string(), None, None),
            0x25 => ("READ CAPACITY (读取磁盘容量)".to_string(), None, None),
            0x28 => {
                let lba_val = u32::from_be_bytes([payload[17], payload[18], payload[19], payload[20]]) as u64;
                let blk_cnt = u16::from_be_bytes([payload[22], payload[23]]) as u32;
                (format!("READ(10) [LBA: 0x{:08X}, 扇区数: {}]", lba_val, blk_cnt), Some(lba_val), Some(blk_cnt))
            }
            0x2A => {
                let lba_val = u32::from_be_bytes([payload[17], payload[18], payload[19], payload[20]]) as u64;
                let blk_cnt = u16::from_be_bytes([payload[22], payload[23]]) as u32;
                (format!("WRITE(10) [LBA: 0x{:08X}, 扇区数: {}]", lba_val, blk_cnt), Some(lba_val), Some(blk_cnt))
            }
            0x1A => ("MODE SENSE(6)".to_string(), None, None),
            0x5A => ("MODE SENSE(10)".to_string(), None, None),
            0x1E => ("PREVENT/ALLOW MEDIUM REMOVAL".to_string(), None, None),
            _ => (format!("SCSI 指令 (0x{:02X})", scsi_op), None, None),
        };

        let summary = format!(
            "USB SCSI CBW -> {} | LUN:{} 数据量: {}B 方向: {}",
            scsi_name, lun, xfer_len, if is_in { "Device -> Host (IN)" } else { "Host -> Device (OUT)" }
        );

        Some(UsbScsiDissection {
            is_cbw: true,
            tag,
            data_transfer_length: xfer_len,
            direction: if is_in { "IN".into() } else { "OUT".into() },
            lun,
            scsi_opcode: scsi_op,
            scsi_command_name: scsi_name,
            lba,
            transfer_blocks: blocks,
            status: None,
            status_desc: None,
            summary,
        })
    } else if payload.len() >= 13 && &payload[0..4] == b"USBS" {
        // CSW: 13 字节
        let tag = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let residue = u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]);
        let status = payload[12];
        let status_desc = match status {
            0 => "指令执行成功 (COMMAND_PASSED)".to_string(),
            1 => "指令执行失败 (COMMAND_FAILED)".to_string(),
            2 => "阶段错误 (PHASE_ERROR)".to_string(),
            _ => format!("未知状态 (0x{:02X})", status),
        };

        let summary = format!(
            "USB SCSI CSW <- 状态: {} | Tag:0x{:08X} 剩余未传: {}B",
            status_desc, tag, residue
        );

        Some(UsbScsiDissection {
            is_cbw: false,
            tag,
            data_transfer_length: residue,
            direction: "IN".into(),
            lun: 0,
            scsi_opcode: 0,
            scsi_command_name: "CSW".into(),
            lba: None,
            transfer_blocks: None,
            status: Some(status),
            status_desc: Some(status_desc),
            summary,
        })
    } else {
        None
    }
}

/// USB HID 键盘按键剖析结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbHidKeyboardDissection {
    pub modifiers: Vec<String>,
    pub keycodes: Vec<u8>,
    pub key_names: Vec<String>,
    pub summary: String,
}

/// USB HID 标准键盘按键映射 (Usage ID -> 键名)
fn map_hid_key(code: u8) -> &'static str {
    match code {
        0x04 => "A", 0x05 => "B", 0x06 => "C", 0x07 => "D", 0x08 => "E",
        0x09 => "F", 0x0A => "G", 0x0B => "H", 0x0C => "I", 0x0D => "J",
        0x0E => "K", 0x0F => "L", 0x10 => "M", 0x11 => "N", 0x12 => "O",
        0x13 => "P", 0x14 => "Q", 0x15 => "R", 0x16 => "S", 0x17 => "T",
        0x18 => "U", 0x19 => "V", 0x1A => "W", 0x1B => "X", 0x1C => "Y",
        0x1D => "Z",
        0x1E => "1", 0x1F => "2", 0x20 => "3", 0x21 => "4", 0x22 => "5",
        0x23 => "6", 0x24 => "7", 0x25 => "8", 0x26 => "9", 0x27 => "0",
        0x28 => "Enter", 0x29 => "Escape", 0x2A => "Backspace", 0x2B => "Tab",
        0x2C => "Space", 0x2D => "-", 0x2E => "=", 0x2F => "[", 0x30 => "]",
        0x31 => "\\", 0x33 => ";", 0x34 => "'", 0x35 => "`", 0x36 => ",",
        0x37 => ".", 0x38 => "/", 0x39 => "CapsLock",
        0x3A => "F1", 0x3B => "F2", 0x3C => "F3", 0x3D => "F4",
        0x3E => "F5", 0x3F => "F6", 0x40 => "F7", 0x41 => "F8",
        0x42 => "F9", 0x43 => "F10", 0x44 => "F11", 0x45 => "F12",
        0x4C => "Delete", 0x4F => "Right", 0x50 => "Left", 0x51 => "Down", 0x52 => "Up",
        _ => "UnknownKey",
    }
}


/// BadUSB 物理外设恶意行为审计判定结构体
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BadUsbAuditResult {
    pub is_threat: bool,
    pub threat_type: String,
    pub description: String,
    pub confidence: f64,
    pub burst_rate_kps: f64,
}

/// 工业级 BadUSB 物理击键与外设行为审计器
pub struct BadUsbAuditor {
    pub keystroke_timestamps: Vec<u64>,
    pub key_history: Vec<String>,
}

impl BadUsbAuditor {
    pub fn new() -> Self {
        Self {
            keystroke_timestamps: Vec::new(),
            key_history: Vec::new(),
        }
    }

    /// 针对 USB HID 键盘报文执行动态行为时序审计
    pub fn audit_keystroke(&mut self, kbd: &UsbHidKeyboardDissection, epoch_ms: u64) -> Option<BadUsbAuditResult> {
        if kbd.keycodes.is_empty() {
            return None;
        }

        self.keystroke_timestamps.push(epoch_ms);
        self.keystroke_timestamps.retain(|&t| epoch_ms.saturating_sub(t) <= 2000);

        for name in &kbd.key_names {
            self.key_history.push(name.clone());
        }
        if self.key_history.len() > 30 {
            self.key_history.remove(0);
        }

        let count = self.keystroke_timestamps.len();
        // 判定 1: 瞬时高频击键 (2 秒内连续击键 >= 12 次且平均间隔 < 25ms, 非人类生物物理极限)
        if count >= 12 {
            let kps = count as f64 / 2.0;
            let deltas: Vec<u64> = self.keystroke_timestamps.windows(2).map(|w| w[1].saturating_sub(w[0])).collect();
            let recent_deltas = if deltas.len() >= 10 { &deltas[deltas.len() - 10..] } else { &deltas[..] };
            let avg_iat = if !recent_deltas.is_empty() {
                recent_deltas.iter().sum::<u64>() as f64 / recent_deltas.len() as f64
            } else {
                100.0
            };

            if avg_iat < 25.0 {
                return Some(BadUsbAuditResult {
                    is_threat: true,
                    threat_type: "CRITICAL_BADUSB_SCRIPT_INJECTION".into(),
                    description: format!(
                        "检测到恶意物理 BadUSB 硬件击键注入攻击！瞬时包率: {:.1} 键/秒, 平均物理击键间隔: {:.1}ms (非人类打字特征)",
                        kps, avg_iat
                    ),
                    confidence: 0.98,
                    burst_rate_kps: kps,
                });
            }
        }

        // 判定 2: 危险快捷指令触发 (GUI+R / Win+R 自动化渗透特征)
        if kbd.modifiers.contains(&"LGUI".to_string()) || kbd.modifiers.contains(&"RGUI".to_string()) {
            if kbd.key_names.contains(&"r".to_string()) || kbd.key_names.contains(&"R".to_string()) {
                return Some(BadUsbAuditResult {
                    is_threat: true,
                    threat_type: "SUSPICIOUS_BADUSB_HOTKEY_TRIGGER".into(),
                    description: "检测到物理 USB 硬件自动触发 GUI+R (Win+R) 快捷指令，疑似渗透脚本调用执行器".into(),
                    confidence: 0.85,
                    burst_rate_kps: 0.0,
                });
            }
        }

        None
    }
}

pub static GLOBAL_BADUSB_AUDITOR: once_cell::sync::Lazy<std::sync::Mutex<BadUsbAuditor>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(BadUsbAuditor::new()));

/// 解析 USB HID 标准 8 字节键盘输入报文
pub fn dissect_usb_hid_keyboard(payload: &[u8]) -> Option<UsbHidKeyboardDissection> {
    if payload.len() != 8 {
        return None;
    }
    let mod_byte = payload[0];
    let mut modifiers = Vec::new();
    if (mod_byte & 0x01) != 0 { modifiers.push("LCtrl".into()); }
    if (mod_byte & 0x02) != 0 { modifiers.push("LShift".into()); }
    if (mod_byte & 0x04) != 0 { modifiers.push("LAlt".into()); }
    if (mod_byte & 0x08) != 0 { modifiers.push("LGUI".into()); }
    if (mod_byte & 0x10) != 0 { modifiers.push("RCtrl".into()); }
    if (mod_byte & 0x20) != 0 { modifiers.push("RShift".into()); }
    if (mod_byte & 0x40) != 0 { modifiers.push("RAlt".into()); }
    if (mod_byte & 0x80) != 0 { modifiers.push("RGUI".into()); }

    let mut keycodes = Vec::new();
    let mut key_names = Vec::new();
    for &code in &payload[2..8] {
        if code != 0 {
            keycodes.push(code);
            key_names.push(map_hid_key(code).to_string());
        }
    }

    let summary = if key_names.is_empty() && modifiers.is_empty() {
        "USB HID 键盘: 全部按键已释放 (Key Release)".into()
    } else {
        let mut parts = modifiers.clone();
        parts.extend(key_names.clone());
        format!("USB HID 键盘按键: {}", parts.join(" + "))
    };

    Some(UsbHidKeyboardDissection {
        modifiers,
        keycodes,
        key_names,
        summary,
    })
}

/// 解析 USB HID 鼠标输入报文 (3~5 字节)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbHidMouseDissection {
    pub left_button: bool,
    pub right_button: bool,
    pub middle_button: bool,
    pub delta_x: i8,
    pub delta_y: i8,
    pub delta_wheel: i8,
    pub summary: String,
}

pub fn dissect_usb_hid_mouse(payload: &[u8]) -> Option<UsbHidMouseDissection> {
    if payload.len() < 3 || payload.len() > 5 {
        return None;
    }
    let btn = payload[0];
    let left = (btn & 0x01) != 0;
    let right = (btn & 0x02) != 0;
    let middle = (btn & 0x04) != 0;
    let dx = payload[1] as i8;
    let dy = payload[2] as i8;
    let wheel = if payload.len() >= 4 { payload[3] as i8 } else { 0 };

    let summary = format!(
        "USB HID 鼠标: [左:{} 右:{} 中:{}] 位移:(dX:{}, dY:{}) 滚轮:{}",
        if left { "按下" } else { "放开" },
        if right { "按下" } else { "放开" },
        if middle { "按下" } else { "放开" },
        dx, dy, wheel
    );

    Some(UsbHidMouseDissection {
        left_button: left,
        right_button: right,
        middle_button: middle,
        delta_x: dx,
        delta_y: dy,
        delta_wheel: wheel,
        summary,
    })
}

fn classify_usb_service(service: &str, name: &str) -> String {
    let s = service.to_lowercase();
    let n = name.to_lowercase();

    if s.contains("usbstor") || n.contains("mass storage") || n.contains("flash disk") || n.contains("u盘") {
        "大容量存储 (U盘/移动硬盘)".into()
    } else if s.contains("usbser") || s.contains("ser2pl") || s.contains("ftdi") || s.contains("ch34") || n.contains("serial") || n.contains("com") {
        "工业通信与串口 (CDC/ACM/RS485)".into()
    } else if s.contains("hidusb") || s.contains("kbd") || s.contains("mou") || n.contains("keyboard") || n.contains("mouse") {
        "人机交互设备 (HID 键鼠/工控触控)".into()
    } else if s.contains("usbaudio") || n.contains("audio") || n.contains("microphone") {
        "音频/多媒体采集设备".into()
    } else if s.contains("usbvideo") || n.contains("camera") || n.contains("相机") {
        "机器视觉与摄像头 (UVC)".into()
    } else if s.contains("usbccgp") {
        "复合型多功能控制器 (Composite Hub)".into()
    } else if s.contains("winusb") {
        "WinUSB 工业免驱传输设备".into()
    } else {
        "专用总线设备 / 外设".into()
    }
}

/// 构造物理 USB 插拔事件的标准 PacketRecord
pub fn build_usb_event_record(
    event_type: &str, // "USB_ATTACH" 或 "USB_DETACH"
    dev: &UsbDeviceInfo,
) -> PacketRecord {
    let id = USB_PACKET_COUNTER.fetch_add(1, Ordering::Relaxed);
    let ts_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let timestamp = chrono::Local::now().format("%H:%M:%S.%3f").to_string();

    let mut b_map = HashMap::new();
    b_map.insert("event_type".into(), serde_json::json!(event_type));
    b_map.insert("device_name".into(), serde_json::json!(&dev.device_name));
    b_map.insert("vendor_id".into(), serde_json::json!(&dev.vid));
    b_map.insert("product_id".into(), serde_json::json!(&dev.pid));
    b_map.insert("device_class".into(), serde_json::json!(&dev.class_desc));
    b_map.insert("driver_service".into(), serde_json::json!(&dev.service));
    b_map.insert("manufacturer".into(), serde_json::json!(&dev.manufacturer));
    b_map.insert("instance_id".into(), serde_json::json!(&dev.instance_id));
    b_map.insert("location".into(), serde_json::json!(&dev.location_info));

    let summary_text = if event_type == "USB_ATTACH" {
        format!("USB 物理设备已挂载接入: {} [VID:{} PID:{}] 类别: {}", dev.device_name, dev.vid, dev.pid, dev.class_desc)
    } else {
        format!("USB 物理设备已断开拔出: {} [VID:{} PID:{}]", dev.device_name, dev.vid, dev.pid)
    };

    let payload_bytes = summary_text.as_bytes();
    let entropy = ForensicEngine::calculate_entropy(payload_bytes);
    let is_storage = dev.service.to_lowercase().contains("usbstor");
    let entropy_level = if is_storage { "suspicious" } else { "safe" };

    PacketRecord {
        id,
        timestamp,
        timestamp_ns: ts_ns,
        direction: event_type.to_string(),
        transport: "USB".into(),
        protocol: if is_storage { "USB_STORAGE".into() } else { "USB_PnP".into() },
        src_ip: format!("USB_VID_{}_PID_{}", dev.vid, dev.pid),
        dst_ip: "HOST_ROOT_HUB".into(),
        src_port: 0,
        dst_port: 0,
        length: payload_bytes.len(),
        payload_hex: hex::encode(payload_bytes),
        raw_frame_hex: hex::encode(payload_bytes),
        entropy,
        entropy_level: entropy_level.into(),
        mac_src: format!("USB:{}", dev.vid),
        mac_dst: "HOST".into(),
        chain_hash: format!("USB_{}_{}", event_type, id),
        business_data: Some(b_map),
        raw_text: Some(summary_text),
    }
}

/// 启动 USB 嗅探引擎（双轨架构：支持驱动级 USBPcap URB 抓包与 Windows 原生 PnP 设备总线审计）
pub fn start_usb_sniffer(app: tauri::AppHandle) -> Result<String, String> {
    {
        let mut r = USB_RUNNING.lock().unwrap();
        if *r {
            return Ok("[USB] USB 嗅探引擎已在运行中".into());
        }
        *r = true;
    }

    let usbpcap_opt = find_usbpcap_executable();
    let app_clone = app.clone();
    let running = USB_RUNNING.clone();

    if let Some(usbpcap_path) = usbpcap_opt {
        // === 模式 1: 具备 USBPcap 驱动时，执行微秒级 URB 数据包物理抓包 ===
        #[cfg(windows)]
        use std::os::windows::process::CommandExt;

        let mut cmd = Command::new(usbpcap_path);
        cmd.args(&["-d", r"\\.\USBPcap1", "-o", "-", "-A"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        #[cfg(windows)]
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW: 彻底杜绝黑窗口

        let child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                let _ = app.emit("system-log", format!("[USB] 驱动句柄打开提示: {}，降级为原生 PnP 模式", e));
                return start_native_usb_pnp_mode(app);
            }
        };

        std::thread::spawn(move || {
            let mut child = child;
            let stdout = match child.stdout.take() {
                Some(s) => s,
                None => return,
            };

            if let Ok(mut child_lock) = USB_CHILD.lock() {
                *child_lock = Some(child);
            }

            let _ = app_clone.emit("system-log", "[USB] ✅ 成功挂钩 USB 核心物理总线 (USBPcap1 URB 链路捕获已激活)");

            let mut reader = BufReader::new(stdout);
            let mut buf = [0u8; 1024];

            while *running.lock().unwrap() {
                match reader.read(&mut buf) {
                    Ok(n) if n > 0 => {
                        let payload = &buf[..n];
                        let entropy = ForensicEngine::calculate_entropy(payload);
                        let mut entropy_level = if entropy >= 7.5 {
                            "critical"
                        } else if entropy >= 6.0 {
                            "suspicious"
                        } else {
                            "safe"
                        };

                        let id = USB_PACKET_COUNTER.fetch_add(1, Ordering::Relaxed);
                        let ts_ns = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_nanos();

                        let mut b_map = HashMap::new();
                        b_map.insert("bus_type".into(), serde_json::json!("USB_URB"));
                        b_map.insert("controller_device".into(), serde_json::json!("USBPcap1"));
                        b_map.insert("urb_bytes".into(), serde_json::json!(n));
                        b_map.insert("entropy_score".into(), serde_json::json!(entropy));
                        b_map.insert("entropy_level".into(), serde_json::json!(entropy_level));

                        let mut protocol = "USBPcap".to_string();
                        let mut summary_text = format!("USB URB 总线报文 [USBPcap1 -> Host] 长度: {}B", n);

                        // 深度应用层规约剖析 (SCSI / HID / CDC)
                        if let Some(scsi) = dissect_usb_mass_storage(payload) {
                            protocol = "USB_SCSI".into();
                            summary_text = scsi.summary.clone();
                            b_map.insert("usb_scsi".into(), serde_json::to_value(&scsi).unwrap_or_default());
                        } else if let Some(kbd) = dissect_usb_hid_keyboard(payload) {
                            protocol = "USB_HID_KBD".into();
                            summary_text = kbd.summary.clone();
                            b_map.insert("usb_hid_kbd".into(), serde_json::to_value(&kbd).unwrap_or_default());

                            // 触发物理 BadUSB 行为审计器
                            let epoch_ms = (ts_ns / 1_000_000) as u64;
                            if let Ok(mut auditor) = GLOBAL_BADUSB_AUDITOR.lock() {
                                if let Some(alert) = auditor.audit_keystroke(&kbd, epoch_ms) {
                                    entropy_level = "critical";
                                    summary_text = format!("[BADUSB 拦截] {}", alert.description);
                                    b_map.insert("badusb_alert".into(), serde_json::to_value(&alert).unwrap_or_default());
                                    let _ = app_clone.emit("hardware-alert", format!("🚨 物理安全告警: {}", alert.description));
                                }
                            }
                        } else if let Some(mou) = dissect_usb_hid_mouse(payload) {
                            protocol = "USB_HID_MOUSE".into();
                            summary_text = mou.summary.clone();
                            b_map.insert("usb_hid_mouse".into(), serde_json::to_value(&mou).unwrap_or_default());
                        }

                        let record = PacketRecord {
                            id,
                            timestamp: chrono::Local::now().format("%H:%M:%S.%3f").to_string(),
                            timestamp_ns: ts_ns,
                            direction: "USB_BUS".into(),
                            transport: "USB".into(),
                            protocol,
                            src_ip: "USBPcap1".into(),
                            dst_ip: "HOST_CONTROLLER".into(),
                            src_port: 0,
                            dst_port: 0,
                            length: n,
                            payload_hex: hex::encode(payload),
                            raw_frame_hex: hex::encode(payload),
                            entropy,
                            entropy_level: entropy_level.into(),
                            mac_src: "USB".into(),
                            mac_dst: "HOST".into(),
                            chain_hash: format!("USB_{}", id),
                            business_data: Some(b_map),
                            raw_text: Some(summary_text),
                        };

                        let _ = crate::cloud::emit_record(serde_json::to_value(&record).unwrap_or_default());
                        let _ = app_clone.emit("packet-received", &record);
                    }
                    _ => break,
                }
            }

            let _ = app_clone.emit("system-log", "[USB] USB URB 数据抓包流水线已退出");
        });

        Ok("[USB] USB 驱动级抓包引擎启动成功 (USBPcap)".into())
    } else {
        // === 模式 2: 未安装第三方 USBPcap 时，自动无缝启动系统级物理设备生命周期与操作审计 ===
        start_native_usb_pnp_mode(app)
    }
}

fn start_native_usb_pnp_mode(app: tauri::AppHandle) -> Result<String, String> {
    let app_clone = app.clone();
    let running = USB_RUNNING.clone();

    std::thread::spawn(move || {
        let initial_devices = scan_connected_usb_devices();
        let _ = app_clone.emit(
            "system-log",
            format!(
                "[USB] 🔌 Windows 原生物理 USB 设备总线探针已就绪 (当前物理在线外设: {} 个)",
                initial_devices.len()
            ),
        );

        // 立即向前端同步当前最新的物理在线 USB 设备画像列表
        let _ = app_clone.emit("usb-devices-changed", &initial_devices);

        // 将当前物理在线的 USB 设备作为基线广播至数据总线
        for dev in &initial_devices {
            let rec = build_usb_event_record("USB_ATTACH", dev);
            let _ = app_clone.emit("packet-received", &rec);
        }

        let mut known_map: HashMap<String, UsbDeviceInfo> = initial_devices
            .into_iter()
            .map(|d| (d.instance_id.clone(), d))
            .collect();

        while *running.lock().unwrap() {
            // 800ms 高灵敏度轮询周期 (SetupAPI DIGCF_PRESENT 耗时 < 2ms)
            std::thread::sleep(std::time::Duration::from_millis(800));

            let current_devices = scan_connected_usb_devices();
            let current_map: HashMap<String, UsbDeviceInfo> = current_devices
                .iter()
                .cloned()
                .map(|d| (d.instance_id.clone(), d))
                .collect();

            let mut state_changed = false;

            // 1. 毫秒级检测新插入物理 USB 设备 (Attach)
            for (inst_id, dev) in &current_map {
                if !known_map.contains_key(inst_id) {
                    state_changed = true;
                    let rec = build_usb_event_record("USB_ATTACH", dev);
                    let _ = app_clone.emit(
                        "system-log",
                        format!("[USB] 🔌 物理 USB 设备已接入: {} [{}:{}] ({})", dev.device_name, dev.vid, dev.pid, dev.class_desc),
                    );
                    let _ = app_clone.emit("packet-received", &rec);
                    let _ = app_clone.emit("hardware-alert", serde_json::json!({
                        "alert_type": "USB_ATTACH",
                        "device_name": &dev.device_name,
                        "device_id": &dev.instance_id,
                        "timestamp": chrono::Local::now().format("%H:%M:%S").to_string(),
                    }));
                }
            }

            // 2. 毫秒级检测已拔出物理 USB 设备 (Detach)
            for (inst_id, dev) in &known_map {
                if !current_map.contains_key(inst_id) {
                    state_changed = true;
                    let rec = build_usb_event_record("USB_DETACH", dev);
                    let _ = app_clone.emit(
                        "system-log",
                        format!("[USB] ⚠️ 物理 USB 设备已断开拔出: {} [{}:{}]", dev.device_name, dev.vid, dev.pid),
                    );
                    let _ = app_clone.emit("packet-received", &rec);
                    let _ = app_clone.emit("hardware-alert", serde_json::json!({
                        "alert_type": "USB_DETACH",
                        "device_name": &dev.device_name,
                        "device_id": &dev.instance_id,
                        "timestamp": chrono::Local::now().format("%H:%M:%S").to_string(),
                    }));
                }
            }

            // 若发生物理拓扑变更，立即向全系统推送最新 USB 设备列表
            if state_changed {
                let _ = app_clone.emit("usb-devices-changed", &current_devices);
            }

            known_map = current_map;
        }

        let _ = app_clone.emit("system-log", "[USB] 原生物理 USB 设备总线探针已安全停止");
    });

    Ok("[USB] 原生物理 USB 设备总线审计探针已启动 (免驱动模式)".into())
}


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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_usb_descriptor_tree() {
        // 构造标准 USB 描述符二进制流:
        // 1. Device Descriptor (18B): 12 01 00 02 00 00 00 40 C4 10 60 EA 00 01 01 02 03 01
        // (bLength=18, bDescriptorType=1, bcdUSB=0x0200, VID=0x10C4, PID=0xEA60, bNumConfigurations=1)
        let mut raw = vec![
            0x12, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40,
            0xC4, 0x10, 0x60, 0xEA, 0x00, 0x01, 0x01, 0x02, 0x03, 0x01,
        ];
        // 2. Configuration Descriptor (9B): 09 02 20 00 01 01 00 80 32
        // (bLength=9, bDescriptorType=2, wTotalLength=32, bNumInterfaces=1, bMaxPower=50*2=100mA)
        raw.extend_from_slice(&[0x09, 0x02, 0x20, 0x00, 0x01, 0x01, 0x00, 0x80, 0x32]);
        // 3. Interface Descriptor (9B): 09 04 00 00 02 08 06 50 00
        // (bLength=9, bDescriptorType=4, bInterfaceNumber=0, bNumEndpoints=2, bInterfaceClass=0x08 Mass Storage)
        raw.extend_from_slice(&[0x09, 0x04, 0x00, 0x00, 0x02, 0x08, 0x06, 0x50, 0x00]);
        // 4. Endpoint Descriptor 1 (7B): 07 05 81 02 40 00 00 (EP 1 IN Bulk 64B)
        raw.extend_from_slice(&[0x07, 0x05, 0x81, 0x02, 0x40, 0x00, 0x00]);
        // 5. Endpoint Descriptor 2 (7B): 07 05 02 02 40 00 00 (EP 2 OUT Bulk 64B)
        raw.extend_from_slice(&[0x07, 0x05, 0x02, 0x02, 0x40, 0x00, 0x00]);

        let tree = parse_usb_descriptor_tree(&raw).expect("解析 USB 描述符树失败");
        let dev = tree.device.expect("未解析出设备描述符");
        assert_eq!(dev.id_vendor, 0x10C4);
        assert_eq!(dev.id_product, 0xEA60);
        assert_eq!(dev.bcd_usb, "2.00");

        assert_eq!(tree.configurations.len(), 1);
        let cfg = &tree.configurations[0];
        assert_eq!(cfg.max_power_ma, 100);
        assert_eq!(cfg.interfaces.len(), 1);

        let iface = &cfg.interfaces[0];
        assert_eq!(iface.interface_class, 0x08);
        assert!(iface.interface_class_desc.contains("大容量存储"));
        assert_eq!(iface.endpoints.len(), 2);
        assert_eq!(iface.endpoints[0].direction, "IN");
        assert_eq!(iface.endpoints[1].direction, "OUT");
    }

    #[test]
    fn test_usb_scsi_cbw_csw() {
        // 构造 SCSI CBW: READ(10), LBA=0x00000008, Blocks=1, Transfer Length=512
        let mut cbw = vec![0u8; 31];
        cbw[0..4].copy_from_slice(b"USBC");
        cbw[4..8].copy_from_slice(&1234u32.to_le_bytes()); // Tag
        cbw[8..12].copy_from_slice(&512u32.to_le_bytes()); // Transfer length
        cbw[12] = 0x80; // IN (Device to Host)
        cbw[13] = 0x00; // LUN
        cbw[14] = 10;   // SCSI CDB length
        cbw[15] = 0x28; // READ(10)
        cbw[17..21].copy_from_slice(&8u32.to_be_bytes()); // LBA 8
        cbw[22..24].copy_from_slice(&1u16.to_be_bytes()); // 1 block

        let parsed_cbw = dissect_usb_mass_storage(&cbw).expect("解析 CBW 失败");
        assert!(parsed_cbw.is_cbw);
        assert_eq!(parsed_cbw.tag, 1234);
        assert_eq!(parsed_cbw.data_transfer_length, 512);
        assert_eq!(parsed_cbw.direction, "IN");
        assert_eq!(parsed_cbw.scsi_opcode, 0x28);
        assert_eq!(parsed_cbw.lba, Some(8));
        assert_eq!(parsed_cbw.transfer_blocks, Some(1));

        // 构造 SCSI CSW: Success
        let mut csw = vec![0u8; 13];
        csw[0..4].copy_from_slice(b"USBS");
        csw[4..8].copy_from_slice(&1234u32.to_le_bytes()); // Tag
        csw[8..12].copy_from_slice(&0u32.to_le_bytes());   // Residue 0
        csw[12] = 0; // Status: Command Passed

        let parsed_csw = dissect_usb_mass_storage(&csw).expect("解析 CSW 失败");
        assert!(!parsed_csw.is_cbw);
        assert_eq!(parsed_csw.tag, 1234);
        assert_eq!(parsed_csw.status, Some(0));
        assert!(parsed_csw.summary.contains("指令执行成功"));
    }

    #[test]
    fn test_usb_hid_keyboard_and_mouse() {
        // 键盘按下 Left Shift + 'A' (Usage ID 0x04)
        let kbd_payload = [0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00];
        let kbd = dissect_usb_hid_keyboard(&kbd_payload).expect("解析 HID 键盘失败");
        assert_eq!(kbd.modifiers, vec!["LShift"]);
        assert_eq!(kbd.key_names, vec!["A"]);
        assert!(kbd.summary.contains("LShift + A"));

        // 鼠标按下左键并向右移动 15 像素
        let mouse_payload = [0x01, 15, 0, 0];
        let mouse = dissect_usb_hid_mouse(&mouse_payload).expect("解析 HID 鼠标失败");
        assert!(mouse.left_button);
        assert!(!mouse.right_button);
        assert_eq!(mouse.delta_x, 15);
        assert_eq!(mouse.delta_y, 0);
    }

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

    #[test]
    fn test_badusb_rapid_keystroke_injection_detection() {
        let mut auditor = BadUsbAuditor::new();

        // 1. 模拟人类常规按键打字: 字符间隔 100ms
        let normal_kbd = UsbHidKeyboardDissection {
            modifiers: vec![],
            keycodes: vec![0x04],
            key_names: vec!["A".into()],
            summary: "A".into(),
        };
        let res1 = auditor.audit_keystroke(&normal_kbd, 1000);
        assert!(res1.is_none());

        // 2. 模拟 BadUSB 硬件毫秒级快速注入: 15 次击键, 每次仅相隔 10ms
        let mut alert_opt = None;
        for i in 0..15 {
            let t = 2000 + i * 10;
            if let Some(alert) = auditor.audit_keystroke(&normal_kbd, t) {
                alert_opt = Some(alert);
                break;
            }
        }
        assert!(alert_opt.is_some(), "应当成功检测到非人类 BadUSB 击键突发");
        let alert = alert_opt.unwrap();
        assert_eq!(alert.threat_type, "CRITICAL_BADUSB_SCRIPT_INJECTION");
        assert!(alert.confidence > 0.95);

        // 3. 模拟 Win+R 快捷键调用测试
        let hotkey_kbd = UsbHidKeyboardDissection {
            modifiers: vec!["LGUI".into()],
            keycodes: vec![0x15],
            key_names: vec!["R".into()],
            summary: "LGUI + R".into(),
        };
        let res_hotkey = auditor.audit_keystroke(&hotkey_kbd, 5000);
        assert!(res_hotkey.is_some());
        assert_eq!(res_hotkey.unwrap().threat_type, "SUSPICIOUS_BADUSB_HOTKEY_TRIGGER");
    }

}
