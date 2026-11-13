// ============================================================================
// Omni-Probe 工业全能网络探针系统 - Windows Filtering Platform (WFP) 内核级过滤引擎
// 模块名称: wfp_engine.rs
// 核心机制:
//   1. 直连 Windows 系统级过滤平台 (fwpuclnt.dll -> BFE Base Filtering Engine);
//   2. 创建动态 WFP 会话 (FWPM_SESSION_FLAG_DYNAMIC)，进程退出时 OS 自动回收防止规则残留;
//   3. 注册专属子层并在 ALE 入站/出站双层 (RECV_ACCEPT_V4 / CONNECT_V4) 下发硬阻断;
//   4. 严格执行权限边界检测与环回自保校验 (ERROR_ACCESS_DENIED 时诚实暴露提权诉求，绝不静默假装已拦截).
// ============================================================================

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WfpKernelRule {
    pub target: String,
    pub cidr_normalized: String,
    pub reason: String,
    pub inbound_filter_id: u64,
    pub outbound_filter_id: u64,
    pub created_at: String,
    pub enforcement_mode: String, // "WFP_KERNEL_ACTIVE" | "USER_XDP_DROP_ONLY"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WfpBlockOutcome {
    pub success: bool,
    pub kernel_enforced: bool,
    pub permission_denied: bool,
    pub target: String,
    pub cidr_normalized: String,
    pub inbound_filter_id: u64,
    pub outbound_filter_id: u64,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WfpStatusReport {
    pub os_supported: bool,
    pub engine_connected: bool,
    pub permission_denied: bool,
    pub last_status_code: u32,
    pub last_message: String,
    pub active_rules: Vec<WfpKernelRule>,
}

/// 严格校验目标 IPv4 或 CIDR，返回 (标准主机序 IP u32, 主机序子网掩码 u32, 规范化 CIDR 串)
/// 时间复杂度: O(1), 空间复杂度: O(1)
pub fn parse_and_validate_ipv4_cidr(input: &str) -> Result<(u32, u32, String), String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("目标 IP 不能为空".to_string());
    }

    let (ip_part, prefix_len) = if let Some((ip_s, mask_s)) = trimmed.split_once('/') {
        let p: u32 = mask_s
            .trim()
            .parse()
            .map_err(|_| format!("非法 CIDR 掩码长度: {}", mask_s))?;
        if p == 0 || p > 32 {
            return Err("出于系统保护要求，禁止阻断 /0 全网段，仅支持 /1 ~ /32".to_string());
        }
        (ip_s.trim(), p)
    } else {
        (trimmed, 32u32)
    };

    let ipv4: Ipv4Addr = ip_part
        .parse()
        .map_err(|_| format!("非合法 IPv4 地址 (WFP V4 引擎仅接收单 IP 或 CIDR): {}", ip_part))?;

    // 防自锁死底线拦截：严禁把本机回环或未指定地址写入内核阻断规则
    if ipv4.is_loopback() || ipv4.is_unspecified() || ipv4.is_broadcast() || ipv4.is_multicast() {
        return Err(format!(
            "安全策略保护: 禁止对系统保留/回环/广播地址 {} 下发内核硬阻断",
            ipv4
        ));
    }

    let mask_u32: u32 = if prefix_len == 32 {
        0xFFFF_FFFF
    } else {
        (!0u32) << (32 - prefix_len)
    };
    // Windows WFP FWP_V4_ADDR_AND_MASK 强制使用主机字节序 (Host Byte Order)
    let addr_u32 = u32::from_be_bytes(ipv4.octets()) & mask_u32;
    let net_ip = Ipv4Addr::from(addr_u32.to_be_bytes());
    let norm = if prefix_len == 32 {
        net_ip.to_string()
    } else {
        format!("{}/{}", net_ip, prefix_len)
    };

    Ok((addr_u32, mask_u32, norm))
}

#[cfg(windows)]
mod win_wfp_impl {
    use super::*;
    use windows_sys::core::GUID;
    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, HANDLE};
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteById0,
        FwpmSubLayerAdd0, FWPM_ACTION0, FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_DISPLAY_DATA0,
        FWPM_FILTER0, FWPM_FILTER_CONDITION0, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC,
        FWPM_SUBLAYER0, FWP_ACTION_BLOCK, FWP_BYTE_BLOB, FWP_CONDITION_VALUE0,
        FWP_CONDITION_VALUE0_0, FWP_EMPTY, FWP_MATCH_EQUAL, FWP_V4_ADDR_AND_MASK,
        FWP_V4_ADDR_MASK, FWP_VALUE0, FWP_VALUE0_0,
    };
    use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

    // Omni-Probe 专属 WFP SubLayer GUID (固定可识别标识)
    const OMNI_PROBE_SUBLAYER_GUID: GUID =
        GUID::from_u128(0x6c42d9a1_3f8e_4b12_91c4_a8b300010203);
    const FWP_E_ALREADY_EXISTS: u32 = 0x80320009;

    fn to_wide_null(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub struct NativeWfpManager {
        engine_handle: HANDLE,
        sublayer_ready: bool,
        last_status: u32,
        last_message: String,
        active_rules: HashMap<String, WfpKernelRule>,
    }

    // Windows WFP HANDLE 支持跨线程在互斥锁保护下访问与清理
    unsafe impl Send for NativeWfpManager {}
    unsafe impl Sync for NativeWfpManager {}

    impl NativeWfpManager {
        pub fn new() -> Self {
            Self {
                engine_handle: std::ptr::null_mut(),
                sublayer_ready: false,
                last_status: 0,
                last_message: "WFP 内核过滤引擎待命（按需延迟绑定 BFE 会话）".to_string(),
                active_rules: HashMap::new(),
            }
        }

        fn ensure_session(&mut self) -> Result<HANDLE, (u32, String)> {
            if !self.engine_handle.is_null() && self.sublayer_ready {
                return Ok(self.engine_handle);
            }

            unsafe {
                if self.engine_handle.is_null() {
                    let mut name_w = to_wide_null("Omni-Probe WFP Kernel Session");
                    let mut desc_w =
                        to_wide_null("Dynamic Kernel-Level Threat Blocking Session (Auto Cleanup)");
                    let session = FWPM_SESSION0 {
                        sessionKey: GUID::from_u128(0x6c42d9a1_3f8e_4b12_91c4_a8b300010101),
                        displayData: FWPM_DISPLAY_DATA0 {
                            name: name_w.as_mut_ptr(),
                            description: desc_w.as_mut_ptr(),
                        },
                        flags: FWPM_SESSION_FLAG_DYNAMIC,
                        txnWaitTimeoutInMSec: 0,
                        processId: 0,
                        sid: std::ptr::null_mut(),
                        username: std::ptr::null_mut(),
                        kernelMode: 0,
                    };

                    let mut handle: HANDLE = std::ptr::null_mut();
                    let status = FwpmEngineOpen0(
                        std::ptr::null(),
                        RPC_C_AUTHN_WINNT,
                        std::ptr::null(),
                        &session,
                        &mut handle,
                    );

                    if status != 0 {
                        self.last_status = status;
                        let msg = if status == ERROR_ACCESS_DENIED {
                            "系统内核拒绝打开 WFP 会话 (ERROR_ACCESS_DENIED: 5)：需要以管理员权限启动程序方可下发真内核阻断".to_string()
                        } else {
                            format!("打开 Windows WFP BFE 过滤引擎失败 (Win32 错误码: 0x{:08X})", status)
                        };
                        self.last_message = msg.clone();
                        return Err((status, msg));
                    }
                    self.engine_handle = handle;
                }

                if !self.sublayer_ready {
                    let mut sub_name = to_wide_null("Omni-Probe Kernel Mitigation SubLayer");
                    let mut sub_desc =
                        to_wide_null("High-priority ALE inbound/outbound drop sublayer");
                    let sublayer = FWPM_SUBLAYER0 {
                        subLayerKey: OMNI_PROBE_SUBLAYER_GUID,
                        displayData: FWPM_DISPLAY_DATA0 {
                            name: sub_name.as_mut_ptr(),
                            description: sub_desc.as_mut_ptr(),
                        },
                        flags: 0,
                        providerKey: std::ptr::null_mut(),
                        providerData: FWP_BYTE_BLOB {
                            size: 0,
                            data: std::ptr::null_mut(),
                        },
                        weight: 0x7FFF,
                    };

                    let st = FwpmSubLayerAdd0(self.engine_handle, &sublayer, std::ptr::null_mut());
                    if st != 0 && st != FWP_E_ALREADY_EXISTS {
                        self.last_status = st;
                        let msg = format!("注册 WFP SubLayer 失败 (0x{:08X})", st);
                        self.last_message = msg.clone();
                        return Err((st, msg));
                    }
                    self.sublayer_ready = true;
                }

                self.last_status = 0;
                self.last_message = "WFP BFE 动态内核会话已连接就绪".to_string();
                Ok(self.engine_handle)
            }
        }

        fn add_single_layer_block_filter(
            handle: HANDLE,
            layer_key: GUID,
            filter_name: &str,
            filter_desc: &str,
            addr_u32: u32,
            mask_u32: u32,
        ) -> Result<u64, u32> {
            unsafe {
                let mut name_w = to_wide_null(filter_name);
                let mut desc_w = to_wide_null(filter_desc);
                let mut addr_mask = FWP_V4_ADDR_AND_MASK {
                    addr: addr_u32,
                    mask: mask_u32,
                };

                let mut cond = FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    matchType: FWP_MATCH_EQUAL,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_V4_ADDR_MASK,
                        Anonymous: FWP_CONDITION_VALUE0_0 {
                            v4AddrMask: &mut addr_mask,
                        },
                    },
                };

                let empty_blob = FWP_BYTE_BLOB {
                    size: 0,
                    data: std::ptr::null_mut(),
                };
                let zero_guid = GUID::from_u128(0);

                let filter = FWPM_FILTER0 {
                    filterKey: zero_guid,
                    displayData: FWPM_DISPLAY_DATA0 {
                        name: name_w.as_mut_ptr(),
                        description: desc_w.as_mut_ptr(),
                    },
                    flags: 0,
                    providerKey: std::ptr::null_mut(),
                    providerData: empty_blob,
                    layerKey: layer_key,
                    subLayerKey: OMNI_PROBE_SUBLAYER_GUID,
                    weight: FWP_VALUE0 {
                        r#type: FWP_EMPTY,
                        Anonymous: FWP_VALUE0_0 { uint64: std::ptr::null_mut() },
                    },
                    numFilterConditions: 1,
                    filterCondition: &mut cond,
                    action: FWPM_ACTION0 {
                        r#type: FWP_ACTION_BLOCK,
                        Anonymous: std::mem::zeroed(),
                    },
                    Anonymous: std::mem::zeroed(),
                    reserved: std::ptr::null_mut(),
                    filterId: 0,
                    effectiveWeight: FWP_VALUE0 {
                        r#type: FWP_EMPTY,
                        Anonymous: FWP_VALUE0_0 { uint64: std::ptr::null_mut() },
                    },
                };

                let mut assigned_id: u64 = 0;
                let st = FwpmFilterAdd0(handle, &filter, std::ptr::null_mut(), &mut assigned_id);
                if st == 0 {
                    Ok(assigned_id)
                } else {
                    Err(st)
                }
            }
        }

        pub fn block_ip(&mut self, target: &str, reason: &str) -> WfpBlockOutcome {
            let (addr_u32, mask_u32, norm) = match parse_and_validate_ipv4_cidr(target) {
                Ok(v) => v,
                Err(e) => {
                    return WfpBlockOutcome {
                        success: false,
                        kernel_enforced: false,
                        permission_denied: false,
                        target: target.to_string(),
                        cidr_normalized: String::new(),
                        inbound_filter_id: 0,
                        outbound_filter_id: 0,
                        message: e,
                    };
                }
            };

            if let Some(existing) = self.active_rules.get(&norm) {
                return WfpBlockOutcome {
                    success: true,
                    kernel_enforced: existing.enforcement_mode == "WFP_KERNEL_ACTIVE",
                    permission_denied: false,
                    target: target.to_string(),
                    cidr_normalized: existing.cidr_normalized.clone(),
                    inbound_filter_id: existing.inbound_filter_id,
                    outbound_filter_id: existing.outbound_filter_id,
                    message: format!("目标 {} 已处于 WFP 内核硬阻断生效中", norm),
                };
            }

            let handle = match self.ensure_session() {
                Ok(h) => h,
                Err((code, msg)) => {
                    return WfpBlockOutcome {
                        success: false,
                        kernel_enforced: false,
                        permission_denied: code == ERROR_ACCESS_DENIED,
                        target: target.to_string(),
                        cidr_normalized: norm,
                        inbound_filter_id: 0,
                        outbound_filter_id: 0,
                        message: msg,
                    };
                }
            };

            let in_name = format!("OmniProbe-Block-In-{}", norm);
            let out_name = format!("OmniProbe-Block-Out-{}", norm);
            let clean_reason = if reason.trim().is_empty() {
                "Threat mitigation by Omni-Probe WFP engine"
            } else {
                reason.trim()
            };

            let in_id = match Self::add_single_layer_block_filter(
                handle,
                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                &in_name,
                clean_reason,
                addr_u32,
                mask_u32,
            ) {
                Ok(id) => id,
                Err(st) => {
                    self.last_status = st;
                    return WfpBlockOutcome {
                        success: false,
                        kernel_enforced: false,
                        permission_denied: st == ERROR_ACCESS_DENIED,
                        target: target.to_string(),
                        cidr_normalized: norm,
                        inbound_filter_id: 0,
                        outbound_filter_id: 0,
                        message: format!("下发 WFP 入站拦截过滤器失败 (0x{:08X})", st),
                    };
                }
            };

            let out_id = match Self::add_single_layer_block_filter(
                handle,
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                &out_name,
                clean_reason,
                addr_u32,
                mask_u32,
            ) {
                Ok(id) => id,
                Err(st) => {
                    unsafe {
                        let _ = FwpmFilterDeleteById0(handle, in_id);
                    }
                    self.last_status = st;
                    return WfpBlockOutcome {
                        success: false,
                        kernel_enforced: false,
                        permission_denied: st == ERROR_ACCESS_DENIED,
                        target: target.to_string(),
                        cidr_normalized: norm,
                        inbound_filter_id: 0,
                        outbound_filter_id: 0,
                        message: format!("下发 WFP 出站拦截过滤器失败 (0x{:08X})，已回滚入站规则", st),
                    };
                }
            };

            let rule = WfpKernelRule {
                target: target.to_string(),
                cidr_normalized: norm.clone(),
                reason: clean_reason.to_string(),
                inbound_filter_id: in_id,
                outbound_filter_id: out_id,
                created_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                enforcement_mode: "WFP_KERNEL_ACTIVE".to_string(),
            };
            self.active_rules.insert(norm.clone(), rule);
            self.last_status = 0;
            self.last_message = format!("已下发 WFP 双层内核阻断规则 -> {}", norm);

            WfpBlockOutcome {
                success: true,
                kernel_enforced: true,
                permission_denied: false,
                target: target.to_string(),
                cidr_normalized: norm,
                inbound_filter_id: in_id,
                outbound_filter_id: out_id,
                message: format!(
                    "已写入 Windows 内核 WFP 防火墙阻断 (Inbound ID #{}, Outbound ID #{})",
                    in_id, out_id
                ),
            }
        }

        pub fn unblock_ip(&mut self, target: &str) -> Result<String, String> {
            let norm = parse_and_validate_ipv4_cidr(target)
                .map(|(_, _, n)| n)
                .unwrap_or_else(|_| target.trim().to_string());

            let rule = self
                .active_rules
                .remove(&norm)
                .or_else(|| self.active_rules.remove(target.trim()))
                .ok_or_else(|| format!("未在当前动态 WFP 会话中找到规则: {}", target))?;

            if !self.engine_handle.is_null() {
                unsafe {
                    let s1 = FwpmFilterDeleteById0(self.engine_handle, rule.inbound_filter_id);
                    let s2 = FwpmFilterDeleteById0(self.engine_handle, rule.outbound_filter_id);
                    if s1 != 0 && s2 != 0 {
                        return Err(format!(
                            "移除 WFP 内核规则返回非零状态 (In: 0x{:08X}, Out: 0x{:08X})",
                            s1, s2
                        ));
                    }
                }
            }
            self.last_message = format!("已从 WFP 内核卸载规则: {}", norm);
            Ok(format!("已从 Windows WFP 内核层撤销 {} 的流量阻断", norm))
        }

        pub fn status_report(&mut self) -> WfpStatusReport {
            // 触发轻量只读探活（若此前未打开则尝试连接一次看当前进程特权状态）
            let conn = self.ensure_session().is_ok();
            WfpStatusReport {
                os_supported: true,
                engine_connected: conn,
                permission_denied: self.last_status == ERROR_ACCESS_DENIED,
                last_status_code: self.last_status,
                last_message: self.last_message.clone(),
                active_rules: self.active_rules.values().cloned().collect(),
            }
        }
    }

    impl Drop for NativeWfpManager {
        fn drop(&mut self) {
            if !self.engine_handle.is_null() {
                unsafe {
                    for rule in self.active_rules.values() {
                        let _ = FwpmFilterDeleteById0(self.engine_handle, rule.inbound_filter_id);
                        let _ = FwpmFilterDeleteById0(self.engine_handle, rule.outbound_filter_id);
                    }
                    let _ = FwpmEngineClose0(self.engine_handle);
                }
                self.engine_handle = std::ptr::null_mut();
            }
        }
    }
}

/// 跨平台 Linux `nftables` 防火墙规则参数构造器（纯参数数组零 Shell 注入，先校验标准化 CIDR）
pub fn build_linux_nft_block_cmds(raw_target: &str) -> Result<(String, Vec<Vec<String>>), String> {
    let (_, _, norm) = parse_and_validate_ipv4_cidr(raw_target)?;
    // 初始化 inet omni_probe_guard 表及输入/输出 hook 链，再下发带 handle 回显的 drop 规则
    let cmds = vec![
        vec!["add".into(), "table".into(), "inet".into(), "omni_probe_guard".into()],
        vec![
            "add".into(), "chain".into(), "inet".into(), "omni_probe_guard".into(), "omni_in".into(),
            "{".into(), "type".into(), "filter".into(), "hook".into(), "input".into(), "priority".into(), "0".into(), ";".into(), "policy".into(), "accept".into(), ";".into(), "}".into(),
        ],
        vec![
            "add".into(), "chain".into(), "inet".into(), "omni_probe_guard".into(), "omni_out".into(),
            "{".into(), "type".into(), "filter".into(), "hook".into(), "output".into(), "priority".into(), "0".into(), ";".into(), "policy".into(), "accept".into(), ";".into(), "}".into(),
        ],
        vec![
            "--echo".into(), "--handle".into(),
            "add".into(), "rule".into(), "inet".into(), "omni_probe_guard".into(), "omni_in".into(),
            "ip".into(), "saddr".into(), norm.clone(), "counter".into(), "drop".into(),
        ],
        vec![
            "--echo".into(), "--handle".into(),
            "add".into(), "rule".into(), "inet".into(), "omni_probe_guard".into(), "omni_out".into(),
            "ip".into(), "daddr".into(), norm.clone(), "counter".into(), "drop".into(),
        ],
    ];
    Ok((norm, cmds))
}

/// 从 `nft --echo --handle` 标准输出提取新增规则句柄号 (`# handle <N>`)
pub fn parse_linux_nft_handle(stdout_text: &str) -> u64 {
    for token_pair in stdout_text.split_whitespace().collect::<Vec<_>>().windows(2) {
        if token_pair[0] == "handle" {
            if let Ok(h) = token_pair[1].trim_end_matches(';').parse::<u64>() {
                return h;
            }
        }
    }
    0
}

#[cfg(not(windows))]
mod win_wfp_impl {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum LinuxFirewallDriver {
        Nftables,
        Iptables,
        Unavailable,
    }

    pub struct NativeWfpManager {
        active_rules: HashMap<String, WfpKernelRule>,
        driver: LinuxFirewallDriver,
        last_message: String,
        permission_denied: bool,
    }

    impl NativeWfpManager {
        pub fn new() -> Self {
            #[cfg(target_os = "linux")]
            let (driver, msg) = if std::process::Command::new("nft").arg("--version").output().is_ok_and(|o| o.status.success()) {
                (LinuxFirewallDriver::Nftables, "Linux 内核防线就绪: nftables (inet omni_probe_guard)".to_string())
            } else if std::process::Command::new("iptables").arg("--version").output().is_ok_and(|o| o.status.success()) {
                (LinuxFirewallDriver::Iptables, "Linux 内核防线就绪: iptables 兼容模式".to_string())
            } else {
                (LinuxFirewallDriver::Unavailable, "未检测到 nftables (nft) 或 iptables 命令，将仅启用用户态拦截".to_string())
            };
            #[cfg(not(target_os = "linux"))]
            let (driver, msg) = (
                LinuxFirewallDriver::Unavailable,
                "当前非 Windows/Linux 桌面环境，未挂载系统防火墙驱动".to_string(),
            );
            Self {
                active_rules: HashMap::new(),
                driver,
                last_message: msg,
                permission_denied: false,
            }
        }

        pub fn block_ip(&mut self, target: &str, reason: &str) -> WfpBlockOutcome {
            let (norm, cmds) = match build_linux_nft_block_cmds(target) {
                Ok(v) => v,
                Err(e) => {
                    return WfpBlockOutcome {
                        success: false,
                        kernel_enforced: false,
                        permission_denied: false,
                        target: target.to_string(),
                        cidr_normalized: String::new(),
                        inbound_filter_id: 0,
                        outbound_filter_id: 0,
                        message: e,
                    };
                }
            };

            if self.driver == LinuxFirewallDriver::Nftables {
                let mut in_handle = 0u64;
                let mut out_handle = 0u64;
                for (idx, args) in cmds.iter().enumerate() {
                    match std::process::Command::new("nft").args(args).output() {
                        Ok(out) if out.status.success() => {
                            let s = String::from_utf8_lossy(&out.stdout);
                            if idx == 3 {
                                in_handle = parse_linux_nft_handle(&s);
                            } else if idx == 4 {
                                out_handle = parse_linux_nft_handle(&s);
                            }
                        }
                        Ok(out) => {
                            let err = String::from_utf8_lossy(&out.stderr).to_string();
                            let denied = err.contains("Operation not permitted") || err.contains("Permission denied") || err.contains("root");
                            self.permission_denied = denied;
                            self.last_message = if denied {
                                format!("权限不足：请运行 `sudo nft add rule inet omni_probe_guard omni_in ip saddr {} drop` ({})", norm, err.trim())
                            } else {
                                format!("nftables 下发失败: {}", err.trim())
                            };
                            return WfpBlockOutcome {
                                success: false,
                                kernel_enforced: false,
                                permission_denied: denied,
                                target: target.to_string(),
                                cidr_normalized: norm,
                                inbound_filter_id: 0,
                                outbound_filter_id: 0,
                                message: self.last_message.clone(),
                            };
                        }
                        Err(e) => {
                            return WfpBlockOutcome {
                                success: false,
                                kernel_enforced: false,
                                permission_denied: false,
                                target: target.to_string(),
                                cidr_normalized: norm,
                                inbound_filter_id: 0,
                                outbound_filter_id: 0,
                                message: format!("调用 nft 失败: {}", e),
                            };
                        }
                    }
                }
                let rule = WfpKernelRule {
                    target: target.to_string(),
                    cidr_normalized: norm.clone(),
                    reason: reason.to_string(),
                    inbound_filter_id: in_handle,
                    outbound_filter_id: out_handle,
                    created_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                    enforcement_mode: "LINUX_NFTABLES_ACTIVE".to_string(),
                };
                self.active_rules.insert(norm.clone(), rule);
                self.permission_denied = false;
                self.last_message = format!("已在 Linux nftables (inet omni_probe_guard) 下发双向硬阻断: {}", norm);
                return WfpBlockOutcome {
                    success: true,
                    kernel_enforced: true,
                    permission_denied: false,
                    target: target.to_string(),
                    cidr_normalized: norm,
                    inbound_filter_id: in_handle,
                    outbound_filter_id: out_handle,
                    message: self.last_message.clone(),
                };
            } else if self.driver == LinuxFirewallDriver::Iptables {
                let r1 = std::process::Command::new("iptables")
                    .args(["-I", "INPUT", "-s", &norm, "-j", "DROP"])
                    .output();
                let r2 = std::process::Command::new("iptables")
                    .args(["-I", "OUTPUT", "-d", &norm, "-j", "DROP"])
                    .output();
                match (r1, r2) {
                    (Ok(o1), Ok(o2)) if o1.status.success() && o2.status.success() => {
                        let rule = WfpKernelRule {
                            target: target.to_string(),
                            cidr_normalized: norm.clone(),
                            reason: reason.to_string(),
                            inbound_filter_id: 1,
                            outbound_filter_id: 1,
                            created_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                            enforcement_mode: "LINUX_IPTABLES_ACTIVE".to_string(),
                        };
                        self.active_rules.insert(norm.clone(), rule);
                        self.last_message = format!("已在 Linux iptables 下发入出站硬阻断: {}", norm);
                        return WfpBlockOutcome {
                            success: true,
                            kernel_enforced: true,
                            permission_denied: false,
                            target: target.to_string(),
                            cidr_normalized: norm,
                            inbound_filter_id: 1,
                            outbound_filter_id: 1,
                            message: self.last_message.clone(),
                        };
                    }
                    (Ok(o1), _) => {
                        let err = String::from_utf8_lossy(&o1.stderr).to_string();
                        let denied = err.contains("Permission denied") || err.contains("root");
                        self.permission_denied = denied;
                        return WfpBlockOutcome {
                            success: false,
                            kernel_enforced: false,
                            permission_denied: denied,
                            target: target.to_string(),
                            cidr_normalized: norm,
                            inbound_filter_id: 0,
                            outbound_filter_id: 0,
                            message: format!("iptables 执行失败: {}", err.trim()),
                        };
                    }
                    _ => {}
                }
            }

            WfpBlockOutcome {
                success: false,
                kernel_enforced: false,
                permission_denied: false,
                target: target.to_string(),
                cidr_normalized: norm,
                inbound_filter_id: 0,
                outbound_filter_id: 0,
                message: self.last_message.clone(),
            }
        }

        pub fn unblock_ip(&mut self, target: &str) -> Result<String, String> {
            let norm = parse_and_validate_ipv4_cidr(target)
                .map(|(_, _, n)| n)
                .unwrap_or_else(|_| target.trim().to_string());
            let removed = self.active_rules.remove(&norm).or_else(|| self.active_rules.remove(target));
            if let Some(rule) = removed {
                if rule.enforcement_mode == "LINUX_NFTABLES_ACTIVE" {
                    if rule.inbound_filter_id > 0 {
                        let _ = std::process::Command::new("nft")
                            .args(["delete", "rule", "inet", "omni_probe_guard", "omni_in", "handle", &rule.inbound_filter_id.to_string()])
                            .output();
                    }
                    if rule.outbound_filter_id > 0 {
                        let _ = std::process::Command::new("nft")
                            .args(["delete", "rule", "inet", "omni_probe_guard", "omni_out", "handle", &rule.outbound_filter_id.to_string()])
                            .output();
                    }
                    return Ok(format!("已从 Linux nftables 移除阻断规则: {}", rule.cidr_normalized));
                } else if rule.enforcement_mode == "LINUX_IPTABLES_ACTIVE" {
                    let _ = std::process::Command::new("iptables")
                        .args(["-D", "INPUT", "-s", &rule.cidr_normalized, "-j", "DROP"])
                        .output();
                    let _ = std::process::Command::new("iptables")
                        .args(["-D", "OUTPUT", "-d", &rule.cidr_normalized, "-j", "DROP"])
                        .output();
                    return Ok(format!("已从 Linux iptables 移除阻断规则: {}", rule.cidr_normalized));
                }
            }
            Err(format!("未找到 {} 的活跃内核防火墙阻断条目", target))
        }

        pub fn status_report(&mut self) -> WfpStatusReport {
            WfpStatusReport {
                os_supported: self.driver != LinuxFirewallDriver::Unavailable,
                engine_connected: self.driver != LinuxFirewallDriver::Unavailable,
                permission_denied: self.permission_denied,
                last_status_code: 0,
                last_message: self.last_message.clone(),
                active_rules: self.active_rules.values().cloned().collect(),
            }
        }
    }
}

pub static GLOBAL_WFP_MANAGER: Lazy<Mutex<win_wfp_impl::NativeWfpManager>> =
    Lazy::new(|| Mutex::new(win_wfp_impl::NativeWfpManager::new()));

pub fn block_ip_kernel_wfp(target: &str, reason: &str) -> WfpBlockOutcome {
    let mut mgr = crate::lock_guard::lock_mutex(&GLOBAL_WFP_MANAGER, "wfp_engine::block_ip");
    mgr.block_ip(target, reason)
}

pub fn unblock_ip_kernel_wfp(target: &str) -> Result<String, String> {
    let mut mgr = crate::lock_guard::lock_mutex(&GLOBAL_WFP_MANAGER, "wfp_engine::unblock_ip");
    mgr.unblock_ip(target)
}

pub fn get_wfp_kernel_status() -> WfpStatusReport {
    let mut mgr = crate::lock_guard::lock_mutex(&GLOBAL_WFP_MANAGER, "wfp_engine::status");
    mgr.status_report()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_cidr_parsing_and_host_order() {
        // 192.168.10.5 -> 0xC0A80A05
        let (addr, mask, norm) = parse_and_validate_ipv4_cidr("192.168.10.5").expect("合法 IP 应通过");
        assert_eq!(addr, 0xC0A8_0A05);
        assert_eq!(mask, 0xFFFF_FFFF);
        assert_eq!(norm, "192.168.10.5");

        // 10.20.30.99/16 -> 10.20.0.0/16
        let (addr2, mask2, norm2) =
            parse_and_validate_ipv4_cidr("10.20.30.99/16").expect("合法 CIDR 应归并网络号");
        assert_eq!(addr2, 0x0A14_0000);
        assert_eq!(mask2, 0xFFFF_0000);
        assert_eq!(norm2, "10.20.0.0/16");
    }

    #[test]
    fn test_wfp_self_protection_guards() {
        assert!(parse_and_validate_ipv4_cidr("127.0.0.1").is_err(), "必须拦截回环地址");
        assert!(parse_and_validate_ipv4_cidr("0.0.0.0").is_err(), "必须拦截全零未指定地址");
        assert!(parse_and_validate_ipv4_cidr("10.0.0.0/0").is_err(), "必须禁止 /0 阻断");
        assert!(parse_and_validate_ipv4_cidr("not_an_ip").is_err(), "必须拒绝畸形输入");
    }

    #[test]
    fn test_wfp_status_probe_never_panics() {
        // 无论单元测试进程是否具有管理员权限，探测 WFP 状态都不能崩溃且应准确报告连接或权限受阻
        let report = get_wfp_kernel_status();
        #[cfg(windows)]
        assert!(report.os_supported);
        assert!(!report.last_message.is_empty());
    }

    #[test]
    fn test_linux_nftables_command_generation_handle_parsing_and_self_protection() {
        let (norm, cmds) = build_linux_nft_block_cmds("45.33.32.156/24").expect("合法外部网段应生成 nft 策略");
        assert_eq!(norm, "45.33.32.0/24");
        assert_eq!(cmds.len(), 5);
        assert!(cmds[3].contains(&"45.33.32.0/24".to_string()));
        assert!(cmds[4].contains(&"daddr".to_string()));

        // 防自锁与防注入校验
        assert!(build_linux_nft_block_cmds("127.0.0.1").is_err());
        assert!(build_linux_nft_block_cmds("0.0.0.0/0").is_err());
        assert!(build_linux_nft_block_cmds("1.2.3.4; rm -rf /").is_err());

        // nft --echo --handle 真实输出解析测试
        let sample_echo = "add rule inet omni_probe_guard omni_in ip saddr 45.33.32.0/24 counter packets 0 bytes 0 drop # handle 42";
        assert_eq!(parse_linux_nft_handle(sample_echo), 42);
        assert_eq!(parse_linux_nft_handle("unexpected output"), 0);
    }
}
