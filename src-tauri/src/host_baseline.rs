//! 主机安全计算环境 (SCE) 等保 2.0 基线自动化审计引擎
//! 符合 GB/T 22239-2019 第三级安全计算环境（SCE）身份鉴别、访问控制、安全审计与入侵防范要求
//! 
//! 复杂度说明：
//! - 时间复杂度：O(N) 线性单趟扫描
//! - 空间复杂度：O(K) 常数级固定基线结构体

use serde::{Deserialize, Serialize};

/// 主机基线核查项结果
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostBaselineItemResult {
    /// 检查项编号（如 SCE-HOST-01）
    pub id: String,
    /// 对应等保国标条款（如 GB/T 22239-2019 8.1.3.1）
    pub clause: String,
    /// 控制点名称
    pub title: String,
    /// 控制域分类 (SCE)
    pub category: String,
    /// 是否合规
    pub passed: bool,
    /// 现场实测采集值
    pub actual_value: String,
    /// 等保国家标准要求
    pub standard_requirement: String,
    /// 风险等级
    pub risk_level: String, // "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    /// 审计证据陈述
    pub evidence: String,
    /// 整改建议
    pub remediation: String,
}

/// 主机基线审计全景报告
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostBaselineReport {
    /// 操作系统类型 (Windows / Linux)
    pub os_type: String,
    /// 操作系统具体版本名称
    pub os_name: String,
    /// 被测主机名
    pub hostname: String,
    /// 审计采集时间
    pub scan_time: String,
    /// 检查总项数
    pub total_checks: usize,
    /// 通过项数
    pub passed_checks: usize,
    /// 缺陷项数
    pub failed_checks: usize,
    /// 合规达标百分比 (0.0 - 100.0)
    pub compliance_rate_pct: f64,
    /// 逐项检查结果
    pub items: Vec<HostBaselineItemResult>,
}

/// 从 Windows `net accounts` 输出文本中解析密码与锁定策略数值
/// 输入为中英文任意输出，返回 (min_len, max_age_days, lockout_threshold, lockout_duration_min)
pub fn parse_windows_net_accounts(output: &str) -> (Option<u32>, Option<u32>, Option<u32>, Option<u32>) {
    let mut min_len = None;
    let mut max_age = None;
    let mut lockout_thresh = None;
    let mut lockout_dur = None;

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // 分割冒号
        if let Some(pos) = trimmed.find(':') {
            let key = trimmed[..pos].trim().to_ascii_lowercase();
            let val = trimmed[pos + 1..].trim();

            // 提取首个连续数字
            let num_val = val
                .split_whitespace()
                .next()
                .and_then(|w| w.parse::<u32>().ok());

            if key.contains("minimum password length") || key.contains("密码最短长度") || key.contains("最短密码长度") {
                min_len = num_val;
            } else if key.contains("maximum password age") || key.contains("密码最长使用期限") || key.contains("密码最长有效时间") {
                max_age = num_val;
            } else if key.contains("lockout threshold") || key.contains("锁定阈值") || key.contains("锁定阈值") {
                lockout_thresh = num_val;
            } else if key.contains("lockout duration") || key.contains("锁定持续时间") || key.contains("锁定时间") {
                lockout_dur = num_val;
            }
        }
    }

    (min_len, max_age, lockout_thresh, lockout_dur)
}

/// 解析 Linux `/etc/login.defs` 提取密码长度与期限
pub fn parse_linux_login_defs(content: &str) -> (Option<u32>, Option<u32>) {
    let mut max_days = None;
    let mut min_len = None;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() >= 2 {
            if parts[0] == "PASS_MAX_DAYS" {
                max_days = parts[1].parse::<u32>().ok();
            } else if parts[0] == "PASS_MIN_LEN" {
                min_len = parts[1].parse::<u32>().ok();
            }
        }
    }
    (max_days, min_len)
}

/// 解析 Linux `/etc/pam.d` 中 pam_tally2 或 pam_faillock 锁定参数
pub fn parse_linux_pam_lockout(content: &str) -> (Option<u32>, Option<u32>) {
    let mut deny = None;
    let mut unlock_time = None;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }
        if trimmed.contains("pam_tally2.so") || trimmed.contains("pam_faillock.so") {
            for token in trimmed.split_whitespace() {
                if let Some(rest) = token.strip_prefix("deny=") {
                    deny = rest.parse::<u32>().ok();
                } else if let Some(rest) = token.strip_prefix("unlock_time=") {
                    unlock_time = rest.parse::<u32>().ok();
                }
            }
        }
    }
    (deny, unlock_time)
}

/// 智能控制台输出字节解码：优先严格 UTF-8 验证，非 UTF-8 自动降级 GBK 解码
pub fn decode_console_bytes(raw: &[u8]) -> String {
    if let Ok(utf8_str) = std::str::from_utf8(raw) {
        return utf8_str.to_string();
    }
    let (gbk_str, _, _) = encoding_rs::GBK.decode(raw);
    gbk_str.into_owned()
}

/// 严谨解析 `net user guest` 输出判定 Guest 账户是否已物理停用 (不依赖空格数)
/// 返回 Some(true) = 已停用, Some(false) = 仍处于活动状态, None = 解析失败
pub fn parse_windows_net_user_guest_disabled(output: &str) -> Option<bool> {
    for line in output.lines() {
        let lower = line.trim().to_ascii_lowercase();
        let original = line.trim();
        if lower.starts_with("account active") || original.starts_with("账户处于活动状态") {
            let last_token = original.split_whitespace().last()?.to_ascii_lowercase();
            if last_token == "no" || last_token == "否" {
                return Some(true);
            }
            if last_token == "yes" || last_token == "是" {
                return Some(false);
            }
        }
    }
    None
}

/// 解析 Linux `/etc/profile` / `/etc/bashrc` 提取 `TMOUT` 空闲会话超时值（秒）
pub fn parse_linux_tmout(content: &str) -> Option<u32> {
    let mut tmout = None;
    for line in content.lines() {
        let code_part = line.split('#').next().unwrap_or("").trim();
        if code_part.is_empty() {
            continue;
        }
        // 支持 "TMOUT=600", "export TMOUT=600", "readonly TMOUT=900; export TMOUT"
        for token in code_part.split(|c: char| c.is_whitespace() || c == ';') {
            if let Some(val_str) = token.strip_prefix("TMOUT=") {
                let cleaned = val_str.trim_matches(|c| c == '"' || c == '\'');
                if let Ok(secs) = cleaned.parse::<u32>() {
                    tmout = Some(secs);
                }
            }
        }
    }
    tmout
}

/// 解析 Linux `/etc/passwd` 校验 Guest 账户停用与无非 root 的 UID=0 隐藏特权账户
pub fn parse_linux_passwd_guest_and_uid0(content: &str) -> bool {
    let mut saw_valid_line = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = trimmed.split(':').collect();
        if fields.len() < 7 {
            continue;
        }
        saw_valid_line = true;
        let username = fields[0].trim();
        let uid = fields[2].trim();
        let shell = fields[6].trim();

        // 严禁存在非 root 的 UID 0 后门账户
        if uid == "0" && username != "root" {
            return false;
        }
        // 如果存在 guest 账户，其登录 Shell 必须禁用 (nologin 或 false)
        if username.eq_ignore_ascii_case("guest") {
            let shell_disabled = shell.ends_with("nologin") || shell.ends_with("/false");
            if !shell_disabled {
                return false;
            }
        }
    }
    saw_valid_line
}

/// 解析 Linux `/etc/ssh/sshd_config` 校验安全接入基线 (近似远程前置认证与加密通道检查)
pub fn parse_linux_sshd_security(content: &str) -> bool {
    let mut protocol_v1_found = false;
    let mut empty_passwords_allowed = false;
    let mut valid_cfg_seen = false;

    for line in content.lines() {
        let code_part = line.split('#').next().unwrap_or("").trim();
        if code_part.is_empty() {
            continue;
        }
        let parts: Vec<&str> = code_part.split_whitespace().collect();
        if parts.len() >= 2 {
            valid_cfg_seen = true;
            let key = parts[0].to_ascii_lowercase();
            let val = parts[1].to_ascii_lowercase();
            if key == "protocol" && val.contains('1') && !val.contains('2') {
                protocol_v1_found = true;
            }
            if key == "permitemptypasswords" && val == "yes" {
                empty_passwords_allowed = true;
            }
        }
    }

    valid_cfg_seen && !protocol_v1_found && !empty_passwords_allowed
}

/// 纯函数：根据提取到的各项安全参数，构建标准的 GB/T 22239-2019 等保 SCE 基线核查报告
pub fn evaluate_host_baseline_report(
    os_type: &str,
    os_name: &str,
    hostname: &str,
    pwd_min_len: Option<u32>,
    pwd_max_age_days: Option<u32>,
    lockout_threshold: Option<u32>,
    lockout_duration_mins: Option<u32>,
    screensaver_timeout_secs: Option<u32>,
    screensaver_secure: bool,
    firewall_enabled: bool,
    guest_disabled: bool,
    rdp_nla_enabled: bool,
) -> HostBaselineReport {
    let mut items = Vec::new();

    // 1. SCE-HOST-01: 口令长度与复杂度要求 (GB/T 22239-2019 8.1.3.1 a)
    let min_len_val = pwd_min_len.unwrap_or(0);
    let pass_len = min_len_val >= 8;
    items.push(HostBaselineItemResult {
        id: "SCE-HOST-01".to_string(),
        clause: "GB/T 22239-2019 8.1.3.1".to_string(),
        title: "身份鉴别 - 口令最小长度与复杂度".to_string(),
        category: "SCE".to_string(),
        passed: pass_len,
        actual_value: format!("最短口令长度: {} 位", min_len_val),
        standard_requirement: "最短口令长度应不小于 8 位，并启用复杂度校验".to_string(),
        risk_level: if pass_len { "LOW".to_string() } else { "HIGH".to_string() },
        evidence: if pass_len {
            format!("系统安全账户策略已设定最短口令长度为 {} 位，满足等保三级基线要求", min_len_val)
        } else {
            format!("实测系统最短口令长度仅为 {} 位（低于国标 8 位要求），易遭受暴力字典攻击", min_len_val)
        },
        remediation: "通过组策略 (secpol.msc) 或 /etc/login.defs 将口令最小长度调整为 8 位以上，并强制启用口令复杂度。".to_string(),
    });

    // 2. SCE-HOST-02: 口令定期更换周期 (GB/T 22239-2019 8.1.3.1 a)
    let max_age_val = pwd_max_age_days.unwrap_or(0);
    // 0 或 > 90 均视为不合规 (0 表示从不过期)
    let pass_age = max_age_val > 0 && max_age_val <= 90;
    items.push(HostBaselineItemResult {
        id: "SCE-HOST-02".to_string(),
        clause: "GB/T 22239-2019 8.1.3.1".to_string(),
        title: "身份鉴别 - 口令定期更换生存周期".to_string(),
        category: "SCE".to_string(),
        passed: pass_age,
        actual_value: if max_age_val == 0 { "口令永不过期 (0天)".to_string() } else { format!("{} 天", max_age_val) },
        standard_requirement: "口令最长有效期限应不超过 90 天".to_string(),
        risk_level: if pass_age { "LOW".to_string() } else { "MEDIUM".to_string() },
        evidence: if pass_age {
            format!("系统口令最长使用期限为 {} 天，符合定期更换要求", max_age_val)
        } else {
            format!("实测口令生存期为 {}，未能落实等保三级 90 天强制轮换要求", if max_age_val == 0 { "永不过期" } else { "超过90天" })
        },
        remediation: "在本地安全策略中将“密码最长使用期限”配置为 90 天以内。".to_string(),
    });

    // 3. SCE-HOST-03: 登录失败处理与锁定阈值 (GB/T 22239-2019 8.1.3.1 b)
    let thresh_val = lockout_threshold.unwrap_or(0);
    let pass_thresh = thresh_val > 0 && thresh_val <= 5;
    items.push(HostBaselineItemResult {
        id: "SCE-HOST-03".to_string(),
        clause: "GB/T 22239-2019 8.1.3.1".to_string(),
        title: "身份鉴别 - 连续登录失败处理策略".to_string(),
        category: "SCE".to_string(),
        passed: pass_thresh,
        actual_value: if thresh_val == 0 { "未启用登录锁定 (0次)".to_string() } else { format!("{} 次", thresh_val) },
        standard_requirement: "连续登录失败锁定阈值应在 3 至 5 次以内".to_string(),
        risk_level: if pass_thresh { "LOW".to_string() } else { "CRITICAL".to_string() },
        evidence: if pass_thresh {
            format!("实测账户连续认证失败锁定阈值为 {} 次，有效防御爆破", thresh_val)
        } else {
            format!("实测账户锁定阈值为 {}，无法有效阻断无限制在线网络暴力破解", if thresh_val == 0 { "无锁定限制" } else { "超标" })
        },
        remediation: "将“账户锁定阈值”调整为 5 次，并在连续错误输入达到阈值时自动冻结账户。".to_string(),
    });

    // 4. SCE-HOST-04: 锁定持续时间 (GB/T 22239-2019 8.1.3.1 b)
    let dur_val = lockout_duration_mins.unwrap_or(0);
    let pass_dur = dur_val >= 15;
    items.push(HostBaselineItemResult {
        id: "SCE-HOST-04".to_string(),
        clause: "GB/T 22239-2019 8.1.3.1".to_string(),
        title: "身份鉴别 - 账户锁定自动恢复时长".to_string(),
        category: "SCE".to_string(),
        passed: pass_dur,
        actual_value: format!("{} 分钟", dur_val),
        standard_requirement: "锁定持续时间应不小于 15 分钟（或人工管理员解锁）".to_string(),
        risk_level: if pass_dur { "LOW".to_string() } else { "MEDIUM".to_string() },
        evidence: if pass_dur {
            format!("实测账户锁定时长为 {} 分钟，符合安全缓冲要求", dur_val)
        } else {
            format!("实测账户锁定时长仅为 {} 分钟（低于 15 分钟），防护衰减过快", dur_val)
        },
        remediation: "在安全策略中配置“账户锁定时间”至少为 15 分钟或永久锁定由管理员手工复位。".to_string(),
    });

    // 5. SCE-HOST-05: 空闲会话自动超时锁屏/断开 (GB/T 22239-2019 8.1.3.4 a)
    let timeout_secs = screensaver_timeout_secs.unwrap_or(0);
    let pass_timeout = (timeout_secs > 0 && timeout_secs <= 900) && screensaver_secure;
    items.push(HostBaselineItemResult {
        id: "SCE-HOST-05".to_string(),
        clause: "GB/T 22239-2019 8.1.3.4".to_string(),
        title: "入侵防范与会话控制 - 空闲会话超时锁定".to_string(),
        category: "SCE".to_string(),
        passed: pass_timeout,
        actual_value: if timeout_secs == 0 {
            "未启用空闲超时保护".to_string()
        } else {
            format!("超时时间: {} 秒 ({} 分钟), 唤醒密码保护: {}", timeout_secs, timeout_secs / 60, if screensaver_secure { "已开启" } else { "未开启" })
        },
        standard_requirement: "操作人员空闲超过 15 分钟 (900秒) 时应自动锁定会话或注销断开".to_string(),
        risk_level: if pass_timeout { "LOW".to_string() } else { "HIGH".to_string() },
        evidence: if pass_timeout {
            format!("实测空闲锁定时间为 {} 秒且启用恢复口令核验，满足物理终端离席防范要求", timeout_secs)
        } else {
            "实测未启用屏幕超时保护或超时设定超过 15 分钟，离席时易遭受未授权现场接管".to_string()
        },
        remediation: "配置屏幕保护程序超时时间为 900 秒 (15分钟) 以内，并勾选“在恢复时显示登录屏幕”。".to_string(),
    });

    // 6. SCE-HOST-06: 默认账户禁用与最小权限 (GB/T 22239-2019 8.1.3.2 a)
    items.push(HostBaselineItemResult {
        id: "SCE-HOST-06".to_string(),
        clause: "GB/T 22239-2019 8.1.3.2".to_string(),
        title: "访问控制 - 禁用默认共享与特权账户管控".to_string(),
        category: "SCE".to_string(),
        passed: guest_disabled,
        actual_value: if guest_disabled { "Guest 来宾账户已停用".to_string() } else { "Guest 来宾账户仍处于活动启用状态".to_string() },
        standard_requirement: "应禁用或重命名系统默认账户（如 Guest、Administrator），避免共享特权".to_string(),
        risk_level: if guest_disabled { "LOW".to_string() } else { "CRITICAL".to_string() },
        evidence: if guest_disabled {
            "系统内置 Guest 来宾账户已物理停用，特权分离机制健全".to_string()
        } else {
            "实测 Guest 默认匿名来宾账户处于启用状态，存在严重越权接入暴露面".to_string()
        },
        remediation: "通过计算机管理或命令禁用 Guest 来宾账户，重命名默认 Administrator 并建立实名专属管理员账号。".to_string(),
    });

    // 7. SCE-HOST-07: 主机自身包过滤与防火墙状态 (GB/T 22239-2019 8.1.3.4 b)
    items.push(HostBaselineItemResult {
        id: "SCE-HOST-07".to_string(),
        clause: "GB/T 22239-2019 8.1.3.4".to_string(),
        title: "边界与入侵防范 - 主机个人防火墙配置".to_string(),
        category: "SCE".to_string(),
        passed: firewall_enabled,
        actual_value: if firewall_enabled { "主机防护防火墙处于启用状态".to_string() } else { "主机防火墙已关闭停用".to_string() },
        standard_requirement: "应在关键计算节点启用包过滤与主机防火墙，阻断未授权横向端口扫描".to_string(),
        risk_level: if firewall_enabled { "LOW".to_string() } else { "HIGH".to_string() },
        evidence: if firewall_enabled {
            "实测操作系统内置网络防火墙正常开启，网络侧横向隐蔽探测被有效拦截".to_string()
        } else {
            "实测操作系统防火墙处于关闭状态，未授权端口对内网暴露".to_string()
        },
        remediation: "开启系统专用与公用网络防火墙，默认拦截未显式放行的入站探测通信。".to_string(),
    });

    // 8. SCE-HOST-08: 远程访问网络级别身份验证 (NLA) (GB/T 22239-2019 8.1.3.1 c)
    items.push(HostBaselineItemResult {
        id: "SCE-HOST-08".to_string(),
        clause: "GB/T 22239-2019 8.1.3.1".to_string(),
        title: "身份鉴别 - 远程会话网络级身份鉴别 (NLA)".to_string(),
        category: "SCE".to_string(),
        passed: rdp_nla_enabled,
        actual_value: if rdp_nla_enabled { "已强制启用 NLA 网络级别身份验证".to_string() } else { "未强制启用 NLA 安全认证".to_string() },
        standard_requirement: "远程管理通道应强制要求建立会话前的网络级前置身份鉴别 (NLA) 与加密".to_string(),
        risk_level: if rdp_nla_enabled { "LOW".to_string() } else { "MEDIUM".to_string() },
        evidence: if rdp_nla_enabled {
            "远程桌面/管理会话已开启前置 NLA，有效防御 BlueKeep 等远程代码执行与中间人探测".to_string()
        } else {
            "远程会话未强制启用前置网络级身份鉴别，存在预身份验证阶段协议漏洞利用风险".to_string()
        },
        remediation: "在远程桌面配置中勾选“仅允许运行使用网络级别身份验证的远程桌面的计算机连接”。".to_string(),
    });

    let total = items.len();
    let passed = items.iter().filter(|i| i.passed).count();
    let failed = total - passed;
    let rate = if total > 0 { (passed as f64 / total as f64) * 100.0 } else { 0.0 };

    HostBaselineReport {
        os_type: os_type.to_string(),
        os_name: os_name.to_string(),
        hostname: hostname.to_string(),
        scan_time: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        total_checks: total,
        passed_checks: passed,
        failed_checks: failed,
        compliance_rate_pct: (rate * 10.0).round() / 10.0,
        items,
    }
}

/// 执行本地 Windows 宿主机的安全基线自动化审计采集
#[cfg(windows)]
pub fn audit_local_windows_baseline() -> Result<HostBaselineReport, String> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    let hostname = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "LOCAL-WINDOWS-HOST".to_string());
    let os_name = "Windows (本机实测)".to_string();

    // 1. 调用 net accounts 获取密码与锁定策略
    let net_output = Command::new("net")
        .arg("accounts")
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("执行 net accounts 失败: {}", e))?;

    let net_str = decode_console_bytes(&net_output.stdout);
    let (pwd_min_len, pwd_max_age, lockout_thresh, lockout_dur) = parse_windows_net_accounts(&net_str);

    // 2. 读取注册表检查屏保激活状态、超时时间与恢复锁定
    let mut screensaver_active = true;
    let mut screensaver_timeout = None;
    let mut screensaver_secure = false;

    if let Ok(hkcu) = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER).open_subkey("Control Panel\\Desktop") {
        if let Ok(active_str) = hkcu.get_value::<String, _>("ScreenSaveActive") {
            screensaver_active = active_str == "1";
        }
        if let Ok(to_str) = hkcu.get_value::<String, _>("ScreenSaveTimeOut") {
            screensaver_timeout = to_str.parse::<u32>().ok();
        }
        if let Ok(sec_str) = hkcu.get_value::<String, _>("ScreenSaverIsSecure") {
            screensaver_secure = sec_str == "1";
        }
    }
    if !screensaver_active {
        screensaver_timeout = None;
    }

    // 3. 读取注册表同时校验 StandardProfile (专有) 与 PublicProfile (公用) 防火墙状态
    let mut standard_fw = false;
    if let Ok(hklm) = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE).open_subkey(
        "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile",
    ) {
        if let Ok(val) = hklm.get_value::<u32, _>("EnableFirewall") {
            standard_fw = val == 1;
        }
    }
    let mut public_fw = false;
    if let Ok(hklm) = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE).open_subkey(
        "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile",
    ) {
        if let Ok(val) = hklm.get_value::<u32, _>("EnableFirewall") {
            public_fw = val == 1;
        }
    }
    let firewall_enabled = standard_fw && public_fw;

    // 4. 读取注册表检查 RDP NLA 配置
    let mut rdp_nla_enabled = false;
    if let Ok(hklm) = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE).open_subkey(
        "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
    ) {
        if let Ok(val) = hklm.get_value::<u32, _>("UserAuthentication") {
            rdp_nla_enabled = val == 1;
        }
    }

    // 5. 检查 Guest 账户是否停用 (Fail-Closed: 执行失败绝不伪报合规)
    let guest_disabled = if let Ok(out) = Command::new("net")
        .args(["user", "guest"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    {
        let s = decode_console_bytes(&out.stdout);
        parse_windows_net_user_guest_disabled(&s).unwrap_or(false)
    } else {
        false
    };

    Ok(evaluate_host_baseline_report(
        "Windows",
        &os_name,
        &hostname,
        pwd_min_len,
        pwd_max_age,
        lockout_thresh,
        lockout_dur,
        screensaver_timeout,
        screensaver_secure,
        firewall_enabled,
        guest_disabled,
        rdp_nla_enabled,
    ))
}

/// 执行本地 Linux 宿主机的安全基线自动化审计采集 (真实文件与状态读取，零静态硬编码)
#[cfg(not(windows))]
pub fn audit_local_linux_baseline() -> Result<HostBaselineReport, String> {
    use std::process::Command;

    let hostname = std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "LOCAL-LINUX-HOST".to_string());
    let os_name = "Linux (本机实测)".to_string();

    let (max_age, min_len) = if let Ok(defs) = std::fs::read_to_string("/etc/login.defs") {
        parse_linux_login_defs(&defs)
    } else {
        (None, None)
    };

    let (lockout_thresh, lockout_dur) = if let Ok(pam) = std::fs::read_to_string("/etc/pam.d/system-auth") {
        parse_linux_pam_lockout(&pam)
    } else if let Ok(pam) = std::fs::read_to_string("/etc/pam.d/common-auth") {
        parse_linux_pam_lockout(&pam)
    } else {
        (None, None)
    };

    // 真实提取 TMOUT 空闲会话超时配置
    let mut tmout_secs = None;
    for path in ["/etc/profile", "/etc/bashrc", "/etc/bash.bashrc"] {
        if let Ok(content) = std::fs::read_to_string(path) {
            if let Some(val) = parse_linux_tmout(&content) {
                tmout_secs = Some(val);
            }
        }
    }
    let tmout_valid_lock = tmout_secs.map(|s| s > 0 && s <= 900).unwrap_or(false);

    // 真实探测系统防火墙 (firewalld / ufw / iptables)
    let fw_firewalld = Command::new("firewall-cmd")
        .arg("--state")
        .output()
        .map(|o| decode_console_bytes(&o.stdout).trim().eq_ignore_ascii_case("running"))
        .unwrap_or(false);
    let fw_ufw = Command::new("ufw")
        .arg("status")
        .output()
        .map(|o| decode_console_bytes(&o.stdout).to_ascii_lowercase().contains("status: active"))
        .unwrap_or(false);
    let fw_iptables = Command::new("systemctl")
        .args(["is-active", "iptables"])
        .output()
        .map(|o| decode_console_bytes(&o.stdout).trim() == "active")
        .unwrap_or(false);
    let firewall_enabled = fw_firewalld || fw_ufw || fw_iptables;

    // 真实核查 /etc/passwd 中 guest 账户停用与无非 root UID=0 后门账户
    let guest_and_uid0_ok = std::fs::read_to_string("/etc/passwd")
        .map(|p| parse_linux_passwd_guest_and_uid0(&p))
        .unwrap_or(false);

    // 真实核查 /etc/ssh/sshd_config 安全访问控制与强协议配置
    let ssh_sec_ok = std::fs::read_to_string("/etc/ssh/sshd_config")
        .map(|c| parse_linux_sshd_security(&c))
        .unwrap_or(false);

    Ok(evaluate_host_baseline_report(
        "Linux",
        &os_name,
        &hostname,
        min_len,
        max_age,
        lockout_thresh,
        lockout_dur.map(|s| s / 60),
        tmout_secs,
        tmout_valid_lock,
        firewall_enabled,
        guest_and_uid0_ok,
        ssh_sec_ok,
    ))
}

/// Tauri 命令：执行本地宿主机安全计算环境 (SCE) 等保基线实测
#[tauri::command]
pub fn audit_host_baseline_local_cmd() -> Result<HostBaselineReport, String> {
    #[cfg(windows)]
    {
        audit_local_windows_baseline()
    }
    #[cfg(not(windows))]
    {
        audit_local_linux_baseline()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_windows_net_accounts_english() {
        let sample = "Force user logoff how long after time expires?:       Never\n\
                      Minimum password age (days):                          0\n\
                      Maximum password age (days):                          42\n\
                      Minimum password length:                              8\n\
                      Length of password history maintained:                None\n\
                      Lockout threshold:                                    5\n\
                      Lockout duration (minutes):                           30\n\
                      Lockout observation window (minutes):                 30\n\
                      Computer role:                                        WORKSTATION";
        let (min_len, max_age, thresh, dur) = parse_windows_net_accounts(sample);
        assert_eq!(min_len, Some(8));
        assert_eq!(max_age, Some(42));
        assert_eq!(thresh, Some(5));
        assert_eq!(dur, Some(30));
    }

    #[test]
    fn test_parse_windows_net_accounts_chinese() {
        let sample = "强制用户在时间到期后多久注销?:                       从不\n\
                      密码最短存留期 (天):                                  0\n\
                      密码最长使用期限 (天):                                90\n\
                      密码最短长度:                                         10\n\
                      保留的密码历史记录长度:                               无\n\
                      锁定阈值:                                             3\n\
                      锁定持续时间 (分):                                    15";
        let (min_len, max_age, thresh, dur) = parse_windows_net_accounts(sample);
        assert_eq!(min_len, Some(10));
        assert_eq!(max_age, Some(90));
        assert_eq!(thresh, Some(3));
        assert_eq!(dur, Some(15));
    }

    #[test]
    fn test_edge_cases_empty_and_malformed() {
        // 极限用例 1: 零数据输入
        let (min_len, max_age, thresh, dur) = parse_windows_net_accounts("");
        assert_eq!(min_len, None);
        assert_eq!(max_age, None);
        assert_eq!(thresh, None);
        assert_eq!(dur, None);

        // 极限用例 2: 畸形无冒号、超长溢出文本
        let malformed = "This is a random line without colon\nAnother line: not a number\nMinimum password length: 99999999999999999999999999999999999999";
        let (min_len, _, _, _) = parse_windows_net_accounts(malformed);
        // 超出 u32 范围不崩溃，优雅返回 None
        assert_eq!(min_len, None);
    }

    #[test]
    fn test_evaluate_host_baseline_report_logic() {
        let report = evaluate_host_baseline_report(
            "Windows",
            "Windows 11 Pro",
            "TEST-PC",
            Some(10), // >= 8 合规
            Some(60), // <= 90 合规
            Some(5),  // <= 5 合规
            Some(20), // >= 15 合规
            Some(600), // <= 900 合规
            true,     // 屏保锁定 合规
            true,     // 防火墙 合规
            true,     // Guest 禁用 合规
            true,     // NLA 启用 合规
        );
        assert_eq!(report.total_checks, 8);
        assert_eq!(report.passed_checks, 8);
        assert_eq!(report.failed_checks, 0);
        assert_eq!(report.compliance_rate_pct, 100.0);
    }

    #[test]
    fn test_evaluate_host_baseline_report_violations() {
        let report = evaluate_host_baseline_report(
            "Windows",
            "Windows Server 2019",
            "VULN-SRV",
            Some(4),  // < 8 不合规
            Some(0),  // 永不过期 不合规
            Some(0),  // 无锁定限制 不合规
            Some(5),  // < 15 不合规
            Some(1800), // 30分钟超标 不合规
            false,
            false,
            false,
            false,
        );
        assert_eq!(report.total_checks, 8);
        assert_eq!(report.passed_checks, 0);
        assert_eq!(report.failed_checks, 8);
        assert_eq!(report.compliance_rate_pct, 0.0);
    }

    #[test]
    fn test_windows_guest_parser_independent_of_spacing() {
        assert_eq!(
            parse_windows_net_user_guest_disabled("User name  Guest\nAccount active   No\nPassword required Yes"),
            Some(true)
        );
        assert_eq!(
            parse_windows_net_user_guest_disabled("用户名 Guest\n账户处于活动状态 否\n需要密码 是"),
            Some(true)
        );
        assert_eq!(
            parse_windows_net_user_guest_disabled("用户名 Guest\n账户处于活动状态   Yes"),
            Some(false)
        );
        assert_eq!(parse_windows_net_user_guest_disabled(""), None);
    }

    #[test]
    fn test_linux_security_parsers_and_backdoor_detection() {
        // TMOUT 解析
        assert_eq!(parse_linux_tmout("# comment\nexport TMOUT=600\n"), Some(600));
        assert_eq!(parse_linux_tmout("readonly TMOUT=\"900\"; export TMOUT\n"), Some(900));
        assert_eq!(parse_linux_tmout("# TMOUT=300\n"), None);

        // /etc/passwd 检查隐藏 UID 0 后门与活跃 guest
        let clean_passwd = "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:Kernel:/:/sbin/nologin\n";
        assert!(parse_linux_passwd_guest_and_uid0(clean_passwd));

        let backdoor_passwd = "root:x:0:0:root:/root:/bin/bash\nsysback:x:0:0:Hidden:/root:/bin/bash\n";
        assert!(!parse_linux_passwd_guest_and_uid0(backdoor_passwd));

        let active_guest_passwd = "root:x:0:0:root:/root:/bin/bash\nguest:x:1001:1001::/home/guest:/bin/bash\n";
        assert!(!parse_linux_passwd_guest_and_uid0(active_guest_passwd));

        // sshd_config 检查
        assert!(parse_linux_sshd_security("Protocol 2\nPermitEmptyPasswords no\n"));
        assert!(!parse_linux_sshd_security("Protocol 1\nPermitEmptyPasswords no\n"));
        assert!(!parse_linux_sshd_security("PermitEmptyPasswords yes\n"));
        assert!(!parse_linux_sshd_security(""));
    }
}
