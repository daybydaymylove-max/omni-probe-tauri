use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};

// ============================================================
// 等保三级 (GB/T 22239-2019 8.1.4.1/8.1.4.4) 三员分立访问控制与操作审计引擎
// 严格实现：系统管理员、安全管理员、安全审计员 权限正交隔离
// 任何角色不得物理清空审计日志，所有管理变更强制记录抗抵赖证据链
// ============================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserRole {
    SysAdmin,   // 系统管理员：设备参数、网卡嗅探、串口总线配置
    SecAdmin,   // 安全管理员：安全域划分、等保合规规则、通信白名单策略、蜜罐配置
    AuditAdmin, // 安全审计员：独立审查审计日志、司法证据验真、合规报告导出
}

impl UserRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            UserRole::SysAdmin => "SysAdmin",
            UserRole::SecAdmin => "SecAdmin",
            UserRole::AuditAdmin => "AuditAdmin",
        }
    }

    pub fn title_zh(&self) -> &'static str {
        match self {
            UserRole::SysAdmin => "系统管理员 (SysAdmin)",
            UserRole::SecAdmin => "安全管理员 (SecAdmin)",
            UserRole::AuditAdmin => "安全审计员 (AuditAdmin)",
        }
    }

    pub fn permissions(&self) -> Vec<&'static str> {
        match self {
            UserRole::SysAdmin => vec![
                "IFACE_CONFIG", "SERIAL_CONFIG", "STORAGE_CONFIG", "PROBE_CONTROL"
            ],
            UserRole::SecAdmin => vec![
                "ZONE_POLICY", "BASELINE_POLICY", "HONEYPOT_CONFIG", "SECURITY_ALERT_AUDIT"
            ],
            UserRole::AuditAdmin => vec![
                "AUDIT_READ", "EVIDENCE_VERIFY", "REPORT_EXPORT", "SYSLOG_AUDIT"
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentUser {
    pub role: String,
    pub role_title: String,
    pub username: String,
    pub login_time: String,
    pub permissions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminAuditRecord {
    pub id: u64,
    pub timestamp: String,
    pub operator: String,
    pub role: String,
    pub action: String,
    pub details: String,
    pub status: String, // "SUCCESS" | "BLOCKED"
}

static CURRENT_SESSION: Lazy<Arc<Mutex<CurrentUser>>> = Lazy::new(|| {
    let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    Arc::new(Mutex::new(CurrentUser {
        role: UserRole::SecAdmin.as_str().to_string(),
        role_title: UserRole::SecAdmin.title_zh().to_string(),
        username: "sec_admin".to_string(),
        login_time: now,
        permissions: UserRole::SecAdmin.permissions().into_iter().map(String::from).collect(),
    }))
});

static AUDIT_COUNTER: AtomicU64 = AtomicU64::new(1);
static ADMIN_AUDIT_TRAIL: Lazy<Arc<Mutex<Vec<AdminAuditRecord>>>> =
    Lazy::new(|| Arc::new(Mutex::new(Vec::new())));

/// 记录管理操作审计日志（写入内存并同步触发 Syslog）
pub fn record_admin_audit(action: &str, details: &str, status: &str) {
    let (operator, role) = {
        let sess = crate::lock_guard::lock_mutex(&CURRENT_SESSION, "rbac::record_admin_audit_session");
        (sess.username.clone(), sess.role.clone())
    };

    let id = AUDIT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();

    let record = AdminAuditRecord {
        id,
        timestamp: timestamp.clone(),
        operator: operator.clone(),
        role: role.clone(),
        action: action.to_string(),
        details: details.to_string(),
        status: status.to_string(),
    };

    {
        let mut trail = crate::lock_guard::lock_mutex(&ADMIN_AUDIT_TRAIL, "rbac::record_admin_audit_trail");
        trail.insert(0, record);
        if trail.len() > 2000 {
            trail.pop();
        }
    }

    // 联动 Syslog 集中外发
    let sev = if status == "BLOCKED" { 4 } else { 6 };
    crate::syslog::emit_syslog(sev, &format!("[ADMIN_AUDIT] Operator={} Role={} Action={} Status={} Details={}", operator, role, action, status, details));
}

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

type HmacSha256 = Hmac<Sha256>;

/// PBKDF2-HMAC-SHA256 默认迭代轮次 (满足等保三级高强度防离线破解要求)
pub const PBKDF2_ITERATIONS: u32 = 100_000;
const PBKDF2_PREFIX: &str = "pbkdf2-sha256$";
const CREDENTIALS_FILE: &str = "rbac_credentials.json";
const BOOTSTRAP_NOTICE_FILE: &str = "rbac_initial_credentials.txt";

/// 历史上曾被静态声明过的弱盐名，仅用于存量迁移期识别待加固账号（绝不在源码留存任何口令字面量）
const LEGACY_WEAK_SALTS: [&str; 4] = [
    "salt_sys_2026",
    "salt_sec_2026",
    "salt_audit_2026",
    "default_salt",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RbacSecurityStatus {
    pub pending_password_change_roles: Vec<String>,
    pub all_credentials_hardened: bool,
    pub bootstrap_credentials_file: Option<String>,
    pub algorithm: String,
    pub iterations: u32,
    pub active_roles_count: usize,
}

/// 跨平台操作系统内核级强熵随机字节填充
/// 时间复杂度: O(N)，空间复杂度: O(1)
#[cfg(windows)]
fn os_fill_random(buf: &mut [u8]) -> Result<(), String> {
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn SystemFunction036(random_buffer: *mut u8, random_buffer_length: u32) -> u8;
    }
    let len = u32::try_from(buf.len()).map_err(|_| "随机长度超出 u32 上限".to_string())?;
    // SAFETY: buf 指向有效可写内存且长度为 len，SystemFunction036 对应 Win32 RtlGenRandom 标准 ABI
    let ok = unsafe { SystemFunction036(buf.as_mut_ptr(), len) };
    if ok == 0 {
        return Err("Windows 内核强随机数生成失败".to_string());
    }
    Ok(())
}

#[cfg(unix)]
fn os_fill_random(buf: &mut [u8]) -> Result<(), String> {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom")
        .map_err(|e| format!("无法打开 /dev/urandom 获取系统熵: {}", e))?;
    f.read_exact(buf)
        .map_err(|e| format!("读取 /dev/urandom 失败: {}", e))?;
    Ok(())
}

#[cfg(not(any(windows, unix)))]
fn os_fill_random(_buf: &mut [u8]) -> Result<(), String> {
    Err("当前目标平台未实现受信任的操作系统 CSPRNG 接口".to_string())
}

/// 生成 16 字节强随机十六进制盐值
fn generate_random_salt_hex() -> Result<String, String> {
    let mut raw = [0u8; 16];
    os_fill_random(&mut raw)?;
    Ok(hex::encode(raw))
}

/// 生成满足等保复杂度的高强度初始随机口令 (16 位：包含大写、小写、数字及特殊符号)
fn generate_strong_initial_password(len: usize) -> Result<String, String> {
    const UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
    const LOWER: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
    const DIGIT: &[u8] = b"23456789";
    const SYMBOL: &[u8] = b"@#%_-+=";
    const ALL: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789@#%_-+=";

    let target_len = len.max(12);
    let mut rand_bytes = vec![0u8; target_len * 2];
    os_fill_random(&mut rand_bytes)?;

    let mut chars = Vec::with_capacity(target_len);
    chars.push(UPPER[rand_bytes[0] as usize % UPPER.len()]);
    chars.push(LOWER[rand_bytes[1] as usize % LOWER.len()]);
    chars.push(DIGIT[rand_bytes[2] as usize % DIGIT.len()]);
    chars.push(SYMBOL[rand_bytes[3] as usize % SYMBOL.len()]);
    for i in 4..target_len {
        chars.push(ALL[rand_bytes[i] as usize % ALL.len()]);
    }

    // Fisher-Yates 无偏置随机打乱，避免首位类别位置固定
    for i in (1..chars.len()).rev() {
        let j = (rand_bytes[target_len + (i % target_len)] as usize) % (i + 1);
        chars.swap(i, j);
    }
    String::from_utf8(chars).map_err(|e| format!("随机口令编码失败: {}", e))
}

/// RFC 2898 标准 PBKDF2-HMAC-SHA256 密钥派生函数
/// 时间复杂度: O(iterations * ceil(dk_len / 32))，空间复杂度: O(1)
pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, dk_len: usize) -> Vec<u8> {
    if iterations == 0 || dk_len == 0 {
        return Vec::new();
    }
    let mut derived = Vec::with_capacity(dk_len);
    let mut block_index: u32 = 1;
    while derived.len() < dk_len {
        let mut mac = HmacSha256::new_from_slice(password)
            .expect("HMAC-SHA256 接受任意长度密钥输入");
        mac.update(salt);
        mac.update(&block_index.to_be_bytes());
        let mut u = mac.finalize().into_bytes();
        let mut t = u;

        for _ in 1..iterations {
            let mut next_mac = HmacSha256::new_from_slice(password)
                .expect("HMAC-SHA256 接受任意长度密钥输入");
            next_mac.update(&u);
            u = next_mac.finalize().into_bytes();
            for (ti, ui) in t.iter_mut().zip(u.iter()) {
                *ti ^= *ui;
            }
        }

        let need = (dk_len - derived.len()).min(32);
        derived.extend_from_slice(&t[..need]);
        block_index = block_index.saturating_add(1);
    }
    derived
}

/// 恒定时间相等判定，防止认证哈希比对产生计时侧信道
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn hash_pwd_pbkdf2(salt: &str, pwd: &str, iterations: u32) -> String {
    let dk = pbkdf2_hmac_sha256(pwd.as_bytes(), salt.as_bytes(), iterations, 32);
    format!("{}{}${}", PBKDF2_PREFIX, iterations, hex::encode(dk))
}

fn verify_stored_hash(salt: &str, pwd: &str, stored_hash: &str) -> bool {
    if let Some(rest) = stored_hash.strip_prefix(PBKDF2_PREFIX) {
        let mut parts = rest.splitn(2, '$');
        if let (Some(iter_str), Some(hex_dk)) = (parts.next(), parts.next()) {
            if hex_dk.len() != 64 {
                return false;
            }
            if let Ok(iters) = iter_str.parse::<u32>() {
                if iters == 0 || iters > 2_000_000 {
                    return false;
                }
                let expected = hash_pwd_pbkdf2(salt, pwd, iters);
                return constant_time_eq(expected.as_bytes(), stored_hash.as_bytes());
            }
        }
        return false;
    }

    // 兼容历史遗留单轮加盐 SHA-256 记录验证（命中后在 pending 列表保留升级强制标记）
    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update(pwd.as_bytes());
    let legacy_hex = format!("{:x}", hasher.finalize());
    constant_time_eq(legacy_hex.as_bytes(), stored_hash.as_bytes())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CredentialStore {
    /// role -> (salt_hex, pbkdf2_encoded_hash)
    pub credentials: HashMap<String, (String, String)>,
    /// 尚未修改首次初始口令或仍使用历史弱算法的角色清单
    #[serde(default)]
    pub pending_password_change_roles: Vec<String>,
    /// 一次性初始化凭据说明文件路径（所有角色首次改密后自动销毁）
    #[serde(default)]
    pub bootstrap_notice_path: Option<String>,
}

impl CredentialStore {
    /// 构建首次冷启动的随机强口令库并将一次性引导凭单安全写入受限文件
    fn bootstrap_new(cred_path: &PathBuf, notice_path: &PathBuf) -> Self {
        let mut map = HashMap::new();
        let mut pending = Vec::new();
        let mut generated_lines = Vec::new();
        generated_lines.push("==================================================================".to_string());
        generated_lines.push("OMNI-PROBE 等保三级 RBAC 首次初始化一次性随机口令凭单".to_string());
        generated_lines.push("安全声明：本文件仅在首次初始化时于本机生成，请在首次登录后立即".to_string());
        generated_lines.push("修改三员口令。所有角色完成改密后，本文件将被自动覆写并销毁。".to_string());
        generated_lines.push("==================================================================".to_string());

        for role in ["SysAdmin", "SecAdmin", "AuditAdmin"] {
            let salt = generate_random_salt_hex().unwrap_or_else(|e| {
                panic!("初始化安全随机盐失败，拒绝以不安全默认值启动: {}", e);
            });
            let init_pwd = generate_strong_initial_password(16).unwrap_or_else(|e| {
                panic!("初始化强随机初始口令失败: {}", e);
            });
            let hash = hash_pwd_pbkdf2(&salt, &init_pwd, PBKDF2_ITERATIONS);
            map.insert(role.to_string(), (salt, hash));
            pending.push(role.to_string());
            generated_lines.push(format!("{:<12} : {}", role, init_pwd));
        }

        if let Some(parent) = notice_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let notice_body = generated_lines.join("\n") + "\n";
        let _ = std::fs::write(notice_path, notice_body.as_bytes());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(notice_path, std::fs::Permissions::from_mode(0o600));
        }

        let store = Self {
            credentials: map,
            pending_password_change_roles: pending,
            bootstrap_notice_path: Some(notice_path.to_string_lossy().to_string()),
        };

        if let Some(parent) = cred_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(j) = serde_json::to_string_pretty(&store) {
            let _ = std::fs::write(cred_path, j);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(cred_path, std::fs::Permissions::from_mode(0o600));
            }
        }
        store
    }

    /// 审计存量磁盘记录，标记遗留固定盐或非 PBKDF2 摘要为待改密加固
    fn audit_legacy_risks(&mut self) {
        for role in ["SysAdmin", "SecAdmin", "AuditAdmin"] {
            if let Some((salt, hash)) = self.credentials.get(role) {
                let uses_legacy_salt = LEGACY_WEAK_SALTS.contains(&salt.as_str());
                let lacks_pbkdf2 = !hash.starts_with(PBKDF2_PREFIX);
                if (uses_legacy_salt || lacks_pbkdf2)
                    && !self.pending_password_change_roles.iter().any(|r| r == role)
                {
                    self.pending_password_change_roles.push(role.to_string());
                }
            }
        }
    }
}

fn load_or_init_store(cred_path: &PathBuf, notice_path: &PathBuf) -> CredentialStore {
    if cred_path.exists() {
        if let Ok(c) = std::fs::read_to_string(cred_path) {
            if let Ok(mut parsed) = serde_json::from_str::<CredentialStore>(&c) {
                parsed.audit_legacy_risks();
                return parsed;
            }
        }
    }
    CredentialStore::bootstrap_new(cred_path, notice_path)
}

static CREDENTIALS: Lazy<Arc<Mutex<CredentialStore>>> = Lazy::new(|| {
    let cred_path = crate::forensics::data_path(CREDENTIALS_FILE);
    let notice_path = crate::forensics::data_path(BOOTSTRAP_NOTICE_FILE);
    let store = load_or_init_store(&cred_path, &notice_path);
    Arc::new(Mutex::new(store))
});

// 连续失败锁定计数器: role -> (失败次数, 锁定截止时间)
static LOCKOUT_MAP: Lazy<Arc<Mutex<HashMap<String, (u32, Option<Instant>)>>>> =
    Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

fn parse_role(target_role: &str) -> Result<UserRole, String> {
    match target_role {
        "SysAdmin" | "sys_admin" => Ok(UserRole::SysAdmin),
        "SecAdmin" | "sec_admin" => Ok(UserRole::SecAdmin),
        "AuditAdmin" | "audit_admin" => Ok(UserRole::AuditAdmin),
        _ => Err(format!("未知的等保角色: {}", target_role)),
    }
}

/// 获取当前 RBAC 凭据合规加固现状（绝不返回口令本身，仅返回待改密清单与引导文件路径）
pub fn get_rbac_security_status() -> RbacSecurityStatus {
    let creds = crate::lock_guard::lock_mutex(&CREDENTIALS, "rbac::get_rbac_security_status");
    let pending = creds.pending_password_change_roles.clone();
    let notice_exists = creds
        .bootstrap_notice_path
        .as_ref()
        .filter(|p| std::path::Path::new(p).exists())
        .cloned();
    RbacSecurityStatus {
        all_credentials_hardened: pending.is_empty(),
        pending_password_change_roles: pending,
        bootstrap_credentials_file: notice_exists,
        algorithm: "PBKDF2-HMAC-SHA256".to_string(),
        iterations: PBKDF2_ITERATIONS,
        active_roles_count: creds.credentials.len(),
    }
}

/// 切换三员身份（PBKDF2-HMAC-SHA256 恒定时间认证 + 5次锁定防爆破）
pub fn switch_user_role(target_role: &str, password: &str) -> Result<CurrentUser, String> {
    if password.is_empty() {
        return Err("身份认证失败：操作员授权口令不能为空".to_string());
    }
    let role_enum = parse_role(target_role)?;
    let role_str = role_enum.as_str().to_string();

    // 1. 防暴力破解锁判定（连续失败 5 次锁定 15 分钟）
    {
        let mut lock_map = crate::lock_guard::lock_mutex(&LOCKOUT_MAP, "rbac::switch_user_role_lockout_check");
        if let Some((fails, lock_until)) = lock_map.get_mut(&role_str) {
            if let Some(until) = *lock_until {
                if Instant::now() < until {
                    let remain_secs = (until - Instant::now()).as_secs();
                    drop(lock_map);
                    record_admin_audit("SWITCH_ROLE_BLOCKED", &format!("角色 {} 处于防爆破锁定中，剩余 {} 秒", role_str, remain_secs), "BLOCKED");
                    return Err(format!("账户因连续验证失败已触发安全锁定，请在 {} 秒后重试", remain_secs));
                } else {
                    *fails = 0;
                    *lock_until = None;
                }
            }
        }
    }

    // 2. 验证密码（基于 PBKDF2-HMAC-SHA256 恒定时间摘要校验）
    let is_valid = {
        let creds = crate::lock_guard::lock_mutex(&CREDENTIALS, "rbac::switch_user_role_credentials");
        if let Some((salt, expected_hash)) = creds.credentials.get(&role_str) {
            verify_stored_hash(salt, password, expected_hash)
        } else {
            false
        }
    };

    if !is_valid {
        let mut triggered_lockout = false;
        {
            let mut lock_map = crate::lock_guard::lock_mutex(&LOCKOUT_MAP, "rbac::switch_user_role_fail_count");
            let entry = lock_map.entry(role_str.clone()).or_insert((0, None));
            entry.0 += 1;
            if entry.0 >= 5 {
                entry.1 = Some(Instant::now() + Duration::from_secs(900));
                triggered_lockout = true;
            }
        }
        if triggered_lockout {
            record_admin_audit("ACCOUNT_LOCKED", &format!("角色 {} 连续失败 5 次，触发 15 分钟锁定", role_str), "BLOCKED");
        }
        record_admin_audit("SWITCH_ROLE", &format!("尝试切换至 {} 认证失败: 口令错误", role_str), "BLOCKED");
        return Err("身份认证失败：口令错误。为保障等保合规安全，连续失败 5 次将锁定 15 分钟".to_string());
    }

    // 认证成功，重置失败计数
    {
        let mut lock_map = crate::lock_guard::lock_mutex(&LOCKOUT_MAP, "rbac::switch_user_role_reset_lockout");
        if let Some(entry) = lock_map.get_mut(&role_str) {
            entry.0 = 0;
            entry.1 = None;
        }
    }

    let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let new_user = CurrentUser {
        role: role_enum.as_str().to_string(),
        role_title: role_enum.title_zh().to_string(),
        username: match role_enum {
            UserRole::SysAdmin => "sys_admin".to_string(),
            UserRole::SecAdmin => "sec_admin".to_string(),
            UserRole::AuditAdmin => "audit_admin".to_string(),
        },
        login_time: now,
        permissions: role_enum.permissions().into_iter().map(String::from).collect(),
    };

    {
        let mut sess = crate::lock_guard::lock_mutex(&CURRENT_SESSION, "rbac::switch_user_role_set_session");
        *sess = new_user.clone();
    }

    record_admin_audit("SWITCH_ROLE", &format!("成功切换至 {}", role_enum.as_str()), "SUCCESS");
    Ok(new_user)
}

fn change_role_password_in_store(
    creds: &mut CredentialStore,
    cred_path: &PathBuf,
    target_role: &str,
    old_password: &str,
    new_password: &str,
) -> Result<String, String> {
    let role_enum = parse_role(target_role)?;
    let role_str = role_enum.as_str().to_string();

    if old_password.is_empty() || new_password.is_empty() {
        return Err("原口令与新口令均不能为空".to_string());
    }
    if old_password == new_password {
        return Err("新口令不得与当前口令相同".to_string());
    }
    if new_password.len() < 8 || new_password.len() > 256 {
        return Err("新口令长度必须介于 8 至 256 个字符之间".to_string());
    }
    let has_upper = new_password.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = new_password.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = new_password.chars().any(|c| c.is_ascii_digit());
    if !has_upper || !has_lower || !has_digit {
        return Err("新口令复杂度不合规：必须同时包含大写字母、小写字母和数字".to_string());
    }

    // 验证旧口令
    let old_ok = match creds.credentials.get(&role_str) {
        Some((salt, expected_hash)) => verify_stored_hash(salt, old_password, expected_hash),
        None => false,
    };
    if !old_ok {
        return Err("原口令验证错误，无法修改".to_string());
    }

    // 每次改密强制生成全新 16B 随机盐并执行 PBKDF2-HMAC-SHA256 派生
    let new_salt = generate_random_salt_hex()?;
    let new_hash = hash_pwd_pbkdf2(&new_salt, new_password, PBKDF2_ITERATIONS);
    creds.credentials.insert(role_str.clone(), (new_salt, new_hash));
    creds.pending_password_change_roles.retain(|r| r != &role_str);

    // 所有初始口令全部改密完毕后，安全覆写并删除一次性初始口令凭单文件
    if creds.pending_password_change_roles.is_empty() {
        if let Some(notice_p) = creds.bootstrap_notice_path.take() {
            let path_ref = std::path::Path::new(&notice_p);
            if path_ref.exists() {
                let _ = std::fs::write(path_ref, vec![0u8; 512]);
                let _ = std::fs::remove_file(path_ref);
            }
        }
    }

    if let Some(parent) = cred_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(j) = serde_json::to_string_pretty(creds) {
        let _ = std::fs::write(cred_path, j);
    }

    Ok(format!("角色 {} 口令已通过 PBKDF2-HMAC-SHA256 加固并固化", role_enum.title_zh()))
}

/// 修改三员操作口令（等保三级 8.1.1.1 复杂度强制校验 + 动态随机盐重置 + 持久化落盘）
pub fn change_role_password(target_role: &str, old_password: &str, new_password: &str) -> Result<String, String> {
    let role_enum = parse_role(target_role)?;
    let role_str = role_enum.as_str().to_string();
    let cred_path = crate::forensics::data_path(CREDENTIALS_FILE);

    let mut creds = crate::lock_guard::lock_mutex(&CREDENTIALS, "rbac::change_role_password");
    match change_role_password_in_store(&mut creds, &cred_path, &role_str, old_password, new_password) {
        Ok(msg) => {
            drop(creds);
            record_admin_audit("CHANGE_PWD_SUCCESS", &format!("角色 {} 成功更新高强度加盐口令", role_str), "SUCCESS");
            Ok(msg)
        }
        Err(e) => {
            drop(creds);
            record_admin_audit("CHANGE_PWD_FAIL", &format!("角色 {} 修改口令受阻: {}", role_str, e), "BLOCKED");
            Err(e)
        }
    }
}

pub fn get_current_user() -> CurrentUser {
    crate::lock_guard::lock_mutex(&CURRENT_SESSION, "rbac::get_current_user").clone()
}

pub fn get_admin_audit_trail() -> Vec<AdminAuditRecord> {
    crate::lock_guard::lock_mutex(&ADMIN_AUDIT_TRAIL, "rbac::get_admin_audit_trail").clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_test_dir(tag: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        dir.push(format!("omni_rbac_test_{}_{}_{}", tag, std::process::id(), nanos));
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    /// 1. RFC 6070 PBKDF2-HMAC-SHA256 标准官方测试向量精确对齐校验
    #[test]
    fn test_pbkdf2_hmac_sha256_rfc6070_vectors() {
        let dk1 = pbkdf2_hmac_sha256(b"password", b"salt", 1, 32);
        assert_eq!(
            hex::encode(dk1),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );

        let dk2 = pbkdf2_hmac_sha256(b"password", b"salt", 2, 32);
        assert_eq!(
            hex::encode(dk2),
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
        );

        let dk3 = pbkdf2_hmac_sha256(b"password", b"salt", 4096, 32);
        assert_eq!(
            hex::encode(dk3),
            "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
        );
    }

    /// 2. 冷启动随机强凭据生成、改密加固及一次性凭单自动销毁闭环测试
    #[test]
    fn test_bootstrap_random_creds_hardening_and_notice_wipe() {
        let dir = temp_test_dir("bootstrap");
        let cred_path = dir.join(CREDENTIALS_FILE);
        let notice_path = dir.join(BOOTSTRAP_NOTICE_FILE);

        let mut store = CredentialStore::bootstrap_new(&cred_path, &notice_path);
        assert_eq!(store.pending_password_change_roles.len(), 3);
        assert!(notice_path.exists());

        // 从一次性文件解析三员随机初始口令（各自独立且绝非固定弱口令）
        let notice_txt = std::fs::read_to_string(&notice_path).unwrap();
        let mut parsed_pwds: HashMap<String, String> = HashMap::new();
        for line in notice_txt.lines() {
            if let Some((k, v)) = line.split_once(':') {
                let role = k.trim().to_string();
                let pwd = v.trim().to_string();
                if matches!(role.as_str(), "SysAdmin" | "SecAdmin" | "AuditAdmin") {
                    parsed_pwds.insert(role, pwd);
                }
            }
        }
        assert_eq!(parsed_pwds.len(), 3);
        assert_ne!(parsed_pwds["SysAdmin"], parsed_pwds["SecAdmin"]);

        // 逐个完成改密，验证改密后旧随机口令作废且新 salt 改变
        let old_salt_sys = store.credentials["SysAdmin"].0.clone();
        change_role_password_in_store(
            &mut store,
            &cred_path,
            "SysAdmin",
            &parsed_pwds["SysAdmin"],
            "NewStrong#Sys99",
        )
        .unwrap();
        assert_ne!(store.credentials["SysAdmin"].0, old_salt_sys);
        assert!(notice_path.exists(), "仅修改部分角色时凭单尚应保留给剩余角色");

        change_role_password_in_store(
            &mut store,
            &cred_path,
            "SecAdmin",
            &parsed_pwds["SecAdmin"],
            "NewStrong#Sec88",
        )
        .unwrap();
        change_role_password_in_store(
            &mut store,
            &cred_path,
            "AuditAdmin",
            &parsed_pwds["AuditAdmin"],
            "NewStrong#Aud77",
        )
        .unwrap();

        assert!(store.pending_password_change_roles.is_empty());
        assert!(!notice_path.exists(), "全部角色改密后一次性凭单必须被彻底擦除销毁");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 3. 遗留弱盐与单轮旧哈希迁移风险自动识别 + 3 类极限边界防御
    #[test]
    fn test_legacy_risk_detection_and_extreme_boundaries() {
        let dir = temp_test_dir("edge");
        let cred_path = dir.join(CREDENTIALS_FILE);

        // (a) 模拟存量遗留单轮哈希与弱盐
        let mut hasher = Sha256::new();
        hasher.update(b"salt_sys_2026");
        hasher.update(b"LegacyPass#1");
        let legacy_hex = format!("{:x}", hasher.finalize());

        let mut map = HashMap::new();
        map.insert("SysAdmin".to_string(), ("salt_sys_2026".to_string(), legacy_hex));
        let mut store = CredentialStore {
            credentials: map,
            pending_password_change_roles: Vec::new(),
            bootstrap_notice_path: None,
        };
        store.audit_legacy_risks();
        assert!(store.pending_password_change_roles.contains(&"SysAdmin".to_string()));

        // (b) 边界 1: 空输入拦截 & 同口令拦截 & 弱口令拦截
        assert!(change_role_password_in_store(&mut store, &cred_path, "SysAdmin", "", "ValidPass123").is_err());
        assert!(change_role_password_in_store(&mut store, &cred_path, "SysAdmin", "LegacyPass#1", "weak").is_err());
        assert!(change_role_password_in_store(&mut store, &cred_path, "SysAdmin", "LegacyPass#1", "LegacyPass#1").is_err());

        // (c) 边界 2: 超长溢出 (> 256 chars) 拦截
        let oversized = "Abcdef12".repeat(40);
        assert!(change_role_password_in_store(&mut store, &cred_path, "SysAdmin", "LegacyPass#1", &oversized).is_err());

        // (d) 边界 3: 非法角色与损坏 PBKDF2 字符串容错拒绝
        assert!(parse_role("RootGod").is_err());
        assert!(!verify_stored_hash("s", "p", "pbkdf2-sha256$0$deadbeef"));
        assert!(!verify_stored_hash("s", "p", "pbkdf2-sha256$not_a_number$deadbeef"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
