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
        if let Ok(sess) = CURRENT_SESSION.lock() {
            (sess.username.clone(), sess.role.clone())
        } else {
            ("unknown".to_string(), "unknown".to_string())
        }
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

    if let Ok(mut trail) = ADMIN_AUDIT_TRAIL.lock() {
        trail.insert(0, record);
        if trail.len() > 2000 {
            trail.pop();
        }
    }

    // 联动 Syslog 集中外发
    let sev = if status == "BLOCKED" { 4 } else { 6 };
    crate::syslog::emit_syslog(sev, &format!("[ADMIN_AUDIT] Operator={} Role={} Action={} Status={} Details={}", operator, role, action, status, details));
}

use sha2::Digest;
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CredentialStore {
    // role -> (salt, sha256_hex)
    pub credentials: HashMap<String, (String, String)>,
}

impl Default for CredentialStore {
    fn default() -> Self {
        let mut map = HashMap::new();
        // 初始密码：admin@123, sec@123, audit@123
        map.insert("SysAdmin".to_string(), (
            "salt_sys_2026".to_string(),
            hash_pwd("salt_sys_2026", "admin@123")
        ));
        map.insert("SecAdmin".to_string(), (
            "salt_sec_2026".to_string(),
            hash_pwd("salt_sec_2026", "sec@123")
        ));
        map.insert("AuditAdmin".to_string(), (
            "salt_audit_2026".to_string(),
            hash_pwd("salt_audit_2026", "audit@123")
        ));
        Self { credentials: map }
    }
}

fn hash_pwd(salt: &str, pwd: &str) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update(pwd.as_bytes());
    format!("{:x}", hasher.finalize())
}

static CREDENTIALS: Lazy<Arc<Mutex<CredentialStore>>> = Lazy::new(|| {
    let path = crate::forensics::data_path("rbac_credentials.json");
    let store = if path.exists() {
        if let Ok(c) = std::fs::read_to_string(&path) {
            serde_json::from_str::<CredentialStore>(&c).unwrap_or_default()
        } else {
            CredentialStore::default()
        }
    } else {
        let def = CredentialStore::default();
        if let Ok(j) = serde_json::to_string_pretty(&def) {
            let _ = std::fs::write(path, j);
        }
        def
    };
    Arc::new(Mutex::new(store))
});

// 连续失败锁定计数器: role -> (失败次数, 锁定截止时间)
static LOCKOUT_MAP: Lazy<Arc<Mutex<HashMap<String, (u32, Option<Instant>)>>>> =
    Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

/// 切换三员身份（严格加盐哈希认证 + 防暴力破解锁定）
pub fn switch_user_role(target_role: &str, password: &str) -> Result<CurrentUser, String> {
    let role_enum = match target_role {
        "SysAdmin" | "sys_admin" => UserRole::SysAdmin,
        "SecAdmin" | "sec_admin" => UserRole::SecAdmin,
        "AuditAdmin" | "audit_admin" => UserRole::AuditAdmin,
        _ => return Err(format!("未知的等保角色: {}", target_role)),
    };
    let role_str = role_enum.as_str().to_string();

    // 1. 防暴力破解锁判定（连续失败 5 次锁定 15 分钟）
    if let Ok(mut lock_map) = LOCKOUT_MAP.lock() {
        if let Some((fails, lock_until)) = lock_map.get_mut(&role_str) {
            if let Some(until) = *lock_until {
                if Instant::now() < until {
                    let remain_secs = (until - Instant::now()).as_secs();
                    record_admin_audit("SWITCH_ROLE_BLOCKED", &format!("角色 {} 处于防爆破锁定中，剩余 {} 秒", role_str, remain_secs), "BLOCKED");
                    return Err(format!("账户因连续验证失败已触发安全锁定，请在 {} 秒后重试", remain_secs));
                } else {
                    // 锁定超时，重置计数
                    *fails = 0;
                    *lock_until = None;
                }
            }
        }
    }

    // 2. 验证密码（基于持久化加盐 SHA-256）
    let is_valid = {
        let creds = CREDENTIALS.lock().map_err(|e| e.to_string())?;
        if let Some((salt, expected_hash)) = creds.credentials.get(&role_str) {
            let computed = hash_pwd(salt, password);
            computed == *expected_hash
        } else {
            false
        }
    };

    if !is_valid {
        // 记录失败并判定锁定
        if let Ok(mut lock_map) = LOCKOUT_MAP.lock() {
            let entry = lock_map.entry(role_str.clone()).or_insert((0, None));
            entry.0 += 1;
            if entry.0 >= 5 {
                entry.1 = Some(Instant::now() + Duration::from_secs(900)); // 锁定 15 分钟
                record_admin_audit("ACCOUNT_LOCKED", &format!("角色 {} 连续失败 5 次，触发 15 分钟锁定", role_str), "BLOCKED");
            }
        }
        record_admin_audit("SWITCH_ROLE", &format!("尝试切换至 {} 认证失败: 口令错误", role_str), "BLOCKED");
        return Err("身份认证失败：口令错误。为保障等保合规安全，连续失败 5 次将锁定 15 分钟".to_string());
    }

    // 认证成功，重置失败计数
    if let Ok(mut lock_map) = LOCKOUT_MAP.lock() {
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

    if let Ok(mut sess) = CURRENT_SESSION.lock() {
        *sess = new_user.clone();
    }

    record_admin_audit("SWITCH_ROLE", &format!("成功切换至 {}", role_enum.as_str()), "SUCCESS");
    Ok(new_user)
}

/// 修改三员操作口令（等保三级 8.1.1.1 复杂度强制校验 + 持久化落盘）
pub fn change_role_password(target_role: &str, old_password: &str, new_password: &str) -> Result<String, String> {
    let role_enum = match target_role {
        "SysAdmin" | "sys_admin" => UserRole::SysAdmin,
        "SecAdmin" | "sec_admin" => UserRole::SecAdmin,
        "AuditAdmin" | "audit_admin" => UserRole::AuditAdmin,
        _ => return Err(format!("未知的等保角色: {}", target_role)),
    };
    let role_str = role_enum.as_str().to_string();

    // 1. 口令复杂度校验：长度 >= 8，必须包含大写、小写字母与数字
    if new_password.len() < 8 {
        return Err("新口令长度不足：必须至少包含 8 个字符".to_string());
    }
    let has_upper = new_password.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = new_password.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = new_password.chars().any(|c| c.is_ascii_digit());
    if !has_upper || !has_lower || !has_digit {
        return Err("新口令复杂度不合规：必须同时包含大写字母、小写字母和数字".to_string());
    }

    // 2. 验证旧口令
    let mut creds = CREDENTIALS.lock().map_err(|e| e.to_string())?;
    let salt = if let Some((salt, expected_hash)) = creds.credentials.get(&role_str) {
        if hash_pwd(salt, old_password) != *expected_hash {
            record_admin_audit("CHANGE_PWD_FAIL", &format!("角色 {} 原口令校验失败", role_str), "BLOCKED");
            return Err("原口令验证错误，无法修改".to_string());
        }
        salt.clone()
    } else {
        "default_salt".to_string()
    };

    // 3. 更新加盐哈希并持久化写入 rbac_credentials.json
    let new_hash = hash_pwd(&salt, new_password);
    creds.credentials.insert(role_str.clone(), (salt, new_hash));

    let path = crate::forensics::data_path("rbac_credentials.json");
    if let Ok(j) = serde_json::to_string_pretty(&*creds) {
        let _ = std::fs::write(path, j);
    }

    record_admin_audit("CHANGE_PWD_SUCCESS", &format!("角色 {} 成功更新口令并持久化至磁盘", role_str), "SUCCESS");
    Ok(format!("角色 {} 口令已成功更新并固化", role_enum.title_zh()))
}

pub fn get_current_user() -> CurrentUser {
    CURRENT_SESSION.lock().map(|u| u.clone()).unwrap_or_else(|_| {
        let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        CurrentUser {
            role: "SecAdmin".to_string(),
            role_title: "安全管理员".to_string(),
            username: "sec_admin".to_string(),
            login_time: now,
            permissions: vec![],
        }
    })
}

pub fn get_admin_audit_trail() -> Vec<AdminAuditRecord> {
    ADMIN_AUDIT_TRAIL.lock().map(|t| t.clone()).unwrap_or_default()
}
