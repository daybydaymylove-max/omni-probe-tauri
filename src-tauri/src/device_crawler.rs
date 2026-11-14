//! 网络设备在线自动化凭据采集与配置抓取引擎
//! 支持基于 SSH 与 RFC 854 Telnet 自动化管道登录华为 (Huawei VRP)、思科 (Cisco IOS)、新华三 (H3C Comware)、锐捷 (Ruijie RGOS)
//! 自动下发无分页指令，提取设备 `running-config` 文本并管道化灌入等保 Dissector
//!
//! 算法复杂度：
//! - 时间复杂度：O(T + N) 网络 I/O 耗时 + 线性缓冲流
//! - 空间复杂度：O(M) 抓取配置报文内存缓冲区

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// 网络设备采集参数
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeviceCrawlerParams {
    pub host: String,
    pub port: u16,
    pub protocol: String, // "SSH" | "TELNET"
    pub username: String,
    pub password: Option<String>,
    pub enable_password: Option<String>,
    pub vendor_hint: Option<String>, // "HUAWEI" | "CISCO" | "H3C" | "RUIJIE" | "AUTO"
    pub timeout_secs: Option<u64>,
}

/// RFC 854 Telnet 常用常量
const TELNET_IAC: u8 = 255;
const TELNET_DONT: u8 = 254;
const TELNET_DO: u8 = 253;
const TELNET_WONT: u8 = 252;
const TELNET_WILL: u8 = 251;
const TELNET_SB: u8 = 250;
const TELNET_SE: u8 = 240;

/// 过滤与清洗 Telnet IAC 协商字节序列，并生成反向拒绝/应答报文
/// 算法确保不会陷入协商死循环
pub fn process_telnet_iac_stream(raw: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut clean_text = Vec::new();
    let mut response_buf = Vec::new();

    let mut i = 0;
    while i < raw.len() {
        if raw[i] == TELNET_IAC {
            if i + 1 >= raw.len() {
                break;
            }
            let cmd = raw[i + 1];
            if cmd == TELNET_IAC {
                // 转义 IAC (0xFF 0xFF -> 0xFF)
                clean_text.push(TELNET_IAC);
                i += 2;
                continue;
            }
            if cmd == TELNET_DO {
                if i + 2 < raw.len() {
                    let opt = raw[i + 2];
                    // 默认拒绝所有服务器要求的主动特性: IAC WONT <opt>
                    response_buf.extend_from_slice(&[TELNET_IAC, TELNET_WONT, opt]);
                    i += 3;
                    continue;
                }
            } else if cmd == TELNET_DONT {
                if i + 2 < raw.len() {
                    let opt = raw[i + 2];
                    response_buf.extend_from_slice(&[TELNET_IAC, TELNET_WONT, opt]);
                    i += 3;
                    continue;
                }
            } else if cmd == TELNET_WILL {
                if i + 2 < raw.len() {
                    let opt = raw[i + 2];
                    // 默认拒绝服务器提供特性: IAC DONT <opt> (除非回显抑制)
                    response_buf.extend_from_slice(&[TELNET_IAC, TELNET_DONT, opt]);
                    i += 3;
                    continue;
                }
            } else if cmd == TELNET_WONT {
                if i + 2 < raw.len() {
                    let opt = raw[i + 2];
                    response_buf.extend_from_slice(&[TELNET_IAC, TELNET_DONT, opt]);
                    i += 3;
                    continue;
                }
            } else if cmd == TELNET_SB {
                // 子协商跳过直到 IAC SE
                let mut found_se = false;
                for j in (i + 2)..raw.len() {
                    if raw[j] == TELNET_IAC && j + 1 < raw.len() && raw[j + 1] == TELNET_SE {
                        i = j + 2;
                        found_se = true;
                        break;
                    }
                }
                if found_se {
                    continue;
                }
            }
            i += 2;
        } else {
            clean_text.push(raw[i]);
            i += 1;
        }
    }

    (clean_text, response_buf)
}

/// 纯 Rust 实现的轻量 Telnet RFC 854 自动化会话执行器
pub async fn crawl_device_via_telnet(
    host: &str,
    port: u16,
    username: &str,
    password: Option<&str>,
    enable_password: Option<&str>,
    timeout_secs: u64,
) -> Result<String, String> {
    let addr_str = format!("{}:{}", host, port);
    let socket_addr: SocketAddr = addr_str
        .parse()
        .map_err(|e| format!("目标网络设备地址格式非法 ({}): {}", addr_str, e))?;

    let timeout_dur = Duration::from_secs(timeout_secs);
    let mut stream = tokio::time::timeout(timeout_dur, TcpStream::connect(socket_addr))
        .await
        .map_err(|_| format!("连接设备 {} 超时 ({} 秒)", addr_str, timeout_secs))?
        .map_err(|e| format!("连接网络设备 TCP 端口失败: {}", e))?;

    let mut captured_output = String::new();
    let mut stage = 0; // 0: 初始读提示符, 1: 已发用户名, 2: 已发密码, 3: 已发特权密码, 4: 已下发导出指令, 5: 抓取完成
    let mut read_buf = [0u8; 4096];
    let start_instant = std::time::Instant::now();

    while start_instant.elapsed() < timeout_dur {
        let n = match tokio::time::timeout(Duration::from_millis(800), stream.read(&mut read_buf)).await {
            Ok(Ok(0)) => break, // 对端关闭
            Ok(Ok(bytes_read)) => bytes_read,
            Ok(Err(e)) => return Err(format!("网络设备读取失败: {}", e)),
            Err(_) => {
                // 读取微超时（提示符通常在该间隙出现）
                0
            }
        };

        if n > 0 {
            let (clean, reply) = process_telnet_iac_stream(&read_buf[..n]);
            if !reply.is_empty() {
                let _ = stream.write_all(&reply).await;
            }
            let decoded = crate::host_baseline::decode_console_bytes(&clean);
            captured_output.push_str(&decoded);
        }

        let lower_all = captured_output.to_ascii_lowercase();

        match stage {
            0 => {
                if lower_all.contains("login:") || lower_all.contains("username:") || lower_all.contains("user:") || lower_all.contains("用户") {
                    let _ = stream.write_all(format!("{}\r\n", username).as_bytes()).await;
                    stage = 1;
                }
            }
            1 => {
                if lower_all.contains("password:") || lower_all.contains("passwd:") || lower_all.contains("密码") {
                    let pwd = password.unwrap_or("");
                    let _ = stream.write_all(format!("{}\r\n", pwd).as_bytes()).await;
                    stage = 2;
                }
            }
            2 => {
                let trimmed = captured_output.trim_end();
                if is_cli_prompt(trimmed) {
                    if trimmed.ends_with('>') && !trimmed.contains('<') && enable_password.is_some() {
                        let _ = stream.write_all(b"enable\r\n").await;
                        stage = 3;
                    } else {
                        write_export_commands(&mut stream, &captured_output, None).await?;
                        stage = 4;
                    }
                }
            }
            3 => {
                if lower_all.contains("password:") {
                    let epwd = enable_password.unwrap_or("");
                    let _ = stream.write_all(format!("{}\r\n", epwd).as_bytes()).await;
                    write_export_commands(&mut stream, &captured_output, None).await?;
                    stage = 4;
                }
            }
            4 => {
                if is_config_dump_finished(&captured_output) {
                    let _ = stream.write_all(b"quit\r\n").await;
                    break;
                }
            }
            _ => break,
        }
    }

    if captured_output.trim().is_empty() {
        return Err("采集超时：未从网络设备获取到任何有效配置文本或提示符".to_string());
    }

    Ok(captured_output)
}

#[inline]
fn is_cli_prompt(trimmed: &str) -> bool {
    trimmed.ends_with('>') || trimmed.ends_with('#') || trimmed.ends_with(']')
}

#[inline]
fn is_config_dump_finished(output: &str) -> bool {
    let has_end_marker = output.contains("return\r\n")
        || output.contains("return\n")
        || output.contains("\nend\r\n")
        || output.contains("\nend\n");
    has_end_marker && is_cli_prompt(output.trim_end())
}

/// 识别设备提示符或厂商提示，通过任意 AsyncWriteExt 管道下发无分页与配置导出指令
async fn write_export_commands<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    current_context: &str,
    vendor_hint: Option<&str>,
) -> Result<(), String> {
    let hint_lower = vendor_hint.unwrap_or("").to_ascii_lowercase();
    let ctx_lower = current_context.to_ascii_lowercase();
    let is_huawei_or_h3c = hint_lower == "huawei"
        || hint_lower == "h3c"
        || current_context.contains('<')
        || current_context.contains('[')
        || ctx_lower.contains("huawei")
        || ctx_lower.contains("h3c");

    let cmd = if is_huawei_or_h3c {
        "screen-length 0 temporary\r\ndisplay current-configuration\r\n"
    } else {
        "terminal length 0\r\nshow running-config\r\n"
    };
    writer.write_all(cmd.as_bytes()).await.map_err(|e| e.to_string())?;
    writer.flush().await.map_err(|e| e.to_string())?;
    Ok(())
}

/// 严格白名单字符校验：同时拦截命令注入（;|&$`\r\n空格）与 OpenSSH 选项参数注入（前导 `-`）
pub fn validate_ssh_target_token(token: &str, field_label: &str) -> Result<(), String> {
    let trimmed = token.trim();
    if trimmed.is_empty() || trimmed.len() > 128 {
        return Err(format!("{} 长度非法（必须为 1~128 个字符）", field_label));
    }
    if trimmed.starts_with('-') {
        return Err(format!("{} 包含高危非法前导符号 '-'，命令参数注入已被安全拦截", field_label));
    }
    let valid = trimmed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'));
    if !valid {
        return Err(format!(
            "{} 包含高危非法字符（仅允许字母、数字、点、下划线、冒号、连字符），命令已被安全拦截",
            field_label
        ));
    }
    Ok(())
}

/// 跨平台 SSH_ASKPASS 临时脚本 RAII 守卫：
/// 1. 脚本源码绝不含明文密码，仅读取受控环境变量 `OMNI_PROBE_SSH_CRED`；
/// 2. 在作用域结束（含异常或异步取消）时自动物理删除临时脚本。
pub struct TempAskPassGuard {
    script_path: PathBuf,
}

impl TempAskPassGuard {
    pub fn create() -> Result<Self, String> {
        let unique_id = format!(
            "omni_askpass_{}_{}.{}",
            std::process::id(),
            chrono::Local::now().timestamp_nanos_opt().unwrap_or(0),
            if cfg!(windows) { "cmd" } else { "sh" }
        );
        let script_path = std::env::temp_dir().join(unique_id);

        #[cfg(windows)]
        {
            // 仅从隔离环境变量输出密码，绝不将密码硬编码进磁盘脚本
            let content = "@echo off\r\nsetlocal EnableDelayedExpansion\r\necho(!OMNI_PROBE_SSH_CRED!\r\n";
            std::fs::write(&script_path, content)
                .map_err(|e| format!("创建安全 SSH_ASKPASS 脚本失败: {}", e))?;
        }
        #[cfg(not(windows))]
        {
            use std::os::unix::fs::PermissionsExt;
            let content = "#!/bin/sh\nprintf '%s\\n' \"$OMNI_PROBE_SSH_CRED\"\n";
            std::fs::write(&script_path, content)
                .map_err(|e| format!("创建安全 SSH_ASKPASS 脚本失败: {}", e))?;
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(&script_path, perms)
                .map_err(|e| format!("设置 SSH_ASKPASS 执行权限失败: {}", e))?;
        }

        Ok(Self { script_path })
    }

    pub fn path_str(&self) -> String {
        self.script_path.to_string_lossy().into_owned()
    }
}

impl Drop for TempAskPassGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.script_path);
    }
}

/// 调用系统原生 OpenSSH 交互式双工管道采集网络设备配置
/// 通过 SSH_ASKPASS + 隔离环境变量实现零明文落盘自动密码认证，自动发送厂商自适应导出指令
pub async fn crawl_device_via_ssh(
    host: &str,
    port: u16,
    username: &str,
    password: Option<&str>,
    enable_password: Option<&str>,
    vendor_hint: Option<&str>,
    timeout_secs: u64,
) -> Result<String, String> {
    validate_ssh_target_token(host, "目标主机地址")?;
    validate_ssh_target_token(username, "登录用户名")?;

    let host_clean = host.trim();
    let user_clean = username.trim();
    let port_str = port.to_string();
    let user_host = format!("{}@{}", user_clean, host_clean);
    let known_hosts_null = if cfg!(windows) { "NUL" } else { "/dev/null" };

    let _askpass_guard = if password.is_some() {
        Some(TempAskPassGuard::create()?)
    } else {
        None
    };

    let mut cmd = tokio::process::Command::new("ssh");
    cmd.args([
        "-p",
        &port_str,
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        &format!("UserKnownHostsFile={}", known_hosts_null),
        "-o",
        &format!("ConnectTimeout={}", timeout_secs.min(10)),
        "-o",
        "LogLevel=ERROR",
        "-o",
        "NumberOfPasswordPrompts=1",
        "--",
        &user_host,
    ])
    .stdin(std::process::Stdio::piped())
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::piped());

    if let (Some(pwd), Some(guard)) = (password, &_askpass_guard) {
        cmd.env("OMNI_PROBE_SSH_CRED", pwd);
        cmd.env("SSH_ASKPASS", guard.path_str());
        cmd.env("SSH_ASKPASS_REQUIRE", "force");
        cmd.env("DISPLAY", "omni:0");
    } else {
        cmd.args(["-o", "BatchMode=yes"]);
    }

    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("启动系统原生 OpenSSH 客户端失败: {}", e))?;

    let mut stdin = child.stdin.take().ok_or("无法打开 SSH stdin 管道")?;
    let mut stdout = child.stdout.take().ok_or("无法打开 SSH stdout 管道")?;
    let mut stderr = child.stderr.take().ok_or("无法打开 SSH stderr 管道")?;

    let timeout_dur = Duration::from_secs(timeout_secs);
    let start_instant = std::time::Instant::now();
    let mut captured_output = String::new();
    let mut captured_err = String::new();
    let mut out_buf = [0u8; 4096];
    let mut err_buf = [0u8; 2048];
    let mut stage = 0u8; // 0: 等提示符, 1: 已发 enable 等密码, 2: 已发导出指令等待结束

    // 发送回车探活，促使无 PTY 通道的网络设备尽快吐出提示符
    let _ = stdin.write_all(b"\r\n").await;
    let _ = stdin.flush().await;

    while start_instant.elapsed() < timeout_dur {
        tokio::select! {
            res_out = tokio::time::timeout(Duration::from_millis(600), stdout.read(&mut out_buf)) => {
                match res_out {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => {
                        let text = crate::host_baseline::decode_console_bytes(&out_buf[..n]);
                        captured_output.push_str(&text);
                    }
                    Ok(Err(e)) => {
                        let _ = child.kill().await;
                        return Err(format!("SSH 标准输出读取失败: {}", e));
                    }
                    Err(_) => {}
                }
            }
            res_err = stderr.read(&mut err_buf) => {
                if let Ok(n) = res_err {
                    if n > 0 {
                        let err_txt = crate::host_baseline::decode_console_bytes(&err_buf[..n]);
                        captured_err.push_str(&err_txt);
                    }
                }
            }
        }

        let trimmed = captured_output.trim_end();
        let lower_all = captured_output.to_ascii_lowercase();

        match stage {
            0 => {
                if is_cli_prompt(trimmed) {
                    if trimmed.ends_with('>') && !trimmed.contains('<') && enable_password.is_some() {
                        let _ = stdin.write_all(b"enable\r\n").await;
                        let _ = stdin.flush().await;
                        stage = 1;
                    } else {
                        write_export_commands(&mut stdin, &captured_output, vendor_hint).await?;
                        stage = 2;
                    }
                }
            }
            1 => {
                if lower_all.contains("password:") {
                    let epwd = enable_password.unwrap_or("");
                    let _ = stdin.write_all(format!("{}\r\n", epwd).as_bytes()).await;
                    let _ = stdin.flush().await;
                    write_export_commands(&mut stdin, &captured_output, vendor_hint).await?;
                    stage = 2;
                }
            }
            2 => {
                if is_config_dump_finished(&captured_output) {
                    let _ = stdin.write_all(b"quit\r\n").await;
                    let _ = stdin.flush().await;
                    break;
                }
            }
            _ => break,
        }
    }

    let _ = child.kill().await;

    if captured_output.trim().is_empty() {
        return Err(format!(
            "SSH 采集未获取到有效配置输出。错误信息: {}",
            captured_err.trim()
        ));
    }

    Ok(captured_output)
}

/// Tauri 命令：在线自动化采集远程网络设备配置
#[tauri::command]
pub async fn fetch_remote_device_config_cmd(params: DeviceCrawlerParams) -> Result<String, String> {
    let timeout = params.timeout_secs.unwrap_or(15).max(3).min(60);

    if params.protocol.eq_ignore_ascii_case("TELNET") {
        crawl_device_via_telnet(
            &params.host,
            params.port,
            &params.username,
            params.password.as_deref(),
            params.enable_password.as_deref(),
            timeout,
        )
        .await
    } else {
        crawl_device_via_ssh(
            &params.host,
            params.port,
            &params.username,
            params.password.as_deref(),
            params.enable_password.as_deref(),
            params.vendor_hint.as_deref(),
            timeout,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn test_process_telnet_iac_stream_negotiation() {
        let raw = [
            TELNET_IAC, TELNET_DO, 1,
            b'U', b's', b'e', b'r', b'n', b'a', b'm', b'e', b':', b' ',
        ];
        let (clean, reply) = process_telnet_iac_stream(&raw);
        assert_eq!(String::from_utf8_lossy(&clean), "Username: ");
        assert_eq!(reply, vec![TELNET_IAC, TELNET_WONT, 1]);
    }

    #[test]
    fn test_edge_cases_iac_handling() {
        let (clean, reply) = process_telnet_iac_stream(&[]);
        assert!(clean.is_empty());
        assert!(reply.is_empty());

        let raw_truncated = [b'A', b'B', TELNET_IAC];
        let (clean2, _) = process_telnet_iac_stream(&raw_truncated);
        assert_eq!(clean2, vec![b'A', b'B']);

        let raw_escaped = [TELNET_IAC, TELNET_IAC];
        let (clean3, _) = process_telnet_iac_stream(&raw_escaped);
        assert_eq!(clean3, vec![TELNET_IAC]);
    }

    #[test]
    fn test_ssh_command_and_option_injection_defense() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            // 1. 分号管道符命令注入
            let res_host = crawl_device_via_ssh("192.168.1.1; rm -rf /", 22, "admin", None, None, None, 5).await;
            assert!(res_host.is_err());
            assert!(res_host.unwrap_err().contains("高危非法字符"));

            // 2. OpenSSH 选项参数注入 (-oProxyCommand=calc.exe)
            let res_opt_user = crawl_device_via_ssh("192.168.1.1", 22, "-oProxyCommand=calc", None, None, None, 5).await;
            assert!(res_opt_user.is_err());
            assert!(res_opt_user.unwrap_err().contains("高危非法前导符号"));

            // 3. 用户名换行符注入
            let res_crlf_user = crawl_device_via_ssh("192.168.1.1", 22, "admin\ncat /etc/passwd", None, None, None, 5).await;
            assert!(res_crlf_user.is_err());
        });
    }

    #[test]
    fn test_temp_askpass_guard_zero_plaintext_and_auto_cleanup() {
        let captured_path: PathBuf;
        {
            let guard = TempAskPassGuard::create().expect("创建 AskPass 守卫应成功");
            captured_path = guard.script_path.clone();
            assert!(captured_path.exists());
            let script_body = std::fs::read_to_string(&captured_path).unwrap();
            assert!(script_body.contains("OMNI_PROBE_SSH_CRED"));
        }
        // 脱离作用域自动 Drop 销毁临时脚本
        assert!(!captured_path.exists());
    }

    #[test]
    fn test_end_to_end_loopback_telnet_crawler_huawei_session() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();

            // 模拟真实华为 VRP Telnet 交换机服务端：IAC 协商 -> 认证 -> 下发配置
            tokio::spawn(async move {
                if let Ok((mut sock, _)) = listener.accept().await {
                    let mut buf = [0u8; 1024];
                    // 1. 发送 IAC DO ECHO + Username:
                    let _ = sock.write_all(&[TELNET_IAC, TELNET_DO, 1]).await;
                    let _ = sock.write_all(b"Username: ").await;
                    let _ = sock.read(&mut buf).await; // 读客户端 IAC WONT + admin
                    let _ = sock.write_all(b"Password: ").await;
                    let _ = sock.read(&mut buf).await; // 读密码
                    let _ = sock.write_all(b"\r\n<HUAWEI-CORE-SW>").await;

                    // 2. 等待接收关闭翻页与 display current-configuration
                    let mut cmd_acc = String::new();
                    for _ in 0..5 {
                        if let Ok(n) = sock.read(&mut buf).await {
                            if n == 0 {
                                break;
                            }
                            cmd_acc.push_str(&String::from_utf8_lossy(&buf[..n]));
                            if cmd_acc.contains("display current-configuration") {
                                break;
                            }
                        }
                    }
                    if cmd_acc.contains("screen-length 0 temporary") {
                        let cfg = "\r\n#\r\nsysname HUAWEI-CORE-SW\r\nssh server protocol-version 2\r\n#\r\nreturn\r\n<HUAWEI-CORE-SW>";
                        let _ = sock.write_all(cfg.as_bytes()).await;
                    }
                }
            });

            let result = crawl_device_via_telnet(
                "127.0.0.1",
                port,
                "admin",
                Some("P@ssw0rd!"),
                None,
                5,
            )
            .await
            .expect("本地回环 Telnet 采集必须成功完成");

            assert!(result.contains("sysname HUAWEI-CORE-SW"));
            assert!(result.contains("ssh server protocol-version 2"));
        });
    }
}
