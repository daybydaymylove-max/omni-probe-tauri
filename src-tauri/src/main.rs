#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

#[cfg(windows)]
fn init_windows_gui_stdio() {
    use std::fs::OpenOptions;
    use std::os::windows::io::IntoRawHandle;

    unsafe extern "system" {
        fn GetStdHandle(n_std_handle: u32) -> isize;
        fn SetStdHandle(n_std_handle: u32, h_handle: isize) -> i32;
    }

    const STD_INPUT_HANDLE: u32 = 0xFFFFFFF6;
    const STD_OUTPUT_HANDLE: u32 = 0xFFFFFFF5;
    const STD_ERROR_HANDLE: u32 = 0xFFFFFFF4;

    unsafe {
        let stdout_h = GetStdHandle(STD_OUTPUT_HANDLE);
        if stdout_h == 0 || stdout_h == -1 {
            if let Ok(nul) = OpenOptions::new().write(true).open("NUL") {
                SetStdHandle(STD_OUTPUT_HANDLE, nul.into_raw_handle() as isize);
            }
        }
        let stderr_h = GetStdHandle(STD_ERROR_HANDLE);
        if stderr_h == 0 || stderr_h == -1 {
            if let Ok(nul) = OpenOptions::new().write(true).open("NUL") {
                SetStdHandle(STD_ERROR_HANDLE, nul.into_raw_handle() as isize);
            }
        }
        let stdin_h = GetStdHandle(STD_INPUT_HANDLE);
        if stdin_h == 0 || stdin_h == -1 {
            if let Ok(nul) = OpenOptions::new().read(true).open("NUL") {
                SetStdHandle(STD_INPUT_HANDLE, nul.into_raw_handle() as isize);
            }
        }
    }
}

#[cfg(windows)]
fn resolve_portable_webview2_dir() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let exe_dir = exe.parent()?;
    for sub in ["WebView2Runtime", "webview2"] {
        let candidate = exe_dir.join(sub);
        if candidate.join("msedgewebview2.exe").is_file() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(windows)]
fn is_system_webview2_installed() -> bool {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    use winreg::RegKey;

    if let Ok(env_dir) = std::env::var("WEBVIEW2_BROWSER_EXECUTABLE_FOLDER") {
        if let Ok(file) = std::fs::File::open(std::path::Path::new(&env_dir).join("msedgewebview2.exe")) {
            drop(file);
            return true;
        }
    }

    // 1. 物理检查系统标准 EdgeWebView 应用目录及用户局部目录中的有效可读二进制
    for env_key in ["ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"] {
        if let Ok(base) = std::env::var(env_key) {
            let app_dir = std::path::Path::new(&base)
                .join("Microsoft")
                .join("EdgeWebView")
                .join("Application");
            if app_dir.is_dir() {
                if let Ok(entries) = std::fs::read_dir(&app_dir) {
                    for entry in entries.flatten() {
                        let exe_candidate = entry.path().join("msedgewebview2.exe");
                        if exe_candidate.is_file() {
                            // 关键防御：必须能够真实 open 读取，杜绝因 Windows ACL 跨用户隔离导致的假阳性
                            if let Ok(f) = std::fs::File::open(&exe_candidate) {
                                drop(f);
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. 检查注册表指向的具体路径是否真实存在且当前用户具备访问权限
    const CLIENT_GUID: &str = "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}";
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let keys = [
        (&hklm, format!(r"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{}", CLIENT_GUID)),
        (&hklm, format!(r"SOFTWARE\Microsoft\EdgeUpdate\Clients\{}", CLIENT_GUID)),
        (&hkcu, format!(r"SOFTWARE\Microsoft\EdgeUpdate\Clients\{}", CLIENT_GUID)),
    ];

    for (root, path) in keys {
        if let Ok(subkey) = root.open_subkey(path) {
            if let Ok(pv) = subkey.get_value::<String, _>("pv") {
                let trimmed = pv.trim();
                if !trimmed.is_empty() && trimmed != "0.0.0.0" {
                    if let Ok(loc) = subkey.get_value::<String, _>("location") {
                        let loc_path = std::path::Path::new(&loc);
                        if let Ok(f) = std::fs::File::open(loc_path.join("msedgewebview2.exe")) {
                            drop(f);
                            return true;
                        }
                    }
                }
            }
        }
    }

    false
}

#[cfg(windows)]
fn ensure_windows_webview2_ready() -> bool {
    if let Some(portable_dir) = resolve_portable_webview2_dir() {
        // SAFETY: 在启动任意多线程或 WebView2 Loader 之前设置进程级运行时目录
        unsafe {
            std::env::set_var("WEBVIEW2_BROWSER_EXECUTABLE_FOLDER", &portable_dir);
        }
        return true;
    }

    if is_system_webview2_installed() {
        return true;
    }

    // 检查程序同级目录是否已备有官方微型安装器 MicrosoftEdgeWebview2Setup.exe
    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            let local_installer = exe_dir.join("MicrosoftEdgeWebview2Setup.exe");
            if local_installer.is_file() {
                let _ = std::process::Command::new(local_installer).spawn();
                return false;
            }
        }
    }

    use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, IDYES, MB_ICONWARNING, MB_YESNO};
    let title: Vec<u16> = "Omni-Probe 运行环境检测提示 (WebView2 Runtime 缺失)\0".encode_utf16().collect();
    let msg_str = concat!(
        "检测到当前系统或当前 Windows 登录账户未就绪 Microsoft Edge WebView2 运行时。\n\n",
        "【故障根因】\n",
        "1. 系统为精简版 Windows 11 / LTSC，Edge 组件与运行时被剥离；\n",
        "2. WebView2 曾仅在其他管理员账户下以 Per-User 方式安装，当前账户因 Windows ACL 隔离无法访问。\n\n",
        "【推荐解决方案】\n",
        "方案 1 (推荐)：下载官方安装包后，右键选择「以管理员身份运行」，确保安装为全系统 (All Users) 全局运行时；\n",
        "方案 2 (纯绿色免装)：下载微软 WebView2 Fixed Version，解压至本程序同级 `WebView2Runtime\\` 目录直接双击即可启动；\n",
        "方案 3：点击「是(Y)」立即跳转微软官网下载 WebView2 Runtime 引导程序。\n\n",
        "是否立即打开浏览器前往微软官网下载？\0"
    );
    let body: Vec<u16> = msg_str.encode_utf16().collect();
    let choice = unsafe { MessageBoxW(std::ptr::null_mut(), body.as_ptr(), title.as_ptr(), MB_YESNO | MB_ICONWARNING) };
    if choice == IDYES {
        let _ = std::process::Command::new("cmd")
            .args(["/c", "start", "", "https://developer.microsoft.com/en-us/microsoft-edge/webview2/"])
            .spawn();
    }
    false
}

fn main() {
    #[cfg(windows)]
    {
        init_windows_gui_stdio();
        if !ensure_windows_webview2_ready() {
            std::process::exit(1);
        }
    }

    omni_probe_tauri_lib::instance_guard::setup_panic_hook();
    omni_probe_tauri_lib::instance_guard::cleanup_stale_webview_locks();
    omni_probe_tauri_lib::run();
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    #[test]
    fn test_webview2_probe_executes_without_panic() {
        // 本开发机环境下执行探测应正常返回布尔结果且不发生崩溃
        let _ = super::resolve_portable_webview2_dir();
        let _ = super::is_system_webview2_installed();
    }
}
