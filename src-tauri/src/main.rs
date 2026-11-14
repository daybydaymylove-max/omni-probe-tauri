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
fn download_and_launch_webview2_setup() -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;

    let temp_installer = std::env::temp_dir().join("MicrosoftEdgeWebview2Setup.exe");

    // 检查缓存的安装包是否已存在且完整（> 1MB）
    let need_download = match std::fs::metadata(&temp_installer) {
        Ok(meta) => meta.len() < 1_000_000,
        Err(_) => true,
    };

    if need_download {
        let download_url = "https://go.microsoft.com/fwlink/p/?LinkId=2124703";
        let url_wide: Vec<u16> = std::ffi::OsStr::new(download_url)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let dest_wide: Vec<u16> = temp_installer
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut download_ok = false;

        // 1. 优先使用 Win32 urlmon!URLDownloadToFileW 进行原生零依赖安全下载
        unsafe {
            #[link(name = "urlmon")]
            unsafe extern "system" {
                fn URLDownloadToFileW(
                    p_caller: *mut std::ffi::c_void,
                    sz_url: *const u16,
                    sz_file_name: *const u16,
                    dw_reserved: u32,
                    lpfn_cb: *mut std::ffi::c_void,
                ) -> i32;
            }

            let hr = URLDownloadToFileW(
                std::ptr::null_mut(),
                url_wide.as_ptr(),
                dest_wide.as_ptr(),
                0,
                std::ptr::null_mut(),
            );
            if hr == 0 && temp_installer.is_file() {
                download_ok = true;
            }
        }

        // 2. 降级容灾：若 Win32 下载受阻，通过轻量 PowerShell 管道触发下载
        if !download_ok {
            let ps_script = format!(
                "$ProgressPreference = 'SilentlyContinue'; [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; (New-Object System.Net.WebClient).DownloadFile('{}', '{}')",
                download_url,
                temp_installer.display()
            );
            let ps_res = std::process::Command::new("powershell")
                .args(["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", &ps_script])
                .status();

            if ps_res.map(|s| s.success()).unwrap_or(false) && temp_installer.is_file() {
                download_ok = true;
            }
        }

        if !download_ok || !temp_installer.is_file() {
            return Err("下载微软官方 WebView2 安装包失败。可能由于当前网络连接受限。".to_string());
        }
    }

    // 唤起安装向导（带 UAC 管理员提权）
    let file_wide: Vec<u16> = temp_installer
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let verb_runas: Vec<u16> = std::ffi::OsStr::new("runas")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        #[link(name = "shell32")]
        unsafe extern "system" {
            fn ShellExecuteW(
                hwnd: *mut std::ffi::c_void,
                lpOperation: *const u16,
                lpFile: *const u16,
                lpParameters: *const u16,
                lpDirectory: *const u16,
                nShowCmd: i32,
            ) -> usize;
        }
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetLastError() -> u32;
        }

        let res = ShellExecuteW(
            std::ptr::null_mut(),
            verb_runas.as_ptr(),
            file_wide.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1, // SW_SHOWNORMAL
        );

        if res > 32 {
            return Ok(());
        }

        let last_err = GetLastError();
        if last_err == 1223 || res == 5 {
            return Err("用户已取消 Windows 用户账户控制 (UAC) 提权授权，安装未启动。".to_string());
        }

        if std::process::Command::new(&temp_installer).spawn().is_ok() {
            return Ok(());
        }

        Err(format!(
            "安装包已下载至 {:?}，但启动向导失败。请手动双击该文件运行安装。",
            temp_installer
        ))
    }
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
                use std::os::windows::ffi::OsStrExt;
                let file_wide: Vec<u16> = local_installer
                    .as_os_str()
                    .encode_wide()
                    .chain(std::iter::once(0))
                    .collect();
                let verb_runas: Vec<u16> = std::ffi::OsStr::new("runas")
                    .encode_wide()
                    .chain(std::iter::once(0))
                    .collect();

                unsafe {
                    #[link(name = "shell32")]
                    unsafe extern "system" {
                        fn ShellExecuteW(
                            hwnd: *mut std::ffi::c_void,
                            lpOperation: *const u16,
                            lpFile: *const u16,
                            lpParameters: *const u16,
                            lpDirectory: *const u16,
                            nShowCmd: i32,
                        ) -> usize;
                    }
                    let res = ShellExecuteW(
                        std::ptr::null_mut(),
                        verb_runas.as_ptr(),
                        file_wide.as_ptr(),
                        std::ptr::null(),
                        std::ptr::null(),
                        1,
                    );
                    if res <= 32 {
                        let _ = std::process::Command::new(local_installer).spawn();
                    }
                }
                return false;
            }
        }
    }

    use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, IDYES, MB_ICONWARNING, MB_ICONERROR, MB_YESNO};
    let title: Vec<u16> = "Omni-Probe 运行环境检测提示 (WebView2 Runtime 缺失)\0".encode_utf16().collect();
    let msg_str = concat!(
        "检测到当前系统或当前 Windows 登录账户未就绪 Microsoft Edge WebView2 运行时。\n\n",
        "【故障根因】\n",
        "1. 系统为精简版 Windows 11 / LTSC，Edge 组件与运行时被精简剥离；\n",
        "2. WebView2 曾仅在其他管理员账户下以 Per-User 方式安装，当前账户因 Windows ACL 隔离无法访问。\n\n",
        "【一键自动装配】\n",
        "点击「是(Y)」：系统将立即自动从微软官方直链下载 WebView2 安装向导 (约 1.8MB) 并直接启动安装；\n",
        "点击「否(N)」：取消并退出。\n\n",
        "是否立即自动下载并安装 Microsoft Edge WebView2？\0"
    );
    let body: Vec<u16> = msg_str.encode_utf16().collect();
    let choice = unsafe { MessageBoxW(std::ptr::null_mut(), body.as_ptr(), title.as_ptr(), MB_YESNO | MB_ICONWARNING) };
    if choice == IDYES {
        if let Err(err_msg) = download_and_launch_webview2_setup() {
            // 若自动下载或启动向导受阻，弹出友好提示并提供官网打开选项
            let fail_title: Vec<u16> = "Omni-Probe 运行时安装提示\0".encode_utf16().collect();
            let fail_msg = format!(
                "{}\n\n是否打开默认浏览器前往微软官网手动下载？\0",
                err_msg
            );
            let fail_body: Vec<u16> = fail_msg.encode_utf16().collect();
            let fail_choice = unsafe {
                MessageBoxW(
                    std::ptr::null_mut(),
                    fail_body.as_ptr(),
                    fail_title.as_ptr(),
                    MB_YESNO | MB_ICONERROR,
                )
            };
            if fail_choice == IDYES {
                use std::os::windows::ffi::OsStrExt;
                let url_wide: Vec<u16> = std::ffi::OsStr::new("https://developer.microsoft.com/en-us/microsoft-edge/webview2/")
                    .encode_wide()
                    .chain(std::iter::once(0))
                    .collect();
                let verb_open: Vec<u16> = std::ffi::OsStr::new("open")
                    .encode_wide()
                    .chain(std::iter::once(0))
                    .collect();
                unsafe {
                    #[link(name = "shell32")]
                    unsafe extern "system" {
                        fn ShellExecuteW(
                            hwnd: *mut std::ffi::c_void,
                            lpOperation: *const u16,
                            lpFile: *const u16,
                            lpParameters: *const u16,
                            lpDirectory: *const u16,
                            nShowCmd: i32,
                        ) -> usize;
                    }
                    ShellExecuteW(
                        std::ptr::null_mut(),
                        verb_open.as_ptr(),
                        url_wide.as_ptr(),
                        std::ptr::null(),
                        std::ptr::null(),
                        1,
                    );
                }
            }
        }
    }
    false
}

#[cfg(target_os = "linux")]
fn detect_linux_webkit_library() -> Option<String> {
    let candidates = [
        "/usr/lib/x86_64-linux-gnu/libwebkit2gtk-4.1.so.0",
        "/usr/lib/aarch64-linux-gnu/libwebkit2gtk-4.1.so.0",
        "/usr/lib/loongarch64-linux-gnu/libwebkit2gtk-4.1.so.0",
        "/usr/lib64/libwebkit2gtk-4.1.so.0",
        "/usr/lib/libwebkit2gtk-4.1.so.0",
        "/usr/lib/x86_64-linux-gnu/libwebkit2gtk-4.0.so.37",
        "/usr/lib/aarch64-linux-gnu/libwebkit2gtk-4.0.so.37",
        "/usr/lib/loongarch64-linux-gnu/libwebkit2gtk-4.0.so.37",
        "/usr/lib64/libwebkit2gtk-4.0.so.37",
        "/usr/lib/libwebkit2gtk-4.0.so.37",
    ];
    for p in candidates {
        if std::path::Path::new(p).exists() {
            return Some(p.to_string());
        }
    }

    if let Ok(out) = std::process::Command::new("ldconfig").arg("-p").output() {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            if line.contains("libwebkit2gtk-4.1.so") || line.contains("libwebkit2gtk-4.0.so") {
                if let Some(path_part) = line.split("=>").nth(1) {
                    return Some(path_part.trim().to_string());
                }
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn ensure_linux_webkit_ready() -> bool {
    if let Some(_lib_path) = detect_linux_webkit_library() {
        return true;
    }

    let os_release = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let distro_id = os_release
        .lines()
        .find(|l| l.starts_with("ID="))
        .map(|l| l.trim_start_matches("ID=").trim_matches('"').to_lowercase())
        .unwrap_or_else(|| "unknown".to_string());

    let (distro_name, install_cmd) = match distro_id.as_str() {
        "uos" | "deepin" => (
            "统信 UOS / Deepin",
            "sudo apt-get update && sudo apt-get install -y libwebkit2gtk-4.1-0 libgtk-3-0",
        ),
        "kylin" => (
            "银河麒麟 Kylin Linux",
            "sudo yum install -y webkit2gtk4.1 || sudo apt-get install -y libwebkit2gtk-4.1-0",
        ),
        "openeuler" => (
            "openEuler 欧拉操作系统",
            "sudo dnf install -y webkit2gtk4.1 gtk3",
        ),
        "ubuntu" | "debian" => (
            "Ubuntu / Debian",
            "sudo apt-get update && sudo apt-get install -y libwebkit2gtk-4.1-0 libgtk-3-0",
        ),
        "fedora" | "rhel" | "centos" | "rocky" | "alma" => (
            "Fedora / RHEL / CentOS",
            "sudo dnf install -y webkit2gtk4.1 gtk3",
        ),
        "arch" | "manjaro" => (
            "Arch Linux / Manjaro",
            "sudo pacman -S webkit2gtk-4.1 gtk3",
        ),
        _ => (
            "通用 Linux 平台",
            "请通过系统包管理器安装 WebKit2GTK 4.1 共享库 (例如: apt install libwebkit2gtk-4.1-0 / dnf install webkit2gtk4.1)",
        ),
    };

    let warn_banner = format!(
        "\n================================================================================\n\
         [Omni-Probe 运行时依赖缺失提示 - WebKit2GTK Not Found]\n\
         当前检测到系统未就绪 WebKit2GTK 4.1 渲染引擎共享库，桌面图形界面无法正常初始化。\n\
         --------------------------------------------------------------------------------\n\
         操作系统识别: {}\n\
         推荐一键安装命令:\n\
           {}\n\
         ================================================================================\n",
        distro_name, install_cmd
    );
    eprintln!("{}", warn_banner);

    let has_display = std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some();
    if has_display {
        let msg = format!(
            "Omni-Probe 启动失败：系统缺少 WebKit2GTK 渲染运行时。\n\n检测到当前发行版: {}\n请在终端执行以下命令进行安装：\n\n{}",
            distro_name, install_cmd
        );
        let zenity_res = std::process::Command::new("zenity")
            .args(["--warning", "--title=Omni-Probe 运行环境提示", "--text", &msg, "--width=480"])
            .spawn();
        if zenity_res.is_err() {
            let _ = std::process::Command::new("kdialog")
                .args(["--title", "Omni-Probe 运行环境提示", "--sorry", &msg])
                .spawn();
        }
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

    #[cfg(target_os = "linux")]
    {
        if !ensure_linux_webkit_ready() {
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

    #[cfg(target_os = "linux")]
    #[test]
    fn test_linux_webkit_probe_executes_without_panic() {
        let _ = super::detect_linux_webkit_library();
    }
}
