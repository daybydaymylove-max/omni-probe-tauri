// ============================================================
// 工业级单实例互斥守卫与崩溃可观测性诊断子系统 (Windows/Universal)
// 职责：
// 1. Windows 原生命名互斥体 (Named Mutex) 防多实例竞态与 EBWebView 锁死崩溃
// 2. 重复启动时精准识别同名主程序窗口并呼出还原 (BringToFront)，杜绝按标题误判外部软件 (如 VS Code/终端)
// 3. 自愈回收孤立无界面的历史残留幽灵进程 (Ghost Process)，清理文件锁与端口冲突
// 4. 致命 panic 工业级审计追踪与 crash.log 自动落盘
// 5. EBWebView 孤立临时文件自愈清理
// ============================================================

#[cfg(windows)]
use std::sync::Mutex;
#[cfg(windows)]
use once_cell::sync::Lazy;

#[cfg(windows)]
static MUTEX_HANDLE: Lazy<Mutex<Option<usize>>> = Lazy::new(|| Mutex::new(None));

/// 初始化全局未捕获异常崩溃诊断 Hook
pub fn setup_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let timestamp = chrono::Local::now().to_rfc3339();
        let payload = if let Some(s) = info.payload().downcast_ref::<&str>() {
            (*s).to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "Unknown panic payload".to_string()
        };
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown location".to_string());

        let crash_msg = format!(
            "==================== OMNI-PROBE CRASH AUDIT REPORT ====================\n\
             时间: {}\n\
             致命异常: {}\n\
             代码位置: {}\n\
             =======================================================================\n",
            timestamp, payload, location
        );
        eprintln!("{}", crash_msg);

        // 写入当前工作目录
        let _ = std::fs::write("crash.log", &crash_msg);

        // 写入 LocalAppData 目录
        if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
            let dir = std::path::PathBuf::from(local_appdata).join("com.chinacpu.omni-probe-tauri");
            let _ = std::fs::create_dir_all(&dir);
            let _ = std::fs::write(dir.join("crash.log"), &crash_msg);
        }

        default_hook(info);
    }));
}

/// 检查指定 PID 的进程镜像名称是否为 omni-probe-tauri.exe
#[cfg(windows)]
unsafe fn is_omni_probe_process(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION};

    let h_proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
    if h_proc.is_null() {
        return false;
    }

    let mut buf = [0u16; 1024];
    let mut size = buf.len() as u32;
    let ok = QueryFullProcessImageNameW(h_proc, 0, buf.as_mut_ptr(), &mut size);
    CloseHandle(h_proc);

    if ok != 0 && size > 0 {
        let full_path = String::from_utf16_lossy(&buf[..size as usize]).to_lowercase();
        return full_path.ends_with("omni-probe-tauri.exe");
    }
    false
}

/// 工业级自愈：终止无界面残留的孤立 omni-probe-tauri 幽灵进程，释放端口与 EBWebView 锁
#[cfg(windows)]
pub fn terminate_stale_ghost_instances(current_pid: u32) {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return;
        }

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            cntUsage: 0,
            th32ProcessID: 0,
            th32DefaultHeapID: 0,
            th32ModuleID: 0,
            cntThreads: 0,
            th32ParentProcessID: 0,
            pcPriClassBase: 0,
            dwFlags: 0,
            szExeFile: [0u16; 260],
        };

        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let pid = entry.th32ProcessID;
                if pid != current_pid && pid > 4 {
                    let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
                    let exe_name = String::from_utf16_lossy(&entry.szExeFile[..len]).to_lowercase();

                    if exe_name == "omni-probe-tauri.exe" {
                        eprintln!("[INSTANCE] ⚡ 发现历史残留孤立幽灵进程 (PID: {})，执行自愈强制终结...", pid);
                        let h_proc = OpenProcess(PROCESS_TERMINATE, 0, pid);
                        if !h_proc.is_null() {
                            let _ = TerminateProcess(h_proc, 1);
                            CloseHandle(h_proc);
                            eprintln!("[INSTANCE] ✓ 成功终止残留进程 PID: {}，底层资源与端口已释放", pid);
                        }
                    }
                }

                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
    }
}

/// 确保全局仅运行单一探针实例 (Windows Named Mutex)
/// 如果检测到已有实例在运行且存在正常可见窗口，则呼起已有窗口并让当前进程安全退出 (exit 0)
/// 如果检测到互斥体已被创建但并未发现任何可见图形窗口（历史异常残留），则终结幽灵进程并执行自愈接管
pub fn ensure_single_instance() {
    #[cfg(windows)]
    {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError, HWND, LPARAM, BOOL, TRUE};
        use windows_sys::Win32::System::Threading::{CreateMutexW, GetCurrentProcessId};
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            EnumWindows, GetWindowTextW, GetWindowThreadProcessId, IsWindowVisible,
            SetForegroundWindow, ShowWindow, SW_RESTORE,
        };

        struct EnumCtx {
            found_visible_window: bool,
            current_pid: u32,
        }

        let mut mutex_name: Vec<u16> = OsStr::new("Local\\OmniProbeTauri_SingleInstance_Mutex")
            .encode_wide()
            .collect();
        mutex_name.push(0);

        unsafe {
            let current_pid = GetCurrentProcessId();
            let handle = CreateMutexW(std::ptr::null(), 0, mutex_name.as_ptr());
            if handle.is_null() {
                eprintln!("[INSTANCE] ⚠️ 无法创建命名互斥锁，跳过单实例校验");
                return;
            }

            if GetLastError() == ERROR_ALREADY_EXISTS {
                let mut ctx = EnumCtx {
                    found_visible_window: false,
                    current_pid,
                };

                unsafe extern "system" fn enum_windows_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
                    let ctx_ptr = lparam as *mut EnumCtx;
                    let mut win_pid = 0u32;
                    GetWindowThreadProcessId(hwnd, &mut win_pid);

                    // 排除当前正在启动的进程自身
                    if win_pid != (*ctx_ptr).current_pid && win_pid > 4 {
                        // 1. 严格校验所属进程是否确实为 omni-probe-tauri.exe（杜绝误判 VSCode/终端/浏览器）
                        if is_omni_probe_process(win_pid) && IsWindowVisible(hwnd) != 0 {
                            let mut buf = [0u16; 512];
                            let len = GetWindowTextW(hwnd, buf.as_mut_ptr(), 512);
                            let title = if len > 0 {
                                String::from_utf16_lossy(&buf[..len as usize])
                            } else {
                                String::new()
                            };

                            // 2. 确认拥有有效窗口标题或真实探针主界面
                            if title.contains("Omni-Probe") || title.contains("网络探针") || len == 0 {
                                ShowWindow(hwnd, SW_RESTORE);
                                SetForegroundWindow(hwnd);
                                (*ctx_ptr).found_visible_window = true;
                                return 0; // 找到真实前台主窗口后终止遍历
                            }
                        }
                    }
                    TRUE
                }

                EnumWindows(Some(enum_windows_proc), &mut ctx as *mut EnumCtx as LPARAM);

                if ctx.found_visible_window {
                    eprintln!("[INSTANCE] ℹ️ 检测到已运行的 Omni-Probe 探针真实前台图形窗口，已将其激活还原并退出新启动进程");
                    std::process::exit(0);
                } else {
                    eprintln!("[INSTANCE] ⚠️ 检测到互斥体存在但未发现有效图形窗口（孤立幽灵残留），启动自愈清理回收流程...");
                    // 彻底清除系统中遗留的无窗口孤立旧进程
                    terminate_stale_ghost_instances(current_pid);
                    cleanup_stale_webview_locks();
                    // 等待 150ms 供操作系统回收句柄
                    std::thread::sleep(std::time::Duration::from_millis(150));
                }
            }

            if let Ok(mut lock) = MUTEX_HANDLE.lock() {
                *lock = Some(handle as usize);
            }
        }
    }
}

/// 自愈清理历史由于断电或强制杀掉进程遗留的孤立 EBWebView 锁
pub fn cleanup_stale_webview_locks() {
    if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
        let eb_dir = std::path::PathBuf::from(local_appdata)
            .join("com.chinacpu.omni-probe-tauri")
            .join("EBWebView");
        if eb_dir.exists() {
            // 清理 EBWebView 根目录下可能遗留的单进程锁文件
            let candidate_locks = ["EBWebView.lock", "lockfile"];
            for lock_name in &candidate_locks {
                let lock_file = eb_dir.join(lock_name);
                if lock_file.exists() {
                    let _ = std::fs::remove_file(lock_file);
                }
            }
        }
    }
}
