// ============================================================
// 工业级单实例互斥守卫与崩溃可观测性诊断子系统 (Windows/Universal)
// 职责：
// 1. Windows 原生命名互斥体 (Named Mutex) 防多实例竞态与 EBWebView 锁死崩溃
// 2. 重复启动时精准呼出并还原已有探针界面 (BringToFront)
// 3. 致命 panic 工业级审计追踪与 crash.log 自动落盘
// 4. EBWebView 孤立临时文件自愈清理
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

/// 确保全局仅运行单一探针实例 (Windows Named Mutex)
/// 如果检测到已有实例在运行且存在正常可见窗口，则呼起已有窗口并让当前进程安全退出 (exit 0)
/// 如果检测到互斥体已被创建但并未发现任何可见图形窗口（历史残留僵尸死锁），则执行工业自愈接管，继续启动
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
            let handle = CreateMutexW(std::ptr::null(), 0, mutex_name.as_ptr());
            if handle.is_null() {
                eprintln!("[INSTANCE] ⚠️ 无法创建命名互斥锁，跳过单实例校验");
                return;
            }

            if GetLastError() == ERROR_ALREADY_EXISTS {
                let current_pid = GetCurrentProcessId();
                let mut ctx = EnumCtx {
                    found_visible_window: false,
                    current_pid,
                };

                unsafe extern "system" fn enum_windows_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
                    let ctx_ptr = lparam as *mut EnumCtx;
                    let mut win_pid = 0u32;
                    GetWindowThreadProcessId(hwnd, &mut win_pid);

                    // 排除当前正在启动的进程自身
                    if win_pid != (*ctx_ptr).current_pid {
                        let mut buf = [0u16; 512];
                        let len = GetWindowTextW(hwnd, buf.as_mut_ptr(), 512);
                        if len > 0 {
                            let title = String::from_utf16_lossy(&buf[..len as usize]);
                            if title.contains("Omni-Probe") && IsWindowVisible(hwnd) != 0 {
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
                    eprintln!("[INSTANCE] ℹ️ 检测到已运行的 Omni-Probe 探针前台图形窗口，已将其激活还原并退出新启动进程");
                    std::process::exit(0);
                } else {
                    eprintln!("[INSTANCE] ⚠️ 检测到互斥体存在但未发现有效可见图形窗口（历史异常残留），执行工业级自愈接管，继续正常启动主程序");
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
