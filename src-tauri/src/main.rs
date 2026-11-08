#![windows_subsystem = "windows"]

#[cfg(windows)]
fn init_windows_gui_stdio() {
    use std::fs::OpenOptions;
    use std::os::windows::io::IntoRawHandle;

    extern "system" {
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

fn main() {
    #[cfg(windows)]
    init_windows_gui_stdio();

    omni_probe_tauri_lib::instance_guard::setup_panic_hook();
    omni_probe_tauri_lib::instance_guard::cleanup_stale_webview_locks();
    omni_probe_tauri_lib::run();
}
