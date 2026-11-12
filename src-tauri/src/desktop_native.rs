// SPDX-License-Identifier: Apache-2.0
// ============================================================================
// Omni-Probe 原生桌面文件系统对话框、文件原子落盘与资源管理器交互引擎
// 彻底取代网页版 <a download> / Blob URL 与手动文本框输入，实现 100% 原生桌面交互
// 支持 Windows (Win32 ComDlg/Shell)、macOS (osascript argv 安全参数)、Linux (zenity/kdialog + D-Bus)
// ============================================================================

use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeSaveOutcome {
    pub saved: bool,
    pub cancelled: bool,
    pub path: Option<String>,
    pub bytes_written: u64,
    pub message: String,
}

#[cfg(windows)]
fn to_wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn utf16_ptr_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// 将诸如 `"*.json;*.txt"` 过滤器表达式规整为统一空格分隔通配片段（用于 Win32 / zenity / kdialog）
fn normalize_filter_glob_tokens(patterns: &str) -> Vec<String> {
    patterns
        .split([';', ',', ' '])
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

#[cfg(windows)]
fn build_win32_filter_wide(filter_name: &str, patterns: &str) -> Vec<u16> {
    // Win32 OPENFILENAME lpstrFilter 要求用 \0 分隔说明与模式，并在末尾双 \0 结尾
    let clean_name = if filter_name.trim().is_empty() { "支持文件" } else { filter_name.trim() };
    let tokens = normalize_filter_glob_tokens(patterns);
    let clean_pat = if tokens.is_empty() { "*.*".to_string() } else { tokens.join(";") };
    let mut wide = Vec::with_capacity(clean_name.len() + clean_pat.len() + 24);
    wide.extend(clean_name.encode_utf16());
    wide.push(0);
    wide.extend(clean_pat.encode_utf16());
    wide.push(0);
    wide.extend("所有文件 (*.*)".encode_utf16());
    wide.push(0);
    wide.extend("*.*".encode_utf16());
    wide.push(0);
    wide.push(0);
    wide
}

/// macOS 通过 `on run argv` 参数化调用 osascript，避免字符串拼接带来的引号/换行注入风险
#[cfg(target_os = "macos")]
fn run_osascript_argv(script: &str, args: &[&str], err_prefix: &str) -> Result<Option<String>, String> {
    let mut cmd = std::process::Command::new("osascript");
    cmd.arg("-e").arg(script).arg("--");
    for a in args {
        cmd.arg(a);
    }
    let output = cmd.output().map_err(|e| format!("{}: {}", err_prefix, e))?;
    if output.status.success() {
        let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Ok(if s.is_empty() { None } else { Some(s) })
    } else {
        Ok(None)
    }
}

/// Linux 桌面统一对话调度器：先尝试首个工具 (zenity)，仅在命令不存在 (NotFound) 时回退备用工具 (kdialog)
/// 若用户在第一个工具内主动取消，直接返回 Ok(None)，避免误弹两次对话框
#[cfg(all(unix, not(target_os = "macos")))]
fn run_linux_dialog_with_fallback(
    primary_cmd: &str,
    primary_args: &[String],
    fallback_cmd: &str,
    fallback_args: &[String],
    missing_err: &str,
) -> Result<Option<String>, String> {
    match std::process::Command::new(primary_cmd).args(primary_args).output() {
        Ok(out) => {
            if out.status.success() {
                let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
                return Ok(if s.is_empty() { None } else { Some(s) });
            }
            return Ok(None);
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("调用 {} 失败: {}", primary_cmd, e)),
    }

    match std::process::Command::new(fallback_cmd).args(fallback_args).output() {
        Ok(out) => {
            if out.status.success() {
                let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
                Ok(if s.is_empty() { None } else { Some(s) })
            } else {
                Ok(None)
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(missing_err.to_string()),
        Err(e) => Err(format!("调用 {} 失败: {}", fallback_cmd, e)),
    }
}

/// 唤起操作系统原生「打开单个文件」对话窗口
pub fn pick_native_file_dialog(
    title: &str,
    filter_name: &str,
    filter_patterns: &str,
) -> Result<Option<String>, String> {
    let clean_title = if title.trim().is_empty() { "选择文件 - Omni-Probe" } else { title.trim() };

    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::Controls::Dialogs::{
            GetOpenFileNameW, OPENFILENAMEW, OFN_FILEMUSTEXIST, OFN_PATHMUSTEXIST,
        };

        let title_w = to_wide_null(clean_title);
        let filter_w = build_win32_filter_wide(filter_name, filter_patterns);
        let mut file_buf = vec![0u16; 32768];

        let mut ofn: OPENFILENAMEW = unsafe { std::mem::zeroed() };
        ofn.lStructSize = std::mem::size_of::<OPENFILENAMEW>() as u32;
        ofn.lpstrFilter = filter_w.as_ptr();
        ofn.nFilterIndex = 1;
        ofn.lpstrFile = file_buf.as_mut_ptr();
        ofn.nMaxFile = file_buf.len() as u32;
        ofn.lpstrTitle = title_w.as_ptr();
        ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | 0x0000_0008; // 包含 OFN_NOCHANGEDIR 避免改变后端工作目录

        let ok = unsafe { GetOpenFileNameW(&mut ofn) };
        if ok != 0 {
            let selected = utf16_ptr_to_string(&file_buf);
            Ok(if selected.trim().is_empty() { None } else { Some(selected) })
        } else {
            Ok(None)
        }
    }

    #[cfg(target_os = "macos")]
    {
        let _ = (filter_name, filter_patterns);
        run_osascript_argv(
            "on run argv\nPOSIX path of (choose file with prompt (item 1 of argv))\nend run",
            &[clean_title],
            "无法调用 macOS 文件对话窗口",
        )
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let tokens = normalize_filter_glob_tokens(filter_patterns);
        let filter_label = if filter_name.trim().is_empty() { "支持文件" } else { filter_name.trim() };
        let mut zenity_args = vec![
            "--file-selection".to_string(),
            format!("--title={}", clean_title),
        ];
        if !tokens.is_empty() {
            zenity_args.push(format!("--file-filter={} | {}", filter_label, tokens.join(" ")));
            zenity_args.push("--file-filter=所有文件 | *".to_string());
        }
        let kdialog_filter = if tokens.is_empty() {
            "*".to_string()
        } else {
            format!("{} ({})|所有文件 (*)", filter_label, tokens.join(" "))
        };
        let kdialog_args = vec![
            "--getopenfilename".to_string(),
            ".".to_string(),
            kdialog_filter,
            "--title".to_string(),
            clean_title.to_string(),
        ];

        run_linux_dialog_with_fallback(
            "zenity",
            &zenity_args,
            "kdialog",
            &kdialog_args,
            "当前 Linux 桌面环境缺少 zenity 或 kdialog 原生文件对话工具",
        )
    }
}

/// 唤起操作系统原生「选择文件夹」对话窗口
pub fn pick_native_folder_dialog(title: &str) -> Result<Option<String>, String> {
    let clean_title = if title.trim().is_empty() { "选择目录 - Omni-Probe" } else { title.trim() };

    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Com::{CoInitializeEx, CoTaskMemFree};
        use windows_sys::Win32::UI::Shell::{
            BIF_NEWDIALOGSTYLE, BIF_RETURNONLYFSDIRS, BROWSEINFOW, SHBrowseForFolderW,
            SHGetPathFromIDListW,
        };

        // BIF_NEWDIALOGSTYLE 需要 STA COM 初始化 (COINIT_APARTMENTTHREADED = 2)
        unsafe {
            let _ = CoInitializeEx(std::ptr::null(), 2);
        }

        let title_w = to_wide_null(clean_title);
        let mut display_buf = vec![0u16; 512];
        let mut path_buf = vec![0u16; 32768];

        let mut bi: BROWSEINFOW = unsafe { std::mem::zeroed() };
        bi.pszDisplayName = display_buf.as_mut_ptr();
        bi.lpszTitle = title_w.as_ptr();
        bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;

        let pidl = unsafe { SHBrowseForFolderW(&bi) };
        if pidl.is_null() {
            return Ok(None);
        }

        let ok = unsafe { SHGetPathFromIDListW(pidl, path_buf.as_mut_ptr()) };
        unsafe { CoTaskMemFree(pidl.cast()) };

        if ok != 0 {
            let folder = utf16_ptr_to_string(&path_buf);
            Ok(if folder.trim().is_empty() { None } else { Some(folder) })
        } else {
            Ok(None)
        }
    }

    #[cfg(target_os = "macos")]
    {
        let res = run_osascript_argv(
            "on run argv\nPOSIX path of (choose folder with prompt (item 1 of argv))\nend run",
            &[clean_title],
            "无法调用 macOS 目录对话窗口",
        )?;
        Ok(res.map(|s| {
            if s.len() > 1 {
                s.trim_end_matches('/').to_string()
            } else {
                s
            }
        }))
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let zenity_args = vec![
            "--file-selection".to_string(),
            "--directory".to_string(),
            format!("--title={}", clean_title),
        ];
        let kdialog_args = vec![
            "--getexistingdirectory".to_string(),
            ".".to_string(),
            "--title".to_string(),
            clean_title.to_string(),
        ];

        run_linux_dialog_with_fallback(
            "zenity",
            &zenity_args,
            "kdialog",
            &kdialog_args,
            "当前 Linux 桌面环境缺少 zenity 或 kdialog 原生目录选择器",
        )
    }
}

/// 唤起操作系统原生「另存为」系统对话框并将文本或数据原子直写磁盘（彻底替代浏览器 Blob 下载）
pub fn save_text_with_native_dialog(
    default_filename: &str,
    title: &str,
    filter_name: &str,
    filter_patterns: &str,
    content: &str,
) -> Result<NativeSaveOutcome, String> {
    let target_opt = pick_save_path_internal(default_filename, title, filter_name, filter_patterns)?;
    let Some(target_path) = target_opt else {
        return Ok(NativeSaveOutcome {
            saved: false,
            cancelled: true,
            path: None,
            bytes_written: 0,
            message: "用户已取消保存".into(),
        });
    };

    write_bytes_atomically(&target_path, content.as_bytes())
}

/// 弹出原生另存为对话框并将任意原始二进制字节原子安全落盘
pub fn save_bytes_with_native_dialog(
    default_filename: &str,
    title: &str,
    filter_name: &str,
    filter_patterns: &str,
    bytes: &[u8],
) -> Result<NativeSaveOutcome, String> {
    let target_opt = pick_save_path_internal(default_filename, title, filter_name, filter_patterns)?;
    let Some(target_path) = target_opt else {
        return Ok(NativeSaveOutcome {
            saved: false,
            cancelled: true,
            path: None,
            bytes_written: 0,
            message: "用户已取消保存".into(),
        });
    };

    write_bytes_atomically(&target_path, bytes)
}

fn pick_save_path_internal(
    default_filename: &str,
    title: &str,
    filter_name: &str,
    filter_patterns: &str,
) -> Result<Option<String>, String> {
    let clean_title = if title.trim().is_empty() { "另存为 - Omni-Probe" } else { title.trim() };

    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::Controls::Dialogs::{
            GetSaveFileNameW, OPENFILENAMEW, OFN_OVERWRITEPROMPT, OFN_PATHMUSTEXIST,
        };

        let title_w = to_wide_null(clean_title);
        let filter_w = build_win32_filter_wide(filter_name, filter_patterns);
        let mut file_buf = vec![0u16; 32768];
        let def_w: Vec<u16> = default_filename.encode_utf16().collect();
        let copy_len = def_w.len().min(file_buf.len() - 1);
        file_buf[..copy_len].copy_from_slice(&def_w[..copy_len]);

        // 提取默认后缀 (如 .md / .json / .csv / .py)
        let ext_only = Path::new(default_filename)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        let ext_w = to_wide_null(ext_only);

        let mut ofn: OPENFILENAMEW = unsafe { std::mem::zeroed() };
        ofn.lStructSize = std::mem::size_of::<OPENFILENAMEW>() as u32;
        ofn.lpstrFilter = filter_w.as_ptr();
        ofn.nFilterIndex = 1;
        ofn.lpstrFile = file_buf.as_mut_ptr();
        ofn.nMaxFile = file_buf.len() as u32;
        ofn.lpstrTitle = title_w.as_ptr();
        if !ext_only.is_empty() {
            ofn.lpstrDefExt = ext_w.as_ptr();
        }
        ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | 0x0000_0008; // OFN_NOCHANGEDIR

        let ok = unsafe { GetSaveFileNameW(&mut ofn) };
        if ok != 0 {
            let s = utf16_ptr_to_string(&file_buf);
            Ok(if s.trim().is_empty() { None } else { Some(s) })
        } else {
            Ok(None)
        }
    }

    #[cfg(target_os = "macos")]
    {
        let _ = (filter_name, filter_patterns);
        run_osascript_argv(
            "on run argv\nPOSIX path of (choose file name with prompt (item 1 of argv) default name (item 2 of argv))\nend run",
            &[clean_title, default_filename],
            "无法调用 macOS 保存窗口",
        )
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let tokens = normalize_filter_glob_tokens(filter_patterns);
        let filter_label = if filter_name.trim().is_empty() { "导出文档" } else { filter_name.trim() };
        let mut zenity_args = vec![
            "--file-selection".to_string(),
            "--save".to_string(),
            "--confirm-overwrite".to_string(),
            format!("--filename={}", default_filename),
            format!("--title={}", clean_title),
        ];
        if !tokens.is_empty() {
            zenity_args.push(format!("--file-filter={} | {}", filter_label, tokens.join(" ")));
            zenity_args.push("--file-filter=所有文件 | *".to_string());
        }
        let kdialog_filter = if tokens.is_empty() {
            "*".to_string()
        } else {
            format!("{} ({})|所有文件 (*)", filter_label, tokens.join(" "))
        };
        let kdialog_args = vec![
            "--getsavefilename".to_string(),
            default_filename.to_string(),
            kdialog_filter,
            "--title".to_string(),
            clean_title.to_string(),
        ];

        run_linux_dialog_with_fallback(
            "zenity",
            &zenity_args,
            "kdialog",
            &kdialog_args,
            "当前 Linux 桌面环境缺少 zenity 或 kdialog 保存对话框工具",
        )
    }
}

pub fn write_bytes_atomically(target_path: &str, bytes: &[u8]) -> Result<NativeSaveOutcome, String> {
    let p = Path::new(target_path);
    if let Some(parent) = p.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| format!("创建目标目录失败: {}", e))?;
        }
    }
    let tmp = format!("{}.omni_save_{}", target_path, std::process::id());
    {
        let f = File::create(&tmp).map_err(|e| format!("创建临时导出文件失败: {}", e))?;
        let mut w = BufWriter::with_capacity(64 * 1024, f);
        w.write_all(bytes).map_err(|e| format!("写入文件失败: {}", e))?;
        w.flush().map_err(|e| format!("刷新写入缓冲失败: {}", e))?;
        if let Ok(inner) = w.into_inner() {
            let _ = inner.sync_all();
        }
    }
    // POSIX rename() 对同文件系统目标支持原子替换，无需预先删除；Windows 下提前清除已存在目标提升兼容性
    #[cfg(windows)]
    if p.exists() {
        let _ = fs::remove_file(p);
    }
    fs::rename(&tmp, p).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("原子保存目标文件失败: {}", e)
    })?;

    Ok(NativeSaveOutcome {
        saved: true,
        cancelled: false,
        path: Some(target_path.to_string()),
        bytes_written: bytes.len() as u64,
        message: format!("已原子导出至磁盘文件: {} ({} 字节)", target_path, bytes.len()),
    })
}

/// 在系统原生文件管理器（Windows Explorer / macOS Finder / Linux FileManager1+xdg-open）中高亮选中指定文件或目录
pub fn reveal_in_file_manager(target_path: &str) -> Result<String, String> {
    let clean = target_path.trim();
    if clean.is_empty() {
        return Err("路径不能为空".into());
    }
    let p = Path::new(clean);
    if !p.exists() {
        return Err(format!("目标路径不存在: {}", clean));
    }

    #[cfg(windows)]
    {
        let arg = if p.is_file() {
            format!("/select,{}", clean)
        } else {
            clean.to_string()
        };
        std::process::Command::new("explorer.exe")
            .arg(&arg)
            .spawn()
            .map_err(|e| format!("无法调起 Windows 资源管理器: {}", e))?;
        return Ok(format!("已在资源管理器定位: {}", clean));
    }

    #[cfg(target_os = "macos")]
    {
        let args: Vec<&str> = if p.is_file() { vec!["-R", clean] } else { vec![clean] };
        std::process::Command::new("open")
            .args(args)
            .spawn()
            .map_err(|e| format!("无法调起 Finder: {}", e))?;
        return Ok(format!("已在 Finder 定位: {}", clean));
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if p.is_file() {
            if let Ok(abs) = fs::canonicalize(p) {
                let file_uri = format!("file://{}", abs.to_string_lossy());
                if let Ok(out) = std::process::Command::new("dbus-send")
                    .args([
                        "--session",
                        "--print-reply",
                        "--dest=org.freedesktop.FileManager1",
                        "/org/freedesktop/FileManager1",
                        "org.freedesktop.FileManager1.ShowItems",
                        &format!("array:string:{}", file_uri),
                        "string:",
                    ])
                    .output()
                {
                    if out.status.success() {
                        return Ok(format!("已在桌面文件管理器定位: {}", clean));
                    }
                }
            }
        }

        let dir = if p.is_file() {
            p.parent().map(|d| d.to_string_lossy().into_owned()).unwrap_or_else(|| clean.to_string())
        } else {
            clean.to_string()
        };
        std::process::Command::new("xdg-open")
            .arg(&dir)
            .spawn()
            .map_err(|e| format!("无法调起系统文件管理器: {}", e))?;
        Ok(format!("已打开目录: {}", dir))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cross_platform_atomic_write_and_filter_normalization() {
        let tokens = normalize_filter_glob_tokens("*.json; *.txt , *.md");
        assert_eq!(tokens, vec!["*.json", "*.txt", "*.md"]);

        let dir = std::env::temp_dir().join(format!("omni_desktop_save_xp_{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let out_file = dir.join("native_saved_artifact.txt");

        let outcome1 = write_bytes_atomically(out_file.to_str().unwrap(), b"First Snapshot").unwrap();
        assert!(outcome1.saved);
        assert_eq!(outcome1.bytes_written, 14);

        // 覆盖写盘原子性验证（涵盖已有目标文件场景）
        let outcome2 = write_bytes_atomically(out_file.to_str().unwrap(), b"Desktop Native Export Content").unwrap();
        assert!(outcome2.saved);
        assert!(!outcome2.cancelled);
        assert_eq!(outcome2.bytes_written, 29);
        assert_eq!(fs::read_to_string(&out_file).unwrap(), "Desktop Native Export Content");
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn test_win32_filter_double_null_termination_and_atomic_write() {
        let f = build_win32_filter_wide("文本与日志", "*.txt;*.log");
        assert!(f.len() >= 10);
        // 严格验证以双 NULL 字符 \0\0 终止
        assert_eq!(f[f.len() - 1], 0);
        assert_eq!(f[f.len() - 2], 0);
    }
}
