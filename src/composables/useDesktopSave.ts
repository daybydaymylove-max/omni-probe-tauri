import { invoke } from '@tauri-apps/api/core';
import { notifySuccess, notifyInfo, notifyError } from './useNotification';

export interface NativeSaveOutcome {
  saved: boolean;
  cancelled: boolean;
  path?: string | null;
  bytes_written: number;
  message: string;
}

/**
 * 调用操作系统原生「另存为」系统对话框并由 Rust 原子直写磁盘，彻底摒弃网页 Blob 下载模式
 */
export async function saveTextViaNativeDesktop(
  defaultFilename: string,
  content: string,
  filterName = '导出报告/脚本文件',
  filterPatterns = '*.txt;*.md;*.json;*.csv;*.py;*.patch',
  title = '另存为 - Omni-Probe 原生桌面导出'
): Promise<NativeSaveOutcome | null> {
  try {
    const res = await invoke<NativeSaveOutcome>('save_text_with_native_dialog_cmd', {
      defaultFilename,
      title,
      filterName,
      filterPatterns,
      content,
    });
    if (res.saved && res.path) {
      notifySuccess('已导出至本地磁盘', `${res.path} (${res.bytes_written} 字节)`);
    } else if (res.cancelled) {
      notifyInfo('已取消导出', '未写入任何文件');
    }
    return res;
  } catch (e) {
    notifyError('原生文件写入失败', String(e));
    return null;
  }
}

export async function pickNativeFilePath(
  title = '选择磁盘文件',
  filterName = '所有支持文件',
  filterPatterns = '*.*'
): Promise<string | null> {
  try {
    return await invoke<string | null>('pick_native_file_dialog_cmd', {
      title,
      filterName,
      filterPatterns,
    });
  } catch (e) {
    notifyError('调起系统文件选择框失败', String(e));
    return null;
  }
}

export async function pickNativeFolderPath(title = '选择本地目录'): Promise<string | null> {
  try {
    return await invoke<string | null>('pick_native_folder_dialog_cmd', { title });
  } catch (e) {
    notifyError('调起系统目录选择框失败', String(e));
    return null;
  }
}

export async function revealInDesktopExplorer(path: string): Promise<void> {
  try {
    await invoke<string>('reveal_in_file_manager_cmd', { path });
  } catch (e) {
    notifyError('无法打开系统文件管理器', String(e));
  }
}
