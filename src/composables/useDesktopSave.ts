import { invoke } from '@tauri-apps/api/core';
import { t } from '../i18n';
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
  filterName = t('common.exportFileFilter'),
  filterPatterns = '*.txt;*.md;*.json;*.csv;*.py;*.patch',
  title = t('common.saveAsTitle')
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
      notifySuccess(t('common.exportedToDisk'), `${res.path} (${res.bytes_written} ${t('common.bytes') || 'bytes'})`);
    } else if (res.cancelled) {
      notifyInfo(t('common.exportCancelled'), t('common.noFileWritten'));
    }
    return res;
  } catch (e) {
    notifyError(t('common.fileWriteFailed'), String(e));
    return null;
  }
}

export async function pickNativeFilePath(
  title = t('common.selectDiskFile'),
  filterName = t('common.allSupportedFiles'),
  filterPatterns = '*.*'
): Promise<string | null> {
  try {
    return await invoke<string | null>('pick_native_file_dialog_cmd', {
      title,
      filterName,
      filterPatterns,
    });
  } catch (e) {
    notifyError(t('common.fileWriteFailed'), String(e));
    return null;
  }
}

export async function pickNativeFolderPath(title = t('common.selectLocalFolder')): Promise<string | null> {
  try {
    return await invoke<string | null>('pick_native_folder_dialog_cmd', { title });
  } catch (e) {
    notifyError(t('common.openFolderFailed'), String(e));
    return null;
  }
}

export async function revealInDesktopExplorer(path: string): Promise<void> {
  try {
    await invoke<string>('reveal_in_file_manager_cmd', { path });
  } catch (e) {
    notifyError(t('common.openFolderFailed'), String(e));
  }
}
