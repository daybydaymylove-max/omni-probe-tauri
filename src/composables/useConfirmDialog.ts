import { ref } from 'vue';
import { t } from '../i18n';

export interface SheetDialogOptions {
  mode: 'confirm' | 'prompt';
  title: string;
  message: string;
  confirmText?: string;
  cancelText?: string;
  danger?: boolean;
  defaultValue?: string;
  placeholder?: string;
  allowEmpty?: boolean;
}

export interface ActiveSheetState extends SheetDialogOptions {
  id: number;
  inputValue: string;
  validationError: string;
  resolve: (value: boolean | string | null) => void;
}

const currentDialog = ref<ActiveSheetState | null>(null);
const queue: ActiveSheetState[] = [];
let dialogSeq = 0;

function presentNext() {
  if (currentDialog.value || queue.length === 0) return;
  currentDialog.value = queue.shift() || null;
}

function enqueueDialog<T extends boolean | string | null>(
  opts: SheetDialogOptions
): Promise<T> {
  return new Promise<T>((resolve) => {
    const item: ActiveSheetState = {
      ...opts,
      id: ++dialogSeq,
      inputValue: opts.defaultValue ?? '',
      validationError: '',
      resolve: (val) => resolve(val as T),
    };
    if (!currentDialog.value) {
      currentDialog.value = item;
    } else {
      queue.push(item);
    }
  });
}

/**
 * Apple Sheet style non-blocking confirmation dialog.
 */
export function uiConfirm(
  message: string,
  options?: {
    title?: string;
    confirmText?: string;
    cancelText?: string;
    danger?: boolean;
  }
): Promise<boolean> {
  return enqueueDialog<boolean>({
    mode: 'confirm',
    title: options?.title || t('common.confirmAction'),
    message,
    confirmText: options?.confirmText || t('common.confirmExecute'),
    cancelText: options?.cancelText || t('common.cancel'),
    danger: options?.danger ?? true,
  });
}

/**
 * Apple Sheet style non-blocking text input dialog.
 */
export function uiPrompt(
  message: string,
  defaultValue = '',
  options?: {
    title?: string;
    confirmText?: string;
    cancelText?: string;
    placeholder?: string;
    allowEmpty?: boolean;
  }
): Promise<string | null> {
  return enqueueDialog<string | null>({
    mode: 'prompt',
    title: options?.title || t('common.inputParam'),
    message,
    defaultValue,
    placeholder: options?.placeholder || t('common.inputPlaceholder'),
    confirmText: options?.confirmText || t('common.ok'),
    cancelText: options?.cancelText || t('common.cancel'),
    allowEmpty: options?.allowEmpty ?? false,
  });
}

export function submitActiveDialog() {
  const dlg = currentDialog.value;
  if (!dlg) return;
  if (dlg.mode === 'prompt') {
    const trimmed = dlg.inputValue.trim();
    if (!dlg.allowEmpty && !trimmed) {
      dlg.validationError = t('common.cannotBeEmpty');
      return;
    }
    const val = dlg.allowEmpty ? dlg.inputValue : trimmed;
    currentDialog.value = null;
    dlg.resolve(val);
    presentNext();
    return;
  }
  currentDialog.value = null;
  dlg.resolve(true);
  presentNext();
}

export function cancelActiveDialog() {
  const dlg = currentDialog.value;
  if (!dlg) return;
  const fallback = dlg.mode === 'confirm' ? false : null;
  currentDialog.value = null;
  dlg.resolve(fallback);
  presentNext();
}

export function useConfirmDialogState() {
  return {
    currentDialog,
    submitActiveDialog,
    cancelActiveDialog,
  };
}
