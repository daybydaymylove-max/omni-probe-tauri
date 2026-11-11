<template>
  <Teleport to="body">
    <Transition name="splash-fade">
      <div
        v-if="currentDialog"
        class="fixed inset-0 z-[10000] ui-modal-backdrop flex items-center justify-center p-4"
        role="dialog"
        aria-modal="true"
        :aria-labelledby="`sheet-title-${currentDialog.id}`"
        @mousedown.self="cancelActiveDialog"
      >
        <div class="ui-modal-surface w-full max-w-[420px] p-5 flex flex-col gap-4 select-none">
          <span class="lens-edge-lip" aria-hidden="true"></span>
          <div class="flex items-start gap-3">
            <div
              class="w-9 h-9 rounded-[10px] flex items-center justify-center shrink-0"
              :style="{
                background: currentDialog.danger ? 'var(--accent-red-soft)' : 'var(--accent-primary-soft)',
                color: currentDialog.danger ? 'var(--accent-red)' : 'var(--accent-primary-text)',
              }"
            >
              <AppIcon :name="currentDialog.danger ? 'alert' : 'info'" :size="18" />
            </div>
            <div class="min-w-0 flex-1">
              <h3
                :id="`sheet-title-${currentDialog.id}`"
                class="text-[14px] font-semibold text-[var(--text-primary)] leading-snug"
              >
                {{ currentDialog.title }}
              </h3>
              <p class="text-[12px] text-[var(--text-secondary)] mt-1 leading-relaxed ui-selectable whitespace-pre-wrap">
                {{ currentDialog.message }}
              </p>
            </div>
          </div>

          <div v-if="currentDialog.mode === 'prompt'" class="flex flex-col gap-1.5">
            <input
              ref="promptInputRef"
              v-model="currentDialog.inputValue"
              type="text"
              :placeholder="currentDialog.placeholder"
              class="ui-input text-[13px]"
              @input="currentDialog.validationError = ''"
              @keydown.enter.prevent="submitActiveDialog"
            />
            <span v-if="currentDialog.validationError" class="text-[11px] text-[var(--accent-red)] font-medium">
              {{ currentDialog.validationError }}
            </span>
          </div>

          <div class="flex items-center justify-end gap-2.5 pt-1">
            <button
              ref="cancelBtnRef"
              type="button"
              class="ui-btn-secondary"
              @click="cancelActiveDialog"
            >
              {{ currentDialog.cancelText || '取消' }}
            </button>
            <button
              ref="confirmBtnRef"
              type="button"
              :class="currentDialog.danger ? 'ui-btn-danger' : 'ui-btn-primary'"
              @click="submitActiveDialog"
            >
              {{ currentDialog.confirmText || '确定' }}
            </button>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
import { watch, nextTick, onMounted, onUnmounted, ref } from 'vue';
import { useConfirmDialogState } from '../composables/useConfirmDialog';
import AppIcon from './AppIcon.vue';

const { currentDialog, submitActiveDialog, cancelActiveDialog } = useConfirmDialogState();
const promptInputRef = ref<HTMLInputElement | null>(null);
const cancelBtnRef = ref<HTMLButtonElement | null>(null);
const confirmBtnRef = ref<HTMLButtonElement | null>(null);

watch(currentDialog, async (dlg) => {
  if (!dlg) return;
  await nextTick();
  if (dlg.mode === 'prompt' && promptInputRef.value) {
    promptInputRef.value.focus();
    promptInputRef.value.select();
  } else if (dlg.danger && cancelBtnRef.value) {
    // 危险操作默认焦点落于取消按钮，遵循 macOS 防误删规范
    cancelBtnRef.value.focus();
  } else if (confirmBtnRef.value) {
    confirmBtnRef.value.focus();
  }
});

function handleKeydown(e: KeyboardEvent) {
  if (!currentDialog.value) return;
  if (e.key === 'Escape') {
    e.preventDefault();
    cancelActiveDialog();
  }
}

onMounted(() => window.addEventListener('keydown', handleKeydown));
onUnmounted(() => window.removeEventListener('keydown', handleKeydown));
</script>
