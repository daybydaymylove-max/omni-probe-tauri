<template>
  <div v-if="isOpen" class="ui-modal-backdrop fixed inset-0 z-50 flex items-center justify-center animate-in fade-in duration-150 select-none">
    <div class="ui-modal-surface rounded-3xl w-[680px] max-w-[92vw] max-h-[85vh] flex flex-col overflow-hidden animate-in zoom-in-95 duration-200">
      
      <!-- 1. 弹窗头部 -->
      <div class="ui-nav-glass px-6 py-4 border-b border-(--border-subtle) flex items-center justify-between shrink-0">
        <div class="flex items-center gap-2.5">
          <div class="w-8 h-8 rounded-xl bg-sky-500/12 border border-sky-500/30 flex items-center justify-center text-sky-600 dark:text-sky-400">
            <AppIcon name="sliders" class="w-4 h-4" />
          </div>
          <div>
            <h3 class="text-sm font-bold text-(--text-primary) tracking-wide">侦听列表字段显示长度与列宽调节</h3>
            <p class="text-xs text-(--text-muted)">自由设定各字段显示宽度、显示/隐藏开关，或选用场景预设</p>
          </div>
        </div>
        <button @click="$emit('close')"
          class="ui-btn-secondary w-8 h-8 rounded-xl p-0 flex items-center justify-center cursor-pointer"
          aria-label="关闭弹窗">
          <AppIcon name="close" class="w-4 h-4" />
        </button>
      </div>

      <!-- 2. 快捷预设分段选择 -->
      <div class="px-6 py-3 bg-(--surface-content-alt) border-b border-(--border-subtle) flex flex-wrap items-center justify-between gap-3 shrink-0">
        <span class="text-xs font-bold text-(--text-secondary) shrink-0">快捷场景预设:</span>
        <div class="flex items-center gap-2">
          <button @click="applyPreset('compact')"
            class="ui-btn-secondary px-3 py-1.5 text-xs font-semibold inline-flex items-center gap-1.5 cursor-pointer">
            <AppIcon name="minimize" class="w-3.5 h-3.5" />
            <span>紧凑小屏视图</span>
          </button>
          <button @click="applyPreset('standard')"
            class="ui-btn-secondary px-3 py-1.5 text-xs font-semibold inline-flex items-center gap-1.5 cursor-pointer">
            <AppIcon name="layers" class="w-3.5 h-3.5" />
            <span>标准平衡视图</span>
          </button>
          <button @click="applyPreset('wide')"
            class="ui-btn-secondary px-3 py-1.5 text-xs font-semibold inline-flex items-center gap-1.5 cursor-pointer">
            <AppIcon name="maximize" class="w-3.5 h-3.5" />
            <span>宽屏/全景视图</span>
          </button>
        </div>
      </div>

      <!-- 3. 字段明细列表配置区 -->
      <div class="flex-1 overflow-y-auto custom-scrollbar p-6 space-y-2.5 min-h-0">
        <div v-for="(col, idx) in localColumns" :key="col.key"
          class="ui-content-card p-3 rounded-2xl flex items-center justify-between gap-4 hover:border-sky-500/40 transition-colors">
          
          <!-- 左侧：显示开关与列名 -->
          <div class="flex items-center gap-3 w-44 shrink-0">
            <input type="checkbox" :id="`col-vis-${col.key}`" v-model="col.visible"
              class="w-4 h-4 rounded accent-sky-600 cursor-pointer">
            <label :for="`col-vis-${col.key}`" class="cursor-pointer min-w-0">
              <div class="text-xs font-bold text-(--text-primary) truncate" :class="{ 'line-through text-(--text-muted)': !col.visible }">
                {{ col.label }}
              </div>
              <div class="text-[11px] font-mono-code text-(--text-muted) truncate">{{ col.key }}</div>
            </label>
          </div>

          <!-- 中间：滑块拖拽调节宽度 -->
          <div class="flex-1 flex items-center gap-3">
            <input type="range"
              :min="col.minWidth"
              :max="600"
              :step="5"
              v-model.number="col.width"
              :disabled="!col.visible"
              class="flex-1 h-1.5 bg-(--surface-content-alt) rounded-lg appearance-none cursor-pointer accent-sky-600 disabled:opacity-40">
          </div>

          <!-- 右侧：数字输入与恢复默认 -->
          <div class="flex items-center gap-2 w-36 justify-end shrink-0">
            <div class="relative flex items-center">
              <input type="number"
                :min="col.minWidth"
                :max="1200"
                v-model.number="col.width"
                :disabled="!col.visible"
                class="ui-input ui-num font-mono-code w-16 px-2 py-1 text-right text-xs font-bold disabled:opacity-40">
              <span class="text-[11px] font-mono-code text-(--text-muted) ml-1">px</span>
            </div>

            <button @click="resetSingleCol(idx)" title="恢复该字段默认宽度"
              class="ui-btn-secondary p-1.5 rounded-lg flex items-center justify-center cursor-pointer"
              aria-label="恢复默认宽度">
              <AppIcon name="refresh" class="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      <!-- 4. 底部操作栏 -->
      <div class="px-6 py-3 border-t border-(--border-subtle) bg-(--surface-content-alt) flex items-center justify-between shrink-0">
        <button @click="resetAllToDefault"
          class="ui-btn-secondary px-3 py-1.5 text-xs font-semibold cursor-pointer inline-flex items-center gap-1.5">
          <AppIcon name="refresh" class="w-3.5 h-3.5" />
          <span>恢复全部默认</span>
        </button>

        <div class="flex items-center gap-2.5">
          <button @click="$emit('close')"
            class="ui-btn-secondary px-4 py-1.5 text-xs font-semibold cursor-pointer">
            取消
          </button>
          <button @click="applyAndSave"
            class="ui-btn-primary text-xs px-5 py-1.5 font-bold cursor-pointer">
            应用并保存设置
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue';
import AppIcon from './AppIcon.vue';

export interface ColumnDef {
  key: string;
  label: string;
  defaultWidth: number;
  minWidth: number;
  width: number;
  sortable?: boolean;
  visible?: boolean;
}

const props = defineProps<{
  isOpen: boolean;
  columns: ColumnDef[];
}>();

const emit = defineEmits<{
  (e: 'close'): void;
  (e: 'save', columns: ColumnDef[]): void;
}>();

const localColumns = ref<ColumnDef[]>([]);

watch(() => props.isOpen, (open) => {
  if (open) {
    localColumns.value = props.columns.map(c => ({
      ...c,
      visible: c.visible !== false,
    }));
  }
}, { immediate: true });

function resetSingleCol(index: number) {
  const col = localColumns.value[index];
  if (col) {
    col.width = col.defaultWidth;
    col.visible = true;
  }
}

function resetAllToDefault() {
  localColumns.value.forEach(col => {
    col.width = col.defaultWidth;
    col.visible = true;
  });
}

function applyPreset(preset: 'compact' | 'standard' | 'wide') {
  const presetMap: Record<string, { width: number; visible?: boolean }> = {};
  if (preset === 'compact') {
    presetMap['timestamp'] = { width: 85 };
    presetMap['direction'] = { width: 65 };
    presetMap['transport'] = { width: 60 };
    presetMap['protocol'] = { width: 90 };
    presetMap['src_ip'] = { width: 200 };
    presetMap['mac_src'] = { width: 90, visible: false };
    presetMap['src_port'] = { width: 60 };
    presetMap['dst_port'] = { width: 60 };
    presetMap['length'] = { width: 55 };
    presetMap['entropy'] = { width: 65 };
    presetMap['payload'] = { width: 260 };
  } else if (preset === 'standard') {
    localColumns.value.forEach(col => {
      col.width = col.defaultWidth;
      col.visible = true;
    });
    return;
  } else if (preset === 'wide') {
    presetMap['timestamp'] = { width: 120 };
    presetMap['direction'] = { width: 90 };
    presetMap['transport'] = { width: 85 };
    presetMap['protocol'] = { width: 130 };
    presetMap['src_ip'] = { width: 360 };
    presetMap['mac_src'] = { width: 140, visible: true };
    presetMap['src_port'] = { width: 85 };
    presetMap['dst_port'] = { width: 85 };
    presetMap['length'] = { width: 80 };
    presetMap['entropy'] = { width: 85 };
    presetMap['payload'] = { width: 480 };
  }

  localColumns.value.forEach(col => {
    if (presetMap[col.key]) {
      col.width = Math.max(col.minWidth, presetMap[col.key].width);
      if (presetMap[col.key].visible !== undefined) {
        col.visible = presetMap[col.key].visible;
      }
    }
  });
}

function applyAndSave() {
  emit('save', localColumns.value.map(c => ({ ...c })));
  emit('close');
}
</script>
