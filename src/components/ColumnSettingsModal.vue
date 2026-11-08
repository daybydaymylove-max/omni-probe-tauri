<template>
  <div v-if="isOpen" class="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 backdrop-blur-sm animate-in fade-in duration-150 select-none">
    <div class="bg-white/95 backdrop-blur-2xl rounded-3xl border border-white/80 shadow-2xl w-[680px] max-w-[92vw] max-h-[85vh] flex flex-col overflow-hidden animate-in zoom-in-95 duration-200">
      
      <!-- 1. 弹窗头部 -->
      <div class="px-6 py-4 border-b border-slate-200/70 flex items-center justify-between bg-gradient-to-r from-slate-50 to-white">
        <div class="flex items-center gap-2.5">
          <div class="w-8 h-8 rounded-xl bg-blue-500/10 border border-blue-200 flex items-center justify-center text-blue-600 font-bold text-sm">
            📐
          </div>
          <div>
            <h3 class="text-sm font-bold text-slate-800 tracking-wide">侦听列表字段显示长度与列宽调节</h3>
            <p class="text-[11px] text-slate-400">自由设定各字段显示宽度、显示/隐藏开关，或选用场景预设</p>
          </div>
        </div>
        <button @click="$emit('close')"
          class="w-7 h-7 rounded-xl hover:bg-slate-200/60 text-slate-400 hover:text-slate-700 flex items-center justify-center transition-colors cursor-pointer">
          ✕
        </button>
      </div>

      <!-- 2. 快捷预设分段选择 -->
      <div class="px-6 py-3 bg-slate-100/60 border-b border-slate-200/50 flex items-center justify-between gap-3">
        <span class="text-xs font-bold text-slate-600 shrink-0">快捷场景预设:</span>
        <div class="flex items-center gap-2">
          <button @click="applyPreset('compact')"
            class="px-3 py-1 text-xs rounded-xl border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-semibold transition-all shadow-2xs hover:border-blue-400 active:scale-95 cursor-pointer">
            📱 紧凑小屏视图
          </button>
          <button @click="applyPreset('standard')"
            class="px-3 py-1 text-xs rounded-xl border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-semibold transition-all shadow-2xs hover:border-blue-400 active:scale-95 cursor-pointer">
            💻 标准平衡视图
          </button>
          <button @click="applyPreset('wide')"
            class="px-3 py-1 text-xs rounded-xl border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-semibold transition-all shadow-2xs hover:border-blue-400 active:scale-95 cursor-pointer">
            🖥 宽屏/全景视图
          </button>
        </div>
      </div>

      <!-- 3. 字段明细列表配置区 -->
      <div class="flex-1 overflow-y-auto custom-scrollbar p-6 space-y-3 min-h-0 bg-slate-50/30">
        <div v-for="(col, idx) in localColumns" :key="col.key"
          class="p-3 bg-white rounded-2xl border border-slate-200/70 shadow-2xs flex items-center justify-between gap-4 hover:border-blue-300/80 transition-colors">
          
          <!-- 左侧：显示开关与列名 -->
          <div class="flex items-center gap-3 w-40 shrink-0">
            <input type="checkbox" :id="`col-vis-${col.key}`" v-model="col.visible"
              class="w-4 h-4 rounded text-blue-600 focus:ring-blue-500 cursor-pointer">
            <label :for="`col-vis-${col.key}`" class="cursor-pointer">
              <div class="text-xs font-bold text-slate-800" :class="{ 'line-through text-slate-400': !col.visible }">
                {{ col.label }}
              </div>
              <div class="text-[10px] font-mono text-slate-400">{{ col.key }}</div>
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
              class="flex-1 h-1.5 bg-slate-200 rounded-lg appearance-none cursor-pointer accent-blue-600 disabled:opacity-40">
          </div>

          <!-- 右侧：数字输入与恢复默认 -->
          <div class="flex items-center gap-2 w-36 justify-end shrink-0">
            <div class="relative flex items-center">
              <input type="number"
                :min="col.minWidth"
                :max="1200"
                v-model.number="col.width"
                :disabled="!col.visible"
                class="w-16 px-2 py-1 text-right text-xs font-mono font-bold bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/30 disabled:opacity-40">
              <span class="text-[10px] font-mono text-slate-400 ml-1">px</span>
            </div>

            <button @click="resetSingleCol(idx)" title="恢复该字段默认宽度"
              class="p-1 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors cursor-pointer text-xs">
              ⟲
            </button>
          </div>
        </div>
      </div>

      <!-- 4. 底部操作栏 -->
      <div class="px-6 py-3 border-t border-slate-200/70 bg-white flex items-center justify-between shrink-0">
        <button @click="resetAllToDefault"
          class="px-3 py-1.5 rounded-xl border border-slate-200 text-xs font-semibold text-slate-600 hover:bg-slate-100 transition-colors cursor-pointer flex items-center gap-1.5">
          <span>⟲ 恢复全部默认</span>
        </button>

        <div class="flex items-center gap-2.5">
          <button @click="$emit('close')"
            class="px-4 py-1.5 rounded-xl border border-slate-200 text-xs font-semibold text-slate-600 hover:bg-slate-100 transition-colors cursor-pointer">
            取消
          </button>
          <button @click="applyAndSave"
            class="bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white text-xs px-5 py-1.5 rounded-xl font-bold cursor-pointer transition-all shadow-sm active:scale-95">
            应用并保存设置
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue';

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
