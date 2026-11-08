<template>
  <div v-if="isOpen" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-md animate-in fade-in duration-150">
    <div class="w-full max-w-2xl bg-white/95 backdrop-blur-2xl rounded-3xl border border-white/60 shadow-2xl flex flex-col overflow-hidden max-h-[85vh]">
      
      <!-- 1. 顶栏 -->
      <div class="px-6 py-4 border-b border-slate-200/60 bg-white/40 flex items-center justify-between shrink-0">
        <div class="flex items-center gap-2.5">
          <span class="w-3 h-3 rounded-full bg-indigo-600 shadow-sm"></span>
          <div>
            <h3 class="text-sm font-bold text-slate-900">内网私网 CIDR 资产定义与安全域管理</h3>
            <p class="text-[11px] text-slate-500 font-mono">100% 物理隔离离线匹配，为进出流量自动标注企业业务域与安全等级</p>
          </div>
        </div>
        <button @click="$emit('close')" class="w-8 h-8 rounded-full flex items-center justify-center text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors cursor-pointer">
          ✕
        </button>
      </div>

      <!-- 2. 规则列表与新增表单 -->
      <div class="p-6 overflow-auto custom-scrollbar space-y-4 text-xs font-mono">
        <!-- 新增规则表单 -->
        <div class="bg-slate-50 p-4 rounded-2xl border border-slate-200/80 space-y-3">
          <div class="font-bold text-slate-800 flex items-center gap-2">
            <span>➕ 添加自定义网段资产规则</span>
          </div>
          <div class="grid grid-cols-1 md:grid-cols-4 gap-2">
            <div>
              <label class="block text-[10px] text-slate-500 font-semibold mb-1">CIDR 网段</label>
              <input v-model="newRule.cidr" placeholder="如: 192.168.1.0/24"
                class="w-full bg-white border border-slate-200 rounded-xl px-2.5 py-1.5 text-xs font-mono">
            </div>
            <div>
              <label class="block text-[10px] text-slate-500 font-semibold mb-1">安全域/分区名称</label>
              <input v-model="newRule.zone_name" placeholder="如: 生产控制PLC区"
                class="w-full bg-white border border-slate-200 rounded-xl px-2.5 py-1.5 text-xs">
            </div>
            <div>
              <label class="block text-[10px] text-slate-500 font-semibold mb-1">安全等级</label>
              <select v-model="newRule.security_level"
                class="w-full bg-white border border-slate-200 rounded-xl px-2 py-1.5 text-xs">
                <option value="核心">核心 (Core)</option>
                <option value="重要">重要 (Important)</option>
                <option value="普通">普通 (Normal)</option>
                <option value="外部">外部隔离区 (DMZ)</option>
              </select>
            </div>
            <div>
              <label class="block text-[10px] text-slate-500 font-semibold mb-1">描述与责任人</label>
              <input v-model="newRule.description" placeholder="如: 车间生产线"
                class="w-full bg-white border border-slate-200 rounded-xl px-2.5 py-1.5 text-xs">
            </div>
          </div>
          <div class="flex justify-end">
            <button @click="addRule" :disabled="!newRule.cidr.trim() || !newRule.zone_name.trim()"
              class="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-1.5 rounded-xl font-bold transition-all shadow-xs cursor-pointer disabled:opacity-40">
              添加规则
            </button>
          </div>
        </div>

        <!-- 当前规则列表 -->
        <div>
          <div class="font-bold text-slate-800 mb-2 flex items-center justify-between">
            <span>当前已加载的网段资产规则 ({{ rules.length }} 条)</span>
            <span class="text-[10px] text-slate-400 font-normal">匹配遵循最长前缀优先原则</span>
          </div>

          <div class="space-y-2">
            <div v-for="(rule, idx) in rules" :key="idx"
              class="p-3 bg-white border border-slate-200 rounded-xl flex items-center justify-between shadow-2xs hover:border-indigo-300 transition-colors">
              <div class="space-y-0.5">
                <div class="flex items-center gap-2">
                  <span class="font-bold text-indigo-700">{{ rule.cidr }}</span>
                  <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-indigo-50 text-indigo-800 border border-indigo-200">
                    {{ rule.zone_name }}
                  </span>
                  <span :class="[
                    'px-1.5 py-0.5 rounded text-[9px] font-bold',
                    rule.security_level === '核心' ? 'bg-rose-100 text-rose-800' :
                    rule.security_level === '重要' ? 'bg-amber-100 text-amber-800' : 'bg-slate-100 text-slate-700'
                  ]">
                    {{ rule.security_level }}
                  </span>
                </div>
                <div class="text-[11px] text-slate-400">{{ rule.description || '无补充描述' }}</div>
              </div>

              <button @click="removeRule(idx)" class="text-rose-500 hover:text-rose-700 hover:bg-rose-50 p-1.5 rounded-lg transition-colors cursor-pointer text-xs">
                删除
              </button>
            </div>
          </div>
        </div>
      </div>

      <!-- 3. 底栏 -->
      <div class="px-6 py-3 border-t border-slate-200/60 bg-white/40 flex items-center justify-between shrink-0">
        <span class="text-[11px] text-slate-400 font-mono">修改后将实时注入流分析引擎</span>
        <div class="flex items-center gap-2">
          <button @click="$emit('close')" class="px-4 py-1.5 rounded-xl text-xs font-semibold text-slate-600 hover:bg-slate-100 transition-colors cursor-pointer">
            关闭
          </button>
          <button @click="saveRules" :disabled="isSaving"
            class="bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-700 text-white text-xs px-5 py-1.5 rounded-xl font-bold cursor-pointer transition-all shadow-sm active:scale-95 disabled:opacity-40">
            <span v-if="isSaving">保存中...</span>
            <span v-else>保存并生效</span>
          </button>
        </div>
      </div>

    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue';
import { invoke } from '@tauri-apps/api/core';

interface CidrRule {
  cidr: string;
  zone_name: string;
  security_level: string;
  description: string;
}

const props = defineProps<{
  isOpen: boolean;
}>();

const emit = defineEmits(['close', 'log']);

const rules = ref<CidrRule[]>([]);
const isSaving = ref(false);

const newRule = ref<CidrRule>({
  cidr: '',
  zone_name: '',
  security_level: '重要',
  description: '',
});

watch(
  () => props.isOpen,
  async (open) => {
    if (open) {
      await loadRules();
    }
  }
);

async function loadRules() {
  try {
    rules.value = await invoke<CidrRule[]>('get_cidr_rules_cmd');
  } catch (e) {
    console.warn('获取 CIDR 规则失败:', e);
  }
}

function addRule() {
  if (!newRule.value.cidr.trim() || !newRule.value.zone_name.trim()) return;
  rules.value.push({ ...newRule.value });
  newRule.value = {
    cidr: '',
    zone_name: '',
    security_level: '重要',
    description: '',
  };
}

function removeRule(index: number) {
  rules.value.splice(index, 1);
}

async function saveRules() {
  isSaving.value = true;
  try {
    const count = await invoke<number>('save_cidr_rules_cmd', { rules: rules.value });
    emit('log', `[CIDR-ASSET] 成功更新 ${count} 条内网资产安全域规则`);
    emit('close');
  } catch (e) {
    console.error('保存 CIDR 规则失败:', e);
  } finally {
    isSaving.value = false;
  }
}
</script>
