<template>
  <div v-if="isOpen" class="ui-modal-backdrop fixed inset-0 z-50 flex items-center justify-center p-4 animate-in fade-in duration-150">
    <div class="ui-modal-surface w-full max-w-2xl rounded-3xl flex flex-col overflow-hidden max-h-[85vh]">
      
      <!-- 1. 顶栏 -->
      <div class="ui-nav-glass px-6 py-4 border-b border-(--border-subtle) flex items-center justify-between shrink-0">
        <div class="flex items-center gap-2.5">
          <div class="w-8 h-8 rounded-xl bg-indigo-500/12 border border-indigo-500/30 flex items-center justify-center text-indigo-600 dark:text-indigo-400">
            <AppIcon name="shield" class="w-4 h-4" />
          </div>
          <div>
            <h3 class="text-sm font-bold text-(--text-primary)">内网私网 CIDR 资产定义与安全域管理</h3>
            <p class="text-xs text-(--text-muted) font-mono-code">离线匹配进出流量，自动标注业务域与安全等级</p>
          </div>
        </div>
        <button @click="$emit('close')" class="ui-btn-secondary w-8 h-8 rounded-full p-0 flex items-center justify-center cursor-pointer" aria-label="关闭弹窗">
          <AppIcon name="close" class="w-4 h-4" />
        </button>
      </div>

      <!-- 2. 规则列表与新增表单 -->
      <div class="p-6 overflow-auto custom-scrollbar space-y-4 text-xs">
        <!-- 新增规则表单 -->
        <div class="ui-sub-card p-4 rounded-2xl space-y-3">
          <div class="font-bold text-(--text-primary) flex items-center gap-1.5">
            <AppIcon name="plus" class="w-3.5 h-3.5 text-indigo-600 dark:text-indigo-400" />
            <span>添加自定义网段资产规则</span>
          </div>
          <div class="grid grid-cols-1 md:grid-cols-4 gap-2.5">
            <div>
              <label class="block text-[11px] text-(--text-muted) font-semibold mb-1">CIDR 网段</label>
              <input v-model="newRule.cidr" placeholder="如: 192.168.1.0/24"
                class="ui-input w-full px-2.5 py-1.5 text-xs font-mono-code">
            </div>
            <div>
              <label class="block text-[11px] text-(--text-muted) font-semibold mb-1">安全域/分区名称</label>
              <input v-model="newRule.zone_name" placeholder="如: 生产控制PLC区"
                class="ui-input w-full px-2.5 py-1.5 text-xs">
            </div>
            <div>
              <label class="block text-[11px] text-(--text-muted) font-semibold mb-1">安全等级</label>
              <select v-model="newRule.security_level"
                class="ui-input w-full px-2 py-1.5 text-xs">
                <option value="核心">核心 (Core)</option>
                <option value="重要">重要 (Important)</option>
                <option value="普通">普通 (Normal)</option>
                <option value="外部">外部隔离区 (DMZ)</option>
              </select>
            </div>
            <div>
              <label class="block text-[11px] text-(--text-muted) font-semibold mb-1">描述与责任人</label>
              <input v-model="newRule.description" placeholder="如: 车间生产线"
                class="ui-input w-full px-2.5 py-1.5 text-xs">
            </div>
          </div>
          <div class="flex justify-end">
            <button @click="addRule" :disabled="!newRule.cidr.trim() || !newRule.zone_name.trim()"
              class="ui-btn-primary px-4 py-1.5 text-xs font-bold cursor-pointer disabled:opacity-40">
              添加规则
            </button>
          </div>
        </div>

        <!-- 当前规则列表 -->
        <div>
          <div class="font-bold text-(--text-primary) mb-2 flex items-center justify-between">
            <span>当前已加载的网段资产规则 (<span class="ui-num">{{ rules.length }}</span> 条)</span>
            <span class="text-[11px] text-(--text-muted) font-normal">匹配遵循最长前缀优先原则</span>
          </div>

          <div class="space-y-2">
            <div v-for="(rule, idx) in rules" :key="idx"
              class="ui-content-card p-3 rounded-xl flex items-center justify-between gap-2 hover:border-indigo-500/40 transition-colors">
              <div class="space-y-0.5 min-w-0">
                <div class="flex flex-wrap items-center gap-2">
                  <span class="font-bold text-indigo-600 dark:text-indigo-400 font-mono-code ui-num select-text">{{ rule.cidr }}</span>
                  <span class="px-2 py-0.5 rounded text-[11px] font-bold bg-indigo-500/12 text-indigo-700 dark:text-indigo-300 border border-indigo-500/30">
                    {{ rule.zone_name }}
                  </span>
                  <span :class="[
                    'px-1.5 py-0.5 rounded text-[11px] font-bold border',
                    rule.security_level === '核心' ? 'bg-rose-500/12 text-rose-700 dark:text-rose-300 border-rose-500/30' :
                    rule.security_level === '重要' ? 'bg-amber-500/12 text-amber-700 dark:text-amber-300 border-amber-500/30' : 'ui-pill text-(--text-secondary)'
                  ]">
                    {{ rule.security_level }}
                  </span>
                </div>
                <div class="text-[11px] text-(--text-muted) select-text">{{ rule.description || '无补充描述' }}</div>
              </div>

              <button @click="removeRule(idx)" class="ui-btn-danger px-2.5 py-1 text-xs font-semibold cursor-pointer shrink-0">
                删除
              </button>
            </div>

            <EmptyState
              v-if="rules.length === 0"
              icon="shield"
              title="暂无自定义 CIDR 规则"
              description="请在上方填入内网网段与安全域信息，保存后将注入流分类引擎。"
            />
          </div>
        </div>
      </div>

      <!-- 3. 底栏 -->
      <div class="px-6 py-3 border-t border-(--border-subtle) bg-(--surface-content-alt) flex items-center justify-between shrink-0">
        <span class="text-xs text-(--text-muted) font-mono-code">修改后将实时注入流分析引擎</span>
        <div class="flex items-center gap-2">
          <button @click="$emit('close')" class="ui-btn-secondary px-4 py-1.5 text-xs font-semibold cursor-pointer">
            关闭
          </button>
          <button @click="saveRules" :disabled="isSaving"
            class="ui-btn-primary text-xs px-5 py-1.5 font-bold cursor-pointer disabled:opacity-40">
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
import AppIcon from './AppIcon.vue';
import EmptyState from './EmptyState.vue';

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
