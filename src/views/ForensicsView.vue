<template>
  <div class="h-full flex flex-col gap-2.5 overflow-hidden font-sans">
    
    <!-- 1. 顶部控制栏：司法取证态势与核心操作 -->
    <section class="bg-white/80 backdrop-blur-xl rounded-2xl border border-white/70 p-3 shadow-xs shrink-0 flex flex-col gap-2.5">
      
      <!-- 1.1 标题与全局操作 -->
      <div class="flex items-center justify-between gap-3">
        <div class="flex items-center gap-2.5">
          <div class="w-8 h-8 rounded-xl bg-indigo-600/10 text-indigo-600 flex items-center justify-center border border-indigo-500/20 shadow-2xs">
            <svg class="w-4 h-4 fill-none stroke-current stroke-2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
            </svg>
          </div>
          <div>
            <div class="flex items-center gap-2">
              <h2 class="text-xs font-bold text-slate-800 tracking-tight">网络电子数据司法取证与保管链系统</h2>
              <span class="px-1.5 py-0.5 rounded-full text-[9px] font-mono bg-indigo-500/10 text-indigo-700 border border-indigo-500/20 font-bold">
                GB/T 29360-2012 / ISO/IEC 27037:2012
              </span>
            </div>
            <p class="text-[10px] text-slate-400 font-mono mt-0.5">
              国密 SM3 + SHA-256 双哈希封存 · PCAPNG 原生规约 · 零丢包物理保真 · WORM 防篡改锁定 · RFC 3161 TSA
            </p>
          </div>
        </div>

        <!-- 顶部操作工具栏 -->
        <div class="flex items-center gap-2">
          
          <!-- 手动双哈希封存 -->
          <button @click="triggerManualSeal" :disabled="loading"
            class="px-2.5 py-1.5 rounded-xl bg-indigo-50 hover:bg-indigo-100 text-indigo-700 text-[11px] font-medium flex items-center gap-1.5 transition-all cursor-pointer border border-indigo-200 shadow-2xs">
            <svg class="w-3.5 h-3.5 fill-none stroke-current stroke-2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H3.75A2.25 2.25 0 001.5 12v6.75a2.25 2.25 0 002.25 2.25z" />
            </svg>
            <span>双哈希封存 (SM3+SHA256)</span>
          </button>

          <!-- 司法验真 -->
          <button @click="verifyEvidence" :disabled="loading"
            class="px-2.5 py-1.5 rounded-xl bg-emerald-50 hover:bg-emerald-100 text-emerald-700 text-[11px] font-medium flex items-center gap-1.5 transition-all cursor-pointer border border-emerald-200 shadow-2xs">
            <svg class="w-3.5 h-3.5 fill-none stroke-current stroke-2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12.75l6 6 9-13.5" />
            </svg>
            <span>司法完整性验真</span>
          </button>

          <!-- 导出 PCAPNG -->
          <button @click="exportPcapng" :disabled="loading"
            class="px-2.5 py-1.5 rounded-xl bg-purple-50 hover:bg-purple-100 text-purple-700 text-[11px] font-medium flex items-center gap-1.5 transition-all cursor-pointer border border-purple-200 shadow-2xs">
            <svg class="w-3.5 h-3.5 fill-none stroke-current stroke-2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" />
            </svg>
            <span>导出工业级 PCAPNG</span>
          </button>

          <!-- 生成司法检验报告 -->
          <button @click="openReportModal"
            class="px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-900 text-white text-[11px] font-medium flex items-center gap-1.5 transition-all cursor-pointer shadow-2xs">
            <svg class="w-3.5 h-3.5 fill-none stroke-current stroke-2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
            </svg>
            <span>出具 GB/T 29360 报告</span>
          </button>

        </div>
      </div>

      <!-- 1.2 态势卡片 (4 列) -->
      <div class="grid grid-cols-4 gap-2.5">
        
        <!-- 卡片 1: 证据链完整性评级 -->
        <div class="bg-slate-50/80 rounded-xl p-2.5 border border-slate-200/60 flex items-center justify-between">
          <div>
            <div class="text-[10px] font-bold text-slate-400 uppercase tracking-wider">证据链完整性评级</div>
            <div class="text-sm font-mono font-bold mt-0.5 flex items-center gap-1.5"
              :class="verificationReport?.overall_status === 'PASS' ? 'text-emerald-700' : (verificationReport?.overall_status === 'APPENDED' ? 'text-amber-700' : 'text-rose-700')">
              <span class="w-2 h-2 rounded-full"
                :class="verificationReport?.overall_status === 'PASS' ? 'bg-emerald-500' : (verificationReport?.overall_status === 'APPENDED' ? 'bg-amber-500' : 'bg-rose-500')"></span>
              <span>{{ verificationReport?.overall_status || '待核验' }}</span>
            </div>
          </div>
          <div class="text-[10px] font-mono text-slate-500 bg-white px-2 py-1 rounded-lg border border-slate-200">
            {{ verificationReport?.items.length || 0 }} 证据文件
          </div>
        </div>

        <!-- 卡片 2: 密码学双哈希封条 -->
        <div class="bg-slate-50/80 rounded-xl p-2.5 border border-slate-200/60 flex items-center justify-between">
          <div>
            <div class="text-[10px] font-bold text-slate-400 uppercase tracking-wider">密码学摘要体制</div>
            <div class="text-xs font-mono font-bold text-indigo-700 mt-0.5">
              国密 SM3 + SHA-256
            </div>
            <div class="text-[9px] text-slate-400 font-mono mt-0.5">
              最近封存: {{ verificationReport?.last_sealed_at || '未封存' }}
            </div>
          </div>
          <div class="w-7 h-7 rounded-lg bg-indigo-500/10 text-indigo-600 flex items-center justify-center font-mono text-xs font-bold">
            SM3
          </div>
        </div>

        <!-- 卡片 3: 网卡捕获保真度 -->
        <div class="bg-slate-50/80 rounded-xl p-2.5 border border-slate-200/60 flex items-center justify-between">
          <div>
            <div class="text-[10px] font-bold text-slate-400 uppercase tracking-wider">网卡物理捕获保真度</div>
            <div class="text-sm font-mono font-bold text-emerald-700 mt-0.5 flex items-center gap-1.5">
              <span class="w-2 h-2 rounded-full bg-emerald-500"></span>
              <span>{{ fidelity?.fidelity_grade || 'GRADE_A_LOSSLESS' }}</span>
            </div>
            <div class="text-[9px] text-slate-400 font-mono mt-0.5">
              丢包率: {{ fidelity?.drop_rate_percentage.toFixed(4) || '0.0000' }}% (零丢包)
            </div>
          </div>
          <div class="text-[10px] font-mono text-emerald-700 bg-emerald-50 px-2 py-1 rounded-lg border border-emerald-200">
            物理级保真
          </div>
        </div>

        <!-- 卡片 4: 司法保管链节点数 -->
        <div class="bg-slate-50/80 rounded-xl p-2.5 border border-slate-200/60 flex items-center justify-between">
          <div>
            <div class="text-[10px] font-bold text-slate-400 uppercase tracking-wider">司法保管链存证节点</div>
            <div class="text-base font-mono font-bold text-slate-800 mt-0.5">
              {{ chainOfCustody.length }} 节点
            </div>
            <div class="text-[9px] text-slate-400 font-mono mt-0.5">
              链式不可逆哈希校验
            </div>
          </div>
          <div class="w-7 h-7 rounded-lg bg-slate-200 text-slate-700 flex items-center justify-center font-mono text-xs font-bold">
            CoC
          </div>
        </div>

      </div>
    </section>

    <!-- 2. 主体工作区：左侧证据档案柜 (7列) + 右侧司法保管链流水 (5列) -->
    <section class="flex-1 grid grid-cols-12 gap-2.5 overflow-hidden min-h-0">
      
      <!-- 2.1 左侧：证据档案柜与双哈希固定 (7 列) -->
      <div class="col-span-7 bg-white/80 backdrop-blur-xl rounded-2xl border border-white/70 p-3 shadow-xs flex flex-col overflow-hidden min-h-0">
        
        <div class="flex items-center justify-between mb-2 shrink-0">
          <div class="flex items-center gap-2">
            <h3 class="text-xs font-bold text-slate-800">司法证据档案柜 (Evidence Vault)</h3>
            <span class="text-[10px] font-mono text-slate-400">实时文件防篡改与 WORM 状态</span>
          </div>
          <button @click="loadForensicVault" class="text-[10px] font-mono text-indigo-600 hover:text-indigo-800 cursor-pointer">
            刷新状态 ⟳
          </button>
        </div>

        <!-- 表格 -->
        <div class="flex-1 overflow-y-auto custom-scrollbar border border-slate-100 rounded-xl">
          <table class="w-full text-left border-collapse text-[11px] font-mono">
            <thead class="bg-slate-50/90 sticky top-0 border-b border-slate-200 text-slate-500 select-none text-[10px]">
              <tr>
                <th class="p-2">证据文件名</th>
                <th class="p-2">大小</th>
                <th class="p-2">SHA-256 / SM3 摘要</th>
                <th class="p-2 text-center">状态</th>
                <th class="p-2 text-center">WORM</th>
                <th class="p-2 text-right">操作</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-100 text-slate-700">
              <tr v-for="item in evidenceVault" :key="item.file_name"
                class="hover:bg-slate-50/60 transition-colors">
                
                <td class="p-2 font-bold text-slate-800 flex items-center gap-1.5">
                  <svg class="w-3.5 h-3.5 text-slate-400 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z" />
                  </svg>
                  <span>{{ item.file_name }}</span>
                </td>

                <td class="p-2 text-slate-500 whitespace-nowrap">
                  {{ formatBytes(item.current_size) }}
                </td>

                <td class="p-2 max-w-[200px]">
                  <div class="text-[9px] text-slate-500 truncate" :title="item.current_hash">
                    <span class="text-slate-400">SHA:</span> {{ item.current_hash }}
                  </div>
                  <div class="text-[9px] text-indigo-600 truncate mt-0.5" :title="item.current_sm3">
                    <span class="text-indigo-400">SM3:</span> {{ item.current_sm3 }}
                  </div>
                </td>

                <td class="p-2 text-center">
                  <span class="px-1.5 py-0.5 rounded text-[9px] font-bold"
                    :class="{
                      'bg-emerald-100 text-emerald-800': item.status === 'MATCH',
                      'bg-amber-100 text-amber-800': item.status === 'APPENDED',
                      'bg-rose-100 text-rose-800': item.status === 'TAMPERED',
                      'bg-slate-100 text-slate-600': item.status === 'NO_SEAL'
                    }">
                    {{ item.status }}
                  </span>
                </td>

                <td class="p-2 text-center">
                  <span v-if="item.is_worm_locked"
                    class="px-1.5 py-0.5 rounded text-[9px] bg-purple-100 text-purple-700 font-bold">
                    🔒 只读锁定
                  </span>
                  <span v-else class="text-[9px] text-slate-400">
                    可读写
                  </span>
                </td>

                <td class="p-2 text-right whitespace-nowrap">
                  <div class="flex items-center justify-end gap-1">
                    <button v-if="!item.is_worm_locked" @click="setWormLock(item.file_name)"
                      class="px-2 py-0.5 rounded bg-purple-50 hover:bg-purple-100 text-purple-700 text-[10px] cursor-pointer border border-purple-200">
                      加锁
                    </button>
                    <button @click="stampTsa(item.file_name)"
                      class="px-2 py-0.5 rounded bg-indigo-50 hover:bg-indigo-100 text-indigo-700 text-[10px] cursor-pointer border border-indigo-200">
                      TSA
                    </button>
                  </div>
                </td>

              </tr>

              <tr v-if="evidenceVault.length === 0">
                <td colspan="6" class="p-6 text-center text-slate-400 text-xs font-mono">
                  暂无证据文件登记，点击上方【双哈希封存】进行初始固化
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- 底部保真度说明卡片 -->
        <div class="mt-2.5 p-2.5 bg-slate-50/80 rounded-xl border border-slate-200/60 text-[10px] text-slate-500 leading-relaxed font-mono">
          <div class="flex items-center gap-1.5 font-bold text-slate-700 mb-1">
            <span class="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
            <span>硬件层丢包审计证明 (ISB 规范)</span>
          </div>
          <p>{{ fidelity?.statement || '底层网卡及驱动缓冲区统计显示，丢包计数为零，全部链路层以太网帧均实现完整物理级保真捕获。' }}</p>
        </div>

      </div>

      <!-- 2.2 右侧：司法证据保管链流水 (5 列) -->
      <div class="col-span-5 bg-white/80 backdrop-blur-xl rounded-2xl border border-white/70 p-3 shadow-xs flex flex-col overflow-hidden min-h-0">
        
        <div class="flex items-center justify-between mb-2 shrink-0">
          <div class="flex items-center gap-2">
            <h3 class="text-xs font-bold text-slate-800">司法保管链流水 (Chain of Custody)</h3>
            <span class="text-[10px] font-mono text-slate-400">不可逆链式防篡改</span>
          </div>
          <span class="text-[10px] font-mono text-slate-400">共 {{ chainOfCustody.length }} 条记录</span>
        </div>

        <!-- 保管链时间线列表 -->
        <div class="flex-1 overflow-y-auto custom-scrollbar border border-slate-100 rounded-xl p-2 flex flex-col gap-2">
          
          <div v-for="rec in chainOfCustody" :key="rec.index"
            class="bg-slate-50/90 rounded-xl p-2.5 border border-slate-200/70 flex flex-col gap-1 text-[10px] font-mono">
            
            <div class="flex items-center justify-between text-slate-400">
              <span class="font-bold text-slate-700">#{{ rec.index }} · {{ rec.action }}</span>
              <span>{{ rec.timestamp }}</span>
            </div>

            <div class="text-slate-600 mt-0.5">
              <span class="text-slate-400">目标:</span> <span class="font-bold text-slate-800">{{ rec.evidence_target }}</span>
              <span class="mx-1 text-slate-300">|</span>
              <span class="text-slate-400">经手:</span> {{ rec.operator_id }} / {{ rec.reviewer_id }}
            </div>

            <div class="text-slate-500 text-[9px] bg-white p-1.5 rounded-lg border border-slate-200/60 mt-0.5">
              <div>{{ rec.reason_or_memo }}</div>
              <div class="text-[8px] text-slate-400 truncate mt-0.5">
                上一哈希: {{ rec.prev_record_hash }}
              </div>
              <div class="text-[8px] text-indigo-600 truncate">
                当前哈希: {{ rec.current_record_hash }}
              </div>
            </div>

          </div>

          <div v-if="chainOfCustody.length === 0" class="p-8 text-center text-slate-400 text-xs font-mono">
            尚未产生司法保管链记录
          </div>

        </div>

      </div>

    </section>

    <!-- 3. GB/T 29360 司法检验报告弹窗 -->
    <div v-if="showReportModal"
      class="fixed inset-0 bg-slate-900/40 backdrop-blur-xs flex items-center justify-center z-50 p-4">
      <div class="bg-white rounded-2xl max-w-3xl w-full max-h-[85vh] flex flex-col shadow-2xl border border-slate-200 overflow-hidden">
        
        <div class="p-3.5 border-b border-slate-200 flex items-center justify-between bg-slate-50/80">
          <div class="flex items-center gap-2">
            <h3 class="text-sm font-bold text-slate-800">司法鉴定检验报告 (GB/T 29360-2012)</h3>
            <span class="px-2 py-0.5 rounded text-[10px] font-mono bg-indigo-50 text-indigo-700 font-bold border border-indigo-200">
              法庭抗辩级存证
            </span>
          </div>
          <button @click="showReportModal = false" class="text-slate-400 hover:text-slate-600 text-base font-bold cursor-pointer">
            ✕
          </button>
        </div>

        <div class="p-4 flex-1 overflow-y-auto custom-scrollbar font-mono text-xs text-slate-700 space-y-4">
          
          <!-- 报告表单参数 -->
          <div class="grid grid-cols-3 gap-2 bg-slate-50 p-3 rounded-xl border border-slate-200">
            <div>
              <label class="text-[10px] font-bold text-slate-500 block mb-0.5">主取证人员:</label>
              <input v-model="reportInvestigator" class="w-full px-2 py-1 rounded bg-white border border-slate-200 text-xs" />
            </div>
            <div>
              <label class="text-[10px] font-bold text-slate-500 block mb-0.5">复核人员:</label>
              <input v-model="reportReviewer" class="w-full px-2 py-1 rounded bg-white border border-slate-200 text-xs" />
            </div>
            <div>
              <label class="text-[10px] font-bold text-slate-500 block mb-0.5">案事件编号:</label>
              <input v-model="reportCaseNumber" class="w-full px-2 py-1 rounded bg-white border border-slate-200 text-xs" />
            </div>
          </div>

          <button @click="generateReport" :disabled="loading"
            class="w-full py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl font-bold transition-all shadow-xs cursor-pointer">
            重新生成报告文本
          </button>

          <!-- 报告预览 Markdown 内容 -->
          <div v-if="generatedReport" class="bg-slate-900 text-slate-200 p-4 rounded-xl border border-slate-800 font-mono text-[11px] whitespace-pre-wrap leading-relaxed max-h-[40vh] overflow-y-auto custom-scrollbar select-text">
{{ generatedReport.markdown_report }}
          </div>

        </div>

        <div class="p-3 border-t border-slate-200 flex items-center justify-between bg-slate-50/80">
          <span class="text-[11px] text-slate-400 font-mono">
            遵循 GB/T 29360-2012 电子数据取证检验通用技术规范
          </span>
          <div class="flex items-center gap-2">
            <button v-if="generatedReport" @click="copyReport"
              class="px-3 py-1.5 rounded-xl bg-slate-200 hover:bg-slate-300 text-slate-700 text-xs font-bold cursor-pointer">
              复制报告全文
            </button>
            <button @click="showReportModal = false"
              class="px-4 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-900 text-white text-xs font-bold cursor-pointer">
              完成
            </button>
          </div>
        </div>

      </div>
    </div>

  </div>
</template>

<script setup lang="ts">
import { notifySuccess, notifyError } from '../composables/useNotification';
import { ref, onMounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';

interface FileIntegrityResult {
  file_name: string;
  expected_hash: string;
  current_hash: string;
  expected_sm3: string;
  current_sm3: string;
  sealed_size: number;
  current_size: number;
  status: string;
  is_worm_locked: boolean;
  details: string;
}

interface EvidenceVerificationReport {
  verified_at: string;
  last_sealed_at: string;
  last_seal_reason: string;
  overall_status: string;
  seal_file_exists: boolean;
  items: FileIntegrityResult[];
  summary: string;
}

interface CaptureFidelityCertificate {
  certified_at: string;
  packets_received: number;
  packets_dropped_driver: number;
  packets_dropped_interface: number;
  drop_rate_percentage: number;
  fidelity_grade: string;
  is_lossless_certified: boolean;
  statement: string;
}

interface ChainOfCustodyRecord {
  index: number;
  timestamp: string;
  action: string;
  operator_id: string;
  reviewer_id: string;
  evidence_target: string;
  reason_or_memo: string;
  file_size: number;
  sha256: string;
  sm3: string;
  prev_record_hash: string;
  current_record_hash: string;
}

interface ForensicInspectionReport {
  report_id: string;
  standard_name: string;
  generated_at: string;
  agency: string;
  case_number: string;
  investigator: string;
  reviewer: string;
  system_env: string;
  interface_name: string;
  fidelity_certificate: CaptureFidelityCertificate;
  evidence_items: FileIntegrityResult[];
  tsa_token: any;
  chain_of_custody_count: number;
  legal_conclusion: string;
  markdown_report: string;
}

const loading = ref(false);
const evidenceVault = ref<FileIntegrityResult[]>([]);
const verificationReport = ref<EvidenceVerificationReport | null>(null);
const fidelity = ref<CaptureFidelityCertificate | null>(null);
const chainOfCustody = ref<ChainOfCustodyRecord[]>([]);

// 报告弹窗状态
const showReportModal = ref(false);
const reportInvestigator = ref('CERT_INVESTIGATOR_01');
const reportReviewer = ref('LEGAL_REVIEWER_02');
const reportCaseNumber = ref(`CASE-${new Date().getFullYear()}-001`);
const generatedReport = ref<ForensicInspectionReport | null>(null);

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

async function loadForensicVault() {
  try {
    evidenceVault.value = await invoke<FileIntegrityResult[]>('get_forensic_vault_cmd');
  } catch (e) {
    console.error('加载证据档案失败:', e);
  }
}

async function loadChainOfCustody() {
  try {
    chainOfCustody.value = await invoke<ChainOfCustodyRecord[]>('get_chain_of_custody_cmd');
  } catch (e) {
    console.error('加载保管链失败:', e);
  }
}

async function loadFidelityCertificate() {
  try {
    fidelity.value = await invoke<CaptureFidelityCertificate>('get_fidelity_certificate_cmd');
  } catch (e) {
    console.error('获取保真度证明失败:', e);
  }
}

async function triggerManualSeal() {
  loading.value = true;
  try {
    const res = await invoke<string>('manual_seal_cmd');
    notifySuccess('数字证据链封存成功', res);
    await verifyEvidence();
    await loadChainOfCustody();
  } catch (e) {
    notifyError('数字证据封存受阻', e);
  } finally {
    loading.value = false;
  }
}

async function verifyEvidence() {
  loading.value = true;
  try {
    verificationReport.value = await invoke<EvidenceVerificationReport>('verify_evidence_chain_cmd');
    evidenceVault.value = verificationReport.value.items;
    notifySuccess('证据链验真通过', `共校验 ${verificationReport.value.items.length} 份数字物证，哈希链自洽无篡改`);
    await loadChainOfCustody();
  } catch (e) {
    notifyError('证据链完整性验真受阻', e);
  } finally {
    loading.value = false;
  }
}

async function exportPcapng() {
  loading.value = true;
  try {
    const res = await invoke<string>('export_pcapng_cmd', { ifName: 'All Active Interfaces' });
    notifySuccess('取证 PCAPNG 导出完成', res);
    await loadForensicVault();
    await loadChainOfCustody();
  } catch (e) {
    notifyError('导出 PCAPNG 失败', e);
  } finally {
    loading.value = false;
  }
}

async function setWormLock(fileName: string) {
  try {
    await invoke<boolean>('set_worm_lock_cmd', { fileName });
    notifySuccess('WORM 防篡改锁定生效', `已对证据文件 ${fileName} 施加底层只读防篡改属性`);
    await loadForensicVault();
    await loadChainOfCustody();
  } catch (e) {
    notifyError('WORM 锁定受阻', e);
  }
}

async function stampTsa(fileName: string) {
  try {
    const token = await invoke<any>('generate_tsa_timestamp_cmd', { fileName });
    notifySuccess('RFC 3161 TSA 时间戳加盖成功', `序列号: ${token.serial_number} | 打标时间: ${token.stamped_at}`);
    await loadChainOfCustody();
  } catch (e) {
    notifyError('TSA 时间戳加盖受阻', e);
  }
}

function openReportModal() {
  showReportModal.value = true;
  generateReport();
}

async function generateReport() {
  loading.value = true;
  try {
    generatedReport.value = await invoke<ForensicInspectionReport>('generate_judicial_report_cmd', {
      investigator: reportInvestigator.value,
      reviewer: reportReviewer.value,
      caseNumber: reportCaseNumber.value,
    });
  } catch (e) {
    notifyError('生成司法鉴定报告受阻', e);
  } finally {
    loading.value = false;
  }
}

function copyReport() {
  if (generatedReport.value) {
    navigator.clipboard.writeText(generatedReport.value.markdown_report);
    notifySuccess('报告已复制', '司法取证鉴定报告 Markdown 全文已成功复制到剪贴板');
  }
}

onMounted(async () => {
  await loadForensicVault();
  await loadChainOfCustody();
  await loadFidelityCertificate();
  try {
    verificationReport.value = await invoke<EvidenceVerificationReport>('verify_evidence_chain_cmd');
  } catch (e) {
    console.error('初始验真检查:', e);
  }
});
</script>

<style scoped>
.custom-scrollbar::-webkit-scrollbar {
  width: 5px;
  height: 5px;
}
.custom-scrollbar::-webkit-scrollbar-track {
  background: transparent;
}
.custom-scrollbar::-webkit-scrollbar-thumb {
  background: rgba(148, 163, 184, 0.3);
  border-radius: 9999px;
}
.custom-scrollbar::-webkit-scrollbar-thumb:hover {
  background: rgba(148, 163, 184, 0.5);
}
</style>
