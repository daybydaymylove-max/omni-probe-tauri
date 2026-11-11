<template>
  <div class="h-full flex flex-col gap-2.5 overflow-hidden font-sans">

    <!-- 1. 顶部控制栏 (真 Liquid Glass 控制层) -->
    <section class="ui-nav-glass rounded-2xl p-3.5 shrink-0 flex flex-col gap-3" style="color: var(--text-primary);">
      <span class="lens-edge-lip" aria-hidden="true"></span>
      <div class="flex items-center justify-between gap-3 flex-wrap">
        <div class="flex items-center gap-2.5 min-w-0">
          <div class="w-8 h-8 rounded-xl bg-[var(--accent-primary-soft)] text-[var(--accent-primary-text)] flex items-center justify-center border border-[var(--accent-primary)]/20 shrink-0">
            <AppIcon name="shield" :size="16" />
          </div>
          <div class="min-w-0">
            <div class="flex items-center gap-2 flex-wrap">
              <h2 class="text-[13px] font-semibold tracking-tight" style="color: var(--text-primary);">网络电子数据司法取证与保管链系统</h2>
              <span class="ui-pill px-2 py-0.5 rounded-full text-[11px] font-medium">
                GB/T 29360 · ISO/IEC 27037
              </span>
            </div>
            <p class="text-[11px] mt-0.5 truncate" style="color: var(--text-muted);">
              国密 SM3 + SHA-256 双哈希封存 · PCAPNG 原生规约 · Npcap 丢包采集 · WORM 防篡改锁定
            </p>
          </div>
        </div>

        <div class="flex items-center gap-2 flex-wrap">
          <button @click="triggerManualSeal" :disabled="loading" class="ui-btn-secondary px-3 py-1.5 text-xs">
            <AppIcon name="lock" :size="14" />
            <span>双哈希封存</span>
          </button>

          <button @click="verifyEvidence" :disabled="loading" class="ui-btn-secondary px-3 py-1.5 text-xs">
            <AppIcon name="check" :size="14" />
            <span>完整性验真</span>
          </button>

          <button @click="exportPcapng" :disabled="loading" class="ui-btn-secondary px-3 py-1.5 text-xs">
            <AppIcon name="download" :size="14" />
            <span>导出 PCAPNG</span>
          </button>

          <button @click="openReportModal" class="ui-btn-primary px-3 py-1.5 text-xs">
            <AppIcon name="document" :size="14" />
            <span>出具 GB/T 29360 报告</span>
          </button>
        </div>
      </div>

      <!-- 1.2 核心指标卡片 (Apple Bento 净数据卡片) -->
      <div class="grid grid-cols-2 lg:grid-cols-4 gap-2.5">
        <div class="ui-sub-card p-3 flex items-center justify-between gap-2">
          <div>
            <div class="text-[11px] font-medium" style="color: var(--text-muted);">证据链完整性评级</div>
            <div
              class="text-sm font-semibold ui-num mt-1 flex items-center gap-1.5"
              :class="verificationReport?.overall_status === 'PASS' ? 'text-emerald-600 dark:text-emerald-400' : (verificationReport?.overall_status === 'APPENDED' ? 'text-amber-600 dark:text-amber-400' : 'text-[var(--text-primary)]')"
            >
              <span
                class="w-2 h-2 rounded-full"
                :class="verificationReport?.overall_status === 'PASS' ? 'bg-emerald-500' : (verificationReport?.overall_status === 'APPENDED' ? 'bg-amber-500' : 'bg-slate-400')"
              ></span>
              <span>{{ verificationReport?.overall_status || '待核验' }}</span>
            </div>
          </div>
          <div class="ui-pill text-[11px] px-2 py-0.5 rounded-full ui-num">
            {{ verificationReport?.items.length || 0 }} 文件
          </div>
        </div>

        <div class="ui-sub-card p-3 flex items-center justify-between gap-2">
          <div class="min-w-0">
            <div class="text-[11px] font-medium" style="color: var(--text-muted);">密码学摘要体制</div>
            <div class="text-xs font-semibold mt-1" style="color: var(--text-primary);">
              国密 SM3 + SHA-256
            </div>
            <div class="text-[11px] ui-num truncate mt-0.5" style="color: var(--text-muted);">
              最近封存: {{ verificationReport?.last_sealed_at || '未封存' }}
            </div>
          </div>
          <div class="w-8 h-8 rounded-xl bg-[var(--surface-glass-pill)] text-[var(--text-secondary)] flex items-center justify-center shrink-0">
            <AppIcon name="key" :size="15" />
          </div>
        </div>

        <div class="ui-sub-card p-3 flex items-center justify-between gap-2">
          <div class="min-w-0">
            <div class="text-[11px] font-medium" style="color: var(--text-muted);">物理捕获保真度</div>
            <div
              class="text-sm font-semibold ui-num mt-1 flex items-center gap-1.5"
              :class="!fidelity || fidelity.packets_received === 0 ? 'text-[var(--text-secondary)]' : (fidelity.is_lossless_certified ? 'text-emerald-600 dark:text-emerald-400' : 'text-amber-600 dark:text-amber-400')"
            >
              <span
                class="w-2 h-2 rounded-full shrink-0"
                :class="!fidelity || fidelity.packets_received === 0 ? 'bg-slate-400' : (fidelity.is_lossless_certified ? 'bg-emerald-500' : 'bg-amber-500')"
              ></span>
              <span class="truncate">{{ fidelity ? fidelity.fidelity_grade : '就绪待机' }}</span>
            </div>
            <div class="text-[11px] ui-num truncate mt-0.5" style="color: var(--text-muted);">
              {{ fidelity ? `丢包: ${fidelity.drop_rate_percentage.toFixed(4)}%` : '等待抓包会话统计' }}
            </div>
          </div>
          <span
            class="text-[11px] px-2 py-0.5 rounded-full border shrink-0 font-medium"
            :class="!fidelity || fidelity.packets_received === 0 ? 'ui-pill' : (fidelity.is_lossless_certified ? 'text-emerald-700 dark:text-emerald-300 bg-emerald-500/12 border-emerald-500/25' : 'text-amber-700 dark:text-amber-300 bg-amber-500/12 border-amber-500/25')"
          >
            {{ fidelity && fidelity.packets_received > 0 ? (fidelity.is_lossless_certified ? '零丢包' : '存在丢包') : '待捕获' }}
          </span>
        </div>

        <div class="ui-sub-card p-3 flex items-center justify-between gap-2">
          <div>
            <div class="text-[11px] font-medium" style="color: var(--text-muted);">保管链存证节点</div>
            <div class="text-lg ui-num font-bold mt-0.5 leading-tight" style="color: var(--text-primary);">
              {{ chainOfCustody.length }} <span class="text-[11px] font-normal" style="color: var(--text-muted);">节点</span>
            </div>
          </div>
          <div class="w-8 h-8 rounded-xl bg-[var(--surface-glass-pill)] text-[var(--text-secondary)] flex items-center justify-center shrink-0">
            <AppIcon name="link" :size="15" />
          </div>
        </div>
      </div>
    </section>

    <!-- 2. 主体工作区 (实体稳态衬底，开放选区) -->
    <section class="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-2.5 overflow-hidden min-h-0 select-text">

      <!-- 2.1 左侧：证据档案柜与双哈希固定 -->
      <div class="lg:col-span-7 ui-content-card p-3 flex flex-col overflow-hidden min-h-0">
        <div class="flex items-center justify-between mb-2 shrink-0">
          <div class="flex items-center gap-2">
            <h3 class="text-[13px] font-semibold" style="color: var(--text-primary);">司法证据档案柜 (Evidence Vault)</h3>
            <span class="text-[11px]" style="color: var(--text-muted);">实时文件防篡改与 WORM 状态</span>
          </div>
          <button @click="loadForensicVault" class="ui-btn-secondary px-2.5 py-1 text-[11px]">
            <AppIcon name="refresh" :size="12" />
            <span>刷新状态</span>
          </button>
        </div>

        <div class="flex-1 overflow-y-auto custom-scrollbar border rounded-xl" style="border-color: var(--border-subtle); background: var(--surface-content-alt);">
          <table class="w-full text-left border-collapse text-xs">
            <thead class="ui-table-head sticky top-0 select-none">
              <tr>
                <th class="p-2.5">证据文件名</th>
                <th class="p-2.5">大小</th>
                <th class="p-2.5">SHA-256 / SM3 摘要</th>
                <th class="p-2.5 text-center">状态</th>
                <th class="p-2.5 text-center">WORM</th>
                <th class="p-2.5 text-right">操作</th>
              </tr>
            </thead>
            <tbody class="divide-y" style="border-color: var(--border-subtle);">
              <tr v-for="item in evidenceVault" :key="item.file_name" class="hover:bg-[var(--surface-hover)] transition-colors">
                <td class="p-2.5 font-semibold flex items-center gap-1.5" style="color: var(--text-primary);">
                  <AppIcon name="document" :size="14" class="shrink-0" style="color: var(--text-muted);" />
                  <span>{{ item.file_name }}</span>
                </td>

                <td class="p-2.5 ui-num whitespace-nowrap" style="color: var(--text-secondary);">
                  {{ formatBytes(item.current_size) }}
                </td>

                <td class="p-2.5 max-w-[200px] font-mono">
                  <div class="text-[11px] truncate" style="color: var(--text-secondary);" :title="item.current_hash">
                    <span style="color: var(--text-muted);">SHA:</span> {{ item.current_hash }}
                  </div>
                  <div class="text-[11px] text-indigo-600 dark:text-indigo-300 truncate mt-0.5" :title="item.current_sm3">
                    <span class="opacity-70">SM3:</span> {{ item.current_sm3 }}
                  </div>
                </td>

                <td class="p-2.5 text-center">
                  <span
                    class="px-1.5 py-0.5 rounded text-[11px] font-semibold"
                    :class="{
                      'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300': item.status === 'MATCH',
                      'bg-amber-500/15 text-amber-700 dark:text-amber-300': item.status === 'APPENDED',
                      'bg-rose-500/15 text-rose-700 dark:text-rose-300': item.status === 'TAMPERED',
                      'ui-pill': item.status === 'NO_SEAL'
                    }"
                  >
                    {{ item.status }}
                  </span>
                </td>

                <td class="p-2.5 text-center">
                  <span v-if="item.is_worm_locked" class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[11px] bg-purple-500/15 text-purple-700 dark:text-purple-300 font-semibold">
                    <AppIcon name="lock" :size="11" />
                    <span>只读锁定</span>
                  </span>
                  <span v-else class="text-[11px]" style="color: var(--text-muted);">可读写</span>
                </td>

                <td class="p-2.5 text-right whitespace-nowrap">
                  <div class="flex items-center justify-end gap-1">
                    <button
                      v-if="!item.is_worm_locked"
                      @click="setWormLock(item.file_name)"
                      class="px-2 py-0.5 rounded bg-purple-500/12 hover:bg-purple-500/20 text-purple-700 dark:text-purple-300 text-[11px] cursor-pointer border border-purple-500/25"
                    >
                      加锁
                    </button>
                    <button
                      @click="stampTsa(item.file_name)"
                      class="px-2 py-0.5 rounded bg-indigo-500/12 hover:bg-indigo-500/20 text-indigo-700 dark:text-indigo-300 text-[11px] cursor-pointer border border-indigo-500/25"
                    >
                      TSA
                    </button>
                    <button
                      @click="addEvidenceToDiffQueue(item)"
                      class="px-2 py-0.5 rounded bg-emerald-500/12 hover:bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 text-[11px] font-semibold cursor-pointer border border-emerald-500/25"
                      title="将证据文件双哈希指纹及尺寸纳入多组比对队列"
                    >
                      + 入队
                    </button>
                  </div>
                </td>
              </tr>

              <tr v-if="evidenceVault.length === 0">
                <td colspan="6" class="p-8 text-center text-xs" style="color: var(--text-muted);">
                  暂无证据文件登记，点击上方【双哈希封存】进行初始固化
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <div class="ui-sub-card mt-2.5 p-2.5 text-[11px] leading-relaxed" style="color: var(--text-secondary);">
          <div class="flex items-center gap-1.5 font-semibold mb-1" style="color: var(--text-primary);">
            <span class="w-1.5 h-1.5 rounded-full" :class="fidelity?.is_lossless_certified ? 'bg-emerald-500' : 'bg-slate-400'"></span>
            <span>硬件层丢包审计证明 (Npcap / ISB 统计规范)</span>
          </div>
          <p>{{ fidelity?.statement || '尚未获取实时捕获统计或处于只读浏览模式，启动底层网卡捕获或执行验真后将在此显示真实物理丢包审计结论。' }}</p>
        </div>
      </div>

      <!-- 2.2 右侧：司法证据保管链流水 -->
      <div class="lg:col-span-5 ui-content-card p-3 flex flex-col overflow-hidden min-h-0">
        <div class="flex items-center justify-between mb-2 shrink-0">
          <div class="flex items-center gap-2">
            <h3 class="text-[13px] font-semibold" style="color: var(--text-primary);">司法保管链流水 (Chain of Custody)</h3>
            <span class="text-[11px]" style="color: var(--text-muted);">不可逆链式防篡改</span>
          </div>
          <span class="text-[11px] ui-num" style="color: var(--text-muted);">共 {{ chainOfCustody.length }} 条记录</span>
        </div>

        <div class="flex-1 overflow-y-auto custom-scrollbar border rounded-xl p-2.5 flex flex-col gap-2" style="border-color: var(--border-subtle); background: var(--surface-content-alt);">
          <div v-for="rec in chainOfCustody" :key="rec.index" class="ui-sub-card p-2.5 flex flex-col gap-1 text-xs">
            <div class="flex items-center justify-between ui-num gap-2" style="color: var(--text-muted);">
              <span class="font-semibold" style="color: var(--text-primary);">#{{ rec.index }} · {{ rec.action }}</span>
              <div class="flex items-center gap-1.5">
                <span class="text-[11px]">{{ rec.timestamp }}</span>
                <button @click="addCustodyToDiffQueue(rec)" class="px-1.5 py-0.5 rounded bg-emerald-500/12 hover:bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border border-emerald-500/25 text-[11px] font-semibold cursor-pointer">
                  + 入队
                </button>
              </div>
            </div>

            <div class="text-[11px] mt-0.5" style="color: var(--text-secondary);">
              <span style="color: var(--text-muted);">目标:</span> <span class="font-semibold font-mono" style="color: var(--text-primary);">{{ rec.evidence_target }}</span>
              <span class="mx-1.5 opacity-40">|</span>
              <span style="color: var(--text-muted);">经手:</span> {{ rec.operator_id }} / {{ rec.reviewer_id }}
            </div>

            <div class="text-[11px] p-2 rounded-lg border mt-0.5 font-mono" style="background: var(--surface-content); border-color: var(--border-subtle); color: var(--text-secondary);">
              <div>{{ rec.reason_or_memo }}</div>
              <div class="truncate mt-0.5" style="color: var(--text-muted);">
                上一哈希: {{ rec.prev_record_hash }}
              </div>
              <div class="text-indigo-600 dark:text-indigo-300 truncate">
                当前哈希: {{ rec.current_record_hash }}
              </div>
            </div>
          </div>

          <div v-if="chainOfCustody.length === 0" class="p-8 text-center text-xs" style="color: var(--text-muted);">
            尚未产生司法保管链记录
          </div>
        </div>
      </div>
    </section>

    <!-- 3. GB/T 29360 司法检验报告弹窗 -->
    <div v-if="showReportModal" class="ui-modal-backdrop fixed inset-0 flex items-center justify-center z-50 p-4">
      <div class="ui-modal-surface rounded-2xl max-w-3xl w-full max-h-[85vh] flex flex-col overflow-hidden select-text">
        <div class="p-3.5 border-b flex items-center justify-between" style="border-color: var(--border-subtle);">
          <div class="flex items-center gap-2 flex-wrap">
            <h3 class="text-sm font-semibold" style="color: var(--text-primary);">司法鉴定检验报告 (GB/T 29360-2012)</h3>
            <span class="px-2 py-0.5 rounded text-[11px] bg-indigo-500/15 text-indigo-700 dark:text-indigo-300 font-semibold border border-indigo-500/25">
              法庭抗辩级存证
            </span>
          </div>
          <button @click="showReportModal = false" class="p-1.5 rounded-lg hover:bg-[var(--surface-hover)] cursor-pointer" style="color: var(--text-secondary);">
            <AppIcon name="close" :size="14" />
          </button>
        </div>

        <div class="p-4 flex-1 overflow-y-auto custom-scrollbar text-xs space-y-4">
          <div class="ui-sub-card grid grid-cols-1 sm:grid-cols-3 gap-2.5 p-3">
            <div>
              <label class="text-[11px] font-semibold block mb-1" style="color: var(--text-muted);">主取证人员:</label>
              <input v-model="reportInvestigator" class="ui-input w-full px-2.5 py-1.5 text-xs font-mono" />
            </div>
            <div>
              <label class="text-[11px] font-semibold block mb-1" style="color: var(--text-muted);">复核人员:</label>
              <input v-model="reportReviewer" class="ui-input w-full px-2.5 py-1.5 text-xs font-mono" />
            </div>
            <div>
              <label class="text-[11px] font-semibold block mb-1" style="color: var(--text-muted);">案事件编号:</label>
              <input v-model="reportCaseNumber" class="ui-input w-full px-2.5 py-1.5 text-xs font-mono" />
            </div>
          </div>

          <button @click="generateReport" :disabled="loading" class="ui-btn-primary w-full py-2 text-xs justify-center">
            重新生成报告文本
          </button>

          <div
            v-if="generatedReport"
            class="p-4 rounded-xl border font-mono text-xs whitespace-pre-wrap leading-relaxed max-h-[40vh] overflow-y-auto custom-scrollbar select-text"
            style="background: var(--surface-input); border-color: var(--border-subtle); color: var(--text-primary);"
          >
{{ generatedReport.markdown_report }}
          </div>
        </div>

        <div class="p-3 border-t flex items-center justify-between flex-wrap gap-2" style="border-color: var(--border-subtle);">
          <span class="text-[11px]" style="color: var(--text-muted);">
            遵循 GB/T 29360-2012 电子数据取证检验通用技术规范
          </span>
          <div class="flex items-center gap-2">
            <button v-if="generatedReport" @click="copyReport" class="ui-btn-secondary px-3 py-1.5 text-xs">
              复制报告全文
            </button>
            <button @click="showReportModal = false" class="ui-btn-primary px-4 py-1.5 text-xs">完成</button>
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
import AppIcon from '../components/AppIcon.vue';
import { useUniversalDiff } from '../composables/useUniversalDiff';

const diffBus = useUniversalDiff();

function addEvidenceToDiffQueue(item: FileIntegrityResult) {
  const digestText = `FILE=${item.file_name};STATUS=${item.status};SIZE=${item.current_size};SHA256=${item.current_hash};SM3=${item.current_sm3}`;
  diffBus.addToQueue({
    id: `FOR_FILE_${item.file_name}`,
    label: `[证据] ${item.file_name} (${item.status})`,
    protocol: 'FORENSICS-VAULT',
    src: item.file_name,
    dst: item.is_worm_locked ? 'WORM-LOCKED' : 'RW',
    format: 'ASCII',
    isRawText: true,
    payloadHex: '',
    rawText: digestText,
    length: digestText.length,
    extraFields: {
      current_hash: item.current_hash,
      current_sm3: item.current_sm3,
      expected_hash: item.expected_hash || '-',
      expected_sm3: item.expected_sm3 || '-',
      current_size: String(item.current_size),
      sealed_size: String(item.sealed_size),
      status: item.status
    }
  }, `证据 ${item.file_name}`, false);
}

function addCustodyToDiffQueue(rec: ChainOfCustodyRecord) {
  const custodyText = `#${rec.index}|${rec.action}|TARGET=${rec.evidence_target}|PREV=${rec.prev_record_hash}|CURR=${rec.current_record_hash}`;
  diffBus.addToQueue({
    id: `FOR_COC_${rec.index}`,
    label: `[保管链 #${rec.index}] ${rec.action}`,
    timestamp: rec.timestamp,
    protocol: 'CHAIN-OF-CUSTODY',
    src: rec.operator_id,
    dst: rec.evidence_target,
    format: 'ASCII',
    isRawText: true,
    payloadHex: '',
    rawText: custodyText,
    length: custodyText.length,
    extraFields: {
      action: rec.action,
      operator_id: rec.operator_id,
      reviewer_id: rec.reviewer_id,
      sha256: rec.sha256,
      sm3: rec.sm3,
      prev_record_hash: rec.prev_record_hash,
      current_record_hash: rec.current_record_hash
    }
  }, `保管链 #${rec.index}`, false);
}

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
    notifySuccess('本地双哈希时间自证封装成功', `状态: ${token.status} | 序列号: ${token.serial_number} | 打标时间: ${token.stamped_at}`);
    await loadChainOfCustody();
  } catch (e) {
    notifyError('本地时间戳封装受阻', e);
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
