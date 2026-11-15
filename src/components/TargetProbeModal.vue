<template>
  <div v-if="isOpen" class="fixed inset-0 z-50 flex items-center justify-center p-4 ui-modal-backdrop">
    <div class="w-full max-w-4xl ui-modal-surface rounded-3xl flex flex-col overflow-hidden max-h-[92vh]">

      <!-- 顶栏 (Liquid Glass) -->
      <header class="ui-nav-glass border-b px-6 py-4 flex items-center justify-between shrink-0">
        <div class="flex items-center gap-2.5">
          <span class="w-3 h-3 rounded-full bg-amber-500 shrink-0"></span>
          <div>
            <h3 class="text-sm font-bold" style="color: var(--text-primary)">{{ t('targetProbe.title') }}</h3>
            <p class="text-[11px] ui-num mt-0.5" style="color: var(--text-muted)">
              {{ t('targetProbe.subtitle') }}
            </p>
          </div>
        </div>
        <button @click="$emit('close')" class="w-8 h-8 rounded-full ui-pill flex items-center justify-center cursor-pointer" :title="t('common.close')">
          <AppIcon name="close" :size="15" />
        </button>
      </header>

      <!-- 参数表单与动作区 -->
      <div class="p-5 space-y-4 overflow-auto custom-scrollbar" style="background: var(--surface-content)">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-3.5">
          <div>
            <label class="block text-xs font-bold mb-1" style="color: var(--text-secondary)">
              {{ t('targetProbe.targetIpLabel') }}
            </label>
            <input
              v-model="targetIp"
              :placeholder="t('targetProbe.targetIpPlaceholder')"
              class="w-full ui-input ui-num px-3 py-2 text-xs"
            />
          </div>
          <div>
            <div class="flex items-center justify-between mb-1">
              <label class="text-xs font-bold" style="color: var(--text-secondary)">{{ t('targetProbe.portExprLabel') }}</label>
              <div class="flex items-center gap-1 text-[10px]">
                <button
                  @click="targetPort = 'top25'"
                  class="px-1.5 py-0.5 rounded ui-pill hover:bg-sky-500/15 cursor-pointer font-semibold"
                  :title="t('targetProbe.presetTop25Title')"
                >
                  Top25
                </button>
                <button
                  @click="targetPort = 'ics'"
                  class="px-1.5 py-0.5 rounded ui-pill hover:bg-sky-500/15 cursor-pointer font-semibold"
                  :title="t('targetProbe.presetIcsTitle')"
                >
                  {{ t('targetProbe.presetIcs') }}
                </button>
                <button
                  @click="targetPort = 'db_admin'"
                  class="px-1.5 py-0.5 rounded ui-pill hover:bg-sky-500/15 cursor-pointer font-semibold"
                  :title="t('targetProbe.presetDbAdminTitle')"
                >
                  {{ t('targetProbe.presetDbAdmin') }}
                </button>
              </div>
            </div>
            <input
              v-model="targetPort"
              :placeholder="t('targetProbe.portExprPlaceholder')"
              class="w-full ui-input ui-num px-3 py-2 text-xs"
            />
          </div>
        </div>

        <div class="flex items-center gap-2.5 pt-0.5 flex-wrap">
          <button
            @click="doBatchBannerScan"
            :disabled="isProbing || !targetIp.trim() || !targetPort.trim()"
            class="flex-1 ui-btn-primary justify-center text-xs px-3.5 py-2.5 rounded-xl min-w-[190px]"
          >
            <AppIcon name="radar" :size="13" />
            <span>{{ isProbing ? t('targetProbe.scanning') : t('targetProbe.startScan') }}</span>
          </button>
          <label class="flex items-center gap-1.5 text-[11px] ui-pill px-2.5 py-2 rounded-xl cursor-pointer select-none" style="color: var(--text-secondary)" :title="t('targetProbe.includeUdpTitle')">
            <input type="checkbox" v-model="includeUdp" class="rounded" />
            <span>{{ t('targetProbe.includeUdp') }}</span>
          </label>
          <button
            @click="doPing"
            :disabled="isProbing || !targetIp.trim()"
            class="ui-btn-secondary justify-center text-xs px-3.5 py-2.5 rounded-xl font-semibold"
          >
            <AppIcon name="activity" :size="13" />
            <span>{{ t('targetProbe.pingSingle') }}</span>
          </button>
          <button
            @click="doTcpProbe"
            :disabled="isProbing || !targetIp.trim()"
            class="ui-btn-secondary justify-center text-xs px-3.5 py-2.5 rounded-xl font-semibold"
          >
            <AppIcon name="link" :size="13" />
            <span>{{ t('targetProbe.tcpSingle') }}</span>
          </button>
          <button @click="clearOutputs" class="ui-btn-secondary px-3 py-2.5 rounded-xl text-xs font-semibold">
            {{ t('targetProbe.clearScreen') }}
          </button>
        </div>

        <!-- 批量扫描结果图形与台账 -->
        <div v-if="scanSummary" class="ui-sub-card p-3.5 space-y-3">
          <div class="flex items-center justify-between flex-wrap gap-2">
            <div class="flex items-center gap-2">
              <span class="w-2 h-2 rounded-full bg-sky-500"></span>
              <span class="text-xs font-bold" style="color: var(--text-primary)">
                {{ t('targetProbe.statsLedger', { target: scanSummary.target_spec, port: scanSummary.port_spec }) }}
              </span>
            </div>
            <div class="flex items-center gap-3 text-[11px] ui-num" style="color: var(--text-secondary)">
              <span>{{ t('targetProbe.totalProbes') }}: <strong>{{ scanSummary.total_probes }}</strong></span>
              <span class="text-emerald-700 dark:text-emerald-300 font-bold">{{ t('targetProbe.openCount') }}: {{ scanSummary.open_count }}</span>
              <span :class="scanSummary.high_risk_count > 0 ? 'text-rose-700 dark:text-rose-300 font-bold' : ''">
                {{ t('targetProbe.highRiskCount') }}: {{ scanSummary.high_risk_count }}
              </span>
              <span>{{ t('targetProbe.avgRtt') }}: {{ scanSummary.avg_open_rtt_ms.toFixed(2) }}ms</span>
              <span>{{ t('targetProbe.duration') }}: {{ scanSummary.duration_ms }}ms</span>
            </div>
          </div>

          <p class="text-[10px]" style="color: var(--text-muted)">
            {{ t('targetProbe.probeMethodNote') }}: {{ scanSummary.probe_method_note }}
          </p>

          <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
            <!-- RTT 分布 ECharts 柱状图 -->
            <div class="ui-content-card p-2.5 flex flex-col h-[195px]">
              <div class="text-[11px] font-bold mb-1" style="color: var(--text-primary)">{{ t('targetProbe.rttDistTitle') }}</div>
              <v-chart :option="rttChartOption" autoresize class="flex-1 w-full min-h-[145px]" />
            </div>

            <!-- 开放端口与 Banner 明细表 -->
            <div class="md:col-span-2 ui-content-card p-0 overflow-hidden flex flex-col h-[195px]">
              <div class="overflow-auto custom-scrollbar flex-1">
                <table class="w-full text-left text-[11px] ui-num border-collapse">
                  <thead class="ui-table-head sticky top-0">
                    <tr>
                      <th class="p-1.5">{{ t('targetProbe.colHostIp') }}</th>
                      <th class="p-1.5 text-right">{{ t('targetProbe.colPort') }}</th>
                      <th class="p-1.5">{{ t('targetProbe.colProtocol') }}</th>
                      <th class="p-1.5 text-right">{{ t('targetProbe.colRtt') }}</th>
                      <th class="p-1.5">{{ t('targetProbe.colRisk') }}</th>
                      <th class="p-1.5">{{ t('targetProbe.colBanner') }}</th>
                    </tr>
                  </thead>
                  <tbody class="divide-y" style="border-color: var(--border-subtle); color: var(--text-secondary)">
                    <tr v-for="(item, idx) in scanSummary.open_items" :key="idx" class="hover:bg-black/5 dark:hover:bg-white/5">
                      <td class="p-1.5 font-mono font-bold">{{ item.ip }}</td>
                      <td class="p-1.5 text-right font-bold text-emerald-700 dark:text-emerald-300">{{ item.port }}</td>
                      <td class="p-1.5">{{ item.protocol }}</td>
                      <td class="p-1.5 text-right">{{ item.rtt_ms.toFixed(1) }}ms</td>
                      <td class="p-1.5">
                        <span
                          v-if="item.risk_flag"
                          class="px-1.5 py-0.5 rounded text-[10px] font-bold bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/30"
                        >
                          {{ item.risk_flag }}
                        </span>
                        <span v-else class="text-[10px]" style="color: var(--text-muted)">{{ t('targetProbe.normalRisk') }}</span>
                      </td>
                      <td class="p-1.5 font-mono truncate max-w-[220px]" :title="item.banner">
                        {{ item.banner || '-' }}
                      </td>
                    </tr>
                    <tr v-if="scanSummary.open_items.length === 0">
                      <td colspan="6" class="p-6 text-center text-xs" style="color: var(--text-muted)">
                        {{ t('targetProbe.emptyOpenTitle') }}
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>

        <!-- 连续心跳与拉流引擎卡片 -->
        <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div class="ui-sub-card p-3 space-y-2">
            <div class="flex items-center justify-between flex-wrap gap-2">
              <div class="flex items-center gap-2">
                <span class="w-2 h-2 rounded-full shrink-0" :class="continuousRunning ? 'bg-emerald-500' : 'bg-slate-400'"></span>
                <span class="text-xs font-bold" style="color: var(--text-primary)">{{ t('targetProbe.continuousProbe') }}</span>
              </div>
              <span v-if="continuousRunning" class="text-[10px] font-bold text-emerald-700 dark:text-emerald-300 bg-emerald-500/12 px-2 py-0.5 rounded-lg border border-emerald-500/25">{{ t('targetProbe.running') }}</span>
            </div>
            <div class="flex items-center gap-2 flex-wrap">
              <input v-model.number="continuousInterval" type="number" min="1" max="3600" :title="locale === 'en-US' ? 'Probe Interval (s)' : '探测周期（秒）'"
                class="w-16 ui-input ui-num px-2 py-1 text-xs" />
              <span class="text-[11px]" style="color: var(--text-muted)">{{ t('targetProbe.secPerTime') }}</span>
              <div class="flex-1"></div>
              <button v-if="!continuousRunning" @click="startContinuous" :disabled="isProbing || !targetIp.trim()"
                class="ui-btn-primary text-xs px-3 py-1 rounded-xl">
                {{ t('targetProbe.startHeartbeat') }}
              </button>
              <button v-else @click="stopAllEngines" class="ui-btn-danger text-xs px-3 py-1 rounded-xl">
                {{ t('targetProbe.stop') }}
              </button>
            </div>
          </div>

          <div class="ui-sub-card p-3 space-y-2">
            <div class="flex items-center justify-between flex-wrap gap-2">
              <div class="flex items-center gap-2">
                <span class="w-2 h-2 rounded-full shrink-0" :class="pullRunning ? 'bg-indigo-500' : 'bg-slate-400'"></span>
                <span class="text-xs font-bold" style="color: var(--text-primary)">{{ t('targetProbe.activePull') }}</span>
              </div>
              <span v-if="pullRunning" class="text-[10px] font-bold text-indigo-700 dark:text-indigo-300 bg-indigo-500/12 px-2 py-0.5 rounded-lg border border-indigo-500/25">{{ t('targetProbe.pulling') }}</span>
            </div>
            <div class="flex items-center gap-2 flex-wrap">
              <input v-model.number="pullReconnect" type="number" min="1" max="600" :title="locale === 'en-US' ? 'Reconnect Interval (s)' : '断线重连间隔（秒）'"
                class="w-16 ui-input ui-num px-2 py-1 text-xs" />
              <span class="text-[11px]" style="color: var(--text-muted)">{{ t('targetProbe.secReconnect') }}</span>
              <div class="flex-1"></div>
              <button v-if="!pullRunning" @click="startPull" :disabled="isProbing || !targetIp.trim()"
                class="ui-btn-primary text-xs px-3 py-1 rounded-xl">
                {{ t('targetProbe.startPull') }}
              </button>
              <button v-else @click="stopAllEngines" class="ui-btn-danger text-xs px-3 py-1 rounded-xl">
                {{ t('targetProbe.stop') }}
              </button>
            </div>
          </div>
        </div>

        <!-- 实时控制台日志输出 -->
        <div class="flex flex-col gap-1.5 select-text">
          <div class="flex items-center justify-between text-[11px] ui-num" style="color: var(--text-muted)">
            <span>{{ t('targetProbe.consoleLogs') }}</span>
            <span>{{ t('targetProbe.logRecordsCount', { n: logs.length }) }}</span>
          </div>
          <div ref="logBoxRef" class="ui-input font-mono-code p-3 text-xs h-40 overflow-auto space-y-1">
            <div v-for="(log, idx) in logs" :key="idx" :class="log.color || 'text-emerald-700 dark:text-emerald-400'" class="leading-relaxed">
              {{ log.text }}
            </div>
            <EmptyState
              v-if="logs.length === 0"
              class="py-5"
              icon="terminal"
              :title="t('targetProbe.emptyLogsTitle')"
              :description="t('targetProbe.emptyLogsDesc')"
            />
          </div>
        </div>
      </div>

      <!-- 底栏 -->
      <footer class="px-6 py-3 border-t flex items-center justify-between shrink-0 text-xs ui-num" style="background: var(--surface-content-alt); border-color: var(--border-subtle); color: var(--text-muted)">
        <span>{{ t('targetProbe.footerSummary') }}</span>
        <button @click="$emit('close')" class="ui-btn-secondary px-4 py-1.5 rounded-xl font-semibold">
          {{ locale === 'en-US' ? 'Close' : '关闭' }}
        </button>
      </footer>

    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, nextTick, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import { use } from 'echarts/core';
import { CanvasRenderer } from 'echarts/renderers';
import { BarChart } from 'echarts/charts';
import { GridComponent, TooltipComponent } from 'echarts/components';
import VChart from 'vue-echarts';
import type { EChartsOption } from 'echarts';
import AppIcon from './AppIcon.vue';
import { useI18n } from '../i18n';
import EmptyState from './EmptyState.vue';

use([CanvasRenderer, BarChart, GridComponent, TooltipComponent]);

const { t, locale } = useI18n();

interface ProbeResult {
  id: number;
  timestamp: string;
  target: string;
  protocol: string;
  status: string;
  latency_ms: number;
  payload_hex: string;
  detected_protocol: string;
}

interface NetworkPortScanItem {
  ip: string;
  port: number;
  status: string;
  protocol: string;
  rtt_ms: number;
  banner: string;
  is_high_risk: boolean;
  risk_flag: string | null;
}

interface RttHistogramBucket {
  label: string;
  count: number;
}

interface NetworkPortScanSummary {
  target_spec: string;
  port_spec: string;
  host_count: number;
  port_count: number;
  total_probes: number;
  open_count: number;
  closed_count: number;
  high_risk_count: number;
  avg_open_rtt_ms: number;
  max_open_rtt_ms: number;
  duration_ms: number;
  scanned_at_ms: number;
  probe_method_note: string;
  open_items: NetworkPortScanItem[];
  rtt_histogram: RttHistogramBucket[];
}

const props = defineProps<{
  isOpen: boolean;
  defaultIp?: string;
  defaultPort?: string | number;
}>();

defineEmits(['close']);

const isDarkTheme = ref(!document.documentElement.classList.contains('theme-apple-light'));
let themeObserver: MutationObserver | null = null;

const targetIp = ref(props.defaultIp || '');
const targetPort = ref(String(props.defaultPort || '80,443,22,502'));
const includeUdp = ref(true);
const isProbing = ref(false);
const logs = ref<Array<{ text: string; color?: string }>>([]);
const logBoxRef = ref<HTMLElement | null>(null);
const scanSummary = ref<NetworkPortScanSummary | null>(null);

const continuousRunning = ref(false);
const continuousInterval = ref(5);
const pullRunning = ref(false);
const pullReconnect = ref(5);

watch(() => props.isOpen, (open) => {
  if (open) {
    if (props.defaultIp) targetIp.value = props.defaultIp;
    if (props.defaultPort) targetPort.value = String(props.defaultPort);
  }
});

const rttChartOption = computed<EChartsOption>(() => {
  const hist = scanSummary.value?.rtt_histogram || [];
  const labelColor = isDarkTheme.value ? '#94a3b8' : '#475569';
  const splitColor = isDarkTheme.value ? 'rgba(148,163,184,0.14)' : 'rgba(100,116,139,0.2)';
  return {
    tooltip: {
      trigger: 'axis',
      textStyle: { fontSize: 11 },
    },
    grid: { top: 12, right: 10, bottom: 26, left: 32 },
    xAxis: {
      type: 'category',
      data: hist.map((b) => b.label),
      axisLabel: { color: labelColor, fontSize: 9 },
    },
    yAxis: {
      type: 'value',
      minInterval: 1,
      axisLabel: { color: labelColor, fontSize: 10 },
      splitLine: { lineStyle: { color: splitColor, type: 'dashed' } },
    },
    series: [
      {
        name: locale.value === 'en-US' ? 'Open Ports' : '开放端口数',
        type: 'bar',
        itemStyle: { color: '#0ea5e9', borderRadius: [3, 3, 0, 0] },
        data: hist.map((b) => b.count),
      },
    ],
  };
});

function appendLog(text: string, color = 'text-emerald-700 dark:text-emerald-400') {
  const ts = new Date().toLocaleTimeString('zh-CN', { hour12: false });
  logs.value.push({ text: `[${ts}] ${text}`, color });
  nextTick(() => {
    if (logBoxRef.value) {
      logBoxRef.value.scrollTop = logBoxRef.value.scrollHeight;
    }
  });
}

function clearOutputs() {
  logs.value = [];
  scanSummary.value = null;
}

function firstIp(): string {
  const raw = targetIp.value.trim();
  const base = raw.split('/')[0].split('-')[0].split(',')[0].trim();
  return base;
}

function firstPort(): number | null {
  const raw = targetPort.value.trim().toLowerCase();
  if (raw === 'top25') return 80;
  if (raw === 'ics') return 502;
  if (raw === 'db_admin') return 22;
  const firstToken = raw.split(',')[0].split('-')[0].trim();
  const p = parseInt(firstToken, 10);
  return !isNaN(p) && p > 0 && p <= 65535 ? p : null;
}

async function doBatchBannerScan() {
  const spec = targetIp.value.trim();
  const portSpec = targetPort.value.trim();
  if (!spec || !portSpec) return;

  isProbing.value = true;
  appendLog(locale.value === 'en-US' ? `[*] Starting concurrent scan: Target=[${spec}], Ports=[${portSpec}] (Semaphore=64, Readonly Banner)...` : `[*] 正在启动并发扫描: 目标=[${spec}], 端口=[${portSpec}] (信号量限流=64, 附只读 Banner 提取)...`, 'text-sky-700 dark:text-sky-300');

  try {
    const res = await invoke<NetworkPortScanSummary>('run_network_port_scan_cmd', {
      targetSpec: spec,
      portSpec,
      timeoutMs: 650,
      includeClosed: false,
      includeUdp: includeUdp.value,
    });
    scanSummary.value = res;
    appendLog(
      locale.value === 'en-US' ? `[+] Scan complete: Probed ${res.total_probes} items, ${res.open_count} open, ${res.high_risk_count} high-risk, Elapsed ${res.duration_ms}ms` : `[+] 扫描完成: 共探测 ${res.total_probes} 项, 开放 ${res.open_count} 个, 高危 ${res.high_risk_count} 个, 耗时 ${res.duration_ms}ms`,
      res.high_risk_count > 0 ? 'text-amber-700 dark:text-amber-300 font-bold' : 'text-emerald-700 dark:text-emerald-300 font-bold'
    );
    for (const item of res.open_items.slice(0, 12)) {
      const bannerTxt = item.banner ? ` | Banner: ${item.banner}` : '';
      const riskTxt = item.risk_flag ? ` [${item.risk_flag}]` : '';
      appendLog(
        `    OPEN ${item.ip}:${item.port} (${item.protocol}, ${item.rtt_ms.toFixed(1)}ms)${riskTxt}${bannerTxt}`,
        item.is_high_risk ? 'text-rose-700 dark:text-rose-300' : 'text-emerald-700 dark:text-emerald-400'
      );
    }
  } catch (e: unknown) {
    appendLog(locale.value === 'en-US' ? `[-] Concurrent scan aborted: ${String(e)}` : `[-] 并发扫描中止: ${String(e)}`, 'text-rose-700 dark:text-rose-400');
  } finally {
    isProbing.value = false;
  }
}

async function doPing() {
  const ip = firstIp();
  if (!ip) return;
  isProbing.value = true;
  appendLog(locale.value === 'en-US' ? `[*] Transmitting ICMP echo probe to ${ip} (L3 Ping)...` : `[*] 正在向 ${ip} 发射 ICMP 回显探针 (真实物理层 Ping)...`, 'text-sky-700 dark:text-sky-300');

  try {
    const res = await invoke<ProbeResult>('run_icmp_ping_cmd', { targetIp: ip, timeoutMs: 3000 });
    if (res.status === 'ONLINE') {
      appendLog(locale.value === 'en-US' ? `[+] ICMP Echo reply: ${res.target} alive (RTT: ${res.latency_ms.toFixed(1)}ms)` : `[+] ICMP 应答成功: ${res.target} 存活 (RTT: ${res.latency_ms.toFixed(1)}ms)`, 'text-emerald-700 dark:text-emerald-300 font-bold');
      if (res.payload_hex) {
        appendLog(locale.value === 'en-US' ? `    Reply Payload: ${res.payload_hex}` : `    应答载荷: ${res.payload_hex}`, 'text-[var(--text-secondary)]');
      }
    } else if (res.status === 'TIMEOUT') {
      appendLog(locale.value === 'en-US' ? `[!] ICMP Probe timeout: ${ip} no response (Target offline or firewall filtered)` : `[!] ICMP 探针超时: ${ip} 无应答 (目标离线或防火墙丢弃回显)`, 'text-amber-700 dark:text-amber-300');
    } else {
      appendLog(locale.value === 'en-US' ? `[-] ICMP Probe failed: ${ip} status=${res.status} (RTT: ${res.latency_ms.toFixed(1)}ms)` : `[-] ICMP 探测失败: ${ip} 状态=${res.status} (RTT: ${res.latency_ms.toFixed(1)}ms)`, 'text-rose-700 dark:text-rose-400');
    }
  } catch (e: unknown) {
    appendLog(locale.value === 'en-US' ? `[-] ICMP Probe exception: ${String(e)}` : `[-] ICMP 探测异常: ${String(e)}`, 'text-rose-700 dark:text-rose-400');
  } finally {
    isProbing.value = false;
  }
}

async function doTcpProbe() {
  const ip = firstIp();
  const portStr = targetPort.value.trim();
  if (!ip) return;

  const ports = portStr.split(',').map((p) => parseInt(p.trim(), 10)).filter((p) => !isNaN(p) && p > 0 && p <= 65535);
  if (ports.length === 0) {
    appendLog(locale.value === 'en-US' ? `[!] Single target mode requires comma-separated numeric ports, or use Concurrent Scan for ranges.` : `[!] 单目标模式请使用逗号分隔纯数字端口，或点击【并发网段与 Banner 扫描】支持区间与模板`, 'text-amber-700 dark:text-amber-300');
    return;
  }

  isProbing.value = true;
  appendLog(locale.value === 'en-US' ? `[*] Probing TCP 3-way handshake on ${ip} ports [${ports.join(', ')}]...` : `[*] 正在向 ${ip} 目标端口 [${ports.join(', ')}] 发起 TCP 三次握手事件探测...`, 'text-sky-700 dark:text-sky-300');

  const targets = ports.map((port) => ({ ip, port }));
  try {
    await invoke('run_target_scan_cmd', { targets, timeoutMs: 2500 });
    appendLog(locale.value === 'en-US' ? `[*] Handshake probe dispatched, observing receipts in event stream...` : `[*] 靶向握手探测指令已下发，请留意系统日志流中的实时握手回执...`, 'text-[var(--text-secondary)]');
  } catch (e: unknown) {
    appendLog(locale.value === 'en-US' ? `[-] Port probe failed: ${String(e)}` : `[-] 端口探测失败: ${String(e)}`, 'text-rose-700 dark:text-rose-400');
  } finally {
    isProbing.value = false;
  }
}

async function startContinuous() {
  const ip = firstIp();
  const port = firstPort();
  if (!ip || !port) {
    appendLog(locale.value === 'en-US' ? `[!] Error: Specify valid single target IP and port first` : `[!] 错误: 请先填写有效的单目标 IP 与端口`, 'text-rose-700 dark:text-rose-400');
    return;
  }
  try {
    const res = await invoke<string>('start_continuous_probe_cmd', {
      host: ip,
      port,
      intervalSecs: continuousInterval.value,
    });
    continuousRunning.value = true;
    appendLog(res, 'text-emerald-700 dark:text-emerald-300 font-bold');
  } catch (e: unknown) {
    appendLog(locale.value === 'en-US' ? `[-] Heartbeat probe failed to start: ${String(e)}` : `[-] 心跳探针启动失败: ${String(e)}`, 'text-rose-700 dark:text-rose-400');
  }
}

async function startPull() {
  const ip = firstIp();
  const port = firstPort();
  if (!ip || !port) {
    appendLog(locale.value === 'en-US' ? `[!] Error: Specify valid single target IP and port first` : `[!] 错误: 请先填写有效的单目标 IP 与端口`, 'text-rose-700 dark:text-rose-400');
    return;
  }
  try {
    const res = await invoke<string>('start_stream_pull_cmd', {
      host: ip,
      port,
      reconnectSecs: pullReconnect.value,
    });
    pullRunning.value = true;
    appendLog(res, 'text-indigo-700 dark:text-indigo-300 font-bold');
  } catch (e: unknown) {
    appendLog(locale.value === 'en-US' ? `[-] Pull stream engine failed to start: ${String(e)}` : `[-] 拉流引擎启动失败: ${String(e)}`, 'text-rose-700 dark:text-rose-400');
  }
}

async function stopAllEngines() {
  if (continuousRunning.value) {
    try {
      const res = await invoke<string>('stop_continuous_probe_cmd');
      appendLog(res, 'text-[var(--text-secondary)]');
    } catch (e: unknown) {
      appendLog(locale.value === 'en-US' ? `[-] Failed to stop heartbeat probe: ${String(e)}` : `[-] 停止心跳探针失败: ${String(e)}`, 'text-rose-700 dark:text-rose-400');
    }
    continuousRunning.value = false;
  }
  if (pullRunning.value) {
    try {
      const res = await invoke<string>('stop_stream_pull_cmd');
      appendLog(res, 'text-[var(--text-secondary)]');
    } catch (e: unknown) {
      appendLog(locale.value === 'en-US' ? `[-] Failed to stop stream pull: ${String(e)}` : `[-] 停止拉流失败: ${String(e)}`, 'text-rose-700 dark:text-rose-400');
    }
    pullRunning.value = false;
  }
}

onMounted(() => {
  themeObserver = new MutationObserver(() => {
    isDarkTheme.value = !document.documentElement.classList.contains('theme-apple-light');
  });
  themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });
});

onUnmounted(() => {
  if (themeObserver) {
    themeObserver.disconnect();
    themeObserver = null;
  }
});
</script>
