<template>
  <div v-if="isOpen" class="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-5 ui-modal-backdrop">
    <div class="w-full max-w-6xl max-h-[93vh] ui-modal-surface rounded-3xl flex flex-col overflow-hidden">
      <!-- 顶栏 (Liquid Glass) -->
      <header class="ui-nav-glass border-b px-6 py-3.5 flex items-center justify-between flex-wrap gap-3 shrink-0">
        <div class="flex items-center gap-3">
          <div class="w-9 h-9 rounded-xl bg-rose-500/15 border border-rose-500/30 flex items-center justify-center text-rose-700 dark:text-rose-300 shrink-0">
            <AppIcon name="shield" :size="18" />
          </div>
          <div>
            <h3 class="text-sm font-bold" style="color: var(--text-primary)">
              全环境 VPN 与加密代理隧道四维交叉侦测引擎
            </h3>
            <p class="text-[11px] ui-num mt-0.5" style="color: var(--text-muted)">
              终端网卡/路由/端口/进程/CA · 链路 DPI 协议指纹 · DFI 熵/χ²/MSS缩水 · 机房归属与主动代理探测
            </p>
          </div>
        </div>

        <div class="flex items-center gap-2 flex-wrap">
          <button
            @click="runFullAudit"
            :disabled="isScanning"
            class="ui-btn-primary px-3.5 py-1.5 rounded-xl text-xs font-semibold"
          >
            <AppIcon name="radar" :size="13" :class="isScanning ? 'animate-spin' : ''" />
            <span>{{ isScanning ? '多维侦测扫描中...' : '执行四维交叉侦测' }}</span>
          </button>
          <button
            @click="auditOfflinePcap"
            :disabled="isScanning"
            class="ui-btn-secondary px-3 py-1.5 rounded-xl text-xs font-semibold"
            title="导入离线 .pcap/.cap 抓包文件执行纯链路四维 VPN/代理隧道审计"
          >
            导入 .pcap 离线侦测
          </button>
          <button
            @click="resetLinkStats"
            :disabled="isScanning"
            class="ui-btn-secondary px-2.5 py-1.5 rounded-xl text-xs font-semibold"
            title="重置链路层 DPI/DFI/MSS 累计证据"
          >
            清空链路累计
          </button>
          <button
            @click="exportReport('markdown')"
            :disabled="!report"
            class="ui-btn-secondary px-2.5 py-1.5 rounded-xl text-xs font-semibold disabled:opacity-45"
          >
            导出 MD
          </button>
          <button
            @click="exportReport('html')"
            :disabled="!report"
            class="ui-btn-secondary px-2.5 py-1.5 rounded-xl text-xs font-semibold disabled:opacity-45"
          >
            导出 HTML
          </button>
          <button
            @click="$emit('close')"
            class="w-8 h-8 rounded-full ui-pill flex items-center justify-center cursor-pointer"
            title="关闭"
          >
            <AppIcon name="close" :size="15" />
          </button>
        </div>
      </header>

      <!-- 主内容滚动区 -->
      <div class="flex-1 overflow-y-auto custom-scrollbar p-5 space-y-4" style="background: var(--surface-content)">
        <div v-if="noticeMsg" class="ui-sub-card px-3 py-2 text-xs font-semibold" style="color: var(--accent-primary-text)">
          {{ noticeMsg }}
        </div>

        <template v-if="report">
          <!-- 1. 综合结论与四维得分横幅 -->
          <div class="ui-content-card p-4 space-y-3">
            <div class="flex items-center justify-between flex-wrap gap-3">
              <div class="flex items-center gap-3 flex-wrap">
                <span class="px-3 py-1 rounded-xl text-xs font-bold border" :class="verdictClass(report.verdict)">
                  {{ verdictLabel(report.verdict) }}
                </span>
                <div class="text-xs ui-num" style="color: var(--text-primary)">
                  综合置信度: <strong class="text-base">{{ report.overall_confidence }}%</strong>
                </div>
                <div class="text-[11px] ui-num" style="color: var(--text-muted)">
                  链路已审计 {{ report.link_telemetry.inspected_packets.toLocaleString() }} 帧 · 检出证据 {{ report.evidences.length }} 项
                </div>
              </div>
              <div class="text-[11px] ui-num" style="color: var(--text-muted)">
                扫描时刻: {{ new Date(report.scanned_at_ms).toLocaleTimeString('zh-CN', { hour12: false }) }}
              </div>
            </div>

            <div class="grid grid-cols-2 lg:grid-cols-4 gap-2.5 text-xs">
              <div class="ui-sub-card p-2.5">
                <div class="text-[10px]" style="color: var(--text-muted)">1. 终端本地扫描分</div>
                <div class="text-sm font-bold ui-num mt-0.5 text-sky-700 dark:text-sky-300">
                  {{ report.dimension_scores.host_local_score }} / 100
                </div>
              </div>
              <div class="ui-sub-card p-2.5">
                <div class="text-[10px]" style="color: var(--text-muted)">2. 链路 DPI 协议指纹分</div>
                <div class="text-sm font-bold ui-num mt-0.5 text-rose-700 dark:text-rose-300">
                  {{ report.dimension_scores.dpi_fingerprint_score }} / 100
                </div>
              </div>
              <div class="ui-sub-card p-2.5">
                <div class="text-[10px]" style="color: var(--text-muted)">3. DFI 随机度 & MSS 缩水分</div>
                <div class="text-sm font-bold ui-num mt-0.5 text-amber-700 dark:text-amber-300">
                  {{ report.dimension_scores.dfi_entropy_mss_score }} / 100
                </div>
              </div>
              <div class="ui-sub-card p-2.5">
                <div class="text-[10px]" style="color: var(--text-muted)">4. 机房 ASN / DoH 错位分</div>
                <div class="text-sm font-bold ui-num mt-0.5 text-indigo-700 dark:text-indigo-300">
                  {{ report.dimension_scores.geo_dns_mismatch_score }} / 100
                </div>
              </div>
            </div>

            <p class="text-[11px]" style="color: var(--text-muted)">
              {{ report.limitation_note }}
            </p>
          </div>

          <!-- 2. 四维交叉雷达图 + 归因方式置信度柱图 + 检出翻墙/VPN方式归因清单 -->
          <div class="grid grid-cols-1 lg:grid-cols-12 gap-3.5">
            <div class="lg:col-span-4 ui-content-card p-3.5 flex flex-col h-[270px]">
              <div class="text-xs font-bold mb-1" style="color: var(--text-primary)">四维交叉侦测可信度雷达图</div>
              <VChart :option="radarOption" autoresize class="flex-1 w-full min-h-[215px]" />
            </div>

            <div class="lg:col-span-4 ui-content-card p-3.5 flex flex-col h-[270px]">
              <div class="text-xs font-bold mb-1" style="color: var(--text-primary)">归因方式置信度与证据贡献柱图</div>
              <VChart v-if="report.detected_methods.length > 0" :option="methodBarOption" autoresize class="flex-1 w-full min-h-[215px]" />
              <EmptyState
                v-else
                class="flex-1 py-6"
                icon="check"
                title="暂无高风险归因柱状条目"
                description="检出可疑隧道方式后将自动绘制证据分布。"
              />
            </div>

            <div class="lg:col-span-4 ui-content-card p-3.5 flex flex-col h-[270px]">
              <div class="flex items-center justify-between mb-2">
                <span class="text-xs font-bold" style="color: var(--text-primary)">
                  识别到的 VPN / 翻墙技术方式 ({{ report.detected_methods.length }})
                </span>
                <span class="text-[10px] ui-num" style="color: var(--text-muted)">按置信度降序</span>
              </div>

              <div class="flex-1 overflow-y-auto custom-scrollbar space-y-2 pr-1">
                <div
                  v-for="(m, idx) in report.detected_methods"
                  :key="idx"
                  class="ui-sub-card p-2.5 text-xs space-y-1"
                >
                  <div class="flex items-center justify-between gap-2">
                    <span class="font-bold text-rose-700 dark:text-rose-300">{{ m.method_name }}</span>
                    <div class="flex items-center gap-2 text-[11px] ui-num">
                      <span class="px-1.5 py-0.5 rounded bg-rose-500/15 text-rose-700 dark:text-rose-300 font-bold">
                        置信度 {{ m.confidence_pct }}%
                      </span>
                      <span style="color: var(--text-muted)">{{ m.evidence_count }} 项依据</span>
                    </div>
                  </div>
                  <div class="text-[11px]" style="color: var(--text-secondary)">{{ m.rationale }}</div>
                  <div v-if="m.primary_endpoints.length > 0" class="text-[10px] font-mono truncate" style="color: var(--text-muted)">
                    样本/细节: {{ m.primary_endpoints.join(' | ') }}
                  </div>
                </div>

                <EmptyState
                  v-if="report.detected_methods.length === 0"
                  class="py-8"
                  icon="check"
                  title="未检出明确的 VPN 或代理隧道方式"
                  description="本机虚拟网卡、路由分流、系统代理、DPI 指纹及 DFI/MSS 均处于正常态。"
                />
              </div>
            </div>
          </div>

          <!-- 3. 终端本地环境详情 + 链路层遥测与主动代理验证 -->
          <div class="grid grid-cols-1 lg:grid-cols-2 gap-3.5">
            <div class="ui-content-card p-3.5 space-y-2.5 text-xs">
              <div class="font-bold flex items-center justify-between" style="color: var(--text-primary)">
                <span>终端本地底层环境扫描实况</span>
                <span class="text-[10px] ui-num" style="color: var(--text-muted)">
                  虚拟网卡 {{ report.local_env.virtual_adapters.length }} · 监听端口 {{ report.local_env.open_proxy_ports.length }} · 进程 {{ report.local_env.matched_processes.length }}
                </span>
              </div>

              <div class="space-y-1.5 text-[11px] ui-num" style="color: var(--text-secondary)">
                <div>
                  <strong>系统全局代理: </strong>
                  <span v-if="report.local_env.system_proxy_enabled" class="text-amber-700 dark:text-amber-300 font-bold">
                    已开启 ({{ report.local_env.system_proxy_server || report.local_env.system_pac_url }})
                  </span>
                  <span v-else class="text-emerald-700 dark:text-emerald-300">未开启</span>
                </div>
                <div>
                  <strong>路由表分流接管 (0.0.0.0/1 + 128.0.0.0/1): </strong>
                  <span :class="report.local_env.has_split_default_route ? 'text-rose-700 dark:text-rose-300 font-bold' : 'text-emerald-700 dark:text-emerald-300'">
                    {{ report.local_env.has_split_default_route ? '已接管全局路由' : '正常默认网关路由' }}
                  </span>
                </div>
                <div v-if="report.local_env.virtual_adapters.length > 0">
                  <strong>虚拟 TUN/TAP 接口: </strong>
                  <span>
                    {{ report.local_env.virtual_adapters.map((a) => `${a.name}[MTU=${a.mtu ?? '-'},IP=${a.ipv4 || '-'}]`).join('; ') }}
                  </span>
                </div>
                <div v-if="report.local_env.open_proxy_ports.length > 0">
                  <strong>本地开放代理端口: </strong>
                  <span>
                    {{ report.local_env.open_proxy_ports.map((p) => `127.0.0.1:${p.port}(${p.verified_protocol})`).join(', ') }}
                  </span>
                </div>
                <div v-if="report.local_env.matched_processes.length > 0">
                  <strong>代理/VPN 进程: </strong>
                  <span>{{ report.local_env.matched_processes.join(', ') }}</span>
                </div>
                <div v-if="report.local_env.kernel_tunnel_drivers.length > 0">
                  <strong>内核隧道驱动: </strong>
                  <span>{{ report.local_env.kernel_tunnel_drivers.join(', ') }}</span>
                </div>
                <div v-if="report.local_env.suspicious_root_certs.length > 0">
                  <strong>代理类自定义根证书: </strong>
                  <span>{{ report.local_env.suspicious_root_certs.join('; ') }}</span>
                </div>
              </div>
            </div>

            <!-- 链路层遥测统计 + 可控主动代理探测 -->
            <div class="ui-content-card p-3.5 space-y-2.5 text-xs">
              <div class="font-bold" style="color: var(--text-primary)">链路 DPI/DFI/MSS 遥测与主动代理探测</div>
              <div class="grid grid-cols-2 sm:grid-cols-3 gap-2 text-[11px] ui-num">
                <div class="ui-sub-card p-2">
                  <div style="color: var(--text-muted)">最小 TCP SYN MSS</div>
                  <div class="font-bold mt-0.5" :class="(report.link_telemetry.min_observed_syn_mss ?? 1500) <= 1410 ? 'text-rose-600 dark:text-rose-300' : ''" style="color: var(--text-primary)">
                    {{ report.link_telemetry.min_observed_syn_mss ? `${report.link_telemetry.min_observed_syn_mss} B` : '未捕获 SYN' }}
                  </div>
                </div>
                <div class="ui-sub-card p-2">
                  <div style="color: var(--text-muted)">高熵均匀流 (χ²)</div>
                  <div class="font-bold mt-0.5" style="color: var(--text-primary)">
                    {{ report.link_telemetry.uniform_random_cipher_hits }} 帧 / {{ report.link_telemetry.high_entropy_flows }} 流
                  </div>
                </div>
                <div class="ui-sub-card p-2">
                  <div style="color: var(--text-muted)">Fake-IP / DoH / DNS错位</div>
                  <div class="font-bold mt-0.5" style="color: var(--text-primary)">
                    {{ report.link_telemetry.fake_ip_connections }} / {{ report.link_telemetry.doh_dot_bypass_hits }} / {{ report.link_telemetry.dns_geo_mismatch_hits }}
                  </div>
                </div>
              </div>

              <!-- 主动协议探针 (SOCKS5 / HTTP CONNECT / RFC TLS) -->
              <div class="ui-sub-card p-2.5 space-y-2">
                <div class="text-[11px] font-bold" style="color: var(--text-primary)">可疑端口主动协议与 TLS 行为探测 (SOCKS5 / CONNECT / TLS)</div>
                <div class="flex items-center gap-2 flex-wrap">
                  <input v-model="probeHost" placeholder="127.0.0.1" class="ui-input ui-num w-36 px-2.5 py-1 text-xs" />
                  <input v-model.number="probePort" type="number" min="1" max="65535" placeholder="7890" class="ui-input ui-num w-24 px-2.5 py-1 text-xs" />
                  <button @click="runActiveProxyProbe" :disabled="isProbingEndpoint" class="ui-btn-primary px-3 py-1 rounded-lg text-xs">
                    {{ isProbingEndpoint ? '探测中...' : '验证代理/TLS 响应' }}
                  </button>
                </div>
                <div v-if="activeProbeResult" class="text-[11px] ui-num" style="color: var(--text-secondary)">
                  [{{ activeProbeResult.target }} · {{ activeProbeResult.rtt_ms }}ms · TLS={{ activeProbeResult.tls_probe_behavior }}]
                  <strong class="ml-1">{{ activeProbeResult.verdict_note }}</strong>
                  <span v-if="activeProbeResult.detected_banner" class="ml-1 font-mono">({{ activeProbeResult.detected_banner }})</span>
                </div>
              </div>
            </div>
          </div>

          <!-- 4. 全量实证证据链明细表 -->
          <div class="ui-content-card p-3.5 space-y-2">
            <div class="flex items-center justify-between flex-wrap gap-2">
              <span class="text-xs font-bold" style="color: var(--text-primary)">
                全量跨维证据链台账 ({{ filteredEvidences.length }})
              </span>
              <div class="flex items-center gap-1 ui-pill p-0.5 rounded-xl text-[11px]">
                <button
                  v-for="f in dimFilters"
                  :key="f.id"
                  @click="activeDimFilter = f.id"
                  :class="['px-2.5 py-0.5 rounded-lg cursor-pointer font-semibold', activeDimFilter === f.id ? 'bg-sky-600 text-white' : '']"
                  :style="activeDimFilter !== f.id ? { color: 'var(--text-secondary)' } : undefined"
                >
                  {{ f.label }}
                </button>
              </div>
            </div>

            <div class="max-h-56 overflow-y-auto custom-scrollbar ui-sub-card p-0">
              <table class="w-full text-left text-[11px] ui-num border-collapse">
                <thead class="ui-table-head sticky top-0">
                  <tr>
                    <th class="p-2">维度</th>
                    <th class="p-2">置信度</th>
                    <th class="p-2">归属方式</th>
                    <th class="p-2">实证摘要</th>
                    <th class="p-2">技术细节</th>
                  </tr>
                </thead>
                <tbody class="divide-y" style="border-color: var(--border-subtle); color: var(--text-secondary)">
                  <tr v-for="(ev, idx) in filteredEvidences" :key="idx" class="hover:bg-black/5 dark:hover:bg-white/5">
                    <td class="p-2 font-mono font-bold">{{ ev.dimension }}</td>
                    <td class="p-2 font-bold" :class="ev.confidence >= 85 ? 'text-rose-700 dark:text-rose-300' : 'text-amber-700 dark:text-amber-300'">
                      {{ ev.confidence }}%
                    </td>
                    <td class="p-2 font-semibold" style="color: var(--text-primary)">{{ ev.method_category }}</td>
                    <td class="p-2">{{ ev.summary }}</td>
                    <td class="p-2 font-mono break-all max-w-[260px]">{{ ev.detail }}</td>
                  </tr>
                  <tr v-if="filteredEvidences.length === 0">
                    <td colspan="5" class="p-6 text-center text-xs" style="color: var(--text-muted)">
                      当前筛选维度下暂无风险或隧道证据
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </template>

        <EmptyState
          v-else
          class="py-12"
          icon="radar"
          title="正在初始化 VPN / 代理隧道多维侦测引擎"
          description="请点击右上角【执行四维交叉侦测】开始全环境扫描。"
        />
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import { use } from 'echarts/core';
import { CanvasRenderer } from 'echarts/renderers';
import { RadarChart, BarChart } from 'echarts/charts';
import { TooltipComponent, GridComponent } from 'echarts/components';
import VChart from 'vue-echarts';
import type { EChartsOption } from 'echarts';
import AppIcon from './AppIcon.vue';
import EmptyState from './EmptyState.vue';

use([CanvasRenderer, RadarChart, BarChart, TooltipComponent, GridComponent]);

interface LocalVirtualAdapterItem {
  name: string;
  ipv4: string;
  mtu: number | null;
  matched_vendor: string;
}

interface LocalProxyPortItem {
  port: number;
  service_hint: string;
  verified_protocol: string;
}

interface LocalEnvironmentAudit {
  virtual_adapters: LocalVirtualAdapterItem[];
  has_split_default_route: boolean;
  route_flags: string[];
  system_proxy_enabled: boolean;
  system_proxy_server: string;
  system_pac_url: string;
  open_proxy_ports: LocalProxyPortItem[];
  matched_processes: string[];
  suspicious_root_certs: string[];
  kernel_tunnel_drivers: string[];
}

interface VpnEvidenceItem {
  dimension: string;
  method_category: string;
  confidence: number;
  summary: string;
  detail: string;
  timestamp_ms: number;
}

interface SuspectedTunnelMethod {
  method_name: string;
  confidence_pct: number;
  evidence_count: number;
  primary_endpoints: string[];
  rationale: string;
}

interface VpnDimensionScores {
  host_local_score: number;
  dpi_fingerprint_score: number;
  dfi_entropy_mss_score: number;
  geo_dns_mismatch_score: number;
}

interface VpnLinkTrafficTelemetry {
  inspected_packets: number;
  high_entropy_flows: number;
  uniform_random_cipher_hits: number;
  fake_ip_connections: number;
  mss_shrink_hits: number;
  min_observed_syn_mss: number | null;
  doh_dot_bypass_hits: number;
  dns_geo_mismatch_hits: number;
  datacenter_egress_ips: string[];
  observed_tunnel_protocols: Record<string, number>;
}

interface VpnDetectionReport {
  verdict: string;
  overall_confidence: number;
  dimension_scores: VpnDimensionScores;
  local_env: LocalEnvironmentAudit;
  link_telemetry: VpnLinkTrafficTelemetry;
  detected_methods: SuspectedTunnelMethod[];
  evidences: VpnEvidenceItem[];
  limitation_note: string;
  scanned_at_ms: number;
}

interface ActiveProxyProbeResult {
  target: string;
  socks5_supported: boolean;
  http_connect_supported: boolean;
  tls_handshake_supported: boolean;
  tls_probe_behavior: string;
  detected_banner: string;
  rtt_ms: number;
  verdict_note: string;
}

const props = defineProps<{
  isOpen: boolean;
}>();

defineEmits(['close']);

const isDarkTheme = ref(!document.documentElement.classList.contains('theme-apple-light'));
let themeObserver: MutationObserver | null = null;

const isScanning = ref(false);
const report = ref<VpnDetectionReport | null>(null);
const noticeMsg = ref('');

const activeDimFilter = ref<'ALL' | 'HOST_LOCAL' | 'LINK_DPI' | 'DFI_STAT_MSS' | 'GEO_DNS_RISK'>('ALL');
const dimFilters = [
  { id: 'ALL', label: '全部维度' },
  { id: 'HOST_LOCAL', label: '终端本地' },
  { id: 'LINK_DPI', label: '链路 DPI' },
  { id: 'DFI_STAT_MSS', label: 'DFI & MSS' },
  { id: 'GEO_DNS_RISK', label: '机房 & DoH' },
] as const;

const probeHost = ref('127.0.0.1');
const probePort = ref(7890);
const isProbingEndpoint = ref(false);
const activeProbeResult = ref<ActiveProxyProbeResult | null>(null);

const filteredEvidences = computed(() => {
  const list = report.value?.evidences || [];
  if (activeDimFilter.value === 'ALL') return list;
  return list.filter((e) => e.dimension === activeDimFilter.value);
});

const radarOption = computed<EChartsOption>(() => {
  const s = report.value?.dimension_scores;
  const labelColor = isDarkTheme.value ? '#cbd5e1' : '#334155';
  const splitLineColor = isDarkTheme.value ? 'rgba(148,163,184,0.2)' : 'rgba(100,116,139,0.22)';
  return {
    tooltip: { trigger: 'item', textStyle: { fontSize: 11 } },
    radar: {
      radius: '64%',
      indicator: [
        { name: '终端本地环境', max: 100 },
        { name: '链路 DPI 指纹', max: 100 },
        { name: 'DFI 熵与 MSS', max: 100 },
        { name: '机房/DNS 错位', max: 100 },
      ],
      axisName: { color: labelColor, fontSize: 11 },
      splitLine: { lineStyle: { color: splitLineColor } },
      splitArea: { show: false },
    },
    series: [
      {
        name: '四维风险评分',
        type: 'radar',
        areaStyle: { color: 'rgba(244, 63, 94, 0.25)' },
        lineStyle: { color: '#f43f5e', width: 2 },
        itemStyle: { color: '#f43f5e' },
        data: [
          {
            value: [
              s?.host_local_score ?? 0,
              s?.dpi_fingerprint_score ?? 0,
              s?.dfi_entropy_mss_score ?? 0,
              s?.geo_dns_mismatch_score ?? 0,
            ],
            name: '检出维度得分',
          },
        ],
      },
    ],
  };
});

const methodBarOption = computed<EChartsOption>(() => {
  const list = (report.value?.detected_methods || []).slice(0, 6).reverse();
  const labelColor = isDarkTheme.value ? '#cbd5e1' : '#334155';
  const splitColor = isDarkTheme.value ? 'rgba(148,163,184,0.16)' : 'rgba(100,116,139,0.18)';
  return {
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' }, textStyle: { fontSize: 11 } },
    grid: { left: 10, right: 18, top: 8, bottom: 20, containLabel: true },
    xAxis: {
      type: 'value',
      max: 100,
      axisLabel: { color: labelColor, fontSize: 10, formatter: '{value}%' },
      splitLine: { lineStyle: { color: splitColor } },
    },
    yAxis: {
      type: 'category',
      data: list.map((m) => (m.method_name.length > 16 ? `${m.method_name.slice(0, 15)}…` : m.method_name)),
      axisLabel: { color: labelColor, fontSize: 10 },
    },
    series: [
      {
        name: '归因置信度',
        type: 'bar',
        barWidth: 12,
        data: list.map((m) => m.confidence_pct),
        itemStyle: { color: '#f43f5e', borderRadius: [0, 4, 4, 0] },
      },
      {
        name: '实证证据条数',
        type: 'bar',
        barWidth: 8,
        data: list.map((m) => Math.min(100, m.evidence_count * 10)),
        itemStyle: { color: '#0284c7', borderRadius: [0, 4, 4, 0] },
      },
    ],
  };
});

function verdictLabel(v: string): string {
  if (v === 'CONFIRMED_VPN_OR_PROXY') return '已实证存在 VPN / 代理隧道';
  if (v === 'SUSPECTED_TUNNEL') return '高度疑似存在加密代理通道';
  return '未检出明显 VPN / 代理特征';
}

function verdictClass(v: string): string {
  if (v === 'CONFIRMED_VPN_OR_PROXY') return 'bg-rose-500/20 text-rose-700 dark:text-rose-300 border-rose-500/40';
  if (v === 'SUSPECTED_TUNNEL') return 'bg-amber-500/20 text-amber-700 dark:text-amber-300 border-amber-500/40';
  return 'bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border-emerald-500/40';
}

async function runFullAudit() {
  if (isScanning.value) return;
  isScanning.value = true;
  noticeMsg.value = '';
  try {
    report.value = await invoke<VpnDetectionReport>('run_vpn_environment_audit_cmd');
  } catch (e: unknown) {
    noticeMsg.value = `侦测执行异常: ${String(e)}`;
  } finally {
    isScanning.value = false;
  }
}

async function auditOfflinePcap() {
  if (isScanning.value) return;
  isScanning.value = true;
  noticeMsg.value = '';
  try {
    const res = await invoke<VpnDetectionReport | null>('audit_vpn_pcap_file_cmd', { includeLocalEnv: false });
    if (res) {
      report.value = res;
      noticeMsg.value = '已完成离线 .pcap/.cap 抓包文件的纯链路层 VPN/代理四维侦测';
    }
  } catch (e: unknown) {
    noticeMsg.value = `离线抓包侦测失败: ${String(e)}`;
  } finally {
    isScanning.value = false;
  }
}

async function resetLinkStats() {
  try {
    await invoke('reset_vpn_audit_stats_cmd');
    noticeMsg.value = '已重置链路层 VPN/代理统计状态';
    await runFullAudit();
  } catch (e: unknown) {
    noticeMsg.value = `重置失败: ${String(e)}`;
  }
}

async function runActiveProxyProbe() {
  if (!probeHost.value.trim() || !probePort.value) return;
  isProbingEndpoint.value = true;
  try {
    activeProbeResult.value = await invoke<ActiveProxyProbeResult>('probe_suspected_proxy_endpoint_cmd', {
      host: probeHost.value.trim(),
      port: probePort.value,
      timeoutMs: 1200,
    });
  } catch (e: unknown) {
    noticeMsg.value = `主动探测失败: ${String(e)}`;
  } finally {
    isProbingEndpoint.value = false;
  }
}

async function exportReport(format: 'markdown' | 'html') {
  if (!report.value) return;
  try {
    const path = await invoke<string | null>('export_vpn_audit_report_cmd', {
      report: report.value,
      format,
    });
    if (path) {
      noticeMsg.value = `审计报告已导出: ${path}`;
    }
  } catch (e: unknown) {
    noticeMsg.value = `导出报告失败: ${String(e)}`;
  }
}

watch(
  () => props.isOpen,
  (open) => {
    if (open) {
      runFullAudit();
    }
  }
);

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
