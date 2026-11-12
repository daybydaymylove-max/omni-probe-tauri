<template>
  <div class="flex-1 flex flex-col gap-2.5 h-full overflow-hidden min-h-0">
    <!-- 顶部控制、模式切换与多维基准工具栏 -->
    <div class="ui-content-card p-3 flex flex-col gap-2.5 shrink-0">
      <div class="flex items-center justify-between flex-wrap gap-2">
        <div class="flex items-center gap-2 flex-wrap">
          <span class="w-2.5 h-2.5 rounded-full bg-sky-500"></span>
          <h3 class="text-xs font-bold" style="color: var(--text-primary)">
            IO Graphs 多维流量分析与基线对比引擎
          </h3>
          <div class="flex ui-pill p-0.5 rounded-xl text-[11px] font-semibold">
            <button
              @click="activePanelMode = 'timeseries'"
              :class="[
                'px-2.5 py-1 rounded-lg transition-colors cursor-pointer',
                activePanelMode === 'timeseries' ? 'bg-sky-600 text-white shadow-xs font-bold' : 'hover:bg-black/5 dark:hover:bg-white/5',
              ]"
              :style="activePanelMode !== 'timeseries' ? { color: 'var(--text-secondary)' } : undefined"
            >
              时序曲线与点阵
            </button>
            <button
              @click="switchToMultidim"
              :class="[
                'px-2.5 py-1 rounded-lg transition-colors cursor-pointer',
                activePanelMode === 'multidim' ? 'bg-indigo-600 text-white shadow-xs font-bold' : 'hover:bg-black/5 dark:hover:bg-white/5',
              ]"
              :style="activePanelMode !== 'multidim' ? { color: 'var(--text-secondary)' } : undefined"
            >
              多维统计画像 ({{ totalAnalyzedPackets }})
            </button>
            <button
              @click="activePanelMode = 'compare'"
              :class="[
                'px-2.5 py-1 rounded-lg transition-colors cursor-pointer',
                activePanelMode === 'compare' ? 'bg-emerald-600 text-white shadow-xs font-bold' : 'hover:bg-black/5 dark:hover:bg-white/5',
              ]"
              :style="activePanelMode !== 'compare' ? { color: 'var(--text-secondary)' } : undefined"
            >
              基线 / .pcap 对比
            </button>
          </div>
        </div>

        <div class="flex items-center gap-1.5 text-xs flex-wrap">
          <button
            @click="saveBaseline"
            :disabled="isBaselineBusy || !hasAnyTraffic"
            class="ui-btn-secondary px-2.5 py-1 rounded-xl text-[11px] font-semibold disabled:opacity-45"
            title="将当前实时流量分布固化为本地黄金基线文件"
          >
            固化网络基线
          </button>
          <button
            @click="compareWithBaseline"
            :disabled="isBaselineBusy || !hasAnyTraffic"
            class="ui-btn-secondary px-2.5 py-1 rounded-xl text-[11px] font-semibold disabled:opacity-45"
            title="将当前实时流量与已保存的黄金基线进行对比"
          >
            对比黄金基线
          </button>
          <button
            @click="compareWithPcapFile"
            :disabled="isBaselineBusy || !hasAnyTraffic"
            class="ui-btn-secondary px-2.5 py-1 rounded-xl text-[11px] font-semibold disabled:opacity-45"
            title="选择本地历史 .pcap 文件与当前实时捕获进行双样本对账"
          >
            导入 .pcap 对比
          </button>
          <button
            @click="exportAuditReport('markdown')"
            :disabled="!hasAnyTraffic"
            class="ui-btn-secondary px-2 py-1 rounded-xl text-[11px] font-semibold disabled:opacity-45"
            title="导出 Markdown 格式网络统计与安全审计报告"
          >
            导出 MD
          </button>
          <button
            @click="exportAuditReport('html')"
            :disabled="!hasAnyTraffic"
            class="ui-btn-secondary px-2 py-1 rounded-xl text-[11px] font-semibold disabled:opacity-45"
            title="导出全转义自包含 HTML 网络统计与安全审计报告"
          >
            导出 HTML
          </button>
        </div>
      </div>

      <!-- 时序控杆行 + 状态提示 -->
      <div class="flex items-center justify-between flex-wrap gap-2">
        <div class="flex items-center gap-2 text-xs flex-wrap">
          <div class="flex ui-pill p-0.5 rounded-xl text-xs font-semibold">
            <button
              @click="activeMetric = 'pps'"
              :class="[
                'px-2.5 py-1 rounded-lg transition-colors cursor-pointer',
                activeMetric === 'pps' ? 'bg-sky-500 text-white shadow-xs font-bold' : 'hover:bg-black/5 dark:hover:bg-white/5',
              ]"
              :style="activeMetric !== 'pps' ? { color: 'var(--text-secondary)' } : undefined"
            >
              包率 (PPS)
            </button>
            <button
              @click="activeMetric = 'bandwidth'"
              :class="[
                'px-2.5 py-1 rounded-lg transition-colors cursor-pointer',
                activeMetric === 'bandwidth' ? 'bg-emerald-600 text-white shadow-xs font-bold' : 'hover:bg-black/5 dark:hover:bg-white/5',
              ]"
              :style="activeMetric !== 'bandwidth' ? { color: 'var(--text-secondary)' } : undefined"
            >
              带宽 (KB/s)
            </button>
            <button
              @click="activeMetric = 'rtt'"
              :class="[
                'px-2.5 py-1 rounded-lg transition-colors cursor-pointer',
                activeMetric === 'rtt' ? 'bg-indigo-600 text-white shadow-xs font-bold' : 'hover:bg-black/5 dark:hover:bg-white/5',
              ]"
              :style="activeMetric !== 'rtt' ? { color: 'var(--text-secondary)' } : undefined"
            >
              TCP RTT (ms)
            </button>
            <button
              @click="activeMetric = 'retrans'"
              :class="[
                'px-2.5 py-1 rounded-lg transition-colors cursor-pointer',
                activeMetric === 'retrans' ? 'bg-rose-600 text-white shadow-xs font-bold' : 'hover:bg-black/5 dark:hover:bg-white/5',
              ]"
              :style="activeMetric !== 'retrans' ? { color: 'var(--text-secondary)' } : undefined"
            >
              重传异常
            </button>
          </div>

          <select
            v-model="selectedBusFilter"
            @change="fetchData"
            class="ui-input w-auto px-2.5 py-1 text-xs cursor-pointer"
            title="选择聚合的物理或网络总线来源"
          >
            <option value="ALL">全部总线 (综合)</option>
            <option value="ETHERNET">网卡以太网 (NIC)</option>
            <option value="SERIAL">COM 物理串口</option>
            <option value="USB">USB 控制器总线</option>
            <option value="WIRELESS">Wi-Fi / 蓝牙无线</option>
          </select>

          <select
            v-model.number="selectedWindow"
            @change="fetchData"
            class="ui-input ui-num w-auto px-2.5 py-1 text-xs cursor-pointer"
          >
            <option :value="30">近 30 秒</option>
            <option :value="60">近 60 秒</option>
            <option :value="120">近 120 秒</option>
            <option :value="300">近 300 秒</option>
          </select>

          <button
            @click="toggleAutoRefresh"
            :class="[
              'px-2.5 py-1 rounded-xl text-xs font-semibold border transition-colors cursor-pointer flex items-center gap-1.5',
              isAutoRefreshing ? 'bg-sky-500/15 text-sky-700 dark:text-sky-300 border-sky-500/35' : 'ui-pill',
            ]"
          >
            <span class="w-1.5 h-1.5 rounded-full" :class="isAutoRefreshing ? 'bg-sky-500' : 'bg-slate-400'"></span>
            <span>{{ isAutoRefreshing ? '自动刷新 (1s)' : '自动刷新: 关' }}</span>
          </button>

          <button @click="refreshAll" :disabled="isLoading" class="ui-btn-secondary px-2.5 py-1 rounded-xl text-xs">
            <AppIcon name="refresh" :size="12" :class="isLoading ? 'animate-spin' : ''" />
            <span>刷新</span>
          </button>
        </div>

        <div v-if="actionNotice" class="text-[11px] font-semibold px-2.5 py-1 rounded-lg ui-sub-card" style="color: var(--accent-primary-text)">
          {{ actionNotice }}
        </div>
      </div>

      <!-- 4 核心摘要卡片 -->
      <div v-if="seriesData" class="grid grid-cols-2 gap-2 text-xs">
        <div class="ui-sub-card bg-blue-500/8 border-blue-500/25 p-2">
          <div class="text-[10px] text-blue-700 dark:text-sky-300 font-bold uppercase truncate">窗口吞吐 / 报文总数</div>
          <div class="text-xs font-bold ui-num mt-0.5 truncate" style="color: var(--text-primary)">
            {{ formatBytes(summaryStats.totalBytes) }} / {{ summaryStats.totalPackets }} 帧
          </div>
        </div>
        <div class="ui-sub-card bg-emerald-500/8 border-emerald-500/25 p-2">
          <div class="text-[10px] text-emerald-700 dark:text-emerald-300 font-bold uppercase truncate">包率 (PPS: 均值 / 峰值)</div>
          <div class="text-xs font-bold ui-num mt-0.5 truncate" style="color: var(--text-primary)">
            {{ summaryStats.avgPps.toFixed(1) }} / <span class="text-emerald-700 dark:text-emerald-400">{{ summaryStats.maxPps }} pps</span>
          </div>
        </div>
        <div class="ui-sub-card bg-indigo-500/8 border-indigo-500/25 p-2">
          <div class="text-[10px] text-indigo-700 dark:text-indigo-300 font-bold uppercase truncate">带宽 (均值 / 峰值)</div>
          <div class="text-xs font-bold ui-num mt-0.5 truncate" style="color: var(--text-primary)">
            {{ formatBytes(summaryStats.avgBps) }}/s / <span class="text-indigo-700 dark:text-indigo-400">{{ formatBytes(summaryStats.maxBps) }}/s</span>
          </div>
        </div>
        <div class="ui-sub-card bg-purple-500/8 border-purple-500/25 p-2">
          <div class="text-[10px] text-purple-700 dark:text-purple-300 font-bold uppercase truncate">TCP RTT / 包间隔 MAD 抖动</div>
          <div class="text-xs font-bold ui-num mt-0.5 truncate" style="color: var(--text-primary)">
            {{ summaryStats.avgRttMs.toFixed(2) }}ms / <span class="text-purple-700 dark:text-purple-300">{{ trafficStats?.jitter_ms?.toFixed(2) ?? '0.00' }}ms</span>
          </div>
        </div>
      </div>
    </div>

    <!-- 主内容视图 1: ECharts 高精时序曲线 + 基线对照 + 点阵明细 -->
    <div v-if="activePanelMode === 'timeseries'" class="flex-1 ui-content-card p-3 flex flex-col min-h-0 overflow-hidden">
      <div class="flex items-center justify-between text-xs ui-num mb-2 shrink-0 flex-wrap gap-2" style="color: var(--text-secondary)">
        <div class="flex items-center gap-2 flex-wrap">
          <span class="text-sky-700 dark:text-sky-400 font-bold">当前曲线: {{ metricTitle }}</span>
          <span style="color: var(--border-strong)">|</span>
          <span>时间跨度: {{ selectedWindow }} 秒</span>
          <span style="color: var(--border-strong)">|</span>
          <span>采样点: {{ validBuckets.length }} 点</span>
          <span v-if="savedBaseline" class="text-amber-700 dark:text-amber-300 font-semibold">
            | 黄金基线均值参考已叠加 ({{ savedBaseline.name }})
          </span>
        </div>
      </div>

      <div class="flex-1 relative min-h-[190px] w-full">
        <v-chart
          v-if="validBuckets.length > 1"
          :option="timeSeriesOption"
          autoresize
          class="w-full h-full min-h-[190px]"
        />
        <EmptyState
          v-else
          class="h-full py-6"
          icon="activity"
          title="正在捕获并聚合时序采样点"
          description="请等待数据包流入并生成 2 个以上连续时间桶，或点击上方【刷新】按钮。"
        />
      </div>

      <!-- 底部时序点阵数据明细折叠表 (保持既有交互与检索关键字) -->
      <div class="mt-2 border-t pt-2 shrink-0" style="border-color: var(--border-subtle)">
        <div class="flex items-center justify-between text-[11px] mb-1.5" style="color: var(--text-secondary)">
          <span class="font-bold">秒级时序点阵明细流水 (最近 {{ validBuckets.length }} 秒桶)</span>
          <button
            @click="showTable = !showTable"
            class="font-semibold hover:underline cursor-pointer flex items-center gap-1"
            style="color: var(--accent-primary-text)"
          >
            <span>{{ showTable ? '收起明细' : '展开点阵明细' }}</span>
            <AppIcon :name="showTable ? 'chevron-up' : 'chevron-down'" :size="12" />
          </button>
        </div>

        <div v-if="showTable" class="max-h-36 overflow-auto custom-scrollbar ui-sub-card p-0 select-text">
          <table class="w-full text-left text-[11px] ui-num border-collapse table-fixed">
            <thead class="ui-table-head sticky top-0">
              <tr>
                <th class="p-1.5 w-[20%]">时间点</th>
                <th class="p-1.5 w-[20%] text-right">包数量 (PPS)</th>
                <th class="p-1.5 w-[20%] text-right">吞吐量 (BPS)</th>
                <th class="p-1.5 w-[20%] text-right">TCP RTT (ms)</th>
                <th class="p-1.5 w-[20%] text-right">重传计数</th>
              </tr>
            </thead>
            <tbody class="divide-y" style="border-color: var(--border-subtle); color: var(--text-secondary)">
              <tr v-for="b in validBuckets.slice().reverse()" :key="b.timestamp_sec" class="hover:bg-black/5 dark:hover:bg-white/5">
                <td class="p-1.5 truncate">{{ b.time_str }}</td>
                <td class="p-1.5 text-right font-bold text-blue-700 dark:text-sky-400">{{ b.packet_count }}</td>
                <td class="p-1.5 text-right text-emerald-700 dark:text-emerald-400">{{ formatBytes(b.byte_count) }}</td>
                <td class="p-1.5 text-right" :class="b.avg_rtt_ms > 50 ? 'text-amber-700 dark:text-amber-400 font-bold' : ''">
                  {{ b.avg_rtt_ms.toFixed(2) }}
                </td>
                <td
                  class="p-1.5 text-right"
                  :class="b.retrans_count > 0 ? 'text-rose-700 dark:text-rose-400 font-bold' : ''"
                  :style="b.retrans_count === 0 ? { color: 'var(--text-muted)' } : undefined"
                >
                  {{ b.retrans_count }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- 主内容视图 2: Wireshark 级多维流量统计面板 -->
    <div v-else-if="activePanelMode === 'multidim'" class="flex-1 ui-content-card p-3 flex flex-col gap-3 min-h-0 overflow-y-auto custom-scrollbar">
      <div v-if="trafficStats && trafficStats.total_packets > 0" class="flex flex-col gap-3">
        <!-- 统计 KPI 指标条 -->
        <div class="grid grid-cols-2 gap-2 text-xs">
          <div class="ui-sub-card p-2">
            <div class="text-[10px]" style="color: var(--text-muted)">分析包样本 / 字节</div>
            <div class="font-bold ui-num mt-0.5" style="color: var(--text-primary)">
              {{ trafficStats.total_packets }} 帧 / {{ formatBytes(trafficStats.total_bytes) }}
            </div>
          </div>
          <div class="ui-sub-card p-2">
            <div class="text-[10px]" style="color: var(--text-muted)">唯一主机节点数</div>
            <div class="font-bold ui-num mt-0.5 text-sky-700 dark:text-sky-300">{{ trafficStats.unique_ips }} 台</div>
          </div>
          <div class="ui-sub-card p-2">
            <div class="text-[10px]" style="color: var(--text-muted)">平均帧长 / 信息熵</div>
            <div class="font-bold ui-num mt-0.5" style="color: var(--text-primary)">
              {{ trafficStats.avg_packet_len.toFixed(1) }} B / {{ trafficStats.avg_entropy.toFixed(2) }} b/B
            </div>
          </div>
          <div class="ui-sub-card p-2">
            <div class="text-[10px]" style="color: var(--text-muted)">包间隔均值 / MAD 抖动</div>
            <div class="font-bold ui-num mt-0.5 text-emerald-700 dark:text-emerald-300">
              {{ trafficStats.mean_iat_ms.toFixed(2) }}ms / <span class="text-amber-700 dark:text-amber-300">{{ trafficStats.jitter_ms.toFixed(2) }}ms</span>
            </div>
          </div>
        </div>

        <!-- 三联科研图表（适配侧边抽屉宽度纵向全宽堆叠） -->
        <div class="grid grid-cols-1 gap-2.5">
          <div class="ui-sub-card p-2.5 flex flex-col h-[205px]">
            <div class="text-[11px] font-bold mb-1" style="color: var(--text-primary)">协议层次占比分布 (字节/包量)</div>
            <v-chart :option="protocolPieOption" autoresize class="flex-1 w-full min-h-[160px]" />
          </div>
          <div class="ui-sub-card p-2.5 flex flex-col h-[215px]">
            <div class="text-[11px] font-bold mb-1" style="color: var(--text-primary)">Top Talkers 活跃主机 Tx/Rx 吞吐</div>
            <v-chart :option="topTalkersOption" autoresize class="flex-1 w-full min-h-[170px]" />
          </div>
          <div class="ui-sub-card p-2.5 flex flex-col h-[205px]">
            <div class="text-[11px] font-bold mb-1" style="color: var(--text-primary)">RFC 2544 标准报文长度七档分布</div>
            <v-chart :option="lengthDistOption" autoresize class="flex-1 w-full min-h-[160px]" />
          </div>
        </div>

        <!-- Top 活跃五元组会话表格 -->
        <div class="ui-sub-card p-2">
          <div class="text-[11px] font-bold mb-1.5" style="color: var(--text-primary)">Top 10 活跃通信会话 (无向五元组聚合)</div>
          <div class="max-h-40 overflow-auto custom-scrollbar">
            <table class="w-full text-left text-[11px] ui-num border-collapse">
              <thead class="ui-table-head sticky top-0">
                <tr>
                  <th class="p-1.5">通信端点 A</th>
                  <th class="p-1.5">通信端点 B</th>
                  <th class="p-1.5">协议</th>
                  <th class="p-1.5 text-right">帧数</th>
                  <th class="p-1.5 text-right">双向总字节</th>
                </tr>
              </thead>
              <tbody class="divide-y" style="border-color: var(--border-subtle); color: var(--text-secondary)">
                <tr v-for="(conv, idx) in trafficStats.top_conversations" :key="idx" class="hover:bg-black/5 dark:hover:bg-white/5">
                  <td class="p-1.5 font-mono">{{ conv.endpoint_a }}</td>
                  <td class="p-1.5 font-mono">{{ conv.endpoint_b }}</td>
                  <td class="p-1.5 font-bold text-sky-700 dark:text-sky-300">{{ conv.protocol }}</td>
                  <td class="p-1.5 text-right">{{ conv.packet_count }}</td>
                  <td class="p-1.5 text-right font-bold">{{ formatBytes(conv.byte_count) }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <EmptyState
        v-else
        class="h-full py-10"
        icon="layers"
        title="尚无可用于多维分析的实时抓包样本"
        description="启动网络抓包或加载数据包后，将自动计算协议分布、Top Talkers 带宽榜、活跃会话与 RFC 2544 包长分布。"
      />
    </div>

    <!-- 主内容视图 3: 黄金基线 & 离线 .pcap 对比面板 -->
    <div v-else class="flex-1 ui-content-card p-3 flex flex-col gap-3 min-h-0 overflow-y-auto custom-scrollbar">
      <div v-if="comparisonReport" class="flex flex-col gap-3">
        <!-- 判定结论条 -->
        <div class="ui-sub-card p-2.5 flex items-center justify-between flex-wrap gap-2">
          <div class="flex items-center gap-2">
            <span
              class="px-2 py-0.5 rounded-md text-[11px] font-bold"
              :class="verdictBadgeClass(comparisonReport.anomaly_verdict)"
            >
              {{ verdictLabel(comparisonReport.anomaly_verdict) }}
            </span>
            <span class="text-xs font-bold" style="color: var(--text-primary)">
              对比基准: {{ comparisonReport.baseline_name }}
            </span>
            <span class="text-[11px] ui-num" style="color: var(--text-muted)">
              (基准 {{ comparisonReport.baseline_total_packets }} 帧 vs 当前 {{ comparisonReport.current_total_packets }} 帧)
            </span>
          </div>
          <div class="text-[11px] ui-num flex items-center gap-3" style="color: var(--text-secondary)">
            <span>熵变: <strong>{{ formatSigned(comparisonReport.entropy_delta, 3) }}</strong> b/B</span>
            <span>抖动差: <strong>{{ formatSigned(comparisonReport.jitter_delta_ms, 2) }}</strong> ms</span>
            <span>PPS 变化: <strong>{{ formatSigned(comparisonReport.pps_change_pct, 1) }}%</strong></span>
          </div>
        </div>

        <!-- 诊断归因列表 -->
        <div class="ui-sub-card p-2.5 text-xs">
          <div class="text-[11px] font-bold mb-1" style="color: var(--text-primary)">智能漂移归因诊断</div>
          <ul class="list-disc pl-4 space-y-0.5 text-[11px]" style="color: var(--text-secondary)">
            <li v-for="(reason, idx) in comparisonReport.anomaly_reasons" :key="idx">{{ reason }}</li>
          </ul>
          <div v-if="comparisonReport.new_external_ips.length > 0" class="mt-2 pt-2 border-t text-[11px]" style="border-color: var(--border-subtle)">
            <span class="font-bold text-rose-700 dark:text-rose-300">基线未收录新增活跃 IP ({{ comparisonReport.new_external_ips.length }}): </span>
            <span class="font-mono" style="color: var(--text-secondary)">{{ comparisonReport.new_external_ips.slice(0, 15).join(', ') }}</span>
          </div>
        </div>

        <!-- 双柱对照 ECharts 视图（全宽纵向排布防侧边抽屉挤压） -->
        <div class="grid grid-cols-1 gap-2.5">
          <div class="ui-sub-card p-2.5 flex flex-col h-[230px]">
            <div class="text-[11px] font-bold mb-1" style="color: var(--text-primary)">协议占比分布对比 (基线/.pcap vs 实时 %)</div>
            <v-chart :option="compareProtoOption" autoresize class="flex-1 w-full min-h-[175px]" />
          </div>
          <div class="ui-sub-card p-2.5 flex flex-col h-[230px]">
            <div class="text-[11px] font-bold mb-1" style="color: var(--text-primary)">RFC 2544 报文长度分布对比 (基线/.pcap vs 实时 %)</div>
            <v-chart :option="compareLengthOption" autoresize class="flex-1 w-full min-h-[175px]" />
          </div>
        </div>
      </div>

      <EmptyState
        v-else
        class="h-full py-10"
        icon="git-compare"
        title="尚未执行历史基线或 .pcap 对比"
        description="点击右上角【固化网络基线】保存当前健康态，或点击【对比黄金基线】 / 【导入 .pcap 对比】进行双样本统计对比。"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import { use } from 'echarts/core';
import { CanvasRenderer } from 'echarts/renderers';
import { LineChart, BarChart, PieChart, ScatterChart } from 'echarts/charts';
import {
  GridComponent,
  TooltipComponent,
  LegendComponent,
  DataZoomComponent,
  MarkLineComponent,
} from 'echarts/components';
import VChart from 'vue-echarts';
import type { EChartsOption } from 'echarts';
import AppIcon from './AppIcon.vue';
import EmptyState from './EmptyState.vue';

use([
  CanvasRenderer,
  LineChart,
  BarChart,
  PieChart,
  ScatterChart,
  GridComponent,
  TooltipComponent,
  LegendComponent,
  DataZoomComponent,
  MarkLineComponent,
]);

export interface RawIoGraphBucket {
  timestamp_sec: number;
  packet_count: number;
  byte_count: number;
  avg_rtt_ms: number;
  rtt_samples?: number;
  retrans_count: number;
  time_str?: string;
}

export interface IoGraphPoint {
  timestamp_sec: number;
  time_str: string;
  packet_count: number;
  byte_count: number;
  avg_rtt_ms: number;
  retrans_count: number;
}

export interface RawIoGraphSeries {
  buckets: RawIoGraphBucket[];
  total_packets: number;
  total_bytes: number;
  global_avg_rtt_ms?: number;
  max_bandwidth_bps?: number;
  avg_pps?: number;
  max_pps?: number;
  avg_bps?: number;
  max_bps?: number;
  avg_rtt_ms?: number;
  max_rtt_ms?: number;
}

export type IoGraphSeries = RawIoGraphSeries;

export interface NetPacketPropItem {
  protocol: string;
  transport: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  length: number;
  timestamp_ns?: number;
  entropy?: number;
}

interface NetTrafficSamplePayload {
  protocol: string;
  transport: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  length: number;
  timestamp_ns: number;
  entropy: number;
}

interface ProtocolStatItem {
  protocol: string;
  packet_count: number;
  byte_count: number;
  packet_ratio_pct: number;
  byte_ratio_pct: number;
}

interface IpTalkerItem {
  ip: string;
  tx_packets: number;
  rx_packets: number;
  total_packets: number;
  tx_bytes: number;
  rx_bytes: number;
  total_bytes: number;
  peer_count: number;
}

interface ConversationStatItem {
  endpoint_a: string;
  endpoint_b: string;
  protocol: string;
  packet_count: number;
  byte_count: number;
}

interface PacketLengthBucket {
  label: string;
  packet_count: number;
  ratio_pct: number;
}

interface NetworkTrafficStats {
  total_packets: number;
  total_bytes: number;
  unique_ips: number;
  avg_packet_len: number;
  avg_entropy: number;
  duration_sec: number;
  mean_iat_ms: number;
  jitter_ms: number;
  protocol_breakdown: ProtocolStatItem[];
  top_talkers: IpTalkerItem[];
  top_conversations: ConversationStatItem[];
  length_distribution: PacketLengthBucket[];
  active_ips: string[];
}

interface NetworkTrafficBaseline {
  name: string;
  saved_at_ms: number;
  avg_pps: number;
  avg_bps: number;
  avg_rtt_ms: number;
  retrans_rate_pct: number;
  stats: NetworkTrafficStats;
}

interface ProtocolDeltaItem {
  protocol: string;
  baseline_pct: number;
  current_pct: number;
  delta_pct: number;
}

interface LengthBucketDeltaItem {
  label: string;
  baseline_pct: number;
  current_pct: number;
  delta_pct: number;
}

interface NetworkComparisonReport {
  baseline_name: string;
  baseline_saved_at_ms: number;
  baseline_total_packets: number;
  current_total_packets: number;
  baseline_avg_pps: number;
  current_avg_pps: number;
  pps_change_pct: number;
  baseline_avg_bps: number;
  current_avg_bps: number;
  bps_change_pct: number;
  entropy_delta: number;
  jitter_delta_ms: number;
  avg_len_delta: number;
  protocol_deltas: ProtocolDeltaItem[];
  length_deltas: LengthBucketDeltaItem[];
  new_external_ips: string[];
  disappeared_ips: string[];
  anomaly_verdict: string;
  anomaly_reasons: string[];
}

const props = withDefaults(
  defineProps<{
    packets?: NetPacketPropItem[];
  }>(),
  {
    packets: () => [],
  }
);

const isDarkTheme = ref(!document.documentElement.classList.contains('theme-apple-light'));
let themeObserver: MutationObserver | null = null;

const activePanelMode = ref<'timeseries' | 'multidim' | 'compare'>('timeseries');
const selectedBusFilter = ref<'ALL' | 'ETHERNET' | 'SERIAL' | 'USB' | 'WIRELESS'>('ALL');
const selectedWindow = ref(60);
const activeMetric = ref<'pps' | 'bandwidth' | 'rtt' | 'retrans'>('pps');
const isAutoRefreshing = ref(true);
const isLoading = ref(false);
const isBaselineBusy = ref(false);
const showTable = ref(false);
const actionNotice = ref('');

const seriesData = ref<RawIoGraphSeries | null>(null);
const trafficStats = ref<NetworkTrafficStats | null>(null);
const savedBaseline = ref<NetworkTrafficBaseline | null>(null);
const comparisonReport = ref<NetworkComparisonReport | null>(null);

let refreshTimer: ReturnType<typeof setInterval> | null = null;
let statsDebounceTimer: ReturnType<typeof setTimeout> | null = null;

const packetSamples = computed<NetTrafficSamplePayload[]>(() => {
  const list = props.packets || [];
  const slice = list.length > 2500 ? list.slice(-2500) : list;
  return slice.map((p) => ({
    protocol: p.protocol || 'UNKNOWN',
    transport: p.transport || '',
    src_ip: p.src_ip || '',
    dst_ip: p.dst_ip || '',
    src_port: Number.isFinite(p.src_port) ? p.src_port : 0,
    dst_port: Number.isFinite(p.dst_port) ? p.dst_port : 0,
    length: Number.isFinite(p.length) ? p.length : 0,
    timestamp_ns: typeof p.timestamp_ns === 'number' && Number.isFinite(p.timestamp_ns) ? p.timestamp_ns : 0,
    entropy: typeof p.entropy === 'number' && Number.isFinite(p.entropy) ? p.entropy : 0,
  }));
});

function formatSecToHms(tsSec: number): string {
  if (!Number.isFinite(tsSec) || tsSec <= 0) return '--:--:--';
  const d = new Date(tsSec * 1000);
  const hh = String(d.getHours()).padStart(2, '0');
  const mm = String(d.getMinutes()).padStart(2, '0');
  const ss = String(d.getSeconds()).padStart(2, '0');
  return `${hh}:${mm}:${ss}`;
}

const validBuckets = computed<IoGraphPoint[]>(() => {
  const rawList = seriesData.value?.buckets || [];
  return rawList.map((b) => ({
    timestamp_sec: Number.isFinite(b.timestamp_sec) ? b.timestamp_sec : 0,
    time_str: b.time_str && b.time_str.trim() ? b.time_str : formatSecToHms(b.timestamp_sec),
    packet_count: Number.isFinite(b.packet_count) ? b.packet_count : 0,
    byte_count: Number.isFinite(b.byte_count) ? b.byte_count : 0,
    avg_rtt_ms: Number.isFinite(b.avg_rtt_ms) ? b.avg_rtt_ms : 0,
    retrans_count: Number.isFinite(b.retrans_count) ? b.retrans_count : 0,
  }));
});

const summaryStats = computed(() => {
  const raw = seriesData.value;
  const buckets = validBuckets.value;
  const count = buckets.length;
  const totalPackets = raw && Number.isFinite(raw.total_packets) ? raw.total_packets : 0;
  const totalBytes = raw && Number.isFinite(raw.total_bytes) ? raw.total_bytes : 0;

  let maxPps = 0;
  let maxBps = 0;
  let maxRttMs = 0;
  let sumRttMs = 0;
  let rttBucketCount = 0;

  for (const b of buckets) {
    if (b.packet_count > maxPps) maxPps = b.packet_count;
    if (b.byte_count > maxBps) maxBps = b.byte_count;
    if (b.avg_rtt_ms > 0) {
      sumRttMs += b.avg_rtt_ms;
      rttBucketCount += 1;
      if (b.avg_rtt_ms > maxRttMs) maxRttMs = b.avg_rtt_ms;
    }
  }

  const avgPps = raw?.avg_pps ?? (count > 0 ? totalPackets / count : 0);
  const avgBps = raw?.avg_bps ?? (count > 0 ? totalBytes / count : 0);
  const resolvedMaxBps = raw?.max_bps ?? raw?.max_bandwidth_bps ?? maxBps;
  const avgRttMs = raw?.avg_rtt_ms ?? raw?.global_avg_rtt_ms ?? (rttBucketCount > 0 ? sumRttMs / rttBucketCount : 0);

  return {
    totalPackets,
    totalBytes,
    avgPps: Number.isFinite(avgPps) ? avgPps : 0,
    maxPps: raw?.max_pps ?? maxPps,
    avgBps: Number.isFinite(avgBps) ? avgBps : 0,
    maxBps: Number.isFinite(resolvedMaxBps) ? resolvedMaxBps : 0,
    avgRttMs: Number.isFinite(avgRttMs) ? avgRttMs : 0,
    maxRttMs: raw?.max_rtt_ms ?? maxRttMs,
  };
});

const metricTitle = computed(() => {
  switch (activeMetric.value) {
    case 'pps': return '报文包率 (Packets / Second)';
    case 'bandwidth': return '吞吐带宽 (KB/s)';
    case 'rtt': return 'TCP 往返时延 RTT (ms)';
    case 'retrans': return 'TCP 重传异常计数 (Retransmissions)';
  }
});

const metricColor = computed(() => {
  switch (activeMetric.value) {
    case 'pps': return '#0ea5e9';
    case 'bandwidth': return '#10b981';
    case 'rtt': return '#6366f1';
    case 'retrans': return '#f43f5e';
  }
});

const chartColors = computed(() => ({
  text: isDarkTheme.value ? '#cbd5e1' : '#334155',
  muted: isDarkTheme.value ? '#94a3b8' : '#64748b',
  splitLine: isDarkTheme.value ? 'rgba(148,163,184,0.14)' : 'rgba(100,116,139,0.18)',
  tooltipBg: isDarkTheme.value ? 'rgba(15,23,42,0.95)' : 'rgba(255,255,255,0.96)',
  tooltipBorder: isDarkTheme.value ? '#334155' : '#cbd5e1',
}));

const timeSeriesOption = computed<EChartsOption>(() => {
  const buckets = validBuckets.value;
  const labels = buckets.map((b) => b.time_str);
  const values = buckets.map((b) => {
    if (activeMetric.value === 'pps') return b.packet_count;
    if (activeMetric.value === 'bandwidth') return Number((b.byte_count / 1024).toFixed(2));
    if (activeMetric.value === 'rtt') return Number(b.avg_rtt_ms.toFixed(2));
    return b.retrans_count;
  });

  const retransScatter: Array<[string, number]> = [];
  buckets.forEach((b, idx) => {
    if (b.retrans_count > 0) {
      retransScatter.push([b.time_str, values[idx]]);
    }
  });

  let baselineRefVal: number | null = null;
  if (savedBaseline.value) {
    if (activeMetric.value === 'pps') baselineRefVal = Number(savedBaseline.value.avg_pps.toFixed(2));
    else if (activeMetric.value === 'bandwidth') baselineRefVal = Number((savedBaseline.value.avg_bps / 1024).toFixed(2));
    else if (activeMetric.value === 'rtt') baselineRefVal = Number(savedBaseline.value.avg_rtt_ms.toFixed(2));
  }

  return {
    animationDuration: 240,
    tooltip: {
      trigger: 'axis',
      backgroundColor: chartColors.value.tooltipBg,
      borderColor: chartColors.value.tooltipBorder,
      textStyle: { color: chartColors.value.text, fontSize: 11 },
    },
    grid: { top: 24, right: 20, bottom: 38, left: 52 },
    dataZoom: [
      { type: 'inside', throttle: 50 },
      { type: 'slider', height: 14, bottom: 4, textStyle: { color: chartColors.value.muted, fontSize: 10 } },
    ],
    xAxis: {
      type: 'category',
      data: labels,
      axisLabel: { color: chartColors.value.muted, fontSize: 10 },
      axisLine: { lineStyle: { color: chartColors.value.splitLine } },
    },
    yAxis: {
      type: 'value',
      axisLabel: { color: chartColors.value.muted, fontSize: 10 },
      splitLine: { lineStyle: { color: chartColors.value.splitLine, type: 'dashed' } },
    },
    series: [
      {
        name: metricTitle.value,
        type: 'line',
        smooth: 0.25,
        showSymbol: buckets.length <= 40,
        symbolSize: 5,
        itemStyle: { color: metricColor.value },
        lineStyle: { width: 2.2, color: metricColor.value },
        areaStyle: { color: metricColor.value, opacity: 0.14 },
        data: values,
        markLine:
          baselineRefVal !== null && baselineRefVal > 0
            ? {
                silent: true,
                symbol: 'none',
                lineStyle: { type: 'dashed', color: '#f59e0b', width: 1.5 },
                label: { formatter: `黄金基线均值: ${baselineRefVal}`, color: '#f59e0b', fontSize: 10 },
                data: [{ yAxis: baselineRefVal }],
              }
            : undefined,
      },
      {
        name: 'TCP 重传触发点',
        type: 'scatter',
        symbolSize: 9,
        itemStyle: { color: '#e11d48', borderColor: '#fff', borderWidth: 1.5 },
        data: retransScatter,
      },
    ],
  };
});

const protocolPieOption = computed<EChartsOption>(() => {
  const list = trafficStats.value?.protocol_breakdown || [];
  return {
    tooltip: {
      trigger: 'item',
      backgroundColor: chartColors.value.tooltipBg,
      borderColor: chartColors.value.tooltipBorder,
      textStyle: { color: chartColors.value.text, fontSize: 11 },
      formatter: '{b}: {c} Bytes ({d}%)',
    },
    legend: {
      type: 'scroll',
      orient: 'vertical',
      right: 0,
      top: 10,
      bottom: 10,
      textStyle: { color: chartColors.value.muted, fontSize: 10 },
    },
    series: [
      {
        name: '协议流量分布',
        type: 'pie',
        radius: ['42%', '72%'],
        center: ['36%', '52%'],
        label: { show: false },
        data: list.map((p) => ({ name: p.protocol, value: p.byte_count })),
      },
    ],
  };
});

const topTalkersOption = computed<EChartsOption>(() => {
  const list = (trafficStats.value?.top_talkers || []).slice(0, 8).reverse();
  return {
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'shadow' },
      backgroundColor: chartColors.value.tooltipBg,
      borderColor: chartColors.value.tooltipBorder,
      textStyle: { color: chartColors.value.text, fontSize: 11 },
    },
    legend: {
      top: 0,
      textStyle: { color: chartColors.value.muted, fontSize: 10 },
    },
    grid: { top: 24, right: 16, bottom: 20, left: 96 },
    xAxis: {
      type: 'value',
      axisLabel: { color: chartColors.value.muted, fontSize: 10 },
      splitLine: { lineStyle: { color: chartColors.value.splitLine, type: 'dashed' } },
    },
    yAxis: {
      type: 'category',
      data: list.map((t) => t.ip),
      axisLabel: { color: chartColors.value.text, fontSize: 10 },
    },
    series: [
      {
        name: 'Tx 发送(B)',
        type: 'bar',
        stack: 'bw',
        itemStyle: { color: '#0ea5e9' },
        data: list.map((t) => t.tx_bytes),
      },
      {
        name: 'Rx 接收(B)',
        type: 'bar',
        stack: 'bw',
        itemStyle: { color: '#10b981' },
        data: list.map((t) => t.rx_bytes),
      },
    ],
  };
});

const lengthDistOption = computed<EChartsOption>(() => {
  const list = trafficStats.value?.length_distribution || [];
  return {
    tooltip: {
      trigger: 'axis',
      backgroundColor: chartColors.value.tooltipBg,
      borderColor: chartColors.value.tooltipBorder,
      textStyle: { color: chartColors.value.text, fontSize: 11 },
    },
    grid: { top: 16, right: 12, bottom: 32, left: 38 },
    xAxis: {
      type: 'category',
      data: list.map((b) => b.label),
      axisLabel: { color: chartColors.value.muted, fontSize: 9, rotate: 22 },
    },
    yAxis: {
      type: 'value',
      axisLabel: { color: chartColors.value.muted, fontSize: 10 },
      splitLine: { lineStyle: { color: chartColors.value.splitLine, type: 'dashed' } },
    },
    series: [
      {
        name: '帧计数',
        type: 'bar',
        itemStyle: { color: '#6366f1', borderRadius: [3, 3, 0, 0] },
        data: list.map((b) => b.packet_count),
      },
    ],
  };
});

const compareProtoOption = computed<EChartsOption>(() => {
  const list = (comparisonReport.value?.protocol_deltas || []).slice(0, 8);
  return {
    tooltip: {
      trigger: 'axis',
      backgroundColor: chartColors.value.tooltipBg,
      borderColor: chartColors.value.tooltipBorder,
      textStyle: { color: chartColors.value.text, fontSize: 11 },
    },
    legend: { top: 0, textStyle: { color: chartColors.value.muted, fontSize: 10 } },
    grid: { top: 26, right: 12, bottom: 26, left: 40 },
    xAxis: {
      type: 'category',
      data: list.map((d) => d.protocol),
      axisLabel: { color: chartColors.value.muted, fontSize: 10 },
    },
    yAxis: {
      type: 'value',
      name: '%',
      axisLabel: { color: chartColors.value.muted, fontSize: 10 },
      splitLine: { lineStyle: { color: chartColors.value.splitLine, type: 'dashed' } },
    },
    series: [
      {
        name: '基准/.pcap (%)',
        type: 'bar',
        itemStyle: { color: '#94a3b8' },
        data: list.map((d) => d.baseline_pct),
      },
      {
        name: '当前实时 (%)',
        type: 'bar',
        itemStyle: { color: '#0ea5e9' },
        data: list.map((d) => d.current_pct),
      },
    ],
  };
});

const compareLengthOption = computed<EChartsOption>(() => {
  const list = comparisonReport.value?.length_deltas || [];
  return {
    tooltip: {
      trigger: 'axis',
      backgroundColor: chartColors.value.tooltipBg,
      borderColor: chartColors.value.tooltipBorder,
      textStyle: { color: chartColors.value.text, fontSize: 11 },
    },
    legend: { top: 0, textStyle: { color: chartColors.value.muted, fontSize: 10 } },
    grid: { top: 26, right: 12, bottom: 32, left: 40 },
    xAxis: {
      type: 'category',
      data: list.map((d) => d.label),
      axisLabel: { color: chartColors.value.muted, fontSize: 9, rotate: 20 },
    },
    yAxis: {
      type: 'value',
      name: '%',
      axisLabel: { color: chartColors.value.muted, fontSize: 10 },
      splitLine: { lineStyle: { color: chartColors.value.splitLine, type: 'dashed' } },
    },
    series: [
      {
        name: '基准/.pcap (%)',
        type: 'bar',
        itemStyle: { color: '#94a3b8' },
        data: list.map((d) => d.baseline_pct),
      },
      {
        name: '当前实时 (%)',
        type: 'bar',
        itemStyle: { color: '#10b981' },
        data: list.map((d) => d.current_pct),
      },
    ],
  };
});

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  if (bytes < 1024) return `${Math.round(bytes)} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function formatSigned(val: number, digits: number): string {
  const fixed = Number.isFinite(val) ? val.toFixed(digits) : '0';
  return val > 0 ? `+${fixed}` : fixed;
}

function verdictLabel(v: string): string {
  if (v === 'SIGNIFICANT_ANOMALY') return '显著偏移异常';
  if (v === 'DRIFT_WARNING') return '轻度分布漂移';
  return '符合历史基线';
}

function verdictBadgeClass(v: string): string {
  if (v === 'SIGNIFICANT_ANOMALY') return 'bg-rose-500/20 text-rose-700 dark:text-rose-300 border border-rose-500/40';
  if (v === 'DRIFT_WARNING') return 'bg-amber-500/20 text-amber-700 dark:text-amber-300 border border-amber-500/40';
  return 'bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border border-emerald-500/40';
}

const totalAnalyzedPackets = computed<number>(
  () => trafficStats.value?.total_packets ?? packetSamples.value.length
);

const hasAnyTraffic = computed<boolean>(
  () => totalAnalyzedPackets.value > 0 || packetSamples.value.length > 0
);

function fallbackSamplesIfNeeded(): NetTrafficSamplePayload[] | null {
  if (trafficStats.value && trafficStats.value.total_packets > 0) {
    return null;
  }
  return packetSamples.value.length > 0 ? packetSamples.value : null;
}

async function fetchData() {
  if (isLoading.value) return;
  isLoading.value = true;
  try {
    const res = await invoke<RawIoGraphSeries>('get_io_graph_series_cmd', {
      windowSeconds: selectedWindow.value,
      busFilter: selectedBusFilter.value === 'ALL' ? null : selectedBusFilter.value,
    });
    seriesData.value = res;
  } catch (e) {
    console.error('获取 IO Graph 数据失败:', e);
  } finally {
    isLoading.value = false;
  }
}

async function refreshTrafficStats() {
  try {
    const res = await invoke<NetworkTrafficStats>('analyze_network_traffic_stats_cmd', {
      samples: packetSamples.value.length > 0 ? packetSamples.value : null,
      useBackendFull: true,
    });
    trafficStats.value = res.total_packets > 0 ? res : null;
  } catch (e) {
    console.error('计算多维流量统计失败:', e);
  }
}

async function loadSavedBaseline() {
  try {
    savedBaseline.value = await invoke<NetworkTrafficBaseline | null>('get_network_baseline_cmd');
  } catch (e) {
    console.error('读取黄金网络基线失败:', e);
  }
}

function currentBucketInputs() {
  return validBuckets.value.map((b) => ({
    packet_count: b.packet_count,
    byte_count: b.byte_count,
    avg_rtt_ms: b.avg_rtt_ms,
    retrans_count: b.retrans_count,
  }));
}

async function saveBaseline() {
  isBaselineBusy.value = true;
  try {
    const res = await invoke<NetworkTrafficBaseline>('save_network_baseline_cmd', {
      name: `黄金基线-${new Date().toLocaleTimeString()}`,
      samples: fallbackSamplesIfNeeded(),
      buckets: currentBucketInputs(),
      useBackendFull: true,
    });
    savedBaseline.value = res;
    actionNotice.value = `已固化网络基线 (${res.stats.total_packets} 帧)`;
  } catch (e) {
    actionNotice.value = `固化基线失败: ${String(e)}`;
  } finally {
    isBaselineBusy.value = false;
  }
}

async function compareWithBaseline() {
  isBaselineBusy.value = true;
  try {
    const res = await invoke<NetworkComparisonReport>('compare_network_with_baseline_cmd', {
      samples: fallbackSamplesIfNeeded(),
      buckets: currentBucketInputs(),
      useBackendFull: true,
    });
    comparisonReport.value = res;
    activePanelMode.value = 'compare';
    actionNotice.value = `基线对比完成: ${verdictLabel(res.anomaly_verdict)}`;
  } catch (e) {
    actionNotice.value = `基线对比失败: ${String(e)}`;
  } finally {
    isBaselineBusy.value = false;
  }
}

async function compareWithPcapFile() {
  isBaselineBusy.value = true;
  try {
    const res = await invoke<NetworkComparisonReport | null>('pick_and_compare_network_pcap_cmd', {
      currentSamples: fallbackSamplesIfNeeded(),
      currentBuckets: currentBucketInputs(),
      useBackendFull: true,
    });
    if (res) {
      comparisonReport.value = res;
      activePanelMode.value = 'compare';
      actionNotice.value = `离线 .pcap 对照完成: ${verdictLabel(res.anomaly_verdict)}`;
    }
  } catch (e) {
    actionNotice.value = `导入 .pcap 对比失败: ${String(e)}`;
  } finally {
    isBaselineBusy.value = false;
  }
}

async function exportAuditReport(format: 'markdown' | 'html') {
  try {
    const savedPath = await invoke<string | null>('export_network_audit_report_cmd', {
      title: 'Omni-Probe 网络深度流量统计与安全审计报告',
      format,
      samples: fallbackSamplesIfNeeded(),
      comparison: comparisonReport.value,
      useBackendFull: true,
    });
    if (savedPath) {
      actionNotice.value = `报告已导出: ${savedPath}`;
    }
  } catch (e) {
    actionNotice.value = `报告导出失败: ${String(e)}`;
  }
}

function switchToMultidim() {
  activePanelMode.value = 'multidim';
  refreshTrafficStats();
}

function refreshAll() {
  fetchData();
  refreshTrafficStats();
}

function toggleAutoRefresh() {
  isAutoRefreshing.value = !isAutoRefreshing.value;
  if (isAutoRefreshing.value) {
    startAutoRefresh();
  } else {
    stopAutoRefresh();
  }
}

function startAutoRefresh() {
  stopAutoRefresh();
  refreshTimer = setInterval(() => {
    fetchData();
  }, 1000);
}

function stopAutoRefresh() {
  if (refreshTimer) {
    clearInterval(refreshTimer);
    refreshTimer = null;
  }
}

watch(
  () => props.packets?.length ?? 0,
  () => {
    if (statsDebounceTimer) clearTimeout(statsDebounceTimer);
    statsDebounceTimer = setTimeout(() => {
      refreshTrafficStats();
    }, 450);
  }
);

onMounted(() => {
  themeObserver = new MutationObserver(() => {
    isDarkTheme.value = !document.documentElement.classList.contains('theme-apple-light');
  });
  themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });

  loadSavedBaseline();
  fetchData();
  refreshTrafficStats();
  if (isAutoRefreshing.value) {
    startAutoRefresh();
  }
});

onUnmounted(() => {
  if (themeObserver) {
    themeObserver.disconnect();
    themeObserver = null;
  }
  if (statsDebounceTimer) {
    clearTimeout(statsDebounceTimer);
    statsDebounceTimer = null;
  }
  stopAutoRefresh();
});
</script>
