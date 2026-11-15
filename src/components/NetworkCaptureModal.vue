<template>
  <div v-if="isOpen" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-fade-in">
    <div
      class="w-full max-w-4xl max-h-[90vh] flex flex-col rounded-2xl overflow-hidden border shadow-2xl transition-all"
      style="background: var(--surface-content); border-color: var(--border-subtle);"
    >
      <!-- 顶层标题栏 -->
      <header class="px-6 py-4 border-b flex items-center justify-between shrink-0" style="border-color: var(--border-subtle); background: var(--surface-content-alt);">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-xl bg-sky-500/15 border border-sky-500/30 flex items-center justify-center text-sky-600 dark:text-sky-400 shrink-0">
            <AppIcon name="cpu" :size="20" />
          </div>
          <div>
            <h2 class="text-base font-bold flex items-center gap-2" style="color: var(--text-primary)">
              {{ locale === 'en-US' ? 'Professional Network Capture Setup' : '专业网络抓包配置与物理接口画像' }}
              <span class="text-[11px] px-2 py-0.5 rounded-full font-semibold border" :class="isNpcapReady ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/30' : 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30'">
                {{ isNpcapReady ? (locale === 'en-US' ? 'Npcap Driver Ready' : 'Npcap 驱动就绪 (L2混杂)') : (locale === 'en-US' ? 'NDIS-ETW / Raw Socket Mode' : 'NDIS-ETW / Raw Socket 兜底') }}
              </span>
            </h2>
            <p class="text-xs mt-0.5" style="color: var(--text-muted)">
              {{ locale === 'en-US' ? 'Configure physical network interfaces, BPF filter presets, snaplen, and zero-copy ring buffers.' : '配置宿主机物理网卡画像、实时 BPF 过滤器预设、抓包截断长度与零拷贝环形缓冲。' }}
            </p>
          </div>
        </div>

        <button
          @click="$emit('close')"
          class="p-2 rounded-xl border border-transparent hover:border-(--border-subtle) hover:bg-(--surface-glass-pill) text-(--text-muted) hover:text-(--text-primary) cursor-pointer transition-all"
          :title="locale === 'en-US' ? 'Close' : '关闭'"
        >
          <AppIcon name="x" :size="18" />
        </button>
      </header>

      <!-- 导航 Tab -->
      <nav class="flex items-center gap-2 px-6 py-2.5 border-b text-xs font-semibold shrink-0" style="border-color: var(--border-subtle); background: var(--surface-content);">
        <button
          v-for="tab in tabs"
          :key="tab.id"
          @click="activeTab = tab.id"
          class="px-3.5 py-1.5 rounded-xl transition-all flex items-center gap-2 cursor-pointer"
          :class="activeTab === tab.id ? 'bg-sky-500/15 text-sky-700 dark:text-sky-300 border border-sky-500/30 font-bold' : 'text-(--text-secondary) hover:bg-(--surface-glass-pill)'"
        >
          <AppIcon :name="tab.icon" :size="14" />
          <span>{{ tab.label }}</span>
        </button>
      </nav>

      <!-- 主体内容区 -->
      <div class="flex-1 overflow-y-auto p-6 space-y-5" style="color: var(--text-secondary);">

        <!-- ==================== TAB 1: 物理网络接口画像 ==================== -->
        <div v-if="activeTab === 'adapters'" class="space-y-4">
          <div class="flex items-center justify-between">
            <span class="text-xs font-bold uppercase tracking-wider" style="color: var(--text-primary)">
              {{ locale === 'en-US' ? 'Detected Network Adapters' : '已探明物理网络接口列表' }} ({{ interfaces.length }})
            </span>
            <button
              @click="loadInterfaces"
              :disabled="isLoadingIfaces"
              class="px-2.5 py-1 text-xs rounded-lg border border-(--border-subtle) hover:bg-(--surface-glass-pill) flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
            >
              <AppIcon name="refresh" :size="12" :class="{ 'animate-spin': isLoadingIfaces }" />
              <span>{{ locale === 'en-US' ? 'Refresh Interfaces' : '刷新网卡画像' }}</span>
            </button>
          </div>

          <div v-if="isLoadingIfaces" class="py-12 flex flex-col items-center justify-center gap-3">
            <div class="w-8 h-8 rounded-full border-2 border-sky-500 border-t-transparent animate-spin"></div>
            <span class="text-xs" style="color: var(--text-muted)">{{ locale === 'en-US' ? 'Scanning host network topology...' : '正在扫描宿主机物理网卡与路由拓扑...' }}</span>
          </div>

          <div v-else-if="interfaces.length === 0" class="py-12 text-center text-xs" style="color: var(--text-muted)">
            {{ locale === 'en-US' ? 'No physical network adapters found. Using default loopback.' : '未发现可用网卡，系统将使用自动回退链路。' }}
          </div>

          <div v-else class="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div
              v-for="iface in interfaces"
              :key="iface.name"
              @click="selectedIface = iface.name"
              class="p-4 rounded-xl border transition-all cursor-pointer flex flex-col justify-between gap-3 relative"
              :class="selectedIface === iface.name ? 'border-sky-500 bg-sky-500/8 shadow-sm ring-1 ring-sky-500/30' : 'border-(--border-subtle) bg-[var(--surface-content-alt)] hover:border-sky-500/40'"
            >
              <!-- 顶部状态 -->
              <div class="flex items-start justify-between gap-2">
                <div class="flex items-center gap-2.5 min-w-0">
                  <div
                    class="w-8 h-8 rounded-lg flex items-center justify-center shrink-0 border"
                    :class="iface.is_wireless ? 'bg-cyan-500/12 text-cyan-600 dark:text-cyan-400 border-cyan-500/30' : (iface.is_loopback ? 'bg-amber-500/12 text-amber-600 dark:text-amber-400 border-amber-500/30' : 'bg-emerald-500/12 text-emerald-600 dark:text-emerald-400 border-emerald-500/30')"
                  >
                    <AppIcon :name="iface.is_wireless ? 'wifi' : (iface.is_loopback ? 'repeat' : 'activity')" :size="16" />
                  </div>
                  <div class="min-w-0">
                    <div class="font-bold text-xs truncate" style="color: var(--text-primary)" :title="iface.friendly_name">
                      {{ iface.friendly_name }}
                    </div>
                    <div class="text-[10px] font-mono truncate" style="color: var(--text-muted)" :title="iface.name">
                      {{ iface.name }}
                    </div>
                  </div>
                </div>

                <span
                  v-if="iface.is_default_gateway"
                  class="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30 shrink-0"
                >
                  {{ locale === 'en-US' ? 'Default Egress Gateway' : '外网出口 · 推荐' }}
                </span>
              </div>

              <!-- IP 地址与参数标签 -->
              <div class="pt-2 border-t flex flex-wrap items-center justify-between gap-1 text-[11px] ui-num" style="border-color: var(--border-subtle);">
                <div class="flex items-center gap-1.5 flex-wrap">
                  <span
                    v-for="ip in iface.ips.slice(0, 2)"
                    :key="ip"
                    class="px-1.5 py-0.5 rounded bg-[var(--surface-glass-pill)] border border-(--border-subtle) font-mono"
                  >
                    {{ ip }}
                  </span>
                  <span v-if="iface.ips.length === 0" class="text-[10px] text-(--text-muted)">
                    {{ locale === 'en-US' ? 'No IPv4 Assigned' : '未分配 IPv4' }}
                  </span>
                </div>

                <div class="flex items-center gap-1 text-[10px]" style="color: var(--text-muted)">
                  <span v-if="iface.is_wireless">{{ locale === 'en-US' ? '802.11 Wi-Fi' : 'Wi-Fi 无线' }}</span>
                  <span v-else-if="iface.is_loopback">{{ locale === 'en-US' ? 'Loopback' : '本地回环' }}</span>
                  <span v-else>{{ locale === 'en-US' ? 'Ethernet L2' : '以太网 L2' }}</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- ==================== TAB 2: 工业级抓包物理参数 ==================== -->
        <div v-else-if="activeTab === 'options'" class="space-y-5">
          <!-- 1. 抓包截断长度 (Snaplen) -->
          <div class="p-4 rounded-xl border space-y-3" style="background: var(--surface-content-alt); border-color: var(--border-subtle);">
            <div class="flex items-center justify-between">
              <div>
                <div class="text-xs font-bold" style="color: var(--text-primary)">
                  {{ locale === 'en-US' ? 'Packet Snapshot Truncation (Snaplen)' : '数据报文截断抓取长度 (Snaplen)' }}
                </div>
                <div class="text-[11px] mt-0.5" style="color: var(--text-muted)">
                  {{ locale === 'en-US' ? 'Truncate frame payload to reduce CPU cache and disk space consumption during high-throughput sniffing.' : '在千兆/万兆高吞吐监控时截断载荷，降低 CPU 缓存未命中与磁盘写入损耗。' }}
                </div>
              </div>
              <span class="text-xs font-mono font-bold text-sky-600 dark:text-sky-400">
                {{ snaplen === 65535 ? '65535 Bytes (Full)' : '96 Bytes (Header Only)' }}
              </span>
            </div>

            <div class="grid grid-cols-2 gap-3 pt-2">
              <label
                @click="snaplen = 65535"
                class="p-3 rounded-xl border flex items-center gap-3 cursor-pointer transition-all"
                :class="snaplen === 65535 ? 'border-sky-500 bg-sky-500/10' : 'border-(--border-subtle) bg-[var(--surface-content)]'"
              >
                <input type="radio" :checked="snaplen === 65535" class="accent-sky-500" />
                <div>
                  <div class="text-xs font-bold" style="color: var(--text-primary)">
                    {{ locale === 'en-US' ? 'Full Frame (65535B)' : '全量完整包 (65535B)' }}
                  </div>
                  <div class="text-[10px]" style="color: var(--text-muted)">
                    {{ locale === 'en-US' ? 'Retain full L7 payload, required for TLS decryption and forensic reconstruction.' : '保留应用层全量载荷，满足协议深度还原、TLS 密钥解密与取证。' }}
                  </div>
                </div>
              </label>

              <label
                @click="snaplen = 96"
                class="p-3 rounded-xl border flex items-center gap-3 cursor-pointer transition-all"
                :class="snaplen === 96 ? 'border-sky-500 bg-sky-500/10' : 'border-(--border-subtle) bg-[var(--surface-content)]'"
              >
                <input type="radio" :checked="snaplen === 96" class="accent-sky-500" />
                <div>
                  <div class="text-xs font-bold" style="color: var(--text-primary)">
                    {{ locale === 'en-US' ? 'Header Only (96B)' : '仅抓报头 (96B)' }}
                  </div>
                  <div class="text-[10px]" style="color: var(--text-muted)">
                    {{ locale === 'en-US' ? 'Captures Ethernet, IP, and TCP headers only. Zero payload leak, optimal for wire-rate analysis.' : '仅采集以太网+IP+TCP/UDP头部，保护隐私并实现超高线速防丢包。' }}
                  </div>
                </div>
              </label>
            </div>
          </div>

          <!-- 2. 混杂模式与接收环形缓冲 -->
          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <!-- 混杂模式 -->
            <div class="p-4 rounded-xl border flex flex-col justify-between gap-3" style="background: var(--surface-content-alt); border-color: var(--border-subtle);">
              <div>
                <div class="text-xs font-bold" style="color: var(--text-primary)">
                  {{ locale === 'en-US' ? 'Promiscuous Mode' : '网卡混杂模式 (Promiscuous Mode)' }}
                </div>
                <div class="text-[11px] mt-0.5" style="color: var(--text-muted)">
                  {{ locale === 'en-US' ? 'Allow network card to capture all frames on wire regardless of destination MAC.' : '指示网卡物理芯片接收同物理网段所有广播、组播与单播穿透帧。' }}
                </div>
              </div>

              <div class="flex items-center justify-between pt-2">
                <span class="text-xs font-semibold" :class="promiscuousMode ? 'text-emerald-600 dark:text-emerald-400' : 'text-(--text-muted)'">
                  {{ promiscuousMode ? (locale === 'en-US' ? 'Enabled (Full Promisc)' : '已启用 (全网广播/穿透监听)') : (locale === 'en-US' ? 'Disabled (Unicast Only)' : '已禁用 (仅监听直达本机单播)') }}
                </span>
                <input type="checkbox" v-model="promiscuousMode" class="w-4 h-4 accent-sky-500 cursor-pointer" />
              </div>
            </div>

            <!-- 环形缓冲容量 -->
            <div class="p-4 rounded-xl border flex flex-col justify-between gap-3" style="background: var(--surface-content-alt); border-color: var(--border-subtle);">
              <div>
                <div class="text-xs font-bold" style="color: var(--text-primary)">
                  {{ locale === 'en-US' ? 'Kernel Ring Buffer Capacity' : '内核接收环形缓冲区大小' }}
                </div>
                <div class="text-[11px] mt-0.5" style="color: var(--text-muted)">
                  {{ locale === 'en-US' ? 'Allocated contiguous pinned memory to prevent packet drops during micro-bursts.' : '预分配锁页连续内存池，抵御突发网络微暴风雨造成的丢包。' }}
                </div>
              </div>

              <div class="flex items-center gap-2 pt-2">
                <select v-model.number="bufferSizeMb" class="ui-input w-full px-2 py-1 text-xs">
                  <option :value="16">16 MB ({{ locale === 'en-US' ? 'Low RAM Footprint' : '轻量低开销' }})</option>
                  <option :value="32">32 MB ({{ locale === 'en-US' ? 'Recommended Baseline' : '基线推荐' }})</option>
                  <option :value="64">64 MB ({{ locale === 'en-US' ? 'Burst-Drop Resistant' : '抗突发丢包强化' }})</option>
                  <option :value="128">128 MB ({{ locale === 'en-US' ? 'Heavy 10GbE Ingestion' : '重度大吞吐吸收' }})</option>
                </select>
              </div>
            </div>
          </div>
        </div>

        <!-- ==================== TAB 3: BPF 规则与专业预设库 ==================== -->
        <div v-else-if="activeTab === 'bpf'" class="space-y-4">
          <!-- BPF 输入框与实时语法校验指示 -->
          <div class="p-4 rounded-xl border space-y-2.5" style="background: var(--surface-content-alt); border-color: var(--border-subtle);">
            <div class="flex items-center justify-between">
              <label class="text-xs font-bold" style="color: var(--text-primary)">
                {{ locale === 'en-US' ? 'Berkeley Packet Filter (BPF) Expression' : 'Berkeley 报文过滤器 (BPF) 表达式' }}
              </label>
              <div class="flex items-center gap-1.5 text-xs font-semibold">
                <span v-if="bpfStatus === 'VALID'" class="text-emerald-600 dark:text-emerald-400 flex items-center gap-1">
                  <AppIcon name="check" :size="13" />
                  <span>{{ locale === 'en-US' ? 'BPF Syntax Valid' : 'BPF 语法验证通过 (内核编译就绪)' }}</span>
                </span>
                <span v-else-if="bpfStatus === 'ERROR'" class="text-rose-600 dark:text-rose-400 flex items-center gap-1" :title="bpfErrorMsg">
                  <AppIcon name="alert-triangle" :size="13" />
                  <span class="truncate max-w-[280px]">{{ bpfErrorMsg }}</span>
                </span>
                <span v-else class="text-(--text-muted)">
                  {{ locale === 'en-US' ? 'No Filter (Capture All)' : '无过滤 (全量捕获)' }}
                </span>
              </div>
            </div>

            <div class="relative">
              <input
                v-model="bpfInput"
                @input="onBpfInput"
                type="text"
                placeholder="例如: tcp port 80 or udp port 53"
                class="ui-input w-full px-3 py-2 text-xs font-mono pr-20"
                :class="{
                  'border-emerald-500 focus:border-emerald-500 ring-emerald-500/20': bpfStatus === 'VALID',
                  'border-rose-500 focus:border-rose-500 ring-rose-500/20': bpfStatus === 'ERROR'
                }"
              />
              <button
                v-if="bpfInput"
                @click="bpfInput = ''; onBpfInput()"
                class="absolute right-2 top-1/2 -translate-y-1/2 px-2 py-0.5 text-[10px] rounded hover:bg-(--surface-glass-pill) text-(--text-muted) cursor-pointer"
              >
                {{ locale === 'en-US' ? 'Clear' : '清空' }}
              </button>
            </div>

            <p class="text-[11px]" style="color: var(--text-muted)">
              {{ locale === 'en-US' ? 'BPF expressions compile directly to kernel bytecode via Npcap dead-capture offline compiler.' : 'BPF 表达式将在网卡驱动层由内核直接编译执行，过滤未匹配帧开销近乎为零。' }}
            </p>
          </div>

          <!-- 专业预设库分类按钮 -->
          <div class="space-y-2">
            <span class="text-xs font-bold uppercase tracking-wider" style="color: var(--text-primary)">
              {{ locale === 'en-US' ? 'One-Click Professional Presets' : '一键载入工业生产级常用 BPF 规则库' }}
            </span>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-2">
              <button
                v-for="preset in bpfPresets"
                :key="preset.filter"
                @click="applyPreset(preset.filter)"
                class="p-2.5 rounded-xl border border-(--border-subtle) hover:border-sky-500/50 hover:bg-sky-500/5 text-left transition-all flex flex-col gap-1 cursor-pointer"
              >
                <div class="flex items-center justify-between">
                  <span class="text-xs font-bold" style="color: var(--text-primary)">{{ preset.name }}</span>
                  <span class="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[var(--surface-glass-pill)] text-(--text-muted)">{{ preset.category }}</span>
                </div>
                <code class="text-[11px] font-mono text-sky-600 dark:text-sky-400 truncate">{{ preset.filter || '(Capture All)' }}</code>
                <span class="text-[10px]" style="color: var(--text-muted)">{{ preset.desc }}</span>
              </button>
            </div>
          </div>
        </div>

      </div>

      <!-- 底部控制与操作栏 -->
      <footer class="px-6 py-4 border-t flex items-center justify-between shrink-0" style="border-color: var(--border-subtle); background: var(--surface-content-alt);">
        <div class="flex items-center gap-3 text-xs" style="color: var(--text-muted);">
          <span>{{ locale === 'en-US' ? 'Target Adapter:' : '目标物理网卡:' }} <strong class="font-mono" style="color: var(--text-primary);">{{ selectedIface || 'auto' }}</strong></span>
          <span>|</span>
          <span>{{ locale === 'en-US' ? 'BPF:' : '过滤规则:' }} <strong class="font-mono text-sky-600 dark:text-sky-400">{{ bpfInput.trim() || (locale === 'en-US' ? 'None' : '全量') }}</strong></span>
        </div>

        <div class="flex items-center gap-3">
          <button
            @click="$emit('close')"
            class="ui-btn-secondary px-4 py-1.5 text-xs font-semibold cursor-pointer"
          >
            {{ locale === 'en-US' ? 'Cancel' : '取消' }}
          </button>

          <button
            @click="handleApplyAndStart"
            :disabled="bpfStatus === 'ERROR'"
            class="ui-btn-primary px-5 py-1.5 text-xs font-bold flex items-center gap-2 cursor-pointer disabled:opacity-50"
          >
            <AppIcon name="play" :size="13" />
            <span>{{ isRunning ? (locale === 'en-US' ? 'Apply & Re-bind Capture' : '应用配置并重开抓包') : (locale === 'en-US' ? 'Start Professional Capture' : '立即启动专业抓包') }}</span>
          </button>
        </div>
      </footer>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import AppIcon from './AppIcon.vue';
import { useI18n } from '../i18n';

const { locale } = useI18n();

const props = defineProps<{
  isOpen: boolean;
  currentIface: string;
  currentBpf: string;
  isRunning: boolean;
}>();

const emit = defineEmits<{
  (e: 'close'): void;
  (e: 'apply', payload: { iface: string; bpf: string; snaplen: number; promisc: boolean; bufferMb: number }): void;
}>();

type TabId = 'adapters' | 'options' | 'bpf';

const activeTab = ref<TabId>('adapters');
const selectedIface = ref('auto');
const bpfInput = ref('');
const bpfStatus = ref<'EMPTY' | 'VALID' | 'ERROR'>('EMPTY');
const bpfErrorMsg = ref('');
const snaplen = ref(65535);
const promiscuousMode = ref(true);
const bufferSizeMb = ref(32);
const isNpcapReady = ref(true);

interface DetailedInterface {
  name: string;
  description: string;
  friendly_name: string;
  ips: string[];
  mac: string;
  is_up: boolean;
  is_loopback: boolean;
  is_wireless: boolean;
  is_default_gateway: boolean;
}

const interfaces = ref<DetailedInterface[]>([]);
const isLoadingIfaces = ref(false);

const tabs = computed(() => [
  { id: 'adapters' as TabId, label: locale.value === 'en-US' ? 'Network Adapters' : '物理网卡画像', icon: 'activity' },
  { id: 'options' as TabId, label: locale.value === 'en-US' ? 'Capture Parameters' : '截断与缓冲参数', icon: 'settings' },
  { id: 'bpf' as TabId, label: locale.value === 'en-US' ? 'BPF Filter & Presets' : 'BPF 规则库与校验', icon: 'filter' },
]);

// 预设 BPF 规则集
const bpfPresets = computed(() => [
  {
    name: locale.value === 'en-US' ? 'Capture All Traffic' : '全量网络通信流量',
    category: 'Baseline',
    filter: '',
    desc: locale.value === 'en-US' ? 'No BPF restriction, captures all ingress/egress packets.' : '不过滤任何流量，全量收集物理介质上传输的报文。',
  },
  {
    name: locale.value === 'en-US' ? 'Industrial Modbus Protocol' : '工控 Modbus 专用规约',
    category: 'ICS / SCADA',
    filter: 'tcp port 502',
    desc: locale.value === 'en-US' ? 'Monitors industrial Modbus TCP telemetry and register writes.' : '捕获 PLC、RTU 与组态上位机之间的 Modbus TCP 寄存器交互。',
  },
  {
    name: locale.value === 'en-US' ? 'Water Conservancy SL651' : '水利水文遥测规约 (SL651)',
    category: 'National Std',
    filter: 'port 5003 or port 5002',
    desc: locale.value === 'en-US' ? 'China National Standard SL651 hydrology telemetry packets.' : '捕获遥测站上报的库水位、雨量及工况 BCD 规约报文。',
  },
  {
    name: locale.value === 'en-US' ? 'IoT MQTT Telemetry' : '物联网 MQTT 消息流',
    category: 'IoT Cloud',
    filter: 'tcp port 1883 or tcp port 8883',
    desc: locale.value === 'en-US' ? 'Inspects standard and TLS-wrapped MQTT broker transmissions.' : '采集边缘传感器发布与订阅的主题载荷数据。',
  },
  {
    name: locale.value === 'en-US' ? 'DNS Domain Resolution' : 'DNS 域名解析活动',
    category: 'Core Net',
    filter: 'udp port 53',
    desc: locale.value === 'en-US' ? 'Captures all DNS requests, responses, and PTR queries.' : '监控内网所有主机发起的域名解析与反向 PTR 记录。',
  },
  {
    name: locale.value === 'en-US' ? 'Cleartext Web Traffic' : 'HTTP 明文规约交互',
    category: 'Security',
    filter: 'tcp port 80',
    desc: locale.value === 'en-US' ? 'Audits insecure HTTP transmissions for potential leaks.' : '审计局域网未加密的 Web 明文接口与公文附件传输。',
  },
  {
    name: locale.value === 'en-US' ? 'TCP Handshake Probing' : 'TCP 三次握手事件探针',
    category: 'Diagnosis',
    filter: 'tcp[tcpflags] & (tcp-syn) != 0',
    desc: locale.value === 'en-US' ? 'Captures SYN packets to detect scans and new connections.' : '仅抓取 SYN 握手发起帧，快速发现内网端口扫描或资产漫游。',
  },
  {
    name: locale.value === 'en-US' ? 'ICMP Diagnostic Echo' : 'ICMP 物理层 Ping 诊断',
    category: 'L3 Echo',
    filter: 'icmp',
    desc: locale.value === 'en-US' ? 'Filters ping requests, unreachable replies, and TTL drops.' : '捕获网络探针、主机可达性探测及路由器超时差错报文。',
  },
]);

watch(() => props.isOpen, (open) => {
  if (open) {
    selectedIface.value = props.currentIface || 'auto';
    bpfInput.value = props.currentBpf || '';
    loadInterfaces();
    checkBpfValidity(bpfInput.value);
  }
});

let bpfDebounceTimer: any = null;
function onBpfInput() {
  clearTimeout(bpfDebounceTimer);
  bpfDebounceTimer = setTimeout(() => {
    checkBpfValidity(bpfInput.value);
  }, 200);
}

async function checkBpfValidity(filter: string) {
  if (!filter.trim()) {
    bpfStatus.value = 'EMPTY';
    bpfErrorMsg.value = '';
    return;
  }

  try {
    const res = await invoke<string>('validate_bpf_filter_cmd', { filter });
    if (res === 'VALID') {
      bpfStatus.value = 'VALID';
      bpfErrorMsg.value = '';
    } else {
      bpfStatus.value = 'EMPTY';
    }
  } catch (err: any) {
    bpfStatus.value = 'ERROR';
    bpfErrorMsg.value = String(err?.message || err);
  }
}

function applyPreset(filter: string) {
  bpfInput.value = filter;
  checkBpfValidity(filter);
}

async function loadInterfaces() {
  isLoadingIfaces.value = true;
  try {
    const list = await invoke<DetailedInterface[]>('get_detailed_network_interfaces_cmd');
    interfaces.value = list;
    if (list.length > 0 && selectedIface.value === 'auto') {
      const defaultOne = list.find(i => i.is_default_gateway);
      if (defaultOne) {
        selectedIface.value = defaultOne.name;
      }
    }
  } catch (err) {
    console.warn('[NetworkCaptureModal] Failed to get detailed interfaces:', err);
  } finally {
    isLoadingIfaces.value = false;
  }
}

function handleApplyAndStart() {
  if (bpfStatus.value === 'ERROR') return;
  emit('apply', {
    iface: selectedIface.value,
    bpf: bpfInput.value.trim(),
    snaplen: snaplen.value,
    promisc: promiscuousMode.value,
    bufferMb: bufferSizeMb.value,
  });
  emit('close');
}

onMounted(() => {
  if (props.isOpen) {
    loadInterfaces();
  }
});
</script>

<style scoped>
@keyframes fadeIn {
  from { opacity: 0; transform: scale(0.98); }
  to { opacity: 1; transform: scale(1); }
}
.animate-fade-in {
  animation: fadeIn 0.15s ease-out forwards;
}
</style>
