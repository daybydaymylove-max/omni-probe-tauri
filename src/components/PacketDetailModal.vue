<template>
  <div v-if="isOpen && packet" class="fixed inset-0 z-50 flex items-center justify-center p-4 ui-modal-backdrop">
    <div class="w-full max-w-5xl max-h-[92vh] ui-modal-surface rounded-3xl flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-200">
      
      <!-- 顶栏：报文元数据与关闭按钮 (Liquid Glass) -->
      <header class="ui-nav-glass border-b px-6 py-3.5 flex items-center justify-between shrink-0 flex-wrap gap-3">
        <div class="flex items-center gap-3">
          <span class="w-3 h-3 rounded-full bg-sky-500 shrink-0"></span>
          <div>
            <h3 class="text-sm font-bold flex items-center gap-2 flex-wrap" style="color: var(--text-primary)">
              <span>工业全景深度解剖器</span>
              <span class="text-xs ui-num font-normal" style="color: var(--text-muted)">#{{ packet.id }}</span>
              <span class="text-[11px] px-2 py-0.5 rounded-full font-bold bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30">
                纯自主内生解析
              </span>
            </h3>
            <div class="text-[11px] ui-num flex items-center gap-2 mt-0.5 flex-wrap" style="color: var(--text-muted)">
              <span>捕获时间: <strong style="color: var(--text-secondary)">{{ packet.timestamp }}</strong></span>
              <span>·</span>
              <span>长度: <strong style="color: var(--text-secondary)">{{ packet.length }}</strong> 字节</span>
              <span>·</span>
              <span>总线: <strong style="color: var(--text-secondary)">{{ packet.transport }}</strong></span>
              <span>·</span>
              <span>规约: <strong class="text-blue-700 dark:text-sky-300">{{ packet.protocol }}</strong></span>
            </div>
          </div>
        </div>

        <div class="flex items-center gap-2 flex-wrap">
          <button @click="copyHex" class="ui-btn-secondary text-xs px-3 py-1.5 rounded-xl">
            <AppIcon :name="isHexCopied ? 'check' : 'code'" :size="12" />
            <span>{{ isHexCopied ? '已复制 HEX' : '复制 HEX' }}</span>
          </button>
          <button @click="copyAscii" class="ui-btn-secondary text-xs px-3 py-1.5 rounded-xl">
            <AppIcon :name="isAsciiCopied ? 'check' : 'document'" :size="12" />
            <span>{{ isAsciiCopied ? '已复制 ASCII' : '复制 ASCII' }}</span>
          </button>
          <button @click="$emit('replayPacket', packet)" class="ui-btn-primary text-xs px-3 py-1.5 rounded-xl">
            <AppIcon name="play" :size="12" />
            <span>L4 重放</span>
          </button>
          <button @click="$emit('saveBaseline', packet)" class="px-3 py-1.5 rounded-xl text-xs font-bold bg-teal-500/15 hover:bg-teal-500/25 text-teal-700 dark:text-teal-300 border border-teal-500/30 transition-colors cursor-pointer flex items-center gap-1">
            <AppIcon name="archive" :size="12" />
            <span>存为基线</span>
          </button>
          <button @click="$emit('close')" class="w-8 h-8 rounded-full ui-pill flex items-center justify-center cursor-pointer ml-1" title="关闭">
            <AppIcon name="close" :size="15" />
          </button>
        </div>
      </header>

      <!-- 选项卡切换 -->
      <div class="px-6 border-b flex items-center gap-5 text-xs font-semibold shrink-0 overflow-x-auto" style="background: var(--surface-content-alt); border-color: var(--border-subtle)">
        <button v-for="tab in tabs" :key="tab.id" @click="selectTab(tab.id)"
          :class="[
            'py-3 transition-colors cursor-pointer border-b-2 flex items-center gap-2 shrink-0',
            activeTab === tab.id ? 'border-sky-500 font-bold' : 'border-transparent hover:opacity-80'
          ]"
          :style="{ color: activeTab === tab.id ? 'var(--accent-primary-text)' : 'var(--text-muted)' }">
          <span>{{ tab.label }}</span>
          <span v-if="tab.badge" :class="[
            'text-[11px] px-2 py-0.5 rounded-full ui-num font-bold border',
            tab.id === 'native_tree' ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/30' :
            tab.id === 'tshark' ? 'bg-indigo-500/15 text-indigo-700 dark:text-indigo-300 border-indigo-500/30' :
            'ui-pill'
          ]">
            {{ tab.badge }}
          </span>
        </button>
      </div>

      <!-- 模态框主体内容 -->
      <div class="flex-1 overflow-auto custom-scrollbar p-6 min-h-[380px] max-h-[62vh]" style="background: var(--surface-content)">
        
        <!-- 选项卡 1：自研全协议原生逐层解剖树 -->
        <div v-if="activeTab === 'native_tree'" class="space-y-3 text-xs">
          <div class="px-4 py-2.5 rounded-2xl border bg-emerald-500/10 border-emerald-500/25 flex items-center justify-between text-xs flex-wrap gap-2">
            <div class="flex items-center gap-2 text-emerald-700 dark:text-emerald-300">
              <span class="w-2 h-2 rounded-full bg-emerald-500"></span>
              <span class="font-bold">自主内生全协议状态机解构中</span>
              <span class="font-normal opacity-80">· 无需第三方工具 · 纯 Rust 深度解析</span>
            </div>
            <div class="text-[11px] ui-num text-emerald-700 dark:text-emerald-300">
              <span>协议层级: <strong>{{ nativeProtocolLayers.length }}</strong> 层</span>
              <span class="mx-2">·</span>
              <span>解析字段: <strong>{{ totalNativeFieldsCount }}</strong> 项</span>
            </div>
          </div>

          <div class="space-y-2.5">
            <div v-for="layer in nativeProtocolLayers" :key="layer.id" class="ui-content-card overflow-hidden">
              <div @click="toggleNativeLayer(layer.id)"
                class="px-4 py-3 border-b flex items-center justify-between cursor-pointer hover:bg-black/5 dark:hover:bg-white/5 transition-colors select-none"
                style="background: var(--surface-content-alt); border-color: var(--border-subtle)">
                <div class="flex items-center gap-2.5 min-w-0">
                  <AppIcon :name="expandedNativeLayers[layer.id] ? 'chevron-down' : 'chevron-right'" :size="14" style="color: var(--text-muted)" />
                  <span :class="['px-2 py-0.5 rounded-lg text-[11px] font-bold tracking-wider uppercase border', layer.badgeClass]">
                    {{ layer.badge }}
                  </span>
                  <span class="font-bold text-xs" style="color: var(--text-primary)">{{ layer.title }}</span>
                  <span class="text-[11px] font-normal hidden sm:inline truncate" style="color: var(--text-muted)">{{ layer.subtitle }}</span>
                </div>
                <div class="flex items-center gap-2 shrink-0">
                  <span v-if="layer.warning" class="px-2 py-0.5 rounded-full text-[11px] font-bold bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/30">
                    {{ layer.warning }}
                  </span>
                  <span class="text-[11px] ui-num" style="color: var(--text-muted)">
                    {{ layer.fields.length }} 个参数
                  </span>
                </div>
              </div>

              <div v-if="expandedNativeLayers[layer.id]" class="p-3">
                <div class="grid grid-cols-1 md:grid-cols-2 gap-2">
                  <div v-for="field in layer.fields" :key="field.name"
                    class="ui-sub-card p-2.5 hover:border-sky-500/40 transition-colors flex flex-col gap-1">
                    <div class="flex items-center justify-between text-[11px]">
                      <span class="font-semibold" style="color: var(--text-secondary)">{{ field.label }}</span>
                      <span class="text-[11px] ui-num uppercase" style="color: var(--text-muted)">{{ field.name }}</span>
                    </div>
                    <div class="flex items-center justify-between gap-2 mt-0.5">
                      <span :class="['ui-num font-bold text-xs break-all select-text', field.highlightClass || '']" :style="!field.highlightClass ? { color: 'var(--text-primary)' } : undefined">
                        {{ field.value }}
                      </span>
                      <span v-if="field.hexDesc" class="text-[11px] ui-num shrink-0" style="color: var(--text-muted)">
                        {{ field.hexDesc }}
                      </span>
                    </div>
                    <div v-if="field.extraNote" class="text-[11px] px-2 py-1 rounded mt-0.5" style="background: var(--surface-content); color: var(--text-secondary)">
                      {{ field.extraNote }}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- 选项卡 2：16 字节对齐 HexDump + ASCII -->
        <div v-else-if="activeTab === 'hexdump'" class="h-full flex flex-col gap-2">
          <div class="flex items-center justify-between text-xs ui-num" style="color: var(--text-muted)">
            <span>标准 16 字节边界对齐物理转储 (Offset | 00..07 08..0F | ASCII)</span>
            <span>载荷长度: {{ cleanHex.length / 2 }} Bytes</span>
          </div>

          <div class="flex-1 ui-sub-card p-4 font-mono-code text-xs overflow-auto select-text">
            <div class="font-bold border-b pb-1.5 mb-2 select-none" style="color: var(--text-muted); border-color: var(--border-subtle)">
              偏移量 | 00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F | ASCII 文本解析
            </div>
            <div v-for="(line, idx) in formattedHexLines" :key="idx" class="leading-relaxed hover:bg-black/5 dark:hover:bg-white/5 px-1 rounded transition-colors">
              <span style="color: var(--text-muted)">{{ line.offset }} | </span>
              <span class="text-emerald-700 dark:text-emerald-400 font-semibold">{{ line.part1 }} </span>
              <span style="color: var(--border-strong)"> </span>
              <span class="text-teal-700 dark:text-teal-300 font-semibold">{{ line.part2 }} | </span>
              <span class="text-sky-700 dark:text-sky-300">{{ line.ascii }}</span>
            </div>
            <EmptyState
              v-if="formattedHexLines.length === 0"
              class="py-10"
              icon="code"
              title="无应用层载荷"
              description="该数据包仅包含物理层与链路层握手控制元数据。"
            />
          </div>
        </div>

        <!-- 选项卡 3：分层报头树 (L2-L4) -->
        <div v-else-if="activeTab === 'layers'" class="space-y-4 ui-num text-xs select-text">
          <div class="ui-content-card p-4">
            <div class="font-bold text-sm mb-2.5 flex items-center gap-2 font-sans" style="color: var(--text-primary)">
              <span class="w-2.5 h-2.5 rounded-full bg-blue-500"></span>
              <span>Layer 2: Data Link Layer (数据链路层 / 以太网)</span>
            </div>
            <div class="grid grid-cols-2 md:grid-cols-4 gap-3" style="color: var(--text-secondary)">
              <div>源 MAC: <strong class="block font-bold" style="color: var(--text-primary)">{{ packet.mac_src || '00:00:00:00:00:00' }}</strong></div>
              <div>目的 MAC: <strong class="block font-bold" style="color: var(--text-primary)">{{ packet.mac_dst || '00:00:00:00:00:00' }}</strong></div>
              <div>以太网类型: <strong class="block font-bold" style="color: var(--text-primary)">IPv4 (0x0800)</strong></div>
              <div>帧总长度: <strong class="block font-bold" style="color: var(--text-primary)">{{ packet.length }} Bytes</strong></div>
            </div>
          </div>

          <div class="ui-content-card p-4">
            <div class="font-bold text-sm mb-2.5 flex items-center gap-2 font-sans" style="color: var(--text-primary)">
              <span class="w-2.5 h-2.5 rounded-full bg-emerald-500"></span>
              <span>Layer 3: Internet Protocol (网络层 / IPv4)</span>
            </div>
            <div class="grid grid-cols-2 md:grid-cols-4 gap-3" style="color: var(--text-secondary)">
              <div>源 IP: <strong class="text-blue-700 dark:text-sky-300 block font-bold" :title="formatRemoteIp(packet)">{{ formatRemoteIp(packet) }}</strong></div>
              <div>目的 IP: <strong class="text-blue-700 dark:text-sky-300 block font-bold">{{ packet.dst_ip }}</strong></div>
              <div>信息熵 (Entropy): 
                <strong :class="packet.entropy >= 7.5 ? 'text-rose-700 dark:text-rose-400 font-bold block' : 'font-bold block'" :style="packet.entropy < 7.5 ? { color: 'var(--text-primary)' } : undefined">
                  {{ packet.entropy ? packet.entropy.toFixed(3) : '0.000' }} ({{ packet.entropy_level }})
                </strong>
              </div>
              <div>防篡改哈希: <span class="text-[11px] block truncate" style="color: var(--text-muted)" :title="packet.chain_hash">{{ packet.chain_hash }}</span></div>
            </div>
            <div v-if="packet.business_data?.src_geo || packet.business_data?.src_zone"
              class="mt-3 pt-3 border-t grid grid-cols-2 md:grid-cols-4 gap-3" style="border-color: var(--border-subtle); color: var(--text-secondary)">
              <div>源 IP 归属地: <strong class="block" style="color: var(--text-primary)">{{ packet.business_data?.src_geo || '未知' }}</strong></div>
              <div>安全域划分: <strong class="text-indigo-700 dark:text-indigo-300 block">{{ packet.business_data?.src_zone || '未划分' }}</strong></div>
              <div>网络运营商 (ISP): <strong class="block" style="color: var(--text-primary)">{{ packet.business_data?.src_isp || 'N/A' }}</strong></div>
              <div>目的端安全域: <strong class="block" style="color: var(--text-primary)">{{ packet.business_data?.dst_zone || '未划分' }}</strong></div>
            </div>
          </div>

          <div class="ui-content-card p-4">
            <div class="font-bold text-sm mb-2.5 flex items-center gap-2 font-sans" style="color: var(--text-primary)">
              <span class="w-2.5 h-2.5 rounded-full bg-indigo-500"></span>
              <span>Layer 4: Transport Layer (传输层 / {{ packet.transport }})</span>
            </div>
            <div class="grid grid-cols-2 md:grid-cols-4 gap-3" style="color: var(--text-secondary)">
              <div>传输协议: <strong class="text-indigo-700 dark:text-indigo-300 block font-bold">{{ packet.transport }}</strong></div>
              <div>源端口: <strong class="block font-bold" style="color: var(--text-primary)">{{ packet.src_port }}</strong></div>
              <div>目的端口: <strong class="block font-bold" style="color: var(--text-primary)">{{ packet.dst_port }}</strong></div>
              <div>规约特征: <strong class="text-emerald-700 dark:text-emerald-400 block font-bold">{{ packet.protocol }}</strong></div>
            </div>
          </div>
        </div>

        <!-- 选项卡 4：原生工控与通用规约解析字典 -->
        <div v-else-if="activeTab === 'dissection'" class="h-full">
          <div v-if="packet.business_data && Object.keys(packet.business_data).length > 0" class="ui-content-card p-5">
            <div class="font-bold text-sm mb-3 border-b pb-2 flex items-center justify-between" style="color: var(--text-primary); border-color: var(--border-subtle)">
              <span>{{ packet.protocol }} 原生 Rust 规约字典解析明细</span>
              <span class="text-xs font-normal ui-num" style="color: var(--text-muted)">共 {{ Object.keys(packet.business_data).length }} 项字段</span>
            </div>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-3 ui-num text-xs select-text">
              <div v-for="(val, key) in packet.business_data" :key="key" class="ui-sub-card p-3 flex flex-col gap-1">
                <span class="text-[11px] uppercase font-bold tracking-wider" style="color: var(--text-muted)">{{ key }}</span>
                <span class="font-bold text-sm break-all" style="color: var(--text-primary)">{{ val }}</span>
              </div>
            </div>
          </div>
          <EmptyState
            v-else
            class="py-14"
            icon="layers"
            title="未匹配原生专精规约字典"
            description="载荷可能属于非标编码，可调用 Wireshark 全量通用解剖引擎继续探测。"
          >
            <template #actions>
              <button @click="selectTab('tshark')" class="ui-btn-secondary text-xs">
                <span>切换至 Wireshark 全量通用解剖引擎</span>
                <AppIcon name="arrow-right" :size="12" />
              </button>
            </template>
          </EmptyState>
        </div>

        <!-- 选项卡 5：Wireshark 3000+ 官方全量解剖树 -->
        <div v-else-if="activeTab === 'tshark'" class="space-y-4">
          <div class="ui-sub-card p-4 flex items-center justify-between flex-wrap gap-3">
            <div class="flex items-center gap-3">
              <div class="w-9 h-9 rounded-xl bg-blue-600 text-white flex items-center justify-center font-bold text-xs shrink-0">
                WS
              </div>
              <div>
                <div class="text-xs font-bold flex items-center gap-2 flex-wrap" style="color: var(--text-primary)">
                  <span>Wireshark / TShark 官方全量解剖引擎</span>
                  <span v-if="tsharkStatus?.is_available" class="text-[11px] bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 px-2 py-0.5 rounded-full ui-num font-bold border border-emerald-500/30">
                    引擎在线 (3,200+ 规约库)
                  </span>
                  <span v-else class="text-[11px] bg-amber-500/15 text-amber-700 dark:text-amber-300 px-2 py-0.5 rounded-full ui-num font-bold border border-amber-500/30">
                    未检测到引擎 (纯离线自研引擎接管)
                  </span>
                </div>
                <div class="text-[11px] ui-num mt-0.5" style="color: var(--text-muted)">
                  {{ tsharkStatus?.version || 'TShark 检测中...' }} · 跨进程纯内存管道
                </div>
              </div>
            </div>

            <button @click="runTsharkDissection" :disabled="tsharkLoading || !tsharkStatus?.is_available" class="ui-btn-primary text-xs px-3.5 py-1.5 rounded-xl">
              <AppIcon name="refresh" :size="12" :class="tsharkLoading ? 'animate-spin' : ''" />
              <span>{{ tsharkLoading ? '正在解剖...' : '重新全量解剖' }}</span>
            </button>
          </div>

          <div v-if="tsharkLoading" class="flex flex-col items-center justify-center py-16 gap-3" style="color: var(--text-muted)">
            <div class="w-8 h-8 border-2 border-sky-500 border-t-transparent rounded-full animate-spin"></div>
            <span class="text-xs ui-num">正在通过内存管道调用 Wireshark 解剖器...</span>
          </div>

          <div v-else-if="tsharkResult && tsharkResult.success" class="space-y-3">
            <div class="ui-sub-card px-4 py-2.5 flex items-center justify-between text-xs ui-num">
              <span class="font-semibold" style="color: var(--text-primary)">{{ tsharkResult.summary_text }}</span>
              <span class="text-[11px]" style="color: var(--text-muted)">执行耗时: <strong>{{ tsharkResult.execution_time_ms }}</strong> ms</span>
            </div>

            <div class="space-y-2.5">
              <div v-for="(layerData, layerName) in tsharkResult.layers" :key="layerName" class="ui-content-card overflow-hidden">
                <div @click="toggleLayerExpand(String(layerName))"
                  class="px-4 py-2.5 hover:bg-black/5 dark:hover:bg-white/5 border-b flex items-center justify-between cursor-pointer transition-colors"
                  style="background: var(--surface-content-alt); border-color: var(--border-subtle)">
                  <div class="flex items-center gap-2 text-xs font-bold ui-num" style="color: var(--text-primary)">
                    <AppIcon :name="expandedLayers[String(layerName)] ? 'chevron-down' : 'chevron-right'" :size="13" style="color: var(--text-muted)" />
                    <span class="text-blue-700 dark:text-sky-300 uppercase">{{ layerName }}</span>
                    <span class="text-[11px] font-normal font-sans" style="color: var(--text-muted)">协议层</span>
                  </div>
                  <span class="text-[11px] ui-num" style="color: var(--text-muted)">
                    {{ isObject(layerData) ? Object.keys(layerData).length + ' 项属性' : '基础标量' }}
                  </span>
                </div>

                <div v-if="expandedLayers[String(layerName)]" class="p-3 text-xs ui-num">
                  <div v-if="isObject(layerData)" class="space-y-1">
                    <div v-for="(val, field) in layerData" :key="field"
                      class="grid grid-cols-1 md:grid-cols-3 gap-2 py-1 px-2 rounded hover:bg-black/5 dark:hover:bg-white/5 transition-colors border-b last:border-0"
                      style="border-color: var(--border-subtle)">
                      <span class="text-[11px] font-semibold truncate" style="color: var(--text-muted)" :title="String(field)">{{ field }}</span>
                      <span class="col-span-2 break-all select-text text-[11px]" style="color: var(--text-primary)">{{ formatLayerValue(val) }}</span>
                    </div>
                  </div>
                  <div v-else class="p-2 break-all select-text" style="color: var(--text-primary)">
                    {{ layerData }}
                  </div>
                </div>
              </div>
            </div>
          </div>

          <EmptyState
            v-else
            class="py-10"
            icon="cpu"
            title="当前处于纯自主内生解析模式"
            description="宿主机未安装 Wireshark 或处于隔离环境，所有采集、解析与时序基线均由自研纯 Rust 原生引擎独立完成。"
          >
            <template #actions>
              <button @click="selectTab('native_tree')" class="ui-btn-primary text-xs">
                <span>查看自研原生逐层解剖树</span>
                <AppIcon name="arrow-right" :size="12" />
              </button>
            </template>
          </EmptyState>
        </div>

      </div>

      <!-- 底栏状态汇总 -->
      <footer class="px-6 py-3 border-t flex items-center justify-between text-[11px] ui-num shrink-0 flex-wrap gap-2" style="background: var(--surface-content-alt); border-color: var(--border-subtle); color: var(--text-muted)">
        <div class="flex items-center gap-2">
          <span>防篡改哈希: <strong class="font-normal truncate max-w-[280px] inline-block align-bottom" style="color: var(--text-primary)" :title="packet.chain_hash">{{ packet.chain_hash }}</strong></span>
        </div>
        <div class="flex items-center gap-3">
          <span>信息熵: <strong style="color: var(--text-primary)">{{ packet.entropy ? packet.entropy.toFixed(3) : '0.000' }}</strong> ({{ packet.entropy_level }})</span>
          <span>·</span>
          <span class="text-emerald-700 dark:text-emerald-400 font-semibold">自研纯 Rust 内核运行正常</span>
        </div>
      </footer>

    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import AppIcon from './AppIcon.vue';
import EmptyState from './EmptyState.vue';
interface PacketRecord {
  id: number;
  timestamp: string;
  timestamp_ns?: number;
  direction: string;
  transport: string;
  protocol: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  length: number;
  payload_hex: string;
  raw_frame_hex?: string;
  entropy: number;
  entropy_level: string;
  mac_src: string;
  mac_dst: string;
  chain_hash: string;
  business_data?: Record<string, any>;
  raw_text?: string;
}

const props = defineProps<{
  isOpen: boolean;
  packet: PacketRecord | null;
}>();

defineEmits(['close', 'replayPacket', 'saveBaseline']);

const tabs = [
  { id: 'native_tree', label: '自研原生逐层解剖 (OSI 7层)', badge: '纯自主内生' },
  { id: 'hexdump', label: '十六进制与 ASCII 转储', badge: '16字节对齐' },
  { id: 'tshark', label: 'Wireshark 官方 3200+ 辅助对照', badge: '可选管道' },
];
const activeTab = ref('native_tree');

const isHexCopied = ref(false);
const isAsciiCopied = ref(false);

// TShark 状态与解剖结果
const tsharkStatus = ref<any>(null);
const tsharkResult = ref<any>(null);
const tsharkLoading = ref(false);
const expandedLayers = ref<Record<string, boolean>>({});

// 自研原生协议层折叠状态 (默认全展开)
const expandedNativeLayers = ref<Record<string, boolean>>({
  frame: true,
  ethernet: true,
  network: true,
  transport: true,
  application: true,
  security: true,
});

function toggleNativeLayer(layerId: string) {
  expandedNativeLayers.value[layerId] = !expandedNativeLayers.value[layerId];
}

const cleanHex = computed(() => {
  if (!props.packet?.payload_hex) return '';
  return props.packet.payload_hex.replace(/\s+/g, '');
});

// =============================================================================
// 自研全协议原生逐层解剖树生成逻辑 (Native Universal Protocol Tree Builder)
// 100% 纯自研、纯离线、零外部依赖
// =============================================================================
interface NativeField {
  name: string;
  label: string;
  value: string;
  hexDesc?: string;
  highlightClass?: string;
  extraNote?: string;
}

interface NativeLayer {
  id: string;
  title: string;
  subtitle: string;
  badge: string;
  badgeClass: string;
  warning?: string;
  fields: NativeField[];
}

interface RealParsedHeaders {
  ipTtl?: number;
  ipTotalLen?: number;
  ipFlagsDesc?: string;
  tcpSeq?: number;
  tcpAck?: number;
  tcpFlagsDesc?: string;
  tcpWindow?: number;
  tcpChecksumHex?: string;
}

function parseRealEthernetHeaders(rawFrameHex?: string): RealParsedHeaders {
  if (!rawFrameHex) return {};
  const cleaned = rawFrameHex.replace(/\s+/g, '');
  if (cleaned.length < 68) return {}; // 至少 14B Ethernet + 20B IPv4
  const bytes: number[] = [];
  for (let i = 0; i + 1 < cleaned.length; i += 2) {
    const v = parseInt(cleaned.slice(i, i + 2), 16);
    if (Number.isNaN(v)) return {};
    bytes.push(v);
  }
  if (bytes.length < 34) return {};
  const isVlan = bytes[12] === 0x81 && bytes[13] === 0x00;
  const ethLen = isVlan ? 18 : 14;
  if (bytes.length < ethLen + 20) return {};
  const etherType = (bytes[ethLen - 2] << 8) | bytes[ethLen - 1];
  if (etherType !== 0x0800) return {}; // 仅解析 IPv4 首部

  const ipVer = bytes[ethLen] >> 4;
  const ihl = (bytes[ethLen] & 0x0f) * 4;
  if (ipVer !== 4 || ihl < 20 || bytes.length < ethLen + ihl) return {};

  const ipTotalLen = (bytes[ethLen + 2] << 8) | bytes[ethLen + 3];
  const flagsBits = (bytes[ethLen + 6] >> 5) & 0x07;
  const ipFlagsDesc = (flagsBits & 0x02) !== 0
    ? "0x02 (Don't Fragment / DF)"
    : ((flagsBits & 0x01) !== 0 ? '0x01 (More Fragments / MF)' : `0x${flagsBits.toString(16).padStart(2, '0')}`);
  const ipTtl = bytes[ethLen + 8];
  const ipProto = bytes[ethLen + 9];

  const out: RealParsedHeaders = { ipTtl, ipTotalLen, ipFlagsDesc };
  if (ipProto === 6 && bytes.length >= ethLen + ihl + 20) {
    const tcpOff = ethLen + ihl;
    const tcpSeq = (((bytes[tcpOff + 4] << 24) | (bytes[tcpOff + 5] << 16) | (bytes[tcpOff + 6] << 8) | bytes[tcpOff + 7]) >>> 0);
    const tcpAck = (((bytes[tcpOff + 8] << 24) | (bytes[tcpOff + 9] << 16) | (bytes[tcpOff + 10] << 8) | bytes[tcpOff + 11]) >>> 0);
    const rawFlags = bytes[tcpOff + 13];
    const flagNames: string[] = [];
    if (rawFlags & 0x01) flagNames.push('FIN');
    if (rawFlags & 0x02) flagNames.push('SYN');
    if (rawFlags & 0x04) flagNames.push('RST');
    if (rawFlags & 0x08) flagNames.push('PSH');
    if (rawFlags & 0x10) flagNames.push('ACK');
    if (rawFlags & 0x20) flagNames.push('URG');
    const tcpFlagsDesc = flagNames.length > 0 ? `${flagNames.join(', ')} (0x${rawFlags.toString(16).padStart(2, '0')})` : `0x${rawFlags.toString(16).padStart(2, '0')}`;
    const tcpWindow = (bytes[tcpOff + 14] << 8) | bytes[tcpOff + 15];
    const tcpChecksumHex = `0x${((bytes[tcpOff + 16] << 8) | bytes[tcpOff + 17]).toString(16).toUpperCase().padStart(4, '0')}`;
    out.tcpSeq = tcpSeq;
    out.tcpAck = tcpAck;
    out.tcpFlagsDesc = tcpFlagsDesc;
    out.tcpWindow = tcpWindow;
    out.tcpChecksumHex = tcpChecksumHex;
  }
  return out;
}

const nativeProtocolLayers = computed<NativeLayer[]>(() => {
  const p = props.packet;
  if (!p) return [];

  const layers: NativeLayer[] = [];
  const bdata = p.business_data || {};
  const parsedHdr = parseRealEthernetHeaders(p.raw_frame_hex);

  // ---------------------------------------------------------------------------
  // 1. Frame 物理与时间戳元数据层
  // ---------------------------------------------------------------------------
  const frameFields: NativeField[] = [
    { name: 'frame.number', label: '全局报文序号 (ID)', value: `#${p.id}`, highlightClass: 'text-blue-700 dark:text-sky-300' },
    { name: 'frame.time', label: '系统捕获绝对时间', value: p.timestamp },
    { name: 'frame.time_ns', label: '纳秒单调时钟戳 (Epoch ns)', value: String(p.timestamp_ns || 'N/A') },
    { name: 'frame.len', label: '物理帧原始长度', value: `${p.length} 字节`, hexDesc: `0x${p.length.toString(16).toUpperCase()}` },
    { name: 'frame.cap_len', label: '探针捕获存储长度', value: `${cleanHex.value.length / 2} 字节` },
    { name: 'frame.entropy', label: '香农信息熵 (Entropy)', value: `${p.entropy ? p.entropy.toFixed(4) : '0.0000'} bit/B (${p.entropy_level})`, highlightClass: p.entropy >= 7.2 ? 'text-amber-700 dark:text-amber-300 font-bold' : '' },
    { name: 'frame.merkle_hash', label: '防伪存证链式哈希 (SHA256)', value: p.chain_hash || 'PENDING' },
    { name: 'frame.bus_mode', label: '采集总线与流向', value: `${p.transport} · ${p.direction}`, highlightClass: 'text-indigo-700 dark:text-indigo-300' },
  ];
  layers.push({
    id: 'frame',
    title: 'Frame 1: 物理层与到达时序元数据',
    subtitle: `到达时间: ${p.timestamp} · 长度: ${p.length}B`,
    badge: 'PHY/TS',
    badgeClass: 'ui-pill',
    fields: frameFields,
  });

  // ---------------------------------------------------------------------------
  // 2. Layer 2: Ethernet II 以太网数据链路层 (硬件 OUI 与规约知识库解析)
  // ---------------------------------------------------------------------------
  const srcVendor = bdata.src_mac_vendor_cn ? ` [${bdata.src_mac_vendor_cn}]` : '';
  const dstVendor = bdata.dst_mac_vendor_cn ? ` [${bdata.dst_mac_vendor_cn}]` : '';
  const etherType = bdata.ethertype_name 
    ? `${bdata.ethertype_name} - ${bdata.ethertype_desc}`
    : (p.src_ip.includes(':') ? '0x86DD (IPv6)' : p.protocol === 'ARP' ? '0x0806 (ARP)' : '0x0800 (IPv4)');

  const ethFields: NativeField[] = [
    { name: 'eth.dst', label: '目的物理 MAC 地址', value: `${p.mac_dst || '00:00:00:00:00:00'}${dstVendor}`, highlightClass: 'font-bold' },
    { name: 'eth.src', label: '源物理 MAC 地址', value: `${p.mac_src || '00:00:00:00:00:00'}${srcVendor}`, highlightClass: 'font-bold' },
    { name: 'eth.type', label: '以太网协议类型 (EtherType)', value: etherType, highlightClass: 'text-blue-700 dark:text-sky-300 font-mono-code' },
    { name: 'eth.fcs', label: '帧校验和 (FCS)', value: '物理 NIC 校验 (驱动层剥离 FCS 尾帧)' },
  ];
  if (bdata.src_device_cat) {
    ethFields.push({ name: 'eth.src_category', label: '源端工业设备类型', value: String(bdata.src_device_cat), highlightClass: 'text-indigo-700 dark:text-indigo-300 font-bold' });
  }
  layers.push({
    id: 'ethernet',
    title: 'Layer 2: Ethernet II (以太网数据链路层)',
    subtitle: `${p.mac_src || '00:..'}${srcVendor} → ${p.mac_dst || '00:..'}${dstVendor}`,
    badge: bdata.is_industrial_l2 ? 'IND ETH' : 'L2 ETH',
    badgeClass: bdata.is_industrial_l2 ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30' : 'bg-blue-500/15 text-blue-700 dark:text-sky-300 border-blue-500/30',
    fields: ethFields,
  });

  // ---------------------------------------------------------------------------
  // 3. Layer 3: Internet Protocol 网络层 (IPv4 / IPv6 / ARP)
  // ---------------------------------------------------------------------------
  const netFields: NativeField[] = [
    { name: 'ip.src', label: '源网络 IP 地址', value: p.src_ip, highlightClass: 'text-blue-700 dark:text-sky-300 font-bold' },
    { name: 'ip.dst', label: '目的网络 IP 地址', value: p.dst_ip, highlightClass: 'text-blue-700 dark:text-sky-300 font-bold' },
    { name: 'ip.proto', label: '传输层规约代码', value: `${p.transport} (${p.transport === 'TCP' ? 6 : p.transport === 'UDP' ? 17 : 1})` },
    { name: 'ip.ttl', label: '生存时间 (TTL)', value: bdata.ip_ttl !== undefined ? String(bdata.ip_ttl) : (parsedHdr.ipTtl !== undefined ? String(parsedHdr.ipTtl) : '未提取 (非原始 L3 头)') },
    { name: 'ip.total_len', label: 'IP 报文总长度', value: parsedHdr.ipTotalLen !== undefined ? `${parsedHdr.ipTotalLen} 字节` : `${Math.max(0, p.length - 14)} 字节 (含载荷估计)` },
    { name: 'ip.flags', label: '分片标志 (Flags)', value: parsedHdr.ipFlagsDesc ?? '未提取 (无原始 IP 头部字节)' },
  ];

  if (bdata.src_geo || bdata.src_zone || bdata.src_isp) {
    netFields.push({
      name: 'ip.src_geo',
      label: '源端地理定位与安全域',
      value: `${bdata.src_geo || '本地局域网'} [${bdata.src_zone || '工业控制网'}]`,
      highlightClass: 'text-indigo-700 dark:text-indigo-300 font-semibold',
      extraNote: bdata.src_isp ? `运营商: ${bdata.src_isp}` : undefined,
    });
  }

  layers.push({
    id: 'network',
    title: `Layer 3: Internet Protocol (${p.src_ip.includes(':') ? 'IPv6' : 'IPv4'})`,
    subtitle: `${p.src_ip} → ${p.dst_ip}`,
    badge: 'L3 IP',
    badgeClass: 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/30',
    fields: netFields,
  });

  // ---------------------------------------------------------------------------
  // 4. Layer 4: Transport Layer 传输层 (TCP / UDP / ICMP / SERIAL)
  // ---------------------------------------------------------------------------
  const transFields: NativeField[] = [
    { name: 'trans.srcport', label: '源端口 (Source Port)', value: String(p.src_port) },
    { name: 'trans.dstport', label: '目的端口 (Dest Port)', value: String(p.dst_port), highlightClass: 'text-indigo-700 dark:text-indigo-300 font-bold' },
    { name: 'trans.service', label: '推断工业服务', value: p.protocol, highlightClass: 'text-emerald-700 dark:text-emerald-300 font-bold' },
  ];

  if (p.transport === 'TCP') {
    const seq = bdata.sequence_number ?? parsedHdr.tcpSeq;
    const ack = bdata.acknowledgment_number ?? parsedHdr.tcpAck;
    const win = bdata.window_size ?? parsedHdr.tcpWindow;
    const flags = bdata.flags ?? parsedHdr.tcpFlagsDesc;

    transFields.push(
      { name: 'tcp.seq', label: '序列号 (Sequence Number)', value: seq !== undefined ? String(seq) : '未提取 (无 L4 原始头)' },
      { name: 'tcp.ack', label: '确认号 (Acknowledgment Number)', value: ack !== undefined ? String(ack) : '未提取 (无 L4 原始头)' },
      { name: 'tcp.flags', label: 'TCP 标志位集合 (Flags)', value: flags ? String(flags) : '未提取 (Socket 应用层直采)', highlightClass: 'text-purple-700 dark:text-purple-300 font-bold' },
      { name: 'tcp.window_size', label: '接收窗口大小 (Window Size)', value: win !== undefined ? `${win} 字节` : '未提取' },
      { name: 'tcp.checksum', label: '传输层校验和', value: parsedHdr.tcpChecksumHex ?? '由操作系统协议栈 / NIC 校验' },
    );
  }

  layers.push({
    id: 'transport',
    title: `Layer 4: Transport Layer (${p.transport})`,
    subtitle: `端口映射: ${p.src_port} → ${p.dst_port} [${p.protocol}]`,
    badge: 'L4 TRANS',
    badgeClass: 'bg-purple-500/15 text-purple-700 dark:text-purple-300 border-purple-500/30',
    fields: transFields,
  });

  // ---------------------------------------------------------------------------
  // 5. Layer 7: Industrial Protocol & Application Semantics 原生工控规约语义层
  // ---------------------------------------------------------------------------
  const appFields: NativeField[] = [];
  let isDangerousWrite = false;

  // 逐项转换 business_data 为深度工控展开字段
  for (const [key, val] of Object.entries(bdata)) {
    if (['src_geo', 'src_zone', 'src_isp', 'dst_zone', 'sequence_number', 'acknowledgment_number', 'window_size', 'flags', 'ip_ttl'].includes(key)) {
      continue;
    }

    const fieldLabel = formatFieldLabel(key);
    const strVal = String(val);

    if (key.includes('write') || key.includes('danger') || key.includes('override') || strVal.includes('WRITE')) {
      isDangerousWrite = true;
    }

    appFields.push({
      name: `app.${key}`,
      label: fieldLabel,
      value: strVal,
      highlightClass: isDangerousWrite ? 'text-rose-700 dark:text-rose-300 font-bold' : undefined,
    });
  }

  if (appFields.length === 0) {
    appFields.push(
      { name: 'app.protocol', label: '应用层规约识别', value: p.protocol, highlightClass: 'text-blue-700 dark:text-sky-300 font-bold' },
      { name: 'app.payload_size', label: '有效载荷长度', value: `${cleanHex.value.length / 2} 字节` },
      { name: 'app.raw_preview', label: '载荷数据摘要', value: p.raw_text || (cleanHex.value.slice(0, 32) + '...') },
    );
  }

  layers.push({
    id: 'application',
    title: `Layer 7: ${p.protocol} 工业规约语义层`,
    subtitle: `深度解析业务功能码与工业过程参数`,
    badge: 'L7 APP',
    badgeClass: 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30',
    warning: isDangerousWrite ? '包含写控制/覆写操作' : undefined,
    fields: appFields,
  });

  // ---------------------------------------------------------------------------
  // 6. 工业网络安全审查与合规层
  // ---------------------------------------------------------------------------
  const hasAclViolation = Boolean(bdata.ics_acl_violation);
  if (isDangerousWrite || p.entropy >= 7.5 || hasAclViolation) {
    const secFields: NativeField[] = [
      { 
        name: 'sec.audit_status', 
        label: '工业控制安全策略审查', 
        value: hasAclViolation 
          ? `严重违规: 触发工控访问控制 (ICS-ACL) 拦截 - ${(bdata.ics_acl_violation as any)?.violation_reason || '未授权访问'}`
          : (isDangerousWrite ? '违规警示: 捕获到控制器关键写操作' : '安全合规'), 
        highlightClass: hasAclViolation || isDangerousWrite ? 'text-rose-700 dark:text-rose-300 font-bold' : 'text-emerald-700 dark:text-emerald-300' 
      },
      { 
        name: 'sec.risk_level', 
        label: '工业风险评估等级', 
        value: hasAclViolation ? 'CRITICAL (IEC 62443 细粒度控制边界阻断)' : (isDangerousWrite ? 'HIGH (高风险业务写操作)' : 'LOW (稳态通信)'),
        highlightClass: hasAclViolation || isDangerousWrite ? 'text-rose-700 dark:text-rose-300 font-bold' : undefined
      },
      {
        name: 'sec.iec62443_rule',
        label: '等保 2.0 / IEC 62443 映射',
        value: hasAclViolation ? 'IEC 62443-3-3 SR 5.1 网络边界分割 / SR 5.2 区域访问控制' : 'SR 1.3 账户与特权控制 / SR 3.1 通信完整性校验',
        extraNote: hasAclViolation 
          ? '策略引擎根据源/目 IP、从站 Unit ID 与功能码/寄存器白名单执行微秒级拦截并审计。' 
          : '工业网络安全基准规范要求对所有 PLC 寄存器写操作留存不可篡改证据链。',
      }
    ];

    layers.push({
      id: 'security',
      title: 'Security Audit: 工控合规与威胁防范审查',
      subtitle: hasAclViolation ? '工控细粒度访问控制违规告警' : (isDangerousWrite ? '监测到向控制器下发写参数操作' : '安全策略全量合规'),
      badge: hasAclViolation ? 'ACL BLOCK' : 'AUDIT',
      badgeClass: 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-500/30',
      warning: hasAclViolation ? '工控边界策略违规阻断' : '工控安全合规事件',
      fields: secFields,
    });
  }

  return layers;
});

const totalNativeFieldsCount = computed(() => {
  return nativeProtocolLayers.value.reduce((acc, l) => acc + l.fields.length, 0);
});

function formatFieldLabel(key: string): string {
  const dictionary: Record<string, string> = {
    // Modbus
    function_code: 'Modbus 功能码 (Function Code)',
    transaction_id: '事务处理标识符 (Transaction ID)',
    protocol_id: '协议标识符 (Protocol ID)',
    unit_id: '从站设备单元号 (Unit ID)',
    starting_address: '寄存器起始物理地址',
    register_count: '操作寄存器数量',
    write_value: '写入数值 / 线圈状态',
    // S7
    s7_pdu_type: 'S7 协议数据单元类别 (PDU Type)',
    s7_function: 'S7comm 功能操作代码',
    s7_rosctr: 'S7 消息类别 (ROSCTR)',
    // 菲尼克斯
    command_description: 'ProConOS 控制器指令释义',
    // 电力
    asdu_type: 'IEC 104 ASDU 规约类型标识',
    cot_reason: 'IEC 104 传输原因代码 (COT)',
    dnp3_func_code: 'DNP3 功能码',
    // DNS (RFC 1035)
    dns_trans_id: 'DNS 事务识别码 (Transaction ID)',
    dns_is_response: 'DNS 报文流向 (Query / Response)',
    dns_message_type: 'DNS 报文类型',
    dns_opcode: 'DNS 操作代码 (Opcode)',
    dns_flags_hex: 'DNS 标志位十六进制字',
    dns_flag_aa_authoritative: 'DNS 权威应答标志 (AA)',
    dns_flag_tc_truncated: 'DNS 截断标志 (TC)',
    dns_flag_rd_recursion_desired: 'DNS 期望递归 (RD)',
    dns_flag_ra_recursion_available: 'DNS 支持递归 (RA)',
    dns_rcode: 'DNS 应答返回码 (RCODE)',
    dns_questions_count: 'DNS 问题记录数 (Questions)',
    dns_answers_count: 'DNS 回答记录数 (Answer RRs)',
    dns_authority_count: 'DNS 权威名称服务器记录数',
    dns_additional_count: 'DNS 额外附加记录数',
    dns_query_name: 'DNS 查询请求域名 (QName)',
    dns_query_type: 'DNS 查询资源记录类型 (QType)',
    dns_query_class: 'DNS 查询类 (QClass)',
    // DHCP (RFC 2131)
    dhcp_message_op: 'DHCP 消息操作类型 (Opcode)',
    dhcp_hardware_type: 'DHCP 硬件链路层类型 (HwType)',
    dhcp_trans_xid: 'DHCP 事务标识符 (Transaction XID)',
    dhcp_client_ip_ciaddr: 'DHCP 客户端现有 IP (ciaddr)',
    dhcp_your_assigned_ip_yiaddr: 'DHCP 服务器分配 IP (yiaddr)',
    dhcp_server_ip_siaddr: 'DHCP 下一阶段引导服务器 IP (siaddr)',
    dhcp_relay_gateway_giaddr: 'DHCP 中继代理网关 IP (giaddr)',
    dhcp_client_mac_chaddr: 'DHCP 客户端物理 MAC 地址 (chaddr)',
    dhcp_option_53_message_type: 'DHCP 选项 53: 报文类型 (Message Type)',
    dhcp_option_50_requested_ip: 'DHCP 选项 50: 请求分配的目标 IP',
    dhcp_option_54_server_identifier: 'DHCP 选项 54: 服务端标识 IP (Server ID)',
    dhcp_option_51_lease_time_sec: 'DHCP 选项 51: IP 地址租用有效时长 (秒)',
    dhcp_option_12_hostname: 'DHCP 选项 12: 客户端主机名 (Hostname)',
    // NTP (RFC 5905)
    ntp_leap_indicator: 'NTP 闰秒指示标志 (Leap Indicator)',
    ntp_version_number: 'NTP 协议版本号 (Version)',
    ntp_mode: 'NTP 工作运行模式 (Mode)',
    ntp_stratum: 'NTP 时钟分层等级 (Stratum)',
    ntp_poll_interval_sec: 'NTP 轮询时间间隔 (Poll Interval)',
    ntp_root_delay_ms: 'NTP 根时钟网络往返延迟 (Root Delay)',
    ntp_root_dispersion_ms: 'NTP 根时钟离散误差 (Root Dispersion)',
    ntp_reference_identifier: 'NTP 参考时钟源标识 (Reference ID)',
    // MQTT
    mqtt_packet_type: 'MQTT 控制报文类型 (Packet Type)',
    mqtt_flag_dup: 'MQTT 重复交付标志 (DUP)',
    mqtt_flag_qos: 'MQTT 服务质量等级 (QoS Level)',
    mqtt_flag_retain: 'MQTT 消息保持标志 (RETAIN)',
    mqtt_remaining_length: 'MQTT 变长剩余数据长度 (Remaining Length)',
    mqtt_protocol_name: 'MQTT 协议名称',
    mqtt_protocol_level: 'MQTT 规约版本等级',
    mqtt_clean_session: 'MQTT 清理会话标志 (Clean Session)',
    mqtt_keep_alive_sec: 'MQTT 保持连接心跳周期 (Keep Alive)',
    mqtt_client_identifier: 'MQTT 客户端唯一标识 (Client ID)',
    mqtt_topic_name: 'MQTT 消息发布/订阅主题 (Topic)',
    mqtt_payload_preview: 'MQTT 有效载荷文本预览',
    // CIP / EtherNet/IP
    cip_command_code: 'CIP 封装命令字 (Command Code)',
    cip_command_name: 'CIP 工业服务命令释义',
    cip_encap_length: 'CIP 封装有效长度',
    cip_session_handle: 'CIP 会话句柄 (Session Handle)',
    cip_status_code: 'CIP 执行返回状态码',
    cip_cpf_item_count: 'CIP 通用报文格式项数 (CPF Items)',
    // Omron FINS
    fins_icf_control: 'FINS 信息控制字段 (ICF)',
    fins_response_required: 'FINS 是否需要应答确认',
    fins_gateway_count_gct: 'FINS 跨网关路由跳数 (GCT)',
    fins_dest_network_dna: 'FINS 目的网络号 (DNA)',
    fins_dest_node_da1: 'FINS 目的节点号 (DA1)',
    fins_dest_unit_da2: 'FINS 目的单元号 (DA2)',
    fins_source_network_sna: 'FINS 源端网络号 (SNA)',
    fins_source_node_sa1: 'FINS 源端节点号 (SA1)',
    fins_command_code: 'FINS 主/次命令码 (MRC/SRC)',
    fins_command_name: 'FINS 工控指令释义',
    fins_memory_area_code: 'FINS 目标 PLC 内存区域代码',
    fins_start_word_address: 'FINS 目标起始通道/字地址',
    // CoAP
    coap_version: 'CoAP 协议版本',
    coap_type: 'CoAP 消息确认类型',
    coap_code: 'CoAP 请求方法/响应状态码',
    coap_message_id: 'CoAP 消息唯一编号 (Message ID)',
    coap_token_hex: 'CoAP 关联令牌 (Token Hex)',
    // SNMP
    snmp_version: 'SNMP 协议版本',
    snmp_community: 'SNMP 共同体鉴权名 (Community String)',
    snmp_pdu_type: 'SNMP 协议数据单元类型 (PDU Type)',
    // OPC UA
    opcua_message_type: 'OPC UA 报文类型',
    opcua_chunk_type: 'OPC UA 连续分片标记 (Chunk Type)',
    opcua_message_size: 'OPC UA 二进制报文总字节数',
    opcua_secure_channel_id: 'OPC UA 安全通道标识 (SecureChannelId)',
    // ARP
    arp_hardware_type: 'ARP 物理硬件类型',
    arp_protocol_type: 'ARP 上层网络协议类型',
    arp_opcode: 'ARP 操作码 (Opcode)',
    arp_sender_mac: 'ARP 发送端物理 MAC 地址',
    arp_sender_ip: 'ARP 发送端逻辑 IP 地址',
    arp_target_mac: 'ARP 目标端物理 MAC 地址',
    arp_target_ip: 'ARP 目标端逻辑 IP 地址',
    // ICMP
    icmp_type: 'ICMP 报文类型代码 (Type)',
    icmp_code: 'ICMP 业务子代码 (Code)',
    icmp_checksum: 'ICMP 首部校验和',
    icmp_identifier: 'ICMP 进程标识号 (ID)',
    icmp_sequence_number: 'ICMP 报文序列号 (Sequence)',
    // Modbus RTU
    modbus_rtu_slave_address: 'Modbus-RTU 物理从站地址',
    modbus_rtu_function_code: 'Modbus-RTU 功能码',
    modbus_rtu_function_name: 'Modbus-RTU 功能操作释义',
    modbus_rtu_start_register: 'Modbus-RTU 起始寄存器地址',
    modbus_rtu_register_count: 'Modbus-RTU 操作寄存器数量',
    modbus_rtu_crc16_hex: 'Modbus-RTU 末尾 CRC16 校验字',
    modbus_rtu_crc16_valid: 'Modbus-RTU CRC16 物理校验有效性',
    // 长尾未知自省展开
    longtail_protocol_tag: '自省探针定性标签',
    longtail_payload_length_bytes: '原始载荷总字节数',
    longtail_lead_magic_signature: '首部特征魔数签名',
    longtail_inferred_command_byte: '启发式推断操作/控制码',
    longtail_inferred_sequence_be: '启发式序列号 (大端推测)',
    longtail_inferred_sequence_le: '启发式序列号 (小端推测)',
    longtail_shannon_entropy: '有效载荷香农信息熵',
    longtail_printable_ascii_ratio: 'ASCII 可打印字符率',
    longtail_encoding_type: '载荷数据编码推测形态',
    longtail_tail_checksum_word: '尾部校验和推断字',
  };

  return dictionary[key] || key.replace(/_/g, ' ').toUpperCase();
}

const formattedHexLines = computed(() => {
  const hex = cleanHex.value;
  if (!hex) return [];
  const lines: Array<{ offset: string; part1: string; part2: string; ascii: string }> = [];

  for (let offset = 0; offset < hex.length; offset += 32) {
    const chunk = hex.slice(offset, offset + 32);
    const offsetHex = (offset / 2).toString(16).padStart(4, '0').toUpperCase();
    const hexBytes: string[] = [];
    const asciiChars: string[] = [];

    for (let i = 0; i < 32; i += 2) {
      if (i < chunk.length) {
        const bHex = chunk.slice(i, i + 2).toUpperCase();
        hexBytes.push(bHex);
        const bVal = parseInt(bHex, 16);
        asciiChars.push(bVal >= 32 && bVal <= 126 ? String.fromCharCode(bVal) : '.');
      } else {
        hexBytes.push('  ');
      }
    }

    const part1 = hexBytes.slice(0, 8).join(' ');
    const part2 = hexBytes.slice(8, 16).join(' ');
    lines.push({ offset: offsetHex, part1, part2, ascii: asciiChars.join('') });
  }
  return lines;
});

function selectTab(tabId: string) {
  activeTab.value = tabId;
  if (tabId === 'tshark' && !tsharkResult.value && !tsharkLoading.value && tsharkStatus.value?.is_available) {
    runTsharkDissection();
  }
}

async function checkTsharkStatus() {
  try {
    const res = await invoke('check_tshark_status_cmd');
    tsharkStatus.value = res;
  } catch (e) {
    console.warn('[TSHARK_STATUS] 探活失败:', e);
  }
}

async function runTsharkDissection() {
  if (!cleanHex.value) {
    tsharkResult.value = {
      success: false,
      error_message: '当前数据包未包含有效十六进制载荷',
    };
    return;
  }

  tsharkLoading.value = true;
  try {
    const res: any = await invoke('dissect_packet_with_tshark_cmd', {
      packetHex: cleanHex.value,
      linkType: 1, // LINKTYPE_ETHERNET
    });
    tsharkResult.value = res;
    if (res.layers) {
      const exp: Record<string, boolean> = {};
      for (const k of Object.keys(res.layers)) {
        exp[k] = true;
      }
      expandedLayers.value = exp;
    }
  } catch (e: any) {
    tsharkResult.value = {
      success: false,
      error_message: String(e),
    };
  } finally {
    tsharkLoading.value = false;
  }
}

function toggleLayerExpand(layerName: string) {
  expandedLayers.value[layerName] = !expandedLayers.value[layerName];
}

function isObject(val: any): boolean {
  return typeof val === 'object' && val !== null;
}

function formatLayerValue(val: any): string {
  if (val === null || val === undefined) return '-';
  if (typeof val === 'object') {
    return JSON.stringify(val);
  }
  return String(val);
}

function copyHex() {
  if (!cleanHex.value) return;
  navigator.clipboard.writeText(cleanHex.value);
  isHexCopied.value = true;
  setTimeout(() => { isHexCopied.value = false; }, 2000);
}

function copyAscii() {
  const ascii = formattedHexLines.value.map(l => l.ascii).join('');
  if (!ascii) return;
  navigator.clipboard.writeText(ascii);
  isAsciiCopied.value = true;
  setTimeout(() => { isAsciiCopied.value = false; }, 2000);
}

function formatRemoteIp(pkt: PacketRecord | null | undefined): string {
  if (!pkt) return '';
  const ip = pkt.src_ip || 'LOCAL_HOST';
  const bdata = pkt.business_data;
  if (!bdata) return ip;

  const country = bdata.src_country && bdata.src_country !== '0' ? String(bdata.src_country).trim() : '';
  const province = bdata.src_province && bdata.src_province !== '0' && bdata.src_province !== country ? String(bdata.src_province).trim() : '';
  const city = bdata.src_city && bdata.src_city !== '0' && bdata.src_city !== province ? String(bdata.src_city).trim() : '';
  const isp = bdata.src_isp && bdata.src_isp !== '0' ? String(bdata.src_isp).trim() : '';

  const segments: string[] = [];
  if (country) segments.push(country);
  if (province) segments.push(province);
  if (city) segments.push(city);
  if (isp) segments.push(isp);

  if (segments.length > 0) {
    return `${ip} (${segments.join('/')})`;
  }

  if (bdata.src_zone) {
    return `${ip} (${bdata.src_zone})`;
  }

  if (bdata.src_geo) {
    return `${ip} (${bdata.src_geo})`;
  }

  return ip;
}

watch(() => props.packet?.id, () => {
  tsharkResult.value = null;
  if (activeTab.value === 'tshark' && tsharkStatus.value?.is_available) {
    runTsharkDissection();
  }
});

watch(() => props.isOpen, (open) => {
  if (open) {
    checkTsharkStatus();
    if (activeTab.value === 'tshark' && !tsharkResult.value && tsharkStatus.value?.is_available) {
      runTsharkDissection();
    }
  }
});

onMounted(() => {
  checkTsharkStatus();
});
</script>
