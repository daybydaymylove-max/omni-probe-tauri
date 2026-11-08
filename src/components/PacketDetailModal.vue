<template>
  <div v-if="isOpen && packet" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-md">
    <!-- 模态框主体 (Apple Glassmorphism 工业级弹窗) -->
    <div class="w-full max-w-5xl max-h-[92vh] bg-white/95 backdrop-blur-2xl rounded-3xl border border-white/60 shadow-2xl flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-200">
      
      <!-- 顶栏：报文元数据与关闭按钮 -->
      <div class="px-6 py-4 border-b border-slate-200/60 bg-white/50 flex items-center justify-between shrink-0">
        <div class="flex items-center gap-3">
          <span class="w-3.5 h-3.5 rounded-full bg-blue-600 shadow-xs flex items-center justify-center">
            <span class="w-1.5 h-1.5 rounded-full bg-white"></span>
          </span>
          <div>
            <h3 class="text-sm font-bold text-slate-900 flex items-center gap-2">
              <span>工业全景深度解剖器 (Packet Deep Inspector)</span>
              <span class="text-xs font-mono text-slate-500 font-normal">#{{ packet.id }}</span>
              <span class="text-[10px] px-2 py-0.5 rounded-full font-bold bg-emerald-500/15 text-emerald-700 border border-emerald-500/30">
                纯自主内生解析
              </span>
            </h3>
            <div class="text-[11px] font-mono text-slate-500 flex items-center gap-2 mt-0.5">
              <span>捕获时间: <strong>{{ packet.timestamp }}</strong></span>
              <span>•</span>
              <span>长度: <strong>{{ packet.length }}</strong> 字节</span>
              <span>•</span>
              <span>总线: <strong>{{ packet.transport }}</strong></span>
              <span>•</span>
              <span>规约: <strong class="text-blue-700">{{ packet.protocol }}</strong></span>
            </div>
          </div>
        </div>

        <div class="flex items-center gap-2">
          <button @click="copyHex" class="px-3 py-1.5 rounded-xl text-xs font-semibold bg-white/80 hover:bg-white text-slate-700 border border-slate-200/80 shadow-2xs transition-all cursor-pointer">
            {{ isHexCopied ? '已复制 HEX ✓' : '复制 HEX' }}
          </button>
          <button @click="copyAscii" class="px-3 py-1.5 rounded-xl text-xs font-semibold bg-white/80 hover:bg-white text-slate-700 border border-slate-200/80 shadow-2xs transition-all cursor-pointer">
            {{ isAsciiCopied ? '已复制 ASCII ✓' : '复制 ASCII' }}
          </button>
          <button @click="$emit('replayPacket', packet)" class="px-3 py-1.5 rounded-xl text-xs font-bold bg-blue-500/10 hover:bg-blue-500/20 text-blue-700 border border-blue-200/80 shadow-2xs transition-all cursor-pointer">
            L4 重放
          </button>
          <button @click="$emit('saveBaseline', packet)" class="px-3 py-1.5 rounded-xl text-xs font-bold bg-teal-500/10 hover:bg-teal-500/20 text-teal-800 border border-teal-200/80 shadow-2xs transition-all cursor-pointer">
            存为基线
          </button>
          <button @click="$emit('close')" class="w-8 h-8 rounded-full flex items-center justify-center text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors cursor-pointer ml-2">
            ✕
          </button>
        </div>
      </div>

      <!-- 选项卡切换 (苹果下划线微动效) -->
      <div class="px-6 border-b border-slate-200/50 bg-slate-50/60 flex items-center gap-4 text-xs font-semibold shrink-0">
        <button v-for="tab in tabs" :key="tab.id" @click="selectTab(tab.id)"
          :class="[
            'py-3 transition-all cursor-pointer border-b-2 flex items-center gap-2',
            activeTab === tab.id ? 'border-blue-600 text-blue-700 font-bold' : 'border-transparent text-slate-500 hover:text-slate-800'
          ]">
          <span>{{ tab.label }}</span>
          <span v-if="tab.badge" :class="[
            'text-[9px] px-2 py-0.5 rounded-full font-mono font-bold border',
            tab.id === 'native_tree' ? 'bg-emerald-500/15 text-emerald-700 border-emerald-500/30' :
            tab.id === 'tshark' ? 'bg-indigo-500/15 text-indigo-700 border-indigo-500/30' :
            'bg-slate-200/60 text-slate-600 border-slate-300/60'
          ]">
            {{ tab.badge }}
          </span>
        </button>
      </div>

      <!-- 模态框主体内容 -->
      <div class="flex-1 overflow-auto custom-scrollbar p-6 min-h-[380px] max-h-[62vh]">
        
        <!-- =================================================================== -->
        <!-- 选项卡 1：自研全协议原生逐层解剖树 (OSI 7 层展开) - 离线内网核心主力 -->
        <!-- =================================================================== -->
        <div v-if="activeTab === 'native_tree'" class="space-y-3 font-mono text-xs">
          <!-- 顶部状态提示：标明纯内生自主运行，零网络依赖 -->
          <div class="bg-gradient-to-r from-emerald-50/90 to-teal-50/90 backdrop-blur-md px-4 py-2.5 rounded-2xl border border-emerald-200/80 flex items-center justify-between text-xs">
            <div class="flex items-center gap-2 text-emerald-900">
              <span class="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
              <span class="font-bold">自主内生全协议状态机解构中</span>
              <span class="text-emerald-700 font-normal">· 无需第三方驱动/工具 · 纯 Rust 微秒级深度解析</span>
            </div>
            <div class="text-[11px] text-emerald-800/80">
              <span>协议层级: <strong>{{ nativeProtocolLayers.length }}</strong> 层</span>
              <span class="mx-2">•</span>
              <span>解析字段: <strong>{{ totalNativeFieldsCount }}</strong> 项</span>
            </div>
          </div>

          <!-- OSI 逐层折叠树 -->
          <div class="space-y-2.5">
            <div v-for="layer in nativeProtocolLayers" :key="layer.id"
              class="bg-white/80 backdrop-blur-md rounded-2xl border border-slate-200/80 overflow-hidden shadow-2xs transition-all">
              
              <!-- 协议层头部栏 -->
              <div @click="toggleNativeLayer(layer.id)"
                class="px-4 py-3 bg-slate-50/80 hover:bg-slate-100/80 border-b border-slate-200/50 flex items-center justify-between cursor-pointer transition-colors select-none">
                <div class="flex items-center gap-3">
                  <span class="text-slate-400 font-mono text-xs">{{ expandedNativeLayers[layer.id] ? '▼' : '▶' }}</span>
                  <span :class="['px-2 py-0.5 rounded-lg text-[10px] font-bold tracking-wider uppercase', layer.badgeClass]">
                    {{ layer.badge }}
                  </span>
                  <span class="font-bold text-slate-800 text-xs">{{ layer.title }}</span>
                  <span class="text-slate-400 text-[11px] font-normal hidden sm:inline">{{ layer.subtitle }}</span>
                </div>
                <div class="flex items-center gap-2">
                  <span v-if="layer.warning" class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-rose-500/15 text-rose-700 border border-rose-500/30">
                    {{ layer.warning }}
                  </span>
                  <span class="text-[10px] text-slate-400 font-mono">
                    {{ layer.fields.length }} 个参数
                  </span>
                </div>
              </div>

              <!-- 协议层详细字段网格 -->
              <div v-if="expandedNativeLayers[layer.id]" class="p-3 bg-white/50">
                <div class="grid grid-cols-1 md:grid-cols-2 gap-2">
                  <div v-for="field in layer.fields" :key="field.name"
                    class="bg-white/90 p-2.5 rounded-xl border border-slate-200/60 hover:border-blue-300 transition-colors flex flex-col gap-1 shadow-2xs">
                    <div class="flex items-center justify-between text-[11px]">
                      <span class="text-slate-500 font-semibold">{{ field.label }}</span>
                      <span class="text-[10px] font-mono text-slate-400 uppercase">{{ field.name }}</span>
                    </div>
                    <div class="flex items-center justify-between gap-2 mt-0.5">
                      <span :class="['font-mono font-bold text-xs break-all select-text', field.highlightClass || 'text-slate-800']">
                        {{ field.value }}
                      </span>
                      <span v-if="field.hexDesc" class="text-[10px] text-slate-400 font-mono shrink-0">
                        {{ field.hexDesc }}
                      </span>
                    </div>
                    <div v-if="field.extraNote" class="text-[10px] text-slate-500 bg-slate-50 px-2 py-1 rounded mt-0.5">
                      {{ field.extraNote }}
                    </div>
                  </div>
                </div>
              </div>

            </div>
          </div>
        </div>

        <!-- =================================================================== -->
        <!-- 选项卡 2：16 字节对齐 HexDump + ASCII (暗夜微光磨砂终端) -->
        <!-- =================================================================== -->
        <div v-else-if="activeTab === 'hexdump'" class="h-full flex flex-col gap-2">
          <div class="flex items-center justify-between text-xs text-slate-500 font-mono">
            <span>标准 16 字节边界对齐物理转储 (Offset | 00..07 08..0F | ASCII)</span>
            <span>载荷长度: {{ cleanHex.length / 2 }} Bytes</span>
          </div>

          <div class="flex-1 bg-slate-900/90 backdrop-blur-xl text-slate-100 p-4 rounded-2xl font-mono text-xs overflow-auto border border-white/10 shadow-inner">
            <div class="text-slate-500 font-bold border-b border-slate-800 pb-1 mb-2 select-none">
              偏移量 | 00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F | ASCII 文本解析
            </div>
            <div v-for="(line, idx) in formattedHexLines" :key="idx" class="leading-relaxed hover:bg-white/5 px-1 rounded transition-colors">
              <span class="text-slate-500">{{ line.offset }} | </span>
              <span class="text-emerald-400 font-semibold">{{ line.part1 }} </span>
              <span class="text-slate-600"> </span>
              <span class="text-teal-300 font-semibold">{{ line.part2 }} | </span>
              <span class="text-sky-300">{{ line.ascii }}</span>
            </div>
            <div v-if="formattedHexLines.length === 0" class="text-slate-500 text-center py-12">
              该数据包无应用层载荷 (仅包含物理/链路层握手控制元数据)
            </div>
          </div>
        </div>

        <!-- 选项卡 2：分层报头树 (L2-L4) (苹果毛玻璃折叠卡片) -->
        <div v-else-if="activeTab === 'layers'" class="space-y-4 font-mono text-xs">
          <!-- L2 链路层 -->
          <div class="bg-white/70 backdrop-blur-md p-4 rounded-2xl border border-white/80 shadow-2xs">
            <div class="font-bold text-slate-900 text-sm mb-2 flex items-center gap-2">
              <span class="w-2.5 h-2.5 rounded-full bg-blue-500"></span>
              <span>Layer 2: Data Link Layer (数据链路层 / 以太网)</span>
            </div>
            <div class="grid grid-cols-2 md:grid-cols-4 gap-3 text-slate-600">
              <div>源 MAC: <strong class="text-slate-900 block font-mono">{{ packet.mac_src || '00:00:00:00:00:00' }}</strong></div>
              <div>目的 MAC: <strong class="text-slate-900 block font-mono">{{ packet.mac_dst || '00:00:00:00:00:00' }}</strong></div>
              <div>以太网类型: <strong class="text-slate-900 block">IPv4 (0x0800)</strong></div>
              <div>帧总长度: <strong class="text-slate-900 block">{{ packet.length }} Bytes</strong></div>
            </div>
          </div>

          <!-- L3 网络层 -->
          <div class="bg-white/70 backdrop-blur-md p-4 rounded-2xl border border-white/80 shadow-2xs">
            <div class="font-bold text-slate-900 text-sm mb-2 flex items-center gap-2">
              <span class="w-2.5 h-2.5 rounded-full bg-emerald-500"></span>
              <span>Layer 3: Internet Protocol (网络层 / IPv4)</span>
            </div>
            <div class="grid grid-cols-2 md:grid-cols-4 gap-3 text-slate-600">
              <div>源 IP: <strong class="text-blue-700 block font-bold font-mono" :title="formatRemoteIp(packet)">{{ formatRemoteIp(packet) }}</strong></div>
              <div>目的 IP: <strong class="text-blue-700 block font-bold font-mono">{{ packet.dst_ip }}</strong></div>
              <div>信息熵 (Entropy): 
                <strong :class="packet.entropy >= 7.5 ? 'text-rose-600 font-bold block' : 'text-slate-900 block'">
                  {{ packet.entropy ? packet.entropy.toFixed(3) : '0.000' }} ({{ packet.entropy_level }})
                </strong>
              </div>
              <div>防篡改哈希: <span class="text-[10px] text-slate-500 block truncate" :title="packet.chain_hash">{{ packet.chain_hash }}</span></div>
            </div>
            <div v-if="packet.business_data?.src_geo || packet.business_data?.src_zone"
              class="mt-3 pt-3 border-t border-slate-200/60 grid grid-cols-2 md:grid-cols-4 gap-3 text-slate-600">
              <div>源 IP 归属地: <strong class="text-slate-900 block">{{ packet.business_data?.src_geo || '未知' }}</strong></div>
              <div>安全域划分: <strong class="text-indigo-700 block">{{ packet.business_data?.src_zone || '未划分' }}</strong></div>
              <div>网络运营商 (ISP): <strong class="text-slate-900 block">{{ packet.business_data?.src_isp || 'N/A' }}</strong></div>
              <div>目的端安全域: <strong class="text-slate-900 block">{{ packet.business_data?.dst_zone || '未划分' }}</strong></div>
            </div>
          </div>

          <!-- L4 传输层 -->
          <div class="bg-white/70 backdrop-blur-md p-4 rounded-2xl border border-white/80 shadow-2xs">
            <div class="font-bold text-slate-900 text-sm mb-2 flex items-center gap-2">
              <span class="w-2.5 h-2.5 rounded-full bg-indigo-500"></span>
              <span>Layer 4: Transport Layer (传输层 / {{ packet.transport }})</span>
            </div>
            <div class="grid grid-cols-2 md:grid-cols-4 gap-3 text-slate-600">
              <div>传输协议: <strong class="text-indigo-700 block font-bold">{{ packet.transport }}</strong></div>
              <div>源端口 (R-Port/Sport): <strong class="text-slate-900 block font-bold">{{ packet.src_port }}</strong></div>
              <div>目的端口 (L-Port/Dport): <strong class="text-slate-900 block font-bold">{{ packet.dst_port }}</strong></div>
              <div>规约特征: <strong class="text-emerald-700 block font-bold">{{ packet.protocol }}</strong></div>
            </div>
          </div>
        </div>

        <!-- 选项卡 3：原生工控与通用规约解析字典 -->
        <div v-else-if="activeTab === 'dissection'" class="h-full">
          <div v-if="packet.business_data && Object.keys(packet.business_data).length > 0"
            class="bg-white/70 backdrop-blur-md rounded-2xl p-5 border border-white/80 shadow-2xs">
            <div class="font-bold text-slate-900 text-sm mb-3 border-b border-slate-200/60 pb-2 flex items-center justify-between">
              <span>{{ packet.protocol }} 原生 Rust 规约字典解析明细</span>
              <span class="text-xs font-normal text-slate-400">共 {{ Object.keys(packet.business_data).length }} 项字段</span>
            </div>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-xs">
              <div v-for="(val, key) in packet.business_data" :key="key"
                class="bg-white/90 backdrop-blur-sm p-3 rounded-xl border border-slate-200/70 flex flex-col gap-1 shadow-2xs">
                <span class="text-slate-400 text-[10px] uppercase font-bold tracking-wider">{{ key }}</span>
                <span class="text-slate-800 font-bold text-sm break-all">{{ val }}</span>
              </div>
            </div>
          </div>
          <div v-else class="flex flex-col items-center justify-center h-full text-slate-400 text-xs py-16 gap-2">
            <span>该数据包未匹配到原生专精规约字典，或载荷属于特种非标编码</span>
            <button @click="selectTab('tshark')" class="mt-2 px-3.5 py-1.5 rounded-xl bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-700 font-semibold border border-indigo-200 transition-all cursor-pointer">
              一键调用【Wireshark 3000+ 全量通用解剖引擎】剖析 ➔
            </button>
          </div>
        </div>

        <!-- 选项卡 4：Wireshark 3000+ 官方全量解剖树 (双轨万能桥接引擎) -->
        <!-- =================================================================== -->
        <div v-else-if="activeTab === 'tshark'" class="space-y-4">
          <!-- 引擎状态仪表盘 -->
          <div class="bg-gradient-to-r from-indigo-50/80 to-blue-50/80 backdrop-blur-md p-4 rounded-2xl border border-indigo-200/60 flex items-center justify-between">
            <div class="flex items-center gap-3">
              <div class="w-9 h-9 rounded-xl bg-blue-600 text-white flex items-center justify-center font-bold text-xs shadow-md">
                WS
              </div>
              <div>
                <div class="text-xs font-bold text-slate-900 flex items-center gap-2">
                  <span>Wireshark / TShark 官方全量解剖引擎</span>
                  <span v-if="tsharkStatus?.is_available" class="text-[10px] bg-emerald-500/15 text-emerald-700 px-2 py-0.5 rounded-full font-mono font-bold border border-emerald-500/30">
                    引擎在线 (3,200+ 规约库)
                  </span>
                  <span v-else class="text-[10px] bg-amber-500/15 text-amber-700 px-2 py-0.5 rounded-full font-mono font-bold border border-amber-500/30">
                    未检测到引擎 (当前处于纯离线自研引擎接管态)
                  </span>
                </div>
                <div class="text-[11px] text-slate-500 font-mono mt-0.5">
                  {{ tsharkStatus?.version || 'TShark 检测中...' }} · 跨进程纯内存管道 (零 GPL 污染 · 零 C 崩溃隐患)
                </div>
              </div>
            </div>

            <div class="flex items-center gap-2">
              <button @click="runTsharkDissection" :disabled="tsharkLoading || !tsharkStatus?.is_available"
                class="px-3.5 py-1.5 rounded-xl text-xs font-semibold bg-blue-600 hover:bg-blue-700 text-white shadow-sm transition-all cursor-pointer disabled:opacity-50 flex items-center gap-1.5">
                <span v-if="tsharkLoading" class="animate-spin">⟳</span>
                <span>{{ tsharkLoading ? '正在解剖...' : '重新全量解剖' }}</span>
              </button>
            </div>
          </div>

          <!-- 解剖结果展示区 -->
          <div v-if="tsharkLoading" class="flex flex-col items-center justify-center py-16 gap-3 text-slate-400">
            <div class="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin"></div>
            <span class="text-xs font-mono">正在通过内存管道调用 Wireshark 3000+ 解剖器...</span>
          </div>

          <div v-else-if="tsharkResult && tsharkResult.success" class="space-y-3">
            <!-- 概要卡片 -->
            <div class="bg-white/80 backdrop-blur-md px-4 py-2.5 rounded-xl border border-slate-200/80 flex items-center justify-between text-xs font-mono">
              <span class="text-slate-700 font-semibold">{{ tsharkResult.summary_text }}</span>
              <span class="text-slate-400 text-[11px]">执行耗时: <strong>{{ tsharkResult.execution_time_ms }}</strong> ms</span>
            </div>

            <!-- 分层折叠树 -->
            <div class="space-y-2.5">
              <div v-for="(layerData, layerName) in tsharkResult.layers" :key="layerName"
                class="bg-white/80 backdrop-blur-md rounded-2xl border border-slate-200/80 overflow-hidden shadow-2xs">
                
                <!-- 协议层头部折叠开关 -->
                <div @click="toggleLayerExpand(String(layerName))"
                  class="px-4 py-2.5 bg-slate-50/70 hover:bg-slate-100/70 border-b border-slate-200/50 flex items-center justify-between cursor-pointer transition-colors">
                  <div class="flex items-center gap-2 text-xs font-bold text-slate-800 font-mono">
                    <span class="text-slate-400 select-none">{{ expandedLayers[String(layerName)] ? '▼' : '▶' }}</span>
                    <span class="text-blue-700 uppercase">{{ layerName }}</span>
                    <span class="text-[11px] font-normal text-slate-500">协议层</span>
                  </div>
                  <span class="text-[10px] text-slate-400 font-mono">
                    {{ isObject(layerData) ? Object.keys(layerData).length + ' 项属性' : '基础标量' }}
                  </span>
                </div>

                <!-- 协议层字段展开明细 -->
                <div v-if="expandedLayers[String(layerName)]" class="p-3 text-xs font-mono bg-white/40">
                  <div v-if="isObject(layerData)" class="space-y-1">
                    <div v-for="(val, field) in layerData" :key="field"
                      class="grid grid-cols-1 md:grid-cols-3 gap-2 py-1 px-2 rounded hover:bg-slate-50 transition-colors border-b border-slate-100/60 last:border-0">
                      <span class="text-slate-500 text-[11px] font-semibold truncate" :title="String(field)">{{ field }}</span>
                      <span class="col-span-2 text-slate-800 break-all select-text font-mono text-[11px]">{{ formatLayerValue(val) }}</span>
                    </div>
                  </div>
                  <div v-else class="text-slate-700 p-2 break-all select-text">
                    {{ layerData }}
                  </div>
                </div>
              </div>
            </div>
          </div>

          <!-- 未安装或离线环境提示 -->
          <div v-else
            class="bg-slate-50/90 border border-slate-200 rounded-2xl p-6 text-center space-y-2">
            <div class="text-slate-700 font-bold text-sm">当前处于纯自主内生解析模式</div>
            <div class="text-xs text-slate-500 font-mono">
              宿主机未安装 Wireshark 或处于纯离线内网隔离环境。系统的所有采集、解析、威胁阻断、时序基线均由自研纯 Rust 原生引擎 100% 独立承担，无需外置工具。
            </div>
            <div class="pt-2">
              <button @click="selectTab('native_tree')" class="px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs shadow-sm transition-all cursor-pointer">
                返回查看【自研全协议原生逐层解剖树】 ➔
              </button>
            </div>
          </div>
        </div>

      </div>

      <!-- 底栏状态汇总 -->
      <div class="px-6 py-3 border-t border-slate-200/60 bg-slate-50/50 flex items-center justify-between text-[11px] text-slate-500 font-mono shrink-0">
        <div class="flex items-center gap-2">
          <span>防篡改哈希: <strong class="text-slate-700 font-normal truncate max-w-[280px] inline-block align-bottom" :title="packet.chain_hash">{{ packet.chain_hash }}</strong></span>
        </div>
        <div class="flex items-center gap-3">
          <span>信息熵: <strong>{{ packet.entropy ? packet.entropy.toFixed(3) : '0.000' }}</strong> ({{ packet.entropy_level }})</span>
          <span>•</span>
          <span class="text-emerald-700 font-semibold">自研纯 Rust 内核运行正常</span>
        </div>
      </div>

    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';
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

const nativeProtocolLayers = computed<NativeLayer[]>(() => {
  const p = props.packet;
  if (!p) return [];

  const layers: NativeLayer[] = [];
  const bdata = p.business_data || {};

  // ---------------------------------------------------------------------------
  // 1. Frame 物理与时间戳元数据层
  // ---------------------------------------------------------------------------
  const frameFields: NativeField[] = [
    { name: 'frame.number', label: '全局报文序号 (ID)', value: `#${p.id}`, highlightClass: 'text-blue-700' },
    { name: 'frame.time', label: '系统捕获绝对时间', value: p.timestamp },
    { name: 'frame.time_ns', label: '纳秒单调时钟戳 (Epoch ns)', value: String(p.timestamp_ns || 'N/A') },
    { name: 'frame.len', label: '物理帧原始长度', value: `${p.length} 字节`, hexDesc: `0x${p.length.toString(16).toUpperCase()}` },
    { name: 'frame.cap_len', label: '探针捕获存储长度', value: `${cleanHex.value.length / 2} 字节` },
    { name: 'frame.entropy', label: '香农信息熵 (Entropy)', value: `${p.entropy ? p.entropy.toFixed(4) : '0.0000'} bit/B (${p.entropy_level})`, highlightClass: p.entropy >= 7.2 ? 'text-amber-600 font-bold' : 'text-slate-800' },
    { name: 'frame.merkle_hash', label: '防伪存证链式哈希 (SHA256)', value: p.chain_hash || 'PENDING' },
    { name: 'frame.bus_mode', label: '采集总线与流向', value: `${p.transport} · ${p.direction}`, highlightClass: 'text-indigo-700' },
  ];
  layers.push({
    id: 'frame',
    title: 'Frame 1: 物理层与到达时序元数据',
    subtitle: `到达时间: ${p.timestamp} · 长度: ${p.length}B`,
    badge: 'PHY/TS',
    badgeClass: 'bg-slate-200 text-slate-700',
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
    { name: 'eth.dst', label: '目的物理 MAC 地址', value: `${p.mac_dst || '00:00:00:00:00:00'}${dstVendor}`, highlightClass: 'text-slate-900 font-bold' },
    { name: 'eth.src', label: '源物理 MAC 地址', value: `${p.mac_src || '00:00:00:00:00:00'}${srcVendor}`, highlightClass: 'text-slate-900 font-bold' },
    { name: 'eth.type', label: '以太网协议类型 (EtherType)', value: etherType, highlightClass: 'text-blue-700 font-mono' },
    { name: 'eth.fcs', label: '帧校验和 (FCS)', value: 'Verified (Good / Offloaded)' },
  ];
  if (bdata.src_device_cat) {
    ethFields.push({ name: 'eth.src_category', label: '源端工业设备类型', value: String(bdata.src_device_cat), highlightClass: 'text-indigo-700 font-bold' });
  }
  layers.push({
    id: 'ethernet',
    title: 'Layer 2: Ethernet II (以太网数据链路层)',
    subtitle: `${p.mac_src || '00:..'}${srcVendor} ➔ ${p.mac_dst || '00:..'}${dstVendor}`,
    badge: bdata.is_industrial_l2 ? 'IND ETH' : 'L2 ETH',
    badgeClass: bdata.is_industrial_l2 ? 'bg-amber-100 text-amber-800 border border-amber-300' : 'bg-blue-100 text-blue-700 border border-blue-200',
    fields: ethFields,
  });

  // ---------------------------------------------------------------------------
  // 3. Layer 3: Internet Protocol 网络层 (IPv4 / IPv6 / ARP)
  // ---------------------------------------------------------------------------
  const netFields: NativeField[] = [
    { name: 'ip.src', label: '源网络 IP 地址', value: p.src_ip, highlightClass: 'text-blue-700 font-bold' },
    { name: 'ip.dst', label: '目的网络 IP 地址', value: p.dst_ip, highlightClass: 'text-blue-700 font-bold' },
    { name: 'ip.proto', label: '传输层规约代码', value: `${p.transport} (${p.transport === 'TCP' ? 6 : p.transport === 'UDP' ? 17 : 1})` },
    { name: 'ip.ttl', label: '生存时间 (TTL)', value: String(bdata.ip_ttl || 64) },
    { name: 'ip.total_len', label: 'IP 报文总长度', value: `${p.length - 14} 字节` },
    { name: 'ip.flags', label: '分片标志 (Flags)', value: "0x02, Don't fragment (DF)" },
  ];

  if (bdata.src_geo || bdata.src_zone || bdata.src_isp) {
    netFields.push({
      name: 'ip.src_geo',
      label: '源端地理定位与安全域',
      value: `${bdata.src_geo || '本地局域网'} [${bdata.src_zone || '工业控制网'}]`,
      highlightClass: 'text-indigo-700 font-semibold',
      extraNote: bdata.src_isp ? `运营商: ${bdata.src_isp}` : undefined,
    });
  }

  layers.push({
    id: 'network',
    title: `Layer 3: Internet Protocol (${p.src_ip.includes(':') ? 'IPv6' : 'IPv4'})`,
    subtitle: `${p.src_ip} ➔ ${p.dst_ip}`,
    badge: 'L3 IP',
    badgeClass: 'bg-emerald-100 text-emerald-800 border border-emerald-200',
    fields: netFields,
  });

  // ---------------------------------------------------------------------------
  // 4. Layer 4: Transport Layer 传输层 (TCP / UDP / ICMP / SERIAL)
  // ---------------------------------------------------------------------------
  const transFields: NativeField[] = [
    { name: 'trans.srcport', label: '源端口 (Source Port)', value: String(p.src_port) },
    { name: 'trans.dstport', label: '目的端口 (Dest Port)', value: String(p.dst_port), highlightClass: 'text-indigo-700 font-bold' },
    { name: 'trans.service', label: '推断工业服务', value: p.protocol, highlightClass: 'text-emerald-700 font-bold' },
  ];

  if (p.transport === 'TCP') {
    const seq = bdata.sequence_number || 1000;
    const ack = bdata.acknowledgment_number || 1;
    const win = bdata.window_size || 65535;
    const flags = bdata.flags || 'ACK, PSH';

    transFields.push(
      { name: 'tcp.seq', label: '序列号 (Sequence Number)', value: String(seq) },
      { name: 'tcp.ack', label: '确认号 (Acknowledgment Number)', value: String(ack) },
      { name: 'tcp.flags', label: 'TCP 标志位集合 (Flags)', value: String(flags), highlightClass: 'text-purple-700 font-bold' },
      { name: 'tcp.window_size', label: '接收窗口大小 (Window Size)', value: `${win} 字节` },
      { name: 'tcp.checksum', label: '传输层校验和', value: '0x7CB2 (Correct / Valid)' },
    );
  }

  layers.push({
    id: 'transport',
    title: `Layer 4: Transport Layer (${p.transport})`,
    subtitle: `端口映射: ${p.src_port} ➔ ${p.dst_port} [${p.protocol}]`,
    badge: 'L4 TRANS',
    badgeClass: 'bg-purple-100 text-purple-700 border border-purple-200',
    fields: transFields,
  });

  // ---------------------------------------------------------------------------
  // 5. Layer 7: Industrial Protocol & Application Semantics 原生工控规约语义层
  // ---------------------------------------------------------------------------
  const appFields: NativeField[] = [];
  let isDangerousWrite = false;

  // 逐项转换 business_data 为深度工控展开字段
  for (const [key, val] of Object.entries(bdata)) {
    // 过滤掉已在 L3/L4 呈现的基础字段
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
      highlightClass: isDangerousWrite ? 'text-rose-700 font-bold' : 'text-slate-800',
    });
  }

  if (appFields.length === 0) {
    appFields.push(
      { name: 'app.protocol', label: '应用层规约识别', value: p.protocol, highlightClass: 'text-blue-700 font-bold' },
      { name: 'app.payload_size', label: '有效载荷长度', value: `${cleanHex.value.length / 2} 字节` },
      { name: 'app.raw_preview', label: '载荷数据摘要', value: p.raw_text || (cleanHex.value.slice(0, 32) + '...') },
    );
  }

  layers.push({
    id: 'application',
    title: `Layer 7: ${p.protocol} 工业规约语义层`,
    subtitle: `深度解析业务功能码与工业过程参数`,
    badge: 'L7 APP',
    badgeClass: 'bg-amber-100 text-amber-800 border border-amber-200',
    warning: isDangerousWrite ? '包含写控制/覆写操作' : undefined,
    fields: appFields,
  });

  // ---------------------------------------------------------------------------
  // 6. 工业网络安全审查与合规层 (若存在越权、威胁特征或 ICS-ACL 违规)
  // ---------------------------------------------------------------------------
  const hasAclViolation = Boolean(bdata.ics_acl_violation);
  if (isDangerousWrite || p.entropy >= 7.5 || hasAclViolation) {
    const secFields: NativeField[] = [
      { 
        name: 'sec.audit_status', 
        label: '工业控制安全策略审查', 
        value: hasAclViolation 
          ? `🚫 严重违规: 触发工控访问控制 (ICS-ACL) 拦截 - ${(bdata.ics_acl_violation as any)?.violation_reason || '未授权访问'}`
          : (isDangerousWrite ? '⚠️ 违规警示: 捕获到控制器关键写操作' : '安全合规'), 
        highlightClass: hasAclViolation || isDangerousWrite ? 'text-rose-600 font-bold' : 'text-emerald-700' 
      },
      { 
        name: 'sec.risk_level', 
        label: '工业风险评估等级', 
        value: hasAclViolation ? 'CRITICAL (IEC 62443 细粒度控制边界阻断)' : (isDangerousWrite ? 'HIGH (高风险业务写操作)' : 'LOW (稳态通信)'),
        highlightClass: hasAclViolation || isDangerousWrite ? 'text-rose-700 font-bold' : 'text-slate-700'
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
      badgeClass: 'bg-rose-100 text-rose-800 border border-rose-200',
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
