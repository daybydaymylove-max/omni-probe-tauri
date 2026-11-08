<template>
  <div v-if="isOpen && packet" class="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 backdrop-blur-sm p-4 overflow-hidden">
    <div class="bg-white rounded-2xl border border-slate-200 shadow-2xl w-full max-w-5xl max-h-[92vh] flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-150">
      <!-- 弹窗顶栏 -->
      <div class="px-5 py-3.5 border-b border-slate-100 bg-slate-50/80 flex items-center justify-between shrink-0">
        <div class="flex items-center gap-3">
          <div class="w-8 h-8 rounded-xl bg-blue-600 text-white flex items-center justify-center font-bold text-sm shadow-xs">
            🔬
          </div>
          <div>
            <div class="flex items-center gap-2">
              <h2 class="text-sm font-bold text-slate-800">全景报文深度剖析器 (Packet Deep Dissector)</h2>
              <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-200 text-slate-700 font-bold">
                #{{ packet.id }}
              </span>
              <span :class="['text-[10px] font-bold px-2 py-0.5 rounded', protocolBadgeColor(packet.protocol)]">
                {{ packet.protocol }}
              </span>
              <span :class="[
                'text-[10px] font-bold px-2 py-0.5 rounded',
                packet.entropy >= 7.5 ? 'bg-rose-100 text-rose-700' :
                packet.entropy >= 6.0 ? 'bg-amber-100 text-amber-700' :
                'bg-emerald-100 text-emerald-700'
              ]">
                {{ packet.entropy >= 7.5 ? '☢️ 高危密文' : packet.entropy >= 6.0 ? '⚠️ 混淆数据' : '🟢 明文载荷' }} (Shannon: {{ packet.entropy.toFixed(2) }})
              </span>
            </div>
            <p class="text-[11px] text-slate-400 mt-0.5">
              时间: {{ packet.timestamp }} | 流向: {{ packet.direction }} | 长度: {{ packet.length }} 字节
            </p>
          </div>
        </div>

        <div class="flex items-center gap-2">
          <!-- 关闭按钮 -->
          <button @click="$emit('close')" class="w-7 h-7 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-200/60 flex items-center justify-center transition-colors text-base font-bold">
            ✕
          </button>
        </div>
      </div>

      <!-- 弹窗主体内容区（双栏或分层） -->
      <div class="flex-1 overflow-y-auto custom-scrollbar p-5 space-y-4">
        <!-- 核心通信元组卡片 -->
        <div class="grid grid-cols-4 gap-3">
          <div class="bg-slate-50 border border-slate-100 p-2.5 rounded-xl">
            <div class="text-[10px] text-slate-400 font-bold uppercase mb-1">源端 Source</div>
            <div class="text-xs font-mono font-bold text-slate-800 truncate" :title="packet.src_ip + ':' + packet.src_port">
              {{ packet.src_ip }}<span class="text-blue-600">:{{ packet.src_port }}</span>
            </div>
            <div class="text-[10px] text-slate-400 font-mono mt-0.5 truncate" :title="packet.mac_src">
              MAC: {{ packet.mac_src || 'N/A' }}
            </div>
          </div>
          <div class="bg-slate-50 border border-slate-100 p-2.5 rounded-xl">
            <div class="text-[10px] text-slate-400 font-bold uppercase mb-1">目标端 Target</div>
            <div class="text-xs font-mono font-bold text-slate-800 truncate" :title="packet.dst_ip + ':' + packet.dst_port">
              {{ packet.dst_ip }}<span class="text-indigo-600">:{{ packet.dst_port }}</span>
            </div>
            <div class="text-[10px] text-slate-400 font-mono mt-0.5 truncate" :title="packet.mac_dst">
              MAC: {{ packet.mac_dst || 'N/A' }}
            </div>
          </div>
          <div class="bg-slate-50 border border-slate-100 p-2.5 rounded-xl">
            <div class="text-[10px] text-slate-400 font-bold uppercase mb-1">传输与规约</div>
            <div class="text-xs font-mono font-bold text-slate-800 flex items-center gap-1.5">
              <span class="px-1.5 py-0.2 rounded bg-slate-200 text-slate-700 text-[10px]">{{ packet.transport }}</span>
              <span class="text-blue-700 font-semibold">{{ packet.protocol }}</span>
            </div>
            <div class="text-[10px] text-slate-400 font-mono mt-0.5">
              总载荷: {{ packet.length }} Bytes
            </div>
          </div>
          <div class="bg-slate-50 border border-slate-100 p-2.5 rounded-xl">
            <div class="text-[10px] text-slate-400 font-bold uppercase mb-1">区块链司法存证</div>
            <div class="text-[10px] font-mono text-emerald-700 font-bold truncate" :title="packet.chain_hash">
              SHA-256: {{ packet.chain_hash?.slice(0, 14) }}...
            </div>
            <button @click="copyText(packet.chain_hash)" class="text-[9px] text-blue-600 hover:underline mt-0.5">
              复制存证完整哈希
            </button>
          </div>
        </div>

        <!-- 规约结构化深度解析 (业务字典/规约细化) -->
        <div v-if="packet.business_data && Object.keys(packet.business_data).length > 0" class="border border-indigo-100 rounded-xl overflow-hidden shadow-xs">
          <div class="bg-indigo-50/70 px-4 py-2 border-b border-indigo-100 flex items-center justify-between">
            <span class="text-xs font-bold text-indigo-900 flex items-center gap-1.5">
              <span>📊</span> {{ packet.protocol }} 规约结构化解析字段 (Protocol Dissected Fields)
            </span>
            <span class="text-[10px] text-indigo-600 font-mono">
              共 {{ Object.keys(packet.business_data).length }} 个解析项
            </span>
          </div>
          <div class="p-4 bg-indigo-50/20 grid grid-cols-2 md:grid-cols-3 gap-3">
            <div v-for="(val, key) in packet.business_data" :key="key" 
              class="bg-white/90 border border-indigo-100/80 rounded-lg p-2.5 shadow-2xs flex flex-col gap-1">
              <span class="text-[10px] font-bold text-slate-400 uppercase tracking-wider">{{ formatFieldLabel(String(key)) }}</span>
              <span class="text-xs font-mono font-extrabold text-indigo-950 break-all select-all">
                {{ formatFieldValue(val) }}
              </span>
            </div>
          </div>
        </div>

        <!-- 真实载荷内容 -->
        <div class="border border-slate-200 rounded-xl overflow-hidden shadow-xs">
          <div class="px-4 py-2 bg-slate-50 border-b border-slate-200 flex items-center justify-between">
            <span class="text-xs font-bold text-slate-700 flex items-center gap-1.5">
              <span>📝</span> 客观真实原始明文内容 (Raw Original Plaintext)
            </span>
            <div class="flex items-center gap-2">
              <button @click="copyText(packet.raw_text || '')"
                class="text-[10px] text-blue-600 hover:text-blue-800 font-medium cursor-pointer">
                📋 复制文本
              </button>
            </div>
          </div>
          <div class="p-3.5 text-xs font-mono leading-relaxed break-all select-all max-h-48 overflow-y-auto custom-scrollbar whitespace-pre-wrap bg-amber-50/40 text-amber-950 font-semibold">
            {{ packet.raw_text || '[EMPTY PAYLOAD]' }}
          </div>
        </div>

        <!-- 专业十六进制与 ASCII 对齐转储 (Wireshark 级 Hex Dump) -->
        <div class="border border-slate-800 rounded-xl overflow-hidden shadow-xs bg-slate-950">
          <div class="px-4 py-2 bg-slate-900 border-b border-slate-800 flex items-center justify-between text-slate-300">
            <span class="text-xs font-bold font-mono flex items-center gap-1.5">
              <span>🖥️</span> 专业 16 字节对齐十六进制与 ASCII 转储 (Aligned Hex & ASCII Dump)
            </span>
            <div class="flex items-center gap-3 text-[10px] font-mono">
              <button @click="copyText(packet.payload_hex)" class="text-emerald-400 hover:underline">复制纯 HEX</button>
              <button @click="copyText(formatDumpText(packet.payload_hex))" class="text-blue-400 hover:underline">复制完整转储</button>
              <span class="text-slate-500">共 {{ packet.length }} 字节</span>
            </div>
          </div>
          <div class="p-3.5 text-[11px] font-mono leading-relaxed text-emerald-400 select-all max-h-64 overflow-auto custom-scrollbar whitespace-pre">
            <div v-for="(line, idx) in formatAlignedHexDump(packet.payload_hex)" :key="idx" class="hover:bg-slate-900/80 px-1 rounded transition-colors">
              {{ line }}
            </div>
            <div v-if="!packet.payload_hex || packet.payload_hex.length === 0" class="text-slate-600 italic">
              [EMPTY PAYLOAD - 0 BYTES]
            </div>
          </div>
        </div>
      </div>

      <!-- 弹窗底栏动作按钮 -->
      <div class="px-5 py-3 border-t border-slate-100 bg-slate-50/80 flex items-center justify-between shrink-0">
        <div class="flex items-center gap-2">
          <button @click="$emit('replay', packet)" class="bg-amber-500 hover:bg-amber-600 text-white text-xs px-3 py-1.5 rounded-lg font-medium shadow-xs transition-all flex items-center gap-1">
            ▶ 物理重放报文
          </button>
          <button @click="$emit('saveBaseline', packet)" class="bg-cyan-600 hover:bg-cyan-700 text-white text-xs px-3 py-1.5 rounded-lg font-medium shadow-xs transition-all flex items-center gap-1">
            💾 固化为历史基线
          </button>
          <button @click="$emit('openWave', packet)" class="bg-indigo-600 hover:bg-indigo-700 text-white text-xs px-3 py-1.5 rounded-lg font-medium shadow-xs transition-all flex items-center gap-1">
            📈 提取波形追踪
          </button>
          <button @click="$emit('openProbe', packet)" class="bg-emerald-600 hover:bg-emerald-700 text-white text-xs px-3 py-1.5 rounded-lg font-medium shadow-xs transition-all flex items-center gap-1">
            🎯 靶向主动反探
          </button>
        </div>

        <button @click="$emit('close')" class="bg-slate-200 hover:bg-slate-300 text-slate-700 text-xs px-4 py-1.5 rounded-lg font-semibold transition-all">
          关闭窗口
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { defineProps, defineEmits } from 'vue';

defineProps<{
  packet: any | null;
  isOpen: boolean;
}>();

defineEmits(['close', 'replay', 'saveBaseline', 'openWave', 'openProbe']);

function protocolBadgeColor(proto: string): string {
  if (!proto) return 'bg-slate-100 text-slate-600';
  if (proto.includes('SL651')) return 'bg-teal-100 text-teal-800';
  if (proto.includes('MODBUS')) return 'bg-amber-100 text-amber-800';
  if (proto.includes('MQTT')) return 'bg-purple-100 text-purple-800';
  if (proto.includes('HTTP')) return 'bg-blue-100 text-blue-800';
  if (proto.includes('HJ212')) return 'bg-emerald-100 text-emerald-800';
  return 'bg-slate-100 text-slate-700';
}

function formatFieldLabel(key: string): string {
  const map: Record<string, string> = {
    telemetry_station_bcd: '遥测站测站地址 (BCD)',
    function_code: '规约功能码 (Function Code)',
    function_name: '报文功能释义 (Function Meaning)',
    center_address: '中心站地址 (Center Addr)',
    center_password_hex: '中心站密码 (Password Hex)',
    crc16: 'CRC16 校验码 (Checksum)',
    sl651_frame_bytes: 'SL651 帧总长度 (Bytes)',
    slave_id: 'Modbus 单元标识 (Slave ID)',
    modbus_function: 'Modbus 功能码',
    register_address: '起始寄存器地址',
    register_count: '寄存器数量',
    topic: 'MQTT 主题 (Topic)',
    http_method: 'HTTP 请求方法',
    http_path: 'HTTP 请求路径',
    status_code: '响应状态码',
  };
  return map[key] || key.replace(/_/g, ' ');
}

function formatFieldValue(val: any): string {
  if (val === null || val === undefined) return 'N/A';
  if (typeof val === 'object') return JSON.stringify(val);
  return String(val);
}

function formatAlignedHexDump(hexStr: string): string[] {
  if (!hexStr) return [];
  const clean = hexStr.replace(/\s+/g, '');
  const lines: string[] = [];
  
  for (let offset = 0; offset < clean.length; offset += 32) {
    const chunk = clean.slice(offset, offset + 32);
    const offsetHex = (offset / 2).toString(16).padStart(4, '0').toUpperCase();
    
    // 生成 HEX 字节
    const hexBytes: string[] = [];
    const asciiChars: string[] = [];
    
    for (let i = 0; i < 32; i += 2) {
      if (i < chunk.length) {
        const byteHex = chunk.slice(i, i + 2).toUpperCase();
        hexBytes.push(byteHex);
        const byteVal = parseInt(byteHex, 16);
        if (byteVal >= 32 && byteVal <= 126) {
          asciiChars.push(String.fromCharCode(byteVal));
        } else {
          asciiChars.push('.');
        }
      } else {
        hexBytes.push('  ');
      }
    }
    
    // 8 字节分隔
    const part1 = hexBytes.slice(0, 8).join(' ');
    const part2 = hexBytes.slice(8, 16).join(' ');
    const asciiPart = asciiChars.join('');
    
    lines.push(`${offsetHex} | ${part1}  ${part2} | ${asciiPart}`);
  }
  
  return lines;
}

function formatDumpText(hexStr: string): string {
  return formatAlignedHexDump(hexStr).join('\n');
}

function copyText(text?: string) {
  if (!text) return;
  navigator.clipboard.writeText(text);
}
</script>
