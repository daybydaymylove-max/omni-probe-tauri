<template>
  <div v-if="isOpen && packet" class="ui-modal-backdrop fixed inset-0 z-50 flex items-center justify-center p-4 overflow-hidden">
    <div class="ui-modal-surface rounded-3xl w-full max-w-5xl max-h-[92vh] flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-150">
      <!-- 弹窗顶栏 -->
      <div class="ui-nav-glass px-5 py-3.5 border-b border-(--border-subtle) flex items-center justify-between shrink-0">
        <div class="flex items-center gap-3 min-w-0">
          <div class="w-8 h-8 rounded-xl bg-sky-500/12 border border-sky-500/30 text-sky-600 dark:text-sky-400 flex items-center justify-center shrink-0">
            <AppIcon name="search" class="w-4 h-4" />
          </div>
          <div class="min-w-0">
            <div class="flex flex-wrap items-center gap-2">
              <h2 class="text-sm font-bold text-(--text-primary)">全景报文深度剖析器 (Packet Deep Dissector)</h2>
              <span class="ui-pill text-[11px] ui-num font-mono-code px-2 py-0.5 font-bold">
                #{{ packet.id }}
              </span>
              <span :class="['text-[11px] font-bold px-2 py-0.5 rounded border', protocolBadgeColor(packet.protocol)]">
                {{ packet.protocol }}
              </span>
              <span :class="[
                'text-[11px] font-bold px-2 py-0.5 rounded border ui-num',
                packet.entropy >= 7.5 ? 'bg-rose-500/12 text-rose-700 dark:text-rose-300 border-rose-500/30' :
                packet.entropy >= 6.0 ? 'bg-amber-500/12 text-amber-700 dark:text-amber-300 border-amber-500/30' :
                'bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 border-emerald-500/30'
              ]">
                {{ packet.entropy >= 7.5 ? '高熵密文' : packet.entropy >= 6.0 ? '混淆数据' : '明文载荷' }} (Shannon: {{ packet.entropy.toFixed(2) }})
              </span>
            </div>
            <p class="text-xs text-(--text-muted) ui-num mt-0.5">
              时间: {{ packet.timestamp }} | 流向: {{ packet.direction }} | 长度: {{ packet.length }} 字节
            </p>
          </div>
        </div>

        <div class="flex items-center gap-2 shrink-0">
          <button @click="$emit('close')" class="ui-btn-secondary w-8 h-8 rounded-full p-0 flex items-center justify-center cursor-pointer" aria-label="关闭窗口">
            <AppIcon name="close" class="w-4 h-4" />
          </button>
        </div>
      </div>

      <!-- 弹窗主体内容区 -->
      <div class="flex-1 overflow-y-auto custom-scrollbar p-5 space-y-4">
        <!-- 核心通信元组卡片 -->
        <div class="grid grid-cols-2 lg:grid-cols-4 gap-3">
          <div class="ui-content-card p-3 rounded-xl">
            <div class="text-[11px] text-(--text-muted) font-bold uppercase mb-1">源端 Source</div>
            <div class="text-xs font-mono-code ui-num font-bold text-(--text-primary) truncate select-text" :title="packet.src_ip + ':' + packet.src_port">
              {{ packet.src_ip }}<span class="text-sky-600 dark:text-sky-400">:{{ packet.src_port }}</span>
            </div>
            <div class="text-[11px] text-(--text-muted) font-mono-code ui-num mt-0.5 truncate select-text" :title="packet.mac_src">
              MAC: {{ packet.mac_src || 'N/A' }}
            </div>
          </div>
          <div class="ui-content-card p-3 rounded-xl">
            <div class="text-[11px] text-(--text-muted) font-bold uppercase mb-1">目标端 Target</div>
            <div class="text-xs font-mono-code ui-num font-bold text-(--text-primary) truncate select-text" :title="packet.dst_ip + ':' + packet.dst_port">
              {{ packet.dst_ip }}<span class="text-indigo-600 dark:text-indigo-400">:{{ packet.dst_port }}</span>
            </div>
            <div class="text-[11px] text-(--text-muted) font-mono-code ui-num mt-0.5 truncate select-text" :title="packet.mac_dst">
              MAC: {{ packet.mac_dst || 'N/A' }}
            </div>
          </div>
          <div class="ui-content-card p-3 rounded-xl">
            <div class="text-[11px] text-(--text-muted) font-bold uppercase mb-1">传输与规约</div>
            <div class="text-xs font-mono-code font-bold text-(--text-primary) flex items-center gap-1.5">
              <span class="ui-pill px-1.5 py-0.2 text-[11px]">{{ packet.transport }}</span>
              <span class="text-sky-600 dark:text-sky-400 font-semibold">{{ packet.protocol }}</span>
            </div>
            <div class="text-[11px] text-(--text-muted) font-mono-code ui-num mt-0.5">
              总载荷: {{ packet.length }} Bytes
            </div>
          </div>
          <div class="ui-content-card p-3 rounded-xl">
            <div class="text-[11px] text-(--text-muted) font-bold uppercase mb-1">区块链司法存证</div>
            <div class="text-[11px] font-mono-code ui-num text-emerald-600 dark:text-emerald-400 font-bold truncate select-text" :title="packet.chain_hash">
              SHA-256: {{ packet.chain_hash?.slice(0, 14) }}...
            </div>
            <button @click="copyText(packet.chain_hash)" class="text-[11px] text-sky-600 dark:text-sky-400 hover:underline mt-0.5 cursor-pointer">
              复制存证完整哈希
            </button>
          </div>
        </div>

        <!-- 规约结构化深度解析 (业务字典/规约细化) -->
        <div v-if="packet.business_data && Object.keys(packet.business_data).length > 0" class="ui-content-card rounded-xl overflow-hidden">
          <div class="bg-(--surface-content-alt) px-4 py-2 border-b border-(--border-subtle) flex items-center justify-between">
            <span class="text-xs font-bold text-(--text-primary) flex items-center gap-1.5">
              <AppIcon name="layers" class="w-3.5 h-3.5 text-indigo-600 dark:text-indigo-400" />
              <span>{{ packet.protocol }} 规约结构化解析字段 (Protocol Dissected Fields)</span>
            </span>
            <span class="text-[11px] text-(--text-muted) font-mono-code ui-num">
              共 {{ Object.keys(packet.business_data).length }} 个解析项
            </span>
          </div>
          <div class="p-4 grid grid-cols-2 md:grid-cols-3 gap-3">
            <div v-for="(val, key) in packet.business_data" :key="key" 
              class="ui-sub-card rounded-lg p-2.5 flex flex-col gap-1">
              <span class="text-[11px] font-bold text-(--text-muted) uppercase tracking-wider">{{ formatFieldLabel(String(key)) }}</span>
              <span class="text-xs font-mono-code font-bold text-(--text-primary) break-all select-text">
                {{ formatFieldValue(val) }}
              </span>
            </div>
          </div>
        </div>

        <!-- 真实载荷内容 -->
        <div class="ui-content-card rounded-xl overflow-hidden">
          <div class="px-4 py-2 bg-(--surface-content-alt) border-b border-(--border-subtle) flex items-center justify-between">
            <span class="text-xs font-bold text-(--text-primary) flex items-center gap-1.5">
              <AppIcon name="document" class="w-3.5 h-3.5 text-amber-600 dark:text-amber-400" />
              <span>客观真实原始明文内容 (Raw Original Plaintext)</span>
            </span>
            <div class="flex items-center gap-2">
              <button @click="copyText(packet.raw_text || '')"
                class="ui-btn-secondary inline-flex items-center gap-1 px-2 py-0.5 text-[11px] font-medium cursor-pointer">
                <AppIcon name="code" class="w-3 h-3" />
                <span>复制文本</span>
              </button>
            </div>
          </div>
          <div class="p-3.5 text-xs font-mono-code leading-relaxed break-all select-text max-h-48 overflow-y-auto custom-scrollbar whitespace-pre-wrap bg-(--surface-window) text-(--text-primary)">
            {{ packet.raw_text || '[EMPTY PAYLOAD]' }}
          </div>
        </div>

        <!-- 专业十六进制与 ASCII 对齐转储 (Wireshark 级 Hex Dump) -->
        <div class="ui-content-card rounded-xl overflow-hidden">
          <div class="px-4 py-2 bg-(--surface-content-alt) border-b border-(--border-subtle) flex items-center justify-between text-(--text-primary)">
            <span class="text-xs font-bold font-mono-code flex items-center gap-1.5">
              <AppIcon name="terminal" class="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
              <span>16 字节对齐十六进制与 ASCII 转储 (Aligned Hex & ASCII Dump)</span>
            </span>
            <div class="flex items-center gap-3 text-[11px] font-mono-code">
              <button @click="copyText(packet.payload_hex)" class="text-emerald-600 dark:text-emerald-400 hover:underline cursor-pointer">复制纯 HEX</button>
              <button @click="copyText(formatDumpText(packet.payload_hex))" class="text-sky-600 dark:text-sky-400 hover:underline cursor-pointer">复制完整转储</button>
              <span class="text-(--text-muted) ui-num">共 {{ packet.length }} 字节</span>
            </div>
          </div>
          <div class="p-3.5 text-xs font-mono-code ui-num leading-relaxed bg-(--surface-window) text-(--text-primary) select-text max-h-64 overflow-auto custom-scrollbar whitespace-pre">
            <div v-for="(line, idx) in formatAlignedHexDump(packet.payload_hex)" :key="idx" class="hover:bg-sky-500/8 px-1 rounded transition-colors">
              {{ line }}
            </div>
            <div v-if="!packet.payload_hex || packet.payload_hex.length === 0" class="text-(--text-muted) italic">
              [EMPTY PAYLOAD - 0 BYTES]
            </div>
          </div>
        </div>
      </div>

      <!-- 弹窗底栏动作按钮 -->
      <div class="px-5 py-3 border-t border-(--border-subtle) bg-(--surface-content-alt) flex flex-wrap items-center justify-between gap-2 shrink-0">
        <div class="flex flex-wrap items-center gap-2">
          <button @click="$emit('replay', packet)" class="ui-btn-secondary border-amber-500/35 text-amber-700 dark:text-amber-300 text-xs px-3 py-1.5 font-medium inline-flex items-center gap-1.5 cursor-pointer">
            <AppIcon name="play" class="w-3.5 h-3.5" />
            <span>物理重放报文</span>
          </button>
          <button @click="$emit('saveBaseline', packet)" class="ui-btn-secondary border-cyan-500/35 text-cyan-700 dark:text-cyan-300 text-xs px-3 py-1.5 font-medium inline-flex items-center gap-1.5 cursor-pointer">
            <AppIcon name="database" class="w-3.5 h-3.5" />
            <span>固化为历史基线</span>
          </button>
          <button @click="$emit('openWave', packet)" class="ui-btn-secondary border-indigo-500/35 text-indigo-700 dark:text-indigo-300 text-xs px-3 py-1.5 font-medium inline-flex items-center gap-1.5 cursor-pointer">
            <AppIcon name="activity" class="w-3.5 h-3.5" />
            <span>提取波形追踪</span>
          </button>
          <button @click="$emit('openProbe', packet)" class="ui-btn-secondary border-emerald-500/35 text-emerald-700 dark:text-emerald-300 text-xs px-3 py-1.5 font-medium inline-flex items-center gap-1.5 cursor-pointer">
            <AppIcon name="radar" class="w-3.5 h-3.5" />
            <span>目标主动探测</span>
          </button>
        </div>

        <button @click="$emit('close')" class="ui-btn-secondary text-xs px-4 py-1.5 font-semibold cursor-pointer">
          关闭窗口
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import AppIcon from './AppIcon.vue';

defineProps<{
  packet: any | null;
  isOpen: boolean;
}>();

defineEmits(['close', 'replay', 'saveBaseline', 'openWave', 'openProbe']);

function protocolBadgeColor(proto: string): string {
  if (!proto) return 'bg-slate-500/12 text-(--text-secondary) border-(--border-subtle)';
  if (proto.includes('SL651')) return 'bg-teal-500/12 text-teal-700 dark:text-teal-300 border-teal-500/30';
  if (proto.includes('MODBUS')) return 'bg-amber-500/12 text-amber-700 dark:text-amber-300 border-amber-500/30';
  if (proto.includes('MQTT')) return 'bg-purple-500/12 text-purple-700 dark:text-purple-300 border-purple-500/30';
  if (proto.includes('HTTP')) return 'bg-sky-500/12 text-sky-700 dark:text-sky-300 border-sky-500/30';
  if (proto.includes('HJ212')) return 'bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 border-emerald-500/30';
  return 'bg-slate-500/12 text-(--text-secondary) border-(--border-subtle)';
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
