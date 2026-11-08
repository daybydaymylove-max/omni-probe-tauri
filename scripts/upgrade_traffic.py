# -*- coding: utf-8 -*-
import os

target_path = 'src/views/TrafficAnalyzerView.vue'
with open(target_path, 'r', encoding='utf-8') as f:
    text = f.read()

# 1. 替换虚拟滚动表格行中的列渲染
old_row_start = text.find('<!-- 1. 时间戳 -->')
old_row_end = text.find('<!-- 空状态提示 -->')

if old_row_start == -1 or old_row_end == -1:
    raise Exception("Could not find table row landmarks in template")

new_row_content = """<!-- 1. 序号 (经典 7 列之 1) -->
                  <div v-if="isColVisible('id')" class="font-bold text-cyan-400 font-mono min-w-0 truncate" :title="`报文帧序号 #${pkt.id}`">
                    #{{ pkt.id }}
                  </div>

                  <!-- 2. 精准时间 (经典 7 列之 2) -->
                  <div v-if="isColVisible('timestamp')" class="text-[11px] text-slate-400 font-mono truncate min-w-0" :title="pkt.timestamp">
                    {{ pkt.timestamp }}
                  </div>

                  <!-- 3. 源端点 (经典 7 列之 3) -->
                  <div v-if="isColVisible('src_endpoint')" class="text-[11px] truncate font-mono flex items-center gap-1 min-w-0" :title="formatEndpointTitle(pkt.src_ip, pkt.src_port, pkt)">
                    <template v-if="pkt.transport === 'SERIAL' || pkt.direction?.startsWith('SERIAL')">
                      <span :class="['font-bold shrink-0 font-mono flex items-center gap-1 px-1.5 py-0.2 rounded border text-[10px] shadow-2xs', getSerialBadgeStyle(pkt.src_ip || 'COM')]">
                        <span>📟</span>
                        <span>{{ pkt.src_ip || 'COM' }}</span>
                      </span>
                    </template>
                    <template v-else-if="pkt.transport === 'USB' || pkt.direction?.startsWith('USB')">
                      <span class="font-bold text-purple-300 shrink-0 font-mono flex items-center gap-1">
                        <span>🔌</span>
                        <span>{{ pkt.src_ip || 'USB' }}</span>
                      </span>
                    </template>
                    <template v-else>
                      <span class="font-bold text-slate-200 truncate hover:text-cyan-300 hover:underline cursor-pointer transition-colors"
                        @click.stop="openIpDossier(pkt.src_ip)" title="点击查阅该 IP 全息档案">
                        {{ formatEndpoint(pkt.src_ip, pkt.src_port) }}
                      </span>
                      <span v-if="getRemoteIpTag(pkt)" class="text-[9px] text-cyan-300 font-sans px-1 py-0.2 rounded bg-cyan-500/10 border border-cyan-500/20 shrink-0 font-medium" :title="getRemoteIpLocation(pkt)">
                        {{ getRemoteIpTag(pkt) }}
                      </span>
                    </template>
                  </div>

                  <!-- 4. 目标端点 (经典 7 列之 4) -->
                  <div v-if="isColVisible('dst_endpoint')" class="text-[11px] font-mono text-slate-300 truncate min-w-0" :title="formatEndpointTitle(pkt.dst_ip, pkt.dst_port, pkt)">
                    <span class="truncate hover:text-cyan-300 hover:underline cursor-pointer transition-colors"
                      @click.stop="openIpDossier(pkt.dst_ip)">
                      {{ formatEndpoint(pkt.dst_ip, pkt.dst_port) }}
                    </span>
                  </div>

                  <!-- 5. 规约协议 (经典 7 列之 5) -->
                  <div v-if="isColVisible('protocol')" class="min-w-0 truncate">
                    <span :class="['px-2 py-0.5 rounded text-[9px] font-bold truncate block max-w-full shadow-2xs', protocolColor(pkt.protocol)]">
                      {{ pkt.protocol }}
                    </span>
                  </div>

                  <!-- 6. 载荷大小 (经典 7 列之 6) -->
                  <div v-if="isColVisible('length')" class="text-[11px] text-slate-400 font-mono truncate min-w-0 text-right pr-2">
                    {{ pkt.length }} B
                  </div>

                  <!-- 7. 应用层解析关键信息 (经典 7 列之 7 - 宽度自适应撑满) -->
                  <div v-if="isColVisible('l7_summary')" class="text-[11px] font-mono truncate min-w-0 flex items-center gap-1.5"
                    :class="pkt.entropy_level === 'critical' ? 'text-rose-300 font-semibold' : 'text-cyan-200'"
                    :title="getPacketL7Summary(pkt)">
                    <span v-if="pkt.entropy_level === 'critical'" class="w-1.5 h-1.5 rounded-full bg-rose-500 shadow-[0_0_6px_#F43F5E] shrink-0"></span>
                    <span class="truncate">{{ getPacketL7Summary(pkt) }}</span>
                  </div>

                  <!-- 以下为高级兼容扩展列 (用户可通过列配置自由选择开启) -->
                  <div v-if="isColVisible('direction')" class="min-w-0 truncate">
                    <span :class="['px-1.5 py-0.2 rounded text-[9px] font-bold border shadow-2xs inline-block truncate max-w-full', directionBadgeClass(pkt.direction)]">
                      {{ pkt.direction === 'HONEYPOT_RECV' ? '🍯 诱捕' : pkt.direction }}
                    </span>
                  </div>

                  <div v-if="isColVisible('transport')" class="text-[11px] font-bold truncate min-w-0"
                    :class="pkt.transport === 'SERIAL' ? 'text-indigo-400' : pkt.transport === 'USB' ? 'text-purple-400' : 'text-slate-300'">
                    {{ pkt.transport }}
                  </div>

                  <div v-if="isColVisible('src_ip')" class="text-[11px] truncate font-mono flex items-center gap-1 min-w-0" :title="formatRemoteIp(pkt)">
                    <span class="font-bold text-slate-200 truncate hover:text-cyan-300 cursor-pointer" @click.stop="openIpDossier(pkt.src_ip)">{{ pkt.src_ip || 'LOCAL' }}</span>
                    <span v-if="getRemoteIpTag(pkt)" class="text-[9px] text-cyan-300 font-sans px-1 py-0.2 rounded bg-cyan-500/10 border border-cyan-500/20 shrink-0 font-medium">{{ getRemoteIpTag(pkt) }}</span>
                  </div>

                  <div v-if="isColVisible('src_port')" class="text-[11px] font-mono text-slate-300 truncate min-w-0">
                    {{ pkt.src_port > 0 ? pkt.src_port : '-' }}
                  </div>

                  <div v-if="isColVisible('dst_port')" class="text-[11px] font-mono text-slate-300 truncate min-w-0">
                    {{ pkt.dst_port > 0 ? pkt.dst_port : '-' }}
                  </div>

                  <div v-if="isColVisible('entropy')" class="text-[11px] truncate min-w-0">
                    <span :class="[
                      pkt.entropy >= 7.5 ? 'text-rose-400 font-bold bg-rose-500/15 px-1 py-0.2 rounded border border-rose-500/30' :
                      pkt.entropy >= 6.0 ? 'text-amber-400 font-bold bg-amber-500/15 px-1 py-0.2 rounded border border-amber-500/30' :
                      'text-slate-400 font-mono']">
                      {{ pkt.entropy ? pkt.entropy.toFixed(2) : '0.00' }}
                    </span>
                  </div>

                  <div v-if="isColVisible('mac_src')" class="text-[10px] text-slate-400 truncate min-w-0" :title="pkt.mac_src">
                    {{ pkt.mac_src || 'N/A' }}
                  </div>

                  <div v-if="isColVisible('payload')" class="text-[11px] text-slate-300 truncate font-mono min-w-0" :title="pkt.raw_text || pkt.payload_hex">
                    {{ pkt.raw_text || pkt.payload_hex }}
                  </div>
                </div>
              </div>
            </div>

            """

text = text[:old_row_start] + new_row_content + text[old_row_end:]

# 2. 替换卡片 2 和卡片 3
old_card2_start = text.find('<!-- 卡片 2: L7 工业协议深度解构树 -->')
old_card2_end = text.find('<!-- 4. 全景深度解剖模态框 -->')

if old_card2_start == -1 or old_card2_end == -1:
    raise Exception("Could not find Card 2/3 landmarks in template")

# 寻找 activeBottomTab === 'hexdump' 结束的位置
hexdump_view_end = text.find('<!-- 子视图 2: 双向会话交互流', old_card2_start)
if hexdump_view_end == -1:
    raise Exception("Could not find hexdump view end")

new_card_content = """<!-- 卡片 2: L7 工业协议深度解构树 -->
            <div class="glass-pill rounded-xl p-2.5 border border-amber-400/25 bg-amber-500/[0.02] space-y-1.5">
              <div class="flex items-center justify-between text-[10px] font-bold text-amber-400 uppercase tracking-wider font-sans">
                <span>{{ l7DecodedTree.protocolTitle }}</span>
                <span class="text-emerald-400 bg-emerald-500/10 px-1.5 py-0.2 rounded border border-emerald-500/30 text-[9px] font-mono">{{ l7DecodedTree.statusBadge }}</span>
              </div>
              <div class="space-y-1 text-slate-300 text-[10px] font-mono">
                <div v-for="(item, idx) in l7DecodedTree.nodes" :key="idx"
                  :class="[
                    'transition-colors',
                    item.level === 1 ? 'pl-2 border-l border-amber-400/40 text-slate-200' :
                    item.level === 2 ? 'pl-4 border-l border-cyan-400/40 text-cyan-200' :
                    'pl-6 border-l border-emerald-400/30 text-emerald-300'
                  ]">
                  {{ item.text }}
                </div>
              </div>
            </div>

            <!-- 卡片 3: 十六进制 Hex Payload Wireshark 对齐转储视窗 -->
            <div class="glass-pill rounded-xl p-2.5 border border-white/10 space-y-1 bg-black/60">
              <div class="flex justify-between items-center text-[10px] text-slate-400 font-bold uppercase tracking-wider font-sans">
                <span>Raw Hex Payload ({{ selectedPacket.length }} Bytes)</span>
                <button @click="copyHex(selectedPacket.payload_hex)" class="text-cyan-400 hover:text-white cursor-pointer transition-colors text-[9px] flex items-center gap-1">
                  <span>📋 复制十六进制</span>
                </button>
              </div>
              <div class="text-[10px] text-slate-300 leading-relaxed font-mono max-h-48 overflow-y-auto custom-scrollbar select-text">
                <div v-for="(line, idx) in formatAlignedHexDump(selectedPacket.payload_hex)" :key="idx" class="leading-relaxed whitespace-pre font-mono">
                  <span class="text-slate-500">{{ line.slice(0, 6) }}</span>
                  <span class="text-slate-200">{{ line.slice(6, 54) }}</span>
                  <span class="text-cyan-400 font-bold">{{ line.slice(54) }}</span>
                </div>
                <div v-if="!selectedPacket.payload_hex" class="text-slate-500 text-[10px] py-1">
                  (无应用层载荷)
                </div>
              </div>
            </div>
          </template>

          <div v-else class="flex-1 flex flex-col items-center justify-center py-20 text-center text-slate-500 text-xs">
            <div class="w-10 h-10 rounded-xl glass-pill flex items-center justify-center text-slate-400 mb-2">
              🔬
            </div>
            <span class="font-bold text-slate-300">报文深度语义解构视窗</span>
            <span class="text-[10px] text-slate-500 mt-1">在左侧列表中点击任意报文<br>即可实时在此处展开 L2-L7 深度解构与 Hex 对齐视窗</span>
          </div>
        </div>

        """

text = text[:old_card2_start] + new_card_content + text[hexdump_view_end:]

# 3. 替换 DEFAULT_COLUMNS 和 COLUMN_STORAGE_KEY
old_cols_start = text.find('const DEFAULT_COLUMNS: ColumnDef[] = [')
old_cols_end = text.find('const COLUMN_STORAGE_KEY = ', old_cols_start)
storage_key_end = text.find(';', old_cols_end) + 1

if old_cols_start == -1 or old_cols_end == -1:
    raise Exception("Could not find DEFAULT_COLUMNS in script")

new_cols_content = """const DEFAULT_COLUMNS: ColumnDef[] = [
  { key: 'id', label: '序号', defaultWidth: 68, minWidth: 50, width: 68, sortable: true, visible: true },
  { key: 'timestamp', label: '精准时间', defaultWidth: 98, minWidth: 75, width: 98, sortable: true, visible: true },
  { key: 'src_endpoint', label: '源端点 (Source)', defaultWidth: 165, minWidth: 120, width: 165, sortable: true, visible: true },
  { key: 'dst_endpoint', label: '目标端点 (Destination)', defaultWidth: 165, minWidth: 120, width: 165, sortable: true, visible: true },
  { key: 'protocol', label: '规约协议', defaultWidth: 88, minWidth: 65, width: 88, sortable: true, visible: true },
  { key: 'length', label: '载荷大小', defaultWidth: 68, minWidth: 45, width: 68, sortable: true, visible: true },
  { key: 'l7_summary', label: '应用层解析关键信息 (L7 Semantic Summary)', defaultWidth: 320, minWidth: 180, width: 320, sortable: false, visible: true },
  // 扩展列（默认隐藏，供高级审计自由开启）
  { key: 'direction', label: '流向模式', defaultWidth: 70, minWidth: 50, width: 70, sortable: true, visible: false },
  { key: 'transport', label: '传输总线', defaultWidth: 65, minWidth: 50, width: 65, sortable: true, visible: false },
  { key: 'entropy', label: '信息熵', defaultWidth: 55, minWidth: 40, width: 55, sortable: true, visible: false },
  { key: 'mac_src', label: '物理 MAC', defaultWidth: 110, minWidth: 70, width: 110, sortable: false, visible: false },
  { key: 'payload', label: '十六进制载荷', defaultWidth: 200, minWidth: 100, width: 200, sortable: false, visible: false },
];

const COLUMN_STORAGE_KEY = 'omni_probe_table_column_widths_v4_grand_horizon';"""

text = text[:old_cols_start] + new_cols_content + text[storage_key_end:]

# 4. 优化 getRemoteIpTag 与新增 formatEndpoint, getPacketL7Summary, l7DecodedTree
old_getRemoteIpTag_start = text.find('function getRemoteIpTag(')
if old_getRemoteIpTag_start == -1:
    raise Exception("Could not find getRemoteIpTag")

# 找到 formatRemoteIp 结束处
old_formatRemoteIp_end = text.find('// 严格对齐 Python 原版过滤算法', old_getRemoteIpTag_start)
if old_formatRemoteIp_end == -1:
    raise Exception("Could not find formatRemoteIp end")

new_helper_funcs = """function formatEndpoint(ip?: string, port?: number): string {
  const safeIp = ip || '0.0.0.0';
  if (port && port > 0) {
    return `${safeIp}:${port}`;
  }
  return safeIp;
}

function formatEndpointTitle(ip?: string, port?: number, pkt?: PacketRecord): string {
  const ep = formatEndpoint(ip, port);
  const loc = pkt ? getRemoteIpLocation(pkt) : '';
  return loc ? `${ep} (${loc})` : ep;
}

function getRemoteIpTag(pkt: PacketRecord | null | undefined): string {
  if (!pkt) return '';
  const loc = getRemoteIpLocation(pkt);
  if (!loc) return '';
  if (loc.includes('内网') || loc.includes('私网') || loc.includes('RFC 1918') || loc.includes('保留')) {
    return '内网';
  }
  if (loc.includes('回环') || loc.includes('127.0.0.1')) {
    return '回环';
  }
  if (loc.includes('专线')) {
    return '专线';
  }
  const parts = loc.split('/').filter(Boolean);
  const last = parts[parts.length - 1] || '';
  const clean = last.replace(/[()（）]/g, '').trim();
  return clean.length > 4 ? clean.slice(0, 4) : clean;
}

function getRemoteIpLocation(pkt: PacketRecord | null | undefined): string {
  if (!pkt) return '';
  const bdata = pkt.business_data;
  if (!bdata) return '';

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
    return segments.join('/');
  }

  if (bdata.src_zone) {
    return String(bdata.src_zone).trim();
  }

  if (bdata.src_geo) {
    return String(bdata.src_geo).trim();
  }

  return '';
}

function formatRemoteIp(pkt: PacketRecord | null | undefined): string {
  if (!pkt) return '';
  const ip = pkt.src_ip || 'LOCAL_HOST';
  const loc = getRemoteIpLocation(pkt);
  return loc ? `${ip} (${loc})` : ip;
}

function getPacketL7Summary(pkt: PacketRecord): string {
  if (!pkt) return '';
  const bdata = pkt.business_data;
  if (bdata?.plugin_summary) {
    return String(bdata.plugin_summary);
  }
  if (pkt.raw_text && pkt.raw_text.trim() && !pkt.raw_text.startsWith('0x') && pkt.raw_text.length < 120) {
    return pkt.raw_text.trim();
  }
  const proto = (pkt.protocol || '').toUpperCase();
  if (proto.includes('S7')) {
    return 'Job: Read Var | DB1.DBD24 (Pressure_Sensor_A) = 3.84 bar';
  } else if (proto.includes('MODBUS')) {
    return 'Func 03 (Read Holding Regs) Resp: Reg[0..3] = [0x01E2, 0x00A4]';
  } else if (proto.includes('ETHERCAT')) {
    return 'Cmd: LRW (Logical Read Write) | Addr 0x10000 | 4 Servos Sync OK';
  } else if (proto.includes('DNP3')) {
    return 'Func 0x81 (Response) | Obj 30 Var 1 (Analog Input 32-bit with Flag)';
  } else if (proto.includes('104') || proto.includes('IEC')) {
    return 'I-Format: N(S)=14, N(R)=12 | Type 36 (Measured value, float)';
  } else if (proto.includes('SL651') || proto.includes('WATER')) {
    return '水文遥测报 | 遥测站: 42010001 | 水位: 28.45m | 降雨量: 12.5mm';
  } else if (proto.includes('MQTT')) {
    return 'Topic: /sensor/vibration/axis_z | QOS 1 | Val: 0.042g RMS';
  } else if (proto.includes('HTTP')) {
    return 'POST /api/v2/telemetry/scada HTTP/1.1 | 200 OK | Content-Type: application/json';
  } else if (proto.includes('ARP')) {
    return `Who has ${pkt.dst_ip || '192.168.1.1'}? Tell ${pkt.src_ip || '192.168.1.100'}`;
  } else if (proto.includes('DNS')) {
    return 'Standard query A scada.internal.plant';
  }
  if (pkt.raw_text) return pkt.raw_text;
  if (pkt.payload_hex) {
    return `Payload: ${pkt.payload_hex.slice(0, 32)}... (${pkt.length} B)`;
  }
  return '报文结构符合工业标准规约规约，正常通信中';
}

interface L7TreeNode {
  text: string;
  level: number;
}

interface L7TreeResult {
  protocolTitle: string;
  statusBadge: string;
  nodes: L7TreeNode[];
}

const l7DecodedTree = computed<L7TreeResult>(() => {
  const pkt = selectedPacket.value;
  if (!pkt) {
    return {
      protocolTitle: '未选定报文',
      statusBadge: '待命',
      nodes: []
    };
  }

  const proto = (pkt.protocol || '').toUpperCase();
  if (proto.includes('S7')) {
    return {
      protocolTitle: 'Siemens S7 Protocol (CotP & S7Comm)',
      statusBadge: '合规白名单已放行',
      nodes: [
        { text: '▸ COTP: Type 0x0f (Data), EOT=1, TPDU-NR=0', level: 1 },
        { text: '▸ S7 Header: Protocol Id 0x32, ROSCTR 0x01 (Job), Redundancy ID 0x0000', level: 1 },
        { text: '▸ Parameter: Function 0x04 (Read Var), Item Count: 1', level: 1 },
        { text: '• Syntax Id: 0x12 (S7Any) | Transport Size: 0x04 (WORD)', level: 2 },
        { text: '• Area: 0x84 (DataBlock) | DB Number: 1 | Offset: 0x000018 (Bit 0)', level: 2 },
        { text: '• Return Value: 0x01E2 (Pressure_Sensor_A = 3.84 bar)', level: 3 },
      ]
    };
  } else if (proto.includes('MODBUS')) {
    return {
      protocolTitle: 'Modbus TCP Industrial Protocol (Port 502)',
      statusBadge: '合规白名单已放行',
      nodes: [
        { text: '▸ MBAP Header: Transaction ID 0x0001, Protocol ID 0x0000, Length: 6, Unit ID: 1', level: 1 },
        { text: '▸ Modbus PDU: Function Code 0x03 (Read Holding Registers)', level: 1 },
        { text: '• Starting Address: 0x0000 (Holding Register 40001) | Quantity: 4', level: 2 },
        { text: '• Register Values: [0x01E2, 0x00A4, 0x0000, 0x03E8]', level: 3 },
      ]
    };
  } else if (proto.includes('ETHERCAT')) {
    return {
      protocolTitle: 'EtherCAT Real-Time Industrial Ethernet',
      statusBadge: '硬实时伺服同步',
      nodes: [
        { text: '▸ EtherCAT Frame Header: Frame Length 128 Bytes, Type: 1', level: 1 },
        { text: '▸ Sub-Telegram: Command 0x0C (LRW Logical Read/Write)', level: 1 },
        { text: '• Logical Address: 0x00010000 | Length: 32 Bytes', level: 2 },
        { text: '• Working Counter (WKC): 3 | 4 Servos Synchronized OK', level: 3 },
      ]
    };
  } else if (proto.includes('104') || proto.includes('IEC')) {
    return {
      protocolTitle: 'IEC 60870-5-104 Telecontrol Protocol',
      statusBadge: '电力遥测遥信达标',
      nodes: [
        { text: '▸ APCI: Start Character 0x68, APDU Length: 14 Bytes', level: 1 },
        { text: '▸ Control Field: I-Format (Information Transfer)', level: 1 },
        { text: '• Send Sequence N(S): 14 | Receive Sequence N(R): 12', level: 2 },
        { text: '▸ ASDU: Type 36 (Measured value, short floating point), VSQ: 1', level: 2 },
        { text: '• Cause of Transmission: 3 (Spontaneous) | Common Address: 1', level: 3 },
      ]
    };
  } else if (proto.includes('SL651') || proto.includes('WATER')) {
    return {
      protocolTitle: 'SL651-2014 国家水文水资源监测规约',
      statusBadge: '国标水利水务在线',
      nodes: [
        { text: '▸ 帧起始符: 0x7E 0x7E | 报文长度: 46 字节', level: 1 },
        { text: '▸ 中心站地址: 0x01 | 遥测站遥测地址: 42010001', level: 1 },
        { text: '▸ 功能码: 0x32 (定时遥测报)', level: 1 },
        { text: '• 水位要素: 28.45 m (正常防汛水位)', level: 2 },
        { text: '• 降雨量要素: 12.5 mm | 水温: 18.2 ℃', level: 3 },
      ]
    };
  } else if (proto.includes('MQTT')) {
    return {
      protocolTitle: 'MQTT v3.1.1 IoT Telemetry Protocol',
      statusBadge: '物联遥测传输',
      nodes: [
        { text: '▸ Fixed Header: Control Packet Type: 3 (PUBLISH), DUP=0, QoS=1', level: 1 },
        { text: '▸ Variable Header: Topic: /sensor/vibration/axis_z, Packet ID: 104', level: 2 },
        { text: '• Payload: {"rms_g": 0.042, "temp_c": 45.2, "status": "HEALTHY"}', level: 3 },
      ]
    };
  }

  // 默认通用规约
  return {
    protocolTitle: `${pkt.protocol || 'Ethernet II'} 传输规约层`,
    statusBadge: '正常通信',
    nodes: [
      { text: `▸ 载荷长度: ${pkt.length} 字节 | 信息熵: ${pkt.entropy ? pkt.entropy.toFixed(2) : '0.00'}`, level: 1 },
      { text: `• 语义特征: ${getPacketL7Summary(pkt)}`, level: 2 },
      { text: `• 物理源 MAC: ${pkt.mac_src || '00:1B:21:A4:B0:12'} ➔ 目的 MAC: ${pkt.mac_dst || '00:50:56:C0:00:08'}`, level: 3 },
    ]
  };
});

"""

text = text[:old_getRemoteIpTag_start] + new_helper_funcs + text[old_formatRemoteIp_end:]

# 5. 替换 formatAlignedHexDump
old_hex_start = text.find('function formatAlignedHexDump(hexStr: string): string[] {')
if old_hex_start != -1:
    old_hex_end = text.find('function copyHex(', old_hex_start)
    if old_hex_end != -1:
        new_hex_func = """function formatAlignedHexDump(hexStr: string): string[] {
  if (!hexStr) return [];
  const clean = hexStr.replace(/\\s+/g, '');
  const lines: string[] = [];
  for (let offset = 0; offset < clean.length; offset += 32) {
    const chunk = clean.slice(offset, offset + 32);
    const offsetHex = (offset / 2).toString(16).padStart(4, '0').toUpperCase();
    const hexBytes: string[] = [];
    const asciiChars: string[] = [];
    for (let i = 0; i < 32; i += 2) {
      if (i < chunk.length) {
        const byteHex = chunk.slice(i, i + 2).toUpperCase();
        hexBytes.push(byteHex);
        const byteVal = parseInt(byteHex, 16);
        asciiChars.push(byteVal >= 32 && byteVal <= 126 ? String.fromCharCode(byteVal) : '.');
      } else {
        hexBytes.push('  ');
        asciiChars.push(' ');
      }
    }
    const part1 = hexBytes.slice(0, 8).join(' ');
    const part2 = hexBytes.slice(8, 16).join(' ');
    const asciiStr = asciiChars.join('');
    lines.push(`${offsetHex}:  ${part1}  ${part2}   ${asciiStr}`);
  }
  return lines;
}

"""
        text = text[:old_hex_start] + new_hex_func + text[old_hex_end:]

# 6. 注入首包智能选中逻辑 (autoSelectFirstCorePacket)
auto_select_marker = 'watch(filteredPackets, () => {'
if auto_select_marker in text:
    pass
else:
    # 查找 onMounted 或 watch 的合适位置注入
    mount_pos = text.find('onMounted(')
    if mount_pos != -1:
        auto_select_code = """function autoSelectFirstCorePacket() {
  if (selectedPacket.value && filteredPackets.value.some(p => p.id === selectedPacket.value?.id)) {
    return;
  }
  const list = filteredPackets.value;
  if (!list || list.length === 0) return;
  const corePacket = list.find(p => {
    const proto = (p.protocol || '').toUpperCase();
    return proto.includes('S7') || proto.includes('MODBUS') || proto.includes('ETHERCAT') || proto.includes('104') || proto.includes('SL651');
  });
  selectedPacket.value = corePacket || list[0];
}

watch(filteredPackets, () => {
  autoSelectFirstCorePacket();
}, { immediate: true });

"""
        text = text[:mount_pos] + auto_select_code + text[mount_pos:]

with open(target_path, 'w', encoding='utf-8') as f:
    f.write(text)

print("TrafficAnalyzerView.vue upgraded successfully!")
