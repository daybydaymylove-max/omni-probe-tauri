import { ref, computed } from 'vue';
import { notifyInfo } from './useNotification';

export interface UniversalDiffItem {
  id?: number | string;
  label: string;
  timestamp?: string;
  protocol?: string;
  src?: string;
  dst?: string;
  payloadHex: string;
  rawText?: string;
  length?: number;
  direction?: string;
  extraFields?: Record<string, string>;
}

// 全局单例比对工作台状态
const isDiffModalOpen = ref(false);
const activeMode = ref<'hex' | 'fields' | 'wave' | 'samples' | 'scratchpad'>('hex');

// 正在比对的两项
const currentItemA = ref<UniversalDiffItem | null>(null);
const currentItemB = ref<UniversalDiffItem | null>(null);

// 暂存对比槽位 (Slot A & Slot B)，供跨视图、跨列表点选
const slotA = ref<UniversalDiffItem | null>(null);
const slotB = ref<UniversalDiffItem | null>(null);

// 自由草稿文本
const scratchpadTextA = ref('');
const scratchpadTextB = ref('');

/**
 * 工业级数据对象规整适配器
 * 将 PacketRecord、网络调试日志、串口帧、纯 Hex 字符串或文本归一化为 UniversalDiffItem
 */
export function normalizeToDiffableItem(input: any, defaultLabel = '数据样本'): UniversalDiffItem {
  if (!input) {
    return {
      label: defaultLabel,
      payloadHex: '',
      rawText: '',
      length: 0
    };
  }

  // 1. 纯字符串输入 (HEX 串或普通文本)
  if (typeof input === 'string') {
    const trimmed = input.trim();
    const isPureHex = /^[0-9a-fA-F\s]+$/.test(trimmed) && trimmed.replace(/\s+/g, '').length % 2 === 0;
    if (isPureHex) {
      const clean = trimmed.replace(/\s+/g, '');
      return {
        label: defaultLabel,
        payloadHex: trimmed,
        rawText: hexToAsciiSafe(clean),
        length: clean.length / 2,
        protocol: 'RAW_HEX'
      };
    } else {
      return {
        label: defaultLabel,
        payloadHex: asciiToHexSafe(trimmed),
        rawText: trimmed,
        length: trimmed.length,
        protocol: 'ASCII_TEXT'
      };
    }
  }

  // 2. 网络调试工作台日志项 (PacketLogItem)
  if ('payloadHex' in input && 'direction' in input && 'endpoint' in input) {
    const extra: Record<string, string> = {
      '通信流向': input.direction,
      '通信端点': input.endpoint,
      '规约模式': input.mode || 'DEBUG'
    };
    return {
      id: input.id,
      label: `${defaultLabel} [${input.direction}] ${input.endpoint}`,
      timestamp: input.timestamp,
      protocol: input.mode || 'NET_ASSIST',
      src: input.direction === 'TX' ? '本地发送区' : input.endpoint,
      dst: input.direction === 'TX' ? input.endpoint : '本地接收区',
      payloadHex: input.payloadHex || '',
      rawText: input.payloadAscii || '',
      length: input.byteLength || (input.payloadHex ? input.payloadHex.replace(/\s+/g, '').length / 2 : 0),
      direction: input.direction,
      extraFields: extra
    };
  }

  // 3. 网络嗅探抓包记录 (PacketRecord)
  if ('protocol' in input && ('payload_hex' in input || 'raw_frame_hex' in input)) {
    const extra: Record<string, string> = {};
    if (input.business_data && typeof input.business_data === 'object') {
      for (const [k, v] of Object.entries(input.business_data)) {
        extra[k] = String(v);
      }
    }
    if (input.entropy !== undefined) {
      extra['信息熵'] = `${Number(input.entropy).toFixed(3)} (${input.entropy_level || 'normal'})`;
    }
    return {
      id: input.id,
      label: `${defaultLabel} #${input.id} [${input.protocol}]`,
      timestamp: input.timestamp,
      protocol: input.protocol,
      src: input.src_ip ? `${input.src_ip}:${input.src_port || 0}` : '-',
      dst: input.dst_ip ? `${input.dst_ip}:${input.dst_port || 0}` : '-',
      payloadHex: input.payload_hex || input.raw_frame_hex || '',
      rawText: input.raw_text || '',
      length: input.length || 0,
      direction: input.direction,
      extraFields: extra
    };
  }

  // 4. 硬件总线条目 (HardwareBus / Serial)
  if ('bus_type' in input || 'port' in input || 'baudrate' in input) {
    const extra: Record<string, string> = {
      '总线类型': input.bus_type || 'SERIAL',
      '物理端口': input.port || '-'
    };
    if (input.baudrate) extra['波特率'] = String(input.baudrate);
    return {
      id: input.id || Date.now(),
      label: `${defaultLabel} [${input.bus_type || 'SERIAL'}] ${input.port || ''}`,
      timestamp: input.timestamp,
      protocol: input.protocol || 'BUS_IO',
      src: input.direction === 'TX' ? '主机端口' : (input.port || '从机'),
      dst: input.direction === 'TX' ? (input.port || '从机') : '主机端口',
      payloadHex: input.payload_hex || input.payloadHex || '',
      rawText: input.raw_text || '',
      length: input.length || 0,
      direction: input.direction,
      extraFields: extra
    };
  }

  // 5. 通用兜底
  return {
    id: input.id,
    label: input.label || defaultLabel,
    timestamp: input.timestamp,
    protocol: input.protocol || 'GENERIC',
    src: input.src || input.src_ip || '-',
    dst: input.dst || input.dst_ip || '-',
    payloadHex: input.payloadHex || input.payload_hex || '',
    rawText: input.rawText || input.raw_text || '',
    length: input.length || 0,
    direction: input.direction,
    extraFields: input.extraFields || input.business_data || {}
  };
}

function hexToAsciiSafe(hex: string): string {
  try {
    let str = '';
    for (let i = 0; i < hex.length; i += 2) {
      const code = parseInt(hex.slice(i, i + 2), 16);
      if (code >= 32 && code <= 126) {
        str += String.fromCharCode(code);
      } else {
        str += '.';
      }
    }
    return str;
  } catch {
    return '';
  }
}

function asciiToHexSafe(ascii: string): string {
  try {
    let hex = '';
    for (let i = 0; i < ascii.length; i++) {
      const h = ascii.charCodeAt(i).toString(16).padStart(2, '0');
      hex += (i === 0 ? '' : ' ') + h;
    }
    return hex;
  } catch {
    return '';
  }
}

export function useUniversalDiff() {
  const hasBothSlots = computed(() => !!slotA.value && !!slotB.value);

  /**
   * 直接打开双项比对工作台
   */
  function openUniversalDiff(itemA: any, itemB: any, mode: 'hex' | 'fields' | 'wave' = 'hex') {
    currentItemA.value = normalizeToDiffableItem(itemA, '比对样本 A');
    currentItemB.value = normalizeToDiffableItem(itemB, '比对样本 B');
    activeMode.value = mode;
    isDiffModalOpen.value = true;
  }

  /**
   * 打开自由草稿工作台（支持随意粘贴两组十六进制或文本）
   */
  function openScratchpad(initialA = '', initialB = '') {
    scratchpadTextA.value = initialA;
    scratchpadTextB.value = initialB;
    currentItemA.value = normalizeToDiffableItem(initialA, '草稿 A');
    currentItemB.value = normalizeToDiffableItem(initialB, '草稿 B');
    activeMode.value = 'scratchpad';
    isDiffModalOpen.value = true;
  }

  /**
   * 将任意数据项存入槽位 A
   */
  function setSlotA(item: any, label = '比对项 A') {
    slotA.value = normalizeToDiffableItem(item, label);
    notifyInfo('已存入比对槽位 A', `${slotA.value.label} (${slotA.value.length} 字节)`);
  }

  /**
   * 将任意数据项存入槽位 B
   */
  function setSlotB(item: any, label = '比对项 B') {
    slotB.value = normalizeToDiffableItem(item, label);
    notifyInfo('已存入比对槽位 B', `${slotB.value.label} (${slotB.value.length} 字节)`);
  }

  /**
   * 交换槽位 A 与槽位 B
   */
  function swapSlots() {
    const temp = slotA.value;
    slotA.value = slotB.value;
    slotB.value = temp;
    if (currentItemA.value && currentItemB.value) {
      const curTemp = currentItemA.value;
      currentItemA.value = currentItemB.value;
      currentItemB.value = curTemp;
    }
  }

  /**
   * 触发比对槽位 A 和槽位 B
   */
  function compareSlots() {
    if (!slotA.value || !slotB.value) {
      notifyInfo('提示', '请先在两个槽位中均填入数据项');
      return;
    }
    openUniversalDiff(slotA.value, slotB.value);
  }

  /**
   * 清空槽位
   */
  function clearSlots() {
    slotA.value = null;
    slotB.value = null;
  }

  /**
   * 关闭比对工作台
   */
  function closeUniversalDiff() {
    isDiffModalOpen.value = false;
  }

  return {
    isDiffModalOpen,
    activeMode,
    currentItemA,
    currentItemB,
    slotA,
    slotB,
    hasBothSlots,
    scratchpadTextA,
    scratchpadTextB,
    openUniversalDiff,
    openScratchpad,
    setSlotA,
    setSlotB,
    swapSlots,
    compareSlots,
    clearSlots,
    closeUniversalDiff,
    normalizeToDiffableItem
  };
}
