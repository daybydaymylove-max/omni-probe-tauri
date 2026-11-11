import { ref, computed } from 'vue';
import { notifyInfo, notifySuccess } from './useNotification';

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

export type DiffViewMode = 'hex' | 'multi' | 'fields' | 'wave' | 'samples' | 'scratchpad' | 'file_merge';

// 全局单例比对工作台状态 (支持 2 组精细比对及 N >= 2 不封顶多组 Center-Star 对齐矩阵)
const isDiffModalOpen = ref(false);
const activeMode = ref<DiffViewMode>('hex');

// 当前活跃比对队列 (默认最多 2 项走双栏，>= 3 项自动进入多组精比矩阵，2 项亦可切换多组矩阵)
const diffQueue = ref<UniversalDiffItem[]>([]);
const anchorIndex = ref<number>(0);

// 兼容 2 项对比引用 (当仅对比 2 项或点击设为 A / B 时双向映射)
const currentItemA = ref<UniversalDiffItem | null>(null);
const currentItemB = ref<UniversalDiffItem | null>(null);
const slotA = ref<UniversalDiffItem | null>(null);
const slotB = ref<UniversalDiffItem | null>(null);
const droppedFileLeft = ref<string>('');
const droppedFileRight = ref<string>('');

// 自由草稿文本 (支持 2 组及以上无限扩展)
const scratchpadTextA = ref('');
const scratchpadTextB = ref('');
const scratchpadList = ref<Array<{ label: string; text: string }>>([
  { label: '草稿组 #1 (基准)', text: '' },
  { label: '草稿组 #2', text: '' },
]);

/**
 * 判断纯十六进制格式（剥离空白与 0x 前缀后全为合法偶数字节）
 */
function isStrictHexString(raw: string): string | null {
  const cleaned = raw.replace(/0x/gi, '').replace(/[\s\r\n\t,:-]/g, '');
  if (cleaned.length >= 2 && cleaned.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(cleaned)) {
    return cleaned.toUpperCase();
  }
  return null;
}

/**
 * 递归扁平化嵌套元数据对象，避免前端出现 "[object Object]" 不可读字符串
 */
function flattenToExtraFields(obj: unknown, prefix = '', out: Record<string, string> = {}): Record<string, string> {
  if (!obj || typeof obj !== 'object') return out;
  const entries = Object.entries(obj as Record<string, unknown>);
  for (const [key, val] of entries) {
    if (val === undefined || val === null) continue;
    const fullKey = prefix ? `${prefix}.${key}` : key;
    if (Array.isArray(val)) {
      out[fullKey] = val.map((v) => (typeof v === 'object' ? JSON.stringify(v) : String(v))).join(', ');
    } else if (typeof val === 'object') {
      flattenToExtraFields(val, fullKey, out);
    } else {
      out[fullKey] = String(val);
    }
  }
  return out;
}

function hexToAsciiSafe(hex: string): string {
  try {
    let str = '';
    for (let i = 0; i < hex.length; i += 2) {
      const code = parseInt(hex.slice(i, i + 2), 16);
      str += code >= 32 && code <= 126 ? String.fromCharCode(code) : '.';
    }
    return str;
  } catch {
    return '';
  }
}

function resolvePayloadEncoding(hexCandidate: string, rawTextCandidate: string, forceRawText = false): { payloadHex: string; rawText: string; length: number } {
  if (forceRawText) {
    return {
      payloadHex: '',
      rawText: rawTextCandidate || hexCandidate,
      length: (rawTextCandidate || hexCandidate).length,
    };
  }

  const trimmedHex = (hexCandidate || '').trim();
  if (trimmedHex.length > 0) {
    const strictHex = isStrictHexString(trimmedHex);
    if (strictHex) {
      return {
        payloadHex: strictHex,
        rawText: rawTextCandidate || hexToAsciiSafe(strictHex),
        length: strictHex.length / 2,
      };
    }
    // 非法 Hex 但传在了 payloadHex 字段里：回退为明文 rawText 处理
    const textVal = rawTextCandidate || trimmedHex;
    return {
      payloadHex: '',
      rawText: textVal,
      length: textVal.length,
    };
  }

  const textVal = rawTextCandidate || '';
  return {
    payloadHex: '',
    rawText: textVal,
    length: textVal.length,
  };
}

/**
 * 工业级全源数据对象规整适配器
 * 兼容 PacketRecord、网络调试日志、硬件总线、解密明文、合规审计、取证档案及纯 Hex/ASCII 草稿
 */
export function normalizeToDiffableItem(input: any, defaultLabel = '数据样本'): UniversalDiffItem {
  if (!input) {
    return {
      label: defaultLabel,
      payloadHex: '',
      rawText: '',
      length: 0,
    };
  }

  // 1. 纯字符串输入 (区分严格 HEX 码流与 ASCII 明文字符串)
  if (typeof input === 'string') {
    const trimmed = input.trim();
    const strictHex = isStrictHexString(trimmed);
    if (strictHex) {
      return {
        label: defaultLabel,
        payloadHex: strictHex,
        rawText: hexToAsciiSafe(strictHex),
        length: strictHex.length / 2,
        protocol: 'RAW_HEX',
      };
    }
    return {
      label: defaultLabel,
      payloadHex: '',
      rawText: trimmed,
      length: trimmed.length,
      protocol: 'ASCII_TEXT',
    };
  }

  // 2. 网络调试工作台日志项 (PacketLogItem)
  if ('payloadHex' in input && 'direction' in input && 'endpoint' in input) {
    const extra: Record<string, string> = {
      '通信流向': String(input.direction || ''),
      '通信端点': String(input.endpoint || ''),
      '规约模式': String(input.mode || 'DEBUG'),
    };
    const isAsciiOnly = Boolean(input.isRawText || input.format === 'ASCII');
    const enc = resolvePayloadEncoding(input.payloadHex || '', input.payloadAscii || input.rawText || '', isAsciiOnly);
    return {
      id: input.id,
      label: input.label || `${defaultLabel} [${input.direction}] ${input.endpoint}`,
      timestamp: input.timestamp,
      protocol: input.mode || 'NET_ASSIST',
      src: input.direction === 'TX' ? '本地发送区' : input.endpoint,
      dst: input.direction === 'TX' ? input.endpoint : '本地接收区',
      payloadHex: enc.payloadHex,
      rawText: enc.rawText,
      length: input.byteLength || enc.length,
      direction: input.direction,
      extraFields: extra,
    };
  }

  // 3. 网络嗅探抓包记录 (PacketRecord)
  if ('protocol' in input && ('payload_hex' in input || 'raw_frame_hex' in input)) {
    const extra = flattenToExtraFields(input.business_data);
    if (input.entropy !== undefined) {
      extra['信息熵'] = `${Number(input.entropy).toFixed(3)} (${input.entropy_level || 'normal'})`;
    }
    const enc = resolvePayloadEncoding(input.payload_hex || input.raw_frame_hex || '', input.raw_text || '');
    return {
      id: input.id,
      label: input.label || `${defaultLabel} #${input.id} [${input.protocol}]`,
      timestamp: input.timestamp,
      protocol: input.protocol,
      src: input.src_ip ? `${input.src_ip}:${input.src_port || 0}` : (input.endpoint_src || '-'),
      dst: input.dst_ip ? `${input.dst_ip}:${input.dst_port || 0}` : (input.endpoint_dst || '-'),
      payloadHex: enc.payloadHex,
      rawText: enc.rawText,
      length: input.length || enc.length,
      direction: input.direction,
      extraFields: extra,
    };
  }

  // 4. 硬件总线条目 (HardwareBus / Serial)
  if ('bus_type' in input || 'port' in input || 'baudrate' in input) {
    const extra: Record<string, string> = {
      '总线类型': String(input.bus_type || 'SERIAL'),
      '物理端口': String(input.port || '-'),
      ...flattenToExtraFields(input.extraFields || input.extra_fields),
    };
    if (input.baudrate) extra['波特率'] = String(input.baudrate);
    const enc = resolvePayloadEncoding(input.payload_hex || input.payloadHex || '', input.raw_text || input.rawText || '');
    return {
      id: input.id || Date.now(),
      label: input.label || `${defaultLabel} [${input.bus_type || 'SERIAL'}] ${input.port || ''}`,
      timestamp: input.timestamp,
      protocol: input.protocol || 'BUS_IO',
      src: input.src || input.endpoint_src || (input.direction === 'TX' ? '主机端口' : (input.port || '从机')),
      dst: input.dst || input.endpoint_dst || (input.direction === 'TX' ? (input.port || '从机') : '主机端口'),
      payloadHex: enc.payloadHex,
      rawText: enc.rawText,
      length: input.length || enc.length,
      direction: input.direction,
      extraFields: extra,
    };
  }

  // 5. 通用跨模块兜底 (完整兼容 endpoint_src / endpoint_dst / source / target / extra_fields)
  const isRaw = Boolean(input.isRawText);
  const enc = resolvePayloadEncoding(input.payloadHex || input.payload_hex || '', input.rawText || input.raw_text || '', isRaw);
  const flatExtra = flattenToExtraFields(input.extraFields || input.extra_fields || input.business_data);

  return {
    id: input.id,
    label: input.label || defaultLabel,
    timestamp: input.timestamp,
    protocol: input.protocol || 'GENERIC',
    src: input.src || input.endpoint_src || input.src_ip || input.source || '-',
    dst: input.dst || input.endpoint_dst || input.dst_ip || input.target || '-',
    payloadHex: enc.payloadHex,
    rawText: enc.rawText,
    length: input.length || input.byteLength || enc.length,
    direction: input.direction,
    extraFields: flatExtra,
  };
}

function syncSlotsWithQueue() {
  slotA.value = diffQueue.value[0] || null;
  slotB.value = diffQueue.value[1] || null;
  currentItemA.value = diffQueue.value[0] || null;
  currentItemB.value = diffQueue.value[1] || null;
  if (anchorIndex.value >= diffQueue.value.length) {
    anchorIndex.value = 0;
  }
}

export function useUniversalDiff() {
  const hasBothSlots = computed(() => diffQueue.value.length >= 2 || (!!slotA.value && !!slotB.value));
  const queueCount = computed(() => diffQueue.value.length);

  /**
   * 直接打开双项比对工作台
   */
  function openUniversalDiff(itemA: any, itemB: any, mode: DiffViewMode = 'hex') {
    const normA = normalizeToDiffableItem(itemA, '比对样本 A');
    const normB = normalizeToDiffableItem(itemB, '比对样本 B');
    diffQueue.value = [normA, normB];
    anchorIndex.value = 0;
    syncSlotsWithQueue();
    activeMode.value = mode;
    isDiffModalOpen.value = true;
  }

  /**
   * 直接打开 N >= 2 组精准对齐比对工作台
   */
  function openMultiDiff(items: any[], preferredAnchor = 0, mode: DiffViewMode = 'multi') {
    const normalized = items.map((it, idx) => normalizeToDiffableItem(it, `样本 #${idx + 1}`));
    if (normalized.length === 0) return;
    diffQueue.value = normalized;
    anchorIndex.value = Math.max(0, Math.min(preferredAnchor, normalized.length - 1));
    syncSlotsWithQueue();
    activeMode.value = normalized.length >= 2 ? mode : 'scratchpad';
    isDiffModalOpen.value = true;
  }

  /**
   * 向全局多组比对队列追加一项数据（支持任意组数扩展: 2/3/4/5...组）
   */
  function addToQueue(item: any, label = `样本 #${diffQueue.value.length + 1}`, openIfReady = false) {
    const normalized = normalizeToDiffableItem(item, label);
    diffQueue.value = [...diffQueue.value, normalized];
    syncSlotsWithQueue();
    notifySuccess(
      '已加入多组比对队列',
      `[${normalized.label}] 已入队，当前队列共 ${diffQueue.value.length} 组样本`
    );
    if (openIfReady && diffQueue.value.length >= 2) {
      activeMode.value = diffQueue.value.length > 2 ? 'multi' : 'hex';
      isDiffModalOpen.value = true;
    }
  }

  function removeFromQueue(index: number) {
    if (index < 0 || index >= diffQueue.value.length) return;
    const next = [...diffQueue.value];
    next.splice(index, 1);
    diffQueue.value = next;
    if (anchorIndex.value >= next.length) anchorIndex.value = 0;
    syncSlotsWithQueue();
  }

  function setAnchorIndex(index: number) {
    if (index >= 0 && index < diffQueue.value.length) {
      anchorIndex.value = index;
    }
  }

  /**
   * 打开自由草稿工作台（支持 2 组及动态增行多组对比）
   */
  function openScratchpad(initialA = '', initialB = '') {
    scratchpadTextA.value = initialA;
    scratchpadTextB.value = initialB;
    scratchpadList.value = [
      { label: '草稿组 #1 (基准)', text: initialA },
      { label: '草稿组 #2', text: initialB },
    ];
    if (initialA || initialB) {
      diffQueue.value = [
        normalizeToDiffableItem(initialA, '草稿 #1'),
        normalizeToDiffableItem(initialB, '草稿 #2'),
      ];
      syncSlotsWithQueue();
    }
    activeMode.value = 'scratchpad';
    isDiffModalOpen.value = true;
  }

  /**
   * 将任意数据项设为比对项 A（队列第 1 位）
   */
  function setSlotA(item: any, label = '比对项 A') {
    const norm = normalizeToDiffableItem(item, label);
    const next = [...diffQueue.value];
    next[0] = norm;
    diffQueue.value = next;
    syncSlotsWithQueue();
    notifyInfo('已存入比对基准 A', `${norm.label} (${norm.length} 字节)`);
  }

  /**
   * 将任意数据项设为比对项 B（队列第 2 位）
   */
  function setSlotB(item: any, label = '比对项 B') {
    const norm = normalizeToDiffableItem(item, label);
    const next = [...diffQueue.value];
    if (next.length === 0) {
      next.push(normalizeToDiffableItem('', '待填充基准 A'));
    }
    next[1] = norm;
    diffQueue.value = next;
    syncSlotsWithQueue();
    notifyInfo('已存入比对样本 B', `${norm.label} (${norm.length} 字节)`);
  }

  /**
   * 交换项 A 与项 B
   */
  function swapSlots() {
    if (diffQueue.value.length < 2) return;
    const next = [...diffQueue.value];
    const tmp = next[0];
    next[0] = next[1];
    next[1] = tmp;
    diffQueue.value = next;
    syncSlotsWithQueue();
  }

  /**
   * 触发当前队列（>=2 组自动切分：2组默认 Hex 双栏，>=3 组默认多组矩阵）
   */
  function compareSlots() {
    if (diffQueue.value.length < 2) {
      notifyInfo('提示', '请至少放入 2 组数据样本后再开启比对');
      return;
    }
    activeMode.value = diffQueue.value.length >= 3 ? 'multi' : 'hex';
    isDiffModalOpen.value = true;
  }

  function clearSlots() {
    diffQueue.value = [];
    anchorIndex.value = 0;
    syncSlotsWithQueue();
  }

  function closeUniversalDiff() {
    isDiffModalOpen.value = false;
  }

  function openFileMergeWithPaths(left?: string, right?: string) {
    if (left) droppedFileLeft.value = left;
    if (right) droppedFileRight.value = right;
    activeMode.value = 'file_merge';
    isDiffModalOpen.value = true;
  }

  return {
    isDiffModalOpen,
    activeMode,
    diffQueue,
    queueCount,
    anchorIndex,
    currentItemA,
    currentItemB,
    slotA,
    slotB,
    droppedFileLeft,
    droppedFileRight,
    hasBothSlots,
    scratchpadTextA,
    scratchpadTextB,
    scratchpadList,
    openUniversalDiff,
    openMultiDiff,
    openScratchpad,
    openFileMergeWithPaths,
    addToQueue,
    removeFromQueue,
    setAnchorIndex,
    setSlotA,
    setSlotB,
    swapSlots,
    compareSlots,
    clearSlots,
    closeUniversalDiff,
    normalizeToDiffableItem,
  };
}
