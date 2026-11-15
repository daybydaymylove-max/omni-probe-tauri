import { ref } from 'vue';
import { t, activeLocale } from '../i18n';

export type NotificationType = 'success' | 'info' | 'warning' | 'error';

export interface NotificationAction {
  label: string;
  onClick: () => void;
}

export interface NotificationItem {
  id: string;
  type: NotificationType;
  title: string;
  message: string;
  action?: NotificationAction;
  duration: number;
  timestamp: number;
  count: number;
}

export interface NotifyOptions {
  type?: NotificationType;
  title: string;
  message?: string;
  action?: NotificationAction;
  duration?: number;
}

// 全局单例通知状态
const notifications = ref<NotificationItem[]>([]);
const MAX_NOTIFICATIONS = 4;
const DEFAULT_DURATION_MAP: Record<NotificationType, number> = {
  success: 3200,
  info: 3500,
  warning: 4500,
  error: 6000,
};

let counter = 0;

/**
 * 工业级智能错误语义解析器
 * 将底层系统调用、网络驱动与硬件异常转换为面向工业运维人员的友好提示与处置指导
 * 时间复杂度: O(1)
 * 空间复杂度: O(1)
 */
export function formatFriendlyError(err: unknown, defaultTitle: string = t('errors.operationBlocked')): { title: string; message: string; action?: NotificationAction } {
  const rawStr = err instanceof Error ? err.message : String(err || '');

  // 1. Npcap / WinPcap 底层网卡抓包驱动缺失或未启动
  if (
    rawStr.includes('pcap_findalldevs') ||
    rawStr.includes('wpcap.dll') ||
    rawStr.includes('Packet.dll') ||
    rawStr.includes('Npcap') ||
    rawStr.includes('No packet capture driver')
  ) {
    return {
      title: t('errors.driverNotReadyTitle'),
      message: t('errors.driverNotReadyMsg'),
    };
  }

  // 2. 操作系统提权受限 (Permission Denied / Administrator required)
  if (
    rawStr.includes('Access is denied') ||
    rawStr.includes('code: 5') ||
    rawStr.includes('PermissionDenied') ||
    rawStr.includes('Operation not permitted')
  ) {
    return {
      title: t('errors.permDeniedTitle'),
      message: t('errors.permDeniedMsg'),
    };
  }

  // 3. 通信串口被独占占用 (Port Busy / Access Denied on COM)
  if (
    rawStr.includes('The device is already in use') ||
    rawStr.includes('Device is busy') ||
    rawStr.includes('Resource busy') ||
    (rawStr.includes('COM') && rawStr.includes('denied'))
  ) {
    return {
      title: t('errors.serialBusyTitle'),
      message: t('errors.serialBusyMsg'),
    };
  }

  // 4. 离线蓝牙串口寻呼超时
  if (rawStr.includes('BTHENUM') || (rawStr.includes('Bluetooth') && rawStr.includes('timeout'))) {
    return {
      title: t('errors.bluetoothTimeoutTitle'),
      message: t('errors.bluetoothTimeoutMsg'),
    };
  }

  // 5. BPF 捕获规则表达式语法错误
  if (
    rawStr.includes('syntax error in filter') ||
    rawStr.includes('BPF') ||
    rawStr.includes('pcap_compile')
  ) {
    return {
      title: t('errors.bpfSyntaxTitle'),
      message: t('errors.bpfSyntaxMsg', { err: rawStr }),
    };
  }

  // 6. 等保三级安全审计与操作阻断
  if (rawStr.includes('等保三级') || rawStr.includes('AuditAdmin') || rawStr.includes('权限不足') || rawStr.includes('Permission denied')) {
    return {
      title: t('errors.complianceDeniedTitle'),
      message: rawStr,
    };
  }

  // 7. 通用降级友好包裹
  const cleanMsg = rawStr.length > 200 ? rawStr.substring(0, 200) + '...' : rawStr;
  return {
    title: defaultTitle,
    message: cleanMsg || t('errors.operationBlocked'),
  };
}

/**
 * 后端 Rust 错误/状态消息智能转译表 (Chinese -> English)
 * 彻底消除底层未改造 Command 直出中文引起的界面中英混血
 * 时间复杂度: O(M) (M <= 30)
 * 空间复杂度: O(1)
 */
const BACKEND_MSG_MAP: Array<[RegExp, string]> = [
  [/未检测到可用网卡/i, 'No available network adapters detected'],
  [/打开设备失败|打开网卡失败/i, 'Failed to open network capture device'],
  [/打开串口失败/i, 'Failed to open serial port'],
  [/设备已被占用|串口已被占用|端口被占用/i, 'Device or serial port is already in use'],
  [/WFP.*提权受限|WFP.*权限不足|需要管理员权限/i, 'Administrator privileges required for WFP filter engine'],
  [/PCAP.*导出受阻|导出.*PCAP.*失败/i, 'Failed to export PCAP packet dump'],
  [/保存.*成功/i, 'Saved successfully'],
  [/操作成功/i, 'Operation completed successfully'],
  [/参数错误|非法参数/i, 'Invalid parameters specified'],
  [/设备未连接|未发现设备/i, 'Device not connected or unreachable'],
  [/数据包解析错误|解码异常/i, 'Packet dissection exception'],
  [/等保.*合规阻断|权限不足/i, 'Access denied by compliance security policy'],
  [/抓包已启动|已启动抓包/i, 'Packet capture started'],
  [/已停止抓包|抓包已停止/i, 'Packet capture stopped'],
  [/已复制.*剪贴板|已复制/i, 'Copied to clipboard'],
  [/正在探测/i, 'Probing in progress...'],
  [/探测完成|扫描完成/i, 'Probe completed successfully'],
  [/连接超时|请求超时/i, 'Connection or request timed out'],
  [/连接被拒绝|对端拒绝/i, 'Connection refused by remote host'],
  [/网络不可达/i, 'Network unreachable'],
  [/文件不存在|找不到指定文件/i, 'File not found or inaccessible'],
  [/写入失败|磁盘空间不足/i, 'Write operation failed or disk full'],
  [/校验码错误|CRC错误/i, 'Checksum / CRC verification failed'],
  [/重放已终止|重放受阻/i, 'Packet replay aborted'],
  [/注入失败/i, 'Frame injection failed'],
  [/解密失败/i, 'Decryption failed'],
  [/重构失败/i, 'Reconstruction failed'],
];

export function translateBackendMessage(msg: string): string {
  if (!msg || activeLocale.value !== 'en-US') return msg;
  let translated = msg;
  for (const [pattern, enText] of BACKEND_MSG_MAP) {
    if (pattern.test(translated)) {
      translated = translated.replace(pattern, enText);
    }
  }
  return translated;
}

/**
 * 触发通用全局通知 (支持自动防抖与暴风雨抑制)
 * 时间复杂度: O(N) (N <= 4)
 * 空间复杂度: O(1)
 */
export function notify(options: NotifyOptions): string {
  const type = options.type || 'info';
  const duration = options.duration !== undefined ? options.duration : DEFAULT_DURATION_MAP[type];
  let title = options.title.trim();
  let message = (options.message || '').trim();

  // 若处于英文环境，自动将底层未处理的中文错误与状态转译为标准英文
  if (activeLocale.value === 'en-US') {
    title = translateBackendMessage(title);
    message = translateBackendMessage(message);
  }

  const now = Date.now();

  // 风暴抑制：检查队列中是否有 1.5 秒内相同类型和标题的通知，若有则进行合并与频次累加
  const existing = notifications.value.find(
    (n) => n.type === type && n.title === title && now - n.timestamp < 1500
  );

  if (existing) {
    existing.count += 1;
    existing.timestamp = now;
    if (message && message !== existing.message) {
      existing.message = message;
    }
    return existing.id;
  }

  // 生成唯一 ID
  counter = (counter + 1) % 1000000;
  const id = `notif_${now}_${counter}`;

  const item: NotificationItem = {
    id,
    type,
    title,
    message,
    action: options.action,
    duration,
    timestamp: now,
    count: 1,
  };

  // 保持队列容量不超过阈值，淘汰最老通知
  if (notifications.value.length >= MAX_NOTIFICATIONS) {
    notifications.value.shift();
  }

  notifications.value.push(item);
  return id;
}

export function notifySuccess(title: string, message?: string, duration?: number): string {
  return notify({ type: 'success', title, message, duration });
}

export function notifyInfo(title: string, message?: string, duration?: number): string {
  return notify({ type: 'info', title, message, duration });
}

export function notifyWarning(title: string, message?: string, duration?: number): string {
  return notify({ type: 'warning', title, message, duration });
}

export function notifyError(title: string, errOrMsg?: unknown, duration?: number): string {
  const parsed = formatFriendlyError(errOrMsg, title);
  return notify({
    type: 'error',
    title: parsed.title,
    message: parsed.message,
    action: parsed.action,
    duration,
  });
}

export function removeNotification(id: string): void {
  const idx = notifications.value.findIndex((n) => n.id === id);
  if (idx !== -1) {
    notifications.value.splice(idx, 1);
  }
}

export function clearAllNotifications(): void {
  notifications.value = [];
}

export function useNotification() {
  return {
    notifications,
    notify,
    notifySuccess,
    notifyInfo,
    notifyWarning,
    notifyError,
    formatFriendlyError,
    translateBackendMessage,
    removeNotification,
    clearAllNotifications,
  };
}
