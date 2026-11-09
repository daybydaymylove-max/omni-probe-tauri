import { ref } from 'vue';

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
 * 将底层晦涩的系统调用、网络驱动与硬件异常转换为面向工业运维人员的友好提示与处置指导
 * 时间复杂度: O(1)
 * 空间复杂度: O(1)
 */
export function formatFriendlyError(err: unknown, defaultTitle: string = '操作执行受阻'): { title: string; message: string; action?: NotificationAction } {
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
      title: '底层网络捕获驱动未就绪',
      message: 'Windows 操作系统未检测到或无法加载 Npcap/WinPcap 驱动核心组件。请前往顶部菜单【环境诊断】一键下载并完成驱动热补丁安装。',
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
      title: '系统底层访问权限不足',
      message: '操作系统安全沙箱拦截了底层物理网卡混杂模式或串口独占控制权。建议关闭程序后，右键图标选择【以管理员身份运行】。',
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
      title: '目标通信串口已被独占',
      message: '当前选中的物理/虚拟 COM 端口已被其他 PLC 组态工具、串口助手或后台进程独占占用。请释放占用程序后再试。',
    };
  }

  // 4. 离线蓝牙串口寻呼超时
  if (rawStr.includes('BTHENUM') || (rawStr.includes('Bluetooth') && rawStr.includes('timeout'))) {
    return {
      title: '蓝牙虚拟串口连接超时',
      message: '远端配对的蓝牙终端当前处于关机、休眠或超出无线通信射频覆盖范围，底层基带寻呼未获得应答。',
    };
  }

  // 5. BPF 捕获规则表达式语法错误
  if (
    rawStr.includes('syntax error in filter') ||
    rawStr.includes('BPF') ||
    rawStr.includes('pcap_compile')
  ) {
    return {
      title: 'BPF 过滤表达式语法错误',
      message: `输入的 Berkeley Packet Filter 规则格式非法 (${rawStr})。请参考如 "tcp and port 80" 或 "ip host 192.168.1.1" 的标准语法。`,
    };
  }

  // 6. 等保三级安全审计与操作阻断
  if (rawStr.includes('等保三级') || rawStr.includes('AuditAdmin') || rawStr.includes('权限不足')) {
    return {
      title: '安全合规与等保权限拦截',
      message: rawStr,
    };
  }

  // 7. 通用降级友好包裹
  const cleanMsg = rawStr.length > 200 ? rawStr.substring(0, 200) + '...' : rawStr;
  return {
    title: defaultTitle,
    message: cleanMsg || '底层返回未明异常，请查阅底部系统运行控制台日志获取调用栈详情。',
  };
}

/**
 * 触发通用全局通知 (支持自动防抖与暴风雨抑制)
 * 时间复杂度: O(N) (N <= 4)
 * 空间复杂度: O(1)
 */
export function notify(options: NotifyOptions): string {
  const type = options.type || 'info';
  const duration = options.duration !== undefined ? options.duration : DEFAULT_DURATION_MAP[type];
  const title = options.title.trim();
  const message = (options.message || '').trim();
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
    removeNotification,
    clearAllNotifications,
  };
}
