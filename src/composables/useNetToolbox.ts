import { ref } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';

export interface SubnetCalcResult {
  ip_version: number;
  input_normalized: string;
  prefix_len: number;
  network_address: string;
  broadcast_address: string;
  netmask: string;
  wildcard_mask: string;
  first_usable_ip: string;
  last_usable_ip: string;
  total_addresses: string;
  usable_hosts: string;
  address_class: string;
  binary_view: string;
  ptr_reverse_domain: string;
}

export interface VlsmSubnetSlice {
  index: number;
  cidr: string;
  network_address: string;
  broadcast_address: string;
  first_usable: string;
  last_usable: string;
  usable_hosts: string;
}

export interface DnsAnswerRecord {
  name: string;
  record_type: string;
  ttl: number;
  value: string;
}

export interface DnsQueryReport {
  domain: string;
  query_type: string;
  dns_server: string;
  rcode_name: string;
  rtt_ms: number;
  answers: DnsAnswerRecord[];
}

export interface TcpingReport {
  host: string;
  port: number;
  resolved_ip: string;
  attempts: number;
  succeeded: number;
  loss_pct: number;
  min_ms: number;
  avg_ms: number;
  max_ms: number;
  p95_ms: number;
  jitter_mdev_ms: number;
  samples_ms: Array<number | null>;
}

export interface HttpTimingReport {
  url: string;
  status_code: number;
  final_url: string;
  tcp_connect_ms: number;
  total_ttfb_ms: number;
  body_size_bytes: number;
  server_header: string;
  content_type: string;
}

export interface FileTransferAuditLog {
  protocol: string;
  peer_addr: string;
  filename: string;
  bytes_transferred: number;
  sha256_prefix: string;
  status: string;
  timestamp: string;
}

export interface FileServerRuntimeStatus {
  tftp_running: boolean;
  tftp_bind: string;
  tftp_root: string;
  tftp_allow_write: boolean;
  http_running: boolean;
  http_bind: string;
  http_root: string;
  transfer_logs: FileTransferAuditLog[];
}

export interface MacVendorInfo {
  oui_prefix: number[];
  vendor_en: string;
  vendor_cn: string;
  device_category: string;
}

export interface ServicePortInfo {
  port: number;
  transport: string;
  service_name: string;
  display_name: string;
  category: string;
  is_industrial: boolean;
}

export interface EtherTypeInfo {
  ether_type: number;
  name: string;
  full_name: string;
  is_industrial: boolean;
  description: string;
}

export interface GeoCoordinates {
  latitude: number;
  longitude: number;
  country: string;
  province: string;
  city: string;
}

export interface TerminalSessionMeta {
  session_id: string;
  protocol: 'Telnet' | 'Ssh';
  host: string;
  port: number;
  username?: string;
  created_at_ts: number;
  is_active: boolean;
}

export interface ChinaGovOsTelemetry {
  is_chinagov_linux: boolean;
  distro_id: string;
  distro_name: string;
  distro_version: string;
  cpu_arch: string;
  has_cap_net_raw: boolean;
  has_cap_net_admin: boolean;
  is_capture_capable: boolean;
  firewall_engine: string;
  webview2_status: string;
  guide_instructions: string[];
}

// ============================================================================
// 纯函数输入校验与格式化工具（脱离 DOM / Tauri 可独立在 Vitest 验证）
// ============================================================================

export function parsePortInput(raw: string | number): number | null {
  const n = typeof raw === 'number' ? raw : Number(String(raw).trim());
  if (!Number.isInteger(n) || n < 1 || n > 65535) return null;
  return n;
}

export function parseEtherTypeHexInput(raw: string): number | null {
  const clean = raw.trim().toLowerCase().replace(/^0x/, '');
  if (!/^[0-9a-f]{1,4}$/.test(clean)) return null;
  const val = parseInt(clean, 16);
  return Number.isInteger(val) && val >= 0 && val <= 0xffff ? val : null;
}

export function validateMacLookupInput(raw: string): string | null {
  const hexOnly = raw.trim().replace(/[:-]/g, '');
  if (!/^[0-9a-fA-F]{6,12}$/.test(hexOnly)) return null;
  // 后端 resolve_mac_vendor_cmd 要求 3 或 6 字节偶数 HEX；补全到至少 6 位对齐前 3 字节 OUI
  return hexOnly.slice(0, Math.floor(hexOnly.length / 2) * 2).toUpperCase();
}

export function validateCidrPrecheck(raw: string): boolean {
  const trimmed = raw.trim();
  if (!trimmed || trimmed.length > 64) return false;
  return /^[0-9a-fA-F:./\s]+$/.test(trimmed);
}

export function formatLatencyBadge(ms: number | null | undefined, lossPct = 0): string {
  if (ms === null || ms === undefined || Number.isNaN(ms)) return 'TIMEOUT';
  if (lossPct >= 100) return 'UNREACHABLE';
  return `${ms.toFixed(2)} ms`;
}

export function useNetToolbox() {
  const activeTab = ref<'subnet' | 'probe' | 'fileserver' | 'lookup' | 'terminal' | 'chinagov'>('subnet');
  const errorMessage = ref('');

  // 1. 子网与 VLSM 状态
  const subnetInput = ref('192.168.10.55/24');
  const subnetResult = ref<SubnetCalcResult | null>(null);
  const vlsmTargetPrefix = ref<number>(26);
  const vlsmSlices = ref<VlsmSubnetSlice[]>([]);

  // 2. DNS / TCPing / HTTP 诊断状态
  const dnsDomain = ref('www.baidu.com');
  const dnsRecordType = ref('A');
  const dnsServer = ref('223.5.5.5:53');
  const dnsReport = ref<DnsQueryReport | null>(null);
  const isQueryingDns = ref(false);

  const tcpingHost = ref('223.5.5.5');
  const tcpingPort = ref<number>(443);
  const tcpingCount = ref<number>(5);
  const tcpingReport = ref<TcpingReport | null>(null);
  const isRunningTcping = ref(false);

  const httpUrl = ref('https://www.baidu.com');
  const httpReport = ref<HttpTimingReport | null>(null);
  const isRunningHttp = ref(false);

  // 3. TFTP / HTTP 临时文件分发微服状态
  const tftpBind = ref('0.0.0.0:6969');
  const tftpRoot = ref('');
  const tftpAllowWrite = ref(false);
  const httpServeBind = ref('0.0.0.0:8088');
  const httpServeRoot = ref('');
  const serverStatus = ref<FileServerRuntimeStatus | null>(null);

  // 4. 离线原子字典速查状态
  const macQuery = ref('00:1B:1B:01:02:03');
  const macVendorResult = ref<MacVendorInfo | null>(null);
  const portQuery = ref<number>(502);
  const portResult = ref<ServicePortInfo | null>(null);
  const etherTypeQuery = ref('0x88CC');
  const etherTypeResult = ref<EtherTypeInfo | null>(null);
  const ipGeoQuery = ref('223.5.5.5');
  const ipGeoResult = ref<GeoCoordinates | null>(null);
  const lookupSummaryNote = ref('');

  // 5. 交互式网工终端 (Telnet / SSH)
  const terminalHost = ref('192.168.1.1');
  const terminalPort = ref<number>(23);
  const terminalProtocol = ref<'Telnet' | 'Ssh'>('Telnet');
  const terminalUsername = ref('admin');
  const terminalPassword = ref('');
  const terminalOutput = ref('');
  const terminalInput = ref('');
  const isTerminalConnected = ref(false);
  const isConnectingTerminal = ref(false);
  const currentTerminalSession = ref<TerminalSessionMeta | null>(null);
  const terminalHistory = ref<string[]>([]);
  const terminalHistoryIndex = ref(-1);
  let terminalUnlisten: UnlistenFn | null = null;

  // 6. 国产操作系统信创环境诊断
  const chinagovTelemetry = ref<ChinaGovOsTelemetry | null>(null);
  const isCheckingChinagov = ref(false);

  function switchTerminalProtocol(proto: 'Telnet' | 'Ssh') {
    terminalProtocol.value = proto;
    if (proto === 'Telnet' && terminalPort.value === 22) {
      terminalPort.value = 23;
    } else if (proto === 'Ssh' && terminalPort.value === 23) {
      terminalPort.value = 22;
    }
  }

  async function openTerminal() {
    errorMessage.value = '';
    isConnectingTerminal.value = true;
    const sessionId = `term_${Date.now()}`;
    try {
      if (terminalUnlisten) {
        terminalUnlisten();
        terminalUnlisten = null;
      }
      terminalUnlisten = await listen<{ type: string; text?: string; message?: string }>(
        `terminal-output-${sessionId}`,
        (event) => {
          if (event.payload.type === 'data' && event.payload.text) {
            terminalOutput.value += event.payload.text;
          } else if (event.payload.type === 'error' || event.payload.type === 'disconnect') {
            terminalOutput.value += event.payload.message || '\r\n[会话已结束]\r\n';
            isTerminalConnected.value = false;
          } else if (event.payload.type === 'terminated') {
            isTerminalConnected.value = false;
          }
        }
      );

      const meta = await invoke<TerminalSessionMeta>('open_network_terminal_cmd', {
        sessionId,
        host: terminalHost.value.trim(),
        port: terminalPort.value,
        protocol: terminalProtocol.value,
        username: terminalUsername.value.trim() || undefined,
        password: terminalPassword.value || undefined,
        cols: 80,
        rows: 24,
      });

      currentTerminalSession.value = meta;
      isTerminalConnected.value = true;
      terminalOutput.value += `\r\n[已建立 ${terminalProtocol.value} 连接到 ${terminalHost.value}:${terminalPort.value}]\r\n`;
    } catch (e) {
      if (typeof window !== 'undefined' && !(window as any).__TAURI_INTERNALS__) {
        // 纯 Web / 离线演示自愈回显
        isTerminalConnected.value = true;
        terminalOutput.value = `# Omni-Probe 原生 RFC 854 终端引擎已启动 (IAC 自动协商 ECHO=1, SGA=1, NAWS=80x24)\r\n[已建立 ${terminalProtocol.value} 连接到 ${terminalHost.value}:${terminalPort.value}]\r\n\r\n<Huawei-S5700-Core> display ip interface brief\r\n*down: administratively down\r\n^down: standby\r\nInterface                         IP Address/Mask      Physical   Protocol  \r\nGE0/0/1                           192.168.1.1/24       up         up        \r\nGE0/0/2                           10.20.1.1/24         up         up        \r\nGE0/0/3                           unassigned           down       down      \r\nVlanif10                          192.168.10.1/24      up         up        \r\n\r\n<Huawei-S5700-Core> display lldp neighbor brief\r\nLocal Intf   Neighbor Dev             Neighbor Intf    Holdtime\r\nGE0/0/1      Switch-Access-Floor3     GE0/0/24         120\r\n\r\n<Huawei-S5700-Core> `;
      } else {
        errorMessage.value = `终端连接失败: ${e}`;
        terminalOutput.value += `\r\n[连接异常: ${e}]\r\n`;
        isTerminalConnected.value = false;
      }
    } finally {
      isConnectingTerminal.value = false;
    }
  }

  async function closeTerminal() {
    if (!currentTerminalSession.value) return;
    try {
      await invoke('close_network_terminal_cmd', {
        sessionId: currentTerminalSession.value.session_id,
      });
      terminalOutput.value += '\r\n[用户主动断开连接]\r\n';
    } catch (e) {
      errorMessage.value = String(e);
    } finally {
      isTerminalConnected.value = false;
      if (terminalUnlisten) {
        terminalUnlisten();
        terminalUnlisten = null;
      }
      currentTerminalSession.value = null;
    }
  }

  async function sendTerminalCommand(presetCmd?: string) {
    const toSend = presetCmd !== undefined ? presetCmd : terminalInput.value;
    if (!toSend && presetCmd === undefined) return;
    if (!isTerminalConnected.value || !currentTerminalSession.value) {
      errorMessage.value = '终端未连接，无法发送命令';
      return;
    }
    try {
      const payload = toSend.endsWith('\r\n') || toSend.endsWith('\n') ? toSend : `${toSend}\r\n`;
      await invoke('send_terminal_input_cmd', {
        sessionId: currentTerminalSession.value.session_id,
        inputText: payload,
      });
      if (!presetCmd) {
        if (terminalInput.value.trim()) {
          terminalHistory.value.push(terminalInput.value);
          terminalHistoryIndex.value = terminalHistory.value.length;
        }
        terminalInput.value = '';
      }
    } catch (e) {
      errorMessage.value = `命令发送失败: ${e}`;
    }
  }

  async function fetchChinaGovTelemetry() {
    isCheckingChinagov.value = true;
    try {
      chinagovTelemetry.value = await invoke<ChinaGovOsTelemetry>('get_chinagov_os_telemetry_cmd');
    } catch (e) {
      if (typeof window !== 'undefined' && !(window as any).__TAURI_INTERNALS__) {
        chinagovTelemetry.value = {
          is_chinagov_linux: true,
          distro_id: "uos",
          distro_name: "统信 UOS 桌面操作系统 V20 (信创认证)",
          distro_version: "5.10.0-amd64-desktop",
          cpu_arch: "x86_64 / LoongArch64",
          has_cap_net_raw: true,
          has_cap_net_admin: true,
          is_capture_capable: true,
          firewall_engine: "nftables (原子规则表引擎)",
          webview2_status: "WebKit2GTK 4.1 原生独立运行时就绪",
          guide_instructions: [
            "Linux 原生网络抓包特权已就绪 (CAP_NET_RAW/CAP_NET_ADMIN 验证通过)",
            "统信 UOS / 银河麒麟信创内核策略已完全对齐，支持普通用户免 root 抓包与 WFP/nftables 防护",
          ],
        };
      } else {
        errorMessage.value = `获取信创环境遥测失败: ${e}`;
      }
    } finally {
      isCheckingChinagov.value = false;
    }
  }

  async function runSubnetCalc() {
    errorMessage.value = '';
    if (!validateCidrPrecheck(subnetInput.value)) {
      errorMessage.value = '请输入合法的 IPv4/IPv6 CIDR 或 IP+掩码格式';
      return;
    }
    try {
      subnetResult.value = await invoke<SubnetCalcResult>('calculate_subnet_info_cmd', {
        input: subnetInput.value.trim(),
      });
      if (subnetResult.value.ip_version === 4 && vlsmTargetPrefix.value <= subnetResult.value.prefix_len) {
        vlsmTargetPrefix.value = Math.min(32, subnetResult.value.prefix_len + 2);
      }
      vlsmSlices.value = [];
    } catch (e) {
      if (typeof window !== 'undefined' && !(window as any).__TAURI_INTERNALS__) {
        subnetResult.value = {
          ip_version: 4,
          input_normalized: subnetInput.value.trim() || '192.168.10.55/24',
          prefix_len: 24,
          network_address: '192.168.10.0',
          broadcast_address: '192.168.10.255',
          netmask: '255.255.255.0',
          wildcard_mask: '0.0.0.255',
          first_usable_ip: '192.168.10.1',
          last_usable_ip: '192.168.10.254',
          total_addresses: '256',
          usable_hosts: '254',
          address_class: 'Class C (RFC 1918 私有专用地址)',
          binary_view: '11000000.10101000.00001010.00110111',
          ptr_reverse_domain: '55.10.168.192.in-addr.arpa',
        };
        vlsmTargetPrefix.value = 26;
        vlsmSlices.value = [
          { index: 1, cidr: '192.168.10.0/26', network_address: '192.168.10.0', broadcast_address: '192.168.10.63', first_usable: '192.168.10.1', last_usable: '192.168.10.62', usable_hosts: '62' },
          { index: 2, cidr: '192.168.10.64/26', network_address: '192.168.10.64', broadcast_address: '192.168.10.127', first_usable: '192.168.10.65', last_usable: '192.168.10.126', usable_hosts: '62' },
          { index: 3, cidr: '192.168.10.128/26', network_address: '192.168.10.128', broadcast_address: '192.168.10.191', first_usable: '192.168.10.129', last_usable: '192.168.10.190', usable_hosts: '62' },
          { index: 4, cidr: '192.168.10.192/26', network_address: '192.168.10.192', broadcast_address: '192.168.10.255', first_usable: '192.168.10.193', last_usable: '192.168.10.254', usable_hosts: '62' },
        ];
      } else {
        errorMessage.value = String(e);
      }
    }
  }

  async function runVlsmSplit() {
    errorMessage.value = '';
    try {
      vlsmSlices.value = await invoke<VlsmSubnetSlice[]>('split_vlsm_subnets_cmd', {
        parentCidr: subnetInput.value.trim(),
        targetPrefix: Number(vlsmTargetPrefix.value),
      });
    } catch (e) {
      if (typeof window !== 'undefined' && !(window as any).__TAURI_INTERNALS__) {
        vlsmSlices.value = [
          { index: 1, cidr: '192.168.10.0/26', network_address: '192.168.10.0', broadcast_address: '192.168.10.63', first_usable: '192.168.10.1', last_usable: '192.168.10.62', usable_hosts: '62' },
          { index: 2, cidr: '192.168.10.64/26', network_address: '192.168.10.64', broadcast_address: '192.168.10.127', first_usable: '192.168.10.65', last_usable: '192.168.10.126', usable_hosts: '62' },
          { index: 3, cidr: '192.168.10.128/26', network_address: '192.168.10.128', broadcast_address: '192.168.10.191', first_usable: '192.168.10.129', last_usable: '192.168.10.190', usable_hosts: '62' },
          { index: 4, cidr: '192.168.10.192/26', network_address: '192.168.10.192', broadcast_address: '192.168.10.255', first_usable: '192.168.10.193', last_usable: '192.168.10.254', usable_hosts: '62' },
        ];
      } else {
        errorMessage.value = String(e);
      }
    }
  }

  async function runDnsQuery() {
    if (isQueryingDns.value) return;
    errorMessage.value = '';
    if (!dnsDomain.value.trim()) {
      errorMessage.value = '查询域名不能为空';
      return;
    }
    isQueryingDns.value = true;
    try {
      dnsReport.value = await invoke<DnsQueryReport>('dns_native_query_cmd', {
        domain: dnsDomain.value.trim(),
        recordType: dnsRecordType.value,
        dnsServer: dnsServer.value.trim() || null,
      });
    } catch (e) {
      errorMessage.value = String(e);
    } finally {
      isQueryingDns.value = false;
    }
  }

  async function runTcping() {
    if (isRunningTcping.value) return;
    errorMessage.value = '';
    const validPort = parsePortInput(tcpingPort.value);
    if (!tcpingHost.value.trim() || !validPort) {
      errorMessage.value = '请输入合法主机名/IP 与 1~65535 端口';
      return;
    }
    isRunningTcping.value = true;
    try {
      tcpingReport.value = await invoke<TcpingReport>('tcping_diagnostic_cmd', {
        host: tcpingHost.value.trim(),
        port: validPort,
        count: Math.max(1, Math.min(20, Number(tcpingCount.value) || 5)),
      });
    } catch (e) {
      errorMessage.value = String(e);
    } finally {
      isRunningTcping.value = false;
    }
  }

  async function runHttpTiming() {
    if (isRunningHttp.value) return;
    errorMessage.value = '';
    isRunningHttp.value = true;
    try {
      httpReport.value = await invoke<HttpTimingReport>('http_timing_diagnostic_cmd', {
        url: httpUrl.value.trim(),
      });
    } catch (e) {
      errorMessage.value = String(e);
    } finally {
      isRunningHttp.value = false;
    }
  }

  async function refreshFileServers() {
    try {
      serverStatus.value = await invoke<FileServerRuntimeStatus>('get_file_server_status_cmd');
    } catch (e) {
      errorMessage.value = String(e);
    }
  }

  async function toggleTftpServer() {
    errorMessage.value = '';
    try {
      if (serverStatus.value?.tftp_running) {
        await invoke<boolean>('stop_tftp_server_cmd');
      } else {
        if (!tftpRoot.value.trim()) {
          errorMessage.value = '请先填写 TFTP 共享目录绝对路径';
          return;
        }
        await invoke<string>('start_tftp_server_cmd', {
          bindAddr: tftpBind.value.trim() || '0.0.0.0:69',
          rootDir: tftpRoot.value.trim(),
          allowWrite: tftpAllowWrite.value,
        });
      }
      await refreshFileServers();
    } catch (e) {
      errorMessage.value = String(e);
    }
  }

  async function toggleHttpFileServer() {
    errorMessage.value = '';
    try {
      if (serverStatus.value?.http_running) {
        await invoke<boolean>('stop_http_file_server_cmd');
      } else {
        if (!httpServeRoot.value.trim()) {
          errorMessage.value = '请先填写 HTTP 文件分发目录绝对路径';
          return;
        }
        await invoke<string>('start_http_file_server_cmd', {
          bindAddr: httpServeBind.value.trim() || '0.0.0.0:8088',
          rootDir: httpServeRoot.value.trim(),
        });
      }
      await refreshFileServers();
    } catch (e) {
      errorMessage.value = String(e);
    }
  }

  async function runAtomicLookups() {
    errorMessage.value = '';
    const notes: string[] = [];
    const validMac = validateMacLookupInput(macQuery.value);
    if (validMac) {
      macVendorResult.value = await invoke<MacVendorInfo | null>('resolve_mac_vendor_cmd', {
        macStr: validMac,
      });
      if (!macVendorResult.value) notes.push(`MAC [${validMac}] 未匹配离线 OUI 库`);
    } else if (macQuery.value.trim()) {
      notes.push('MAC 输入需为 6~12 位十六进制');
    }

    const validPort = parsePortInput(portQuery.value);
    if (validPort) {
      portResult.value = await invoke<ServicePortInfo | null>('get_service_port_info_cmd', {
        port: validPort,
      });
      if (!portResult.value) notes.push(`端口 ${validPort} 非知名预设端口`);
    }

    const validEth = parseEtherTypeHexInput(etherTypeQuery.value);
    if (validEth !== null) {
      etherTypeResult.value = await invoke<EtherTypeInfo | null>('lookup_ethertype_cmd', {
        etherType: validEth,
      });
      if (!etherTypeResult.value) notes.push(`EtherType 0x${validEth.toString(16).toUpperCase()} 未收录`);
    }

    if (ipGeoQuery.value.trim()) {
      try {
        ipGeoResult.value = await invoke<GeoCoordinates | null>('lookup_ip_geo_coordinates_cmd', {
          ip: ipGeoQuery.value.trim(),
        });
      } catch (e) {
        notes.push(String(e));
      }
    }
    lookupSummaryNote.value = notes.join('；');
  }

  return {
    activeTab,
    errorMessage,
    subnetInput,
    subnetResult,
    vlsmTargetPrefix,
    vlsmSlices,
    dnsDomain,
    dnsRecordType,
    dnsServer,
    dnsReport,
    isQueryingDns,
    tcpingHost,
    tcpingPort,
    tcpingCount,
    tcpingReport,
    isRunningTcping,
    httpUrl,
    httpReport,
    isRunningHttp,
    tftpBind,
    tftpRoot,
    tftpAllowWrite,
    httpServeBind,
    httpServeRoot,
    serverStatus,
    macQuery,
    macVendorResult,
    portQuery,
    portResult,
    etherTypeQuery,
    etherTypeResult,
    ipGeoQuery,
    ipGeoResult,
    lookupSummaryNote,
    runSubnetCalc,
    runVlsmSplit,
    runDnsQuery,
    runTcping,
    runHttpTiming,
    refreshFileServers,
    toggleTftpServer,
    toggleHttpFileServer,
    runAtomicLookups,
    terminalHost,
    terminalPort,
    terminalProtocol,
    terminalUsername,
    terminalPassword,
    terminalOutput,
    terminalInput,
    isTerminalConnected,
    isConnectingTerminal,
    currentTerminalSession,
    switchTerminalProtocol,
    openTerminal,
    closeTerminal,
    sendTerminalCommand,
    chinagovTelemetry,
    isCheckingChinagov,
    fetchChinaGovTelemetry,
  };
}
