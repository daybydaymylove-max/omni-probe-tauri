import { computeSm3Hex, computeSha256Hex, escapeHtml } from '../utils/cryptoDigest';

/**
 * 模块一：USB 历史插拔痕迹条目 DTO (与 src-tauri/src/secrecy_usb_forensics.rs 对齐)
 */
export interface UsbHistoryEvidenceItem {
  device_id: string;
  vendor_id: string;
  product_id: string;
  serial_number: string;
  device_name: string;
  class_guid: string;
  first_installed_time: string;
  last_arrival_time: string;
  assigned_drive_letter: string;
  is_whitelisted: boolean;
  violation_level: string;
  evidence_source: string;
}

export interface SecrecyUsbAuditReport {
  scanned_host: string;
  scan_time: string;
  total_devices_found: number;
  unauthorized_device_count: number;
  has_critical_violation: boolean;
  devices: UsbHistoryEvidenceItem[];
  summary_conclusion: string;
}

/**
 * 模块二：复合文档深度解构命中 DTO (与 src-tauri/src/secrecy_document_dissector.rs 对齐)
 */
export interface SecrecyDocumentHit {
  file_path: string;
  file_type: string;
  file_size_bytes: number;
  sha256_hash: string;
  sm3_hash: string;
  secrecy_level: string;
  matched_markers: string[];
  document_signatures: string[];
  snippet_preview: string;
  is_archive_nested: boolean;
  nested_path: string | null;
}

export interface SecrecyDissectBatchReport {
  target_folder: string;
  scanned_files_count: number;
  hit_files_count: number;
  encrypted_or_blocked_count: number;
  duration_ms: number;
  top_secret_count: number;
  confidential_count: number;
  secret_count: number;
  hits: SecrecyDocumentHit[];
  warnings: string[];
}

/**
 * 模块三：双网卡一机两用探测 DTO (与 src-tauri/src/secrecy_dual_homed_audit.rs 对齐)
 */
export interface NicInterfaceAuditItem {
  name: string;
  if_type: string;
  is_up: boolean;
  ip_addresses: string[];
  gateway_addresses: string[];
  is_connected_to_private: boolean;
  is_connected_to_public: boolean;
}

export interface DualHomedAuditVerdict {
  is_dual_homed_violation: boolean;
  active_nic_count: number;
  has_simultaneous_wired_and_wireless: boolean;
  has_public_and_private_bridging: boolean;
  wireless_ssid: string | null;
  risk_level: string;
  reason: string;
  interfaces: NicInterfaceAuditItem[];
}

/**
 * 网流及即席文本涉密捕获记录 DTO
 */
export interface ConfidentialityAlertRecord {
  timestamp: number;
  source: string;
  destination: string;
  level: string;
  matchedKeywords: string[];
  documentSignatures: string[];
  snippet: string;
}

export type SecrecyClassificationLevel = '秘密级' | '机密级' | '绝密级' | '非涉密终端自查';

export type SecrecyVerdictCode = 'QUALIFIED' | 'CONDITIONALLY_QUALIFIED' | 'DISQUALIFIED_VETOED';

export interface SecrecyBmbControlRow {
  clauseId: string;
  standardRef: string;
  controlTitle: string;
  status: 'PASS' | 'WARN' | 'VETO_FAIL' | 'NOT_EXECUTED';
  evidenceSummary: string;
}

export interface SecrecyCanonicalDigest {
  sm3Hex: string;
  sha256Hex: string;
  canonicalByteLength: number;
  reportId: string;
}

export interface SecrecyFormalReportVerdict {
  code: SecrecyVerdictCode;
  label: '【合格】' | '【基本合格】' | '【不合格 (触发一票否决)】';
  isVetoed: boolean;
  vetoReasons: string[];
  warningReasons: string[];
  bmbMatrix: SecrecyBmbControlRow[];
  summaryText: string;
}

/**
 * 模块四：非涉密网络与历史外联取证 DTO (与 src-tauri/src/secrecy_history_network_forensics.rs 对齐)
 */
export interface WifiProfileHistoryItem {
  profile_name: string;
  ssid: string;
  auth_type: string;
  cipher: string;
  is_mobile_hotspot_feature: boolean;
  last_modified_time: string;
}

export interface NetworkListProfileItem {
  profile_name: string;
  network_category: string;
  last_connected_time: string;
}

export interface SecrecyNetworkHistoryReport {
  scanned_host: string;
  scan_time: string;
  total_wifi_profiles_found: number;
  suspicious_mobile_hotspots: WifiProfileHistoryItem[];
  all_wifi_profiles: WifiProfileHistoryItem[];
  historic_rndis_devices: string[];
  historic_dialup_connections: string[];
  historic_network_profiles: NetworkListProfileItem[];
  has_historic_violation: boolean;
  summary_conclusion: string;
  degrade_notes: string[];
}

/**
 * 模块五：老旧 OLE2 复合公文与空闲扇区残片检索 DTO (与 src-tauri/src/secrecy_ole2_and_slack_scanner.rs 对齐)
 */
export interface Ole2DocumentHit {
  file_path: string;
  sub_stream_name: string;
  sha256_hash: string;
  sm3_hash: string;
  secrecy_level: string;
  matched_markers: string[];
  document_signatures: string[];
  snippet_preview: string;
}

export interface SlackSpaceSnippetHit {
  drive_letter: string;
  sector_offset: number;
  matched_marker: string;
  snippet_preview: string;
}

export interface SecrecyDeepContentReport {
  target_folder: string;
  scanned_ole2_files: number;
  ole2_hits: Ole2DocumentHit[];
  slack_scanned_bytes: number;
  slack_hits: SlackSpaceSnippetHit[];
  duration_ms: number;
  warnings: string[];
}

/**
 * 模块六：操作系统最近访问 (.lnk)、打印假脱机 (.SHD) 与开关机时间线 DTO (与 src-tauri/src/secrecy_os_usage_forensics.rs 对齐)
 */
export interface RecentFileAccessItem {
  shortcut_name: string;
  target_real_path: string;
  target_creation_time: string;
  target_last_access_time: string;
  drive_type: string;
  is_removable_media_target: boolean;
  is_secrecy_named: boolean;
}

export interface PrintJobSpoolerItem {
  job_id: string;
  document_name: string;
  printer_name: string;
  submit_time: string;
  spool_file_path: string;
  is_secrecy_suspicious: boolean;
}

export interface SecrecyOsUsageReport {
  scanned_host: string;
  scan_time: string;
  total_lnk_parsed: number;
  recent_files: RecentFileAccessItem[];
  print_spooler_jobs: PrintJobSpoolerItem[];
  system_boot_history: string[];
  suspicious_u_disk_file_count: number;
  secrecy_named_access_count: number;
  degrade_notes: string[];
}

/**
 * 模块七：浏览器下载记录与办公即时通信外发痕迹 DTO (与 src-tauri/src/secrecy_app_trace_audit.rs 对齐)
 */
export interface BrowserDownloadHitItem {
  browser_type: string;
  target_file_path: string;
  original_url: string;
  download_time: string;
  is_suspicious_secrecy: boolean;
  matched_marker: string | null;
}

export interface ChatFileTraceItem {
  app_name: string;
  file_name: string;
  file_path: string;
  file_size: number;
  hit_secrecy_marker: string | null;
}

export interface SecrecyAppTraceReport {
  scanned_host: string;
  scan_time: string;
  total_downloads_checked: number;
  suspicious_downloads: BrowserDownloadHitItem[];
  recent_downloads_sample: BrowserDownloadHitItem[];
  chat_files_checked: number;
  chat_file_hits: ChatFileTraceItem[];
  degrade_notes: string[];
}

export interface SecrecyReportParams {
  targetUnitName: string;
  systemName: string;
  systemClassification: SecrecyClassificationLevel;
  inspectorName: string;
  inspectionTimeIso: string;
  usbReport: SecrecyUsbAuditReport | null;
  dissectReport: SecrecyDissectBatchReport | null;
  dualHomedReport: DualHomedAuditVerdict | null;
  networkAlerts: ConfidentialityAlertRecord[];
  networkHistoryReport?: SecrecyNetworkHistoryReport | null;
  ole2Report?: SecrecyDeepContentReport | null;
  osUsageReport?: SecrecyOsUsageReport | null;
  appTraceReport?: SecrecyAppTraceReport | null;
}

const LEGAL_SECRECY_GRADES = new Set(['TOP_SECRET', 'CONFIDENTIAL', 'SECRET']);

/**
 * 评估第 2 阶段 4 项深度取证扩展控制矩阵（历史外联 / OLE2 与扇区残片 / OS 使用轨迹 / 应用外发）
 *
 * 时间复杂度: O(N + E + O + T)
 * 空间复杂度: O(1)
 */
function evaluateDeepForensicsControls(
  params: SecrecyReportParams,
  vetoReasons: string[],
  warningReasons: string[],
): SecrecyBmbControlRow[] {
  const rows: SecrecyBmbControlRow[] = [];

  if (params.networkHistoryReport) {
    const netHis = params.networkHistoryReport;
    const hasMobileOrRndis =
      netHis.has_historic_violation ||
      netHis.suspicious_mobile_hotspots.length > 0 ||
      netHis.historic_rndis_devices.length > 0;
    if (hasMobileOrRndis) {
      const msg = `检出历史无线热点/手机 USB RNDIS 共享外联痕迹（可疑热点 ${netHis.suspicious_mobile_hotspots.length} 项，RNDIS 共享设备 ${netHis.historic_rndis_devices.length} 台）`;
      vetoReasons.push(`[BMB22-5.2.1-HIS 一票否决] ${msg}`);
      rows.push({
        clauseId: 'BMB22-HIS-NET',
        standardRef: 'BMB22-2007 5.2.1 历史违规外联溯源',
        controlTitle: '历史 Wi-Fi 配置文件、手机热点与 RNDIS 共享痕迹核查',
        status: 'VETO_FAIL',
        evidenceSummary: msg,
      });
    } else if (netHis.all_wifi_profiles.length > 0 || netHis.historic_dialup_connections.length > 0) {
      const msg = `存在 ${netHis.all_wifi_profiles.length} 项普通 Wi-Fi 历史配置及 ${netHis.historic_dialup_connections.length} 项拨号记录，需人工复核授权边界`;
      warningReasons.push(msg);
      rows.push({
        clauseId: 'BMB22-HIS-NET',
        standardRef: 'BMB22-2007 5.2.1 历史违规外联溯源',
        controlTitle: '历史 Wi-Fi 配置文件、手机热点与 RNDIS 共享痕迹核查',
        status: 'WARN',
        evidenceSummary: msg,
      });
    } else {
      rows.push({
        clauseId: 'BMB22-HIS-NET',
        standardRef: 'BMB22-2007 5.2.1 历史违规外联溯源',
        controlTitle: '历史 Wi-Fi 配置文件、手机热点与 RNDIS 共享痕迹核查',
        status: 'PASS',
        evidenceSummary: `主机 ${netHis.scanned_host} 无线配置、RNDIS 及拨号历史记录核查洁净。`,
      });
    }
  }

  if (params.ole2Report) {
    const ole2 = params.ole2Report;
    const legalHits = ole2.ole2_hits.filter((h) => LEGAL_SECRECY_GRADES.has(h.secrecy_level));
    if (legalHits.length > 0 || ole2.slack_hits.length > 0) {
      const msg = `检出老旧 OLE2 涉密公文 ${legalHits.length} 份及磁盘扇区残片命中 ${ole2.slack_hits.length} 处`;
      vetoReasons.push(`[BMB20-OLE2 一票否决] ${msg}`);
      rows.push({
        clauseId: 'BMB20-OLE2-SLACK',
        standardRef: 'BMB20-2007 老旧公文与介质残片清查',
        controlTitle: 'OLE2 二进制流 (DOC/XLS/PPT) 与扇区残片涉密检索',
        status: 'VETO_FAIL',
        evidenceSummary: msg,
      });
    } else if (ole2.ole2_hits.length > 0) {
      const msg = `在 ${ole2.scanned_ole2_files} 份 OLE2 文件中检出 ${ole2.ole2_hits.length} 份受保护或内部关键词文件`;
      warningReasons.push(msg);
      rows.push({
        clauseId: 'BMB20-OLE2-SLACK',
        standardRef: 'BMB20-2007 老旧公文与介质残片清查',
        controlTitle: 'OLE2 二进制流 (DOC/XLS/PPT) 与扇区残片涉密检索',
        status: 'WARN',
        evidenceSummary: msg,
      });
    } else {
      rows.push({
        clauseId: 'BMB20-OLE2-SLACK',
        standardRef: 'BMB20-2007 老旧公文与介质残片清查',
        controlTitle: 'OLE2 二进制流 (DOC/XLS/PPT) 与扇区残片涉密检索',
        status: 'PASS',
        evidenceSummary: `已解构 ${ole2.scanned_ole2_files} 份 OLE2 文档并扫描 ${ole2.slack_scanned_bytes} Bytes 扇区空间，未检出涉密残片。`,
      });
    }
  }

  if (params.osUsageReport) {
    const os = params.osUsageReport;
    const uDiskSecrecyLnks = os.recent_files.filter(
      (item) => item.is_removable_media_target && item.is_secrecy_named,
    );
    const suspiciousPrints = os.print_spooler_jobs.filter((job) => job.is_secrecy_suspicious);
    if (uDiskSecrecyLnks.length > 0 || suspiciousPrints.length > 0) {
      const msg = `检出可移动介质直接访问涉密文件名快捷方式 ${uDiskSecrecyLnks.length} 项，假脱机涉密打印作业 ${suspiciousPrints.length} 项`;
      vetoReasons.push(`[BMB20-TRACE 一票否决] ${msg}`);
      rows.push({
        clauseId: 'BMB20-OS-LNK',
        standardRef: 'BMB20-2007 终端操作与打印留痕审计',
        controlTitle: '快捷方式 (.lnk)、Spooler 打印留痕与开关机时间线核查',
        status: 'VETO_FAIL',
        evidenceSummary: msg,
      });
    } else if (os.suspicious_u_disk_file_count > 0 || os.secrecy_named_access_count > 0) {
      const msg = `检出可移动介质打开记录 ${os.suspicious_u_disk_file_count} 条及敏感命名访问 ${os.secrecy_named_access_count} 条，请核查业务合规性`;
      warningReasons.push(msg);
      rows.push({
        clauseId: 'BMB20-OS-LNK',
        standardRef: 'BMB20-2007 终端操作与打印留痕审计',
        controlTitle: '快捷方式 (.lnk)、Spooler 打印留痕与开关机时间线核查',
        status: 'WARN',
        evidenceSummary: msg,
      });
    } else {
      rows.push({
        clauseId: 'BMB20-OS-LNK',
        standardRef: 'BMB20-2007 终端操作与打印留痕审计',
        controlTitle: '快捷方式 (.lnk)、Spooler 打印留痕与开关机时间线核查',
        status: 'PASS',
        evidenceSummary: `解析 ${os.total_lnk_parsed} 条最近访问及 ${os.print_spooler_jobs.length} 条打印脱机记录，未发现跨介质涉密打开或违规打印。`,
      });
    }
  }

  if (params.appTraceReport) {
    const app = params.appTraceReport;
    if (app.suspicious_downloads.length > 0 || app.chat_file_hits.length > 0) {
      const msg = `检出浏览器涉密下载记录 ${app.suspicious_downloads.length} 条及即时通信传输命中 ${app.chat_file_hits.length} 份涉密命名文件`;
      vetoReasons.push(`[BMB17-APP 一票否决] ${msg}`);
      rows.push({
        clauseId: 'BMB17-APP-TRACE',
        standardRef: 'BMB17-2006 应用层防泄密通信审计',
        controlTitle: '浏览器历史下载数据库与即时通信软件外发轨迹核查',
        status: 'VETO_FAIL',
        evidenceSummary: msg,
      });
    } else {
      rows.push({
        clauseId: 'BMB17-APP-TRACE',
        standardRef: 'BMB17-2006 应用层防泄密通信审计',
        controlTitle: '浏览器历史下载数据库与即时通信软件外发轨迹核查',
        status: 'PASS',
        evidenceSummary: `核验 ${app.total_downloads_checked} 条浏览器下载记录及 ${app.chat_files_checked} 份即时通信缓存文件，未发现涉密外发命中。`,
      });
    }
  }

  return rows;
}

/**
 * 评估国家保密局 BMB17-2006 / BMB20-2007 / BMB22-2007 合规总结论与控制矩阵
 *
 * 时间复杂度: O(U + H + I + A + N + E + O + T)
 * 空间复杂度: O(1) 辅助判断空间 + O(C) 控制表输出 (C 为控制条款数)
 */
export function evaluateSecrecyBmbVerdict(params: SecrecyReportParams): SecrecyFormalReportVerdict {
  const vetoReasons: string[] = [];
  const warningReasons: string[] = [];

  // 1. BMB22-2007 5.2.2 移动存储介质接入痕迹检查
  let usbStatus: SecrecyBmbControlRow['status'] = 'NOT_EXECUTED';
  let usbEvidence = '本次检查尚未执行本地 USB 历史痕迹提取。';
  if (params.usbReport) {
    if (params.usbReport.has_critical_violation || params.usbReport.unauthorized_device_count > 0) {
      usbStatus = 'VETO_FAIL';
      const msg = `检出 ${params.usbReport.unauthorized_device_count} 个未列入涉密授权白名单的历史接入 USB 介质（共扫描 ${params.usbReport.total_devices_found} 个设备记录）`;
      usbEvidence = msg;
      vetoReasons.push(`[BMB22-5.2.2 一票否决] ${msg}`);
    } else {
      usbStatus = 'PASS';
      usbEvidence = `主机 ${params.usbReport.scanned_host} 历史接入 ${params.usbReport.total_devices_found} 个 USB 设备全部符合白名单或无非授权记录。`;
    }
  } else {
    warningReasons.push('USB 历史接入痕迹核查尚未执行，介质交叉风险处于未核验状态');
  }

  // 2. BMB22-2007 5.2.1 双网卡“一机两用”与违规外联检查
  let dualStatus: SecrecyBmbControlRow['status'] = 'NOT_EXECUTED';
  let dualEvidence = '本次检查尚未执行宿主机网卡与核心路由表排查。';
  if (params.dualHomedReport) {
    if (
      params.dualHomedReport.is_dual_homed_violation ||
      params.dualHomedReport.has_simultaneous_wired_and_wireless ||
      params.dualHomedReport.has_public_and_private_bridging
    ) {
      dualStatus = 'VETO_FAIL';
      dualEvidence = params.dualHomedReport.reason;
      vetoReasons.push(`[BMB22-5.2.1 一票否决] 触发一机两用违规外联风险：${params.dualHomedReport.reason}`);
    } else if (params.dualHomedReport.risk_level === 'HIGH') {
      dualStatus = 'WARN';
      dualEvidence = params.dualHomedReport.reason;
      warningReasons.push(`网络边界预警：${params.dualHomedReport.reason}`);
    } else {
      dualStatus = 'PASS';
      dualEvidence = `${params.dualHomedReport.reason}（活动物理接口 ${params.dualHomedReport.active_nic_count} 个）`;
    }
  } else {
    warningReasons.push('宿主机“一机两用”双网路由冲突核查尚未执行');
  }

  // 3. BMB20-2007 / GB/T 9704 复合公文及压缩归档标密穿透检出
  let docStatus: SecrecyBmbControlRow['status'] = 'NOT_EXECUTED';
  let docEvidence = '本次检查尚未执行指定目录复合文档（DOCX/OFD/PDF/ZIP）穿透检索。';
  if (params.dissectReport) {
    const statHits = params.dissectReport.hits.filter(
      (h) => h.secrecy_level !== 'ENCRYPTED_FILE' && h.secrecy_level !== 'ZIP_BOMB_BLOCKED',
    );
    const encOrBombCount = params.dissectReport.encrypted_or_blocked_count;

    if (statHits.length > 0) {
      docStatus = 'VETO_FAIL';
      const msg = `在目录 "${params.dissectReport.target_folder}" 解构 ${params.dissectReport.scanned_files_count} 个文件时，穿透检出 ${statHits.length} 份含国家秘密标志或涉密字号文件（绝密 ${params.dissectReport.top_secret_count} / 机密 ${params.dissectReport.confidential_count} / 秘密 ${params.dissectReport.secret_count}）`;
      docEvidence = msg;
      vetoReasons.push(`[BMB20 一票否决] ${msg}`);
    } else if (encOrBombCount > 0) {
      docStatus = 'WARN';
      docEvidence = `目录 "${params.dissectReport.target_folder}" 共扫描 ${params.dissectReport.scanned_files_count} 份文件，未命中明文涉密字号，但发现 ${encOrBombCount} 份受口令加密保护或压缩异常文档，需人工解码复核。`;
      warningReasons.push(`存在 ${encOrBombCount} 份加密/阻塞文档待现场拆解复核`);
    } else {
      docStatus = 'PASS';
      docEvidence = `目录 "${params.dissectReport.target_folder}" 共深度穿透扫描 ${params.dissectReport.scanned_files_count} 份文件（耗时 ${params.dissectReport.duration_ms} ms），未检出违规存放涉密文档。`;
    }
  } else {
    warningReasons.push('本地复合文档涉密标密穿透检查尚未执行');
  }

  // 4. BMB17-2006 / 网流审计：涉密信息明文跨网泄露阻断
  const severeNetAlerts = params.networkAlerts.filter(
    (a) =>
      a.level === 'TOP_SECRET' ||
      a.level === 'CONFIDENTIAL' ||
      a.level === 'SECRET' ||
      a.level === 'COMMERCIAL_SECRET',
  );
  let netFlowStatus: SecrecyBmbControlRow['status'] = 'PASS';
  let netFlowEvidence = '网络嗅探总线及即席文本分析均未捕获明文涉密公文或红头字号传输。';
  if (severeNetAlerts.length > 0) {
    netFlowStatus = 'VETO_FAIL';
    const msg = `探针在实时通信流或即席公文送检中捕获 ${severeNetAlerts.length} 次高密级标识明文泄露事件`;
    netFlowEvidence = msg;
    vetoReasons.push(`[BMB17-传输保密 一票否决] ${msg}`);
  }

  const bmbMatrix: SecrecyBmbControlRow[] = [
    {
      clauseId: 'BMB22-5.2.2',
      standardRef: 'BMB22-2007 第5.2.2节 / GB/T 29360',
      controlTitle: '涉密终端存储介质注册表 (USBSTOR) 与跨区交叉使用核查',
      status: usbStatus,
      evidenceSummary: usbEvidence,
    },
    {
      clauseId: 'BMB22-5.2.1',
      standardRef: 'BMB22-2007 第5.2.1节',
      controlTitle: '“一机两用”有线/无线双联接入与公私网交叉路由禁止',
      status: dualStatus,
      evidenceSummary: dualEvidence,
    },
    {
      clauseId: 'BMB20-DOC',
      standardRef: 'BMB20-2007 / GB/T 9704-2012 / GB/T 33190',
      controlTitle: '复合公文 (DOCX/OFD/PDF/ZIP) 违规存放国家秘密标识穿透检索',
      status: docStatus,
      evidenceSummary: docEvidence,
    },
    {
      clauseId: 'BMB17-FLOW',
      standardRef: 'BMB17-2006 网络传输保密防护规范',
      controlTitle: '网络通信平面涉密关键字与发文字号明文传输实时监测',
      status: netFlowStatus,
      evidenceSummary: netFlowEvidence,
    },
    ...evaluateDeepForensicsControls(params, vetoReasons, warningReasons),
  ];

  const isVetoed = vetoReasons.length > 0;
  let code: SecrecyVerdictCode = 'QUALIFIED';
  let label: SecrecyFormalReportVerdict['label'] = '【合格】';
  let summaryText =
    '受检信息系统或终端各项现场物理取证与穿透检测结果均符合 BMB17/BMB20/BMB22 保密标准基线，未发现一机两用外联、非授权 USB 介质交叉及违规涉密标密文件留存。';

  if (isVetoed) {
    code = 'DISQUALIFIED_VETOED';
    label = '【不合格 (触发一票否决)】';
    summaryText = `根据国家保密局涉密信息系统分级保护一票否决裁决规约，受检对象命中 ${vetoReasons.length} 项严重违反保密规定红线，判定为不合格，须立即断开物理网络连接并启动违规溯源处置。`;
  } else if (warningReasons.length > 0) {
    code = 'CONDITIONALLY_QUALIFIED';
    label = '【基本合格】';
    summaryText = `受检对象暂未检出一票否决级别泄密违规，但存在 ${warningReasons.length} 项未完成核查或预警事项，请补充取证与人工复核后归档确认。`;
  }

  return {
    code,
    label,
    isVetoed,
    vetoReasons,
    warningReasons,
    bmbMatrix,
    summaryText,
  };
}

/**
 * 构建确定性规范化电子物证 JSON 载荷并计算 SM3 + SHA-256 双密码学摘要
 *
 * 时间复杂度: O(L)，L 为规范化后文本字节长度
 * 空间复杂度: O(L)
 */
export function buildCanonicalSecrecyDigest(
  params: SecrecyReportParams,
  verdict: SecrecyFormalReportVerdict,
): SecrecyCanonicalDigest {
  const canonicalPayload = JSON.stringify({
    schema: 'OMNI-PROBE-BMB-REPORT-V1',
    unit: params.targetUnitName.trim(),
    system: params.systemName.trim(),
    classification: params.systemClassification,
    inspector: params.inspectorName.trim(),
    inspectionTime: params.inspectionTimeIso,
    verdictCode: verdict.code,
    vetoReasons: verdict.vetoReasons,
    usbDevices: (params.usbReport?.devices ?? [])
      .map((d) => `${d.device_id}|${d.serial_number}|${d.violation_level}|${d.last_arrival_time}`)
      .sort(),
    docHits: (params.dissectReport?.hits ?? [])
      .map((h) => `${h.file_path}|${h.sha256_hash}|${h.sm3_hash}|${h.secrecy_level}`)
      .sort(),
    networkInterfaces: (params.dualHomedReport?.interfaces ?? [])
      .map((nic) => `${nic.name}|${nic.if_type}|${nic.is_up}|${nic.ip_addresses.join(',')}|${nic.gateway_addresses.join(',')}`)
      .sort(),
    networkAlerts: params.networkAlerts
      .map((a) => `${a.timestamp}|${a.source}->${a.destination}|${a.level}|${a.matchedKeywords.join(',')}`)
      .sort(),
    historicNetwork: params.networkHistoryReport
      ? {
          wifiHotspots: params.networkHistoryReport.suspicious_mobile_hotspots
            .map((w) => `${w.profile_name}|${w.ssid}|${w.last_modified_time}`)
            .sort(),
          rndis: [...params.networkHistoryReport.historic_rndis_devices].sort(),
          dialup: [...params.networkHistoryReport.historic_dialup_connections].sort(),
        }
      : null,
    ole2AndSlack: params.ole2Report
      ? {
          ole2Hits: params.ole2Report.ole2_hits
            .map((h) => `${h.file_path}|${h.sub_stream_name}|${h.sm3_hash}|${h.secrecy_level}`)
            .sort(),
          slackHits: params.ole2Report.slack_hits
            .map((s) => `${s.drive_letter}|${s.sector_offset}|${s.matched_marker}`)
            .sort(),
        }
      : null,
    osUsage: params.osUsageReport
      ? {
          uDiskCount: params.osUsageReport.suspicious_u_disk_file_count,
          secrecyNamedCount: params.osUsageReport.secrecy_named_access_count,
          spoolerSuspects: params.osUsageReport.print_spooler_jobs
            .filter((j) => j.is_secrecy_suspicious)
            .map((j) => `${j.job_id}|${j.document_name}|${j.submit_time}`)
            .sort(),
        }
      : null,
    appTraces: params.appTraceReport
      ? {
          downloads: params.appTraceReport.suspicious_downloads
            .map((d) => `${d.browser_type}|${d.target_file_path}|${d.original_url}`)
            .sort(),
          chatHits: params.appTraceReport.chat_file_hits
            .map((c) => `${c.app_name}|${c.file_path}|${c.file_size}`)
            .sort(),
        }
      : null,
  });

  const sm3Hex = computeSm3Hex(canonicalPayload);
  const sha256Hex = computeSha256Hex(canonicalPayload);
  const yearMatch = /^(\d{4})/.exec(params.inspectionTimeIso);
  const yearStr = yearMatch ? yearMatch[1] : String(new Date().getFullYear());
  const reportId = `BMJC-${yearStr}-${sm3Hex.slice(0, 8).toUpperCase()}`;

  return {
    sm3Hex,
    sha256Hex,
    canonicalByteLength: new TextEncoder().encode(canonicalPayload).length,
    reportId,
  };
}

function renderStatusText(status: SecrecyBmbControlRow['status']): string {
  switch (status) {
    case 'PASS':
      return '合规通过';
    case 'WARN':
      return '预警复核';
    case 'VETO_FAIL':
      return '严重违规 (一票否决)';
    case 'NOT_EXECUTED':
      return '未执行核验';
  }
}

function renderSecrecyLevelLabel(level: string): string {
  switch (level) {
    case 'TOP_SECRET':
      return '绝密级特征';
    case 'CONFIDENTIAL':
      return '机密级特征';
    case 'SECRET':
      return '秘密级特征';
    case 'COMMERCIAL_SECRET':
      return '商业秘密/内部';
    case 'ENCRYPTED_FILE':
      return '加密受保护文档';
    case 'ZIP_BOMB_BLOCKED':
      return '压缩异常熔断';
    default:
      return level;
  }
}

function appendDeepForensicsMarkdown(lines: string[], params: SecrecyReportParams): void {
  lines.push('## 六、深度历史外联、OLE2 残片、系统轨迹及应用外发取证明细', '');

  lines.push('### 6.1 历史外联与手机共享网络取证', '');
  if (!params.networkHistoryReport) {
    lines.push('> 本次勘验未执行历史 Wi-Fi 配置、USB RNDIS 共享及拨号外联痕迹检索。', '');
  } else {
    const r = params.networkHistoryReport;
    lines.push(`- **历史外联综合结论**: ${r.summary_conclusion}`);
    lines.push(
      `- **统计摘要**: Wi-Fi 历史配置 ${r.total_wifi_profiles_found} 项 · 可疑移动热点 ${r.suspicious_mobile_hotspots.length} 项 · RNDIS 共享设备 ${r.historic_rndis_devices.length} 台 · 拨号/VPN 配置 ${r.historic_dialup_connections.length} 项`,
    );
    if (r.suspicious_mobile_hotspots.length > 0) {
      lines.push('', '| 配置文件名 | SSID | 认证/加密 | 末次修改时间 |');
      lines.push('| :--- | :--- | :--- | :--- |');
      for (const w of r.suspicious_mobile_hotspots) {
        lines.push(`| ${w.profile_name} | \`${w.ssid}\` | ${w.auth_type} / ${w.cipher} | ${w.last_modified_time} |`);
      }
    }
    if (r.historic_rndis_devices.length > 0) {
      lines.push('', `- **RNDIS / 手机 USB 共享网卡实例**: ${r.historic_rndis_devices.join('；')}`);
    }
    lines.push('');
  }

  lines.push('### 6.2 老旧 OLE2 复合文档及空闲扇区残片扫描', '');
  if (!params.ole2Report) {
    lines.push('> 本次勘验未执行老旧二进制 OLE2 (DOC/XLS/PPT) 解构与扇区残片检索。', '');
  } else {
    const r = params.ole2Report;
    lines.push(
      `- **扫描统计**: 已解构 OLE2 文档 ${r.scanned_ole2_files} 份（命中 ${r.ole2_hits.length} 份），检索扇区 ${r.slack_scanned_bytes} Bytes（残片命中 ${r.slack_hits.length} 处）`,
    );
    if (r.ole2_hits.length > 0) {
      lines.push('', '| 文件路径 | 内部子流 | 密级判定 | 命中标识 | SM3 摘要 (前16位) |');
      lines.push('| :--- | :--- | :--- | :--- | :--- |');
      for (const h of r.ole2_hits) {
        lines.push(
          `| \`${h.file_path}\` | \`${h.sub_stream_name}\` | ${renderSecrecyLevelLabel(h.secrecy_level)} | ${[...h.matched_markers, ...h.document_signatures].join('、') || '-'} | \`${h.sm3_hash.slice(0, 16)}...\` |`,
        );
      }
    }
    if (r.slack_hits.length > 0) {
      lines.push('', '| 目标卷/设备 | 物理字节偏移 | 命中标志词 | 脱敏残片 |');
      lines.push('| :--- | :--- | :--- | :--- |');
      for (const s of r.slack_hits) {
        lines.push(`| \`${s.drive_letter}\` | 0x${s.sector_offset.toString(16).toUpperCase()} | ${s.matched_marker} | ${s.snippet_preview} |`);
      }
    }
    lines.push('');
  }

  lines.push('### 6.3 操作系统最近访问 (.lnk)、打印假脱机 (.SHD) 与开关机时间线', '');
  if (!params.osUsageReport) {
    lines.push('> 本次勘验未执行快捷方式、Spooler 打印影子及系统开关机时间线审计。', '');
  } else {
    const r = params.osUsageReport;
    lines.push(
      `- **统计摘要**: 解析快捷方式 ${r.total_lnk_parsed} 条（可移动介质目标 ${r.suspicious_u_disk_file_count} 条，涉密命名 ${r.secrecy_named_access_count} 条） · Spooler 打印作业 ${r.print_spooler_jobs.length} 条 · 开关机记录 ${r.system_boot_history.length} 条`,
    );
    const flaggedLnk = r.recent_files.filter((f) => f.is_removable_media_target || f.is_secrecy_named);
    if (flaggedLnk.length > 0) {
      lines.push('', '| 快捷方式名 | 真实指向路径 | 驱动类型 | 可移动介质 | 涉密命名 |');
      lines.push('| :--- | :--- | :--- | :--- | :--- |');
      for (const f of flaggedLnk.slice(0, 40)) {
        lines.push(
          `| ${f.shortcut_name} | \`${f.target_real_path}\` | ${f.drive_type} | ${f.is_removable_media_target ? '是' : '否'} | ${f.is_secrecy_named ? '是' : '否'} |`,
        );
      }
    }
    if (r.print_spooler_jobs.length > 0) {
      lines.push('', '| 打印文档名 | 打印机 | 提交时间 | 脱机文件名 | 涉密嫌疑 |');
      lines.push('| :--- | :--- | :--- | :--- | :--- |');
      for (const j of r.print_spooler_jobs.slice(0, 40)) {
        lines.push(
          `| ${j.document_name} | ${j.printer_name} | ${j.submit_time} | \`${j.spool_file_path}\` | ${j.is_secrecy_suspicious ? '可疑涉密' : '常规'} |`,
        );
      }
    }
    lines.push('');
  }

  lines.push('### 6.4 浏览器下载记录与办公即时通信外发痕迹', '');
  if (!params.appTraceReport) {
    lines.push('> 本次勘验未执行浏览器 SQLite 历史下载库与即时通信外发传输目录审计。', '');
  } else {
    const r = params.appTraceReport;
    lines.push(
      `- **统计摘要**: 核验浏览器下载 ${r.total_downloads_checked} 条（涉密命中 ${r.suspicious_downloads.length} 条） · 扫描即时通信传输文件 ${r.chat_files_checked} 份（涉密命中 ${r.chat_file_hits.length} 份）`,
    );
    if (r.suspicious_downloads.length > 0) {
      lines.push('', '| 浏览器 | 目标本地路径 | 来源 URL | 下载时间 | 命中标识 |');
      lines.push('| :--- | :--- | :--- | :--- | :--- |');
      for (const d of r.suspicious_downloads) {
        lines.push(
          `| ${d.browser_type} | \`${d.target_file_path}\` | \`${d.original_url}\` | ${d.download_time} | ${d.matched_marker || '-'} |`,
        );
      }
    }
    if (r.chat_file_hits.length > 0) {
      lines.push('', '| 通信软件 | 文件名 | 物理路径 | 大小 (Bytes) | 命中标识 |');
      lines.push('| :--- | :--- | :--- | :--- | :--- |');
      for (const c of r.chat_file_hits) {
        lines.push(
          `| ${c.app_name} | ${c.file_name} | \`${c.file_path}\` | ${c.file_size} | ${c.hit_secrecy_marker || '-'} |`,
        );
      }
    }
    lines.push('');
  }
}

/**
 * 导出保密现场勘验标准 Markdown 报告
 *
 * 时间复杂度: O(U + H + I + A + L + N + E + O + T)
 * 空间复杂度: O(L)
 */
export function generateSecrecyFormalReportMarkdown(params: SecrecyReportParams): string {
  const verdict = evaluateSecrecyBmbVerdict(params);
  const digest = buildCanonicalSecrecyDigest(params, verdict);

  const lines: string[] = [
    '# 涉及国家秘密信息系统保密安全现场勘验技术报告',
    '',
    `- **报告编号**: ${digest.reportId}`,
    `- **被检查单位**: ${params.targetUnitName || '未指定受检单位'}`,
    `- **被检信息系统**: ${params.systemName || '未指定系统'}`,
    `- **涉密等级定位**: ${params.systemClassification}`,
    `- **保密检查负责人**: ${params.inspectorName || '保密现场检查员'}`,
    `- **现场勘验日期**: ${params.inspectionTimeIso}`,
    `- **电子物证 SM3 摘要**: \`${digest.sm3Hex}\``,
    `- **电子物证 SHA-256 摘要**: \`${digest.sha256Hex}\``,
    '',
    '## 一、保密勘验法定结论与裁决依据',
    '',
    `**综合评定结论**：${verdict.label}`,
    '',
    `**依据标准**：BMB17-2006 / BMB20-2007 / BMB22-2007 / GB/T 9704-2012`,
    '',
    `**结论说明**：${verdict.summaryText}`,
    '',
  ];

  if (verdict.vetoReasons.length > 0) {
    lines.push('### 触发一票否决高危违规清单');
    for (const r of verdict.vetoReasons) {
      lines.push(`- ${r}`);
    }
    lines.push('');
  }

  lines.push('## 二、BMB 分级保护核心核查控制矩阵', '');
  lines.push('| 控制项编码 | 引用国标/保密标准 | 核心核查要求 | 判定结果 | 现场物理证据链摘要 |');
  lines.push('| :--- | :--- | :--- | :--- | :--- |');
  for (const row of verdict.bmbMatrix) {
    lines.push(
      `| ${row.clauseId} | ${row.standardRef} | ${row.controlTitle} | ${renderStatusText(row.status)} | ${row.evidenceSummary} |`,
    );
  }
  lines.push('');

  lines.push('## 三、涉密移动存储介质 (USB) 物理痕迹核查大表', '');
  if (!params.usbReport) {
    lines.push('> 本次勘验未执行 USB 注册表与 setupapi.dev.log 历史取证。', '');
  } else if (params.usbReport.devices.length === 0) {
    lines.push(`> 主机 \`${params.usbReport.scanned_host}\` 未发现任何 USB 存储介质接入历史。`, '');
  } else {
    lines.push('| 设备硬件名称 | 厂商 VID / 产品 PID | 硬件序列号 (Serial) | 分配盘符 | 首次接入 / 末次接入 | 合规判定 |');
    lines.push('| :--- | :--- | :--- | :--- | :--- | :--- |');
    for (const dev of params.usbReport.devices) {
      lines.push(
        `| ${dev.device_name} | ${dev.vendor_id} / ${dev.product_id} | \`${dev.serial_number}\` | ${dev.assigned_drive_letter} | ${dev.first_installed_time} / ${dev.last_arrival_time} | ${dev.is_whitelisted ? '授权涉密介质' : '非授权违规介质'} |`,
      );
    }
    lines.push('');
  }

  lines.push('## 四、涉密公文与标密文件穿透式核验清单', '');
  if (!params.dissectReport) {
    lines.push('> 本次勘验未执行本地复合文档（DOCX/OFD/PDF/ZIP）物理二进制穿透扫描。', '');
  } else if (params.dissectReport.hits.length === 0) {
    lines.push(
      `> 已穿透扫描目录 \`${params.dissectReport.target_folder}\` 共 ${params.dissectReport.scanned_files_count} 个文件，未检出涉密标志文档。`,
      '',
    );
  } else {
    lines.push('| 文件路径 (含嵌套路径) | 文件类型 | 标密判级 | 命中标识/发文字号 | SM3 摘要 (前16位) | 脱敏摘要 |');
    lines.push('| :--- | :--- | :--- | :--- | :--- | :--- |');
    for (const hit of params.dissectReport.hits) {
      const pathDisplay = hit.nested_path ? `${hit.file_path} -> [${hit.nested_path}]` : hit.file_path;
      const markers = [...hit.matched_markers, ...hit.document_signatures].join('; ');
      lines.push(
        `| \`${pathDisplay}\` | ${hit.file_type} | ${renderSecrecyLevelLabel(hit.secrecy_level)} | ${markers} | \`${hit.sm3_hash.slice(0, 16)}...\` | ${hit.snippet_preview} |`,
      );
    }
    lines.push('');
  }

  lines.push('## 五、网络违规外联与一机两用排查实测证据表', '');
  if (!params.dualHomedReport) {
    lines.push('> 本次勘验未执行“一机两用”网卡与路由表核查。', '');
  } else {
    lines.push(`- **一机两用综合判定**: ${params.dualHomedReport.is_dual_homed_violation ? '存在严重一机两用双联违规' : '未触发双联违规'} (${params.dualHomedReport.risk_level})`);
    lines.push(`- **核心判定理由**: ${params.dualHomedReport.reason}`);
    if (params.dualHomedReport.wireless_ssid) {
      lines.push(`- **关联无线热点 SSID**: \`${params.dualHomedReport.wireless_ssid}\``);
    }
    lines.push('');
    if (params.dualHomedReport.interfaces.length > 0) {
      lines.push('| 接口名称 | 接口类型 | 运行状态 | IPv4 地址 | 默认网关 | 私网/公网属性 |');
      lines.push('| :--- | :--- | :--- | :--- | :--- | :--- |');
      for (const nic of params.dualHomedReport.interfaces) {
        const netAttr = nic.is_connected_to_public
          ? '公网暴露'
          : nic.is_connected_to_private
            ? '内部私网'
            : '未知网段';
        lines.push(
          `| ${nic.name} | ${nic.if_type} | ${nic.is_up ? 'UP (已连接)' : 'DOWN'} | ${nic.ip_addresses.join(', ') || '-'} | ${nic.gateway_addresses.join(', ') || '-'} | ${netAttr} |`,
        );
      }
      lines.push('');
    }
  }

  if (params.networkAlerts.length > 0) {
    lines.push('### 网络通信平面 / 即席公文涉密告警明细', '');
    for (const alert of params.networkAlerts) {
      lines.push(
        `- [${new Date(alert.timestamp).toLocaleString('zh-CN')}] ${alert.source} -> ${alert.destination} | ${renderSecrecyLevelLabel(alert.level)} | 命中: ${[...alert.matchedKeywords, ...alert.documentSignatures].join('、')}`,
      );
    }
    lines.push('');
  }

  appendDeepForensicsMarkdown(lines, params);

  lines.push('## 七、四方责任主体现场签章确认', '');
  lines.push('- 保密检查组组长（签字）：______________________  日期：____年__月__日');
  lines.push('- 被检查单位保密总监/归口负责人（签字 + 公章）：______________________  日期：____年__月__日');
  lines.push('- 被检信息系统安全保密管理员（签字）：______________________  日期：____年__月__日');
  lines.push('- 涉密资产责任人/终端使用人（签字）：______________________  日期：____年__月__日');
  lines.push('');

  return lines.join('\n');
}

/**
 * 导出符合国家保密局版式规约的 A4 Portrait 自包含矢量打印 HTML 报告
 * 严格对全部用户输入与系统采集字段实施 escapeHtml 实体转义防御 XSS
 *
 * 时间复杂度: O(U + H + I + A + L)
 * 空间复杂度: O(L)
 */
function buildDeepForensicsHtmlSection(params: SecrecyReportParams): string {
  const parts: string[] = [];

  if (!params.networkHistoryReport) {
    parts.push('<p class="empty-note">6.1 本次勘验未执行历史 Wi-Fi 配置、USB RNDIS 共享及拨号外联痕迹检索。</p>');
  } else {
    const r = params.networkHistoryReport;
    const hotspotRows = r.suspicious_mobile_hotspots
      .map(
        (w) => `
          <tr>
            <td><b>${escapeHtml(w.profile_name)}</b></td>
            <td class="sub-mono">${escapeHtml(w.ssid)}</td>
            <td style="text-align: center;">${escapeHtml(w.auth_type)} / ${escapeHtml(w.cipher)}</td>
            <td class="sub-mono">${escapeHtml(w.last_modified_time)}</td>
          </tr>`,
      )
      .join('');
    parts.push(`
      <p class="meta-inline"><b>6.1 历史外联与手机共享网络取证：</b>${escapeHtml(r.summary_conclusion)}（Wi-Fi 配置 ${r.total_wifi_profiles_found} 项，可疑热点 ${r.suspicious_mobile_hotspots.length} 项，RNDIS 设备 ${r.historic_rndis_devices.length} 台，拨号配置 ${r.historic_dialup_connections.length} 项）</p>
      ${
        r.suspicious_mobile_hotspots.length > 0
          ? `<table><thead><tr><th>配置文件名</th><th>SSID</th><th style="text-align:center;">认证/加密</th><th>末次记录时间</th></tr></thead><tbody>${hotspotRows}</tbody></table>`
          : ''
      }
      ${
        r.historic_rndis_devices.length > 0
          ? `<div class="info-box" style="border-left: 4px solid #dc2626;"><b>检出 RNDIS / USB 网络共享设备：</b>${escapeHtml(r.historic_rndis_devices.join('；'))}</div>`
          : ''
      }`);
  }

  if (!params.ole2Report) {
    parts.push('<p class="empty-note">6.2 本次勘验未执行老旧 OLE2 复合公文解构及空闲扇区残片检索。</p>');
  } else {
    const r = params.ole2Report;
    const oleRows = r.ole2_hits
      .map(
        (h) => `
          <tr>
            <td class="sub-mono">${escapeHtml(h.file_path)}</td>
            <td class="sub-mono">${escapeHtml(h.sub_stream_name)}</td>
            <td style="text-align: center;"><span class="tag tag-fail">${escapeHtml(renderSecrecyLevelLabel(h.secrecy_level))}</span></td>
            <td>${escapeHtml([...h.matched_markers, ...h.document_signatures].join('、') || '-')}</td>
            <td class="sub-mono">SM3: ${escapeHtml(h.sm3_hash.slice(0, 20))}...<br /><span class="snippet-txt">${escapeHtml(h.snippet_preview)}</span></td>
          </tr>`,
      )
      .join('');
    const slackRows = r.slack_hits
      .map(
        (s) => `
          <tr>
            <td class="sub-mono">${escapeHtml(s.drive_letter)}</td>
            <td class="sub-mono">0x${s.sector_offset.toString(16).toUpperCase()}</td>
            <td><b>${escapeHtml(s.matched_marker)}</b></td>
            <td class="snippet-txt">${escapeHtml(s.snippet_preview)}</td>
          </tr>`,
      )
      .join('');
    parts.push(`
      <p class="meta-inline"><b>6.2 老旧 OLE2 复合公文及扇区残片取证：</b>扫描目录 <code>${escapeHtml(r.target_folder)}</code> 共 <b>${r.scanned_ole2_files}</b> 份 OLE2 文件（命中 <b style="color:${r.ole2_hits.length > 0 ? '#dc2626' : '#059669'};">${r.ole2_hits.length}</b> 份），读取扇区 <b>${r.slack_scanned_bytes}</b> Bytes（残片命中 <b style="color:${r.slack_hits.length > 0 ? '#dc2626' : '#059669'};">${r.slack_hits.length}</b> 处）。</p>
      ${
        r.ole2_hits.length > 0
          ? `<table><thead><tr><th>文件路径</th><th>CFBF 内部子流</th><th style="text-align:center;">密级判定</th><th>命中字号/标志词</th><th>SM3 哈希与脱敏摘要</th></tr></thead><tbody>${oleRows}</tbody></table>`
          : ''
      }
      ${
        r.slack_hits.length > 0
          ? `<table><thead><tr><th>卷/目标文件</th><th>字节偏移</th><th>命中关键字</th><th>扇区残片脱敏片段</th></tr></thead><tbody>${slackRows}</tbody></table>`
          : ''
      }`);
  }

  if (!params.osUsageReport) {
    parts.push('<p class="empty-note">6.3 本次勘验未执行快捷方式 (.lnk)、Spooler 打印留痕与开关机时间线检索。</p>');
  } else {
    const r = params.osUsageReport;
    const flaggedLnk = r.recent_files.filter((f) => f.is_removable_media_target || f.is_secrecy_named);
    const lnkRows = flaggedLnk
      .slice(0, 40)
      .map(
        (f) => `
          <tr>
            <td>${escapeHtml(f.shortcut_name)}</td>
            <td class="sub-mono">${escapeHtml(f.target_real_path)}</td>
            <td style="text-align:center;">${escapeHtml(f.drive_type)}</td>
            <td style="text-align:center;">${f.is_removable_media_target ? '<span class="tag tag-warn">可移动介质</span>' : '本地'}</td>
            <td style="text-align:center;">${f.is_secrecy_named ? '<span class="tag tag-fail">涉密命名</span>' : '普通'}</td>
          </tr>`,
      )
      .join('');
    const spoolRows = r.print_spooler_jobs
      .slice(0, 40)
      .map(
        (j) => `
          <tr>
            <td><b>${escapeHtml(j.document_name)}</b></td>
            <td>${escapeHtml(j.printer_name)}</td>
            <td class="sub-mono">${escapeHtml(j.submit_time)}</td>
            <td class="sub-mono">${escapeHtml(j.spool_file_path)}</td>
            <td style="text-align:center;"><span class="tag ${j.is_secrecy_suspicious ? 'tag-fail' : 'tag-pass'}">${j.is_secrecy_suspicious ? '涉密嫌疑' : '常规'}</span></td>
          </tr>`,
      )
      .join('');
    parts.push(`
      <p class="meta-inline"><b>6.3 操作系统最近访问、打印脱机及开关机时间线：</b>已解析快捷方式 <b>${r.total_lnk_parsed}</b> 条（U 盘等可移动目标 ${r.suspicious_u_disk_file_count} 条，涉密命名 ${r.secrecy_named_access_count} 条），打印影子作业 <b>${r.print_spooler_jobs.length}</b> 条，开关机事件 <b>${r.system_boot_history.length}</b> 条。</p>
      ${
        flaggedLnk.length > 0
          ? `<table><thead><tr><th>快捷方式</th><th>真实目标路径</th><th style="text-align:center;">介质类型</th><th style="text-align:center;">可移动属性</th><th style="text-align:center;">命名标密属性</th></tr></thead><tbody>${lnkRows}</tbody></table>`
          : ''
      }
      ${
        r.print_spooler_jobs.length > 0
          ? `<table><thead><tr><th>打印任务文档名</th><th>打印机</th><th>提交时间</th><th>影子文件路径</th><th style="text-align:center;">合规判断</th></tr></thead><tbody>${spoolRows}</tbody></table>`
          : ''
      }`);
  }

  if (!params.appTraceReport) {
    parts.push('<p class="empty-note">6.4 本次勘验未执行浏览器历史下载库与即时通信外发轨迹审计。</p>');
  } else {
    const r = params.appTraceReport;
    const dlRows = r.suspicious_downloads
      .map(
        (d) => `
          <tr>
            <td style="text-align:center;"><b>${escapeHtml(d.browser_type)}</b></td>
            <td class="sub-mono">${escapeHtml(d.target_file_path)}</td>
            <td class="sub-mono">${escapeHtml(d.original_url)}</td>
            <td class="sub-mono">${escapeHtml(d.download_time)}</td>
            <td style="text-align:center;"><span class="tag tag-fail">${escapeHtml(d.matched_marker || '命中')}</span></td>
          </tr>`,
      )
      .join('');
    const chatRows = r.chat_file_hits
      .map(
        (c) => `
          <tr>
            <td style="text-align:center;"><b>${escapeHtml(c.app_name)}</b></td>
            <td>${escapeHtml(c.file_name)}</td>
            <td class="sub-mono">${escapeHtml(c.file_path)}</td>
            <td style="text-align:right;">${c.file_size}</td>
            <td style="text-align:center;"><span class="tag tag-fail">${escapeHtml(c.hit_secrecy_marker || '命中')}</span></td>
          </tr>`,
      )
      .join('');
    parts.push(`
      <p class="meta-inline"><b>6.4 浏览器下载与即时通信涉密外发轨迹审计：</b>核验浏览器下载记录 <b>${r.total_downloads_checked}</b> 条（可疑涉密 ${r.suspicious_downloads.length} 条），核验即时通信传输目录文件 <b>${r.chat_files_checked}</b> 份（涉密命中 ${r.chat_file_hits.length} 份）。</p>
      ${
        r.suspicious_downloads.length > 0
          ? `<table><thead><tr><th style="text-align:center;">浏览器</th><th>下载落盘路径</th><th>来源 URL</th><th>下载时间</th><th style="text-align:center;">命中关键字</th></tr></thead><tbody>${dlRows}</tbody></table>`
          : ''
      }
      ${
        r.chat_file_hits.length > 0
          ? `<table><thead><tr><th style="text-align:center;">应用</th><th>传输文件名</th><th>物理路径</th><th style="text-align:right;">字节大小</th><th style="text-align:center;">命中关键字</th></tr></thead><tbody>${chatRows}</tbody></table>`
          : ''
      }`);
  }

  return parts.join('\n');
}

export function generateSecrecyFormalReportHtml(params: SecrecyReportParams): string {
  const verdict = evaluateSecrecyBmbVerdict(params);
  const digest = buildCanonicalSecrecyDigest(params, verdict);

  const safeUnit = escapeHtml(params.targetUnitName || '未指定受检单位');
  const safeSystem = escapeHtml(params.systemName || '涉密办公信息系统终端');
  const safeClass = escapeHtml(params.systemClassification);
  const safeInspector = escapeHtml(params.inspectorName || '保密检查组现场操作员');
  const safeTime = escapeHtml(params.inspectionTimeIso);
  const safeReportId = escapeHtml(digest.reportId);

  const deepForensicsSectionHtml = buildDeepForensicsHtmlSection(params);

  const badgeColor =
    verdict.code === 'QUALIFIED'
      ? '#059669'
      : verdict.code === 'CONDITIONALLY_QUALIFIED'
        ? '#d97706'
        : '#dc2626';

  const statusTagHtml = (status: SecrecyBmbControlRow['status']): string => {
    const cls =
      status === 'PASS'
        ? 'tag-pass'
        : status === 'WARN'
          ? 'tag-warn'
          : status === 'VETO_FAIL'
            ? 'tag-fail'
            : 'tag-na';
    return `<span class="tag ${cls}">${escapeHtml(renderStatusText(status))}</span>`;
  };

  const usbSectionHtml = !params.usbReport
    ? '<p class="empty-note">本次现场勘验未执行注册表 USBSTOR 与系统安装日志历史提取。</p>'
    : params.usbReport.devices.length === 0
      ? `<p class="clean-note">经穿透读取受检终端 <code>${escapeHtml(params.usbReport.scanned_host)}</code> 注册表及安装审计日志，历史 USB 移动存储介质接入记录为 0 条。</p>`
      : `
        <p class="meta-inline">受检主机：<b>${escapeHtml(params.usbReport.scanned_host)}</b> · 提取时间：${escapeHtml(params.usbReport.scan_time)} · 共检出历史 USB 记录 <b>${params.usbReport.total_devices_found}</b> 条，其中非授权违规介质 <b style="color: ${params.usbReport.unauthorized_device_count > 0 ? '#dc2626' : '#059669'};">${params.usbReport.unauthorized_device_count}</b> 个。</p>
        <table>
          <thead>
            <tr>
              <th style="width: 24%;">设备名称与证据源</th>
              <th style="width: 14%;">VID / PID</th>
              <th style="width: 20%;">唯一序列号 (Serial)</th>
              <th style="width: 8%; text-align: center;">盘符</th>
              <th style="width: 20%;">首/末次接入物理时间</th>
              <th style="width: 14%; text-align: center;">合规状态</th>
            </tr>
          </thead>
          <tbody>
            ${params.usbReport.devices
              .map(
                (dev) => `
              <tr>
                <td><b>${escapeHtml(dev.device_name)}</b><br /><span class="sub-mono">${escapeHtml(dev.evidence_source)}</span></td>
                <td class="sub-mono">${escapeHtml(dev.vendor_id)} : ${escapeHtml(dev.product_id)}</td>
                <td class="sub-mono">${escapeHtml(dev.serial_number)}</td>
                <td style="text-align: center; font-weight: bold;">${escapeHtml(dev.assigned_drive_letter)}</td>
                <td class="sub-mono">首: ${escapeHtml(dev.first_installed_time)}<br />末: ${escapeHtml(dev.last_arrival_time)}</td>
                <td style="text-align: center;">
                  <span class="tag ${dev.is_whitelisted ? 'tag-pass' : 'tag-fail'}">${dev.is_whitelisted ? '授权白名单' : '非授权违规'}</span>
                </td>
              </tr>`,
              )
              .join('')}
          </tbody>
        </table>`;

  const docSectionHtml = !params.dissectReport
    ? '<p class="empty-note">本次现场勘验未执行指定目录复合公文及压缩包深度解构扫描。</p>'
    : params.dissectReport.hits.length === 0
      ? `<p class="clean-note">已对目标目录 <code>${escapeHtml(params.dissectReport.target_folder)}</code> 共 <b>${params.dissectReport.scanned_files_count}</b> 份复合/文本文件实施二进制流解构（耗时 ${params.dissectReport.duration_ms} ms），未检出含法定涉密标密词或红头字号的文档。</p>`
      : `
        <p class="meta-inline">扫描路径：<code>${escapeHtml(params.dissectReport.target_folder)}</code> · 共解构文件 <b>${params.dissectReport.scanned_files_count}</b> 份（耗时 ${params.dissectReport.duration_ms} ms） · 异常命中 <b style="color: #dc2626;">${params.dissectReport.hits.length}</b> 份。</p>
        <table>
          <thead>
            <tr>
              <th style="width: 28%;">物理文件路径 (含压缩嵌套层)</th>
              <th style="width: 10%; text-align: center;">文档类型</th>
              <th style="width: 12%; text-align: center;">标密判定</th>
              <th style="width: 22%;">命中关键词 / 公文发文字号</th>
              <th style="width: 28%;">SM3 哈希防伪与脱敏摘要</th>
            </tr>
          </thead>
          <tbody>
            ${params.dissectReport.hits
              .map((hit) => {
                const fullPath = hit.nested_path ? `${hit.file_path} -> [${hit.nested_path}]` : hit.file_path;
                const markers = [...hit.matched_markers, ...hit.document_signatures].join('、') || '-';
                const tagCls =
                  hit.secrecy_level === 'ENCRYPTED_FILE' || hit.secrecy_level === 'ZIP_BOMB_BLOCKED'
                    ? 'tag-warn'
                    : 'tag-fail';
                return `
              <tr>
                <td class="sub-mono">${escapeHtml(fullPath)}</td>
                <td style="text-align: center;">${escapeHtml(hit.file_type)}</td>
                <td style="text-align: center;"><span class="tag ${tagCls}">${escapeHtml(renderSecrecyLevelLabel(hit.secrecy_level))}</span></td>
                <td><b>${escapeHtml(markers)}</b></td>
                <td><span class="sub-mono">SM3: ${escapeHtml(hit.sm3_hash.slice(0, 20))}...</span><br /><span class="snippet-txt">${escapeHtml(hit.snippet_preview)}</span></td>
              </tr>`;
              })
              .join('')}
          </tbody>
        </table>`;

  const dualSectionHtml = !params.dualHomedReport
    ? '<p class="empty-note">本次现场勘验未执行“一机两用”网卡接口与内核路由表穿透排查。</p>'
    : `
      <div class="info-box" style="border-left: 4px solid ${params.dualHomedReport.is_dual_homed_violation ? '#dc2626' : params.dualHomedReport.risk_level === 'HIGH' ? '#d97706' : '#059669'};">
        <b>“一机两用”双网连通性核心裁决：</b>
        <span class="tag ${params.dualHomedReport.is_dual_homed_violation ? 'tag-fail' : params.dualHomedReport.risk_level === 'HIGH' ? 'tag-warn' : 'tag-pass'}">${escapeHtml(params.dualHomedReport.risk_level)}</span><br />
        <span>${escapeHtml(params.dualHomedReport.reason)}</span>
        ${params.dualHomedReport.wireless_ssid ? `<br /><b>已关联无线热点 (SSID)：</b><code>${escapeHtml(params.dualHomedReport.wireless_ssid)}</code>` : ''}
      </div>
      ${
        params.dualHomedReport.interfaces.length === 0
          ? '<p class="empty-note">未枚举到有效网卡接口。</p>'
          : `
        <table>
          <thead>
            <tr>
              <th style="width: 24%;">接口描述符</th>
              <th style="width: 14%; text-align: center;">物理链路类型</th>
              <th style="width: 10%; text-align: center;">激活状态</th>
              <th style="width: 20%;">配置 IPv4 地址</th>
              <th style="width: 18%;">关联默认网关</th>
              <th style="width: 14%; text-align: center;">网络边界归属</th>
            </tr>
          </thead>
          <tbody>
            ${params.dualHomedReport.interfaces
              .map(
                (nic) => `
              <tr>
                <td><b>${escapeHtml(nic.name)}</b></td>
                <td style="text-align: center;">${escapeHtml(nic.if_type)}</td>
                <td style="text-align: center;"><span class="tag ${nic.is_up ? 'tag-pass' : 'tag-na'}">${nic.is_up ? 'UP 已连接' : 'DOWN'}</span></td>
                <td class="sub-mono">${escapeHtml(nic.ip_addresses.join(', ') || '-')}</td>
                <td class="sub-mono">${escapeHtml(nic.gateway_addresses.join(', ') || '-')}</td>
                <td style="text-align: center;">${nic.is_connected_to_public ? '<b style="color:#dc2626;">公网外联路由</b>' : nic.is_connected_to_private ? '内部私网段' : '未编址'}</td>
              </tr>`,
              )
              .join('')}
          </tbody>
        </table>`
      }`;

  const alertsHtml =
    params.networkAlerts.length === 0
      ? '<p class="clean-note">网流深包解析与即席文本自检模块均未检出涉密通信特征记录。</p>'
      : `
        <table>
          <thead>
            <tr>
              <th style="width: 18%;">捕获时间</th>
              <th style="width: 22%;">通信源 / 目的端点</th>
              <th style="width: 14%; text-align: center;">密级标识</th>
              <th style="width: 20%;">命中文号 / 关键词</th>
              <th style="width: 26%;">载荷脱敏摘录</th>
            </tr>
          </thead>
          <tbody>
            ${params.networkAlerts
              .slice(0, 60)
              .map(
                (a) => `
              <tr>
                <td class="sub-mono">${escapeHtml(new Date(a.timestamp).toLocaleString('zh-CN'))}</td>
                <td class="sub-mono">${escapeHtml(a.source)} -> ${escapeHtml(a.destination)}</td>
                <td style="text-align: center;"><span class="tag tag-fail">${escapeHtml(renderSecrecyLevelLabel(a.level))}</span></td>
                <td><b>${escapeHtml([...a.matchedKeywords, ...a.documentSignatures].join('、') || '-')}</b></td>
                <td class="snippet-txt">${escapeHtml(a.snippet)}</td>
              </tr>`,
              )
              .join('')}
          </tbody>
        </table>`;

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <title>涉及国家秘密信息系统保密安全现场勘验技术报告 - ${safeReportId}</title>
  <style>
    @page {
      size: A4 portrait;
      margin: 18mm 15mm;
    }
    * {
      box-sizing: border-box;
      -webkit-print-color-adjust: exact !important;
      print-color-adjust: exact !important;
    }
    body {
      font-family: "SimSun", "FangSong", -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
      font-size: 10pt;
      line-height: 1.55;
      color: #111827;
      background: #ffffff;
      margin: 0;
      padding: 0;
    }
    .page-cover {
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      height: 252mm;
      padding: 18mm 12mm;
      text-align: center;
      page-break-after: always;
      border: 2px solid #991b1b;
    }
    .cover-header {
      font-size: 12pt;
      font-weight: 700;
      letter-spacing: 1.5px;
      color: #991b1b;
      border-bottom: 1.5px solid #991b1b;
      padding-bottom: 4mm;
    }
    .cover-title {
      margin-top: 28mm;
    }
    .cover-title h1 {
      font-size: 22pt;
      font-weight: 800;
      color: #111827;
      letter-spacing: 3px;
      line-height: 1.4;
      margin: 0;
    }
    .cover-title h2 {
      font-size: 14pt;
      font-weight: 600;
      color: #991b1b;
      margin-top: 6mm;
    }
    .cover-meta {
      margin: 0 auto;
      width: 84%;
      text-align: left;
      font-size: 10.5pt;
      line-height: 2.15;
      border-top: 1px solid #d1d5db;
      padding-top: 6mm;
    }
    .cover-meta-row {
      display: flex;
      justify-content: space-between;
      border-bottom: 1px dashed #d1d5db;
    }
    .cover-footer {
      font-size: 9.5pt;
      color: #4b5563;
      border-top: 1px solid #e5e7eb;
      padding-top: 3mm;
    }
    .section-title {
      font-size: 12.5pt;
      font-weight: 700;
      color: #111827;
      border-left: 4px solid #991b1b;
      padding-left: 3mm;
      margin: 7mm 0 3.5mm 0;
      page-break-after: avoid;
    }
    .verdict-box {
      border: 2px solid ${badgeColor};
      border-radius: 3px;
      padding: 4.5mm;
      margin-bottom: 5mm;
      background: #fefefe;
      page-break-inside: avoid;
    }
    .verdict-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 2.5mm;
    }
    .verdict-badge {
      display: inline-block;
      padding: 1.5mm 4.5mm;
      color: #ffffff;
      background: ${badgeColor};
      font-weight: 800;
      font-size: 12pt;
      border-radius: 3px;
    }
    .hash-badge {
      font-family: Consolas, Monaco, monospace;
      background: #f3f4f6;
      padding: 2mm;
      font-size: 8pt;
      border-radius: 2px;
      word-break: break-all;
      margin-top: 2.5mm;
      border: 1px solid #e5e7eb;
    }
    .signature-grid {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 4.5mm;
      margin-top: 4mm;
      page-break-inside: avoid;
    }
    .signature-box {
      border: 1px solid #9ca3af;
      border-radius: 2px;
      padding: 3.5mm;
      background: #fafafa;
      min-height: 24mm;
    }
    .info-box {
      background: #f9fafb;
      border: 1px solid #e5e7eb;
      padding: 3mm 4mm;
      margin-bottom: 3.5mm;
      font-size: 9pt;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-bottom: 5mm;
      font-size: 8.5pt;
      page-break-inside: auto;
    }
    tr {
      page-break-inside: avoid;
      page-break-after: auto;
    }
    th, td {
      border: 1px solid #d1d5db;
      padding: 1.8mm 2.2mm;
      text-align: left;
      vertical-align: top;
    }
    th {
      background: #f3f4f6;
      font-weight: 700;
      color: #1f2937;
    }
    .tag {
      display: inline-block;
      padding: 0.4mm 1.5mm;
      border-radius: 2px;
      font-weight: 700;
      font-size: 7.5pt;
    }
    .tag-pass { background: #d1fae5; color: #065f46; }
    .tag-warn { background: #fef3c7; color: #92400e; }
    .tag-fail { background: #fee2e2; color: #991b1b; }
    .tag-na { background: #f3f4f6; color: #6b7280; }
    .sub-mono {
      font-family: Consolas, "Liberation Mono", Menlo, monospace;
      font-size: 7.5pt;
      color: #374151;
      word-break: break-all;
    }
    .snippet-txt {
      font-size: 8pt;
      color: #4b5563;
      word-break: break-all;
    }
    .clean-note {
      color: #065f46;
      background: #ecfdf5;
      border: 1px solid #a7f3d0;
      padding: 2.5mm 3.5mm;
      font-size: 9pt;
      margin-bottom: 4mm;
    }
    .empty-note {
      color: #6b7280;
      background: #f9fafb;
      border: 1px dashed #d1d5db;
      padding: 2.5mm 3.5mm;
      font-size: 9pt;
      margin-bottom: 4mm;
    }
    .meta-inline {
      font-size: 9pt;
      color: #374151;
      margin-bottom: 2.5mm;
    }
    .page-break {
      page-break-after: always;
    }
  </style>
</head>
<body>

  <!-- 标准封皮页 -->
  <div class="page-cover">
    <div class="cover-header">
      中华人民共和国国家保密标准 (BMB17-2006 / BMB20-2007 / BMB22-2007)<br />
      涉密信息系统分级保护与终端口物理防泄密核验报告
    </div>

    <div class="cover-title">
      <h1>涉及国家秘密信息系统<br />保密安全现场勘验技术报告</h1>
      <h2>【涉密等级定位：${safeClass}】</h2>
    </div>

    <div class="cover-meta">
      <div class="cover-meta-row"><span>勘验报告法定编号:</span><b>${safeReportId}</b></div>
      <div class="cover-meta-row"><span>被检查单位名称:</span><b>${safeUnit}</b></div>
      <div class="cover-meta-row"><span>被检信息系统 / 终端:</span><b>${safeSystem}</b></div>
      <div class="cover-meta-row"><span>现场综合裁决结论:</span><b style="color: ${badgeColor};">${escapeHtml(verdict.label)}</b></div>
      <div class="cover-meta-row"><span>勘验核查工具链:</span><b>Omni-Probe BMB 涉密取证引擎</b></div>
      <div class="cover-meta-row"><span>保密检查负责人:</span><b>${safeInspector}</b></div>
      <div class="cover-meta-row"><span>现场取证固化时间:</span><b>${safeTime}</b></div>
    </div>

    <div class="cover-footer">
      依据标准：BMB17-2006 · BMB20-2007 · BMB22-2007 · GB/T 9704-2012 · GB/T 29360-2012<br />
      严禁擅自涂改电子勘验数据 · 报告正文受国密 SM3 与 SHA-256 双摘要锁保护
    </div>
  </div>

  <!-- 第一部分：保密勘验法定结论与电子物证保全 -->
  <div class="section-title">一、保密勘验法定结论与电子物证保全</div>
  <div class="verdict-box">
    <div class="verdict-header">
      <div>
        <div style="font-size: 11pt; font-weight: bold;">保密现场勘验综合裁决结论：</div>
        <div style="font-size: 8.5pt; color: #4b5563; margin-top: 0.8mm;">
          依据 BMB17-2006 / BMB20-2007 / BMB22-2007 涉密信息系统一票否决裁决规则生成
        </div>
      </div>
      <span class="verdict-badge">${escapeHtml(verdict.label)}</span>
    </div>
    <div style="font-size: 9.5pt; line-height: 1.6;">
      <b>裁决评估摘要：</b>${escapeHtml(verdict.summaryText)}
      ${
        verdict.vetoReasons.length > 0
          ? `<div style="margin-top: 2mm; color: #991b1b; font-weight: bold;">一票否决触发项：<ul style="margin: 1mm 0 0 5mm; padding: 0;">${verdict.vetoReasons.map((r) => `<li>${escapeHtml(r)}</li>`).join('')}</ul></div>`
          : ''
      }
      ${
        verdict.warningReasons.length > 0
          ? `<div style="margin-top: 2mm; color: #92400e;">需复核提示事项：<ul style="margin: 1mm 0 0 5mm; padding: 0;">${verdict.warningReasons.map((w) => `<li>${escapeHtml(w)}</li>`).join('')}</ul></div>`
          : ''
      }
    </div>
    <div class="hash-badge">
      <b>电子物证双密码学防篡改摘要 (规范化载荷 ${digest.canonicalByteLength} Bytes)：</b><br />
      SM3 (国密算法): ${digest.sm3Hex}<br />
      SHA-256: ${digest.sha256Hex}
    </div>
  </div>

  <!-- 第二部分：四方责任主体签章确认栏 -->
  <div class="section-title">二、四方责任主体现场签章确认栏</div>
  <div class="signature-grid">
    <div class="signature-box">
      <b>保密检查组组长 (签字):</b>
      <div style="margin-top: 11mm; border-bottom: 1px solid #6b7280; width: 72%;"></div>
      <div style="font-size: 7.5pt; color: #6b7280; margin-top: 1mm;">日期: ______年____月____日</div>
    </div>
    <div class="signature-box">
      <b>被检查单位保密总监 / 归口负责人 (签字 + 公章):</b>
      <div style="margin-top: 11mm; border-bottom: 1px solid #6b7280; width: 72%;"></div>
      <div style="font-size: 7.5pt; color: #6b7280; margin-top: 1mm;">日期: ______年____月____日 (部门公章)</div>
    </div>
    <div class="signature-box">
      <b>被检信息系统安全保密管理员 (签字):</b>
      <div style="margin-top: 11mm; border-bottom: 1px solid #6b7280; width: 72%;"></div>
      <div style="font-size: 7.5pt; color: #6b7280; margin-top: 1mm;">日期: ______年____月____日</div>
    </div>
    <div class="signature-box">
      <b>涉密资产责任人 / 终端使用人 (签字):</b>
      <div style="margin-top: 11mm; border-bottom: 1px solid #6b7280; width: 72%;"></div>
      <div style="font-size: 7.5pt; color: #6b7280; margin-top: 1mm;">日期: ______年____月____日</div>
    </div>
  </div>

  <div class="section-title">BMB 分级保护核心核查控制矩阵</div>
  <table>
    <thead>
      <tr>
        <th style="width: 14%;">控制条款</th>
        <th style="width: 24%;">引用标准与要求</th>
        <th style="width: 14%; text-align: center;">核查结论</th>
        <th style="width: 48%;">现场实测物理证据链摘要</th>
      </tr>
    </thead>
    <tbody>
      ${verdict.bmbMatrix
        .map(
          (row) => `
        <tr>
          <td><b>${escapeHtml(row.clauseId)}</b></td>
          <td><b>${escapeHtml(row.controlTitle)}</b><br /><span class="sub-mono">${escapeHtml(row.standardRef)}</span></td>
          <td style="text-align: center;">${statusTagHtml(row.status)}</td>
          <td>${escapeHtml(row.evidenceSummary)}</td>
        </tr>`,
        )
        .join('')}
    </tbody>
  </table>

  <div class="page-break"></div>

  <!-- 第三部分：涉密移动存储介质 (USB) 物理痕迹核查大表 -->
  <div class="section-title">三、涉密移动存储介质 (USB) 物理痕迹核查大表</div>
  ${usbSectionHtml}

  <!-- 第四部分：涉密公文与标密文件穿透式核验清单 -->
  <div class="section-title">四、涉密公文与标密文件穿透式核验清单</div>
  ${docSectionHtml}

  <!-- 第五部分：网络违规外联与一机两用排查实测证据表 -->
  <div class="section-title">五、网络违规外联与“一机两用”排查实测证据表</div>
  ${dualSectionHtml}
  ${alertsHtml}

  <!-- 第六部分：深度历史外联、OLE2 残片、系统使用轨迹及应用外发取证明细 -->
  <div class="section-title">六、深度历史外联、OLE2 残片、系统使用轨迹及应用外发取证明细</div>
  ${deepForensicsSectionHtml}

  <div style="margin-top: 8mm; font-size: 8pt; color: #6b7280; text-align: center; border-top: 1px solid #e5e7eb; padding-top: 3mm;">
    —— 涉及国家秘密信息系统保密安全现场勘验技术报告终页 · Omni-Probe BMB 电子取证系统生成 ——
  </div>

</body>
</html>`;
}
