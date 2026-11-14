import { describe, expect, it } from 'vitest';
import {
  buildCanonicalSecrecyDigest,
  evaluateSecrecyBmbVerdict,
  generateSecrecyFormalReportHtml,
  generateSecrecyFormalReportMarkdown,
  type SecrecyReportParams,
} from '../useSecrecyFormalReport';

function buildBaseCleanParams(): SecrecyReportParams {
  return {
    targetUnitName: '某涉密研发中心实验室',
    systemName: '内部核心研发终端 #01',
    systemClassification: '机密级',
    inspectorName: '张工',
    inspectionTimeIso: '2026-11-14T10:30:00+08:00',
    usbReport: {
      scanned_host: 'LAB-WORKSTATION-01',
      scan_time: '2026-11-14 10:28:00',
      total_devices_found: 1,
      unauthorized_device_count: 0,
      has_critical_violation: false,
      devices: [
        {
          device_id: 'USBSTOR\\DISK&VEN_HUAWEI\\SEC001',
          vendor_id: '12D1',
          product_id: '3609',
          serial_number: 'SEC99887766',
          device_name: '授权涉密加密盘',
          class_guid: '{4d36e967-e325-11ce-bfc1-08002be10318}',
          first_installed_time: '2026-01-15 09:00:00',
          last_arrival_time: '2026-11-10 14:22:00',
          assigned_drive_letter: 'E:',
          is_whitelisted: true,
          violation_level: 'CLEAN',
          evidence_source: 'REGISTRY:USBSTOR',
        },
      ],
      summary_conclusion: '历史介质合规',
    },
    dissectReport: {
      target_folder: 'D:\\PublicWork',
      scanned_files_count: 25,
      hit_files_count: 0,
      encrypted_or_blocked_count: 0,
      duration_ms: 18,
      top_secret_count: 0,
      confidential_count: 0,
      secret_count: 0,
      hits: [],
      warnings: [],
    },
    dualHomedReport: {
      is_dual_homed_violation: false,
      active_nic_count: 1,
      has_simultaneous_wired_and_wireless: false,
      has_public_and_private_bridging: false,
      wireless_ssid: null,
      risk_level: 'CLEAN',
      reason: '仅存在单张涉密专网物理有线接口处于激活状态',
      interfaces: [
        {
          name: '涉密内网口',
          if_type: 'ETHERNET',
          is_up: true,
          ip_addresses: ['10.10.20.88'],
          gateway_addresses: ['10.10.20.1'],
          is_connected_to_private: true,
          is_connected_to_public: false,
        },
      ],
    },
    networkAlerts: [],
  };
}

describe('useSecrecyFormalReport (BMB17/BMB20/BMB22 保密现场勘验报告引擎)', () => {
  it('三项取证均合规且网流洁净时，应评定为 QUALIFIED 【合格】', () => {
    const params = buildBaseCleanParams();
    const verdict = evaluateSecrecyBmbVerdict(params);

    expect(verdict.code).toBe('QUALIFIED');
    expect(verdict.label).toBe('【合格】');
    expect(verdict.isVetoed).toBe(false);
    expect(verdict.vetoReasons).toHaveLength(0);
    expect(verdict.bmbMatrix.every((row) => row.status === 'PASS')).toBe(true);
  });

  it('检出未授权历史 USB 或一机两用双联或涉密文件留存时，均应精准触发一票否决', () => {
    const usbFail = buildBaseCleanParams();
    if (usbFail.usbReport) {
      usbFail.usbReport.unauthorized_device_count = 1;
      usbFail.usbReport.has_critical_violation = true;
    }
    const v1 = evaluateSecrecyBmbVerdict(usbFail);
    expect(v1.code).toBe('DISQUALIFIED_VETOED');
    expect(v1.label).toBe('【不合格 (触发一票否决)】');
    expect(v1.vetoReasons.some((r) => r.includes('BMB22-5.2.2'))).toBe(true);

    const dualFail = buildBaseCleanParams();
    if (dualFail.dualHomedReport) {
      dualFail.dualHomedReport.is_dual_homed_violation = true;
      dualFail.dualHomedReport.has_simultaneous_wired_and_wireless = true;
      dualFail.dualHomedReport.wireless_ssid = 'iPhone_Hotspot';
    }
    const v2 = evaluateSecrecyBmbVerdict(dualFail);
    expect(v2.code).toBe('DISQUALIFIED_VETOED');
    expect(v2.vetoReasons.some((r) => r.includes('BMB22-5.2.1'))).toBe(true);

    const docFail = buildBaseCleanParams();
    if (docFail.dissectReport) {
      docFail.dissectReport.hit_files_count = 1;
      docFail.dissectReport.top_secret_count = 1;
      docFail.dissectReport.hits = [
        {
          file_path: 'D:\\PublicWork\\汇总.docx',
          file_type: 'DOCX',
          file_size_bytes: 12040,
          sha256_hash: 'a'.repeat(64),
          sm3_hash: 'b'.repeat(64),
          secrecy_level: 'TOP_SECRET',
          matched_markers: ['绝密★30年'],
          document_signatures: ['中办发〔2025〕8号'],
          snippet_preview: '...[绝密★30年] 关于内部系统...',
          is_archive_nested: false,
          nested_path: null,
        },
      ];
    }
    const v3 = evaluateSecrecyBmbVerdict(docFail);
    expect(v3.code).toBe('DISQUALIFIED_VETOED');
    expect(v3.vetoReasons.some((r) => r.includes('BMB20'))).toBe(true);
  });

  it('极限零数据边界（三项实测均未执行、空单位名）不崩溃并回落为【基本合格】', () => {
    const emptyParams: SecrecyReportParams = {
      targetUnitName: '',
      systemName: '',
      systemClassification: '秘密级',
      inspectorName: '',
      inspectionTimeIso: '2026-11-14T12:00:00Z',
      usbReport: null,
      dissectReport: null,
      dualHomedReport: null,
      networkAlerts: [],
    };
    const verdict = evaluateSecrecyBmbVerdict(emptyParams);
    expect(verdict.code).toBe('CONDITIONALLY_QUALIFIED');
    expect(verdict.label).toBe('【基本合格】');

    const md = generateSecrecyFormalReportMarkdown(emptyParams);
    expect(md).toContain('涉及国家秘密信息系统保密安全现场勘验技术报告');
    expect(md).toContain('BMJC-2026-');
  });

  it('规范化电子物证遵循 BMJC-<Year>-<SM3前8位> 格式，且具备单字符雪崩不可篡改性', () => {
    const p1 = buildBaseCleanParams();
    const v1 = evaluateSecrecyBmbVerdict(p1);
    const d1 = buildCanonicalSecrecyDigest(p1, v1);

    expect(d1.reportId).toMatch(/^BMJC-2026-[0-9A-F]{8}$/);
    expect(d1.sm3Hex).toMatch(/^[0-9a-f]{64}$/);
    expect(d1.sha256Hex).toMatch(/^[0-9a-f]{64}$/);

    const p2 = buildBaseCleanParams();
    p2.targetUnitName = '某涉密研发中心实验台'; // 改动单个汉字
    const v2 = evaluateSecrecyBmbVerdict(p2);
    const d2 = buildCanonicalSecrecyDigest(p2, v2);

    expect(d1.sm3Hex).not.toBe(d2.sm3Hex);
    expect(d1.sha256Hex).not.toBe(d2.sha256Hex);
  });

  it('A4 HTML 勘验报告包含 A4 Portrait 打印规则、四方签章栏及严密 XSS 实体转义', () => {
    const xssParams = buildBaseCleanParams();
    xssParams.targetUnitName = '<script>alert("xss")</script>保密室';
    if (xssParams.dualHomedReport) {
      xssParams.dualHomedReport.wireless_ssid = '<img src=x onerror=alert(1)>';
    }

    const html = generateSecrecyFormalReportHtml(xssParams);
    expect(html).toContain('size: A4 portrait;');
    expect(html).toContain('margin: 18mm 15mm;');
    expect(html).toContain('四方责任主体现场签章确认栏');
    expect(html).toContain('保密检查组组长 (签字)');
    expect(html).toContain('被检查单位保密总监 / 归口负责人 (签字 + 公章)');
    expect(html).not.toContain('<script>alert("xss")</script>');
    expect(html).not.toContain('<img src=x onerror=alert(1)>');
    expect(html).toContain('&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;保密室');
  });

  it('第 2 阶段四大深度取证模块洁净接入时，BMB 矩阵扩展为 8 项且全量通过', () => {
    const p = buildBaseCleanParams();
    p.networkHistoryReport = {
      scanned_host: 'LAB-WORKSTATION-01',
      scan_time: '2026-11-14 10:32:00',
      total_wifi_profiles_found: 0,
      suspicious_mobile_hotspots: [],
      all_wifi_profiles: [],
      historic_rndis_devices: [],
      historic_dialup_connections: [],
      historic_network_profiles: [],
      has_historic_violation: false,
      summary_conclusion: '无违规外联历史',
      degrade_notes: [],
    };
    p.ole2Report = {
      target_folder: 'D:\\PublicWork',
      scanned_ole2_files: 6,
      ole2_hits: [],
      slack_scanned_bytes: 1048576,
      slack_hits: [],
      duration_ms: 42,
      warnings: [],
    };
    p.osUsageReport = {
      scanned_host: 'LAB-WORKSTATION-01',
      scan_time: '2026-11-14 10:33:00',
      total_lnk_parsed: 12,
      recent_files: [],
      print_spooler_jobs: [],
      system_boot_history: ['2026-11-14 08:50:00 Event 6005'],
      suspicious_u_disk_file_count: 0,
      secrecy_named_access_count: 0,
      degrade_notes: [],
    };
    p.appTraceReport = {
      scanned_host: 'LAB-WORKSTATION-01',
      scan_time: '2026-11-14 10:34:00',
      total_downloads_checked: 18,
      suspicious_downloads: [],
      recent_downloads_sample: [],
      chat_files_checked: 20,
      chat_file_hits: [],
      degrade_notes: [],
    };

    const verdict = evaluateSecrecyBmbVerdict(p);
    expect(verdict.code).toBe('QUALIFIED');
    expect(verdict.bmbMatrix).toHaveLength(8);
    expect(verdict.bmbMatrix.every((row) => row.status === 'PASS')).toBe(true);
  });

  it('第 2 阶段四大深度取证模块检出历史热点/OLE2残片/U盘涉密访问/应用外发时，均应准确触发一票否决与SM3雪崩', () => {
    const netHisFail = buildBaseCleanParams();
    netHisFail.networkHistoryReport = {
      scanned_host: 'HOST-01',
      scan_time: '2026-11-14 11:00:00',
      total_wifi_profiles_found: 1,
      suspicious_mobile_hotspots: [
        {
          profile_name: 'Huawei_P60_AP',
          ssid: 'HUAWEI P60 Pro',
          auth_type: 'WPA2PSK',
          cipher: 'AES',
          is_mobile_hotspot_feature: true,
          last_modified_time: '2026-10-01 09:00:00',
        },
      ],
      all_wifi_profiles: [],
      historic_rndis_devices: ['USB\\VID_12D1&PID_108A\\RNDIS'],
      historic_dialup_connections: [],
      historic_network_profiles: [],
      has_historic_violation: true,
      summary_conclusion: '检出手机热点与 RNDIS 共享外联',
      degrade_notes: [],
    };
    const vNet = evaluateSecrecyBmbVerdict(netHisFail);
    expect(vNet.code).toBe('DISQUALIFIED_VETOED');
    expect(vNet.vetoReasons.some((r) => r.includes('BMB22-5.2.1-HIS'))).toBe(true);

    const oleFail = buildBaseCleanParams();
    oleFail.ole2Report = {
      target_folder: 'D:\\Temp',
      scanned_ole2_files: 3,
      ole2_hits: [
        {
          file_path: 'D:\\Temp\\old.doc',
          sub_stream_name: 'WordDocument',
          sha256_hash: 'c'.repeat(64),
          sm3_hash: 'd'.repeat(64),
          secrecy_level: 'SECRET',
          matched_markers: ['秘密★10年'],
          document_signatures: [],
          snippet_preview: '...秘密★10年...',
        },
      ],
      slack_scanned_bytes: 65536,
      slack_hits: [
        {
          drive_letter: 'D:',
          sector_offset: 4096,
          matched_marker: '机密★20年',
          snippet_preview: '...残片内容...',
        },
      ],
      duration_ms: 15,
      warnings: [],
    };
    const vOle = evaluateSecrecyBmbVerdict(oleFail);
    expect(vOle.code).toBe('DISQUALIFIED_VETOED');
    expect(vOle.vetoReasons.some((r) => r.includes('BMB20-OLE2'))).toBe(true);

    const osFail = buildBaseCleanParams();
    osFail.osUsageReport = {
      scanned_host: 'HOST-01',
      scan_time: '2026-11-14 11:02:00',
      total_lnk_parsed: 5,
      recent_files: [
        {
          shortcut_name: '方案.doc.lnk',
          target_real_path: 'F:\\核心方案(机密).doc',
          target_creation_time: '2026-11-10 10:00:00',
          target_last_access_time: '2026-11-11 10:00:00',
          drive_type: 'DRIVE_REMOVABLE',
          is_removable_media_target: true,
          is_secrecy_named: true,
        },
      ],
      print_spooler_jobs: [
        {
          job_id: '00005',
          document_name: '涉密汇总表.xlsx',
          printer_name: 'HP LaserJet',
          submit_time: '2026-11-12 15:00:00',
          spool_file_path: '00005.SHD',
          is_secrecy_suspicious: true,
        },
      ],
      system_boot_history: [],
      suspicious_u_disk_file_count: 1,
      secrecy_named_access_count: 1,
      degrade_notes: [],
    };
    const vOs = evaluateSecrecyBmbVerdict(osFail);
    expect(vOs.code).toBe('DISQUALIFIED_VETOED');
    expect(vOs.vetoReasons.some((r) => r.includes('BMB20-TRACE'))).toBe(true);

    const appFail = buildBaseCleanParams();
    appFail.appTraceReport = {
      scanned_host: 'HOST-01',
      scan_time: '2026-11-14 11:03:00',
      total_downloads_checked: 10,
      suspicious_downloads: [
        {
          browser_type: 'Edge',
          target_file_path: 'C:\\Users\\a\\Downloads\\<script>机密报告.pdf',
          original_url: 'https://example.invalid/leak',
          download_time: '2026-11-13 09:00:00',
          is_suspicious_secrecy: true,
          matched_marker: '机密',
        },
      ],
      recent_downloads_sample: [],
      chat_files_checked: 4,
      chat_file_hits: [
        {
          app_name: 'WeChat',
          file_name: '秘密件.docx',
          file_path: 'D:\\WeChat Files\\秘密件.docx',
          file_size: 8192,
          hit_secrecy_marker: '秘密',
        },
      ],
      degrade_notes: [],
    };
    const vApp = evaluateSecrecyBmbVerdict(appFail);
    expect(vApp.code).toBe('DISQUALIFIED_VETOED');
    expect(vApp.vetoReasons.some((r) => r.includes('BMB17-APP'))).toBe(true);

    // 验证 XSS 转义与 SM3 雪崩
    const html = generateSecrecyFormalReportHtml(appFail);
    expect(html).toContain('六、深度历史外联、OLE2 残片、系统使用轨迹及应用外发取证明细');
    expect(html).not.toContain('<script>机密报告.pdf');
    expect(html).toContain('&lt;script&gt;机密报告.pdf');

    const md = generateSecrecyFormalReportMarkdown(oleFail);
    expect(md).toContain('## 六、深度历史外联、OLE2 残片、系统轨迹及应用外发取证明细');
    expect(md).toContain('## 七、四方责任主体现场签章确认');

    const dApp1 = buildCanonicalSecrecyDigest(appFail, vApp);
    const appFailMutated = { ...appFail, appTraceReport: { ...appFail.appTraceReport!, chat_file_hits: [] } };
    const dApp2 = buildCanonicalSecrecyDigest(appFailMutated, evaluateSecrecyBmbVerdict(appFailMutated));
    expect(dApp1.sm3Hex).not.toBe(dApp2.sm3Hex);
  });
});
