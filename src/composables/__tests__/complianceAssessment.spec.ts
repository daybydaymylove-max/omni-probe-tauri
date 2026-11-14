import { describe, it, expect } from 'vitest';
import {
  createDefaultComplianceItems,
  applyProbeTelemetryToAssessment,
  applyDeviceConfigReportToAssessment,
  applyHostBaselineReportToAssessment,
  calculateAssessmentMetrics,
  evaluateOverallComplianceVerdict,
  generateGbMarkdownReport,
  generateGbFormalAuditReportHtml,
  type ProbeContext,
  type HostBaselineReport,
} from '../useTargetComplianceAssessment';
import { dissectNetworkDeviceConfig } from '../../utils/networkDeviceConfigDissector';

describe('useTargetComplianceAssessment 工业级等保现场核查引擎', () => {
  it('初始化应包含 GB/T 22239-2019 全部 7 大核心控制域的 32 项实测条款', () => {
    const items = createDefaultComplianceItems();
    expect(items.length).toBe(32);

    const categories = new Set(items.map((i) => i.category));
    expect(categories.has('SCN')).toBe(true);
    expect(categories.has('SAB')).toBe(true);
    expect(categories.has('SCE')).toBe(true);
    expect(categories.has('SMC')).toBe(true);
    expect(categories.has('ICS')).toBe(true);
    expect(categories.has('CLOUD')).toBe(true);
    expect(categories.has('IOT')).toBe(true);

    const defaultMetrics = calculateAssessmentMetrics(items);
    expect(defaultMetrics.totalCount).toBe(32);
    expect(defaultMetrics.applicableCount).toBe(32);
    expect(defaultMetrics.categories.length).toBe(7);
  });

  it('探针实测探活：检出明文协议端口 (23/21) 时，通信传输保密性条款必须判定为不符合 (CRITICAL)', () => {
    const items = createDefaultComplianceItems();
    const probeCtx: ProbeContext = {
      targetIp: '192.168.1.100',
      pingAlive: true,
      pingRttMs: 1.5,
      openPorts: [21, 23, 80],
      cidrRuleCount: 2,
      baselineMode: 'ENFORCING',
      baselineRuleCount: 15,
      syslogEnabled: true,
      syslogServer: '192.168.1.250:514',
      icsAclRuleCount: 5,
      evidenceChainPassed: true,
      rbacHardened: true,
    };

    const evaluated = applyProbeTelemetryToAssessment(items, probeCtx);
    const scn03 = evaluated.find((i) => i.id === 'SCN-03');
    expect(scn03).toBeDefined();
    expect(scn03?.status).toBe('NON_COMPLIANT');
    expect(scn03?.riskLevel).toBe('CRITICAL');
    expect(scn03?.evidence).toContain('21, 23, 80');
  });

  it('探针实测探活：未暴露明文协议且使用加密端口 (443/22) 时，保密性条款判定为符合', () => {
    const items = createDefaultComplianceItems();
    const probeCtx: ProbeContext = {
      targetIp: '192.168.1.1',
      pingAlive: true,
      pingRttMs: 0.8,
      openPorts: [22, 443],
      cidrRuleCount: 3,
      baselineMode: 'ENFORCING',
      baselineRuleCount: 10,
      syslogEnabled: true,
      syslogServer: '10.0.0.99:514',
      icsAclRuleCount: 2,
      evidenceChainPassed: true,
      rbacHardened: true,
    };

    const evaluated = applyProbeTelemetryToAssessment(items, probeCtx);
    const scn03 = evaluated.find((i) => i.id === 'SCN-03');
    expect(scn03?.status).toBe('COMPLIANT');
    expect(scn03?.evidence).toContain('22, 443');
  });

  it('探针实测探活：检出高危端口 445 (SMB) 暴露时，最小化端口服务条款必须判定为不符合', () => {
    const items = createDefaultComplianceItems();
    const probeCtx: ProbeContext = {
      targetIp: '192.168.1.50',
      pingAlive: true,
      pingRttMs: 2.1,
      openPorts: [445, 135],
      cidrRuleCount: 0,
      baselineMode: 'DISABLED',
      baselineRuleCount: 0,
      syslogEnabled: false,
      syslogServer: '',
      icsAclRuleCount: 0,
      evidenceChainPassed: false,
      rbacHardened: false,
    };

    const evaluated = applyProbeTelemetryToAssessment(items, probeCtx);
    const sce02 = evaluated.find((i) => i.id === 'SCE-02');
    expect(sce02?.status).toBe('NON_COMPLIANT');
    expect(sce02?.riskLevel).toBe('CRITICAL');
    expect(sce02?.evidence).toContain('445, 135');
  });

  it('探针实测探活：检出工控端口 502 (Modbus)，无 ICS-ACL 策略时判定为部分符合，有策略时判定为符合', () => {
    const items = createDefaultComplianceItems();
    const probeNoAcl: ProbeContext = {
      targetIp: '192.168.1.200',
      pingAlive: true,
      pingRttMs: 1.1,
      openPorts: [502],
      cidrRuleCount: 1,
      baselineMode: 'LEARNING',
      baselineRuleCount: 5,
      syslogEnabled: false,
      syslogServer: '',
      icsAclRuleCount: 0,
      evidenceChainPassed: false,
      rbacHardened: false,
    };

    const resNoAcl = applyProbeTelemetryToAssessment(items, probeNoAcl);
    const ics03NoAcl = resNoAcl.find((i) => i.id === 'ICS-03');
    expect(ics03NoAcl?.status).toBe('PARTIAL');

    const probeWithAcl: ProbeContext = {
      ...probeNoAcl,
      icsAclRuleCount: 8,
    };
    const resWithAcl = applyProbeTelemetryToAssessment(items, probeWithAcl);
    const ics03WithAcl = resWithAcl.find((i) => i.id === 'ICS-03');
    expect(ics03WithAcl?.status).toBe('COMPLIANT');
    expect(ics03WithAcl?.evidence).toContain('8 条 ICS-ACL');
  });

  it('综合合规得分率与大类加权算法数学逻辑自洽', () => {
    const items = createDefaultComplianceItems();
    // 手工构造测试集合：10 项符合 (10分), 4 项部分符合 (2分), 2 项不符合 (0分), 2 项不适用 (排除分母)
    // 适用项 = 16项，总分 = 12分，得分率 = (12 / 16) * 100 = 75.0%
    items.forEach((item, idx) => {
      if (idx < 10) item.status = 'COMPLIANT';
      else if (idx < 14) item.status = 'PARTIAL';
      else if (idx < 16) item.status = 'NON_COMPLIANT';
      else if (idx < 18) item.status = 'NA';
      else item.status = 'COMPLIANT';
    });

    const m = calculateAssessmentMetrics(items);
    expect(m.naCount).toBe(2);
    expect(m.applicableCount).toBe(30);
    expect(m.compliantCount).toBe(24);
    expect(m.partialCount).toBe(4);
    expect(m.nonCompliantCount).toBe(2);
    // (24 * 1 + 4 * 0.5) / 30 * 100 = 26 / 30 * 100 = 86.7%
    expect(m.overallScorePct).toBe(86.7);
  });

  it('国家标准 Markdown 报告能够完整输出 GB/T 22239-2019 测评摘要、大类矩阵与缺陷项', () => {
    const items = createDefaultComplianceItems();
    items[2].status = 'NON_COMPLIANT';
    items[2].evidence = '实测开放 23 Telnet 端口';
    const metrics = calculateAssessmentMetrics(items);

    const md = generateGbMarkdownReport({
      targetIp: '192.168.1.100',
      targetLevel: '等保三级 (GB/T 22239-2019 第8章)',
      inspectorName: '张工',
      inspectorRole: '安全管理员 (SecAdmin)',
      items,
      metrics,
      generatedAt: '2026-11-14 10:00:00',
    });

    expect(md).toContain('网络安全等级保护 2.0 / 3.0 现场测评核查报告');
    expect(md).toContain('GB/T 22239-2019');
    expect(md).toContain('192.168.1.100');
    expect(md).toContain('张工 (安全管理员 (SecAdmin))');
    expect(md).toContain('安全通信网络 (SCN)');
    expect(md).toContain('SCN-03');
    expect(md).toContain('实测开放 23 Telnet 端口');
  });

  it('设备配置报告注入：导入存在明文与弱安全缺陷的思科配置后，相关条款自动映射不符合', () => {
    const items = createDefaultComplianceItems();
    const vulnerableCisco = `
!
version 15.2
hostname CORE-SW-02
username admin password 0 ClearText123!
telnet server enable
snmp-server community public RO
line vty 0 4
 transport input all
 exec-timeout 0 0
!
    `;
    const report = dissectNetworkDeviceConfig(vulnerableCisco);
    const updated = applyDeviceConfigReportToAssessment(items, report);

    // SCN-03 (明文远程管理)
    const scn03 = updated.find((i) => i.id === 'SCN-03');
    expect(scn03?.status).toBe('NON_COMPLIANT');
    expect(scn03?.evidence).toContain('CORE-SW-02');

    // SCE-01 (明文密码)
    const sce01 = updated.find((i) => i.id === 'SCE-01');
    expect(sce01?.status).toBe('NON_COMPLIANT');
    expect(sce01?.evidence).toContain('明文密码保存');

    // SCE-06 (永不超时)
    const sce06 = updated.find((i) => i.id === 'SCE-06');
    expect(sce06?.status).toBe('NON_COMPLIANT');
    expect(sce06?.evidence).toContain('exec-timeout 0 0');
  });

  it('主机安全计算环境 (SCE) 8 项基线实测报告自动映射至控制点', () => {
    const items = createDefaultComplianceItems();
    const mockHostReport: HostBaselineReport = {
      hostname: 'PROBE-SRV-01',
      os_type: 'windows',
      os_name: 'Windows 10 Pro (Build 19045)',
      scan_time: '2026-11-14 10:30:00',
      total_checks: 8,
      passed_checks: 6,
      failed_checks: 2,
      compliance_rate_pct: 75.0,
      items: [
        {
          id: 'SCE-HOST-01',
          title: '最小密码长度策略',
          category: '身份鉴别',
          clause: '8.1.4.1 a',
          passed: true,
          standard_requirement: '最小密码长度 >= 8 字符',
          actual_value: '最小密码长度: 12 字符',
          risk_level: 'HIGH',
          evidence: '最小密码长度: 12 字符 (>= 8)',
          remediation: '',
        },
        {
          id: 'SCE-HOST-02',
          title: '密码最长存活周期策略',
          category: '身份鉴别',
          clause: '8.1.4.1 a',
          passed: false,
          standard_requirement: '最大使用期限 <= 90 天',
          actual_value: '密码最长存活期: 从不更换 (永不过期)',
          risk_level: 'HIGH',
          evidence: '密码最长存活期: 永不过期',
          remediation: '修改密码最长存活期 <= 90 天',
        },
        {
          id: 'SCE-HOST-03',
          title: '账户锁定阈值策略',
          category: '身份鉴别',
          clause: '8.1.4.1 c',
          passed: false,
          standard_requirement: '失败锁定阈值介于 3 至 5 次之间',
          actual_value: '失败锁定阈值: 0 次 (从不锁定)',
          risk_level: 'CRITICAL',
          evidence: '账户失败锁定阈值: 0 次 (不锁定)',
          remediation: '运行 secpol.msc 配置账户锁定策略',
        },
        {
          id: 'SCE-HOST-04',
          title: '账户锁定时长策略',
          category: '身份鉴别',
          clause: '8.1.4.1 c',
          passed: false,
          standard_requirement: '锁定持续时间 >= 15 分钟',
          actual_value: '锁定持续时间: 0 分钟',
          risk_level: 'HIGH',
          evidence: '账户锁定持续时间: 0 分钟 (< 15)',
          remediation: '配置锁定时长 >= 15 分钟',
        },
      ],
    };

    const updated = applyHostBaselineReportToAssessment(items, mockHostReport);
    const sce01 = updated.find((i) => i.id === 'SCE-01');
    expect(sce01?.status).toBe('NON_COMPLIANT');
    expect(sce01?.evidence).toContain('PROBE-SRV-01');
    expect(sce01?.evidence).toContain('密码最长存活期');

    const sce02 = updated.find((i) => i.id === 'SCE-02');
    expect(sce02?.status).toBe('NON_COMPLIANT');
    expect(sce02?.evidence).toContain('失败锁定阈值: 0 次');
  });

  describe('GB/T 28448-2019 标准测评裁决极限用例测试 (3 类极限边界验证)', () => {
    it('极限用例 1：所有条款 100% 达成，裁决为“符合”', () => {
      const items = createDefaultComplianceItems();
      for (const item of items) {
        item.status = 'COMPLIANT';
      }
      const verdict = evaluateOverallComplianceVerdict(items, 100.0);
      expect(verdict.level).toBe('COMPLIANT');
      expect(verdict.levelText).toBe('符合');
      expect(verdict.isVetoedByCriticalRisk).toBe(false);
      expect(verdict.criticalDefectCount).toBe(0);
    });

    it('极限用例 2：一票否决红线！虽然得分率高达 95%，但存在 1 项 CRITICAL 缺陷，总体裁决必为“不符合”', () => {
      const items = createDefaultComplianceItems();
      for (const item of items) {
        item.status = 'COMPLIANT';
      }
      // 故意置入 1 项 CRITICAL 级别不符合项（如明文协议或弱口令）
      const criticalItem = items.find((i) => i.id === 'SCN-03');
      expect(criticalItem).toBeDefined();
      if (criticalItem) {
        criticalItem.status = 'NON_COMPLIANT';
        criticalItem.riskLevel = 'CRITICAL';
      }

      const verdict = evaluateOverallComplianceVerdict(items, 95.0);
      expect(verdict.level).toBe('NON_COMPLIANT');
      expect(verdict.levelText).toBe('不符合');
      expect(verdict.isVetoedByCriticalRisk).toBe(true);
      expect(verdict.criticalDefectCount).toBe(1);
      expect(verdict.reason).toContain('一票否决红线');
    });

    it('极限用例 3：临界阈值判定 (69.9% 判定为不符合 vs 70.0% 判定为基本符合)', () => {
      const items = createDefaultComplianceItems();
      // 将所有项设为低危或中危的部分符合，消除所有 CRITICAL / HIGH 缺陷
      for (const item of items) {
        item.status = 'PARTIAL';
        item.riskLevel = 'LOW';
      }

      // 分数 69.9% -> 判定为不符合
      const verdictUnderThreshold = evaluateOverallComplianceVerdict(items, 69.9);
      expect(verdictUnderThreshold.level).toBe('NON_COMPLIANT');
      expect(verdictUnderThreshold.levelText).toBe('不符合');
      expect(verdictUnderThreshold.isVetoedByCriticalRisk).toBe(false);
      expect(verdictUnderThreshold.reason).toContain('未达到 GB/T 28448-2019 规定的 70.0% 基本符合底线阈值');

      // 分数 70.0% -> 判定为基本符合
      const verdictAtThreshold = evaluateOverallComplianceVerdict(items, 70.0);
      expect(verdictAtThreshold.level).toBe('PARTIALLY_COMPLIANT');
      expect(verdictAtThreshold.levelText).toBe('基本符合');
      expect(verdictAtThreshold.isVetoedByCriticalRisk).toBe(false);
      expect(verdictAtThreshold.reason).toContain('达到 GB/T 28448-2019“基本符合”标准');
    });
  });

  it('公安部标准 A4 打印级正式 HTML 测评大报告能正常生成，包含四方签署、防伪摘要与 PoAM 缺陷清单', () => {
    const items = createDefaultComplianceItems();
    items[0].status = 'NON_COMPLIANT';
    items[0].evidence = '未划分 VLAN 子网';
    const metrics = calculateAssessmentMetrics(items);

    const html = generateGbFormalAuditReportHtml({
      targetIp: '192.168.1.1',
      targetLevel: '等保三级 (GB/T 22239-2019 第8章)',
      inspectorName: '李工',
      inspectorRole: '安全审计员 (AuditAdmin)',
      items,
      metrics,
      generatedAt: '2026-11-14 11:00:00',
    });

    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('size: A4 portrait;');
    expect(html).toContain('现场测评核查技术报告');
    expect(html).toContain('192.168.1.1');
    expect(html).toContain('李工 (安全审计员 (AuditAdmin))');
    expect(html).toContain('四方责任主体与测评结论签章确认栏');
    expect(html).toContain('电子物证哈希防篡改摘要');
    expect(html).toContain('实测高危安全缺陷与加固整改行动表 (PoAM)');
    expect(html).toContain('未划分 VLAN 子网');
    // 绝不包含原先静态假哈希
    expect(html).not.toContain('8f4e2b0a1c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f');
  });

  it('电子物证防伪哈希真实雪崩效应与 HTML XSS 注入实体防御测试', () => {
    const itemsA = createDefaultComplianceItems();
    itemsA[0].status = 'NON_COMPLIANT';
    itemsA[0].evidence = '<script>alert(1)</script>';
    const metricsA = calculateAssessmentMetrics(itemsA);

    const htmlA = generateGbFormalAuditReportHtml({
      targetIp: '10.0.0.1',
      targetLevel: '等保三级',
      inspectorName: '张<工>',
      inspectorRole: 'SecAdmin',
      items: itemsA,
      metrics: metricsA,
      generatedAt: '2026-11-14 12:00:00',
    });

    // XSS 必须被转义
    expect(htmlA).not.toContain('<script>alert(1)</script>');
    expect(htmlA).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
    expect(htmlA).toContain('张&lt;工&gt;');

    const sm3MatchA = htmlA.match(/SM3:\s*([0-9a-f]{64})/);
    const shaMatchA = htmlA.match(/SHA-256:\s*([0-9a-f]{64})/);
    expect(sm3MatchA).not.toBeNull();
    expect(shaMatchA).not.toBeNull();

    // 篡改单条证据，验证 SM3 与 SHA-256 必须同步雪崩改变
    const itemsB = createDefaultComplianceItems();
    itemsB[0].status = 'NON_COMPLIANT';
    itemsB[0].evidence = '<script>alert(2)</script>';
    const metricsB = calculateAssessmentMetrics(itemsB);
    const htmlB = generateGbFormalAuditReportHtml({
      targetIp: '10.0.0.1',
      targetLevel: '等保三级',
      inspectorName: '张<工>',
      inspectorRole: 'SecAdmin',
      items: itemsB,
      metrics: metricsB,
      generatedAt: '2026-11-14 12:00:00',
    });

    const sm3MatchB = htmlB.match(/SM3:\s*([0-9a-f]{64})/);
    const shaMatchB = htmlB.match(/SHA-256:\s*([0-9a-f]{64})/);
    expect(sm3MatchB?.[1]).not.toBe(sm3MatchA?.[1]);
    expect(shaMatchB?.[1]).not.toBe(shaMatchA?.[1]);
  });
});
