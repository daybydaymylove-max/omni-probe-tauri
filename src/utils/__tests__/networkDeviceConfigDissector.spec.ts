import { describe, it, expect } from 'vitest';
import {
  detectDeviceVendor,
  extractDeviceHostname,
  dissectNetworkDeviceConfig,
} from '../networkDeviceConfigDissector';

describe('networkDeviceConfigDissector 交换机/路由器设备配置等保基线分析器', () => {
  const huaweiCompliantSample = `
#
sysname CORE-SW-01
#
ssh server protocol-version 2
undo telnet server enable
#
local-user admin password irreversible-cipher $1a$u/2134kjahsd$
local-user admin service-type ssh
local-user secadmin password irreversible-cipher $1a$lkasd91823$
local-user secadmin service-type ssh
#
account login-failed threshold 5
#
snmp-agent sys-info version v3
snmp-agent group v3 admin_group privacy
#
info-center loghost 192.168.10.250
#
user-interface vty 0 4
 authentication-mode aaa
 user-role network-admin
 idle-timeout 10 0
 protocol inbound ssh
#
return
  `;

  const ciscoVulnerableSample = `
!
version 15.2
hostname EDGE-ROUTER-01
!
enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0
username admin password 0 Cisco123!
!
ip http server
telnet server enable
!
snmp-server community public RO
snmp-server community private RW
!
line vty 0 4
 transport input all
 exec-timeout 0 0
 login local
!
end
  `;

  it('能精准识别华为与思科配置方言与主机名', () => {
    expect(detectDeviceVendor(huaweiCompliantSample)).toBe('HUAWEI');
    expect(extractDeviceHostname(huaweiCompliantSample)).toBe('CORE-SW-01');

    expect(detectDeviceVendor(ciscoVulnerableSample)).toBe('CISCO');
    expect(extractDeviceHostname(ciscoVulnerableSample)).toBe('EDGE-ROUTER-01');
  });

  it('针对合规基线配置应全项通过并达到 100% 达标率', () => {
    const report = dissectNetworkDeviceConfig(huaweiCompliantSample);
    expect(report.vendor).toBe('HUAWEI');
    expect(report.hostname).toBe('CORE-SW-01');
    expect(report.passedCount).toBe(8);
    expect(report.failedCount).toBe(0);
    expect(report.complianceRatePct).toBe(100.0);

    const sshRule = report.results.find((r) => r.ruleId === 'NET-CFG-04');
    expect(sshRule?.passed).toBe(true);

    const timeoutRule = report.results.find((r) => r.ruleId === 'NET-CFG-05');
    expect(timeoutRule?.passed).toBe(true);
    expect(timeoutRule?.evidence).toContain('idle-timeout 10 0');
  });

  it('针对存在缺陷配置应精准检出明文口令、明文管理与永不超时风险', () => {
    const report = dissectNetworkDeviceConfig(ciscoVulnerableSample);
    expect(report.vendor).toBe('CISCO');
    expect(report.passedCount).toBeLessThan(8);

    // 规则 2：口令明文检测
    const pwdRule = report.results.find((r) => r.ruleId === 'NET-CFG-02');
    expect(pwdRule?.passed).toBe(false);
    expect(pwdRule?.severity).toBe('CRITICAL');
    expect(pwdRule?.evidence).toContain('明文密码保存');

    // 规则 3：明文 Telnet / HTTP
    const telnetRule = report.results.find((r) => r.ruleId === 'NET-CFG-03');
    expect(telnetRule?.passed).toBe(false);
    expect(telnetRule?.severity).toBe('CRITICAL');

    // 规则 5：超时 0 0 (永不超时)
    const timeoutRule = report.results.find((r) => r.ruleId === 'NET-CFG-05');
    expect(timeoutRule?.passed).toBe(false);
    expect(timeoutRule?.evidence).toContain('exec-timeout 0 0');

    // 规则 7：SNMP public / private 弱口令
    const snmpRule = report.results.find((r) => r.ruleId === 'NET-CFG-07');
    expect(snmpRule?.passed).toBe(false);
    expect(snmpRule?.evidence).toContain('public');
  });

  it('混合块级边界测试：防止 Console 合格掩盖 VTY 0 0 永不超时，并支持华为 protocol inbound all 与非默认 SNMP 明文检测', () => {
    const trickyConfig = `
sysname TRICKY-SW
logging 192.168.100.250
snmp-server community SecretCorpRO RO
user-interface con 0
 idle-timeout 10 0
user-interface vty 0 4
 idle-timeout 0 0
 protocol inbound all
    `;
    const report = dissectNetworkDeviceConfig(trickyConfig);

    // 尽管 con 0 配了 idle-timeout 10 0，但 vty 0 4 配了 0 0，必须严格判为失败！
    const timeoutRule = report.results.find((r) => r.ruleId === 'NET-CFG-05');
    expect(timeoutRule?.passed).toBe(false);
    expect(timeoutRule?.evidence).toContain('idle-timeout 0 0');

    // 华为 protocol inbound all 开放明文 Telnet，必须拦截
    const telnetRule = report.results.find((r) => r.ruleId === 'NET-CFG-03');
    expect(telnetRule?.passed).toBe(false);
    expect(telnetRule?.evidence).toContain('protocol inbound all');

    // 非默认团体字但未启用 SNMP v3，必须明确指出而非空括号
    const snmpRule = report.results.find((r) => r.ruleId === 'NET-CFG-07');
    expect(snmpRule?.passed).toBe(false);
    expect(snmpRule?.evidence).toContain('SecretCorpRO');

    // 旧版 logging <IP> 必须正确识别
    const logRule = report.results.find((r) => r.ruleId === 'NET-CFG-08');
    expect(logRule?.passed).toBe(true);
  });
});
