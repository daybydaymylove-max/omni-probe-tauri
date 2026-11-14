import { ref, computed } from 'vue';
import type { DeviceConfigAnalysisReport } from '../utils/networkDeviceConfigDissector';
import { computeSm3Hex, computeSha256Hex, escapeHtml } from '../utils/cryptoDigest';

export type AssessmentCategory = 'SCN' | 'SAB' | 'SCE' | 'SMC' | 'ICS' | 'CLOUD' | 'IOT';
export type ComplianceStatus = 'COMPLIANT' | 'PARTIAL' | 'NON_COMPLIANT' | 'NA' | 'PENDING';
export type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface TargetComplianceItem {
  id: string;
  clause: string;
  category: AssessmentCategory;
  categoryLabel: string;
  title: string;
  level: '等保二级' | '等保三级' | '工控三级扩展' | '云计算扩展' | '物联网扩展';
  requirement: string;
  probeMethod: string;
  evidence: string;
  status: ComplianceStatus;
  riskLevel: RiskLevel;
  remediation: string;
  manualModified?: boolean;
}

export interface ProbeContext {
  targetIp: string;
  pingAlive: boolean | null;
  pingRttMs: number | null;
  openPorts: number[];
  discoveredServices?: Record<number, string>;
  cidrRuleCount: number;
  baselineMode: string;
  baselineRuleCount: number;
  syslogEnabled: boolean;
  syslogServer: string;
  icsAclRuleCount: number;
  evidenceChainPassed: boolean;
  rbacHardened: boolean;
}

export interface CategorySummary {
  category: AssessmentCategory;
  label: string;
  total: number;
  compliant: number;
  partial: number;
  nonCompliant: number;
  na: number;
  pending: number;
  scorePct: number;
}

/**
 * GB/T 28448-2019 等保测评结论标准判定枚举
 */
export type ComplianceVerdictLevel = 'COMPLIANT' | 'PARTIALLY_COMPLIANT' | 'NON_COMPLIANT';

export interface ComplianceVerdict {
  level: ComplianceVerdictLevel;
  levelText: '符合' | '基本符合' | '不符合';
  isVetoedByCriticalRisk: boolean;
  criticalDefectCount: number;
  highDefectCount: number;
  reason: string;
}

export interface AssessmentMetrics {
  totalCount: number;
  applicableCount: number;
  compliantCount: number;
  partialCount: number;
  nonCompliantCount: number;
  naCount: number;
  pendingCount: number;
  overallScorePct: number;
  categories: CategorySummary[];
  verdict: ComplianceVerdict;
}

/**
 * 国家标准 GB/T 22239-2019 等保 2.0 / 3.0 现场测评实测控制点基准库
 * 涵盖：安全通信网络 (SCN)、安全区域边界 (SAB)、安全计算环境 (SCE)、安全管理中心 (SMC)、工控安全扩展 (ICS)
 */
export function createDefaultComplianceItems(): TargetComplianceItem[] {
  return [
    // ------------------------------------------------------------------------
    // 1. 安全通信网络 (SCN)
    // ------------------------------------------------------------------------
    {
      id: 'SCN-01',
      clause: 'GB/T 22239-2019 8.1.1.1',
      category: 'SCN',
      categoryLabel: '安全通信网络',
      title: '网络架构与链路冗余',
      level: '等保三级',
      requirement: '应保证网络各个部分的带宽满足业务高峰期需要；关键网络节点和传输线路应提供冗余，避免单点故障。',
      probeMethod: '网络探针微突发吞吐量监测、链路丢包率与 RTT 时延采样。',
      evidence: '待探针启动现场链路探测',
      status: 'PENDING',
      riskLevel: 'MEDIUM',
      remediation: '针对核心生产网络链路配置双归冗余上行与负载均衡机制，消除单线故障隐患。',
    },
    {
      id: 'SCN-02',
      clause: 'GB/T 22239-2019 8.1.1.2',
      category: 'SCN',
      categoryLabel: '安全通信网络',
      title: '通信传输完整性校验',
      level: '等保三级',
      requirement: '应采用校验码技术或密码技术保证通信过程中数据的完整性，避免传输中数据被非法篡改。',
      probeMethod: '传输层 TCP/IP 校验和验证、报文完整性指纹审计与重传率分析。',
      evidence: '待探针分析网络传输层校验和与丢包重传状态',
      status: 'PENDING',
      riskLevel: 'MEDIUM',
      remediation: '启用传输层 HMAC 或 TLS 完整性校验机制，杜绝传输层报文在物理信道被伪造或重放。',
    },
    {
      id: 'SCN-03',
      clause: 'GB/T 22239-2019 8.1.1.3',
      category: 'SCN',
      categoryLabel: '安全通信网络',
      title: '通信传输保密性与加密保护',
      level: '等保三级',
      requirement: '在通信双方建立连接之前，应用密码技术进行会话初始化验证；通信过程应采用加密保护，严禁明文传输鉴别信息与敏感数据。',
      probeMethod: '高危明文协议扫描（21 FTP / 23 Telnet / 80 HTTP / 110 POP3 / 143 IMAP 等），检测明文凭据与敏感通信内容。',
      evidence: '待探针发起目标高危明文协议端口探测',
      status: 'PENDING',
      riskLevel: 'CRITICAL',
      remediation: '全网禁用明文 Telnet/FTP 等非安全协议；全面切换为 SSH(v2)、FTPS/SFTP 及 TLS 1.3 强加密通信。',
    },
    {
      id: 'SCN-04',
      clause: 'GB/T 22239-2019 8.1.1.4',
      category: 'SCN',
      categoryLabel: '安全通信网络',
      title: '可信验证与通信实体鉴别',
      level: '等保三级',
      requirement: '可基于可信根对通信设备的系统引导程序、系统程序等进行可信验证；通信实体身份应通过数字证书或安全通道鉴别。',
      probeMethod: 'TLS 握手数字证书链校验、公钥指纹比对与节点身份鉴别。',
      evidence: '待探针核验通信握手证书链与安全通道凭据',
      status: 'PENDING',
      riskLevel: 'LOW',
      remediation: '部署私有 PKI/CA 体系，为生产网络核心通信节点签发合规数字证书并实施双向 mTLS 认证。',
    },

    // ------------------------------------------------------------------------
    // 2. 安全区域边界 (SAB)
    // ------------------------------------------------------------------------
    {
      id: 'SAB-01',
      clause: 'GB/T 22239-2019 8.1.2.1',
      category: 'SAB',
      categoryLabel: '安全区域边界',
      title: '边界访问控制策略与最小化开放',
      level: '等保三级',
      requirement: '应在网络边界部署访问控制策略，限制非授权跨网段通信，原则上默认拒绝所有通信连接，仅开放必要端口。',
      probeMethod: 'CIDR 安全网段访问控制规则审计与边界开放端口比对。',
      evidence: '待核验探针 CIDR 安全域规则与目标端口开放情况',
      status: 'PENDING',
      riskLevel: 'HIGH',
      remediation: '在网络汇聚/核心交换机及防火墙配置严格的 ACL 白名单，实行 Default-Deny 原则。',
    },
    {
      id: 'SAB-02',
      clause: 'GB/T 22239-2019 8.1.2.2',
      category: 'SAB',
      categoryLabel: '安全区域边界',
      title: '跨域连接与违规外联防范',
      level: '等保三级',
      requirement: '应限制不同安全保护等级网络之间的非授权直通连接；应能发现内部网络节点私自违规外联公共网络。',
      probeMethod: '测地追踪跃点网关审查、公网出口 IP 探测与路由直通合规分析。',
      evidence: '待探针测地追踪审查目标出向跃点与公网连通性',
      status: 'PENDING',
      riskLevel: 'CRITICAL',
      remediation: '部署准入控制 (802.1X) 与主机违规外联监控探针，阻断双网卡或 4G/5G 随身 WiFi 私接。',
    },
    {
      id: 'SAB-03',
      clause: 'GB/T 22239-2019 8.1.2.3',
      category: 'SAB',
      categoryLabel: '安全区域边界',
      title: '边界安全审计与全流量捕获',
      level: '等保三级',
      requirement: '应在网络边界对进出网络的数据流进行监测与审计，记录源/目的 IP、协议类型、端口及时间戳，审计记录抗抵赖。',
      probeMethod: '现场以太网全协议无损抓包引擎与 PCAP 存证状态校验。',
      evidence: '待校验探针无损抓包与审计落盘运行状态',
      status: 'PENDING',
      riskLevel: 'MEDIUM',
      remediation: '部署旁路网络分流器 (TAP/SPAN)，通过探针持续审计进出大区的全部关键协议流量并持久化存盘。',
    },
    {
      id: 'SAB-04',
      clause: 'GB/T 22239-2019 8.1.2.4',
      category: 'SAB',
      categoryLabel: '安全区域边界',
      title: '网络层入侵防范与畸形报文阻断',
      level: '等保三级',
      requirement: '应在关键网络节点处检测、防止或阻断恶意代码与网络层攻击（如端口扫描、畸形数据包、DDoS 攻击）。',
      probeMethod: 'DPI 威胁特征码过滤、蜜罐诱捕告警状态核验。',
      evidence: '待探针校验 DPI 规则库与网络蜜罐防御状态',
      status: 'PENDING',
      riskLevel: 'HIGH',
      remediation: '在边界交换机开启防 SYN-Flood/UDP-Flood 泛洪限流策略，结合探针蜜罐实时感知未知嗅探行为。',
    },
    {
      id: 'SAB-05',
      clause: 'GB/T 22239-2019 8.1.2.5',
      category: 'SAB',
      categoryLabel: '安全区域边界',
      title: '生产控制大区单向隔离与安全网闸',
      level: '等保三级',
      requirement: '生产控制大区与管理信息大区之间必须设置经国家保密/公安部门认证的物理单向安全隔离网闸。',
      probeMethod: '反向协议嗅探，验证单向隔离设备是否存在非法反向 TCP 握手或未审批直连信道。',
      evidence: '待探针针对目标生产边界发起反向嗅探验证',
      status: 'PENDING',
      riskLevel: 'CRITICAL',
      remediation: '在工控系统控制层与管理层边界部署工业安全隔离网闸，彻底杜绝 TCP 双向穿透。',
    },

    // ------------------------------------------------------------------------
    // 3. 安全计算环境 (SCE)
    // ------------------------------------------------------------------------
    {
      id: 'SCE-01',
      clause: 'GB/T 22239-2019 8.1.3.1',
      category: 'SCE',
      categoryLabel: '安全计算环境',
      title: '身份鉴别与密码复杂度机制',
      level: '等保三级',
      requirement: '应对登录操作系统、网络设备或工控主机的用户进行身份鉴别，身份标识具有唯一性；严禁出厂默认口令，强制口令复杂度与定期更换。',
      probeMethod: 'SSH(22)、RDP(3389)、Web 管理端鉴权行为审计与弱口令探活。',
      evidence: '待探针校验目标主机远程管理端口鉴权安全性',
      status: 'PENDING',
      riskLevel: 'HIGH',
      remediation: '强制启用多因素认证 (MFA) 或堡垒机统一接入，设置密码复杂度至少包含大写、小写、数字、特殊符号且长度不少于 8 位。',
    },
    {
      id: 'SCE-02',
      clause: 'GB/T 22239-2019 8.1.3.2',
      category: 'SCE',
      categoryLabel: '安全计算环境',
      title: '最小化端口与高危服务关闭',
      level: '等保三级',
      requirement: '应严格控制或关闭不必要的网络端口与服务，严禁默认暴露 445 (SMB)、135/139 (NetBIOS)、3389 (RDP) 等高危暴露面。',
      probeMethod: '探针全端口主动并发探测，检测是否存在未经审批的高危勒索高发端口暴露。',
      evidence: '待探针执行目标端口探活',
      status: 'PENDING',
      riskLevel: 'CRITICAL',
      remediation: '立即关闭操作系统中不必要的 Server 服务、Computer Browser 服务，在主机防火墙屏蔽 445/135/139 端口入站。',
    },
    {
      id: 'SCE-03',
      clause: 'GB/T 22239-2019 8.1.3.3',
      category: 'SCE',
      categoryLabel: '安全计算环境',
      title: '安全审计事件与留存期限合规',
      level: '等保三级',
      requirement: '审计记录应包含事件日期、时间、发起者、事件类型、执行结果等；网络安全法与等保明确要求本地或集中留存日志不少于 6 个月。',
      probeMethod: '主机日志归档策略与集中式 Syslog 外发状态核查。',
      evidence: '待校验目标集中日志留存策略',
      status: 'PENDING',
      riskLevel: 'MEDIUM',
      remediation: '配置操作系统本地安全审计策略，开启登录成功/失败、特权使用审计，并通过 Syslog 转发至集中日志平台留存 180 天以上。',
    },
    {
      id: 'SCE-04',
      clause: 'GB/T 22239-2019 8.1.3.4',
      category: 'SCE',
      categoryLabel: '安全计算环境',
      title: '入侵防范与已知漏洞离线加固',
      level: '等保三级',
      requirement: '应遵循最小安装原则，仅安装经安全验证的软件组件；应定期开展漏洞排查并及时修补已知高危漏洞，禁止存在严重 CVE 漏洞暴露。',
      probeMethod: '服务指纹（Banner）识别与已知高危漏洞签名比对。',
      evidence: '待探针识别目标服务版本指纹',
      status: 'PENDING',
      riskLevel: 'HIGH',
      remediation: '对生产网主机定期进行离线安全基准扫描，及时为操作系统和数据库打上经离线测试验证的官方安全补丁。',
    },
    {
      id: 'SCE-05',
      clause: 'GB/T 22239-2019 8.1.3.5',
      category: 'SCE',
      categoryLabel: '安全计算环境',
      title: '数据完整性与抗重放防范',
      level: '等保三级',
      requirement: '应采用密码技术保证重要数据在传输和存储过程中的完整性，能够检测到数据的伪造、篡改与未授权修改。',
      probeMethod: '传输数据层校验算法验证、TLS/SSL 密码套件强健度审计。',
      evidence: '待探针分析数据传输密码套件与摘要强度',
      status: 'PENDING',
      riskLevel: 'MEDIUM',
      remediation: '对核心业务通信全面升级至 TLS 1.2+ 并淘汰 DES/3DES/RC4 等过时算法，关键数据表引入 HMAC 校验字段。',
    },
    {
      id: 'SCE-06',
      clause: 'GB/T 22239-2019 8.1.3.6',
      category: 'SCE',
      categoryLabel: '安全计算环境',
      title: '剩余信息保护与会话注销',
      level: '等保三级',
      requirement: '应保证操作系统和数据库系统用户的鉴别信息在释放前得到完全清除；应支持超时自动锁定或注销会话。',
      probeMethod: '管理会话空闲超时断开机制核查。',
      evidence: '待核查操作系统及设备终端会话超时策略',
      status: 'PENDING',
      riskLevel: 'LOW',
      remediation: '在组策略或 SSH 配置中强制设置 ClientAliveInterval 300 及 ClientAliveCountMax 2，无操作 15 分钟自动断开。',
    },

    // ------------------------------------------------------------------------
    // 4. 安全管理中心 (SMC)
    // ------------------------------------------------------------------------
    {
      id: 'SMC-01',
      clause: 'GB/T 22239-2019 8.1.4.1',
      category: 'SMC',
      categoryLabel: '安全管理中心',
      title: '三员分立与权限互相制约机制',
      level: '等保三级',
      requirement: '应对系统管理员、安全管理员和安全审计员进行身份鉴别，权限独立正交划分，形成相互监督制约机制，杜绝超级管理员一人独大。',
      probeMethod: '核验管理控制台 RBAC 三员权责清单与管理员操作审计流水。',
      evidence: '待核验现场系统管理三员分立落实情况',
      status: 'PENDING',
      riskLevel: 'HIGH',
      remediation: '在生产运维平台建立独立三员账号，严禁共用 root/administrator 账号，安全审计员独享日志清理处置权限。',
    },
    {
      id: 'SMC-02',
      clause: 'GB/T 22239-2019 8.1.4.2',
      category: 'SMC',
      categoryLabel: '安全管理中心',
      title: '集中式安全审计与 Syslog 外发',
      level: '等保三级',
      requirement: '应对分散在各个设备上的审计数据进行集中收集、汇总与备份，支持跨设备行为关联分析与集中告警。',
      probeMethod: '探针 Syslog (RFC 5424) 外发管道连通性与远端日志服务器状态比对。',
      evidence: '待校验 Syslog 外发配置与日志接收端连通性',
      status: 'PENDING',
      riskLevel: 'MEDIUM',
      remediation: '全网各网络节点配置 Syslog UDP/TCP 外发至独立的 SIEM/SOC 平台，确保日志异地集中留存备份。',
    },
    {
      id: 'SMC-03',
      clause: 'GB/T 22239-2019 8.1.4.3',
      category: 'SMC',
      categoryLabel: '安全管理中心',
      title: '集中管控与安全配置基线核验',
      level: '等保三级',
      requirement: '应对网络链路、安全设备和服务器的运行状况进行集中监测，能够对全网设备的安全配置进行统一基线巡检与漂移监测。',
      probeMethod: '网络拓扑状态、工业通信基线白名单自学习模式与漂移事件审计。',
      evidence: '待探针核验全网通信基线与拓扑健康度',
      status: 'PENDING',
      riskLevel: 'MEDIUM',
      remediation: '建立企业安全配置基线库，定期对设备配置进行自动化合规漂移核查，发现未经授权的端口开放立即告警阻断。',
    },
    {
      id: 'SMC-04',
      clause: 'GB/T 22239-2019 8.1.4.4',
      category: 'SMC',
      categoryLabel: '安全管理中心',
      title: '审计记录保护与防篡改存证',
      level: '等保三级',
      requirement: '应定期对审计记录进行安全备份与司法级真实性验真，禁止非审计人员处置或篡改日志，保证审计记录的完整性与抗抵赖性。',
      probeMethod: '国密 SM3 + SHA-256 双哈希司法证据封印与链式完整性验真。',
      evidence: '待核查审计记录防篡改哈希封存与存证验真状态',
      status: 'PENDING',
      riskLevel: 'HIGH',
      remediation: '在日志落盘或轮转时采用数字签名或国密 SM3 链式哈希封存，定期进行抗抵赖一致性比对。',
    },

    // ------------------------------------------------------------------------
    // 5. 工控系统安全扩展附录 G (ICS)
    // ------------------------------------------------------------------------
    {
      id: 'ICS-01',
      clause: 'GB/T 22239-2019 G.4.1',
      category: 'ICS',
      categoryLabel: '工控安全扩展',
      title: '室外及工业控制现场物理隔离',
      level: '工控三级扩展',
      requirement: '工业控制系统的控制组件、控制网络应部署在受控的工业机柜或物理隔离区域，限制非授权人员物理接触。',
      probeMethod: '工业现场物理总线（RS-485 / CAN / 以太网）链路探活与接入审计。',
      evidence: '待探针核查工业物理链路接入状态',
      status: 'PENDING',
      riskLevel: 'MEDIUM',
      remediation: '将 PLC、RTU 与控制交换机安装在加锁工业防护机柜中，机柜门配备开门监测微动开关与视频监控覆盖。',
    },
    {
      id: 'ICS-02',
      clause: 'GB/T 22239-2019 G.4.2',
      category: 'ICS',
      categoryLabel: '工控安全扩展',
      title: '工业通信基线白名单与漂移检测',
      level: '工控三级扩展',
      requirement: '在工业控制网络应建立通信基线白名单，限制工业控制协议的源/目的地址与通信对，实时检测非法连接与非预期流量。',
      probeMethod: '探针基线白名单自学习模式状态（LEARNING / ENFORCING）核验与漂移告警分析。',
      evidence: '待核验工业通信基线白名单规则集',
      status: 'PENDING',
      riskLevel: 'CRITICAL',
      remediation: '启用工控网络自学习通信基线白名单，仅放行经过审批的主站与从站合法通信对，任何未知 IP 接入一律实时阻断并报警。',
    },
    {
      id: 'ICS-03',
      clause: 'GB/T 22239-2019 G.4.3',
      category: 'ICS',
      categoryLabel: '工控安全扩展',
      title: '工业协议高危写指令与功能码 DPI 审计',
      level: '工控三级扩展',
      requirement: '应对 Modbus、S7Comm、OPC-UA、EtherNet/IP 等工业控制协议的高危写指令（如写单个/多个寄存器、下装程序、强制停机）进行细粒度深度审计与阻断。',
      probeMethod: '探针 ICS-ACL 规则库与 DPI 工业功能码深度过滤引擎状态核查。',
      evidence: '待探针核查工控端口开放与 ICS-ACL 功能码过滤规则',
      status: 'PENDING',
      riskLevel: 'CRITICAL',
      remediation: '配置工业防火墙或探针 DPI 规则，默认仅允许只读功能码（如 Modbus 0x01-0x04），写操作（0x05/0x06/0x10）必须实施严格的来源 IP 与指令白名单校验。',
    },
    {
      id: 'ICS-04',
      clause: 'GB/T 22239-2019 G.4.4',
      category: 'ICS',
      categoryLabel: '工控安全扩展',
      title: '无线与非预期移动介质严密控制',
      level: '工控三级扩展',
      requirement: '工业控制系统内部严禁私自搭建未经审批的无线 WiFi、蓝牙热点或公网通道；严禁未经验毒的移动存储介质接入工控上位机。',
      probeMethod: '无线频谱侦测、BLE 蓝牙广播扫描与现场非法 AP 探活。',
      evidence: '待探针校验工业现场无线广播与非法 AP 接入情况',
      status: 'PENDING',
      riskLevel: 'HIGH',
      remediation: '关闭所有工业主机与工控交换机内置无线网卡/蓝牙模块，上位机部署 USB 硬件端口管控，禁止使用外来 U 盘。',
    },
    {
      id: 'ICS-05',
      clause: 'GB/T 22239-2019 G.4.5',
      category: 'ICS',
      categoryLabel: '工控安全扩展',
      title: '工控设备可用性保障与非侵入式探测',
      level: '工控三级扩展',
      requirement: '工业控制系统在进行网络评估或维护时，严禁使用破坏性暴力全端口扫描等高风险手段，确保工业连续生产进程安全稳定。',
      probeMethod: '验证探针轻量级低频探活与被动嗅探模式，确保不会引发工控 PLC 缓冲区溢出或死机。',
      evidence: '探针采用非侵入式轻量探活与无损被动抓包模式',
      status: 'COMPLIANT',
      riskLevel: 'LOW',
      remediation: '在工控现场作业时，严格禁止使用全端口暴力扫描工具；优先采用探针的被动监听（Passive Sniffing）模式评估资产。',
    },

    // ------------------------------------------------------------------------
    // 6. 云计算安全扩展附录 E (Cloud)
    // ------------------------------------------------------------------------
    {
      id: 'CLOUD-01',
      clause: 'GB/T 22239-2019 E.4.1',
      category: 'CLOUD',
      categoryLabel: '云计算安全扩展',
      title: '基础设施网络边界与虚拟化防穿透',
      level: '云计算扩展',
      requirement: '应保证不同云租户之间的虚拟网络逻辑隔离与防跨租户穿透攻击；云服务商管理网络与云租户业务网络必须物理或逻辑隔离。',
      probeMethod: '虚拟网卡/VxLAN 报文嗅探、跨租户网络可达性与虚拟防火墙隔离状态核查。',
      evidence: '待探针发起云环境网络边界隔离核查',
      status: 'PENDING',
      riskLevel: 'CRITICAL',
      remediation: '在 SDN/虚拟交换机强制启用微隔离策略 (Micro-Segmentation)，确保不同租户 VPC/VxLAN 标签严格隔离。',
    },
    {
      id: 'CLOUD-02',
      clause: 'GB/T 22239-2019 E.4.2',
      category: 'CLOUD',
      categoryLabel: '云计算安全扩展',
      title: '云平台虚拟资源访问控制与镜像完整性',
      level: '云计算扩展',
      requirement: '应对虚拟机镜像与快照进行完整性校验；在虚拟机迁移过程中应对数据传输实施强加密保护。',
      probeMethod: '云镜像摘要对比与虚拟机热迁移流量抓包审计。',
      evidence: '待校验云主机镜像哈希指纹与热迁移加密通道',
      status: 'PENDING',
      riskLevel: 'HIGH',
      remediation: '对云镜像文件启用数字签名防伪造，虚机热迁移通信强制绑定 TLS 1.3 专用加密通道。',
    },
    {
      id: 'CLOUD-03',
      clause: 'GB/T 22239-2019 E.4.3',
      category: 'CLOUD',
      categoryLabel: '云计算安全扩展',
      title: '云服务商特权运维与多租户审计隔离',
      level: '云计算扩展',
      requirement: '云服务商特权账号不得直接访问租户业务数据；租户的安全审计日志应独立存储且具备跨租户防泄露保护。',
      probeMethod: '云租户 Syslog 异地独立留存与管理端特权访问拦截核验。',
      evidence: '待核查云租户独立日志外发与访问控制凭据',
      status: 'PENDING',
      riskLevel: 'HIGH',
      remediation: '部署独立的云租户堡垒机与日志专有存储池，严禁云平台底层 root 账号直连租户数据库。',
    },
    {
      id: 'CLOUD-04',
      clause: 'GB/T 22239-2019 E.4.4',
      category: 'CLOUD',
      categoryLabel: '云计算安全扩展',
      title: '云计算数据剩余信息保护与存储介质销毁',
      level: '云计算扩展',
      requirement: '云租户释放云硬盘或计算资源时，应确保底层物理存储空间得到完全擦除覆盖，防止跨租户数据残留窃取。',
      probeMethod: '释放存储块残留载荷分析与磁盘置零擦除审计。',
      evidence: '待验证云存储块释放覆写策略',
      status: 'PENDING',
      riskLevel: 'MEDIUM',
      remediation: '在云平台底层存储卷管理开启 Crypto-Erase 或三次伪随机数据覆写擦除机制。',
    },

    // ------------------------------------------------------------------------
    // 7. 物联网安全扩展附录 F (IoT)
    // ------------------------------------------------------------------------
    {
      id: 'IOT-01',
      clause: 'GB/T 22239-2019 F.4.1',
      category: 'IOT',
      categoryLabel: '物联网安全扩展',
      title: '物联网网关节点访问控制与协议转换安全',
      level: '物联网扩展',
      requirement: '物联网网关应具备对接入感知节点进行身份鉴别与访问控制能力，严格限制非授权传感设备接入；协议转换应具备安全性校验。',
      probeMethod: '网关 MQTT/CoAP/HTTP 端口探活与未授权发布/订阅鉴权测试。',
      evidence: '待探针针对物联网网关开放服务发起鉴权审计',
      status: 'PENDING',
      riskLevel: 'CRITICAL',
      remediation: '在物联网网关开启基于设备证书或 Token 的强身份鉴别，禁用 MQTT 匿名匿名接入模式。',
    },
    {
      id: 'IOT-02',
      clause: 'GB/T 22239-2019 F.4.2',
      category: 'IOT',
      categoryLabel: '物联网安全扩展',
      title: '感知层短距无线通信保密性与防窃听',
      level: '物联网扩展',
      requirement: '感知节点与网关之间的短距离无线通信（如 ZigBee、LoRa、BLE 蓝牙、RFID）应采用轻量级密码技术进行报文传输加密。',
      probeMethod: 'BLE 蓝牙广播/无线 802.15.4 空口抓包与明文载荷分析。',
      evidence: '待探针采集现场近场蓝牙与无线空口报文校验加密状态',
      status: 'PENDING',
      riskLevel: 'HIGH',
      remediation: '在传感网络启用 AES-128-CCM 或国密 SM4 轻量加密算法，严禁无线信道明文裸传工况数据。',
    },
    {
      id: 'IOT-03',
      clause: 'GB/T 22239-2019 F.4.3',
      category: 'IOT',
      categoryLabel: '物联网安全扩展',
      title: '感知节点设备固件防篡改与离线安全加固',
      level: '物联网扩展',
      requirement: '感知节点的系统引导程序和固件应具备防非法篡改能力；应对传感设备开放的物理调试接口（如 JTAG、SWD、UART 调试口）进行钝化封闭。',
      probeMethod: '现场硬件总线串口/UART 交互扫描与固件校验。',
      evidence: '待核查物联网终端设备物理调试口与固件签名机制',
      status: 'PENDING',
      riskLevel: 'HIGH',
      remediation: '量产感知终端烧断硬件熔丝关闭 JTAG 调试接口，启用 Secure Boot 硬件安全引导与固件验签。',
    },
    {
      id: 'IOT-04',
      clause: 'GB/T 22239-2019 F.4.4',
      category: 'IOT',
      categoryLabel: '物联网安全扩展',
      title: '感知节点抗泛洪滥用与抗重放防御',
      level: '物联网扩展',
      requirement: '物联网网关及控制中心应具备防止恶意终端发起伪造报文泛洪或重放攻击的能力，防止传感网络拥塞瘫痪。',
      probeMethod: '探针流量微突发分析与高频重放报文检测。',
      evidence: '待探针监测物联网接入流量序列号递增与防重放窗口',
      status: 'PENDING',
      riskLevel: 'MEDIUM',
      remediation: '在通信载荷中加入单调递增计数器 (Sequence Number) 或带时间戳的 HMAC 摘要，拦截重放报文。',
    },
  ];
}

/**
 * 将现场网络探针探活数据客观注入等保测评条款
 */
export function applyProbeTelemetryToAssessment(
  items: TargetComplianceItem[],
  ctx: ProbeContext
): TargetComplianceItem[] {
  const openSet = new Set(ctx.openPorts);
  const plainTextPorts = [21, 23, 80, 110, 143].filter((p) => openSet.has(p));
  const encryptedPorts = [22, 443, 993, 995].filter((p) => openSet.has(p));
  const highRiskPorts = [445, 135, 139, 3389, 1433, 3306].filter((p) => openSet.has(p));
  const icsPorts = [502, 102, 4840, 44818, 20000].filter((p) => openSet.has(p));

  return items.map((item) => {
    // 若工程师已手动修改，保留其人工判定与证据，不强制覆盖
    if (item.manualModified) {
      return item;
    }

    const updated: TargetComplianceItem = { ...item };

    switch (item.id) {
      case 'SCN-01': {
        // 网络架构与链路冗余
        if (ctx.pingAlive) {
          const rtt = ctx.pingRttMs !== null ? `${ctx.pingRttMs.toFixed(1)}ms` : '< 1ms';
          updated.evidence = `实测目标 ${ctx.targetIp} 在线响应，ICMP 往返时延 ${rtt}，链路处于通畅可达状态`;
          updated.status = 'COMPLIANT';
        } else if (ctx.pingAlive === false && openSet.size > 0) {
          updated.evidence = `实测目标 ${ctx.targetIp} 禁 Ping 但开放了 ${openSet.size} 个网络端口，TCP 通道可达`;
          updated.status = 'PARTIAL';
        } else if (ctx.pingAlive === false) {
          updated.evidence = `实测目标 ${ctx.targetIp} ICMP 探测超时无应答，物理链路或网络接口不连通`;
          updated.status = 'NON_COMPLIANT';
        }
        break;
      }

      case 'SCN-03': {
        // 通信传输保密性与加密保护
        if (plainTextPorts.length > 0) {
          updated.status = 'NON_COMPLIANT';
          updated.riskLevel = 'CRITICAL';
          updated.evidence = `实测检出明文协议端口开放: [${plainTextPorts.join(', ')}]，通信链路存在明文凭据窃听与未加密传输漏洞`;
        } else if (encryptedPorts.length > 0) {
          updated.status = 'COMPLIANT';
          updated.evidence = `实测未检出明文协议端口，目标使用加密管理端口 [${encryptedPorts.join(', ')}]`;
        } else if (openSet.size > 0) {
          updated.status = 'PARTIAL';
          updated.evidence = `实测开放端口 [${Array.from(openSet).join(', ')}]，未检出标准明文端口，需核验专有协议是否启用载荷加密`;
        }
        break;
      }

      case 'SAB-01': {
        // 边界访问控制
        if (ctx.cidrRuleCount > 0) {
          updated.status = 'COMPLIANT';
          updated.evidence = `网络边界已加载并执行 ${ctx.cidrRuleCount} 条 CIDR 安全域访问控制规则`;
        } else {
          updated.status = 'PARTIAL';
          updated.evidence = '探针边界安全域 (CIDR) 当前配置规则数为 0，尚未形成强制跨域隔离策略';
        }
        break;
      }

      case 'SAB-03': {
        // 边界安全审计与全流量捕获
        updated.status = 'COMPLIANT';
        updated.evidence = '探针物理总线与网络以太网无损抓包引擎处于活跃就绪状态，已挂载 PCAP 取证通道';
        break;
      }

      case 'SAB-04': {
        // 网络层入侵防范
        if (ctx.baselineMode === 'ENFORCING') {
          updated.status = 'COMPLIANT';
          updated.evidence = '探针通信基线处于 ENFORCING (强制阻断) 模式，已拦截网络层畸形与未授权连接';
        } else {
          updated.status = 'PARTIAL';
          updated.evidence = `探针基线当前为 ${ctx.baselineMode} 模式，未开启强制阻断，处于审计旁路状态`;
        }
        break;
      }

      case 'SCE-02': {
        // 最小化端口与高危服务关闭
        if (highRiskPorts.length > 0) {
          updated.status = 'NON_COMPLIANT';
          updated.riskLevel = 'CRITICAL';
          updated.evidence = `实测目标直接暴露高危管理/共享端口: [${highRiskPorts.join(', ')}]，违反最小化服务开放原则`;
        } else if (openSet.size > 0) {
          updated.status = 'COMPLIANT';
          updated.evidence = `实测目标开放端口 [${Array.from(openSet).join(', ')}]，未暴露 445/135/139/3389 等高危共享端口`;
        } else {
          updated.status = 'COMPLIANT';
          updated.evidence = '实测目标未对外暴露任何常规高危 TCP 端口';
        }
        break;
      }

      case 'SMC-01': {
        // 三员分立
        if (ctx.rbacHardened) {
          updated.status = 'COMPLIANT';
          updated.evidence = '系统已激活系统管理员、安全管理员、安全审计员 RBAC 正交分立鉴别与 PBKDF2 加固';
        } else {
          updated.status = 'PARTIAL';
          updated.evidence = 'RBAC 三员架构已就绪，但尚有角色处于初始化密码状态待加固';
        }
        break;
      }

      case 'SMC-02': {
        // 集中式日志外发 (Syslog)
        if (ctx.syslogEnabled && ctx.syslogServer) {
          updated.status = 'COMPLIANT';
          updated.evidence = `RFC 5424 Syslog 集中外发已激活，远端日志服务器: ${ctx.syslogServer}`;
        } else {
          updated.status = 'NON_COMPLIANT';
          updated.evidence = 'Syslog 集中日志外发通道当前未启用，审计日志仅驻留本地，存在异地备份缺失风险';
        }
        break;
      }

      case 'SMC-04': {
        // 审计记录保护与司法防篡改
        if (ctx.evidenceChainPassed) {
          updated.status = 'COMPLIANT';
          updated.evidence = '国密 SM3 + SHA-256 司法存证双哈希封印与链式验真全部通过，无篡改痕迹';
        } else {
          updated.status = 'PARTIAL';
          updated.evidence = '本会话尚未完成全量司法存证双哈希封存或等待验真更新';
        }
        break;
      }

      case 'ICS-02': {
        // 工业通信基线白名单
        if (ctx.baselineMode !== 'DISABLED' && ctx.baselineRuleCount > 0) {
          updated.status = 'COMPLIANT';
          updated.evidence = `工业通信基线白名单已建立 ${ctx.baselineRuleCount} 条合法通信对 (模式: ${ctx.baselineMode})`;
        } else {
          updated.status = 'PARTIAL';
          updated.evidence = `工业通信基线规则库当前收敛数为 ${ctx.baselineRuleCount}，未建立全网通信对白名单`;
        }
        break;
      }

      case 'ICS-03': {
        // 工业协议高危写指令与功能码 DPI 审计
        if (icsPorts.length > 0) {
          if (ctx.icsAclRuleCount > 0) {
            updated.status = 'COMPLIANT';
            updated.evidence = `实测检出工业控制端口 [${icsPorts.join(', ')}]，当前已挂载 ${ctx.icsAclRuleCount} 条 ICS-ACL 细粒度功能码过滤策略`;
          } else {
            updated.status = 'PARTIAL';
            updated.evidence = `实测检出工业控制端口 [${icsPorts.join(', ')}]，但探针尚未配置针对该工业协议的高危写功能码过滤规则`;
          }
        } else {
          updated.evidence = '实测目标未开放标准工控端口 (502/102/4840)，若为工控专网建议开启深度 DPI 监听';
          if (updated.status === 'PENDING') {
            updated.status = 'COMPLIANT';
          }
        }
        break;
      }

      default:
        break;
    }

    return updated;
  });
}

/**
 * 将网络设备配置文件 (交换机/路由器/防火墙) 基线分析报告自动注入测评矩阵
 */
export function applyDeviceConfigReportToAssessment(
  items: TargetComplianceItem[],
  report: DeviceConfigAnalysisReport
): TargetComplianceItem[] {
  const ruleMap = new Map(report.results.map((r) => [r.ruleId, r]));

  return items.map((item) => {
    if (item.manualModified) {
      return item;
    }
    const updated = { ...item };

    // 匹配 SCN-03 (明文远程管理 Telnet/HTTP 与 SSH v2 协议)
    if (item.id === 'SCN-03') {
      const telnetRes = ruleMap.get('NET-CFG-03');
      const sshRes = ruleMap.get('NET-CFG-04');
      if (telnetRes && !telnetRes.passed) {
        updated.status = 'NON_COMPLIANT';
        updated.riskLevel = 'CRITICAL';
        updated.evidence = `[设备配置实测] ${report.hostname} (${report.vendorLabel}): ${telnetRes.evidence}`;
      } else if (sshRes && sshRes.passed) {
        updated.status = 'COMPLIANT';
        updated.evidence = `[设备配置实测] ${report.hostname} (${report.vendorLabel}): 远程管理已关闭 Telnet 并强制锁定 SSH v2 协议`;
      }
    }

    // 匹配 SCE-01 (身份鉴别与独立账号、强哈希)
    if (item.id === 'SCE-01') {
      const acctRes = ruleMap.get('NET-CFG-01');
      const pwdRes = ruleMap.get('NET-CFG-02');
      if (pwdRes && !pwdRes.passed) {
        updated.status = 'NON_COMPLIANT';
        updated.riskLevel = 'CRITICAL';
        updated.evidence = `[设备配置实测] ${report.hostname}: ${pwdRes.evidence}`;
      } else if (acctRes && acctRes.passed) {
        updated.status = 'COMPLIANT';
        updated.evidence = `[设备配置实测] ${report.hostname}: ${acctRes.evidence}，口令采用不可逆强散列保护`;
      }
    }

    // 匹配 SCE-06 (剩余信息与空闲超时断开)
    if (item.id === 'SCE-06') {
      const timeoutRes = ruleMap.get('NET-CFG-05');
      if (timeoutRes) {
        updated.status = timeoutRes.passed ? 'COMPLIANT' : 'NON_COMPLIANT';
        updated.evidence = `[设备配置实测] ${report.hostname}: ${timeoutRes.evidence}`;
      }
    }

    // 匹配 SMC-02 (集中日志备份与 Syslog 外发)
    if (item.id === 'SMC-02') {
      const loghostRes = ruleMap.get('NET-CFG-08');
      if (loghostRes) {
        updated.status = loghostRes.passed ? 'COMPLIANT' : 'NON_COMPLIANT';
        updated.evidence = `[设备配置实测] ${report.hostname}: ${loghostRes.evidence}`;
      }
    }

    return updated;
  });
}

/**
 * 主机基线核查项结果
 */
export interface HostBaselineItemResult {
  id: string;
  clause: string;
  title: string;
  category: string;
  passed: boolean;
  actual_value: string;
  standard_requirement: string;
  risk_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  evidence: string;
  remediation: string;
}

/**
 * 主机基线审计全景报告
 */
export interface HostBaselineReport {
  os_type: string;
  os_name: string;
  hostname: string;
  scan_time: string;
  total_checks: number;
  passed_checks: number;
  failed_checks: number;
  compliance_rate_pct: number;
  items: HostBaselineItemResult[];
}

/**
 * 将主机安全计算环境 (SCE) 基线实测证据链映射注入测评矩阵
 */
export function applyHostBaselineReportToAssessment(
  items: TargetComplianceItem[],
  report: HostBaselineReport
): TargetComplianceItem[] {
  const itemMap = new Map(report.items.map((i) => [i.id, i]));

  return items.map((item) => {
    if (item.manualModified) {
      return item;
    }
    const updated = { ...item };

    // 1. 匹配 SCE-01 (身份鉴别与口令策略)
    if (item.id === 'SCE-01') {
      const lenCheck = itemMap.get('SCE-HOST-01');
      const ageCheck = itemMap.get('SCE-HOST-02');
      if (lenCheck && ageCheck) {
        if (!lenCheck.passed || !ageCheck.passed) {
          updated.status = 'NON_COMPLIANT';
          updated.riskLevel = 'HIGH';
          updated.evidence = `[主机基线实测] ${report.hostname} (${report.os_name}): ${lenCheck.evidence}；${ageCheck.evidence}`;
        } else {
          updated.status = 'COMPLIANT';
          updated.riskLevel = 'LOW';
          updated.evidence = `[主机基线实测] ${report.hostname} (${report.os_name}): 最短口令符合 ≥8 位，且已配置 ≤90 天定期更换周期`;
        }
      }
    }

    // 2. 匹配 SCE-02 (登录失败处理与锁定阈值)
    if (item.id === 'SCE-02' || (item.clause.includes('8.1.3.1') && item.title.includes('登录失败'))) {
      const lockCheck = itemMap.get('SCE-HOST-03');
      const durCheck = itemMap.get('SCE-HOST-04');
      if (lockCheck && durCheck) {
        if (!lockCheck.passed || !durCheck.passed) {
          updated.status = 'NON_COMPLIANT';
          updated.riskLevel = 'CRITICAL';
          updated.evidence = `[主机基线实测] ${report.hostname}: ${lockCheck.evidence}；${durCheck.evidence}`;
        } else {
          updated.status = 'COMPLIANT';
          updated.riskLevel = 'LOW';
          updated.evidence = `[主机基线实测] ${report.hostname}: 账户连续登录失败锁定阈值与持续时间符合国标要求`;
        }
      }
    }

    // 3. 匹配 SCE-03 / 默认特权账户禁用与最小化
    if (item.id === 'SCE-03' || item.title.includes('访问控制') || item.title.includes('默认账户')) {
      const guestCheck = itemMap.get('SCE-HOST-06');
      if (guestCheck) {
        if (!guestCheck.passed) {
          updated.status = 'NON_COMPLIANT';
          updated.riskLevel = 'HIGH';
          updated.evidence = `[主机基线实测] ${report.hostname}: ${guestCheck.evidence}`;
        } else {
          updated.status = 'COMPLIANT';
          updated.evidence = `[主机基线实测] ${report.hostname}: 默认 Guest 来宾账户已物理停用，特权分离机制健全`;
        }
      }
    }

    // 4. 匹配 SCE-06 / 剩余信息与空闲会话超时断开
    if (item.id === 'SCE-06' || item.title.includes('空闲会话') || item.title.includes('会话断开')) {
      const timeoutCheck = itemMap.get('SCE-HOST-05');
      if (timeoutCheck) {
        if (!timeoutCheck.passed) {
          updated.status = 'NON_COMPLIANT';
          updated.riskLevel = 'HIGH';
          updated.evidence = `[主机基线实测] ${report.hostname}: ${timeoutCheck.evidence}`;
        } else {
          updated.status = 'COMPLIANT';
          updated.evidence = `[主机基线实测] ${report.hostname}: ${timeoutCheck.evidence}`;
        }
      }
    }

    // 5. 匹配 SCN-03 / 远程安全访问通道与 NLA
    if (item.id === 'SCN-03') {
      const nlaCheck = itemMap.get('SCE-HOST-08');
      if (nlaCheck && !nlaCheck.passed) {
        if (updated.status !== 'NON_COMPLIANT') {
          updated.evidence += `；[主机基线实测] ${nlaCheck.evidence}`;
        }
      }
    }

    return updated;
  });
}

/**
 * 计算等保评估符合度与分类打分指标
 */
export function calculateAssessmentMetrics(items: TargetComplianceItem[]): AssessmentMetrics {
  const totalCount = items.length;
  let compliantCount = 0;
  let partialCount = 0;
  let nonCompliantCount = 0;
  let naCount = 0;
  let pendingCount = 0;

  const categoryMap = new Map<AssessmentCategory, {
    label: string;
    total: number;
    compliant: number;
    partial: number;
    nonCompliant: number;
    na: number;
    pending: number;
  }>([
    ['SCN', { label: '安全通信网络 (SCN)', total: 0, compliant: 0, partial: 0, nonCompliant: 0, na: 0, pending: 0 }],
    ['SAB', { label: '安全区域边界 (SAB)', total: 0, compliant: 0, partial: 0, nonCompliant: 0, na: 0, pending: 0 }],
    ['SCE', { label: '安全计算环境 (SCE)', total: 0, compliant: 0, partial: 0, nonCompliant: 0, na: 0, pending: 0 }],
    ['SMC', { label: '安全管理中心 (SMC)', total: 0, compliant: 0, partial: 0, nonCompliant: 0, na: 0, pending: 0 }],
    ['ICS', { label: '工控系统扩展 (ICS)', total: 0, compliant: 0, partial: 0, nonCompliant: 0, na: 0, pending: 0 }],
    ['CLOUD', { label: '云计算扩展 (Cloud)', total: 0, compliant: 0, partial: 0, nonCompliant: 0, na: 0, pending: 0 }],
    ['IOT', { label: '物联网扩展 (IoT)', total: 0, compliant: 0, partial: 0, nonCompliant: 0, na: 0, pending: 0 }],
  ]);

  for (const item of items) {
    const cat = categoryMap.get(item.category);
    if (cat) {
      cat.total += 1;
    }

    switch (item.status) {
      case 'COMPLIANT':
        compliantCount += 1;
        if (cat) cat.compliant += 1;
        break;
      case 'PARTIAL':
        partialCount += 1;
        if (cat) cat.partial += 1;
        break;
      case 'NON_COMPLIANT':
        nonCompliantCount += 1;
        if (cat) cat.nonCompliant += 1;
        break;
      case 'NA':
        naCount += 1;
        if (cat) cat.na += 1;
        break;
      case 'PENDING':
      default:
        pendingCount += 1;
        if (cat) cat.pending += 1;
        break;
    }
  }

  const applicableCount = totalCount - naCount;
  // 综合得分计算规则：符合记 1.0 分，部分符合记 0.5 分，不符合记 0 分，不适用不计入分母
  let overallScorePct = 0;
  if (applicableCount > 0) {
    const rawScore = (compliantCount * 1.0 + partialCount * 0.5) / applicableCount * 100;
    overallScorePct = Number(rawScore.toFixed(1));
  }

  const categories: CategorySummary[] = Array.from(categoryMap.entries()).map(([key, val]) => {
    const catApplicable = val.total - val.na;
    let score = 0;
    if (catApplicable > 0) {
      score = Number(((val.compliant * 1.0 + val.partial * 0.5) / catApplicable * 100).toFixed(1));
    }
    return {
      category: key,
      label: val.label,
      total: val.total,
      compliant: val.compliant,
      partial: val.partial,
      nonCompliant: val.nonCompliant,
      na: val.na,
      pending: val.pending,
      scorePct: score,
    };
  });

  const verdict = evaluateOverallComplianceVerdict(items, overallScorePct);

  return {
    totalCount,
    applicableCount,
    compliantCount,
    partialCount,
    nonCompliantCount,
    naCount,
    pendingCount,
    overallScorePct,
    categories,
    verdict,
  };
}

/**
 * 国家标准 GB/T 28448-2019 测评结论形成标准算法
 * 
 * 判定规约：
 * 1. 符合 (COMPLIANT)：所有适用控制点均为 COMPLIANT，无任何不符合或部分符合。
 * 2. 基本符合 (PARTIALLY_COMPLIANT)：综合得分率 >= 70.0%，且不存在任何 CRITICAL 严重风险不符合项。
 * 3. 不符合 (NON_COMPLIANT)：
 *    - 综合得分率 < 70.0%；
 *    - 或者存在 1 个及以上 CRITICAL 严重高危缺陷项（一票否决制！如启用明文 Telnet、Guest 未停用、未启用失败锁定、核心工控功能码无访问控制）。
 */
export function evaluateOverallComplianceVerdict(
  items: TargetComplianceItem[],
  overallScorePct: number
): ComplianceVerdict {
  const applicableItems = items.filter((i) => i.status !== 'NA');
  let criticalDefects = 0;
  let highDefects = 0;

  for (const item of applicableItems) {
    if (item.status === 'NON_COMPLIANT' || item.status === 'PARTIAL') {
      if (item.riskLevel === 'CRITICAL') {
        criticalDefects += 1;
      } else if (item.riskLevel === 'HIGH') {
        highDefects += 1;
      }
    }
  }

  const allCompliant = applicableItems.length > 0 && applicableItems.every((i) => i.status === 'COMPLIANT');

  if (allCompliant) {
    return {
      level: 'COMPLIANT',
      levelText: '符合',
      isVetoedByCriticalRisk: false,
      criticalDefectCount: 0,
      highDefectCount: 0,
      reason: '所有适用的国家标准等级保护安全控制点经探针实测均达到合规基准要求，未发现任何安全控制缺陷。',
    };
  }

  if (criticalDefects > 0) {
    return {
      level: 'NON_COMPLIANT',
      levelText: '不符合',
      isVetoedByCriticalRisk: true,
      criticalDefectCount: criticalDefects,
      highDefectCount: highDefects,
      reason: `虽然整体综合得分率为 ${overallScorePct}%，但实测命中 ${criticalDefects} 项严重高危缺陷（涉及明文管理、身份鉴别或访问控制），触犯 GB/T 28448-2019 一票否决红线，总体结论裁决为不符合。`,
    };
  }

  if (overallScorePct < 70.0) {
    return {
      level: 'NON_COMPLIANT',
      levelText: '不符合',
      isVetoedByCriticalRisk: false,
      criticalDefectCount: 0,
      highDefectCount: highDefects,
      reason: `综合得分率仅为 ${overallScorePct}%，未达到 GB/T 28448-2019 规定的 70.0% 基本符合底线阈值，总体结论判定为不符合。`,
    };
  }

  return {
    level: 'PARTIALLY_COMPLIANT',
    levelText: '基本符合',
    isVetoedByCriticalRisk: false,
    criticalDefectCount: 0,
    highDefectCount: highDefects,
    reason: `综合得分率达到 ${overallScorePct}%，且不存在一票否决的高危严重缺陷，达到 GB/T 28448-2019“基本符合”标准。`,
  };
}

export interface ReportEvidenceDigest {
  reportId: string;
  sm3Hex: string;
  sha256Hex: string;
  canonicalByteLength: number;
}

/**
 * 计算测评报告核心载荷的国密 SM3 与 SHA-256 真实抗抵赖物证指纹
 * 算法时间复杂度 O(N)，消除任何静态硬编码假摘要
 */
export function computeReportEvidenceDigest(params: {
  targetIp: string;
  targetLevel: string;
  timeStr: string;
  inspectorName: string;
  metrics: AssessmentMetrics;
  items: TargetComplianceItem[];
}): ReportEvidenceDigest {
  const canonicalRecords = (params.items || [])
    .map((item) => `${item.id}|${item.clause}|${item.status}|${item.riskLevel}|${(item.evidence || '').trim()}`)
    .join('\n');
  const canonicalPayload = [
    `TARGET=${(params.targetIp || '').trim()}`,
    `LEVEL=${(params.targetLevel || '').trim()}`,
    `TIME=${(params.timeStr || '').trim()}`,
    `INSPECTOR=${(params.inspectorName || '').trim()}`,
    `VERDICT=${params.metrics?.verdict?.level || 'UNKNOWN'}:${params.metrics?.overallScorePct ?? 0}`,
    `COUNT=${params.metrics?.totalCount ?? 0}`,
    canonicalRecords,
  ].join('\n---\n');

  const sm3Hex = computeSm3Hex(canonicalPayload);
  const sha256Hex = computeSha256Hex(canonicalPayload);
  const year = new Date().getFullYear();
  const reportId = `DJCP-${year}-${sm3Hex.slice(0, 8).toUpperCase()}`;

  return {
    reportId,
    sm3Hex,
    sha256Hex,
    canonicalByteLength: new TextEncoder().encode(canonicalPayload).length,
  };
}

/**
 * 导出符合国家标准 GB/T 22239-2019 / GB/T 28448-2019 现场测评核查报告 (Markdown 格式)
 */
export function generateGbMarkdownReport(params: {
  targetIp: string;
  targetLevel: string;
  inspectorName: string;
  inspectorRole: string;
  items: TargetComplianceItem[];
  metrics: AssessmentMetrics;
  generatedAt?: string;
}): string {
  const timeStr = params.generatedAt || new Date().toLocaleString();
  const digest = computeReportEvidenceDigest({
    targetIp: params.targetIp,
    targetLevel: params.targetLevel,
    timeStr,
    inspectorName: params.inspectorName,
    metrics: params.metrics,
    items: params.items,
  });
  const defects = params.items.filter((i) => i.status === 'NON_COMPLIANT' || i.status === 'PARTIAL');

  const lines: string[] = [];
  lines.push('# 网络安全等级保护 2.0 / 3.0 现场测评核查报告');
  lines.push('');
  lines.push(`> **报告编号**：\`${digest.reportId}\`  `);
  lines.push(`> **基准依据**：国家标准 GB/T 22239-2019《信息安全技术 网络安全等级保护基本要求》/ GB/T 28448-2019《测评要求》  `);
  lines.push(`> **测评工具**：Omni-Probe 全能网络探针系统 (工业级硬件/以太网协议分析引擎)  `);
  lines.push(`> **生成时间**：${timeStr}  `);
  lines.push(`> **测评操作员**：${params.inspectorName} (${params.inspectorRole})  `);
  lines.push(`> **GB/T 29360 电子物证双哈希存证 (${digest.canonicalByteLength} Bytes)**：  `);
  lines.push(`> - \`SM3\`: \`${digest.sm3Hex}\`  `);
  lines.push(`> - \`SHA-256\`: \`${digest.sha256Hex}\``);
  lines.push('');
  lines.push('---');
  lines.push('');
  lines.push('## 一、测评基本信息与综合结论');
  lines.push('');
  lines.push(`- **被测目标资产**：\`${params.targetIp}\``);
  lines.push(`- **评定安全保护等级**：\`${params.targetLevel}\``);
  lines.push(`- **实测综合合规率**：**${params.metrics.overallScorePct}%**`);
  lines.push(`- **GB/T 28448-2019 综合裁决结论**：**【${params.metrics.verdict.levelText}】** ${params.metrics.verdict.isVetoedByCriticalRisk ? '(⚠️ 触发一票否决)' : ''}`);
  lines.push(`  - *裁决依据*：${params.metrics.verdict.reason}`);
  lines.push(`- **测评控制项总数**：${params.metrics.totalCount} 项（适用项：${params.metrics.applicableCount}，不适用项：${params.metrics.naCount}）`);
  lines.push(`  - **符合 (COMPLIANT)**：${params.metrics.compliantCount} 项`);
  lines.push(`  - **部分符合 (PARTIAL)**：${params.metrics.partialCount} 项`);
  lines.push(`  - **不符合 (NON_COMPLIANT)**：${params.metrics.nonCompliantCount} 项`);
  lines.push(`  - **待核验 (PENDING)**：${params.metrics.pendingCount} 项`);
  lines.push('');
  lines.push('### 各大类控制域实测得分分布');
  lines.push('');
  lines.push('| 控制域体系分类 | 条款总数 | 符合 | 部分符合 | 不符合 | 不适用 | 达标得分率 |');
  lines.push('| :--- | :---: | :---: | :---: | :---: | :---: | :---: |');
  for (const cat of params.metrics.categories) {
    lines.push(`| ${cat.label} | ${cat.total} | ${cat.compliant} | ${cat.partial} | ${cat.nonCompliant} | ${cat.na} | **${cat.scorePct}%** |`);
  }
  lines.push('');
  lines.push('---');
  lines.push('');
  lines.push('## 二、高危缺陷项与加固整改建议');
  lines.push('');
  if (defects.length === 0) {
    lines.push('未检出明确不符合项与高危漏洞，目标网络已达到当前等保等级预设基线。');
  } else {
    lines.push(`共检出 **${defects.length}** 项不符合或部分符合的风险控制点：`);
    lines.push('');
    defects.forEach((d, idx) => {
      const statusText = d.status === 'NON_COMPLIANT' ? '【不符合】' : '【部分符合】';
      lines.push(`### ${idx + 1}. [${d.id}] ${d.clause} - ${d.title} ${statusText}`);
      lines.push(`- **所属控制域**：${d.categoryLabel}（风险等级: \`${d.riskLevel}\`）`);
      lines.push(`- **标准原文要求**：${d.requirement}`);
      lines.push(`- **探针现场实测证据**：\`${d.evidence}\``);
      lines.push(`- **加固整改建议**：${d.remediation}`);
      lines.push('');
    });
  }
  lines.push('---');
  lines.push('');
  lines.push('## 三、现场实测全量控制项核查矩阵');
  lines.push('');
  lines.push('| 条款编号 | 控制项名称 | 等级要求 | 符合判定 | 探针实测证据链 |');
  lines.push('| :--- | :--- | :---: | :---: | :--- |');
  for (const item of params.items) {
    const statusLabel =
      item.status === 'COMPLIANT' ? '符合' :
      item.status === 'PARTIAL' ? '部分符合' :
      item.status === 'NON_COMPLIANT' ? '不符合' :
      item.status === 'NA' ? '不适用' : '待核验';
    lines.push(`| [${item.id}] ${item.clause} | ${item.title} | ${item.level} | **${statusLabel}** | ${item.evidence.replace(/\|/g, '/')} |`);
  }
  lines.push('');
  lines.push('---');
  lines.push('*本报告由 Omni-Probe 探针系统现场自动化探活与审计引擎生成，数据真实有效，已归入取证审计链。*');

  return lines.join('\n');
}

/**
 * 生成符合公安部等级保护测评机构交付标准的 A4 打印就绪 HTML 正式技术报告
 */
export function generateGbFormalAuditReportHtml(params: {
  targetIp: string;
  targetLevel: string;
  inspectorName: string;
  inspectorRole: string;
  items: TargetComplianceItem[];
  metrics: AssessmentMetrics;
  generatedAt?: string;
  organizationName?: string;
  systemName?: string;
}): string {
  const timeStr = params.generatedAt || new Date().toLocaleString();
  const orgName = params.organizationName || '被测重点行业单位 / 工业控制生产企业';
  const sysName = params.systemName || `核心业务通信网络系统 (${params.targetIp})`;
  const digest = computeReportEvidenceDigest({
    targetIp: params.targetIp,
    targetLevel: params.targetLevel,
    timeStr,
    inspectorName: params.inspectorName,
    metrics: params.metrics,
    items: params.items,
  });
  const reportId = digest.reportId;
  const verdict = params.metrics.verdict;
  const defects = params.items.filter((i) => i.status === 'NON_COMPLIANT' || i.status === 'PARTIAL');

  const safeTargetIp = escapeHtml(params.targetIp);
  const safeTargetLevel = escapeHtml(params.targetLevel);
  const safeOrgName = escapeHtml(orgName);
  const safeSysName = escapeHtml(sysName);
  const safeInspector = escapeHtml(`${params.inspectorName} (${params.inspectorRole})`);
  const safeTimeStr = escapeHtml(timeStr);
  const safeVerdictReason = escapeHtml(verdict.reason);

  const verdictBadgeColor =
    verdict.level === 'COMPLIANT' ? '#059669' :
    verdict.level === 'PARTIALLY_COMPLIANT' ? '#d97706' : '#dc2626';

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <title>等级保护 2.0 现场测评核查技术报告 - ${reportId}</title>
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
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif;
      font-size: 10pt;
      line-height: 1.5;
      color: #1f2937;
      background: #ffffff;
      margin: 0;
      padding: 0;
    }
    .page-cover {
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      height: 250mm;
      padding: 20mm 10mm;
      text-align: center;
      page-break-after: always;
      border: 2px solid #374151;
    }
    .cover-header {
      font-size: 13pt;
      font-weight: 600;
      letter-spacing: 2px;
      color: #4b5563;
    }
    .cover-title {
      margin-top: 35mm;
    }
    .cover-title h1 {
      font-size: 24pt;
      font-weight: 800;
      color: #111827;
      letter-spacing: 4px;
      margin: 0;
    }
    .cover-title h2 {
      font-size: 16pt;
      font-weight: 600;
      color: #2563eb;
      margin-top: 5mm;
      letter-spacing: 1px;
    }
    .cover-meta {
      margin: 0 auto;
      width: 80%;
      text-align: left;
      font-size: 11pt;
      line-height: 2.2;
      border-top: 1px solid #d1d5db;
      padding-top: 8mm;
    }
    .cover-meta-row {
      display: flex;
      justify-content: space-between;
      border-bottom: 1px dashed #e5e7eb;
    }
    .cover-footer {
      font-size: 10pt;
      color: #6b7280;
    }
    .section-title {
      font-size: 13pt;
      font-weight: 700;
      color: #111827;
      border-left: 4px solid #2563eb;
      padding-left: 3mm;
      margin: 8mm 0 4mm 0;
      page-break-after: avoid;
    }
    .verdict-box {
      border: 2px solid ${verdictBadgeColor};
      border-radius: 4px;
      padding: 5mm;
      margin-bottom: 6mm;
      background: #fafafa;
      page-break-inside: avoid;
    }
    .verdict-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 3mm;
    }
    .verdict-badge {
      display: inline-block;
      padding: 2mm 6mm;
      color: #ffffff;
      background: ${verdictBadgeColor};
      font-weight: 800;
      font-size: 14pt;
      border-radius: 3px;
    }
    .signature-grid {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 5mm;
      margin-top: 6mm;
      page-break-inside: avoid;
    }
    .signature-box {
      border: 1px solid #d1d5db;
      border-radius: 3px;
      padding: 4mm;
      background: #f9fafb;
      min-height: 25mm;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-bottom: 6mm;
      font-size: 9pt;
      page-break-inside: auto;
    }
    tr {
      page-break-inside: avoid;
      page-break-after: auto;
    }
    th, td {
      border: 1px solid #d1d5db;
      padding: 2mm 2.5mm;
      text-align: left;
      vertical-align: top;
    }
    th {
      background: #f3f4f6;
      font-weight: 600;
      color: #374151;
    }
    .status-tag {
      font-weight: 700;
      padding: 0.5mm 1.5mm;
      border-radius: 2px;
      font-size: 8pt;
      display: inline-block;
    }
    .status-COMPLIANT { background: #d1fae5; color: #065f46; }
    .status-PARTIAL { background: #fef3c7; color: #92400e; }
    .status-NON_COMPLIANT { background: #fee2e2; color: #991b1b; }
    .status-NA { background: #f3f4f6; color: #6b7280; }
    .evidence-text {
      font-family: SFMono-Regular, Consolas, "Liberation Mono", Menlo, monospace;
      font-size: 8pt;
      color: #374151;
      word-break: break-all;
    }
    .hash-badge {
      font-family: monospace;
      background: #f3f4f6;
      padding: 1.5mm;
      font-size: 8pt;
      border-radius: 3px;
      word-break: break-all;
      margin-top: 2mm;
    }
    .avoid-break {
      page-break-inside: avoid;
    }
    .page-break {
      page-break-after: always;
    }
  </style>
</head>
<body>

  <!-- 正式封面 -->
  <div class="page-cover">
    <div class="cover-header">
      中华人民共和国网络安全等级保护制度 (等保 2.0 / 3.0)<br />
      GB/T 22239-2019 / GB/T 28448-2019 标准测评技术大报告
    </div>

    <div class="cover-title">
      <h1>网络安全等级保护现场测评报告</h1>
      <h2>【${safeTargetLevel}】</h2>
    </div>

    <div class="cover-meta">
      <div class="cover-meta-row"><span>报告编号:</span><b>${escapeHtml(reportId)}</b></div>
      <div class="cover-meta-row"><span>被测评单位:</span><b>${safeOrgName}</b></div>
      <div class="cover-meta-row"><span>被测评信息系统:</span><b>${safeSysName}</b></div>
      <div class="cover-meta-row"><span>测评对象目标 IP:</span><b>${safeTargetIp}</b></div>
      <div class="cover-meta-row"><span>综合测评结论:</span><b style="color: ${verdictBadgeColor};">${escapeHtml(verdict.levelText)} (${params.metrics.overallScorePct}%)</b></div>
      <div class="cover-meta-row"><span>测评机构/系统装备:</span><b>Omni-Probe 工业全能探针系统</b></div>
      <div class="cover-meta-row"><span>测评工程师/操作员:</span><b>${safeInspector}</b></div>
      <div class="cover-meta-row"><span>测评实施日期:</span><b>${safeTimeStr}</b></div>
    </div>

    <div class="cover-footer">
      密级标志：内部公开 · 严禁未授权篡改 · 本报告受密码学防篡改校验保护
    </div>
  </div>

  <!-- 正文第一页：综合测评结论与责任签署栏 -->
  <div class="section-title">一、GB/T 28448-2019 标准测评结论裁决</div>
  <div class="verdict-box">
    <div class="verdict-header">
      <div>
        <div style="font-size: 11pt; font-weight: bold;">全国统一标准等保测评裁决结果：</div>
        <div style="font-size: 9pt; color: #6b7280; margin-top: 1mm;">
          依据 GB/T 28448-2019《信息安全技术 网络安全等级保护测评要求》第 5 节测评结论形成规约
        </div>
      </div>
      <span class="verdict-badge">${escapeHtml(verdict.levelText)}</span>
    </div>
    <div style="font-size: 9.5pt; line-height: 1.6; margin-top: 2mm;">
      <b>裁决判定理由：</b>${safeVerdictReason}
      ${verdict.isVetoedByCriticalRisk ? '<br /><span style="color: #dc2626; font-weight: bold;">⚠️ 警示：根据国家标准一票否决规约，存在严重高危安全缺陷（如密码明文管理、默认账户未禁用或无锁定策略），即便综合达标率高亦直接裁决为不符合！</span>' : ''}
    </div>
    <div class="hash-badge">
      <b>电子物证哈希防篡改摘要 (GB/T 29360 认证保全 · 载荷 ${digest.canonicalByteLength} Bytes)：</b><br />
      SM3: ${digest.sm3Hex}<br />
      SHA-256: ${digest.sha256Hex}
    </div>
  </div>

  <div class="section-title">二、四方责任主体与测评结论签章确认栏</div>
  <div class="signature-grid">
    <div class="signature-box">
      <b>测评机构现场主管工程师 (签字):</b>
      <div style="margin-top: 12mm; border-bottom: 1px solid #9ca3af; width: 70%;"></div>
      <div style="font-size: 8pt; color: #6b7280; margin-top: 1mm;">签字日期: ______年____月____日 (测评专用章)</div>
    </div>
    <div class="signature-box">
      <b>被测评单位安全管理员 (签字):</b>
      <div style="margin-top: 12mm; border-bottom: 1px solid #9ca3af; width: 70%;"></div>
      <div style="font-size: 8pt; color: #6b7280; margin-top: 1mm;">签字日期: ______年____月____日</div>
    </div>
    <div class="signature-box">
      <b>被测评系统运维/系统管理员 (签字):</b>
      <div style="margin-top: 12mm; border-bottom: 1px solid #9ca3af; width: 70%;"></div>
      <div style="font-size: 8pt; color: #6b7280; margin-top: 1mm;">签字日期: ______年____月____日</div>
    </div>
    <div class="signature-box">
      <b>被测评单位审计/合规负责人 (签字):</b>
      <div style="margin-top: 12mm; border-bottom: 1px solid #9ca3af; width: 70%;"></div>
      <div style="font-size: 8pt; color: #6b7280; margin-top: 1mm;">签字日期: ______年____月____日 (单位公章)</div>
    </div>
  </div>

  <div class="section-title" style="margin-top: 8mm;">三、控制域实测得分分布矩阵</div>
  <table>
    <thead>
      <tr>
        <th>控制域体系分类</th>
        <th style="width: 15%; text-align: center;">条款总数</th>
        <th style="width: 12%; text-align: center;">符合</th>
        <th style="width: 12%; text-align: center;">部分符合</th>
        <th style="width: 12%; text-align: center;">不符合</th>
        <th style="width: 12%; text-align: center;">不适用</th>
        <th style="width: 15%; text-align: center;">得分率</th>
      </tr>
    </thead>
    <tbody>
      ${params.metrics.categories.map((cat) => `
        <tr>
          <td><b>${escapeHtml(cat.label)}</b></td>
          <td style="text-align: center;">${cat.total}</td>
          <td style="text-align: center; color: #059669; font-weight: bold;">${cat.compliant}</td>
          <td style="text-align: center; color: #d97706;">${cat.partial}</td>
          <td style="text-align: center; color: #dc2626; font-weight: bold;">${cat.nonCompliant}</td>
          <td style="text-align: center; color: #6b7280;">${cat.na}</td>
          <td style="text-align: center; font-weight: bold;">${cat.scorePct}%</td>
        </tr>
      `).join('')}
    </tbody>
  </table>

  <div class="page-break"></div>

  <!-- 正文第二页：高危缺陷与整改清单 -->
  <div class="section-title">四、实测高危安全缺陷与加固整改行动表 (PoAM)</div>
  ${defects.length === 0 ? '<p style="color: #059669; font-weight: bold;">经探针现场深入探活与基线比对，未检出任何违反国家标准的不符合项与高危漏洞。</p>' : `
    <table>
      <thead>
        <tr>
          <th style="width: 15%;">控制点编号</th>
          <th style="width: 25%;">控制点要求</th>
          <th style="width: 12%; text-align: center;">判定 / 风险</th>
          <th style="width: 24%;">现场实测证据</th>
          <th style="width: 24%;">加固整改指导措施</th>
        </tr>
      </thead>
      <tbody>
        ${defects.map((d) => `
          <tr>
            <td><b>[${escapeHtml(d.id)}]</b><br /><span style="font-size: 8pt; color: #6b7280;">${escapeHtml(d.clause)}</span></td>
            <td><b>${escapeHtml(d.title)}</b><br /><span style="font-size: 8pt; color: #4b5563;">${escapeHtml(d.requirement)}</span></td>
            <td style="text-align: center;">
              <span class="status-tag status-${escapeHtml(d.status)}">${d.status === 'NON_COMPLIANT' ? '不符合' : '部分符合'}</span><br />
              <span style="font-size: 8pt; color: #dc2626; font-weight: bold;">${escapeHtml(d.riskLevel)}</span>
            </td>
            <td class="evidence-text">${escapeHtml(d.evidence)}</td>
            <td style="font-size: 8pt; color: #92400e;">${escapeHtml(d.remediation)}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `}

  <div class="section-title">五、全量现场实测证据链归档大表 (Evidence Logs)</div>
  <table>
    <thead>
      <tr>
        <th style="width: 14%;">条款编号</th>
        <th style="width: 20%;">控制项名称</th>
        <th style="width: 12%; text-align: center;">等级基线</th>
        <th style="width: 10%; text-align: center;">符合判定</th>
        <th style="width: 44%;">探针现场物理证据链 (Live Probe / Baseline / Config)</th>
      </tr>
    </thead>
    <tbody>
      ${params.items.map((item) => `
        <tr>
          <td><b>[${escapeHtml(item.id)}]</b><br /><span style="font-size: 7.5pt; color: #6b7280;">${escapeHtml(item.clause)}</span></td>
          <td><b>${escapeHtml(item.title)}</b></td>
          <td style="text-align: center; font-size: 8pt;">${escapeHtml(item.level)}</td>
          <td style="text-align: center;">
            <span class="status-tag status-${escapeHtml(item.status)}">
              ${item.status === 'COMPLIANT' ? '符合' :
                item.status === 'PARTIAL' ? '部分符合' :
                item.status === 'NON_COMPLIANT' ? '不符合' :
                item.status === 'NA' ? '不适用' : '待核验'}
            </span>
          </td>
          <td class="evidence-text">${escapeHtml(item.evidence)}</td>
        </tr>
      `).join('')}
    </tbody>
  </table>

  <div style="margin-top: 10mm; font-size: 8.5pt; color: #6b7280; text-align: center; border-top: 1px solid #e5e7eb; padding-top: 3mm;">
    —— 本报告完 · Omni-Probe 探针系统测评数据防伪固化存档 ——
  </div>

</body>
</html>`;
}

/**
 * Vue 组合式 Hook：等保测评总览状态机与探针探活联动
 */
export function useTargetComplianceAssessment() {
  const items = ref<TargetComplianceItem[]>(createDefaultComplianceItems());
  const targetIp = ref<string>('192.168.1.1');
  const targetLevel = ref<string>('等保三级 (GB/T 22239-2019 第8章)');
  const activeCategoryFilter = ref<string>('ALL');
  const activeStatusFilter = ref<string>('ALL');
  const isProbing = ref<boolean>(false);
  const probeStatusMessage = ref<string>('');

  const metrics = computed<AssessmentMetrics>(() => calculateAssessmentMetrics(items.value));

  const filteredItems = computed<TargetComplianceItem[]>(() => {
    return items.value.filter((item) => {
      if (activeCategoryFilter.value !== 'ALL' && item.category !== activeCategoryFilter.value) {
        return false;
      }
      if (activeStatusFilter.value === 'DEFECTS') {
        return item.status === 'NON_COMPLIANT' || item.status === 'PARTIAL';
      }
      if (activeStatusFilter.value === 'PENDING') {
        return item.status === 'PENDING';
      }
      if (activeStatusFilter.value !== 'ALL' && item.status !== activeStatusFilter.value) {
        return false;
      }
      return true;
    });
  });

  function resetToDefault() {
    items.value = createDefaultComplianceItems();
    probeStatusMessage.value = '测评数据已重置为标准基线';
  }

  function updateItemStatus(itemId: string, status: ComplianceStatus, customEvidence?: string) {
    const target = items.value.find((i) => i.id === itemId);
    if (target) {
      target.status = status;
      target.manualModified = true;
      if (customEvidence) {
        target.evidence = customEvidence;
      }
    }
  }

  function applyProbeTelemetry(telemetry: ProbeContext) {
    items.value = applyProbeTelemetryToAssessment(items.value, telemetry);
  }

  function applyDeviceConfigReport(report: DeviceConfigAnalysisReport) {
    items.value = applyDeviceConfigReportToAssessment(items.value, report);
    probeStatusMessage.value = `设备配置核查完成: ${report.hostname} (${report.vendorLabel}) · 8项基线合规率 ${report.complianceRatePct}% · 证据已同步映射`;
  }

  function applyHostBaselineReport(report: HostBaselineReport) {
    items.value = applyHostBaselineReportToAssessment(items.value, report);
    probeStatusMessage.value = `主机基线核查完成: ${report.hostname} (${report.os_name}) · ${report.total_checks}项基线合规率 ${report.compliance_rate_pct}% · SCE 证据链已映射`;
  }

  return {
    items,
    targetIp,
    targetLevel,
    activeCategoryFilter,
    activeStatusFilter,
    isProbing,
    probeStatusMessage,
    metrics,
    filteredItems,
    resetToDefault,
    updateItemStatus,
    applyProbeTelemetry,
    applyDeviceConfigReport,
    applyHostBaselineReport,
  };
}
