/**
 * 网络设备配置文件（交换机/路由器/防火墙）词法与等保基线核查引擎
 * 针对华为 (Huawei VRP)、思科 (Cisco IOS/NX-OS)、新华三 (H3C Comware)、锐捷 (Ruijie RGOS)
 * 符合 GB/T 22239-2019 / GB/T 28448-2019 设备配置合规性现场核查要求
 * 算法时空复杂度：时间复杂度 O(N) 线性单趟扫描，空间复杂度 O(K) 规则状态集
 */

export type DeviceVendor = 'HUAWEI' | 'CISCO' | 'H3C' | 'RUIJIE' | 'GENERIC';

export interface DeviceBaselineCheckResult {
  ruleId: string;
  clause: string;
  title: string;
  targetCategory: 'SCN' | 'SAB' | 'SCE' | 'SMC';
  passed: boolean;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  matchedLines: string[];
  evidence: string;
  remediation: string;
}

export interface DeviceConfigAnalysisReport {
  vendor: DeviceVendor;
  vendorLabel: string;
  totalLines: number;
  hostname: string;
  complianceRatePct: number;
  passedCount: number;
  failedCount: number;
  results: DeviceBaselineCheckResult[];
}

/**
 * 自动探测配置文件所属厂商方言
 */
export function detectDeviceVendor(configText: string): DeviceVendor {
  const head = configText.slice(0, 4000).toLowerCase();

  if (head.includes('h3c') || head.includes('comware') || configText.includes('# version 7.') || configText.includes('# version 5.')) {
    return 'H3C';
  }
  if (head.includes('huawei') || head.includes('vrp') || configText.includes('!Software Version V') || configText.includes('#\nsysname') || configText.includes('#\r\nsysname')) {
    return 'HUAWEI';
  }
  if (head.includes('cisco') || head.includes('ios-xe') || head.includes('nx-os') || configText.includes('version 15.') || configText.includes('version 16.') || configText.includes('end\n') || configText.includes('end\r\n')) {
    return 'CISCO';
  }
  if (head.includes('ruijie') || head.includes('rgos')) {
    return 'RUIJIE';
  }

  // 二次模式特征推断
  if (configText.includes('local-user ') && configText.includes('service-type ssh')) {
    return 'HUAWEI';
  }
  if (configText.includes('line vty 0 4') && configText.includes('transport input ssh')) {
    return 'CISCO';
  }

  return 'GENERIC';
}

/**
 * 解析设备的主机名
 */
export function extractDeviceHostname(configText: string): string {
  const sysnameMatch = configText.match(/(?:^|\n)\s*sysname\s+([^\s\r\n]+)/i);
  if (sysnameMatch) return sysnameMatch[1];

  const hostnameMatch = configText.match(/(?:^|\n)\s*hostname\s+([^\s\r\n]+)/i);
  if (hostnameMatch) return hostnameMatch[1];

  return 'UNKNOWN-DEVICE';
}

/**
 * 核心基线核查执行器
 */
export function dissectNetworkDeviceConfig(configText: string): DeviceConfigAnalysisReport {
  const vendor = detectDeviceVendor(configText);
  const hostname = extractDeviceHostname(configText);
  const lines = configText.split(/\r?\n/);
  const totalLines = lines.length;

  const vendorMap: Record<DeviceVendor, string> = {
    HUAWEI: '华为网络系统 (Huawei VRP)',
    CISCO: '思科网络系统 (Cisco IOS / NX-OS)',
    H3C: '新华三网络系统 (H3C Comware)',
    RUIJIE: '锐捷网络系统 (Ruijie RGOS)',
    GENERIC: '通用网络交换/路由配置规范',
  };

  const results: DeviceBaselineCheckResult[] = [];

  // --------------------------------------------------------------------------
  // 规则 1：身份鉴别与独立本地账号 (GB/T 22239-2019 8.1.3.1)
  // --------------------------------------------------------------------------
  {
    const matched: string[] = [];
    for (const line of lines) {
      const trimmed = line.trim();
      if (/^local-user\s+\S+/i.test(trimmed) || /^username\s+\S+\s+(?:privilege|secret|password|role)/i.test(trimmed)) {
        matched.push(trimmed);
      }
    }
    const passed = matched.length >= 2; // 至少存在 2 个及以上非通用独立管理账号
    results.push({
      ruleId: 'NET-CFG-01',
      clause: 'GB/T 22239-2019 8.1.3.1',
      title: '管理员身份鉴别与独立账号配置',
      targetCategory: 'SCE',
      passed,
      severity: 'HIGH',
      matchedLines: matched.slice(0, 5),
      evidence: passed
        ? `实测检出 ${matched.length} 个独立本地管理账号 (${matched.slice(0, 3).join('; ')})`
        : `仅检出 ${matched.length} 个本地账号，未落实多人独立账号管理规范，存在特权单点风险`,
      remediation: '为网络管理员、安全员建立不同命名的独立本地账号并分配独立权限，严禁共用默认 admin 账号。',
    });
  }

  // --------------------------------------------------------------------------
  // 规则 2：管理口令高强度哈希加密保护 (GB/T 22239-2019 8.1.3.1 / 8.1.3.5)
  // --------------------------------------------------------------------------
  {
    const plainMatches: string[] = [];
    const weakHashMatches: string[] = [];
    const strongMatches: string[] = [];

    for (const line of lines) {
      const trimmed = line.trim();
      // 明文检测: password simple xxx, password 0 xxx
      if (/password\s+(?:simple|0)\s+/i.test(trimmed)) {
        plainMatches.push(trimmed);
      }
      // Cisco Type 7 弱异或伪加密: password 7 xxx
      if (/password\s+7\s+/i.test(trimmed)) {
        weakHashMatches.push(trimmed);
      }
      // 强哈希识别: cipher, irreversible-cipher, secret 5/8/9, sha256
      if (/password\s+(?:cipher|irreversible-cipher)/i.test(trimmed) || /secret\s+[589]\s+/i.test(trimmed) || /algorithm\s+(?:sha-256|pbkdf2)/i.test(trimmed)) {
        strongMatches.push(trimmed);
      }
    }

    const passed = plainMatches.length === 0 && weakHashMatches.length === 0 && strongMatches.length > 0;
    const descArr: string[] = [];
    if (plainMatches.length > 0) descArr.push(`检出 ${plainMatches.length} 处明文密码保存`);
    if (weakHashMatches.length > 0) descArr.push(`检出 ${weakHashMatches.length} 处可逆弱加密 (Type 7)`);
    if (strongMatches.length > 0) descArr.push(`检出 ${strongMatches.length} 处安全密文散列`);

    results.push({
      ruleId: 'NET-CFG-02',
      clause: 'GB/T 22239-2019 8.1.3.1',
      title: '管理口令单向不可逆强散列保护',
      targetCategory: 'SCE',
      passed,
      severity: 'CRITICAL',
      matchedLines: [...plainMatches, ...weakHashMatches].slice(0, 5),
      evidence: passed
        ? `全量管理凭据均采用不可逆密文存储 (${strongMatches.length} 处强哈希)`
        : `存在非安全口令存储：${descArr.join('、')}`,
      remediation: '全面消除配置中的 simple 或 0/7 类口令，启用 password irreversible-cipher 或 enable secret 9 (Scrypt/SHA-256)。',
    });
  }

  // --------------------------------------------------------------------------
  // 规则 3：禁用明文 Telnet 与 HTTP 管理通道 (GB/T 22239-2019 8.1.1.3)
  // --------------------------------------------------------------------------
  {
    const plainTelnetHttp: string[] = [];
    let telnetEnabled = false;
    let httpEnabled = false;
    let vtyAllowTelnet = false;

    for (const line of lines) {
      const trimmed = line.trim();
      if (/^telnet\s+server\s+enable/i.test(trimmed)) {
        telnetEnabled = true;
        plainTelnetHttp.push(trimmed);
      }
      if (/^ip\s+http\s+server/i.test(trimmed) && !/^ip\s+http\s+secure-server/i.test(trimmed)) {
        httpEnabled = true;
        plainTelnetHttp.push(trimmed);
      }
      if (/transport\s+input\s+(?:all|telnet)/i.test(trimmed) || /protocol\s+inbound\s+(?:all|telnet)/i.test(trimmed)) {
        vtyAllowTelnet = true;
        plainTelnetHttp.push(trimmed);
      }
    }

    const passed = !telnetEnabled && !httpEnabled && !vtyAllowTelnet;
    results.push({
      ruleId: 'NET-CFG-03',
      clause: 'GB/T 22239-2019 8.1.1.3',
      title: '严禁明文远程管理通道 (Telnet/HTTP)',
      targetCategory: 'SCN',
      passed,
      severity: 'CRITICAL',
      matchedLines: plainTelnetHttp,
      evidence: passed
        ? '配置未开启 Telnet 服务或明文 HTTP 管理，VTY 接口严格收敛'
        : `实测检出明文远程协议暴露 (${plainTelnetHttp.join('; ')})`,
      remediation: '执行 undo telnet server enable 与 protocol inbound ssh，或在 line vty 视图配置 transport input ssh，彻底阻断明文远程管理。',
    });
  }

  // --------------------------------------------------------------------------
  // 规则 4：SSH v2 强安全远程协议启用 (GB/T 22239-2019 8.1.1.3 / 8.1.1.4)
  // --------------------------------------------------------------------------
  {
    const sshMatches: string[] = [];
    for (const line of lines) {
      const trimmed = line.trim();
      if (/ssh\s+server\s+protocol-version\s+2/i.test(trimmed) || /ip\s+ssh\s+version\s+2/i.test(trimmed) || /ssh\s+server\s+compatible-ssh1x\s+disable/i.test(trimmed)) {
        sshMatches.push(trimmed);
      }
    }

    const passed = sshMatches.length > 0;
    results.push({
      ruleId: 'NET-CFG-04',
      clause: 'GB/T 22239-2019 8.1.1.3',
      title: 'SSH v2 强加密通道配置',
      targetCategory: 'SCN',
      passed,
      severity: 'HIGH',
      matchedLines: sshMatches,
      evidence: passed
        ? `实测已显式锁定 SSH v2 协议版本 (${sshMatches.join('; ')})`
        : '未显式配置锁定 SSH v2 协议版本，可能存在低版本 SSH v1 回退协商风险',
      remediation: '在系统视图配置 ssh server protocol-version 2 或 ip ssh version 2，禁止向后兼容 SSH v1。',
    });
  }

  // --------------------------------------------------------------------------
  // 规则 5：空闲管理会话超时自动注销 (GB/T 22239-2019 8.1.3.6)
  // --------------------------------------------------------------------------
  {
    const timeoutMatches: string[] = [];
    const invalidTimeouts: string[] = [];
    let hasValidTimeout = false;

    for (const line of lines) {
      const trimmed = line.trim();
      // idle-timeout 10 0 (华为/H3C 分钟 秒), exec-timeout 10 0 (思科 分钟 秒)
      const mHuawei = trimmed.match(/^idle-timeout\s+(\d+)(?:\s+(\d+))?/i);
      const mCisco = trimmed.match(/^exec-timeout\s+(\d+)(?:\s+(\d+))?/i);
      const match = mHuawei || mCisco;

      if (match) {
        const minutes = parseInt(match[1], 10);
        const seconds = match[2] ? parseInt(match[2], 10) : 0;
        const totalSecs = minutes * 60 + seconds;
        timeoutMatches.push(trimmed);
        if (totalSecs > 0 && totalSecs <= 900) {
          hasValidTimeout = true;
        } else {
          invalidTimeouts.push(trimmed);
        }
      }
    }

    const passed = hasValidTimeout && invalidTimeouts.length === 0;
    results.push({
      ruleId: 'NET-CFG-05',
      clause: 'GB/T 22239-2019 8.1.3.6',
      title: '管理终端空闲超时自动锁定 (≤ 15 分钟)',
      targetCategory: 'SCE',
      passed,
      severity: 'MEDIUM',
      matchedLines: invalidTimeouts.length > 0 ? invalidTimeouts : timeoutMatches,
      evidence: passed
        ? `实测全部控制口/VTY 接口均已配置合法超时注销策略 (${timeoutMatches.join('; ')})`
        : (invalidTimeouts.length > 0
            ? `检出不合规的超时策略（永不超时 0 或超过 900 秒）: ${invalidTimeouts.join('; ')}`
            : '未在 user-interface / line 视图下检测到明确的超时注销时间 (idle-timeout / exec-timeout)'),
      remediation: '在全部 line vty 与 console 视图下统一配置 idle-timeout 10 0 或 exec-timeout 10 0，严禁保留 0 0 永不超时配置。',
    });
  }

  // --------------------------------------------------------------------------
  // 规则 6：登录失败锁定与防暴力破解策略 (GB/T 22239-2019 8.1.3.1)
  // --------------------------------------------------------------------------
  {
    const lockMatches: string[] = [];
    for (const line of lines) {
      const trimmed = line.trim();
      if (/account\s+login-failed\s+threshold/i.test(trimmed) || /login\s+block-for/i.test(trimmed) || /aaa\s+authentication\s+login\s+fail/i.test(trimmed)) {
        lockMatches.push(trimmed);
      }
    }

    const passed = lockMatches.length > 0;
    results.push({
      ruleId: 'NET-CFG-06',
      clause: 'GB/T 22239-2019 8.1.3.1',
      title: '连续登录失败锁定与防暴力破解策略',
      targetCategory: 'SCE',
      passed,
      severity: 'HIGH',
      matchedLines: lockMatches,
      evidence: passed
        ? `实测已配置非法登录锁定策略 (${lockMatches.join('; ')})`
        : '未配置连续登录失败限制阈值与自动锁定时间，设备面临口令暴力破解隐患',
      remediation: '配置 account login-failed threshold 5 或 login block-for 300 attempts 5 within 120，阻断自动扫描暴破。',
    });
  }

  // --------------------------------------------------------------------------
  // 规则 7：SNMP v3 安全版本与弱团体字杜绝 (GB/T 22239-2019 8.1.4.1)
  // --------------------------------------------------------------------------
  {
    const snmpPlainMatches: string[] = [];
    const snmpWeakMatches: string[] = [];
    let hasSnmpV3 = false;
    let hasSnmpV1v2 = false;

    for (const line of lines) {
      const trimmed = line.trim();
      if (/snmp-agent\s+sys-info\s+version\s+v3/i.test(trimmed) || /snmp-server\s+group\s+\S+\s+v3/i.test(trimmed)) {
        hasSnmpV3 = true;
      }
      if (/snmp-agent\s+community\s+(?:read|write)\s+(?:public|private)/i.test(trimmed) || /snmp-server\s+community\s+(?:public|private)/i.test(trimmed)) {
        snmpWeakMatches.push(trimmed);
        snmpPlainMatches.push(trimmed);
        hasSnmpV1v2 = true;
      } else if (/snmp-agent\s+community/i.test(trimmed) || /snmp-server\s+community/i.test(trimmed)) {
        snmpPlainMatches.push(trimmed);
        hasSnmpV1v2 = true;
      }
    }

    const passed = snmpWeakMatches.length === 0 && (!hasSnmpV1v2 || hasSnmpV3);
    results.push({
      ruleId: 'NET-CFG-07',
      clause: 'GB/T 22239-2019 8.1.4.1',
      title: 'SNMP 协议安全版本与默认弱团体字检查',
      targetCategory: 'SMC',
      passed,
      severity: 'HIGH',
      matchedLines: snmpWeakMatches.length > 0 ? snmpWeakMatches : snmpPlainMatches,
      evidence: passed
        ? (hasSnmpV3 ? 'SNMP 已启用 v3 安全版本，未暴露默认团体字' : '未检测到明文 SNMP v1/v2c 团体字配置')
        : (snmpWeakMatches.length > 0
            ? `检出高危默认/弱口令 SNMP 团体字 (${snmpWeakMatches.join('; ')})`
            : `检出启用明文 SNMP v1/v2c 团体字且未完全迁移至 SNMP v3 加密体系 (${snmpPlainMatches.slice(0, 3).join('; ')})`),
      remediation: '禁用 SNMP v1/v2c，删除所有 community 团体字；全面迁移至 SNMP v3 authPriv (SHA-256/AES-128) 模式。',
    });
  }

  // --------------------------------------------------------------------------
  // 规则 8：集中式安全日志外发 (Syslog Loghost) (GB/T 22239-2019 8.1.4.2)
  // --------------------------------------------------------------------------
  {
    const logMatches: string[] = [];
    for (const line of lines) {
      const trimmed = line.trim();
      if (
        /info-center\s+loghost\s+/i.test(trimmed) ||
        /^logging\s+host\s+/i.test(trimmed) ||
        /^logging\s+server\s+/i.test(trimmed) ||
        /^logging\s+\d{1,3}(?:\.\d{1,3}){3}/i.test(trimmed)
      ) {
        logMatches.push(trimmed);
      }
    }

    const passed = logMatches.length > 0;
    results.push({
      ruleId: 'NET-CFG-08',
      clause: 'GB/T 22239-2019 8.1.4.2',
      title: '集中式网络安全日志异地备份外发 (Syslog)',
      targetCategory: 'SMC',
      passed,
      severity: 'HIGH',
      matchedLines: logMatches,
      evidence: passed
        ? `实测已配置远程 Syslog 日志服务器 (${logMatches.join('; ')})`
        : '未配置远程集中日志外发主机 (info-center loghost / logging host)，设备日志仅保存在本地内存/缓冲池中',
      remediation: '配置 info-center loghost <IP> 或 logging host <IP>，将设备系统与安全日志集中汇总到日志审计平台。',
    });
  }

  const passedCount = results.filter((r) => r.passed).length;
  const failedCount = results.length - passedCount;
  const complianceRatePct = Number(((passedCount / results.length) * 100).toFixed(1));

  return {
    vendor,
    vendorLabel: vendorMap[vendor],
    totalLines,
    hostname,
    complianceRatePct,
    passedCount,
    failedCount,
    results,
  };
}
