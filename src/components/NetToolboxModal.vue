<template>
  <div
    v-if="show"
    class="fixed inset-0 z-50 flex items-center justify-center p-4 ui-modal-backdrop"
    @click.self="$emit('close')"
  >
    <div class="w-full max-w-4xl max-h-[88vh] ui-modal-surface rounded-3xl flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-200 relative border border-[var(--border-subtle)] shadow-2xl">
      <span class="lens-edge-lip" aria-hidden="true"></span>
      <!-- 顶栏 -->
      <div class="px-5 py-3.5 flex items-center justify-between border-b shrink-0" style="border-color: var(--border-subtle)">
        <div class="flex items-center gap-3">
          <div class="w-8 h-8 rounded-xl bg-sky-500/15 text-sky-600 dark:text-sky-300 flex items-center justify-center font-bold text-sm">
            ⌘T
          </div>
          <div>
            <h3 class="text-sm font-bold tracking-tight" style="color: var(--text-primary)">
              {{ t('netToolbox.modalTitle') }}
            </h3>
            <p class="text-[11px]" style="color: var(--text-muted)">
              {{ t('netToolbox.modalSubtitle') }}
            </p>
          </div>
        </div>
        <button @click="$emit('close')" class="ui-btn-secondary px-3 py-1 text-xs">{{ t('netToolbox.closeEsc') }}</button>
      </div>

      <!-- 4 大功能分页栏 -->
      <div class="px-5 py-2.5 flex items-center gap-2 border-b shrink-0 flex-wrap" style="border-color: var(--border-subtle)">
        <button
          @click="activeTab = 'subnet'"
          :class="activeTab === 'subnet' ? 'ui-btn-primary' : 'ui-btn-secondary'"
          class="px-3 py-1.5 text-xs"
        >
          {{ t('netToolbox.tabSubnet') }}
        </button>
        <button
          @click="activeTab = 'probe'"
          :class="activeTab === 'probe' ? 'ui-btn-primary' : 'ui-btn-secondary'"
          class="px-3 py-1.5 text-xs"
        >
          {{ t('netToolbox.tabProbe') }}
        </button>
        <button
          @click="activeTab = 'fileserver'; refreshFileServers()"
          :class="activeTab === 'fileserver' ? 'ui-btn-primary' : 'ui-btn-secondary'"
          class="px-3 py-1.5 text-xs"
        >
          {{ t('netToolbox.tabFileServer') }}
        </button>
        <button
          @click="activeTab = 'lookup'"
          :class="activeTab === 'lookup' ? 'ui-btn-primary' : 'ui-btn-secondary'"
          class="px-3 py-1.5 text-xs"
        >
          {{ t('netToolbox.tabLookup') }}
        </button>
        <button
          @click="activeTab = 'terminal'"
          :class="activeTab === 'terminal' ? 'ui-btn-primary' : 'ui-btn-secondary'"
          class="px-3 py-1.5 text-xs"
        >
          {{ t('netToolbox.tabTerminal') }}
        </button>
        <button
          @click="activeTab = 'chinagov'; fetchChinaGovTelemetry()"
          :class="activeTab === 'chinagov' ? 'ui-btn-primary' : 'ui-btn-secondary'"
          class="px-3 py-1.5 text-xs"
        >
          {{ t('netToolbox.tabChinaGov') }}
        </button>
      </div>

      <!-- 错误告警条 -->
      <div v-if="errorMessage" class="mx-5 mt-3 px-3 py-2 rounded-xl bg-rose-500/15 border border-rose-500/30 text-rose-700 dark:text-rose-300 text-xs">
        {{ errorMessage }}
      </div>

      <!-- 主内容区 -->
      <div class="p-5 overflow-y-auto flex-1 space-y-4">
        <!-- 1. IPv4 / IPv6 子网掩码规划与 VLSM -->
        <div v-if="activeTab === 'subnet'" class="space-y-4">
          <div class="ui-sub-card p-4 rounded-xl space-y-3">
            <div class="flex items-center gap-2 flex-wrap">
              <input
                v-model="subnetInput"
                @keyup.enter="runSubnetCalc"
                :placeholder="t('netToolbox.subnetPlaceholder')"
                class="ui-input px-3 py-1.5 text-xs flex-1 min-w-[260px] ui-num"
              />
              <button @click="runSubnetCalc" class="ui-btn-primary px-3.5 py-1.5 text-xs">{{ t('netToolbox.calcSubnet') }}</button>
              <div class="flex items-center gap-1.5">
                <span class="text-xs" style="color: var(--text-muted)">{{ t('netToolbox.vlsmSplitTo') }}</span>
                <input v-model.number="vlsmTargetPrefix" type="number" min="1" max="128" class="ui-input px-2 py-1.5 text-xs w-16 ui-num" />
                <button @click="runVlsmSplit" class="ui-btn-secondary px-3 py-1.5 text-xs">{{ t('netToolbox.splitSubnetTable') }}</button>
              </div>
            </div>

            <div v-if="subnetResult" class="grid grid-cols-2 md:grid-cols-3 gap-2.5 text-xs">
              <div class="p-2.5 rounded-lg border" style="border-color: var(--border-subtle)">
                <div class="text-[11px]" style="color: var(--text-muted)">{{ locale === 'en-US' ? 'Network / Prefix' : '网络号 / 前缀' }}</div>
                <div class="font-bold ui-num mt-0.5">{{ subnetResult.network_address }} /{{ subnetResult.prefix_len }}</div>
              </div>
              <div class="p-2.5 rounded-lg border" style="border-color: var(--border-subtle)">
                <div class="text-[11px]" style="color: var(--text-muted)">{{ locale === 'en-US' ? 'Netmask & ACL Wildcard' : '掩码 & ACL 通配符反掩码' }}</div>
                <div class="font-bold ui-num mt-0.5">{{ subnetResult.netmask }} | {{ subnetResult.wildcard_mask }}</div>
              </div>
              <div class="p-2.5 rounded-lg border" style="border-color: var(--border-subtle)">
                <div class="text-[11px]" style="color: var(--text-muted)">{{ locale === 'en-US' ? 'Broadcast / End IP' : '广播 / 末地址' }}</div>
                <div class="font-bold ui-num mt-0.5">{{ subnetResult.broadcast_address }}</div>
              </div>
              <div class="p-2.5 rounded-lg border" style="border-color: var(--border-subtle)">
                <div class="text-[11px]" style="color: var(--text-muted)">{{ locale === 'en-US' ? 'Usable IP Range' : '可用起止 IP 范围' }}</div>
                <div class="font-bold ui-num mt-0.5">{{ subnetResult.first_usable_ip }} ~ {{ subnetResult.last_usable_ip }}</div>
              </div>
              <div class="p-2.5 rounded-lg border" style="border-color: var(--border-subtle)">
                <div class="text-[11px]" style="color: var(--text-muted)">{{ locale === 'en-US' ? 'Usable Hosts / Total Space' : '可用主机数 / 总空间' }}</div>
                <div class="font-bold ui-num mt-0.5">{{ subnetResult.usable_hosts }} / {{ subnetResult.total_addresses }}</div>
              </div>
              <div class="p-2.5 rounded-lg border" style="border-color: var(--border-subtle)">
                <div class="text-[11px]" style="color: var(--text-muted)">{{ locale === 'en-US' ? 'RFC Address Class' : 'RFC 地址分类' }}</div>
                <div class="font-semibold mt-0.5">{{ subnetResult.address_class }}</div>
              </div>
              <div class="col-span-2 md:col-span-3 p-2.5 rounded-lg border space-y-1 text-[11px] ui-num" style="border-color: var(--border-subtle)">
                <div><span style="color: var(--text-muted)">{{ locale === 'en-US' ? 'Binary / Expanded View: ' : '二进制/全展开视图：' }}</span>{{ subnetResult.binary_view }}</div>
                <div><span style="color: var(--text-muted)">{{ locale === 'en-US' ? 'PTR Reverse Domain: ' : 'PTR 反向解析域名：' }}</span>{{ subnetResult.ptr_reverse_domain }}</div>
              </div>
            </div>
          </div>

          <div v-if="vlsmSlices.length" class="ui-sub-card p-3 rounded-xl">
            <div class="text-xs font-bold mb-2">{{ locale === 'en-US' ? `VLSM Slices (${vlsmSlices.length} subnets)` : `VLSM 子网切分明细 (${vlsmSlices.length} 个子网)` }}</div>
            <div class="max-h-60 overflow-y-auto">
              <table class="w-full text-left text-xs ui-num">
                <thead class="border-b" style="border-color: var(--border-subtle); color: var(--text-muted)">
                  <tr>
                    <th class="py-1.5 px-2">#</th>
                    <th class="py-1.5 px-2">{{ locale === 'en-US' ? 'Subnet CIDR' : '子网 CIDR' }}</th>
                    <th class="py-1.5 px-2">{{ locale === 'en-US' ? 'First Usable IP' : '首可用 IP' }}</th>
                    <th class="py-1.5 px-2">{{ locale === 'en-US' ? 'Last Usable IP' : '末可用 IP' }}</th>
                    <th class="py-1.5 px-2">{{ locale === 'en-US' ? 'Broadcast IP' : '广播地址' }}</th>
                    <th class="py-1.5 px-2">{{ locale === 'en-US' ? 'Usable Hosts' : '可用数' }}</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="s in vlsmSlices" :key="s.index" class="border-b last:border-0" style="border-color: var(--border-subtle)">
                    <td class="py-1 px-2">{{ s.index }}</td>
                    <td class="py-1 px-2 font-semibold">{{ s.cidr }}</td>
                    <td class="py-1 px-2">{{ s.first_usable }}</td>
                    <td class="py-1 px-2">{{ s.last_usable }}</td>
                    <td class="py-1 px-2">{{ s.broadcast_address }}</td>
                    <td class="py-1 px-2">{{ s.usable_hosts }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <!-- 2. 原生 DNS / TCPing / HTTP 诊断 -->
        <div v-if="activeTab === 'probe'" class="space-y-4">
          <!-- 原生 DNS 查询 -->
          <div class="ui-sub-card p-4 rounded-xl space-y-2.5">
            <div class="text-xs font-bold">{{ locale === 'en-US' ? 'RFC 1035 Native UDP DNS Query (nslookup-free)' : 'RFC 1035 原生 UDP DNS 报文查询 (不依赖 nslookup)' }}</div>
            <div class="flex items-center gap-2 flex-wrap">
              <input v-model="dnsDomain" :placeholder="locale === 'en-US' ? 'Domain (e.g. www.google.com)' : '域名 (如 www.baidu.com)'" class="ui-input px-2.5 py-1.5 text-xs flex-1 min-w-[180px]" />
              <select v-model="dnsRecordType" class="ui-input px-2.5 py-1.5 text-xs ui-num">
                <option value="A">A</option>
                <option value="AAAA">AAAA</option>
                <option value="CNAME">CNAME</option>
                <option value="MX">MX</option>
                <option value="TXT">TXT</option>
                <option value="NS">NS</option>
                <option value="PTR">PTR</option>
                <option value="SOA">SOA</option>
                <option value="SRV">SRV</option>
              </select>
              <input v-model="dnsServer" :placeholder="locale === 'en-US' ? 'DNS Server (e.g. 8.8.8.8:53)' : 'DNS 服务器 (如 223.5.5.5:53)'" class="ui-input px-2.5 py-1.5 text-xs w-44 ui-num" />
              <button @click="runDnsQuery" :disabled="isQueryingDns" class="ui-btn-primary px-3 py-1.5 text-xs">
                {{ isQueryingDns ? (locale === 'en-US' ? 'Querying...' : '查询中...') : (locale === 'en-US' ? 'Send UDP Query' : '发送 UDP 查询') }}
              </button>
            </div>
            <div v-if="dnsReport" class="text-xs space-y-1.5 pt-1">
              <div class="ui-num" style="color: var(--text-muted)">
                {{ locale === 'en-US' ? 'Status: ' : '状态: ' }}<span class="font-bold text-emerald-600 dark:text-emerald-400">{{ dnsReport.rcode_name }}</span> · 服务器 {{ dnsReport.dns_server }} · 耗时 {{ dnsReport.rtt_ms }} ms · 记录 {{ dnsReport.answers.length }} 条
              </div>
              <div v-for="(ans, idx) in dnsReport.answers" :key="idx" class="px-2.5 py-1 rounded-lg border text-[11px] ui-num flex items-center justify-between gap-2" style="border-color: var(--border-subtle)">
                <span>[{{ ans.record_type }}] {{ ans.name }} → <strong>{{ ans.value }}</strong></span>
                <span style="color: var(--text-muted)">TTL {{ ans.ttl }}s</span>
              </div>
            </div>
          </div>

          <!-- TCPing + HTTP Timing -->
          <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div class="ui-sub-card p-4 rounded-xl space-y-2.5">
              <div class="text-xs font-bold">{{ locale === 'en-US' ? 'TCPing Multi-Sample Jitter & Loss Diagnostics' : 'TCPing 多采样抖动与丢包诊断' }}</div>
              <div class="flex items-center gap-2 flex-wrap">
                <input v-model="tcpingHost" :placeholder="locale === 'en-US' ? 'Host or IP' : '主机或 IP'" class="ui-input px-2.5 py-1.5 text-xs flex-1 min-w-[120px] ui-num" />
                <input v-model.number="tcpingPort" type="number" min="1" max="65535" class="ui-input px-2 py-1.5 text-xs w-20 ui-num" />
                <input v-model.number="tcpingCount" type="number" min="1" max="20" class="ui-input px-2 py-1.5 text-xs w-16 ui-num" />
                <button @click="runTcping" :disabled="isRunningTcping" class="ui-btn-primary px-3 py-1.5 text-xs">
                  {{ isRunningTcping ? (locale === 'en-US' ? 'Probing...' : '探测中...') : 'TCPing' }}
                </button>
              </div>
              <div v-if="tcpingReport" class="text-xs ui-num space-y-1">
                <div>{{ locale === 'en-US' ? 'Resolved IP: ' : '解析 IP: ' }}<strong>{{ tcpingReport.resolved_ip }}</strong> | {{ locale === 'en-US' ? 'Success: ' : '成功 ' }}{{ tcpingReport.succeeded }}/{{ tcpingReport.attempts }} ({{ locale === 'en-US' ? 'Loss ' : '丢包 ' }}{{ tcpingReport.loss_pct }}%)</div>
                <div>Min {{ tcpingReport.min_ms }}ms · Avg {{ tcpingReport.avg_ms }}ms · P95 {{ tcpingReport.p95_ms }}ms · Max {{ tcpingReport.max_ms }}ms · 抖动 {{ tcpingReport.jitter_mdev_ms }}ms</div>
                <div class="flex flex-wrap gap-1 pt-0.5">
                  <span v-for="(s, idx) in tcpingReport.samples_ms" :key="idx" class="ui-pill px-2 py-0.5 text-[10px]">
                    #{{ idx + 1 }}: {{ formatLatencyBadge(s) }}
                  </span>
                </div>
              </div>
            </div>

            <div class="ui-sub-card p-4 rounded-xl space-y-2.5">
              <div class="text-xs font-bold">{{ locale === 'en-US' ? 'HTTP(S) Phased Latency Probe (TCP + TTFB)' : 'HTTP(S) 分阶段耗时探针 (TCP + TTFB)' }}</div>
              <div class="flex items-center gap-2">
                <input v-model="httpUrl" placeholder="https://example.com" class="ui-input px-2.5 py-1.5 text-xs flex-1 ui-num" />
                <button @click="runHttpTiming" :disabled="isRunningHttp" class="ui-btn-primary px-3 py-1.5 text-xs">
                  {{ isRunningHttp ? (locale === 'en-US' ? 'Testing...' : '测速中...') : (locale === 'en-US' ? 'Test Speed' : '测速') }}
                </button>
              </div>
              <div v-if="httpReport" class="text-xs ui-num space-y-1">
                <div>{{ locale === 'en-US' ? 'HTTP Status: ' : 'HTTP 状态: ' }}<strong>{{ httpReport.status_code }}</strong> · {{ locale === 'en-US' ? 'TCP Connect ' : 'TCP 建连 ' }}{{ httpReport.tcp_connect_ms }}ms · {{ locale === 'en-US' ? 'Total TTFB ' : '总响应 ' }}{{ httpReport.total_ttfb_ms }}ms</div>
                <div>{{ locale === 'en-US' ? 'Payload Size: ' : '载荷大小: ' }}{{ httpReport.body_size_bytes.toLocaleString() }} B · Server: {{ httpReport.server_header || '-' }}</div>
                <div class="truncate" style="color: var(--text-muted)">{{ locale === 'en-US' ? 'Final URL: ' : '终点 URL: ' }}{{ httpReport.final_url }}</div>
              </div>
            </div>
          </div>
        </div>

        <!-- 3. TFTP / HTTP 临时文件分发微服 -->
        <div v-if="activeTab === 'fileserver'" class="space-y-4">
          <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div class="ui-sub-card p-4 rounded-xl space-y-2.5">
              <div class="flex items-center justify-between">
                <span class="text-xs font-bold">{{ locale === 'en-US' ? 'RFC 1350 TFTP UDP Firmware Service' : 'RFC 1350 TFTP UDP 固件传包服务' }}</span>
                <span class="ui-pill px-2 py-0.5 text-[11px]" :class="serverStatus?.tftp_running ? 'text-emerald-600 dark:text-emerald-400' : ''">
                  {{ serverStatus?.tftp_running ? (locale === 'en-US' ? `Running ${serverStatus.tftp_bind}` : `运行中 ${serverStatus.tftp_bind}`) : (locale === 'en-US' ? 'Stopped' : '已停止') }}
                </span>
              </div>
              <input v-model="tftpBind" :placeholder="locale === 'en-US' ? 'Bind address (e.g. 0.0.0.0:69)' : '监听地址 (如 0.0.0.0:69 或 0.0.0.0:6969)'" class="ui-input w-full px-2.5 py-1.5 text-xs ui-num" />
              <input v-model="tftpRoot" :placeholder="locale === 'en-US' ? 'Shared root path (e.g. E:\\firmware)' : '共享根目录绝对路径 (例如 E:\\firmware)'" class="ui-input w-full px-2.5 py-1.5 text-xs ui-num" />
              <label class="flex items-center gap-2 text-xs">
                <input v-model="tftpAllowWrite" type="checkbox" />
                <span>{{ locale === 'en-US' ? 'Allow device WRQ writeback (sandbox root only)' : '允许设备执行 WRQ 写回备份配置（仅限沙箱根目录内）' }}</span>
              </label>
              <button @click="toggleTftpServer" :class="serverStatus?.tftp_running ? 'ui-btn-secondary' : 'ui-btn-primary'" class="px-3.5 py-1.5 text-xs w-full">
                {{ serverStatus?.tftp_running ? (locale === 'en-US' ? 'Stop TFTP Service' : '停止 TFTP 服务') : (locale === 'en-US' ? 'Start TFTP Service' : '启动 TFTP 服务') }}
              </button>
            </div>

            <div class="ui-sub-card p-4 rounded-xl space-y-2.5">
              <div class="flex items-center justify-between">
                <span class="text-xs font-bold">{{ locale === 'en-US' ? 'Temporary HTTP Static Distribution Microserver' : '临时 HTTP 静态分发微服务器' }}</span>
                <span class="ui-pill px-2 py-0.5 text-[11px]" :class="serverStatus?.http_running ? 'text-emerald-600 dark:text-emerald-400' : ''">
                  {{ serverStatus?.http_running ? (locale === 'en-US' ? `Running ${serverStatus.http_bind}` : `运行中 ${serverStatus.http_bind}`) : (locale === 'en-US' ? 'Stopped' : '已停止') }}
                </span>
              </div>
              <input v-model="httpServeBind" :placeholder="locale === 'en-US' ? 'Bind address (e.g. 0.0.0.0:8088)' : '监听地址 (如 0.0.0.0:8088)'" class="ui-input w-full px-2.5 py-1.5 text-xs ui-num" />
              <input v-model="httpServeRoot" :placeholder="locale === 'en-US' ? 'HTTP root absolute path' : 'HTTP 下载目录绝对路径'" class="ui-input w-full px-2.5 py-1.5 text-xs ui-num" />
              <div class="text-[11px]" style="color: var(--text-muted)">
                {{ locale === 'en-US' ? 'Built-in directory traversal (../) sandbox protection; supports browser downloads and switch HTTP firmware updates.' : '内置目录穿越 (../) 物理沙箱拦截；支持浏览器列表下载与交换机 HTTP 升级拉包。' }}
              </div>
              <button @click="toggleHttpFileServer" :class="serverStatus?.http_running ? 'ui-btn-secondary' : 'ui-btn-primary'" class="px-3.5 py-1.5 text-xs w-full">
                {{ serverStatus?.http_running ? (locale === 'en-US' ? 'Stop HTTP Server' : '停止 HTTP 微服') : (locale === 'en-US' ? 'Start HTTP Server' : '启动 HTTP 微服') }}
              </button>
            </div>
          </div>

          <div class="ui-sub-card p-3 rounded-xl">
            <div class="flex items-center justify-between mb-2">
              <span class="text-xs font-bold">{{ locale === 'en-US' ? 'Real-time Transfer & Security Audit Logs' : '实时传输与安全审计记录' }}</span>
              <button @click="refreshFileServers" class="ui-btn-secondary px-2.5 py-1 text-[11px]">{{ locale === 'en-US' ? 'Refresh Logs' : '刷新流水' }}</button>
            </div>
            <div v-if="!serverStatus?.transfer_logs.length" class="text-xs py-3 text-center" style="color: var(--text-muted)">
              {{ locale === 'en-US' ? 'No file transfer logs yet (records and SHA-256 digests will log in real time)' : '暂无文件传输流水（启动后传输记录及 SHA-256 摘要将实时落账）' }}
            </div>
            <div v-else class="space-y-1 max-h-44 overflow-y-auto text-[11px] ui-num">
              <div v-for="(l, i) in serverStatus.transfer_logs" :key="i" class="flex items-center justify-between px-2.5 py-1 rounded border" style="border-color: var(--border-subtle)">
                <span>[{{ l.timestamp }}] {{ l.protocol }} · {{ l.peer_addr }} → <strong>{{ l.filename }}</strong> ({{ l.bytes_transferred }} B, sha256:{{ l.sha256_prefix }})</span>
                <span :class="l.status === 'OK' ? 'text-emerald-600 dark:text-emerald-400' : 'text-rose-500'">{{ l.status }}</span>
              </div>
            </div>
          </div>
        </div>

        <!-- 4. OUI / 端口 / EtherType / IP 离线原子字典速查 -->
        <div v-if="activeTab === 'lookup'" class="space-y-3">
          <div class="ui-sub-card p-4 rounded-xl space-y-3">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
              <label class="space-y-1">
                <span style="color: var(--text-muted)">{{ locale === 'en-US' ? 'MAC Address OUI Vendor Lookup' : 'MAC 地址 OUI 厂商识别' }}</span>
                <input v-model="macQuery" :placeholder="locale === 'en-US' ? 'e.g. 00:1B:1B:01:02:03' : '如 00:1B:1B:01:02:03'" class="ui-input w-full px-2.5 py-1.5 ui-num" />
              </label>
              <label class="space-y-1">
                <span style="color: var(--text-muted)">{{ locale === 'en-US' ? 'TCP/UDP Well-Known Port Lookup' : 'TCP/UDP 知名端口服务查询' }}</span>
                <input v-model.number="portQuery" type="number" min="1" max="65535" class="ui-input w-full px-2.5 py-1.5 ui-num" />
              </label>
              <label class="space-y-1">
                <span style="color: var(--text-muted)">{{ locale === 'en-US' ? 'Ethernet EtherType HEX Lookup' : '以太网 EtherType HEX 查询' }}</span>
                <input v-model="etherTypeQuery" :placeholder="locale === 'en-US' ? 'e.g. 0x88CC / 0x0800' : '如 0x88CC / 0x0800'" class="ui-input w-full px-2.5 py-1.5 ui-num" />
              </label>
              <label class="space-y-1">
                <span style="color: var(--text-muted)">{{ locale === 'en-US' ? 'IP Offline Coordinates & Geo Lookup' : 'IP 离线坐标与归属地查询' }}</span>
                <input v-model="ipGeoQuery" :placeholder="locale === 'en-US' ? 'e.g. 8.8.8.8' : '如 223.5.5.5'" class="ui-input w-full px-2.5 py-1.5 ui-num" />
              </label>
            </div>
            <div class="flex items-center justify-between gap-2">
              <span class="text-[11px]" style="color: var(--text-muted)">{{ lookupSummaryNote || (locale === 'en-US' ? 'Reuses backend offline static protocol & OUI engine dictionary' : '直接复用后端离线静态协议与 OUI 引擎字典') }}</span>
              <button @click="runAtomicLookups" class="ui-btn-primary px-4 py-1.5 text-xs">{{ locale === 'en-US' ? 'Execute Quick Lookup' : '执行一键速查' }}</button>
            </div>
          </div>

          <div class="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
            <div v-if="macVendorResult" class="ui-sub-card p-3 rounded-xl space-y-1">
              <div class="font-bold">{{ locale === 'en-US' ? 'MAC OUI Identification' : 'MAC OUI 识别' }}</div>
              <div>{{ locale === 'en-US' ? 'Vendor: ' : '厂商: ' }}{{ macVendorResult.vendor_cn }} ({{ macVendorResult.vendor_en }})</div>
              <div style="color: var(--text-muted)">{{ locale === 'en-US' ? 'Category: ' : '类别: ' }}{{ macVendorResult.device_category }}</div>
            </div>
            <div v-if="portResult" class="ui-sub-card p-3 rounded-xl space-y-1">
              <div class="font-bold">{{ locale === 'en-US' ? 'Port' : '端口' }} {{ portResult.port }} ({{ portResult.transport }})</div>
              <div>{{ locale === 'en-US' ? 'Service: ' : '服务: ' }}{{ portResult.service_name }} · {{ portResult.display_name }}</div>
              <div style="color: var(--text-muted)">{{ locale === 'en-US' ? 'Category: ' : '分类: ' }}{{ portResult.category }}{{ portResult.is_industrial ? (locale === 'en-US' ? ' [Industrial Dedicated]' : ' [工业规约]') : '' }}</div>
            </div>
            <div v-if="etherTypeResult" class="ui-sub-card p-3 rounded-xl space-y-1">
              <div class="font-bold">EtherType {{ etherTypeResult.name }} (0x{{ etherTypeResult.ether_type.toString(16).toUpperCase() }})</div>
              <div>{{ etherTypeResult.full_name }}</div>
              <div style="color: var(--text-muted)">{{ etherTypeResult.description }}</div>
            </div>
            <div v-if="ipGeoResult" class="ui-sub-card p-3 rounded-xl space-y-1">
              <div class="font-bold">{{ locale === 'en-US' ? 'IP Geo Location Attribution' : 'IP 地理信息归属' }}</div>
              <div>{{ ipGeoResult.country }} {{ ipGeoResult.province }} {{ ipGeoResult.city }}</div>
              <div class="ui-num" style="color: var(--text-muted)">{{ locale === 'en-US' ? 'Coords: ' : '坐标: ' }}{{ ipGeoResult.latitude.toFixed(4) }}, {{ ipGeoResult.longitude.toFixed(4) }}</div>
            </div>
          </div>
        </div>

        <!-- 5. 交互式网工管理终端 (Telnet / SSH) -->
        <div v-if="activeTab === 'terminal'" class="space-y-3">
          <div class="ui-sub-card p-3 rounded-xl flex items-center gap-2 flex-wrap text-xs">
            <div class="flex items-center gap-1 bg-black/10 dark:bg-white/10 p-0.5 rounded-lg">
              <button
                @click="switchTerminalProtocol('Telnet')"
                :class="terminalProtocol === 'Telnet' ? 'ui-btn-primary' : 'px-2 py-1'"
                class="rounded-md text-[11px] font-bold"
              >
                Telnet (23)
              </button>
              <button
                @click="switchTerminalProtocol('Ssh')"
                :class="terminalProtocol === 'Ssh' ? 'ui-btn-primary' : 'px-2 py-1'"
                class="rounded-md text-[11px] font-bold"
              >
                SSH2 (22)
              </button>
            </div>

            <input
              v-model="terminalHost"
              :placeholder="locale === 'en-US' ? 'Switch/Gateway IP or Hostname' : '交换机/网关 IP 或主机名'"
              class="ui-input px-2.5 py-1 text-xs w-44 ui-num"
            />
            <input
              v-model.number="terminalPort"
              type="number"
              :placeholder="locale === 'en-US' ? 'Port' : '端口'"
              class="ui-input px-2.5 py-1 text-xs w-20 ui-num"
            />

            <input
              v-if="terminalProtocol === 'Ssh'"
              v-model="terminalUsername"
              :placeholder="locale === 'en-US' ? 'Username' : '用户名'"
              class="ui-input px-2.5 py-1 text-xs w-28 font-mono"
            />
            <input
              v-if="terminalProtocol === 'Ssh'"
              v-model="terminalPassword"
              type="password"
              :placeholder="locale === 'en-US' ? 'Password (Optional)' : '密码 (可选)'"
              class="ui-input px-2.5 py-1 text-xs w-28 font-mono"
            />

            <button
              v-if="!isTerminalConnected"
              @click="openTerminal"
              :disabled="isConnectingTerminal"
              class="ui-btn-primary px-3 py-1 text-xs font-bold"
            >
              {{ isConnectingTerminal ? (locale === 'en-US' ? 'Connecting...' : '正在连接...') : (locale === 'en-US' ? 'Connect Device' : '一键连接设备') }}
            </button>
            <button
              v-else
              @click="closeTerminal"
              class="ui-btn-secondary px-3 py-1 text-xs text-rose-600 dark:text-rose-400 font-bold"
            >
              {{ locale === 'en-US' ? 'Disconnect' : '断开终端' }}
            </button>
            <button
              @click="terminalOutput = ''"
              class="ui-btn-secondary px-2.5 py-1 text-xs"
            >
              {{ locale === 'en-US' ? 'Clear' : '清屏' }}
            </button>
          </div>

          <div class="flex items-center gap-1.5 flex-wrap text-[11px]">
            <span class="text-[var(--text-muted)]">{{ locale === 'en-US' ? 'Shortcuts:' : '快捷排障指令:' }}</span>
            <button
              @click="sendTerminalCommand('display ip interface brief')"
              class="px-2 py-0.5 rounded bg-sky-500/10 text-sky-600 dark:text-sky-300 border border-sky-500/25 hover:bg-sky-500/20 font-mono"
            >
              VRP: dis ip int brief
            </button>
            <button
              @click="sendTerminalCommand('show ip interface brief')"
              class="px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-600 dark:text-indigo-300 border border-indigo-500/25 hover:bg-indigo-500/20 font-mono"
            >
              IOS: show ip int brief
            </button>
            <button
              @click="sendTerminalCommand('display lldp neighbor brief')"
              class="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-600 dark:text-emerald-300 border border-emerald-500/25 hover:bg-emerald-500/20 font-mono"
            >
              {{ locale === 'en-US' ? 'LLDP Neighbors' : 'LLDP 邻居' }}
            </button>
            <button
              @click="sendTerminalCommand('display mac-address')"
              class="px-2 py-0.5 rounded bg-amber-500/10 text-amber-600 dark:text-amber-300 border border-amber-500/25 hover:bg-amber-500/20 font-mono"
            >
              {{ locale === 'en-US' ? 'MAC Table' : 'MAC 转发表' }}
            </button>
          </div>

          <div class="relative rounded-xl overflow-hidden border border-black/30 bg-black/90 p-3 shadow-inner">
            <div
              class="h-72 overflow-y-auto font-mono text-xs text-emerald-400 whitespace-pre-wrap select-text leading-relaxed custom-scrollbar"
            >
              <div v-if="!terminalOutput" class="text-zinc-500 italic select-none">
                {{ locale === 'en-US' ? '# Omni-Probe RFC 854 Terminal engine ready. Enter device IP and click Connect to start session...' : '# Omni-Probe 原生 RFC 854 终端引擎已就绪。输入交换机/路由器 IP 并点击【一键连接设备】开始命令行会话...' }}
              </div>
              <div>{{ terminalOutput }}</div>
            </div>
            <div class="mt-2 pt-2 border-t border-zinc-800 flex items-center gap-2">
              <span class="text-xs font-mono text-emerald-500 select-none">&gt;</span>
              <input
                v-model="terminalInput"
                @keyup.enter="sendTerminalCommand()"
                :disabled="!isTerminalConnected"
                :placeholder="locale === 'en-US' ? 'Type configuration command and press Enter...' : '键入设备配置命令，按 Enter 键发送...'"
                class="bg-transparent text-xs font-mono text-zinc-100 flex-1 focus:outline-none placeholder-zinc-600"
              />
              <button
                @click="sendTerminalCommand()"
                :disabled="!isTerminalConnected"
                class="px-3 py-1 text-xs rounded bg-emerald-600 hover:bg-emerald-500 text-white font-medium disabled:opacity-40"
              >
                {{ locale === 'en-US' ? 'Send' : '发送' }}
              </button>
            </div>
          </div>
        </div>

        <!-- 6. 国产操作系统信创环境诊断 -->
        <div v-if="activeTab === 'chinagov'" class="space-y-4">
          <div class="ui-sub-card p-4 rounded-xl space-y-3">
            <div class="flex items-center justify-between">
              <div class="font-bold text-xs">{{ locale === 'en-US' ? 'Operating System & Domestic Environment Diagnostics' : '信创与国产化操作系统运行环境体检' }}</div>
              <button
                @click="fetchChinaGovTelemetry"
                :disabled="isCheckingChinagov"
                class="ui-btn-primary px-3 py-1 text-xs"
              >
                {{ isCheckingChinagov ? (locale === 'en-US' ? 'Checking...' : '检查中...') : (locale === 'en-US' ? 'Recheck' : '重新自检') }}
              </button>
            </div>

            <div v-if="chinagovTelemetry" class="space-y-3 text-xs">
              <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div class="p-3 rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-content)] space-y-1">
                  <div class="font-semibold text-[11px] text-[var(--text-muted)]">{{ locale === 'en-US' ? 'Operating System Identifier' : '操作系统标识' }}</div>
                  <div class="text-sm font-bold flex items-center gap-1.5">
                    <span>{{ chinagovTelemetry.distro_name }}</span>
                    <span v-if="chinagovTelemetry.is_chinagov_linux" class="badge-subtle bg-emerald-500/20 text-emerald-600">国产信创系统</span>
                  </div>
                  <div class="text-[11px] text-[var(--text-muted)] font-mono">{{ locale === 'en-US' ? 'Kernel/Version: ' : '内核/版本: ' }}{{ chinagovTelemetry.distro_version }} · {{ locale === 'en-US' ? 'Arch: ' : '架构: ' }}{{ chinagovTelemetry.cpu_arch }}</div>
                </div>

                <div class="p-3 rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-content)] space-y-1">
                  <div class="font-semibold text-[11px] text-[var(--text-muted)]">{{ locale === 'en-US' ? 'Packet Capture & Firewall Backend' : '网络抓包与防火墙后端' }}</div>
                  <div class="text-sm font-bold flex items-center gap-1.5">
                    <span>{{ chinagovTelemetry.firewall_engine }}</span>
                  </div>
                  <div class="text-[11px] text-[var(--text-muted)]">
                    {{ locale === 'en-US' ? 'Promiscuous Capability:' : '混杂抓包权能:' }}
                    <span :class="chinagovTelemetry.is_capture_capable ? 'text-emerald-500 font-bold' : 'text-rose-500 font-bold'">
                      {{ chinagovTelemetry.is_capture_capable ? (locale === 'en-US' ? 'Ready (Capable)' : '就绪 (Capable)') : (locale === 'en-US' ? 'Restricted (Elevation Required)' : '受限 (需要提权)') }}
                    </span>
                  </div>
                </div>
              </div>

              <div class="p-3 rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-content)] space-y-1">
                <div class="font-semibold text-[11px] text-[var(--text-muted)]">{{ locale === 'en-US' ? 'Portable Offline Runtime Status (WebView2 / WebKit)' : '便携式离线运行时状态 (WebView2 / WebKit)' }}</div>
                <div class="font-mono text-xs">{{ chinagovTelemetry.webview2_status }}</div>
              </div>

              <div class="p-3 rounded-lg bg-sky-500/10 border border-sky-500/20 text-sky-800 dark:text-sky-300 space-y-1">
                <div class="font-bold text-xs flex items-center gap-1">
                  <span>{{ locale === 'en-US' ? 'Field Operations & Elevation Guidelines:' : '现场运维与提权指引:' }}</span>
                </div>
                <div v-for="(inst, i) in chinagovTelemetry.guide_instructions" :key="i" class="text-xs font-mono select-text">
                  • {{ inst }}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, onUnmounted } from 'vue';
import { formatLatencyBadge, useNetToolbox } from '../composables/useNetToolbox';
import { useI18n } from '../i18n';

const { t, locale } = useI18n();
void t;
void locale;

defineProps<{ show: boolean }>();
const emit = defineEmits<{ (e: 'close'): void }>();

const {
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
  switchTerminalProtocol,
  openTerminal,
  closeTerminal,
  sendTerminalCommand,
  chinagovTelemetry,
  isCheckingChinagov,
  fetchChinaGovTelemetry,
} = useNetToolbox();

function onKeydown(e: KeyboardEvent) {
  if (e.key === 'Escape') emit('close');
}

onMounted(() => {
  window.addEventListener('keydown', onKeydown);
  runSubnetCalc();
});

onUnmounted(() => {
  window.removeEventListener('keydown', onKeydown);
});
</script>
