<template>
  <div v-if="isOpen && targetIp" class="fixed inset-0 z-50 flex items-center justify-center p-4 ui-modal-backdrop select-none">
    <div class="w-full max-w-4xl ui-modal-surface rounded-3xl flex flex-col overflow-hidden max-h-[92vh] animate-in fade-in zoom-in-95 duration-150">
      
      <!-- 1. 顶层标题栏 (Liquid Glass) -->
      <header class="ui-nav-glass border-b px-6 py-3.5 flex items-center justify-between shrink-0 flex-wrap gap-3">
        <div class="flex items-center gap-3">
          <span class="w-3 h-3 rounded-full shrink-0" :class="ipScopeClass.dot"></span>
          <div>
            <div class="flex items-center gap-2 flex-wrap">
              <h3 class="text-base font-bold ui-num" style="color: var(--text-primary)">{{ targetIp }}</h3>
              <span :class="['px-2 py-0.5 rounded-lg text-[11px] font-semibold border', ipScopeClass.badge]">
                {{ ipScopeText }}
              </span>
              <span v-if="intel?.zone_name" class="px-2 py-0.5 rounded-lg text-[11px] font-semibold bg-indigo-500/12 text-indigo-700 dark:text-indigo-300 border border-indigo-500/30">
                {{ intel.zone_name }}
              </span>
              <span v-if="hostnameInfo?.hostname" class="px-2 py-0.5 rounded-lg text-[11px] font-semibold bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30 flex items-center gap-1">
                <AppIcon name="info" :size="11" />
                <span>{{ hostnameInfo.hostname }}</span>
              </span>
            </div>
            <p class="text-[11px] ui-num mt-0.5" style="color: var(--text-muted)">
              目标 IP 深度活动追踪、数据出入侦测与全维档案中心
            </p>
          </div>
        </div>

        <div class="flex items-center gap-2 flex-wrap">
          <div class="relative">
            <button @click="showExportMenu = !showExportMenu" class="ui-btn-secondary text-xs px-3 py-1.5 rounded-xl">
              <AppIcon name="document" :size="13" />
              <span>导出报告/PCAP</span>
              <AppIcon name="chevron-down" :size="11" />
            </button>
            <div v-if="showExportMenu"
              class="absolute right-0 top-full mt-1 w-52 ui-modal-surface rounded-xl py-1 z-30 text-xs shadow-lg">
              <button @click="exportReport('markdown')"
                class="w-full text-left px-3 py-1.5 hover:bg-black/5 dark:hover:bg-white/5 flex items-center gap-2 cursor-pointer" style="color: var(--text-primary)">
                <AppIcon name="document" :size="13" />
                <span>Markdown 审计报告 (.md)</span>
              </button>
              <button @click="exportReport('json')"
                class="w-full text-left px-3 py-1.5 hover:bg-black/5 dark:hover:bg-white/5 flex items-center gap-2 cursor-pointer" style="color: var(--text-primary)">
                <AppIcon name="code" :size="13" />
                <span>JSON 全维数据包 (.json)</span>
              </button>
              <div class="border-t my-1" style="border-color: var(--border-subtle)"></div>
              <button @click="exportPcapForTargetIp"
                class="w-full text-left px-3 py-1.5 hover:bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 flex items-center gap-2 cursor-pointer font-medium">
                <AppIcon name="download" :size="13" />
                <span>该 IP 独立抓包切片 (.pcap)</span>
              </button>
            </div>
          </div>

          <button @click="isTracerouteOpen = true"
            class="px-3 py-1.5 rounded-xl bg-sky-500/12 hover:bg-sky-500/20 text-sky-700 dark:text-cyan-300 border border-sky-500/30 text-xs font-semibold transition-colors flex items-center gap-1.5 cursor-pointer"
            title="启动测地线可视路由追踪，绘制该 IP 在地球上的大圆物理路由">
            <AppIcon name="globe" :size="13" />
            <span>测地追踪</span>
          </button>
          <button @click="filterInTrafficList"
            class="ui-btn-primary text-xs px-3 py-1.5 rounded-xl"
            title="在主流量分析列表中即时过滤以该 IP 为源或目的的全部会话">
            <AppIcon name="search" :size="13" />
            <span>流量穿透</span>
          </button>
          <button @click="$emit('close')" class="w-8 h-8 rounded-full ui-pill flex items-center justify-center cursor-pointer" title="关闭">
            <AppIcon name="close" :size="15" />
          </button>
        </div>
      </header>

      <!-- 1.5 功能 Tab 导航栏 -->
      <div class="px-6 py-2 border-b flex items-center justify-between shrink-0 text-xs flex-wrap gap-2" style="background: var(--surface-content-alt); border-color: var(--border-subtle)">
        <div class="flex items-center gap-1.5 flex-wrap">
          <button
            @click="activeTab = 'dossier'"
            :class="['px-3 py-1.5 rounded-xl font-semibold transition-colors cursor-pointer flex items-center gap-1.5',
              activeTab === 'dossier' ? 'bg-sky-500 text-white shadow-xs font-bold' : 'ui-pill']"
          >
            <AppIcon name="info" :size="13" />
            <span>全维身份与情报画像</span>
          </button>
          <button
            @click="activeTab = 'stream'"
            :class="['px-3 py-1.5 rounded-xl font-semibold transition-colors cursor-pointer flex items-center gap-1.5',
              activeTab === 'stream' ? 'bg-sky-500 text-white shadow-xs font-bold' : 'ui-pill']"
          >
            <AppIcon name="activity" :size="13" />
            <span>实时活动追踪与数据出入</span>
            <span class="px-1.5 py-0.5 rounded-full text-[11px] ui-num font-bold"
              :class="activeTab === 'stream' ? 'bg-white/20 text-white' : 'bg-sky-500/15 text-sky-700 dark:text-sky-300'">
              {{ targetPackets.length }} 帧
            </span>
          </button>
          <button
            @click="activeTab = 'security'"
            :class="['px-3 py-1.5 rounded-xl font-semibold transition-colors cursor-pointer flex items-center gap-1.5',
              activeTab === 'security' ? 'bg-sky-500 text-white shadow-xs font-bold' : 'ui-pill']"
          >
            <AppIcon name="shield" :size="13" />
            <span>等保合规与威胁研判</span>
            <span :class="['px-1.5 py-0.5 rounded-full text-[11px] font-bold ui-num border', riskAssessment.badgeClass]">
              {{ riskAssessment.score }}分
            </span>
          </button>
        </div>

        <div class="text-[11px] ui-num" style="color: var(--text-muted)">
          <span>累计出入: </span>
          <strong style="color: var(--text-primary)">{{ stats.rxPackets + stats.txPackets }} 帧</strong>
          <span class="mx-1">|</span>
          <span>总吞吐: </span>
          <strong style="color: var(--text-primary)">{{ formatBytes(stats.rxBytes + stats.txBytes) }}</strong>
        </div>
      </div>

      <!-- 2. 主体内容区 (按 Tab 切换) -->
      <div class="flex-1 overflow-auto custom-scrollbar p-6 space-y-4 text-xs select-text" style="background: var(--surface-content)" @click="showExportMenu = false">
        
        <!-- ==================== TAB 1: 全维身份与情报画像 ==================== -->
        <template v-if="activeTab === 'dossier'">
          <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 ui-sub-card p-3.5 ui-num">
            <div>
              <span class="text-[11px] uppercase font-bold block mb-0.5 font-sans" style="color: var(--text-muted)">地理与运营商 (ISP)</span>
              <div class="font-semibold truncate" style="color: var(--text-primary)" :title="intel?.geo_summary || '本地局域网私网网段'">
                {{ intel?.geo_summary || '本地局域网私网网段' }}
              </div>
            </div>
            <div>
              <span class="text-[11px] uppercase font-bold block mb-0.5 font-sans" style="color: var(--text-muted)">物理 MAC / 链路地址</span>
              <div class="font-semibold truncate" style="color: var(--text-primary)" :title="matchedAsset?.mac || '跨三层路由未知'">
                {{ matchedAsset?.mac || '跨三层路由未知' }}
              </div>
            </div>
            <div>
              <span class="text-[11px] uppercase font-bold block mb-0.5 font-sans" style="color: var(--text-muted)">设备厂商画像 (OUI)</span>
              <div class="font-semibold truncate" style="color: var(--text-primary)" :title="matchedAsset?.vendor || '通用网络节点'">
                {{ matchedAsset?.vendor || '通用网络节点' }}
              </div>
            </div>
            <div>
              <span class="text-[11px] uppercase font-bold block mb-0.5 font-sans" style="color: var(--text-muted)">网络角色推断</span>
              <div class="text-indigo-700 dark:text-indigo-300 font-bold truncate">
                {{ matchedAsset?.role || inferRoleFallback(targetIp) }}
              </div>
            </div>

            <div>
              <span class="text-[11px] uppercase font-bold block mb-0.5 font-sans" style="color: var(--text-muted)">被动操作系统指纹 (TTL)</span>
              <div class="font-bold truncate flex items-center gap-1" style="color: var(--text-primary)" :title="osFingerprint.details">
                <span>{{ osFingerprint.osName }}</span>
                <span v-if="osFingerprint.observedTtl" class="text-[11px] font-normal" style="color: var(--text-muted)">
                  (TTL: {{ osFingerprint.observedTtl }})
                </span>
              </div>
            </div>
            <div>
              <span class="text-[11px] uppercase font-bold block mb-0.5 font-sans" style="color: var(--text-muted)">网络路由跳数推导 (Hops)</span>
              <div class="font-semibold truncate" style="color: var(--text-primary)">
                <span v-if="osFingerprint.hopCount !== null" class="text-emerald-700 dark:text-emerald-400 font-bold">
                  约 {{ osFingerprint.hopCount }} 跳
                </span>
                <span v-else style="color: var(--text-muted)">本地直连或未捕获出向</span>
              </div>
            </div>
            <div>
              <span class="text-[11px] uppercase font-bold block mb-0.5 font-sans" style="color: var(--text-muted)">主机名 / 计算机名</span>
              <div class="font-semibold truncate flex items-center justify-between gap-1" style="color: var(--text-primary)" :title="hostnameInfo?.hostname || '未注册或未响应'">
                <span class="truncate">{{ hostnameInfo?.hostname || '未注册或未响应' }}</span>
                <button @click="fetchHostname" :disabled="isResolvingHostname"
                  class="text-[11px] hover:underline shrink-0 cursor-pointer flex items-center" style="color: var(--accent-primary-text)" title="重新解析主机名">
                  <AppIcon name="refresh" :size="12" :class="isResolvingHostname ? 'animate-spin' : ''" />
                </button>
              </div>
            </div>
            <div>
              <span class="text-[11px] uppercase font-bold block mb-0.5 font-sans" style="color: var(--text-muted)">反向 PTR 域名 (RFC 1035)</span>
              <div class="font-semibold truncate" style="color: var(--text-primary)" :title="hostnameInfo?.reverse_ptr || '无 PTR 记录'">
                {{ hostnameInfo?.reverse_ptr || '无 PTR 记录' }}
              </div>
            </div>
          </div>

          <div class="space-y-2.5 ui-num">
            <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div class="ui-content-card p-3.5">
                <span class="text-[11px] uppercase font-bold block mb-1 font-sans" style="color: var(--text-muted)">入向数据出入 (RX)</span>
                <div class="text-base font-bold text-sky-700 dark:text-sky-400">{{ stats.rxPackets }} <span class="text-xs font-normal" style="color: var(--text-muted)">帧</span></div>
                <div class="text-[11px] mt-0.5" style="color: var(--text-secondary)">{{ formatBytes(stats.rxBytes) }}</div>
              </div>

              <div class="ui-content-card p-3.5">
                <span class="text-[11px] uppercase font-bold block mb-1 font-sans" style="color: var(--text-muted)">出向数据出入 (TX)</span>
                <div class="text-base font-bold text-emerald-700 dark:text-emerald-400">{{ stats.txPackets }} <span class="text-xs font-normal" style="color: var(--text-muted)">帧</span></div>
                <div class="text-[11px] mt-0.5" style="color: var(--text-secondary)">{{ formatBytes(stats.txBytes) }}</div>
              </div>

              <div class="ui-content-card p-3.5">
                <span class="text-[11px] uppercase font-bold block mb-1 font-sans" style="color: var(--text-muted)">首现与末次活跃</span>
                <div class="text-[11px] truncate" style="color: var(--text-secondary)" :title="stats.firstSeen || 'N/A'">首现: {{ stats.firstSeen || '本次未捕获' }}</div>
                <div class="text-[11px] truncate mt-0.5" style="color: var(--text-secondary)" :title="stats.lastSeen || 'N/A'">末次: {{ stats.lastSeen || '本次未捕获' }}</div>
              </div>
            </div>

            <div class="ui-content-card p-3">
              <div class="flex items-center justify-between text-[11px] font-semibold mb-1.5">
                <span class="text-sky-700 dark:text-sky-400">入向接收 (RX): {{ rxRatioText }}%</span>
                <span class="font-normal" style="color: var(--text-secondary)">通信形态: <strong style="color: var(--text-primary)">{{ trafficRoleText }}</strong></span>
                <span class="text-emerald-700 dark:text-emerald-400">出向发送 (TX): {{ txRatioText }}%</span>
              </div>
              <div class="w-full h-2 rounded-full overflow-hidden flex" style="background: var(--surface-elevated)">
                <div class="bg-sky-500 h-full transition-all duration-300" :style="{ width: rxRatioText + '%' }"></div>
                <div class="bg-emerald-500 h-full transition-all duration-300" :style="{ width: txRatioText + '%' }"></div>
              </div>
            </div>
          </div>

          <div class="ui-content-card p-3.5 space-y-2">
            <span class="text-[11px] uppercase font-bold block" style="color: var(--text-muted)">涉及网络规约分布 (Protocol Fingerprints)</span>
            <div class="flex items-center gap-1.5 flex-wrap">
              <div v-for="(cnt, pr) in stats.protocolCounts" :key="pr"
                class="flex items-center gap-1.5 ui-pill px-2.5 py-1 rounded-xl text-xs font-semibold">
                <span class="font-bold text-blue-700 dark:text-sky-300">{{ pr }}</span>
                <span class="text-[11px] px-1.5 py-0.5 rounded-md ui-num" style="background: var(--surface-content); color: var(--text-secondary)">{{ cnt }} 帧</span>
              </div>
              <div v-if="Object.keys(stats.protocolCounts).length === 0" class="text-xs py-1" style="color: var(--text-muted)">
                暂未沉淀规约数据
              </div>
            </div>
          </div>

          <div class="ui-content-card p-3.5 space-y-2">
            <div class="flex items-center justify-between">
              <span class="text-[11px] uppercase font-bold" style="color: var(--text-muted)">高频通信对端节点 (Top Communication Peers)</span>
              <span class="text-[11px] ui-num" style="color: var(--text-muted)">共关联 {{ topPeers.length }} 个节点</span>
            </div>
            <div class="divide-y max-h-40 overflow-auto custom-scrollbar pr-1 ui-num" style="border-color: var(--border-subtle)">
              <div v-for="peer in topPeers" :key="peer.peerIp"
                class="py-1.5 flex items-center justify-between hover:bg-black/5 dark:hover:bg-white/5 px-2 rounded-lg transition-colors cursor-pointer"
                @click="drillDownToPeer(peer.peerIp)">
                <div class="flex items-center gap-2 truncate max-w-sm">
                  <span :class="peer.direction === 'out' ? 'text-emerald-700 dark:text-emerald-400' : 'text-sky-700 dark:text-sky-400'" class="font-bold">
                    {{ peer.direction === 'out' ? '→' : '←' }}
                  </span>
                  <span class="font-bold hover:underline" style="color: var(--text-primary)">{{ peer.peerIp }}</span>
                  <span v-if="peer.zoneOrGeo" class="text-[11px] truncate max-w-[140px] ui-pill px-1.5 py-0.5 rounded">
                    {{ peer.zoneOrGeo }}
                  </span>
                </div>
                <div class="flex items-center gap-3 text-[11px] shrink-0" style="color: var(--text-muted)">
                  <span class="text-amber-700 dark:text-amber-300 font-semibold">{{ peer.mainProtocol }}</span>
                  <span class="font-bold" style="color: var(--text-primary)">{{ peer.count }} 次会话</span>
                  <span class="text-[11px] font-semibold hover:underline" style="color: var(--accent-primary-text)">穿透</span>
                </div>
              </div>
              <div v-if="topPeers.length === 0" class="text-xs py-3 text-center" style="color: var(--text-muted)">
                暂无已记录的对端通信会话
              </div>
            </div>
          </div>

          <div class="ui-content-card p-3.5 space-y-3">
            <div class="flex items-center justify-between flex-wrap gap-2">
              <span class="text-[11px] uppercase font-bold" style="color: var(--text-muted)">合规连通性探活与端口审计 (Compliance Probing)</span>
              <span class="text-[11px]" style="color: var(--text-muted)">基于 RFC 792 ICMP Echo 与 RFC 793 TCP Connect</span>
            </div>

            <div class="flex items-center gap-3 flex-wrap">
              <button @click="doIcmpPing" :disabled="isPinging" class="ui-btn-primary text-xs px-3 py-1.5 rounded-xl">
                <AppIcon :name="isPinging ? 'refresh' : 'zap'" :size="13" :class="isPinging ? 'animate-spin' : ''" />
                <span>ICMP 连通性测试 (Ping)</span>
              </button>

              <button @click="doPortProbe" :disabled="isProbingPorts" class="ui-btn-secondary text-xs px-3 py-1.5 rounded-xl">
                <AppIcon :name="isProbingPorts ? 'refresh' : 'search'" :size="13" :class="isProbingPorts ? 'animate-spin' : ''" />
                <span>网络服务与端口探测</span>
              </button>
            </div>

            <div v-if="pingResult" class="p-2.5 rounded-xl border text-xs ui-num"
              :class="pingResult.status === 'ONLINE' ? 'bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 border-emerald-500/30' : 'bg-rose-500/12 text-rose-700 dark:text-rose-300 border-rose-500/30'">
              <div class="flex items-center justify-between">
                <span>状态: <strong>{{ pingResult.status === 'ONLINE' ? '在线可达 (Host Reachable)' : '不可达/超时 (Offline/Timeout)' }}</strong></span>
                <span>RTT 时延: <strong>{{ pingResult.latency_ms.toFixed(1) }} ms</strong></span>
              </div>
            </div>

            <div v-if="openPorts.length > 0" class="space-y-1">
              <span class="text-[11px] font-bold block" style="color: var(--text-secondary)">发现开放端口与服务画像:</span>
              <div class="flex items-center gap-1.5 flex-wrap">
                <span v-for="port in openPorts" :key="port"
                  class="px-2 py-0.5 rounded-lg bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30 text-[11px] font-bold ui-num">
                  :{{ port }} ({{ inferProtocolByPort(port) }})
                </span>
              </div>
            </div>
          </div>
        </template>

        <!-- ==================== TAB 2: 实时活动追踪与数据出入 ==================== -->
        <template v-else-if="activeTab === 'stream'">
          <div class="space-y-3">
            <div class="flex items-center justify-between gap-3 flex-wrap">
              <div class="flex items-center gap-2 flex-1 min-w-[240px]">
                <input
                  v-model="streamSearch"
                  placeholder="过滤对端 IP / 端口 / 协议 / 载荷文本"
                  class="w-full ui-input ui-num text-xs py-1.5 px-3"
                />
              </div>

              <button @click="exportPcapForTargetIp" class="ui-btn-primary text-xs px-3 py-1.5 rounded-xl">
                <AppIcon name="download" :size="13" />
                <span>导出该 IP 抓包 (.pcap)</span>
              </button>
            </div>

            <div class="ui-content-card overflow-hidden">
              <div class="max-h-[50vh] overflow-auto custom-scrollbar">
                <table class="w-full text-left text-xs border-collapse table-fixed">
                  <thead class="ui-table-head text-[11px] font-bold uppercase sticky top-0 z-10 select-none">
                    <tr>
                      <th class="p-2 w-[16%]">时间戳</th>
                      <th class="p-2 w-[12%] text-center">出入流向</th>
                      <th class="p-2 w-[30%]">通信端点 (对端)</th>
                      <th class="p-2 w-[12%]">规约协议</th>
                      <th class="p-2 w-[10%] text-right">载荷长度</th>
                      <th class="p-2 w-[20%]">载荷摘要 / 交互特征</th>
                    </tr>
                  </thead>
                  <tbody class="divide-y ui-num" style="border-color: var(--border-subtle); color: var(--text-secondary)">
                    <tr
                      v-for="pkt in filteredTargetPackets"
                      :key="pkt.id"
                      @click="selectedStreamPacket = selectedStreamPacket?.id === pkt.id ? null : pkt"
                      :class="['hover:bg-black/5 dark:hover:bg-white/5 cursor-pointer transition-colors',
                        selectedStreamPacket?.id === pkt.id ? 'bg-sky-500/10' : '']"
                    >
                      <td class="p-2 text-[11px] truncate" style="color: var(--text-muted)">{{ pkt.timestamp }}</td>
                      <td class="p-2 text-center">
                        <span
                          :class="['px-1.5 py-0.5 rounded text-[11px] font-bold uppercase border',
                            pkt.src_ip === targetIp ? 'bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 border-emerald-500/30' : 'bg-sky-500/12 text-sky-700 dark:text-sky-300 border-sky-500/30']"
                        >
                          {{ pkt.src_ip === targetIp ? 'TX 出向' : 'RX 入向' }}
                        </span>
                      </td>
                      <td class="p-2 truncate font-bold" style="color: var(--text-primary)">
                        <span v-if="pkt.src_ip === targetIp">→ {{ pkt.dst_ip }}:{{ pkt.dst_port }}</span>
                        <span v-else>← {{ pkt.src_ip }}:{{ pkt.src_port }}</span>
                      </td>
                      <td class="p-2 truncate">
                        <span class="px-1.5 py-0.5 rounded ui-pill font-bold text-[11px]">
                          {{ pkt.protocol }}
                        </span>
                      </td>
                      <td class="p-2 text-right font-bold truncate" style="color: var(--text-primary)">{{ pkt.length }} B</td>
                      <td class="p-2 text-[11px] truncate" style="color: var(--text-muted)" :title="pkt.raw_text || pkt.payload_hex">
                        {{ pkt.raw_text || (pkt.payload_hex ? `HEX[${pkt.payload_hex.slice(0, 20)}...]` : '[空载荷]') }}
                      </td>
                    </tr>
                    <tr v-if="filteredTargetPackets.length === 0">
                      <td colspan="6" class="p-8">
                        <EmptyState icon="activity" title="暂无符合条件的实时出入数据帧" description="请在主监控界面启动抓取嗅探以持续收集关联会话。" />
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

            <!-- 选中报文的十六进制 HexDump 与深度展开 -->
            <div v-if="selectedStreamPacket" class="ui-sub-card p-4 space-y-2 text-xs ui-num animate-in fade-in duration-100">
              <div class="flex items-center justify-between border-b pb-2" style="border-color: var(--border-subtle)">
                <span class="font-bold text-emerald-700 dark:text-emerald-400">
                  报文 #{{ selectedStreamPacket.id }} 深度剖析 ({{ selectedStreamPacket.protocol }})
                </span>
                <span class="text-[11px]" style="color: var(--text-muted)">
                  物理长度: {{ selectedStreamPacket.length }} 字节 | 熵值: {{ selectedStreamPacket.entropy?.toFixed(2) }}
                </span>
              </div>
              <div class="text-[11px]" style="color: var(--text-secondary)">
                <span>通信方向: </span>
                <strong :class="selectedStreamPacket.src_ip === targetIp ? 'text-emerald-700 dark:text-emerald-400' : 'text-sky-700 dark:text-sky-400'">
                  {{ selectedStreamPacket.src_ip }}:{{ selectedStreamPacket.src_port }} → {{ selectedStreamPacket.dst_ip }}:{{ selectedStreamPacket.dst_port }}
                </strong>
              </div>
              <div v-if="selectedStreamPacket.raw_text" class="ui-input font-mono-code p-2.5 text-[11px] whitespace-pre-wrap max-h-32 overflow-auto custom-scrollbar">
                {{ selectedStreamPacket.raw_text }}
              </div>
              <div v-if="selectedStreamPacket.payload_hex" class="ui-input font-mono-code p-2.5 text-[11px] break-all max-h-24 overflow-auto custom-scrollbar" style="color: var(--text-secondary)">
                {{ selectedStreamPacket.payload_hex }}
              </div>
            </div>
          </div>
        </template>

        <!-- ==================== TAB 3: 等保合规与威胁研判 ==================== -->
        <template v-else-if="activeTab === 'security'">
          <div class="ui-content-card p-5 space-y-4">
            <div class="flex items-center justify-between flex-wrap gap-3">
              <div>
                <h4 class="text-sm font-bold" style="color: var(--text-primary)">等保 2.0 行为异常与合规风险研判模型</h4>
                <p class="text-[11px] mt-0.5" style="color: var(--text-muted)">
                  依据 GB/T 22239-2019 标准，针对目标 IP 的通信流量、端口探测、高熵通道与会话对称性进行全自动审计
                </p>
              </div>
              <div class="text-right">
                <span :class="['px-3 py-1 rounded-xl text-xs font-bold border inline-block ui-num', riskAssessment.badgeClass]">
                  健康指数: {{ riskAssessment.score }} / 100
                </span>
                <span class="block text-[11px] mt-1" style="color: var(--text-muted)">综合定级: {{ riskAssessment.levelText }}</span>
              </div>
            </div>

            <div class="space-y-2.5">
              <div v-for="(item, idx) in riskAssessment.items" :key="idx"
                class="p-3.5 rounded-2xl text-xs flex items-start justify-between border"
                :class="item.severity === 'high' ? 'bg-rose-500/12 text-rose-700 dark:text-rose-200 border-rose-500/30' : (item.severity === 'medium' ? 'bg-amber-500/12 text-amber-700 dark:text-amber-200 border-amber-500/30' : 'bg-emerald-500/12 text-emerald-700 dark:text-emerald-200 border-emerald-500/30')">
                <div class="flex items-start gap-3">
                  <AppIcon :name="item.severity === 'low' ? 'check' : 'alert'" :size="16" class="shrink-0 mt-0.5" />
                  <div class="space-y-1">
                    <span class="font-bold text-sm block" style="color: var(--text-primary)">{{ item.title }}</span>
                    <p class="text-xs leading-relaxed" style="color: var(--text-secondary)">{{ item.desc }}</p>
                  </div>
                </div>
                <span class="text-xs font-bold ui-num shrink-0 ml-3 px-2 py-0.5 rounded-lg ui-pill">
                  {{ item.scoreText }}
                </span>
              </div>
            </div>

            <div class="ui-sub-card p-4 space-y-2 text-xs">
              <span class="font-bold flex items-center gap-1.5" style="color: var(--text-primary)">
                <AppIcon name="shield" :size="14" />
                <span>等保审计与运维处置建议</span>
              </span>
              <ul class="list-disc list-inside space-y-1 text-[11px]" style="color: var(--text-secondary)">
                <li>如检测到高频多端口探测，建议核实该节点是否为合法网络扫描器；若非授权，需在核心交换机/网关上阻断其横向通信；</li>
                <li>如存在非标准端口高熵载荷，需结合深度包检测（DPI）研判是否存在外部 C2 通道或未加密敏感资产外发；</li>
                <li>对于明文传输（HTTP/Telnet/FTP），建议整改升级为 TLS 1.3 / SSH 等机密性传输规约。</li>
              </ul>
            </div>
          </div>
        </template>

      </div>

      <!-- 3. 底层控制按钮 -->
      <footer class="px-6 py-3 border-t flex items-center justify-between shrink-0 text-xs" style="background: var(--surface-content-alt); border-color: var(--border-subtle)">
        <span class="text-[11px]" style="color: var(--text-muted)">Omni-Probe 全维 IP 画像与深度追踪引擎</span>
        <button @click="$emit('close')" class="ui-btn-secondary text-xs px-4 py-1.5 rounded-xl font-semibold">
          关闭
        </button>
      </footer>
    </div>

    <GeodesicTracerouteModal
      :isOpen="isTracerouteOpen"
      :initialTarget="targetIp"
      @close="isTracerouteOpen = false"
    />
  </div>
</template>

<script setup lang="ts">
import { notifySuccess, notifyError } from '../composables/useNotification';
import { ref, computed, watch } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import AppIcon from './AppIcon.vue';
import EmptyState from './EmptyState.vue';
import GeodesicTracerouteModal from './GeodesicTracerouteModal.vue';
import { saveTextViaNativeDesktop } from '../composables/useDesktopSave';

const isTracerouteOpen = ref(false);

interface DiscoveredAsset {
  ip: string;
  mac: string;
  role: string;
  scope: string;
  vendor: string;
  first_seen_ts: number;
  last_seen_ts: number;
  packet_count: number;
  protocols: string[];
  ports: number[];
  zone_name?: string;
  geo_summary?: string;
  hostname?: string;
}

interface IpIntelligenceResult {
  ip: string;
  is_rfc1918: boolean;
  is_loopback: boolean;
  is_multicast: boolean;
  zone_name: string;
  geo_summary: string;
  country: string;
  province: string;
  city: string;
  isp: string;
}

interface IpHostnameInfo {
  ip: string;
  hostname?: string;
  reverse_ptr?: string;
  netbios_name?: string;
}

const props = defineProps<{
  isOpen: boolean;
  targetIp: string;
  packets: any[];
  assets?: DiscoveredAsset[];
}>();

const emit = defineEmits(['close', 'filterTraffic', 'drillDown']);

const activeTab = ref<'dossier' | 'stream' | 'security'>('dossier');
const intel = ref<IpIntelligenceResult | null>(null);
const hostnameInfo = ref<IpHostnameInfo | null>(null);
const isResolvingHostname = ref(false);
const showExportMenu = ref(false);

const streamSearch = ref('');
const selectedStreamPacket = ref<any | null>(null);

const isPinging = ref(false);
const pingResult = ref<any | null>(null);
const isProbingPorts = ref(false);
const openPorts = ref<number[]>([]);

// 过滤出所有与当前 targetIp 相关的出入报文（按时间倒序）
const targetPackets = computed(() => {
  const ip = props.targetIp;
  if (!ip || !props.packets) return [];
  return props.packets.filter(p => p.src_ip === ip || p.dst_ip === ip);
});

// 实时活动流二次文本过滤
const filteredTargetPackets = computed(() => {
  let list = targetPackets.value;
  const q = streamSearch.value.trim().toLowerCase();
  if (!q) return list.slice(-200).reverse();

  return list.filter(p => {
    return p.src_ip.toLowerCase().includes(q) ||
      p.dst_ip.toLowerCase().includes(q) ||
      String(p.src_port).includes(q) ||
      String(p.dst_port).includes(q) ||
      (p.protocol && p.protocol.toLowerCase().includes(q)) ||
      (p.raw_text && p.raw_text.toLowerCase().includes(q)) ||
      (p.payload_hex && p.payload_hex.toLowerCase().includes(q));
  }).slice(-200).reverse();
});

// 匹配资产库中的设备画像
const matchedAsset = computed(() => {
  return props.assets?.find(a => a.ip === props.targetIp);
});

// IP 作用域与徽章色彩
const ipScopeText = computed(() => {
  const ip = props.targetIp;
  if (ip === '127.0.0.1' || ip === '::1' || ip.toLowerCase() === 'localhost') return '本地回环';
  if (ip.startsWith('192.168.') || ip.startsWith('10.') || (ip.startsWith('172.') && !ip.startsWith('172.0.'))) return '局域网私网 (LAN)';
  if (ip.startsWith('169.254.')) return '链路本地 (APIPA)';
  if (ip.startsWith('224.') || ip.startsWith('239.')) return '组播地址';
  return '公网/外部节点 (WAN)';
});

const ipScopeClass = computed(() => {
  const text = ipScopeText.value;
  if (text.includes('LAN')) return { dot: 'bg-sky-500', badge: 'bg-sky-500/12 text-sky-700 dark:text-sky-300 border-sky-500/30' };
  if (text.includes('WAN')) return { dot: 'bg-emerald-500', badge: 'bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 border-emerald-500/30' };
  if (text.includes('回环')) return { dot: 'bg-amber-500', badge: 'bg-amber-500/12 text-amber-700 dark:text-amber-300 border-amber-500/30' };
  return { dot: 'bg-slate-400', badge: 'ui-pill' };
});

// 行为吞吐统计
const stats = computed(() => {
  const ip = props.targetIp;
  let rxPackets = 0;
  let rxBytes = 0;
  let txPackets = 0;
  let txBytes = 0;
  let firstSeen: string | null = null;
  let lastSeen: string | null = null;
  const protocolCounts: Record<string, number> = {};

  if (!ip || !props.packets) return { rxPackets, rxBytes, txPackets, txBytes, firstSeen, lastSeen, protocolCounts };

  for (const p of props.packets) {
    const isSrc = p.src_ip === ip;
    const isDst = p.dst_ip === ip;
    if (!isSrc && !isDst) continue;

    if (!firstSeen) firstSeen = p.timestamp;
    lastSeen = p.timestamp;

    const len = p.length || 0;
    if (isSrc) {
      txPackets++;
      txBytes += len;
    }
    if (isDst) {
      rxPackets++;
      rxBytes += len;
    }

    const pr = p.protocol || 'TCP';
    protocolCounts[pr] = (protocolCounts[pr] || 0) + 1;
  }

  return { rxPackets, rxBytes, txPackets, txBytes, firstSeen, lastSeen, protocolCounts };
});

// 流量比例与角色计算
const rxRatioText = computed(() => {
  const total = stats.value.rxBytes + stats.value.txBytes;
  if (total === 0) return '50.0';
  return ((stats.value.rxBytes / total) * 100).toFixed(1);
});

const txRatioText = computed(() => {
  const total = stats.value.rxBytes + stats.value.txBytes;
  if (total === 0) return '50.0';
  return ((stats.value.txBytes / total) * 100).toFixed(1);
});

const trafficRoleText = computed(() => {
  const rx = stats.value.rxBytes;
  const tx = stats.value.txBytes;
  const total = rx + tx;
  if (total === 0) return '待观测';
  if (tx / total > 0.75) return '数据服务提供端 (Server/Producer)';
  if (rx / total > 0.75) return '数据消费者/客户端 (Client/Consumer)';
  return '双向交互对等端 (Balanced Peer)';
});

// 被动操作系统指纹识别与路由跳数推导 (Passive OS Fingerprinting via TTL)
const osFingerprint = computed(() => {
  const ip = props.targetIp;
  if (!ip || !props.packets) {
    return { osName: '未知系统', hopCount: null, observedTtl: null, details: '暂无出向数据帧' };
  }

  let observedTtl: number | null = null;
  for (const p of props.packets) {
    if (p.src_ip === ip && p.business_data && typeof p.business_data.ttl === 'number' && p.business_data.ttl > 0) {
      observedTtl = p.business_data.ttl;
      break;
    }
  }

  if (observedTtl === null) {
    return { osName: '未捕获出向报文', hopCount: null, observedTtl: null, details: '尚未捕获到该 IP 发出的三层报文' };
  }

  if (observedTtl <= 64) {
    const hop = 64 - observedTtl;
    return {
      osName: 'Linux / Unix / macOS / 嵌入式RTOS',
      hopCount: hop,
      observedTtl,
      details: `推导初始 TTL=64, 观测 TTL=${observedTtl}, 经历约 ${hop} 跳路由`
    };
  } else if (observedTtl <= 128) {
    const hop = 128 - observedTtl;
    return {
      osName: 'Microsoft Windows (Desktop/Server)',
      hopCount: hop,
      observedTtl,
      details: `推导初始 TTL=128, 观测 TTL=${observedTtl}, 经历约 ${hop} 跳路由`
    };
  } else {
    const hop = 255 - observedTtl;
    return {
      osName: '网络设备 / Cisco IOS / 工业交换机',
      hopCount: hop,
      observedTtl,
      details: `推导初始 TTL=255, 观测 TTL=${observedTtl}, 经历约 ${hop} 跳路由`
    };
  }
});

// 等保 2.0 异常行为与合规风险研判模型
const riskAssessment = computed(() => {
  const ip = props.targetIp;
  let score = 100;
  const items: Array<{ title: string; desc: string; severity: 'low' | 'medium' | 'high'; scoreText: string }> = [];

  if (!ip || !props.packets) {
    return { score: 100, levelText: '基线正常', badgeClass: 'bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 border-emerald-500/30', items };
  }

  const targetPorts = new Set<number>();
  let txCount = 0;
  let hasHighEntropy = false;
  let hasCleartext = false;

  for (const p of props.packets) {
    if (p.src_ip === ip) {
      txCount++;
      if (p.dst_port) targetPorts.add(p.dst_port);
      if (p.entropy && p.entropy >= 7.2 && p.dst_port !== 443 && p.dst_port !== 8443) {
        hasHighEntropy = true;
      }
      if (['HTTP', 'TELNET', 'FTP', 'TFTP'].includes(p.protocol)) {
        hasCleartext = true;
      }
    }
  }

  if (targetPorts.size >= 6) {
    score -= 25;
    items.push({
      title: '高频多端口探测嫌疑 (Port Probing)',
      desc: `该节点在监测周期内向 ${targetPorts.size} 个不同端口发起连接请求，疑似正在执行资产遍历或服务发现`,
      severity: 'high',
      scoreText: '-25 分'
    });
  }

  if (hasHighEntropy) {
    score -= 20;
    items.push({
      title: '非标准端口高熵载荷 (High-Entropy Egress)',
      desc: '观测到在非 443 端口上载荷信息熵 ≥ 7.2，疑似存在隐蔽加密通道、勒索数据外发或打包压缩流量',
      severity: 'high',
      scoreText: '-20 分'
    });
  }

  if (hasCleartext) {
    score -= 15;
    items.push({
      title: '非安全明文规约通信 (Cleartext Transmission)',
      desc: '检测到 HTTP / Telnet / FTP 明文规约通信，不符合等保 2.0 通信传输机密性与完整性审计要求',
      severity: 'medium',
      scoreText: '-15 分'
    });
  }

  if (txCount > 50 && stats.value.rxPackets === 0) {
    score -= 15;
    items.push({
      title: '单向报文无应答倾斜 (Traffic Asymmetry)',
      desc: '发包数量较多但未收到任何对端回包，疑似存在单向泛洪或未建立连接的半开探测',
      severity: 'medium',
      scoreText: '-15 分'
    });
  }

  if (items.length === 0) {
    items.push({
      title: '未发现异常威胁与违规行为 (Clean & Compliant)',
      desc: '网络行为特征平稳，未检测到端口扫描、隐蔽高熵通道或异常明文泄露',
      severity: 'low',
      scoreText: '合规基线达标'
    });
  }

  score = Math.max(0, score);
  let levelText = '基线正常';
  let badgeClass = 'bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 border-emerald-500/30';
  if (score < 70) {
    levelText = '高危威胁';
    badgeClass = 'bg-rose-500/12 text-rose-700 dark:text-rose-300 border-rose-500/30';
  } else if (score < 90) {
    levelText = '中危关注';
    badgeClass = 'bg-amber-500/12 text-amber-700 dark:text-amber-300 border-amber-500/30';
  }

  return { score, levelText, badgeClass, items };
});

// 计算高频通信对端 (Top Peers)
const topPeers = computed(() => {
  const ip = props.targetIp;
  if (!ip || !props.packets) return [];

  const peerMap = new Map<string, { count: number; direction: 'in' | 'out'; mainProtocol: string }>();

  for (const p of props.packets) {
    if (p.src_ip === ip && p.dst_ip && p.dst_ip !== ip) {
      const entry = peerMap.get(p.dst_ip) || { count: 0, direction: 'out', mainProtocol: p.protocol || 'TCP' };
      entry.count++;
      peerMap.set(p.dst_ip, entry);
    } else if (p.dst_ip === ip && p.src_ip && p.src_ip !== ip) {
      const entry = peerMap.get(p.src_ip) || { count: 0, direction: 'in', mainProtocol: p.protocol || 'TCP' };
      entry.count++;
      peerMap.set(p.src_ip, entry);
    }
  }

  const list = Array.from(peerMap.entries()).map(([peerIp, data]) => {
    const asset = props.assets?.find(a => a.ip === peerIp);
    return {
      peerIp,
      count: data.count,
      direction: data.direction,
      mainProtocol: data.mainProtocol,
      zoneOrGeo: asset?.zone_name || asset?.geo_summary || (peerIp.startsWith('192.168.') ? '局域网' : ''),
    };
  });

  list.sort((a, b) => b.count - a.count);
  return list.slice(0, 10);
});

// 监听目标 IP 变化，自动查询 IP 资产情报与主机名
watch(() => [props.isOpen, props.targetIp], async ([open, ip]) => {
  if (open && ip) {
    pingResult.value = null;
    openPorts.value = matchedAsset.value?.ports || [];
    try {
      intel.value = await invoke<IpIntelligenceResult>('classify_ip_cmd', { ip });
    } catch {
      intel.value = null;
    }
    fetchHostname();
  }
}, { immediate: true });

async function fetchHostname() {
  if (!props.targetIp || isResolvingHostname.value) return;
  isResolvingHostname.value = true;
  try {
    hostnameInfo.value = await invoke<IpHostnameInfo>('resolve_ip_hostname_cmd', { ip: props.targetIp });
  } catch {
    hostnameInfo.value = null;
  } finally {
    isResolvingHostname.value = false;
  }
}

async function doIcmpPing() {
  if (!props.targetIp || isPinging.value) return;
  isPinging.value = true;
  pingResult.value = null;
  try {
    pingResult.value = await invoke('run_icmp_ping_cmd', { targetIp: props.targetIp, timeoutMs: 2500 });
  } catch (e: any) {
    pingResult.value = { status: 'OFFLINE', latency_ms: 0 };
  } finally {
    isPinging.value = false;
  }
}

async function doPortProbe() {
  if (!props.targetIp || isProbingPorts.value) return;
  isProbingPorts.value = true;
  try {
    const ports = await invoke<number[]>('probe_asset_ports_cmd', { ip: props.targetIp });
    openPorts.value = ports;
  } catch (err) {
    console.warn('[IpDossierModal] probe_asset_ports_cmd failed for target IP:', props.targetIp, err);
  } finally {
    isProbingPorts.value = false;
  }
}

function filterInTrafficList() {
  emit('filterTraffic', props.targetIp);
  emit('close');
}

function drillDownToPeer(peerIp: string) {
  emit('drillDown', peerIp);
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function inferRoleFallback(ip: string): string {
  if (ip.endsWith('.1') || ip.endsWith('.254')) return '核心网关 / 路由器';
  if (ip.startsWith('192.168.') || ip.startsWith('10.')) return '局域网活跃终端';
  return '外部网络节点';
}

function inferProtocolByPort(port: number): string {
  const map: Record<number, string> = {
    80: 'HTTP', 443: 'HTTPS', 502: 'Modbus', 5003: 'SL651水利',
    1883: 'MQTT', 22: 'SSH', 445: 'SMB', 53: 'DNS', 21: 'FTP',
    23: 'Telnet', 3389: 'RDP', 8080: 'Web'
  };
  return map[port] || 'TCP';
}

// 导出当前 IP 专属 PCAP 抓包文件
async function exportPcapForTargetIp() {
  showExportMenu.value = false;
  const ip = props.targetIp;
  const dateStr = new Date().toISOString().replace(/[:.]/g, '-');
  const filename = `OmniProbe_Target_${ip}_${dateStr}.pcap`;

  const packetsToExport = targetPackets.value.map(p => ({
    id: p.id,
    timestamp: p.timestamp,
    direction: p.direction,
    transport: p.transport,
    protocol: p.protocol,
    src_ip: p.src_ip,
    dst_ip: p.dst_ip,
    src_port: p.src_port,
    dst_port: p.dst_port,
    length: p.length,
    payload_hex: p.payload_hex,
    entropy: p.entropy,
    entropy_level: p.entropy_level,
    mac_src: p.mac_src,
    mac_dst: p.mac_dst,
    chain_hash: p.chain_hash,
    raw_text: p.raw_text,
  }));

  try {
    const count = await invoke<number>('export_packets_pcap_cmd', {
      packets: packetsToExport,
      filePath: filename,
    });
    notifySuccess('PCAP 数据包导出成功', `成功将目标 IP ${ip} 的 ${count} 帧报文导出至文件: ${filename}`);
  } catch (e: any) {
    notifyError('导出 PCAP 文件受阻', e);
  }
}

// 导出工业级 IP 全息溯源报告 (Markdown / JSON)
async function exportReport(format: 'markdown' | 'json') {
  showExportMenu.value = false;
  const ip = props.targetIp;
  const dateStr = new Date().toISOString().replace(/[:.]/g, '-');

  if (format === 'json') {
    const reportData = {
      meta: {
        report_type: 'Omni-Probe IP Intelligence & Dossier Audit',
        generated_at: new Date().toISOString(),
        target_ip: ip,
        health_score: riskAssessment.value.score,
        risk_level: riskAssessment.value.levelText,
      },
      identity: {
        scope: ipScopeText.value,
        zone_name: intel.value?.zone_name || 'N/A',
        geo_summary: intel.value?.geo_summary || 'N/A',
        mac: matchedAsset.value?.mac || 'N/A',
        vendor: matchedAsset.value?.vendor || 'N/A',
        role: matchedAsset.value?.role || inferRoleFallback(ip),
        hostname: hostnameInfo.value?.hostname || 'N/A',
        reverse_ptr: hostnameInfo.value?.reverse_ptr || 'N/A',
        os_fingerprint: osFingerprint.value,
      },
      traffic_statistics: {
        rx_packets: stats.value.rxPackets,
        rx_bytes: stats.value.rxBytes,
        tx_packets: stats.value.txPackets,
        tx_bytes: stats.value.txBytes,
        first_seen: stats.value.firstSeen,
        last_seen: stats.value.lastSeen,
        traffic_role: trafficRoleText.value,
        protocols: stats.value.protocolCounts,
      },
      security_assessment: riskAssessment.value.items,
      top_peers: topPeers.value,
      open_ports: openPorts.value.map(p => ({ port: p, service: inferProtocolByPort(p) })),
    };

    await saveTextViaNativeDesktop(
      `OmniProbe_Dossier_${ip}_${dateStr}.json`,
      JSON.stringify(reportData, null, 2),
      'JSON 档案 (*.json)',
      '*.json',
      '导出 IP 全息数字档案 JSON'
    );
  } else {
    const md = `# Omni-Probe 工业级 IP 全息画像与审计溯源报告

- **目标 IP 地址**: \`${ip}\`
- **生成时间**: ${new Date().toLocaleString()}
- **等保 2.0 健康指数**: **${riskAssessment.value.score} / 100** (${riskAssessment.value.levelText})
- **网络作用域**: ${ipScopeText.value}
- **所属安全域**: ${intel.value?.zone_name || '未划分'}
- **地理/运营商**: ${intel.value?.geo_summary || '本地局域网私网'}

---

## 1. 节点网络身份与物理画像
| 属性 | 观测画像值 |
| :--- | :--- |
| **物理 MAC** | \`${matchedAsset.value?.mac || '跨三层路由未知'}\` |
| **硬件厂商 (OUI)** | ${matchedAsset.value?.vendor || '通用网络节点'} |
| **网络角色** | ${matchedAsset.value?.role || inferRoleFallback(ip)} |
| **操作系统指纹** | **${osFingerprint.value.osName}** (${osFingerprint.value.details}) |
| **主机名 (NetBIOS/DNS)** | ${hostnameInfo.value?.hostname || '未响应'} |
| **反向 PTR 记录** | ${hostnameInfo.value?.reverse_ptr || '无 PTR 记录'} |

---

## 2. 行为吞吐与传输特征
- **入向接收 (RX)**: ${stats.value.rxPackets} 帧 (${formatBytes(stats.value.rxBytes)}) [占比: ${rxRatioText.value}%]
- **出向发送 (TX)**: ${stats.value.txPackets} 帧 (${formatBytes(stats.value.txBytes)}) [占比: ${txRatioText.value}%]
- **通信行为形态**: **${trafficRoleText.value}**
- **首现时间**: ${stats.value.firstSeen || 'N/A'}
- **末次活跃**: ${stats.value.lastSeen || 'N/A'}

### 协议指纹分布
${Object.entries(stats.value.protocolCounts).map(([pr, cnt]) => `- **${pr}**: ${cnt} 帧`).join('\n') || '- 暂无'}

---

## 3. 等保 2.0 行为异常与合规研判
${riskAssessment.value.items.map(item => `### [${item.severity.toUpperCase()}] ${item.title} (${item.scoreText})\n> ${item.desc}`).join('\n\n')}

---

## 4. 高频通信对端拓扑矩阵 (Top Peers)
| 交互方向 | 对端 IP | 归属/安全域 | 主通信协议 | 会话次数 |
| :---: | :--- | :--- | :---: | :---: |
${topPeers.value.map(p => `| ${p.direction === 'out' ? '➔ 出向' : '⬅ 入向'} | \`${p.peerIp}\` | ${p.zoneOrGeo || 'N/A'} | ${p.mainProtocol} | ${p.count} |`).join('\n') || '| - | 暂无对端通信 | - | - | - |'}

---

## 5. 开放端口与服务探活
${openPorts.value.map(p => `- 端口 \`:${p}\`: **${inferProtocolByPort(p)}**`).join('\n') || '- 暂无开放端口发现'}

---
*报告由 Omni-Probe 工业网络探针引擎自动生成，具备司法证据链哈希保真效力。*
`;

    await saveTextViaNativeDesktop(
      `OmniProbe_Dossier_${ip}_${dateStr}.md`,
      md,
      'Markdown 档案 (*.md)',
      '*.md',
      '导出 IP 全息数字档案 Markdown'
    );
  }
}
</script>
