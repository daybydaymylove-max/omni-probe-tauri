<template>
  <div v-if="isOpen && targetIp" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/60 backdrop-blur-md select-none">
    <div class="w-full max-w-4xl bg-white/95 backdrop-blur-2xl rounded-3xl border border-white/70 shadow-2xl flex flex-col overflow-hidden max-h-[92vh] animate-in fade-in zoom-in-95 duration-150">
      
      <!-- 1. 顶层标题栏 (Apple Glassmorphism 工业风) -->
      <div class="px-6 py-3.5 border-b border-slate-200/70 bg-white/50 backdrop-blur-md flex items-center justify-between shrink-0">
        <div class="flex items-center gap-3">
          <span class="w-3.5 h-3.5 rounded-full" :class="ipScopeClass.dot"></span>
          <div>
            <div class="flex items-center gap-2 flex-wrap">
              <h3 class="text-base font-bold font-mono text-slate-900">{{ targetIp }}</h3>
              <span :class="['px-2 py-0.5 rounded-lg text-[10px] font-bold border shadow-2xs', ipScopeClass.badge]">
                {{ ipScopeText }}
              </span>
              <span v-if="intel?.zone_name" class="px-2 py-0.5 rounded-lg text-[10px] font-bold bg-indigo-50 text-indigo-700 border border-indigo-200 shadow-2xs">
                {{ intel.zone_name }}
              </span>
              <span v-if="hostnameInfo?.hostname" class="px-2 py-0.5 rounded-lg text-[10px] font-bold bg-emerald-50 text-emerald-700 border border-emerald-200 shadow-2xs flex items-center gap-1">
                <span>🏷️</span>
                <span>{{ hostnameInfo.hostname }}</span>
              </span>
            </div>
            <p class="text-[11px] text-slate-500 font-mono mt-0.5">
              目标 IP 深度活动追踪、数据出入侦测与全息档案中心 (Deep IP Tracking & Surveillance)
            </p>
          </div>
        </div>

        <div class="flex items-center gap-2">
          <!-- 导出溯源报告按钮 -->
          <div class="relative group">
            <button @click="showExportMenu = !showExportMenu"
              class="bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-200/80 text-xs px-3 py-1.5 rounded-xl font-semibold transition-all flex items-center gap-1.5 cursor-pointer active:scale-95 shadow-2xs">
              <span>📑 导出报告/PCAP</span>
              <span class="text-[10px]">▼</span>
            </button>
            <div v-if="showExportMenu"
              class="absolute right-0 top-full mt-1 w-48 bg-white/95 backdrop-blur-xl rounded-xl border border-slate-200/80 shadow-xl py-1 z-30 font-mono text-xs">
              <button @click="exportReport('markdown')"
                class="w-full text-left px-3 py-1.5 hover:bg-blue-50 text-slate-700 hover:text-blue-700 flex items-center gap-2 cursor-pointer">
                <span>📝 Markdown 审计报告 (.md)</span>
              </button>
              <button @click="exportReport('json')"
                class="w-full text-left px-3 py-1.5 hover:bg-blue-50 text-slate-700 hover:text-blue-700 flex items-center gap-2 cursor-pointer">
                <span>📦 JSON 全维数据包 (.json)</span>
              </button>
              <div class="border-t border-slate-100 my-1"></div>
              <button @click="exportPcapForTargetIp"
                class="w-full text-left px-3 py-1.5 hover:bg-emerald-50 text-emerald-700 flex items-center gap-2 cursor-pointer">
                <span>💾 该 IP 独立抓包切片 (.pcap)</span>
              </button>
            </div>
          </div>

          <button @click="filterInTrafficList"
            class="bg-blue-50 hover:bg-blue-100 text-blue-700 border border-blue-200 text-xs px-3 py-1.5 rounded-xl font-semibold transition-all flex items-center gap-1 cursor-pointer active:scale-95 shadow-2xs"
            title="在主流量分析列表中即时过滤以该 IP 为源或目的的全部会话">
            <span>🔍 流量穿透</span>
          </button>
          <button @click="$emit('close')" class="w-8 h-8 rounded-full flex items-center justify-center text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors cursor-pointer text-base">
            ✕
          </button>
        </div>
      </div>

      <!-- 1.5 功能 Tab 导航栏 (全息情报 / 实时活动流 / 等保研判) -->
      <div class="px-6 py-2 border-b border-slate-200/50 bg-slate-50/70 flex items-center justify-between shrink-0 text-xs">
        <div class="flex items-center gap-2 font-mono">
          <button
            @click="activeTab = 'dossier'"
            :class="['px-3 py-1.5 rounded-xl font-bold transition-all cursor-pointer flex items-center gap-1.5',
              activeTab === 'dossier' ? 'bg-white text-blue-700 shadow-sm border border-slate-200/80' : 'text-slate-600 hover:text-slate-900 hover:bg-white/50']"
          >
            <span>📊 全维身份与情报画像</span>
          </button>
          <button
            @click="activeTab = 'stream'"
            :class="['px-3 py-1.5 rounded-xl font-bold transition-all cursor-pointer flex items-center gap-1.5',
              activeTab === 'stream' ? 'bg-white text-blue-700 shadow-sm border border-slate-200/80' : 'text-slate-600 hover:text-slate-900 hover:bg-white/50']"
          >
            <span>⚡ 实时活动追踪与数据出入</span>
            <span class="px-1.5 py-0.2 rounded-full text-[10px] bg-blue-100 text-blue-800">
              {{ targetPackets.length }} 帧
            </span>
          </button>
          <button
            @click="activeTab = 'security'"
            :class="['px-3 py-1.5 rounded-xl font-bold transition-all cursor-pointer flex items-center gap-1.5',
              activeTab === 'security' ? 'bg-white text-blue-700 shadow-sm border border-slate-200/80' : 'text-slate-600 hover:text-slate-900 hover:bg-white/50']"
          >
            <span>🛡️ 等保合规与威胁研判</span>
            <span :class="['px-1.5 py-0.2 rounded-full text-[10px] font-bold', riskAssessment.badgeClass]">
              {{ riskAssessment.score }}分
            </span>
          </button>
        </div>

        <div class="text-[11px] text-slate-400 font-mono">
          <span>累计监听出入: </span>
          <strong class="text-slate-700">{{ stats.rxPackets + stats.txPackets }} 帧</strong>
          <span class="mx-1">|</span>
          <span>总吞吐: </span>
          <strong class="text-slate-700">{{ formatBytes(stats.rxBytes + stats.txBytes) }}</strong>
        </div>
      </div>

      <!-- 2. 主体内容区 (按 Tab 切换) -->
      <div class="flex-1 overflow-auto custom-scrollbar p-6 space-y-4 text-xs font-mono text-slate-700" @click="showExportMenu = false">
        
        <!-- ==================== TAB 1: 全维身份与情报画像 ==================== -->
        <template v-if="activeTab === 'dossier'">
          <!-- 2.1 网络身份与被动指纹全维元数据画像 (Identity & Fingerprints) -->
          <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-slate-50/80 p-3.5 rounded-2xl border border-slate-200/70">
            <div>
              <span class="text-[10px] text-slate-400 uppercase font-bold block mb-0.5">地理与运营商 (ISP)</span>
              <div class="text-slate-800 font-semibold truncate" :title="intel?.geo_summary || '本地局域网私网网段'">
                {{ intel?.geo_summary || '本地局域网私网网段' }}
              </div>
            </div>
            <div>
              <span class="text-[10px] text-slate-400 uppercase font-bold block mb-0.5">物理 MAC / 链路地址</span>
              <div class="text-slate-800 font-semibold truncate" :title="matchedAsset?.mac || '跨三层路由未知'">
                {{ matchedAsset?.mac || '跨三层路由未知' }}
              </div>
            </div>
            <div>
              <span class="text-[10px] text-slate-400 uppercase font-bold block mb-0.5">设备厂商画像 (OUI)</span>
              <div class="text-slate-800 font-semibold truncate" :title="matchedAsset?.vendor || '通用网络节点'">
                {{ matchedAsset?.vendor || '通用网络节点' }}
              </div>
            </div>
            <div>
              <span class="text-[10px] text-slate-400 uppercase font-bold block mb-0.5">网络角色推断</span>
              <div class="text-indigo-700 font-bold truncate">
                {{ matchedAsset?.role || inferRoleFallback(targetIp) }}
              </div>
            </div>

            <!-- 第二行：被动操作系统指纹、路由跳数推导、主机名、反向 PTR -->
            <div>
              <span class="text-[10px] text-slate-400 uppercase font-bold block mb-0.5">被动操作系统指纹 (TTL)</span>
              <div class="text-slate-800 font-bold truncate flex items-center gap-1" :title="osFingerprint.details">
                <span>{{ osFingerprint.osName }}</span>
                <span v-if="osFingerprint.observedTtl" class="text-[9px] font-normal text-slate-500">
                  (TTL: {{ osFingerprint.observedTtl }})
                </span>
              </div>
            </div>
            <div>
              <span class="text-[10px] text-slate-400 uppercase font-bold block mb-0.5">网络路由跳数推导 (Hops)</span>
              <div class="text-slate-800 font-semibold truncate">
                <span v-if="osFingerprint.hopCount !== null" class="text-emerald-700 font-bold">
                  约 {{ osFingerprint.hopCount }} 跳
                </span>
                <span v-else class="text-slate-400">本地直连或未捕获出向</span>
              </div>
            </div>
            <div>
              <span class="text-[10px] text-slate-400 uppercase font-bold block mb-0.5">主机名 / 计算机名</span>
              <div class="text-slate-800 font-semibold truncate flex items-center justify-between" :title="hostnameInfo?.hostname || '未注册或未响应'">
                <span class="truncate">{{ hostnameInfo?.hostname || '未注册或未响应' }}</span>
                <button @click="fetchHostname" :disabled="isResolvingHostname"
                  class="text-[9px] text-blue-600 hover:text-blue-700 hover:underline shrink-0 ml-1 cursor-pointer">
                  {{ isResolvingHostname ? '⏳' : '⟳' }}
                </button>
              </div>
            </div>
            <div>
              <span class="text-[10px] text-slate-400 uppercase font-bold block mb-0.5">反向 PTR 域名 (RFC 1035)</span>
              <div class="text-slate-800 font-semibold truncate" :title="hostnameInfo?.reverse_ptr || '无 PTR 记录'">
                {{ hostnameInfo?.reverse_ptr || '无 PTR 记录' }}
              </div>
            </div>
          </div>

          <!-- 2.2 流量统计与双向对称性特征 (Behavioral Analytics & Symmetry) -->
          <div class="space-y-2">
            <div class="grid grid-cols-3 gap-3">
              <div class="bg-white/80 p-3.5 rounded-2xl border border-slate-200/80 shadow-2xs">
                <span class="text-[10px] text-slate-400 uppercase font-bold block mb-1">入向数据出入 (RX)</span>
                <div class="text-base font-bold text-sky-700">{{ stats.rxPackets }} <span class="text-xs font-normal text-slate-500">帧</span></div>
                <div class="text-[11px] text-slate-500 mt-0.5">{{ formatBytes(stats.rxBytes) }}</div>
              </div>

              <div class="bg-white/80 p-3.5 rounded-2xl border border-slate-200/80 shadow-2xs">
                <span class="text-[10px] text-slate-400 uppercase font-bold block mb-1">出向数据出入 (TX)</span>
                <div class="text-base font-bold text-emerald-700">{{ stats.txPackets }} <span class="text-xs font-normal text-slate-500">帧</span></div>
                <div class="text-[11px] text-slate-500 mt-0.5">{{ formatBytes(stats.txBytes) }}</div>
              </div>

              <div class="bg-white/80 p-3.5 rounded-2xl border border-slate-200/80 shadow-2xs">
                <span class="text-[10px] text-slate-400 uppercase font-bold block mb-1">首现与末次活跃</span>
                <div class="text-[11px] text-slate-700 truncate" :title="stats.firstSeen || 'N/A'">首现: {{ stats.firstSeen || '本次未捕获' }}</div>
                <div class="text-[11px] text-slate-700 truncate mt-0.5" :title="stats.lastSeen || 'N/A'">末次: {{ stats.lastSeen || '本次未捕获' }}</div>
              </div>
            </div>

            <!-- 双向传输对称度比例条 -->
            <div class="bg-white/80 p-3 rounded-2xl border border-slate-200/80 shadow-2xs">
              <div class="flex items-center justify-between text-[10px] font-bold mb-1">
                <span class="text-sky-700">入向接收 (RX): {{ rxRatioText }}%</span>
                <span class="text-slate-500 font-normal">通信形态: <strong>{{ trafficRoleText }}</strong></span>
                <span class="text-emerald-700">出向发送 (TX): {{ txRatioText }}%</span>
              </div>
              <div class="w-full h-2 rounded-full bg-slate-100 overflow-hidden flex">
                <div class="bg-sky-500 h-full transition-all duration-300" :style="{ width: rxRatioText + '%' }"></div>
                <div class="bg-emerald-500 h-full transition-all duration-300" :style="{ width: txRatioText + '%' }"></div>
              </div>
            </div>
          </div>

          <!-- 2.3 涉及网络规约分布 (Protocols Profiling) -->
          <div class="bg-white/80 p-3.5 rounded-2xl border border-slate-200/80 shadow-2xs space-y-2">
            <span class="text-[10px] text-slate-400 uppercase font-bold block">涉及网络规约分布 (Protocol Fingerprints)</span>
            <div class="flex items-center gap-1.5 flex-wrap">
              <div v-for="(cnt, pr) in stats.protocolCounts" :key="pr"
                class="flex items-center gap-1.5 bg-slate-100 hover:bg-slate-200 px-2.5 py-1 rounded-xl text-xs font-semibold text-slate-800 transition-colors shadow-2xs">
                <span class="font-bold text-blue-700">{{ pr }}</span>
                <span class="text-[10px] text-slate-500 bg-white px-1.5 py-0.2 rounded-md font-mono">{{ cnt }} 帧</span>
              </div>
              <div v-if="Object.keys(stats.protocolCounts).length === 0" class="text-slate-400 text-xs py-1">
                暂未沉淀规约数据
              </div>
            </div>
          </div>

          <!-- 2.4 会话对端拓扑关联网 (Top Peers) -->
          <div class="bg-white/80 p-3.5 rounded-2xl border border-slate-200/80 shadow-2xs space-y-2">
            <div class="flex items-center justify-between">
              <span class="text-[10px] text-slate-400 uppercase font-bold">高频通信对端节点 (Top Communication Peers)</span>
              <span class="text-[10px] text-slate-400">共关联 {{ topPeers.length }} 个节点</span>
            </div>
            <div class="divide-y divide-slate-100 max-h-40 overflow-auto custom-scrollbar pr-1">
              <div v-for="peer in topPeers" :key="peer.peerIp"
                class="py-1.5 flex items-center justify-between hover:bg-slate-50 px-2 rounded-lg transition-colors cursor-pointer"
                @click="drillDownToPeer(peer.peerIp)">
                <div class="flex items-center gap-2 truncate max-w-sm">
                  <span :class="peer.direction === 'out' ? 'text-emerald-600' : 'text-sky-600'" class="font-bold">
                    {{ peer.direction === 'out' ? '➔' : '⬅' }}
                  </span>
                  <span class="font-bold text-slate-800 hover:text-blue-600 transition-colors">{{ peer.peerIp }}</span>
                  <span v-if="peer.zoneOrGeo" class="text-[10px] text-slate-500 truncate max-w-[140px] bg-slate-100 px-1.5 py-0.2 rounded">
                    {{ peer.zoneOrGeo }}
                  </span>
                </div>
                <div class="flex items-center gap-3 text-[11px] text-slate-500 shrink-0">
                  <span class="text-amber-600 font-semibold">{{ peer.mainProtocol }}</span>
                  <span class="font-bold text-slate-700">{{ peer.count }} 次会话</span>
                  <span class="text-[10px] text-blue-600 font-semibold hover:underline">穿透 ↗</span>
                </div>
              </div>
              <div v-if="topPeers.length === 0" class="text-slate-400 text-xs py-3 text-center">
                暂无已记录的对端通信会话
              </div>
            </div>
          </div>

          <!-- 2.5 合规主动探活与服务探测工具箱 (Compliance Probing) -->
          <div class="bg-white/80 p-3.5 rounded-2xl border border-slate-200/80 shadow-2xs space-y-3">
            <div class="flex items-center justify-between">
              <span class="text-[10px] text-slate-400 uppercase font-bold">合规连通性探活与端口审计 (Compliance Probing)</span>
              <span class="text-[9px] text-slate-400">基于 RFC 792 ICMP Echo 与 RFC 793 TCP Connect</span>
            </div>

            <div class="flex items-center gap-3 flex-wrap">
              <button @click="doIcmpPing" :disabled="isPinging"
                class="bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white text-xs px-3 py-1.5 rounded-xl font-semibold transition-all flex items-center gap-1.5 cursor-pointer disabled:opacity-40 shadow-sm active:scale-95">
                <span v-if="isPinging" class="animate-spin">⏳</span>
                <span v-else>⚡</span>
                <span>ICMP 连通性测试 (Ping)</span>
              </button>

              <button @click="doPortProbe" :disabled="isProbingPorts"
                class="bg-emerald-600 hover:bg-emerald-700 text-white text-xs px-3 py-1.5 rounded-xl font-semibold transition-all flex items-center gap-1.5 cursor-pointer disabled:opacity-40 shadow-sm active:scale-95">
                <span v-if="isProbingPorts" class="animate-spin">⏳</span>
                <span v-else>🔍</span>
                <span>网络服务与端口探测</span>
              </button>
            </div>

            <!-- ICMP 结果回显 -->
            <div v-if="pingResult" class="p-2.5 rounded-xl border text-xs font-mono"
              :class="pingResult.status === 'ONLINE' ? 'bg-emerald-50 text-emerald-900 border-emerald-200' : 'bg-rose-50 text-rose-900 border-rose-200'">
              <div class="flex items-center justify-between">
                <span>状态: <strong>{{ pingResult.status === 'ONLINE' ? '✅ 在线可达 (Host Reachable)' : '❌ 不可达/超时 (Offline/Timeout)' }}</strong></span>
                <span>RTT 时延: <strong>{{ pingResult.latency_ms.toFixed(1) }} ms</strong></span>
              </div>
            </div>

            <!-- 端口探测结果回显 -->
            <div v-if="openPorts.length > 0" class="space-y-1">
              <span class="text-[10px] text-slate-500 font-bold block">发现开放端口与服务画像:</span>
              <div class="flex items-center gap-1.5 flex-wrap">
                <span v-for="port in openPorts" :key="port"
                  class="px-2 py-0.5 rounded-lg bg-emerald-500/10 text-emerald-800 border border-emerald-300/70 text-[10px] font-bold shadow-2xs">
                  :{{ port }} ({{ inferProtocolByPort(port) }})
                </span>
              </div>
            </div>
          </div>
        </template>

        <!-- ==================== TAB 2: 实时活动追踪与数据出入 ==================== -->
        <template v-else-if="activeTab === 'stream'">
          <div class="space-y-3">
            <!-- 实时过滤与操作工具栏 -->
            <div class="flex items-center justify-between gap-3 flex-wrap">
              <div class="flex items-center gap-2 flex-1 min-w-[240px]">
                <input
                  v-model="streamSearch"
                  placeholder="过滤对端 IP / 端口 / 协议 / 载荷文本"
                  class="w-full bg-white border border-slate-200 rounded-xl px-3 py-1.5 text-xs text-slate-700 focus:outline-none focus:ring-2 focus:ring-blue-500/30 font-mono shadow-2xs"
                />
              </div>

              <div class="flex items-center gap-2">
                <button
                  @click="exportPcapForTargetIp"
                  class="px-3 py-1.5 rounded-xl bg-emerald-600 hover:bg-emerald-700 text-white font-semibold transition-all flex items-center gap-1 cursor-pointer shadow-sm active:scale-95"
                >
                  <span>💾 导出该 IP 抓包 (.pcap)</span>
                </button>
              </div>
            </div>

            <!-- 专属活动流时序表格 -->
            <div class="bg-white rounded-2xl border border-slate-200 overflow-hidden shadow-sm">
              <div class="max-h-[50vh] overflow-auto custom-scrollbar">
                <table class="w-full text-left text-xs font-mono border-collapse table-fixed">
                  <thead class="bg-slate-100/80 border-b border-slate-200 text-[10px] font-bold text-slate-500 uppercase sticky top-0 z-10 select-none">
                    <tr>
                      <th class="p-2 w-[16%]">时间戳</th>
                      <th class="p-2 w-[12%] text-center">出入流向</th>
                      <th class="p-2 w-[30%]">通信端点 (对端)</th>
                      <th class="p-2 w-[12%]">规约协议</th>
                      <th class="p-2 w-[10%] text-right">载荷长度</th>
                      <th class="p-2 w-[20%]">载荷摘要 / 交互特征</th>
                    </tr>
                  </thead>
                  <tbody class="divide-y divide-slate-100">
                    <tr
                      v-for="pkt in filteredTargetPackets"
                      :key="pkt.id"
                      @click="selectedStreamPacket = selectedStreamPacket?.id === pkt.id ? null : pkt"
                      :class="['hover:bg-blue-50/50 cursor-pointer transition-colors',
                        selectedStreamPacket?.id === pkt.id ? 'bg-blue-50/80' : '']"
                    >
                      <td class="p-2 text-slate-500 text-[11px] truncate">{{ pkt.timestamp }}</td>
                      <td class="p-2 text-center">
                        <span
                          :class="['px-1.5 py-0.5 rounded text-[9px] font-bold uppercase',
                            pkt.src_ip === targetIp ? 'bg-emerald-100 text-emerald-800' : 'bg-sky-100 text-sky-800']"
                        >
                          {{ pkt.src_ip === targetIp ? '➔ TX 出向' : '⬅ RX 入向' }}
                        </span>
                      </td>
                      <td class="p-2 truncate font-bold text-slate-700">
                        <span v-if="pkt.src_ip === targetIp">
                          ➔ {{ pkt.dst_ip }}:{{ pkt.dst_port }}
                        </span>
                        <span v-else>
                          ⬅ {{ pkt.src_ip }}:{{ pkt.src_port }}
                        </span>
                      </td>
                      <td class="p-2 truncate">
                        <span class="px-1.5 py-0.2 rounded bg-slate-100 text-slate-700 font-bold text-[10px]">
                          {{ pkt.protocol }}
                        </span>
                      </td>
                      <td class="p-2 text-right font-bold text-slate-600 truncate">{{ pkt.length }} B</td>
                      <td class="p-2 text-slate-500 text-[11px] truncate" :title="pkt.raw_text || pkt.payload_hex">
                        {{ pkt.raw_text || (pkt.payload_hex ? `HEX[${pkt.payload_hex.slice(0, 20)}...]` : '[空载荷]') }}
                      </td>
                    </tr>
                    <tr v-if="filteredTargetPackets.length === 0">
                      <td colspan="6" class="p-10 text-center text-slate-400">
                        暂无符合条件的该 IP 实时出入数据帧，可在主界面启动嗅探以持续监测
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

            <!-- 选中报文的十六进制 HexDump 与深度展开 -->
            <div v-if="selectedStreamPacket" class="bg-slate-900 text-slate-100 p-4 rounded-2xl space-y-2 text-xs font-mono shadow-md animate-in fade-in duration-100">
              <div class="flex items-center justify-between border-b border-slate-800 pb-2">
                <span class="font-bold text-emerald-400">
                  报文 #{{ selectedStreamPacket.id }} 深度剖析 ({{ selectedStreamPacket.protocol }})
                </span>
                <span class="text-[10px] text-slate-400">
                  物理长度: {{ selectedStreamPacket.length }} 字节 | 熵值: {{ selectedStreamPacket.entropy?.toFixed(2) }}
                </span>
              </div>
              <div class="text-[11px] text-slate-300">
                <span>通信方向: </span>
                <strong :class="selectedStreamPacket.src_ip === targetIp ? 'text-emerald-400' : 'text-sky-400'">
                  {{ selectedStreamPacket.src_ip }}:{{ selectedStreamPacket.src_port }} ➔ {{ selectedStreamPacket.dst_ip }}:{{ selectedStreamPacket.dst_port }}
                </strong>
              </div>
              <div v-if="selectedStreamPacket.raw_text" class="bg-slate-950 p-2.5 rounded-xl border border-slate-800 text-[11px] whitespace-pre-wrap max-h-32 overflow-auto custom-scrollbar text-amber-200">
                {{ selectedStreamPacket.raw_text }}
              </div>
              <div v-if="selectedStreamPacket.payload_hex" class="bg-slate-950 p-2.5 rounded-xl border border-slate-800 text-[10px] break-all max-h-24 overflow-auto custom-scrollbar text-slate-400">
                {{ selectedStreamPacket.payload_hex }}
              </div>
            </div>
          </div>
        </template>

        <!-- ==================== TAB 3: 等保合规与威胁研判 ==================== -->
        <template v-else-if="activeTab === 'security'">
          <div class="bg-white/80 p-5 rounded-2xl border border-slate-200/80 shadow-2xs space-y-4">
            <div class="flex items-center justify-between">
              <div>
                <h4 class="text-sm font-bold text-slate-800">等保 2.0 行为异常与合规风险研判模型</h4>
                <p class="text-[11px] text-slate-500 mt-0.5">
                  依据 GB/T 22239-2019 标准，针对目标 IP 的通信流量、端口探测、高熵通道与会话对称性进行全自动审计
                </p>
              </div>
              <div class="text-right">
                <span :class="['px-3 py-1 rounded-xl text-xs font-bold border shadow-xs inline-block', riskAssessment.badgeClass]">
                  健康指数: {{ riskAssessment.score }} / 100
                </span>
                <span class="block text-[10px] text-slate-400 mt-1">综合定级: {{ riskAssessment.levelText }}</span>
              </div>
            </div>

            <!-- 详细审计条目 -->
            <div class="space-y-2">
              <div v-for="(item, idx) in riskAssessment.items" :key="idx"
                class="p-3.5 rounded-2xl text-xs flex items-start justify-between border"
                :class="item.severity === 'high' ? 'bg-rose-50/90 text-rose-950 border-rose-200 shadow-2xs' : (item.severity === 'medium' ? 'bg-amber-50/90 text-amber-950 border-amber-200 shadow-2xs' : 'bg-emerald-50/90 text-emerald-950 border-emerald-200 shadow-2xs')">
                <div class="flex items-start gap-3">
                  <span class="text-base">{{ item.severity === 'high' ? '🚨' : (item.severity === 'medium' ? '⚠️' : '✅') }}</span>
                  <div class="space-y-1">
                    <span class="font-bold text-sm block">{{ item.title }}</span>
                    <p class="text-slate-700 text-xs leading-relaxed">{{ item.desc }}</p>
                  </div>
                </div>
                <span class="text-xs font-bold font-mono shrink-0 ml-3 px-2 py-0.5 rounded-lg bg-white/80 border border-slate-200/60 shadow-2xs">
                  {{ item.scoreText }}
                </span>
              </div>
            </div>

            <!-- 合规处置建议 -->
            <div class="bg-slate-50 p-4 rounded-2xl border border-slate-200/80 space-y-2 text-xs">
              <span class="font-bold text-slate-800 block">🛡️ 等保审计与运维处置建议:</span>
              <ul class="list-disc list-inside space-y-1 text-slate-600 text-[11px]">
                <li>如检测到高频多端口探测，建议核实该节点是否为合法网络扫描器；若非授权，需在核心交换机/网关上阻断其横向通信；</li>
                <li>如存在非标准端口高熵载荷，需结合深度包检测（DPI）研判是否存在外部 C2 通道或未加密敏感资产外发；</li>
                <li>对于明文传输（HTTP/Telnet/FTP），建议整改升级为 TLS 1.3 / SSH 等机密性传输规约。</li>
              </ul>
            </div>
          </div>
        </template>

      </div>

      <!-- 3. 底层控制按钮 -->
      <div class="px-6 py-3 border-t border-slate-200/60 bg-white/40 flex items-center justify-between shrink-0 text-xs">
        <span class="text-slate-400 text-[11px]">Omni-Probe 司法级全维 IP 画像与深度追踪引擎</span>
        <button @click="$emit('close')"
          class="px-4 py-1.5 rounded-xl font-semibold bg-slate-100 hover:bg-slate-200 text-slate-700 transition-colors cursor-pointer">
          关闭
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue';
import { invoke } from '@tauri-apps/api/core';

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
  if (text.includes('LAN')) return { dot: 'bg-sky-500 animate-pulse', badge: 'bg-sky-50 text-sky-700 border-sky-200' };
  if (text.includes('WAN')) return { dot: 'bg-emerald-500 animate-pulse', badge: 'bg-emerald-50 text-emerald-700 border-emerald-200' };
  if (text.includes('回环')) return { dot: 'bg-amber-500', badge: 'bg-amber-50 text-amber-700 border-amber-200' };
  return { dot: 'bg-slate-400', badge: 'bg-slate-100 text-slate-700 border-slate-200' };
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
    return { score: 100, levelText: '基线正常', badgeClass: 'bg-emerald-50 text-emerald-700 border-emerald-200', items };
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
  let badgeClass = 'bg-emerald-50 text-emerald-700 border-emerald-200';
  if (score < 70) {
    levelText = '高危威胁';
    badgeClass = 'bg-rose-50 text-rose-700 border-rose-200';
  } else if (score < 90) {
    levelText = '中危关注';
    badgeClass = 'bg-amber-50 text-amber-700 border-amber-200';
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
  } catch {
    // 忽略
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
    alert(`成功将目标 IP ${ip} 的 ${count} 帧出入报文导出为独立 PCAP 文件:\n${filename}`);
  } catch (e: any) {
    alert(`导出 PCAP 失败: ${e}`);
  }
}

// 导出工业级 IP 全息溯源报告 (Markdown / JSON)
function exportReport(format: 'markdown' | 'json') {
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

    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    downloadBlob(blob, `OmniProbe_Dossier_${ip}_${dateStr}.json`);
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

    const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
    downloadBlob(blob, `OmniProbe_Dossier_${ip}_${dateStr}.md`);
  }
}

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
</script>
