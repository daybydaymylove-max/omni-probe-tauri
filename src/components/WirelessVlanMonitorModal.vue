<template>
  <div v-if="isOpen" class="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-slate-950/60 backdrop-blur-md animate-in fade-in duration-200">
    <!-- 模态框主体 (Apple Mica Frost 工业级深浅自适应面板) -->
    <div class="w-full max-w-6xl max-h-[92vh] bg-white/95 dark:bg-slate-900/95 backdrop-blur-2xl rounded-3xl border border-white/60 dark:border-white/10 shadow-2xl flex flex-col overflow-hidden">
      
      <!-- 顶栏：标题与分段控制器 -->
      <div class="px-6 py-4 border-b border-slate-200/80 dark:border-white/10 bg-slate-50/50 dark:bg-black/30 flex flex-col md:flex-row md:items-center justify-between gap-4 shrink-0">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-2xl bg-gradient-to-tr from-sky-500 via-indigo-600 to-purple-600 flex items-center justify-center text-white shadow-lg shadow-indigo-500/25">
            <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071c3.904-3.905 10.236-3.905 14.141 0M1.394 9.393c5.857-5.857 15.355-5.857 21.213 0" />
            </svg>
          </div>
          <div>
            <div class="flex items-center gap-2">
              <h3 class="text-base font-bold text-slate-900 dark:text-white">
                无线链路与虚拟局域网专业监测控制台
              </h3>
              <span class="px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-indigo-100 text-indigo-700 dark:bg-indigo-950/70 dark:text-indigo-300 border border-indigo-200 dark:border-indigo-800">
                PRO-WIRELESS & VLAN
              </span>
            </div>
            <p class="text-xs text-slate-500 dark:text-slate-400 mt-0.5 font-mono">
              IEEE 802.11 Radiotap 信道热力 · 802.1Q/ad QinQ 跨层审计 · BLE HCI 空间路径衰减感知
            </p>
          </div>
        </div>

        <!-- 四模态切换按钮组 -->
        <div class="flex items-center gap-3">
          <div class="p-1 rounded-2xl bg-slate-200/70 dark:bg-slate-800/80 border border-slate-300/60 dark:border-white/5 flex items-center gap-1 text-xs font-semibold">
            <button
              v-for="tab in tabs"
              :key="tab.id"
              @click="activeTab = tab.id"
              :class="[
                'px-3 py-1.5 rounded-xl transition-all flex items-center gap-1.5 cursor-pointer',
                activeTab === tab.id
                  ? 'bg-white dark:bg-indigo-600 text-slate-900 dark:text-white shadow-sm font-bold'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
              ]"
            >
              <span>{{ tab.icon }}</span>
              <span>{{ tab.label }}</span>
            </button>
          </div>

          <!-- 刷新与关闭 -->
          <div class="flex items-center gap-2">
            <button
              @click="refreshCurrentTelemetry"
              :disabled="loading"
              class="w-9 h-9 rounded-2xl bg-white dark:bg-slate-800 border border-slate-200 dark:border-white/10 hover:bg-slate-50 dark:hover:bg-slate-700/60 text-slate-700 dark:text-slate-200 flex items-center justify-center shadow-xs transition-colors cursor-pointer disabled:opacity-50"
              title="刷新遥测指标"
            >
              <span :class="loading ? 'animate-spin' : ''">⟳</span>
            </button>
            <button
              @click="$emit('close')"
              class="w-9 h-9 rounded-2xl bg-white dark:bg-slate-800 border border-slate-200 dark:border-white/10 hover:bg-red-50 hover:text-red-600 dark:hover:bg-red-950/40 dark:hover:text-red-400 text-slate-500 flex items-center justify-center shadow-xs transition-colors cursor-pointer"
            >
              ✕
            </button>
          </div>
        </div>
      </div>

      <!-- 主体内容区域 -->
      <div class="flex-1 overflow-y-auto custom-scrollbar p-6 space-y-6">

        <!-- ======================= 1. Wi-Fi 频谱与无线威胁监测 ======================= -->
        <div v-if="activeTab === 'wifi'" class="space-y-6">
          <!-- 统计概览卡片组 -->
          <div class="grid grid-cols-2 md:grid-cols-5 gap-3">
            <div class="p-4 rounded-2xl bg-slate-50/80 dark:bg-slate-800/40 border border-slate-200/80 dark:border-white/10">
              <div class="text-xs text-slate-500 dark:text-slate-400 font-medium">总捕获 Wi-Fi 帧数</div>
              <div class="text-2xl font-mono font-bold text-slate-900 dark:text-white mt-1">
                {{ wifiData.total_wifi_frames.toLocaleString() }}
              </div>
              <div class="text-[11px] text-slate-400 font-mono mt-1">Radiotap / 802.11 物理载荷</div>
            </div>

            <div class="p-4 rounded-2xl bg-slate-50/80 dark:bg-slate-800/40 border border-slate-200/80 dark:border-white/10">
              <div class="text-xs text-slate-500 dark:text-slate-400 font-medium">AP 热点 / BSSID 资产</div>
              <div class="text-2xl font-mono font-bold text-sky-600 dark:text-sky-400 mt-1">
                {{ wifiData.ap_assets.length }}
              </div>
              <div class="text-[11px] text-slate-400 font-mono mt-1">活跃接入点空间感知</div>
            </div>

            <div class="p-4 rounded-2xl bg-slate-50/80 dark:bg-slate-800/40 border border-slate-200/80 dark:border-white/10">
              <div class="text-xs text-slate-500 dark:text-slate-400 font-medium">802.11 管理与控制帧</div>
              <div class="text-2xl font-mono font-bold text-indigo-600 dark:text-indigo-400 mt-1">
                {{ (wifiData.management_frames + wifiData.control_frames).toLocaleString() }}
              </div>
              <div class="text-[11px] text-slate-400 font-mono mt-1">Beacon / Probe / RTS / ACK</div>
            </div>

            <div class="p-4 rounded-2xl bg-slate-50/80 dark:bg-slate-800/40 border border-slate-200/80 dark:border-white/10">
              <div class="text-xs text-slate-500 dark:text-slate-400 font-medium">802.11 QoS 数据帧</div>
              <div class="text-2xl font-mono font-bold text-emerald-600 dark:text-emerald-400 mt-1">
                {{ wifiData.data_frames.toLocaleString() }}
              </div>
              <div class="text-[11px] text-slate-400 font-mono mt-1">上层应用通信流量载荷</div>
            </div>

            <div class="p-4 rounded-2xl bg-slate-50/80 dark:bg-slate-800/40 border border-slate-200/80 dark:border-white/10"
              :class="wifiData.deauth_attack_count > 0 ? 'border-red-300 dark:border-red-800/60 bg-red-50/30 dark:bg-red-950/10' : ''">
              <div class="text-xs text-slate-500 dark:text-slate-400 font-medium">Deauth 洪水告警</div>
              <div class="text-2xl font-mono font-bold mt-1"
                :class="wifiData.deauth_attack_count > 0 ? 'text-red-600 dark:text-red-400' : 'text-slate-700 dark:text-slate-300'">
                {{ wifiData.deauth_attack_count }}
              </div>
              <div class="text-[11px] text-slate-400 font-mono mt-1">拒绝服务断开攻击监测</div>
            </div>
          </div>

          <!-- 2.4 GHz 与 5 GHz 物理信道热力分布图 -->
          <div class="p-5 rounded-2xl bg-slate-50/60 dark:bg-slate-800/30 border border-slate-200/80 dark:border-white/10 space-y-3">
            <div class="flex items-center justify-between">
              <h4 class="text-xs font-bold text-slate-800 dark:text-slate-200 flex items-center gap-2">
                <span>📶 物理频段信道占用热力图谱 (Channel Spectrum Heatmap)</span>
                <span class="text-[10px] font-normal text-slate-400">2.4 GHz (Ch 1-14) / 5 GHz (Ch 36-165)</span>
              </h4>
              <span class="text-[11px] font-mono text-indigo-600 dark:text-indigo-400">
                活跃信道数: {{ Object.keys(wifiData.channel_distribution).length }}
              </span>
            </div>

            <!-- 信道柱状图 -->
            <div class="grid grid-cols-7 sm:grid-cols-14 gap-2 pt-2">
              <div
                v-for="ch in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]"
                :key="'ch2g-' + ch"
                class="flex flex-col items-center gap-1.5 p-2 rounded-xl bg-white dark:bg-slate-900 border border-slate-200/60 dark:border-white/5"
              >
                <div class="w-full h-20 bg-slate-100 dark:bg-slate-800 rounded-lg flex items-end p-1 relative overflow-hidden">
                  <div
                    class="w-full rounded-md transition-all duration-500 bg-gradient-to-t from-sky-500 to-indigo-500"
                    :style="{ height: getChannelPercent(ch) + '%' }"
                  ></div>
                </div>
                <div class="text-[11px] font-bold font-mono text-slate-700 dark:text-slate-300">
                  Ch {{ ch }}
                </div>
                <div class="text-[9px] font-mono text-slate-400">
                  {{ wifiData.channel_distribution[ch] || 0 }} 帧
                </div>
              </div>
            </div>
          </div>

          <!-- AP 资产感知列表 -->
          <div class="p-5 rounded-2xl bg-slate-50/60 dark:bg-slate-800/30 border border-slate-200/80 dark:border-white/10 space-y-3">
            <div class="flex items-center justify-between">
              <h4 class="text-xs font-bold text-slate-800 dark:text-slate-200 flex items-center gap-2">
                <span>🛰️ 捕获的 Wi-Fi 接入点资产拓扑 (Access Points Topology)</span>
                <span class="text-[10px] px-2 py-0.5 rounded-full bg-slate-200 dark:bg-slate-700 text-slate-600 dark:text-slate-300 font-mono">
                  共 {{ wifiData.ap_assets.length }} 个 AP
                </span>
              </h4>
            </div>

            <div class="overflow-x-auto">
              <table class="w-full text-left border-collapse">
                <thead>
                  <tr class="border-b border-slate-200 dark:border-white/10 text-[11px] font-semibold text-slate-400 font-mono uppercase tracking-wider">
                    <th class="py-2.5 px-3">SSID (网络热点名称)</th>
                    <th class="py-2.5 px-3">BSSID MAC 地址</th>
                    <th class="py-2.5 px-3">物理信道 / 频段</th>
                    <th class="py-2.5 px-3">RSSI 信号强度</th>
                    <th class="py-2.5 px-3">认证与加密规约</th>
                    <th class="py-2.5 px-3">捕获帧数</th>
                    <th class="py-2.5 px-3">安全态势</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-slate-100 dark:divide-white/5 text-xs font-mono">
                  <tr
                    v-for="ap in wifiData.ap_assets"
                    :key="ap.bssid"
                    class="hover:bg-white/60 dark:hover:bg-slate-800/50 transition-colors"
                  >
                    <td class="py-3 px-3 font-semibold text-slate-900 dark:text-white flex items-center gap-2">
                      <span class="text-sky-500">📶</span>
                      <span>{{ ap.ssid }}</span>
                    </td>
                    <td class="py-3 px-3 text-slate-600 dark:text-slate-300">
                      {{ ap.bssid }}
                    </td>
                    <td class="py-3 px-3">
                      <span class="px-2 py-0.5 rounded-md text-[11px] font-bold bg-indigo-50 dark:bg-indigo-950/60 text-indigo-600 dark:text-indigo-400 border border-indigo-200/60 dark:border-indigo-800/40">
                        Ch {{ ap.channel }} ({{ ap.band_desc }})
                      </span>
                    </td>
                    <td class="py-3 px-3">
                      <div class="flex items-center gap-2">
                        <span
                          class="font-bold"
                          :class="getRssiColorClass(ap.last_rssi_dbm)"
                        >
                          {{ ap.last_rssi_dbm }} dBm
                        </span>
                        <div class="w-16 h-2 bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden">
                          <div
                            class="h-full rounded-full"
                            :class="getRssiBgClass(ap.last_rssi_dbm)"
                            :style="{ width: Math.min(100, Math.max(10, (ap.last_rssi_dbm + 100) * 1.6)) + '%' }"
                          ></div>
                        </div>
                      </div>
                    </td>
                    <td class="py-3 px-3">
                      <span
                        class="px-2 py-0.5 rounded-md text-[10px] font-bold"
                        :class="getEncryptionClass(ap.encryption_type)"
                      >
                        {{ ap.encryption_type }}
                      </span>
                    </td>
                    <td class="py-3 px-3 text-slate-500 dark:text-slate-400">
                      信标: {{ ap.beacon_count }} / 数据: {{ ap.data_packet_count }}
                    </td>
                    <td class="py-3 px-3">
                      <div v-if="ap.security_alerts.length === 0" class="text-emerald-600 dark:text-emerald-400 text-[11px] flex items-center gap-1">
                        <span>✓</span>
                        <span>信道与加密合规</span>
                      </div>
                      <div v-else class="flex flex-wrap gap-1">
                        <span
                          v-for="alert in ap.security_alerts"
                          :key="alert"
                          class="px-2 py-0.5 rounded-md text-[10px] font-bold bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-300 border border-red-200 dark:border-red-800"
                        >
                          ⚠️ {{ alert }}
                        </span>
                      </div>
                    </td>
                  </tr>

                  <!-- 无数据空状态 -->
                  <tr v-if="wifiData.ap_assets.length === 0">
                    <td colspan="7" class="py-8 text-center text-slate-400 font-sans text-xs">
                      暂未捕获到 Wi-Fi 802.11 管理帧或信标，请确认无线网卡已开启监听捕获，或点击“载入测试样本”进行仿真探查。
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <!-- ======================= 2. VLAN 拓扑与隔离安全审计 ======================= -->
        <div v-if="activeTab === 'vlan'" class="space-y-6">
          <!-- 统计概览卡片组 -->
          <div class="grid grid-cols-2 md:grid-cols-5 gap-3">
            <div class="p-4 rounded-2xl bg-slate-50/80 dark:bg-slate-800/40 border border-slate-200/80 dark:border-white/10">
              <div class="text-xs text-slate-500 dark:text-slate-400 font-medium">总 VLAN 报文数</div>
              <div class="text-2xl font-mono font-bold text-slate-900 dark:text-white mt-1">
                {{ vlanData.total_vlan_packets.toLocaleString() }}
              </div>
              <div class="text-[11px] text-slate-400 font-mono mt-1">
                吞吐: {{ formatBytes(vlanData.total_vlan_bytes) }}
              </div>
            </div>

            <div class="p-4 rounded-2xl bg-slate-50/80 dark:bg-slate-800/40 border border-slate-200/80 dark:border-white/10">
              <div class="text-xs text-slate-500 dark:text-slate-400 font-medium">活跃 VLAN 隔离域</div>
              <div class="text-2xl font-mono font-bold text-indigo-600 dark:text-indigo-400 mt-1">
                {{ vlanData.active_vlan_count }}
              </div>
              <div class="text-[11px] text-slate-400 font-mono mt-1">VID 范围: 0 - 4095</div>
            </div>

            <div class="p-4 rounded-2xl bg-slate-50/80 dark:bg-slate-800/40 border border-slate-200/80 dark:border-white/10">
              <div class="text-xs text-slate-500 dark:text-slate-400 font-medium">IEEE 802.1ad (QinQ) 双层</div>
              <div class="text-2xl font-mono font-bold text-purple-600 dark:text-purple-400 mt-1">
                {{ vlanData.qinq_packets.toLocaleString() }}
              </div>
              <div class="text-[11px] text-slate-400 font-mono mt-1">S-Tag 运营商隧道流</div>
            </div>

            <div class="p-4 rounded-2xl bg-slate-50/80 dark:bg-slate-800/40 border border-slate-200/80 dark:border-white/10"
              :class="vlanData.vlan_hopping_threats > 0 ? 'border-red-300 dark:border-red-800/60 bg-red-50/30 dark:bg-red-950/10' : ''">
              <div class="text-xs text-slate-500 dark:text-slate-400 font-medium">Double Tagging 跳跃穿透攻击</div>
              <div class="text-2xl font-mono font-bold mt-1"
                :class="vlanData.vlan_hopping_threats > 0 ? 'text-red-600 dark:text-red-400' : 'text-slate-700 dark:text-slate-300'">
                {{ vlanData.vlan_hopping_threats }}
              </div>
              <div class="text-[11px] text-slate-400 font-mono mt-1">VLAN Hopping 跨域越权告警</div>
            </div>

            <div class="p-4 rounded-2xl bg-slate-50/80 dark:bg-slate-800/40 border border-slate-200/80 dark:border-white/10"
              :class="vlanData.default_vlan1_packets > 0 ? 'border-amber-300 dark:border-amber-800/60 bg-amber-50/30 dark:bg-amber-950/10' : ''">
              <div class="text-xs text-slate-500 dark:text-slate-400 font-medium">Default VLAN 1 敏感流量</div>
              <div class="text-2xl font-mono font-bold mt-1"
                :class="vlanData.default_vlan1_packets > 0 ? 'text-amber-600 dark:text-amber-400' : 'text-slate-700 dark:text-slate-300'">
                {{ vlanData.default_vlan1_packets.toLocaleString() }}
              </div>
              <div class="text-[11px] text-slate-400 font-mono mt-1">默认未划分生产网泄露风险</div>
            </div>
          </div>

          <!-- IEEE 802.1p CoS 优先级直方图 -->
          <div class="p-5 rounded-2xl bg-slate-50/60 dark:bg-slate-800/30 border border-slate-200/80 dark:border-white/10 space-y-3">
            <h4 class="text-xs font-bold text-slate-800 dark:text-slate-200 flex items-center justify-between">
              <span>🎚️ 802.1p CoS 业务优先级分布矩阵 (PCP 0-7 Class of Service)</span>
              <span class="text-[11px] font-normal text-slate-400">语音 (5) / 视频 (4) / 关键工控应用 (3)</span>
            </h4>

            <div class="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-8 gap-2 pt-2">
              <div
                v-for="pcp in [0, 1, 2, 3, 4, 5, 6, 7]"
                :key="'pcp-' + pcp"
                class="p-2.5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200/60 dark:border-white/5 flex flex-col justify-between"
              >
                <div class="text-[10px] text-slate-400 font-mono">
                  PCP {{ pcp }}
                </div>
                <div class="text-base font-bold font-mono text-slate-800 dark:text-slate-200 my-1">
                  {{ getPcpTotalCount(pcp).toLocaleString() }}
                </div>
                <div class="text-[9px] text-slate-500 dark:text-slate-400 leading-tight">
                  {{ getPcpShortLabel(pcp) }}
                </div>
              </div>
            </div>
          </div>

          <!-- VLAN 拓扑与隔离审计表格 -->
          <div class="p-5 rounded-2xl bg-slate-50/60 dark:bg-slate-800/30 border border-slate-200/80 dark:border-white/10 space-y-3">
            <div class="flex items-center justify-between">
              <h4 class="text-xs font-bold text-slate-800 dark:text-slate-200 flex items-center gap-2">
                <span>🌐 Trunk 链路 VLAN 划分与安全合规表 (Trunk VLAN Topology)</span>
              </h4>
            </div>

            <div class="overflow-x-auto">
              <table class="w-full text-left border-collapse">
                <thead>
                  <tr class="border-b border-slate-200 dark:border-white/10 text-[11px] font-semibold text-slate-400 font-mono uppercase tracking-wider">
                    <th class="py-2.5 px-3">VLAN 标识 (VID)</th>
                    <th class="py-2.5 px-3">封装类型</th>
                    <th class="py-2.5 px-3">外层 S-Tag</th>
                    <th class="py-2.5 px-3">累计报文数</th>
                    <th class="py-2.5 px-3">累计流量</th>
                    <th class="py-2.5 px-3">活跃 MAC 数</th>
                    <th class="py-2.5 px-3">采样 MAC 节点</th>
                    <th class="py-2.5 px-3">安全合规审计</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-slate-100 dark:divide-white/5 text-xs font-mono">
                  <tr
                    v-for="stat in vlanData.stats"
                    :key="'vlan-' + stat.vid + '-' + (stat.outer_vid || 0)"
                    class="hover:bg-white/60 dark:hover:bg-slate-800/50 transition-colors"
                  >
                    <td class="py-3 px-3 font-bold text-slate-900 dark:text-white flex items-center gap-2">
                      <span class="w-2.5 h-2.5 rounded-full" :class="stat.vid === 1 ? 'bg-amber-500' : 'bg-indigo-500'"></span>
                      <span>VLAN {{ stat.vid }}</span>
                    </td>
                    <td class="py-3 px-3">
                      <span
                        class="px-2 py-0.5 rounded-md text-[10px] font-bold"
                        :class="stat.is_qinq ? 'bg-purple-100 text-purple-700 dark:bg-purple-950 dark:text-purple-300' : 'bg-indigo-100 text-indigo-700 dark:bg-indigo-950 dark:text-indigo-300'"
                      >
                        {{ stat.is_qinq ? '802.1ad (QinQ)' : '802.1Q' }}
                      </span>
                    </td>
                    <td class="py-3 px-3 text-slate-500">
                      {{ stat.outer_vid !== null ? 'VID ' + stat.outer_vid : '—' }}
                    </td>
                    <td class="py-3 px-3 text-slate-700 dark:text-slate-300 font-semibold">
                      {{ stat.packet_count.toLocaleString() }}
                    </td>
                    <td class="py-3 px-3 text-slate-600 dark:text-slate-300">
                      {{ formatBytes(stat.byte_count) }}
                    </td>
                    <td class="py-3 px-3 text-indigo-600 dark:text-indigo-400 font-bold">
                      {{ stat.active_mac_count }}
                    </td>
                    <td class="py-3 px-3 text-[11px] text-slate-500 max-w-xs truncate">
                      {{ stat.sample_macs.join(', ') || '无记录' }}
                    </td>
                    <td class="py-3 px-3">
                      <div v-if="stat.security_flags.length === 0" class="text-emerald-600 dark:text-emerald-400 text-[11px] flex items-center gap-1">
                        <span>✓</span>
                        <span>隔离正常</span>
                      </div>
                      <div v-else class="flex flex-wrap gap-1">
                        <span
                          v-for="flag in stat.security_flags"
                          :key="flag"
                          class="px-2 py-0.5 rounded-md text-[10px] font-bold"
                          :class="flag.includes('HOPPING') ? 'bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-300 border border-red-200' : 'bg-amber-100 text-amber-700 dark:bg-amber-950 dark:text-amber-300 border border-amber-200'"
                        >
                          ⚠️ {{ flag }}
                        </span>
                      </div>
                    </td>
                  </tr>

                  <!-- 空状态 -->
                  <tr v-if="vlanData.stats.length === 0">
                    <td colspan="8" class="py-8 text-center text-slate-400 font-sans text-xs">
                      当前监听网络未检测到 IEEE 802.1Q 标签报文。若需验证，请点击“诊断工作台”载入 802.1Q / QinQ 样本报文。
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <!-- ======================= 3. 蓝牙近场空间感知与 BLE 资产雷达 ======================= -->
        <div v-if="activeTab === 'bluetooth'" class="space-y-6">
          <!-- 统计概览卡片组 -->
          <div class="grid grid-cols-2 md:grid-cols-5 gap-3">
            <div class="p-4 rounded-2xl bg-slate-50/80 dark:bg-slate-800/40 border border-slate-200/80 dark:border-white/10">
              <div class="text-xs text-slate-500 dark:text-slate-400 font-medium">总蓝牙 HCI 封包数</div>
              <div class="text-2xl font-mono font-bold text-slate-900 dark:text-white mt-1">
                {{ btData.total_packets.toLocaleString() }}
              </div>
              <div class="text-[11px] text-slate-400 font-mono mt-1">HCI H4 捕获数据流</div>
            </div>

            <div class="p-4 rounded-2xl bg-slate-50/80 dark:bg-slate-800/40 border border-slate-200/80 dark:border-white/10">
              <div class="text-xs text-slate-500 dark:text-slate-400 font-medium">空间感知设备总数</div>
              <div class="text-2xl font-mono font-bold text-blue-600 dark:text-blue-400 mt-1">
                {{ btData.active_device_count }}
              </div>
              <div class="text-[11px] text-slate-400 font-mono mt-1">BD_ADDR 物理地址资产</div>
            </div>

            <div class="p-4 rounded-2xl bg-slate-50/80 dark:bg-slate-800/40 border border-slate-200/80 dark:border-white/10">
              <div class="text-xs text-slate-500 dark:text-slate-400 font-medium">BLE 广播报文 (ADV)</div>
              <div class="text-2xl font-mono font-bold text-indigo-600 dark:text-indigo-400 mt-1">
                {{ btData.advertising_packets.toLocaleString() }}
              </div>
              <div class="text-[11px] text-slate-400 font-mono mt-1">ADV_IND / NONCONN / SCAN</div>
            </div>

            <div class="p-4 rounded-2xl bg-slate-50/80 dark:bg-slate-800/40 border border-slate-200/80 dark:border-white/10">
              <div class="text-xs text-slate-500 dark:text-slate-400 font-medium">L2CAP ACL 活跃数据流</div>
              <div class="text-2xl font-mono font-bold text-emerald-600 dark:text-emerald-400 mt-1">
                {{ btData.acl_data_packets.toLocaleString() }}
              </div>
              <div class="text-[11px] text-slate-400 font-mono mt-1">点对点连接通信通道</div>
            </div>

            <div class="p-4 rounded-2xl bg-slate-50/80 dark:bg-slate-800/40 border border-slate-200/80 dark:border-white/10"
              :class="btData.unencrypted_att_count > 0 ? 'border-amber-300 dark:border-amber-800/60 bg-amber-50/30 dark:bg-amber-950/10' : ''">
              <div class="text-xs text-slate-500 dark:text-slate-400 font-medium">未加密 ATT 读写告警</div>
              <div class="text-2xl font-mono font-bold mt-1"
                :class="btData.unencrypted_att_count > 0 ? 'text-amber-600 dark:text-amber-400' : 'text-slate-700 dark:text-slate-300'">
                {{ btData.unencrypted_att_count }}
              </div>
              <div class="text-[11px] text-slate-400 font-mono mt-1">明文工控传感器数据暴露</div>
            </div>
          </div>

          <!-- 蓝牙设备资产空间感知列表 -->
          <div class="p-5 rounded-2xl bg-slate-50/60 dark:bg-slate-800/30 border border-slate-200/80 dark:border-white/10 space-y-3">
            <div class="flex items-center justify-between">
              <h4 class="text-xs font-bold text-slate-800 dark:text-slate-200 flex items-center gap-2">
                <span>🔵 蓝牙/BLE 设备雷达与距离衰减估算 (Path Loss Distance Estimation)</span>
                <span class="text-[10px] text-slate-400 font-mono font-normal">基于 Log-Distance 物理路径损耗模型 d = 10^((A-RSSI)/(10n))</span>
              </h4>
            </div>

            <div class="overflow-x-auto">
              <table class="w-full text-left border-collapse">
                <thead>
                  <tr class="border-b border-slate-200 dark:border-white/10 text-[11px] font-semibold text-slate-400 font-mono uppercase tracking-wider">
                    <th class="py-2.5 px-3">设备广播名称</th>
                    <th class="py-2.5 px-3">BD_ADDR 蓝牙物理地址</th>
                    <th class="py-2.5 px-3">地址类别</th>
                    <th class="py-2.5 px-3">RSSI 信号</th>
                    <th class="py-2.5 px-3">物理估算距离</th>
                    <th class="py-2.5 px-3">暴露服务 (UUID)</th>
                    <th class="py-2.5 px-3">安全与配对态势</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-slate-100 dark:divide-white/5 text-xs font-mono">
                  <tr
                    v-for="dev in btData.devices"
                    :key="dev.address"
                    class="hover:bg-white/60 dark:hover:bg-slate-800/50 transition-colors"
                  >
                    <td class="py-3 px-3 font-bold text-slate-900 dark:text-white flex items-center gap-2">
                      <span class="text-blue-500">🔵</span>
                      <span>{{ dev.device_name }}</span>
                    </td>
                    <td class="py-3 px-3 text-slate-600 dark:text-slate-300">
                      {{ dev.address }}
                    </td>
                    <td class="py-3 px-3 text-[11px]">
                      <span class="px-2 py-0.5 rounded-md" :class="dev.address_type.includes('Public') ? 'bg-sky-100 text-sky-700 dark:bg-sky-950 dark:text-sky-300' : 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-400'">
                        {{ dev.address_type }}
                      </span>
                    </td>
                    <td class="py-3 px-3">
                      <span class="font-bold" :class="getRssiColorClass(dev.last_rssi_dbm)">
                        {{ dev.last_rssi_dbm }} dBm
                      </span>
                    </td>
                    <td class="py-3 px-3">
                      <div class="flex items-center gap-2">
                        <span class="font-bold text-indigo-600 dark:text-indigo-400">
                          ≈ {{ dev.estimated_distance_m }} 米
                        </span>
                        <span class="text-[10px] px-1.5 py-0.5 rounded bg-slate-200 dark:bg-slate-700 text-slate-600 dark:text-slate-300">
                          {{ getDistanceZone(dev.estimated_distance_m) }}
                        </span>
                      </div>
                    </td>
                    <td class="py-3 px-3 max-w-xs truncate text-[11px] text-slate-500">
                      {{ dev.service_uuids.join(', ') || '未广播标准 UUID' }}
                    </td>
                    <td class="py-3 px-3">
                      <div v-if="dev.security_flags.length === 0" class="text-emerald-600 dark:text-emerald-400 text-[11px] flex items-center gap-1">
                        <span>✓</span>
                        <span>广播安全</span>
                      </div>
                      <div v-else class="flex flex-wrap gap-1">
                        <span
                          v-for="flag in dev.security_flags"
                          :key="flag"
                          class="px-2 py-0.5 rounded-md text-[10px] font-bold bg-amber-100 text-amber-700 dark:bg-amber-950 dark:text-amber-300 border border-amber-200"
                        >
                          ⚠️ {{ flag }}
                        </span>
                      </div>
                    </td>
                  </tr>

                  <!-- 空状态 -->
                  <tr v-if="btData.devices.length === 0">
                    <td colspan="7" class="py-8 text-center text-slate-400 font-sans text-xs">
                      未捕获到蓝牙 HCI 封包。请连接蓝牙抓包 Dongle 或在“诊断工作台”中载入 BLE 样本进行解剖验证。
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <!-- ======================= 4. 报文深度解剖诊断工作台 ======================= -->
        <div v-if="activeTab === 'workbench'" class="space-y-6">
          <div class="p-5 rounded-2xl bg-slate-50/80 dark:bg-slate-800/40 border border-slate-200/80 dark:border-white/10 space-y-4">
            <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h4 class="text-xs font-bold text-slate-800 dark:text-slate-200 flex items-center gap-2">
                  <span>🔬 无线与 VLAN 原生十六进制解剖工作台 (Hex Dissector Workbench)</span>
                </h4>
                <p class="text-[11px] text-slate-500 font-mono mt-0.5">
                  输入包含 Radiotap / 802.11 / 802.1Q / Bluetooth HCI 的十六进制报文字符串进行逐层深度解剖
                </p>
              </div>

              <!-- 样本载入按钮 -->
              <div class="flex flex-wrap items-center gap-2">
                <span class="text-[11px] text-slate-400">快速载入标准样本:</span>
                <button
                  @click="loadSample('wifi')"
                  class="px-2.5 py-1 rounded-xl text-[11px] font-semibold bg-white dark:bg-slate-700 text-sky-600 dark:text-sky-300 border border-slate-200 dark:border-white/10 hover:bg-sky-50 cursor-pointer shadow-2xs"
                >
                  Wi-Fi Beacon
                </button>
                <button
                  @click="loadSample('vlan')"
                  class="px-2.5 py-1 rounded-xl text-[11px] font-semibold bg-white dark:bg-slate-700 text-indigo-600 dark:text-indigo-300 border border-slate-200 dark:border-white/10 hover:bg-indigo-50 cursor-pointer shadow-2xs"
                >
                  QinQ Double Tagging
                </button>
                <button
                  @click="loadSample('bluetooth')"
                  class="px-2.5 py-1 rounded-xl text-[11px] font-semibold bg-white dark:bg-slate-700 text-purple-600 dark:text-purple-300 border border-slate-200 dark:border-white/10 hover:bg-purple-50 cursor-pointer shadow-2xs"
                >
                  BLE Advertising
                </button>
              </div>
            </div>

            <!-- Hex 输入框 -->
            <div class="space-y-2">
              <textarea
                v-model="customHexInput"
                rows="4"
                placeholder="请在此粘贴 Hex 原始字符串（例如: 00 00 12 00 6C 00 00 00 6C 00 6C 09 A0 00 D3 A1 00 00...）"
                class="w-full p-3 rounded-xl bg-white dark:bg-slate-900 border border-slate-300 dark:border-white/10 font-mono text-xs text-slate-800 dark:text-slate-200 focus:outline-none focus:ring-2 focus:ring-indigo-500"
              ></textarea>
              <div class="flex items-center justify-between">
                <div class="flex items-center gap-3">
                  <label class="text-xs font-semibold text-slate-600 dark:text-slate-400">解剖模式:</label>
                  <select
                    v-model="dissectMode"
                    class="px-3 py-1 rounded-lg bg-white dark:bg-slate-800 border border-slate-300 dark:border-white/10 text-xs font-mono font-medium text-slate-700 dark:text-slate-200 cursor-pointer"
                  >
                    <option value="auto">自动探查 (Auto Detect)</option>
                    <option value="wifi">Wi-Fi (802.11 / Radiotap)</option>
                    <option value="vlan">VLAN (802.1Q / 802.1ad QinQ)</option>
                    <option value="bluetooth">蓝牙 (Bluetooth HCI / BLE)</option>
                  </select>
                </div>

                <button
                  @click="triggerDissect"
                  :disabled="!customHexInput.trim() || dissecting"
                  class="px-5 py-2 rounded-xl text-xs font-bold bg-indigo-600 hover:bg-indigo-700 text-white shadow-md shadow-indigo-500/25 transition-all cursor-pointer disabled:opacity-50 flex items-center gap-1.5"
                >
                  <span>{{ dissecting ? '解剖分析中...' : '执行深度原生解剖' }}</span>
                </button>
              </div>
            </div>

            <!-- 解剖结果展示卡片 -->
            <div v-if="dissectionResult" class="p-4 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-white/10 space-y-3">
              <div class="flex items-center justify-between border-b border-slate-100 dark:border-white/10 pb-2">
                <div class="flex items-center gap-2">
                  <span class="w-3 h-3 rounded-full" :class="dissectionResult.success ? 'bg-emerald-500' : 'bg-red-500'"></span>
                  <span class="text-xs font-bold text-slate-900 dark:text-white">
                    解剖定性: {{ dissectionResult.identified_protocol }}
                  </span>
                  <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-500">
                    载荷大小: {{ dissectionResult.raw_bytes_count }} 字节
                  </span>
                </div>
                <div class="text-[11px] font-mono font-semibold" :class="dissectionResult.success ? 'text-emerald-600 dark:text-emerald-400' : 'text-red-500'">
                  {{ dissectionResult.success ? '✓ 协议解剖成功' : '✗ 解析异常' }}
                </div>
              </div>

              <!-- 威胁检测警报列表 -->
              <div v-if="dissectionResult.security_threats && dissectionResult.security_threats.length > 0" class="p-3 rounded-lg bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-800 space-y-1">
                <div class="text-xs font-bold text-red-700 dark:text-red-300 flex items-center gap-1.5">
                  <span>⚠️ 触发的安全威胁与规约违规审计:</span>
                </div>
                <ul class="list-disc list-inside text-xs font-mono text-red-600 dark:text-red-400 space-y-0.5">
                  <li v-for="threat in dissectionResult.security_threats" :key="threat">
                    {{ threat }}
                  </li>
                </ul>
              </div>

              <!-- 结构化 JSON 视图 -->
              <div class="space-y-1">
                <div class="text-[11px] font-bold text-slate-400 font-mono">结构化元数据树 (Structured Syntax Details):</div>
                <pre class="p-3 rounded-lg bg-slate-950 text-emerald-400 font-mono text-xs overflow-x-auto max-h-64 custom-scrollbar">{{ JSON.stringify(dissectionResult.structured_details, null, 2) }}</pre>
              </div>
            </div>
          </div>
        </div>

      </div>

      <!-- 底栏：状态与快捷操作 -->
      <div class="px-6 py-3 border-t border-slate-200/80 dark:border-white/10 bg-slate-50/50 dark:bg-black/30 flex items-center justify-between text-xs text-slate-500 font-mono shrink-0">
        <div class="flex items-center gap-4">
          <span class="flex items-center gap-1.5">
            <span class="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            <span>引擎状态: 实时多协议物理层/链路层感知就绪</span>
          </span>
          <span class="hidden sm:inline text-slate-300 dark:text-slate-700">|</span>
          <span class="hidden sm:inline">覆盖: 802.11 a/b/g/n/ac/ax/be · 802.1Q/ad · BLE HCI H4</span>
        </div>

        <div class="flex items-center gap-2">
          <button
            @click="resetTelemetry"
            class="px-3 py-1 rounded-lg text-slate-600 dark:text-slate-400 hover:text-red-600 dark:hover:text-red-400 hover:bg-slate-200/50 dark:hover:bg-slate-800 transition-colors cursor-pointer"
          >
            清空遥测历史
          </button>
          <button
            @click="$emit('close')"
            class="px-4 py-1.5 rounded-xl font-bold bg-slate-200 hover:bg-slate-300 dark:bg-slate-700 dark:hover:bg-slate-600 text-slate-800 dark:text-white transition-all cursor-pointer"
          >
            完成并关闭
          </button>
        </div>
      </div>

    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';

defineProps<{
  isOpen: boolean;
}>();

defineEmits<{
  (e: 'close'): void;
}>();

const activeTab = ref<'wifi' | 'vlan' | 'bluetooth' | 'workbench'>('wifi');
const loading = ref(false);
const dissecting = ref(false);

const tabs = [
  { id: 'wifi', label: 'Wi-Fi 频谱与 AP 资产', icon: '📶' },
  { id: 'vlan', label: 'VLAN 拓扑与隔离审计', icon: '🌐' },
  { id: 'bluetooth', label: '蓝牙近场空间感知', icon: '🔵' },
  { id: 'workbench', label: '单帧深度解剖诊断', icon: '🔬' },
] as const;

// Wi-Fi 遥测模型
interface WifiAP {
  bssid: string;
  ssid: string;
  channel: number;
  band_desc: string;
  last_rssi_dbm: number;
  avg_rssi_dbm: number;
  beacon_count: number;
  data_packet_count: number;
  encryption_type: string;
  vendor_name: string;
  last_seen_timestamp: string;
  security_alerts: string[];
}

interface WifiTelemetry {
  total_wifi_frames: number;
  management_frames: number;
  control_frames: number;
  data_frames: number;
  deauth_attack_count: number;
  rogue_ap_alerts: number;
  channel_distribution: Record<number, number>;
  ap_assets: WifiAP[];
}

// VLAN 遥测模型
interface VlanStat {
  vid: number;
  is_qinq: boolean;
  outer_vid: number | null;
  packet_count: number;
  byte_count: number;
  pcp_distribution: number[];
  active_mac_count: number;
  sample_macs: string[];
  last_seen_timestamp: string;
  security_flags: string[];
}

interface VlanTelemetry {
  total_vlan_packets: number;
  total_vlan_bytes: number;
  active_vlan_count: number;
  qinq_packets: number;
  vlan_hopping_threats: number;
  default_vlan1_packets: number;
  stats: VlanStat[];
}

// 蓝牙遥测模型
interface BluetoothDevice {
  address: string;
  address_type: string;
  device_name: string;
  last_rssi_dbm: number;
  avg_rssi_dbm: number;
  estimated_distance_m: number;
  tx_power_dbm: number;
  packet_count: number;
  service_uuids: string[];
  vendor_info: string;
  last_seen_timestamp: string;
  is_connectable: boolean;
  security_flags: string[];
}

interface BluetoothTelemetry {
  total_packets: number;
  advertising_packets: number;
  acl_data_packets: number;
  unencrypted_att_count: number;
  active_device_count: number;
  devices: BluetoothDevice[];
}

// 统一解剖结果
interface DissectionResult {
  mode: string;
  identified_protocol: string;
  raw_bytes_count: number;
  success: boolean;
  error_message?: string;
  structured_details: any;
  security_threats: string[];
}

const wifiData = ref<WifiTelemetry>({
  total_wifi_frames: 0,
  management_frames: 0,
  control_frames: 0,
  data_frames: 0,
  deauth_attack_count: 0,
  rogue_ap_alerts: 0,
  channel_distribution: {},
  ap_assets: [],
});

const vlanData = ref<VlanTelemetry>({
  total_vlan_packets: 0,
  total_vlan_bytes: 0,
  active_vlan_count: 0,
  qinq_packets: 0,
  vlan_hopping_threats: 0,
  default_vlan1_packets: 0,
  stats: [],
});

const btData = ref<BluetoothTelemetry>({
  total_packets: 0,
  advertising_packets: 0,
  acl_data_packets: 0,
  unencrypted_att_count: 0,
  active_device_count: 0,
  devices: [],
});

// 解剖工作台状态
const customHexInput = ref('');
const dissectMode = ref('auto');
const dissectionResult = ref<DissectionResult | null>(null);

let pollTimer: number | null = null;

async function fetchWifiTelemetry() {
  try {
    const res = await invoke<WifiTelemetry>('get_wifi_telemetry_cmd');
    if (res) wifiData.value = res;
  } catch (err) {
    console.error('获取 Wi-Fi 遥测失败:', err);
  }
}

async function fetchVlanTelemetry() {
  try {
    const res = await invoke<VlanTelemetry>('get_vlan_telemetry_cmd');
    if (res) vlanData.value = res;
  } catch (err) {
    console.error('获取 VLAN 遥测失败:', err);
  }
}

async function fetchBluetoothTelemetry() {
  try {
    const res = await invoke<BluetoothTelemetry>('get_bluetooth_telemetry_cmd');
    if (res) btData.value = res;
  } catch (err) {
    console.error('获取蓝牙遥测失败:', err);
  }
}

async function refreshCurrentTelemetry() {
  loading.value = true;
  await Promise.allSettled([
    fetchWifiTelemetry(),
    fetchVlanTelemetry(),
    fetchBluetoothTelemetry(),
  ]);
  loading.value = false;
}

async function resetTelemetry() {
  try {
    if (activeTab.value === 'wifi') {
      await invoke('reset_wifi_telemetry_cmd');
      await fetchWifiTelemetry();
    } else if (activeTab.value === 'vlan') {
      await invoke('reset_vlan_telemetry_cmd');
      await fetchVlanTelemetry();
    } else if (activeTab.value === 'bluetooth') {
      await invoke('reset_bluetooth_telemetry_cmd');
      await fetchBluetoothTelemetry();
    }
  } catch (err) {
    console.error('重置遥测失败:', err);
  }
}

async function triggerDissect() {
  if (!customHexInput.value.trim()) return;
  dissecting.value = true;
  try {
    const res = await invoke<DissectionResult>('dissect_wireless_or_vlan_hex_cmd', {
      rawHex: customHexInput.value,
      mode: dissectMode.value,
    });
    dissectionResult.value = res;
  } catch (err: any) {
    dissectionResult.value = {
      mode: dissectMode.value,
      identified_protocol: 'ERROR',
      raw_bytes_count: 0,
      success: false,
      error_message: String(err),
      structured_details: {},
      security_threats: [],
    };
  } finally {
    dissecting.value = false;
  }
}

function loadSample(type: 'wifi' | 'vlan' | 'bluetooth') {
  if (type === 'wifi') {
    // 带有 Radiotap 头 (18B) 的 802.11 Beacon 帧 (包含 SSID "Industrial-WLAN", Ch 6, RSSI -45dBm)
    customHexInput.value = '000012006C0000006C006C09A000D3A1000080000000FFFFFFFFFFFF0011223344550011223344550000000000000000000064001100000F496E647573747269616C2D574C414E030106';
    dissectMode.value = 'wifi';
  } else if (type === 'vlan') {
    // IEEE 802.1ad QinQ 双层标签以太网帧 (S-Tag VID 1 Native -> C-Tag VID 200 Target, IPv4)
    customHexInput.value = 'FFFFFFFFFFFF00112233445588A800018100A0C80800450000280001000040067CCE7F0000017F00000104D20050000000010000000050022000B5200000';
    dissectMode.value = 'vlan';
  } else if (type === 'bluetooth') {
    // Bluetooth HCI H4 Event 0x3E LE Meta Event (Advertising Report, Name "OMNI", RSSI -65dBm)
    customHexInput.value = '043E1E020100001122334455660A02010605094F4D4E4900BF';
    dissectMode.value = 'bluetooth';
  }
  triggerDissect();
}

function getChannelPercent(channel: number): number {
  const counts = wifiData.value.channel_distribution;
  const current = counts[channel] || 0;
  let max = 1;
  for (const k in counts) {
    if (counts[k] > max) max = counts[k];
  }
  return Math.max(10, Math.min(100, Math.round((current / max) * 100)));
}

function getPcpTotalCount(pcp: number): number {
  let sum = 0;
  for (const s of vlanData.value.stats) {
    if (s.pcp_distribution && s.pcp_distribution[pcp] !== undefined) {
      sum += s.pcp_distribution[pcp];
    }
  }
  return sum;
}

function getPcpShortLabel(pcp: number): string {
  const labels = [
    '尽力而为 (BE)',
    '背景流量 (BK)',
    '优先业务 (EE)',
    '工控关键 (CA)',
    '视频低延时',
    '实时语音 (VO)',
    '拓扑控制 (IC)',
    '网络保护 (NC)',
  ];
  return labels[pcp] || 'PCP ' + pcp;
}

function getRssiColorClass(rssi: number): string {
  if (rssi >= -60) return 'text-emerald-500 dark:text-emerald-400';
  if (rssi >= -75) return 'text-sky-500 dark:text-sky-400';
  if (rssi >= -85) return 'text-amber-500 dark:text-amber-400';
  return 'text-red-500 dark:text-red-400';
}

function getRssiBgClass(rssi: number): string {
  if (rssi >= -60) return 'bg-emerald-500';
  if (rssi >= -75) return 'bg-sky-500';
  if (rssi >= -85) return 'bg-amber-500';
  return 'bg-red-500';
}

function getEncryptionClass(enc: string): string {
  if (enc.includes('WPA3')) return 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300';
  if (enc.includes('WPA2')) return 'bg-sky-100 text-sky-800 dark:bg-sky-950 dark:text-sky-300';
  if (enc.includes('WEP')) return 'bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300';
  return 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300';
}

function getDistanceZone(m: number): string {
  if (m < 1.0) return '近场 (<1m)';
  if (m < 5.0) return '中场 (1-5m)';
  return '远场 (>5m)';
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
}

onMounted(() => {
  refreshCurrentTelemetry();
  pollTimer = window.setInterval(() => {
    if (activeTab.value === 'wifi') fetchWifiTelemetry();
    else if (activeTab.value === 'vlan') fetchVlanTelemetry();
    else if (activeTab.value === 'bluetooth') fetchBluetoothTelemetry();
  }, 3000);
});

onUnmounted(() => {
  if (pollTimer) clearInterval(pollTimer);
});
</script>

<style scoped>
.custom-scrollbar::-webkit-scrollbar {
  width: 6px;
  height: 6px;
}
.custom-scrollbar::-webkit-scrollbar-track {
  background: transparent;
}
.custom-scrollbar::-webkit-scrollbar-thumb {
  background: rgba(148, 163, 184, 0.25);
  border-radius: 9999px;
}
.custom-scrollbar::-webkit-scrollbar-thumb:hover {
  background: rgba(148, 163, 184, 0.4);
}
</style>
