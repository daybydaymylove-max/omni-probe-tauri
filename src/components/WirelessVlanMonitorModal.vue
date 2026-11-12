<template>
  <div v-if="isOpen" class="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 ui-modal-backdrop animate-in fade-in duration-200">
    <div class="w-full max-w-6xl max-h-[92vh] ui-modal-surface rounded-3xl flex flex-col overflow-hidden">
      <span class="lens-edge-lip" aria-hidden="true"></span>
      
      <!-- 顶栏：标题与分段控制器 (Liquid Glass) -->
      <header class="ui-nav-glass border-b px-6 py-3.5 flex flex-col md:flex-row md:items-center justify-between gap-3 shrink-0">
        <div class="flex items-center gap-3">
          <div class="w-9 h-9 rounded-xl bg-sky-500/15 border border-sky-500/30 flex items-center justify-center text-sky-700 dark:text-sky-300 shrink-0">
            <AppIcon name="wifi" :size="18" />
          </div>
          <div>
            <div class="flex items-center gap-2 flex-wrap">
              <h3 class="text-sm font-bold" style="color: var(--text-primary)">
                无线链路与虚拟局域网监测控制台
              </h3>
              <span class="px-2 py-0.5 rounded-full text-[11px] ui-num font-semibold bg-indigo-500/12 text-indigo-700 dark:text-indigo-300 border border-indigo-500/25">
                PRO-WIRELESS & VLAN
              </span>
            </div>
            <p class="text-[11px] ui-num mt-0.5" style="color: var(--text-muted)">
              IEEE 802.11 Radiotap 信道热力 · 802.1Q/ad QinQ 跨层审计 · BLE HCI 空间路径衰减感知
            </p>
          </div>
        </div>

        <div class="flex items-center gap-2.5 flex-wrap">
          <div class="p-1 rounded-2xl ui-pill flex items-center gap-1 text-xs font-semibold flex-wrap">
            <button
              v-for="tab in tabs"
              :key="tab.id"
              @click="activeTab = tab.id"
              :class="[
                'px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer',
                activeTab === tab.id ? 'bg-sky-500 text-white shadow-xs font-bold' : 'hover:bg-black/5 dark:hover:bg-white/5'
              ]"
              :style="activeTab !== tab.id ? { color: 'var(--text-secondary)' } : undefined"
            >
              <AppIcon :name="tab.icon" :size="13" />
              <span>{{ tab.label }}</span>
            </button>
          </div>

          <div class="flex items-center gap-2">
            <button
              @click="refreshCurrentTelemetry"
              :disabled="loading"
              class="w-8 h-8 rounded-full ui-pill flex items-center justify-center cursor-pointer disabled:opacity-50"
              title="刷新遥测指标"
            >
              <AppIcon name="refresh" :size="14" :class="loading ? 'animate-spin' : ''" />
            </button>
            <button
              @click="$emit('close')"
              class="w-8 h-8 rounded-full ui-pill flex items-center justify-center cursor-pointer"
              title="关闭"
            >
              <AppIcon name="close" :size="15" />
            </button>
          </div>
        </div>
      </header>

      <!-- 主体内容区域 -->
      <div class="flex-1 overflow-y-auto custom-scrollbar p-6 space-y-5 bg-transparent">

        <!-- ======================= 1. Wi-Fi 频谱与无线威胁监测 ======================= -->
        <div v-if="activeTab === 'wifi'" class="space-y-5">
          <div class="grid grid-cols-2 md:grid-cols-5 gap-3">
            <div class="ui-sub-card p-3.5">
              <div class="text-xs font-medium" style="color: var(--text-muted)">总捕获 Wi-Fi 帧数</div>
              <div class="text-2xl ui-num font-bold mt-1" style="color: var(--text-primary)">
                {{ wifiData.total_wifi_frames.toLocaleString() }}
              </div>
              <div class="text-[11px] ui-num mt-1" style="color: var(--text-muted)">Radiotap / 802.11 载荷</div>
            </div>

            <div class="ui-sub-card p-3.5">
              <div class="text-xs font-medium" style="color: var(--text-muted)">AP 热点 / BSSID 资产</div>
              <div class="text-2xl ui-num font-bold text-sky-700 dark:text-sky-400 mt-1">
                {{ wifiData.ap_assets.length }}
              </div>
              <div class="text-[11px] ui-num mt-1" style="color: var(--text-muted)">活跃接入点空间感知</div>
            </div>

            <div class="ui-sub-card p-3.5">
              <div class="text-xs font-medium" style="color: var(--text-muted)">802.11 管理与控制帧</div>
              <div class="text-2xl ui-num font-bold text-indigo-700 dark:text-indigo-400 mt-1">
                {{ (wifiData.management_frames + wifiData.control_frames).toLocaleString() }}
              </div>
              <div class="text-[11px] ui-num mt-1" style="color: var(--text-muted)">Beacon / Probe / RTS / ACK</div>
            </div>

            <div class="ui-sub-card p-3.5">
              <div class="text-xs font-medium" style="color: var(--text-muted)">802.11 QoS 数据帧</div>
              <div class="text-2xl ui-num font-bold text-emerald-700 dark:text-emerald-400 mt-1">
                {{ wifiData.data_frames.toLocaleString() }}
              </div>
              <div class="text-[11px] ui-num mt-1" style="color: var(--text-muted)">上层应用通信流量载荷</div>
            </div>

            <div class="ui-sub-card p-3.5"
              :class="wifiData.deauth_attack_count > 0 ? '!border-rose-500/40 bg-rose-500/10' : ''">
              <div class="text-xs font-medium" style="color: var(--text-muted)">Deauth 洪水告警</div>
              <div class="text-2xl ui-num font-bold mt-1"
                :class="wifiData.deauth_attack_count > 0 ? 'text-rose-700 dark:text-rose-400' : ''" :style="wifiData.deauth_attack_count === 0 ? { color: 'var(--text-primary)' } : undefined">
                {{ wifiData.deauth_attack_count }}
              </div>
              <div class="text-[11px] ui-num mt-1" style="color: var(--text-muted)">拒绝服务断开攻击监测</div>
            </div>
          </div>

          <!-- 原生系统 WLAN 物理扫描 (Windows wlanapi.dll + netsh / Linux nmcli) 置顶直显 -->
          <div class="ui-content-card p-4 space-y-3">
            <div class="flex items-center justify-between flex-wrap gap-2">
              <div class="flex items-center gap-2 flex-wrap">
                <h4 class="text-xs font-bold flex items-center gap-2" style="color: var(--text-primary)">
                  <AppIcon name="wifi" :size="14" />
                  <span>操作系统原生 WLAN 物理适配器周边热点扫描</span>
                </h4>
                <span
                  v-if="nativeWifiScan"
                  :class="['px-2 py-0.5 rounded-full text-[10px] font-bold border',
                    nativeWifiScan.native_scan_available
                      ? 'bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 border-emerald-500/25'
                      : 'bg-amber-500/12 text-amber-700 dark:text-amber-300 border-amber-500/30']"
                >
                  {{
                    nativeWifiScan.native_scan_available
                      ? `已发现 ${nativeWifiScan.scanned_ap_count} 个热点`
                      : nativeWifiScan.reason_code === 'SERVICE_STOPPED'
                        ? 'WLAN 服务已停止'
                        : '无物理无线适配器'
                  }}
                </span>
                <span v-else-if="scanningNativeWifi" class="text-[11px] ui-num text-sky-600 dark:text-sky-300">
                  正在探测系统物理无线网卡...
                </span>
              </div>

              <div class="flex items-center gap-2">
                <button
                  v-if="nativeWifiScan && !nativeWifiScan.native_scan_available"
                  @click="activeTab = 'workbench'; loadSample('wifi')"
                  class="px-2.5 py-1 rounded-lg bg-sky-500/12 hover:bg-sky-500/20 text-sky-700 dark:text-sky-300 border border-sky-500/25 text-[11px] font-semibold cursor-pointer"
                >
                  载入 802.11 样本分析
                </button>
                <button @click="runNativeWifiScan" :disabled="scanningNativeWifi" class="ui-btn-secondary px-3 py-1 text-xs">
                  <AppIcon name="refresh" :size="12" :class="scanningNativeWifi ? 'animate-spin' : ''" />
                  <span>{{ scanningNativeWifi ? '扫描中...' : '重新扫描 WLAN' }}</span>
                </button>
              </div>
            </div>

            <div
              v-if="nativeWifiScan"
              :class="[
                'text-[11px] ui-num px-3 py-2 rounded-lg border flex items-center justify-between gap-2 flex-wrap',
                nativeWifiScan.native_scan_available
                  ? 'bg-emerald-500/8 border-emerald-500/25 text-emerald-800 dark:text-emerald-200'
                  : 'bg-amber-500/8 border-amber-500/25 text-amber-800 dark:text-amber-200'
              ]"
            >
              <span>[{{ nativeWifiScan.platform }} · {{ nativeWifiScan.reason_code }}] {{ nativeWifiScan.status_message }}</span>
              <button
                v-if="!nativeWifiScan.native_scan_available"
                @click="activeTab = 'bluetooth'"
                class="underline font-semibold cursor-pointer shrink-0"
              >
                切至蓝牙实机扫描 →
              </button>
            </div>

            <div v-if="nativeWifiScan && (nativeWifiScan.aps?.length ?? 0) > 0" class="overflow-x-auto max-h-56 overflow-y-auto custom-scrollbar">
              <table class="w-full text-left border-collapse text-xs ui-num">
                <thead class="ui-table-head text-[10px] uppercase sticky top-0">
                  <tr>
                    <th class="py-2 px-3">SSID</th>
                    <th class="py-2 px-3">BSSID</th>
                    <th class="py-2 px-3">信道 / 频段</th>
                    <th class="py-2 px-3">RSSI 场强</th>
                    <th class="py-2 px-3">认证加密</th>
                  </tr>
                </thead>
                <tbody class="divide-y" style="border-color: var(--border-subtle); color: var(--text-secondary);">
                  <tr v-for="(ap, idx) in nativeWifiScan.aps" :key="ap.bssid + '-' + idx" class="hover:bg-black/5 dark:hover:bg-white/5">
                    <td class="py-2 px-3 font-semibold" style="color: var(--text-primary);">{{ ap.ssid || '<Hidden SSID>' }}</td>
                    <td class="py-2 px-3 font-mono">{{ ap.bssid }}</td>
                    <td class="py-2 px-3">Ch {{ ap.channel ?? '-' }} ({{ ap.band_desc || '-' }})</td>
                    <td class="py-2 px-3 font-bold" :class="getRssiColorClass(ap.last_rssi_dbm ?? -80)">{{ ap.last_rssi_dbm ?? -80 }} dBm</td>
                    <td class="py-2 px-3">{{ ap.encryption_type }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <div class="ui-content-card p-5 space-y-4">
            <div class="flex items-center justify-between flex-wrap gap-2">
              <h4 class="text-xs font-bold flex items-center gap-2" style="color: var(--text-primary)">
                <AppIcon name="activity" :size="14" />
                <span>物理频段信道占用热力图谱 (Channel Spectrum Heatmap)</span>
                <span class="text-[11px] font-normal" style="color: var(--text-muted)">2.4 GHz (Ch 1-14) / 5 GHz (Ch 36-165)</span>
              </h4>
              <span class="text-[11px] ui-num text-indigo-700 dark:text-indigo-400 font-semibold">
                活跃信道数: {{ Object.keys(wifiData.channel_distribution).length }}
              </span>
            </div>

            <div class="space-y-2">
              <div class="text-[10px] font-semibold uppercase tracking-wider" style="color: var(--text-muted)">2.4 GHz 频段信道 (Ch 1 - 14)</div>
              <div class="grid grid-cols-7 lg:grid-cols-14 gap-2">
                <div
                  v-for="ch in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]"
                  :key="'ch2g-' + ch"
                  class="flex flex-col items-center gap-1.5 p-2 rounded-xl ui-sub-card"
                >
                  <div class="w-full h-16 rounded-lg flex items-end p-1 relative overflow-hidden" style="background: var(--surface-elevated)">
                    <div
                      class="w-full rounded-md transition-all duration-500 bg-gradient-to-t from-sky-500 to-indigo-500"
                      :style="{ height: getChannelPercent(ch) + '%' }"
                    ></div>
                  </div>
                  <div class="text-[11px] font-bold ui-num" style="color: var(--text-primary)">
                    Ch {{ ch }}
                  </div>
                  <div class="text-[10px] ui-num" style="color: var(--text-muted)">
                    {{ wifiData.channel_distribution[ch] || 0 }} 帧
                  </div>
                </div>
              </div>
            </div>

            <div class="space-y-2 pt-1">
              <div class="text-[10px] font-semibold uppercase tracking-wider" style="color: var(--text-muted)">5 GHz 高速频段信道 (Ch 36 - 165)</div>
              <div class="grid grid-cols-7 lg:grid-cols-13 gap-2">
                <div
                  v-for="ch5 in [36, 40, 44, 48, 52, 56, 60, 64, 149, 153, 157, 161, 165]"
                  :key="'ch5g-' + ch5"
                  class="flex flex-col items-center gap-1.5 p-2 rounded-xl ui-sub-card"
                >
                  <div class="w-full h-14 rounded-lg flex items-end p-1 relative overflow-hidden" style="background: var(--surface-elevated)">
                    <div
                      class="w-full rounded-md transition-all duration-500 bg-gradient-to-t from-emerald-500 to-teal-400"
                      :style="{ height: getChannelPercent(ch5) + '%' }"
                    ></div>
                  </div>
                  <div class="text-[11px] font-bold ui-num" style="color: var(--text-primary)">
                    Ch {{ ch5 }}
                  </div>
                  <div class="text-[10px] ui-num" style="color: var(--text-muted)">
                    {{ wifiData.channel_distribution[ch5] || 0 }} 帧
                  </div>
                </div>
              </div>
            </div>

            <!-- Wi-Fi RSSI 时序信号强度折线图 -->
            <div class="pt-2 border-t space-y-2" style="border-color: var(--border-subtle)">
              <div class="flex items-center justify-between text-xs">
                <span class="font-bold flex items-center gap-1.5" style="color: var(--text-primary)">
                  <AppIcon name="activity" :size="13" />
                  <span>Wi-Fi RSSI 时序场强波动曲线 (dBm)</span>
                </span>
                <span class="text-[11px] ui-num" style="color: var(--text-muted)">
                  采样点数: {{ (wifiData.rssi_history || []).length }}
                </span>
              </div>
              <div class="h-28 rounded-xl border p-2 flex items-center justify-center relative overflow-hidden" style="border-color: var(--border-subtle); background: rgba(15, 23, 42, 0.92);">
                <svg v-if="(wifiData.rssi_history || []).length >= 2" viewBox="0 0 760 90" class="w-full h-full">
                  <line x1="0" y1="22" x2="760" y2="22" stroke="rgba(148,163,184,0.16)" stroke-dasharray="3 3" />
                  <line x1="0" y1="45" x2="760" y2="45" stroke="rgba(148,163,184,0.16)" stroke-dasharray="3 3" />
                  <line x1="0" y1="68" x2="760" y2="68" stroke="rgba(148,163,184,0.16)" stroke-dasharray="3 3" />
                  <polyline :points="wifiRssiPolyline" fill="none" stroke="#38bdf8" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" />
                </svg>
                <span v-else class="text-[11px] text-slate-400">等待 802.11 / 原生 WLAN 扫描采集至少 2 个场强采样点</span>
              </div>
            </div>
          </div>

          <div class="ui-content-card p-5 space-y-3">
            <div class="flex items-center justify-between">
              <h4 class="text-xs font-bold flex items-center gap-2" style="color: var(--text-primary)">
                <AppIcon name="radar" :size="14" />
                <span>捕获的 Wi-Fi 接入点资产拓扑</span>
                <span class="text-[11px] px-2 py-0.5 rounded-full ui-pill ui-num">
                  共 {{ wifiData.ap_assets.length }} 个 AP
                </span>
              </h4>
            </div>

            <div class="overflow-x-auto select-text">
              <table class="w-full text-left border-collapse">
                <thead class="ui-table-head text-[11px] font-semibold uppercase tracking-wider">
                  <tr>
                    <th class="py-2.5 px-3">SSID (网络热点名称)</th>
                    <th class="py-2.5 px-3">BSSID MAC 地址</th>
                    <th class="py-2.5 px-3">物理信道 / 频段</th>
                    <th class="py-2.5 px-3">RSSI 信号强度</th>
                    <th class="py-2.5 px-3">认证与加密规约</th>
                    <th class="py-2.5 px-3">捕获帧数</th>
                    <th class="py-2.5 px-3">安全概况</th>
                    <th class="py-2.5 px-3 text-right">比对</th>
                  </tr>
                </thead>
                <tbody class="divide-y text-xs ui-num" style="border-color: var(--border-subtle); color: var(--text-secondary)">
                  <tr
                    v-for="ap in wifiData.ap_assets"
                    :key="ap.bssid"
                    class="hover:bg-black/5 dark:hover:bg-white/5 transition-colors"
                  >
                    <td class="py-3 px-3 font-semibold flex items-center gap-2" style="color: var(--text-primary)">
                      <AppIcon name="wifi" :size="13" class="text-sky-600 dark:text-sky-400 shrink-0" />
                      <span>{{ ap.ssid }}</span>
                    </td>
                    <td class="py-3 px-3">{{ ap.bssid }}</td>
                    <td class="py-3 px-3">
                      <span class="px-2 py-0.5 rounded-md text-[11px] font-bold bg-indigo-500/12 text-indigo-700 dark:text-indigo-300 border border-indigo-500/25">
                        Ch {{ ap.channel }} ({{ ap.band_desc }})
                      </span>
                    </td>
                    <td class="py-3 px-3">
                      <div class="flex items-center gap-2">
                        <span class="font-bold" :class="getRssiColorClass(ap.last_rssi_dbm)">
                          {{ ap.last_rssi_dbm }} dBm
                        </span>
                        <div class="w-16 h-2 rounded-full overflow-hidden" style="background: var(--surface-elevated)">
                          <div
                            class="h-full rounded-full"
                            :class="getRssiBgClass(ap.last_rssi_dbm)"
                            :style="{ width: Math.min(100, Math.max(10, (ap.last_rssi_dbm + 100) * 1.6)) + '%' }"
                          ></div>
                        </div>
                      </div>
                    </td>
                    <td class="py-3 px-3">
                      <span class="px-2 py-0.5 rounded-md text-[11px] font-bold border" :class="getEncryptionClass(ap.encryption_type)">
                        {{ ap.encryption_type }}
                      </span>
                    </td>
                    <td class="py-3 px-3" style="color: var(--text-muted)">
                      信标: {{ ap.beacon_count }} / 数据: {{ ap.data_packet_count }}
                    </td>
                    <td class="py-3 px-3">
                      <div v-if="ap.security_alerts.length === 0" class="text-emerald-700 dark:text-emerald-400 text-[11px] flex items-center gap-1">
                        <AppIcon name="check" :size="12" />
                        <span>信道与加密合规</span>
                      </div>
                      <div v-else class="flex flex-wrap gap-1">
                        <span
                          v-for="alert in ap.security_alerts"
                          :key="alert"
                          class="px-2 py-0.5 rounded-md text-[11px] font-bold bg-rose-500/12 text-rose-700 dark:text-rose-300 border border-rose-500/30 flex items-center gap-1"
                        >
                          <AppIcon name="alert" :size="11" />
                          <span>{{ alert }}</span>
                        </span>
                      </div>
                    </td>
                    <td class="py-3 px-3 text-right">
                      <button @click="addWifiApToDiffQueue(ap)"
                        class="px-2 py-0.5 rounded bg-emerald-500/12 hover:bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border border-emerald-500/25 text-[11px] font-semibold cursor-pointer"
                        title="将该 AP 信标属性加入全局多组比对队列">
                        + 入队
                      </button>
                    </td>
                  </tr>

                  <tr v-if="wifiData.ap_assets.length === 0">
                    <td colspan="8" class="py-8">
                      <EmptyState icon="wifi" title="暂未捕获 Wi-Fi 802.11 管理帧" description="需要处于 Monitor Mode (Radiotap/802.11) 链路的无线适配器抓包；亦可直接在下方打开单帧解码器载入 Radiotap 报文样本验证。">
                        <template #actions>
                          <button @click="activeTab = 'workbench'; loadSample('wifi')" class="ui-btn-secondary px-3 py-1 text-xs">
                            <AppIcon name="zap" :size="12" />
                            <span>载入 802.11 Radiotap 样本解码测试</span>
                          </button>
                        </template>
                      </EmptyState>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <!-- ======================= 2. VLAN 拓扑与隔离安全审计 ======================= -->
        <div v-if="activeTab === 'vlan'" class="space-y-5">
          <div class="grid grid-cols-2 md:grid-cols-5 gap-3">
            <div class="ui-sub-card p-3.5">
              <div class="text-xs font-medium" style="color: var(--text-muted)">总 VLAN 报文数</div>
              <div class="text-2xl ui-num font-bold mt-1" style="color: var(--text-primary)">
                {{ vlanData.total_vlan_packets.toLocaleString() }}
              </div>
              <div class="text-[11px] ui-num mt-1" style="color: var(--text-muted)">吞吐: {{ formatBytes(vlanData.total_vlan_bytes) }}</div>
            </div>

            <div class="ui-sub-card p-3.5">
              <div class="text-xs font-medium" style="color: var(--text-muted)">活跃 VLAN 隔离域</div>
              <div class="text-2xl ui-num font-bold text-indigo-700 dark:text-indigo-400 mt-1">
                {{ vlanData.active_vlan_count }}
              </div>
              <div class="text-[11px] ui-num mt-1" style="color: var(--text-muted)">VID 范围: 0 - 4095</div>
            </div>

            <div class="ui-sub-card p-3.5">
              <div class="text-xs font-medium" style="color: var(--text-muted)">IEEE 802.1ad (QinQ) 双层</div>
              <div class="text-2xl ui-num font-bold text-purple-700 dark:text-purple-400 mt-1">
                {{ vlanData.qinq_packets.toLocaleString() }}
              </div>
              <div class="text-[11px] ui-num mt-1" style="color: var(--text-muted)">S-Tag 运营商隧道流</div>
            </div>

            <div class="ui-sub-card p-3.5"
              :class="vlanData.vlan_hopping_threats > 0 ? '!border-rose-500/40 bg-rose-500/10' : ''">
              <div class="text-xs font-medium" style="color: var(--text-muted)">Double Tagging 跳跃穿透</div>
              <div class="text-2xl ui-num font-bold mt-1"
                :class="vlanData.vlan_hopping_threats > 0 ? 'text-rose-700 dark:text-rose-400' : ''" :style="vlanData.vlan_hopping_threats === 0 ? { color: 'var(--text-primary)' } : undefined">
                {{ vlanData.vlan_hopping_threats }}
              </div>
              <div class="text-[11px] ui-num mt-1" style="color: var(--text-muted)">VLAN Hopping 越权告警</div>
            </div>

            <div class="ui-sub-card p-3.5"
              :class="vlanData.default_vlan1_packets > 0 ? '!border-amber-500/40 bg-amber-500/10' : ''">
              <div class="text-xs font-medium" style="color: var(--text-muted)">Default VLAN 1 流量</div>
              <div class="text-2xl ui-num font-bold mt-1"
                :class="vlanData.default_vlan1_packets > 0 ? 'text-amber-700 dark:text-amber-400' : ''" :style="vlanData.default_vlan1_packets === 0 ? { color: 'var(--text-primary)' } : undefined">
                {{ vlanData.default_vlan1_packets.toLocaleString() }}
              </div>
              <div class="text-[11px] ui-num mt-1" style="color: var(--text-muted)">默认未划分生产网泄露风险</div>
            </div>
          </div>

          <div class="ui-content-card p-5 space-y-3">
            <h4 class="text-xs font-bold flex items-center justify-between flex-wrap gap-2" style="color: var(--text-primary)">
              <span class="flex items-center gap-2">
                <AppIcon name="sliders" :size="14" />
                <span>802.1p CoS 业务优先级分布矩阵 (PCP 0-7 Class of Service)</span>
              </span>
              <span class="text-[11px] font-normal" style="color: var(--text-muted)">语音 (5) / 视频 (4) / 关键工控应用 (3)</span>
            </h4>

            <div class="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-8 gap-2 pt-2">
              <div
                v-for="pcp in [0, 1, 2, 3, 4, 5, 6, 7]"
                :key="'pcp-' + pcp"
                class="p-2.5 ui-sub-card flex flex-col justify-between"
              >
                <div class="text-[11px] ui-num" style="color: var(--text-muted)">PCP {{ pcp }}</div>
                <div class="text-base font-bold ui-num my-1" style="color: var(--text-primary)">
                  {{ getPcpTotalCount(pcp).toLocaleString() }}
                </div>
                <div class="text-[11px] leading-tight" style="color: var(--text-secondary)">
                  {{ getPcpShortLabel(pcp) }}
                </div>
              </div>
            </div>
          </div>

          <div class="ui-content-card p-5 space-y-3">
            <h4 class="text-xs font-bold flex items-center gap-2" style="color: var(--text-primary)">
              <AppIcon name="globe" :size="14" />
              <span>Trunk 链路 VLAN 划分与安全合规表</span>
            </h4>

            <div class="overflow-x-auto select-text">
              <table class="w-full text-left border-collapse">
                <thead class="ui-table-head text-[11px] font-semibold uppercase tracking-wider">
                  <tr>
                    <th class="py-2.5 px-3">VLAN 标识 (VID)</th>
                    <th class="py-2.5 px-3">封装类型</th>
                    <th class="py-2.5 px-3">外层 S-Tag</th>
                    <th class="py-2.5 px-3">累计报文数</th>
                    <th class="py-2.5 px-3">累计流量</th>
                    <th class="py-2.5 px-3">活跃 MAC 数</th>
                    <th class="py-2.5 px-3">采样 MAC 节点</th>
                    <th class="py-2.5 px-3">安全合规审计</th>
                    <th class="py-2.5 px-3 text-right">比对</th>
                  </tr>
                </thead>
                <tbody class="divide-y text-xs ui-num" style="border-color: var(--border-subtle); color: var(--text-secondary)">
                  <tr
                    v-for="stat in vlanData.stats"
                    :key="'vlan-' + stat.vid + '-' + (stat.outer_vid || 0)"
                    class="hover:bg-black/5 dark:hover:bg-white/5 transition-colors"
                  >
                    <td class="py-3 px-3 font-bold flex items-center gap-2" style="color: var(--text-primary)">
                      <span class="w-2.5 h-2.5 rounded-full" :class="stat.vid === 1 ? 'bg-amber-500' : 'bg-indigo-500'"></span>
                      <span>VLAN {{ stat.vid }}</span>
                    </td>
                    <td class="py-3 px-3">
                      <span
                        class="px-2 py-0.5 rounded-md text-[11px] font-bold border"
                        :class="stat.is_qinq ? 'bg-purple-500/12 text-purple-700 dark:text-purple-300 border-purple-500/25' : 'bg-indigo-500/12 text-indigo-700 dark:text-indigo-300 border-indigo-500/25'"
                      >
                        {{ stat.is_qinq ? '802.1ad (QinQ)' : '802.1Q' }}
                      </span>
                    </td>
                    <td class="py-3 px-3" style="color: var(--text-muted)">
                      {{ stat.outer_vid !== null ? 'VID ' + stat.outer_vid : '—' }}
                    </td>
                    <td class="py-3 px-3 font-semibold" style="color: var(--text-primary)">
                      {{ stat.packet_count.toLocaleString() }}
                    </td>
                    <td class="py-3 px-3">{{ formatBytes(stat.byte_count) }}</td>
                    <td class="py-3 px-3 text-indigo-700 dark:text-indigo-400 font-bold">
                      {{ stat.active_mac_count }}
                    </td>
                    <td class="py-3 px-3 text-[11px] max-w-xs truncate" style="color: var(--text-muted)">
                      {{ stat.sample_macs.join(', ') || '无记录' }}
                    </td>
                    <td class="py-3 px-3">
                      <div v-if="stat.security_flags.length === 0" class="text-emerald-700 dark:text-emerald-400 text-[11px] flex items-center gap-1">
                        <AppIcon name="check" :size="12" />
                        <span>隔离正常</span>
                      </div>
                      <div v-else class="flex flex-wrap gap-1">
                        <span
                          v-for="flag in stat.security_flags"
                          :key="flag"
                          class="px-2 py-0.5 rounded-md text-[11px] font-bold border flex items-center gap-1"
                          :class="flag.includes('HOPPING') ? 'bg-rose-500/12 text-rose-700 dark:text-rose-300 border-rose-500/30' : 'bg-amber-500/12 text-amber-700 dark:text-amber-300 border-amber-500/30'"
                        >
                          <AppIcon name="alert" :size="11" />
                          <span>{{ flag }}</span>
                        </span>
                      </div>
                    </td>
                    <td class="py-3 px-3 text-right">
                      <button @click="addVlanToDiffQueue(stat)"
                        class="px-2 py-0.5 rounded bg-emerald-500/12 hover:bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border border-emerald-500/25 text-[11px] font-semibold cursor-pointer"
                        title="将该 VLAN 隔离统计特征加入全局多组比对队列">
                        + 入队
                      </button>
                    </td>
                  </tr>

                  <tr v-if="vlanData.stats.length === 0">
                    <td colspan="9" class="py-8">
                      <EmptyState icon="globe" title="未检测到 IEEE 802.1Q 标签报文" description="可在【单帧深度解剖诊断】中载入 802.1Q / QinQ 样本报文进行解码验证。" />
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <!-- ======================= 3. 蓝牙近场空间感知与 BLE 资产雷达 ======================= -->
        <div v-if="activeTab === 'bluetooth'" class="space-y-5">
          <div class="grid grid-cols-2 md:grid-cols-5 gap-3">
            <div class="ui-sub-card p-3.5">
              <div class="text-xs font-medium" style="color: var(--text-muted)">总蓝牙 HCI 封包数</div>
              <div class="text-2xl ui-num font-bold mt-1" style="color: var(--text-primary)">
                {{ btData.total_packets.toLocaleString() }}
              </div>
              <div class="text-[11px] ui-num mt-1" style="color: var(--text-muted)">HCI H4 捕获数据流</div>
            </div>

            <div class="ui-sub-card p-3.5">
              <div class="text-xs font-medium" style="color: var(--text-muted)">空间感知设备总数</div>
              <div class="text-2xl ui-num font-bold text-blue-700 dark:text-blue-400 mt-1">
                {{ btData.active_device_count }}
              </div>
              <div class="text-[11px] ui-num mt-1" style="color: var(--text-muted)">BD_ADDR 物理地址资产</div>
            </div>

            <div class="ui-sub-card p-3.5">
              <div class="text-xs font-medium" style="color: var(--text-muted)">BLE 广播报文 (ADV)</div>
              <div class="text-2xl ui-num font-bold text-indigo-700 dark:text-indigo-400 mt-1">
                {{ btData.advertising_packets.toLocaleString() }}
              </div>
              <div class="text-[11px] ui-num mt-1" style="color: var(--text-muted)">ADV_IND / NONCONN / SCAN</div>
            </div>

            <div class="ui-sub-card p-3.5">
              <div class="text-xs font-medium" style="color: var(--text-muted)">L2CAP ACL 活跃数据流</div>
              <div class="text-2xl ui-num font-bold text-emerald-700 dark:text-emerald-400 mt-1">
                {{ btData.acl_data_packets.toLocaleString() }}
              </div>
              <div class="text-[11px] ui-num mt-1" style="color: var(--text-muted)">点对点连接通信通道</div>
            </div>

            <div class="ui-sub-card p-3.5"
              :class="btData.unencrypted_att_count > 0 ? '!border-amber-500/40 bg-amber-500/10' : ''">
              <div class="text-xs font-medium" style="color: var(--text-muted)">未加密 ATT 读写告警</div>
              <div class="text-2xl ui-num font-bold mt-1"
                :class="btData.unencrypted_att_count > 0 ? 'text-amber-700 dark:text-amber-400' : ''" :style="btData.unencrypted_att_count === 0 ? { color: 'var(--text-primary)' } : undefined">
                {{ btData.unencrypted_att_count }}
              </div>
              <div class="text-[11px] ui-num mt-1" style="color: var(--text-muted)">明文工控传感器数据暴露</div>
            </div>
          </div>

          <!-- Win32 + WinRT + BTHPORT-ETW 原生蓝牙硬件双模连续监测台 + 单设备近场追踪 -->
          <div class="ui-content-card p-5 space-y-3">
            <div class="flex items-center justify-between flex-wrap gap-2">
              <div class="flex items-center gap-2 flex-wrap">
                <h4 class="text-xs font-bold flex items-center gap-2" style="color: var(--text-primary)">
                  <AppIcon name="cpu" :size="14" />
                  <span>蓝牙控制器 · BLE 5.0 连续空口监听 & BTHPORT 底层协议追踪</span>
                </h4>
                <span
                  v-if="nativeBtScan"
                  :class="['px-2 py-0.5 rounded-full text-[10px] font-bold border',
                    nativeBtScan.native_scan_available
                      ? 'bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 border-emerald-500/25'
                      : 'bg-amber-500/12 text-amber-700 dark:text-amber-300 border-amber-500/30']"
                >
                  {{ nativeBtScan.adapters.length }} 适配器 · {{ btData.total_packets }} 帧 · {{ btData.active_device_count }} 活跃BLE · {{ nativeBtScan.devices.length }} 配对
                </span>
              </div>
              <div class="flex items-center gap-2 flex-wrap">
                <button
                  @click="toggleContinuousBle"
                  :class="['px-3 py-1 rounded-lg text-xs font-semibold border cursor-pointer flex items-center gap-1.5 transition-all',
                    btData.continuous_ble_active || continuousBleActive
                      ? 'bg-emerald-600 text-white border-emerald-500 shadow-xs'
                      : 'ui-btn-secondary']"
                  title="开启常驻后台 WinRT BLE 5.0 Watcher，实时统计广播周期(ms)、包速率、完整 AD TLV 与靠近/远离轨迹"
                >
                  <span class="w-2 h-2 rounded-full" :class="btData.continuous_ble_active || continuousBleActive ? 'bg-white animate-pulse' : 'bg-slate-400'"></span>
                  <span>{{ btData.continuous_ble_active || continuousBleActive ? '停止实时空口监听' : '开启实时空口监听' }}</span>
                </button>
                <button
                  @click="toggleBthEtwCapture"
                  :class="['px-2.5 py-1 rounded-lg text-xs font-semibold border cursor-pointer transition-all',
                    btData.bthport_etw_active || bthEtwActive
                      ? 'bg-indigo-600 text-white border-indigo-500'
                      : 'ui-btn-secondary']"
                  title="无需 USBPcap，通过 Windows 内置 BTHPORT ETW 捕获原生双向 HCI CMD/EVT 与 L2CAP/ATT/SMP 帧（需管理员权限）"
                >
                  <span>{{ btData.bthport_etw_active || bthEtwActive ? '停止 BTHPORT HCI' : 'BTHPORT HCI 抓包' }}</span>
                </button>
                <label class="flex items-center gap-1 text-[11px] cursor-pointer" style="color: var(--text-secondary)">
                  <input type="checkbox" v-model="btInquiryMode" class="accent-sky-500" />
                  <span>深度无线寻呼 (~2.2s)</span>
                </label>
                <button @click="runNativeBtScan" :disabled="scanningNativeBt" class="ui-btn-secondary px-3 py-1 text-xs">
                  <AppIcon name="refresh" :size="12" :class="scanningNativeBt ? 'animate-spin' : ''" />
                  <span>{{ scanningNativeBt ? '扫描中...' : 'BLE+经典双模扫描' }}</span>
                </button>
              </div>
            </div>

            <!-- 历史基线保存 / 实时与历史对照 / 标准 BTSnoop (RFC 1761) 导入导出工具带 -->
            <div class="flex items-center justify-between flex-wrap gap-2 pt-2 border-t" style="border-color: var(--border-subtle)">
              <div class="flex items-center gap-2 flex-wrap">
                <button
                  @click="saveBluetoothBaseline"
                  :disabled="btToolBusy || btData.devices.length === 0"
                  class="ui-btn-secondary px-2.5 py-1 text-[11px] flex items-center gap-1 disabled:opacity-50"
                  title="将当前捕获的蓝牙资产设备名单与平均 RSSI/距离保存为物理环境参考基线"
                >
                  <AppIcon name="database" :size="12" />
                  <span>保存资产基线</span>
                </button>
                <button
                  @click="runBluetoothBaselineComparison(false)"
                  :disabled="btToolBusy"
                  class="px-2.5 py-1 rounded-lg text-[11px] font-semibold border cursor-pointer flex items-center gap-1 bg-sky-500/12 text-sky-700 dark:text-sky-300 border-sky-500/25 hover:bg-sky-500/20 disabled:opacity-50"
                  title="对比当前实时监测设备与历史基线/持久化记录，识别新增陌生设备、失联设备与信号漂移"
                >
                  <AppIcon name="activity" :size="12" />
                  <span>实时 vs 历史对照</span>
                </button>
                <button
                  @click="exportBluetoothBtsnoop"
                  :disabled="btToolBusy || (btData.recent_frames || []).length === 0"
                  class="ui-btn-secondary px-2.5 py-1 text-[11px] flex items-center gap-1 disabled:opacity-50"
                  title="将内存中实时截获帧编码导出为 Wireshark / Ellisys 通用 RFC 1761 标准 .btsnoop 文件"
                >
                  <AppIcon name="download" :size="12" />
                  <span>导出 .btsnoop</span>
                </button>
                <button
                  @click="importBluetoothBtsnoop"
                  :disabled="btToolBusy"
                  class="ui-btn-secondary px-2.5 py-1 text-[11px] flex items-center gap-1 disabled:opacity-50"
                  title="导入 Android btsnoop_hci.log 或 Wireshark .btsnoop 文件重放解码并生成多维统计图表"
                >
                  <AppIcon name="upload" :size="12" />
                  <span>导入 .btsnoop 重放</span>
                </button>
              </div>
              <div v-if="btToolMsg" class="text-[11px] ui-num text-sky-700 dark:text-sky-300 font-medium">
                {{ btToolMsg }}
              </div>
            </div>
            <div v-if="nativeBtScan || bthEtwMsg || btData.bthport_etw_status" class="text-[11px] ui-num px-3 py-2 rounded-lg border bg-[var(--surface-glass-pill)] space-y-1" style="border-color: var(--border-subtle); color: var(--text-secondary);">
              <div v-if="nativeBtScan">[{{ nativeBtScan.platform }}] {{ nativeBtScan.diagnostic_message }}</div>
              <div class="flex flex-wrap items-center justify-between gap-2 text-[10px]" style="color: var(--text-muted)">
                <span>底层 HCI ETW 状态: <strong style="color: var(--text-primary)">{{ bthEtwMsg || btData.bthport_etw_status || '待开启' }}</strong></span>
                <span>HCI Command: {{ btData.hci_command_packets ?? 0 }} | HCI Event: {{ btData.hci_event_packets ?? 0 }} | L2CAP ACL: {{ btData.acl_data_packets }}</span>
              </div>
            </div>
            <div v-if="nativeBtScan && nativeBtScan.adapters.length > 0" class="grid grid-cols-1 md:grid-cols-2 gap-2">
              <div v-for="ad in nativeBtScan.adapters" :key="ad.address" class="ui-sub-card p-2.5 text-xs ui-num flex items-center justify-between">
                <div>
                  <div class="font-bold" style="color: var(--text-primary)">{{ ad.name }}</div>
                  <div class="text-[11px] font-mono" style="color: var(--text-muted)">MAC: {{ ad.address }} | CoD: {{ ad.class_of_device }}</div>
                </div>
                <span class="px-2 py-0.5 rounded bg-sky-500/12 text-sky-600 dark:text-sky-300 text-[10px]">MFR 0x{{ ad.manufacturer_id.toString(16).toUpperCase() }}</span>
              </div>
            </div>
            <div v-if="nativeBtScan && nativeBtScan.devices.length > 0" class="overflow-x-auto">
              <table class="w-full text-left border-collapse text-xs ui-num">
                <thead class="ui-table-head text-[10px] uppercase">
                  <tr>
                    <th class="py-2 px-3">经典配对设备名称</th>
                    <th class="py-2 px-3">BD_ADDR</th>
                    <th class="py-2 px-3">连接 / 配对状态</th>
                    <th class="py-2 px-3">最近使用</th>
                    <th class="py-2 px-3 text-right">操作</th>
                  </tr>
                </thead>
                <tbody class="divide-y" style="border-color: var(--border-subtle); color: var(--text-secondary);">
                  <tr v-for="d in nativeBtScan.devices" :key="d.address">
                    <td class="py-2 px-3 font-semibold" style="color: var(--text-primary);">{{ d.name }}</td>
                    <td class="py-2 px-3 font-mono">{{ d.address }}</td>
                    <td class="py-2 px-3">
                      <span v-if="d.connected" class="px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 text-[10px] font-bold mr-1">已连接</span>
                      <span v-if="d.authenticated" class="px-1.5 py-0.5 rounded bg-sky-500/15 text-sky-700 dark:text-sky-300 text-[10px] mr-1">已配对</span>
                      <span v-if="d.remembered && !d.connected" class="px-1.5 py-0.5 rounded ui-pill text-[10px]">已记住</span>
                    </td>
                    <td class="py-2 px-3">{{ d.last_used }}</td>
                    <td class="py-2 px-3 text-right">
                      <button @click="runBleGattAudit(d.address)" :disabled="auditingGattAddr === d.address"
                        class="px-2 py-0.5 rounded bg-sky-500/12 hover:bg-sky-500/20 text-sky-700 dark:text-sky-300 border border-sky-500/25 text-[10px] font-semibold cursor-pointer disabled:opacity-50">
                        {{ auditingGattAddr === d.address ? '探测中...' : 'GATT 审计' }}
                      </button>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>

            <!-- 四联 ECharts 多维科研统计图形面板 -->
            <div class="pt-3 border-t space-y-3" style="border-color: var(--border-subtle)">
              <div class="flex items-center justify-between text-xs flex-wrap gap-2">
                <span class="font-bold flex items-center gap-1.5" style="color: var(--text-primary)">
                  <AppIcon name="radar" :size="13" />
                  <span>多维射频信号与协议统计图表 (ECharts 实时/历史引擎)</span>
                </span>
                <div class="flex items-center gap-2 text-[11px] ui-num" style="color: var(--text-muted)">
                  <button v-if="selectedBtAddress" @click="selectedBtAddress = null" class="underline text-sky-500 cursor-pointer">解除单设备锁定 ({{ selectedBtAddress }})</button>
                  <span>采样点数: {{ activeBtRssiSamples.length }} · 平均稳定度: {{ btStabilityAggregate.avgStability }}%</span>
                </div>
              </div>

              <div class="grid grid-cols-1 lg:grid-cols-2 gap-3">
                <!-- 图 1: 极坐标近场空间雷达定位分布 -->
                <div class="ui-sub-card p-3 space-y-1.5">
                  <div class="flex items-center justify-between text-[11px]">
                    <span class="font-bold" style="color: var(--text-primary)">1. 极坐标近场空间分布图 (路径衰减测距 m)</span>
                    <span class="text-[10px]" style="color: var(--text-muted)">红=风险 / 绿=可连 / 蓝=广播</span>
                  </div>
                  <div class="h-52 w-full relative">
                    <VChart v-if="filteredBtDevices.length > 0" :option="btPolarRadarOption" autoresize class="w-full h-full" />
                    <div v-else class="w-full h-full flex items-center justify-center text-[11px]" style="color: var(--text-muted)">
                      等待捕获活跃 BLE/经典蓝牙资产后绘出空间距度分布
                    </div>
                  </div>
                  <div class="text-[10px]" style="color: var(--text-muted)">
                    注: 径向距离依据真实 RSSI/TxPower 衰减模型估算，极角按设备 MAC 哈希稳定映射（单天线 PC 硬件无 AoA 方位角数据）。
                  </div>
                </div>

                <!-- 图 2: 实时流 vs 历史基线 RSSI 双线趋势对比 -->
                <div class="ui-sub-card p-3 space-y-1.5">
                  <div class="flex items-center justify-between text-[11px]">
                    <span class="font-bold" style="color: var(--text-primary)">
                      {{ selectedBtAddress ? `2. ${selectedBtAddress} 单设备实时 vs 历史基准` : '2. 实时场强流 vs 历史持久化均值对照 (dBm)' }}
                    </span>
                    <span class="text-[10px] ui-num" style="color: var(--text-muted)">实时均值 {{ btComparison?.realtime_mean_rssi_dbm ?? '-' }} vs 历史 {{ btComparison?.historical_mean_rssi_dbm ?? '-' }} dBm</span>
                  </div>
                  <div class="h-52 w-full relative">
                    <VChart
                      v-if="activeBtRssiSamples.length >= 2 || (btComparison && btComparison.trend_buckets.length >= 2)"
                      :option="btRealtimeVsHistoryOption"
                      autoresize
                      class="w-full h-full"
                    />
                    <div v-else class="w-full h-full flex items-center justify-center text-[11px]" style="color: var(--text-muted)">
                      开启「实时空口监听」或导入 .btsnoop 后自动绘出双线趋势对比
                    </div>
                  </div>
                  <div class="text-[10px]" style="color: var(--text-muted)">
                    历史采样数据源自本地持久化 `bluetooth_history.jsonl` 与基线快照 `bluetooth_baseline.json`。
                  </div>
                </div>

                <!-- 图 3: 广播间隔分布直方图 & RSSI 抖动方差统计 -->
                <div class="ui-sub-card p-3 space-y-1.5">
                  <div class="flex items-center justify-between text-[11px]">
                    <span class="font-bold" style="color: var(--text-primary)">3. 广播间隔分布直方图与链路稳态</span>
                    <span class="text-[10px] ui-num" style="color: var(--text-muted)">最大抖动: {{ btStabilityAggregate.worstName }} (σ={{ btStabilityAggregate.worstStddev }} dB)</span>
                  </div>
                  <div class="h-48 w-full relative">
                    <VChart v-if="btData.devices.length > 0" :option="btIntervalHistogramOption" autoresize class="w-full h-full" />
                    <div v-else class="w-full h-full flex items-center justify-center text-[11px]" style="color: var(--text-muted)">
                      连续采集数秒后统计设备广播间隔 (&lt;35ms 触发高频告警)
                    </div>
                  </div>
                </div>

                <!-- 图 4: 协议层次 / SIG 厂商生态环形分布图 -->
                <div class="ui-sub-card p-3 space-y-1.5">
                  <div class="flex items-center justify-between text-[11px]">
                    <span class="font-bold" style="color: var(--text-primary)">
                      {{ btPieMode === 'protocol' ? '4. 真实协议分层占比 (HCI/L2CAP/ADV)' : '4. Bluetooth SIG 厂商生态占比' }}
                    </span>
                    <button
                      @click="btPieMode = btPieMode === 'protocol' ? 'vendor' : 'protocol'"
                      class="text-[10px] px-2 py-0.5 rounded border ui-btn-secondary cursor-pointer"
                    >
                      切换至 {{ btPieMode === 'protocol' ? 'SIG 厂商' : '协议分层' }}
                    </button>
                  </div>
                  <div class="h-48 w-full relative">
                    <VChart
                      v-if="btData.devices.length > 0 || (btData.recent_frames || []).length > 0"
                      :option="btProtocolVendorOption"
                      autoresize
                      class="w-full h-full"
                    />
                    <div v-else class="w-full h-full flex items-center justify-center text-[11px]" style="color: var(--text-muted)">
                      暂无分片流量样本
                    </div>
                  </div>
                  <div class="text-[10px]" style="color: var(--text-muted)">
                    注: Windows 通用蓝牙适配器底层不向 OS 暴露物理 Ch37/38/39 广播信道号（需专用 RF 硬件如 nRF Sniffer）。
                  </div>
                </div>
              </div>
            </div>
          </div>

          <!-- 实时 vs 历史基线偏差审计明细面板 -->
          <div v-if="btComparison && btComparison.has_baseline" class="ui-content-card p-5 space-y-3">
            <div class="flex items-center justify-between flex-wrap gap-2">
              <h4 class="text-xs font-bold flex items-center gap-2" style="color: var(--text-primary)">
                <AppIcon name="shield" :size="14" />
                <span>蓝牙实时环境 vs 历史基线差异审计面板</span>
                <span v-if="btComparison.baseline_saved_at" class="text-[11px] font-normal ui-num" style="color: var(--text-muted)">基线时间: {{ btComparison.baseline_saved_at }}</span>
              </h4>
              <div class="flex items-center gap-2 text-[11px] ui-num">
                <span class="px-2 py-0.5 rounded bg-rose-500/12 text-rose-700 dark:text-rose-300 font-bold">新增陌生: {{ btComparison.new_device_count }}</span>
                <span class="px-2 py-0.5 rounded bg-amber-500/12 text-amber-700 dark:text-amber-300 font-bold">基线失联: {{ btComparison.missing_device_count }}</span>
                <span class="px-2 py-0.5 rounded bg-indigo-500/12 text-indigo-700 dark:text-indigo-300 font-bold">场强漂移: {{ btComparison.drifted_device_count }}</span>
                <span class="px-2 py-0.5 rounded bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 font-bold">一致稳定: {{ btComparison.stable_device_count }}</span>
              </div>
            </div>
            <div class="text-[11px] ui-num px-3 py-1.5 rounded-lg border bg-[var(--surface-glass-pill)] flex items-center justify-between flex-wrap gap-2" style="border-color: var(--border-subtle); color: var(--text-secondary)">
              <span>{{ btComparison.diagnostic_message }}</span>
              <span>已扫历史存档 {{ btComparison.history_records_scanned }} 条<template v-if="btComparison.corrupted_history_lines > 0"> (已安全跳过异常行 {{ btComparison.corrupted_history_lines }})</template></span>
            </div>
            <div v-if="btComparison.drift_items.length > 0" class="max-h-56 overflow-y-auto overflow-x-auto border rounded-xl select-text" style="border-color: var(--border-subtle)">
              <table class="w-full text-left border-collapse text-[11px] ui-num">
                <thead class="ui-table-head text-[10px] uppercase sticky top-0">
                  <tr>
                    <th class="py-1.5 px-2.5">偏差状态</th>
                    <th class="py-1.5 px-2.5">设备 / BD_ADDR</th>
                    <th class="py-1.5 px-2.5">基线 RSSI → 实时 RSSI (Δ)</th>
                    <th class="py-1.5 px-2.5">测距变化</th>
                    <th class="py-1.5 px-2.5">审计摘要</th>
                  </tr>
                </thead>
                <tbody class="divide-y" style="border-color: var(--border-subtle); color: var(--text-secondary)">
                  <tr v-for="item in btComparison.drift_items.slice(0, 40)" :key="item.status + item.address">
                    <td class="py-1.5 px-2.5 whitespace-nowrap">
                      <span
                        class="px-1.5 py-0.5 rounded text-[10px] font-bold border"
                        :class="item.status === 'NEW_UNKNOWN' ? 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-500/30'
                          : item.status === 'MISSING' ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30'
                          : item.status === 'DRIFTED' ? 'bg-indigo-500/15 text-indigo-700 dark:text-indigo-300 border-indigo-500/30'
                          : 'bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 border-emerald-500/25'"
                      >
                        {{ item.status === 'NEW_UNKNOWN' ? '新增陌生' : item.status === 'MISSING' ? '基线失联' : item.status === 'DRIFTED' ? '显著漂移' : '一致稳定' }}
                      </span>
                    </td>
                    <td class="py-1.5 px-2.5">
                      <span class="font-semibold" style="color: var(--text-primary)">{{ item.device_name }}</span>
                      <span class="font-mono ml-1.5 opacity-80">{{ item.address }}</span>
                    </td>
                    <td class="py-1.5 px-2.5 whitespace-nowrap">
                      {{ item.baseline_rssi_dbm !== null ? item.baseline_rssi_dbm + ' dBm' : '-' }} →
                      {{ item.realtime_rssi_dbm !== null ? item.realtime_rssi_dbm + ' dBm' : '-' }}
                      <span v-if="item.rssi_delta_db !== null" class="font-bold ml-1">({{ item.rssi_delta_db > 0 ? '+' : '' }}{{ item.rssi_delta_db }} dB)</span>
                    </td>
                    <td class="py-1.5 px-2.5 whitespace-nowrap">
                      {{ item.baseline_distance_m !== null ? item.baseline_distance_m + 'm' : '-' }} → {{ item.realtime_distance_m !== null ? item.realtime_distance_m + 'm' : '-' }}
                    </td>
                    <td class="py-1.5 px-2.5">{{ item.note }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <!-- 蓝牙/BLE 设备深度解析雷达与单设备 AD TLV 下钻透视台 -->
          <div class="ui-content-card p-5 space-y-3">
            <div class="flex items-center justify-between flex-wrap gap-2">
              <h4 class="text-xs font-bold flex items-center gap-2 flex-wrap" style="color: var(--text-primary)">
                <AppIcon name="radar" :size="14" />
                <span>蓝牙/BLE 物理指纹、广播周期、Beacon 解码与安全评估表</span>
                <span class="text-[11px] ui-num font-normal" style="color: var(--text-muted)">已过滤显示 {{ filteredBtDevices.length }} / {{ btData.devices.length }} 台</span>
              </h4>
              <div class="flex items-center gap-2 flex-wrap text-[11px]">
                <input v-model="btSearchQuery" placeholder="搜名称 / MAC / 厂商 / iBeacon" class="ui-input w-44 px-2 py-1 text-xs" />
                <select v-model.number="btMinRssi" class="ui-input w-28 px-1.5 py-1 text-xs ui-num">
                  <option :value="-120">全部 RSSI</option>
                  <option :value="-85">&ge; -85 dBm</option>
                  <option :value="-70">&ge; -70 dBm (近)</option>
                  <option :value="-55">&ge; -55 dBm (极近)</option>
                </select>
                <label class="flex items-center gap-1 cursor-pointer" style="color: var(--text-secondary)">
                  <input type="checkbox" v-model="btOnlyConnectable" class="accent-sky-500" />
                  <span>仅可连接</span>
                </label>
              </div>
            </div>

            <div class="overflow-x-auto select-text">
              <table class="w-full text-left border-collapse">
                <thead class="ui-table-head text-[11px] font-semibold uppercase tracking-wider">
                  <tr>
                    <th class="py-2.5 px-2.5">设备 / SIG 厂商</th>
                    <th class="py-2.5 px-2.5">BD_ADDR · PHY</th>
                    <th class="py-2.5 px-2.5">RSSI (Min~Max)</th>
                    <th class="py-2.5 px-2.5">估算距离</th>
                    <th class="py-2.5 px-2.5">广播周期 / 收包率</th>
                    <th class="py-2.5 px-2.5">深度载荷 / Beacon 解码</th>
                    <th class="py-2.5 px-2.5">安全态势评估</th>
                    <th class="py-2.5 px-2.5 text-right">深度操作</th>
                  </tr>
                </thead>
                <tbody class="divide-y text-xs ui-num" style="border-color: var(--border-subtle); color: var(--text-secondary)">
                  <tr
                    v-for="dev in filteredBtDevices"
                    :key="dev.address"
                    @click="selectedBtAddress = dev.address"
                    class="hover:bg-black/5 dark:hover:bg-white/5 transition-colors cursor-pointer"
                    :class="selectedBtAddress === dev.address ? 'bg-sky-500/8' : ''"
                  >
                    <td class="py-2.5 px-2.5">
                      <div class="font-bold flex items-center gap-1.5" style="color: var(--text-primary)">
                        <span class="w-2 h-2 rounded-full shrink-0" :class="dev.is_connectable ? 'bg-emerald-500' : 'bg-blue-500'"></span>
                        <span>{{ dev.device_name }}</span>
                      </div>
                      <div class="text-[10px] mt-0.5" style="color: var(--text-muted)">
                        {{ dev.vendor_info }}<template v-if="dev.company_id"> (0x{{ dev.company_id.toString(16).padStart(4, '0').toUpperCase() }})</template>
                        <template v-if="dev.appearance_desc"> · {{ dev.appearance_desc }}</template>
                      </div>
                    </td>
                    <td class="py-2.5 px-2.5">
                      <div class="font-mono">{{ dev.address }}</div>
                      <div class="text-[10px] flex items-center gap-1 mt-0.5">
                        <span class="px-1.5 py-0.2 rounded border" :class="dev.address_type.includes('Public') ? 'bg-sky-500/12 text-sky-700 dark:text-sky-300 border-sky-500/25' : 'ui-pill'">{{ dev.address_type.split(' ')[0] }}</span>
                        <span class="px-1.5 py-0.2 rounded bg-indigo-500/12 text-indigo-700 dark:text-indigo-300">{{ dev.phy_desc || 'LE 1M' }}</span>
                      </div>
                    </td>
                    <td class="py-2.5 px-2.5">
                      <div class="font-bold" :class="getRssiColorClass(dev.last_rssi_dbm)">{{ dev.last_rssi_dbm }} dBm</div>
                      <div class="text-[10px]" style="color: var(--text-muted)">
                        {{ dev.min_rssi_dbm ?? dev.last_rssi_dbm }}..{{ dev.max_rssi_dbm ?? dev.last_rssi_dbm }} · σ={{ (dev.rssi_stddev ?? 0).toFixed(1) }} dB · 稳态 {{ (dev.stability_score ?? 100).toFixed(0) }}%
                      </div>
                    </td>
                    <td class="py-2.5 px-2.5">
                      <span class="font-bold text-indigo-700 dark:text-indigo-400">≈ {{ dev.estimated_distance_m }} m</span>
                      <div class="text-[10px] mt-0.5" style="color: var(--text-muted)">{{ getDistanceZone(dev.estimated_distance_m) }}</div>
                    </td>
                    <td class="py-2.5 px-2.5">
                      <div>{{ dev.adv_interval_ms ? dev.adv_interval_ms.toFixed(0) + ' ms' : '单次快照' }}</div>
                      <div class="text-[10px]" style="color: var(--text-muted)">
                        {{ dev.packet_count }} 帧<template v-if="dev.packet_rate_pps"> · {{ dev.packet_rate_pps.toFixed(1) }} pps</template>
                      </div>
                    </td>
                    <td class="py-2.5 px-2.5 max-w-[230px]">
                      <div v-if="dev.beacon_summary" class="text-[11px] font-semibold text-purple-700 dark:text-purple-300 truncate" :title="dev.beacon_summary">{{ dev.beacon_summary }}</div>
                      <div class="text-[10px] truncate" style="color: var(--text-muted)" :title="dev.service_uuids.join(', ')">
                        {{ dev.service_uuids.join(', ') || (dev.ad_sections?.length ? `${dev.ad_sections.length} 段 AD TLV` : '无公开 UUID') }}
                      </div>
                    </td>
                    <td class="py-2.5 px-2.5">
                      <div v-if="dev.security_flags.length === 0" class="text-emerald-700 dark:text-emerald-400 text-[11px] flex items-center gap-1">
                        <AppIcon name="check" :size="12" />
                        <span>无异常告警</span>
                      </div>
                      <div v-else class="flex flex-wrap gap-1">
                        <span
                          v-for="flag in dev.security_flags"
                          :key="flag"
                          class="px-1.5 py-0.5 rounded text-[10px] font-bold border"
                          :class="flag.includes('FLOOD') || flag.includes('UNENCRYPTED') || flag.includes('SMP_') ? 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-500/35' : 'bg-amber-500/12 text-amber-700 dark:text-amber-300 border-amber-500/30'"
                        >
                          {{ flag }}
                        </span>
                      </div>
                    </td>
                    <td class="py-2.5 px-2.5 text-right" @click.stop>
                      <div class="inline-flex items-center gap-1">
                        <button @click="selectedBtAddress = selectedBtAddress === dev.address ? null : dev.address"
                          class="px-2 py-0.5 rounded bg-indigo-500/12 hover:bg-indigo-500/20 text-indigo-700 dark:text-indigo-300 border border-indigo-500/25 text-[10px] font-semibold cursor-pointer">
                          {{ selectedBtAddress === dev.address ? '收起' : '透视' }}
                        </button>
                        <button @click="runBleGattAudit(dev.address)" :disabled="auditingGattAddr === dev.address"
                          class="px-2 py-0.5 rounded bg-sky-500/12 hover:bg-sky-500/20 text-sky-700 dark:text-sky-300 border border-sky-500/25 text-[10px] font-semibold cursor-pointer disabled:opacity-50">
                          {{ auditingGattAddr === dev.address ? '探测中' : 'GATT 审计' }}
                        </button>
                        <button @click="addBleDeviceToDiffQueue(dev)"
                          class="px-2 py-0.5 rounded bg-emerald-500/12 hover:bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border border-emerald-500/25 text-[10px] font-semibold cursor-pointer">
                          + 入队
                        </button>
                      </div>
                    </td>
                  </tr>

                  <tr v-if="filteredBtDevices.length === 0">
                    <td colspan="8" class="py-8">
                      <EmptyState icon="radar" title="未检测到符合条件的蓝牙资产" description="可点击「开启实时空口监听」或「BLE+经典双模扫描」实时探测周边蓝牙广播与已配对主机，亦可载入样本验证解构引擎。">
                        <template #actions>
                          <button @click="activeTab = 'workbench'; loadSample('bluetooth')" class="ui-btn-secondary px-3 py-1 text-xs">
                            <AppIcon name="zap" :size="12" />
                            <span>载入 BLE Advertising 样本解码测试</span>
                          </button>
                        </template>
                      </EmptyState>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>

            <!-- 选中设备的 AD Structure TLV 分段逐字节二进制透视下钻卡片 -->
            <div v-if="selectedBtDevice" class="mt-3 pt-3 border-t space-y-2.5 text-xs select-text" style="border-color: var(--border-subtle)">
              <div class="flex items-center justify-between flex-wrap gap-2">
                <div class="font-bold flex items-center gap-2 ui-num" style="color: var(--text-primary)">
                  <span>设备深钻透视: {{ selectedBtDevice.device_name }} ({{ selectedBtDevice.address }})</span>
                  <span v-if="selectedBtDevice.beacon_summary" class="px-2 py-0.5 rounded bg-purple-500/15 text-purple-700 dark:text-purple-300 text-[10px]">
                    {{ selectedBtDevice.beacon_summary }}
                  </span>
                </div>
                <div class="flex items-center gap-2">
                  <button v-if="selectedBtDevice.raw_frame_hex" @click="sendHexToWorkbench(selectedBtDevice.raw_frame_hex)"
                    class="ui-btn-secondary px-2.5 py-0.5 text-[11px]">
                    在解剖台逐字节拆解此帧 →
                  </button>
                  <button @click="selectedBtAddress = null" class="text-[11px] underline cursor-pointer" style="color: var(--text-muted)">关闭透视</button>
                </div>
              </div>
              <div v-if="(selectedBtDevice.ad_sections || []).length > 0" class="grid grid-cols-1 md:grid-cols-2 gap-2">
                <div v-for="(sec, idx) in selectedBtDevice.ad_sections" :key="idx" class="ui-sub-card p-2 text-[11px] ui-num space-y-1">
                  <div class="flex items-center justify-between font-semibold" style="color: var(--text-primary)">
                    <span>AD 0x{{ sec.ad_type.toString(16).padStart(2, '0').toUpperCase() }} · {{ sec.ad_type_name }}</span>
                    <span class="text-purple-600 dark:text-purple-300 text-[10px]">{{ sec.decoded_summary }}</span>
                  </div>
                  <div class="font-mono text-[10px] break-all" style="color: var(--text-muted)">HEX: {{ sec.data_hex || '(Empty)' }}</div>
                </div>
              </div>
              <div v-else class="text-[11px]" style="color: var(--text-muted)">该条目暂未记录扩展 AD DataSections（可能为被动仅地址响应帧）。</div>
            </div>

            <!-- WinRT BLE GATT 服务与特征只读安全穿透结果 (含读值展示) -->
            <div v-if="gattAudit" class="mt-3 pt-3 border-t space-y-2.5 text-xs select-text" style="border-color: var(--border-subtle)">
              <div class="flex items-center justify-between flex-wrap gap-2">
                <span class="font-bold flex items-center gap-2 ui-num" style="color: var(--text-primary)">
                  <span>BLE GATT 服务安全审计与特征读值 · {{ gattAudit.device_name || gattAudit.target_address }}</span>
                  <span v-if="gattAudit.unauthenticated_write_count > 0" class="px-2 py-0.5 rounded bg-rose-500/15 text-rose-600 dark:text-rose-300 border border-rose-500/30 text-[10px]">
                    无鉴权可写风险: {{ gattAudit.unauthenticated_write_count }}
                  </span>
                </span>
                <button @click="gattAudit = null" class="text-[11px] underline cursor-pointer" style="color: var(--text-muted)">收起</button>
              </div>
              <div class="text-[11px] ui-num px-2.5 py-1.5 rounded border bg-[var(--surface-glass-pill)]" style="border-color: var(--border-subtle); color: var(--text-secondary)">
                {{ gattAudit.diagnostic_message }}
              </div>
              <div v-if="gattAudit.services.length > 0" class="grid grid-cols-1 md:grid-cols-2 gap-2">
                <div v-for="(svc, svcIdx) in gattAudit.services" :key="svc.uuid + '-' + svc.handle" class="ui-sub-card p-2.5 space-y-1.5 text-[11px] ui-num">
                  <div class="font-bold flex items-center justify-between" style="color: var(--text-primary)">
                    <span>{{ svc.uuid }} · {{ svc.service_name }}</span>
                    <span class="text-[10px]" style="color: var(--text-muted)">H=0x{{ svc.handle.toString(16).toUpperCase() }}</span>
                  </div>
                  <div v-for="(chr, chrIdx) in svc.characteristics" :key="chr.uuid + '-' + chr.handle" class="space-y-0.5 pl-2 border-l-2" :class="chr.security_warning ? 'border-rose-500 text-rose-600 dark:text-rose-300' : 'border-emerald-500/50'">
                    <div class="flex items-center justify-between gap-2">
                      <span class="font-mono truncate">{{ chr.uuid }} [{{ chr.properties }}]</span>
                      <div class="flex items-center gap-1.5 shrink-0">
                        <span class="text-[10px]">{{ chr.security_warning || chr.protection_level }}</span>
                        <button
                          v-if="chr.properties.includes('Read')"
                          @click="readBleGattCharacteristic(gattAudit.target_address, chr.uuid, svcIdx, chrIdx)"
                          :disabled="readingGattCharKey === `${svcIdx}:${chrIdx}`"
                          class="px-1.5 py-0.2 rounded bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30 text-[10px] font-semibold cursor-pointer disabled:opacity-50"
                        >
                          {{ readingGattCharKey === `${svcIdx}:${chrIdx}` ? '读取中...' : '实时读值' }}
                        </button>
                      </div>
                    </div>
                    <div v-if="chr.decoded_value || chr.raw_value_hex" class="text-[10px] text-emerald-700 dark:text-emerald-300 font-mono">
                      实读数值: {{ chr.decoded_value || '' }} <span v-if="chr.raw_value_hex" style="color: var(--text-muted)">[{{ chr.raw_value_hex }}]</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <!-- 点对点 HCI/ACL 会话重建、ATT MTU 协商与 Handle→UUID 自动学习字典表 -->
          <div class="ui-content-card p-5 space-y-2.5">
            <div class="flex items-center justify-between flex-wrap gap-2">
              <h4 class="text-xs font-bold flex items-center gap-2" style="color: var(--text-primary)">
                <AppIcon name="layers" :size="14" />
                <span>HCI / L2CAP / ATT / SMP 点对点会话状态重建 &amp; Handle 字典自动学习</span>
              </h4>
              <span class="text-[11px] ui-num" style="color: var(--text-muted)">活跃会话句柄: {{ (btData.active_sessions || []).length }}</span>
            </div>
            <div v-if="(btData.active_sessions || []).length > 0" class="grid grid-cols-1 md:grid-cols-2 gap-2.5 select-text">
              <div v-for="sess in btData.active_sessions" :key="sess.conn_handle" class="ui-sub-card p-3 space-y-1.5 text-[11px] ui-num">
                <div class="flex items-center justify-between gap-2">
                  <span class="font-bold" style="color: var(--text-primary)">
                    Handle 0x{{ sess.conn_handle.toString(16).padStart(4, '0').toUpperCase() }} · {{ sess.peer_address }}
                  </span>
                  <span
                    class="px-1.5 py-0.5 rounded text-[10px] font-bold border"
                    :class="sess.encrypted ? 'bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 border-emerald-500/25' : 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30'"
                  >
                    {{ sess.encrypted ? '链路已加密' : '未见 EncryptionChange' }}
                  </span>
                </div>
                <div class="flex flex-wrap gap-2 text-[10px]" style="color: var(--text-secondary)">
                  <span>ATT MTU: <strong style="color: var(--text-primary)">{{ sess.negotiated_mtu }} B</strong></span>
                  <span>Read: {{ sess.att_reads }}</span>
                  <span>Write: {{ sess.att_writes }}</span>
                  <span>Notify: {{ sess.att_notifies }}</span>
                  <span>SMP: {{ sess.smp_events }}</span>
                  <span>更新: {{ sess.last_seen_timestamp }}</span>
                </div>
                <div v-if="sess.handle_uuid_map && sess.handle_uuid_map.length > 0" class="flex flex-wrap gap-1 pt-1">
                  <span
                    v-for="[hdl, uuidLabel] in sess.handle_uuid_map.slice(0, 12)"
                    :key="hdl"
                    class="px-1.5 py-0.5 rounded bg-indigo-500/12 text-indigo-700 dark:text-indigo-300 text-[10px] font-mono"
                  >
                    0x{{ hdl.toString(16).padStart(4, '0').toUpperCase() }} → {{ uuidLabel }}
                  </span>
                </div>
              </div>
            </div>
            <div v-else class="text-[11px] ui-num" style="color: var(--text-muted)">
              当前仅检测到广播无连接流量；开启「BTHPORT HCI 抓包」或点击「导入 .btsnoop 重放」含 ACL 会话文件后将自动重建 MTU、EncryptionChange 与 Handle→UUID 字典。
            </div>
          </div>

          <!-- 底层蓝牙 HCI / BLE-ADV / L2CAP-ATT / SMP 实时报文时间线瀑布 -->
          <div class="ui-content-card p-5 space-y-2.5">
            <div class="flex items-center justify-between flex-wrap gap-2">
              <h4 class="text-xs font-bold flex items-center gap-2" style="color: var(--text-primary)">
                <AppIcon name="terminal" :size="14" />
                <span>实时底层蓝牙报文流水 (WinRT 空口 / BTHPORT-ETW HCI / L2CAP-ATT / SMP)</span>
              </h4>
              <span class="text-[11px] ui-num" style="color: var(--text-muted)">留存最近 {{ (btData.recent_frames || []).length }} / 120 帧 · 点击任意帧一键逐字节拆解</span>
            </div>
            <div class="max-h-56 overflow-y-auto overflow-x-auto select-text border rounded-xl" style="border-color: var(--border-subtle)">
              <table class="w-full text-left border-collapse text-[11px] ui-num">
                <thead class="ui-table-head text-[10px] uppercase sticky top-0">
                  <tr>
                    <th class="py-1.5 px-2.5">时间</th>
                    <th class="py-1.5 px-2.5">通道 / 方向</th>
                    <th class="py-1.5 px-2.5">协议层</th>
                    <th class="py-1.5 px-2.5">地址</th>
                    <th class="py-1.5 px-2.5">长度</th>
                    <th class="py-1.5 px-2.5">语义摘要</th>
                    <th class="py-1.5 px-2.5 text-right">剖析</th>
                  </tr>
                </thead>
                <tbody class="divide-y" style="border-color: var(--border-subtle); color: var(--text-secondary)">
                  <tr v-for="fr in (btData.recent_frames || []).slice(0, 60)" :key="fr.id"
                    @click="fr.raw_hex && sendHexToWorkbench(fr.raw_hex)"
                    class="hover:bg-black/5 dark:hover:bg-white/5 cursor-pointer">
                    <td class="py-1.5 px-2.5 whitespace-nowrap">{{ fr.timestamp }}</td>
                    <td class="py-1.5 px-2.5 whitespace-nowrap">{{ fr.source }} · {{ fr.direction }}</td>
                    <td class="py-1.5 px-2.5 font-semibold" style="color: var(--text-primary)">{{ fr.protocol_layer }}</td>
                    <td class="py-1.5 px-2.5 font-mono">{{ fr.address }}</td>
                    <td class="py-1.5 px-2.5">{{ fr.length }} B</td>
                    <td class="py-1.5 px-2.5 max-w-xs truncate" :title="fr.summary">{{ fr.summary }}</td>
                    <td class="py-1.5 px-2.5 text-right">
                      <span v-if="fr.raw_hex" class="text-sky-600 dark:text-sky-400 underline">拆解</span>
                    </td>
                  </tr>
                  <tr v-if="!(btData.recent_frames && btData.recent_frames.length)">
                    <td colspan="7" class="py-5 text-center text-xs" style="color: var(--text-muted)">暂无实时蓝牙底层报文记录，可启动上方「开启实时空口监听」或「BTHPORT HCI 抓包」。</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <!-- ======================= 4. 报文深度解剖诊断工作台 ======================= -->
        <div v-if="activeTab === 'workbench'" class="space-y-5">
          <div class="ui-content-card p-5 space-y-4">
            <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h4 class="text-xs font-bold flex items-center gap-2" style="color: var(--text-primary)">
                  <AppIcon name="search" :size="14" />
                  <span>无线与 VLAN 原生十六进制解剖工作台</span>
                </h4>
                <p class="text-[11px] ui-num mt-0.5" style="color: var(--text-muted)">
                  输入包含 Radiotap / 802.11 / 802.1Q / Bluetooth HCI 的十六进制报文进行逐层深度解剖
                </p>
              </div>

              <div class="flex flex-wrap items-center gap-2">
                <span class="text-[11px]" style="color: var(--text-muted)">快速载入标准样本:</span>
                <button @click="loadSample('wifi')" class="px-2.5 py-1 rounded-xl text-[11px] font-semibold ui-pill text-sky-700 dark:text-sky-300 cursor-pointer">
                  Wi-Fi Beacon
                </button>
                <button @click="loadSample('vlan')" class="px-2.5 py-1 rounded-xl text-[11px] font-semibold ui-pill text-indigo-700 dark:text-indigo-300 cursor-pointer">
                  QinQ Double Tagging
                </button>
                <button @click="loadSample('bluetooth')" class="px-2.5 py-1 rounded-xl text-[11px] font-semibold ui-pill text-purple-700 dark:text-purple-300 cursor-pointer">
                  BLE Advertising
                </button>
              </div>
            </div>

            <div class="space-y-2.5">
              <textarea
                v-model="customHexInput"
                rows="4"
                placeholder="请在此粘贴 Hex 原始字符串（例如: 00 00 12 00 6C 00 00 00 6C 00 6C 09 A0 00 D3 A1 00 00...）"
                class="w-full ui-input font-mono-code text-xs p-3"
              ></textarea>
              <div class="flex items-center justify-between flex-wrap gap-2">
                <div class="flex items-center gap-3">
                  <label class="text-xs font-semibold" style="color: var(--text-secondary)">解剖模式:</label>
                  <select v-model="dissectMode" class="ui-input w-auto px-3 py-1 text-xs ui-num cursor-pointer">
                    <option value="auto">自动探查 (Auto Detect)</option>
                    <option value="wifi">Wi-Fi (802.11 / Radiotap)</option>
                    <option value="vlan">VLAN (802.1Q / 802.1ad QinQ)</option>
                    <option value="bluetooth">蓝牙 (Bluetooth HCI / BLE)</option>
                  </select>
                </div>

                <button
                  @click="triggerDissect"
                  :disabled="!customHexInput.trim() || dissecting"
                  class="ui-btn-primary px-5 py-2 rounded-xl text-xs font-bold"
                >
                  <AppIcon name="zap" :size="13" />
                  <span>{{ dissecting ? '解剖分析中...' : '执行深度原生解剖' }}</span>
                </button>
              </div>
            </div>

            <div v-if="dissectionResult" class="ui-sub-card p-4 space-y-3 select-text">
              <div class="flex items-center justify-between border-b pb-2 flex-wrap gap-2" style="border-color: var(--border-subtle)">
                <div class="flex items-center gap-2">
                  <span class="w-2.5 h-2.5 rounded-full" :class="dissectionResult.success ? 'bg-emerald-500' : 'bg-rose-500'"></span>
                  <span class="text-xs font-bold" style="color: var(--text-primary)">
                    解剖定性: {{ dissectionResult.identified_protocol }}
                  </span>
                  <span class="text-[11px] ui-num px-2 py-0.5 rounded ui-pill">
                    载荷大小: {{ dissectionResult.raw_bytes_count }} 字节
                  </span>
                </div>
                <div class="flex items-center gap-2 shrink-0">
                  <button @click="addDissectedFrameToDiffQueue"
                    class="px-2.5 py-0.5 rounded-lg bg-emerald-500/12 hover:bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border border-emerald-500/25 text-[11px] font-semibold cursor-pointer"
                    title="将原始十六进制帧与结构化解码字段加入全局多组比对队列">
                    + 加入多组比对队列
                  </button>
                  <div class="text-[11px] ui-num font-semibold" :class="dissectionResult.success ? 'text-emerald-700 dark:text-emerald-400' : 'text-rose-700 dark:text-rose-400'">
                    {{ dissectionResult.success ? '协议解剖成功' : '解析异常' }}
                  </div>
                </div>
              </div>

              <div v-if="dissectionResult.security_threats && dissectionResult.security_threats.length > 0" class="p-3 rounded-lg bg-rose-500/12 border border-rose-500/30 space-y-1">
                <div class="text-xs font-bold text-rose-700 dark:text-rose-300 flex items-center gap-1.5">
                  <AppIcon name="alert" :size="13" />
                  <span>触发的安全威胁与规约违规审计:</span>
                </div>
                <ul class="list-disc list-inside text-xs ui-num text-rose-700 dark:text-rose-300 space-y-0.5">
                  <li v-for="threat in dissectionResult.security_threats" :key="threat">
                    {{ threat }}
                  </li>
                </ul>
              </div>

              <div class="space-y-1">
                <div class="text-[11px] font-bold" style="color: var(--text-muted)">结构化元数据树 (Structured Syntax Details):</div>
                <pre class="p-3 rounded-lg ui-input font-mono-code text-xs text-emerald-700 dark:text-emerald-400 overflow-x-auto max-h-64 custom-scrollbar">{{ JSON.stringify(dissectionResult.structured_details, null, 2) }}</pre>
              </div>
            </div>
          </div>
        </div>

      </div>

      <!-- 底栏：状态与快捷操作 -->
      <footer class="px-6 py-3 border-t flex items-center justify-between text-xs ui-num shrink-0 flex-wrap gap-2" style="background: var(--surface-content-alt); border-color: var(--border-subtle); color: var(--text-muted)">
        <div class="flex items-center gap-4">
          <span class="flex items-center gap-1.5">
            <span class="w-2 h-2 rounded-full bg-emerald-500"></span>
            <span>引擎状态: 实时多协议物理层/链路层感知就绪</span>
          </span>
          <span class="hidden sm:inline" style="color: var(--border-strong)">|</span>
          <span class="hidden sm:inline">覆盖: 802.11 a/b/g/n/ac/ax/be · 802.1Q/ad · BLE HCI H4</span>
        </div>

        <div class="flex items-center gap-2">
          <button @click="resetTelemetry" class="ui-btn-danger text-xs px-3 py-1 rounded-lg">
            清空遥测历史
          </button>
          <button @click="$emit('close')" class="ui-btn-secondary text-xs px-4 py-1.5 rounded-xl font-bold">
            完成并关闭
          </button>
        </div>
      </footer>

    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import { use } from 'echarts/core';
import { CanvasRenderer } from 'echarts/renderers';
import { ScatterChart, LineChart, BarChart, PieChart } from 'echarts/charts';
import { PolarComponent, GridComponent, TooltipComponent, LegendComponent } from 'echarts/components';
import VChart from 'vue-echarts';
import AppIcon from './AppIcon.vue';
import EmptyState from './EmptyState.vue';
import { useUniversalDiff } from '../composables/useUniversalDiff';

use([
  CanvasRenderer,
  ScatterChart,
  LineChart,
  BarChart,
  PieChart,
  PolarComponent,
  GridComponent,
  TooltipComponent,
  LegendComponent,
]);

const diffBus = useUniversalDiff();

function addWifiApToDiffQueue(ap: WifiAP) {
  const summary = `SSID=${ap.ssid}|BSSID=${ap.bssid}|CH=${ap.channel}(${ap.band_desc})|RSSI=${ap.last_rssi_dbm}dBm|ENC=${ap.encryption_type}|BEACON=${ap.beacon_count}|DATA=${ap.data_packet_count}`;
  diffBus.addToQueue({
    id: `WIFI_${ap.bssid}`,
    label: `[Wi-Fi AP] ${ap.ssid || ap.bssid}`,
    timestamp: ap.last_seen_timestamp,
    protocol: '802.11-WIFI',
    src: ap.bssid,
    dst: `Ch-${ap.channel}`,
    format: 'ASCII',
    isRawText: true,
    payloadHex: '',
    rawText: summary,
    length: summary.length,
    extraFields: {
      ssid: ap.ssid,
      bssid: ap.bssid,
      channel: String(ap.channel),
      band: ap.band_desc,
      encryption: ap.encryption_type,
      vendor: ap.vendor_name,
      rssi_dbm: String(ap.last_rssi_dbm),
      alerts: ap.security_alerts.join(', ') || '合规'
    }
  }, `Wi-Fi ${ap.ssid || ap.bssid}`, false);
}

function addVlanToDiffQueue(stat: VlanStat) {
  const summary = `VID=${stat.vid}|QINQ=${stat.is_qinq}|OUTER=${stat.outer_vid ?? 'NONE'}|PKTS=${stat.packet_count}|BYTES=${stat.byte_count}|MACS=${stat.active_mac_count}`;
  diffBus.addToQueue({
    id: `VLAN_${stat.vid}_${stat.outer_vid ?? 0}`,
    label: `[VLAN ${stat.vid}] ${stat.is_qinq ? '802.1ad QinQ' : '802.1Q'}`,
    timestamp: stat.last_seen_timestamp,
    protocol: stat.is_qinq ? '802.1ad-QinQ' : '802.1Q-VLAN',
    src: `VID-${stat.vid}`,
    dst: stat.outer_vid !== null ? `Outer-${stat.outer_vid}` : 'Access/Trunk',
    format: 'ASCII',
    isRawText: true,
    payloadHex: '',
    rawText: summary,
    length: summary.length,
    extraFields: {
      vid: String(stat.vid),
      outer_vid: stat.outer_vid !== null ? String(stat.outer_vid) : '-',
      packets: String(stat.packet_count),
      bytes: String(stat.byte_count),
      sample_macs: stat.sample_macs.join(', ') || '-',
      flags: stat.security_flags.join(', ') || '合规'
    }
  }, `VLAN ${stat.vid}`, false);
}

function addBleDeviceToDiffQueue(dev: BluetoothDevice) {
  const summary = `NAME=${dev.device_name}|ADDR=${dev.address}(${dev.address_type})|RSSI=${dev.last_rssi_dbm}dBm|DIST=${dev.estimated_distance_m}m|UUIDS=[${dev.service_uuids.join(',')}]`;
  diffBus.addToQueue({
    id: `BLE_${dev.address}`,
    label: `[BLE] ${dev.device_name || dev.address}`,
    timestamp: dev.last_seen_timestamp,
    protocol: 'BLE-HCI',
    src: dev.address,
    dst: 'HCI-Host',
    format: 'ASCII',
    isRawText: true,
    payloadHex: '',
    rawText: summary,
    length: summary.length,
    extraFields: {
      address: dev.address,
      address_type: dev.address_type,
      vendor: dev.vendor_info || '-',
      rssi_dbm: String(dev.last_rssi_dbm),
      distance_m: String(dev.estimated_distance_m),
      service_uuids: dev.service_uuids.join(', ') || '-'
    }
  }, `BLE ${dev.device_name || dev.address}`, false);
}

function addDissectedFrameToDiffQueue() {
  if (!dissectionResult.value) return;
  const cleanHex = customHexInput.value.replace(/[\s\r\n\t]/g, '');
  diffBus.addToQueue({
    id: `WLS_FRAME_${Date.now()}`,
    label: `[无线/链路帧] ${dissectionResult.value.identified_protocol}`,
    protocol: dissectionResult.value.identified_protocol || 'WIRELESS-FRAME',
    src: 'Monitor-Interface',
    dst: 'Dissector',
    payloadHex: cleanHex,
    rawText: cleanHex ? '' : JSON.stringify(dissectionResult.value.structured_details),
    length: cleanHex ? cleanHex.length / 2 : dissectionResult.value.raw_bytes_count,
    extraFields: dissectionResult.value.structured_details || {}
  }, `无线帧 ${dissectionResult.value.identified_protocol}`, false);
}

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
  { id: 'wifi', label: 'Wi-Fi 频谱与 AP 资产', icon: 'wifi' },
  { id: 'vlan', label: 'VLAN 拓扑与隔离审计', icon: 'globe' },
  { id: 'bluetooth', label: '蓝牙近场空间感知', icon: 'radar' },
  { id: 'workbench', label: '单帧深度解剖诊断', icon: 'search' },
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

interface RssiSample {
  timestamp: string;
  rssi_dbm: number;
  address?: string;
  distance_m?: number;
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
  rssi_history?: RssiSample[];
}

interface NativeWifiScanResult {
  native_scan_available: boolean;
  platform: string;
  reason_code: string;
  status_message: string;
  scanned_ap_count: number;
  interface_name: string;
  aps: WifiAP[];
  summary: WifiTelemetry;
}

interface NativeBluetoothScanResult {
  native_scan_available: boolean;
  platform: string;
  inquiry_executed: boolean;
  ble_adv_count?: number;
  adapters: Array<{
    name: string;
    address: string;
    class_of_device: string;
    manufacturer_id: number;
    lmp_subversion: number;
  }>;
  devices: Array<{
    name: string;
    address: string;
    class_of_device: string;
    connected: boolean;
    remembered: boolean;
    authenticated: boolean;
    last_seen: string;
    last_used: string;
  }>;
  diagnostic_message: string;
  summary?: BluetoothTelemetry;
}

interface BleGattCharacteristicInfo {
  uuid: string;
  handle: number;
  properties: string;
  protection_level: string;
  security_warning: string | null;
  raw_value_hex?: string | null;
  decoded_value?: string | null;
}

interface BleGattServiceInfo {
  uuid: string;
  service_name: string;
  handle: number;
  characteristics: BleGattCharacteristicInfo[];
}

interface BleGattAuditResult {
  target_address: string;
  connected: boolean;
  device_name: string | null;
  services: BleGattServiceInfo[];
  unauthenticated_write_count: number;
  diagnostic_message: string;
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
interface BleAdSectionItem {
  ad_type: number;
  ad_type_name: string;
  data_hex: string;
  decoded_summary: string;
}

interface BluetoothFrameLogItem {
  id: number;
  timestamp: string;
  source: string;
  direction: string;
  protocol_layer: string;
  address: string;
  rssi_dbm: number | null;
  length: number;
  summary: string;
  raw_hex: string;
}

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
  min_rssi_dbm?: number;
  max_rssi_dbm?: number;
  phy_desc?: string;
  company_id?: number | null;
  appearance_desc?: string | null;
  beacon_summary?: string | null;
  adv_interval_ms?: number | null;
  packet_rate_pps?: number;
  ad_sections?: BleAdSectionItem[];
  manufacturer_data_hex?: string | null;
  raw_frame_hex?: string;
  rssi_stddev?: number;
  stability_score?: number;
}

interface BluetoothConnectionSession {
  conn_handle: number;
  peer_address: string;
  negotiated_mtu: number;
  att_reads: number;
  att_writes: number;
  att_notifies: number;
  smp_events: number;
  encrypted: boolean;
  handle_uuid_map: Array<[number, string]>;
  last_seen_timestamp: string;
}

interface BluetoothTelemetry {
  total_packets: number;
  advertising_packets: number;
  acl_data_packets: number;
  unencrypted_att_count: number;
  active_device_count: number;
  devices: BluetoothDevice[];
  rssi_history?: RssiSample[];
  hci_command_packets?: number;
  hci_event_packets?: number;
  continuous_ble_active?: boolean;
  bthport_etw_active?: boolean;
  bthport_etw_status?: string;
  recent_frames?: BluetoothFrameLogItem[];
  active_sessions?: BluetoothConnectionSession[];
}

interface BluetoothBaselineItem {
  address: string;
  device_name: string;
  vendor_info: string;
  address_type: string;
  baseline_rssi_dbm: number;
  baseline_distance_m: number;
  baseline_adv_interval_ms: number | null;
  phy_desc: string;
}

interface BluetoothBaselineSnapshot {
  saved_at: string;
  saved_epoch_ms: number;
  device_count: number;
  items: BluetoothBaselineItem[];
}

interface BluetoothDeviceDriftItem {
  address: string;
  device_name: string;
  vendor_info: string;
  status: 'NEW_UNKNOWN' | 'MISSING' | 'DRIFTED' | 'STABLE' | string;
  baseline_rssi_dbm: number | null;
  realtime_rssi_dbm: number | null;
  rssi_delta_db: number | null;
  baseline_distance_m: number | null;
  realtime_distance_m: number | null;
  adv_interval_delta_ms: number | null;
  security_flags: string[];
  note: string;
}

interface BluetoothTrendBucket {
  time_label: string;
  historical_avg_rssi: number | null;
  historical_device_count: number;
  realtime_avg_rssi: number | null;
  realtime_device_count: number;
}

interface BluetoothBaselineComparisonResult {
  has_baseline: boolean;
  baseline_saved_at: string | null;
  history_records_scanned: number;
  corrupted_history_lines: number;
  realtime_device_count: number;
  baseline_device_count: number;
  new_device_count: number;
  missing_device_count: number;
  drifted_device_count: number;
  stable_device_count: number;
  realtime_mean_rssi_dbm: number;
  historical_mean_rssi_dbm: number;
  drift_items: BluetoothDeviceDriftItem[];
  trend_buckets: BluetoothTrendBucket[];
  diagnostic_message: string;
}

interface BtsnoopExportResult {
  saved: boolean;
  cancelled: boolean;
  path: string | null;
  packet_count: number;
  bytes_written: number;
  message: string;
}

interface BtsnoopImportResult {
  cancelled: boolean;
  file_path: string | null;
  datalink_type: number;
  imported_packets: number;
  skipped_records: number;
  adv_packets: number;
  acl_packets: number;
  cmd_packets: number;
  evt_packets: number;
  summary: BluetoothTelemetry;
  diagnostic_message: string;
}

interface BleGattCharacteristicReadResult {
  target_address: string;
  characteristic_uuid: string;
  success: boolean;
  raw_value_hex: string | null;
  decoded_value: string | null;
  diagnostic_message: string;
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
  rssi_history: [],
});

const nativeWifiScan = ref<NativeWifiScanResult | null>(null);
const scanningNativeWifi = ref(false);
const nativeBtScan = ref<NativeBluetoothScanResult | null>(null);
const scanningNativeBt = ref(false);
const btInquiryMode = ref(false);
const continuousBleActive = ref(false);
const bthEtwActive = ref(false);
const bthEtwMsg = ref('');
const btSearchQuery = ref('');
const btOnlyConnectable = ref(false);
const btMinRssi = ref(-120);
const selectedBtAddress = ref<string | null>(null);

const selectedBtDevice = computed(() => {
  if (!selectedBtAddress.value) return null;
  return btData.value.devices.find(d => d.address === selectedBtAddress.value) || null;
});

const filteredBtDevices = computed(() => {
  const q = btSearchQuery.value.trim().toLowerCase();
  return btData.value.devices.filter(d => {
    if (btOnlyConnectable.value && !d.is_connectable) return false;
    if (d.last_rssi_dbm < btMinRssi.value) return false;
    if (!q) return true;
    const text = [
      d.device_name,
      d.address,
      d.vendor_info,
      d.beacon_summary || '',
      d.appearance_desc || '',
      d.service_uuids.join(' '),
    ]
      .join(' ')
      .toLowerCase();
    return text.includes(q);
  });
});

const activeBtRssiSamples = computed(() => {
  const all = btData.value.rssi_history || [];
  if (!selectedBtAddress.value) return all;
  return all.filter(s => s.address === selectedBtAddress.value);
});

function buildRssiPolyline(samples: RssiSample[] | undefined, width: number, height: number): string {
  const arr = samples || [];
  if (arr.length < 2) return '';
  const stepX = width / Math.max(1, arr.length - 1);
  return arr
    .map((s, idx) => {
      const clamped = Math.max(-100, Math.min(-25, s.rssi_dbm));
      const norm = (clamped - (-100)) / 75;
      const y = height - 8 - norm * (height - 16);
      const x = idx * stepX;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(' ');
}

const wifiRssiPolyline = computed(() => buildRssiPolyline(wifiData.value.rssi_history, 760, 90));

const isDarkTheme = ref(
  typeof document !== 'undefined' ? !document.documentElement.classList.contains('theme-apple-light') : true
);
const btToolBusy = ref(false);
const btToolMsg = ref('');
const btComparison = ref<BluetoothBaselineComparisonResult | null>(null);
const btPieMode = ref<'protocol' | 'vendor'>('protocol');
const readingGattCharKey = ref<string | null>(null);

function macToDeterministicAngle(mac: string): number {
  const clean = mac.replace(/[^0-9A-Fa-f]/g, '');
  if (clean.length < 4) return 45;
  const tail = Number.parseInt(clean.slice(-4), 16);
  if (Number.isNaN(tail)) return 45;
  return Number(((tail % 3600) / 10).toFixed(1));
}

const btChartThemeTokens = computed(() => {
  const dark = isDarkTheme.value;
  return {
    textPrimary: dark ? '#e2e8f0' : '#0f172a',
    textMuted: dark ? '#94a3b8' : '#64748b',
    splitLine: dark ? 'rgba(148, 163, 184, 0.14)' : 'rgba(15, 23, 42, 0.10)',
    tooltipBg: dark ? 'rgba(15, 23, 42, 0.94)' : 'rgba(255, 255, 255, 0.96)',
    tooltipBorder: dark ? 'rgba(148, 163, 184, 0.28)' : 'rgba(15, 23, 42, 0.15)',
  };
});

interface PolarRadarPoint {
  value: [number, number];
  symbolSize: number;
  name: string;
  address: string;
  vendor: string;
  rssi: number;
  phy: string;
  packets: number;
  flags: string[];
  itemStyle: { color: string; shadowBlur: number; shadowColor: string };
}

const btPolarRadarOption = computed(() => {
  const t = btChartThemeTokens.value;
  const devs = filteredBtDevices.value.slice(0, 64);
  const maxDist = Math.max(
    6,
    Math.ceil(devs.reduce((acc, d) => Math.max(acc, Math.min(20, d.estimated_distance_m || 1)), 4))
  );
  const data: PolarRadarPoint[] = devs.map((d) => {
    const dist = Number(Math.min(maxDist, Math.max(0.2, d.estimated_distance_m || 1)).toFixed(2));
    const angle = macToDeterministicAngle(d.address);
    const hasHighAlert = d.security_flags.some(
      (f) => f.includes('FLOOD') || f.includes('UNENCRYPTED') || f.includes('SMP_') || f.includes('FINDMY')
    );
    const color = hasHighAlert ? '#f43f5e' : d.is_connectable ? '#10b981' : '#38bdf8';
    return {
      value: [dist, angle],
      symbolSize: Math.max(10, Math.min(24, 9 + Math.log2((d.packet_count || 1) + 1) * 3)),
      name: d.device_name || d.address,
      address: d.address,
      vendor: d.vendor_info,
      rssi: d.last_rssi_dbm,
      phy: d.phy_desc || 'LE 1M',
      packets: d.packet_count,
      flags: d.security_flags,
      itemStyle: { color, shadowBlur: 8, shadowColor: color },
    };
  });

  return {
    backgroundColor: 'transparent',
    tooltip: {
      trigger: 'item',
      backgroundColor: t.tooltipBg,
      borderColor: t.tooltipBorder,
      textStyle: { color: t.textPrimary, fontSize: 11 },
      formatter: (params: { data?: PolarRadarPoint }) => {
        const p = params.data;
        if (!p) return '';
        const alerts = p.flags.length ? p.flags.join(', ') : '未触发安全告警';
        return `<div style="font-weight:700;margin-bottom:3px">${p.name}</div>
          <div style="font-family:monospace">MAC: ${p.address}</div>
          <div>厂商: ${p.vendor} · ${p.phy}</div>
          <div>测距: <b>${p.value[0]} m</b> · RSSI: <b>${p.rssi} dBm</b> · 包数: ${p.packets}</div>
          <div style="color:${p.flags.length ? '#fb7185' : '#34d399'};margin-top:2px">${alerts}</div>`;
      },
    },
    polar: { radius: '74%', center: ['50%', '52%'] },
    angleAxis: {
      type: 'value',
      startAngle: 90,
      min: 0,
      max: 360,
      interval: 45,
      axisLine: { lineStyle: { color: t.splitLine } },
      axisLabel: { color: t.textMuted, fontSize: 9, formatter: '{value}°' },
      splitLine: { lineStyle: { color: t.splitLine } },
    },
    radiusAxis: {
      min: 0,
      max: maxDist,
      splitNumber: 4,
      axisLine: { show: false },
      axisLabel: { color: t.textMuted, fontSize: 9, formatter: '{value}m' },
      splitLine: { lineStyle: { color: t.splitLine, type: 'dashed' } },
    },
    series: [
      {
        type: 'scatter',
        coordinateSystem: 'polar',
        data,
        emphasis: { scale: 1.28 },
      },
    ],
  };
});

const btRealtimeVsHistoryOption = computed(() => {
  const t = btChartThemeTokens.value;
  const cmp = btComparison.value;
  const locked = selectedBtAddress.value;

  if (!locked && cmp && cmp.trend_buckets.length >= 2) {
    const labels = cmp.trend_buckets.map((b) => b.time_label);
    const rtSeries = cmp.trend_buckets.map((b) => b.realtime_avg_rssi);
    const histSeries = cmp.trend_buckets.map((b) => b.historical_avg_rssi);
    return {
      backgroundColor: 'transparent',
      tooltip: {
        trigger: 'axis',
        backgroundColor: t.tooltipBg,
        borderColor: t.tooltipBorder,
        textStyle: { color: t.textPrimary, fontSize: 11 },
      },
      legend: {
        top: 0,
        textStyle: { color: t.textMuted, fontSize: 10 },
        data: ['实时 RSSI 均值 (dBm)', '历史基线 RSSI (dBm)'],
      },
      grid: { left: 42, right: 16, top: 28, bottom: 24 },
      xAxis: {
        type: 'category',
        data: labels,
        axisLabel: { color: t.textMuted, fontSize: 9 },
        axisLine: { lineStyle: { color: t.splitLine } },
      },
      yAxis: {
        type: 'value',
        min: -100,
        max: -25,
        axisLabel: { color: t.textMuted, fontSize: 9, formatter: '{value}' },
        splitLine: { lineStyle: { color: t.splitLine, type: 'dashed' } },
      },
      series: [
        {
          name: '实时 RSSI 均值 (dBm)',
          type: 'line',
          smooth: true,
          connectNulls: true,
          data: rtSeries,
          lineStyle: { width: 2.2, color: '#38bdf8' },
          itemStyle: { color: '#38bdf8' },
          areaStyle: { color: 'rgba(56, 189, 248, 0.14)' },
        },
        {
          name: '历史基线 RSSI (dBm)',
          type: 'line',
          smooth: true,
          connectNulls: true,
          data: histSeries,
          lineStyle: { width: 2, type: 'dashed', color: '#f59e0b' },
          itemStyle: { color: '#f59e0b' },
        },
      ],
    };
  }

  const samples = activeBtRssiSamples.value.slice(-80);
  const labels = samples.map((s) => s.timestamp.slice(0, 8));
  const values = samples.map((s) => s.rssi_dbm);
  const matchedDrift = locked && cmp ? cmp.drift_items.find((d) => d.address === locked) : undefined;
  const baselineVal = matchedDrift?.baseline_rssi_dbm ?? null;

  const seriesList: Array<Record<string, unknown>> = [
    {
      name: locked ? `${locked} 实时轨迹 (dBm)` : '实时全局场强波动 (dBm)',
      type: 'line',
      smooth: true,
      showSymbol: samples.length <= 24,
      data: values,
      lineStyle: { width: 2.2, color: '#a78bfa' },
      itemStyle: { color: '#a78bfa' },
      areaStyle: { color: 'rgba(167, 139, 250, 0.16)' },
    },
  ];
  if (baselineVal !== null && labels.length > 0) {
    seriesList.push({
      name: `该设备历史基准 (${baselineVal} dBm)`,
      type: 'line',
      showSymbol: false,
      data: labels.map(() => baselineVal),
      lineStyle: { width: 1.8, type: 'dashed', color: '#f59e0b' },
      itemStyle: { color: '#f59e0b' },
    });
  }

  return {
    backgroundColor: 'transparent',
    tooltip: {
      trigger: 'axis',
      backgroundColor: t.tooltipBg,
      borderColor: t.tooltipBorder,
      textStyle: { color: t.textPrimary, fontSize: 11 },
    },
    legend: {
      top: 0,
      textStyle: { color: t.textMuted, fontSize: 10 },
    },
    grid: { left: 42, right: 16, top: 28, bottom: 24 },
    xAxis: {
      type: 'category',
      data: labels,
      axisLabel: { color: t.textMuted, fontSize: 9 },
      axisLine: { lineStyle: { color: t.splitLine } },
    },
    yAxis: {
      type: 'value',
      min: -100,
      max: -25,
      axisLabel: { color: t.textMuted, fontSize: 9 },
      splitLine: { lineStyle: { color: t.splitLine, type: 'dashed' } },
    },
    series: seriesList,
  };
});

const btIntervalHistogramOption = computed(() => {
  const t = btChartThemeTokens.value;
  const buckets = [0, 0, 0, 0, 0];
  for (const d of btData.value.devices) {
    const iv = d.adv_interval_ms;
    if (iv === null || iv === undefined || iv <= 0) buckets[4] += 1;
    else if (iv < 35) buckets[0] += 1;
    else if (iv <= 120) buckets[1] += 1;
    else if (iv <= 500) buckets[2] += 1;
    else buckets[3] += 1;
  }
  const palette = ['#f43f5e', '#10b981', '#38bdf8', '#6366f1', '#94a3b8'];

  return {
    backgroundColor: 'transparent',
    tooltip: {
      trigger: 'axis',
      backgroundColor: t.tooltipBg,
      borderColor: t.tooltipBorder,
      textStyle: { color: t.textPrimary, fontSize: 11 },
    },
    grid: { left: 32, right: 12, top: 18, bottom: 28 },
    xAxis: {
      type: 'category',
      data: ['<35ms 泛洪', '35~120ms', '120~500ms', '>500ms', '单次快照'],
      axisLabel: { color: t.textMuted, fontSize: 9, interval: 0 },
      axisLine: { lineStyle: { color: t.splitLine } },
    },
    yAxis: {
      type: 'value',
      minInterval: 1,
      axisLabel: { color: t.textMuted, fontSize: 9 },
      splitLine: { lineStyle: { color: t.splitLine, type: 'dashed' } },
    },
    series: [
      {
        name: '设备台数',
        type: 'bar',
        barWidth: '48%',
        data: buckets.map((val, idx) => ({
          value: val,
          itemStyle: { color: palette[idx], borderRadius: [5, 5, 0, 0] },
        })),
      },
    ],
  };
});

const btProtocolVendorOption = computed(() => {
  const t = btChartThemeTokens.value;
  const counts = new Map<string, number>();

  if (btPieMode.value === 'protocol' && (btData.value.recent_frames || []).length > 0) {
    for (const f of btData.value.recent_frames || []) {
      const k = f.protocol_layer || 'BLE-ADV';
      counts.set(k, (counts.get(k) || 0) + 1);
    }
  } else {
    for (const d of btData.value.devices) {
      const k = d.vendor_info || 'Bluetooth SIG';
      counts.set(k, (counts.get(k) || 0) + 1);
    }
  }

  const sorted = Array.from(counts.entries()).sort((a, b) => b[1] - a[1]);
  const top = sorted.slice(0, 6);
  const restSum = sorted.slice(6).reduce((acc, [, v]) => acc + v, 0);
  if (restSum > 0) top.push(['其他 SIG 厂商', restSum]);

  const data = top.map(([name, value]) => ({ name, value }));

  return {
    backgroundColor: 'transparent',
    tooltip: {
      trigger: 'item',
      backgroundColor: t.tooltipBg,
      borderColor: t.tooltipBorder,
      textStyle: { color: t.textPrimary, fontSize: 11 },
      formatter: '{b}: <b>{c}</b> ({d}%)',
    },
    legend: {
      orient: 'vertical',
      right: 4,
      top: 'middle',
      textStyle: { color: t.textMuted, fontSize: 10 },
    },
    series: [
      {
        name: btPieMode.value === 'protocol' ? '协议层次帧占比' : 'SIG 厂商设备数',
        type: 'pie',
        radius: ['42%', '72%'],
        center: ['33%', '50%'],
        itemStyle: { borderRadius: 4, borderWidth: 1, borderColor: isDarkTheme.value ? '#0f172a' : '#ffffff' },
        label: { show: false },
        data,
      },
    ],
  };
});

const btStabilityAggregate = computed(() => {
  const devs = btData.value.devices;
  if (devs.length === 0) return { avgStability: 100, worstName: '-', worstStddev: 0 };
  let sum = 0;
  let worst = devs[0];
  for (const d of devs) {
    sum += d.stability_score ?? 100;
    if ((d.rssi_stddev ?? 0) > (worst.rssi_stddev ?? 0)) worst = d;
  }
  return {
    avgStability: Number((sum / devs.length).toFixed(1)),
    worstName: worst.device_name || worst.address,
    worstStddev: Number((worst.rssi_stddev ?? 0).toFixed(2)),
  };
});

async function saveBluetoothBaseline() {
  btToolBusy.value = true;
  try {
    const snap = await invoke<BluetoothBaselineSnapshot>('save_bluetooth_baseline_cmd');
    btToolMsg.value = `已保存物理环境基准快照 (${snap.saved_at} · ${snap.device_count} 台设备)`;
    await runBluetoothBaselineComparison(true);
  } catch (err) {
    btToolMsg.value = `基线保存失败: ${String(err)}`;
  } finally {
    btToolBusy.value = false;
  }
}

async function runBluetoothBaselineComparison(silent = false) {
  if (!silent) btToolBusy.value = true;
  try {
    const res = await invoke<BluetoothBaselineComparisonResult>('compare_bluetooth_realtime_vs_history_cmd');
    btComparison.value = res;
    if (!silent) btToolMsg.value = res.diagnostic_message;
  } catch (err) {
    if (!silent) btToolMsg.value = `实时与历史对照失败: ${String(err)}`;
  } finally {
    if (!silent) btToolBusy.value = false;
  }
}

async function exportBluetoothBtsnoop() {
  btToolBusy.value = true;
  try {
    const res = await invoke<BtsnoopExportResult>('export_bluetooth_btsnoop_cmd');
    btToolMsg.value = res.message;
  } catch (err) {
    btToolMsg.value = `导出 .btsnoop 失败: ${String(err)}`;
  } finally {
    btToolBusy.value = false;
  }
}

async function importBluetoothBtsnoop() {
  btToolBusy.value = true;
  try {
    const res = await invoke<BtsnoopImportResult>('pick_and_import_bluetooth_btsnoop_cmd');
    btToolMsg.value = res.diagnostic_message;
    if (!res.cancelled && res.summary) {
      btData.value = res.summary;
      await runBluetoothBaselineComparison(true);
    }
  } catch (err) {
    btToolMsg.value = `导入 .btsnoop 失败: ${String(err)}`;
  } finally {
    btToolBusy.value = false;
  }
}

async function readBleGattCharacteristic(
  macAddress: string,
  charUuid: string,
  svcIndex: number,
  chrIndex: number
) {
  const key = `${svcIndex}:${chrIndex}`;
  readingGattCharKey.value = key;
  try {
    const res = await invoke<BleGattCharacteristicReadResult>('read_ble_gatt_characteristic_cmd', {
      macAddress,
      charUuid,
    });
    if (res.success && gattAudit.value && gattAudit.value.services[svcIndex]?.characteristics[chrIndex]) {
      gattAudit.value.services[svcIndex].characteristics[chrIndex].raw_value_hex = res.raw_value_hex;
      gattAudit.value.services[svcIndex].characteristics[chrIndex].decoded_value =
        res.decoded_value || res.diagnostic_message;
    }
    btToolMsg.value = res.success
      ? `特征 ${res.characteristic_uuid} 实时读取成功: ${res.decoded_value || res.raw_value_hex || 'OK'}`
      : `特征 ${charUuid} 读取受阻: ${res.diagnostic_message}`;
  } catch (err) {
    btToolMsg.value = `GATT 实时读值异常: ${String(err)}`;
  } finally {
    readingGattCharKey.value = null;
  }
}

let liveBtTimer: number | null = null;
function syncBtPollRate(fast: boolean) {
  if (liveBtTimer) {
    clearInterval(liveBtTimer);
    liveBtTimer = null;
  }
  if (fast) {
    liveBtTimer = window.setInterval(() => {
      if (activeTab.value === 'bluetooth') fetchBluetoothTelemetry();
    }, 850);
  }
}

async function toggleContinuousBle() {
  try {
    if (continuousBleActive.value || btData.value.continuous_ble_active) {
      await invoke('stop_continuous_ble_monitor_cmd');
      continuousBleActive.value = false;
      syncBtPollRate(bthEtwActive.value);
    } else {
      await invoke('start_continuous_ble_monitor_cmd');
      continuousBleActive.value = true;
      syncBtPollRate(true);
    }
    await fetchBluetoothTelemetry();
  } catch (err) {
    bthEtwMsg.value = `实时 BLE 空口启动异常: ${String(err)}`;
  }
}

async function toggleBthEtwCapture() {
  try {
    if (bthEtwActive.value || btData.value.bthport_etw_active) {
      await invoke('stop_bthport_etw_capture_cmd');
      bthEtwActive.value = false;
      bthEtwMsg.value = '已停止 BTHPORT-ETW 驱动级 HCI/L2CAP 抓包';
      syncBtPollRate(continuousBleActive.value);
    } else {
      const msg = await invoke<string>('start_bthport_etw_capture_cmd');
      bthEtwActive.value = true;
      bthEtwMsg.value = msg;
      syncBtPollRate(true);
    }
    await fetchBluetoothTelemetry();
  } catch (err) {
    bthEtwActive.value = false;
    bthEtwMsg.value = String(err);
  }
}

function sendHexToWorkbench(rawHex: string) {
  if (!rawHex.trim()) return;
  customHexInput.value = rawHex.trim();
  dissectMode.value = 'bluetooth';
  activeTab.value = 'workbench';
  triggerDissect();
}

async function runNativeWifiScan() {
  scanningNativeWifi.value = true;
  try {
    const res = await invoke<NativeWifiScanResult>('scan_os_wifi_networks_cmd');
    nativeWifiScan.value = res;
    if (res?.summary) {
      wifiData.value = res.summary;
    } else {
      await fetchWifiTelemetry();
    }
  } catch (err) {
    nativeWifiScan.value = {
      native_scan_available: false,
      platform: 'desktop',
      reason_code: 'INVOKE_ERROR',
      status_message: `原生 WLAN 扫描调用异常: ${String(err)}`,
      scanned_ap_count: 0,
      interface_name: '',
      aps: [],
      summary: wifiData.value,
    };
  } finally {
    scanningNativeWifi.value = false;
  }
}

const gattAudit = ref<BleGattAuditResult | null>(null);
const auditingGattAddr = ref<string | null>(null);

async function runBleGattAudit(macAddress: string) {
  auditingGattAddr.value = macAddress;
  try {
    gattAudit.value = await invoke<BleGattAuditResult>('scan_ble_gatt_services_cmd', {
      macAddress,
    });
  } catch (err) {
    console.error('BLE GATT 服务枚举失败:', err);
  } finally {
    auditingGattAddr.value = null;
  }
}

async function runNativeBtScan() {
  scanningNativeBt.value = true;
  try {
    const res = await invoke<NativeBluetoothScanResult>('scan_native_bluetooth_devices_cmd', {
      issueInquiry: btInquiryMode.value,
    });
    nativeBtScan.value = res;
    if (res?.summary) {
      btData.value = res.summary;
    } else {
      await fetchBluetoothTelemetry();
    }
  } catch (err) {
    console.error('原生蓝牙扫描失败:', err);
  } finally {
    scanningNativeBt.value = false;
  }
}

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
  const tasks: Promise<unknown>[] = [
    fetchWifiTelemetry(),
    fetchVlanTelemetry(),
    fetchBluetoothTelemetry(),
  ];
  if (activeTab.value === 'wifi') tasks.push(runNativeWifiScan());
  if (activeTab.value === 'bluetooth') tasks.push(runNativeBtScan());
  await Promise.allSettled(tasks);
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
  if (current === 0) return 0;
  let max = 1;
  for (const k in counts) {
    if (counts[k] > max) max = counts[k];
  }
  return Math.max(8, Math.min(100, Math.round((current / max) * 100)));
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
  if (rssi >= -60) return 'text-emerald-700 dark:text-emerald-400';
  if (rssi >= -75) return 'text-sky-700 dark:text-sky-400';
  if (rssi >= -85) return 'text-amber-700 dark:text-amber-400';
  return 'text-rose-700 dark:text-rose-400';
}

function getRssiBgClass(rssi: number): string {
  if (rssi >= -60) return 'bg-emerald-500';
  if (rssi >= -75) return 'bg-sky-500';
  if (rssi >= -85) return 'bg-amber-500';
  return 'bg-rose-500';
}

function getEncryptionClass(enc: string): string {
  if (enc.includes('WPA3')) return 'bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 border-emerald-500/25';
  if (enc.includes('WPA2')) return 'bg-sky-500/12 text-sky-700 dark:text-sky-300 border-sky-500/25';
  if (enc.includes('WEP')) return 'bg-rose-500/12 text-rose-700 dark:text-rose-300 border-rose-500/25';
  return 'bg-amber-500/12 text-amber-700 dark:text-amber-300 border-amber-500/25';
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

let themeObserver: MutationObserver | null = null;

onMounted(() => {
  if (typeof document !== 'undefined') {
    const syncTheme = () => {
      isDarkTheme.value = !document.documentElement.classList.contains('theme-apple-light');
    };
    syncTheme();
    themeObserver = new MutationObserver(syncTheme);
    themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });
  }
  refreshCurrentTelemetry();
  runBluetoothBaselineComparison(true);
  if (activeTab.value !== 'wifi') runNativeWifiScan();
  if (activeTab.value !== 'bluetooth') runNativeBtScan();
  pollTimer = window.setInterval(() => {
    if (activeTab.value === 'wifi') fetchWifiTelemetry();
    else if (activeTab.value === 'vlan') fetchVlanTelemetry();
    else if (activeTab.value === 'bluetooth') fetchBluetoothTelemetry();
  }, 3000);
});

onUnmounted(() => {
  if (themeObserver) {
    themeObserver.disconnect();
    themeObserver = null;
  }
  if (pollTimer) clearInterval(pollTimer);
  if (liveBtTimer) clearInterval(liveBtTimer);
  if (continuousBleActive.value) {
    invoke('stop_continuous_ble_monitor_cmd').catch(() => {});
  }
  if (bthEtwActive.value) {
    invoke('stop_bthport_etw_capture_cmd').catch(() => {});
  }
});
</script>
