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

          <div class="ui-content-card p-5 space-y-3">
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

            <div class="grid grid-cols-7 lg:grid-cols-14 gap-2 pt-2">
              <div
                v-for="ch in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]"
                :key="'ch2g-' + ch"
                class="flex flex-col items-center gap-1.5 p-2 rounded-xl ui-sub-card"
              >
                <div class="w-full h-20 rounded-lg flex items-end p-1 relative overflow-hidden" style="background: var(--surface-elevated)">
                  <div
                    class="w-full rounded-md transition-all duration-500 bg-gradient-to-t from-sky-500 to-indigo-500"
                    :style="{ height: getChannelPercent(ch) + '%' }"
                  ></div>
                </div>
                <div class="text-[11px] font-bold ui-num" style="color: var(--text-primary)">
                  Ch {{ ch }}
                </div>
                <div class="text-[11px] ui-num" style="color: var(--text-muted)">
                  {{ wifiData.channel_distribution[ch] || 0 }} 帧
                </div>
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

          <div class="ui-content-card p-5 space-y-3">
            <h4 class="text-xs font-bold flex items-center gap-2 flex-wrap" style="color: var(--text-primary)">
              <AppIcon name="radar" :size="14" />
              <span>蓝牙/BLE 设备雷达与距离衰减估算</span>
              <span class="text-[11px] ui-num font-normal" style="color: var(--text-muted)">基于 Log-Distance 路径损耗模型 d = 10^((A-RSSI)/(10n))</span>
            </h4>

            <div class="overflow-x-auto select-text">
              <table class="w-full text-left border-collapse">
                <thead class="ui-table-head text-[11px] font-semibold uppercase tracking-wider">
                  <tr>
                    <th class="py-2.5 px-3">设备广播名称</th>
                    <th class="py-2.5 px-3">BD_ADDR 蓝牙物理地址</th>
                    <th class="py-2.5 px-3">地址类别</th>
                    <th class="py-2.5 px-3">RSSI 信号</th>
                    <th class="py-2.5 px-3">物理估算距离</th>
                    <th class="py-2.5 px-3">暴露服务 (UUID)</th>
                    <th class="py-2.5 px-3">安全与配对评估</th>
                    <th class="py-2.5 px-3 text-right">比对</th>
                  </tr>
                </thead>
                <tbody class="divide-y text-xs ui-num" style="border-color: var(--border-subtle); color: var(--text-secondary)">
                  <tr
                    v-for="dev in btData.devices"
                    :key="dev.address"
                    class="hover:bg-black/5 dark:hover:bg-white/5 transition-colors"
                  >
                    <td class="py-3 px-3 font-bold flex items-center gap-2" style="color: var(--text-primary)">
                      <span class="w-2 h-2 rounded-full bg-blue-500 shrink-0"></span>
                      <span>{{ dev.device_name }}</span>
                    </td>
                    <td class="py-3 px-3">{{ dev.address }}</td>
                    <td class="py-3 px-3 text-[11px]">
                      <span class="px-2 py-0.5 rounded-md border" :class="dev.address_type.includes('Public') ? 'bg-sky-500/12 text-sky-700 dark:text-sky-300 border-sky-500/25' : 'ui-pill'">
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
                        <span class="font-bold text-indigo-700 dark:text-indigo-400">≈ {{ dev.estimated_distance_m }} 米</span>
                        <span class="text-[11px] px-1.5 py-0.5 rounded ui-pill">
                          {{ getDistanceZone(dev.estimated_distance_m) }}
                        </span>
                      </div>
                    </td>
                    <td class="py-3 px-3 max-w-xs truncate text-[11px]" style="color: var(--text-muted)">
                      {{ dev.service_uuids.join(', ') || '未广播标准 UUID' }}
                    </td>
                    <td class="py-3 px-3">
                      <div v-if="dev.security_flags.length === 0" class="text-emerald-700 dark:text-emerald-400 text-[11px] flex items-center gap-1">
                        <AppIcon name="check" :size="12" />
                        <span>广播安全</span>
                      </div>
                      <div v-else class="flex flex-wrap gap-1">
                        <span
                          v-for="flag in dev.security_flags"
                          :key="flag"
                          class="px-2 py-0.5 rounded-md text-[11px] font-bold bg-amber-500/12 text-amber-700 dark:text-amber-300 border border-amber-500/30 flex items-center gap-1"
                        >
                          <AppIcon name="alert" :size="11" />
                          <span>{{ flag }}</span>
                        </span>
                      </div>
                    </td>
                    <td class="py-3 px-3 text-right">
                      <button @click="addBleDeviceToDiffQueue(dev)"
                        class="px-2 py-0.5 rounded bg-emerald-500/12 hover:bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border border-emerald-500/25 text-[11px] font-semibold cursor-pointer"
                        title="将该 BLE 设备广播与 UUID 服务纳入全局多组比对队列">
                        + 入队
                      </button>
                    </td>
                  </tr>

                  <tr v-if="btData.devices.length === 0">
                    <td colspan="8" class="py-8">
                      <EmptyState icon="radar" title="未捕获到蓝牙 HCI 封包" description="需要启动 USB 嗅探且安装 USBPcap 捕获 USB 蓝牙控制器 HCI URB；亦可直接在下方载入 BLE HCI 样本进行结构化解析。">
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
import { ref, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import AppIcon from './AppIcon.vue';
import EmptyState from './EmptyState.vue';
import { useUniversalDiff } from '../composables/useUniversalDiff';

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
