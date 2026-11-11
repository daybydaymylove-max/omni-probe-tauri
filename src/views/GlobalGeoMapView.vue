<template>
  <div class="h-full flex flex-col gap-2.5 overflow-hidden relative font-sans">
    
    <!-- ============================================================== -->
    <!-- 1. 顶栏：空间测绘数据源状态、投影模式与图层开关 (Liquid Glass)  -->
    <!-- ============================================================== -->
    <header class="ui-nav-glass rounded-2xl px-4 py-2.5 flex flex-wrap items-center justify-between gap-2.5 shrink-0 z-20 select-none">
      <span class="lens-edge-lip" aria-hidden="true"></span>
      <!-- 左侧：标题与真实数据通道指示 -->
      <div class="flex items-center gap-3">
        <div class="w-8 h-8 rounded-xl bg-[var(--accent-primary-soft)] text-[var(--accent-primary-text)] border border-[var(--accent-primary)]/20 flex items-center justify-center shrink-0">
          <AppIcon name="globe" :size="16" />
        </div>
        <div>
          <div class="flex items-center gap-2 flex-wrap">
            <h2 class="text-[13px] font-bold tracking-tight" style="color: var(--text-primary)">
              全球网络空间测绘与双向路由追踪
            </h2>
            <!-- 数据真实来源指示徽章 -->
            <span v-if="dataSource === 'LIVE_SNIFFER'" class="px-2 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30 flex items-center gap-1.5">
              <span class="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
              真实网卡双向嗅探驱动
            </span>
            <span v-else-if="dataSource === 'OS_SOCKETS'" class="px-2 py-0.5 rounded-full text-[11px] font-semibold bg-sky-500/12 text-sky-700 dark:text-sky-300 border border-sky-500/30 flex items-center gap-1.5">
              <span class="w-1.5 h-1.5 rounded-full bg-sky-500"></span>
              OS 实时外联 Socket 快照
            </span>
            <span v-else class="px-2 py-0.5 rounded-full text-[11px] font-semibold bg-slate-500/10 text-slate-600 dark:text-slate-300 border border-slate-500/20">
              待机 (未捕获真实外联流)
            </span>
          </div>
          <div class="text-[11px] ui-num mt-0.5 flex items-center gap-2 flex-wrap" style="color: var(--text-muted)">
            <span>本机位置: <strong class="text-emerald-700 dark:text-emerald-400">{{ selfNode?.city || '定位中...' }}</strong></span>
            <span style="color: var(--border-strong)">|</span>
            <span>通讯对端 IP: <strong class="text-sky-700 dark:text-cyan-300">{{ peerNodes.length }}</strong> 节点</span>
            <span style="color: var(--border-strong)">|</span>
            <span>已定位公网节点: <strong class="text-indigo-700 dark:text-indigo-300">{{ mappedPeerCount }}</strong></span>
            <template v-if="tracerouteHops.length > 0">
              <span style="color: var(--border-strong)">|</span>
              <span class="text-amber-700 dark:text-amber-300 font-semibold">
                路由中转追踪: {{ maxHopNumber }} 跳 ({{ tracerouteHops.filter(h => !h.is_timeout && h.hop > 0).length }} 有效响应)
              </span>
            </template>
          </div>
        </div>
      </div>

      <!-- 右侧：真实探活、投影模式与图层切换 -->
      <div class="flex items-center gap-2 flex-wrap">
        <button
          @click="probeOsSockets"
          :disabled="loadingOsSockets"
          class="ui-btn-secondary text-[11px] font-semibold py-1 px-2.5 rounded-xl"
          title="直接扫描操作系统当前已建立连接的外部 TCP 服务器 IP（无需抓包驱动亦可探测）"
        >
          <AppIcon name="search" :size="13" :class="loadingOsSockets ? 'animate-spin' : ''" />
          <span>{{ loadingOsSockets ? '扫描中...' : '探测本机当前外联' }}</span>
        </button>

        <!-- 投影切换 -->
        <div class="p-0.5 rounded-xl ui-pill flex items-center gap-1 text-[11px] font-semibold">
          <button
            @click="setProjection('3d')"
            :class="[
              'px-2.5 py-1 rounded-lg transition-colors flex items-center gap-1 cursor-pointer',
              projectionMode === '3d' ? 'bg-[var(--accent-primary)] text-white shadow-xs font-semibold' : 'hover:bg-black/5 dark:hover:bg-white/5'
            ]"
            :style="projectionMode !== '3d' ? { color: 'var(--text-secondary)' } : undefined"
          >
            <AppIcon name="globe" :size="13" />
            <span>3D 地球</span>
          </button>
          <button
            @click="setProjection('2d')"
            :class="[
              'px-2.5 py-1 rounded-lg transition-colors flex items-center gap-1 cursor-pointer',
              projectionMode === '2d' ? 'bg-[var(--accent-primary)] text-white shadow-xs font-semibold' : 'hover:bg-black/5 dark:hover:bg-white/5'
            ]"
            :style="projectionMode !== '2d' ? { color: 'var(--text-secondary)' } : undefined"
          >
            <AppIcon name="layers" :size="13" />
            <span>2D 全景</span>
          </button>
        </div>

        <!-- 3D 自转切换 -->
        <button
          v-if="projectionMode === '3d'"
          @click="autoRotate = !autoRotate"
          :class="[
            'px-2.5 py-1 rounded-xl border text-[11px] font-medium transition-colors cursor-pointer flex items-center gap-1',
            autoRotate ? 'bg-[var(--accent-primary)]/15 text-[var(--accent-primary)] border-[var(--accent-primary)]/35' : 'ui-pill'
          ]"
        >
          <AppIcon :name="autoRotate ? 'pause' : 'play'" :size="12" />
          <span>{{ autoRotate ? '自转中' : '自转' }}</span>
        </button>

        <!-- 图层显隐按钮组 -->
        <div class="flex items-center gap-1 text-[11px]">
          <button
            @click="layers.terminator = !layers.terminator"
            :class="layers.terminator ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/35' : 'ui-pill opacity-75'"
            class="px-2 py-1 rounded-xl border transition-colors cursor-pointer flex items-center gap-1 font-medium"
            title="切换太阳昼夜晨昏线"
          >
            <AppIcon name="sun" :size="12" />
            <span>晨昏线</span>
          </button>
          <button
            @click="layers.cables = !layers.cables"
            :class="layers.cables ? 'bg-sky-500/15 text-sky-700 dark:text-cyan-300 border-sky-500/35' : 'ui-pill opacity-75'"
            class="px-2 py-1 rounded-xl border transition-colors cursor-pointer flex items-center gap-1 font-medium"
            title="切换国际海缆参考底图"
          >
            <AppIcon name="link" :size="12" />
            <span>海缆参考</span>
          </button>
          <button
            @click="layers.graticules = !layers.graticules"
            :class="layers.graticules ? 'bg-indigo-500/15 text-indigo-700 dark:text-indigo-300 border-indigo-500/35' : 'ui-pill opacity-75'"
            class="px-2 py-1 rounded-xl border transition-colors cursor-pointer flex items-center gap-1 font-medium"
            title="切换 15° 高精经纬网格"
          >
            <AppIcon name="compass" :size="12" />
            <span>经纬网</span>
          </button>
        </div>

        <button
          @click="resetViewport"
          class="ui-btn-secondary text-[11px] py-1 px-2.5 rounded-xl"
          title="视角复位至本机物理中心"
        >
          <AppIcon name="refresh" :size="12" />
          <span>复位</span>
        </button>
      </div>
    </header>

    <!-- ============================================================== -->
    <!-- 2. 主体区：高精度数字地球视口 + 右侧双向 IP 与多跳路由分析台     -->
    <!-- ============================================================== -->
    <div class="flex-1 ui-content-card flex overflow-hidden relative min-h-0">
      
      <!-- 2.1 主地图 Canvas 视口 (全通透融入液态流光底景) -->
      <div
        ref="mapContainerRef"
        :class="[
          'flex-1 h-full relative cursor-grab active:cursor-grabbing overflow-hidden select-none transition-colors',
          isDarkTheme ? 'bg-slate-950/20' : 'bg-white/20'
        ]"
        @mousedown="handleMouseDown"
        @mousemove="handleMouseMove"
        @mouseup="handleMouseUp"
        @mouseleave="handleMouseUp"
        @wheel.passive="handleWheel"
      >
        <canvas ref="mapCanvasRef" class="w-full h-full block"></canvas>

        <!-- 左上角 HUD 实时定位与方向图例 (Liquid Glass 浮层) -->
        <div class="absolute top-3 left-4 flex flex-wrap items-center gap-2 pointer-events-none text-[11px] ui-num">
          <div class="liquid-panel px-3 py-1 rounded-full flex items-center gap-2.5 flex-wrap" style="color: var(--text-secondary)">
            <span class="lens-edge-lip" aria-hidden="true"></span>
            <span>视口: {{ centerLat >= 0 ? '+' : '' }}{{ centerLat.toFixed(1) }}°N, {{ centerLon >= 0 ? '+' : '' }}{{ centerLon.toFixed(1) }}°E</span>
            <span style="color: var(--border-strong)">|</span>
            <span>{{ scale.toFixed(2) }}x</span>
            <span style="color: var(--border-strong)">|</span>
            <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-emerald-500"></span>本机源端</span>
            <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-sky-500"></span>通信对端</span>
            <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-amber-500"></span>路由中转跳</span>
            <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-rose-500"></span>告警源</span>
          </div>
        </div>

        <!-- 零数据待机提示浮层 -->
        <div
          v-if="dataSource === 'STANDBY' && peerNodes.length === 0"
          class="absolute bottom-5 left-1/2 -translate-x-1/2 z-20 px-5 py-3.5 rounded-2xl ui-modal-surface flex flex-wrap items-center justify-center gap-4 max-w-2xl"
        >
          <div class="text-xs space-y-0.5">
            <div class="font-bold flex items-center gap-2" style="color: var(--text-primary)">
              <span class="w-2 h-2 rounded-full bg-amber-500"></span>
              <span>当前网卡嗅探待机：未捕获到真实双向公网通信流量</span>
            </div>
            <div class="text-[11px]" style="color: var(--text-secondary)">
              本视图严格绑定真实流向。启动网卡嗅探后将实时绘出来往节点，或立即扫描本机已建外联。
            </div>
          </div>
          <div class="flex items-center gap-2 shrink-0">
            <button
              v-if="!isRunning"
              @click="$emit('startCapture')"
              class="ui-btn-primary text-xs py-1.5 px-3 rounded-xl"
            >
              <AppIcon name="play" :size="12" />
              <span>启动网卡嗅探</span>
            </button>
            <button
              @click="probeOsSockets"
              class="ui-btn-secondary text-xs py-1.5 px-3 rounded-xl"
            >
              <AppIcon name="search" :size="12" />
              <span>扫描当前活动外联</span>
            </button>
          </div>
        </div>

        <!-- 路由追踪实时浮动进度提示胶囊 -->
        <div
          v-if="isTracing && tracerouteTargetIp"
          class="absolute bottom-5 left-4 z-20 px-4 py-2.5 rounded-2xl ui-modal-surface border-amber-500/45 flex items-center gap-3 text-xs ui-num"
        >
          <span class="w-3.5 h-3.5 rounded-full border-2 border-amber-500 border-t-transparent animate-spin shrink-0"></span>
          <div>
            <div class="text-amber-700 dark:text-amber-300 font-bold">正在进行逐跳路由中转追踪: {{ tracerouteTargetIp }}</div>
            <div class="text-[11px]" style="color: var(--text-secondary)">
              已收集第 0 ~ {{ maxHopNumber }} 跳中转节点 (TTL Hop-by-Hop 实时绘制中)
            </div>
          </div>
        </div>

        <!-- 悬浮节点 Tooltip HUD -->
        <div
          v-if="hoveredCanvasItem"
          class="absolute z-30 pointer-events-none p-3 rounded-2xl ui-modal-surface text-xs ui-num space-y-1 min-w-56 max-w-xs"
          :style="{ left: tooltipPos.x + 15 + 'px', top: tooltipPos.y - 15 + 'px' }"
        >
          <template v-if="hoveredCanvasItem.kind === 'peer'">
            <div class="font-bold flex items-center justify-between border-b pb-1" style="border-color: var(--border-subtle); color: var(--text-primary)">
              <span class="text-sky-700 dark:text-cyan-300">{{ hoveredCanvasItem.node.ip }}</span>
              <span class="text-[11px] px-1.5 py-0.5 rounded ui-pill">
                {{ hoveredCanvasItem.node.is_self ? '本机源端' : (hoveredCanvasItem.node.country || '未知') }}
              </span>
            </div>
            <div class="text-[11px]" style="color: var(--text-secondary)">位置: {{ hoveredCanvasItem.node.geo_label }}</div>
            <div class="text-[11px]" style="color: var(--text-muted)">运营商: {{ hoveredCanvasItem.node.isp }}</div>
            <div v-if="!hoveredCanvasItem.node.is_self" class="text-[11px] flex justify-between pt-1 text-emerald-700 dark:text-emerald-400 font-semibold">
              <span>入站: {{ formatBytes(hoveredCanvasItem.node.inbound_bytes) }}</span>
              <span>出站: {{ formatBytes(hoveredCanvasItem.node.outbound_bytes) }}</span>
            </div>
            <div v-if="hoveredCanvasItem.node.distance_km > 0" class="text-[11px]" style="color: var(--text-muted)">
              球面测地距离: {{ hoveredCanvasItem.node.distance_km }} km (光纤下限 {{ hoveredCanvasItem.node.theoretical_fiber_rtt_ms }} ms)
            </div>
            <div v-if="!hoveredCanvasItem.node.is_self" class="text-[11px] text-amber-700 dark:text-amber-300 pt-0.5 font-semibold">
              点击节点定位坐标并开启路由中转追踪
            </div>
          </template>

          <template v-else-if="hoveredCanvasItem.kind === 'hop'">
            <div class="font-bold text-amber-700 dark:text-amber-300 border-b pb-1" style="border-color: var(--border-subtle)">
              中转跳点 #{{ hoveredCanvasItem.hop.hop }} · {{ hoveredCanvasItem.hop.ip }}
            </div>
            <div class="text-[11px]" style="color: var(--text-primary)">
              地理归属: {{ hoveredCanvasItem.hop.country }} {{ hoveredCanvasItem.hop.province }} {{ hoveredCanvasItem.hop.city }}
            </div>
            <div class="text-[11px]" style="color: var(--text-muted)">运营商: {{ hoveredCanvasItem.hop.isp }}</div>
            <div class="text-emerald-700 dark:text-emerald-400 text-[11px] font-bold">
              响应耗时 RTT: {{ hoveredCanvasItem.hop.rtt_ms !== null ? hoveredCanvasItem.hop.rtt_ms + ' ms' : '超时' }}
            </div>
            <div class="text-[11px]" style="color: var(--text-muted)">
              累计路由距离: {{ hoveredCanvasItem.hop.cumulative_distance_km.toFixed(1) }} km
            </div>
          </template>
        </div>

      </div>

      <!-- 2.2 右侧：真实对端 IP 清单 & 硬核多跳路由中转剖析台 (实体工作区面板) -->
      <aside
        :class="[
          'w-80 xl:w-96 border-l flex flex-col transition-all duration-300 z-10 shrink-0 overflow-hidden ui-content-card rounded-none border-t-0 border-r-0 border-b-0',
          isSidebarCollapsed ? '!w-0 !border-l-0' : ''
        ]"
      >
        <!-- 侧栏顶部标签与手动输入追踪框 -->
        <div class="p-3.5 border-b space-y-2.5 shrink-0 select-none" style="border-color: var(--border-subtle)">
          <div class="flex items-center justify-between gap-2">
            <div class="flex items-center gap-1.5">
              <button
                @click="activeSideTab = 'peers'"
                :class="[
                  'px-2.5 py-1 rounded-lg text-xs font-semibold transition-colors cursor-pointer',
                  activeSideTab === 'peers' ? 'bg-sky-500/15 text-sky-700 dark:text-cyan-300 border border-sky-500/35' : 'hover:bg-black/5 dark:hover:bg-white/5'
                ]"
                :style="activeSideTab !== 'peers' ? { color: 'var(--text-secondary)' } : undefined"
              >
                通讯 IP 清单 ({{ peerNodes.length }})
              </button>
              <button
                @click="activeSideTab = 'traceroute'"
                :class="[
                  'px-2.5 py-1 rounded-lg text-xs font-semibold transition-colors cursor-pointer flex items-center gap-1',
                  activeSideTab === 'traceroute' ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/35' : 'hover:bg-black/5 dark:hover:bg-white/5'
                ]"
                :style="activeSideTab !== 'traceroute' ? { color: 'var(--text-secondary)' } : undefined"
              >
                <span>路由中转追踪</span>
                <span v-if="tracerouteHops.length > 0" class="px-1.5 py-0.5 rounded-full bg-amber-500/20 text-amber-700 dark:text-amber-300 text-[11px] ui-num">
                  {{ maxHopNumber }}跳
                </span>
              </button>
            </div>
            <button
              @click="isSidebarCollapsed = true"
              class="text-[11px] px-2 py-1 rounded-lg ui-pill flex items-center gap-1 cursor-pointer shrink-0"
              title="收起侧栏"
            >
              <span>收起</span>
              <AppIcon name="chevron-right" :size="12" />
            </button>
          </div>

          <!-- 手动指定 IP 一键地球定位与路由中转追踪栏 -->
          <div class="flex items-center gap-1.5">
            <input
              v-model="manualTargetIp"
              @keyup.enter="handleManualTrace"
              type="text"
              placeholder="输入公网 IP 或域名追踪 (如 8.8.8.8)"
              class="flex-1 ui-input ui-num text-[11px] py-1.5 px-2.5"
            />
            <button
              @click="handleManualTrace"
              :disabled="isTracing || !manualTargetIp.trim()"
              class="ui-btn-primary text-[11px] py-1.5 px-3 rounded-lg shrink-0"
              title="立即标注坐标并追踪经历多少次路由中转"
            >
              {{ isTracing ? '探测中' : '定位+追踪' }}
            </button>
          </div>
        </div>

        <!-- TAB 1: 与本机双向通信的真实 IP 列表 -->
        <div v-if="activeSideTab === 'peers'" class="flex-1 overflow-y-auto custom-scrollbar p-3.5 space-y-3 select-text">
          <!-- 宏观汇总双卡 -->
          <div class="grid grid-cols-2 gap-2 text-xs ui-num">
            <div class="ui-sub-card p-2.5">
              <div class="text-[11px]" style="color: var(--text-muted)">入站总吞吐 (Inbound)</div>
              <div class="text-sm font-bold text-emerald-700 dark:text-emerald-400 mt-0.5">{{ formatBytes(totalInboundBytes) }}</div>
            </div>
            <div class="ui-sub-card p-2.5">
              <div class="text-[11px]" style="color: var(--text-muted)">出站总吞吐 (Outbound)</div>
              <div class="text-sm font-bold text-sky-700 dark:text-cyan-400 mt-0.5">{{ formatBytes(totalOutboundBytes) }}</div>
            </div>
          </div>

          <!-- 所选 IP 快速聚焦卡片 -->
          <div v-if="selectedPeer" class="ui-sub-card p-3 border-indigo-500/40 bg-indigo-500/8 space-y-2 text-xs ui-num">
            <div class="flex items-center justify-between border-b pb-1.5" style="border-color: var(--border-subtle)">
              <span class="font-bold flex items-center gap-1.5" style="color: var(--text-primary)">
                <span class="w-2 h-2 rounded-full bg-sky-500"></span>
                {{ selectedPeer.ip }}
              </span>
              <span class="text-[11px] px-1.5 py-0.5 rounded ui-pill text-sky-700 dark:text-cyan-300 font-semibold">
                {{ selectedPeer.primary_protocol }}
              </span>
            </div>
            <div class="text-[11px] space-y-0.5" style="color: var(--text-secondary)">
              <div>地球定位: <strong style="color: var(--text-primary)">{{ selectedPeer.geo_label }}</strong></div>
              <div>物理坐标: {{ selectedPeer.coord.lat.toFixed(2) }}°, {{ selectedPeer.coord.lon.toFixed(2) }}°</div>
              <div>运营商/归属: {{ selectedPeer.isp }}</div>
              <div v-if="selectedPeer.process_name">关联本地进程: <span class="text-sky-700 dark:text-sky-300 font-semibold">{{ selectedPeer.process_name }}</span></div>
              <div v-if="selectedPeer.distance_km > 0">
                直线球面距离: <strong class="text-amber-700 dark:text-amber-300">{{ selectedPeer.distance_km }} km</strong>
                (理论光纤下限 {{ selectedPeer.theoretical_fiber_rtt_ms }} ms)
              </div>
              <div class="flex justify-between pt-1 text-[11px] font-semibold">
                <span class="text-emerald-700 dark:text-emerald-400">收: {{ formatBytes(selectedPeer.inbound_bytes) }} ({{ selectedPeer.inbound_packets }} pkt)</span>
                <span class="text-sky-700 dark:text-cyan-400">发: {{ formatBytes(selectedPeer.outbound_bytes) }} ({{ selectedPeer.outbound_packets }} pkt)</span>
              </div>
            </div>
            <button
              @click="startTracerouteToIp(selectedPeer.ip)"
              :disabled="isTracing"
              class="w-full ui-btn-primary justify-center py-2 px-3 rounded-xl text-xs"
            >
              <AppIcon name="radar" :size="14" />
              <span>{{ isTracing && tracerouteTargetIp === selectedPeer.ip ? '正在追踪路由中转跳数...' : '追踪该 IP 到本机经历了多少次路由中转' }}</span>
            </button>
          </div>

          <!-- 过滤框 -->
          <div class="flex items-center justify-between text-[11px] select-none" style="color: var(--text-muted)">
            <span>按总流量降序 (点击 IP 定位与追踪)</span>
            <label class="flex items-center gap-1.5 cursor-pointer font-medium" style="color: var(--text-secondary)">
              <input type="checkbox" v-model="hidePrivateIps" class="rounded accent-sky-500" />
              <span>仅看公网 IP</span>
            </label>
          </div>

          <!-- 对端 IP 列表 -->
          <EmptyState
            v-if="filteredPeerNodes.length === 0"
            icon="globe"
            title="暂无已捕获的通信对端 IP"
            description="开启【启动网卡嗅探】后将自动解析往来数据包对端 IP；或点击【探测本机当前外联】获取活跃 Socket。"
          />

          <div v-else class="space-y-1.5">
            <div
              v-for="peer in filteredPeerNodes"
              :key="peer.ip"
              @click="selectPeerAndFocus(peer)"
              :class="[
                'ui-sub-card p-2.5 transition-colors cursor-pointer text-xs ui-num',
                selectedPeer?.ip === peer.ip
                  ? '!border-sky-500/60 bg-sky-500/12'
                  : peer.is_threat
                  ? '!border-rose-500/50 bg-rose-500/10'
                  : 'hover:border-sky-500/40'
              ]"
            >
              <div class="flex items-center justify-between gap-2">
                <span class="font-bold flex items-center gap-1.5 truncate" :class="peer.is_threat ? 'text-rose-700 dark:text-rose-300' : ''" :style="!peer.is_threat ? { color: 'var(--text-primary)' } : undefined">
                  <span class="w-1.5 h-1.5 rounded-full shrink-0" :class="peer.is_private ? 'bg-slate-400' : (peer.is_threat ? 'bg-rose-500' : 'bg-sky-500')"></span>
                  {{ peer.ip }}
                </span>
                <div class="flex items-center gap-1 shrink-0">
                  <span class="text-[11px] px-1.5 py-0.5 rounded ui-pill">
                    {{ peer.primary_protocol }}
                  </span>
                  <button @click.stop="addGeoPeerToDiffQueue(peer)"
                    class="px-1.5 py-0.5 rounded bg-emerald-500/12 hover:bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border border-emerald-500/25 text-[11px] font-semibold cursor-pointer"
                    title="加入全局多组IP特征比对队列">
                    +入队
                  </button>
                </div>
              </div>
              <div class="text-[11px] mt-1 flex items-center justify-between gap-2" style="color: var(--text-secondary)">
                <span class="truncate">{{ peer.geo_label }}</span>
                <span v-if="peer.distance_km > 0" class="shrink-0" style="color: var(--text-muted)">{{ peer.distance_km }} km</span>
              </div>
              <div class="text-[11px] mt-1 flex items-center justify-between gap-2" style="color: var(--text-muted)">
                <span class="truncate">{{ peer.process_name || peer.isp }}</span>
                <span class="text-emerald-700 dark:text-emerald-400 font-semibold shrink-0">
                  ↓{{ formatBytes(peer.inbound_bytes) }} / ↑{{ formatBytes(peer.outbound_bytes) }}
                </span>
              </div>
            </div>
          </div>
        </div>

        <!-- TAB 2: 硬核逐跳路由中转全路径分析面板 (Traceroute Hop-by-Hop) -->
        <div v-else-if="activeSideTab === 'traceroute'" class="flex-1 overflow-y-auto custom-scrollbar p-3.5 space-y-3 select-text">
          <EmptyState
            v-if="tracerouteHops.length === 0 && !isTracing"
            icon="radar"
            title="尚未执行路由中转路径探测"
            description="点击地图上任意通信节点、在列表中选定对端或输入公网 IP，即可实时探测沿途各跳路由器。"
          />

          <!-- 追踪报告总结卡片 -->
          <div v-else class="space-y-3">
            <div class="ui-sub-card p-3 border-amber-500/40 bg-amber-500/8 space-y-2 text-xs ui-num">
              <div class="flex items-center justify-between border-b pb-1.5" style="border-color: var(--border-subtle)">
                <span class="font-bold text-amber-700 dark:text-amber-300">追踪目标: {{ tracerouteTargetIp }}</span>
                <span v-if="isTracing" class="text-[11px] px-2 py-0.5 rounded-full bg-amber-500/18 text-amber-700 dark:text-amber-300 font-semibold">
                  探测进行中...
                </span>
                <span v-else-if="tracerouteReport?.is_completed" class="text-[11px] px-2 py-0.5 rounded-full bg-emerald-500/18 text-emerald-700 dark:text-emerald-300 font-bold">
                  已抵达终点
                </span>
                <span v-else class="text-[11px] px-2 py-0.5 rounded-full ui-pill">
                  部分跳点被屏蔽
                </span>
              </div>

              <div class="grid grid-cols-2 gap-2 pt-0.5">
                <div class="p-2 rounded-xl border" style="background: var(--surface-content); border-color: var(--border-subtle)">
                  <div class="text-[11px]" style="color: var(--text-muted)">总计经历路由中转</div>
                  <div class="text-base font-bold text-amber-700 dark:text-amber-300 mt-0.5">{{ maxHopNumber }} <span class="text-xs font-normal">次跳数 (Hops)</span></div>
                </div>
                <div class="p-2 rounded-xl border" style="background: var(--surface-content); border-color: var(--border-subtle)">
                  <div class="text-[11px]" style="color: var(--text-muted)">累计跨距 / 实测 RTT</div>
                  <div class="text-xs font-bold text-sky-700 dark:text-cyan-300 mt-1">
                    {{ totalTraceDistanceKm.toFixed(0) }} km · {{ endToEndRttText }}
                  </div>
                </div>
              </div>

              <div v-if="tracerouteReport?.summary" class="text-[11px] leading-relaxed pt-1" style="color: var(--text-secondary)">
                {{ tracerouteReport.summary }}
              </div>
            </div>

            <!-- 逐跳垂直路由时间轴 (Hop 0 -> Hop N) -->
            <div class="space-y-1.5">
              <div class="text-[11px] font-bold flex items-center justify-between gap-2" style="color: var(--text-secondary)">
                <span>逐跳中转路径剖析 (Hop-by-Hop)</span>
                <div class="flex items-center gap-1.5">
                  <span class="ui-num" style="color: var(--text-muted)">共 {{ tracerouteHops.length }} 跳</span>
                  <button v-if="tracerouteHops.length > 0" @click="addTracerouteToDiffQueue"
                    class="px-2 py-0.5 rounded bg-emerald-500/12 hover:bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border border-emerald-500/25 text-[11px] font-semibold cursor-pointer"
                    title="将该完整多跳路径序列纳入全局多组路径比对队列">
                    + 整条路径入队
                  </button>
                </div>
              </div>

              <div class="relative pl-4 space-y-2 before:content-[''] before:absolute before:left-1.5 before:top-2 before:bottom-2 before:w-0.5" :class="isDarkTheme ? 'before:bg-slate-700' : 'before:bg-slate-300'">
                <div
                  v-for="hop in tracerouteHops"
                  :key="hop.hop"
                  @click="focusHopOnGlobe(hop)"
                  class="relative ui-sub-card p-2.5 transition-colors cursor-pointer text-xs ui-num"
                  :class="[
                    hop.is_self
                      ? '!border-emerald-500/45 bg-emerald-500/10'
                      : hop.is_timeout
                      ? 'opacity-65'
                      : hop.hop === maxHopNumber && tracerouteReport?.is_completed
                      ? '!border-sky-500/50 bg-sky-500/10'
                      : 'hover:border-amber-500/50'
                  ]"
                >
                  <!-- 左侧时间轴圆点 -->
                  <span
                    class="absolute -left-[15px] top-3.5 w-2.5 h-2.5 rounded-full border-2"
                    :class="hop.is_self ? 'bg-emerald-500' : hop.is_timeout ? 'bg-slate-400' : 'bg-amber-500'"
                    :style="{ borderColor: 'var(--surface-content)' }"
                  ></span>

                  <div class="flex items-center justify-between gap-2">
                    <div class="flex items-center gap-1.5 min-w-0">
                      <span class="px-1.5 py-0.5 rounded ui-pill text-amber-700 dark:text-amber-300 font-bold text-[11px] shrink-0">
                        #{{ hop.hop }}
                      </span>
                      <span class="font-bold truncate" style="color: var(--text-primary)">
                        {{ hop.is_timeout ? '* * * (请求超时 / 防火墙屏蔽)' : hop.ip }}
                      </span>
                    </div>
                    <span
                      v-if="!hop.is_timeout"
                      class="text-[11px] font-bold shrink-0"
                      :class="(hop.rtt_ms || 0) > 120 ? 'text-rose-700 dark:text-rose-400' : (hop.rtt_ms || 0) > 40 ? 'text-amber-700 dark:text-amber-300' : 'text-emerald-700 dark:text-emerald-400'"
                    >
                      {{ hop.rtt_ms !== null ? hop.rtt_ms + ' ms' : '<1 ms' }}
                    </span>
                  </div>

                  <div v-if="!hop.is_timeout" class="text-[11px] mt-1 flex items-center justify-between gap-2" style="color: var(--text-secondary)">
                    <span class="truncate">
                      {{ hop.is_lan ? (hop.lan_role || '内网设备') : `${hop.country} ${hop.province} ${hop.city}`.trim() || '公网路由节点' }}
                    </span>
                    <span class="truncate max-w-28 shrink-0" style="color: var(--text-muted)">{{ hop.isp }}</span>
                  </div>

                  <div v-if="!hop.is_timeout && hop.cumulative_distance_km > 0" class="text-[11px] mt-0.5 flex justify-between" style="color: var(--text-muted)">
                    <span>累计距本机: {{ hop.cumulative_distance_km.toFixed(1) }} km</span>
                    <span>理论光纤 RTT: {{ hop.theoretical_fiber_rtt_ms }} ms</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

      </aside>
    </div>

    <!-- 侧栏折叠时的唤起浮动胶囊 (Liquid Glass) -->
    <button
      v-if="isSidebarCollapsed"
      @click="isSidebarCollapsed = false"
      class="absolute top-14 right-4 z-20 px-3 py-1.5 rounded-xl ui-nav-glass border text-xs font-semibold shadow-md transition-colors cursor-pointer flex items-center gap-1.5"
      style="color: var(--accent-primary-text)"
    >
      <AppIcon name="chevron-left" :size="13" />
      <span>展开通讯清单与路由分析</span>
    </button>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import AppIcon from '../components/AppIcon.vue';
import EmptyState from '../components/EmptyState.vue';
import { useUniversalDiff } from '../composables/useUniversalDiff';

const diffBus = useUniversalDiff();

function addGeoPeerToDiffQueue(peer: RealPeerGeoNode) {
  const summary = `IP=${peer.ip}|GEO=${peer.geo_label}|ISP=${peer.isp}|PROTO=${peer.primary_protocol}|DIST=${peer.distance_km}km|IN=${peer.inbound_bytes}B|OUT=${peer.outbound_bytes}B`;
  diffBus.addToQueue({
    id: `GEO_${peer.ip}`,
    label: `[地理节点] ${peer.ip}`,
    protocol: peer.primary_protocol || 'GEO-PEER',
    src: '本机探测点',
    dst: peer.ip,
    format: 'ASCII',
    isRawText: true,
    payloadHex: '',
    rawText: summary,
    length: summary.length,
    extraFields: {
      geo_label: peer.geo_label,
      isp: peer.isp,
      distance_km: String(peer.distance_km),
      fiber_rtt_ms: String(peer.theoretical_fiber_rtt_ms),
      is_threat: String(peer.is_threat),
      process_name: peer.process_name || '-'
    }
  }, `节点 ${peer.ip}`, false);
}

function addTracerouteToDiffQueue() {
  if (tracerouteHops.value.length === 0) return;
  const hopsText = tracerouteHops.value
    .map(h => `#${h.hop} ${h.is_timeout ? '* * *' : h.ip} (${h.rtt_ms !== null ? h.rtt_ms + 'ms' : '-'}) ${h.isp || ''}`)
    .join('\n');
  diffBus.addToQueue({
    id: `TRACE_${tracerouteTargetIp.value}_${Date.now()}`,
    label: `[路由轨迹] ➔ ${tracerouteTargetIp.value} (${tracerouteHops.value.length}跳)`,
    protocol: 'TRACEROUTE',
    src: 'Local-Gateway',
    dst: tracerouteTargetIp.value || 'Target',
    format: 'ASCII',
    isRawText: true,
    payloadHex: '',
    rawText: hopsText,
    length: hopsText.length,
    extraFields: {
      target_ip: tracerouteTargetIp.value,
      hop_count: String(tracerouteHops.value.length),
      total_distance_km: totalTraceDistanceKm.value.toFixed(1),
      end_to_end_rtt: endToEndRttText.value
    }
  }, `路由 ${tracerouteTargetIp.value}`, false);
}
import {
  HIGH_RES_WORLD_POLYGONS,
  REAL_SUBMARINE_CABLES,
  interpolateGreatCircle,
  type GeoCoord,
} from '../data/worldGeoData';

const isDarkTheme = ref(!document.documentElement.classList.contains('theme-apple-light'));
let themeObserver: MutationObserver | null = null;

const props = defineProps<{
  packets: any[];
  isRunning: boolean;
  isPaused?: boolean;
}>();

defineEmits<{
  (e: 'startCapture'): void;
  (e: 'stopCapture'): void;
}>();

// 数据接口类型对齐 Rust `geo_map_engine.rs` & `traceroute_engine.rs`
interface PeerTrafficInput {
  ip: string;
  inbound_bytes: number;
  outbound_bytes: number;
  inbound_packets: number;
  outbound_packets: number;
  primary_protocol: string;
  is_threat: boolean;
  process_name?: string | null;
}

interface RealPeerGeoNode {
  ip: string;
  is_self: boolean;
  is_private: boolean;
  has_geo: boolean;
  country: string;
  province: string;
  city: string;
  isp: string;
  geo_label: string;
  coord: GeoCoord;
  inbound_bytes: number;
  outbound_bytes: number;
  inbound_packets: number;
  outbound_packets: number;
  primary_protocol: string;
  distance_km: number;
  theoretical_fiber_rtt_ms: number;
  waypoints: GeoCoord[];
  is_threat: boolean;
  process_name?: string | null;
}

interface SolarTerminatorData {
  solar_declination_deg: number;
  subsolar_longitude_deg: number;
  terminator_points: GeoCoord[];
  utc_timestamp: string;
}

interface RealTrafficGeoDataset {
  data_source: string;
  self_node: RealPeerGeoNode;
  peer_nodes: RealPeerGeoNode[];
  terminator: SolarTerminatorData;
  total_inbound_bytes: number;
  total_outbound_bytes: number;
  total_packets: number;
  threat_count: number;
}

interface GeoCoordinates {
  latitude: number;
  longitude: number;
  country: string;
  province: string;
  city: string;
  label: string;
}

interface TracerouteHop {
  hop: number;
  ip: string;
  rtt_ms: number | null;
  is_timeout: boolean;
  geo: GeoCoordinates | null;
  country: string;
  province: string;
  city: string;
  isp: string;
  zone_name: string;
  cumulative_distance_km: number;
  theoretical_fiber_rtt_ms: number;
  is_self: boolean;
  is_lan: boolean;
  lan_role?: string | null;
  subnet_cidr?: string | null;
}

interface TracerouteReport {
  target: string;
  target_ip: string;
  is_completed: boolean;
  total_hops: number;
  end_to_end_rtt_ms: number | null;
  total_distance_km: number;
  hops: TracerouteHop[];
  summary: string;
}

const mapContainerRef = ref<HTMLDivElement | null>(null);
const mapCanvasRef = ref<HTMLCanvasElement | null>(null);

const projectionMode = ref<'3d' | '2d'>('3d');
const autoRotate = ref(false); // 真实测绘场景下默认不乱转，方便精确观察对端 IP 位置，可手动打开
const isSidebarCollapsed = ref(false);
const activeSideTab = ref<'peers' | 'traceroute'>('peers');
const hidePrivateIps = ref(true);

const layers = ref({
  terminator: true,
  cables: true,
  graticules: true,
});

// 真实空间数据源状态
const dataSource = ref<'STANDBY' | 'LIVE_SNIFFER' | 'OS_SOCKETS'>('STANDBY');
const selfNode = ref<RealPeerGeoNode | null>(null);
const peerNodes = ref<RealPeerGeoNode[]>([]);
const solarTerminator = ref<SolarTerminatorData | null>(null);
const totalInboundBytes = ref(0);
const totalOutboundBytes = ref(0);
const loadingOsSockets = ref(false);

const selectedPeer = ref<RealPeerGeoNode | null>(null);
const hoveredCanvasItem = ref<
  | { kind: 'peer'; node: RealPeerGeoNode }
  | { kind: 'hop'; hop: TracerouteHop }
  | null
>(null);
const tooltipPos = ref({ x: 0, y: 0 });

// 路由追踪状态 (Traceroute Hop-by-Hop)
const manualTargetIp = ref('');
const isTracing = ref(false);
const tracerouteTargetIp = ref('');
const tracerouteHops = ref<TracerouteHop[]>([]);
const tracerouteReport = ref<TracerouteReport | null>(null);
let unlistenTraceroute: UnlistenFn | null = null;

// 视口相机状态 (默认面向中国东亚区域)
const centerLat = ref(28.0);
const centerLon = ref(112.0);
const scale = ref(1.0);

let isDragging = false;
let dragMoved = false;
let lastMousePos = { x: 0, y: 0 };
let animationFrameId: number | null = null;
let animPhase = 0;

// 工具：判断 IPv4 是否为内网私有/回环地址
function isPrivateOrLocalIp(ip: string): boolean {
  if (!ip) return true;
  if (ip === '127.0.0.1' || ip === '0.0.0.0' || ip === 'localhost' || ip.includes(':')) return true;
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(isNaN)) return true;
  if (parts[0] === 10) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  if (parts[0] === 169 && parts[1] === 254) return true;
  if (parts[0] === 224 || parts[0] >= 240) return true; // 组播/广播保留段
  return false;
}

const mappedPeerCount = computed(() => peerNodes.value.filter(n => n.has_geo).length);

const filteredPeerNodes = computed(() => {
  if (!hidePrivateIps.value) return peerNodes.value;
  return peerNodes.value.filter(n => !n.is_private);
});

const maxHopNumber = computed(() => {
  if (tracerouteHops.value.length === 0) return 0;
  return tracerouteHops.value[tracerouteHops.value.length - 1].hop;
});

const totalTraceDistanceKm = computed(() => {
  if (tracerouteHops.value.length === 0) return 0;
  for (let i = tracerouteHops.value.length - 1; i >= 0; i--) {
    if (tracerouteHops.value[i].cumulative_distance_km > 0) {
      return tracerouteHops.value[i].cumulative_distance_km;
    }
  }
  return 0;
});

const endToEndRttText = computed(() => {
  if (tracerouteReport.value?.end_to_end_rtt_ms !== null && tracerouteReport.value?.end_to_end_rtt_ms !== undefined) {
    return `${tracerouteReport.value.end_to_end_rtt_ms} ms`;
  }
  for (let i = tracerouteHops.value.length - 1; i >= 0; i--) {
    const rtt = tracerouteHops.value[i].rtt_ms;
    if (rtt !== null && rtt !== undefined) {
      return `${rtt} ms`;
    }
  }
  return '-- ms';
});

// 预先计算当前路由追踪多跳大圆线段 (带有效地理坐标的跳点连线)
const tracerouteSegments = computed(() => {
  const validGeoHops = tracerouteHops.value.filter(h => h.geo !== null && !h.is_timeout);
  const segs: {
    fromHop: TracerouteHop;
    toHop: TracerouteHop;
    waypoints: GeoCoord[];
  }[] = [];

  for (let i = 0; i < validGeoHops.length - 1; i++) {
    const h1 = validGeoHops[i];
    const h2 = validGeoHops[i + 1];
    if (h1.geo && h2.geo) {
      const c1 = { lat: h1.geo.latitude, lon: h1.geo.longitude };
      const c2 = { lat: h2.geo.latitude, lon: h2.geo.longitude };
      const waypoints = interpolateGreatCircle(c1, c2, 20);
      segs.push({ fromHop: h1, toHop: h2, waypoints });
    }
  }
  return segs;
});

// 离线太阳晨昏线物理算法 (用于纯浏览器/待机回退时保底绘制准确昼夜边界)
function calculateLocalSolarTerminator(): SolarTerminatorData {
  const now = new Date();
  const startOfYear = new Date(Date.UTC(now.getUTCFullYear(), 0, 1));
  const dayOfYear = Math.floor((now.getTime() - startOfYear.getTime()) / (24 * 60 * 60 * 1000));
  const hourFrac = now.getUTCHours() + now.getUTCMinutes() / 60 + now.getUTCSeconds() / 3600;
  const declinationDeg = -23.44 * Math.cos(((2 * Math.PI) / 365.25) * (dayOfYear + 10));
  const declinationRad = (declinationDeg * Math.PI) / 180;
  let subsolarLon = -(hourFrac - 12.0) * 15.0;
  while (subsolarLon > 180) subsolarLon -= 360;
  while (subsolarLon < -180) subsolarLon += 360;

  const points: GeoCoord[] = [];
  const tanDelta = Math.tan(declinationRad);
  const safeTanDelta = Math.abs(tanDelta) < 1e-6 ? (tanDelta >= 0 ? 1e-6 : -1e-6) : tanDelta;
  for (let i = 0; i <= 72; i++) {
    const lon = -180 + i * 5;
    const lonRad = ((lon - subsolarLon) * Math.PI) / 180;
    const latDeg = Math.max(-85, Math.min(85, (Math.atan(-Math.cos(lonRad) / safeTanDelta) * 180) / Math.PI));
    points.push({ lat: Math.round(latDeg * 100) / 100, lon });
  }
  return {
    solar_declination_deg: Math.round(declinationDeg * 10) / 10,
    subsolar_longitude_deg: Math.round(subsolarLon * 10) / 10,
    terminator_points: points,
    utc_timestamp: now.toISOString(),
  };
}

// 核心函数 1：从全局真实抓包数据包汇聚所有双向通信 IP，发送至 Rust 批量解析地球坐标
let syncTimer: number | null = null;
async function syncRealTrafficFromPackets() {
  const realPackets = props.packets || [];

  if (realPackets.length === 0) {
    // 如果未处于 OS_SOCKETS 主动快照模式，严格保持零数据待机态
    if (dataSource.value !== 'OS_SOCKETS') {
      await initStandbySelfAnchor();
    }
    return;
  }

  // 从真实数据包中汇总对端 IP 的双向入站/出站流量统计
  const peerAgg = new Map<string, PeerTrafficInput>();

  for (const pkt of realPackets) {
    const srcIp = (pkt.src_ip || '').trim();
    const dstIp = (pkt.dst_ip || '').trim();
    const len = Number(pkt.length || 64);
    const proto = String(pkt.protocol || pkt.transport || 'IP');
    const isThreat = pkt.entropy_level === 'critical' || pkt.direction === 'HONEYPOT_RECV';

    const srcPriv = isPrivateOrLocalIp(srcIp);
    const dstPriv = isPrivateOrLocalIp(dstIp);

    // 1) 本机发往外部对端 (Outbound)
    if (srcPriv && !dstPriv) {
      let entry = peerAgg.get(dstIp);
      if (!entry) {
        entry = {
          ip: dstIp,
          inbound_bytes: 0,
          outbound_bytes: 0,
          inbound_packets: 0,
          outbound_packets: 0,
          primary_protocol: proto,
          is_threat: false,
        };
        peerAgg.set(dstIp, entry);
      }
      entry.outbound_bytes += len;
      entry.outbound_packets += 1;
      if (isThreat) entry.is_threat = true;
    }
    // 2) 外部对端发往本机 (Inbound)
    else if (!srcPriv && dstPriv) {
      let entry = peerAgg.get(srcIp);
      if (!entry) {
        entry = {
          ip: srcIp,
          inbound_bytes: 0,
          outbound_bytes: 0,
          inbound_packets: 0,
          outbound_packets: 0,
          primary_protocol: proto,
          is_threat: false,
        };
        peerAgg.set(srcIp, entry);
      }
      entry.inbound_bytes += len;
      entry.inbound_packets += 1;
      if (isThreat) entry.is_threat = true;
    }
    // 3) 若两方均为公网或抓包口旁路双向公网流
    else if (!srcPriv && !dstPriv) {
      for (const pubIp of [srcIp, dstIp]) {
        let entry = peerAgg.get(pubIp);
        if (!entry) {
          entry = {
            ip: pubIp,
            inbound_bytes: 0,
            outbound_bytes: 0,
            inbound_packets: 0,
            outbound_packets: 0,
            primary_protocol: proto,
            is_threat: false,
          };
          peerAgg.set(pubIp, entry);
        }
        if (pubIp === srcIp) {
          entry.inbound_bytes += len;
          entry.inbound_packets += 1;
        } else {
          entry.outbound_bytes += len;
          entry.outbound_packets += 1;
        }
        if (isThreat) entry.is_threat = true;
      }
    }
  }

  const inputs = Array.from(peerAgg.values());
  if (inputs.length === 0) {
    if (dataSource.value !== 'OS_SOCKETS') {
      await initStandbySelfAnchor();
    }
    return;
  }

  try {
    const res = await invoke<RealTrafficGeoDataset>('resolve_real_traffic_geo_cmd', { peers: inputs });
    applyDataset(res);
  } catch (err) {
    console.warn('调用后端解析真实抓包地理分布失败:', err);
  }
}

async function initStandbySelfAnchor() {
  try {
    const res = await invoke<RealTrafficGeoDataset>('resolve_real_traffic_geo_cmd', { peers: [] });
    applyDataset(res);
  } catch {
    // 非 Tauri 纯前端预览环境下，仅显示真实待机空基准与本地太阳算法
    dataSource.value = 'STANDBY';
    solarTerminator.value = calculateLocalSolarTerminator();
    selfNode.value = {
      ip: '127.0.0.1',
      is_self: true,
      is_private: true,
      has_geo: true,
      country: '中国',
      province: '',
      city: '本机探测终端',
      isp: '本地网络适配器',
      geo_label: '本机源端 (待机预览)',
      coord: { lat: 22.5431, lon: 114.0579 },
      inbound_bytes: 0,
      outbound_bytes: 0,
      inbound_packets: 0,
      outbound_packets: 0,
      primary_protocol: 'HOST',
      distance_km: 0,
      theoretical_fiber_rtt_ms: 0,
      waypoints: [],
      is_threat: false,
    };
    peerNodes.value = [];
    totalInboundBytes.value = 0;
    totalOutboundBytes.value = 0;
  }
}

// 核心函数 2：探测系统当前真实活动 TCP 外联 Socket（免抓包亦可查看本机真实对外连接）
async function probeOsSockets() {
  loadingOsSockets.value = true;
  try {
    const res = await invoke<RealTrafficGeoDataset>('probe_active_os_sockets_cmd');
    applyDataset(res);
    activeSideTab.value = 'peers';
  } catch (err) {
    console.warn('探测 OS 活动 Socket 失败 (仅桌面 Tauri 客户端可执行底层 netstat):', err);
  } finally {
    loadingOsSockets.value = false;
  }
}

function applyDataset(res: RealTrafficGeoDataset) {
  dataSource.value = res.data_source as any;
  selfNode.value = res.self_node;
  peerNodes.value = res.peer_nodes;
  solarTerminator.value = res.terminator;
  totalInboundBytes.value = res.total_inbound_bytes;
  totalOutboundBytes.value = res.total_outbound_bytes;
}

// 核心函数 3：硬核多跳路由中转追踪引擎 (`start_traceroute_cmd` + 流式监听 `traceroute-hop-event`)
async function startTracerouteToIp(targetIp: string) {
  const cleanTarget = targetIp.trim();
  if (!cleanTarget) return;

  tracerouteTargetIp.value = cleanTarget;
  tracerouteHops.value = [];
  tracerouteReport.value = null;
  isTracing.value = true;
  activeSideTab.value = 'traceroute';
  isSidebarCollapsed.value = false;

  try {
    const report = await invoke<TracerouteReport>('start_traceroute_cmd', {
      target: cleanTarget,
      maxHops: 30,
      timeoutMs: 900,
    });
    tracerouteReport.value = report;
    if (report && report.hops && report.hops.length > 0) {
      tracerouteHops.value = report.hops;
    }
  } catch (err) {
    console.error('路由中转追踪失败:', err);
  } finally {
    isTracing.value = false;
  }
}

function handleManualTrace() {
  const t = manualTargetIp.value.trim();
  if (!t) return;
  startTracerouteToIp(t);
}

function selectPeerAndFocus(peer: RealPeerGeoNode) {
  selectedPeer.value = peer;
  if (peer.has_geo) {
    // 聚焦到本机与目标节点的中间地理视图，清晰呈现完整航路
    if (selfNode.value) {
      centerLat.value = (selfNode.value.coord.lat + peer.coord.lat) / 2;
      centerLon.value = (selfNode.value.coord.lon + peer.coord.lon) / 2;
      scale.value = peer.distance_km > 6000 ? 1.05 : peer.distance_km > 2000 ? 1.35 : 1.8;
    } else {
      centerLat.value = peer.coord.lat;
      centerLon.value = peer.coord.lon;
      scale.value = 1.6;
    }
  }
}

function focusHopOnGlobe(hop: TracerouteHop) {
  if (hop.geo) {
    centerLat.value = hop.geo.latitude;
    centerLon.value = hop.geo.longitude;
    scale.value = Math.max(1.5, scale.value);
  }
}

function setProjection(mode: '3d' | '2d') {
  projectionMode.value = mode;
  resetViewport();
}

function resetViewport() {
  if (selfNode.value) {
    centerLat.value = selfNode.value.coord.lat;
    centerLon.value = selfNode.value.coord.lon;
  } else {
    centerLat.value = 28.0;
    centerLon.value = 112.0;
  }
  scale.value = 1.0;
}

function handleMouseDown(e: MouseEvent) {
  isDragging = true;
  dragMoved = false;
  lastMousePos = { x: e.clientX, y: e.clientY };
}

function handleMouseMove(e: MouseEvent) {
  if (isDragging) {
    const dx = e.clientX - lastMousePos.x;
    const dy = e.clientY - lastMousePos.y;
    if (Math.hypot(dx, dy) > 2) dragMoved = true;
    lastMousePos = { x: e.clientX, y: e.clientY };

    const sensitivity = (projectionMode.value === '3d' ? 0.32 : 0.42) / scale.value;
    centerLon.value -= dx * sensitivity;
    centerLat.value += dy * sensitivity;
    centerLat.value = Math.max(-85, Math.min(85, centerLat.value));
    while (centerLon.value > 180) centerLon.value -= 360;
    while (centerLon.value < -180) centerLon.value += 360;
  } else {
    checkCanvasHover(e);
  }
}

function handleMouseUp(_e: MouseEvent) {
  if (!dragMoved && hoveredCanvasItem.value) {
    if (hoveredCanvasItem.value.kind === 'peer') {
      selectPeerAndFocus(hoveredCanvasItem.value.node);
      activeSideTab.value = 'peers';
      isSidebarCollapsed.value = false;
    } else if (hoveredCanvasItem.value.kind === 'hop') {
      focusHopOnGlobe(hoveredCanvasItem.value.hop);
    }
  }
  isDragging = false;
}

function handleWheel(e: WheelEvent) {
  const zoomFactor = e.deltaY < 0 ? 1.15 : 0.85;
  scale.value = Math.max(0.6, Math.min(5.5, scale.value * zoomFactor));
}

function checkCanvasHover(e: MouseEvent) {
  const canvas = mapCanvasRef.value;
  if (!canvas) return;
  const rect = canvas.getBoundingClientRect();
  const mx = e.clientX - rect.left;
  const my = e.clientY - rect.top;

  // 1. 优先命中路由中转跳点
  for (const hop of tracerouteHops.value) {
    if (hop.geo && !hop.is_timeout) {
      const pt = project(hop.geo.latitude, hop.geo.longitude, canvas.width, canvas.height);
      if (pt.visible && Math.hypot(pt.x - mx, pt.y - my) < 12) {
        hoveredCanvasItem.value = { kind: 'hop', hop };
        tooltipPos.value = { x: e.clientX, y: e.clientY };
        return;
      }
    }
  }

  // 2. 命中通讯对端 IP 节点
  for (const peer of peerNodes.value) {
    if (!peer.has_geo) continue;
    const pt = project(peer.coord.lat, peer.coord.lon, canvas.width, canvas.height);
    if (pt.visible && Math.hypot(pt.x - mx, pt.y - my) < 13) {
      hoveredCanvasItem.value = { kind: 'peer', node: peer };
      tooltipPos.value = { x: e.clientX, y: e.clientY };
      return;
    }
  }

  // 3. 命中本机源端锚点
  if (selfNode.value) {
    const pt = project(selfNode.value.coord.lat, selfNode.value.coord.lon, canvas.width, canvas.height);
    if (pt.visible && Math.hypot(pt.x - mx, pt.y - my) < 15) {
      hoveredCanvasItem.value = { kind: 'peer', node: selfNode.value };
      tooltipPos.value = { x: e.clientX, y: e.clientY };
      return;
    }
  }

  hoveredCanvasItem.value = null;
}

// 核心地理投影数学函数 (3D 正射投影 / 2D 等角全景)
function project(lat: number, lon: number, w: number, h: number): { x: number; y: number; visible: boolean } {
  if (projectionMode.value === '3d') {
    const phi = (lat * Math.PI) / 180;
    const lambda = (lon * Math.PI) / 180;
    const phi0 = (centerLat.value * Math.PI) / 180;
    const lambda0 = (centerLon.value * Math.PI) / 180;

    const cosC = Math.sin(phi0) * Math.sin(phi) + Math.cos(phi0) * Math.cos(phi) * Math.cos(lambda - lambda0);
    const visible = cosC > 0.02;

    const r = Math.min(w, h) * 0.44 * scale.value;
    const x = w / 2 + r * Math.cos(phi) * Math.sin(lambda - lambda0);
    const y = h / 2 - r * (Math.cos(phi0) * Math.sin(phi) - Math.sin(phi0) * Math.cos(phi) * Math.cos(lambda - lambda0));
    return { x, y, visible };
  } else {
    let dLon = lon - centerLon.value;
    while (dLon > 180) dLon -= 360;
    while (dLon < -180) dLon += 360;
    const rX = (w / 360) * scale.value;
    const rY = (h / 180) * scale.value;
    const x = w / 2 + dLon * rX;
    const y = h / 2 - (lat - centerLat.value) * rY;
    const visible = x >= -60 && x <= w + 60 && y >= -60 && y <= h + 60;
    return { x, y, visible };
  }
}

// =========================================================================
// 渲染引擎分层绘制子函数 (高内聚、零冗余)
// =========================================================================
function drawGlobeAtmosphere(ctx: CanvasRenderingContext2D, w: number, h: number) {
  if (projectionMode.value !== '3d') return;
  const dark = isDarkTheme.value;
  const cx = w / 2;
  const cy = h / 2;
  const r = Math.min(w, h) * 0.44 * scale.value;

  const atmosphericGlow = ctx.createRadialGradient(cx, cy, r * 0.94, cx, cy, r * 1.22);
  atmosphericGlow.addColorStop(0, dark ? 'rgba(56, 189, 248, 0.28)' : 'rgba(14, 165, 233, 0.22)');
  atmosphericGlow.addColorStop(0.4, dark ? 'rgba(99, 102, 241, 0.14)' : 'rgba(59, 130, 246, 0.08)');
  atmosphericGlow.addColorStop(1, 'rgba(0, 0, 0, 0)');
  ctx.fillStyle = atmosphericGlow;
  ctx.beginPath();
  ctx.arc(cx, cy, r * 1.24, 0, Math.PI * 2);
  ctx.fill();

  const sphereGrad = ctx.createRadialGradient(cx - r * 0.3, cy - r * 0.35, r * 0.05, cx, cy, r);
  if (dark) {
    sphereGrad.addColorStop(0, '#0c1527');
    sphereGrad.addColorStop(0.7, '#070d19');
    sphereGrad.addColorStop(1, '#02050b');
  } else {
    sphereGrad.addColorStop(0, '#d8ecfc');
    sphereGrad.addColorStop(0.7, '#badbf7');
    sphereGrad.addColorStop(1, '#9ac4ec');
  }
  ctx.fillStyle = sphereGrad;
  ctx.beginPath();
  ctx.arc(cx, cy, r, 0, Math.PI * 2);
  ctx.fill();
  ctx.strokeStyle = dark ? 'rgba(56, 189, 248, 0.4)' : 'rgba(14, 116, 144, 0.38)';
  ctx.lineWidth = 1.2;
  ctx.stroke();

  ctx.strokeStyle = dark ? 'rgba(148, 163, 184, 0.16)' : 'rgba(15, 23, 42, 0.14)';
  ctx.lineWidth = 1;
  ctx.setLineDash([4, 6]);
  ctx.beginPath();
  ctx.arc(cx, cy, r * 1.07, 0, Math.PI * 2);
  ctx.stroke();
  ctx.setLineDash([]);
}

function drawLineSafe(ctx: CanvasRenderingContext2D, pts: GeoCoord[], w: number, h: number) {
  ctx.beginPath();
  let prevX: number | null = null;
  for (const p of pts) {
    const pt = project(p.lat, p.lon, w, h);
    if (pt.visible) {
      if (prevX === null || (projectionMode.value === '2d' && Math.abs(pt.x - prevX) > w * 0.45)) {
        ctx.moveTo(pt.x, pt.y);
      } else {
        ctx.lineTo(pt.x, pt.y);
      }
      prevX = pt.x;
    } else {
      prevX = null;
    }
  }
  ctx.stroke();
}

function drawGraticules(ctx: CanvasRenderingContext2D, w: number, h: number) {
  if (!layers.value.graticules) return;
  const dark = isDarkTheme.value;
  for (let lat = -75; lat <= 75; lat += 15) {
    ctx.strokeStyle = lat === 0
      ? (dark ? 'rgba(56, 189, 248, 0.32)' : 'rgba(2, 132, 199, 0.38)')
      : (dark ? 'rgba(148, 163, 184, 0.09)' : 'rgba(15, 23, 42, 0.08)');
    ctx.lineWidth = lat === 0 ? 1.2 : 0.8;
    const pts: GeoCoord[] = [];
    for (let lon = -180; lon <= 180; lon += 4) pts.push({ lat, lon });
    drawLineSafe(ctx, pts, w, h);
  }
  for (let lon = -180; lon < 180; lon += 15) {
    ctx.strokeStyle = lon === 0
      ? (dark ? 'rgba(99, 102, 241, 0.32)' : 'rgba(79, 70, 229, 0.32)')
      : (dark ? 'rgba(148, 163, 184, 0.09)' : 'rgba(15, 23, 42, 0.08)');
    ctx.lineWidth = lon === 0 ? 1.2 : 0.8;
    const pts: GeoCoord[] = [];
    for (let lat = -85; lat <= 85; lat += 3) pts.push({ lat, lon });
    drawLineSafe(ctx, pts, w, h);
  }
}

interface Vec3 {
  x: number;
  y: number;
  z: number;
}

function toViewVec3(lat: number, lon: number, phi0: number, lambda0: number): Vec3 {
  const phi = (lat * Math.PI) / 180;
  const lambda = (lon * Math.PI) / 180;
  const x = Math.cos(phi) * Math.sin(lambda - lambda0);
  const y = -(Math.cos(phi0) * Math.sin(phi) - Math.sin(phi0) * Math.cos(phi) * Math.cos(lambda - lambda0));
  const z = Math.sin(phi0) * Math.sin(phi) + Math.cos(phi0) * Math.cos(phi) * Math.cos(lambda - lambda0);
  return { x, y, z };
}

function intersectHorizon(a: Vec3, b: Vec3): { x: number; y: number } {
  const t = a.z / (a.z - b.z);
  const ix = a.x + t * (b.x - a.x);
  const iy = a.y + t * (b.y - a.y);
  const norm = Math.hypot(ix, iy) || 1;
  return { x: ix / norm, y: iy / norm };
}

function appendHorizonArc(outPts: { x: number; y: number }[], outAngle: number, inAngle: number, cx: number, cy: number, r: number) {
  let diff = inAngle - outAngle;
  while (diff > Math.PI) diff -= 2 * Math.PI;
  while (diff < -Math.PI) diff += 2 * Math.PI;
  const steps = Math.max(2, Math.ceil(Math.abs(diff) / 0.15));
  for (let i = 1; i < steps; i++) {
    const a = outAngle + (diff * i) / steps;
    outPts.push({ x: cx + r * Math.cos(a), y: cy + r * Math.sin(a) });
  }
}

function drawLandmasses(ctx: CanvasRenderingContext2D, w: number, h: number) {
  if (projectionMode.value === '2d') {
    const rX = (w / 360) * scale.value;
    const rY = (h / 180) * scale.value;
    for (const poly of HIGH_RES_WORLD_POLYGONS) {
      if (poly.length < 3) continue;
      // 计算连续展开经度，避免多边形内部跨越 180° 产生断裂
      const unwrappedLons: number[] = [];
      let dLon0 = poly[0][0] - centerLon.value;
      while (dLon0 > 180) dLon0 -= 360;
      while (dLon0 < -180) dLon0 += 360;
      unwrappedLons.push(dLon0);

      let minLon = dLon0;
      let maxLon = dLon0;
      for (let i = 1; i < poly.length; i++) {
        let cur = poly[i][0] - centerLon.value;
        const prev = unwrappedLons[i - 1];
        while (cur - prev > 180) cur -= 360;
        while (cur - prev < -180) cur += 360;
        unwrappedLons.push(cur);
        if (cur < minLon) minLon = cur;
        if (cur > maxLon) maxLon = cur;
      }

      // 在 [-360, 0, +360] 三个水平周期渲染，保证地图任意拖动 100% 无缝衔接
      for (const shift of [-360, 0, 360]) {
        const minX = w / 2 + (minLon + shift) * rX;
        const maxX = w / 2 + (maxLon + shift) * rX;
        if (maxX < -50 || minX > w + 50) continue;

        ctx.beginPath();
        for (let i = 0; i < poly.length; i++) {
          const x = w / 2 + (unwrappedLons[i] + shift) * rX;
          const y = h / 2 - (poly[i][1] - centerLat.value) * rY;
          if (i === 0) ctx.moveTo(x, y);
          else ctx.lineTo(x, y);
        }
        ctx.closePath();
        ctx.fillStyle = isDarkTheme.value ? 'rgba(17, 28, 47, 0.88)' : 'rgba(248, 250, 252, 0.94)';
        ctx.fill();
        ctx.strokeStyle = isDarkTheme.value ? 'rgba(56, 189, 248, 0.42)' : 'rgba(59, 130, 246, 0.38)';
        ctx.lineWidth = 1.15;
        ctx.stroke();
      }
    }
    return;
  }

  // 3D 正射球面投影：执行严格三维地平线截面裁剪 (z >= 0)，彻底消除跨洲直斜线
  const cx = w / 2;
  const cy = h / 2;
  const r = Math.min(w, h) * 0.44 * scale.value;
  const phi0 = (centerLat.value * Math.PI) / 180;
  const lambda0 = (centerLon.value * Math.PI) / 180;

  for (const poly of HIGH_RES_WORLD_POLYGONS) {
    if (poly.length < 3) continue;
    const vecs = poly.map(([lon, lat]) => toViewVec3(lat, lon, phi0, lambda0));

    const fillPts: { x: number; y: number }[] = [];
    const coastChains: { x: number; y: number }[][] = [];
    let currentChain: { x: number; y: number }[] = [];

    let lastOutAngle: number | null = null;
    let firstInAngle: number | null = null;

    for (let i = 0; i < vecs.length - 1; i++) {
      const A = vecs[i];
      const B = vecs[i + 1];
      const inA = A.z >= 0;
      const inB = B.z >= 0;

      if (inA && i === 0) {
        const pA = { x: cx + r * A.x, y: cy + r * A.y };
        fillPts.push(pA);
        currentChain.push(pA);
      }

      if (inA && inB) {
        const pB = { x: cx + r * B.x, y: cy + r * B.y };
        fillPts.push(pB);
        currentChain.push(pB);
      } else if (inA && !inB) {
        const I = intersectHorizon(A, B);
        const pI = { x: cx + r * I.x, y: cy + r * I.y };
        fillPts.push(pI);
        currentChain.push(pI);
        coastChains.push(currentChain);
        currentChain = [];
        lastOutAngle = Math.atan2(I.y, I.x);
      } else if (!inA && inB) {
        const I = intersectHorizon(A, B);
        const inAngle = Math.atan2(I.y, I.x);
        if (lastOutAngle !== null) {
          appendHorizonArc(fillPts, lastOutAngle, inAngle, cx, cy, r);
          lastOutAngle = null;
        } else if (firstInAngle === null) {
          firstInAngle = inAngle;
        }
        const pI = { x: cx + r * I.x, y: cy + r * I.y };
        const pB = { x: cx + r * B.x, y: cy + r * B.y };
        fillPts.push(pI, pB);
        currentChain = [pI, pB];
      }
    }

    if (currentChain.length > 0) {
      coastChains.push(currentChain);
    }
    if (lastOutAngle !== null && firstInAngle !== null) {
      appendHorizonArc(fillPts, lastOutAngle, firstInAngle, cx, cy, r);
    }

    // 1. 填充严谨闭合并贴合地球边缘的陆地内部
    if (fillPts.length >= 3) {
      ctx.beginPath();
      ctx.moveTo(fillPts[0].x, fillPts[0].y);
      for (let k = 1; k < fillPts.length; k++) {
        ctx.lineTo(fillPts[k].x, fillPts[k].y);
      }
      ctx.closePath();
      ctx.fillStyle = isDarkTheme.value ? 'rgba(17, 28, 47, 0.88)' : 'rgba(248, 250, 252, 0.94)';
      ctx.fill();
    }

    // 2. 仅描边真实可见的海岸线，绝不对地平线切线或跨海连线描边
    ctx.strokeStyle = isDarkTheme.value ? 'rgba(56, 189, 248, 0.44)' : 'rgba(59, 130, 246, 0.38)';
    ctx.lineWidth = 1.15;
    for (const chain of coastChains) {
      if (chain.length < 2) continue;
      ctx.beginPath();
      ctx.moveTo(chain[0].x, chain[0].y);
      for (let k = 1; k < chain.length; k++) {
        ctx.lineTo(chain[k].x, chain[k].y);
      }
      ctx.stroke();
    }
  }
}

function drawTerminatorAndCables(ctx: CanvasRenderingContext2D, w: number, h: number) {
  if (layers.value.terminator && solarTerminator.value) {
    ctx.strokeStyle = 'rgba(245, 158, 11, 0.55)';
    ctx.lineWidth = 1.2;
    ctx.setLineDash([3, 3]);
    drawLineSafe(ctx, solarTerminator.value.terminator_points, w, h);
    ctx.setLineDash([]);
  }

  if (layers.value.cables) {
    ctx.strokeStyle = 'rgba(6, 182, 212, 0.25)';
    ctx.lineWidth = 1.0;
    ctx.setLineDash([4, 4]);
    for (const cable of REAL_SUBMARINE_CABLES) {
      drawLineSafe(ctx, cable.landingPoints, w, h);
    }
    ctx.setLineDash([]);
  }
}

function drawRealPeerTrafficArcsAndNodes(ctx: CanvasRenderingContext2D, w: number, h: number) {
  // 1. 绘制所有与本机双向通讯对端的真实球面大圆飞线与双向粒子流
  for (const peer of peerNodes.value) {
    if (!peer.has_geo || peer.waypoints.length < 2) continue;

    const isSelected = selectedPeer.value?.ip === peer.ip;
    const isThreat = peer.is_threat;

    ctx.strokeStyle = isSelected
      ? 'rgba(250, 204, 21, 0.85)'
      : isThreat
      ? 'rgba(244, 63, 94, 0.75)'
      : 'rgba(56, 189, 248, 0.48)';
    ctx.lineWidth = isSelected ? 2.2 : isThreat ? 1.8 : 1.2;

    drawLineSafe(ctx, peer.waypoints, w, h);

    // 双向方向性发光光子粒子
    const nSteps = peer.waypoints.length;
    const isInboundDominant = peer.inbound_bytes > peer.outbound_bytes;
    const phaseRatio = isInboundDominant ? 1.0 - animPhase : animPhase;
    const headIdx = Math.floor(phaseRatio * (nSteps - 1));
    const wp = peer.waypoints[headIdx];
    if (wp) {
      const pt = project(wp.lat, wp.lon, w, h);
      if (pt.visible) {
        ctx.fillStyle = isThreat ? '#fb7185' : isInboundDominant ? '#34d399' : '#38bdf8';
        ctx.beginPath();
        ctx.arc(pt.x, pt.y, isSelected ? 4.2 : 3.2, 0, Math.PI * 2);
        ctx.fill();
      }
    }
  }

  // 2. 绘制通讯对端节点圆点与标签
  for (const peer of peerNodes.value) {
    if (!peer.has_geo) continue;
    const pt = project(peer.coord.lat, peer.coord.lon, w, h);
    if (!pt.visible) continue;

    const isSelected = selectedPeer.value?.ip === peer.ip;
    const isHovered = hoveredCanvasItem.value?.kind === 'peer' && hoveredCanvasItem.value.node.ip === peer.ip;

    // 声纳波纹
    const rippleR = 5 + animPhase * 12;
    const rippleAlpha = Math.max(0, 1.0 - animPhase);
    ctx.fillStyle = peer.is_threat
      ? `rgba(244, 63, 94, ${rippleAlpha * 0.45})`
      : isSelected
      ? `rgba(250, 204, 21, ${rippleAlpha * 0.5})`
      : `rgba(56, 189, 248, ${rippleAlpha * 0.35})`;
    ctx.beginPath();
    ctx.arc(pt.x, pt.y, rippleR, 0, Math.PI * 2);
    ctx.fill();

    // 节点圆点
    ctx.fillStyle = peer.is_threat ? '#f43f5e' : isSelected ? '#facc15' : '#38bdf8';
    ctx.beginPath();
    ctx.arc(pt.x, pt.y, isSelected || isHovered ? 6 : 4, 0, Math.PI * 2);
    ctx.fill();

    if (isSelected || isHovered) {
      ctx.strokeStyle = '#ffffff';
      ctx.lineWidth = 2;
      ctx.stroke();
    }

    if (scale.value >= 0.85 || isSelected || isHovered) {
      ctx.fillStyle = isDarkTheme.value
        ? (isSelected ? '#fde047' : '#e2e8f0')
        : (isSelected ? '#b45309' : '#0f172a');
      ctx.font = 'bold 11px monospace';
      const labelText = `${peer.city || peer.country} (${peer.ip})`;
      ctx.fillText(labelText, pt.x + 8, pt.y + 3);
    }
  }

  // 3. 绘制本机源端地理锚点 (绿色常亮基准锚点)
  if (selfNode.value) {
    const pt = project(selfNode.value.coord.lat, selfNode.value.coord.lon, w, h);
    if (pt.visible) {
      const rippleR = 8 + animPhase * 14;
      ctx.strokeStyle = `rgba(16, 185, 129, ${Math.max(0, 1 - animPhase) * 0.7})`;
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.arc(pt.x, pt.y, rippleR, 0, Math.PI * 2);
      ctx.stroke();

      ctx.fillStyle = '#10b981';
      ctx.beginPath();
      ctx.arc(pt.x, pt.y, 6, 0, Math.PI * 2);
      ctx.fill();
      ctx.strokeStyle = '#ffffff';
      ctx.lineWidth = 1.8;
      ctx.stroke();

      ctx.fillStyle = isDarkTheme.value ? '#34d399' : '#047857';
      ctx.font = 'bold 11px monospace';
      ctx.fillText(`本机 [${selfNode.value.city}]`, pt.x + 9, pt.y - 6);
    }
  }
}

function drawTracerouteHopPath(ctx: CanvasRenderingContext2D, w: number, h: number) {
  if (tracerouteHops.value.length === 0) return;

  // 1. 绘出连续经过多跳路由器的亮金色大圆中转弧段
  for (const seg of tracerouteSegments.value) {
    ctx.strokeStyle = 'rgba(245, 158, 11, 0.9)';
    ctx.lineWidth = 2.6;
    drawLineSafe(ctx, seg.waypoints, w, h);
  }

  // 2. 沿路由全路径接力运行中转探测光子
  const allPts: GeoCoord[] = [];
  for (const seg of tracerouteSegments.value) {
    allPts.push(...seg.waypoints);
  }
  if (allPts.length > 1) {
    const idx = Math.floor(animPhase * (allPts.length - 1));
    const wp = allPts[idx];
    if (wp) {
      const pt = project(wp.lat, wp.lon, w, h);
      if (pt.visible) {
        ctx.fillStyle = '#fef08a';
        ctx.beginPath();
        ctx.arc(pt.x, pt.y, 4.8, 0, Math.PI * 2);
        ctx.fill();
      }
    }
  }

  // 3. 聚合落在同一地理位置的多跳中转标识，防止同城标签重叠糊成一团
  const coordGroups = new Map<string, { lat: number; lon: number; hops: TracerouteHop[] }>();
  for (const hop of tracerouteHops.value) {
    if (!hop.geo || hop.is_timeout) continue;
    const key = `${hop.geo.latitude.toFixed(2)}_${hop.geo.longitude.toFixed(2)}`;
    let grp = coordGroups.get(key);
    if (!grp) {
      grp = { lat: hop.geo.latitude, lon: hop.geo.longitude, hops: [] };
      coordGroups.set(key, grp);
    }
    grp.hops.push(hop);
  }

  for (const grp of coordGroups.values()) {
    const pt = project(grp.lat, grp.lon, w, h);
    if (!pt.visible) continue;

    // 外圈醒目琥珀金光环
    ctx.fillStyle = '#f59e0b';
    ctx.beginPath();
    ctx.arc(pt.x, pt.y, 5.5, 0, Math.PI * 2);
    ctx.fill();
    ctx.strokeStyle = '#ffffff';
    ctx.lineWidth = 1.5;
    ctx.stroke();

    // 清晰写出经历了第几跳 (如 "#1~#4 深圳" 或 "#6 香港 18ms")
    const firstH = grp.hops[0];
    const lastH = grp.hops[grp.hops.length - 1];
    const hopSpan = grp.hops.length > 1 ? `#${firstH.hop}~#${lastH.hop}` : `#${firstH.hop}`;
    const cityLabel = firstH.city || firstH.country || '路由节点';
    const rttTag = lastH.rtt_ms !== null ? ` ${lastH.rtt_ms}ms` : '';

    ctx.fillStyle = isDarkTheme.value ? '#fef08a' : '#b45309';
    ctx.font = 'bold 11px monospace';
    ctx.fillText(`${hopSpan} ${cityLabel}${rttTag}`, pt.x + 8, pt.y + 12);
  }
}

function render() {
  const canvas = mapCanvasRef.value;
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  const w = canvas.width;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);

  animPhase = (animPhase + 0.014) % 1.0;

  if (projectionMode.value === '3d' && autoRotate.value && !isDragging) {
    centerLon.value = (centerLon.value + 0.03) % 360;
    if (centerLon.value > 180) centerLon.value -= 360;
  }

  drawGlobeAtmosphere(ctx, w, h);
  drawGraticules(ctx, w, h);
  drawLandmasses(ctx, w, h);
  drawTerminatorAndCables(ctx, w, h);
  drawRealPeerTrafficArcsAndNodes(ctx, w, h);
  drawTracerouteHopPath(ctx, w, h);

  animationFrameId = requestAnimationFrame(render);
}

function handleResize() {
  const container = mapContainerRef.value;
  const canvas = mapCanvasRef.value;
  if (!container || !canvas) return;
  const rect = container.getBoundingClientRect();
  canvas.width = rect.width;
  canvas.height = rect.height;
}

function formatBytes(bytes: number): string {
  if (!bytes || bytes <= 0) return '0 B';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
  return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
}

// 监听全局数据包长度变化，防抖增量刷新真实通讯地图
watch(
  () => props.packets.length,
  () => {
    if (syncTimer !== null) clearTimeout(syncTimer);
    syncTimer = window.setTimeout(() => {
      syncRealTrafficFromPackets();
    }, 600);
  }
);

watch(projectionMode, () => {
  resetViewport();
});

onMounted(async () => {
  themeObserver = new MutationObserver(() => {
    isDarkTheme.value = !document.documentElement.classList.contains('theme-apple-light');
  });
  themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });

  handleResize();
  window.addEventListener('resize', handleResize);
  await syncRealTrafficFromPackets();
  try {
    unlistenTraceroute = await listen<TracerouteHop>('traceroute-hop-event', ({ payload }) => {
      const idx = tracerouteHops.value.findIndex(h => h.hop === payload.hop);
      if (idx >= 0) tracerouteHops.value[idx] = payload;
      else tracerouteHops.value.push(payload);
    });
  } catch (err) {
    console.warn('[GlobalGeoMapView] Tauri traceroute-hop-event listener unavailable (standalone preview):', err);
  }
  render();
});

onUnmounted(() => {
  if (themeObserver) {
    themeObserver.disconnect();
    themeObserver = null;
  }
  window.removeEventListener('resize', handleResize);
  if (syncTimer !== null) clearTimeout(syncTimer);
  if (unlistenTraceroute) unlistenTraceroute();
  if (animationFrameId !== null) cancelAnimationFrame(animationFrameId);
});
</script>
