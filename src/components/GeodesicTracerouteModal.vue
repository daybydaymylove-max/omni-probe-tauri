<template>
  <div v-if="isOpen" class="fixed inset-0 z-50 flex items-center justify-center p-3 ui-modal-backdrop select-none">
    <div class="w-full max-w-7xl ui-modal-surface rounded-3xl flex flex-col overflow-hidden max-h-[96vh] animate-in fade-in zoom-in-95 duration-150">
      
      <!-- 1. 顶部状态栏与视口控制器 (Liquid Glass) -->
      <header class="ui-nav-glass border-b px-5 py-3 flex items-center justify-between shrink-0 flex-wrap gap-3">
        <div class="flex items-center gap-3">
          <div class="w-9 h-9 rounded-xl bg-sky-500/15 border border-sky-500/30 flex items-center justify-center text-sky-700 dark:text-cyan-300 shrink-0">
            <AppIcon :name="isLanTarget ? 'layers' : 'globe'" :size="18" />
          </div>
          <div>
            <div class="flex items-center gap-2 flex-wrap">
              <h3 class="text-sm font-bold tracking-tight" style="color: var(--text-primary)">
                测地线可视路由追踪与微观虚拟拓扑
              </h3>
              <span class="text-[11px] px-2 py-0.5 rounded-full bg-sky-500/12 text-sky-700 dark:text-cyan-300 border border-sky-500/25 font-medium">
                {{ isLanTarget ? 'LAN Micro-Topology Schematic' : 'Geodesic Digital Globe' }}
              </span>
              <span v-if="isTracing" class="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] ui-num bg-amber-500/12 text-amber-700 dark:text-amber-300 border border-amber-500/30 font-semibold">
                <span class="w-2 h-2 rounded-full bg-amber-500"></span>
                正在流式探测中 (Hop {{ currentHop }})...
              </span>
              <span v-else-if="hops.length > 0 && isFinished" class="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] ui-num bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30 font-semibold">
                <span class="w-2 h-2 rounded-full bg-emerald-500"></span>
                路由追踪就绪 (共 {{ hops.length }} 节点)
              </span>
            </div>
            <p class="text-[11px] mt-0.5" style="color: var(--text-muted)">
              {{ isLanTarget ? '局域网/工控网络微观拓扑架构图示 · 逐级网关与子网跃迁 · 微秒级物理排队时延' : '离线三维数字地球与等角圆柱投影 · 本机物理坐标基准锚定 · 物理光纤时延比对' }}
            </p>
          </div>
        </div>

        <!-- 右侧：3D/2D/LAN 三模切换、控制与关闭 -->
        <div class="flex items-center gap-2 flex-wrap">
          <div class="ui-pill p-0.5 rounded-xl flex items-center gap-0.5 text-[11px] font-semibold">
            <button
              @click="viewMode = 'lan'"
              :class="['px-2.5 py-1 rounded-lg transition-colors cursor-pointer flex items-center gap-1.5',
                viewMode === 'lan' ? 'bg-sky-500 text-white shadow-xs font-bold' : 'hover:bg-black/5 dark:hover:bg-white/5']"
              :style="viewMode !== 'lan' ? { color: 'var(--text-secondary)' } : undefined"
              title="切换至局域网微观虚拟拓扑架构图示"
            >
              <AppIcon name="layers" :size="12" />
              <span>局域网虚拟拓扑</span>
              <span v-if="isLanTarget" class="px-1.5 py-0.5 rounded-full text-[11px] bg-emerald-500/20 text-emerald-700 dark:text-emerald-200 font-bold">
                内网推荐
              </span>
            </button>
            <button
              @click="viewMode = '3d'"
              :class="['px-2.5 py-1 rounded-lg transition-colors cursor-pointer flex items-center gap-1.5',
                viewMode === '3d' ? 'bg-sky-500 text-white shadow-xs font-bold' : 'hover:bg-black/5 dark:hover:bg-white/5']"
              :style="viewMode !== '3d' ? { color: 'var(--text-secondary)' } : undefined"
              title="切换至三维交互式数字地球"
            >
              <AppIcon name="globe" :size="12" />
              <span>3D 数字地球</span>
            </button>
            <button
              @click="viewMode = '2d'"
              :class="['px-2.5 py-1 rounded-lg transition-colors cursor-pointer flex items-center gap-1.5',
                viewMode === '2d' ? 'bg-sky-500 text-white shadow-xs font-bold' : 'hover:bg-black/5 dark:hover:bg-white/5']"
              :style="viewMode !== '2d' ? { color: 'var(--text-secondary)' } : undefined"
              title="切换至二维高精度等角圆柱投影地图"
            >
              <AppIcon name="compass" :size="12" />
              <span>2D 全景地图</span>
            </button>
          </div>

          <template v-if="viewMode === '3d'">
            <button
              @click="toggleGlobeAutoRotate"
              :class="['px-2.5 py-1 rounded-xl border text-[11px] font-medium transition-colors flex items-center gap-1.5 cursor-pointer',
                isAutoRotating ? 'bg-sky-500/15 text-sky-700 dark:text-cyan-300 border-sky-500/35' : 'ui-pill']"
              :title="isAutoRotating ? '暂停地球平滑自转' : '开启地球平滑自转'"
            >
              <AppIcon :name="isAutoRotating ? 'pause' : 'refresh'" :size="12" />
              <span>{{ isAutoRotating ? '停止自转' : '开启自转' }}</span>
            </button>
            <button
              @click="focusOnSelf"
              class="ui-btn-secondary text-[11px] py-1 px-2.5 rounded-xl"
              title="将 3D 地球视角中心对焦至本机真实位置"
            >
              <AppIcon name="radar" :size="12" />
              <span>对焦本机</span>
            </button>
          </template>

          <button
            v-if="hops.length > 0"
            @click="exportTracerouteReport"
            class="ui-btn-secondary text-[11px] py-1 px-3 rounded-xl"
          >
            <AppIcon name="document" :size="12" />
            <span>导出报告</span>
          </button>

          <button
            @click="handleClose"
            class="w-8 h-8 rounded-full flex items-center justify-center ui-pill cursor-pointer"
            title="关闭窗口"
          >
            <AppIcon name="close" :size="15" />
          </button>
        </div>
      </header>

      <!-- 2. 本机自我真实位置 (Hop 0) 核心情报看板 -->
      <div class="px-5 py-2 border-b flex items-center justify-between flex-wrap gap-2 text-xs ui-num select-text" style="background: var(--surface-content-alt); border-color: var(--border-subtle)">
        <div class="flex items-center gap-3 flex-wrap">
          <div class="flex items-center gap-1.5 text-emerald-700 dark:text-emerald-300 font-bold bg-emerald-500/12 px-2.5 py-1 rounded-xl border border-emerald-500/25">
            <span class="w-2 h-2 rounded-full bg-emerald-500"></span>
            <span>本机源端 IP:</span>
            <span class="ml-1" style="color: var(--text-primary)">{{ selfHopInfo.ip }}</span>
          </div>

          <div class="flex items-center gap-1.5" style="color: var(--text-secondary)">
            <span style="color: var(--text-muted)">真实地理归属:</span>
            <strong class="text-sky-700 dark:text-cyan-300 font-bold flex items-center gap-1">
              <AppIcon name="compass" :size="12" />
              <span>{{ selfHopInfo.location }}</span>
            </strong>
            <span v-if="selfHopInfo.isp" class="px-1.5 py-0.5 rounded ui-pill text-[11px]">
              {{ selfHopInfo.isp }}
            </span>
          </div>

          <div class="flex items-center gap-1.5" style="color: var(--text-secondary)">
            <span style="color: var(--text-muted)">测地基准坐标:</span>
            <strong class="text-emerald-700 dark:text-emerald-400">
              [{{ selfHopInfo.lon.toFixed(2) }}°, {{ selfHopInfo.lat.toFixed(2) }}°]
            </strong>
          </div>
        </div>

        <div class="flex items-center gap-3 text-[11px]" style="color: var(--text-muted)">
          <span>定位体系: <strong :class="isLanTarget ? 'text-amber-700 dark:text-amber-300' : 'text-sky-700 dark:text-cyan-300'">{{ isLanTarget ? 'RFC 1918 局域网微观路由' : '全球广域互联网骨干' }}</strong></span>
          <span>·</span>
          <span>状态: <strong class="text-emerald-700 dark:text-emerald-400 font-bold">{{ selfHopInfo.refineStatus }}</strong></span>
        </div>
      </div>

      <!-- 3. 目标主机输入与探测调度条 -->
      <div class="px-5 py-2 border-b flex items-center justify-between flex-wrap gap-3 shrink-0 text-xs" style="background: var(--surface-content); border-color: var(--border-subtle)">
        <div class="flex items-center gap-2 flex-wrap">
          <label class="flex items-center gap-1 font-semibold text-[11px]" style="color: var(--text-secondary)">
            <AppIcon name="radar" :size="13" />
            <span>目标主机:</span>
          </label>
          <input
            v-model="inputTarget"
            :disabled="isTracing"
            type="text"
            placeholder="IPv4 或域名 (如 192.168.1.1 / 8.8.8.8)"
            class="ui-input ui-num w-64 py-1.5 px-3 text-xs"
            @keyup.enter="startTrace"
          />

          <label class="ml-1 text-[11px] font-medium" style="color: var(--text-secondary)">跳数上限:</label>
          <select
            v-model.number="maxHops"
            :disabled="isTracing"
            class="ui-input w-auto py-1 px-2 text-xs cursor-pointer"
          >
            <option :value="15">15 跳 (局域网推荐)</option>
            <option :value="30">30 跳 (标准)</option>
            <option :value="45">45 跳 (深度)</option>
            <option :value="64">64 跳 (全网穷尽)</option>
          </select>

          <label class="ml-1 text-[11px] font-medium" style="color: var(--text-secondary)">单跳超时:</label>
          <select
            v-model.number="timeoutMs"
            :disabled="isTracing"
            class="ui-input w-auto py-1 px-2 text-xs cursor-pointer"
          >
            <option :value="300">300 ms (局域网极速)</option>
            <option :value="1000">1000 ms (推荐)</option>
            <option :value="2000">2000 ms (严密)</option>
          </select>

          <button
            v-if="!isTracing"
            @click="startTrace"
            class="ml-2 ui-btn-primary text-xs py-1.5 px-3.5 rounded-xl"
          >
            <AppIcon name="play" :size="12" />
            <span>启动测地追踪</span>
          </button>
          <button
            v-else
            @click="stopTrace"
            class="ml-2 ui-btn-danger text-xs py-1.5 px-3.5 rounded-xl"
          >
            <AppIcon name="stop" :size="12" />
            <span>强制终止探测</span>
          </button>
        </div>

        <!-- 关键指标摘要 -->
        <div class="flex items-center gap-4 text-xs ui-num select-text">
          <div class="flex items-center gap-1" style="color: var(--text-secondary)">
            <span style="color: var(--text-muted)">{{ isLanTarget ? '内网物理线距:' : '测地直线总距:' }}</span>
            <strong :class="isLanTarget ? 'text-emerald-700 dark:text-emerald-400' : 'text-sky-700 dark:text-cyan-300'">
              {{ isLanTarget ? (totalGeodesicKm * 1000).toFixed(0) + ' m' : totalGeodesicKm.toFixed(1) + ' km' }}
            </strong>
          </div>
          <div class="flex items-center gap-1" style="color: var(--text-secondary)">
            <span style="color: var(--text-muted)">理论最低时延:</span>
            <strong class="text-emerald-700 dark:text-emerald-400">{{ theoreticalMinRtt.toFixed(2) }} ms</strong>
          </div>
          <div class="flex items-center gap-1" style="color: var(--text-secondary)">
            <span style="color: var(--text-muted)">实测终点 RTT:</span>
            <strong :class="actualFinalRttClass">{{ actualFinalRttText }}</strong>
          </div>
        </div>
      </div>

      <!-- 4. 中部核心可视化区 (支持 3D 数字地球 / 2D 全景地图 / 局域网微观虚拟拓扑) -->
      <div class="flex-1 flex flex-col overflow-y-auto p-4 gap-3 min-h-0" style="background: var(--surface-window)">
        
        <!-- 4.1 可视化画布容器 -->
        <div
          class="relative w-full h-80 xl:h-88 rounded-2xl border overflow-hidden flex items-center justify-center shrink-0 shadow-sm ui-sub-card p-0"
          :class="isDarkTheme ? 'border-white/15' : 'border-slate-300/60'"
        >
          <!-- 模式 A: 局域网微观虚拟拓扑架构图示 -->
          <div
            v-show="viewMode === 'lan'"
            class="w-full h-full flex flex-col justify-between p-4 overflow-x-auto select-none"
          >
            <div class="flex items-center justify-between text-xs z-10 flex-wrap gap-2">
              <div class="flex items-center gap-2">
                <span class="w-2 h-2 rounded-full bg-emerald-500"></span>
                <span class="font-bold tracking-tight" style="color: var(--text-primary)">局域网企业架构逐级跃迁虚拟拓扑</span>
                <span class="px-2 py-0.5 rounded-full bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 border border-emerald-500/25 text-[11px]">
                  Purdue Enterprise Hierarchy
                </span>
              </div>
              <div class="text-[11px] ui-num flex items-center gap-2" style="color: var(--text-secondary)">
                <span>介质: <strong class="text-sky-700 dark:text-cyan-400">千兆双绞线 / 工业以太网</strong></span>
                <span>·</span>
                <span>跳步时延: <strong class="text-emerald-700 dark:text-emerald-400">&lt; 1.0 ms</strong></span>
              </div>
            </div>

            <!-- 横向逐跳架构节点卡片流 -->
            <div class="relative flex-1 flex items-center gap-3 overflow-x-auto py-3 px-2 custom-scrollbar">
              <template v-for="(hop, idx) in hops" :key="'lan-node-' + hop.hop_number">
                <div
                  :class="[
                    'relative shrink-0 w-64 ui-content-card p-3.5 transition-colors cursor-pointer flex flex-col justify-between select-text',
                    hop.is_self ? '!border-emerald-500/50 bg-emerald-500/8' : (hop.is_destination ? '!border-amber-500/50 bg-amber-500/8' : 'hover:border-sky-500/50'),
                    selectedHop?.hopNumber === hop.hop_number ? 'ring-2 ring-sky-500' : ''
                  ]"
                  @click="selectHopRow(hop)"
                >
                  <div class="flex items-center justify-between border-b pb-2 mb-2" style="border-color: var(--border-subtle)">
                    <span
                      :class="[
                        'px-2 py-0.5 rounded-md text-[11px] font-bold ui-num',
                        hop.is_self ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30' : (hop.is_destination ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30' : 'ui-pill')
                      ]"
                    >
                      {{ hop.is_self ? '源点 #0 (本机)' : `Hop #${hop.hop_number}` }}
                    </span>
                    <span class="text-[11px] ui-num font-bold" :class="getRttClass(hop.rtt_ms)">
                      {{ hop.is_self ? '0.0 ms' : (hop.is_timeout ? '*' : hop.rtt_ms.toFixed(1) + ' ms') }}
                    </span>
                  </div>

                  <div class="flex items-center gap-2.5 my-1">
                    <div class="w-8 h-8 rounded-lg ui-pill flex items-center justify-center shrink-0" style="color: var(--accent-primary-text)">
                      <AppIcon :name="getLanNodeIcon(hop)" :size="16" />
                    </div>
                    <div class="flex-1 min-w-0">
                      <div class="ui-num font-bold text-sm truncate" style="color: var(--text-primary)">{{ hop.ip }}</div>
                      <div class="text-[11px] text-sky-700 dark:text-cyan-300 font-medium truncate mt-0.5">
                        {{ hop.lan_role || (hop.is_self ? '本机源端' : '局域网路由') }}
                      </div>
                    </div>
                  </div>

                  <div class="mt-2 pt-2 border-t flex items-center justify-between text-[11px] ui-num" style="border-color: var(--border-subtle); color: var(--text-muted)">
                    <span style="color: var(--text-secondary)">网段: {{ hop.subnet_cidr || '局域网/24' }}</span>
                    <span class="text-emerald-700 dark:text-emerald-400 font-semibold">线距: ~{{ Math.round(hop.cumulative_distance_km * 1000) }}m</span>
                  </div>
                </div>

                <div v-if="idx < hops.length - 1" class="shrink-0 flex flex-col items-center justify-center px-1">
                  <div class="relative w-12 h-1 bg-gradient-to-r from-emerald-500/40 via-sky-500 to-emerald-500/40 rounded-full overflow-hidden">
                    <div class="absolute inset-0 bg-white/80 w-4 h-full rounded-full animate-dash-h"></div>
                  </div>
                  <span class="text-[11px] ui-num text-sky-700 dark:text-cyan-400 font-bold mt-1">
                    {{ (hops[idx + 1].rtt_ms - hop.rtt_ms) >= 0 ? '+' + (hops[idx + 1].rtt_ms - hop.rtt_ms).toFixed(1) + 'ms' : '0.2ms' }}
                  </span>
                </div>
              </template>

              <EmptyState
                v-if="hops.length === 0"
                class="w-full"
                icon="layers"
                title="等待启动局域网微观架构探测"
                description="输入局域网 IP (如 192.168.1.1 或 10.0.0.1) 并点击【启动测地追踪】。"
              />
            </div>

            <div class="flex items-center justify-between text-[11px] ui-num border-t pt-2 z-10 flex-wrap gap-2" style="border-color: var(--border-subtle); color: var(--text-muted)">
              <div class="flex items-center gap-3 flex-wrap">
                <span class="text-emerald-700 dark:text-emerald-400 font-bold">二层直通线速 (Line-Rate)</span>
                <span>·</span>
                <span>介质模型: Cat6 综合布线 (增量 ~35m/跳)</span>
                <span>·</span>
                <span>排队诊断: 无内网广播风暴或二层环路</span>
              </div>
              <span>右上角可切换【3D 数字地球】或【2D 全景地图】</span>
            </div>
          </div>

          <!-- 模式 B: 3D 数字地球 Canvas -->
          <canvas
            v-show="viewMode === '3d'"
            ref="globeCanvasRef"
            class="w-full h-full cursor-grab active:cursor-grabbing select-none"
            @mousedown="onGlobeMouseDown"
            @mousemove="onGlobeMouseMove"
            @mouseup="onGlobeMouseUp"
            @mouseleave="onGlobeMouseUp"
            @wheel.prevent="onGlobeWheel"
          ></canvas>

          <!-- 模式 C: 2D 全景平面投影 SVG -->
          <svg
            v-show="viewMode === '2d'"
            viewBox="0 0 960 480"
            class="w-full h-full object-contain select-none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <defs>
              <filter id="glow2d" x="-20%" y="-20%" width="140%" height="140%">
                <feGaussianBlur stdDeviation="2.0" result="blur" />
                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
            </defs>

            <!-- 2D 经纬网格 -->
            <g :class="isDarkTheme ? 'stroke-slate-800/60' : 'stroke-slate-400/35'" stroke-width="0.8" stroke-dasharray="2 3">
              <line x1="0" y1="240" x2="960" y2="240" :class="isDarkTheme ? 'stroke-slate-600/80' : 'stroke-slate-500/45'" stroke-width="1" stroke-dasharray="none" />
              <line x1="480" y1="0" x2="480" y2="480" :class="isDarkTheme ? 'stroke-slate-600/80' : 'stroke-slate-500/45'" stroke-width="1" stroke-dasharray="none" />
              <line x1="0" y1="177.3" x2="960" y2="177.3" :class="isDarkTheme ? 'stroke-cyan-900/30' : 'stroke-sky-500/25'" />
              <line x1="0" y1="302.7" x2="960" y2="302.7" :class="isDarkTheme ? 'stroke-cyan-900/30' : 'stroke-sky-500/25'" />
              <line v-for="y in [80, 160, 320, 400]" :key="'lat-' + y" x1="0" :y1="y" x2="960" :y2="y" />
              <line v-for="x in [80, 160, 240, 320, 400, 560, 640, 720, 800, 880]" :key="'lon-' + x" :x1="x" y1="0" :x2="x" y2="480" />
            </g>

            <!-- 2D 大陆板块 -->
            <g :class="isDarkTheme ? 'fill-slate-800/75 stroke-cyan-500/35' : 'fill-white/90 stroke-blue-500/35'" stroke-width="0.8">
              <path v-for="(pathStr, pIdx) in worldLandPaths2d" :key="'poly-2d-' + pIdx" :d="pathStr" />
            </g>

            <!-- 2D 测地大圆飞线 -->
            <g>
              <template v-for="(flight, idx) in flightArcs2d" :key="'flight-2d-' + idx">
                <path :d="flight.pathData" class="fill-none stroke-sky-500/25 stroke-[3]" />
                <path
                  :d="flight.pathData"
                  class="fill-none stroke-[2] animate-dash"
                  :stroke="flight.strokeColor"
                  stroke-dasharray="6 4"
                  filter="url(#glow2d)"
                />
              </template>
            </g>

            <!-- 2D 航路点标记 -->
            <g>
              <g
                v-for="point in geoWaypoints"
                :key="'wp2d-' + point.hopNumber"
                :transform="`translate(${point.x2d}, ${point.y2d})`"
                class="cursor-pointer hover:scale-125 transition-transform"
                @mouseenter="hoveredHop = point"
                @mouseleave="hoveredHop = null"
                @click="selectHopRow(point.rawHop)"
              >
                <circle
                  r="7"
                  :class="point.isSelf ? 'fill-emerald-500/25 stroke-emerald-500' : (point.isFinal ? 'fill-amber-500/25 stroke-amber-500' : 'fill-sky-500/20 stroke-sky-500')"
                  stroke-width="1.5"
                />
                <circle
                  r="3.5"
                  :class="point.isSelf ? 'fill-emerald-500' : (point.isFinal ? 'fill-amber-500' : 'fill-sky-500')"
                />
                <text
                  text-anchor="middle"
                  y="-10"
                  class="font-mono text-[11px] font-bold select-none"
                  :class="isDarkTheme ? 'fill-slate-200' : 'fill-slate-900'"
                >
                  {{ point.isSelf ? '本机' : '#' + point.hopNumber }}
                </text>
              </g>
            </g>
          </svg>

          <!-- 悬停节点即时卡片 (Liquid Glass Floating Tooltip) -->
          <div
            v-if="hoveredHop"
            class="absolute top-3 left-3 ui-modal-surface rounded-2xl p-3 text-xs ui-num z-30 pointer-events-none max-w-xs"
          >
            <div class="flex items-center justify-between gap-2 border-b pb-1.5 mb-1.5" style="border-color: var(--border-subtle)">
              <span class="font-bold flex items-center gap-1.5" :class="hoveredHop.isSelf ? 'text-emerald-700 dark:text-emerald-400' : 'text-sky-700 dark:text-cyan-400'">
                <span class="w-2 h-2 rounded-full" :class="hoveredHop.isSelf ? 'bg-emerald-500' : 'bg-sky-500'"></span>
                <span>{{ hoveredHop.isSelf ? '本机源端 IP' : `Hop #${hoveredHop.hopNumber}` }}</span>
              </span>
              <span class="text-[11px] px-1.5 py-0.5 rounded ui-pill">
                RTT: {{ hoveredHop.rttMs >= 0 ? hoveredHop.rttMs.toFixed(1) + ' ms' : '*' }}
              </span>
            </div>
            <div class="font-bold mb-1" style="color: var(--text-primary)">{{ hoveredHop.ip }}</div>
            <div class="text-[11px] flex items-center gap-1" style="color: var(--text-secondary)">
              <AppIcon name="compass" :size="12" />
              <span>{{ hoveredHop.location }}</span>
            </div>
            <div v-if="hoveredHop.isp" class="text-[11px] mt-0.5 flex items-center gap-1" style="color: var(--text-muted)">
              <AppIcon name="globe" :size="12" />
              <span>{{ hoveredHop.isp }}</span>
            </div>
            <div class="text-[11px] mt-1.5 flex items-center justify-between gap-2 border-t pt-1" style="border-color: var(--border-subtle); color: var(--text-muted)">
              <span>[{{ hoveredHop.lon.toFixed(2) }}°, {{ hoveredHop.lat.toFixed(2) }}°]</span>
              <span>距起点: {{ (hoveredHop.cumulativeKm * (isLanTarget ? 1000 : 1)).toFixed(1) }} {{ isLanTarget ? 'm' : 'km' }}</span>
            </div>
          </div>

          <!-- 地图底部控制提示与图例 (Liquid Glass 悬浮胶囊) -->
          <div class="absolute bottom-2.5 left-4 text-[11px] ui-num flex items-center gap-2.5 select-none pointer-events-none liquid-panel px-3 py-1 rounded-xl" style="color: var(--text-secondary)">
            <span v-if="viewMode === 'lan'">局域网虚拟架构拓扑: 点击节点卡片可联动下钻下方指标行</span>
            <span v-else-if="viewMode === '3d'">鼠标按住拖拽自由 360° 旋转地球 · 滚轮缩放</span>
            <span v-else>投影体系: WGS-84 等角圆柱投影 · 离线高精经纬度</span>
            <span>·</span>
            <span class="text-emerald-700 dark:text-emerald-400 font-semibold">已锚定本机物理位置</span>
          </div>

          <div class="hidden md:flex absolute bottom-2.5 right-4 items-center gap-3 text-[11px] ui-num liquid-panel px-3 py-1 rounded-xl select-none">
            <div class="flex items-center gap-1.5 text-emerald-700 dark:text-emerald-400">
              <span class="w-2 h-2 rounded-full bg-emerald-500"></span>
              <span>本机主机 (Hop 0)</span>
            </div>
            <div class="flex items-center gap-1.5 text-sky-700 dark:text-cyan-400">
              <span class="w-2 h-2 rounded-full bg-sky-500"></span>
              <span>路由跃点</span>
            </div>
            <div class="flex items-center gap-1.5 text-amber-700 dark:text-amber-400">
              <span class="w-2 h-2 rounded-full bg-amber-500"></span>
              <span>终点主机</span>
            </div>
          </div>
        </div>

        <!-- 4.2 逐跳指标表格 (实体工作区面板) -->
        <div class="flex-1 flex flex-col min-h-0 ui-content-card overflow-hidden">
          
          <div class="px-4 py-2 border-b flex items-center justify-between shrink-0 text-xs flex-wrap gap-2" style="background: var(--surface-content-alt); border-color: var(--border-subtle)">
            <div class="flex items-center gap-2 font-bold" style="color: var(--text-primary)">
              <AppIcon name="radar" :size="14" />
              <span>路由跃点指标明细 (Hop-by-Hop Telemetry)</span>
              <span class="text-[11px] px-2 py-0.5 rounded-full ui-pill font-normal ui-num">
                已探测 {{ hops.length }} 节点
              </span>
            </div>
            <div class="text-[11px]" style="color: var(--text-muted)">
              首行始终对齐本机源端 IP · 自动研判局域网微观角色与子网归属
            </div>
          </div>

          <div class="flex-1 overflow-auto select-text">
            <table class="w-full text-left text-xs border-collapse">
              <thead class="ui-table-head sticky top-0 z-10 text-[11px]">
                <tr>
                  <th class="py-2 px-3 w-20 text-center">跳数</th>
                  <th class="py-2 px-3 w-44">路由器 / 主机 IP</th>
                  <th class="py-2 px-3 w-32">RTT 时延</th>
                  <th class="py-2 px-3 w-48">网络角色 / 拓扑层级</th>
                  <th class="py-2 px-3 w-44">地理归属 (国家/省/市)</th>
                  <th class="py-2 px-3 w-32">子网 (CIDR)</th>
                  <th class="py-2 px-3 w-28">物理线缆距</th>
                  <th class="py-2 px-3 text-right">缓冲排队剖析</th>
                </tr>
              </thead>
              <tbody class="divide-y ui-num" style="border-color: var(--border-subtle); color: var(--text-secondary)">
                <tr
                  v-for="hop in hops"
                  :key="'hop-row-' + hop.hop_number"
                  :class="[
                    'hover:bg-black/5 dark:hover:bg-white/5 transition-colors cursor-pointer',
                    hop.is_self ? 'bg-emerald-500/8 border-l-2 border-l-emerald-500' : '',
                    selectedHop?.hopNumber === hop.hop_number ? 'bg-sky-500/10 border-l-2 border-l-sky-500' : ''
                  ]"
                  @click="selectHopRow(hop)"
                >
                  <td class="py-2 px-3 text-center font-bold">
                    <span
                      :class="[
                        'inline-block px-2 py-0.5 rounded text-[11px]',
                        hop.is_self ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30 font-bold' : (hop.is_destination ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30 font-bold' : 'ui-pill')
                      ]"
                    >
                      {{ hop.is_self ? '源点 #0' : '#' + hop.hop_number }}
                    </span>
                  </td>

                  <td class="py-2 px-3 font-bold flex items-center gap-1.5" style="color: var(--text-primary)">
                    <span v-if="hop.is_timeout" class="italic" style="color: var(--text-muted)">* (超时丢包)</span>
                    <span v-else>{{ hop.ip }}</span>
                    <span v-if="hop.is_self" class="text-[11px] px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30 font-semibold">本机</span>
                    <span v-else-if="hop.is_destination" class="text-[11px] px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30 font-semibold">终点</span>
                  </td>

                  <td class="py-2 px-3">
                    <div v-if="hop.is_timeout" class="italic" style="color: var(--text-muted)">* ms</div>
                    <div v-else-if="hop.is_self" class="text-emerald-700 dark:text-emerald-400 font-bold">0.0 ms</div>
                    <div v-else class="flex items-center gap-2">
                      <span :class="getRttClass(hop.rtt_ms)" class="w-14 font-bold">{{ hop.rtt_ms.toFixed(1) }} ms</span>
                      <div class="w-12 h-1.5 rounded-full overflow-hidden" style="background: var(--surface-elevated)">
                        <div
                          class="h-full rounded-full transition-all"
                          :class="getRttBarColor(hop.rtt_ms)"
                          :style="{ width: Math.min(100, (hop.rtt_ms / (isLanTarget ? 5 : 200)) * 100) + '%' }"
                        ></div>
                      </div>
                    </div>
                  </td>

                  <td class="py-2 px-3 text-sky-700 dark:text-cyan-300 font-medium">
                    <div class="flex items-center gap-1.5">
                      <AppIcon :name="getLanNodeIcon(hop)" :size="14" class="shrink-0" />
                      <span class="truncate">{{ hop.lan_role || (hop.is_self ? '本机源端主机' : '骨干网络跃点') }}</span>
                    </div>
                  </td>

                  <td class="py-2 px-3" style="color: var(--text-primary)">
                    <div class="flex items-center gap-1.5 truncate">
                      <template v-if="hop.country && hop.country !== '未知'">
                        <AppIcon name="globe" :size="12" class="shrink-0" style="color: var(--text-muted)" />
                        <span>{{ formatLocation(hop) }}</span>
                      </template>
                      <template v-else-if="hop.is_self">
                        <AppIcon name="cpu" :size="12" class="shrink-0" style="color: var(--text-muted)" />
                        <span>本地内网主机终端</span>
                      </template>
                      <span v-else class="italic" style="color: var(--text-muted)">内网 / 私有网段</span>
                    </div>
                  </td>

                  <td class="py-2 px-3 text-[11px]">
                    <span v-if="hop.subnet_cidr" class="px-1.5 py-0.5 rounded ui-pill text-sky-700 dark:text-cyan-300 font-medium">
                      {{ hop.subnet_cidr }}
                    </span>
                    <span v-else style="color: var(--text-muted)">-</span>
                  </td>

                  <td class="py-2 px-3 font-bold">
                    <span v-if="isLanTarget" class="text-emerald-700 dark:text-emerald-400">
                      ~{{ Math.round(hop.cumulative_distance_km * 1000) }} m
                    </span>
                    <span v-else-if="hop.cumulative_distance_km > 0" class="text-sky-700 dark:text-cyan-300">
                      {{ hop.cumulative_distance_km.toFixed(1) }} km
                    </span>
                    <span v-else style="color: var(--text-muted)">0.0 km</span>
                  </td>

                  <td class="py-2 px-3 text-right">
                    <span v-if="hop.is_self" class="text-emerald-700 dark:text-emerald-400 text-[11px] font-bold">
                      源起点
                    </span>
                    <span v-else-if="isLanTarget" class="text-emerald-700 dark:text-emerald-400 text-[11px] font-bold">
                      {{ hop.rtt_ms < 1.0 ? '微秒线速' : '正常交换' }}
                    </span>
                    <span
                      v-else-if="!hop.is_timeout && hop.bufferbloat_ratio > 0"
                      :class="[
                        'px-2 py-0.5 rounded text-[11px] font-bold border',
                        hop.bufferbloat_ratio > 10 ? 'bg-rose-500/12 text-rose-700 dark:text-rose-300 border-rose-500/30' : (hop.bufferbloat_ratio > 4 ? 'bg-amber-500/12 text-amber-700 dark:text-amber-300 border-amber-500/30' : 'bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 border-emerald-500/30')
                      ]"
                    >
                      {{ hop.bufferbloat_ratio > 10 ? '严重排队' : (hop.bufferbloat_ratio > 4 ? '轻度拥塞' : '物理极限') }}
                    </span>
                    <span v-else style="color: var(--text-muted)">-</span>
                  </td>
                </tr>

                <tr v-if="hops.length === 0">
                  <td colspan="8" class="py-10">
                    <EmptyState
                      icon="globe"
                      title="等待路由追踪"
                      description="输入目标 IP (支持公网 IP 或 192.168.x.x / 10.x.x.x 局域网)，点击【启动测地追踪】。"
                    />
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

      </div>

      <!-- 5. 底部状态指示条 -->
      <footer class="px-5 py-2 border-t flex items-center justify-between text-[11px] ui-num shrink-0" style="background: var(--surface-content-alt); border-color: var(--border-subtle); color: var(--text-muted)">
        <div class="flex items-center gap-3 flex-wrap">
          <span>三维渲染: 正射空间投影 (Orthographic)</span>
          <span>·</span>
          <span>局域网引擎: Purdue Model 微观拓扑感知</span>
          <span>·</span>
          <span>数据库: ip2region.xdb 联动自适应</span>
        </div>
        <div class="flex items-center gap-2">
          <span v-if="statusMessage" class="text-sky-700 dark:text-cyan-400 font-bold">{{ statusMessage }}</span>
          <span v-else>就绪</span>
        </div>
      </footer>

    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted, onUnmounted, nextTick } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import AppIcon from './AppIcon.vue';
import EmptyState from './EmptyState.vue';
import { saveTextViaNativeDesktop } from '../composables/useDesktopSave';

const isDarkTheme = ref(!document.documentElement.classList.contains('theme-apple-light'));
let themeObserver: MutationObserver | null = null;

export interface TracerouteHopEvent {
  hop_number: number;
  ip: string;
  rtt_ms: number;
  is_timeout: boolean;
  country: string;
  province: string;
  city: string;
  isp: string;
  latitude: number;
  longitude: number;
  has_geo: boolean;
  segment_distance_km: number;
  cumulative_distance_km: number;
  fiber_rtt_ms: number;
  bufferbloat_ratio: number;
  is_destination: boolean;
  status_text: string;
  is_self?: boolean;
  is_lan?: boolean;
  lan_role?: string;
  subnet_cidr?: string;
}

interface GeoPoint {
  hopNumber: number;
  ip: string;
  lon: number;
  lat: number;
  x2d: number;
  y2d: number;
  rttMs: number;
  location: string;
  isp: string;
  cumulativeKm: number;
  isSelf: boolean;
  isFinal: boolean;
  rawHop: TracerouteHopEvent;
}

const props = defineProps<{
  isOpen: boolean;
  initialTarget?: string;
}>();

const emit = defineEmits<{
  (e: 'close'): void;
}>();

// 模式控制: 'lan' (局域网微观虚拟拓扑) | '3d' (三维数字地球) | '2d' (二维全景地图)
const viewMode = ref<'lan' | '3d' | '2d'>('3d');
const isAutoRotating = ref(true);

// 目标与配置
const inputTarget = ref(props.initialTarget || '8.8.8.8');
const maxHops = ref(30);
const timeoutMs = ref(1000);

// 探测状态
const isTracing = ref(false);
const isFinished = ref(false);
const currentHop = ref(0);
const hops = ref<TracerouteHopEvent[]>([]);
const statusMessage = ref('');

// 判断当前目标是否属于局域网范围
const isLanTarget = computed(() => {
  const t = inputTarget.value.trim();
  return t.startsWith('192.168.') || t.startsWith('10.') || t.startsWith('172.') || t.startsWith('127.') || t === 'localhost';
});

// 使用者自我真实主机信息 (Hop 0)
const selfHopInfo = ref({
  ip: '127.0.0.1',
  location: '正在探测本机归属...',
  isp: '',
  lon: 116.4,
  lat: 39.9,
  refineStatus: '初始化'
});

// 交互选中
const hoveredHop = ref<GeoPoint | null>(null);
const selectedHop = ref<GeoPoint | null>(null);

// 3D 地球 Canvas 引用与旋转视角状态
const globeCanvasRef = ref<HTMLCanvasElement | null>(null);
const globeRotation = ref({
  centerLon: 116.4,
  centerLat: 32.0,
  radius: 140,
  isDragging: false,
  lastMouseX: 0,
  lastMouseY: 0
});

let animationFrameId: number | null = null;
let unlistenHopEvent: UnlistenFn | null = null;

// 自然地球真实高精经纬度陆地多边形
const WORLD_LAND_POLYGONS: number[][][] = [
  // 欧亚大陆主陆地板块 (包含中国海岸线/半岛、欧洲大西洋沿岸、斯堪的纳维亚、西伯利亚)
  [
    [121.6, 38.9], [122.5, 37.4], [119.5, 35.0], [121.9, 30.9], [120.0, 26.5], [116.8, 23.5], [113.8, 22.3],
    [110.3, 20.9], [108.5, 21.5], [106.0, 19.5], [109.0, 13.0], [105.0, 10.0], [100.5, 13.7], [103.8, 1.3],
    [98.5, 8.0], [96.0, 17.0], [90.0, 22.0], [80.0, 16.0], [77.5, 8.1], [73.0, 19.0], [68.0, 24.0],
    [57.0, 25.5], [50.0, 26.0], [45.0, 13.0], [43.0, 12.5], [35.0, 28.0], [32.5, 30.0], [35.0, 33.0],
    [28.0, 41.0], [23.7, 38.0], [15.0, 38.0], [12.5, 44.0], [4.0, 43.5], [-1.5, 43.5], [-5.3, 36.1],
    [-9.5, 38.8], [-9.0, 43.0], [1.0, 50.0], [8.5, 54.0], [10.0, 57.5], [5.0, 62.0], [15.0, 68.0],
    [25.8, 71.2], [33.0, 69.0], [40.0, 67.0], [55.0, 68.0], [70.0, 73.0], [100.0, 77.0], [140.0, 72.0],
    [170.0, 66.0], [162.0, 55.0], [143.0, 50.0], [132.0, 43.0], [127.0, 38.0], [129.0, 35.0], [126.0, 37.0],
    [124.5, 40.0], [121.6, 38.9]
  ],
  // 非洲大陆
  [
    [32.5, 30.0], [34.0, 27.0], [43.5, 12.0], [51.2, 10.5], [40.5, -15.0], [35.0, -25.0], [28.0, -32.5],
    [18.5, -34.3], [14.5, -23.0], [12.0, -6.0], [9.0, 4.0], [0.0, 5.5], [-13.0, 9.0], [-17.5, 14.7],
    [-13.0, 27.0], [-5.8, 35.8], [10.5, 37.0], [20.0, 32.0], [30.0, 31.2], [32.5, 30.0]
  ],
  // 北美洲大陆
  [
    [-168.0, 65.5], [-160.0, 56.0], [-140.0, 60.0], [-125.0, 49.0], [-122.4, 37.8], [-117.0, 32.5],
    [-110.0, 23.0], [-105.0, 20.0], [-95.0, 16.0], [-80.0, 8.5], [-77.0, 8.0], [-83.0, 10.0],
    [-89.0, 21.0], [-97.0, 26.0], [-89.5, 29.0], [-80.5, 25.0], [-76.0, 37.0], [-70.0, 43.0],
    [-60.0, 47.0], [-55.0, 50.0], [-65.0, 60.0], [-85.0, 60.0], [-95.0, 70.0], [-120.0, 70.0],
    [-156.7, 71.3], [-168.0, 65.5]
  ],
  // 南美洲大陆
  [
    [-77.0, 8.0], [-70.0, 12.0], [-60.0, 10.0], [-50.0, 0.0], [-35.0, -5.5], [-38.0, -13.0],
    [-43.0, -23.0], [-50.0, -30.0], [-58.0, -35.0], [-65.0, -42.0], [-67.0, -55.0], [-74.0, -45.0],
    [-71.5, -33.0], [-77.0, -12.0], [-80.0, -2.0], [-77.0, 8.0]
  ],
  // 澳大利亚大陆
  [
    [142.5, -11.0], [149.0, -20.0], [153.0, -27.5], [150.0, -37.0], [140.0, -38.0], [130.0, -32.0],
    [115.5, -34.0], [114.0, -22.0], [122.0, -17.0], [130.8, -12.5], [136.0, -12.0], [142.5, -11.0]
  ],
  // 日本列岛
  [
    [140.5, 35.5], [141.5, 38.5], [141.0, 41.5], [140.0, 43.0], [145.0, 44.0], [142.0, 42.0],
    [139.5, 36.5], [135.5, 34.5], [131.0, 31.5], [130.0, 33.5], [133.0, 35.5], [137.0, 37.0], [140.5, 35.5]
  ],
  // 台湾岛
  [
    [121.5, 25.3], [122.0, 24.5], [121.0, 22.0], [120.2, 23.0], [120.5, 24.5], [121.5, 25.3]
  ],
  // 海南岛
  [
    [110.5, 20.0], [111.0, 19.0], [109.5, 18.2], [108.6, 19.2], [110.5, 20.0]
  ],
  // 大不列颠与爱尔兰
  [
    [-5.0, 50.0], [1.5, 51.5], [0.0, 54.0], [-2.0, 58.5], [-5.0, 58.5], [-5.0, 55.0], [-3.0, 51.5], [-5.0, 50.0]
  ],
  // 格陵兰岛
  [
    [-45.0, 60.0], [-35.0, 65.0], [-20.0, 75.0], [-30.0, 82.0], [-60.0, 80.0], [-55.0, 70.0], [-45.0, 60.0]
  ]
];

// 2D 投影路径计算 (Equirectangular WGS-84)
const worldLandPaths2d = computed(() => {
  return WORLD_LAND_POLYGONS.map(poly => {
    return poly.map((pt, i) => {
      const x = ((pt[0] + 180.0) / 360.0) * 960.0;
      const y = ((90.0 - pt[1]) / 180.0) * 480.0;
      return `${i === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)}`;
    }).join(' ') + ' Z';
  });
});

// 提取具备有效经纬度的航路点
const geoWaypoints = computed<GeoPoint[]>(() => {
  const points: GeoPoint[] = [];
  const validHops = hops.value.filter(h => h.has_geo && !h.is_timeout);

  for (let i = 0; i < validHops.length; i++) {
    const hop = validHops[i];
    const x2d = ((hop.longitude + 180.0) / 360.0) * 960.0;
    const y2d = ((90.0 - hop.latitude) / 180.0) * 480.0;

    points.push({
      hopNumber: hop.hop_number,
      ip: hop.ip,
      lon: hop.longitude,
      lat: hop.latitude,
      x2d,
      y2d,
      rttMs: hop.rtt_ms,
      location: formatLocation(hop),
      isp: hop.isp,
      cumulativeKm: hop.cumulative_distance_km,
      isSelf: hop.is_self ?? (hop.hop_number === 0),
      isFinal: hop.is_destination || (i === validHops.length - 1 && validHops.length > 1),
      rawHop: hop
    });
  }
  return points;
});

// 2D 贝塞尔大圆航线
const flightArcs2d = computed(() => {
  const arcs: { pathData: string; distKm: number; strokeColor: string }[] = [];
  const pts = geoWaypoints.value;
  if (pts.length < 2) return arcs;

  for (let i = 0; i < pts.length - 1; i++) {
    const p1 = pts[i];
    const p2 = pts[i + 1];

    const dx = p2.x2d - p1.x2d;
    const dy = p2.y2d - p1.y2d;
    const distPx = Math.sqrt(dx * dx + dy * dy);

    const midX = (p1.x2d + p2.x2d) / 2;
    const arcHeight = Math.min(60, Math.max(15, distPx * 0.25));
    const midY = (p1.y2d + p2.y2d) / 2 - arcHeight;

    const pathData = `M ${p1.x2d.toFixed(1)} ${p1.y2d.toFixed(1)} Q ${midX.toFixed(1)} ${midY.toFixed(1)} ${p2.x2d.toFixed(1)} ${p2.y2d.toFixed(1)}`;

    let strokeColor = '#06b6d4';
    if (p1.isSelf) strokeColor = '#10b981';
    else if (p2.isFinal) strokeColor = '#f59e0b';

    arcs.push({
      pathData,
      distKm: p2.cumulativeKm - p1.cumulativeKm,
      strokeColor
    });
  }
  return arcs;
});

// 统计距离与光纤理论时延
const totalGeodesicKm = computed(() => {
  if (hops.value.length === 0) return 0;
  const last = [...hops.value].reverse().find(h => h.cumulative_distance_km > 0);
  return last ? last.cumulative_distance_km : 0;
});

const theoreticalMinRtt = computed(() => {
  if (totalGeodesicKm.value <= 0) return 0;
  return (totalGeodesicKm.value * 2.0 / 200000.0) * 1000.0;
});

const actualFinalRttText = computed(() => {
  if (hops.value.length === 0) return '-';
  const last = [...hops.value].reverse().find(h => !h.is_timeout && h.rtt_ms >= 0 && !h.is_self);
  return last ? `${last.rtt_ms.toFixed(1)} ms` : (hops.value[0]?.rtt_ms !== undefined ? `${hops.value[0].rtt_ms.toFixed(1)} ms` : '-');
});

const actualFinalRttClass = computed(() => {
  if (hops.value.length === 0) return 'text-slate-400';
  const last = [...hops.value].reverse().find(h => !h.is_timeout && h.rtt_ms >= 0 && !h.is_self);
  return last ? getRttClass(last.rtt_ms) : 'text-slate-400';
});

// 局域网节点图标匹配
function getLanNodeIcon(hop: TracerouteHopEvent): string {
  if (hop.is_self || hop.hop_number === 0) return 'cpu';
  if (hop.is_destination) return 'radar';
  if (hop.hop_number === 1) return 'link';
  return 'shield';
}

// ============================================================
// 3D 数字地球渲染引擎 (Orthographic 3D Canvas)
// ============================================================
let pulseTime = 0;

function projectLonLatToGlobe(lon: number, lat: number, centerLon: number, centerLat: number, radius: number): { x: number; y: number; visible: boolean } {
  const lambda = (lon * Math.PI) / 180.0;
  const phi = (lat * Math.PI) / 180.0;
  const lambda0 = (centerLon * Math.PI) / 180.0;
  const phi0 = (centerLat * Math.PI) / 180.0;

  const cosC = Math.sin(phi0) * Math.sin(phi) + Math.cos(phi0) * Math.cos(phi) * Math.cos(lambda - lambda0);
  const visible = cosC >= 0;

  const x = radius * Math.cos(phi) * Math.sin(lambda - lambda0);
  const y = radius * (Math.sin(phi0) * Math.cos(phi) * Math.cos(lambda - lambda0) - Math.cos(phi0) * Math.sin(phi));

  return { x, y: -y, visible };
}

function render3dGlobe() {
  const canvas = globeCanvasRef.value;
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  const w = canvas.width;
  const h = canvas.height;
  const cx = w / 2;
  const cy = h / 2;
  const r = globeRotation.value.radius;
  const cLon = globeRotation.value.centerLon;
  const cLat = globeRotation.value.centerLat;

  ctx.clearRect(0, 0, w, h);
  const dark = isDarkTheme.value;

  // 1. 大气外散射光环
  const haloGrad = ctx.createRadialGradient(cx, cy, r * 0.9, cx, cy, r * 1.25);
  haloGrad.addColorStop(0, dark ? 'rgba(6, 182, 212, 0.28)' : 'rgba(14, 165, 233, 0.22)');
  haloGrad.addColorStop(0.5, dark ? 'rgba(14, 165, 233, 0.12)' : 'rgba(59, 130, 246, 0.08)');
  haloGrad.addColorStop(1, 'rgba(15, 23, 42, 0)');
  ctx.fillStyle = haloGrad;
  ctx.beginPath();
  ctx.arc(cx, cy, r * 1.25, 0, Math.PI * 2);
  ctx.fill();

  // 2. 球体背景色 (双模态：深海宇宙 / 浅海Atlas)
  const sphereGrad = ctx.createRadialGradient(cx - r * 0.35, cy - r * 0.35, r * 0.1, cx, cy, r);
  if (dark) {
    sphereGrad.addColorStop(0, '#0f2744');
    sphereGrad.addColorStop(0.65, '#07162c');
    sphereGrad.addColorStop(1, '#020617');
  } else {
    sphereGrad.addColorStop(0, '#d8ecfc');
    sphereGrad.addColorStop(0.65, '#badbf7');
    sphereGrad.addColorStop(1, '#98c2eb');
  }
  ctx.fillStyle = sphereGrad;
  ctx.beginPath();
  ctx.arc(cx, cy, r, 0, Math.PI * 2);
  ctx.fill();

  ctx.save();
  ctx.beginPath();
  ctx.arc(cx, cy, r, 0, Math.PI * 2);
  ctx.clip();

  // 3. 经纬线网格 (每 30° 一根)
  ctx.strokeStyle = dark ? 'rgba(56, 189, 248, 0.16)' : 'rgba(15, 23, 42, 0.12)';
  ctx.lineWidth = 0.8;

  for (let lat = -60; lat <= 60; lat += 30) {
    ctx.beginPath();
    let started = false;
    for (let lon = -180; lon <= 180; lon += 5) {
      const p = projectLonLatToGlobe(lon, lat, cLon, cLat, r);
      if (p.visible) {
        if (!started) {
          ctx.moveTo(cx + p.x, cy + p.y);
          started = true;
        } else {
          ctx.lineTo(cx + p.x, cy + p.y);
        }
      } else {
        started = false;
      }
    }
    ctx.stroke();
  }

  for (let lon = -180; lon < 180; lon += 30) {
    ctx.beginPath();
    let started = false;
    for (let lat = -90; lat <= 90; lat += 5) {
      const p = projectLonLatToGlobe(lon, lat, cLon, cLat, r);
      if (p.visible) {
        if (!started) {
          ctx.moveTo(cx + p.x, cy + p.y);
          started = true;
        } else {
          ctx.lineTo(cx + p.x, cy + p.y);
        }
      } else {
        started = false;
      }
    }
    ctx.stroke();
  }

  // 4. 自然地球真实经纬度高精大陆板块
  ctx.fillStyle = dark ? 'rgba(30, 58, 95, 0.72)' : 'rgba(248, 250, 252, 0.94)';
  ctx.strokeStyle = dark ? 'rgba(34, 211, 238, 0.35)' : 'rgba(59, 130, 246, 0.38)';
  ctx.lineWidth = 1;

  for (const poly of WORLD_LAND_POLYGONS) {
    ctx.beginPath();
    let isDrawing = false;
    for (let i = 0; i < poly.length; i++) {
      const pt = poly[i];
      const p = projectLonLatToGlobe(pt[0], pt[1], cLon, cLat, r);
      if (p.visible) {
        if (!isDrawing) {
          ctx.moveTo(cx + p.x, cy + p.y);
          isDrawing = true;
        } else {
          ctx.lineTo(cx + p.x, cy + p.y);
        }
      }
    }
    if (isDrawing) {
      ctx.closePath();
      ctx.fill();
      ctx.stroke();
    }
  }

  // 5. 绘制三维大圆测地飞线与粒子流光
  const pts = geoWaypoints.value;
  if (pts.length >= 2) {
    for (let i = 0; i < pts.length - 1; i++) {
      const p1 = pts[i];
      const p2 = pts[i + 1];

      const numSteps = 24;
      const arcPoints: { x: number; y: number; visible: boolean }[] = [];

      for (let s = 0; s <= numSteps; s++) {
        const t = s / numSteps;
        const interpLon = p1.lon + (p2.lon - p1.lon) * t;
        const interpLat = p1.lat + (p2.lat - p1.lat) * t;
        const alt = Math.sin(t * Math.PI) * (r * 0.18);
        const pt = projectLonLatToGlobe(interpLon, interpLat, cLon, cLat, r + alt);
        arcPoints.push(pt);
      }

      ctx.beginPath();
      let started = false;
      for (const ap of arcPoints) {
        if (ap.visible) {
          if (!started) {
            ctx.moveTo(cx + ap.x, cy + ap.y);
            started = true;
          } else {
            ctx.lineTo(cx + ap.x, cy + ap.y);
          }
        }
      }
      ctx.strokeStyle = p1.isSelf ? 'rgba(16, 185, 129, 0.75)' : (p2.isFinal ? 'rgba(245, 158, 11, 0.75)' : 'rgba(6, 182, 212, 0.75)');
      ctx.lineWidth = 2.2;
      ctx.stroke();

      const flowT = (pulseTime * 0.8 + i * 0.3) % 1.0;
      const flowIdx = Math.floor(flowT * (arcPoints.length - 1));
      const flowPt = arcPoints[flowIdx];
      if (flowPt && flowPt.visible) {
        ctx.fillStyle = '#ffffff';
        ctx.shadowColor = '#06b6d4';
        ctx.shadowBlur = 8;
        ctx.beginPath();
        ctx.arc(cx + flowPt.x, cy + flowPt.y, 3.2, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowBlur = 0;
      }
    }
  }

  // 6. 绘制航路点信标
  for (const pt of pts) {
    const p = projectLonLatToGlobe(pt.lon, pt.lat, cLon, cLat, r);
    if (p.visible) {
      const px = cx + p.x;
      const py = cy + p.y;

      const pulseR = 5 + (Math.sin(pulseTime * 4) + 1) * 2.5;
      ctx.beginPath();
      ctx.arc(px, py, pulseR, 0, Math.PI * 2);
      ctx.strokeStyle = pt.isSelf ? 'rgba(16, 185, 129, 0.5)' : (pt.isFinal ? 'rgba(245, 158, 11, 0.5)' : 'rgba(6, 182, 212, 0.4)');
      ctx.lineWidth = 1.2;
      ctx.stroke();

      ctx.beginPath();
      ctx.arc(px, py, 4, 0, Math.PI * 2);
      ctx.fillStyle = pt.isSelf ? '#10b981' : (pt.isFinal ? '#f59e0b' : '#06b6d4');
      ctx.shadowColor = ctx.fillStyle;
      ctx.shadowBlur = 6;
      ctx.fill();
      ctx.shadowBlur = 0;

      ctx.fillStyle = dark
        ? (pt.isSelf ? '#34d399' : (pt.isFinal ? '#fbbf24' : '#e2e8f0'))
        : (pt.isSelf ? '#047857' : (pt.isFinal ? '#b45309' : '#0f172a'));
      ctx.font = 'bold 11px monospace';
      ctx.textAlign = 'center';
      const labelText = pt.isSelf ? '本机源点' : `#${pt.hopNumber}`;
      ctx.fillText(labelText, px, py - 8);
    }
  }

  ctx.restore();

  ctx.strokeStyle = dark ? 'rgba(56, 189, 248, 0.4)' : 'rgba(14, 116, 144, 0.38)';
  ctx.lineWidth = 1.5;
  ctx.beginPath();
  ctx.arc(cx, cy, r, 0, Math.PI * 2);
  ctx.stroke();
}

function animate() {
  pulseTime += 0.02;

  if (isAutoRotating.value && !globeRotation.value.isDragging && viewMode.value === '3d') {
    globeRotation.value.centerLon = (globeRotation.value.centerLon + 0.15) % 360;
  }

  if (viewMode.value === '3d') {
    render3dGlobe();
  }

  animationFrameId = requestAnimationFrame(animate);
}

function onGlobeMouseDown(e: MouseEvent) {
  globeRotation.value.isDragging = true;
  globeRotation.value.lastMouseX = e.clientX;
  globeRotation.value.lastMouseY = e.clientY;
}

function onGlobeMouseMove(e: MouseEvent) {
  if (!globeRotation.value.isDragging) return;
  const dx = e.clientX - globeRotation.value.lastMouseX;
  const dy = e.clientY - globeRotation.value.lastMouseY;

  globeRotation.value.lastMouseX = e.clientX;
  globeRotation.value.lastMouseY = e.clientY;

  globeRotation.value.centerLon = (globeRotation.value.centerLon - dx * 0.4 + 360) % 360;
  globeRotation.value.centerLat = Math.max(-80, Math.min(80, globeRotation.value.centerLat + dy * 0.4));
}

function onGlobeMouseUp() {
  globeRotation.value.isDragging = false;
}

function onGlobeWheel(e: WheelEvent) {
  const delta = e.deltaY > 0 ? -10 : 10;
  globeRotation.value.radius = Math.max(90, Math.min(240, globeRotation.value.radius + delta));
}

function toggleGlobeAutoRotate() {
  isAutoRotating.value = !isAutoRotating.value;
}

function focusOnSelf() {
  globeRotation.value.centerLon = selfHopInfo.value.lon;
  globeRotation.value.centerLat = selfHopInfo.value.lat;
}

// ============================================================
// 生命周期与数据流
// ============================================================
watch(
  () => props.initialTarget,
  (newVal) => {
    if (newVal) {
      inputTarget.value = newVal;
      // 智能感知: 若为局域网 IP 则自适应切入 LAN 模式
      if (isLanTarget.value) {
        viewMode.value = 'lan';
      } else {
        viewMode.value = '3d';
      }
      if (props.isOpen && !isTracing.value) {
        hops.value = [];
        isFinished.value = false;
      }
    }
  }
);

watch(
  () => props.isOpen,
  (open) => {
    if (open) {
      if (props.initialTarget) {
        inputTarget.value = props.initialTarget;
      }
      if (isLanTarget.value) {
        viewMode.value = 'lan';
      }
      setupEventListener();
      initSelfIpGeo();
      nextTick(() => {
        resizeGlobeCanvas();
      });
    } else {
      cleanupEventListener();
    }
  }
);

onMounted(() => {
  themeObserver = new MutationObserver(() => {
    isDarkTheme.value = !document.documentElement.classList.contains('theme-apple-light');
  });
  themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });

  window.addEventListener('resize', resizeGlobeCanvas);
  if (props.isOpen) {
    if (isLanTarget.value) {
      viewMode.value = 'lan';
    }
    setupEventListener();
    initSelfIpGeo();
  }
  nextTick(() => {
    resizeGlobeCanvas();
    animate();
  });
});

onUnmounted(() => {
  if (themeObserver) {
    themeObserver.disconnect();
    themeObserver = null;
  }
  window.removeEventListener('resize', resizeGlobeCanvas);
  cleanupEventListener();
  if (animationFrameId) {
    cancelAnimationFrame(animationFrameId);
  }
});

function resizeGlobeCanvas() {
  const canvas = globeCanvasRef.value;
  if (!canvas) return;
  const rect = canvas.getBoundingClientRect();
  if (rect.width > 0 && rect.height > 0) {
    canvas.width = rect.width * window.devicePixelRatio;
    canvas.height = rect.height * window.devicePixelRatio;
    globeRotation.value.radius = Math.min(rect.width, rect.height) * 0.42 * window.devicePixelRatio;
  }
}

async function initSelfIpGeo() {
  try {
    const selfHop = await invoke<TracerouteHopEvent>('get_self_ip_geo_cmd', {
      target: inputTarget.value.trim() || undefined
    });
    if (selfHop) {
      updateSelfHopState(selfHop);
    }
  } catch (err) {
    console.warn('获取使用者自我 IP 失败:', err);
  }
}

function updateSelfHopState(hop: TracerouteHopEvent) {
  selfHopInfo.value.ip = hop.ip;
  selfHopInfo.value.location = formatLocation(hop);
  selfHopInfo.value.isp = hop.isp || '本地适配器';
  if (hop.has_geo) {
    selfHopInfo.value.lon = hop.longitude;
    selfHopInfo.value.lat = hop.latitude;
    selfHopInfo.value.refineStatus = hop.ip.startsWith('192.168.') || hop.ip.startsWith('10.') || hop.ip.startsWith('172.') ? '局域网 (已关联物理城市)' : '公网 IP 直连';
    globeRotation.value.centerLon = hop.longitude;
    globeRotation.value.centerLat = hop.latitude;
  }
}

async function setupEventListener() {
  if (unlistenHopEvent) return;
  try {
    unlistenHopEvent = await listen<TracerouteHopEvent>('traceroute-hop-event', (event) => {
      const hop = event.payload;
      currentHop.value = hop.hop_number;

      if (hop.is_self || hop.hop_number === 0) {
        updateSelfHopState(hop);
      }

      const existingIdx = hops.value.findIndex(h => h.hop_number === hop.hop_number);
      if (existingIdx >= 0) {
        hops.value[existingIdx] = hop;
      } else {
        hops.value.push(hop);
      }

      hops.value.sort((a, b) => a.hop_number - b.hop_number);

      statusMessage.value = hop.is_self
        ? `使用者自我源点已锚定: ${hop.ip} (${selfHopInfo.value.location})`
        : `正在探测第 ${hop.hop_number} 跳: ${hop.ip} (${hop.rtt_ms >= 0 ? hop.rtt_ms.toFixed(1) + 'ms' : '*'})`;

      if (hop.is_destination) {
        isFinished.value = true;
        isTracing.value = false;
        statusMessage.value = `已成功抵达最终目标: ${hop.ip}`;
      }
    });
  } catch (err) {
    console.error('注册 traceroute-hop-event 失败:', err);
  }
}

function cleanupEventListener() {
  if (unlistenHopEvent) {
    unlistenHopEvent();
    unlistenHopEvent = null;
  }
}

async function startTrace() {
  if (!inputTarget.value.trim()) return;
  if (isTracing.value) return;

  // 自适应选择模式
  if (isLanTarget.value) {
    viewMode.value = 'lan';
  }

  isTracing.value = true;
  isFinished.value = false;
  hops.value = [];
  hoveredHop.value = null;
  selectedHop.value = null;
  statusMessage.value = `正在启动对 ${inputTarget.value} 的路由追踪...`;

  try {
    await setupEventListener();
    await invoke('start_traceroute_cmd', {
      target: inputTarget.value.trim(),
      maxHops: maxHops.value,
      timeoutMs: timeoutMs.value
    });
    isFinished.value = true;
    statusMessage.value = `路由追踪已完成 (总计 ${hops.value.length} 跃点)`;
  } catch (err: any) {
    statusMessage.value = `探测出错: ${String(err)}`;
  } finally {
    isTracing.value = false;
  }
}

function stopTrace() {
  isTracing.value = false;
  statusMessage.value = '已停止探测';
}

function handleClose() {
  emit('close');
}

function selectHopRow(hop: TracerouteHopEvent) {
  selectedHop.value = {
    hopNumber: hop.hop_number,
    ip: hop.ip,
    lon: hop.longitude,
    lat: hop.latitude,
    x2d: 0,
    y2d: 0,
    rttMs: hop.rtt_ms,
    location: formatLocation(hop),
    isp: hop.isp,
    cumulativeKm: hop.cumulative_distance_km,
    isSelf: hop.is_self ?? (hop.hop_number === 0),
    isFinal: hop.is_destination,
    rawHop: hop
  };
  if (hop.has_geo) {
    globeRotation.value.centerLon = hop.longitude;
    globeRotation.value.centerLat = hop.latitude;
  }
}

function formatLocation(hop: TracerouteHopEvent): string {
  const parts: string[] = [];
  if (hop.country && hop.country !== '未知') parts.push(hop.country);
  if (hop.province && hop.province !== '未知' && hop.province !== hop.country) parts.push(hop.province);
  if (hop.city && hop.city !== '未知' && hop.city !== hop.province) parts.push(hop.city);
  return parts.join(' · ') || (hop.is_self ? '本地主机终端' : (hop.is_lan ? '局域网/内网' : '骨干网络跃点'));
}

function getRttClass(rtt: number): string {
  if (rtt < 0) return 'text-slate-500';
  if (rtt < 1.0) return 'text-emerald-700 dark:text-emerald-400 font-bold';
  if (rtt < 30) return 'text-sky-700 dark:text-cyan-400 font-bold';
  if (rtt < 80) return 'text-blue-700 dark:text-sky-400 font-bold';
  if (rtt < 150) return 'text-amber-700 dark:text-amber-400 font-bold';
  return 'text-rose-700 dark:text-rose-400 font-bold';
}

function getRttBarColor(rtt: number): string {
  if (rtt < 1.0) return 'bg-emerald-500';
  if (rtt < 30) return 'bg-cyan-500';
  if (rtt < 80) return 'bg-sky-500';
  if (rtt < 150) return 'bg-amber-500';
  return 'bg-rose-500';
}

async function exportTracerouteReport() {
  if (hops.value.length === 0) return;

  const now = new Date().toISOString();
  let md = `# Omni-Probe 路由追踪与微观拓扑架构审计报告\n\n`;
  md += `- **目标主机**: \`${inputTarget.value}\` (${isLanTarget.value ? '企业局域网/内网私有地址' : '广域互联网'})\n`;
  md += `- **使用者自我主机 (Hop 0)**: \`${selfHopInfo.value.ip}\` (${selfHopInfo.value.location} · ${selfHopInfo.value.isp})\n`;
  md += `- **探测时间**: ${now}\n`;
  md += `- **探测总跳数**: ${hops.value.length} 跃点\n`;
  md += `- **累计物理线缆跨度**: ${isLanTarget.value ? (totalGeodesicKm.value * 1000).toFixed(0) + ' m' : totalGeodesicKm.value.toFixed(1) + ' km'}\n`;
  md += `- **理论最低时延**: ${theoreticalMinRtt.value.toFixed(2)} ms\n`;
  md += `- **实测终点网络往返 (RTT_act)**: ${actualFinalRttText.value}\n\n`;
  md += `## 1. 逐跳网络拓扑与物理学剖析\n\n`;
  md += `| 跳数 | 路由器 / 主机 IP | RTT (ms) | 网络角色 | 地理归属 | 子网 (CIDR) | 物理线缆距 | 缓冲排队剖析 |\n`;
  md += `| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n`;

  for (const h of hops.value) {
    const loc = formatLocation(h);
    const rtt = h.is_timeout ? '*' : (h.is_self ? '0.0' : h.rtt_ms.toFixed(1));
    const distStr = isLanTarget.value ? `~${Math.round(h.cumulative_distance_km * 1000)}m` : `${h.cumulative_distance_km.toFixed(1)}km`;
    const hopLabel = h.is_self ? '**源点 #0 (本机)**' : `#${h.hop_number}`;
    const role = h.lan_role || (h.is_self ? '本机源端主机' : '骨干网络跃点');
    const subnet = h.subnet_cidr || '-';
    const queueRatio = isLanTarget.value ? (h.rtt_ms < 1.0 ? '微秒线速' : '正常交换') : (h.bufferbloat_ratio > 0 ? `${h.bufferbloat_ratio.toFixed(1)}x` : '-');
    md += `| ${hopLabel} | \`${h.ip}\` | ${rtt} | ${role} | ${loc} | ${subnet} | ${distStr} | ${queueRatio} |\n`;
  }

  md += `\n---\n*Omni-Probe 工业网络全息分析仪 · 物理网络与等保三级司法溯源审计中心*\n`;

  await saveTextViaNativeDesktop(
    `traceroute_report_${inputTarget.value.replace(/[^a-zA-Z0-9]/g, '_')}_${Date.now()}.md`,
    md,
    'Markdown 报告 (*.md)',
    '*.md',
    '导出地理路径剖析报告'
  );
}
</script>

<style scoped>
@keyframes dash {
  to {
    stroke-dashoffset: -40;
  }
}

.animate-dash {
  animation: dash 2s linear infinite;
}

@keyframes dashH {
  0% {
    transform: translateX(-100%);
  }
  100% {
    transform: translateX(300%);
  }
}

.animate-dash-h {
  animation: dashH 1.6s ease-in-out infinite;
}
</style>
