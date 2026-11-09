<template>
  <div v-if="isOpen" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/70 backdrop-blur-md select-none">
    <div class="w-full max-w-6xl bg-slate-900/95 text-slate-100 backdrop-blur-2xl rounded-3xl border border-slate-700/60 shadow-2xl flex flex-col overflow-hidden max-h-[94vh] animate-in fade-in zoom-in-95 duration-150">
      
      <!-- 1. 顶部控制栏 (工业级玻璃质感) -->
      <div class="px-6 py-3.5 border-b border-slate-800 bg-slate-950/60 flex items-center justify-between shrink-0">
        <div class="flex items-center gap-3">
          <div class="w-9 h-9 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 text-lg shadow-inner">
            🌐
          </div>
          <div>
            <div class="flex items-center gap-2">
              <h3 class="text-base font-bold font-mono tracking-tight text-white flex items-center gap-2">
                <span>测地线可视路由追踪</span>
                <span class="text-xs px-2 py-0.5 rounded-full bg-cyan-950 text-cyan-300 border border-cyan-800/60 font-sans">
                  Geodesic Traceroute & Topology
                </span>
              </h3>
              <span v-if="isTracing" class="flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-mono bg-amber-500/10 text-amber-300 border border-amber-500/30 animate-pulse">
                <span class="w-2 h-2 rounded-full bg-amber-400"></span>
                正在流式探测中 (Hop {{ currentHop }})...
              </span>
              <span v-else-if="hops.length > 0 && isFinished" class="flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-mono bg-emerald-500/10 text-emerald-300 border border-emerald-500/30">
                <span class="w-2 h-2 rounded-full bg-emerald-400"></span>
                路由追踪完成 (共 {{ hops.length }} 跳)
              </span>
            </div>
            <p class="text-[11px] text-slate-400 font-mono mt-0.5">
              全球离线测地大圆航线模拟 · 纯脱机经纬度投射 · 物理光纤时延比对与网络排队缓冲剖析
            </p>
          </div>
        </div>

        <!-- 右侧操作按钮组 -->
        <div class="flex items-center gap-2">
          <!-- 导出溯源报告 -->
          <button
            v-if="hops.length > 0"
            @click="exportTracerouteReport"
            class="px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-mono font-medium transition-all flex items-center gap-1.5 cursor-pointer active:scale-95 shadow-sm"
            title="导出当前测地线路由追踪审计报告"
          >
            <span>📑 导出审计报告</span>
          </button>

          <!-- 关闭弹窗 -->
          <button
            @click="handleClose"
            class="w-8 h-8 rounded-full flex items-center justify-center text-slate-400 hover:text-white hover:bg-slate-800 transition-colors cursor-pointer text-base"
          >
            ✕
          </button>
        </div>
      </div>

      <!-- 2. 目标配置与探测调度条 -->
      <div class="px-6 py-2.5 bg-slate-950/40 border-b border-slate-800/80 flex items-center justify-between flex-wrap gap-3 shrink-0 text-xs font-mono">
        <div class="flex items-center gap-2 flex-wrap">
          <label class="text-slate-400 flex items-center gap-1 font-sans">
            <span>🎯 目标主机:</span>
          </label>
          <input
            v-model="inputTarget"
            :disabled="isTracing"
            type="text"
            placeholder="IPv4 地址或域名 (例如: 8.8.8.8, 114.114.114.114)"
            class="px-3 py-1.5 w-64 bg-slate-900 border border-slate-700 rounded-xl text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono text-xs shadow-inner"
            @keyup.enter="startTrace"
          />

          <label class="text-slate-400 ml-2 flex items-center gap-1 font-sans">
            <span>跳数上限:</span>
          </label>
          <select
            v-model.number="maxHops"
            :disabled="isTracing"
            class="px-2 py-1.5 bg-slate-900 border border-slate-700 rounded-xl text-slate-200 focus:outline-none focus:border-cyan-500 text-xs cursor-pointer"
          >
            <option :value="15">15 跳 (快速)</option>
            <option :value="30">30 跳 (标准)</option>
            <option :value="45">45 跳 (深度)</option>
            <option :value="64">64 跳 (全网穷尽)</option>
          </select>

          <label class="text-slate-400 ml-2 flex items-center gap-1 font-sans">
            <span>单跳超时:</span>
          </label>
          <select
            v-model.number="timeoutMs"
            :disabled="isTracing"
            class="px-2 py-1.5 bg-slate-900 border border-slate-700 rounded-xl text-slate-200 focus:outline-none focus:border-cyan-500 text-xs cursor-pointer"
          >
            <option :value="500">500 ms (极速)</option>
            <option :value="1000">1000 ms (推荐)</option>
            <option :value="2000">2000 ms (严密)</option>
          </select>

          <!-- 触发/停止按钮 -->
          <button
            v-if="!isTracing"
            @click="startTrace"
            class="ml-3 px-4 py-1.5 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold text-xs shadow-lg shadow-cyan-600/30 flex items-center gap-1.5 cursor-pointer active:scale-95 transition-all"
          >
            <span>⚡ 启动测地追踪</span>
          </button>
          <button
            v-else
            @click="stopTrace"
            class="ml-3 px-4 py-1.5 rounded-xl bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs shadow-lg shadow-rose-600/30 flex items-center gap-1.5 cursor-pointer active:scale-95 transition-all"
          >
            <span>⏹️ 强制终止探测</span>
          </button>
        </div>

        <!-- 汇总关键指标摘要 (物理距离 & 光速时延) -->
        <div class="flex items-center gap-4 text-xs font-mono">
          <div class="flex items-center gap-1 text-slate-300">
            <span class="text-slate-500">测地直线总距:</span>
            <strong class="text-cyan-400">{{ totalGeodesicKm.toFixed(1) }} km</strong>
          </div>
          <div class="flex items-center gap-1 text-slate-300">
            <span class="text-slate-500">光纤理论往返:</span>
            <strong class="text-emerald-400">{{ theoreticalMinRtt.toFixed(2) }} ms</strong>
          </div>
          <div class="flex items-center gap-1 text-slate-300">
            <span class="text-slate-500">实测终点 RTT:</span>
            <strong :class="actualFinalRttClass">{{ actualFinalRttText }}</strong>
          </div>
        </div>
      </div>

      <!-- 3. 中部核心区：上部脱机世界地图测地大圆投影 + 下部指标详情表格 -->
      <div class="flex-1 flex flex-col overflow-y-auto p-4 gap-4 min-h-0 bg-slate-950/80">
        
        <!-- 3.1 纯离线世界地图测地大圆可视化画布 -->
        <div class="relative w-full h-80 rounded-2xl bg-gradient-to-b from-slate-950 via-slate-900 to-slate-950 border border-slate-800 shadow-2xl overflow-hidden flex items-center justify-center shrink-0">
          
          <!-- 装饰性工业背景网格与经纬坐标 -->
          <div class="absolute inset-0 bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:24px_24px] opacity-40"></div>
          
          <!-- SVG 投影主画布 (960 x 480 等角圆柱投影，支持 100% 脱机矢量渲染) -->
          <svg
            viewBox="0 0 960 480"
            class="w-full h-full object-contain select-none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <defs>
              <!-- 飞线光晕滤镜 -->
              <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
                <feGaussianBlur stdDeviation="3" result="blur" />
                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>

              <!-- 渐变飞线颜色 -->
              <linearGradient id="flightGradient" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stop-color="#10b981" />
                <stop offset="50%" stop-color="#06b6d4" />
                <stop offset="100%" stop-color="#f59e0b" />
              </linearGradient>
            </defs>

            <!-- 1. 经纬线网格 (Equirectangular Grid: 经线每 30° 一条，纬线每 30° 一条) -->
            <g class="stroke-slate-800/50 stroke-[0.8]" stroke-dasharray="2 3">
              <!-- 赤道 (0°) -->
              <line x1="0" y1="240" x2="960" y2="240" class="stroke-slate-700/80 stroke-1" stroke-dasharray="none" />
              <!-- 本初子午线 (0°) -->
              <line x1="480" y1="0" x2="480" y2="480" class="stroke-slate-700/80 stroke-1" stroke-dasharray="none" />
              <!-- 南北回归线 (±23.5°) -->
              <line x1="0" y1="177.3" x2="960" y2="177.3" class="stroke-cyan-900/30" />
              <line x1="0" y1="302.7" x2="960" y2="302.7" class="stroke-cyan-900/30" />
              <!-- 其他纬线 -->
              <line x1="0" y1="80" x2="960" y2="80" />
              <line x1="0" y1="160" x2="960" y2="160" />
              <line x1="0" y1="320" x2="960" y2="320" />
              <line x1="0" y1="400" x2="960" y2="400" />
              <!-- 其他经线 -->
              <line v-for="x in [80, 160, 240, 320, 400, 560, 640, 720, 800, 880]" :key="'meridian-' + x" :x1="x" y1="0" :x2="x" y2="480" />
            </g>

            <!-- 2. 脱机世界陆地轮廓矢量 Path (精简高清等角圆柱轮廓) -->
            <g class="fill-slate-800/60 stroke-slate-700/60 stroke-[0.9]">
              <!-- 欧亚大陆与北非核心板块 -->
              <path d="M 450,110 L 480,105 L 530,95 L 590,95 L 670,115 L 750,105 L 800,120 L 850,140 L 880,170 L 820,200 L 780,240 L 740,230 L 710,270 L 680,260 L 640,240 L 600,230 L 570,200 L 530,210 L 510,230 L 470,225 L 450,190 L 430,170 L 440,135 Z" />
              <!-- 非洲大陆板块 -->
              <path d="M 470,235 L 530,235 L 560,270 L 570,330 L 530,390 L 490,395 L 470,330 L 440,280 L 450,250 Z" />
              <!-- 北美洲板块 -->
              <path d="M 120,110 L 220,95 L 280,120 L 270,180 L 240,210 L 220,235 L 180,240 L 150,210 L 120,160 Z" />
              <!-- 南美洲板块 -->
              <path d="M 230,250 L 270,260 L 300,290 L 280,360 L 250,420 L 225,380 L 220,300 Z" />
              <!-- 澳大利亚板块 -->
              <path d="M 760,310 L 820,300 L 850,330 L 830,380 L 770,380 L 750,340 Z" />
              <!-- 格陵兰岛 -->
              <path d="M 330,70 L 370,60 L 390,90 L 350,110 Z" />
              <!-- 日本列岛与东南亚群岛群 -->
              <path d="M 830,180 L 845,195 L 835,215 Z" />
              <path d="M 720,280 L 750,290 L 740,310 Z" />
            </g>

            <!-- 3. 测地大圆飞线 (贝塞尔航线) 动态渲染 -->
            <g>
              <template v-for="(flight, idx) in flightArcs" :key="'flight-' + idx">
                <!-- 底层柔光阴影线 -->
                <path
                  :d="flight.pathData"
                  class="fill-none stroke-cyan-500/20 stroke-[3]"
                />
                <!-- 主航线 (带流动虚线光效) -->
                <path
                  :d="flight.pathData"
                  class="fill-none stroke-[2] animate-dash"
                  :stroke="flight.strokeColor"
                  stroke-dasharray="6 4"
                  filter="url(#glow)"
                />
                <!-- 飞线中段距离标签 -->
                <g v-if="flight.distKm > 50" :transform="`translate(${flight.midX}, ${flight.midY - 8})`">
                  <rect x="-24" y="-9" width="48" height="15" rx="4" class="fill-slate-900/90 stroke-slate-700/80 stroke-[0.7]" />
                  <text text-anchor="middle" y="2" class="fill-cyan-300 font-mono text-[8px] font-bold">
                    {{ Math.round(flight.distKm) }}km
                  </text>
                </g>
              </template>
            </g>

            <!-- 4. 航路点 (Waypoints / Hops) 标记 -->
            <g>
              <g
                v-for="point in geoWaypoints"
                :key="'wp-' + point.hopNumber"
                :transform="`translate(${point.x}, ${point.y})`"
                class="cursor-pointer transition-transform duration-200 hover:scale-125"
                @mouseenter="hoveredHop = point"
                @mouseleave="hoveredHop = null"
                @click="selectedHop = point"
              >
                <!-- 脉冲外光圈 -->
                <circle
                  r="7"
                  :class="point.isFinal ? 'fill-amber-500/20 stroke-amber-400 animate-ping' : (point.isFirst ? 'fill-emerald-500/20 stroke-emerald-400' : 'fill-cyan-500/20 stroke-cyan-400')"
                  class="stroke-[1.5]"
                />
                <!-- 核心实心圆点 -->
                <circle
                  r="3.5"
                  :class="point.isFinal ? 'fill-amber-400' : (point.isFirst ? 'fill-emerald-400' : 'fill-cyan-400')"
                />
                <!-- 跳数序号徽标 -->
                <text
                  text-anchor="middle"
                  y="-9"
                  class="font-mono text-[9px] font-bold fill-slate-200 select-none shadow-sm"
                >
                  #{{ point.hopNumber }}
                </text>
              </g>
            </g>
          </svg>

          <!-- 悬停节点即时情报卡片 (Floating Tooltip) -->
          <div
            v-if="hoveredHop"
            class="absolute top-3 left-3 bg-slate-900/95 border border-cyan-500/40 rounded-xl p-3 shadow-2xl backdrop-blur-xl text-xs font-mono z-30 pointer-events-none animate-in fade-in zoom-in-95 duration-100 max-w-xs"
          >
            <div class="flex items-center justify-between gap-2 border-b border-slate-800 pb-1.5 mb-1.5">
              <span class="text-cyan-400 font-bold">Hop #{{ hoveredHop.hopNumber }}</span>
              <span class="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-300">
                RTT: {{ hoveredHop.rttMs >= 0 ? hoveredHop.rttMs.toFixed(1) + ' ms' : '*' }}
              </span>
            </div>
            <div class="text-white font-bold mb-1">{{ hoveredHop.ip }}</div>
            <div class="text-slate-300 text-[11px] flex items-center gap-1">
              <span>📍</span>
              <span>{{ hoveredHop.location }}</span>
            </div>
            <div v-if="hoveredHop.isp" class="text-slate-400 text-[10px] mt-0.5">
              🏢 {{ hoveredHop.isp }}
            </div>
            <div class="text-slate-500 text-[9px] mt-1 flex items-center justify-between">
              <span>坐标: [{{ hoveredHop.lon.toFixed(2) }}°, {{ hoveredHop.lat.toFixed(2) }}°]</span>
              <span>距起点: {{ hoveredHop.cumulativeKm.toFixed(1) }} km</span>
            </div>
          </div>

          <!-- 地图左下角底图与投影说明 -->
          <div class="absolute bottom-2 left-3 text-[10px] font-mono text-slate-500 flex items-center gap-2 select-none">
            <span>🗺️ 投影体系: 等角圆柱投影 (Equirectangular WGS-84)</span>
            <span>·</span>
            <span>100% 离线脱机</span>
          </div>

          <!-- 地图右下角图例 (Legend) -->
          <div class="absolute bottom-2 right-3 flex items-center gap-3 text-[10px] font-mono bg-slate-950/80 px-2.5 py-1 rounded-lg border border-slate-800 select-none">
            <div class="flex items-center gap-1 text-emerald-400">
              <span class="w-2 h-2 rounded-full bg-emerald-400"></span>
              <span>源探测点</span>
            </div>
            <div class="flex items-center gap-1 text-cyan-400">
              <span class="w-2 h-2 rounded-full bg-cyan-400"></span>
              <span>骨干跳</span>
            </div>
            <div class="flex items-center gap-1 text-amber-400">
              <span class="w-2 h-2 rounded-full bg-amber-400"></span>
              <span>目标端</span>
            </div>
          </div>
        </div>

        <!-- 3.2 下半部分：逐跳详尽指标数据表 (Hop Table) -->
        <div class="flex-1 flex flex-col min-h-0 bg-slate-900/90 rounded-2xl border border-slate-800 shadow-xl overflow-hidden">
          
          <!-- 表头栏 -->
          <div class="px-4 py-2.5 bg-slate-950/70 border-b border-slate-800 flex items-center justify-between shrink-0 text-xs font-mono">
            <div class="flex items-center gap-2 text-slate-300 font-bold">
              <span>📋 路由跳数全息清单 (Hop-by-Hop Telemetry)</span>
              <span class="text-[11px] px-2 py-0.2 rounded-full bg-slate-800 text-slate-400 font-normal">
                已探测 {{ hops.length }} 节点
              </span>
            </div>
            <div class="text-[11px] text-slate-500">
              与 ip2region.xdb 离线高精库实时比对 · 纯物理测距
            </div>
          </div>

          <!-- 滚动表格列表 -->
          <div class="flex-1 overflow-y-auto">
            <table class="w-full text-left font-mono text-xs border-collapse">
              <thead class="bg-slate-950/90 text-slate-400 sticky top-0 z-10 border-b border-slate-800 text-[11px]">
                <tr>
                  <th class="py-2 px-3 w-14 text-center">跳数</th>
                  <th class="py-2 px-3 w-36">路由器 IP</th>
                  <th class="py-2 px-3 w-28">RTT 时延</th>
                  <th class="py-2 px-3 w-56">地理归属 (国家/省/市)</th>
                  <th class="py-2 px-3 w-32">运营商 (ISP)</th>
                  <th class="py-2 px-3 w-36">测地坐标 (Lon, Lat)</th>
                  <th class="py-2 px-3 w-28">区间物理距</th>
                  <th class="py-2 px-3 w-28">累计物理距</th>
                  <th class="py-2 px-3 text-right">缓冲排队剖析</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-800/60 text-slate-300">
                <tr
                  v-for="hop in hops"
                  :key="'hop-row-' + hop.hop_number"
                  :class="[
                    'hover:bg-slate-800/60 transition-colors cursor-pointer',
                    selectedHop?.hopNumber === hop.hop_number ? 'bg-cyan-950/40 border-l-2 border-l-cyan-400' : ''
                  ]"
                  @click="selectHopRow(hop)"
                >
                  <!-- 跳数序号 -->
                  <td class="py-2 px-3 text-center font-bold">
                    <span
                      :class="[
                        'inline-block px-1.5 py-0.5 rounded text-[10px]',
                        hop.is_destination ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 font-bold' : (hop.hop_number === 1 ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' : 'bg-slate-800 text-slate-300')
                      ]"
                    >
                      #{{ hop.hop_number }}
                    </span>
                  </td>

                  <!-- 节点 IP -->
                  <td class="py-2 px-3 font-bold text-white flex items-center gap-1.5">
                    <span v-if="hop.is_timeout" class="text-slate-500 italic">* (超时丢包)</span>
                    <span v-else>{{ hop.ip }}</span>
                    <span v-if="hop.is_destination" class="text-[9px] px-1 rounded bg-amber-900/60 text-amber-200 border border-amber-700">终点</span>
                  </td>

                  <!-- RTT 延迟与可视化条形图 -->
                  <td class="py-2 px-3">
                    <div v-if="hop.is_timeout" class="text-slate-500 italic">* ms</div>
                    <div v-else class="flex items-center gap-2">
                      <span :class="getRttClass(hop.rtt_ms)" class="w-12 font-bold">{{ hop.rtt_ms.toFixed(1) }} ms</span>
                      <!-- 迷你时延条 -->
                      <div class="w-12 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                        <div
                          class="h-full rounded-full transition-all"
                          :class="getRttBarColor(hop.rtt_ms)"
                          :style="{ width: Math.min(100, (hop.rtt_ms / 200) * 100) + '%' }"
                        ></div>
                      </div>
                    </div>
                  </td>

                  <!-- 地理归属 -->
                  <td class="py-2 px-3 text-slate-200">
                    <div class="flex items-center gap-1">
                      <span v-if="hop.country && hop.country !== '未知'">🌍 {{ formatLocation(hop) }}</span>
                      <span v-else class="text-slate-500 italic">内网 / 未知跃点</span>
                    </div>
                  </td>

                  <!-- 运营商 ISP -->
                  <td class="py-2 px-3 text-slate-300 text-[11px]">
                    <span v-if="hop.isp && hop.isp !== '未知'" class="px-1.5 py-0.5 rounded bg-slate-800/80 border border-slate-700/60 text-slate-200">
                      {{ hop.isp }}
                    </span>
                    <span v-else class="text-slate-600">-</span>
                  </td>

                  <!-- 测地坐标 -->
                  <td class="py-2 px-3 text-slate-400 text-[11px]">
                    <span v-if="hop.has_geo" class="text-cyan-400">
                      [{{ hop.longitude.toFixed(2) }}°, {{ hop.latitude.toFixed(2) }}°]
                    </span>
                    <span v-else class="text-slate-600">-</span>
                  </td>

                  <!-- 区间物理距离 -->
                  <td class="py-2 px-3 text-slate-300">
                    <span v-if="hop.segment_distance_km > 0" class="text-slate-200">
                      +{{ hop.segment_distance_km.toFixed(1) }} km
                    </span>
                    <span v-else class="text-slate-600">0.0 km</span>
                  </td>

                  <!-- 累计物理距离 -->
                  <td class="py-2 px-3 text-slate-300 font-bold">
                    <span v-if="hop.cumulative_distance_km > 0" class="text-cyan-300">
                      {{ hop.cumulative_distance_km.toFixed(1) }} km
                    </span>
                    <span v-else class="text-slate-600">0.0 km</span>
                  </td>

                  <!-- 缓冲排队剖析 (Bufferbloat Analysis) -->
                  <td class="py-2 px-3 text-right">
                    <span
                      v-if="!hop.is_timeout && hop.bufferbloat_ratio > 0"
                      :class="[
                        'px-2 py-0.5 rounded text-[10px] font-bold border',
                        hop.bufferbloat_ratio > 10 ? 'bg-rose-500/10 text-rose-300 border-rose-500/30' : (hop.bufferbloat_ratio > 4 ? 'bg-amber-500/10 text-amber-300 border-amber-500/30' : 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30')
                      ]"
                      :title="`理论光纤时延: ${hop.fiber_rtt_ms.toFixed(2)}ms, 排队比率: ${hop.bufferbloat_ratio.toFixed(1)}x`"
                    >
                      {{ hop.bufferbloat_ratio > 10 ? '严重排队 ⚠️' : (hop.bufferbloat_ratio > 4 ? '轻度拥塞 ⚡' : '物理极限 🟢') }}
                    </span>
                    <span v-else class="text-slate-600">-</span>
                  </td>
                </tr>

                <!-- 空状态说明 -->
                <tr v-if="hops.length === 0">
                  <td colspan="9" class="py-12 text-center text-slate-500">
                    <div class="flex flex-col items-center justify-center gap-2">
                      <span class="text-3xl">🌐</span>
                      <span>暂无路由探测数据。输入目标 IP 或域名，点击【启动测地追踪】开始探测</span>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

      </div>

      <!-- 4. 底部状态指示栏 -->
      <div class="px-6 py-2.5 bg-slate-950 border-t border-slate-800 flex items-center justify-between text-[11px] font-mono text-slate-400 shrink-0">
        <div class="flex items-center gap-3">
          <span>算法核心: Haversine 球面测地大圆公式</span>
          <span>·</span>
          <span>光速参考折射率: n ≈ 1.47 (200,000 km/s)</span>
          <span>·</span>
          <span>IP 引擎: ip2region.xdb 离线嵌入</span>
        </div>
        <div class="flex items-center gap-2">
          <span v-if="statusMessage" class="text-cyan-400">{{ statusMessage }}</span>
          <span v-else class="text-slate-500">就绪</span>
        </div>
      </div>

    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';

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
}

interface GeoPoint {
  hopNumber: number;
  ip: string;
  lon: number;
  lat: number;
  x: number;
  y: number;
  rttMs: number;
  location: string;
  isp: string;
  cumulativeKm: number;
  isFirst: boolean;
  isFinal: boolean;
}

interface FlightArc {
  pathData: string;
  distKm: number;
  midX: number;
  midY: number;
  strokeColor: string;
}

const props = defineProps<{
  isOpen: boolean;
  initialTarget?: string;
}>();

const emit = defineEmits<{
  (e: 'close'): void;
}>();

// 输入与配置
const inputTarget = ref(props.initialTarget || '8.8.8.8');
const maxHops = ref(30);
const timeoutMs = ref(1000);

// 探测状态
const isTracing = ref(false);
const isFinished = ref(false);
const currentHop = ref(1);
const hops = ref<TracerouteHopEvent[]>([]);
const statusMessage = ref('');

// 交互选中
const hoveredHop = ref<GeoPoint | null>(null);
const selectedHop = ref<GeoPoint | null>(null);

let unlistenHopEvent: UnlistenFn | null = null;

// 监听初始传入的目标变化
watch(
  () => props.initialTarget,
  (newVal) => {
    if (newVal) {
      inputTarget.value = newVal;
      // 若弹窗打开且未在探测，直接清空历史准备探测
      if (props.isOpen && !isTracing.value) {
        hops.value = [];
        isFinished.value = false;
      }
    }
  }
);

// 当弹窗打开时，若有 target 且 hops 为空，可自动准备
watch(
  () => props.isOpen,
  (open) => {
    if (open) {
      if (props.initialTarget) {
        inputTarget.value = props.initialTarget;
      }
      setupEventListener();
    } else {
      cleanupEventListener();
    }
  }
);

onMounted(() => {
  if (props.isOpen) {
    setupEventListener();
  }
});

onUnmounted(() => {
  cleanupEventListener();
});

// 设置 Tauri 事件流式监听
async function setupEventListener() {
  if (unlistenHopEvent) return;
  try {
    unlistenHopEvent = await listen<TracerouteHopEvent>('traceroute-hop-event', (event) => {
      const hop = event.payload;
      currentHop.value = hop.hop_number;
      
      // 更新或追加 hop
      const existingIdx = hops.value.findIndex(h => h.hop_number === hop.hop_number);
      if (existingIdx >= 0) {
        hops.value[existingIdx] = hop;
      } else {
        hops.value.push(hop);
      }

      statusMessage.value = `正在探测第 ${hop.hop_number} 跳: ${hop.ip} (${hop.rtt_ms >= 0 ? hop.rtt_ms.toFixed(1) + 'ms' : '*'})`;

      if (hop.is_destination) {
        isFinished.value = true;
        isTracing.value = false;
        statusMessage.value = `已成功到达最终目的地: ${hop.ip}`;
      }
    });
  } catch (err) {
    console.error('注册 traceroute-hop-event 监听器失败:', err);
  }
}

function cleanupEventListener() {
  if (unlistenHopEvent) {
    unlistenHopEvent();
    unlistenHopEvent = null;
  }
}

// 启动路由探测
async function startTrace() {
  if (!inputTarget.value.trim()) return;
  if (isTracing.value) return;

  isTracing.value = true;
  isFinished.value = false;
  hops.value = [];
  hoveredHop.value = null;
  selectedHop.value = null;
  statusMessage.value = `正在启动对 ${inputTarget.value} 的测地线路由追踪...`;

  try {
    await setupEventListener();
    await invoke('start_traceroute_cmd', {
      target: inputTarget.value.trim(),
      maxHops: maxHops.value,
      timeoutMs: timeoutMs.value
    });
    isFinished.value = true;
    statusMessage.value = `测地线路由追踪已完成 (总计 ${hops.value.length} 跳)`;
  } catch (err: any) {
    statusMessage.value = `探测出错: ${String(err)}`;
  } finally {
    isTracing.value = false;
  }
}

// 停止探测
function stopTrace() {
  isTracing.value = false;
  statusMessage.value = '已停止探测';
}

function handleClose() {
  emit('close');
}

function selectHopRow(hop: TracerouteHopEvent) {
  if (hop.has_geo) {
    const pt = geoWaypoints.value.find(p => p.hopNumber === hop.hop_number);
    if (pt) {
      selectedHop.value = pt;
    }
  }
}

// 格式化地理位置
function formatLocation(hop: TracerouteHopEvent): string {
  const parts: string[] = [];
  if (hop.country && hop.country !== '未知') parts.push(hop.country);
  if (hop.province && hop.province !== '未知' && hop.province !== hop.country) parts.push(hop.province);
  if (hop.city && hop.city !== '未知' && hop.city !== hop.province) parts.push(hop.city);
  return parts.join(' · ') || '全球骨干网';
}

// RTT 样式
function getRttClass(rtt: number): string {
  if (rtt < 0) return 'text-slate-500';
  if (rtt < 30) return 'text-emerald-400 font-bold';
  if (rtt < 80) return 'text-cyan-400 font-bold';
  if (rtt < 150) return 'text-amber-400 font-bold';
  return 'text-rose-400 font-bold';
}

function getRttBarColor(rtt: number): string {
  if (rtt < 30) return 'bg-emerald-500';
  if (rtt < 80) return 'bg-cyan-500';
  if (rtt < 150) return 'bg-amber-500';
  return 'bg-rose-500';
}

// 统计指标
const totalGeodesicKm = computed(() => {
  if (hops.value.length === 0) return 0;
  const lastWithDist = [...hops.value].reverse().find(h => h.cumulative_distance_km > 0);
  return lastWithDist ? lastWithDist.cumulative_distance_km : 0;
});

const theoreticalMinRtt = computed(() => {
  if (totalGeodesicKm.value <= 0) return 0;
  // 光纤光速按 200,000 km/s 计算往返
  return (totalGeodesicKm.value * 2.0 / 200000.0) * 1000.0;
});

const actualFinalRttText = computed(() => {
  if (hops.value.length === 0) return '-';
  const last = [...hops.value].reverse().find(h => !h.is_timeout && h.rtt_ms >= 0);
  return last ? `${last.rtt_ms.toFixed(1)} ms` : '-';
});

const actualFinalRttClass = computed(() => {
  if (hops.value.length === 0) return 'text-slate-400';
  const last = [...hops.value].reverse().find(h => !h.is_timeout && h.rtt_ms >= 0);
  return last ? getRttClass(last.rtt_ms) : 'text-slate-400';
});

// Equirectangular 投影坐标映射:
// width = 960, height = 480
// x = ((lon + 180) / 360) * 960
// y = ((90 - lat) / 180) * 480
function projectLonLatToSvg(lon: number, lat: number): { x: number; y: number } {
  const clampedLon = Math.max(-180, Math.min(180, lon));
  const clampedLat = Math.max(-90, Math.min(90, lat));
  const x = ((clampedLon + 180.0) / 360.0) * 960.0;
  const y = ((90.0 - clampedLat) / 180.0) * 480.0;
  return { x, y };
}

// 提取所有具备有效坐标的航路点
const geoWaypoints = computed<GeoPoint[]>(() => {
  const points: GeoPoint[] = [];
  const validHops = hops.value.filter(h => h.has_geo && !h.is_timeout);

  for (let i = 0; i < validHops.length; i++) {
    const hop = validHops[i];
    const { x, y } = projectLonLatToSvg(hop.longitude, hop.latitude);
    points.push({
      hopNumber: hop.hop_number,
      ip: hop.ip,
      lon: hop.longitude,
      lat: hop.latitude,
      x,
      y,
      rttMs: hop.rtt_ms,
      location: formatLocation(hop),
      isp: hop.isp,
      cumulativeKm: hop.cumulative_distance_km,
      isFirst: i === 0,
      isFinal: hop.is_destination || i === validHops.length - 1
    });
  }
  return points;
});

// 构建贝塞尔大圆航线弧形
const flightArcs = computed<FlightArc[]>(() => {
  const arcs: FlightArc[] = [];
  const pts = geoWaypoints.value;
  if (pts.length < 2) return arcs;

  for (let i = 0; i < pts.length - 1; i++) {
    const p1 = pts[i];
    const p2 = pts[i + 1];

    const dx = p2.x - p1.x;
    const dy = p2.y - p1.y;
    const distPx = Math.sqrt(dx * dx + dy * dy);

    // 计算实际大圆距离增量
    const nextHop = hops.value.find(h => h.hop_number === p2.hopNumber);
    const distKm = nextHop ? nextHop.segment_distance_km : 0;

    // 二次贝塞尔控制点：向上弧起一个高度 offset
    const midX = (p1.x + p2.x) / 2;
    // 弧度高度根据像素距离成比例，但不超过 60 像素
    const arcHeight = Math.min(60, Math.max(15, distPx * 0.25));
    const midY = (p1.y + p2.y) / 2 - arcHeight;

    const pathData = `M ${p1.x.toFixed(1)} ${p1.y.toFixed(1)} Q ${midX.toFixed(1)} ${midY.toFixed(1)} ${p2.x.toFixed(1)} ${p2.y.toFixed(1)}`;

    // 渐变色彩区分
    let strokeColor = '#06b6d4'; // cyan
    if (p2.isFinal) strokeColor = '#f59e0b'; // amber
    else if (p1.isFirst) strokeColor = '#10b981'; // emerald

    arcs.push({
      pathData,
      distKm,
      midX,
      midY,
      strokeColor
    });
  }

  return arcs;
});

// 导出审计报告
function exportTracerouteReport() {
  if (hops.value.length === 0) return;

  const now = new Date().toISOString();
  let md = `# Omni-Probe 测地线可视路由追踪与网络物理审计报告\n\n`;
  md += `- **目标主机**: \`${inputTarget.value}\`\n`;
  md += `- **探测时间**: ${now}\n`;
  md += `- **探测总跳数**: ${hops.value.length} 跳\n`;
  md += `- **测地线总物理距离**: ${totalGeodesicKm.value.toFixed(1)} km\n`;
  md += `- **光纤真空理论往返极限 (RTT_min)**: ${theoreticalMinRtt.value.toFixed(2)} ms\n`;
  md += `- **实测终点网络往返 (RTT_act)**: ${actualFinalRttText.value}\n\n`;
  md += `## 1. 逐跳网络拓扑与物理学剖析\n\n`;
  md += `| 跳数 | 路由器 IP | RTT (ms) | 地理归属 | 运营商 (ISP) | 测地经纬度 | 区间距离 (km) | 累计物理距 (km) | 光纤极限 RTT | 缓冲排队比率 |\n`;
  md += `| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n`;

  for (const h of hops.value) {
    const loc = formatLocation(h);
    const rtt = h.is_timeout ? '*' : h.rtt_ms.toFixed(1);
    const coords = h.has_geo ? `[${h.longitude.toFixed(2)}°, ${h.latitude.toFixed(2)}°]` : '-';
    const fiberRtt = h.fiber_rtt_ms > 0 ? h.fiber_rtt_ms.toFixed(2) : '-';
    const queueRatio = h.bufferbloat_ratio > 0 ? `${h.bufferbloat_ratio.toFixed(1)}x` : '-';
    md += `| #${h.hop_number} | \`${h.ip}\` | ${rtt} | ${loc} | ${h.isp || '-'} | ${coords} | ${h.segment_distance_km.toFixed(1)} | ${h.cumulative_distance_km.toFixed(1)} | ${fiberRtt} | ${queueRatio} |\n`;
  }

  md += `\n---\n*Omni-Probe 工业网络全息分析仪 · 物理网络与等保三级司法溯源审计中心*\n`;

  // 创建下载链接导出
  const blob = new Blob([md], { type: 'text/markdown;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `traceroute_audit_${inputTarget.value.replace(/[^a-zA-Z0-9]/g, '_')}_${Date.now()}.md`;
  a.click();
  URL.revokeObjectURL(url);
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
</style>
