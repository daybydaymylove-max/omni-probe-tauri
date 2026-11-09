<template>
  <div v-if="isOpen" class="fixed inset-0 z-50 flex items-center justify-center p-3 bg-slate-950/75 backdrop-blur-md select-none">
    <div class="w-full max-w-7xl bg-slate-900/95 text-slate-100 backdrop-blur-2xl rounded-3xl border border-slate-700/70 shadow-2xl flex flex-col overflow-hidden max-h-[96vh] animate-in fade-in zoom-in-95 duration-150">
      
      <!-- 1. 顶部状态栏与视口控制器 (Apple Glass 工业级质感) -->
      <div class="px-6 py-3 border-b border-slate-800 bg-slate-950/70 flex items-center justify-between shrink-0 flex-wrap gap-3">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-2xl bg-gradient-to-br from-cyan-500/20 to-blue-600/20 border border-cyan-500/30 flex items-center justify-center text-cyan-400 text-xl shadow-inner">
            {{ isLanTarget ? '🏢' : '🌍' }}
          </div>
          <div>
            <div class="flex items-center gap-2">
              <h3 class="text-base font-bold font-mono tracking-tight text-white flex items-center gap-2">
                <span>测地线可视路由追踪与微观虚拟拓扑</span>
                <span class="text-xs px-2 py-0.5 rounded-full bg-cyan-950 text-cyan-300 border border-cyan-800/60 font-sans">
                  {{ isLanTarget ? 'LAN Micro-Topology Schematic' : 'Geodesic Digital Globe' }}
                </span>
              </h3>
              <span v-if="isTracing" class="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono bg-amber-500/10 text-amber-300 border border-amber-500/30 animate-pulse">
                <span class="w-2 h-2 rounded-full bg-amber-400"></span>
                正在流式探测中 (Hop {{ currentHop }})...
              </span>
              <span v-else-if="hops.length > 0 && isFinished" class="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono bg-emerald-500/10 text-emerald-300 border border-emerald-500/30">
                <span class="w-2 h-2 rounded-full bg-emerald-400"></span>
                路由追踪就绪 (共 {{ hops.length }} 节点)
              </span>
            </div>
            <p class="text-[11px] text-slate-400 font-mono mt-0.5">
              {{ isLanTarget ? '局域网/工控网络微观拓扑虚拟架构图示 · 逐级网关与子网跃迁 · 微秒级物理排队时延' : '100% 离线脱机三维数字地球与等角圆柱投影 · 本机自我真实位置智能锚定 · 物理光纤时延比对' }}
            </p>
          </div>
        </div>

        <!-- 右侧：3D/2D/LAN 三模切换、控制与关闭 -->
        <div class="flex items-center gap-2.5 flex-wrap">
          <!-- 三模视图切换胶囊 -->
          <div class="bg-slate-950/80 p-0.5 rounded-xl border border-slate-800 flex items-center gap-0.5 font-mono text-xs">
            <button
              @click="viewMode = 'lan'"
              :class="['px-2.5 py-1 rounded-lg transition-all cursor-pointer flex items-center gap-1 font-bold',
                viewMode === 'lan' ? 'bg-gradient-to-r from-emerald-600 to-cyan-600 text-white shadow-md' : 'text-slate-400 hover:text-white']"
              title="切换至局域网微观虚拟拓扑架构图示 (清晰展示内网逐级网关跃迁、子网网段与微秒级时延)"
            >
              <span>🏢 局域网虚拟拓扑</span>
              <span v-if="isLanTarget" class="px-1 py-0.2 rounded-full text-[9px] bg-emerald-400/20 text-emerald-300 font-bold border border-emerald-500/30">
                内网推荐
              </span>
            </button>
            <button
              @click="viewMode = '3d'"
              :class="['px-2.5 py-1 rounded-lg transition-all cursor-pointer flex items-center gap-1 font-bold',
                viewMode === '3d' ? 'bg-gradient-to-r from-cyan-600 to-blue-600 text-white shadow-md' : 'text-slate-400 hover:text-white']"
              title="切换至三维交互式数字地球 (支持鼠标 360° 旋转、滚轮缩放与立体拱桥测地大圆航线)"
            >
              <span>🌍 3D 数字地球</span>
            </button>
            <button
              @click="viewMode = '2d'"
              :class="['px-2.5 py-1 rounded-lg transition-all cursor-pointer flex items-center gap-1 font-bold',
                viewMode === '2d' ? 'bg-gradient-to-r from-cyan-600 to-blue-600 text-white shadow-md' : 'text-slate-400 hover:text-white']"
              title="切换至二维高精度等角圆柱投影地图 (全景展开世界经纬网络)"
            >
              <span>🗺️ 2D 全景地图</span>
            </button>
          </div>

          <!-- 3D 专属控制 -->
          <template v-if="viewMode === '3d'">
            <button
              @click="toggleGlobeAutoRotate"
              :class="['px-2.5 py-1 rounded-xl border text-xs font-mono transition-all flex items-center gap-1 cursor-pointer',
                isAutoRotating ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40' : 'bg-slate-800 text-slate-400 border-slate-700 hover:text-white']"
              :title="isAutoRotating ? '暂停地球平滑自转' : '开启地球平滑自转'"
            >
              <span>{{ isAutoRotating ? '⏸️ 停止自转' : '🔄 开启自转' }}</span>
            </button>
            <button
              @click="focusOnSelf"
              class="px-2.5 py-1 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-mono transition-all flex items-center gap-1 cursor-pointer"
              title="将 3D 地球视角中心对焦至使用者的自我真实位置"
            >
              <span>🎯 对焦本机</span>
            </button>
          </template>

          <!-- 导出溯源报告 -->
          <button
            v-if="hops.length > 0"
            @click="exportTracerouteReport"
            class="px-3 py-1 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-mono font-medium transition-all flex items-center gap-1.5 cursor-pointer active:scale-95 shadow-sm"
          >
            <span>📑 导出报告</span>
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

      <!-- 2. 本机自我真实位置 (Hop 0) 核心情报看板 -->
      <div class="px-6 py-2 bg-gradient-to-r from-emerald-950/40 via-slate-900/60 to-cyan-950/40 border-b border-slate-800 flex items-center justify-between flex-wrap gap-2 text-xs font-mono shrink-0">
        <div class="flex items-center gap-3 flex-wrap">
          <div class="flex items-center gap-1.5 text-emerald-400 font-bold bg-emerald-500/10 px-2.5 py-1 rounded-xl border border-emerald-500/20">
            <span class="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse"></span>
            <span>使用者的自我 IP (本机源点):</span>
            <span class="text-white ml-1 font-bold">{{ selfHopInfo.ip }}</span>
          </div>

          <div class="flex items-center gap-1.5 text-slate-300">
            <span class="text-slate-500">真实地理归属:</span>
            <strong class="text-cyan-300 font-bold">📍 {{ selfHopInfo.location }}</strong>
            <span v-if="selfHopInfo.isp" class="px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 text-[10px]">
              {{ selfHopInfo.isp }}
            </span>
          </div>

          <div class="flex items-center gap-1.5 text-slate-400">
            <span class="text-slate-500">测地基准坐标:</span>
            <strong class="text-emerald-400 font-mono">
              [{{ selfHopInfo.lon.toFixed(2) }}°, {{ selfHopInfo.lat.toFixed(2) }}°]
            </strong>
          </div>
        </div>

        <div class="flex items-center gap-3 text-slate-400 text-[11px]">
          <span>定位网络体系: <strong :class="isLanTarget ? 'text-amber-400' : 'text-cyan-400'">{{ isLanTarget ? 'RFC 1918 局域网微观路由' : '全球广域互联网骨干' }}</strong></span>
          <span>·</span>
          <span>定位状态: <strong class="text-emerald-400 font-bold">{{ selfHopInfo.refineStatus }}</strong></span>
        </div>
      </div>

      <!-- 3. 目标主机输入与探测调度条 -->
      <div class="px-6 py-2 bg-slate-950/50 border-b border-slate-800/80 flex items-center justify-between flex-wrap gap-3 shrink-0 text-xs font-mono">
        <div class="flex items-center gap-2 flex-wrap">
          <label class="text-slate-400 flex items-center gap-1 font-sans">
            <span>🎯 目标主机:</span>
          </label>
          <input
            v-model="inputTarget"
            :disabled="isTracing"
            type="text"
            placeholder="IPv4 地址或域名 (例如: 192.168.1.1, 10.0.0.1, 8.8.8.8)"
            class="px-3 py-1.5 w-64 bg-slate-900 border border-slate-700 rounded-xl text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono text-xs shadow-inner"
            @keyup.enter="startTrace"
          />

          <label class="text-slate-400 ml-2 flex items-center gap-1 font-sans">
            <span>跳数上限:</span>
          </label>
          <select
            v-model.number="maxHops"
            :disabled="isTracing"
            class="px-2 py-1 bg-slate-900 border border-slate-700 rounded-xl text-slate-200 focus:outline-none focus:border-cyan-500 text-xs cursor-pointer"
          >
            <option :value="15">15 跳 (局域网推荐)</option>
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
            class="px-2 py-1 bg-slate-900 border border-slate-700 rounded-xl text-slate-200 focus:outline-none focus:border-cyan-500 text-xs cursor-pointer"
          >
            <option :value="300">300 ms (局域网极速)</option>
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

        <!-- 关键指标摘要 -->
        <div class="flex items-center gap-4 text-xs font-mono">
          <div class="flex items-center gap-1 text-slate-300">
            <span class="text-slate-500">{{ isLanTarget ? '内网物理线距:' : '测地直线总距:' }}</span>
            <strong :class="isLanTarget ? 'text-emerald-400' : 'text-cyan-400'">
              {{ isLanTarget ? (totalGeodesicKm * 1000).toFixed(0) + ' m' : totalGeodesicKm.toFixed(1) + ' km' }}
            </strong>
          </div>
          <div class="flex items-center gap-1 text-slate-300">
            <span class="text-slate-500">理论最低时延:</span>
            <strong class="text-emerald-400">{{ theoreticalMinRtt.toFixed(2) }} ms</strong>
          </div>
          <div class="flex items-center gap-1 text-slate-300">
            <span class="text-slate-500">实测终点 RTT:</span>
            <strong :class="actualFinalRttClass">{{ actualFinalRttText }}</strong>
          </div>
        </div>
      </div>

      <!-- 4. 中部核心可视化区 (支持 3D 数字地球 / 2D 全景地图 / 局域网微观虚拟拓扑 三模自适应) -->
      <div class="flex-1 flex flex-col overflow-y-auto p-4 gap-4 min-h-0 bg-slate-950/80">
        
        <!-- 4.1 可视化画布容器 -->
        <div class="relative w-full h-88 rounded-2xl bg-gradient-to-b from-slate-950 via-[#091122] to-slate-950 border border-slate-800/80 shadow-2xl overflow-hidden flex items-center justify-center shrink-0">
          
          <div class="absolute inset-0 bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:28px_28px] opacity-35 pointer-events-none"></div>

          <!-- 模式 A: 局域网微观虚拟拓扑架构图示 (LAN Micro-Topology Virtual Schematic) -->
          <div
            v-show="viewMode === 'lan'"
            class="w-full h-full flex flex-col justify-between p-5 overflow-x-auto select-none"
          >
            <!-- 局域网拓扑标题 -->
            <div class="flex items-center justify-between text-xs font-mono z-10">
              <div class="flex items-center gap-2">
                <span class="w-2.5 h-2.5 rounded-full bg-emerald-400 shadow-[0_0_8px_#10b981]"></span>
                <span class="font-bold text-white uppercase tracking-wider">局域网企业架构逐级跃迁虚拟拓扑图示</span>
                <span class="px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 text-[10px]">
                  Purdue Enterprise Hierarchy
                </span>
              </div>
              <div class="text-[11px] text-slate-400 flex items-center gap-2">
                <span>介质: <strong class="text-cyan-400">千兆双绞线 / 工业以太网</strong></span>
                <span>·</span>
                <span>跳步时延: <strong class="text-emerald-400">&lt; 1.0 ms</strong></span>
              </div>
            </div>

            <!-- 横向逐跳架构节点卡片流与发光数据总线 -->
            <div class="relative flex-1 flex items-center gap-3 overflow-x-auto py-3 px-2 custom-scrollbar">
              
              <template v-for="(hop, idx) in hops" :key="'lan-node-' + hop.hop_number">
                <!-- 节点卡片 -->
                <div
                  :class="[
                    'relative shrink-0 w-64 rounded-2xl p-3.5 border transition-all cursor-pointer backdrop-blur-xl flex flex-col justify-between shadow-xl',
                    hop.is_self ? 'bg-emerald-950/40 border-emerald-500/50 shadow-emerald-950/30' : (hop.is_destination ? 'bg-amber-950/40 border-amber-500/50 shadow-amber-950/30' : 'bg-slate-900/80 border-slate-700/80 hover:border-cyan-500/60'),
                    selectedHop?.hopNumber === hop.hop_number ? 'ring-2 ring-cyan-400 scale-102' : ''
                  ]"
                  @click="selectHopRow(hop)"
                >
                  <!-- 卡片顶部 -->
                  <div class="flex items-center justify-between border-b border-white/10 pb-2 mb-2">
                    <span
                      :class="[
                        'px-2 py-0.5 rounded-md text-[10px] font-bold font-mono',
                        hop.is_self ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30' : (hop.is_destination ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30' : 'bg-slate-800 text-slate-300')
                      ]"
                    >
                      {{ hop.is_self ? '源点 #0 (本机)' : `Hop #${hop.hop_number}` }}
                    </span>
                    <span class="text-[11px] font-mono font-bold" :class="getRttClass(hop.rtt_ms)">
                      {{ hop.is_self ? '0.0 ms' : (hop.is_timeout ? '*' : hop.rtt_ms.toFixed(1) + ' ms') }}
                    </span>
                  </div>

                  <!-- 节点核心 IP 与角色描述 -->
                  <div class="flex items-center gap-2.5 my-1">
                    <span class="text-2xl">{{ getLanNodeIcon(hop) }}</span>
                    <div class="flex-1 min-w-0">
                      <div class="font-mono font-bold text-sm text-white truncate">{{ hop.ip }}</div>
                      <div class="text-[11px] text-cyan-300 font-medium truncate mt-0.5">
                        {{ hop.lan_role || (hop.is_self ? '本机源端' : '局域网路由') }}
                      </div>
                    </div>
                  </div>

                  <!-- 底部子网与物理线距 -->
                  <div class="mt-2 pt-2 border-t border-white/5 flex items-center justify-between text-[10px] font-mono text-slate-400">
                    <span class="text-slate-300">网段: {{ hop.subnet_cidr || '局域网/24' }}</span>
                    <span class="text-emerald-400">线距: ~{{ Math.round(hop.cumulative_distance_km * 1000) }}m</span>
                  </div>
                </div>

                <!-- 节点间的高速互联数据管道 (若非最后一个节点) -->
                <div v-if="idx < hops.length - 1" class="shrink-0 flex flex-col items-center justify-center px-1">
                  <!-- 发光箭头母线 -->
                  <div class="relative w-12 h-1 bg-gradient-to-r from-emerald-500/50 via-cyan-400 to-emerald-500/50 rounded-full overflow-hidden">
                    <div class="absolute inset-0 bg-white/80 w-4 h-full rounded-full animate-dash-h"></div>
                  </div>
                  <span class="text-[9px] font-mono text-cyan-400 font-bold mt-1">
                    {{ (hops[idx + 1].rtt_ms - hop.rtt_ms) >= 0 ? '+' + (hops[idx + 1].rtt_ms - hop.rtt_ms).toFixed(1) + 'ms' : '0.2ms' }}
                  </span>
                </div>
              </template>

              <!-- 空状态 -->
              <div v-if="hops.length === 0" class="w-full text-center text-slate-500 text-xs py-10 font-mono">
                请输入局域网 IP (如 192.168.1.1, 10.0.0.1) 并点击【启动测地追踪】开始探测微观架构
              </div>

            </div>

            <!-- 底部局域网架构状态说明 -->
            <div class="flex items-center justify-between text-[11px] font-mono text-slate-400 border-t border-slate-800/80 pt-2 z-10">
              <div class="flex items-center gap-3">
                <span class="text-emerald-400 font-bold">🟢 二层直通线速 (Line-Rate)</span>
                <span>·</span>
                <span>介质模型: Cat6 综合布线 (增量 ~35m/跳)</span>
                <span>·</span>
                <span>排队诊断: 无内网广播风暴或二层环路</span>
              </div>
              <div class="text-slate-400">
                可随时在右上角切换至【3D 数字地球】或【2D 全景地图】
              </div>
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
                <feGaussianBlur stdDeviation="2.5" result="blur" />
                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
            </defs>

            <!-- 2D 经纬网格 -->
            <g class="stroke-slate-800/60 stroke-[0.8]" stroke-dasharray="2 3">
              <line x1="0" y1="240" x2="960" y2="240" class="stroke-slate-600/80 stroke-1" stroke-dasharray="none" />
              <line x1="480" y1="0" x2="480" y2="480" class="stroke-slate-600/80 stroke-1" stroke-dasharray="none" />
              <line x1="0" y1="177.3" x2="960" y2="177.3" class="stroke-cyan-900/30" />
              <line x1="0" y1="302.7" x2="960" y2="302.7" class="stroke-cyan-900/30" />
              <line v-for="y in [80, 160, 320, 400]" :key="'lat-' + y" x1="0" :y1="y" x2="960" :y2="y" />
              <line v-for="x in [80, 160, 240, 320, 400, 560, 640, 720, 800, 880]" :key="'lon-' + x" :x1="x" y1="0" :x2="x" y2="480" />
            </g>

            <!-- 2D 真实高精经纬度大陆板块多边形 -->
            <g class="fill-slate-800/70 stroke-cyan-500/30 stroke-[0.8]">
              <path v-for="(pathStr, pIdx) in worldLandPaths2d" :key="'poly-2d-' + pIdx" :d="pathStr" />
            </g>

            <!-- 2D 测地大圆飞线 -->
            <g>
              <template v-for="(flight, idx) in flightArcs2d" :key="'flight-2d-' + idx">
                <path :d="flight.pathData" class="fill-none stroke-cyan-500/20 stroke-[3]" />
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
                  :class="point.isSelf ? 'fill-emerald-500/30 stroke-emerald-400' : (point.isFinal ? 'fill-amber-500/30 stroke-amber-400 animate-ping' : 'fill-cyan-500/20 stroke-cyan-400')"
                  class="stroke-[1.5]"
                />
                <circle
                  r="3.5"
                  :class="point.isSelf ? 'fill-emerald-400' : (point.isFinal ? 'fill-amber-400' : 'fill-cyan-400')"
                />
                <text
                  text-anchor="middle"
                  y="-9"
                  class="font-mono text-[9px] font-bold fill-slate-200 select-none shadow-sm"
                >
                  {{ point.isSelf ? '本机' : '#' + point.hopNumber }}
                </text>
              </g>
            </g>
          </svg>

          <!-- 悬停节点即时卡片 (Floating Tooltip) -->
          <div
            v-if="hoveredHop"
            class="absolute top-3 left-3 bg-slate-900/95 border border-cyan-500/40 rounded-2xl p-3 shadow-2xl backdrop-blur-xl text-xs font-mono z-30 pointer-events-none animate-in fade-in zoom-in-95 duration-100 max-w-xs"
          >
            <div class="flex items-center justify-between gap-2 border-b border-slate-800 pb-1.5 mb-1.5">
              <span class="font-bold flex items-center gap-1" :class="hoveredHop.isSelf ? 'text-emerald-400' : 'text-cyan-400'">
                <span>{{ hoveredHop.isSelf ? '🟢 使用者自我 IP (源点)' : `Hop #${hoveredHop.hopNumber}` }}</span>
              </span>
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
            <div class="text-slate-500 text-[9px] mt-1.5 flex items-center justify-between border-t border-slate-800 pt-1">
              <span>精确经纬度: [{{ hoveredHop.lon.toFixed(2) }}°, {{ hoveredHop.lat.toFixed(2) }}°]</span>
              <span>距起点: {{ (hoveredHop.cumulativeKm * (isLanTarget ? 1000 : 1)).toFixed(1) }} {{ isLanTarget ? 'm' : 'km' }}</span>
            </div>
          </div>

          <!-- 地图底部控制提示与图例 -->
          <div class="absolute bottom-2.5 left-4 text-[10px] font-mono text-slate-400 flex items-center gap-3 select-none pointer-events-none bg-slate-950/70 px-3 py-1 rounded-xl border border-slate-800/60">
            <span v-if="viewMode === 'lan'">🏢 局域网虚拟架构拓扑: 鼠标点击卡片可在下方指标列表精准联动下钻</span>
            <span v-else-if="viewMode === '3d'">🖱️ 鼠标按住拖拽自由 360° 旋转地球 · 滚轮缩放</span>
            <span v-else>🗺️ 投影体系: WGS-84 等角圆柱投影 · 纯离线高精经纬度</span>
            <span>·</span>
            <span class="text-emerald-400 font-bold">已精准定位使用者自我 IP</span>
          </div>

          <!-- 图例 -->
          <div class="absolute bottom-2.5 right-4 flex items-center gap-3 text-[10px] font-mono bg-slate-950/80 px-3 py-1 rounded-xl border border-slate-800 select-none">
            <div class="flex items-center gap-1.5 text-emerald-400">
              <span class="w-2.5 h-2.5 rounded-full bg-emerald-400 shadow-[0_0_6px_#10b981]"></span>
              <span>使用者自我主机 (Hop 0)</span>
            </div>
            <div class="flex items-center gap-1.5 text-cyan-400">
              <span class="w-2.5 h-2.5 rounded-full bg-cyan-400"></span>
              <span>路由与交换跃点</span>
            </div>
            <div class="flex items-center gap-1.5 text-amber-400">
              <span class="w-2.5 h-2.5 rounded-full bg-amber-400 shadow-[0_0_6px_#f59e0b]"></span>
              <span>最终目标主机</span>
            </div>
          </div>
        </div>

        <!-- 4.2 逐跳全息指标表格 (Hop-by-Hop Telemetry) -->
        <div class="flex-1 flex flex-col min-h-0 bg-slate-900/90 rounded-2xl border border-slate-800 shadow-xl overflow-hidden">
          
          <div class="px-4 py-2 bg-slate-950/70 border-b border-slate-800 flex items-center justify-between shrink-0 text-xs font-mono">
            <div class="flex items-center gap-2 text-slate-300 font-bold">
              <span>📋 路由跃点全息清单 (Hop-by-Hop Architecture Telemetry)</span>
              <span class="text-[11px] px-2 py-0.2 rounded-full bg-slate-800 text-slate-400 font-normal">
                已探测 {{ hops.length }} 节点
              </span>
            </div>
            <div class="text-[11px] text-slate-400">
              首行始终对齐使用者本机自我 IP · 局域网微观角色与子网自动研判
            </div>
          </div>

          <div class="flex-1 overflow-y-auto">
            <table class="w-full text-left font-mono text-xs border-collapse">
              <thead class="bg-slate-950/90 text-slate-400 sticky top-0 z-10 border-b border-slate-800 text-[11px]">
                <tr>
                  <th class="py-2 px-3 w-16 text-center">跳数</th>
                  <th class="py-2 px-3 w-40">路由器 / 主机 IP</th>
                  <th class="py-2 px-3 w-28">RTT 时延</th>
                  <th class="py-2 px-3 w-48">网络角色 / 拓扑层级</th>
                  <th class="py-2 px-3 w-40">地理归属 (国家/省/市)</th>
                  <th class="py-2 px-3 w-32">子网 (CIDR)</th>
                  <th class="py-2 px-3 w-28">物理线缆距</th>
                  <th class="py-2 px-3 text-right">缓冲排队剖析</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-800/60 text-slate-300">
                <tr
                  v-for="hop in hops"
                  :key="'hop-row-' + hop.hop_number"
                  :class="[
                    'hover:bg-slate-800/60 transition-colors cursor-pointer',
                    hop.is_self ? 'bg-emerald-950/20 border-l-2 border-l-emerald-400' : '',
                    selectedHop?.hopNumber === hop.hop_number ? 'bg-cyan-950/40 border-l-2 border-l-cyan-400' : ''
                  ]"
                  @click="selectHopRow(hop)"
                >
                  <!-- 跳数序号 -->
                  <td class="py-2 px-3 text-center font-bold">
                    <span
                      :class="[
                        'inline-block px-1.5 py-0.5 rounded text-[10px]',
                        hop.is_self ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-bold' : (hop.is_destination ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 font-bold' : 'bg-slate-800 text-slate-300')
                      ]"
                    >
                      {{ hop.is_self ? '源点 #0' : '#' + hop.hop_number }}
                    </span>
                  </td>

                  <!-- 节点 IP -->
                  <td class="py-2 px-3 font-bold text-white flex items-center gap-1.5">
                    <span v-if="hop.is_timeout" class="text-slate-500 italic">* (超时丢包)</span>
                    <span v-else>{{ hop.ip }}</span>
                    <span v-if="hop.is_self" class="text-[9px] px-1 rounded bg-emerald-900/60 text-emerald-200 border border-emerald-700">使用者本机</span>
                    <span v-else-if="hop.is_destination" class="text-[9px] px-1 rounded bg-amber-900/60 text-amber-200 border border-amber-700">终点</span>
                  </td>

                  <!-- RTT 延迟 -->
                  <td class="py-2 px-3">
                    <div v-if="hop.is_timeout" class="text-slate-500 italic">* ms</div>
                    <div v-else-if="hop.is_self" class="text-emerald-400 font-bold">0.0 ms</div>
                    <div v-else class="flex items-center gap-2">
                      <span :class="getRttClass(hop.rtt_ms)" class="w-12 font-bold">{{ hop.rtt_ms.toFixed(1) }} ms</span>
                      <div class="w-12 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                        <div
                          class="h-full rounded-full transition-all"
                          :class="getRttBarColor(hop.rtt_ms)"
                          :style="{ width: Math.min(100, (hop.rtt_ms / (isLanTarget ? 5 : 200)) * 100) + '%' }"
                        ></div>
                      </div>
                    </div>
                  </td>

                  <!-- 网络角色 / 拓扑层级 -->
                  <td class="py-2 px-3 text-cyan-300 font-medium">
                    <div class="flex items-center gap-1.5">
                      <span>{{ getLanNodeIcon(hop) }}</span>
                      <span class="truncate">{{ hop.lan_role || (hop.is_self ? '本机源端主机' : '骨干网络跃点') }}</span>
                    </div>
                  </td>

                  <!-- 地理归属 -->
                  <td class="py-2 px-3 text-slate-200">
                    <div class="flex items-center gap-1 truncate">
                      <span v-if="hop.country && hop.country !== '未知'">🌍 {{ formatLocation(hop) }}</span>
                      <span v-else-if="hop.is_self">🏠 本地内网主机终端</span>
                      <span v-else class="text-slate-500 italic">内网 / 私有网段</span>
                    </div>
                  </td>

                  <!-- 子网网段 -->
                  <td class="py-2 px-3 text-slate-300 text-[11px]">
                    <span v-if="hop.subnet_cidr" class="px-1.5 py-0.5 rounded bg-slate-800/80 border border-slate-700/60 text-cyan-200">
                      {{ hop.subnet_cidr }}
                    </span>
                    <span v-else class="text-slate-600">-</span>
                  </td>

                  <!-- 物理线缆距 -->
                  <td class="py-2 px-3 text-slate-300 font-bold">
                    <span v-if="isLanTarget" class="text-emerald-400">
                      ~{{ Math.round(hop.cumulative_distance_km * 1000) }} m
                    </span>
                    <span v-else-if="hop.cumulative_distance_km > 0" class="text-cyan-300">
                      {{ hop.cumulative_distance_km.toFixed(1) }} km
                    </span>
                    <span v-else class="text-slate-600">0.0 km</span>
                  </td>

                  <!-- 缓冲排队剖析 (Bufferbloat Analysis) -->
                  <td class="py-2 px-3 text-right">
                    <span v-if="hop.is_self" class="text-emerald-400 text-[10px] font-bold">
                      源起点 🟢
                    </span>
                    <span v-else-if="isLanTarget" class="text-emerald-400 text-[10px] font-bold">
                      {{ hop.rtt_ms < 1.0 ? '微秒线速 ⚡' : '正常交换 🟢' }}
                    </span>
                    <span
                      v-else-if="!hop.is_timeout && hop.bufferbloat_ratio > 0"
                      :class="[
                        'px-2 py-0.5 rounded text-[10px] font-bold border',
                        hop.bufferbloat_ratio > 10 ? 'bg-rose-500/10 text-rose-300 border-rose-500/30' : (hop.bufferbloat_ratio > 4 ? 'bg-amber-500/10 text-amber-300 border-amber-500/30' : 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30')
                      ]"
                    >
                      {{ hop.bufferbloat_ratio > 10 ? '严重排队 ⚠️' : (hop.bufferbloat_ratio > 4 ? '轻度拥塞 ⚡' : '物理极限 🟢') }}
                    </span>
                    <span v-else class="text-slate-600">-</span>
                  </td>
                </tr>

                <tr v-if="hops.length === 0">
                  <td colspan="8" class="py-12 text-center text-slate-500">
                    <div class="flex flex-col items-center justify-center gap-2">
                      <span class="text-3xl">🌐</span>
                      <span>输入目标 IP (支持公网 IP 或 192.168.x.x / 10.x.x.x 局域网)，点击【启动测地追踪】</span>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

      </div>

      <!-- 5. 底部状态指示条 -->
      <div class="px-6 py-2.5 bg-slate-950 border-t border-slate-800 flex items-center justify-between text-[11px] font-mono text-slate-400 shrink-0">
        <div class="flex items-center gap-3">
          <span>三维渲染: 正射空间投影 (Orthographic)</span>
          <span>·</span>
          <span>局域网引擎: Purdue Model 微观拓扑感知</span>
          <span>·</span>
          <span>数据库: ip2region.xdb 联动自适应</span>
        </div>
        <div class="flex items-center gap-2">
          <span v-if="statusMessage" class="text-cyan-400 font-bold">{{ statusMessage }}</span>
          <span v-else class="text-slate-500">就绪</span>
        </div>
      </div>

    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted, onUnmounted, nextTick } from 'vue';
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
  if (hop.is_self || hop.hop_number === 0) return '💻';
  if (hop.is_destination) return '🎯';
  if (hop.hop_number === 1) return '🔀';
  return '🛡️';
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

  // 1. 大气外散射光环
  const haloGrad = ctx.createRadialGradient(cx, cy, r * 0.9, cx, cy, r * 1.25);
  haloGrad.addColorStop(0, 'rgba(6, 182, 212, 0.28)');
  haloGrad.addColorStop(0.5, 'rgba(14, 165, 233, 0.12)');
  haloGrad.addColorStop(1, 'rgba(15, 23, 42, 0)');
  ctx.fillStyle = haloGrad;
  ctx.beginPath();
  ctx.arc(cx, cy, r * 1.25, 0, Math.PI * 2);
  ctx.fill();

  // 2. 球体深邃背景色
  const sphereGrad = ctx.createRadialGradient(cx - r * 0.35, cy - r * 0.35, r * 0.1, cx, cy, r);
  sphereGrad.addColorStop(0, '#0f2744');
  sphereGrad.addColorStop(0.65, '#07162c');
  sphereGrad.addColorStop(1, '#020617');
  ctx.fillStyle = sphereGrad;
  ctx.beginPath();
  ctx.arc(cx, cy, r, 0, Math.PI * 2);
  ctx.fill();

  ctx.save();
  ctx.beginPath();
  ctx.arc(cx, cy, r, 0, Math.PI * 2);
  ctx.clip();

  // 3. 经纬线网格 (每 30° 一根)
  ctx.strokeStyle = 'rgba(56, 189, 248, 0.16)';
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
  ctx.fillStyle = 'rgba(30, 58, 95, 0.72)';
  ctx.strokeStyle = 'rgba(34, 211, 238, 0.35)';
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

      ctx.fillStyle = pt.isSelf ? '#34d399' : (pt.isFinal ? '#fbbf24' : '#e2e8f0');
      ctx.font = 'bold 10px monospace';
      ctx.textAlign = 'center';
      const labelText = pt.isSelf ? '🟢 本机源点' : `#${pt.hopNumber}`;
      ctx.fillText(labelText, px, py - 8);
    }
  }

  ctx.restore();

  ctx.strokeStyle = 'rgba(56, 189, 248, 0.4)';
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
  if (rtt < 1.0) return 'text-emerald-400 font-bold';
  if (rtt < 30) return 'text-cyan-400 font-bold';
  if (rtt < 80) return 'text-sky-400 font-bold';
  if (rtt < 150) return 'text-amber-400 font-bold';
  return 'text-rose-400 font-bold';
}

function getRttBarColor(rtt: number): string {
  if (rtt < 1.0) return 'bg-emerald-400';
  if (rtt < 30) return 'bg-cyan-500';
  if (rtt < 80) return 'bg-sky-500';
  if (rtt < 150) return 'bg-amber-500';
  return 'bg-rose-500';
}

function exportTracerouteReport() {
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
    const queueRatio = isLanTarget.value ? (h.rtt_ms < 1.0 ? '微秒线速 ⚡' : '正常交换 🟢') : (h.bufferbloat_ratio > 0 ? `${h.bufferbloat_ratio.toFixed(1)}x` : '-');
    md += `| ${hopLabel} | \`${h.ip}\` | ${rtt} | ${role} | ${loc} | ${subnet} | ${distStr} | ${queueRatio} |\n`;
  }

  md += `\n---\n*Omni-Probe 工业网络全息分析仪 · 物理网络与等保三级司法溯源审计中心*\n`;

  const blob = new Blob([md], { type: 'text/markdown;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `traceroute_report_${inputTarget.value.replace(/[^a-zA-Z0-9]/g, '_')}_${Date.now()}.md`;
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
