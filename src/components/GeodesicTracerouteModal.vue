<template>
  <div v-if="isOpen" class="fixed inset-0 z-50 flex items-center justify-center p-2 sm:p-4 ui-modal-backdrop select-none">
    <div class="w-full max-w-[96vw] xl:max-w-[1540px] h-[92vh] max-h-[92vh] ui-modal-surface rounded-3xl flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-150 shadow-2xl border" :class="isDarkTheme ? 'border-cyan-500/25' : 'border-slate-300/80'">
      
      <!-- 1. 顶部全局控制与态势标题栏 (Liquid Glass Header) -->
      <header class="ui-nav-glass border-b px-5 py-3 flex items-center justify-between shrink-0 flex-wrap gap-3">
        <div class="flex items-center gap-3">
          <div class="w-9 h-9 rounded-xl bg-sky-500/15 border border-sky-500/30 flex items-center justify-center text-sky-700 dark:text-cyan-300 shrink-0 shadow-xs">
            <AppIcon :name="viewMode === 'lan' ? 'layers' : 'globe'" :size="19" />
          </div>
          <div>
            <div class="flex items-center gap-2 flex-wrap">
              <h3 class="text-sm font-bold tracking-tight" style="color: var(--text-primary)">
                测地线多跳路由溯源与空间态势看板
              </h3>
              <span class="text-[11px] px-2.5 py-0.5 rounded-full bg-sky-500/12 text-sky-700 dark:text-cyan-300 border border-sky-500/25 font-semibold">
                {{ isLanTarget ? '企业局域网微观架构分析' : '全球互联网骨干测地追踪' }}
              </span>
              <span v-if="isTracing" class="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] ui-num bg-amber-500/12 text-amber-700 dark:text-amber-300 border border-amber-500/30 font-semibold animate-pulse">
                <span class="w-2 h-2 rounded-full bg-amber-500"></span>
                正在流式探测第 {{ currentHop }} 跳...
              </span>
              <span v-else-if="hops.length > 0 && isFinished" class="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] ui-num bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30 font-semibold">
                <span class="w-2 h-2 rounded-full bg-emerald-500"></span>
                路由溯源完成 · 累计跃迁 {{ hops.length }} 节点 (途经 {{ traversedStats.regionCount }} 地区)
              </span>
            </div>
            <p class="text-[11px] mt-0.5" style="color: var(--text-muted)">
              左侧实时监测路由路径与逐级地区流 · 右侧高保真三维数字地球航路飞线 · 纯离线高精经纬度基准
            </p>
          </div>
        </div>

        <!-- 右侧：模式切换、自转、对焦与操作 -->
        <div class="flex items-center gap-2 flex-wrap">
          <!-- 3 种视图模式切换 -->
          <div class="ui-pill p-0.5 rounded-xl flex items-center gap-0.5 text-[11px] font-semibold border" :class="isDarkTheme ? 'border-white/10' : 'border-slate-300/60'">
            <button
              @click="switchViewMode('3d')"
              :class="['px-3 py-1 rounded-lg transition-colors cursor-pointer flex items-center gap-1.5',
                viewMode === '3d' ? 'bg-sky-500 text-white shadow-xs font-bold' : 'hover:bg-black/5 dark:hover:bg-white/5']"
              :style="viewMode !== '3d' ? { color: 'var(--text-secondary)' } : undefined"
              title="切换至三维交互式数字地球"
            >
              <AppIcon name="globe" :size="13" />
              <span>3D 数字地球</span>
            </button>
            <button
              @click="switchViewMode('2d')"
              :class="['px-3 py-1 rounded-lg transition-colors cursor-pointer flex items-center gap-1.5',
                viewMode === '2d' ? 'bg-sky-500 text-white shadow-xs font-bold' : 'hover:bg-black/5 dark:hover:bg-white/5']"
              :style="viewMode !== '2d' ? { color: 'var(--text-secondary)' } : undefined"
              title="切换至二维高精度等角圆柱投影平面地图"
            >
              <AppIcon name="compass" :size="13" />
              <span>2D 全景地图</span>
            </button>
            <button
              @click="switchViewMode('lan')"
              :class="['px-3 py-1 rounded-lg transition-colors cursor-pointer flex items-center gap-1.5',
                viewMode === 'lan' ? 'bg-sky-500 text-white shadow-xs font-bold' : 'hover:bg-black/5 dark:hover:bg-white/5']"
              :style="viewMode !== 'lan' ? { color: 'var(--text-secondary)' } : undefined"
              title="切换至局域网企业架构逐级跃迁拓扑"
            >
              <AppIcon name="layers" :size="13" />
              <span>局域网虚拟拓扑</span>
              <span v-if="isLanTarget" class="px-1.5 py-0.2 rounded-full text-[10px] bg-emerald-500/20 text-emerald-700 dark:text-emerald-200 font-bold">
                内网推荐
              </span>
            </button>
          </div>

          <!-- 布局架构切换：左右分栏 (Split) vs 上下大盘 (Stack) -->
          <div class="ui-pill p-0.5 rounded-xl flex items-center gap-0.5 text-[11px] font-semibold border" :class="isDarkTheme ? 'border-white/10' : 'border-slate-300/60'">
            <button
              @click="layoutMode = 'split'"
              :class="['px-2.5 py-1 rounded-lg transition-colors cursor-pointer flex items-center gap-1.5',
                layoutMode === 'split' ? 'bg-sky-500 text-white shadow-xs font-bold' : 'hover:bg-black/5 dark:hover:bg-white/5']"
              :style="layoutMode !== 'split' ? { color: 'var(--text-secondary)' } : undefined"
              title="左右分栏：左侧数据与地区流，右侧数字地球"
            >
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><line x1="12" y1="3" x2="12" y2="21"/></svg>
              <span>左右分栏</span>
            </button>
            <button
              @click="layoutMode = 'stack'"
              :class="['px-2.5 py-1 rounded-lg transition-colors cursor-pointer flex items-center gap-1.5',
                layoutMode === 'stack' ? 'bg-sky-500 text-white shadow-xs font-bold' : 'hover:bg-black/5 dark:hover:bg-white/5']"
              :style="layoutMode !== 'stack' ? { color: 'var(--text-secondary)' } : undefined"
              title="上下大盘：上方数字地球/拓扑，下方全宽 8 列全量指标表格"
            >
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><line x1="3" y1="12" x2="21" y2="12"/></svg>
              <span>上下大盘</span>
            </button>
          </div>

          <!-- 3D 视角专属控制器 -->
          <template v-if="viewMode === '3d'">
            <button
              @click="toggleGlobeAutoRotate"
              :class="['px-2.5 py-1 rounded-xl border text-[11px] font-medium transition-colors flex items-center gap-1.5 cursor-pointer',
                isAutoRotating ? 'bg-sky-500/15 text-sky-700 dark:text-cyan-300 border-sky-500/35' : 'ui-pill']"
              :title="isAutoRotating ? '暂停数字地球平滑自转' : '开启数字地球平滑自转'"
            >
              <AppIcon :name="isAutoRotating ? 'pause' : 'refresh'" :size="12" />
              <span>{{ isAutoRotating ? '停止自转' : '开启自转' }}</span>
            </button>
            <button
              @click="focusOnSelf"
              class="ui-btn-secondary text-[11px] py-1 px-2.5 rounded-xl"
              title="视角平滑对焦至本机源端物理位置"
            >
              <AppIcon name="radar" :size="12" />
              <span>对焦本机</span>
            </button>
            <button
              @click="focusOnDestination"
              class="ui-btn-secondary text-[11px] py-1 px-2.5 rounded-xl text-amber-700 dark:text-amber-300"
              title="视角平滑对焦至目标终点主机位置"
            >
              <AppIcon name="link" :size="12" />
              <span>对焦终点</span>
            </button>
          </template>

          <button
            v-if="hops.length > 0"
            @click="exportTracerouteReport"
            class="ui-btn-secondary text-[11px] py-1 px-3 rounded-xl"
            title="导出测地线多跳溯源分析 Markdown 审计报告"
          >
            <AppIcon name="document" :size="12" />
            <span>导出报告</span>
          </button>

          <button
            @click="handleClose"
            class="w-8 h-8 rounded-full flex items-center justify-center ui-pill cursor-pointer hover:bg-rose-500/15 hover:text-rose-600 transition-colors"
            title="关闭窗口"
          >
            <AppIcon name="close" :size="15" />
          </button>
        </div>
      </header>

      <!-- 2. 本机自我真实位置 (Hop 0) 情报基准条 -->
      <div class="px-5 py-2 border-b flex items-center justify-between flex-wrap gap-2 text-xs ui-num select-text shrink-0" style="background: var(--surface-content-alt); border-color: var(--border-subtle)">
        <div class="flex items-center gap-3 flex-wrap">
          <div class="flex items-center gap-1.5 text-emerald-700 dark:text-emerald-300 font-bold bg-emerald-500/12 px-2.5 py-0.5 rounded-xl border border-emerald-500/25">
            <span class="w-2 h-2 rounded-full bg-emerald-500"></span>
            <span>本机源端 IP:</span>
            <span class="ml-1 tracking-wider" style="color: var(--text-primary)">{{ selfHopInfo.ip }}</span>
          </div>

          <div class="flex items-center gap-1.5" style="color: var(--text-secondary)">
            <span style="color: var(--text-muted)">真实物理归属:</span>
            <strong class="text-sky-700 dark:text-cyan-300 font-bold flex items-center gap-1">
              <AppIcon name="compass" :size="12" />
              <span>{{ selfHopInfo.location }}</span>
            </strong>
            <span v-if="selfHopInfo.isp" class="px-1.5 py-0.2 rounded ui-pill text-[11px]">
              {{ selfHopInfo.isp }}
            </span>
          </div>

          <div class="flex items-center gap-1.5" style="color: var(--text-secondary)">
            <span style="color: var(--text-muted)">基准测地坐标:</span>
            <strong class="text-emerald-700 dark:text-emerald-400">
              [{{ selfHopInfo.lon.toFixed(2) }}°E, {{ selfHopInfo.lat.toFixed(2) }}°N]
            </strong>
          </div>
        </div>

        <div class="flex items-center gap-3 text-[11px]" style="color: var(--text-muted)">
          <span>网络环境: <strong :class="isLanTarget ? 'text-amber-700 dark:text-amber-300' : 'text-sky-700 dark:text-cyan-300'">{{ isLanTarget ? 'RFC 1918 内部微观路由' : '全球互联网城域出口' }}</strong></span>
          <span>·</span>
          <span>坐标状态: <strong class="text-emerald-700 dark:text-emerald-400 font-bold">{{ selfHopInfo.refineStatus }}</strong></span>
        </div>
      </div>

      <!-- 3. 核心主体结构: 支持左右分栏 (split) 与上下大盘 (stack) 无缝切换 -->
      <div
        :class="[
          'flex-1 min-h-0 overflow-hidden flex',
          layoutMode === 'split' ? 'flex-col md:flex-row' : 'flex-col'
        ]"
        style="background: var(--surface-window)"
      >
        
        <!-- ============================================================ -->
        <!-- 数据与指标工作区 (split 模式下居左 45%，stack 模式下居下 48%) -->
        <!-- ============================================================ -->
        <div
          :class="[
            'flex flex-col min-h-0 overflow-hidden',
            layoutMode === 'split'
              ? 'order-1 w-full md:w-[46%] lg:w-[45%] xl:w-[44%] border-r'
              : 'order-2 w-full h-[48%] border-t shrink-0'
          ]"
          style="border-color: var(--border-subtle)"
        >
          
          <!-- 数据区上部：目标输入与探测启动条 -->
          <div
            :class="[
              'border-b flex shrink-0',
              layoutMode === 'stack' ? 'px-4 py-2 flex-row flex-wrap items-center justify-between gap-3' : 'p-4 flex-col gap-2.5'
            ]"
            style="background: var(--surface-content); border-color: var(--border-subtle)"
          >
            <div class="flex items-center gap-2 flex-wrap">
              <div class="flex-1 min-w-[200px] flex items-center gap-2">
                <label class="font-bold text-xs shrink-0 flex items-center gap-1" style="color: var(--text-secondary)">
                  <AppIcon name="radar" :size="13" />
                  <span>目标主机:</span>
                </label>
                <input
                  v-model="inputTarget"
                  :disabled="isTracing"
                  type="text"
                  placeholder="公网 IP/域名 或 局域网 IP (如 138.197.159.140)"
                  class="ui-input ui-num flex-1 py-1.5 px-3 text-xs"
                  @keyup.enter="startTrace"
                />
              </div>

              <div class="flex items-center gap-1.5 shrink-0">
                <button
                  v-if="!isTracing"
                  @click="startTrace"
                  class="ui-btn-primary text-xs py-1.5 px-4 rounded-xl flex items-center gap-1.5 font-bold cursor-pointer"
                >
                  <AppIcon name="play" :size="12" />
                  <span>启动溯源追踪</span>
                </button>
                <button
                  v-else
                  @click="stopTrace"
                  class="ui-btn-danger text-xs py-1.5 px-4 rounded-xl flex items-center gap-1.5 font-bold cursor-pointer"
                >
                  <AppIcon name="stop" :size="12" />
                  <span>强制终止探测</span>
                </button>
              </div>
            </div>

            <!-- 参数微调与配置 -->
            <div class="flex items-center justify-between text-[11px] flex-wrap gap-2" style="color: var(--text-muted)">
              <div class="flex items-center gap-3">
                <div class="flex items-center gap-1">
                  <span>跳数上限:</span>
                  <select
                    v-model.number="maxHops"
                    :disabled="isTracing"
                    class="ui-input w-auto py-0.5 px-2 text-[11px] cursor-pointer"
                  >
                    <option :value="15">15 跳 (局域网推荐)</option>
                    <option :value="30">30 跳 (标准全网)</option>
                    <option :value="45">45 跳 (深度跨洲)</option>
                    <option :value="64">64 跳 (穷尽穷搜)</option>
                  </select>
                </div>

                <div class="flex items-center gap-1">
                  <span>单跳超时:</span>
                  <select
                    v-model.number="timeoutMs"
                    :disabled="isTracing"
                    class="ui-input w-auto py-0.5 px-2 text-[11px] cursor-pointer"
                  >
                    <option :value="500">500 ms (高速网络)</option>
                    <option :value="1000">1000 ms (推荐标准)</option>
                    <option :value="2000">2000 ms (严密探测)</option>
                  </select>
                </div>
              </div>

              <span class="text-sky-700 dark:text-cyan-400">
                {{ isTracing ? '流式探测执行中 (Windows tracert -d)' : '就绪' }}
              </span>
            </div>
          </div>

          <!-- 左侧中部：4 宫格链路核心物理 KPI 卡片 -->
          <div class="grid grid-cols-2 lg:grid-cols-4 gap-2 p-3 border-b shrink-0 text-xs ui-num" style="background: var(--surface-content-alt); border-color: var(--border-subtle)">
            <!-- KPI 1: 跃迁总跳数 -->
            <div class="ui-content-card p-2.5 flex flex-col justify-between">
              <span class="text-[11px]" style="color: var(--text-muted)">累计跃点数</span>
              <div class="text-base font-bold mt-1 flex items-baseline gap-1" style="color: var(--text-primary)">
                <span>{{ hops.length }}</span>
                <span class="text-[11px] font-normal" style="color: var(--text-secondary)">跳</span>
              </div>
              <span class="text-[10px] mt-0.5" :class="isFinished ? 'text-emerald-700 dark:text-emerald-400 font-semibold' : 'text-sky-700 dark:text-cyan-400'">
                {{ isFinished ? '已抵达目标终点' : (isTracing ? '正在逐跳推进' : '待启动') }}
              </span>
            </div>

            <!-- KPI 2: 途经国家/地区数 -->
            <div class="ui-content-card p-2.5 flex flex-col justify-between">
              <span class="text-[11px]" style="color: var(--text-muted)">途经地区跨度</span>
              <div class="text-base font-bold mt-1 text-sky-700 dark:text-cyan-400 flex items-baseline gap-1">
                <span>{{ traversedStats.regionCount }}</span>
                <span class="text-[11px] font-normal" style="color: var(--text-secondary)">地级市/区</span>
              </div>
              <span class="text-[10px] mt-0.5 text-sky-700 dark:text-cyan-300 truncate" :title="traversedStats.countrySummary">
                跨越 {{ traversedStats.countryCount }} 个国家/地区
              </span>
            </div>

            <!-- KPI 3: 实测 RTT vs 光速时延 -->
            <div class="ui-content-card p-2.5 flex flex-col justify-between">
              <span class="text-[11px]" style="color: var(--text-muted)">终点实测往返 (RTT)</span>
              <div class="text-base font-bold mt-1 flex items-baseline gap-1" :class="actualFinalRttClass">
                <span>{{ actualFinalRttText }}</span>
              </div>
              <span class="text-[10px] mt-0.5 text-emerald-700 dark:text-emerald-400">
                光纤理论极限: {{ theoreticalMinRtt.toFixed(1) }} ms
              </span>
            </div>

            <!-- KPI 4: 累计物理大圆线缆距离 -->
            <div class="ui-content-card p-2.5 flex flex-col justify-between">
              <span class="text-[11px]" style="color: var(--text-muted)">测地累计物理距</span>
              <div class="text-base font-bold mt-1 text-amber-700 dark:text-amber-400 flex items-baseline gap-1">
                <span>{{ isLanTarget ? (totalGeodesicKm * 1000).toFixed(0) : totalGeodesicKm.toFixed(1) }}</span>
                <span class="text-[11px] font-normal" style="color: var(--text-secondary)">{{ isLanTarget ? 'm' : 'km' }}</span>
              </div>
              <span class="text-[10px] mt-0.5" style="color: var(--text-muted)">
                {{ isLanTarget ? 'Cat6 双绞机房跳线' : '球面大圆测地积分' }}
              </span>
            </div>
          </div>

          <!-- 左侧下部：逐跳经过的 IP 地址与地区流 / 全量 8 列指标明细表 -->
          <div class="flex-1 flex flex-col min-h-0 overflow-hidden">
            <div class="px-4 py-2 border-b flex items-center justify-between text-xs shrink-0 flex-wrap gap-2" style="background: var(--surface-content); border-color: var(--border-subtle)">
              <div class="flex items-center gap-2">
                <div class="ui-pill p-0.5 rounded-xl flex items-center gap-0.5 text-[11px] font-semibold">
                  <button
                    @click="leftViewMode = 'timeline'"
                    :class="[
                      'px-2.5 py-1 rounded-lg transition-all cursor-pointer flex items-center gap-1.5',
                      leftViewMode === 'timeline' ? 'bg-sky-500 text-white shadow-xs font-bold' : 'hover:bg-black/5 dark:hover:bg-white/5'
                    ]"
                  >
                    <AppIcon name="link" :size="12" />
                    <span>地区跃迁流</span>
                  </button>
                  <button
                    @click="leftViewMode = 'table'"
                    :class="[
                      'px-2.5 py-1 rounded-lg transition-all cursor-pointer flex items-center gap-1.5',
                      leftViewMode === 'table' ? 'bg-sky-500 text-white shadow-xs font-bold' : 'hover:bg-black/5 dark:hover:bg-white/5'
                    ]"
                  >
                    <AppIcon name="radar" :size="12" />
                    <span>逐跳指标明细 (8列)</span>
                  </button>
                </div>
                <span class="text-[11px] px-2 py-0.5 rounded-full ui-pill font-normal ui-num hidden sm:inline-block">
                  已探测 {{ hops.length }} 节点
                </span>
              </div>
              <div class="text-[11px]" style="color: var(--text-muted)">
                {{ leftViewMode === 'timeline' ? '点击节点，右侧 3D 地球瞬间对焦' : '首行始终对齐本机源端 IP · 8 列指标' }}
              </div>
            </div>

            <!-- 视图 A: 垂直时间轴卡片滚动列表 (Path Progression) -->
            <div v-show="leftViewMode === 'timeline'" class="flex-1 overflow-y-auto p-3.5 space-y-2.5 custom-scrollbar select-text">
              <template v-for="(hop, idx) in hops" :key="'hop-card-' + hop.hop_number">
                <div
                  :class="[
                    'relative ui-content-card p-3 transition-all cursor-pointer rounded-2xl border flex flex-col gap-2',
                    hop.is_self
                      ? '!border-emerald-500/60 bg-emerald-500/8 ring-1 ring-emerald-500/30'
                      : (hop.is_destination
                          ? '!border-amber-500/70 bg-amber-500/10 ring-1 ring-amber-500/40'
                          : (hop.is_timeout ? 'opacity-70 border-dashed' : 'hover:border-sky-500/60 hover:bg-sky-500/5')),
                    selectedHopRow?.hop_number === hop.hop_number ? 'ring-2 ring-sky-500 !border-sky-500' : ''
                  ]"
                  @click="focusOnHop(hop)"
                >
                  <!-- 卡片顶部：跳数徽章 + IP 地址 + 复制 -->
                  <div class="flex items-center justify-between flex-wrap gap-2">
                    <div class="flex items-center gap-2">
                      <span
                        :class="[
                          'px-2 py-0.5 rounded-md text-[11px] font-bold ui-num',
                          hop.is_self ? 'bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30' : (hop.is_destination ? 'bg-amber-500/25 text-amber-700 dark:text-amber-200 border border-amber-500/40 font-bold' : (hop.is_timeout ? 'ui-pill text-slate-400' : 'bg-sky-500/15 text-sky-700 dark:text-cyan-300 border border-sky-500/25'))
                        ]"
                      >
                        {{ hop.is_self ? '源点 #0 (本机)' : (hop.is_destination ? `终点 #${hop.hop_number} (目标)` : `跃点 #${hop.hop_number}`) }}
                      </span>

                      <!-- IP 地址与复制 -->
                      <div class="flex items-center gap-1.5 font-bold font-mono text-sm" style="color: var(--text-primary)">
                        <span v-if="hop.is_timeout" class="italic" style="color: var(--text-muted)">* (路由节点未响应 ICMP 超时)</span>
                        <span v-else>{{ hop.ip }}</span>
                        <button
                          v-if="!hop.is_timeout"
                          @click.stop="copyIp(hop.ip)"
                          class="p-1 rounded hover:bg-black/10 dark:hover:bg-white/10 text-slate-400 hover:text-sky-500 cursor-pointer"
                          title="复制此 IP"
                        >
                          <AppIcon name="clipboard" :size="12" />
                        </button>
                      </div>
                    </div>

                    <!-- 单跳 RTT 与健康度 -->
                    <div class="flex items-center gap-2">
                      <span v-if="hop.is_timeout" class="text-[11px] italic" style="color: var(--text-muted)">* ms</span>
                      <span v-else-if="hop.is_self" class="text-[11px] text-emerald-700 dark:text-emerald-400 font-bold">0.0 ms</span>
                      <template v-else>
                        <span class="text-xs ui-num font-bold" :class="getRttClass(hop.rtt_ms)">
                          {{ hop.rtt_ms >= 0 ? hop.rtt_ms.toFixed(1) + ' ms' : '*' }}
                        </span>
                        <div class="w-12 h-1.5 rounded-full overflow-hidden" style="background: var(--surface-elevated)">
                          <div
                            class="h-full rounded-full transition-all"
                            :class="getRttBarColor(hop.rtt_ms)"
                            :style="{ width: Math.min(100, (hop.rtt_ms / (isLanTarget ? 5 : 200)) * 100) + '%' }"
                          ></div>
                        </div>
                      </template>
                    </div>
                  </div>

                  <!-- 卡片核心：地区归属 (重中之重) -->
                  <div class="flex items-center justify-between text-xs flex-wrap gap-2 pt-1 border-t" style="border-color: var(--border-subtle)">
                    <div class="flex items-center gap-1.5 font-medium truncate" style="color: var(--text-primary)">
                      <AppIcon :name="hop.country && hop.country !== '未知' ? 'globe' : (hop.is_self ? 'cpu' : 'layers')" :size="13" class="shrink-0 text-sky-700 dark:text-cyan-400" />
                      <span class="font-bold text-sky-700 dark:text-cyan-300">
                        {{ formatLocationDetailed(hop) }}
                      </span>
                    </div>

                    <div v-if="hop.isp" class="text-[11px] px-2 py-0.5 rounded-lg ui-pill truncate max-w-[190px]" style="color: var(--text-muted)" :title="hop.isp">
                      {{ hop.isp }}
                    </div>
                  </div>

                  <!-- 卡片底部：经纬度坐标与线缆距离 -->
                  <div class="flex items-center justify-between text-[11px] ui-num" style="color: var(--text-muted)">
                    <div class="flex items-center gap-2">
                      <span class="text-emerald-700 dark:text-emerald-400 font-medium">
                        [{{ getHopCoordinates(hop, idx)[0].toFixed(2) }}°E, {{ getHopCoordinates(hop, idx)[1].toFixed(2) }}°N]
                      </span>
                      <span v-if="hop.subnet_cidr" class="px-1.5 py-0.2 rounded ui-pill text-[10px]">
                        {{ hop.subnet_cidr }}
                      </span>
                    </div>

                    <div class="flex items-center gap-2">
                      <span v-if="isLanTarget" class="text-emerald-700 dark:text-emerald-400 font-semibold">
                        线距: ~{{ Math.round(hop.cumulative_distance_km * 1000) }} m
                      </span>
                      <span v-else-if="hop.cumulative_distance_km > 0" class="text-sky-700 dark:text-cyan-300 font-semibold">
                        累计距: {{ hop.cumulative_distance_km.toFixed(1) }} km
                      </span>
                      <span v-else>距起点: 0.0 km</span>
                    </div>
                  </div>
                </div>

                <!-- 跃点与跃点之间的连接微观指示符 -->
                <div v-if="idx < hops.length - 1" class="flex items-center justify-center my-0.5">
                  <div class="flex items-center gap-1.5 text-[10px] ui-num font-semibold" style="color: var(--text-muted)">
                    <div class="w-1.5 h-1.5 rounded-full bg-sky-500/40"></div>
                    <div class="w-8 h-[2px] bg-sky-500/30"></div>
                    <AppIcon name="arrow-right" :size="10" class="text-sky-500" />
                    <span v-if="hops[idx + 1].cumulative_distance_km > hop.cumulative_distance_km" class="text-sky-700 dark:text-cyan-400">
                      +{{ (hops[idx + 1].cumulative_distance_km - hop.cumulative_distance_km).toFixed(1) }} km
                    </span>
                    <span v-else-if="isLanTarget" class="text-emerald-700 dark:text-emerald-400">
                      微观交换
                    </span>
                    <div class="w-8 h-[2px] bg-sky-500/30"></div>
                    <div class="w-1.5 h-1.5 rounded-full bg-sky-500/40"></div>
                  </div>
                </div>
              </template>

              <!-- 空状态提示 -->
              <EmptyState
                v-if="hops.length === 0"
                class="w-full py-16"
                icon="radar"
                title="等待启动路由溯源"
                description="在上方输入目标主机并点击【启动溯源追踪】，系统将实时嗅探骨干网各级路由器与物理归属地区。"
              />
            </div>

            <!-- 视图 B: 逐跳指标明细表格 (Hop-by-Hop Telemetry 8列全量视图) -->
            <div v-show="leftViewMode === 'table'" class="flex-1 overflow-auto select-text custom-scrollbar ui-content-card border-0 rounded-none">
              <table class="w-full text-left text-xs border-collapse min-w-[740px]">
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
                      selectedHopRow?.hop_number === hop.hop_number ? 'bg-sky-500/10 border-l-2 border-l-sky-500' : ''
                    ]"
                    @click="focusOnHop(hop)"
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
                      <button
                        v-if="!hop.is_timeout"
                        @click.stop="copyIp(hop.ip)"
                        class="p-0.5 rounded hover:bg-black/10 dark:hover:bg-white/10 text-slate-400 hover:text-sky-500 cursor-pointer"
                        title="复制此 IP"
                      >
                        <AppIcon name="clipboard" :size="11" />
                      </button>
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
                          <span>{{ formatLocationDetailed(hop) }}</span>
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
                        v-else-if="!hop.is_timeout && hop.bufferbloat_ratio !== undefined && hop.bufferbloat_ratio > 0"
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

        <!-- ============================================================ -->
        <!-- 图形视口分栏：3D 溯源地图 (地球) / 2D / LAN (split 居右，stack 居上) -->
        <!-- ============================================================ -->
        <div
          :class="[
            'flex-1 flex flex-col min-h-0 relative overflow-hidden',
            layoutMode === 'split' ? 'order-2' : 'order-1'
          ]"
          style="background: radial-gradient(circle at center, rgba(14, 165, 233, 0.04) 0%, transparent 70%)"
        >
          
          <!-- 悬停节点即时弹窗 (Hovered Hop Tooltip: 3D/2D 统一可用) -->
          <div
            v-if="hoveredHop && (viewMode === '3d' || viewMode === '2d')"
            class="absolute top-4 right-4 ui-modal-surface rounded-2xl p-3 text-xs ui-num z-30 pointer-events-none max-w-xs shadow-xl border"
            :class="isDarkTheme ? 'border-cyan-500/30' : 'border-slate-300'"
          >
            <div class="flex items-center justify-between gap-2 border-b pb-1.5 mb-1.5" style="border-color: var(--border-subtle)">
              <span class="font-bold flex items-center gap-1.5" :class="hoveredHop.isSelf ? 'text-emerald-700 dark:text-emerald-400' : (hoveredHop.isFinal ? 'text-amber-700 dark:text-amber-400' : 'text-sky-700 dark:text-cyan-400')">
                <span class="w-2 h-2 rounded-full" :class="hoveredHop.isSelf ? 'bg-emerald-500' : (hoveredHop.isFinal ? 'bg-amber-500' : 'bg-sky-500')"></span>
                <span>{{ hoveredHop.isSelf ? '本机源端 IP' : (hoveredHop.isFinal ? '终点目标主机' : `Hop #${hoveredHop.hopNumber}`) }}</span>
              </span>
              <span class="text-[11px] px-1.5 py-0.5 rounded ui-pill font-bold">
                RTT: {{ hoveredHop.rttMs >= 0 ? hoveredHop.rttMs.toFixed(1) + ' ms' : '*' }}
              </span>
            </div>
            <div class="font-bold font-mono text-sm mb-1" style="color: var(--text-primary)">{{ hoveredHop.ip }}</div>
            <div class="text-[11px] flex items-center gap-1 text-sky-700 dark:text-cyan-300 font-medium">
              <AppIcon name="compass" :size="12" />
              <span>{{ hoveredHop.location }}</span>
            </div>
            <div v-if="hoveredHop.isp" class="text-[11px] mt-0.5 flex items-center gap-1" style="color: var(--text-muted)">
              <AppIcon name="globe" :size="12" />
              <span>{{ hoveredHop.isp }}</span>
            </div>
            <div class="text-[11px] mt-1.5 flex items-center justify-between gap-2 border-t pt-1" style="border-color: var(--border-subtle); color: var(--text-muted)">
              <span>[{{ hoveredHop.lon.toFixed(2) }}°E, {{ hoveredHop.lat.toFixed(2) }}°N]</span>
              <span class="text-emerald-700 dark:text-emerald-400 font-semibold">距起点: {{ (hoveredHop.cumulativeKm * (isLanTarget ? 1000 : 1)).toFixed(1) }} {{ isLanTarget ? 'm' : 'km' }}</span>
            </div>
          </div>

          <!-- 3D 数字地球全高度视口 Canvas -->
          <div v-show="viewMode === '3d'" class="relative w-full h-full flex items-center justify-center overflow-hidden">
            <canvas
              ref="globeCanvasRef"
              class="w-full h-full cursor-grab active:cursor-grabbing select-none block"
              @mousedown="onGlobeMouseDown"
              @mousemove="onGlobeMouseMove"
              @mouseup="onGlobeMouseUp"
              @mouseleave="onGlobeLeave"
              @click="onGlobeClick"
              @wheel.prevent="onGlobeWheel"
            ></canvas>

            <!-- 右侧顶部悬浮：3D 地球视口经纬度指示 -->
            <div class="absolute top-4 left-4 liquid-panel px-3 py-1.5 rounded-2xl text-xs ui-num flex items-center gap-2.5 z-20 pointer-events-none select-none shadow-md">
              <span class="w-2 h-2 rounded-full bg-sky-500 animate-pulse"></span>
              <span class="font-bold tracking-tight" style="color: var(--text-primary)">3D 空间测地数字地球</span>
              <span class="text-sky-700 dark:text-cyan-300 font-mono text-[11px]">
                中心: [{{ globeRotation.centerLon.toFixed(1) }}°E, {{ globeRotation.centerLat.toFixed(1) }}°N]
              </span>
              <span class="text-[11px] text-emerald-700 dark:text-emerald-400 font-semibold">
                标定节点: {{ geoWaypoints.length }} / {{ hops.length }}
              </span>
            </div>

            <!-- 右侧底部悬浮控制提示与图例胶囊 -->
            <div class="absolute bottom-3 left-4 text-[11px] ui-num flex items-center gap-2.5 select-none pointer-events-none liquid-panel px-3.5 py-1.5 rounded-2xl shadow-md" style="color: var(--text-secondary)">
              <span>按住鼠标拖拽 360° 旋转 · 滚轮缩放视距</span>
              <span>·</span>
              <span class="text-emerald-700 dark:text-emerald-400 font-semibold">单击左侧卡片瞬间对焦</span>
            </div>

            <div class="hidden sm:flex absolute bottom-3 right-4 items-center gap-3 text-[11px] ui-num liquid-panel px-3.5 py-1.5 rounded-2xl select-none shadow-md">
              <div class="flex items-center gap-1.5 text-emerald-700 dark:text-emerald-400 font-semibold">
                <span class="w-2.5 h-2.5 rounded-full bg-emerald-500"></span>
                <span>本机 (Hop 0)</span>
              </div>
              <div class="flex items-center gap-1.5 text-sky-700 dark:text-cyan-400 font-semibold">
                <span class="w-2.5 h-2.5 rounded-full bg-sky-500"></span>
                <span>中间跃点</span>
              </div>
              <div class="flex items-center gap-1.5 text-amber-700 dark:text-amber-400 font-semibold">
                <span class="w-2.5 h-2.5 rounded-full bg-amber-500"></span>
                <span>目标主机</span>
              </div>
            </div>
          </div>

          <!-- 2D 全景地图视口 (Equirectangular) -->
          <div v-show="viewMode === '2d'" class="w-full h-full flex items-center justify-center p-4">
            <svg
              viewBox="0 0 960 480"
              class="w-full h-full object-contain select-none shadow-inner rounded-2xl border"
              :class="isDarkTheme ? 'border-cyan-500/20 bg-slate-950/60' : 'border-slate-300 bg-sky-50/50'"
              xmlns="http://www.w3.org/2000/svg"
            >
              <defs>
                <filter id="ptm-glow2d" x="-20%" y="-20%" width="140%" height="140%">
                  <feGaussianBlur stdDeviation="2.0" result="blur" />
                  <feMerge>
                    <feMergeNode in="blur" />
                    <feMergeNode in="SourceGraphic" />
                  </feMerge>
                </filter>
              </defs>

              <!-- 经纬网格 -->
              <g :class="isDarkTheme ? 'stroke-slate-800/60' : 'stroke-slate-400/35'" stroke-width="0.8" stroke-dasharray="2 3">
                <line x1="0" y1="240" x2="960" y2="240" :class="isDarkTheme ? 'stroke-slate-600/80' : 'stroke-slate-500/45'" stroke-width="1.2" stroke-dasharray="none" />
                <line x1="480" y1="0" x2="480" y2="480" :class="isDarkTheme ? 'stroke-slate-600/80' : 'stroke-slate-500/45'" stroke-width="1.2" stroke-dasharray="none" />
                <line x1="0" y1="177.3" x2="960" y2="177.3" :class="isDarkTheme ? 'stroke-cyan-900/30' : 'stroke-sky-500/25'" />
                <line x1="0" y1="302.7" x2="960" y2="302.7" :class="isDarkTheme ? 'stroke-cyan-900/30' : 'stroke-sky-500/25'" />
                <line v-for="y in [80, 160, 320, 400]" :key="'lat-' + y" x1="0" :y1="y" x2="960" :y2="y" />
                <line v-for="x in [80, 160, 240, 320, 400, 560, 640, 720, 800, 880]" :key="'lon-' + x" :x1="x" y1="0" :x2="x" y2="480" />
              </g>

              <!-- 大陆板块 -->
              <g :class="isDarkTheme ? 'fill-slate-800/75 stroke-cyan-500/35' : 'fill-white/90 stroke-blue-500/35'" stroke-width="0.8">
                <path v-for="(pathStr, pIdx) in worldLandPaths2d" :key="'poly-2d-' + pIdx" :d="pathStr" />
              </g>

              <!-- 2D 测地航线 -->
              <g>
                <template v-for="(flight, idx) in flightArcs2d" :key="'flight-2d-' + idx">
                  <path :d="flight.pathData" class="fill-none stroke-sky-500/25 stroke-[3]" />
                  <path
                    :d="flight.pathData"
                    class="fill-none stroke-[2] animate-dash"
                    :stroke="flight.strokeColor"
                    stroke-dasharray="6 4"
                    filter="url(#ptm-glow2d)"
                  />
                </template>
              </g>

              <!-- 2D 节点信标 -->
              <g>
                <g
                  v-for="point in geoWaypoints"
                  :key="'wp2d-' + point.hopNumber"
                  :transform="`translate(${point.x2d}, ${point.y2d})`"
                  class="cursor-pointer hover:scale-125 transition-transform"
                  @mouseenter="hoveredHop = point"
                  @mouseleave="hoveredHop = null"
                  @click="focusOnHop(point.rawHop)"
                >
                  <circle
                    r="8"
                    :class="point.isSelf ? 'fill-emerald-500/25 stroke-emerald-500' : (point.isFinal ? 'fill-amber-500/25 stroke-amber-500' : 'fill-sky-500/20 stroke-sky-500')"
                    stroke-width="1.5"
                  />
                  <circle
                    r="4"
                    :class="point.isSelf ? 'fill-emerald-500' : (point.isFinal ? 'fill-amber-500' : 'fill-sky-500')"
                  />
                  <text
                    text-anchor="middle"
                    y="-11"
                    class="font-mono text-[11px] font-bold select-none"
                    :class="isDarkTheme ? 'fill-slate-200' : 'fill-slate-900'"
                  >
                    {{ point.isSelf ? '本机' : '#' + point.hopNumber }}
                  </text>
                </g>
              </g>
            </svg>
          </div>

          <!-- 模式 LAN: 局域网微观虚拟拓扑架构 -->
          <div v-show="viewMode === 'lan'" class="w-full h-full flex flex-col justify-between p-4 overflow-x-auto select-none">
            <div class="flex items-center justify-between text-xs z-10 flex-wrap gap-2">
              <div class="flex items-center gap-2">
                <span class="w-2 h-2 rounded-full bg-emerald-500"></span>
                <span class="font-bold tracking-tight" style="color: var(--text-primary)">局域网企业架构逐级跃迁虚拟拓扑</span>
                <span class="px-2 py-0.5 rounded-full bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 border border-emerald-500/25 text-[11px]">
                  Purdue Enterprise Model
                </span>
              </div>
              <div class="text-[11px] ui-num flex items-center gap-2" style="color: var(--text-secondary)">
                <span>介质: <strong class="text-sky-700 dark:text-cyan-400">千兆工业双绞线</strong></span>
                <span>·</span>
                <span>单跳时延: <strong class="text-emerald-700 dark:text-emerald-400">&lt; 1.0 ms</strong></span>
              </div>
            </div>

            <!-- 横向逐跳架构节点卡片流 -->
            <div class="relative flex-1 flex items-center gap-3 overflow-x-auto py-3 px-2 custom-scrollbar">
              <template v-for="(hop, idx) in hops" :key="'lan-node-' + hop.hop_number">
                <div
                  :class="[
                    'relative shrink-0 w-64 ui-content-card p-3.5 transition-colors cursor-pointer flex flex-col justify-between select-text rounded-2xl',
                    hop.is_self ? '!border-emerald-500/50 bg-emerald-500/8' : (hop.is_destination ? '!border-amber-500/50 bg-amber-500/8' : 'hover:border-sky-500/50'),
                    selectedHopRow?.hop_number === hop.hop_number ? 'ring-2 ring-sky-500' : ''
                  ]"
                  @click="focusOnHop(hop)"
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

        </div>
      </div>

      <!-- 4. 底部状态指示栏 (Liquid Glass Footer) -->
      <footer class="px-5 py-2 border-t flex items-center justify-between text-[11px] ui-num shrink-0" style="background: var(--surface-content-alt); border-color: var(--border-subtle); color: var(--text-muted)">
        <div class="flex items-center gap-3 flex-wrap">
          <span>三维渲染: 正射空间投影 (Orthographic 3D)</span>
          <span>·</span>
          <span>空间几何: 大圆测地插值 (Great-Circle Slerp) 全节点立体映射</span>
          <span>·</span>
          <span>情报引擎: ip2region.xdb 联动自适应</span>
        </div>
        <div class="flex items-center gap-2">
          <span v-if="statusMessage" class="text-sky-700 dark:text-cyan-400 font-bold">{{ statusMessage }}</span>
          <span v-else>系统就绪</span>
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
import { interpolateGreatCirclePoint, WORLD_LAND_POLYGONS } from '../utils/geoMap';

const isDarkTheme = ref(!document.documentElement.classList.contains('theme-apple-light'));
let themeObserver: MutationObserver | null = null;

export interface TracerouteHopEvent {
  hop: number;
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
  cumulative_distance_km: number;
  theoretical_fiber_rtt_ms: number;
  bufferbloat_ratio?: number;
  is_destination: boolean;
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

// 模式控制: '3d' (三维数字地球) | '2d' (二维全景地图) | 'lan' (局域网微观架构)
const viewMode = ref<'3d' | '2d' | 'lan'>('3d');
const isAutoRotating = ref(true);

// 布局架构模式: 'split' (左右分栏: 左侧数据流/表 + 右侧数字地球) | 'stack' (上下大盘: 上方数字地球/拓扑 + 下方全宽8列表格)
const layoutMode = ref<'split' | 'stack'>('split');

// 左侧数据面板视图模式: 'timeline' (经过的地区路径流) | 'table' (逐跳指标明细8列表格)
const leftViewMode = ref<'timeline' | 'table'>('timeline');

// 目标与配置
const inputTarget = ref(props.initialTarget || '138.197.159.140');
const maxHops = ref(30);
const timeoutMs = ref(1000);

// 探测状态
const isTracing = ref(false);
const isFinished = ref(false);
const currentHop = ref(0);
const hops = ref<TracerouteHopEvent[]>([]);
const statusMessage = ref('');

// 选中的跃点
const selectedHopRow = ref<TracerouteHopEvent | null>(null);
const hoveredHop = ref<GeoPoint | null>(null);

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
  lon: 114.05,
  lat: 22.55,
  refineStatus: '初始化'
});

// 预先获取/估算的目标端点经纬度 (用于第 0 秒即时构建大圆航线骨架)
const targetEstimatedGeo = ref({
  lon: -74.0,
  lat: 40.7,
  location: '目标主机'
});

// 终点目标节点
const destinationHop = computed(() => {
  return hops.value.find(h => h.is_destination) || (hops.value.length > 1 ? hops.value[hops.value.length - 1] : null);
});

// 途经地区统计
const traversedStats = computed(() => {
  const regions = new Set<string>();
  const countries = new Set<string>();
  for (const h of hops.value) {
    if (h.is_timeout) continue;
    if (h.country && h.country !== '未知' && h.country !== '骨干中继') {
      countries.add(h.country);
      if (h.city && h.city !== '未知' && h.city !== h.province) {
        regions.add(`${h.province || h.country} · ${h.city}`);
      } else if (h.province && h.province !== '未知') {
        regions.add(h.province);
      }
    }
  }
  return {
    countryCount: Math.max(1, countries.size),
    regionCount: Math.max(1, regions.size),
    countrySummary: Array.from(countries).join(' / ') || '中国'
  };
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

// 3D 地球 Canvas 引用与旋转状态
const globeCanvasRef = ref<HTMLCanvasElement | null>(null);
const globeRotation = ref({
  centerLon: 114.05,
  centerLat: 22.55,
  targetLon: 114.05,
  targetLat: 22.55,
  isTransitioning: false,
  radius: 170,
  isDragging: false,
  lastMouseX: 0,
  lastMouseY: 0
});

let animationFrameId: number | null = null;
let unlistenHopEvent: UnlistenFn | null = null;

// 2D 投影路径计算
const worldLandPaths2d = computed(() => {
  return WORLD_LAND_POLYGONS.map(poly => {
    return poly.map((pt, i) => {
      const x = ((pt[0] + 180.0) / 360.0) * 960.0;
      const y = ((90.0 - pt[1]) / 180.0) * 480.0;
      return `${i === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)}`;
    }).join(' ') + ' Z';
  });
});

// 计算跳点坐标（如果某跳无明确经纬度，使用大圆 Slerp 进行高精物理空间插值，确保每个节点都在地球上有位置）
function getHopCoordinates(hop: TracerouteHopEvent, idx: number): [number, number] {
  if (hop.has_geo && hop.longitude !== 0 && hop.latitude !== 0) {
    return [hop.longitude, hop.latitude];
  }

  const startLon = selfHopInfo.value.lon || 114.05;
  const startLat = selfHopInfo.value.lat || 22.55;

  let endLon = targetEstimatedGeo.value.lon;
  let endLat = targetEstimatedGeo.value.lat;
  if (destinationHop.value && destinationHop.value.has_geo && destinationHop.value.longitude) {
    endLon = destinationHop.value.longitude;
    endLat = destinationHop.value.latitude;
  }

  if (idx === 0 || hop.is_self) {
    return [startLon, startLat];
  }
  if (hop.is_destination || idx === hops.value.length - 1) {
    return [endLon, endLat];
  }

  const t = idx / Math.max(1, hops.value.length - 1);
  return interpolateGreatCirclePoint(startLon, startLat, endLon, endLat, t);
}

// 提取全量航路点（每一个节点都 100% 包含并映射至经纬度坐标系）
const geoWaypoints = computed<GeoPoint[]>(() => {
  const points: GeoPoint[] = [];
  const total = hops.value.length;
  if (total === 0) return points;

  for (let i = 0; i < total; i++) {
    const hop = hops.value[i];
    const [lon, lat] = getHopCoordinates(hop, i);

    const x2d = ((lon + 180.0) / 360.0) * 960.0;
    const y2d = ((90.0 - lat) / 180.0) * 480.0;

    points.push({
      hopNumber: hop.hop_number,
      ip: hop.ip,
      lon,
      lat,
      x2d,
      y2d,
      rttMs: hop.rtt_ms,
      location: formatLocationDetailed(hop),
      isp: hop.isp,
      cumulativeKm: hop.cumulative_distance_km,
      isSelf: hop.is_self ?? (hop.hop_number === 0),
      isFinal: hop.is_destination || (i === total - 1 && total > 1),
      rawHop: hop
    });
  }
  return points;
});

// 2D 贝塞尔飞线
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

// ============================================================
// 3D 正射空间投影渲染函数
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

  // 1. 大气层扩散光晕
  const haloGrad = ctx.createRadialGradient(cx, cy, r * 0.92, cx, cy, r * 1.35);
  haloGrad.addColorStop(0, dark ? 'rgba(6, 182, 212, 0.35)' : 'rgba(14, 165, 233, 0.25)');
  haloGrad.addColorStop(0.5, dark ? 'rgba(14, 165, 233, 0.15)' : 'rgba(59, 130, 246, 0.10)');
  haloGrad.addColorStop(1, 'rgba(15, 23, 42, 0)');
  ctx.fillStyle = haloGrad;
  ctx.beginPath();
  ctx.arc(cx, cy, r * 1.35, 0, Math.PI * 2);
  ctx.fill();

  // 2. 球体深邃背景色
  const sphereGrad = ctx.createRadialGradient(cx - r * 0.35, cy - r * 0.35, r * 0.1, cx, cy, r);
  if (dark) {
    sphereGrad.addColorStop(0, '#0e2544');
    sphereGrad.addColorStop(0.65, '#06152a');
    sphereGrad.addColorStop(1, '#020617');
  } else {
    sphereGrad.addColorStop(0, '#e0f2fe');
    sphereGrad.addColorStop(0.65, '#bae6fd');
    sphereGrad.addColorStop(1, '#7dd3fc');
  }
  ctx.fillStyle = sphereGrad;
  ctx.beginPath();
  ctx.arc(cx, cy, r, 0, Math.PI * 2);
  ctx.fill();

  ctx.save();
  ctx.beginPath();
  ctx.arc(cx, cy, r, 0, Math.PI * 2);
  ctx.clip();

  // 3. 经纬网格与赤道
  ctx.strokeStyle = dark ? 'rgba(56, 189, 248, 0.18)' : 'rgba(15, 23, 42, 0.14)';
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
    if (lat === 0) {
      ctx.save();
      ctx.strokeStyle = dark ? 'rgba(34, 211, 238, 0.45)' : 'rgba(14, 116, 144, 0.4)';
      ctx.lineWidth = 1.4;
      ctx.stroke();
      ctx.restore();
    } else {
      ctx.stroke();
    }
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

  // 4. 自然地球陆地多边形绘制
  ctx.fillStyle = dark ? 'rgba(30, 58, 95, 0.78)' : 'rgba(248, 250, 252, 0.94)';
  ctx.strokeStyle = dark ? 'rgba(34, 211, 238, 0.4)' : 'rgba(59, 130, 246, 0.42)';
  ctx.lineWidth = 1.1;

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

  // 5. 逐跳大圆立体飞线与粒子流光光弧
  const pts = geoWaypoints.value;
  if (pts.length >= 2) {
    for (let i = 0; i < pts.length - 1; i++) {
      const p1 = pts[i];
      const p2 = pts[i + 1];

      const numSteps = 28;
      const arcPoints: { x: number; y: number; visible: boolean }[] = [];

      for (let s = 0; s <= numSteps; s++) {
        const t = s / numSteps;
        const [interpLon, interpLat] = interpolateGreatCirclePoint(p1.lon, p1.lat, p2.lon, p2.lat, t);
        const alt = Math.sin(t * Math.PI) * (r * 0.22);
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
      ctx.strokeStyle = p1.isSelf
        ? 'rgba(16, 185, 129, 0.85)'
        : (p2.isFinal ? 'rgba(245, 158, 11, 0.85)' : 'rgba(6, 182, 212, 0.8)');
      ctx.lineWidth = 2.4;
      ctx.stroke();

      // 光斑粒子沿飞线航路高速巡航流动
      const flowT = (pulseTime * 0.9 + i * 0.35) % 1.0;
      const flowIdx = Math.floor(flowT * (arcPoints.length - 1));
      const flowPt = arcPoints[flowIdx];
      if (flowPt && flowPt.visible) {
        ctx.fillStyle = '#ffffff';
        ctx.shadowColor = '#38bdf8';
        ctx.shadowBlur = 10;
        ctx.beginPath();
        ctx.arc(cx + flowPt.x, cy + flowPt.y, 3.6, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowBlur = 0;
      }
    }
  }

  // 6. 航路点空间信标与标签 (每一个经过的节点均立体绘制在 3D 地球表面)
  for (const pt of pts) {
    const p = projectLonLatToGlobe(pt.lon, pt.lat, cLon, cLat, r);
    if (p.visible) {
      const px = cx + p.x;
      const py = cy + p.y;

      const isSelected = selectedHopRow.value?.hop_number === pt.hopNumber;
      const pulseR = isSelected ? 8 + Math.sin(pulseTime * 6) * 3 : 5 + (Math.sin(pulseTime * 4) + 1) * 2.2;
      
      ctx.beginPath();
      ctx.arc(px, py, pulseR, 0, Math.PI * 2);
      ctx.strokeStyle = pt.isSelf ? 'rgba(16, 185, 129, 0.6)' : (pt.isFinal ? 'rgba(245, 158, 11, 0.6)' : 'rgba(6, 182, 212, 0.5)');
      ctx.lineWidth = isSelected ? 2.0 : 1.2;
      ctx.stroke();

      ctx.beginPath();
      ctx.arc(px, py, isSelected ? 5.5 : 4.0, 0, Math.PI * 2);
      ctx.fillStyle = pt.isSelf ? '#10b981' : (pt.isFinal ? '#f59e0b' : '#06b6d4');
      ctx.shadowColor = ctx.fillStyle;
      ctx.shadowBlur = isSelected ? 12 : 6;
      ctx.fill();
      ctx.shadowBlur = 0;

      ctx.fillStyle = dark
        ? (pt.isSelf ? '#34d399' : (pt.isFinal ? '#fbbf24' : '#e2e8f0'))
        : (pt.isSelf ? '#047857' : (pt.isFinal ? '#b45309' : '#0f172a'));
      ctx.font = 'bold 11px monospace';
      ctx.textAlign = 'center';
      const labelText = pt.isSelf ? '源点 #0' : (pt.isFinal ? `终点 #${pt.hopNumber}` : `#${pt.hopNumber}`);
      ctx.fillText(labelText, px, py - 9);
    }
  }

  ctx.restore();

  // 外圈描边光圈
  ctx.strokeStyle = dark ? 'rgba(56, 189, 248, 0.45)' : 'rgba(14, 116, 144, 0.4)';
  ctx.lineWidth = 1.6;
  ctx.beginPath();
  ctx.arc(cx, cy, r, 0, Math.PI * 2);
  ctx.stroke();
}

// 动画与平滑对焦旋转
function animate() {
  pulseTime += 0.02;

  // 平滑对焦插值过渡
  if (globeRotation.value.isTransitioning) {
    const targetLon = globeRotation.value.targetLon;
    const targetLat = globeRotation.value.targetLat;
    let diffLon = targetLon - globeRotation.value.centerLon;

    while (diffLon > 180) diffLon -= 360;
    while (diffLon < -180) diffLon += 360;

    const diffLat = targetLat - globeRotation.value.centerLat;

    if (Math.abs(diffLon) < 0.2 && Math.abs(diffLat) < 0.2) {
      globeRotation.value.centerLon = (targetLon + 360) % 360;
      globeRotation.value.centerLat = targetLat;
      globeRotation.value.isTransitioning = false;
    } else {
      globeRotation.value.centerLon = (globeRotation.value.centerLon + diffLon * 0.12 + 360) % 360;
      globeRotation.value.centerLat += diffLat * 0.12;
    }
  } else if (isAutoRotating.value && !globeRotation.value.isDragging && viewMode.value === '3d') {
    globeRotation.value.centerLon = (globeRotation.value.centerLon + 0.16) % 360;
  }

  if (viewMode.value === '3d') {
    render3dGlobe();
  }

  animationFrameId = requestAnimationFrame(animate);
}

// 3D 球面信标拾取热区探测 (将鼠标 CSS 坐标映射至设备像素坐标系对比)
function findHoveredGlobePoint(e: MouseEvent): GeoPoint | null {
  const canvas = globeCanvasRef.value;
  if (!canvas || geoWaypoints.value.length === 0) return null;
  const rect = canvas.getBoundingClientRect();
  const dpr = window.devicePixelRatio || 1;
  const mouseX = (e.clientX - rect.left) * dpr;
  const mouseY = (e.clientY - rect.top) * dpr;
  const cx = canvas.width / 2;
  const cy = canvas.height / 2;
  const hitThreshold = 15 * dpr;

  let closest: GeoPoint | null = null;
  let minDist = Infinity;

  for (const pt of geoWaypoints.value) {
    const proj = projectLonLatToGlobe(
      pt.lon,
      pt.lat,
      globeRotation.value.centerLon,
      globeRotation.value.centerLat,
      globeRotation.value.radius
    );
    if (!proj.visible) continue;
    const dx = mouseX - (cx + proj.x);
    const dy = mouseY - (cy + proj.y);
    const dist = Math.sqrt(dx * dx + dy * dy);
    if (dist <= hitThreshold && dist < minDist) {
      minDist = dist;
      closest = pt;
    }
  }
  return closest;
}

// 鼠标拖拽地球自由旋转
function onGlobeMouseDown(e: MouseEvent) {
  globeRotation.value.isDragging = true;
  globeRotation.value.isTransitioning = false;
  globeRotation.value.lastMouseX = e.clientX;
  globeRotation.value.lastMouseY = e.clientY;
}

function onGlobeMouseMove(e: MouseEvent) {
  if (!globeRotation.value.isDragging) {
    hoveredHop.value = findHoveredGlobePoint(e);
    return;
  }
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

function onGlobeLeave() {
  globeRotation.value.isDragging = false;
  hoveredHop.value = null;
}

function onGlobeClick(e: MouseEvent) {
  const hit = findHoveredGlobePoint(e);
  if (hit) {
    focusOnHop(hit.rawHop);
  }
}

function onGlobeWheel(e: WheelEvent) {
  const delta = e.deltaY > 0 ? -12 : 12;
  globeRotation.value.radius = Math.max(100, Math.min(320, globeRotation.value.radius + delta));
}

function toggleGlobeAutoRotate() {
  isAutoRotating.value = !isAutoRotating.value;
}

function switchViewMode(mode: '3d' | '2d' | 'lan') {
  viewMode.value = mode;
  if (mode === '3d') {
    nextTick(() => {
      resizeGlobeCanvas();
    });
  }
}

// 聚焦到指定经纬度
function focusOnCoord(lon: number, lat: number) {
  globeRotation.value.targetLon = lon;
  globeRotation.value.targetLat = lat;
  globeRotation.value.isTransitioning = true;
}

function focusOnSelf() {
  focusOnCoord(selfHopInfo.value.lon, selfHopInfo.value.lat);
}

function focusOnDestination() {
  const dest = destinationHop.value;
  if (dest) {
    const [lon, lat] = getHopCoordinates(dest, hops.value.length - 1);
    focusOnCoord(lon, lat);
  } else {
    focusOnCoord(targetEstimatedGeo.value.lon, targetEstimatedGeo.value.lat);
  }
}

function focusOnHop(hop: TracerouteHopEvent) {
  selectedHopRow.value = hop;
  const idx = hops.value.findIndex(h => h.hop_number === hop.hop_number);
  const [lon, lat] = getHopCoordinates(hop, Math.max(0, idx));
  focusOnCoord(lon, lat);
}

function copyIp(ip: string) {
  if (!ip || ip === '*') return;
  navigator.clipboard?.writeText(ip);
  statusMessage.value = `已复制 IP 地址: ${ip}`;
}

// 自动对焦至两点间的大圆中点
function autoCenterGlobe(lon1: number, lat1: number, lon2: number, lat2: number) {
  const [midLon, midLat] = interpolateGreatCirclePoint(lon1, lat1, lon2, lat2, 0.5);
  focusOnCoord(midLon, midLat);
}

// ============================================================
// 生命周期与数据流驱动
// ============================================================
watch(layoutMode, (newMode) => {
  if (newMode === 'stack') {
    leftViewMode.value = 'table';
  }
  nextTick(() => {
    resizeGlobeCanvas();
  });
});

watch(
  () => props.initialTarget,
  (newVal) => {
    if (newVal) {
      inputTarget.value = newVal;
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
    globeRotation.value.radius = Math.min(rect.width, rect.height) * 0.44 * window.devicePixelRatio;
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
  selfHopInfo.value.location = formatLocationDetailed(hop);
  selfHopInfo.value.isp = hop.isp || '本地适配器';
  if (hop.has_geo) {
    selfHopInfo.value.lon = hop.longitude;
    selfHopInfo.value.lat = hop.latitude;
    selfHopInfo.value.refineStatus = hop.ip.startsWith('192.168.') || hop.ip.startsWith('10.') || hop.ip.startsWith('172.') ? '局域网 (已关联出口城市)' : '公网 IP 直连';
    globeRotation.value.centerLon = hop.longitude;
    globeRotation.value.centerLat = hop.latitude;
  }
}

async function setupEventListener() {
  if (unlistenHopEvent) return;
  try {
    unlistenHopEvent = await listen<TracerouteHopEvent>('traceroute-hop-event', (event) => {
      const raw = event.payload;
      const hopNum = raw.hop_number ?? (raw as any).hop ?? 0;
      const hop: TracerouteHopEvent = {
        ...raw,
        hop_number: hopNum
      };
      currentHop.value = hopNum;

      if (hop.is_self || hopNum === 0) {
        updateSelfHopState(hop);
      }

      // 防御性查找与安全追加，绝不覆写不同跃点
      const existingIdx = hops.value.findIndex(h => (h.hop_number ?? (h as any).hop) === hopNum);
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
        if (hop.has_geo && hop.longitude) {
          focusOnCoord(hop.longitude, hop.latitude);
        }
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

  const target = inputTarget.value.trim();

  if (isLanTarget.value) {
    viewMode.value = 'lan';
  } else {
    viewMode.value = '3d';
  }

  isTracing.value = true;
  isFinished.value = false;
  hops.value = [];
  selectedHopRow.value = null;
  hoveredHop.value = null;
  statusMessage.value = `正在启动对 ${target} 的逐跳路由溯源追踪...`;

  // 1. 预先解析目标主机的空间坐标（毫秒级瞬时响应）
  try {
    const geo = await invoke<any>('lookup_ip_geo_coordinates_cmd', { ip: target });
    if (geo && geo.longitude && geo.latitude) {
      targetEstimatedGeo.value = {
        lon: geo.longitude,
        lat: geo.latitude,
        location: `${geo.country} · ${geo.province} · ${geo.city}`
      };
    }
  } catch (e) {
    console.warn('预解析目标坐标:', e);
  }

  // 2. 初始预置本地起点 (Hop 0)，立即点亮 3D 地球与左侧列表
  const startHop: TracerouteHopEvent = {
    hop: 0,
    hop_number: 0,
    ip: selfHopInfo.value.ip,
    rtt_ms: 0.0,
    is_timeout: false,
    country: '中国',
    province: '',
    city: selfHopInfo.value.location,
    isp: selfHopInfo.value.isp,
    latitude: selfHopInfo.value.lat,
    longitude: selfHopInfo.value.lon,
    has_geo: true,
    cumulative_distance_km: 0.0,
    theoretical_fiber_rtt_ms: 0.0,
    is_destination: false,
    is_self: true
  };
  hops.value = [startHop];

  // 3. 自动将 3D 地球视角平滑对焦到大圆航线中央
  autoCenterGlobe(selfHopInfo.value.lon, selfHopInfo.value.lat, targetEstimatedGeo.value.lon, targetEstimatedGeo.value.lat);

  try {
    await setupEventListener();
    await invoke('start_traceroute_cmd', {
      target,
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

async function stopTrace() {
  try {
    await invoke('stop_traceroute_cmd');
  } catch (e) {
    console.warn('调用 stop_traceroute_cmd 异常:', e);
  }
  isTracing.value = false;
  statusMessage.value = '已主动终止路由追踪';
}

function handleClose() {
  if (isTracing.value) {
    stopTrace();
  }
  emit('close');
}

// 格式化输出地区层级
function formatLocationDetailed(hop: TracerouteHopEvent): string {
  const parts: string[] = [];
  if (hop.country && hop.country !== '未知') parts.push(hop.country);
  if (hop.province && hop.province !== '未知' && hop.province !== hop.country) parts.push(hop.province);
  if (hop.city && hop.city !== '未知' && hop.city !== hop.province) parts.push(hop.city);
  return parts.join(' · ') || (hop.is_self ? '本地主机终端' : (hop.is_lan ? '局域网/内网专网' : '骨干网络中继节点'));
}

function getLanNodeIcon(hop: TracerouteHopEvent): string {
  if (hop.is_self || hop.hop_number === 0) return 'cpu';
  if (hop.is_destination) return 'radar';
  if (hop.hop_number === 1) return 'link';
  return 'shield';
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
  let md = `# Omni-Probe 路由溯源与测地态势诊断报告\n\n`;
  md += `- **目标主机**: \`${inputTarget.value}\` (${isLanTarget.value ? '企业局域网/内网私有资产' : '全球互联网公共网络'})\n`;
  md += `- **使用者源点 (Hop 0)**: \`${selfHopInfo.value.ip}\` (${selfHopInfo.value.location} · ${selfHopInfo.value.isp})\n`;
  md += `- **探测时间**: ${now}\n`;
  md += `- **总跃点数**: ${hops.value.length} 跃点\n`;
  md += `- **途经地区**: ${traversedStats.value.countrySummary} (共 ${traversedStats.value.regionCount} 地区)\n`;
  md += `- **测地大圆累计物理线距**: ${isLanTarget.value ? (totalGeodesicKm.value * 1000).toFixed(0) + ' m' : totalGeodesicKm.value.toFixed(1) + ' km'}\n`;
  md += `- **理论光纤最低时延**: ${theoreticalMinRtt.value.toFixed(2)} ms\n`;
  md += `- **实测终点网络往返 (RTT)**: ${actualFinalRttText.value}\n\n`;
  md += `## 1. 逐跳经过的 IP 地址与物理地区明细\n\n`;
  md += `| 跳数 | 路由器 / 节点 IP | RTT (ms) | 地理归属 (国家 · 省 · 市) | 机构 / ISP 运营商 | 测地线跨度 |\n`;
  md += `| :--- | :--- | :--- | :--- | :--- | :--- |\n`;

  for (let i = 0; i < hops.value.length; i++) {
    const h = hops.value[i];
    const loc = formatLocationDetailed(h);
    const rtt = h.is_timeout ? '*' : (h.is_self ? '0.0' : h.rtt_ms.toFixed(1));
    const distStr = isLanTarget.value ? `~${Math.round(h.cumulative_distance_km * 1000)}m` : `${h.cumulative_distance_km.toFixed(1)}km`;
    const hopLabel = h.is_self ? '**源点 #0 (本机)**' : (h.is_destination ? `**终点 #${h.hop_number} (目标)**` : `#${h.hop_number}`);
    const isp = h.isp || '-';
    md += `| ${hopLabel} | \`${h.ip}\` | ${rtt} | ${loc} | ${isp} | ${distStr} |\n`;
  }

  md += `\n---\n*Omni-Probe 工业网络全息分析仪 · 物理测地拓扑与网络空间溯源审计*\n`;

  await saveTextViaNativeDesktop(
    `traceroute_geodesic_${inputTarget.value.replace(/[^a-zA-Z0-9]/g, '_')}_${Date.now()}.md`,
    md,
    'Markdown 报告 (*.md)',
    '*.md',
    '导出测地溯源报告'
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

.custom-scrollbar::-webkit-scrollbar {
  width: 5px;
  height: 5px;
}
.custom-scrollbar::-webkit-scrollbar-thumb {
  background: rgba(148, 163, 184, 0.25);
  border-radius: 9999px;
}
.custom-scrollbar::-webkit-scrollbar-thumb:hover {
  background: rgba(14, 165, 233, 0.4);
}
</style>
