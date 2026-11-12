<template>
  <section ref="rootRef" class="ui-content-card p-3 flex flex-col gap-2.5 shrink-0 select-none">
    <!-- 顶部栏：模式切换与总线焦点 -->
    <div class="flex items-center justify-between gap-2 flex-wrap">
      <div class="flex items-center gap-2 flex-wrap">
        <span class="w-2 h-2 rounded-full" :class="filteredPackets.length > 0 ? 'bg-sky-500' : 'bg-slate-400'"></span>
        <h3 class="text-xs font-bold" style="color: var(--text-primary);">
          物理总线实时 / 历史波形统计与示波工作台
        </h3>

        <div class="p-0.5 rounded-xl ui-pill flex items-center gap-0.5 text-[11px] font-semibold">
          <button
            v-for="m in scopeModes"
            :key="m.id"
            @click="activeMode = m.id"
            :class="[
              'px-2 py-0.5 rounded-lg transition-colors cursor-pointer',
              activeMode === m.id ? 'bg-sky-500 text-white shadow-xs font-bold' : 'hover:bg-black/5 dark:hover:bg-white/5'
            ]"
            :style="activeMode !== m.id ? { color: 'var(--text-secondary)' } : undefined"
          >
            {{ m.label }}
          </button>
        </div>
      </div>

      <div class="flex items-center gap-2 text-[11px] flex-wrap">
        <select
          v-model="busScope"
          class="ui-input w-auto px-2 py-0.5 text-[11px] font-medium cursor-pointer"
          title="筛选分析的物理总线范围"
        >
          <option value="ALL">全部物理总线 (COM + USB)</option>
          <option value="SERIAL">仅 COM 串口 / 单片机</option>
          <option value="USB">仅 USB 总线</option>
        </select>

        <label
          v-if="activeMode === 'realtime-vs-history' && busScope === 'SERIAL' && selectedSerialPort"
          class="inline-flex items-center gap-1 px-2 py-0.5 rounded-md border cursor-pointer bg-[var(--surface-glass-pill)]"
          style="border-color: var(--border-subtle); color: var(--text-secondary);"
          title="勾选后仅比对当前选中串口的历史记录"
        >
          <input type="checkbox" v-model="filterByCurrentPort" class="accent-sky-500" />
          <span class="ui-num">仅看 {{ selectedSerialPort }}</span>
        </label>

        <span class="ui-num px-2 py-0.5 rounded-md border bg-[var(--surface-glass-pill)]" style="border-color: var(--border-subtle); color: var(--text-muted);">
          实时样本: <strong style="color: var(--text-primary);">{{ filteredPackets.length }}</strong> 帧
        </span>

        <button
          v-if="activeMode === 'serial-plotter' || activeMode === 'binary-scope'"
          @click="isPaused = !isPaused"
          :class="['px-2 py-0.5 rounded-lg border font-semibold cursor-pointer',
            isPaused ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/35' : 'ui-pill']"
        >
          {{ isPaused ? '已暂停采样' : '实时采集' }}
        </button>

        <button
          v-if="activeMode === 'realtime-vs-history'"
          @click="fetchHistoricalBaseline"
          :disabled="historyLoading"
          class="ui-btn-secondary px-2.5 py-0.5 text-[11px]"
        >
          <AppIcon name="refresh" :size="11" :class="historyLoading ? 'animate-spin' : ''" />
          <span>读取 JSONL 历史归档</span>
        </button>
      </div>
    </div>

    <!-- 模式 1: 多通道文本传感器绘图仪 (Arduino/STM32 COM Serial Plotter) -->
    <div v-if="activeMode === 'serial-plotter'" class="grid grid-cols-1 lg:grid-cols-12 gap-2.5 items-stretch">
      <div class="lg:col-span-9 flex flex-col gap-1.5">
        <div class="relative rounded-xl border overflow-hidden h-44" style="border-color: var(--border-subtle); background: rgba(15, 23, 42, 0.92);">
          <canvas ref="plotterCanvasRef" class="w-full h-full block"></canvas>
          <div v-if="plotterSeries.channels.length === 0" class="absolute inset-0 flex flex-col items-center justify-center text-center px-4">
            <span class="text-xs font-semibold text-slate-300">尚未提取到 COM 串口多通道数值波形</span>
            <span class="text-[11px] text-slate-400 mt-1 font-mono">
              等待单片机输出如 <code class="text-sky-300">temp:25.4 hum:61.2</code> 或 CSV 行 <code class="text-sky-300">25.4,61.2,3.30</code>
            </span>
          </div>
        </div>
        <div class="flex items-center justify-between text-[11px] flex-wrap gap-2" style="color: var(--text-muted);">
          <div class="flex items-center gap-2 flex-wrap">
            <span
              v-for="(ch, idx) in plotterSeries.channels"
              :key="ch.name"
              @click="toggleChannelVisibility(ch.name)"
              class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md border cursor-pointer ui-num"
              :style="{
                borderColor: hiddenChannels.has(ch.name) ? 'var(--border-subtle)' : channelColor(idx),
                opacity: hiddenChannels.has(ch.name) ? 0.45 : 1,
                color: 'var(--text-primary)'
              }"
            >
              <span class="w-2 h-2 rounded-full" :style="{ backgroundColor: channelColor(idx) }"></span>
              <span>{{ ch.name }}</span>
              <strong class="font-mono">{{ ch.latest.toFixed(2) }}</strong>
            </span>
          </div>
          <span class="ui-num">有效时间点: {{ plotterSeries.pointCount }}</span>
        </div>
      </div>

      <div class="lg:col-span-3 ui-sub-card p-2.5 flex flex-col justify-between gap-2 text-[11px]">
        <div class="font-semibold" style="color: var(--text-primary);">通道统计摘要</div>
        <div class="space-y-1.5 overflow-auto max-h-32 custom-scrollbar ui-num">
          <div v-for="(ch, idx) in plotterSeries.channels" :key="ch.name" class="p-1.5 rounded-lg border bg-[var(--surface-glass-pill)]" style="border-color: var(--border-subtle);">
            <div class="flex items-center justify-between">
              <span class="font-bold flex items-center gap-1" style="color: var(--text-primary);">
                <span class="w-1.5 h-1.5 rounded-full" :style="{ backgroundColor: channelColor(idx) }"></span>
                {{ ch.name }}
              </span>
              <span style="color: var(--text-muted);">N={{ ch.samples.length }}</span>
            </div>
            <div class="grid grid-cols-3 gap-1 mt-1 text-[10px]" style="color: var(--text-secondary);">
              <span>Min: {{ ch.min.toFixed(2) }}</span>
              <span>Max: {{ ch.max.toFixed(2) }}</span>
              <span>Avg: {{ ch.avg.toFixed(2) }}</span>
            </div>
          </div>
          <div v-if="plotterSeries.channels.length === 0" class="text-[11px] py-4 text-center" style="color: var(--text-muted);">
            无活跃传感器通道
          </div>
        </div>
        <button
          @click="exportPlotterCsv"
          :disabled="plotterSeries.channels.length === 0"
          class="ui-btn-secondary w-full py-1 text-[11px] justify-center disabled:opacity-40"
        >
          导出波形采样 CSV
        </button>
      </div>
    </div>

    <!-- 模式 2: 二进制寄存器实时解调 / VOFA+ JustFloat / 自定义 Struct 多通道示波 -->
    <div v-else-if="activeMode === 'binary-scope'" class="grid grid-cols-1 lg:grid-cols-12 gap-2.5 items-stretch">
      <div class="lg:col-span-8 flex flex-col gap-1.5">
        <div class="flex items-center justify-between gap-2 text-[11px] flex-wrap">
          <div class="p-0.5 rounded-lg ui-pill flex items-center gap-0.5 font-semibold">
            <button
              @click="binaryDecodeMode = 'single'"
              :class="['px-2 py-0.5 rounded cursor-pointer', binaryDecodeMode === 'single' ? 'bg-sky-500 text-white' : '']"
            >
              单字段高速切片
            </button>
            <button
              @click="binaryDecodeMode = 'justfloat'; refreshStructDecode()"
              :class="['px-2 py-0.5 rounded cursor-pointer', binaryDecodeMode === 'justfloat' ? 'bg-indigo-600 text-white' : '']"
            >
              VOFA+ JustFloat 多浮点
            </button>
            <button
              @click="binaryDecodeMode = 'struct'; refreshStructDecode()"
              :class="['px-2 py-0.5 rounded cursor-pointer', binaryDecodeMode === 'struct' ? 'bg-emerald-600 text-white' : '']"
            >
              自定义 Struct 多通道
            </button>
          </div>
          <span v-if="binaryDecodeMode !== 'single' && structDecodeRes" class="text-[10px] ui-num" style="color: var(--text-muted);">
            已解 {{ structDecodeRes.decoded_frame_count }} 帧 ({{ structDecodeRes.channels.length }} 通道) · 跳过 {{ structDecodeRes.skipped_frame_count }} 帧
          </span>
        </div>

        <div v-if="binaryDecodeMode === 'single'" class="relative rounded-xl border overflow-hidden h-44" style="border-color: var(--border-subtle); background: rgba(15, 23, 42, 0.92);">
          <canvas ref="binaryCanvasRef" class="w-full h-full block"></canvas>
          <div v-if="binarySeries.length === 0" class="absolute inset-0 flex flex-col items-center justify-center text-center px-4">
            <span class="text-xs font-semibold text-slate-300">尚未捕获到满足字节偏移长度的物理载荷</span>
            <span class="text-[11px] text-slate-400 mt-1 ui-num">需存在字节长度 ≥ {{ Math.max(0, Math.floor(binOffset)) + (binFloat32 ? 4 : binWidth) }}B 的串口或 USB 载荷帧</span>
          </div>
        </div>

        <div v-else class="relative rounded-xl border p-2 h-44 ui-sub-card">
          <VChart
            v-if="structDecodeRes && structDecodeRes.channels.length > 0"
            :option="binaryStructEchartOption"
            autoresize
            class="w-full h-full"
          />
          <div v-else class="w-full h-full flex items-center justify-center text-center text-[11px] px-4" style="color: var(--text-muted);">
            {{ binaryDecodeMode === 'justfloat' ? '等待符合 VOFA+ JustFloat (小端 Float32 数组 + 00 00 80 7F 帧尾) 的串口流数据' : '暂无匹配结构模板的二进制帧，可在右侧检查帧头魔数与字段偏移配置后点击重新解构' }}
          </div>
        </div>
      </div>

      <div class="lg:col-span-4 ui-sub-card p-2.5 flex flex-col justify-between gap-2 text-[11px]">
        <template v-if="binaryDecodeMode === 'single'">
          <div class="flex items-center justify-between">
            <span class="font-semibold" style="color: var(--text-primary);">单寄存器切片解码器</span>
            <span class="text-[10px] ui-num" style="color: var(--text-muted);">N={{ binarySeries.length }}</span>
          </div>
          <div class="grid grid-cols-2 gap-1.5">
            <div>
              <label class="text-[10px] block mb-0.5" style="color: var(--text-muted);">偏移 (Byte)</label>
              <input type="number" v-model.number="binOffset" min="0" max="1024" class="ui-input w-full px-2 py-0.5 text-[11px] ui-num" />
            </div>
            <div>
              <label class="text-[10px] block mb-0.5" style="color: var(--text-muted);">位宽</label>
              <select v-model.number="binWidth" :disabled="binFloat32" class="ui-input w-full px-1.5 py-0.5 text-[11px] disabled:opacity-50">
                <option :value="1">8-bit (1B)</option>
                <option :value="2">16-bit (2B)</option>
                <option :value="4">32-bit (4B)</option>
              </select>
            </div>
          </div>
          <div class="flex items-center gap-2.5 text-[11px] flex-wrap">
            <label class="flex items-center gap-1 cursor-pointer">
              <input type="checkbox" v-model="binLittleEndian" class="accent-sky-500" />
              <span style="color: var(--text-secondary);">小端 (LE)</span>
            </label>
            <label class="flex items-center gap-1 cursor-pointer">
              <input type="checkbox" v-model="binSigned" :disabled="binFloat32" class="accent-sky-500" />
              <span style="color: var(--text-secondary);">有符号</span>
            </label>
            <label class="flex items-center gap-1 cursor-pointer">
              <input type="checkbox" v-model="binFloat32" class="accent-indigo-500" />
              <span class="font-semibold text-indigo-600 dark:text-indigo-300">IEEE Float32</span>
            </label>
          </div>
          <div class="grid grid-cols-2 gap-1 p-1.5 rounded-lg border ui-num text-[10px]" style="border-color: var(--border-subtle); color: var(--text-secondary);">
            <span>Min: <strong>{{ binaryStats.min.toFixed(2) }}</strong></span>
            <span>Max: <strong>{{ binaryStats.max.toFixed(2) }}</strong></span>
            <span>Mean: <strong>{{ binaryStats.avg.toFixed(2) }}</strong></span>
            <span>Vpp: <strong>{{ binaryStats.vpp.toFixed(2) }}</strong></span>
          </div>
        </template>

        <template v-else-if="binaryDecodeMode === 'justfloat'">
          <div class="font-semibold" style="color: var(--text-primary);">VOFA+ JustFloat 协议解析</div>
          <div class="text-[10px]" style="color: var(--text-muted);">
            自动从连续/分片串口 HEX 流识别尾标 <code class="font-mono">00 00 80 7F</code> 并拆解多通道小端 IEEE-754 Float32。
          </div>
          <div v-if="structDecodeRes && structDecodeRes.channels.length > 0" class="max-h-24 overflow-y-auto space-y-1">
            <div v-for="ch in structDecodeRes.channels" :key="ch.name" class="px-2 py-0.5 rounded border text-[10px] ui-num flex justify-between" style="border-color: var(--border-subtle);">
              <span class="font-bold">{{ ch.name }}</span>
              <span>现值={{ ch.latest.toFixed(3) }} · [{{ ch.min.toFixed(2) }}..{{ ch.max.toFixed(2) }}]</span>
            </div>
          </div>
          <button @click="refreshStructDecode" class="ui-btn-secondary w-full py-1 text-[11px] justify-center">立即重解 VOFA 帧</button>
        </template>

        <template v-else>
          <div class="flex items-center justify-between">
            <span class="font-semibold" style="color: var(--text-primary);">自定义 Struct 结构模板</span>
            <button @click="addStructFieldRow" class="text-[10px] text-sky-500 underline cursor-pointer">+ 字段</button>
          </div>
          <div class="flex items-center gap-1.5">
            <span class="text-[10px] shrink-0" style="color: var(--text-muted);">同步头(HEX):</span>
            <input v-model="structHeaderHex" placeholder="空则全帧匹配 (如 AA 55)" class="ui-input w-full px-1.5 py-0.5 text-[10px] font-mono" />
          </div>
          <div class="max-h-24 overflow-y-auto space-y-1">
            <div v-for="(f, fIdx) in structFields" :key="fIdx" class="grid grid-cols-[54px_48px_34px_38px_16px] gap-1 items-center text-[10px]">
              <input v-model="f.name" placeholder="名" class="ui-input px-1 py-0.5" />
              <select v-model="f.field_type" class="ui-input px-0.5 py-0.5">
                <option value="U8">U8</option>
                <option value="I8">I8</option>
                <option value="U16">U16</option>
                <option value="I16">I16</option>
                <option value="U32">U32</option>
                <option value="I32">I32</option>
                <option value="F32">F32</option>
              </select>
              <input type="number" v-model.number="f.offset" min="0" title="偏移" class="ui-input px-1 py-0.5 ui-num" />
              <input type="number" v-model.number="f.scale" step="0.1" title="比例系数" class="ui-input px-1 py-0.5 ui-num" />
              <button v-if="structFields.length > 1" @click="structFields.splice(fIdx, 1)" class="text-rose-500 cursor-pointer">×</button>
            </div>
          </div>
          <button @click="refreshStructDecode" class="ui-btn-primary w-full py-1 text-[11px] justify-center">解析多通道 Struct 波形</button>
        </template>
      </div>
    </div>

    <!-- 模式 3: 实时 vs 历史黄金波形 / FFT 频谱 / JSONL 归档智能对比 -->
    <div v-else-if="activeMode === 'realtime-vs-history'" class="flex flex-col gap-2.5">
      <!-- 黄金波形基线操作与智能比对栏 -->
      <div class="flex items-center justify-between gap-2 flex-wrap px-2.5 py-2 rounded-xl border bg-[var(--surface-glass-pill)] text-[11px]" style="border-color: var(--border-subtle);">
        <div class="flex items-center gap-2 flex-wrap">
          <span class="font-bold" style="color: var(--text-primary);">目标比对通道:</span>
          <select v-model="selectedWaveSourceKey" class="ui-input px-2 py-0.5 text-[11px] ui-num">
            <option value="__BINARY__">单寄存器波 (Offset {{ binOffset }}, {{ binFloat32 ? 'Float32' : `${binWidth * 8}-bit` }})</option>
            <option v-for="ch in (structDecodeRes?.channels || [])" :key="'st_' + ch.name" :value="`STRUCT:${ch.name}`">
              Struct/VOFA 通道: {{ ch.name }} ({{ ch.samples.length }} 点)
            </option>
            <option v-for="ch in plotterSeries.channels" :key="ch.name" :value="`CH:${ch.name}`">
              文本传感器通道: {{ ch.name }} ({{ ch.samples.length }} 点)
            </option>
          </select>
          <input
            v-model="baselineNameInput"
            placeholder="基线命名 (如: 空载稳态)"
            class="ui-input w-36 px-2 py-0.5 text-[11px]"
          />
          <button
            @click="saveCurrentAsGoldenBaseline"
            :disabled="waveOpBusy || activeChannelSamples.length < 4"
            class="px-2.5 py-0.5 rounded-lg font-semibold border cursor-pointer bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30 hover:bg-amber-500/25 disabled:opacity-45"
            title="将当前选中通道波形（含均值/标准差/主频）原子固化为黄金基线"
          >
            固化黄金基线 ({{ activeChannelSamples.length }} 点)
          </button>
        </div>

        <div class="flex items-center gap-2 flex-wrap">
          <select v-model="selectedBaselineId" class="ui-input w-48 px-2 py-0.5 text-[11px] ui-num">
            <option value="">-- 选择已存黄金波形基线 ({{ waveBaselines.length }}) --</option>
            <option v-for="b in waveBaselines" :key="b.id" :value="b.id">
              {{ b.name }} [{{ b.channel_name }} · {{ b.samples.length }}点]
            </option>
          </select>
          <button
            @click="runSmartWaveformComparison"
            :disabled="waveOpBusy || !selectedBaselineId || activeChannelSamples.length < 4"
            class="ui-btn-primary px-2.5 py-0.5 text-[11px] disabled:opacity-45"
          >
            {{ waveOpBusy ? '比对中...' : '智能对比 (DTW+FFT)' }}
          </button>
          <button
            v-if="selectedBaselineId"
            @click="removeSelectedBaseline"
            :disabled="waveOpBusy"
            class="ui-btn-danger px-2 py-0.5 text-[11px]"
          >
            删除基线
          </button>
        </div>
      </div>

      <div v-if="waveOpMsg" class="text-[11px] ui-num px-2.5 py-1 rounded-lg bg-sky-500/10 text-sky-700 dark:text-sky-300 border border-sky-500/25">
        {{ waveOpMsg }}
      </div>

      <div class="grid grid-cols-1 lg:grid-cols-12 gap-2.5 items-stretch">
        <!-- 左区: 双 ECharts 科研图形 (波形叠加对齐图 + FFT 功率谱密度图) -->
        <div class="lg:col-span-8 flex flex-col gap-2">
          <div class="grid grid-cols-1 md:grid-cols-2 gap-2">
            <!-- ECharts 1: 实时 vs 黄金基线叠加 / 包速率对照 -->
            <div class="ui-sub-card p-2 flex flex-col gap-1">
              <div class="flex items-center justify-between text-[11px]">
                <span class="font-bold" style="color: var(--text-primary);">
                  {{ smartWaveResult ? '1. 实时波形 vs 历史黄金基线叠加' : '1. 实时与历史吞吐率对照 (pkt/s)' }}
                </span>
                <span class="text-[10px] ui-num" style="color: var(--text-muted);">
                  {{ smartWaveResult ? `对齐 ${smartWaveResult.aligned_length} 点` : `实时 ${realtimeBuckets.length}s / 历史 ${historyData?.trend_points.length || 0}s` }}
                </span>
              </div>
              <div class="h-44 w-full relative">
                <VChart
                  v-if="smartWaveResult || realtimeBuckets.length > 0 || (historyData && historyData.trend_points.length > 0)"
                  :option="compareWaveEchartOption"
                  autoresize
                  class="w-full h-full"
                />
                <div v-else class="w-full h-full flex items-center justify-center text-[11px]" style="color: var(--text-muted);">
                  请点击右上「读取 JSONL 历史归档」或监听串口/USB 获取采样波形
                </div>
              </div>
            </div>

            <!-- ECharts 2: Radix-2 FFT 功率谱对比图 -->
            <div class="ui-sub-card p-2 flex flex-col gap-1">
              <div class="flex items-center justify-between text-[11px]">
                <span class="font-bold" style="color: var(--text-primary);">2. Cooley-Tukey FFT 功率谱密度</span>
                <span class="text-[10px] ui-num" style="color: var(--text-muted);">
                  {{ smartWaveResult ? `频谱相似 ${(smartWaveResult.spectral_cosine_similarity * 100).toFixed(1)}%` : 'Hann 窗单边谱' }}
                </span>
              </div>
              <div class="h-44 w-full relative">
                <VChart
                  v-if="(smartWaveResult && smartWaveResult.realtime_fft.length > 0) || realtimeFftBins.length > 0"
                  :option="fftEchartOption"
                  autoresize
                  class="w-full h-full"
                />
                <div v-else class="w-full h-full flex items-center justify-center text-[11px]" style="color: var(--text-muted);">
                  需要至少 4 个传感器或寄存器采样点后计算频谱
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- 右区: DTW + Pearson + RMSE 智能定量评价 & JSONL 归档定量面板 -->
        <div class="lg:col-span-4 ui-sub-card p-2.5 flex flex-col justify-between gap-2 text-[11px] ui-num">
          <template v-if="smartWaveResult">
            <div class="flex items-center justify-between gap-1">
              <span class="font-semibold" style="color: var(--text-primary);">智能波形对齐量化报告</span>
              <span
                :class="['px-1.5 py-0.5 rounded text-[10px] font-bold',
                  smartWaveResult.dtw_similarity_pct >= 80 ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300' :
                  smartWaveResult.dtw_similarity_pct >= 60 ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300' :
                  'bg-rose-500/15 text-rose-700 dark:text-rose-300']"
              >
                DTW {{ smartWaveResult.dtw_similarity_pct.toFixed(1) }}%
              </span>
            </div>
            <div class="text-[10px] px-2 py-1 rounded border bg-[var(--surface-glass-pill)]" style="border-color: var(--border-subtle); color: var(--text-primary);">
              {{ smartWaveResult.health_verdict }}
            </div>
            <div class="grid grid-cols-2 gap-1.5 text-[11px]">
              <div class="p-1.5 rounded-lg border bg-[var(--surface-glass-pill)]" style="border-color: var(--border-subtle);">
                <div class="text-[10px]" style="color: var(--text-muted);">Pearson 相关系数 r</div>
                <div class="font-bold mt-0.5" style="color: var(--text-primary);">{{ smartWaveResult.pearson_r.toFixed(3) }}</div>
              </div>
              <div class="p-1.5 rounded-lg border bg-[var(--surface-glass-pill)]" style="border-color: var(--border-subtle);">
                <div class="text-[10px]" style="color: var(--text-muted);">均方根误差 (RMSE)</div>
                <div class="font-bold mt-0.5 text-amber-600 dark:text-amber-300">{{ smartWaveResult.rmse.toFixed(2) }}</div>
              </div>
              <div class="p-1.5 rounded-lg border bg-[var(--surface-glass-pill)]" style="border-color: var(--border-subtle);">
                <div class="text-[10px]" style="color: var(--text-muted);">超差采样点数</div>
                <div class="font-bold mt-0.5" :class="smartWaveResult.outlier_point_count > 0 ? 'text-rose-600 dark:text-rose-300' : 'text-emerald-600 dark:text-emerald-300'">
                  {{ smartWaveResult.outlier_point_count }} / {{ smartWaveResult.aligned_length }}
                </div>
              </div>
              <div class="p-1.5 rounded-lg border bg-[var(--surface-glass-pill)]" style="border-color: var(--border-subtle);">
                <div class="text-[10px]" style="color: var(--text-muted);">主频迁移 (基→实)</div>
                <div class="font-bold mt-0.5" style="color: var(--text-primary);">
                  {{ smartWaveResult.baseline_dominant_freq.toFixed(3) }} → {{ smartWaveResult.realtime_dominant_freq.toFixed(3) }}
                </div>
              </div>
            </div>
          </template>

          <template v-else>
            <div class="flex items-center justify-between">
              <span class="font-semibold" style="color: var(--text-primary);">实时 vs 历史归档流量比对</span>
              <span
                v-if="historyData && historyData.matched_packets > 0"
                :class="['px-1.5 py-0.5 rounded text-[10px] font-bold', deltaRatePct >= 0 ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300' : 'bg-rose-500/15 text-rose-700 dark:text-rose-300']"
              >
                吞吐偏差 {{ deltaRatePct >= 0 ? '+' : '' }}{{ deltaRatePct.toFixed(1) }}%
              </span>
            </div>
            <div class="grid grid-cols-2 gap-1.5 text-[11px]">
              <div class="p-1.5 rounded-lg border bg-[var(--surface-glass-pill)]" style="border-color: var(--border-subtle);">
                <div class="text-[10px]" style="color: var(--text-muted);">实时 / 历史包长</div>
                <div class="font-bold mt-0.5" style="color: var(--text-primary);">{{ realtimeAvgLen.toFixed(1) }} / {{ (historyData?.avg_packet_size || 0).toFixed(1) }} B</div>
              </div>
              <div class="p-1.5 rounded-lg border bg-[var(--surface-glass-pill)]" style="border-color: var(--border-subtle);">
                <div class="text-[10px]" style="color: var(--text-muted);">实时 / 历史信息熵</div>
                <div class="font-bold mt-0.5" style="color: var(--text-primary);">
                  {{ realtimeAvgEntropy.toFixed(2) }} / <span class="text-amber-600 dark:text-amber-300">{{ (historyData?.avg_entropy || 0).toFixed(2) }}</span>
                </div>
              </div>
              <div class="p-1.5 rounded-lg border bg-[var(--surface-glass-pill)]" style="border-color: var(--border-subtle);">
                <div class="text-[10px]" style="color: var(--text-muted);">历史命中 / 损坏行</div>
                <div class="font-bold mt-0.5" style="color: var(--text-primary);">
                  {{ historyData?.matched_packets || 0 }} / <span class="text-rose-500">{{ historyData?.corrupted_lines || 0 }}</span>
                </div>
              </div>
              <div class="p-1.5 rounded-lg border bg-[var(--surface-glass-pill)]" style="border-color: var(--border-subtle);">
                <div class="text-[10px]" style="color: var(--text-muted);">已存黄金基线数</div>
                <div class="font-bold mt-0.5 text-sky-600 dark:text-sky-300">{{ waveBaselines.length }} 组</div>
              </div>
            </div>
            <div class="text-[10px] truncate" style="color: var(--text-muted);" v-if="historyData?.diagnostic_message">
              {{ historyData.diagnostic_message }}
            </div>
          </template>

          <!-- 控制工程 PID 闭环阶跃响应瞬态特性测算区 -->
          <div class="pt-2 border-t space-y-1.5" style="border-color: var(--border-subtle);">
            <div class="flex items-center justify-between gap-1 text-[10px]">
              <span class="font-bold" style="color: var(--text-primary);">PID 阶跃响应瞬态分析:</span>
              <div class="flex items-center gap-1">
                <input type="number" v-model.number="stepSetpoint" step="0.5" title="目标稳态设定值" class="ui-input w-14 px-1 py-0.5 text-[10px] ui-num" />
                <input type="number" v-model.number="stepDtMs" min="0.1" step="1" title="采样周期 (ms)" class="ui-input w-12 px-1 py-0.5 text-[10px] ui-num" />
                <button @click="runStepResponseEval" :disabled="activeChannelSamples.length < 4" class="px-2 py-0.5 rounded bg-indigo-500/15 text-indigo-700 dark:text-indigo-300 border border-indigo-500/30 font-semibold cursor-pointer disabled:opacity-45">
                  测算
                </button>
              </div>
            </div>
            <div v-if="stepResult" class="text-[10px] ui-num p-1.5 rounded border bg-[var(--surface-glass-pill)]" style="border-color: var(--border-subtle); color: var(--text-secondary);">
              {{ stepResult.summary }}
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- 模式 4: IEEE 1364 VCD 逻辑分析仪物理采样方波解调 -->
    <div v-else-if="activeMode === 'vcd-logic'" class="grid grid-cols-1 lg:grid-cols-12 gap-2.5 items-stretch">
      <div class="lg:col-span-9 flex flex-col gap-1.5">
        <div class="relative rounded-xl border overflow-hidden h-44" style="border-color: var(--border-subtle); background: rgba(15, 23, 42, 0.92);">
          <canvas ref="vcdCanvasRef" class="w-full h-full block"></canvas>
          <div v-if="!vcdResult" class="absolute inset-0 flex flex-col items-center justify-center text-center px-4">
            <span class="text-xs font-semibold text-slate-300">逻辑分析仪 .vcd 数字电平采集视图就绪</span>
            <span class="text-[11px] text-slate-400 mt-1">支持从 Saleae / PulseView 导出的 IEEE 1364 .vcd 波形文件导入并还原 UART 字节流</span>
          </div>
        </div>
        <div v-if="vcdMultiSummary" class="text-[11px] ui-num px-2 py-1 rounded border border-indigo-500/30 bg-indigo-500/10 text-indigo-700 dark:text-indigo-300">
          {{ vcdMultiSummary }}
        </div>
        <div v-if="vcdResult" class="flex items-center justify-between text-[11px] ui-num flex-wrap gap-2" style="color: var(--text-muted);">
          <span class="truncate max-w-lg" style="color: var(--text-primary);" :title="`HEX: ${vcdResult.decoded_hex}`">
            解码文本: <code class="font-mono text-emerald-600 dark:text-emerald-300">{{ vcdResult.decoded_text || '(无有效字符)' }}</code>
            <span v-if="vcdResult.decoded_hex" class="ml-2 text-[10px]" style="color: var(--text-muted);">[HEX: {{ vcdResult.decoded_hex.slice(0, 32) }}{{ vcdResult.decoded_hex.length > 32 ? '...' : '' }}]</span>
          </span>
          <span>
            精度: <strong class="text-sky-500">{{ vcdResult.detected_timescale }}</strong> |
            跳变点: {{ vcdResult.transitions.length }} | 总时长: {{ vcdResult.total_sample_duration_us }} us | 帧错误:
            <strong :class="vcdResult.framing_errors > 0 ? 'text-rose-500' : 'text-emerald-500'">{{ vcdResult.framing_errors }}</strong> |
            校验错: <strong :class="vcdResult.parity_errors > 0 ? 'text-rose-500' : 'text-emerald-500'">{{ vcdResult.parity_errors }}</strong> |
            毛刺: <strong :class="vcdResult.glitch_count > 0 ? 'text-amber-500' : 'text-emerald-500'">{{ vcdResult.glitch_count }}</strong>
          </span>
        </div>
      </div>

      <div class="lg:col-span-3 ui-sub-card p-2.5 flex flex-col justify-between gap-2 text-[11px]">
        <div class="flex items-center justify-between">
          <span class="font-semibold" style="color: var(--text-primary);">VCD 方波参数配置</span>
          <span v-if="lastVcdFileName" class="text-[10px] truncate max-w-[110px] ui-num" style="color: var(--text-muted);" :title="lastVcdFileName">{{ lastVcdFileName }}</span>
        </div>
        <div class="space-y-1.5">
          <div class="grid grid-cols-2 gap-1.5">
            <div>
              <label class="text-[10px] block mb-0.5" style="color: var(--text-muted);">协议解调模式</label>
              <select v-model="vcdBusMode" @change="redecodeCachedVcd" class="ui-input w-full px-1.5 py-0.5 text-[11px] font-semibold">
                <option value="UART">UART</option>
                <option value="I2C">I2C (双线)</option>
                <option value="SPI">SPI (三线)</option>
                <option value="CAN">CAN (位填充)</option>
              </select>
            </div>
            <div>
              <label class="text-[10px] block mb-0.5" style="color: var(--text-muted);">主通道 ($var)</label>
              <select
                v-if="vcdResult && vcdResult.available_signals.length > 0"
                v-model="vcdSignalName"
                @change="redecodeCachedVcd"
                class="ui-input w-full px-1.5 py-0.5 text-[11px] font-mono"
              >
                <option v-for="sig in vcdResult.available_signals" :key="sig" :value="sig">{{ sig }}</option>
              </select>
              <input v-else v-model="vcdSignalName" type="text" placeholder="如 TX / SCL" class="ui-input w-full px-1.5 py-0.5 text-[11px] font-mono" />
            </div>
          </div>
          <div class="grid grid-cols-2 gap-1.5">
            <div>
              <label class="text-[10px] block mb-0.5" style="color: var(--text-muted);">波特率 (bps)</label>
              <select v-model.number="vcdBaudRate" @change="redecodeCachedVcd" class="ui-input w-full px-1.5 py-0.5 text-[11px] ui-num">
                <option :value="9600">9600 bps</option>
                <option :value="19200">19200 bps</option>
                <option :value="38400">38400 bps</option>
                <option :value="57600">57600 bps</option>
                <option :value="115200">115200 bps</option>
                <option :value="921600">921600 bps</option>
              </select>
            </div>
            <div>
              <label class="text-[10px] block mb-0.5" style="color: var(--text-muted);">奇偶校验</label>
              <select v-model="vcdParity" @change="redecodeCachedVcd" class="ui-input w-full px-1.5 py-0.5 text-[11px]">
                <option value="NONE">无 (N)</option>
                <option value="EVEN">偶校验 (E)</option>
                <option value="ODD">奇校验 (O)</option>
              </select>
            </div>
          </div>
        </div>
        <div v-if="vcdError" class="text-[10px] text-rose-500 break-all">{{ vcdError }}</div>
        <label class="ui-btn-primary w-full py-1.5 text-[11px] justify-center cursor-pointer text-center">
          <span>导入 .vcd 文件解码方波</span>
          <input type="file" accept=".vcd,.txt" class="hidden" @change="onSelectVcdFile" />
        </label>
      </div>
    </div>
  </section>
</template>

<script setup lang="ts">
import { ref, computed, watch, nextTick, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import { use } from 'echarts/core';
import { CanvasRenderer } from 'echarts/renderers';
import { LineChart, BarChart } from 'echarts/charts';
import { GridComponent, TooltipComponent, LegendComponent, DataZoomComponent } from 'echarts/components';
import VChart from 'vue-echarts';
import AppIcon from './AppIcon.vue';

use([CanvasRenderer, LineChart, BarChart, GridComponent, TooltipComponent, LegendComponent, DataZoomComponent]);

export interface OscilloscopePacketItem {
  id: number;
  timestamp: string;
  direction?: string;
  transport: string;
  protocol: string;
  src_ip: string;
  dst_ip: string;
  length: number;
  payload_hex: string;
  raw_frame_hex?: string;
  entropy: number;
  raw_text?: string;
}

const props = defineProps<{
  packets: OscilloscopePacketItem[];
  selectedSerialPort?: string;
}>();

const emit = defineEmits<{
  (e: 'waveCompared', result: SmartWaveformComparisonResult): void;
}>();

type ScopeMode = 'serial-plotter' | 'binary-scope' | 'realtime-vs-history' | 'vcd-logic';

const scopeModes: Array<{ id: ScopeMode; label: string }> = [
  { id: 'serial-plotter', label: '多通道传感曲线' },
  { id: 'binary-scope', label: '寄存器示波' },
  { id: 'realtime-vs-history', label: '实时 vs 历史对照' },
  { id: 'vcd-logic', label: 'VCD 数字方波' },
];

const rootRef = ref<HTMLElement | null>(null);
const activeMode = ref<ScopeMode>('serial-plotter');
const busScope = ref<'ALL' | 'SERIAL' | 'USB'>('ALL');
const filterByCurrentPort = ref(false);
const isPaused = ref(false);

const plotterCanvasRef = ref<HTMLCanvasElement | null>(null);
const binaryCanvasRef = ref<HTMLCanvasElement | null>(null);
const compareCanvasRef = ref<HTMLCanvasElement | null>(null);
const vcdCanvasRef = ref<HTMLCanvasElement | null>(null);

const hiddenChannels = ref<Set<string>>(new Set());

// 二进制解调配置
const binOffset = ref(0);
const binWidth = ref<1 | 2 | 4>(2);
const binLittleEndian = ref(true);
const binSigned = ref(false);
const binFloat32 = ref(false);
const binaryDecodeMode = ref<'single' | 'justfloat' | 'struct'>('single');

interface BinaryStructField {
  name: string;
  field_type: string;
  little_endian: boolean;
  offset: number;
  scale: number;
  bias: number;
}

interface DecodedStructChannel {
  name: string;
  samples: number[];
  latest: number;
  min: number;
  max: number;
  avg: number;
}

interface StructBatchDecodeResult {
  decoded_frame_count: number;
  skipped_frame_count: number;
  mode_used: string;
  channels: DecodedStructChannel[];
}

interface StepResponseMetrics {
  sample_count: number;
  overshoot_pct: number;
  rise_time_ms: number | null;
  settling_time_ms: number | null;
  steady_state_error: number;
  summary: string;
}

const structHeaderHex = ref('AA 55');
const structFields = ref<BinaryStructField[]>([
  { name: 'TempC', field_type: 'F32', little_endian: true, offset: 2, scale: 1.0, bias: 0.0 },
  { name: 'Rpm', field_type: 'I16', little_endian: true, offset: 6, scale: 0.1, bias: 0.0 },
]);
const structDecodeRes = ref<StructBatchDecodeResult | null>(null);
const stepSetpoint = ref(100);
const stepDtMs = ref(10);
const stepResult = ref<StepResponseMetrics | null>(null);

// 历史档案状态
interface HistoricalTrendPoint {
  bucket_label: string;
  packet_count: number;
  byte_count: number;
  packets_per_sec: number;
  bytes_per_sec: number;
}

interface HistoricalBusArchiveResult {
  bus_filter: string;
  source_filter: string | null;
  scanned_files: string[];
  total_lines_scanned: number;
  matched_packets: number;
  matched_bytes: number;
  avg_packet_size: number;
  avg_entropy: number;
  avg_packets_per_sec: number;
  peak_bytes_per_sec: number;
  corrupted_lines: number;
  protocol_breakdown: Record<string, number>;
  trend_points: HistoricalTrendPoint[];
  diagnostic_message: string;
}

const historyData = ref<HistoricalBusArchiveResult | null>(null);
const historyLoading = ref(false);

interface FftBin {
  bin_index: number;
  normalized_freq: number;
  magnitude: number;
}

interface WaveformBaselineSnapshot {
  id: string;
  name: string;
  bus_type: string;
  source_port: string;
  channel_name: string;
  sample_rate_hz: number;
  saved_at: string;
  samples: number[];
  mean: number;
  stddev: number;
  min_val: number;
  max_val: number;
  dominant_fft_ratio: number;
}

export interface SmartWaveformComparisonResult {
  baseline_id: string;
  baseline_name: string;
  channel_name: string;
  sample_count_baseline: number;
  sample_count_realtime: number;
  aligned_length: number;
  pearson_r: number;
  rmse: number;
  mae: number;
  max_deviation: number;
  dtw_distance: number;
  dtw_similarity_pct: number;
  spectral_cosine_similarity: number;
  baseline_dominant_freq: number;
  realtime_dominant_freq: number;
  outlier_point_count: number;
  health_verdict: string;
  diagnostic_summary: string;
  aligned_baseline: number[];
  aligned_realtime: number[];
  pointwise_error: number[];
  baseline_fft: FftBin[];
  realtime_fft: FftBin[];
}

const isDarkTheme = ref(
  typeof document !== 'undefined' ? !document.documentElement.classList.contains('theme-apple-light') : true
);
const selectedWaveSourceKey = ref('__BINARY__');
const baselineNameInput = ref('');
const waveBaselines = ref<WaveformBaselineSnapshot[]>([]);
const selectedBaselineId = ref('');
const smartWaveResult = ref<SmartWaveformComparisonResult | null>(null);
const realtimeFftBins = ref<FftBin[]>([]);
const waveOpBusy = ref(false);
const waveOpMsg = ref('');

// VCD 状态
interface VcdTransition {
  timestamp_us: number;
  level: number;
}

interface VcdUartDecodedResult {
  decoded_bytes: number[];
  decoded_text: string;
  decoded_hex: string;
  total_sample_duration_us: number;
  detected_baud_rate: number;
  detected_timescale: string;
  matched_signal: string;
  available_signals: string[];
  framing_errors: number;
  parity_errors: number;
  glitch_count: number;
  transitions: VcdTransition[];
}

const vcdBusMode = ref<'UART' | 'I2C' | 'SPI' | 'CAN'>('UART');
const vcdMultiSummary = ref('');
const vcdSignalName = ref('TX');
const vcdBaudRate = ref(115200);
const vcdParity = ref<'NONE' | 'EVEN' | 'ODD'>('NONE');
const vcdResult = ref<VcdUartDecodedResult | null>(null);
const vcdError = ref('');
const lastVcdContent = ref('');
const lastVcdFileName = ref('');

const PALETTE = ['#38bdf8', '#34d399', '#fbbf24', '#f472b6', '#a78bfa', '#fb7185'];
function channelColor(idx: number): string {
  return PALETTE[idx % PALETTE.length];
}

function toggleChannelVisibility(name: string) {
  const next = new Set(hiddenChannels.value);
  if (next.has(name)) next.delete(name);
  else next.add(name);
  hiddenChannels.value = next;
}

function isSerialRecord(p: OscilloscopePacketItem): boolean {
  const t = (p.transport || '').toUpperCase();
  const dir = (p.direction || '').toUpperCase();
  const proto = (p.protocol || '').toUpperCase();
  const src = (p.src_ip || '').toUpperCase();
  const dst = (p.dst_ip || '').toUpperCase();
  return (
    t === 'SERIAL' ||
    dir.startsWith('SERIAL') ||
    proto.includes('UART') ||
    proto.includes('MODBUS-RTU') ||
    proto === 'MODBUS_RTU' ||
    proto === 'DL/T 645' ||
    proto === 'NMEA-0183' ||
    src.startsWith('COM') ||
    dst.startsWith('COM')
  );
}

function isUsbRecord(p: OscilloscopePacketItem): boolean {
  const t = (p.transport || '').toUpperCase();
  const dir = (p.direction || '').toUpperCase();
  const proto = (p.protocol || '').toUpperCase();
  const src = (p.src_ip || '').toUpperCase();
  return t === 'USB' || dir.startsWith('USB') || proto.startsWith('USB') || src.startsWith('USB');
}

function isAnyPhysicalBus(p: OscilloscopePacketItem): boolean {
  return isSerialRecord(p) || isUsbRecord(p);
}

function matchesScope(p: OscilloscopePacketItem): boolean {
  if (busScope.value === 'SERIAL') return isSerialRecord(p);
  if (busScope.value === 'USB') return isUsbRecord(p);
  return isAnyPhysicalBus(p);
}

// 先过滤物理总线再保留近 600 帧：彻底避免开启网卡抓包时把 COM/USB 数据冲刷出窗
const snapshotPackets = ref<OscilloscopePacketItem[]>([]);
watch(
  () => props.packets,
  (list) => {
    if (!isPaused.value) {
      snapshotPackets.value = list.filter(isAnyPhysicalBus).slice(-600);
    }
  },
  { immediate: true }
);

const filteredPackets = computed(() => snapshotPackets.value.filter(matchesScope));

function decodePrintableHexFallback(hexStr: string): string {
  const bytes = parseHexBytes(hexStr);
  if (bytes.length === 0) return '';
  let out = '';
  let printableCount = 0;
  for (const b of bytes) {
    if ((b >= 32 && b <= 126) || b === 9 || b === 10 || b === 13) {
      out += String.fromCharCode(b);
      printableCount++;
    }
  }
  return printableCount / bytes.length >= 0.7 ? out : '';
}

function extractCleanSensorText(pkt: OscilloscopePacketItem): string {
  const raw = (pkt.raw_text || '').trim();
  if (raw === '[EMPTY PAYLOAD - 0 BYTES]') return '';
  if (raw.startsWith('[ASCII] ')) {
    const hexSep = raw.indexOf(' | [HEX] ');
    const stripped = hexSep >= 0 ? raw.slice(8, hexSep) : raw.slice(8);
    return stripped.trim();
  }
  if (raw.length > 0) return raw;
  return decodePrintableHexFallback(pkt.payload_hex);
}

/**
 * 解析嵌入式文本传感器帧 (逐行剥离前缀与单位后缀，支持多行粘包切分)
 * 复杂度: O(N * L * K), N <= 600, K <= 6 通道
 */
const plotterSeries = computed(() => {
  const map = new Map<string, number[]>();
  const rows = filteredPackets.value.slice(-180);
  let pointCount = 0;

  for (const pkt of rows) {
    const text = extractCleanSensorText(pkt);
    if (!text) continue;

    const lines = text.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    for (const rawLine of lines) {
      // 剥离可选前导时间戳，如 "[12:00:01] temp:25.4" -> "temp:25.4"
      const line = rawLine.replace(/^\[\d{2}:\d{2}:\d{2}(?:\.\d+)?\]\s*/, '');
      const kvMatches = [...line.matchAll(/([A-Za-z_][A-Za-z0-9_]{0,15})\s*[:=]\s*(-?\d+(?:\.\d+)?)/g)];
      if (kvMatches.length > 0) {
        pointCount++;
        for (const m of kvMatches.slice(0, 6)) {
          const key = m[1];
          const val = Number(m[2]);
          if (Number.isFinite(val)) {
            if (!map.has(key)) map.set(key, []);
            map.get(key)!.push(val);
          }
        }
        continue;
      }

      const csvTokens = line
        .split(/[\s,;]+/)
        .map(s => s.trim())
        .filter(s => /^-?\d+(?:\.\d+)?$/.test(s));
      if (csvTokens.length >= 1 && csvTokens.length <= 6) {
        pointCount++;
        csvTokens.forEach((tok, idx) => {
          const key = `CH${idx}`;
          const val = Number(tok);
          if (Number.isFinite(val)) {
            if (!map.has(key)) map.set(key, []);
            map.get(key)!.push(val);
          }
        });
      }
    }
  }

  const channels = Array.from(map.entries())
    .slice(0, 6)
    .map(([name, rawSamples]) => {
      const samples = rawSamples.slice(-240);
      let min = Infinity;
      let max = -Infinity;
      let sum = 0;
      for (const v of samples) {
        if (v < min) min = v;
        if (v > max) max = v;
        sum += v;
      }
      return {
        name,
        samples,
        latest: samples[samples.length - 1] ?? 0,
        min: Number.isFinite(min) ? min : 0,
        max: Number.isFinite(max) ? max : 0,
        avg: samples.length > 0 ? sum / samples.length : 0,
      };
    });

  return { channels, pointCount };
});

function parseHexBytes(hexStr: string): number[] {
  const clean = (hexStr || '').replace(/\s+/g, '');
  const out: number[] = [];
  for (let i = 0; i + 1 < clean.length; i += 2) {
    const b = parseInt(clean.slice(i, i + 2), 16);
    if (!Number.isNaN(b)) out.push(b);
  }
  return out;
}

const binarySeries = computed(() => {
  const offset = Math.max(0, Math.floor(binOffset.value || 0));
  const width = binFloat32.value ? 4 : binWidth.value;
  const out: number[] = [];

  for (const pkt of filteredPackets.value.slice(-180)) {
    const bytes = parseHexBytes(pkt.payload_hex || pkt.raw_frame_hex || '');
    if (offset + width > bytes.length) continue;
    const slice = bytes.slice(offset, offset + width);
    if (binFloat32.value) {
      const buf = new ArrayBuffer(4);
      const u8 = new Uint8Array(buf);
      slice.forEach((b, idx) => { u8[idx] = b; });
      const val = new DataView(buf).getFloat32(0, binLittleEndian.value);
      if (Number.isFinite(val)) out.push(Number(val.toFixed(4)));
      continue;
    }
    let raw = 0;
    if (binLittleEndian.value) {
      for (let i = width - 1; i >= 0; i--) {
        raw = (raw * 256) + slice[i];
      }
    } else {
      for (let i = 0; i < width; i++) {
        raw = (raw * 256) + slice[i];
      }
    }
    if (binSigned.value) {
      const signBit = Math.pow(2, width * 8 - 1);
      const mod = signBit * 2;
      if (raw >= signBit) raw -= mod;
    }
    out.push(raw);
  }
  return out;
});

const binaryStats = computed(() => {
  const arr = binarySeries.value;
  if (arr.length === 0) return { min: 0, max: 0, avg: 0, vpp: 0 };
  let min = Infinity;
  let max = -Infinity;
  let sum = 0;
  for (const v of arr) {
    if (v < min) min = v;
    if (v > max) max = v;
    sum += v;
  }
  return { min, max, avg: sum / arr.length, vpp: max - min };
});

function extractHhmmssKey(tsRaw: string): string {
  const t = (tsRaw || '').trim();
  const tIdx = t.indexOf('T');
  if (tIdx >= 0 && t.length >= tIdx + 9) {
    return t.slice(tIdx + 1, tIdx + 9);
  }
  if (/^\d{2}:\d{2}:\d{2}/.test(t)) {
    return t.slice(0, 8);
  }
  return t.slice(0, 8) || '00:00:00';
}

// 实时按秒聚合统计
const realtimeBuckets = computed(() => {
  const buckets = new Map<string, { count: number; bytes: number }>();
  for (const p of filteredPackets.value) {
    const sec = extractHhmmssKey(p.timestamp);
    const cur = buckets.get(sec) || { count: 0, bytes: 0 };
    cur.count += 1;
    cur.bytes += p.length || 0;
    buckets.set(sec, cur);
  }
  return Array.from(buckets.entries())
    .slice(-60)
    .map(([label, v]) => ({ label, count: v.count, bytes: v.bytes }));
});

const realtimeAvgPps = computed(() => {
  if (realtimeBuckets.value.length === 0) return 0;
  const total = realtimeBuckets.value.reduce((acc, b) => acc + b.count, 0);
  return total / realtimeBuckets.value.length;
});

const realtimeAvgLen = computed(() => {
  if (filteredPackets.value.length === 0) return 0;
  const sum = filteredPackets.value.reduce((acc, p) => acc + (p.length || 0), 0);
  return sum / filteredPackets.value.length;
});

const realtimeAvgEntropy = computed(() => {
  if (filteredPackets.value.length === 0) return 0;
  const sum = filteredPackets.value.reduce((acc, p) => acc + (p.entropy || 0), 0);
  return sum / filteredPackets.value.length;
});

const deltaRatePct = computed(() => {
  const hist = historyData.value?.avg_packets_per_sec || 0;
  if (hist <= 0) return 0;
  return ((realtimeAvgPps.value - hist) / hist) * 100;
});

async function fetchHistoricalBaseline() {
  historyLoading.value = true;
  try {
    // 全部物理总线模式明确传 PHYSICAL，严格隔离串口与 USB，不掺杂常规网卡包也不强绑 COM1
    const busFilter = busScope.value === 'ALL' ? 'PHYSICAL' : busScope.value;
    const sourceFilter =
      busScope.value === 'SERIAL' && filterByCurrentPort.value && props.selectedSerialPort
        ? props.selectedSerialPort
        : null;
    historyData.value = await invoke<HistoricalBusArchiveResult>('query_historical_bus_archive_cmd', {
      busFilter,
      sourceFilter,
      limit: 200,
    });
  } catch (e) {
    console.error('读取历史归档失败:', e);
  } finally {
    historyLoading.value = false;
    nextTick(drawCompareChart);
  }
}

const activeChannelSamples = computed<number[]>(() => {
  if (selectedWaveSourceKey.value.startsWith('STRUCT:')) {
    const targetName = selectedWaveSourceKey.value.slice(7);
    const ch = structDecodeRes.value?.channels.find(c => c.name === targetName);
    if (ch) return ch.samples;
  }
  if (selectedWaveSourceKey.value.startsWith('CH:')) {
    const targetName = selectedWaveSourceKey.value.slice(3);
    const ch = plotterSeries.value.channels.find(c => c.name === targetName);
    if (ch) return ch.samples;
  }
  if (binarySeries.value.length >= 4) return binarySeries.value;
  return plotterSeries.value.channels[0]?.samples || binarySeries.value;
});

const activeChannelLabel = computed(() => {
  if (selectedWaveSourceKey.value.startsWith('STRUCT:')) {
    return selectedWaveSourceKey.value.slice(7);
  }
  if (selectedWaveSourceKey.value.startsWith('CH:')) {
    return selectedWaveSourceKey.value.slice(3);
  }
  return `REG_OFFSET_${binOffset.value}_${binFloat32.value ? 'F32' : `${binWidth.value * 8}BIT`}`;
});

function addStructFieldRow() {
  if (structFields.value.length >= 8) return;
  const nextOff = structFields.value.reduce((acc, f) => Math.max(acc, f.offset + 2), 0);
  structFields.value.push({
    name: `CH${structFields.value.length}`,
    field_type: 'I16',
    little_endian: true,
    offset: nextOff,
    scale: 1.0,
    bias: 0.0,
  });
}

async function refreshStructDecode() {
  if (binaryDecodeMode.value === 'single') return;
  const payloadsHex = filteredPackets.value
    .slice(-180)
    .map(p => p.payload_hex || p.raw_frame_hex || '')
    .filter(Boolean);
  if (payloadsHex.length === 0) {
    structDecodeRes.value = null;
    return;
  }
  try {
    structDecodeRes.value = await invoke<StructBatchDecodeResult>('parse_binary_struct_batch_cmd', {
      payloadsHex,
      headerHex: structHeaderHex.value,
      fields: structFields.value,
      parseJustfloat: binaryDecodeMode.value === 'justfloat',
    });
  } catch (e) {
    console.error('Struct/VOFA 解构失败:', e);
  }
}

async function runStepResponseEval() {
  const samples = activeChannelSamples.value;
  if (samples.length < 4) return;
  try {
    stepResult.value = await invoke<StepResponseMetrics>('compute_step_response_metrics_cmd', {
      samples,
      targetSetpoint: stepSetpoint.value,
      dtMs: stepDtMs.value || 10,
      tolerancePct: 2.0,
    });
  } catch (e) {
    waveOpMsg.value = `阶跃响应测算受阻: ${String(e)}`;
  }
}

const binaryStructEchartOption = computed(() => {
  const dark = isDarkTheme.value;
  const textPrimary = dark ? '#e2e8f0' : '#0f172a';
  const textMuted = dark ? '#94a3b8' : '#64748b';
  const splitLine = dark ? 'rgba(148,163,184,0.14)' : 'rgba(15,23,42,0.1)';
  const tooltipBg = dark ? 'rgba(15,23,42,0.94)' : 'rgba(255,255,255,0.96)';

  const chs = structDecodeRes.value?.channels || [];
  const maxLen = chs.reduce((acc, c) => Math.max(acc, c.samples.length), 0);
  const xLabels = Array.from({ length: maxLen }, (_, i) => `#${i + 1}`);
  return {
    backgroundColor: 'transparent',
    tooltip: { trigger: 'axis', backgroundColor: tooltipBg, textStyle: { color: textPrimary, fontSize: 11 } },
    legend: { top: 0, textStyle: { color: textMuted, fontSize: 10 } },
    grid: { left: 42, right: 12, top: 26, bottom: 22 },
    dataZoom: [{ type: 'inside', xAxisIndex: 0 }],
    xAxis: { type: 'category', data: xLabels, axisLabel: { color: textMuted, fontSize: 9 }, axisLine: { lineStyle: { color: splitLine } } },
    yAxis: { type: 'value', axisLabel: { color: textMuted, fontSize: 9 }, splitLine: { lineStyle: { color: splitLine, type: 'dashed' } } },
    series: chs.map((c, idx) => ({
      name: c.name,
      type: 'line',
      smooth: true,
      showSymbol: false,
      data: c.samples,
      lineStyle: { width: 2, color: channelColor(idx) },
      itemStyle: { color: channelColor(idx) },
    })),
  };
});

async function refreshWaveBaselines() {
  try {
    const list = await invoke<WaveformBaselineSnapshot[]>('list_waveform_baselines_cmd');
    waveBaselines.value = list;
    if (!selectedBaselineId.value && list.length > 0) {
      selectedBaselineId.value = list[0].id;
    }
  } catch (e) {
    console.error('加载黄金波形基线列表失败:', e);
  }
}

async function computeLiveFft() {
  const arr = activeChannelSamples.value;
  if (arr.length < 4) {
    realtimeFftBins.value = [];
    return;
  }
  try {
    realtimeFftBins.value = await invoke<FftBin[]>('compute_waveform_fft_cmd', { samples: arr });
  } catch (e) {
    console.error('FFT 计算异常:', e);
  }
}

async function saveCurrentAsGoldenBaseline() {
  const samples = activeChannelSamples.value;
  if (samples.length < 4) {
    waveOpMsg.value = '当前通道采样点数不足 4 点，无法建立基线';
    return;
  }
  waveOpBusy.value = true;
  try {
    const saved = await invoke<WaveformBaselineSnapshot>('save_waveform_baseline_cmd', {
      name: baselineNameInput.value.trim() || `${activeChannelLabel.value} 黄金标准`,
      busType: busScope.value,
      sourcePort: props.selectedSerialPort || busScope.value,
      channelName: activeChannelLabel.value,
      sampleRateHz: 100.0,
      samples,
    });
    waveOpMsg.value = `已固化黄金波形基线: ${saved.name} (${saved.samples.length} 点, μ=${saved.mean.toFixed(2)}, σ=${saved.stddev.toFixed(2)})`;
    baselineNameInput.value = '';
    await refreshWaveBaselines();
    selectedBaselineId.value = saved.id;
    await runSmartWaveformComparison();
  } catch (e) {
    waveOpMsg.value = `保存黄金基线失败: ${String(e)}`;
  } finally {
    waveOpBusy.value = false;
  }
}

async function runSmartWaveformComparison() {
  if (!selectedBaselineId.value) return;
  const samples = activeChannelSamples.value;
  if (samples.length < 4) {
    waveOpMsg.value = '当前实时样本不足 4 点，请先采集物理波形';
    return;
  }
  waveOpBusy.value = true;
  try {
    const res = await invoke<SmartWaveformComparisonResult>('smart_compare_waveforms_cmd', {
      baselineId: selectedBaselineId.value,
      realtimeSamples: samples,
      channelName: activeChannelLabel.value,
    });
    smartWaveResult.value = res;
    waveOpMsg.value = res.diagnostic_summary;
    emit('waveCompared', res);
  } catch (e) {
    waveOpMsg.value = `智能比对失败: ${String(e)}`;
  } finally {
    waveOpBusy.value = false;
  }
}

async function removeSelectedBaseline() {
  if (!selectedBaselineId.value) return;
  waveOpBusy.value = true;
  try {
    await invoke('delete_waveform_baseline_cmd', { baselineId: selectedBaselineId.value });
    selectedBaselineId.value = '';
    smartWaveResult.value = null;
    waveOpMsg.value = '已删除选定黄金基线';
    await refreshWaveBaselines();
  } catch (e) {
    waveOpMsg.value = `删除基线失败: ${String(e)}`;
  } finally {
    waveOpBusy.value = false;
  }
}

const compareWaveEchartOption = computed(() => {
  const dark = isDarkTheme.value;
  const textPrimary = dark ? '#e2e8f0' : '#0f172a';
  const textMuted = dark ? '#94a3b8' : '#64748b';
  const splitLine = dark ? 'rgba(148,163,184,0.14)' : 'rgba(15,23,42,0.1)';
  const tooltipBg = dark ? 'rgba(15,23,42,0.94)' : 'rgba(255,255,255,0.96)';

  const wf = smartWaveResult.value;
  if (wf) {
    const idxLabels = wf.aligned_realtime.map((_, i) => `#${i + 1}`);
    return {
      backgroundColor: 'transparent',
      tooltip: { trigger: 'axis', backgroundColor: tooltipBg, textStyle: { color: textPrimary, fontSize: 11 } },
      legend: { top: 0, textStyle: { color: textMuted, fontSize: 10 } },
      grid: { left: 42, right: 14, top: 26, bottom: 26 },
      dataZoom: [{ type: 'inside', xAxisIndex: 0 }],
      xAxis: { type: 'category', data: idxLabels, axisLabel: { color: textMuted, fontSize: 9 }, axisLine: { lineStyle: { color: splitLine } } },
      yAxis: { type: 'value', axisLabel: { color: textMuted, fontSize: 9 }, splitLine: { lineStyle: { color: splitLine, type: 'dashed' } } },
      series: [
        {
          name: '实时序列',
          type: 'line',
          smooth: true,
          showSymbol: false,
          data: wf.aligned_realtime,
          lineStyle: { width: 2, color: '#38bdf8' },
          itemStyle: { color: '#38bdf8' },
        },
        {
          name: `黄金基线 (${wf.baseline_name})`,
          type: 'line',
          smooth: true,
          showSymbol: false,
          data: wf.aligned_baseline,
          lineStyle: { width: 2, type: 'dashed', color: '#f59e0b' },
          itemStyle: { color: '#f59e0b' },
        },
        {
          name: '逐点残差',
          type: 'bar',
          data: wf.pointwise_error,
          itemStyle: { color: 'rgba(244, 63, 94, 0.35)' },
        },
      ],
    };
  }

  const rt = realtimeBuckets.value;
  const hist = historyData.value?.trend_points || [];
  const maxLen = Math.max(rt.length, hist.length);
  const xLabels = Array.from({ length: maxLen }, (_, i) => rt[i]?.label || hist[i]?.bucket_label || `T${i}`);
  return {
    backgroundColor: 'transparent',
    tooltip: { trigger: 'axis', backgroundColor: tooltipBg, textStyle: { color: textPrimary, fontSize: 11 } },
    legend: { top: 0, textStyle: { color: textMuted, fontSize: 10 } },
    grid: { left: 38, right: 12, top: 26, bottom: 24 },
    xAxis: { type: 'category', data: xLabels, axisLabel: { color: textMuted, fontSize: 9 }, axisLine: { lineStyle: { color: splitLine } } },
    yAxis: { type: 'value', minInterval: 1, axisLabel: { color: textMuted, fontSize: 9 }, splitLine: { lineStyle: { color: splitLine, type: 'dashed' } } },
    series: [
      {
        name: '实时包速率',
        type: 'line',
        smooth: true,
        data: rt.map(b => b.count),
        lineStyle: { width: 2, color: '#38bdf8' },
        itemStyle: { color: '#38bdf8' },
      },
      {
        name: '历史归档序列',
        type: 'line',
        smooth: true,
        data: hist.map(h => h.packet_count),
        lineStyle: { width: 2, type: 'dashed', color: '#f59e0b' },
        itemStyle: { color: '#f59e0b' },
      },
    ],
  };
});

const fftEchartOption = computed(() => {
  const dark = isDarkTheme.value;
  const textPrimary = dark ? '#e2e8f0' : '#0f172a';
  const textMuted = dark ? '#94a3b8' : '#64748b';
  const splitLine = dark ? 'rgba(148,163,184,0.14)' : 'rgba(15,23,42,0.1)';
  const tooltipBg = dark ? 'rgba(15,23,42,0.94)' : 'rgba(255,255,255,0.96)';

  const wf = smartWaveResult.value;
  const rtBins = wf ? wf.realtime_fft : realtimeFftBins.value;
  const baseBins = wf ? wf.baseline_fft : [];
  const xLabels = rtBins.map(b => b.normalized_freq.toFixed(3));
  const series: Array<Record<string, unknown>> = [
    {
      name: '实时频谱幅值',
      type: 'bar',
      data: rtBins.map(b => b.magnitude),
      itemStyle: { color: 'rgba(56, 189, 248, 0.78)', borderRadius: [3, 3, 0, 0] },
    },
  ];
  if (baseBins.length > 0) {
    series.push({
      name: '黄金基线频谱',
      type: 'line',
      smooth: true,
      showSymbol: false,
      data: baseBins.map(b => b.magnitude),
      lineStyle: { width: 2, type: 'dashed', color: '#f59e0b' },
      itemStyle: { color: '#f59e0b' },
    });
  }
  return {
    backgroundColor: 'transparent',
    tooltip: { trigger: 'axis', backgroundColor: tooltipBg, textStyle: { color: textPrimary, fontSize: 11 } },
    legend: { top: 0, textStyle: { color: textMuted, fontSize: 10 } },
    grid: { left: 40, right: 12, top: 26, bottom: 24 },
    xAxis: { type: 'category', data: xLabels, axisLabel: { color: textMuted, fontSize: 9 }, axisLine: { lineStyle: { color: splitLine } } },
    yAxis: { type: 'value', axisLabel: { color: textMuted, fontSize: 9 }, splitLine: { lineStyle: { color: splitLine, type: 'dashed' } } },
    series,
  };
});

async function runVcdDecode(content: string, explicitSignal?: string) {
  if (!content) return;
  vcdError.value = '';
  vcdMultiSummary.value = '';
  try {
    const res = await invoke<VcdUartDecodedResult>('decode_vcd_uart_waveform_cmd', {
      vcdContent: content,
      targetSignal: explicitSignal ?? (vcdSignalName.value.trim() || ''),
      baudRate: vcdBaudRate.value || 115200,
      parity: vcdParity.value,
    });
    vcdResult.value = res;
    if (res.matched_signal) {
      vcdSignalName.value = res.matched_signal;
    }
    if (vcdBusMode.value !== 'UART') {
      const multi = await invoke<{ summary_text: string }>('decode_multibus_vcd_cmd', {
        vcdContent: content,
        busType: vcdBusMode.value,
        ch0Name: res.matched_signal || null,
        ch1Name: null,
        ch2Name: null,
        baudRate: vcdBaudRate.value || 115200,
        minGlitchNs: 20,
        spiMode: 0,
      });
      vcdMultiSummary.value = multi.summary_text;
    }
    nextTick(drawVcdWaveform);
  } catch (e) {
    vcdError.value = String(e);
    vcdResult.value = null;
  }
}

async function onSelectVcdFile(evt: Event) {
  const input = evt.target as HTMLInputElement;
  const file = input.files?.[0];
  if (!file) return;
  try {
    const content = await file.text();
    lastVcdContent.value = content;
    lastVcdFileName.value = file.name;
    // 首次导入传当前输入或空以兼容文件真实 $var 首选通道名，并在失败时不丢失缓存
    await runVcdDecode(content, '');
  } finally {
    input.value = '';
  }
}

async function redecodeCachedVcd() {
  if (!lastVcdContent.value) return;
  await runVcdDecode(lastVcdContent.value, vcdSignalName.value);
}

function exportPlotterCsv() {
  const chans = plotterSeries.value.channels;
  if (chans.length === 0) return;
  const maxLen = Math.max(...chans.map(c => c.samples.length));
  const lines = [chans.map(c => c.name).join(',')];
  for (let i = 0; i < maxLen; i++) {
    lines.push(chans.map(c => (c.samples[i] !== undefined ? String(c.samples[i]) : '')).join(','));
  }
  const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `omni_probe_plotter_${Date.now()}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

function setupCanvas(canvas: HTMLCanvasElement | null): { ctx: CanvasRenderingContext2D; w: number; h: number } | null {
  if (!canvas) return null;
  const rect = canvas.getBoundingClientRect();
  if (rect.width <= 0 || rect.height <= 0) return null;
  const dpr = window.devicePixelRatio || 1;
  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  const ctx = canvas.getContext('2d');
  if (!ctx) return null;
  ctx.scale(dpr, dpr);
  ctx.fillStyle = '#090f1d';
  ctx.fillRect(0, 0, rect.width, rect.height);
  return { ctx, w: rect.width, h: rect.height };
}

function drawGrid(ctx: CanvasRenderingContext2D, w: number, h: number, min: number, max: number) {
  ctx.strokeStyle = 'rgba(148, 163, 184, 0.14)';
  ctx.lineWidth = 1;
  ctx.font = '10px ui-monospace, monospace';
  ctx.fillStyle = '#94a3b8';
  const span = max - min || 1;
  for (let g = 0; g <= 4; g++) {
    const y = 14 + (g / 4) * (h - 32);
    ctx.beginPath();
    ctx.moveTo(46, y);
    ctx.lineTo(w - 10, y);
    ctx.stroke();
    ctx.fillText((max - (g / 4) * span).toFixed(1), 4, y + 3);
  }
}

function drawPlotter() {
  const setup = setupCanvas(plotterCanvasRef.value);
  if (!setup) return;
  const { ctx, w, h } = setup;
  const visible = plotterSeries.value.channels.filter(c => !hiddenChannels.value.has(c.name));
  if (visible.length === 0) return;

  let gMin = Infinity;
  let gMax = -Infinity;
  for (const ch of visible) {
    if (ch.min < gMin) gMin = ch.min;
    if (ch.max > gMax) gMax = ch.max;
  }
  if (!Number.isFinite(gMin) || !Number.isFinite(gMax)) return;
  if (gMin === gMax) {
    const pad = Math.max(1, Math.abs(gMin) * 0.1);
    gMin -= pad;
    gMax += pad;
  }
  drawGrid(ctx, w, h, gMin, gMax);

  const range = gMax - gMin || 1;
  const toY = (v: number) => h - 18 - ((v - gMin) / range) * (h - 32);

  visible.forEach((ch, idx) => {
    const pts = ch.samples;
    if (pts.length === 0) return;
    const color = channelColor(idx);
    ctx.strokeStyle = color;
    ctx.fillStyle = color;
    ctx.lineWidth = 1.8;
    const step = pts.length > 1 ? (w - 60) / (pts.length - 1) : 0;
    const xPos = (i: number) => (pts.length === 1 ? (w + 46) / 2 : 48 + i * step);

    if (pts.length >= 2) {
      ctx.beginPath();
      pts.forEach((v, i) => {
        const x = xPos(i);
        const y = toY(v);
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.stroke();
    }

    // 始终渲染末端点（解决单帧点亮黑屏问题并突出当前实时游标点）
    const lastIdx = pts.length - 1;
    const lx = xPos(lastIdx);
    const ly = toY(pts[lastIdx]);
    ctx.beginPath();
    ctx.arc(lx, ly, 3.2, 0, Math.PI * 2);
    ctx.fill();
  });
}

function drawBinaryScope() {
  const setup = setupCanvas(binaryCanvasRef.value);
  if (!setup) return;
  const { ctx, w, h } = setup;
  const pts = binarySeries.value;
  if (pts.length === 0) return;

  let { min, max } = binaryStats.value;
  if (min === max) {
    const pad = Math.max(1, Math.abs(min) * 0.1);
    min -= pad;
    max += pad;
  }
  const span = max - min || 1;
  drawGrid(ctx, w, h, min, max);

  const toY = (v: number) => h - 18 - ((v - min) / span) * (h - 32);
  ctx.strokeStyle = '#38bdf8';
  ctx.fillStyle = '#38bdf8';
  ctx.lineWidth = 2;

  const step = pts.length > 1 ? (w - 60) / (pts.length - 1) : 0;
  const xPos = (i: number) => (pts.length === 1 ? (w + 46) / 2 : 48 + i * step);

  if (pts.length >= 2) {
    ctx.beginPath();
    pts.forEach((v, i) => {
      const x = xPos(i);
      const y = toY(v);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();
  }

  const lastIdx = pts.length - 1;
  ctx.beginPath();
  ctx.arc(xPos(lastIdx), toY(pts[lastIdx]), 3.5, 0, Math.PI * 2);
  ctx.fill();
}

function drawCompareChart() {
  const setup = setupCanvas(compareCanvasRef.value);
  if (!setup) return;
  const { ctx, w, h } = setup;
  const rt = realtimeBuckets.value.map(b => b.count);
  const hist = (historyData.value?.trend_points || []).map(p => p.packet_count);
  if (rt.length === 0 && hist.length === 0) return;

  const maxY = Math.max(1, ...rt, ...hist);
  drawGrid(ctx, w, h, 0, maxY);

  // 对齐统一离散归一化进度槽，若单点同样渲染圆点标记，防止不可见
  const drawSeries = (arr: number[], color: string, dashed: boolean) => {
    if (arr.length === 0) return;
    ctx.save();
    ctx.strokeStyle = color;
    ctx.fillStyle = color;
    ctx.lineWidth = 2;
    if (dashed) ctx.setLineDash([5, 4]);
    const step = arr.length > 1 ? (w - 62) / (arr.length - 1) : 0;
    const xPos = (i: number) => (arr.length === 1 ? (w + 46) / 2 : 48 + i * step);
    const yPos = (v: number) => h - 18 - (v / maxY) * (h - 32);

    if (arr.length >= 2) {
      ctx.beginPath();
      arr.forEach((v, i) => {
        const x = xPos(i);
        const y = yPos(v);
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.stroke();
    }

    if (arr.length === 1) {
      ctx.beginPath();
      ctx.arc(xPos(0), yPos(arr[0]), 4, 0, Math.PI * 2);
      ctx.fill();
    }
    ctx.restore();
  };

  drawSeries(hist, '#fbbf24', true);
  drawSeries(rt, '#38bdf8', false);
}

function drawVcdWaveform() {
  const setup = setupCanvas(vcdCanvasRef.value);
  if (!setup) return;
  const { ctx, w, h } = setup;
  const tr = vcdResult.value?.transitions || [];
  if (tr.length < 2) return;

  const t0 = tr[0].timestamp_us;
  const tEnd = tr[tr.length - 1].timestamp_us > t0 ? tr[tr.length - 1].timestamp_us : t0 + 1;
  const span = Math.max(1, tEnd - t0);
  const yHigh = 24;
  const yLow = h - 26;

  ctx.strokeStyle = 'rgba(148, 163, 184, 0.2)';
  ctx.font = '10px ui-monospace, monospace';
  ctx.fillStyle = '#94a3b8';
  ctx.fillText('HIGH (1)', 6, yHigh + 4);
  ctx.fillText('LOW  (0)', 6, yLow + 4);
  ctx.fillText(`${t0} us`, 56, h - 6);
  const endLabel = `${tEnd} us`;
  ctx.fillText(endLabel, w - 16 - endLabel.length * 6, h - 6);

  ctx.strokeStyle = '#34d399';
  ctx.lineWidth = 2;
  ctx.beginPath();
  const toX = (t: number) => 56 + ((t - t0) / span) * (w - 72);
  let curY = tr[0].level ? yHigh : yLow;
  ctx.moveTo(toX(tr[0].timestamp_us), curY);
  for (let i = 1; i < tr.length; i++) {
    const x = toX(tr[i].timestamp_us);
    const nextY = tr[i].level ? yHigh : yLow;
    ctx.lineTo(x, curY);
    if (nextY !== curY) {
      ctx.lineTo(x, nextY);
      curY = nextY;
    }
  }
  ctx.stroke();
}

function redrawActiveCanvas() {
  if (activeMode.value === 'serial-plotter') drawPlotter();
  else if (activeMode.value === 'binary-scope') drawBinaryScope();
  else if (activeMode.value === 'realtime-vs-history') drawCompareChart();
  else if (activeMode.value === 'vcd-logic') drawVcdWaveform();
}

watch([activeMode, plotterSeries, hiddenChannels], () => nextTick(drawPlotter));
watch([activeMode, binarySeries, binaryDecodeMode], () => {
  nextTick(drawBinaryScope);
  if (activeMode.value === 'binary-scope' && binaryDecodeMode.value !== 'single') {
    refreshStructDecode();
  }
});
watch([activeMode, realtimeBuckets, historyData], () => nextTick(drawCompareChart));
watch([activeMode, vcdResult], () => nextTick(drawVcdWaveform));
watch([busScope, filterByCurrentPort], () => {
  if (activeMode.value === 'realtime-vs-history') {
    fetchHistoricalBaseline();
  }
});
watch([activeMode, activeChannelSamples], () => {
  if (activeMode.value === 'realtime-vs-history') {
    computeLiveFft();
  }
});

let resizeObserver: ResizeObserver | null = null;
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
  refreshWaveBaselines();
  fetchHistoricalBaseline();
  computeLiveFft();
  nextTick(redrawActiveCanvas);
  if (typeof ResizeObserver !== 'undefined' && rootRef.value) {
    resizeObserver = new ResizeObserver(() => {
      nextTick(redrawActiveCanvas);
    });
    resizeObserver.observe(rootRef.value);
  }
});

onUnmounted(() => {
  if (themeObserver) {
    themeObserver.disconnect();
    themeObserver = null;
  }
  if (resizeObserver) {
    resizeObserver.disconnect();
    resizeObserver = null;
  }
});
</script>
