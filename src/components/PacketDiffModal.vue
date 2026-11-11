<template>
  <div v-if="activeIsOpen" class="fixed inset-0 z-50 flex items-center justify-center ui-modal-backdrop p-4 animate-in fade-in duration-200">
    <!-- 主模态视窗 (Beyond Compare + Wireshark + 全局多模块通用差分工作台) -->
    <div class="relative w-full max-w-7xl h-[92vh] ui-modal-surface rounded-2xl flex flex-col overflow-hidden font-sans">
      <span class="lens-edge-lip" aria-hidden="true"></span>
      
      <!-- 1. 顶部控制栏与对比摘要胶囊 (Liquid Glass 双层稳态排布，防关闭按钮折行) -->
      <header class="ui-nav-glass border-b px-5 py-2.5 flex flex-col gap-2 shrink-0">
        <div class="flex items-center justify-between gap-3">
          <div class="flex items-center gap-3 min-w-0">
            <div class="w-8 h-8 rounded-xl bg-indigo-500/15 border border-indigo-500/30 flex items-center justify-center text-indigo-700 dark:text-indigo-300 shrink-0">
              <AppIcon name="scale" :size="16" />
            </div>
            <div class="min-w-0">
              <h2 class="text-sm font-bold flex items-center gap-2 truncate" style="color: var(--text-primary)">
                <span class="truncate">全局通用数据比对与波线波率工作台</span>
                <span class="text-[11px] ui-num px-2 py-0.5 rounded-md bg-indigo-500/12 text-indigo-700 dark:text-indigo-300 border border-indigo-500/25 font-semibold shrink-0">
                  Universal Multi-Bus Diff
                </span>
              </h2>
              <div class="text-[11px] truncate" style="color: var(--text-muted)">
                {{ activeMode === 'multi' ? (multiResult?.summary || 'Center-Star N 组居中 LCS 严格对齐与跨组熵谱对比') : (diffResult?.summary || '逐字节 LCS 严格对齐、多层规约树逐字段差分与载荷波形分析') }}
              </div>
            </div>
          </div>

          <div class="flex items-center gap-2.5 shrink-0">
            <!-- 差异突变率 / 多组统计指示卡 -->
            <div v-if="activeMode === 'multi' && multiResult" class="hidden sm:flex items-center gap-2.5 ui-pill px-3 py-1 rounded-xl text-xs ui-num">
              <span class="text-[11px]" style="color: var(--text-secondary)">
                样本组: <strong class="text-indigo-700 dark:text-indigo-300">{{ multiResult.sample_count }}</strong>
              </span>
              <span class="text-[11px]" style="color: var(--text-secondary)">
                对齐列宽: <strong class="text-emerald-700 dark:text-emerald-300">{{ multiResult.aligned_column_count }}</strong> B
              </span>
            </div>
            <div v-else-if="diffResult" class="hidden sm:flex items-center gap-3 ui-pill px-3 py-1 rounded-xl text-xs ui-num">
              <div class="text-[11px]" style="color: var(--text-secondary)">
                突变字节: <strong class="text-rose-700 dark:text-rose-400">{{ diffResult.mutated_bytes_count }}</strong> / {{ Math.max(diffResult.total_bytes_a, diffResult.total_bytes_b) }}
              </div>
              <div class="w-16 h-2 rounded-full overflow-hidden" style="background: var(--surface-elevated)">
                <div class="h-full transition-all duration-300"
                  :class="diffResult.mutation_rate_percent > 30 ? 'bg-rose-500' : 'bg-amber-500'"
                  :style="{ width: `${Math.min(100, diffResult.mutation_rate_percent)}%` }"></div>
              </div>
              <span :class="['text-[11px] font-bold', diffResult.mutation_rate_percent > 30 ? 'text-rose-700 dark:text-rose-400' : 'text-amber-700 dark:text-amber-300']">
                {{ diffResult.mutation_rate_percent.toFixed(1) }}%
              </span>
            </div>

            <!-- 导出与关闭按钮组 (永远锁定在首行最右侧) -->
            <button v-if="diffResult || (activeMode === 'multi' && multiResult)" @click="exportDiffReport"
              class="ui-btn-secondary text-xs py-1.5 px-3 rounded-xl"
              title="导出当前双组或多组 Center-Star 分析报告 (Markdown)">
              <AppIcon name="download" :size="13" />
              <span>导出差分报告</span>
            </button>
            <button @click="handleClose"
              class="w-8 h-8 rounded-full ui-pill flex items-center justify-center cursor-pointer shrink-0"
              title="关闭工作台">
              <AppIcon name="close" :size="15" />
            </button>
          </div>
        </div>

        <!-- 第二排：一体化模式切换分段控件 (宽敞居中/左对齐绝不拥挤折断) -->
        <div class="flex ui-pill p-1 rounded-xl text-xs font-semibold flex-wrap gap-1 self-start">
          <button @click="switchMode('hex')"
            :class="['px-3 py-1 rounded-lg transition-colors cursor-pointer flex items-center gap-1.5',
              activeMode === 'hex' ? 'bg-indigo-600 text-white shadow-xs font-bold' : 'hover:bg-black/5 dark:hover:bg-white/5']"
            :style="activeMode !== 'hex' ? { color: 'var(--text-secondary)' } : undefined">
            <AppIcon name="code" :size="13" />
            <span>逐字节 Hex 比对</span>
          </button>
          <button @click="switchMode('multi')"
            :class="['px-3 py-1 rounded-lg transition-colors cursor-pointer flex items-center gap-1.5',
              activeMode === 'multi' ? 'bg-indigo-600 text-white shadow-xs font-bold' : 'hover:bg-black/5 dark:hover:bg-white/5']"
            :style="activeMode !== 'multi' ? { color: 'var(--text-secondary)' } : undefined">
            <AppIcon name="git-branch" :size="13" />
            <span>多组 Center-Star 矩阵</span>
            <span v-if="diffBus.queueCount.value > 0"
              :class="['px-1.5 py-0.5 rounded-full text-[11px] ui-num font-bold',
                diffBus.queueCount.value >= 3 ? 'bg-emerald-500 text-white' : 'ui-pill']">
              {{ diffBus.queueCount.value }}
            </span>
          </button>
          <button @click="switchMode('fields')"
            :class="['px-3 py-1 rounded-lg transition-colors cursor-pointer flex items-center gap-1.5',
              activeMode === 'fields' ? 'bg-indigo-600 text-white shadow-xs font-bold' : 'hover:bg-black/5 dark:hover:bg-white/5']"
            :style="activeMode !== 'fields' ? { color: 'var(--text-secondary)' } : undefined">
            <AppIcon name="layers" :size="13" />
            <span>规约字段差异</span>
            <span v-if="differentFieldsCount > 0" class="px-1.5 py-0.5 rounded-full text-[11px] bg-rose-500 text-white ui-num font-bold">
              {{ differentFieldsCount }}
            </span>
          </button>
          <button @click="switchMode('wave')"
            :class="['px-3 py-1 rounded-lg transition-colors cursor-pointer flex items-center gap-1.5',
              activeMode === 'wave' ? 'bg-indigo-600 text-white shadow-xs font-bold' : 'hover:bg-black/5 dark:hover:bg-white/5']"
            :style="activeMode !== 'wave' ? { color: 'var(--text-secondary)' } : undefined">
            <AppIcon name="activity" :size="13" />
            <span>载荷波线与波率</span>
            <span v-if="diffResult?.waveform_metrics" class="px-1.5 py-0.5 rounded-full text-[11px] bg-sky-500/15 text-sky-700 dark:text-cyan-300 border border-sky-500/30 ui-num font-bold">
              {{ diffResult.waveform_metrics.mutation_wave_rate.toFixed(0) }}%
            </span>
          </button>
          <button @click="switchMode('scratchpad')"
            :class="['px-3 py-1 rounded-lg transition-colors cursor-pointer flex items-center gap-1.5',
              activeMode === 'scratchpad' ? 'bg-indigo-600 text-white shadow-xs font-bold' : 'hover:bg-black/5 dark:hover:bg-white/5']"
            :style="activeMode !== 'scratchpad' ? { color: 'var(--text-secondary)' } : undefined">
            <AppIcon name="document" :size="13" />
            <span>自由草稿比对</span>
          </button>
          <button @click="switchMode('samples')"
            :class="['px-3 py-1 rounded-lg transition-colors cursor-pointer flex items-center gap-1.5',
              activeMode === 'samples' ? 'bg-indigo-600 text-white shadow-xs font-bold' : 'hover:bg-black/5 dark:hover:bg-white/5']"
            :style="activeMode !== 'samples' ? { color: 'var(--text-secondary)' } : undefined">
            <AppIcon name="database" :size="13" />
            <span>样本库</span>
            <span v-if="storedSamples.length > 0" class="px-1.5 py-0.5 rounded-full text-[11px] ui-pill ui-num">
              {{ storedSamples.length }}
            </span>
          </button>
          <button @click="switchMode('file_merge')"
            :class="['px-3 py-1 rounded-lg transition-colors cursor-pointer flex items-center gap-1.5',
              activeMode === 'file_merge' ? 'bg-indigo-600 text-white shadow-xs font-bold' : 'hover:bg-black/5 dark:hover:bg-white/5']"
            :style="activeMode !== 'file_merge' ? { color: 'var(--text-secondary)' } : undefined">
            <AppIcon name="git-branch" :size="13" />
            <span>大文件 / 目录双向合并</span>
          </button>
        </div>
      </header>

      <!-- 2. 元信息与队列控制条 (双样本对照条 / 多组队列胶囊条) -->
      <div v-if="activeMode === 'multi'" class="px-5 py-2.5 border-b text-xs ui-num shrink-0 flex items-center justify-between gap-3 flex-wrap" style="background: var(--surface-content-alt); border-color: var(--border-subtle)">
        <div class="flex items-center gap-2 flex-wrap flex-1 min-w-0">
          <span class="text-[11px] font-bold shrink-0" style="color: var(--text-secondary)">比对队列 ({{ diffBus.queueCount.value }} 组):</span>
          <div v-for="(item, idx) in diffBus.diffQueue.value" :key="`${idx}-${item.label}`"
            @click="selectMultiAnchor(idx)"
            :class="['flex items-center gap-1.5 px-2.5 py-1 rounded-xl border text-[11px] cursor-pointer transition-colors max-w-[230px]',
              diffBus.anchorIndex.value === idx
                ? 'bg-indigo-600 text-white border-indigo-500 shadow-xs font-bold'
                : 'ui-sub-card hover:border-indigo-500/40']"
            :title="`点击设为 Anchor 居中基准 | ${item.label} (${item.length || 0} 字节)`">
            <span class="px-1 py-0.2 rounded text-[11px]"
              :class="diffBus.anchorIndex.value === idx ? 'bg-white/20 text-white' : 'bg-indigo-500/12 text-indigo-700 dark:text-indigo-300'">
              {{ diffBus.anchorIndex.value === idx ? '基准#' + (idx + 1) : '#' + (idx + 1) }}
            </span>
            <span class="truncate">{{ item.label }}</span>
            <span class="opacity-75 shrink-0">{{ item.length || 0 }}B</span>
            <button @click.stop="removeMultiQueueItem(idx)"
              class="ml-0.5 hover:text-rose-400 transition-colors px-1 cursor-pointer"
              title="从队列移除该组">
              ×
            </button>
          </div>
          <span v-if="diffBus.queueCount.value === 0" class="text-[11px]" style="color: var(--text-muted)">
            暂无队列项，可在各业务模块点击【+ 加入比对队列】或载入多组演练样本
          </span>
        </div>
        <div class="flex items-center gap-2 shrink-0">
          <button @click="loadMultiPreset3Group"
            class="px-2.5 py-1 rounded-lg bg-emerald-500/12 hover:bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30 text-[11px] cursor-pointer font-semibold">
            载入 3 组变长演练
          </button>
          <button @click="switchMode('scratchpad')"
            class="ui-btn-secondary text-[11px] py-1 px-2.5 rounded-lg">
            草稿增组
          </button>
          <button v-if="diffBus.queueCount.value > 0" @click="clearMultiQueue"
            class="ui-btn-danger text-[11px] py-1 px-2.5 rounded-lg">
            清空队列
          </button>
        </div>
      </div>

      <div v-else-if="activeMode !== 'file_merge'" class="px-5 py-2.5 border-b text-xs ui-num shrink-0 flex items-center gap-3" style="background: var(--surface-content-alt); border-color: var(--border-subtle)">
        <!-- 左侧：基准样本 A -->
        <div class="flex-1 flex items-center justify-between ui-sub-card px-3 py-1.5 min-w-0">
          <div class="flex items-center gap-2 truncate">
            <span class="px-1.5 py-0.5 rounded bg-blue-500/15 text-blue-700 dark:text-blue-300 border border-blue-500/30 text-[11px] font-bold shrink-0">
              基准项 A
            </span>
            <span class="font-bold truncate" style="color: var(--text-primary)">{{ effectiveItemA?.label || '未载入项 A' }}</span>
            <span class="truncate text-[11px]" style="color: var(--text-muted)" v-if="effectiveItemA?.src && effectiveItemA?.src !== '-'">
              {{ effectiveItemA.src }} → {{ effectiveItemA.dst || '-' }}
            </span>
          </div>
          <div class="flex items-center gap-2 shrink-0">
            <span class="text-[11px] font-normal" style="color: var(--text-muted)">{{ effectiveItemA ? `${effectiveItemA.length || 0} 字节` : '' }}</span>
            <button v-if="effectiveItemA && effectiveItemA.payloadHex" @click="doSaveItemSample(effectiveItemA, 'A')"
              class="text-[11px] ui-pill px-2 py-0.5 rounded-lg flex items-center gap-1 cursor-pointer"
              title="将样本 A 固化存入本地样本库">
              <AppIcon name="archive" :size="11" />
              <span>存为样本</span>
            </button>
          </div>
        </div>

        <!-- 中间：互换 A <-> B 按钮 -->
        <button @click="swapItems" :disabled="!effectiveItemA || !effectiveItemB"
          class="shrink-0 w-8 h-8 rounded-xl ui-pill flex items-center justify-center cursor-pointer disabled:opacity-35 disabled:cursor-not-allowed"
          title="互换基准项 A 与比对项 B 的比对方向">
          <AppIcon name="refresh" :size="14" />
        </button>

        <!-- 右侧：比对样本 B -->
        <div class="flex-1 flex items-center justify-between ui-sub-card px-3 py-1.5 min-w-0">
          <div class="flex items-center gap-2 truncate">
            <span class="px-1.5 py-0.5 rounded bg-indigo-500/15 text-indigo-700 dark:text-indigo-300 border border-indigo-500/30 text-[11px] font-bold shrink-0">
              比对项 B
            </span>
            <span class="font-bold truncate" style="color: var(--text-primary)">{{ effectiveItemB?.label || '未载入项 B' }}</span>
            <span class="truncate text-[11px]" style="color: var(--text-muted)" v-if="effectiveItemB?.src && effectiveItemB?.src !== '-'">
              {{ effectiveItemB.src }} → {{ effectiveItemB.dst || '-' }}
            </span>
          </div>
          <div class="flex items-center gap-2 shrink-0">
            <span class="text-[11px] font-normal" style="color: var(--text-muted)">{{ effectiveItemB ? `${effectiveItemB.length || 0} 字节` : '' }}</span>
            <button v-if="effectiveItemB && effectiveItemB.payloadHex" @click="doSaveItemSample(effectiveItemB, 'B')"
              class="text-[11px] ui-pill px-2 py-0.5 rounded-lg flex items-center gap-1 cursor-pointer"
              title="将样本 B 固化存入本地样本库">
              <AppIcon name="archive" :size="11" />
              <span>存为样本</span>
            </button>
          </div>
        </div>
      </div>

      <!-- 3. 主体视窗 (实体高对比稳态工作区) -->
      <div class="flex-1 overflow-hidden min-h-0 relative" style="background: var(--surface-content)">

        <!-- 模式零：多组 Center-Star 居中序列对齐与交叉矩阵工作台 (N >= 2 组不封顶) -->
        <div v-show="activeMode === 'multi'" class="h-full overflow-auto p-5 space-y-5 custom-scrollbar select-text">
          <div v-if="multiError" class="ui-sub-card p-4 border-amber-500/40 bg-amber-500/10 flex items-center justify-between gap-3">
            <div class="text-xs text-amber-800 dark:text-amber-300 font-medium">
              <strong>多组对齐执行提示：</strong> {{ multiError }}
            </div>
            <button @click="runMultiCompare" class="ui-btn-secondary px-3 py-1 text-xs shrink-0">重试对齐</button>
          </div>

          <div v-else-if="diffBus.queueCount.value < 2" class="h-full flex items-center justify-center">
            <div class="ui-sub-card p-6 max-w-xl w-full text-center space-y-4">
              <EmptyState icon="git-branch"
                title="Center-Star 多组居中精准比对就绪"
                :description="`当前比对队列有 ${diffBus.queueCount.value} 组样本（需至少 2 组，支持 3 组、4 组及以上不封顶比对）。您可以在任何工作台点击【加入比对队列】，或下方一键载入多组演练。`" />
              <div class="flex items-center justify-center gap-2.5 flex-wrap">
                <button @click="loadMultiPreset3Group" class="ui-btn-primary text-xs py-1.5 px-4 rounded-xl">
                  <AppIcon name="zap" :size="13" />
                  <span>载入 3 组含前插/尾缺 Modbus 样本</span>
                </button>
                <button @click="switchMode('scratchpad')" class="ui-btn-secondary text-xs py-1.5 px-3.5 rounded-xl">
                  <span>前往自由草稿录入多组</span>
                </button>
                <button @click="switchMode('samples')" class="ui-btn-secondary text-xs py-1.5 px-3.5 rounded-xl">
                  <span>从样本库选取</span>
                </button>
              </div>
            </div>
          </div>

          <template v-else-if="multiResult">
            <!-- 多组宏观度量卡组 -->
            <div class="grid grid-cols-2 lg:grid-cols-4 gap-3 ui-num">
              <div class="ui-sub-card p-3">
                <div class="text-[11px]" style="color: var(--text-muted)">参与比对样本总数</div>
                <div class="text-xl font-bold mt-1 text-indigo-700 dark:text-indigo-300">{{ multiResult.sample_count }} 组</div>
              </div>
              <div class="ui-sub-card p-3">
                <div class="text-[11px]" style="color: var(--text-muted)">居中参照基准 (Anchor)</div>
                <div class="text-sm font-bold mt-1.5 truncate" style="color: var(--text-primary)">
                  #{{ multiResult.anchor_index + 1 }} · {{ multiResult.samples[multiResult.anchor_index]?.label || '-' }}
                </div>
              </div>
              <div class="ui-sub-card p-3">
                <div class="text-[11px]" style="color: var(--text-muted)">Center-Star 全局对齐列数</div>
                <div class="text-xl font-bold mt-1 text-emerald-700 dark:text-emerald-300">{{ multiResult.aligned_column_count }} <span class="text-xs font-normal">列</span></div>
              </div>
              <div class="ui-sub-card p-3">
                <div class="text-[11px]" style="color: var(--text-muted)">非锚点平均变异率</div>
                <div class="text-xl font-bold mt-1 text-rose-700 dark:text-rose-400">{{ multiAvgMutationRate.toFixed(1) }}%</div>
              </div>
            </div>

            <!-- 组别横向统计总览条 -->
            <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-2.5 ui-num">
              <div v-for="smp in multiResult.samples" :key="smp.sample_index"
                @click="selectMultiAnchor(smp.sample_index)"
                :class="['ui-sub-card p-3 flex items-center justify-between gap-2 cursor-pointer transition-colors border',
                  smp.sample_index === multiResult.anchor_index ? 'border-indigo-500/60 bg-indigo-500/10' : 'hover:border-indigo-500/35']">
                <div class="min-w-0">
                  <div class="flex items-center gap-1.5">
                    <span class="px-1.5 py-0.5 rounded text-[11px] font-bold"
                      :class="smp.sample_index === multiResult.anchor_index ? 'bg-indigo-600 text-white' : 'bg-slate-500/15 text-slate-700 dark:text-slate-300'">
                      {{ smp.sample_index === multiResult.anchor_index ? `基准 #${smp.sample_index + 1}` : `#${smp.sample_index + 1}` }}
                    </span>
                    <span class="font-bold text-xs truncate" style="color: var(--text-primary)">{{ smp.label }}</span>
                  </div>
                  <div class="text-[11px] mt-1 truncate" style="color: var(--text-muted)">
                    {{ smp.protocol || 'RAW' }} | {{ smp.byte_length }}B | {{ smp.endpoint_src || '-' }} → {{ smp.endpoint_dst || '-' }}
                  </div>
                </div>
                <div class="text-right shrink-0">
                  <div class="text-xs font-bold"
                    :class="smp.mutation_rate_vs_anchor > 25 ? 'text-rose-700 dark:text-rose-400' : 'text-emerald-700 dark:text-emerald-300'">
                    变异 {{ smp.mutation_rate_vs_anchor.toFixed(1) }}%
                  </div>
                  <div class="text-[11px]" style="color: var(--text-muted)">
                    Cos {{ (smp.cosine_similarity_vs_anchor * 100).toFixed(1) }}%
                  </div>
                </div>
              </div>
            </div>

            <!-- Block A: Center-Star 对齐逐字节交叉矩阵 (每 16 个对齐列分块，多样本逐行对照) -->
            <div class="ui-sub-card p-4 space-y-3">
              <div class="flex items-center justify-between flex-wrap gap-2 border-b pb-2" style="border-color: var(--border-subtle)">
                <div class="flex items-center gap-2 text-xs font-bold" style="color: var(--text-primary)">
                  <AppIcon name="code" :size="14" />
                  <span>Center-Star 多组对齐 Hex 矩阵 (含 "--" 琥珀金缺位插槽)</span>
                </div>
                <span class="text-[11px] ui-num" style="color: var(--text-muted)">
                  对齐长度 {{ multiResult.aligned_column_count }} 列 | 分 {{ multiHexBlocks.length }} 块展示
                </span>
              </div>

              <div class="space-y-4 font-mono-code text-xs">
                <div v-for="blk in multiHexBlocks" :key="blk.blockIndex"
                  class="rounded-xl border overflow-x-auto custom-scrollbar"
                  style="background: var(--surface-content); border-color: var(--border-subtle)">
                  <!-- 块列头 -->
                  <div class="flex items-center px-3 py-1.5 border-b text-[11px] font-bold"
                    style="background: var(--surface-content-alt); border-color: var(--border-subtle); color: var(--text-muted)">
                    <span class="w-40 shrink-0">对齐偏移 {{ blk.offsetHex }}</span>
                    <div class="flex items-center gap-1 min-w-[420px]">
                      <span v-for="col in blk.colIndices" :key="col"
                        class="w-6 text-center shrink-0"
                        :class="col === 8 ? 'ml-2' : ''">
                        {{ col.toString(16).toUpperCase().padStart(2, '0') }}
                      </span>
                    </div>
                    <span class="pl-4 shrink-0">ASCII 投影</span>
                  </div>
                  <!-- 各组样本在该块的对齐字节行 -->
                  <div v-for="sRow in blk.sampleRows" :key="sRow.sampleIndex"
                    class="flex items-center px-3 py-1 border-b last:border-b-0 transition-colors hover:bg-black/5 dark:hover:bg-white/5"
                    :style="sRow.sampleIndex === multiResult.anchor_index ? { background: 'rgba(99, 102, 241, 0.06)', borderColor: 'var(--border-subtle)' } : { borderColor: 'var(--border-subtle)' }">
                    <div class="w-40 shrink-0 pr-2 flex items-center gap-1.5 truncate">
                      <span class="px-1.5 py-0.2 rounded text-[11px] font-bold shrink-0"
                        :class="sRow.sampleIndex === multiResult.anchor_index ? 'bg-indigo-600 text-white' : 'ui-pill'">
                        #{{ sRow.sampleIndex + 1 }}
                      </span>
                      <span class="truncate text-[11px] font-sans font-semibold" style="color: var(--text-primary)" :title="sRow.label">
                        {{ sRow.label }}
                      </span>
                    </div>
                    <div class="flex items-center gap-1 min-w-[420px]">
                      <span v-for="(cell, cIdx) in sRow.cells" :key="cIdx"
                        :class="['w-6 h-5 rounded flex items-center justify-center text-[11px] shrink-0 transition-colors',
                          cIdx === 8 ? 'ml-2' : '',
                          getCellClass(cell.diff_type)]"
                        :title="`组#${sRow.sampleIndex + 1} 对齐列 ${blk.blockIndex * 16 + cIdx}: ${cell.hex} [${cell.diff_type}]`">
                        {{ cell.hex }}
                      </span>
                    </div>
                    <span class="pl-4 text-[11px] whitespace-pre shrink-0" style="color: var(--text-secondary)">{{ sRow.ascii }}</span>
                  </div>
                </div>
              </div>
            </div>

            <!-- Block B: 对齐变异波率与香农熵光谱 Canvas -->
            <div class="ui-sub-card p-4 space-y-2.5">
              <div class="flex items-center justify-between flex-wrap gap-2">
                <span class="text-xs font-bold flex items-center gap-2" style="color: var(--text-primary)">
                  <AppIcon name="activity" :size="14" />
                  <span>对齐位置变异波率与香农信息熵分布谱 (对齐 {{ multiResult.aligned_column_count }} 列)</span>
                </span>
                <div v-if="hoverMultiBin" class="text-[11px] ui-num flex items-center gap-2.5 px-2.5 py-1 rounded-lg border"
                  style="background: var(--surface-content); border-color: var(--border-subtle)">
                  <span style="color: var(--text-primary)">列偏移 <strong>0x{{ hoverMultiBin.offset.toString(16).toUpperCase().padStart(2, '0') }}</strong></span>
                  <span>支配值: <strong>{{ hoverMultiBin.dominant_hex }}</strong></span>
                  <span class="text-rose-600 dark:text-rose-400 font-bold">变异率: {{ hoverMultiBin.mutation_rate.toFixed(1) }}%</span>
                  <span class="text-sky-600 dark:text-cyan-300 font-bold">熵: {{ hoverMultiBin.entropy.toFixed(2) }} bit</span>
                  <span>异值态: {{ hoverMultiBin.unique_values_count }}</span>
                </div>
              </div>
              <div class="relative w-full h-[170px] rounded-xl overflow-hidden border" style="background: var(--surface-content); border-color: var(--border-subtle)">
                <canvas ref="multiSpectrumCanvas" @mousemove="onMultiSpectrumMouseMove" @mouseleave="hoverMultiBin = null" class="w-full h-full block"></canvas>
              </div>
            </div>

            <!-- Block C: 跨多组规约及元数据对比矩阵表 -->
            <div class="ui-sub-card p-4 space-y-3">
              <div class="flex items-center justify-between flex-wrap gap-2">
                <span class="text-xs font-bold flex items-center gap-2" style="color: var(--text-primary)">
                  <AppIcon name="layers" :size="14" />
                  <span>跨多组规约与业务元数据对比矩阵</span>
                </span>
                <label class="flex items-center gap-1.5 text-[11px] cursor-pointer" style="color: var(--text-secondary)">
                  <input type="checkbox" v-model="multiOnlyDiffFields" class="accent-indigo-600 rounded" />
                  <span>仅显示存在差异的字段</span>
                </label>
              </div>
              <div class="overflow-x-auto custom-scrollbar">
                <table class="w-full text-left border-collapse text-xs ui-num">
                  <thead>
                    <tr class="border-b" style="background: var(--surface-content-alt); border-color: var(--border-subtle); color: var(--text-secondary)">
                      <th class="py-2 px-3 w-32">分层</th>
                      <th class="py-2 px-3 w-44">属性 / 字段名</th>
                      <th v-for="smp in multiResult.samples" :key="smp.sample_index" class="py-2 px-3 min-w-[140px]">
                        #{{ smp.sample_index + 1 }} {{ smp.label }}
                      </th>
                      <th class="py-2 px-3 w-20 text-center">判定</th>
                    </tr>
                  </thead>
                  <tbody class="divide-y" style="border-color: var(--border-subtle)">
                    <tr v-for="(row, rIdx) in filteredMultiFieldMatrix" :key="rIdx"
                      class="hover:bg-black/5 dark:hover:bg-white/5 transition-colors">
                      <td class="py-2 px-3 font-semibold text-indigo-700 dark:text-indigo-300">{{ row.layer }}</td>
                      <td class="py-2 px-3 font-medium" style="color: var(--text-primary)">{{ row.field_name }}</td>
                      <td v-for="(val, vIdx) in row.values" :key="vIdx"
                        class="py-2 px-3 font-mono-code break-all"
                        :class="row.has_difference ? 'text-rose-700 dark:text-rose-300 font-semibold' : ''"
                        :style="!row.has_difference ? { color: 'var(--text-secondary)' } : undefined">
                        {{ val || '-' }}
                      </td>
                      <td class="py-2 px-3 text-center">
                        <span v-if="row.has_difference" class="px-2 py-0.5 rounded bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/30 text-[11px] font-bold">差异</span>
                        <span v-else class="px-2 py-0.5 rounded bg-slate-500/12 text-[11px]" style="color: var(--text-muted)">一致</span>
                      </td>
                    </tr>
                    <tr v-if="filteredMultiFieldMatrix.length === 0">
                      <td :colspan="multiResult.sample_count + 3" class="py-6 text-center" style="color: var(--text-muted)">
                        所有展示字段跨组完全一致
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

            <!-- Block D: 多组 Anchor->变体 二进制差异段 Patch 聚类与可执行修订脚本导出 -->
            <div class="ui-sub-card p-4 space-y-3">
              <div class="flex items-center justify-between flex-wrap gap-2">
                <span class="text-xs font-bold flex items-center gap-2" style="color: var(--text-primary)">
                  <AppIcon name="code" :size="14" />
                  <span>基于基准 Anchor 的差异字节段 Patch 汇编与可逆修订脚本</span>
                </span>
                <div class="flex items-center gap-2 flex-wrap">
                  <button
                    @click="generateMultiPatchScript"
                    :disabled="isGeneratingPatch"
                    class="ui-btn-primary text-[11px] py-1 px-3 rounded-xl font-bold cursor-pointer disabled:opacity-45"
                  >
                    {{ isGeneratingPatch ? '聚类分析中...' : '生成差异 Patch 修订脚本' }}
                  </button>
                  <template v-if="multiPatchReport">
                    <div class="flex ui-pill p-0.5 rounded-lg text-[11px]">
                      <button
                        @click="patchPreviewFormat = 'hex'"
                        :class="['px-2 py-0.5 rounded-md cursor-pointer', patchPreviewFormat === 'hex' ? 'bg-indigo-600 text-white font-bold' : '']"
                      >
                        Hex 修订汇编
                      </button>
                      <button
                        @click="patchPreviewFormat = 'python'"
                        :class="['px-2 py-0.5 rounded-md cursor-pointer', patchPreviewFormat === 'python' ? 'bg-indigo-600 text-white font-bold' : '']"
                      >
                        Python 可逆脚本
                      </button>
                    </div>
                    <button @click="copyMultiPatchScript" class="ui-btn-secondary text-[11px] py-1 px-2.5 rounded-lg cursor-pointer">
                      复制脚本
                    </button>
                    <button @click="downloadMultiPatchScript" class="ui-btn-secondary text-[11px] py-1 px-2.5 rounded-lg cursor-pointer">
                      导出 {{ patchPreviewFormat === 'python' ? '.py' : '.patch' }}
                    </button>
                  </template>
                </div>
              </div>

              <div v-if="multiPatchReport" class="space-y-2.5">
                <!-- 连续差异段摘要胶囊 -->
                <div class="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px] ui-num">
                  <div
                    v-for="sb in multiPatchReport.samples"
                    :key="sb.sample_index"
                    class="p-2.5 rounded-xl border space-y-1.5"
                    style="background: var(--surface-content); border-color: var(--border-subtle)"
                  >
                    <div class="flex items-center justify-between font-bold" style="color: var(--text-primary)">
                      <span>Target #{{ sb.sample_index + 1 }}: {{ sb.sample_label }}</span>
                      <span class="text-indigo-700 dark:text-indigo-300">{{ sb.total_hunks }} 处差异段 ({{ sb.target_byte_length }} B)</span>
                    </div>
                    <div v-for="hk in sb.hunks.slice(0, 6)" :key="hk.hunk_index" class="flex items-center justify-between gap-2 text-[11px]" style="color: var(--text-secondary)">
                      <span>@0x{{ hk.anchor_offset.toString(16).toUpperCase().padStart(4, '0') }} [{{ hk.op_kind }}]: {{ hk.anchor_hex || '--' }} → {{ hk.target_hex || '--' }}</span>
                      <span class="opacity-75 truncate max-w-[200px]" :title="hk.semantic_hint">{{ hk.semantic_hint }}</span>
                    </div>
                  </div>
                </div>

                <!-- 可读汇编或 Python 脚本预览区 -->
                <pre
                  class="p-3 rounded-xl border text-[11px] font-mono overflow-auto max-h-60 custom-scrollbar leading-relaxed"
                  style="background: var(--surface-input); border-color: var(--border-subtle); color: var(--text-primary)"
                >{{ patchPreviewFormat === 'python' ? multiPatchReport.python_patch_script : multiPatchReport.hex_revision_script }}</pre>
              </div>
              <div v-else class="text-[11px]" style="color: var(--text-muted)">
                点击右上方【生成差异 Patch 修订脚本】，自动把连续同型字节突变聚合为 OFFSET 修订汇编与可独立校验复现的 Python 3 二进制 Patcher。
              </div>
            </div>
          </template>
        </div>

        <!-- 模式一：逐字节 Hex 同步滚动对齐对比 -->
        <div v-show="activeMode === 'hex'" class="h-full grid grid-cols-1 lg:grid-cols-2 divide-y lg:divide-y-0 lg:divide-x" style="border-color: var(--border-subtle)">
          
          <!-- 左栏：样本 A Hex 视窗 -->
          <div ref="hexScrollA" @scroll="onScrollA"
            class="h-full overflow-y-auto overflow-x-hidden p-4 font-mono-code text-xs select-text custom-scrollbar" style="background: var(--surface-content)">
            <div class="text-[11px] font-bold uppercase tracking-wider mb-2 border-b pb-1 flex justify-between" style="color: var(--text-muted); border-color: var(--border-subtle)">
              <span>偏移量 | 00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F</span>
              <span>ASCII 预览</span>
            </div>

            <div v-if="diffResult?.hex_diff_a?.hex_rows && diffResult.hex_diff_a.hex_rows.length > 0" class="space-y-1">
              <div v-for="row in diffResult.hex_diff_a.hex_rows" :key="row.offset"
                class="flex items-center justify-between hover:bg-black/5 dark:hover:bg-white/5 px-1 py-0.5 rounded transition-colors">
                <span class="select-none w-12 shrink-0" style="color: var(--text-muted)">{{ row.offset }}</span>

                <div class="flex items-center gap-1.5 flex-1 mx-2">
                  <div class="flex items-center gap-1">
                    <span v-for="(cell, ci) in row.cells.slice(0, 8)" :key="ci"
                      :class="['px-1 py-0.5 rounded text-center min-w-[20px] transition-colors', getCellClass(cell.diff_type)]"
                      :title="cell.diff_type !== 'equal' ? `突变类型: ${cell.diff_type}` : ''">
                      {{ cell.hex }}
                    </span>
                  </div>
                  <span class="select-none" style="color: var(--border-strong)">|</span>
                  <div class="flex items-center gap-1">
                    <span v-for="(cell, ci) in row.cells.slice(8, 16)" :key="ci"
                      :class="['px-1 py-0.5 rounded text-center min-w-[20px] transition-colors', getCellClass(cell.diff_type)]"
                      :title="cell.diff_type !== 'equal' ? `突变类型: ${cell.diff_type}` : ''">
                      {{ cell.hex }}
                    </span>
                  </div>
                </div>

                <div class="select-none w-28 shrink-0 tracking-widest pl-2 border-l text-[11px]" style="color: var(--text-secondary); border-color: var(--border-subtle)">
                  {{ row.ascii_repr }}
                </div>
              </div>
            </div>
            <EmptyState
              v-else
              class="py-12"
              icon="code"
              title="等待加载比对基准样本 A"
              description="请选择报文或切换至自由草稿模式输入十六进制/文本内容。"
            />
          </div>

          <!-- 右栏：样本 B Hex 视窗 -->
          <div ref="hexScrollB" @scroll="onScrollB"
            class="h-full overflow-y-auto overflow-x-hidden p-4 font-mono-code text-xs select-text custom-scrollbar" style="background: var(--surface-content)">
            <div class="text-[11px] font-bold uppercase tracking-wider mb-2 border-b pb-1 flex justify-between" style="color: var(--text-muted); border-color: var(--border-subtle)">
              <span>偏移量 | 00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F</span>
              <span>ASCII 预览</span>
            </div>

            <div v-if="diffResult?.hex_diff_b?.hex_rows && diffResult.hex_diff_b.hex_rows.length > 0" class="space-y-1">
              <div v-for="row in diffResult.hex_diff_b.hex_rows" :key="row.offset"
                class="flex items-center justify-between hover:bg-black/5 dark:hover:bg-white/5 px-1 py-0.5 rounded transition-colors">
                <span class="select-none w-12 shrink-0" style="color: var(--text-muted)">{{ row.offset }}</span>

                <div class="flex items-center gap-1.5 flex-1 mx-2">
                  <div class="flex items-center gap-1">
                    <span v-for="(cell, ci) in row.cells.slice(0, 8)" :key="ci"
                      :class="['px-1 py-0.5 rounded text-center min-w-[20px] transition-colors', getCellClass(cell.diff_type)]"
                      :title="cell.diff_type !== 'equal' ? `突变类型: ${cell.diff_type}` : ''">
                      {{ cell.hex }}
                    </span>
                  </div>
                  <span class="select-none" style="color: var(--border-strong)">|</span>
                  <div class="flex items-center gap-1">
                    <span v-for="(cell, ci) in row.cells.slice(8, 16)" :key="ci"
                      :class="['px-1 py-0.5 rounded text-center min-w-[20px] transition-colors', getCellClass(cell.diff_type)]"
                      :title="cell.diff_type !== 'equal' ? `突变类型: ${cell.diff_type}` : ''">
                      {{ cell.hex }}
                    </span>
                  </div>
                </div>

                <div class="select-none w-28 shrink-0 tracking-widest pl-2 border-l text-[11px]" style="color: var(--text-secondary); border-color: var(--border-subtle)">
                  {{ row.ascii_repr }}
                </div>
              </div>
            </div>
            <EmptyState
              v-else
              class="py-12"
              icon="code"
              title="等待加载比对目标样本 B"
              description="请选择报文或切换至自由草稿模式输入对比流。"
            />
          </div>
        </div>

        <!-- 模式二：协议树逐字段差异比对 -->
        <div v-show="activeMode === 'fields'" class="h-full overflow-auto p-4 custom-scrollbar select-text">
          <table class="w-full text-left text-xs border-collapse table-fixed">
            <thead class="ui-table-head text-[11px] font-bold uppercase sticky top-0 z-10">
              <tr>
                <th class="p-2.5 w-[16%]">规约分层</th>
                <th class="p-2.5 w-[24%]">协议字段名称</th>
                <th class="p-2.5 w-[24%]">样本 A 取值 (基准)</th>
                <th class="p-2.5 w-[24%]">样本 B 取值 (比对)</th>
                <th class="p-2.5 w-[12%] text-center">比对状态</th>
              </tr>
            </thead>
            <tbody class="divide-y text-[11px] ui-num" style="border-color: var(--border-subtle); color: var(--text-secondary)">
              <tr v-for="(f, idx) in diffResult?.field_diffs || []" :key="idx"
                :class="['hover:bg-black/5 dark:hover:bg-white/5 transition-colors',
                  f.is_different ? 'bg-amber-500/8' : '']">
                <td class="p-2.5 font-bold truncate" style="color: var(--text-muted)">{{ f.layer }}</td>
                <td class="p-2.5 font-semibold truncate" style="color: var(--text-primary)">{{ f.field_name }}</td>
                <td class="p-2.5 truncate" :title="f.val_a">
                  <span :class="f.is_different ? 'text-amber-700 dark:text-amber-300 font-bold' : ''">{{ f.val_a || '—' }}</span>
                </td>
                <td class="p-2.5 truncate" :title="f.val_b">
                  <span :class="f.is_different ? 'text-rose-700 dark:text-rose-400 font-bold' : ''">{{ f.val_b || '—' }}</span>
                </td>
                <td class="p-2.5 text-center truncate">
                  <span :class="['px-2 py-0.5 rounded text-[11px] font-bold border',
                    f.diff_type === 'EQUAL' ? 'ui-pill' :
                    f.diff_type === 'CHANGED' ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/35' :
                    f.diff_type === 'ADDED_IN_B' ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/35' :
                    'bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-500/35']">
                    {{ f.diff_type === 'EQUAL' ? '一致' : f.diff_type === 'CHANGED' ? '差异' : f.diff_type === 'ADDED_IN_B' ? 'B 新增' : 'B 缺失' }}
                  </span>
                </td>
              </tr>
              <tr v-if="!diffResult?.field_diffs || diffResult.field_diffs.length === 0">
                <td colspan="5" class="p-10">
                  <EmptyState icon="layers" title="暂无元数据与规约字段差异" description="请确保载入的两组样本包含同一协议层的可解构字段。" />
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- 模式三：自由草稿即时比对工作台 (支持 2 组、3 组、4 组及以上自由扩增) -->
        <div v-show="activeMode === 'scratchpad'" class="h-full overflow-auto p-5 space-y-4 custom-scrollbar">
          <div class="flex items-center justify-between ui-sub-card p-3 flex-wrap gap-2">
            <div class="flex items-center gap-2 text-xs flex-wrap">
              <span class="flex items-center gap-1 font-medium" style="color: var(--text-secondary)">
                <AppIcon name="zap" :size="13" />
                <span>快速载入工业规约样本:</span>
              </span>
              <button @click="loadPresetPair('MODBUS')"
                class="px-2.5 py-1 rounded-lg bg-indigo-500/12 hover:bg-indigo-500/20 text-indigo-700 dark:text-indigo-300 border border-indigo-500/30 text-[11px] ui-num cursor-pointer transition-colors">
                Modbus (2组)
              </button>
              <button @click="loadPresetPair('MODBUS_MULTI3')"
                class="px-2.5 py-1 rounded-lg bg-emerald-500/12 hover:bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30 text-[11px] ui-num cursor-pointer transition-colors font-semibold">
                Modbus 含前插与尾缺 (3组)
              </button>
              <button @click="loadPresetPair('TCP_HANDSHAKE')"
                class="px-2.5 py-1 rounded-lg bg-blue-500/12 hover:bg-blue-500/20 text-blue-700 dark:text-blue-300 border border-blue-500/30 text-[11px] ui-num cursor-pointer transition-colors">
                TCP 握手 (2组)
              </button>
              <button @click="loadPresetPair('HTTP')"
                class="px-2.5 py-1 rounded-lg bg-purple-500/12 hover:bg-purple-500/20 text-purple-700 dark:text-purple-300 border border-purple-500/30 text-[11px] ui-num cursor-pointer transition-colors">
                HTTP 请求 (2组)
              </button>
              <button @click="loadPresetPair('DLT645')"
                class="px-2.5 py-1 rounded-lg bg-teal-500/12 hover:bg-teal-500/20 text-teal-700 dark:text-teal-300 border border-teal-500/30 text-[11px] ui-num cursor-pointer transition-colors">
                DLT645 电力 (2组)
              </button>
            </div>
            <div class="flex items-center gap-2">
              <button @click="addScratchpadSlot" class="ui-btn-secondary text-xs py-1.5 px-3 rounded-xl">
                <AppIcon name="plus" :size="13" />
                <span>新增比对组 ({{ diffBus.scratchpadList.value.length }})</span>
              </button>
              <button @click="executeScratchpadCompare" class="ui-btn-primary text-xs py-1.5 px-4 rounded-xl">
                <AppIcon name="zap" :size="13" />
                <span>{{ diffBus.scratchpadList.value.length >= 3 ? `执行 ${diffBus.scratchpadList.value.length} 组 Center-Star 对齐` : '执行差分与波形计算' }}</span>
              </button>
            </div>
          </div>

          <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div v-for="(slot, idx) in diffBus.scratchpadList.value" :key="idx"
              class="ui-sub-card p-4 flex flex-col space-y-2 min-h-[220px]">
              <div class="flex items-center justify-between text-xs pb-1.5 border-b gap-2" style="border-color: var(--border-subtle)">
                <div class="flex items-center gap-2 min-w-0">
                  <span class="w-2.5 h-2.5 rounded-full shrink-0"
                    :class="idx === 0 ? 'bg-blue-500' : idx === 1 ? 'bg-indigo-500' : idx === 2 ? 'bg-emerald-500' : 'bg-amber-500'"></span>
                  <input v-model="slot.label" type="text"
                    class="bg-transparent font-bold text-xs outline-none border-b border-transparent focus:border-indigo-500/50 w-36 truncate"
                    style="color: var(--text-primary)" />
                  <span class="text-[11px] ui-num shrink-0" style="color: var(--text-muted)">
                    {{ slot.text.length }} 字符 | {{ calcByteLength(slot.text) }} 字节
                  </span>
                </div>
                <div class="flex items-center gap-1.5 shrink-0">
                  <button @click="formatScratchpadSlotHex(idx)" class="px-2 py-0.5 rounded ui-pill text-[11px] cursor-pointer">
                    规整 Hex
                  </button>
                  <button @click="slot.text = ''" class="px-2 py-0.5 rounded ui-pill hover:text-rose-600 dark:hover:text-rose-400 text-[11px] cursor-pointer">
                    清空
                  </button>
                  <button v-if="diffBus.scratchpadList.value.length > 2" @click="removeScratchpadSlot(idx)"
                    class="px-2 py-0.5 rounded ui-pill hover:text-rose-600 dark:hover:text-rose-400 text-[11px] cursor-pointer"
                    title="移除该草稿组">
                    移除
                  </button>
                </div>
              </div>
              <textarea v-model="slot.text"
                placeholder="在此直接粘贴十六进制码流 (例如: 01 03 00 00 00 02 C4 0B) 或任意 ASCII 字符串..."
                class="flex-1 w-full min-h-[148px] ui-input font-mono-code text-xs p-3 resize-none custom-scrollbar leading-relaxed"></textarea>
            </div>
          </div>
        </div>

        <!-- 模式四：载荷波线与变异波率分析 -->
        <div v-show="activeMode === 'wave'" class="h-full overflow-auto p-5 space-y-4 custom-scrollbar">
          <div v-if="diffResult?.waveform_metrics" class="grid grid-cols-2 md:grid-cols-5 gap-3 ui-num">
            <div class="ui-sub-card p-3 flex flex-col justify-between">
              <span class="text-[11px] font-sans" style="color: var(--text-muted)">余弦几何相似度 (Cosine)</span>
              <div class="flex items-baseline justify-between mt-1">
                <span class="text-lg font-bold text-sky-700 dark:text-cyan-300">
                  {{ (diffResult.waveform_metrics.cosine_similarity * 100).toFixed(1) }}%
                </span>
                <span class="text-[11px]" style="color: var(--text-muted)">0~100%</span>
              </div>
              <span class="text-[11px] mt-1.5 truncate font-sans" style="color: var(--text-secondary)">
                {{ diffResult.waveform_metrics.cosine_similarity >= 0.95 ? '高度同构' : diffResult.waveform_metrics.cosine_similarity >= 0.7 ? '局部相似' : '结构显著差异' }}
              </span>
            </div>

            <div class="ui-sub-card p-3 flex flex-col justify-between">
              <span class="text-[11px] font-sans" style="color: var(--text-muted)">皮尔逊相关系数 (Pearson)</span>
              <div class="flex items-baseline justify-between mt-1">
                <span class="text-lg font-bold" :class="diffResult.waveform_metrics.pearson_correlation >= 0.7 ? 'text-emerald-700 dark:text-emerald-400' : ''" :style="diffResult.waveform_metrics.pearson_correlation < 0.7 ? { color: 'var(--text-primary)' } : undefined">
                  {{ diffResult.waveform_metrics.pearson_correlation.toFixed(3) }}
                </span>
                <span class="text-[11px]" style="color: var(--text-muted)">-1.0~+1.0</span>
              </div>
              <span class="text-[11px] mt-1.5 truncate font-sans" style="color: var(--text-secondary)">
                {{ diffResult.waveform_metrics.pearson_correlation >= 0.8 ? '高度同向波动' : diffResult.waveform_metrics.pearson_correlation >= 0.3 ? '中度协同' : '弱相关/畸变' }}
              </span>
            </div>

            <div class="ui-sub-card p-3 flex flex-col justify-between">
              <span class="text-[11px] font-sans" style="color: var(--text-muted)">变异波率 (Mutation Rate)</span>
              <div class="flex items-baseline justify-between mt-1">
                <span class="text-lg font-bold" :class="diffResult.waveform_metrics.mutation_wave_rate > 30 ? 'text-rose-700 dark:text-rose-400' : 'text-amber-700 dark:text-amber-300'">
                  {{ diffResult.waveform_metrics.mutation_wave_rate.toFixed(1) }}%
                </span>
                <span class="text-[11px]" style="color: var(--text-muted)">突变点占比</span>
              </div>
              <div class="w-full h-1.5 rounded-full mt-2 overflow-hidden" style="background: var(--surface-elevated)">
                <div class="h-full rounded-full transition-all" :class="diffResult.waveform_metrics.mutation_wave_rate > 30 ? 'bg-rose-500' : 'bg-amber-500'"
                  :style="{ width: `${Math.min(100, diffResult.waveform_metrics.mutation_wave_rate)}%` }"></div>
              </div>
            </div>

            <div class="ui-sub-card p-3 flex flex-col justify-between">
              <span class="text-[11px] font-sans" style="color: var(--text-muted)">最大跳变峰 (Peak Delta)</span>
              <div class="flex items-baseline justify-between mt-1">
                <span class="text-lg font-bold text-rose-700 dark:text-rose-400">
                  Δ{{ diffResult.waveform_metrics.max_delta_value }}
                </span>
                <span class="text-[11px] text-indigo-700 dark:text-indigo-300 bg-indigo-500/15 px-1.5 py-0.5 rounded border border-indigo-500/25">
                  0x{{ diffResult.waveform_metrics.max_delta_offset.toString(16).toUpperCase() }}
                </span>
              </div>
              <span class="text-[11px] mt-1.5 truncate font-sans" style="color: var(--text-secondary)">
                发生于偏移量 #{{ diffResult.waveform_metrics.max_delta_offset }}
              </span>
            </div>

            <div class="ui-sub-card p-3 flex flex-col justify-between">
              <span class="text-[11px] font-sans" style="color: var(--text-muted)">平均绝对振幅差 (MAD)</span>
              <div class="flex items-baseline justify-between mt-1">
                <span class="text-lg font-bold text-purple-700 dark:text-purple-300">
                  {{ diffResult.waveform_metrics.mean_absolute_deviation.toFixed(1) }}
                </span>
                <span class="text-[11px]" style="color: var(--text-muted)">/255</span>
              </div>
              <span class="text-[11px] mt-1.5 truncate font-sans" style="color: var(--text-secondary)">
                全字节平均差异震级
              </span>
            </div>
          </div>

          <div class="ui-sub-card p-4 space-y-3">
            <div class="flex items-center justify-between text-xs pb-1.5 border-b flex-wrap gap-2" style="border-color: var(--border-subtle)">
              <div class="flex items-center gap-3 ui-num">
                <span class="font-bold font-sans text-xs" style="color: var(--text-primary)">载荷逐字节数值波线叠加对照 (Byte Value Waveform)</span>
                <span class="flex items-center gap-1.5 text-[11px] text-sky-700 dark:text-cyan-400">
                  <span class="w-2.5 h-1 bg-sky-500 rounded-full inline-block"></span>
                  <span>基准样本 A</span>
                </span>
                <span class="flex items-center gap-1.5 text-[11px] text-purple-700 dark:text-purple-400">
                  <span class="w-2.5 h-1 bg-purple-500 rounded-full inline-block"></span>
                  <span>比对样本 B</span>
                </span>
              </div>
              <div v-if="hoverPoint" class="text-[11px] ui-num flex items-center gap-2 px-2.5 py-1 rounded-lg border" style="background: var(--surface-content); border-color: var(--border-subtle)">
                <span style="color: var(--text-muted)">偏移: <strong style="color: var(--text-primary)">0x{{ hoverPoint.offset.toString(16).toUpperCase() }} ({{ hoverPoint.offset }})</strong></span>
                <span class="text-sky-700 dark:text-cyan-400">A: 0x{{ hoverPoint.val_a.toString(16).padStart(2,'0').toUpperCase() }} ({{ hoverPoint.val_a }})</span>
                <span class="text-purple-700 dark:text-purple-400">B: 0x{{ hoverPoint.val_b.toString(16).padStart(2,'0').toUpperCase() }} ({{ hoverPoint.val_b }})</span>
                <span :class="hoverPoint.delta !== 0 ? 'text-rose-700 dark:text-rose-400 font-bold' : ''" :style="hoverPoint.delta === 0 ? { color: 'var(--text-muted)' } : undefined">Δ: {{ hoverPoint.delta > 0 ? '+' : '' }}{{ hoverPoint.delta }}</span>
              </div>
              <span v-else class="text-[11px]" style="color: var(--text-muted)">移动鼠标至图表激活十字探针</span>
            </div>

            <div class="h-56 rounded-xl border relative overflow-hidden flex items-center justify-center" style="background: var(--surface-input); border-color: var(--border-subtle)">
              <canvas ref="diffWaveCanvas" @mousemove="onWaveMouseMove" @mouseleave="hoverPoint = null" class="w-full h-full cursor-crosshair"></canvas>
            </div>
          </div>

          <div class="ui-sub-card p-4 space-y-3">
            <div class="flex items-center justify-between text-xs pb-1.5 border-b flex-wrap gap-2" style="border-color: var(--border-subtle)">
              <div class="flex items-center gap-2">
                <span class="font-bold text-xs" style="color: var(--text-primary)">逐字节偏差振幅谱与变异密度 (|Δ| Amplitude Spectrum)</span>
                <span class="text-[11px]" style="color: var(--text-muted)">点击柱位可切换 Hex 查看对应字节</span>
              </div>
              <div class="flex items-center gap-3 text-[11px]" style="color: var(--text-secondary)">
                <span class="flex items-center gap-1"><span class="w-2 h-2 rounded bg-slate-500"></span> 0 一致</span>
                <span class="flex items-center gap-1"><span class="w-2 h-2 rounded bg-amber-500"></span> 1~64 微变</span>
                <span class="flex items-center gap-1"><span class="w-2 h-2 rounded bg-orange-500"></span> 65~128 中变</span>
                <span class="flex items-center gap-1"><span class="w-2 h-2 rounded bg-rose-500"></span> >128 强突变</span>
              </div>
            </div>

            <div class="h-36 rounded-xl border relative overflow-hidden flex items-center justify-center" style="background: var(--surface-input); border-color: var(--border-subtle)">
              <canvas ref="deltaSpectrumCanvas" @mousemove="onDeltaMouseMove" @click="onDeltaSpectrumClick" @mouseleave="hoverDelta = null" class="w-full h-full cursor-pointer"></canvas>
            </div>
          </div>
        </div>

        <!-- 模式五：报文特征样本库管理 -->
        <div v-show="activeMode === 'samples'" class="h-full overflow-auto p-5 space-y-3 custom-scrollbar">
          <div class="flex items-center justify-between border-b pb-2.5" style="border-color: var(--border-subtle)">
            <div class="text-xs" style="color: var(--text-secondary)">
              已固化报文样本库 (共 <strong style="color: var(--text-primary)">{{ storedSamples.length }}</strong> 笔历史样本)
            </div>
            <button @click="loadStoredSamples" class="ui-btn-secondary text-xs py-1 px-3 rounded-xl">
              <AppIcon name="refresh" :size="13" />
              <span>刷新</span>
            </button>
          </div>

          <div class="grid grid-cols-1 md:grid-cols-2 gap-3 select-text">
            <div v-for="s in storedSamples" :key="s.id"
              class="ui-sub-card p-3 flex flex-col gap-2 hover:border-sky-500/40 transition-colors">
              <div class="flex items-center justify-between gap-2">
                <span class="font-bold text-xs truncate max-w-[280px]" style="color: var(--text-primary)" :title="s.name">{{ s.name }}</span>
                <span class="text-[11px] ui-num shrink-0" style="color: var(--text-muted)">{{ s.created_at }}</span>
              </div>
              <div class="text-[11px] ui-num p-2 rounded-lg border" style="background: var(--surface-content); border-color: var(--border-subtle); color: var(--text-secondary)">
                <div>样本: #{{ s.packet.id || '-' }} | 规约: <strong class="text-indigo-700 dark:text-indigo-300">{{ s.packet.protocol || 'RAW' }}</strong> | 长度: {{ s.packet.length || 0 }} 字节</div>
                <div>端点: {{ s.packet.src_ip || '-' }}:{{ s.packet.src_port || 0 }} → {{ s.packet.dst_ip || '-' }}:{{ s.packet.dst_port || 0 }}</div>
              </div>
              <div class="flex items-center justify-end gap-2 pt-1 flex-wrap">
                <button @click="queueSampleToMulti(s)"
                  class="text-[11px] bg-emerald-500/12 hover:bg-emerald-500 text-emerald-700 dark:text-emerald-200 hover:text-white px-2.5 py-1 rounded-lg border border-emerald-500/35 cursor-pointer transition-colors font-medium">
                  + 加入多组队列
                </button>
                <button @click="loadSampleAs('A', s.packet)"
                  class="text-[11px] bg-blue-500/12 hover:bg-blue-500 text-blue-700 dark:text-blue-200 hover:text-white px-2.5 py-1 rounded-lg border border-blue-500/35 cursor-pointer transition-colors font-medium">
                  载入为基准 A
                </button>
                <button @click="loadSampleAs('B', s.packet)"
                  class="text-[11px] bg-indigo-500/12 hover:bg-indigo-500 text-indigo-700 dark:text-indigo-200 hover:text-white px-2.5 py-1 rounded-lg border border-indigo-500/35 cursor-pointer transition-colors font-medium">
                  载入为比对 B
                </button>
                <button @click="doDeleteSample(s.id)"
                  class="ui-btn-danger text-[11px] py-1 px-2.5 rounded-lg">
                  删除
                </button>
              </div>
            </div>
            <div v-if="storedSamples.length === 0" class="col-span-full py-10">
              <EmptyState icon="database" title="样本库为空" description="在上方双样本对照栏点击【存为样本】即可将基准数据持久化入库。" />
            </div>
          </div>
        </div>

        <!-- 模式六：Beyond Compare 级流式磁盘大文件 Myers Diff、GB级二进制分块页对比、目录树比较与双向原子合并 -->
        <div v-show="activeMode === 'file_merge'" class="h-full overflow-hidden">
          <FileDiffMergeWorkspace />
        </div>

      </div>

      <!-- 4. 底部状态与操作栏 -->
      <footer class="px-5 py-2.5 border-t flex items-center justify-between text-xs shrink-0 ui-num" style="background: var(--surface-content-alt); border-color: var(--border-subtle); color: var(--text-secondary)">
        <div class="flex items-center gap-3 flex-wrap">
          <span class="flex items-center gap-1.5">
            <span class="w-2.5 h-2.5 rounded bg-slate-500"></span>
            <span>冷灰: 一致匹配</span>
          </span>
          <span class="flex items-center gap-1.5">
            <span class="w-2.5 h-2.5 rounded bg-rose-500"></span>
            <span>玫瑰红: 数值突变/替换</span>
          </span>
          <span class="flex items-center gap-1.5">
            <span class="w-2.5 h-2.5 rounded bg-emerald-500"></span>
            <span>翡翠绿: 突变插入</span>
          </span>
          <span class="flex items-center gap-1.5">
            <span class="w-2.5 h-2.5 rounded bg-amber-500"></span>
            <span>琥珀金: 缺失/删除</span>
          </span>
        </div>

        <button @click="handleClose" class="ui-btn-secondary text-xs py-1.5 px-4 rounded-xl font-semibold">
          关闭视窗
        </button>
      </footer>

    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, defineAsyncComponent, onMounted, onUnmounted, nextTick } from 'vue';
import { notifySuccess, notifyInfo, notifyError } from '../composables/useNotification';
import { useUniversalDiff, normalizeToDiffableItem, type UniversalDiffItem, type DiffViewMode } from '../composables/useUniversalDiff';
import { uiConfirm, uiPrompt } from '../composables/useConfirmDialog';
import AppIcon from './AppIcon.vue';
import EmptyState from './EmptyState.vue';
import { invoke } from '@tauri-apps/api/core';
import { saveTextViaNativeDesktop } from '../composables/useDesktopSave';

const FileDiffMergeWorkspace = defineAsyncComponent(() => import('./FileDiffMergeWorkspace.vue'));

const isDarkTheme = ref(!document.documentElement.classList.contains('theme-apple-light'));
let themeObserver: MutationObserver | null = null;

export interface ByteCell {
  hex: string;
  ascii: string;
  diff_type: string; // "equal"|"replace"|"insert"|"delete"|"missing"
}

export interface HexRow {
  offset: string;
  cells: ByteCell[];
  ascii_repr: string;
}

export interface ParsedPayload {
  label: string;
  byte_length: number;
  hex_rows: HexRow[];
}

export interface FieldDiffItem {
  layer: string;
  field_name: string;
  val_a: string;
  val_b: string;
  is_different: boolean;
  diff_type: string;
}

export interface DiffWaveformPoint {
  offset: number;
  val_a: number;
  val_b: number;
  delta: number;
  is_mutated: boolean;
}

export interface WaveformComparisonMetrics {
  cosine_similarity: number;
  pearson_correlation: number;
  mean_absolute_deviation: number;
  max_delta_offset: number;
  max_delta_value: number;
  mutation_wave_rate: number;
  waveform_points: DiffWaveformPoint[];
}

export interface DualPacketDiffResult {
  packet_a_id: number;
  packet_b_id: number;
  packet_a_desc: string;
  packet_b_desc: string;
  total_bytes_a: number;
  total_bytes_b: number;
  mutated_bytes_count: number;
  mutation_rate_percent: number;
  hex_diff_a: ParsedPayload;
  hex_diff_b: ParsedPayload;
  field_diffs: FieldDiffItem[];
  summary: string;
  waveform_metrics?: WaveformComparisonMetrics;
}

export interface MutationWaveBin {
  offset: number;
  mutation_rate: number;
  unique_values_count: number;
  entropy: number;
  dominant_hex: string;
}

export interface MultiDiffSampleSummary {
  sample_index: number;
  label: string;
  protocol: string;
  endpoint_src: string;
  endpoint_dst: string;
  byte_length: number;
  mutated_vs_anchor: number;
  mutation_rate_vs_anchor: number;
  cosine_similarity_vs_anchor: number;
  aligned_hex: ParsedPayload;
}

export interface MultiFieldDiffRow {
  layer: string;
  field_name: string;
  values: string[];
  has_difference: boolean;
}

export interface MultiUniversalDiffResult {
  sample_count: number;
  anchor_index: number;
  aligned_column_count: number;
  samples: MultiDiffSampleSummary[];
  field_matrix: MultiFieldDiffRow[];
  aligned_mutation_spectrum: MutationWaveBin[];
  summary: string;
}

export interface StoredPacketSample {
  id: string;
  name: string;
  created_at: string;
  packet: any;
}

const props = withDefaults(defineProps<{
  isOpen?: boolean;
  packetA?: any | null;
  packetB?: any | null;
}>(), {
  isOpen: undefined,
  packetA: null,
  packetB: null
});

const emit = defineEmits(['close', 'selectAsA', 'selectAsB', 'appendLog']);

const diffBus = useUniversalDiff();

// 打开状态：优先取 props，若未传则响应全局比对总线
const activeIsOpen = computed(() => {
  if (props.isOpen !== undefined) return props.isOpen;
  return diffBus.isDiffModalOpen.value;
});

// 与全局总线实时双向同步，根除外部页签直达失灵缺陷
const activeMode = computed<DiffViewMode>({
  get: () => diffBus.activeMode.value,
  set: (v: DiffViewMode) => { diffBus.activeMode.value = v; }
});

const diffResult = ref<DualPacketDiffResult | null>(null);
const multiResult = ref<MultiUniversalDiffResult | null>(null);
const multiError = ref<string | null>(null);
const multiOnlyDiffFields = ref(false);
const storedSamples = ref<StoredPacketSample[]>([]);

interface MultiDiffPatchReport {
  anchor_index: number;
  anchor_label: string;
  anchor_byte_length: number;
  anchor_sha256: string;
  samples: Array<{
    sample_index: number;
    sample_label: string;
    target_byte_length: number;
    target_sha256: string;
    total_hunks: number;
    hunks: Array<{
      hunk_index: number;
      op_kind: string;
      anchor_offset: number;
      anchor_len: number;
      target_len: number;
      anchor_hex: string;
      target_hex: string;
      semantic_hint: string;
    }>;
  }>;
  hex_revision_script: string;
  python_patch_script: string;
}

const multiPatchReport = ref<MultiDiffPatchReport | null>(null);
const isGeneratingPatch = ref(false);
const patchPreviewFormat = ref<'hex' | 'python'>('hex');

// 草稿即时比对文本代理（与 diffBus.scratchpadList 前两项双向关联，向后兼容）
const scratchTextA = computed({
  get: () => diffBus.scratchpadList.value[0]?.text ?? '',
  set: (v: string) => {
    if (!diffBus.scratchpadList.value[0]) {
      diffBus.scratchpadList.value.push({ label: '草稿组 #1 (基准)', text: v });
    } else {
      diffBus.scratchpadList.value[0].text = v;
    }
    diffBus.scratchpadTextA.value = v;
  }
});
const scratchTextB = computed({
  get: () => diffBus.scratchpadList.value[1]?.text ?? '',
  set: (v: string) => {
    while (diffBus.scratchpadList.value.length < 2) {
      diffBus.scratchpadList.value.push({ label: `草稿组 #${diffBus.scratchpadList.value.length + 1}`, text: '' });
    }
    diffBus.scratchpadList.value[1].text = v;
    diffBus.scratchpadTextB.value = v;
  }
});

// 归一化生效数据项（解耦 props 硬覆盖死锁，统一走 diffBus 槽位）
const effectiveItemA = computed<UniversalDiffItem | null>(() => {
  if (diffBus.currentItemA.value) return diffBus.currentItemA.value;
  if (scratchTextA.value) return normalizeToDiffableItem(scratchTextA.value, '草稿组 #1');
  return null;
});

const effectiveItemB = computed<UniversalDiffItem | null>(() => {
  if (diffBus.currentItemB.value) return diffBus.currentItemB.value;
  if (scratchTextB.value) return normalizeToDiffableItem(scratchTextB.value, '草稿组 #2');
  return null;
});

// 波形与多组对齐光谱 Canvas 引用及交互探针
const diffWaveCanvas = ref<HTMLCanvasElement | null>(null);
const deltaSpectrumCanvas = ref<HTMLCanvasElement | null>(null);
const multiSpectrumCanvas = ref<HTMLCanvasElement | null>(null);
const hoverPoint = ref<DiffWaveformPoint | null>(null);
const hoverDelta = ref<DiffWaveformPoint | null>(null);
const hoverMultiBin = ref<MutationWaveBin | null>(null);

// 同步滚动相关引用与标记
const hexScrollA = ref<HTMLElement | null>(null);
const hexScrollB = ref<HTMLElement | null>(null);
let isSyncingA = false;
let isSyncingB = false;

function onScrollA() {
  if (isSyncingA || !hexScrollA.value || !hexScrollB.value) return;
  isSyncingB = true;
  hexScrollB.value.scrollTop = hexScrollA.value.scrollTop;
  requestAnimationFrame(() => { isSyncingB = false; });
}

function onScrollB() {
  if (isSyncingB || !hexScrollA.value || !hexScrollB.value) return;
  isSyncingA = true;
  hexScrollA.value.scrollTop = hexScrollB.value.scrollTop;
  requestAnimationFrame(() => { isSyncingA = false; });
}

function getCellClass(diffType: string): string {
  if (diffType === 'replace') {
    return 'bg-rose-600 text-white font-bold shadow-xs';
  }
  if (diffType === 'insert') {
    return 'bg-emerald-600 text-white font-bold shadow-xs';
  }
  if (diffType === 'delete' || diffType === 'missing') {
    return 'bg-amber-500/25 text-amber-800 dark:text-amber-300 border border-amber-500/45 font-bold';
  }
  return 'text-[var(--text-muted)] hover:text-[var(--text-primary)]';
}

const differentFieldsCount = computed(() => {
  if (!diffResult.value?.field_diffs) return 0;
  return diffResult.value.field_diffs.filter(f => f.is_different).length;
});

const multiAvgMutationRate = computed(() => {
  if (!multiResult.value || multiResult.value.samples.length <= 1) return 0;
  const nonAnchor = multiResult.value.samples.filter(s => s.sample_index !== multiResult.value?.anchor_index);
  if (nonAnchor.length === 0) return 0;
  const sum = nonAnchor.reduce((acc, s) => acc + s.mutation_rate_vs_anchor, 0);
  return sum / nonAnchor.length;
});

const multiHexBlocks = computed(() => {
  if (!multiResult.value || multiResult.value.samples.length === 0) return [];
  const samples = multiResult.value.samples;
  const maxRows = Math.max(...samples.map(s => s.aligned_hex?.hex_rows?.length || 0), 0);
  const blocks: Array<{
    blockIndex: number;
    offsetHex: string;
    colIndices: number[];
    sampleRows: Array<{
      sampleIndex: number;
      label: string;
      cells: ByteCell[];
      ascii: string;
    }>;
  }> = [];

  for (let rIdx = 0; rIdx < maxRows; rIdx++) {
    const rowCols = Math.max(...samples.map(s => s.aligned_hex?.hex_rows?.[rIdx]?.cells?.length || 0), 0);
    const colIndices = Array.from({ length: rowCols }, (_, idx) => idx);
    const firstValidRow = samples.find(s => s.aligned_hex?.hex_rows?.[rIdx])?.aligned_hex?.hex_rows?.[rIdx];
    const offsetHex = firstValidRow?.offset || `0x${(rIdx * 16).toString(16).toUpperCase().padStart(4, '0')}`;
    const sampleRows = samples.map(s => {
      const hr = s.aligned_hex?.hex_rows?.[rIdx];
      return {
        sampleIndex: s.sample_index,
        label: s.label,
        cells: hr?.cells || [],
        ascii: hr?.ascii_repr || ''
      };
    });
    blocks.push({ blockIndex: rIdx, offsetHex, colIndices, sampleRows });
  }
  return blocks;
});

const filteredMultiFieldMatrix = computed(() => {
  if (!multiResult.value?.field_matrix) return [];
  if (!multiOnlyDiffFields.value) return multiResult.value.field_matrix;
  return multiResult.value.field_matrix.filter(r => r.has_difference);
});

function toBackendDiffPayload(item: UniversalDiffItem, fallbackLabel: string) {
  return {
    id: typeof item.id === 'number' ? item.id : undefined,
    label: item.label || fallbackLabel,
    timestamp: item.timestamp,
    protocol: item.protocol,
    endpoint_src: item.src,
    endpoint_dst: item.dst,
    payload_hex: item.payloadHex || '',
    raw_text: item.rawText || '',
    extra_fields: item.extraFields || {}
  };
}

function handleClose() {
  emit('close');
  diffBus.closeUniversalDiff();
}

function switchMode(mode: DiffViewMode) {
  diffBus.activeMode.value = mode;
  if (mode === 'wave') {
    nextTick(() => {
      drawDiffWaveform();
      drawDeltaSpectrum();
    });
  } else if (mode === 'multi') {
    runMultiCompare();
  }
}

async function runCompare() {
  const itemA = effectiveItemA.value;
  const itemB = effectiveItemB.value;
  if (!itemA || !itemB) return;

  try {
    const res = await invoke<DualPacketDiffResult>('compare_universal_payloads_cmd', {
      itemA: toBackendDiffPayload(itemA, '样本 A'),
      itemB: toBackendDiffPayload(itemB, '样本 B')
    });
    diffResult.value = res;
    if (activeMode.value === 'wave') {
      await nextTick();
      drawDiffWaveform();
      drawDeltaSpectrum();
    }
  } catch (e: any) {
    console.error('通用深度差分与波形比对失败:', e);
  }
}

async function runMultiCompare() {
  multiError.value = null;
  multiPatchReport.value = null;
  const queue = diffBus.diffQueue.value;
  if (queue.length < 2) {
    multiResult.value = null;
    return;
  }
  try {
    const items = queue.map((item, idx) => toBackendDiffPayload(item, `样本 #${idx + 1}`));
    const res = await invoke<MultiUniversalDiffResult>('compare_multi_universal_payloads_cmd', {
      items,
      anchorIndex: diffBus.anchorIndex.value
    });
    multiResult.value = res;
    if (activeMode.value === 'multi') {
      await nextTick();
      drawMultiSpectrum();
    }
  } catch (e: any) {
    const msg = e?.message || String(e);
    multiError.value = `Center-Star 多组对齐调用受阻: ${msg}（请确认已运行于 Omni-Probe Tauri 原生引擎内核环境）`;
    console.error('多组 Center-Star 对齐比对失败:', e);
  }
}

async function generateMultiPatchScript() {
  const queue = diffBus.diffQueue.value;
  if (queue.length < 2) return;
  isGeneratingPatch.value = true;
  try {
    const items = queue.map((item, idx) => toBackendDiffPayload(item, `样本 #${idx + 1}`));
    multiPatchReport.value = await invoke<MultiDiffPatchReport>('export_multi_diff_patch_cmd', {
      items,
      anchorIndex: diffBus.anchorIndex.value,
    });
    notifySuccess('Multi-Diff Patch 脚本生成完毕', `已基于基准 #${diffBus.anchorIndex.value + 1} 聚合并导出差异修订脚本`);
  } catch (e) {
    notifyError('Patch 修订脚本生成失败', String(e));
  } finally {
    isGeneratingPatch.value = false;
  }
}

function copyMultiPatchScript() {
  if (!multiPatchReport.value) return;
  const content = patchPreviewFormat.value === 'python'
    ? multiPatchReport.value.python_patch_script
    : multiPatchReport.value.hex_revision_script;
  navigator.clipboard.writeText(content);
  notifySuccess('已复制到剪贴板', patchPreviewFormat.value === 'python' ? 'Python 3 可逆复现脚本已拷贝' : 'Hex 修订摘要指令已拷贝');
}

async function downloadMultiPatchScript() {
  if (!multiPatchReport.value) return;
  const isPy = patchPreviewFormat.value === 'python';
  const content = isPy ? multiPatchReport.value.python_patch_script : multiPatchReport.value.hex_revision_script;
  const fname = isPy ? `omni_multi_patch_${Date.now()}.py` : `omni_multi_revision_${Date.now()}.patch`;
  await saveTextViaNativeDesktop(
    fname,
    content,
    isPy ? 'Python 修订脚本 (*.py)' : 'Patch 修订汇编 (*.patch;*.txt)',
    isPy ? '*.py' : '*.patch;*.txt',
    '导出多组差分修订脚本'
  );
}

function selectMultiAnchor(idx: number) {
  diffBus.setAnchorIndex(idx);
  runMultiCompare();
}

function removeMultiQueueItem(idx: number) {
  diffBus.removeFromQueue(idx);
  runMultiCompare();
  runCompare();
}

function clearMultiQueue() {
  diffBus.clearSlots();
  diffResult.value = null;
  multiResult.value = null;
}

function loadMultiPreset3Group() {
  const presetItems = [
    {
      id: 1,
      label: 'Modbus-RTU 请求帧 (#1)',
      protocol: 'MODBUS-RTU',
      endpoint_src: 'COM3:Master',
      endpoint_dst: 'Slave-01',
      payload_hex: '01 03 00 00 00 02 C4 0B'
    },
    {
      id: 2,
      label: '网关前插头部帧 (#2)',
      protocol: 'MODBUS-RTU',
      endpoint_src: 'GW-Proxy',
      endpoint_dst: 'Slave-01',
      payload_hex: 'AA 01 03 00 00 00 04 C4 0B'
    },
    {
      id: 3,
      label: '校验截断异常帧 (#3)',
      protocol: 'MODBUS-RTU',
      endpoint_src: 'COM3:Master',
      endpoint_dst: 'Slave-01',
      payload_hex: '01 03 00 01 00 02'
    }
  ];
  diffBus.scratchpadList.value = [
    { label: presetItems[0].label, text: presetItems[0].payload_hex },
    { label: presetItems[1].label, text: presetItems[1].payload_hex },
    { label: presetItems[2].label, text: presetItems[2].payload_hex }
  ];
  diffBus.openMultiDiff(presetItems, 0, 'multi');
  notifySuccess('已载入 3 组变长演练样本', '已按 Center-Star 算法自动对齐前插 0xAA 与尾部缺失 "--" 槽位');
}

async function loadStoredSamples() {
  try {
    const res = await invoke<StoredPacketSample[]>('list_packet_samples_cmd');
    storedSamples.value = res || [];
  } catch (e: any) {
    console.error('加载报文样本库失败:', e);
  }
}

function queueSampleToMulti(sample: StoredPacketSample) {
  diffBus.addToQueue(sample.packet, sample.name || `样本 #${sample.packet?.id || ''}`, false);
  if (diffBus.queueCount.value >= 2) {
    runMultiCompare();
  }
}

function loadSampleAs(slot: 'A' | 'B', packet: any) {
  if (slot === 'A') {
    emit('selectAsA', packet);
    diffBus.setSlotA(packet, `样本库 #${packet.id || ''}`);
  } else {
    emit('selectAsB', packet);
    diffBus.setSlotB(packet, `样本库 #${packet.id || ''}`);
  }
  notifyInfo('已载入样本', `已载入样本 #${packet.id || ''} 至槽位 ${slot}`);
  runCompare();
  runMultiCompare();
}

async function doSaveItemSample(item: UniversalDiffItem, slot: 'A' | 'B') {
  const defaultName = `样本_${item.protocol || 'DATA'}_${slot}_${Date.now().toString().slice(-4)}`;
  const name = await uiPrompt('请输入该特征样本归档名称：', defaultName, {
    title: '保存特征样本',
    placeholder: '输入归档名称...',
  });
  if (!name) return;
  try {
    await invoke('save_packet_sample_cmd', {
      name: name.trim(),
      packet: {
        id: item.id || Date.now(),
        protocol: item.protocol || 'GENERIC',
        src_ip: item.src?.split(':')[0] || '127.0.0.1',
        src_port: Number(item.src?.split(':')[1]) || 0,
        dst_ip: item.dst?.split(':')[0] || '127.0.0.1',
        dst_port: Number(item.dst?.split(':')[1]) || 0,
        length: item.length || 0,
        payload_hex: item.payloadHex || '',
        timestamp: item.timestamp || new Date().toISOString()
      }
    });
    await loadStoredSamples();
    notifySuccess('样本固化成功', `特征已成功归档入库: ${name}`);
  } catch (e: any) {
    notifyError('保存特征样本失败', e);
  }
}

async function doDeleteSample(id: string) {
  const ok = await uiConfirm('确定要删除此份历史报文样本吗？删除后将无法恢复。', {
    title: '删除报文样本',
    danger: true,
    confirmText: '确认删除',
  });
  if (!ok) return;
  try {
    await invoke('delete_packet_sample_cmd', { id });
    await loadStoredSamples();
    notifyInfo('特征样本已移除', '该样本已从本地样本库中安全删除');
  } catch (e: any) {
    notifyError('删除特征样本失败', e);
  }
}

function swapItems() {
  diffBus.swapSlots();
  const tTxt = scratchTextA.value;
  scratchTextA.value = scratchTextB.value;
  scratchTextB.value = tTxt;
  runCompare();
  runMultiCompare();
}

function calcByteLength(text: string): number {
  const clean = text.replace(/[\s\r\n\t]/g, '');
  if (/^[0-9a-fA-F]+$/.test(clean) && clean.length % 2 === 0) {
    return clean.length / 2;
  }
  return text.length;
}

function addScratchpadSlot() {
  const nextIdx = diffBus.scratchpadList.value.length + 1;
  diffBus.scratchpadList.value.push({ label: `草稿组 #${nextIdx}`, text: '' });
}

function removeScratchpadSlot(idx: number) {
  if (diffBus.scratchpadList.value.length <= 2) return;
  diffBus.scratchpadList.value.splice(idx, 1);
}

function formatScratchpadSlotHex(idx: number) {
  const slot = diffBus.scratchpadList.value[idx];
  if (!slot) return;
  const clean = slot.text.replace(/[^0-9a-fA-F]/g, '');
  if (!clean) return;
  const chunks: string[] = [];
  for (let i = 0; i < clean.length; i += 2) {
    chunks.push(clean.slice(i, i + 2).toUpperCase());
  }
  slot.text = chunks.join(' ');
}

function loadPresetPair(type: 'MODBUS' | 'MODBUS_MULTI3' | 'TCP_HANDSHAKE' | 'HTTP' | 'DLT645') {
  if (type === 'MODBUS') {
    diffBus.scratchpadList.value = [
      { label: 'Modbus 请求帧', text: '01 03 00 00 00 02 C4 0B' },
      { label: 'Modbus 响应帧', text: '01 03 04 00 12 00 34 89 21' }
    ];
  } else if (type === 'MODBUS_MULTI3') {
    diffBus.scratchpadList.value = [
      { label: 'Modbus 基准帧 (#1)', text: '01 03 00 00 00 02 C4 0B' },
      { label: '网关前插 0xAA (#2)', text: 'AA 01 03 00 00 00 04 C4 0B' },
      { label: '尾部缺失校验 (#3)', text: '01 03 00 01 00 02' }
    ];
  } else if (type === 'TCP_HANDSHAKE') {
    diffBus.scratchpadList.value = [
      { label: 'TCP SYN', text: '45 00 00 34 1a 2b 40 00 40 06 00 00 7f 00 00 01 7f 00 00 01 1f 90 00 50 12 34 56 78 00 00 00 00 80 02 72 10' },
      { label: 'TCP SYN-ACK', text: '45 00 00 34 3c 4d 40 00 40 06 00 00 7f 00 00 01 7f 00 00 01 00 50 1f 90 87 65 43 21 12 34 56 79 80 12 72 10' }
    ];
  } else if (type === 'HTTP') {
    diffBus.scratchpadList.value = [
      { label: 'HTTP GET', text: '47 45 54 20 2f 61 70 69 2f 76 31 2f 73 74 61 74 75 73 20 48 54 54 50 2f 31 2e 31 0d 0a 48 6f 73 74 3a 20 6c 6f 63 61 6c 68 6f 73 74' },
      { label: 'HTTP POST', text: '50 4f 53 54 20 2f 61 70 69 2f 76 31 2f 75 70 64 61 74 65 20 48 54 54 50 2f 31 2e 31 0d 0a 48 6f 73 74 3a 20 6c 6f 63 61 6c 68 6f 73 74' }
    ];
  } else if (type === 'DLT645') {
    diffBus.scratchpadList.value = [
      { label: 'DLT645 抄读帧', text: '68 12 34 56 78 90 12 68 11 04 33 33 33 33 7A 16' },
      { label: 'DLT645 应答帧', text: '68 12 34 56 78 90 12 68 91 08 33 33 33 33 45 67 89 01 EF 16' }
    ];
  }
  executeScratchpadCompare();
}

function executeScratchpadCompare() {
  const validSlots = diffBus.scratchpadList.value.filter(s => s.text.trim().length > 0);
  if (validSlots.length < 2) {
    notifyInfo('请输入至少两组有效数据', '请至少在两组草稿栏中输入十六进制流或 ASCII 文本');
    return;
  }
  const normalized = validSlots.map((s, i) => normalizeToDiffableItem(s.text, s.label || `草稿组 #${i + 1}`));
  if (normalized.length >= 3) {
    diffBus.openMultiDiff(normalized, 0, 'multi');
    runMultiCompare();
    notifySuccess('多组 Center-Star 对齐就绪', `已完成 ${normalized.length} 组自由草稿居中对齐与熵谱计算`);
  } else {
    diffBus.openMultiDiff(normalized, 0, 'hex');
    runCompare();
    runMultiCompare();
    notifySuccess('差分与波形计算就绪', '已基于草稿输入完成逐字节对齐与波形指标分析');
  }
}

async function exportDiffReport() {
  const timeStr = new Date().toISOString().replace(/T/, ' ').replace(/\..+/, '');
  if (activeMode.value === 'multi' && multiResult.value) {
    const mRes = multiResult.value;
    let md = `# Omni-Probe 多组 Center-Star 居中精确比对报告\n\n`;
    md += `- **分析生成时间**: ${timeStr}\n`;
    md += `- **参与样本数**: ${mRes.sample_count} 组 (Anchor 基准: #${mRes.anchor_index + 1})\n`;
    md += `- **居中对齐总列数**: ${mRes.aligned_column_count} 列\n`;
    md += `- **结论摘要**: ${mRes.summary}\n\n`;
    md += `## 1. 各组对比摘要矩阵\n\n| 序号 | 样本标识 | 规约 | 原始长度 | vs 基准变异率 | 余弦相似度 |\n| :--- | :--- | :--- | :--- | :--- | :--- |\n`;
    mRes.samples.forEach(s => {
      md += `| #${s.sample_index + 1}${s.sample_index === mRes.anchor_index ? ' (Anchor)' : ''} | ${s.label} | ${s.protocol || 'RAW'} | ${s.byte_length} B | ${s.mutation_rate_vs_anchor.toFixed(2)}% | ${(s.cosine_similarity_vs_anchor * 100).toFixed(2)}% |\n`;
    });
    md += `\n## 2. 跨多组规约及元数据对比\n\n| 分层 | 字段名 | ${mRes.samples.map(s => `#${s.sample_index + 1} ${s.label}`).join(' | ')} | 判定 |\n| :--- | :--- | ${mRes.samples.map(() => ':---').join(' | ')} | :--- |\n`;
    mRes.field_matrix.forEach(r => {
      md += `| ${r.layer} | ${r.field_name} | ${r.values.map(v => `\`${v || '-'}\``).join(' | ')} | ${r.has_difference ? '**差异**' : '一致'} |\n`;
    });
    await saveTextViaNativeDesktop(
      `multi_diff_report_${Date.now()}.md`,
      md,
      'Markdown 报告 (*.md)',
      '*.md',
      '导出多组居中对齐差分报告'
    );
    return;
  }

  if (!diffResult.value) return;
  const res = diffResult.value;

  let md = `# Omni-Probe 数据深度差分与波形比对分析报告\n\n`;
  md += `- **分析生成时间**: ${timeStr}\n`;
  md += `- **基准样本 A**: #${res.packet_a_id} (${res.packet_a_desc}) - ${res.total_bytes_a} 字节\n`;
  md += `- **比对样本 B**: #${res.packet_b_id} (${res.packet_b_desc}) - ${res.total_bytes_b} 字节\n`;
  md += `- **比对结论**: ${res.summary}\n`;
  md += `- **突变字节数**: ${res.mutated_bytes_count} / ${Math.max(res.total_bytes_a, res.total_bytes_b)} (突变率: ${res.mutation_rate_percent.toFixed(2)}%)\n\n`;

  md += `## 1. 规约与业务字段逐项比对清单\n\n`;
  md += `| 规约分层 | 协议/属性名称 | 样本 A 取值 | 样本 B 取值 | 比对状态 |\n`;
  md += `| :--- | :--- | :--- | :--- | :--- |\n`;
  if (res.field_diffs && res.field_diffs.length > 0) {
    res.field_diffs.forEach(f => {
      const status = f.diff_type === 'EQUAL' ? '一致' : f.diff_type === 'CHANGED' ? '**差异**' : f.diff_type === 'ADDED_IN_B' ? 'B新增' : 'B缺失';
      md += `| ${f.layer} | ${f.field_name} | \`${f.val_a || '-'}\` | \`${f.val_b || '-'}\` | ${status} |\n`;
    });
  } else {
    md += `| 规约层 | 无字段差异记录 | - | - | 一致 |\n`;
  }

  if (res.waveform_metrics) {
    const wm = res.waveform_metrics;
    md += `\n## 2. 载荷波形与变异波率深度分析指标\n\n`;
    md += `- **波形余弦几何相似度**: ${(wm.cosine_similarity * 100).toFixed(2)}%\n`;
    md += `- **皮尔逊线性相关系数**: ${wm.pearson_correlation.toFixed(4)}\n`;
    md += `- **逐字节变异波率**: ${wm.mutation_wave_rate.toFixed(2)}%\n`;
    md += `- **平均绝对振幅偏差 (MAD)**: ${wm.mean_absolute_deviation.toFixed(2)} / 255\n`;
    md += `- **最大跳变峰位**: 偏移量 0x${wm.max_delta_offset.toString(16).toUpperCase()} (#${wm.max_delta_offset})，跳变振幅 Δ${wm.max_delta_value}\n`;
  }

  md += `\n## 3. 载荷十六进制 Myers 差分对齐\n\n`;
  md += `### 样本 A (基准):\n\`\`\`\n`;
  if (res.hex_diff_a?.hex_rows) {
    res.hex_diff_a.hex_rows.forEach(r => {
      const hexStr = r.cells.map(c => c.hex).join(' ');
      md += `${r.offset}  ${hexStr.padEnd(48, ' ')}  |${r.ascii_repr}|\n`;
    });
  }
  md += `\`\`\`\n\n`;

  md += `### 样本 B (比对):\n\`\`\`\n`;
  if (res.hex_diff_b?.hex_rows) {
    res.hex_diff_b.hex_rows.forEach(r => {
      const hexStr = r.cells.map(c => c.hex).join(' ');
      md += `${r.offset}  ${hexStr.padEnd(48, ' ')}  |${r.ascii_repr}|\n`;
    });
  }
  md += `\`\`\`\n\n`;

  await saveTextViaNativeDesktop(
    `data_diff_${Date.now()}.md`,
    md,
    'Markdown 报告 (*.md)',
    '*.md',
    '导出双样本深度差分报告'
  );
}

function drawDiffWaveform() {
  const canvas = diffWaveCanvas.value;
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  if (rect.width === 0 || rect.height === 0) return;

  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  ctx.scale(dpr, dpr);

  const W = rect.width;
  const H = rect.height;
  const dark = isDarkTheme.value;

  // 1. 底色
  ctx.fillStyle = dark ? '#080d16' : '#f8fafc';
  ctx.fillRect(0, 0, W, H);

  const points = diffResult.value?.waveform_metrics?.waveform_points;
  if (!points || points.length === 0) {
    ctx.fillStyle = dark ? '#64748b' : '#475569';
    ctx.font = '12px sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('暂无有效载荷波形点位', W / 2, H / 2);
    return;
  }

  const padL = 38;
  const padR = 16;
  const padT = 16;
  const padB = 22;
  const plotW = W - padL - padR;
  const plotH = H - padT - padB;

  // 2. 标尺网格 (0, 64, 128, 192, 255)
  ctx.strokeStyle = dark ? 'rgba(51, 65, 85, 0.45)' : 'rgba(148, 163, 184, 0.35)';
  ctx.lineWidth = 1;
  ctx.fillStyle = dark ? '#94a3b8' : '#475569';
  ctx.font = '11px monospace';
  ctx.textAlign = 'right';

  const yTicks = [0, 64, 128, 192, 255];
  for (const t of yTicks) {
    const y = padT + plotH - (t / 255) * plotH;
    ctx.beginPath();
    ctx.moveTo(padL, y);
    ctx.lineTo(W - padR, y);
    ctx.stroke();
    ctx.fillText(t.toString(), padL - 6, y + 4);
  }

  const N = points.length;
  const getX = (idx: number) => padL + (N > 1 ? (idx / (N - 1)) * plotW : plotW / 2);
  const getY = (val: number) => padT + plotH - (val / 255) * plotH;

  // 3. 突变区阴影高亮带
  for (let i = 0; i < N; i++) {
    const p = points[i];
    if (p.is_mutated) {
      const x1 = getX(Math.max(0, i - 0.5));
      const x2 = getX(Math.min(N - 1, i + 0.5));
      ctx.fillStyle = dark ? 'rgba(244, 63, 94, 0.14)' : 'rgba(244, 63, 94, 0.10)';
      ctx.fillRect(x1, padT, Math.max(2, x2 - x1), plotH);
    }
  }

  // 4. 绘制折线 A
  const colorA = dark ? '#22d3ee' : '#0284c7';
  const colorB = dark ? '#c084fc' : '#7e22ce';
  ctx.beginPath();
  ctx.strokeStyle = colorA;
  ctx.lineWidth = 1.6;
  for (let i = 0; i < N; i++) {
    const x = getX(i);
    const y = getY(points[i].val_a);
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  }
  ctx.stroke();

  // 5. 绘制折线 B
  ctx.beginPath();
  ctx.strokeStyle = colorB;
  ctx.lineWidth = 1.6;
  for (let i = 0; i < N; i++) {
    const x = getX(i);
    const y = getY(points[i].val_b);
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  }
  ctx.stroke();

  // 6. 鼠标探针十字线
  if (hoverPoint.value) {
    const hIdx = hoverPoint.value.offset;
    if (hIdx >= 0 && hIdx < N) {
      const hx = getX(hIdx);
      ctx.strokeStyle = dark ? 'rgba(255, 255, 255, 0.5)' : 'rgba(15, 23, 42, 0.45)';
      ctx.setLineDash([3, 3]);
      ctx.beginPath();
      ctx.moveTo(hx, padT);
      ctx.lineTo(hx, padT + plotH);
      ctx.stroke();
      ctx.setLineDash([]);

      const ya = getY(hoverPoint.value.val_a);
      ctx.fillStyle = colorA;
      ctx.beginPath();
      ctx.arc(hx, ya, 4, 0, Math.PI * 2);
      ctx.fill();

      const yb = getY(hoverPoint.value.val_b);
      ctx.fillStyle = colorB;
      ctx.beginPath();
      ctx.arc(hx, yb, 4, 0, Math.PI * 2);
      ctx.fill();
    }
  }
}

function drawDeltaSpectrum() {
  const canvas = deltaSpectrumCanvas.value;
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  if (rect.width === 0 || rect.height === 0) return;

  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  ctx.scale(dpr, dpr);

  const W = rect.width;
  const H = rect.height;
  const dark = isDarkTheme.value;

  // 1. 底色
  ctx.fillStyle = dark ? '#080d16' : '#f8fafc';
  ctx.fillRect(0, 0, W, H);

  const points = diffResult.value?.waveform_metrics?.waveform_points;
  if (!points || points.length === 0) return;

  const padL = 38;
  const padR = 16;
  const padT = 10;
  const padB = 20;
  const plotW = W - padL - padR;
  const plotH = H - padT - padB;

  // 2. 标尺线 (0, 128, 255)
  ctx.strokeStyle = dark ? 'rgba(51, 65, 85, 0.45)' : 'rgba(148, 163, 184, 0.35)';
  ctx.lineWidth = 1;
  ctx.fillStyle = dark ? '#94a3b8' : '#475569';
  ctx.font = '11px monospace';
  ctx.textAlign = 'right';

  [0, 128, 255].forEach(v => {
    const y = padT + plotH - (v / 255) * plotH;
    ctx.beginPath();
    ctx.moveTo(padL, y);
    ctx.lineTo(W - padR, y);
    ctx.stroke();
    ctx.fillText(`Δ${v}`, padL - 4, y + 4);
  });

  const N = points.length;
  const barW = Math.max(1, (plotW / N) * 0.85);

  // 3. 直方柱
  for (let i = 0; i < N; i++) {
    const p = points[i];
    const x = padL + (i / N) * plotW;
    const absDelta = Math.abs(p.delta);
    const barH = (absDelta / 255) * plotH;
    const y = padT + plotH - barH;

    if (absDelta === 0) {
      ctx.fillStyle = dark ? 'rgba(51, 65, 85, 0.6)' : 'rgba(148, 163, 184, 0.5)';
      ctx.fillRect(x, padT + plotH - 2, barW, 2);
    } else if (absDelta <= 64) {
      ctx.fillStyle = '#f59e0b';
      ctx.fillRect(x, y, barW, Math.max(2, barH));
    } else if (absDelta <= 128) {
      ctx.fillStyle = '#f97316';
      ctx.fillRect(x, y, barW, Math.max(2, barH));
    } else {
      ctx.fillStyle = '#f43f5e';
      ctx.fillRect(x, y, barW, Math.max(2, barH));
    }
  }

  // 4. 鼠标探针
  if (hoverDelta.value) {
    const hIdx = hoverDelta.value.offset;
    if (hIdx >= 0 && hIdx < N) {
      const hx = padL + (hIdx / N) * plotW;
      ctx.strokeStyle = dark ? 'rgba(255, 255, 255, 0.8)' : 'rgba(15, 23, 42, 0.75)';
      ctx.lineWidth = 1;
      ctx.strokeRect(hx - 1, padT, barW + 2, plotH);
    }
  }
}

function onWaveMouseMove(e: MouseEvent) {
  const canvas = diffWaveCanvas.value;
  if (!canvas) return;
  const rect = canvas.getBoundingClientRect();
  const x = e.clientX - rect.left;
  const padL = 36;
  const padR = 16;
  const plotW = rect.width - padL - padR;

  const points = diffResult.value?.waveform_metrics?.waveform_points;
  if (!points || points.length === 0) return;

  const ratio = Math.max(0, Math.min(1, (x - padL) / plotW));
  const idx = Math.round(ratio * (points.length - 1));
  if (idx >= 0 && idx < points.length) {
    hoverPoint.value = points[idx];
    drawDiffWaveform();
  }
}

function onDeltaMouseMove(e: MouseEvent) {
  const canvas = deltaSpectrumCanvas.value;
  if (!canvas) return;
  const rect = canvas.getBoundingClientRect();
  const x = e.clientX - rect.left;
  const padL = 36;
  const padR = 16;
  const plotW = rect.width - padL - padR;

  const points = diffResult.value?.waveform_metrics?.waveform_points;
  if (!points || points.length === 0) return;

  const ratio = Math.max(0, Math.min(1, (x - padL) / plotW));
  const idx = Math.floor(ratio * points.length);
  if (idx >= 0 && idx < points.length) {
    hoverDelta.value = points[idx];
    drawDeltaSpectrum();
  }
}

function onDeltaSpectrumClick() {
  if (hoverDelta.value) {
    const targetOffset = hoverDelta.value.offset;
    switchMode('hex');
    nextTick(() => {
      const rowIndex = Math.floor(targetOffset / 16);
      if (hexScrollA.value) {
        hexScrollA.value.scrollTop = rowIndex * 26;
      }
    });
  }
}

function drawMultiSpectrum() {
  const canvas = multiSpectrumCanvas.value;
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  if (rect.width === 0 || rect.height === 0) return;

  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  ctx.scale(dpr, dpr);

  const W = rect.width;
  const H = rect.height;
  const dark = isDarkTheme.value;

  ctx.fillStyle = dark ? '#080d16' : '#f8fafc';
  ctx.fillRect(0, 0, W, H);

  const bins = multiResult.value?.aligned_mutation_spectrum;
  if (!bins || bins.length === 0) {
    ctx.fillStyle = dark ? '#64748b' : '#475569';
    ctx.font = '12px sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('暂无多组对齐熵谱数据', W / 2, H / 2);
    return;
  }

  const padL = 38;
  const padR = 16;
  const padT = 18;
  const padB = 22;
  const plotW = W - padL - padR;
  const plotH = H - padT - padB;

  ctx.strokeStyle = dark ? 'rgba(51, 65, 85, 0.45)' : 'rgba(148, 163, 184, 0.35)';
  ctx.lineWidth = 1;
  ctx.fillStyle = dark ? '#94a3b8' : '#475569';
  ctx.font = '11px monospace';
  ctx.textAlign = 'right';

  for (const pct of [0, 50, 100]) {
    const y = padT + plotH - (pct / 100) * plotH;
    ctx.beginPath();
    ctx.moveTo(padL, y);
    ctx.lineTo(W - padR, y);
    ctx.stroke();
    ctx.fillText(`${pct}%`, padL - 6, y + 4);
  }

  const n = bins.length;
  const barW = Math.max(2, plotW / n - 1.5);
  const maxEntropy = Math.max(1, ...bins.map(b => b.entropy));

  // 变异波率柱条
  for (let i = 0; i < n; i++) {
    const b = bins[i];
    const x = padL + (i / n) * plotW;
    const h = (b.mutation_rate / 100) * plotH;
    const y = padT + plotH - h;
    ctx.fillStyle = b.mutation_rate > 0
      ? (dark ? 'rgba(244, 63, 94, 0.72)' : 'rgba(225, 29, 72, 0.72)')
      : (dark ? 'rgba(100, 116, 139, 0.25)' : 'rgba(148, 163, 184, 0.32)');
    ctx.fillRect(x, y, barW, Math.max(1.5, h));
  }

  // 香农熵折线
  ctx.beginPath();
  ctx.strokeStyle = dark ? '#22d3ee' : '#0284c7';
  ctx.lineWidth = 1.6;
  for (let i = 0; i < n; i++) {
    const x = padL + ((i + 0.5) / n) * plotW;
    const y = padT + plotH - (bins[i].entropy / maxEntropy) * plotH;
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  }
  ctx.stroke();

  if (hoverMultiBin.value) {
    const idx = hoverMultiBin.value.offset;
    if (idx >= 0 && idx < n) {
      const hx = padL + ((idx + 0.5) / n) * plotW;
      ctx.strokeStyle = dark ? 'rgba(255, 255, 255, 0.6)' : 'rgba(15, 23, 42, 0.5)';
      ctx.setLineDash([3, 3]);
      ctx.beginPath();
      ctx.moveTo(hx, padT);
      ctx.lineTo(hx, padT + plotH);
      ctx.stroke();
      ctx.setLineDash([]);
    }
  }

  ctx.textAlign = 'left';
  ctx.fillStyle = dark ? '#cbd5e1' : '#334155';
  ctx.font = '11px sans-serif';
  ctx.fillText('柱条: 偏移列变异波率(%)   折线: 香农信息熵(bit)', padL + 4, 13);
}

function onMultiSpectrumMouseMove(e: MouseEvent) {
  const canvas = multiSpectrumCanvas.value;
  if (!canvas) return;
  const rect = canvas.getBoundingClientRect();
  const x = e.clientX - rect.left;
  const padL = 38;
  const padR = 16;
  const plotW = rect.width - padL - padR;

  const bins = multiResult.value?.aligned_mutation_spectrum;
  if (!bins || bins.length === 0) return;

  const ratio = Math.max(0, Math.min(0.9999, (x - padL) / plotW));
  const idx = Math.floor(ratio * bins.length);
  if (idx >= 0 && idx < bins.length) {
    hoverMultiBin.value = bins[idx];
    drawMultiSpectrum();
  }
}

// 兼容 props.packetA / packetB 传入（仅写入总线，不死锁后续样本/草稿替换）
watch(() => props.packetA, (pkt) => {
  if (pkt) diffBus.setSlotA(pkt, '基准样本 A');
}, { immediate: true });

watch(() => props.packetB, (pkt) => {
  if (pkt) diffBus.setSlotB(pkt, '比对样本 B');
}, { immediate: true });

// 监听数据项变更，触发自动双组与多组差分比对
watch([() => effectiveItemA.value?.payloadHex, () => effectiveItemB.value?.payloadHex, () => effectiveItemA.value?.rawText, () => effectiveItemB.value?.rawText], () => {
  if (activeIsOpen.value) {
    runCompare();
  }
});

watch(
  [() => diffBus.diffQueue.value.map(x => `${x.label}:${x.payloadHex}:${x.rawText}`).join('|'), () => diffBus.anchorIndex.value],
  () => {
    if (activeIsOpen.value && diffBus.queueCount.value >= 2) {
      runMultiCompare();
    }
  }
);

watch(() => diffBus.activeMode.value, (mode) => {
  if (!activeIsOpen.value) return;
  if (mode === 'wave') {
    nextTick(() => {
      drawDiffWaveform();
      drawDeltaSpectrum();
    });
  } else if (mode === 'multi' && diffBus.queueCount.value >= 2) {
    runMultiCompare();
  }
});

watch(activeIsOpen, (open) => {
  if (open) {
    loadStoredSamples();
    runCompare();
    if (diffBus.queueCount.value >= 2) {
      runMultiCompare();
    }
  }
});

onMounted(() => {
  themeObserver = new MutationObserver(() => {
    isDarkTheme.value = !document.documentElement.classList.contains('theme-apple-light');
    if (activeMode.value === 'wave' && diffResult.value) {
      drawDiffWaveform();
      drawDeltaSpectrum();
    }
    if (activeMode.value === 'multi' && multiResult.value) {
      drawMultiSpectrum();
    }
  });
  themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });

  if (activeIsOpen.value) {
    loadStoredSamples();
    runCompare();
    if (diffBus.queueCount.value >= 2) {
      runMultiCompare();
    }
  }
});

onUnmounted(() => {
  if (themeObserver) {
    themeObserver.disconnect();
    themeObserver = null;
  }
});
</script>
