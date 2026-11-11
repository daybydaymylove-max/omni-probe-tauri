<template>
  <div class="h-full flex flex-col overflow-hidden p-4 gap-3 text-xs select-text">
    <!-- 顶部子模式切换 + 参数控制条 -->
    <div class="ui-sub-card p-3 flex flex-wrap items-center justify-between gap-3 shrink-0">
      <div class="flex items-center gap-1.5 flex-wrap">
        <button
          v-for="tab in subModes"
          :key="tab.id"
          @click="subMode = tab.id"
          :class="[
            'px-2.5 py-1.5 rounded-xl text-[11px] font-semibold transition-all cursor-pointer border flex items-center gap-1.5',
            subMode === tab.id
              ? 'bg-indigo-600 text-white border-indigo-500 shadow-xs'
              : 'ui-btn-secondary'
          ]"
        >
          <AppIcon :name="tab.icon" :size="13" />
          <span>{{ tab.label }}</span>
        </button>
      </div>

      <!-- 文本比对过滤规则开关 -->
      <div v-if="subMode === 'text'" class="flex items-center gap-3 flex-wrap text-[11px]" style="color: var(--text-secondary)">
        <label class="flex items-center gap-1.5 cursor-pointer select-none">
          <input type="checkbox" v-model="options.ignore_whitespace" class="w-3.5 h-3.5 rounded accent-indigo-600 cursor-pointer" />
          <span>忽略空白符</span>
        </label>
        <label class="flex items-center gap-1.5 cursor-pointer select-none">
          <input type="checkbox" v-model="options.ignore_case" class="w-3.5 h-3.5 rounded accent-indigo-600 cursor-pointer" />
          <span>忽略大小写</span>
        </label>
        <label class="flex items-center gap-1.5 cursor-pointer select-none">
          <input type="checkbox" v-model="options.ignore_line_endings" class="w-3.5 h-3.5 rounded accent-indigo-600 cursor-pointer" />
          <span>忽略 CRLF/LF</span>
        </label>
        <label class="flex items-center gap-1.5 cursor-pointer select-none">
          <input type="checkbox" v-model="onlyDiffHunks" class="w-3.5 h-3.5 rounded accent-indigo-600 cursor-pointer" />
          <span>仅看差异块</span>
        </label>
      </div>

      <!-- 目录验证选项 -->
      <div v-else-if="subMode === 'directory'" class="flex items-center gap-3 flex-wrap text-[11px]" style="color: var(--text-secondary)">
        <label class="flex items-center gap-1.5 cursor-pointer select-none">
          <input type="checkbox" v-model="verifyEqualSizeBytes" class="w-3.5 h-3.5 rounded accent-indigo-600 cursor-pointer" />
          <span>同字节大小文件逐字节校验 (≤50MB)</span>
        </label>
        <label class="flex items-center gap-1.5 cursor-pointer select-none">
          <input type="checkbox" v-model="onlyDirDiffs" class="w-3.5 h-3.5 rounded accent-indigo-600 cursor-pointer" />
          <span>仅显示差异条目</span>
        </label>
      </div>

      <!-- 二进制滚动锚点模式切换 -->
      <div v-else class="flex items-center gap-3 flex-wrap text-[11px]" style="color: var(--text-secondary)">
        <label class="flex items-center gap-1.5 cursor-pointer select-none" title="Gear-Hash 16KB 变长内容切分 + Myers 块锚点再对齐，有效消除前文插删引起的全场偏移雪崩">
          <input type="checkbox" v-model="useFastCdcMode" class="w-3.5 h-3.5 rounded accent-indigo-600 cursor-pointer" />
          <span>启用 Gear-Hash FastCDC 滚动锚点再对齐 (抗字节偏移错位)</span>
        </label>
      </div>
    </div>

    <!-- 路径输入与执行动作栏 -->
    <div class="ui-sub-card p-3 grid grid-cols-1 lg:grid-cols-12 gap-2.5 items-center shrink-0">
      <div class="lg:col-span-5 flex flex-col gap-1">
        <label class="text-[11px] font-semibold" style="color: var(--text-muted)">
          {{ subMode === 'directory' ? '左侧基准目录路径 (支持文件拖入或浏览)' : '左侧基准文件磁盘路径 (支持文件拖入或浏览)' }}
        </label>
        <div class="flex items-center gap-1.5">
          <input
            v-model="leftPath"
            type="text"
            :placeholder="subMode === 'directory' ? '点击右侧浏览按钮或直接拖拽文件夹进窗口...' : '点击右侧浏览按钮或直接拖拽文件进窗口...'"
            class="ui-input px-2.5 py-1.5 text-xs ui-num flex-1 min-w-0"
          />
          <button
            @click="browsePath('left')"
            class="ui-btn-secondary px-2.5 py-1.5 text-[11px] shrink-0 cursor-pointer"
            title="打开操作系统原生文件/目录选择框"
          >
            浏览...
          </button>
        </div>
      </div>

      <div class="lg:col-span-5 flex flex-col gap-1">
        <label class="text-[11px] font-semibold" style="color: var(--text-muted)">
          {{ subMode === 'directory' ? '右侧比对目录路径 (支持文件拖入或浏览)' : '右侧比对文件磁盘路径 (支持文件拖入或浏览)' }}
        </label>
        <div class="flex items-center gap-1.5">
          <input
            v-model="rightPath"
            type="text"
            :placeholder="subMode === 'directory' ? '点击右侧浏览按钮或直接拖拽文件夹进窗口...' : '点击右侧浏览按钮或直接拖拽文件进窗口...'"
            class="ui-input px-2.5 py-1.5 text-xs ui-num flex-1 min-w-0"
          />
          <button
            @click="browsePath('right')"
            class="ui-btn-secondary px-2.5 py-1.5 text-[11px] shrink-0 cursor-pointer"
            title="打开操作系统原生文件/目录选择框"
          >
            浏览...
          </button>
        </div>
      </div>

      <div class="lg:col-span-2 flex items-end justify-end gap-2 h-full pt-4 lg:pt-0">
        <button
          @click="swapLeftRightPaths"
          class="ui-btn-secondary px-2.5 py-1.5 text-xs shrink-0"
          title="互换左右路径"
        >
          ⇄
        </button>
        <button
          @click="executeCompare"
          :disabled="isLoading || !leftPath.trim() || !rightPath.trim()"
          class="ui-btn-primary px-3 py-1.5 text-xs font-bold flex-1 lg:flex-initial shrink-0 disabled:opacity-45"
        >
          {{ isLoading ? '流式计算中...' : '执行比对' }}
        </button>
      </div>
    </div>

    <!-- 错误 / 提示横幅 -->
    <div
      v-if="errorMsg"
      class="px-3 py-2 rounded-xl border border-rose-500/35 bg-rose-500/10 text-rose-700 dark:text-rose-300 text-[11px] flex items-center justify-between gap-2 shrink-0"
    >
      <span>{{ errorMsg }}</span>
      <button @click="errorMsg = ''" class="font-bold px-1.5 cursor-pointer">×</button>
    </div>

    <!-- ================================================================ -->
    <!-- 子视图 1: Myers 线性分治文本 Diff + 逐块双向交互 Merge 工作台 -->
    <!-- ================================================================ -->
    <template v-if="subMode === 'text'">
      <!-- 指标与合并存盘操作条 -->
      <div v-if="textReport" class="ui-sub-card px-3 py-2 flex flex-wrap items-center justify-between gap-2.5 shrink-0">
        <div class="flex items-center gap-3 flex-wrap text-[11px] ui-num" style="color: var(--text-secondary)">
          <span>左: <strong>{{ textReport.left_total_lines.toLocaleString() }}</strong> 行 ({{ formatBytes(textReport.left_size_bytes) }})</span>
          <span>右: <strong>{{ textReport.right_total_lines.toLocaleString() }}</strong> 行 ({{ formatBytes(textReport.right_size_bytes) }})</span>
          <span class="px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 font-semibold">
            相似度 {{ textReport.similarity_percent.toFixed(1) }}%
          </span>
          <span class="text-rose-700 dark:text-rose-300">
            差异块: <strong>{{ textReport.diff_hunks_count }}</strong> (+{{ textReport.inserted_lines }} / -{{ textReport.deleted_lines }})
          </span>
          <span>耗时 {{ textReport.elapsed_ms }} ms</span>
          <span v-if="textReport.is_binary_suspected" class="px-2 py-0.5 rounded bg-amber-500/20 text-amber-800 dark:text-amber-200 font-semibold">
            检测到大量 NULL 字节，建议切换至「大二进制分块页对比」
            <button @click="switchToBinaryFromWarning" class="underline ml-1 cursor-pointer">立即切换</button>
          </span>
        </div>

        <!-- Merge 输出存盘控制组 -->
        <div class="flex items-center gap-2 flex-wrap">
          <input
            v-model="mergeOutputPath"
            type="text"
            placeholder="Merge 保存目标文件路径..."
            class="ui-input px-2.5 py-1 text-[11px] w-56 ui-num"
          />
          <label class="flex items-center gap-1 text-[11px] cursor-pointer" style="color: var(--text-secondary)" title="覆盖已有文件时自动创建 .omni_bak 备份">
            <input type="checkbox" v-model="createBackup" class="w-3.5 h-3.5 rounded accent-indigo-600 cursor-pointer" />
            <span>.omni_bak</span>
          </label>
          <button
            @click="applyBulkMergeChoice('KeepLeft')"
            class="ui-btn-secondary px-2 py-1 text-[11px]"
            title="全部差异块默认采用左侧"
          >
            全采左
          </button>
          <button
            @click="applyBulkMergeChoice('KeepRight')"
            class="ui-btn-secondary px-2 py-1 text-[11px]"
            title="全部差异块默认采用右侧"
          >
            全采右
          </button>
          <button
            @click="exportPatch"
            class="ui-btn-secondary px-2.5 py-1 text-[11px]"
            title="导出 GNU Unified Diff (.patch) 文件"
          >
            导出 .patch
          </button>
          <button
            @click="saveMergedFile"
            :disabled="isSavingMerge || !mergeOutputPath.trim()"
            class="ui-btn-primary px-3 py-1 text-[11px] font-bold disabled:opacity-45"
          >
            {{ isSavingMerge ? '原子写入中...' : '保存 Merge 结果' }}
          </button>
          <button
            v-if="lastMergedSavedPath"
            @click="revealInDesktopExplorer(lastMergedSavedPath)"
            class="ui-btn-secondary px-2 py-1 text-[11px] cursor-pointer"
            title="在操作系统文件管理器中定位显示产物"
          >
            打开所在目录
          </button>
        </div>
      </div>

      <!-- 双栏逐 Hunk 流式对比 + 勾选 Merge 主视口 -->
      <div class="flex-1 min-h-0 overflow-auto ui-content-card p-3 space-y-2.5 custom-scrollbar">
        <EmptyState
          v-if="!textReport"
          icon="document"
          title="Beyond Compare 级流式文本差异与双向合并工作台"
          description="输入左右两份磁盘文件路径（支持十万行级大日志或源代码）后点击【执行比对】，可逐差异块选择采纳左/右或双侧合并并原子写盘。"
        />

        <template v-else>
          <div
            v-if="visibleTextHunks.length === 0"
            class="py-12 text-center text-xs"
            style="color: var(--text-muted)"
          >
            两份文本文件在当前比较规则下 100% 一致，无任何差异区块。
          </div>

          <div
            v-if="textReport.truncated_preview"
            class="px-3 py-1.5 rounded-xl border border-amber-500/35 bg-amber-500/10 text-amber-800 dark:text-amber-200 text-[11px]"
          >
            注意：差异块总数超出 400 块实时预览窗口；未单独修改的后段区块将在保存 Merge 时统一采用当前全量策略（{{ defaultMergeChoice === 'KeepLeft' ? '全采左' : '全采右' }}）。
          </div>

          <div
            v-for="h in visibleTextHunks"
            :key="h.hunk_id"
            class="rounded-xl border overflow-hidden"
            :style="{
              borderColor: h.op === 'equal' ? 'var(--border-subtle)' : 'rgba(99, 102, 241, 0.35)'
            }"
          >
            <!-- Hunk 控制头栏 -->
            <div
              class="px-3 py-1.5 flex items-center justify-between gap-2 flex-wrap text-[11px] ui-num border-b"
              :style="{
                background: h.op === 'equal' ? 'var(--surface-content-alt)' : 'rgba(99, 102, 241, 0.08)',
                borderColor: 'var(--border-subtle)'
              }"
            >
              <div class="flex items-center gap-2">
                <span
                  class="px-1.5 py-0.5 rounded font-bold"
                  :class="hunkBadgeClass(h.op)"
                >
                  {{ hunkOpLabel(h.op) }}
                </span>
                <span style="color: var(--text-secondary)">
                  Hunk #{{ h.hunk_id }} · 左 L{{ h.left_start_line }} ({{ h.left_line_count }}行) ↔ 右 L{{ h.right_start_line }} ({{ h.right_line_count }}行)
                </span>
              </div>

              <!-- 差异块交互式双向 Merge 策略按钮组 -->
              <div v-if="h.op !== 'equal'" class="flex items-center gap-1.5">
                <span class="text-[11px]" style="color: var(--text-muted)">合并决策:</span>
                <button
                  v-for="opt in mergeChoiceOptions"
                  :key="opt.id"
                  @click="setHunkDecision(h.hunk_id, opt.id)"
                  :class="[
                    'px-2 py-0.5 rounded-lg text-[11px] border cursor-pointer transition-all',
                    getHunkDecision(h.hunk_id) === opt.id
                      ? 'bg-indigo-600 text-white border-indigo-500 font-bold'
                      : 'ui-btn-secondary'
                  ]"
                >
                  {{ opt.label }}
                </button>
              </div>
            </div>

            <!-- 左右双栏同步对照区 -->
            <div class="grid grid-cols-1 lg:grid-cols-2 divide-y lg:divide-y-0 lg:divide-x font-mono text-[11px] leading-relaxed" style="border-color: var(--border-subtle)">
              <!-- 左侧源码行 -->
              <div
                class="p-2 overflow-x-auto"
                :class="h.op === 'delete' || h.op === 'replace' ? 'bg-rose-500/8' : ''"
              >
                <div
                  v-for="(line, idx) in h.left_lines"
                  :key="`l-${h.hunk_id}-${idx}`"
                  class="flex gap-2 whitespace-pre"
                >
                  <span class="w-10 shrink-0 text-right select-none opacity-55 ui-num">
                    {{ h.left_start_line + idx }}
                  </span>
                  <span style="color: var(--text-primary)">{{ line }}</span>
                </div>
                <div v-if="h.left_lines.length === 0" class="italic opacity-60 px-2" style="color: var(--text-muted)">
                  [此区域在左侧文件中无对应行]
                </div>
              </div>

              <!-- 右侧源码行 -->
              <div
                class="p-2 overflow-x-auto"
                :class="h.op === 'insert' || h.op === 'replace' ? 'bg-emerald-500/8' : ''"
              >
                <div
                  v-for="(line, idx) in h.right_lines"
                  :key="`r-${h.hunk_id}-${idx}`"
                  class="flex gap-2 whitespace-pre"
                >
                  <span class="w-10 shrink-0 text-right select-none opacity-55 ui-num">
                    {{ h.right_start_line + idx }}
                  </span>
                  <span style="color: var(--text-primary)">{{ line }}</span>
                </div>
                <div v-if="h.right_lines.length === 0" class="italic opacity-60 px-2" style="color: var(--text-muted)">
                  [此区域在右侧文件中已删除]
                </div>
              </div>
            </div>
          </div>
        </template>
      </div>
    </template>

    <!-- ================================================================ -->
    <!-- 子视图 2: GB 级流式 FastCDC 滚动锚点 / 定长 64KB 二进制对比与分页浏览器 -->
    <!-- ================================================================ -->
    <template v-else-if="subMode === 'binary'">
      <div v-if="useFastCdcMode && cdcReport" class="ui-sub-card px-3 py-2 flex flex-wrap items-center justify-between gap-2 shrink-0 text-[11px] ui-num">
        <div class="flex items-center gap-3 flex-wrap" style="color: var(--text-secondary)">
          <span>左: <strong>{{ formatBytes(cdcReport.left_size_bytes) }}</strong> ({{ cdcReport.left_chunks_count }} 变长块)</span>
          <span>右: <strong>{{ formatBytes(cdcReport.right_size_bytes) }}</strong> ({{ cdcReport.right_chunks_count }} 变长块)</span>
          <span class="text-emerald-700 dark:text-emerald-300 font-semibold">同址一致: {{ formatBytes(cdcReport.identical_bytes) }}</span>
          <span class="text-sky-700 dark:text-sky-300 font-semibold">偏移再对齐: {{ formatBytes(cdcReport.shifted_aligned_bytes) }}</span>
          <span class="text-rose-700 dark:text-rose-300 font-bold">修改区: -{{ formatBytes(cdcReport.modified_left_bytes) }} / +{{ formatBytes(cdcReport.modified_right_bytes) }}</span>
          <span class="px-2 py-0.5 rounded bg-indigo-500/15 text-indigo-700 dark:text-indigo-300 font-bold">
            内容重对齐率 {{ cdcReport.similarity_percent.toFixed(2) }}%
          </span>
          <span>耗时 {{ cdcReport.elapsed_ms }} ms</span>
        </div>
        <span style="color: var(--text-muted)">点击左侧区间自动按左右独立校准偏移 Seek 对照</span>
      </div>

      <div v-else-if="!useFastCdcMode && binSummary" class="ui-sub-card px-3 py-2 flex flex-wrap items-center justify-between gap-2 shrink-0 text-[11px] ui-num">
        <div class="flex items-center gap-3 flex-wrap" style="color: var(--text-secondary)">
          <span>左文件: <strong>{{ formatBytes(binSummary.left_size_bytes) }}</strong></span>
          <span>右文件: <strong>{{ formatBytes(binSummary.right_size_bytes) }}</strong></span>
          <span>总块数 ({{ formatBytes(binSummary.chunk_size_bytes) }}/块): <strong>{{ binSummary.total_chunks }}</strong></span>
          <span class="text-emerald-700 dark:text-emerald-300">一致块: <strong>{{ binSummary.identical_chunks }}</strong></span>
          <span class="text-rose-700 dark:text-rose-300 font-bold">差异块: <strong>{{ binSummary.different_chunks_count }}</strong></span>
          <span>扫描耗时 {{ binSummary.elapsed_ms }} ms</span>
        </div>
        <span style="color: var(--text-muted)">点击左侧任意差异块即可从磁盘流式 Seek 检视逐字节偏差</span>
      </div>

      <div class="flex-1 min-h-0 grid grid-cols-1 lg:grid-cols-12 gap-3 overflow-hidden">
        <!-- 左: FastCDC 内容锚点区段表 或 定长 64KB 差异索引表 -->
        <div class="lg:col-span-4 ui-content-card p-3 flex flex-col overflow-hidden">
          <div class="text-xs font-bold mb-2 pb-1.5 border-b shrink-0" style="border-color: var(--border-subtle); color: var(--text-primary)">
            {{ useFastCdcMode ? 'FastCDC 滚动锚点分段索引表' : '64 KB 定长差异块 CRC32 索引列表' }}
          </div>
          <div class="flex-1 overflow-auto space-y-1.5 custom-scrollbar">
            <template v-if="useFastCdcMode">
              <EmptyState
                v-if="!cdcReport"
                icon="database"
                title="Gear-Hash FastCDC 滚动锚点流式比对"
                description="选择两份大二进制固件、PCAP 或镜像文件点击【执行比对】，自动抗插删错位重新对齐后续块。"
              />
              <button
                v-for="seg in (cdcReport?.segments ?? [])"
                :key="seg.segment_index"
                @click="loadDualOffsetBinaryPage(seg.left_offset, seg.right_offset)"
                :class="[
                  'w-full text-left p-2 rounded-xl border text-[11px] ui-num cursor-pointer transition-all',
                  activeBinaryOffset === seg.left_offset && activeBinaryRightOffset === seg.right_offset
                    ? 'bg-indigo-600/15 border-indigo-500 text-indigo-700 dark:text-indigo-200 font-semibold'
                    : 'ui-sub-card hover:border-indigo-500/40'
                ]"
              >
                <div class="flex items-center justify-between gap-1">
                  <span>Seg #{{ seg.segment_index }} · {{ seg.chunk_count }} 块</span>
                  <span
                    class="px-1.5 py-0.5 rounded font-semibold"
                    :class="seg.status === 'Modified'
                      ? 'bg-rose-500/15 text-rose-700 dark:text-rose-300'
                      : seg.status === 'ShiftedIdentical'
                        ? 'bg-sky-500/15 text-sky-700 dark:text-sky-300'
                        : 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300'"
                  >
                    {{ seg.status === 'Modified' ? '真实变更' : seg.status === 'ShiftedIdentical' ? `再对齐 (${seg.shift_delta_bytes >= 0 ? '+' : ''}${seg.shift_delta_bytes}B)` : '同址一致' }}
                  </span>
                </div>
                <div class="opacity-80 mt-0.5">
                  L 0x{{ seg.left_offset.toString(16).toUpperCase() }} ({{ formatBytes(seg.left_len) }}) ↔ R 0x{{ seg.right_offset.toString(16).toUpperCase() }} ({{ formatBytes(seg.right_len) }})
                </div>
              </button>
            </template>

            <template v-else>
              <EmptyState
                v-if="!binSummary"
                icon="database"
                title="大二进制文件流式对比"
                description="选择两份二进制固件、PCAP 或大体积镜像文件点击执行比对。"
              />
              <div v-else-if="binSummary.different_chunks.length === 0" class="py-8 text-center text-xs text-emerald-600 dark:text-emerald-400">
                两份二进制文件按 64 KB 流式逐字节完全一致！
              </div>
              <button
                v-for="c in (binSummary?.different_chunks ?? [])"
                :key="c.chunk_index"
                @click="loadDualOffsetBinaryPage(c.byte_offset, c.byte_offset)"
                :class="[
                  'w-full text-left p-2 rounded-xl border text-[11px] ui-num cursor-pointer transition-all',
                  activeBinaryOffset === c.byte_offset
                    ? 'bg-indigo-600/15 border-indigo-500 text-indigo-700 dark:text-indigo-200 font-semibold'
                    : 'ui-sub-card hover:border-indigo-500/40'
                ]"
              >
                <div class="flex items-center justify-between">
                  <span>Chunk #{{ c.chunk_index }} · 偏移 0x{{ c.byte_offset.toString(16).toUpperCase() }}</span>
                  <span class="px-1.5 py-0.5 rounded bg-rose-500/15 text-rose-700 dark:text-rose-300">{{ c.status }}</span>
                </div>
                <div class="opacity-75 mt-0.5">
                  CRC32: 0x{{ c.crc32_left.toString(16).padStart(8, '0').toUpperCase() }} vs 0x{{ c.crc32_right.toString(16).padStart(8, '0').toUpperCase() }}
                </div>
              </button>
            </template>
          </div>
        </div>

        <!-- 右: 双指针校准分页对照区 (512B 窗口) -->
        <div class="lg:col-span-8 ui-content-card p-3 flex flex-col overflow-hidden">
          <div class="flex items-center justify-between pb-1.5 mb-2 border-b shrink-0 flex-wrap gap-2" style="border-color: var(--border-subtle)">
            <span class="text-xs font-bold ui-num" style="color: var(--text-primary)">
              字节窗口对照 {{ binaryPage ? `(L@0x${activeBinaryOffset.toString(16).toUpperCase()} / R@0x${activeBinaryRightOffset.toString(16).toUpperCase()}, 窗口 ${binaryPage.page_size}B, 差异 ${binaryPage.diff_bytes_in_page}B)` : '' }}
            </span>
            <div v-if="binaryPage" class="flex items-center gap-1.5">
              <button
                @click="loadDualOffsetBinaryPage(Math.max(0, activeBinaryOffset - 512), Math.max(0, activeBinaryRightOffset - 512))"
                :disabled="activeBinaryOffset === 0 && activeBinaryRightOffset === 0"
                class="ui-btn-secondary px-2 py-0.5 text-[11px] disabled:opacity-40"
              >
                ← 上 512B
              </button>
              <button
                @click="loadDualOffsetBinaryPage(activeBinaryOffset + 512, activeBinaryRightOffset + 512)"
                class="ui-btn-secondary px-2 py-0.5 text-[11px]"
              >
                下 512B →
              </button>
            </div>
          </div>

          <div class="flex-1 overflow-auto custom-scrollbar">
            <div v-if="!binaryPage" class="py-12 text-center text-xs" style="color: var(--text-muted)">
              请在左侧点击任意差异 Chunk，实时流式读取 512 字节十六进制对照窗格。
            </div>
            <div v-else class="grid grid-cols-8 md:grid-cols-[repeat(16,minmax(0,1fr))] gap-1 font-mono text-[11px] ui-num">
              <div
                v-for="r in binaryPage.rows"
                :key="r.offset"
                class="p-1 rounded border text-center"
                :class="r.status === 'equal'
                  ? 'border-transparent opacity-80'
                  : 'border-rose-500/45 bg-rose-500/15 font-bold text-rose-700 dark:text-rose-200'"
                :title="`Offset 0x${r.offset.toString(16).toUpperCase()} (${r.offset})`"
              >
                <div>{{ r.left_byte !== null ? r.left_byte.toString(16).padStart(2, '0').toUpperCase() : '--' }}</div>
                <div class="text-[11px] border-t pt-0.5 mt-0.5" style="border-color: var(--border-subtle)">
                  {{ r.right_byte !== null ? r.right_byte.toString(16).padStart(2, '0').toUpperCase() : '--' }}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </template>

    <!-- ================================================================ -->
    <!-- 子视图 3: 目录递归树智能比较与一键下钻工作台 -->
    <!-- ================================================================ -->
    <template v-else-if="subMode === 'directory'">
      <div v-if="dirReport" class="ui-sub-card px-3 py-2 flex flex-wrap items-center justify-between gap-2 shrink-0 text-[11px] ui-num">
        <div class="flex items-center gap-3 flex-wrap" style="color: var(--text-secondary)">
          <span>共扫描 <strong>{{ dirReport.total_entries }}</strong> 项</span>
          <span class="text-rose-700 dark:text-rose-300 font-bold">修改 Modified: {{ dirReport.modified_count }}</span>
          <span class="text-sky-700 dark:text-sky-300 font-bold">仅左侧: {{ dirReport.left_only_count }}</span>
          <span class="text-emerald-700 dark:text-emerald-300 font-bold">仅右侧: {{ dirReport.right_only_count }}</span>
          <span>相同: {{ dirReport.identical_count }}</span>
          <span>耗时 {{ dirReport.elapsed_ms }} ms</span>
        </div>
        <span style="color: var(--text-muted)">点击任意“Modified”行直接进入源码双向 Merge 或二进制核验</span>
      </div>

      <div class="flex-1 min-h-0 overflow-auto ui-content-card p-3 custom-scrollbar">
        <EmptyState
          v-if="!dirReport"
          icon="layers"
          title="双目录结构递归比对 (Beyond Compare 目录视图)"
          description="输入两份工程文件夹或配置文件目录，点击【执行比对】即可自动跳过 .git / target / node_modules 扫描全目录差异。"
        />
        <table v-else class="w-full text-left border-collapse text-xs">
          <thead>
            <tr class="border-b text-[11px] sticky top-0" style="background: var(--surface-content-alt); border-color: var(--border-subtle); color: var(--text-muted)">
              <th class="py-2 px-3">相对路径 (Relative Path)</th>
              <th class="py-2 px-3 w-28">状态</th>
              <th class="py-2 px-3 w-28 text-right">左侧大小</th>
              <th class="py-2 px-3 w-28 text-right">右侧大小</th>
              <th class="py-2 px-3 w-36 text-right">快捷操作</th>
            </tr>
          </thead>
          <tbody class="divide-y ui-num" style="border-color: var(--border-subtle)">
            <tr
              v-for="entry in visibleDirEntries"
              :key="entry.relative_path"
              class="hover:bg-[var(--surface-hover)] transition-colors"
            >
              <td class="py-1.5 px-3 font-mono text-[11px] flex items-center gap-1.5" style="color: var(--text-primary)">
                <AppIcon v-if="entry.is_dir" name="layers" :size="12" class="shrink-0 opacity-75" />
                <span>{{ entry.relative_path }}</span>
              </td>
              <td class="py-1.5 px-3">
                <span class="px-2 py-0.5 rounded text-[11px] font-semibold" :class="dirBadgeClass(entry.status)">
                  {{ entry.status }}
                </span>
              </td>
              <td class="py-1.5 px-3 text-right text-[11px]" style="color: var(--text-secondary)">
                {{ entry.left_size !== null ? formatBytes(entry.left_size) : '-' }}
              </td>
              <td class="py-1.5 px-3 text-right text-[11px]" style="color: var(--text-secondary)">
                {{ entry.right_size !== null ? formatBytes(entry.right_size) : '-' }}
              </td>
              <td class="py-1.5 px-3 text-right">
                <button
                  v-if="!entry.is_dir && entry.left_full_path && entry.right_full_path"
                  @click="drillIntoTextCompare(entry)"
                  class="ui-btn-secondary px-2 py-0.5 text-[11px] cursor-pointer"
                >
                  打开双边合并
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import AppIcon from './AppIcon.vue';
import EmptyState from './EmptyState.vue';
import { notifySuccess, notifyError, notifyWarning } from '../composables/useNotification';
import { pickNativeFilePath, pickNativeFolderPath, revealInDesktopExplorer } from '../composables/useDesktopSave';
import { useUniversalDiff } from '../composables/useUniversalDiff';

interface FileDiffOptions {
  ignore_whitespace: boolean;
  ignore_case: boolean;
  ignore_line_endings: boolean;
}

interface DiffHunkDetail {
  hunk_id: number;
  op: 'equal' | 'replace' | 'insert' | 'delete' | string;
  left_start_line: number;
  left_line_count: number;
  right_start_line: number;
  right_line_count: number;
  left_lines: string[];
  right_lines: string[];
}

interface TextFileDiffReport {
  left_path: string;
  right_path: string;
  left_size_bytes: number;
  right_size_bytes: number;
  left_total_lines: number;
  right_total_lines: number;
  is_binary_suspected: boolean;
  equal_lines: number;
  inserted_lines: number;
  deleted_lines: number;
  replaced_hunks: number;
  diff_hunks_count: number;
  similarity_percent: number;
  elapsed_ms: number;
  truncated_preview: boolean;
  hunks: DiffHunkDetail[];
  unified_patch_preview: string;
}

type MergeChoice = 'KeepLeft' | 'KeepRight' | 'KeepBothLeftFirst' | 'KeepBothRightFirst';

interface MergeSaveOutcome {
  success: boolean;
  output_path: string;
  backup_path?: string | null;
  total_output_lines: number;
  total_output_bytes: number;
  message: string;
}

interface BinaryDiffChunkMeta {
  chunk_index: number;
  byte_offset: number;
  chunk_len_left: number;
  chunk_len_right: number;
  crc32_left: number;
  crc32_right: number;
  status: string;
}

interface BinaryFileDiffSummary {
  left_path: string;
  right_path: string;
  left_size_bytes: number;
  right_size_bytes: number;
  chunk_size_bytes: number;
  total_chunks: number;
  identical_chunks: number;
  different_chunks_count: number;
  elapsed_ms: number;
  different_chunks: BinaryDiffChunkMeta[];
}

interface BinaryPageByte {
  offset: number;
  left_byte: number | null;
  right_byte: number | null;
  status: string;
}

interface BinaryDiffPageResult {
  start_offset: number;
  page_size: number;
  diff_bytes_in_page: number;
  rows: BinaryPageByte[];
}

interface CdcBinaryDiffSegment {
  segment_index: number;
  status: string;
  left_offset: number;
  left_len: number;
  right_offset: number;
  right_len: number;
  shift_delta_bytes: number;
  chunk_count: number;
}

interface FastCdcBinaryDiffReport {
  left_path: string;
  right_path: string;
  left_size_bytes: number;
  right_size_bytes: number;
  left_chunks_count: number;
  right_chunks_count: number;
  identical_bytes: number;
  shifted_aligned_bytes: number;
  modified_left_bytes: number;
  modified_right_bytes: number;
  similarity_percent: number;
  elapsed_ms: number;
  segments: CdcBinaryDiffSegment[];
}

interface DirectoryDiffEntry {
  relative_path: string;
  status: string;
  is_dir: boolean;
  left_size: number | null;
  right_size: number | null;
  left_modified: string | null;
  right_modified: string | null;
  left_full_path: string | null;
  right_full_path: string | null;
}

interface DirectoryCompareReport {
  left_dir: string;
  right_dir: string;
  total_entries: number;
  identical_count: number;
  modified_count: number;
  left_only_count: number;
  right_only_count: number;
  elapsed_ms: number;
  entries: DirectoryDiffEntry[];
}

type FileSubMode = 'text' | 'binary' | 'directory';

const subModes: Array<{ id: FileSubMode; label: string; icon: string }> = [
  { id: 'text', label: '大文件 Myers 行比对与双向合并', icon: 'document' },
  { id: 'binary', label: 'GB 级二进制流式 CRC32 分页对比', icon: 'database' },
  { id: 'directory', label: '文件夹树递归对比', icon: 'layers' },
];

const mergeChoiceOptions: Array<{ id: MergeChoice; label: string }> = [
  { id: 'KeepLeft', label: '采左' },
  { id: 'KeepRight', label: '采右' },
  { id: 'KeepBothLeftFirst', label: '双留(左→右)' },
];

const diffBus = useUniversalDiff();
const subMode = ref<FileSubMode>('text');
const leftPath = ref(diffBus.droppedFileLeft.value || '');
const rightPath = ref(diffBus.droppedFileRight.value || '');
const mergeOutputPath = ref(diffBus.droppedFileLeft.value || '');
const lastMergedSavedPath = ref('');
const createBackup = ref(true);

watch([() => diffBus.droppedFileLeft.value, () => diffBus.droppedFileRight.value], ([nl, nr]) => {
  if (nl) {
    leftPath.value = nl;
    if (!mergeOutputPath.value) mergeOutputPath.value = nl;
  }
  if (nr) rightPath.value = nr;
});

async function browsePath(side: 'left' | 'right') {
  const picked = subMode.value === 'directory'
    ? await pickNativeFolderPath(side === 'left' ? '选择左侧基准目录' : '选择右侧比对目录')
    : await pickNativeFilePath(side === 'left' ? '选择左侧基准磁盘文件' : '选择右侧比对磁盘文件');
  if (picked) {
    if (side === 'left') {
      leftPath.value = picked;
      if (!mergeOutputPath.value) mergeOutputPath.value = picked;
    } else {
      rightPath.value = picked;
    }
  }
}

const options = ref<FileDiffOptions>({
  ignore_whitespace: false,
  ignore_case: false,
  ignore_line_endings: true,
});
const onlyDiffHunks = ref(false);
const verifyEqualSizeBytes = ref(true);
const onlyDirDiffs = ref(true);
const useFastCdcMode = ref(true);

const isLoading = ref(false);
const isSavingMerge = ref(false);
const errorMsg = ref('');

const textReport = ref<TextFileDiffReport | null>(null);
const hunkDecisions = ref<Record<number, MergeChoice>>({});
const defaultMergeChoice = ref<MergeChoice>('KeepLeft');

const cdcReport = ref<FastCdcBinaryDiffReport | null>(null);
const binSummary = ref<BinaryFileDiffSummary | null>(null);
const binaryPage = ref<BinaryDiffPageResult | null>(null);
const activeBinaryOffset = ref<number>(0);
const activeBinaryRightOffset = ref<number>(0);

const dirReport = ref<DirectoryCompareReport | null>(null);

const visibleTextHunks = computed(() => {
  if (!textReport.value) return [];
  return onlyDiffHunks.value
    ? textReport.value.hunks.filter(h => h.op !== 'equal')
    : textReport.value.hunks;
});

const visibleDirEntries = computed(() => {
  if (!dirReport.value) return [];
  return onlyDirDiffs.value
    ? dirReport.value.entries.filter(e => e.status !== 'Identical')
    : dirReport.value.entries;
});

function formatBytes(bytes: number): string {
  if (!bytes || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const i = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  const v = bytes / Math.pow(1024, i);
  return `${v >= 10 ? v.toFixed(1) : v.toFixed(2)} ${units[i]}`;
}

function swapLeftRightPaths() {
  const tmp = leftPath.value;
  leftPath.value = rightPath.value;
  rightPath.value = tmp;
}

function getHunkDecision(hunkId: number): MergeChoice {
  return hunkDecisions.value[hunkId] ?? defaultMergeChoice.value;
}

function setHunkDecision(hunkId: number, choice: MergeChoice) {
  hunkDecisions.value = { ...hunkDecisions.value, [hunkId]: choice };
}

function applyBulkMergeChoice(choice: MergeChoice) {
  defaultMergeChoice.value = choice;
  hunkDecisions.value = {};
  notifySuccess('已批量应用默认合并策略', `所有差异块已设为：${choice === 'KeepLeft' ? '采纳左侧' : '采纳右侧'}`);
}

function hunkOpLabel(op: string): string {
  if (op === 'equal') return '一致';
  if (op === 'insert') return '右侧新增';
  if (op === 'delete') return '左侧删除';
  return '差异替换';
}

function hunkBadgeClass(op: string): string {
  if (op === 'equal') return 'bg-slate-500/15 text-slate-600 dark:text-slate-300';
  if (op === 'insert') return 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300';
  if (op === 'delete') return 'bg-amber-500/15 text-amber-700 dark:text-amber-300';
  return 'bg-rose-500/15 text-rose-700 dark:text-rose-300';
}

function dirBadgeClass(st: string): string {
  if (st === 'Identical') return 'bg-slate-500/15 text-slate-600 dark:text-slate-300';
  if (st === 'Modified') return 'bg-rose-500/15 text-rose-700 dark:text-rose-300';
  if (st === 'LeftOnly') return 'bg-sky-500/15 text-sky-700 dark:text-sky-300';
  return 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300';
}

async function executeCompare() {
  if (!leftPath.value.trim() || !rightPath.value.trim()) return;
  isLoading.value = true;
  errorMsg.value = '';
  try {
    if (subMode.value === 'text') {
      const rep = await invoke<TextFileDiffReport>('compare_text_files_streaming_cmd', {
        leftPath: leftPath.value.trim(),
        rightPath: rightPath.value.trim(),
        options: options.value,
        maxPreviewHunks: 400,
      });
      textReport.value = rep;
      hunkDecisions.value = {};
      if (!mergeOutputPath.value.trim()) {
        mergeOutputPath.value = leftPath.value.trim();
      }
      if (rep.is_binary_suspected) {
        notifyWarning('文件包含大量 NULL 字节', '建议点击提示栏切换为二进制 64KB 流式对比模式');
      }
    } else if (subMode.value === 'binary') {
      binaryPage.value = null;
      if (useFastCdcMode.value) {
        const rep = await invoke<FastCdcBinaryDiffReport>('compare_binary_files_fastcdc_cmd', {
          leftPath: leftPath.value.trim(),
          rightPath: rightPath.value.trim(),
        });
        cdcReport.value = rep;
        const firstDiff = rep.segments.find(s => s.status === 'Modified') ?? rep.segments[0];
        if (firstDiff) {
          await loadDualOffsetBinaryPage(firstDiff.left_offset, firstDiff.right_offset);
        }
      } else {
        const sum = await invoke<BinaryFileDiffSummary>('compare_binary_files_streaming_cmd', {
          leftPath: leftPath.value.trim(),
          rightPath: rightPath.value.trim(),
          chunkSize: 65536,
        });
        binSummary.value = sum;
        if (sum.different_chunks.length > 0) {
          await loadDualOffsetBinaryPage(sum.different_chunks[0].byte_offset, sum.different_chunks[0].byte_offset);
        }
      }
    } else {
      const rep = await invoke<DirectoryCompareReport>('compare_directories_cmd', {
        leftDir: leftPath.value.trim(),
        rightDir: rightPath.value.trim(),
        verifyEqualSizeContents: verifyEqualSizeBytes.value,
      });
      dirReport.value = rep;
    }
  } catch (e) {
    errorMsg.value = `比对执行失败: ${String(e)}`;
    notifyError('磁盘文件/目录比对受阻', String(e));
  } finally {
    isLoading.value = false;
  }
}

async function loadDualOffsetBinaryPage(leftOff: number, rightOff: number) {
  try {
    activeBinaryOffset.value = leftOff;
    activeBinaryRightOffset.value = rightOff;
    binaryPage.value = await invoke<BinaryDiffPageResult>('read_binary_diff_dual_offset_page_cmd', {
      leftPath: leftPath.value.trim(),
      rightPath: rightPath.value.trim(),
      leftOffset: leftOff,
      rightOffset: rightOff,
      pageSize: 512,
    });
  } catch (e) {
    notifyError('读取二进制双指针窗口失败', String(e));
  }
}

async function saveMergedFile() {
  if (!textReport.value || !mergeOutputPath.value.trim()) return;
  isSavingMerge.value = true;
  try {
    const decisions = textReport.value.hunks
      .filter(h => h.op !== 'equal')
      .map(h => ({
        hunk_id: h.hunk_id,
        choice: getHunkDecision(h.hunk_id),
      }));

    const out = await invoke<MergeSaveOutcome>('apply_text_merge_and_save_cmd', {
      leftPath: leftPath.value.trim(),
      rightPath: rightPath.value.trim(),
      outputPath: mergeOutputPath.value.trim(),
      options: options.value,
      decisions,
      defaultChoice: defaultMergeChoice.value,
      createBackup: createBackup.value,
    });
    lastMergedSavedPath.value = out.output_path;
    notifySuccess('双向 Merge 原子保存成功', out.message);
  } catch (e) {
    notifyError('Merge 落盘失败', String(e));
  } finally {
    isSavingMerge.value = false;
  }
}

async function exportPatch() {
  if (!leftPath.value.trim() || !rightPath.value.trim()) return;
  const targetPatch = `${leftPath.value.trim()}.diff.patch`;
  try {
    const msg = await invoke<string>('export_unified_patch_file_cmd', {
      leftPath: leftPath.value.trim(),
      rightPath: rightPath.value.trim(),
      patchOutputPath: targetPatch,
      options: options.value,
    });
    notifySuccess('Unified Patch 已生成', msg);
  } catch (e) {
    notifyError('导出补丁失败', String(e));
  }
}

function switchToBinaryFromWarning() {
  subMode.value = 'binary';
  executeCompare();
}

function drillIntoTextCompare(entry: DirectoryDiffEntry) {
  if (!entry.left_full_path || !entry.right_full_path) return;
  leftPath.value = entry.left_full_path;
  rightPath.value = entry.right_full_path;
  mergeOutputPath.value = entry.left_full_path;
  subMode.value = 'text';
  executeCompare();
}
</script>
