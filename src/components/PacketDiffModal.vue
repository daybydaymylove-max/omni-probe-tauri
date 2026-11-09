<template>
  <div v-if="activeIsOpen" class="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/70 backdrop-blur-md p-4 animate-in fade-in duration-200">
    <!-- 主模态视窗 (Beyond Compare + Wireshark + 全局多模块通用差分工作台) -->
    <div class="w-full max-w-7xl h-[92vh] bg-slate-900/95 backdrop-blur-2xl rounded-2xl border border-slate-700/80 shadow-2xl flex flex-col overflow-hidden text-slate-100 font-sans">
      
      <!-- 1. 顶部控制栏与对比摘要胶囊 -->
      <div class="px-5 py-3 border-b border-slate-800 bg-slate-900/90 flex items-center justify-between shrink-0 flex-wrap gap-3">
        <div class="flex items-center gap-3">
          <div class="w-8 h-8 rounded-xl bg-gradient-to-tr from-blue-600 to-indigo-600 flex items-center justify-center shadow-md">
            <span class="text-sm">⚖️</span>
          </div>
          <div>
            <h2 class="text-sm font-bold text-white flex items-center gap-2">
              <span>全局通用数据比对与波线波率工作台</span>
              <span class="text-[10px] font-mono px-2 py-0.5 rounded-md bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                Universal Multi-Bus Diff
              </span>
            </h2>
            <div class="text-[11px] text-slate-400">
              {{ diffResult?.summary || '逐字节 LCS 严格对齐、多层规约树逐字段差分与载荷波形分析' }}
            </div>
          </div>
        </div>

        <!-- 模式切换分段控件 -->
        <div class="flex bg-slate-800/90 p-1 rounded-xl border border-slate-700/80 text-xs font-semibold">
          <button @click="switchMode('hex')"
            :class="['px-3 py-1 rounded-lg transition-all cursor-pointer flex items-center gap-1.5',
              activeMode === 'hex' ? 'bg-indigo-600 text-white shadow-sm font-bold' : 'text-slate-400 hover:text-white']">
            <span>🔠 逐字节 Hex 同步比对</span>
          </button>
          <button @click="switchMode('fields')"
            :class="['px-3 py-1 rounded-lg transition-all cursor-pointer flex items-center gap-1.5',
              activeMode === 'fields' ? 'bg-indigo-600 text-white shadow-sm font-bold' : 'text-slate-400 hover:text-white']">
            <span>🌲 规约字段差异</span>
            <span v-if="differentFieldsCount > 0" class="px-1.5 py-0.2 rounded-full text-[9px] bg-rose-500 text-white font-mono font-bold">
              {{ differentFieldsCount }}
            </span>
          </button>
          <button @click="switchMode('wave')"
            :class="['px-3 py-1 rounded-lg transition-all cursor-pointer flex items-center gap-1.5',
              activeMode === 'wave' ? 'bg-indigo-600 text-white shadow-sm font-bold' : 'text-slate-400 hover:text-white']">
            <span>📈 载荷波线与波率分析</span>
            <span v-if="diffResult?.waveform_metrics" class="px-1.5 py-0.2 rounded-full text-[9px] bg-cyan-100 text-cyan-950 dark:bg-cyan-500/20 dark:text-cyan-300 border border-cyan-300 dark:border-cyan-500/30 font-mono font-bold">
              {{ diffResult.waveform_metrics.mutation_wave_rate.toFixed(0) }}%
            </span>
          </button>
          <button @click="switchMode('scratchpad')"
            :class="['px-3 py-1 rounded-lg transition-all cursor-pointer flex items-center gap-1.5',
              activeMode === 'scratchpad' ? 'bg-indigo-600 text-white shadow-sm font-bold' : 'text-slate-400 hover:text-white']">
            <span>📝 自由草稿即时比对</span>
          </button>
          <button @click="switchMode('samples')"
            :class="['px-3 py-1 rounded-lg transition-all cursor-pointer flex items-center gap-1.5',
              activeMode === 'samples' ? 'bg-indigo-600 text-white shadow-sm font-bold' : 'text-slate-400 hover:text-white']">
            <span>📦 样本库</span>
            <span v-if="storedSamples.length > 0" class="px-1.5 py-0.2 rounded-full text-[9px] bg-slate-700 text-slate-300 font-mono">
              {{ storedSamples.length }}
            </span>
          </button>
        </div>

        <!-- 差异突变率指示卡 -->
        <div v-if="diffResult" class="flex items-center gap-3 bg-slate-800/80 px-3 py-1.5 rounded-xl border border-slate-700 text-xs font-mono">
          <div class="text-[11px] text-slate-400">
            突变字节: <strong class="text-rose-400">{{ diffResult.mutated_bytes_count }}</strong> / {{ Math.max(diffResult.total_bytes_a, diffResult.total_bytes_b) }}
          </div>
          <div class="w-24 bg-slate-700 h-2 rounded-full overflow-hidden">
            <div class="h-full transition-all duration-300"
              :class="diffResult.mutation_rate_percent > 30 ? 'bg-rose-500' : 'bg-amber-400'"
              :style="{ width: `${Math.min(100, diffResult.mutation_rate_percent)}%` }"></div>
          </div>
          <span :class="['text-[11px] font-bold', diffResult.mutation_rate_percent > 30 ? 'text-rose-400' : 'text-amber-300']">
            {{ diffResult.mutation_rate_percent.toFixed(1) }}%
          </span>
        </div>

        <!-- 导出与关闭按钮组 -->
        <div class="flex items-center gap-2">
          <button v-if="diffResult" @click="exportDiffReport"
            class="px-3 py-1.5 rounded-xl bg-indigo-600/30 hover:bg-indigo-600 text-indigo-200 hover:text-white border border-indigo-500/40 text-xs font-semibold flex items-center gap-1.5 transition-all cursor-pointer shadow-xs"
            title="导出双样本差异分析报告 (Markdown)">
            <span>📥</span>
            <span>导出差分报告</span>
          </button>
          <button @click="handleClose"
            class="w-8 h-8 rounded-xl bg-slate-800 hover:bg-rose-600 hover:text-white text-slate-400 flex items-center justify-center transition-colors cursor-pointer border border-slate-700"
            title="关闭工作台">
            ✕
          </button>
        </div>
      </div>

      <!-- 2. 双样本元信息对比条 (Header Compare Bar) -->
      <div class="px-5 py-2.5 bg-slate-950/60 border-b border-slate-800 text-xs font-mono shrink-0 flex items-center gap-3">
        <!-- 左侧：基准样本 A -->
        <div class="flex-1 flex items-center justify-between bg-slate-900/80 border border-slate-700/80 px-3 py-1.5 rounded-xl">
          <div class="flex items-center gap-2 truncate">
            <span class="px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-300 border border-blue-500/30 text-[10px] font-bold">
              基准项 A
            </span>
            <span class="font-bold text-white truncate">{{ effectiveItemA?.label || '未载入项 A' }}</span>
            <span class="text-slate-400 truncate text-[11px]" v-if="effectiveItemA?.src && effectiveItemA?.src !== '-'">
              {{ effectiveItemA.src }} ➔ {{ effectiveItemA.dst || '-' }}
            </span>
          </div>
          <div class="flex items-center gap-1 shrink-0">
            <span class="text-[10px] text-slate-400 font-normal">{{ effectiveItemA ? `${effectiveItemA.length || 0} 字节` : '' }}</span>
            <button v-if="effectiveItemA && effectiveItemA.payloadHex" @click="doSaveItemSample(effectiveItemA, 'A')"
              class="text-[10px] bg-slate-800 hover:bg-slate-700 text-slate-300 px-2 py-0.5 rounded-lg border border-slate-700 transition-colors cursor-pointer"
              title="将样本 A 固化存入本地样本库">
              💾 存为样本
            </button>
          </div>
        </div>

        <!-- 中间：互换 A ⇄ B 按钮 -->
        <button @click="swapItems" :disabled="!effectiveItemA || !effectiveItemB"
          class="shrink-0 w-8 h-8 rounded-xl bg-slate-800/80 hover:bg-indigo-600/40 text-slate-300 hover:text-white border border-slate-700 flex items-center justify-center transition-all cursor-pointer disabled:opacity-30 disabled:cursor-not-allowed shadow-xs"
          title="互换基准项 A 与比对项 B 的比对方向">
          🔄
        </button>

        <!-- 右侧：比对样本 B -->
        <div class="flex-1 flex items-center justify-between bg-slate-900/80 border border-slate-700/80 px-3 py-1.5 rounded-xl">
          <div class="flex items-center gap-2 truncate">
            <span class="px-1.5 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 text-[10px] font-bold">
              比对项 B
            </span>
            <span class="font-bold text-white truncate">{{ effectiveItemB?.label || '未载入项 B' }}</span>
            <span class="text-slate-400 truncate text-[11px]" v-if="effectiveItemB?.src && effectiveItemB?.src !== '-'">
              {{ effectiveItemB.src }} ➔ {{ effectiveItemB.dst || '-' }}
            </span>
          </div>
          <div class="flex items-center gap-1 shrink-0">
            <span class="text-[10px] text-slate-400 font-normal">{{ effectiveItemB ? `${effectiveItemB.length || 0} 字节` : '' }}</span>
            <button v-if="effectiveItemB && effectiveItemB.payloadHex" @click="doSaveItemSample(effectiveItemB, 'B')"
              class="text-[10px] bg-slate-800 hover:bg-slate-700 text-slate-300 px-2 py-0.5 rounded-lg border border-slate-700 transition-colors cursor-pointer"
              title="将样本 B 固化存入本地样本库">
              💾 存为样本
            </button>
          </div>
        </div>
      </div>

      <!-- 3. 主体视窗：根据 activeMode 呈现 -->
      <div class="flex-1 overflow-hidden min-h-0 relative">
        
        <!-- 模式一：逐字节 Hex 同步滚动对齐对比 (Beyond Compare 核心) -->
        <div v-show="activeMode === 'hex'" class="h-full grid grid-cols-2 gap-px bg-slate-800">
          
          <!-- 左栏：样本 A Hex 视窗 -->
          <div ref="hexScrollA" @scroll="onScrollA"
            class="h-full overflow-y-auto overflow-x-hidden bg-slate-950 p-4 font-mono text-xs select-text custom-scrollbar">
            <div class="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-2 border-b border-slate-800 pb-1 flex justify-between">
              <span>偏移量 | 00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F</span>
              <span>ASCII 预览</span>
            </div>

            <div v-if="diffResult?.hex_diff_a?.hex_rows && diffResult.hex_diff_a.hex_rows.length > 0" class="space-y-1">
              <div v-for="row in diffResult.hex_diff_a.hex_rows" :key="row.offset"
                class="flex items-center justify-between hover:bg-slate-900/80 px-1 py-0.5 rounded transition-colors">
                <!-- 偏移量 -->
                <span class="text-slate-500 select-none w-12 shrink-0">{{ row.offset }}</span>

                <!-- 16 字节十六进制区 -->
                <div class="flex items-center gap-1.5 flex-1 mx-2">
                  <div class="flex items-center gap-1">
                    <span v-for="(cell, ci) in row.cells.slice(0, 8)" :key="ci"
                      :class="['px-1 py-0.2 rounded-xs text-center min-w-[20px] transition-all', getCellClass(cell.diff_type)]"
                      :title="cell.diff_type !== 'equal' ? `突变类型: ${cell.diff_type}` : ''">
                      {{ cell.hex }}
                    </span>
                  </div>
                  <span class="text-slate-700 select-none">|</span>
                  <div class="flex items-center gap-1">
                    <span v-for="(cell, ci) in row.cells.slice(8, 16)" :key="ci"
                      :class="['px-1 py-0.2 rounded-xs text-center min-w-[20px] transition-all', getCellClass(cell.diff_type)]"
                      :title="cell.diff_type !== 'equal' ? `突变类型: ${cell.diff_type}` : ''">
                      {{ cell.hex }}
                    </span>
                  </div>
                </div>

                <!-- ASCII 字符区 -->
                <div class="text-slate-400 select-none w-28 shrink-0 tracking-widest pl-2 border-l border-slate-800 text-[11px]">
                  {{ row.ascii_repr }}
                </div>
              </div>
            </div>
            <div v-else class="text-center text-slate-500 py-16">
              请选择或粘贴两组有效数据执行比对
            </div>
          </div>

          <!-- 右栏：样本 B Hex 视窗 -->
          <div ref="hexScrollB" @scroll="onScrollB"
            class="h-full overflow-y-auto overflow-x-hidden bg-slate-950 p-4 font-mono text-xs select-text custom-scrollbar">
            <div class="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-2 border-b border-slate-800 pb-1 flex justify-between">
              <span>偏移量 | 00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F</span>
              <span>ASCII 预览</span>
            </div>

            <div v-if="diffResult?.hex_diff_b?.hex_rows && diffResult.hex_diff_b.hex_rows.length > 0" class="space-y-1">
              <div v-for="row in diffResult.hex_diff_b.hex_rows" :key="row.offset"
                class="flex items-center justify-between hover:bg-slate-900/80 px-1 py-0.5 rounded transition-colors">
                <!-- 偏移量 -->
                <span class="text-slate-500 select-none w-12 shrink-0">{{ row.offset }}</span>

                <!-- 16 字节十六进制区 -->
                <div class="flex items-center gap-1.5 flex-1 mx-2">
                  <div class="flex items-center gap-1">
                    <span v-for="(cell, ci) in row.cells.slice(0, 8)" :key="ci"
                      :class="['px-1 py-0.2 rounded-xs text-center min-w-[20px] transition-all', getCellClass(cell.diff_type)]"
                      :title="cell.diff_type !== 'equal' ? `突变类型: ${cell.diff_type}` : ''">
                      {{ cell.hex }}
                    </span>
                  </div>
                  <span class="text-slate-700 select-none">|</span>
                  <div class="flex items-center gap-1">
                    <span v-for="(cell, ci) in row.cells.slice(8, 16)" :key="ci"
                      :class="['px-1 py-0.2 rounded-xs text-center min-w-[20px] transition-all', getCellClass(cell.diff_type)]"
                      :title="cell.diff_type !== 'equal' ? `突变类型: ${cell.diff_type}` : ''">
                      {{ cell.hex }}
                    </span>
                  </div>
                </div>

                <!-- ASCII 字符区 -->
                <div class="text-slate-400 select-none w-28 shrink-0 tracking-widest pl-2 border-l border-slate-800 text-[11px]">
                  {{ row.ascii_repr }}
                </div>
              </div>
            </div>
            <div v-else class="text-center text-slate-500 py-16">
              请选择或粘贴两组有效数据执行比对
            </div>
          </div>
        </div>

        <!-- 模式二：协议树逐字段差异比对 (Wireshark 协议解析比对) -->
        <div v-show="activeMode === 'fields'" class="h-full overflow-auto bg-slate-950 p-4 custom-scrollbar">
          <table class="w-full text-left text-xs font-mono border-collapse table-fixed">
            <thead class="bg-slate-900 border-b border-slate-800 text-[10px] font-bold text-slate-400 uppercase sticky top-0 z-10">
              <tr>
                <th class="p-2.5 w-[16%]">规约分层</th>
                <th class="p-2.5 w-[24%]">协议字段名称</th>
                <th class="p-2.5 w-[24%]">样本 A 取值 (基准)</th>
                <th class="p-2.5 w-[24%]">样本 B 取值 (比对)</th>
                <th class="p-2.5 w-[12%] text-center">比对状态</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-800/80 text-[11px]">
              <tr v-for="(f, idx) in diffResult?.field_diffs || []" :key="idx"
                :class="['hover:bg-slate-900/60 transition-colors',
                  f.is_different ? 'bg-amber-950/20' : '']">
                <td class="p-2.5 font-bold text-slate-400 truncate">{{ f.layer }}</td>
                <td class="p-2.5 text-white font-semibold truncate">{{ f.field_name }}</td>
                <td class="p-2.5 text-slate-300 truncate" :title="f.val_a">
                  <span :class="f.is_different ? 'text-amber-300 font-bold' : ''">{{ f.val_a || '—' }}</span>
                </td>
                <td class="p-2.5 text-slate-300 truncate" :title="f.val_b">
                  <span :class="f.is_different ? 'text-rose-400 font-bold' : ''">{{ f.val_b || '—' }}</span>
                </td>
                <td class="p-2.5 text-center truncate">
                  <span :class="['px-2 py-0.5 rounded text-[9px] font-bold',
                    f.diff_type === 'EQUAL' ? 'bg-slate-800 text-slate-400 border border-slate-700' :
                    f.diff_type === 'CHANGED' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' :
                    f.diff_type === 'ADDED_IN_B' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' :
                    'bg-rose-500/20 text-rose-300 border border-rose-500/40']">
                    {{ f.diff_type === 'EQUAL' ? '一致' : f.diff_type === 'CHANGED' ? '差异' : f.diff_type === 'ADDED_IN_B' ? 'B 新增' : 'B 缺失' }}
                  </span>
                </td>
              </tr>
              <tr v-if="!diffResult?.field_diffs || diffResult.field_diffs.length === 0">
                <td colspan="5" class="p-12 text-center text-slate-500">
                  暂无元数据与规约字段差异
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- 模式三：自由草稿即时比对工作台 (Scratchpad) -->
        <div v-show="activeMode === 'scratchpad'" class="h-full overflow-auto bg-slate-950 p-5 space-y-4 custom-scrollbar">
          <!-- 快捷预设模版条 -->
          <div class="flex items-center justify-between bg-slate-900/90 border border-slate-800 p-3 rounded-xl">
            <div class="flex items-center gap-2 text-xs">
              <span class="text-slate-400">⚡ 快速载入工业规约样本比对:</span>
              <button @click="loadPresetPair('MODBUS')"
                class="px-2.5 py-1 rounded-lg bg-indigo-500/20 hover:bg-indigo-500/30 text-indigo-300 border border-indigo-500/40 text-[11px] font-mono cursor-pointer transition-colors">
                Modbus 保持寄存器 (请求 vs 响应)
              </button>
              <button @click="loadPresetPair('TCP_HANDSHAKE')"
                class="px-2.5 py-1 rounded-lg bg-blue-500/20 hover:bg-blue-500/30 text-blue-300 border border-blue-500/40 text-[11px] font-mono cursor-pointer transition-colors">
                TCP 握手 (SYN vs SYN-ACK)
              </button>
              <button @click="loadPresetPair('HTTP')"
                class="px-2.5 py-1 rounded-lg bg-purple-500/20 hover:bg-purple-500/30 text-purple-300 border border-purple-500/40 text-[11px] font-mono cursor-pointer transition-colors">
                HTTP 请求 (GET vs POST)
              </button>
              <button @click="loadPresetPair('DLT645')"
                class="px-2.5 py-1 rounded-lg bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/40 text-[11px] font-mono cursor-pointer transition-colors">
                DLT645 电力规约
              </button>
            </div>
            <button @click="executeScratchpadCompare"
              class="px-4 py-1.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-xs flex items-center gap-1.5 cursor-pointer shadow-md transition-all">
              <span>⚡ 即时执行差分与波形计算</span>
            </button>
          </div>

          <!-- 双栏编辑器 -->
          <div class="grid grid-cols-2 gap-4 h-[calc(100%-120px)]">
            <!-- 左栏：草稿 A -->
            <div class="bg-slate-900/90 border border-slate-800 rounded-2xl p-4 flex flex-col space-y-2">
              <div class="flex items-center justify-between text-xs pb-1 border-b border-slate-800">
                <div class="flex items-center gap-2">
                  <span class="w-2.5 h-2.5 rounded-full bg-blue-500"></span>
                  <span class="font-bold text-white">草稿数据项 A (基准流)</span>
                  <span class="text-[10px] font-mono text-slate-500">
                    {{ scratchTextA.length }} 字符 | 约 {{ calcByteLength(scratchTextA) }} 字节
                  </span>
                </div>
                <div class="flex items-center gap-1.5">
                  <button @click="formatScratchpadHex('A')"
                    class="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] cursor-pointer">
                    规整 Hex
                  </button>
                  <button @click="scratchTextA = ''"
                    class="px-2 py-0.5 rounded bg-slate-800 hover:bg-rose-900/40 text-slate-400 hover:text-rose-300 text-[10px] cursor-pointer">
                    清空
                  </button>
                </div>
              </div>
              <textarea v-model="scratchTextA"
                placeholder="在此直接粘贴十六进制码流 (例如: 01 03 00 00 00 02 C4 0B) 或任意 ASCII 字符串..."
                class="flex-1 w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-xs font-mono text-slate-200 placeholder-slate-600 resize-none focus:outline-none focus:border-indigo-500 custom-scrollbar leading-relaxed"></textarea>
            </div>

            <!-- 右栏：草稿 B -->
            <div class="bg-slate-900/90 border border-slate-800 rounded-2xl p-4 flex flex-col space-y-2">
              <div class="flex items-center justify-between text-xs pb-1 border-b border-slate-800">
                <div class="flex items-center gap-2">
                  <span class="w-2.5 h-2.5 rounded-full bg-indigo-500"></span>
                  <span class="font-bold text-white">草稿数据项 B (比对流)</span>
                  <span class="text-[10px] font-mono text-slate-500">
                    {{ scratchTextB.length }} 字符 | 约 {{ calcByteLength(scratchTextB) }} 字节
                  </span>
                </div>
                <div class="flex items-center gap-1.5">
                  <button @click="formatScratchpadHex('B')"
                    class="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] cursor-pointer">
                    规整 Hex
                  </button>
                  <button @click="scratchTextB = ''"
                    class="px-2 py-0.5 rounded bg-slate-800 hover:bg-rose-900/40 text-slate-400 hover:text-rose-300 text-[10px] cursor-pointer">
                    清空
                  </button>
                </div>
              </div>
              <textarea v-model="scratchTextB"
                placeholder="在此直接粘贴十六进制码流 (例如: 01 03 04 00 12 00 34 89 21) 或任意 ASCII 字符串..."
                class="flex-1 w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-xs font-mono text-slate-200 placeholder-slate-600 resize-none focus:outline-none focus:border-indigo-500 custom-scrollbar leading-relaxed"></textarea>
            </div>
          </div>
        </div>

        <!-- 模式四：载荷波线与变异波率分析 (Waveform & Mutation Wave Rate) -->
        <div v-show="activeMode === 'wave'" class="h-full overflow-auto bg-slate-950 p-5 space-y-4 custom-scrollbar">
          <!-- 1. 五维科学统计指标卡片网格 -->
          <div v-if="diffResult?.waveform_metrics" class="grid grid-cols-5 gap-3 font-mono">
            <!-- 指标 1: 余弦几何相似度 -->
            <div class="bg-slate-900/90 border border-slate-800 rounded-xl p-3 flex flex-col justify-between">
              <span class="text-[10px] text-slate-400 font-sans">余弦几何相似度 (Cosine)</span>
              <div class="flex items-baseline justify-between mt-1">
                <span class="text-lg font-bold font-mono text-cyan-300">
                  {{ (diffResult.waveform_metrics.cosine_similarity * 100).toFixed(1) }}%
                </span>
                <span class="text-[10px] text-slate-500 font-mono">0~100%</span>
              </div>
              <span class="text-[9px] text-slate-400 mt-2 truncate">
                {{ diffResult.waveform_metrics.cosine_similarity >= 0.95 ? '高度同构' : diffResult.waveform_metrics.cosine_similarity >= 0.7 ? '局部相似' : '结构显著差异' }}
              </span>
            </div>

            <!-- 指标 2: 皮尔逊相关系数 -->
            <div class="bg-slate-900/90 border border-slate-800 rounded-xl p-3 flex flex-col justify-between">
              <span class="text-[10px] text-slate-400 font-sans">皮尔逊相关系数 (Pearson)</span>
              <div class="flex items-baseline justify-between mt-1">
                <span class="text-lg font-bold font-mono" :class="diffResult.waveform_metrics.pearson_correlation >= 0.7 ? 'text-emerald-400' : 'text-slate-300'">
                  {{ diffResult.waveform_metrics.pearson_correlation.toFixed(3) }}
                </span>
                <span class="text-[10px] text-slate-500 font-mono">-1.0 ~ +1.0</span>
              </div>
              <span class="text-[9px] text-slate-400 mt-2 truncate">
                {{ diffResult.waveform_metrics.pearson_correlation >= 0.8 ? '高度同向波动' : diffResult.waveform_metrics.pearson_correlation >= 0.3 ? '中度协同' : '弱相关/畸变' }}
              </span>
            </div>

            <!-- 指标 3: 变异波率 -->
            <div class="bg-slate-900/90 border border-slate-800 rounded-xl p-3 flex flex-col justify-between">
              <span class="text-[10px] text-slate-400 font-sans">变异波率 (Mutation Rate)</span>
              <div class="flex items-baseline justify-between mt-1">
                <span class="text-lg font-bold font-mono" :class="diffResult.waveform_metrics.mutation_wave_rate > 30 ? 'text-rose-400' : 'text-amber-300'">
                  {{ diffResult.waveform_metrics.mutation_wave_rate.toFixed(1) }}%
                </span>
                <span class="text-[10px] text-slate-500 font-mono">突变点占比</span>
              </div>
              <div class="w-full bg-slate-800 h-1.5 rounded-full mt-2 overflow-hidden">
                <div class="h-full rounded-full transition-all" :class="diffResult.waveform_metrics.mutation_wave_rate > 30 ? 'bg-rose-500' : 'bg-amber-400'"
                  :style="{ width: `${Math.min(100, diffResult.waveform_metrics.mutation_wave_rate)}%` }"></div>
              </div>
            </div>

            <!-- 指标 4: 最大偏差跃变峰 -->
            <div class="bg-slate-900/90 border border-slate-800 rounded-xl p-3 flex flex-col justify-between">
              <span class="text-[10px] text-slate-400 font-sans">最大跳变峰 (Peak Delta)</span>
              <div class="flex items-baseline justify-between mt-1">
                <span class="text-lg font-bold font-mono text-rose-400">
                  Δ{{ diffResult.waveform_metrics.max_delta_value }}
                </span>
                <span class="text-[10px] font-mono text-indigo-300 bg-indigo-500/20 px-1 py-0.2 rounded border border-indigo-500/30">
                  0x{{ diffResult.waveform_metrics.max_delta_offset.toString(16).toUpperCase() }}
                </span>
              </div>
              <span class="text-[9px] text-slate-400 mt-2 truncate">
                发生于偏移量 #{{ diffResult.waveform_metrics.max_delta_offset }}
              </span>
            </div>

            <!-- 指标 5: 平均绝对偏差 -->
            <div class="bg-slate-900/90 border border-slate-800 rounded-xl p-3 flex flex-col justify-between">
              <span class="text-[10px] text-slate-400 font-sans">平均绝对振幅差 (MAD)</span>
              <div class="flex items-baseline justify-between mt-1">
                <span class="text-lg font-bold font-mono text-purple-300">
                  {{ diffResult.waveform_metrics.mean_absolute_deviation.toFixed(1) }}
                </span>
                <span class="text-[10px] text-slate-500 font-mono">/255</span>
              </div>
              <span class="text-[9px] text-slate-400 mt-2 truncate">
                全字节平均差异震级
              </span>
            </div>
          </div>

          <!-- 2. 双波线叠加视窗与十字标尺信息条 -->
          <div class="bg-slate-900/80 rounded-2xl border border-slate-800 p-4 space-y-3">
            <div class="flex items-center justify-between text-xs pb-1 border-b border-slate-800">
              <div class="flex items-center gap-3 font-mono">
                <span class="font-bold text-white font-sans text-xs">载荷逐字节数值波线叠加对照 (Byte Value Waveform)</span>
                <span class="flex items-center gap-1.5 text-[11px] text-cyan-400">
                  <span class="w-2.5 h-1 bg-cyan-400 rounded-full inline-block"></span>
                  <span>基准样本 A</span>
                </span>
                <span class="flex items-center gap-1.5 text-[11px] text-purple-400">
                  <span class="w-2.5 h-1 bg-purple-400 rounded-full inline-block"></span>
                  <span>比对样本 B</span>
                </span>
              </div>
              <div v-if="hoverPoint" class="text-[11px] font-mono flex items-center gap-2 bg-slate-950 px-2.5 py-1 rounded-lg border border-slate-800">
                <span class="text-slate-400">偏移: <strong class="text-white">0x{{ hoverPoint.offset.toString(16).toUpperCase() }} ({{ hoverPoint.offset }})</strong></span>
                <span class="text-cyan-400">A: 0x{{ hoverPoint.val_a.toString(16).padStart(2,'0').toUpperCase() }} ({{ hoverPoint.val_a }})</span>
                <span class="text-purple-400">B: 0x{{ hoverPoint.val_b.toString(16).padStart(2,'0').toUpperCase() }} ({{ hoverPoint.val_b }})</span>
                <span :class="hoverPoint.delta !== 0 ? 'text-rose-400 font-bold' : 'text-slate-500'">Δ: {{ hoverPoint.delta > 0 ? '+' : '' }}{{ hoverPoint.delta }}</span>
              </div>
              <span v-else class="text-[10px] text-slate-500 font-mono">移动鼠标至图表以激活十字探针</span>
            </div>

            <div class="h-56 bg-slate-950 rounded-xl border border-slate-800 relative overflow-hidden flex items-center justify-center">
              <canvas ref="diffWaveCanvas" @mousemove="onWaveMouseMove" @mouseleave="hoverPoint = null" class="w-full h-full cursor-crosshair"></canvas>
            </div>
          </div>

          <!-- 3. 差分波率与偏差振幅柱状谱 (Delta Spectrum) -->
          <div class="bg-slate-900/80 rounded-2xl border border-slate-800 p-4 space-y-3">
            <div class="flex items-center justify-between text-xs pb-1 border-b border-slate-800 font-mono">
              <div class="flex items-center gap-2">
                <span class="font-bold text-white font-sans text-xs">逐字节偏差振幅谱与变异密度 (|Δ| Amplitude Spectrum)</span>
                <span class="text-[10px] text-slate-500 font-sans">点击柱位可直接切换 Hex 查看对应字节</span>
              </div>
              <div class="flex items-center gap-3 text-[10px] font-sans text-slate-400">
                <span class="flex items-center gap-1"><span class="w-2 h-2 rounded bg-slate-700"></span> 0 一致</span>
                <span class="flex items-center gap-1"><span class="w-2 h-2 rounded bg-amber-500"></span> 1~64 微变</span>
                <span class="flex items-center gap-1"><span class="w-2 h-2 rounded bg-orange-500"></span> 65~128 中变</span>
                <span class="flex items-center gap-1"><span class="w-2 h-2 rounded bg-rose-500"></span> >128 强突变</span>
              </div>
            </div>

            <div class="h-36 bg-slate-950 rounded-xl border border-slate-800 relative overflow-hidden flex items-center justify-center">
              <canvas ref="deltaSpectrumCanvas" @mousemove="onDeltaMouseMove" @click="onDeltaSpectrumClick" @mouseleave="hoverDelta = null" class="w-full h-full cursor-pointer"></canvas>
            </div>
          </div>
        </div>

        <!-- 模式五：报文特征样本库管理 (Packet Sample Archival) -->
        <div v-show="activeMode === 'samples'" class="h-full overflow-auto bg-slate-950 p-5 space-y-3 custom-scrollbar">
          <div class="flex items-center justify-between border-b border-slate-800 pb-2">
            <div class="text-xs text-slate-300">
              已固化报文样本库 (共 <strong>{{ storedSamples.length }}</strong> 笔历史样本)
            </div>
            <button @click="loadStoredSamples"
              class="bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs px-3 py-1 rounded-xl border border-slate-700 transition-colors cursor-pointer">
              🔄 刷新
            </button>
          </div>

          <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div v-for="s in storedSamples" :key="s.id"
              class="bg-slate-900 border border-slate-800 p-3 rounded-xl flex flex-col gap-2 hover:border-slate-700 transition-all">
              <div class="flex items-center justify-between">
                <span class="font-bold text-white text-xs truncate max-w-[280px]" :title="s.name">{{ s.name }}</span>
                <span class="text-[10px] font-mono text-slate-500">{{ s.created_at }}</span>
              </div>
              <div class="text-[11px] font-mono text-slate-400 bg-slate-950/80 p-2 rounded-lg border border-slate-800/80">
                <div>样本: #{{ s.packet.id || '-' }} | 规约: <strong class="text-indigo-400">{{ s.packet.protocol || 'RAW' }}</strong> | 长度: {{ s.packet.length || 0 }} 字节</div>
                <div>端点: {{ s.packet.src_ip || '-' }}:{{ s.packet.src_port || 0 }} ➔ {{ s.packet.dst_ip || '-' }}:{{ s.packet.dst_port || 0 }}</div>
              </div>
              <div class="flex items-center justify-end gap-2 pt-1">
                <button @click="loadSampleAs('A', s.packet)"
                  class="text-[11px] bg-blue-600/30 hover:bg-blue-600 text-blue-200 hover:text-white px-2.5 py-1 rounded-lg border border-blue-500/40 cursor-pointer transition-colors">
                  载入为基准 A
                </button>
                <button @click="loadSampleAs('B', s.packet)"
                  class="text-[11px] bg-indigo-600/30 hover:bg-indigo-600 text-indigo-200 hover:text-white px-2.5 py-1 rounded-lg border border-indigo-500/40 cursor-pointer transition-colors">
                  载入为比对 B
                </button>
                <button @click="doDeleteSample(s.id)"
                  class="text-[11px] bg-rose-600/20 hover:bg-rose-600 text-rose-300 hover:text-white px-2 py-1 rounded-lg border border-rose-500/30 cursor-pointer transition-colors">
                  删除
                </button>
              </div>
            </div>
            <div v-if="storedSamples.length === 0" class="col-span-2 text-center py-12 text-slate-500">
              样本库为空，可在比对界面点击「💾 存为样本」固化基准数据
            </div>
          </div>
        </div>

      </div>

      <!-- 4. 底部状态与操作栏 (多色标注体系) -->
      <div class="px-5 py-2.5 bg-slate-900 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400 shrink-0 font-mono">
        <div class="flex items-center gap-3 flex-wrap">
          <span class="flex items-center gap-1.5">
            <span class="w-2.5 h-2.5 rounded bg-slate-600"></span>
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

        <div class="flex items-center gap-2">
          <button @click="handleClose"
            class="bg-slate-800 hover:bg-slate-700 text-slate-200 px-4 py-1.5 rounded-xl border border-slate-700 transition-colors cursor-pointer font-semibold">
            关闭视窗
          </button>
        </div>
      </div>

    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted, nextTick } from 'vue';
import { notifySuccess, notifyInfo, notifyError } from '../composables/useNotification';
import { useUniversalDiff, normalizeToDiffableItem, type UniversalDiffItem } from '../composables/useUniversalDiff';
import { invoke } from '@tauri-apps/api/core';

export interface ByteCell {
  hex: string;
  ascii: string;
  diff_type: string; // "equal"|"replace"|"insert"|"delete"
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

const activeMode = ref<'hex' | 'fields' | 'wave' | 'samples' | 'scratchpad'>('hex');
const diffResult = ref<DualPacketDiffResult | null>(null);
const storedSamples = ref<StoredPacketSample[]>([]);

// 草稿即时比对文本
const scratchTextA = ref('');
const scratchTextB = ref('');

// 归一化生效数据项
const effectiveItemA = computed<UniversalDiffItem | null>(() => {
  if (props.packetA) return normalizeToDiffableItem(props.packetA, '基准样本 A');
  if (diffBus.currentItemA.value) return diffBus.currentItemA.value;
  if (scratchTextA.value) return normalizeToDiffableItem(scratchTextA.value, '草稿项 A');
  return null;
});

const effectiveItemB = computed<UniversalDiffItem | null>(() => {
  if (props.packetB) return normalizeToDiffableItem(props.packetB, '比对样本 B');
  if (diffBus.currentItemB.value) return diffBus.currentItemB.value;
  if (scratchTextB.value) return normalizeToDiffableItem(scratchTextB.value, '草稿项 B');
  return null;
});

// 波形与差分谱 Canvas 引用与交互探针
const diffWaveCanvas = ref<HTMLCanvasElement | null>(null);
const deltaSpectrumCanvas = ref<HTMLCanvasElement | null>(null);
const hoverPoint = ref<DiffWaveformPoint | null>(null);
const hoverDelta = ref<DiffWaveformPoint | null>(null);

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
  if (diffType === 'replace' || diffType === 'delete') {
    return 'bg-rose-600 text-white font-bold shadow-xs';
  }
  if (diffType === 'insert') {
    return 'bg-emerald-600 text-white font-bold shadow-xs';
  }
  return 'text-slate-400 hover:text-white';
}

const differentFieldsCount = computed(() => {
  if (!diffResult.value?.field_diffs) return 0;
  return diffResult.value.field_diffs.filter(f => f.is_different).length;
});

function handleClose() {
  emit('close');
  diffBus.closeUniversalDiff();
}

function switchMode(mode: 'hex' | 'fields' | 'wave' | 'samples' | 'scratchpad') {
  activeMode.value = mode;
  diffBus.activeMode.value = mode;
  if (mode === 'wave') {
    nextTick(() => {
      drawDiffWaveform();
      drawDeltaSpectrum();
    });
  }
}

async function runCompare() {
  const itemA = effectiveItemA.value;
  const itemB = effectiveItemB.value;
  if (!itemA || !itemB) return;

  try {
    const res = await invoke<DualPacketDiffResult>('compare_universal_payloads_cmd', {
      itemA: {
        id: typeof itemA.id === 'number' ? itemA.id : undefined,
        label: itemA.label || '样本 A',
        timestamp: itemA.timestamp,
        protocol: itemA.protocol,
        endpoint_src: itemA.src,
        endpoint_dst: itemA.dst,
        payload_hex: itemA.payloadHex || '',
        raw_text: itemA.rawText || '',
        extra_fields: itemA.extraFields || {}
      },
      itemB: {
        id: typeof itemB.id === 'number' ? itemB.id : undefined,
        label: itemB.label || '样本 B',
        timestamp: itemB.timestamp,
        protocol: itemB.protocol,
        endpoint_src: itemB.src,
        endpoint_dst: itemB.dst,
        payload_hex: itemB.payloadHex || '',
        raw_text: itemB.rawText || '',
        extra_fields: itemB.extraFields || {}
      }
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

async function loadStoredSamples() {
  try {
    const res = await invoke<StoredPacketSample[]>('list_packet_samples_cmd');
    storedSamples.value = res || [];
  } catch (e: any) {
    console.error('加载报文样本库失败:', e);
  }
}

function loadSampleAs(slot: 'A' | 'B', packet: any) {
  if (slot === 'A') {
    emit('selectAsA', packet);
    diffBus.setSlotA(packet, `样本库 #${packet.id || ''}`);
    diffBus.currentItemA.value = normalizeToDiffableItem(packet, `样本库 #${packet.id || ''}`);
  } else {
    emit('selectAsB', packet);
    diffBus.setSlotB(packet, `样本库 #${packet.id || ''}`);
    diffBus.currentItemB.value = normalizeToDiffableItem(packet, `样本库 #${packet.id || ''}`);
  }
  notifyInfo('已载入样本', `已载入样本 #${packet.id || ''} 至槽位 ${slot}`);
  runCompare();
}

async function doSaveItemSample(item: UniversalDiffItem, slot: 'A' | 'B') {
  const defaultName = `样本_${item.protocol || 'DATA'}_${slot}_${Date.now().toString().slice(-4)}`;
  const name = prompt('请输入该特征样本归档名称:', defaultName);
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
  if (!confirm('确定要删除此份历史报文样本吗？')) return;
  try {
    await invoke('delete_packet_sample_cmd', { id });
    await loadStoredSamples();
    notifyInfo('特征样本已移除', '该样本已从本地样本库中安全删除');
  } catch (e: any) {
    notifyError('删除特征样本失败', e);
  }
}

function swapItems() {
  if (props.packetA && props.packetB) {
    const tempA = props.packetA;
    emit('selectAsA', props.packetB);
    emit('selectAsB', tempA);
  } else {
    diffBus.swapSlots();
  }
  const tTxt = scratchTextA.value;
  scratchTextA.value = scratchTextB.value;
  scratchTextB.value = tTxt;
  runCompare();
}

function calcByteLength(text: string): number {
  const clean = text.replace(/[\s\r\n\t]/g, '');
  if (/^[0-9a-fA-F]+$/.test(clean) && clean.length % 2 === 0) {
    return clean.length / 2;
  }
  return text.length;
}

function formatScratchpadHex(slot: 'A' | 'B') {
  const raw = slot === 'A' ? scratchTextA.value : scratchTextB.value;
  const clean = raw.replace(/[^0-9a-fA-F]/g, '');
  if (!clean) return;
  const chunks: string[] = [];
  for (let i = 0; i < clean.length; i += 2) {
    chunks.push(clean.slice(i, i + 2).toUpperCase());
  }
  const formatted = chunks.join(' ');
  if (slot === 'A') scratchTextA.value = formatted;
  else scratchTextB.value = formatted;
}

function loadPresetPair(type: 'MODBUS' | 'TCP_HANDSHAKE' | 'HTTP' | 'DLT645') {
  if (type === 'MODBUS') {
    scratchTextA.value = '01 03 00 00 00 02 C4 0B'; // 读保持寄存器 0x0000 长度 2
    scratchTextB.value = '01 03 04 00 12 00 34 89 21'; // 响应 4 字节数据 00 12 00 34
  } else if (type === 'TCP_HANDSHAKE') {
    scratchTextA.value = '45 00 00 34 1a 2b 40 00 40 06 00 00 7f 00 00 01 7f 00 00 01 1f 90 00 50 12 34 56 78 00 00 00 00 80 02 72 10';
    scratchTextB.value = '45 00 00 34 3c 4d 40 00 40 06 00 00 7f 00 00 01 7f 00 00 01 00 50 1f 90 87 65 43 21 12 34 56 79 80 12 72 10';
  } else if (type === 'HTTP') {
    scratchTextA.value = '47 45 54 20 2f 61 70 69 2f 76 31 2f 73 74 61 74 75 73 20 48 54 54 50 2f 31 2e 31 0d 0a 48 6f 73 74 3a 20 6c 6f 63 61 6c 68 6f 73 74';
    scratchTextB.value = '50 4f 53 54 20 2f 61 70 69 2f 76 31 2f 75 70 64 61 74 65 20 48 54 54 50 2f 31 2e 31 0d 0a 48 6f 73 74 3a 20 6c 6f 63 61 6c 68 6f 73 74';
  } else if (type === 'DLT645') {
    scratchTextA.value = '68 12 34 56 78 90 12 68 11 04 33 33 33 33 7A 16';
    scratchTextB.value = '68 12 34 56 78 90 12 68 91 08 33 33 33 33 45 67 89 01 EF 16';
  }
  executeScratchpadCompare();
}

function executeScratchpadCompare() {
  diffBus.currentItemA.value = normalizeToDiffableItem(scratchTextA.value, '草稿项 A');
  diffBus.currentItemB.value = normalizeToDiffableItem(scratchTextB.value, '草稿项 B');
  runCompare();
  notifySuccess('差分与波形计算就绪', '已基于草稿输入完成逐字节对齐与波形指标分析');
}

function exportDiffReport() {
  if (!diffResult.value) return;
  const res = diffResult.value;
  const timeStr = new Date().toISOString().replace(/T/, ' ').replace(/\..+/, '');

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

  const blob = new Blob([md], { type: 'text/markdown;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `data_diff_${Date.now()}.md`;
  a.click();
  URL.revokeObjectURL(url);
  notifySuccess('差分分析报告已导出', '已成功生成 Markdown 分析报告');
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

  // 1. 底色
  ctx.fillStyle = '#020617';
  ctx.fillRect(0, 0, W, H);

  const points = diffResult.value?.waveform_metrics?.waveform_points;
  if (!points || points.length === 0) {
    ctx.fillStyle = '#64748b';
    ctx.font = '12px sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('暂无有效载荷波形点位', W / 2, H / 2);
    return;
  }

  const padL = 36;
  const padR = 16;
  const padT = 16;
  const padB = 22;
  const plotW = W - padL - padR;
  const plotH = H - padT - padB;

  // 2. 标尺网格 (0, 64, 128, 192, 255)
  ctx.strokeStyle = 'rgba(51, 65, 85, 0.4)';
  ctx.lineWidth = 1;
  ctx.fillStyle = '#64748b';
  ctx.font = '10px monospace';
  ctx.textAlign = 'right';

  const yTicks = [0, 64, 128, 192, 255];
  for (const t of yTicks) {
    const y = padT + plotH - (t / 255) * plotH;
    ctx.beginPath();
    ctx.moveTo(padL, y);
    ctx.lineTo(W - padR, y);
    ctx.stroke();
    ctx.fillText(t.toString(), padL - 6, y + 3);
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
      ctx.fillStyle = 'rgba(244, 63, 94, 0.12)';
      ctx.fillRect(x1, padT, Math.max(2, x2 - x1), plotH);
    }
  }

  // 4. 绘制折线 A (青蓝色 #22d3ee)
  ctx.beginPath();
  ctx.strokeStyle = '#22d3ee';
  ctx.lineWidth = 1.6;
  for (let i = 0; i < N; i++) {
    const x = getX(i);
    const y = getY(points[i].val_a);
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  }
  ctx.stroke();

  // 5. 绘制折线 B (霓虹紫 #c084fc)
  ctx.beginPath();
  ctx.strokeStyle = '#c084fc';
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
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.5)';
      ctx.setLineDash([3, 3]);
      ctx.beginPath();
      ctx.moveTo(hx, padT);
      ctx.lineTo(hx, padT + plotH);
      ctx.stroke();
      ctx.setLineDash([]);

      const ya = getY(hoverPoint.value.val_a);
      ctx.fillStyle = '#22d3ee';
      ctx.beginPath();
      ctx.arc(hx, ya, 4, 0, Math.PI * 2);
      ctx.fill();

      const yb = getY(hoverPoint.value.val_b);
      ctx.fillStyle = '#c084fc';
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

  // 1. 底色
  ctx.fillStyle = '#020617';
  ctx.fillRect(0, 0, W, H);

  const points = diffResult.value?.waveform_metrics?.waveform_points;
  if (!points || points.length === 0) return;

  const padL = 36;
  const padR = 16;
  const padT = 10;
  const padB = 20;
  const plotW = W - padL - padR;
  const plotH = H - padT - padB;

  // 2. 标尺线 (0, 128, 255)
  ctx.strokeStyle = 'rgba(51, 65, 85, 0.4)';
  ctx.lineWidth = 1;
  ctx.fillStyle = '#64748b';
  ctx.font = '9px monospace';
  ctx.textAlign = 'right';

  [0, 128, 255].forEach(v => {
    const y = padT + plotH - (v / 255) * plotH;
    ctx.beginPath();
    ctx.moveTo(padL, y);
    ctx.lineTo(W - padR, y);
    ctx.stroke();
    ctx.fillText(`Δ${v}`, padL - 4, y + 3);
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
      ctx.fillStyle = 'rgba(51, 65, 85, 0.6)';
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
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.8)';
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

// 监听数据项变更，触发自动差分比对
watch([() => effectiveItemA.value?.payloadHex, () => effectiveItemB.value?.payloadHex], () => {
  if (activeIsOpen.value) {
    runCompare();
  }
});

watch(activeIsOpen, (open) => {
  if (open) {
    if (diffBus.scratchpadTextA.value) scratchTextA.value = diffBus.scratchpadTextA.value;
    if (diffBus.scratchpadTextB.value) scratchTextB.value = diffBus.scratchpadTextB.value;
    loadStoredSamples();
    runCompare();
  }
});

onMounted(() => {
  if (activeIsOpen.value) {
    loadStoredSamples();
    runCompare();
  }
});
</script>
