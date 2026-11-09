<template>
  <div v-if="isOpen" class="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/70 backdrop-blur-md p-4 animate-in fade-in duration-200">
    <!-- 主模态视窗 (Beyond Compare + Wireshark 工业级双栏工作台) -->
    <div class="w-full max-w-7xl h-[90vh] bg-slate-900/95 backdrop-blur-2xl rounded-2xl border border-slate-700/80 shadow-2xl flex flex-col overflow-hidden text-slate-100 font-sans">
      
      <!-- 1. 顶部控制栏与对比摘要胶囊 -->
      <div class="px-5 py-3 border-b border-slate-800 bg-slate-900/90 flex items-center justify-between shrink-0 flex-wrap gap-3">
        <div class="flex items-center gap-3">
          <div class="w-8 h-8 rounded-xl bg-gradient-to-tr from-blue-600 to-indigo-600 flex items-center justify-center shadow-md">
            <span class="text-sm">⚖️</span>
          </div>
          <div>
            <h2 class="text-sm font-bold text-white flex items-center gap-2">
              <span>专业报文协议与 Hex 双栏差分工作台</span>
              <span class="text-[10px] font-mono px-2 py-0.5 rounded-md bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                Wireshark + Beyond Compare 对齐
              </span>
            </h2>
            <div class="text-[11px] text-slate-400">
              {{ diffResult?.summary || '逐字节 LCS 严格对齐与多层协议树逐字段比对' }}
            </div>
          </div>
        </div>

        <!-- 模式切换分段控件 -->
        <div class="flex bg-slate-800/90 p-1 rounded-xl border border-slate-700/80 text-xs font-semibold">
          <button @click="activeMode = 'hex'"
            :class="['px-3 py-1 rounded-lg transition-all cursor-pointer flex items-center gap-1.5',
              activeMode === 'hex' ? 'bg-indigo-600 text-white shadow-sm font-bold' : 'text-slate-400 hover:text-white']">
            <span>🔠 逐字节 Hex 同步比对</span>
          </button>
          <button @click="activeMode = 'fields'"
            :class="['px-3 py-1 rounded-lg transition-all cursor-pointer flex items-center gap-1.5',
              activeMode === 'fields' ? 'bg-indigo-600 text-white shadow-sm font-bold' : 'text-slate-400 hover:text-white']">
            <span>🌲 协议树字段差异</span>
            <span v-if="differentFieldsCount > 0" class="px-1.5 py-0.2 rounded-full text-[9px] bg-rose-500 text-white font-mono font-bold">
              {{ differentFieldsCount }}
            </span>
          </button>
          <button @click="activeMode = 'wave'"
            :class="['px-3 py-1 rounded-lg transition-all cursor-pointer flex items-center gap-1.5',
              activeMode === 'wave' ? 'bg-indigo-600 text-white shadow-sm font-bold' : 'text-slate-400 hover:text-white']">
            <span>📈 载荷波线与波率分析</span>
            <span v-if="diffResult?.waveform_metrics" class="px-1.5 py-0.2 rounded-full text-[9px] bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 font-mono">
              {{ diffResult.waveform_metrics.mutation_wave_rate.toFixed(0) }}%
            </span>
          </button>
          <button @click="activeMode = 'samples'"
            :class="['px-3 py-1 rounded-lg transition-all cursor-pointer flex items-center gap-1.5',
              activeMode === 'samples' ? 'bg-indigo-600 text-white shadow-sm font-bold' : 'text-slate-400 hover:text-white']">
            <span>📦 报文样本库</span>
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
            title="导出双报文差异分析报告 (Markdown)">
            <span>📥</span>
            <span>导出差分报告</span>
          </button>
          <button @click="$emit('close')"
            class="w-8 h-8 rounded-xl bg-slate-800 hover:bg-rose-600 hover:text-white text-slate-400 flex items-center justify-center transition-colors cursor-pointer border border-slate-700"
            title="关闭视窗">
            ✕
          </button>
        </div>
      </div>

      <!-- 2. 双报文元信息对比条 (Header Compare Bar) -->
      <div class="px-5 py-2.5 bg-slate-950/60 border-b border-slate-800 text-xs font-mono shrink-0 flex items-center gap-3">
        <!-- 左侧：基准报文 A -->
        <div class="flex-1 flex items-center justify-between bg-slate-900/80 border border-slate-700/80 px-3 py-1.5 rounded-xl">
          <div class="flex items-center gap-2 truncate">
            <span class="px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-300 border border-blue-500/30 text-[10px] font-bold">
              基准报文 A
            </span>
            <span class="font-bold text-white truncate">{{ packetA ? `#${packetA.id} ${packetA.protocol}` : '未指定' }}</span>
            <span class="text-slate-400 truncate text-[11px]" v-if="packetA">
              {{ packetA.src_ip }}:{{ packetA.src_port }} ➔ {{ packetA.dst_ip }}:{{ packetA.dst_port }}
            </span>
          </div>
          <div class="flex items-center gap-1 shrink-0">
            <span class="text-[10px] text-slate-400 font-normal">{{ packetA ? `${packetA.length} 字节` : '' }}</span>
            <button v-if="packetA" @click="doSaveSample(packetA, 'A')"
              class="text-[10px] bg-slate-800 hover:bg-slate-700 text-slate-300 px-2 py-0.5 rounded-lg border border-slate-700 transition-colors cursor-pointer"
              title="将报文 A 保存到样本库">
              💾 存为样本
            </button>
          </div>
        </div>

        <!-- 中间：互换 A ⇄ B 按钮 -->
        <button @click="swapPackets" :disabled="!packetA || !packetB"
          class="shrink-0 w-8 h-8 rounded-xl bg-slate-800/80 hover:bg-indigo-600/40 text-slate-300 hover:text-white border border-slate-700 flex items-center justify-center transition-all cursor-pointer disabled:opacity-30 disabled:cursor-not-allowed shadow-xs"
          title="互换基准报文 A 与比对报文 B 的比对方向">
          🔄
        </button>

        <!-- 右侧：比对报文 B -->
        <div class="flex-1 flex items-center justify-between bg-slate-900/80 border border-slate-700/80 px-3 py-1.5 rounded-xl">
          <div class="flex items-center gap-2 truncate">
            <span class="px-1.5 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 text-[10px] font-bold">
              比对报文 B
            </span>
            <span class="font-bold text-white truncate">{{ packetB ? `#${packetB.id} ${packetB.protocol}` : '未指定' }}</span>
            <span class="text-slate-400 truncate text-[11px]" v-if="packetB">
              {{ packetB.src_ip }}:{{ packetB.src_port }} ➔ {{ packetB.dst_ip }}:{{ packetB.dst_port }}
            </span>
          </div>
          <div class="flex items-center gap-1 shrink-0">
            <span class="text-[10px] text-slate-400 font-normal">{{ packetB ? `${packetB.length} 字节` : '' }}</span>
            <button v-if="packetB" @click="doSaveSample(packetB, 'B')"
              class="text-[10px] bg-slate-800 hover:bg-slate-700 text-slate-300 px-2 py-0.5 rounded-lg border border-slate-700 transition-colors cursor-pointer"
              title="将报文 B 保存到样本库">
              💾 存为样本
            </button>
          </div>
        </div>
      </div>

      <!-- 3. 主体视窗：根据 activeMode 呈现 -->
      <div class="flex-1 overflow-hidden min-h-0 relative">
        
        <!-- 模式一：逐字节 Hex 同步滚动对齐对比 (Beyond Compare 核心) -->
        <div v-show="activeMode === 'hex'" class="h-full grid grid-cols-2 gap-px bg-slate-800">
          
          <!-- 左栏：报文 A Hex 视窗 -->
          <div ref="hexScrollA" @scroll="onScrollA"
            class="h-full overflow-y-auto overflow-x-hidden bg-slate-950 p-4 font-mono text-xs select-text custom-scrollbar">
            <div class="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-2 border-b border-slate-800 pb-1 flex justify-between">
              <span>偏移量 | 00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F</span>
              <span>ASCII 预览</span>
            </div>

            <div v-if="diffResult?.hex_diff_a?.hex_rows" class="space-y-1">
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
              请选择两个有效报文执行比对
            </div>
          </div>

          <!-- 右栏：报文 B Hex 视窗 -->
          <div ref="hexScrollB" @scroll="onScrollB"
            class="h-full overflow-y-auto overflow-x-hidden bg-slate-950 p-4 font-mono text-xs select-text custom-scrollbar">
            <div class="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-2 border-b border-slate-800 pb-1 flex justify-between">
              <span>偏移量 | 00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F</span>
              <span>ASCII 预览</span>
            </div>

            <div v-if="diffResult?.hex_diff_b?.hex_rows" class="space-y-1">
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
              请选择两个有效报文执行比对
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
                <th class="p-2.5 w-[24%]">报文 A 取值 (基准)</th>
                <th class="p-2.5 w-[24%]">报文 B 取值 (比对)</th>
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
                  暂无协议字段比对数据
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- 模式三：报文特征样本库管理 (Packet Sample Archival) -->
        <div v-show="activeMode === 'samples'" class="h-full overflow-auto bg-slate-950 p-5 space-y-3 custom-scrollbar">
          <div class="flex items-center justify-between border-b border-slate-800 pb-2">
            <div class="text-xs text-slate-300">
              已固化报文样本库 (共 <strong>{{ storedSamples.length }}</strong> 笔历史样本)
            </div>
            <button @click="loadStoredSamples"
              class="bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs px-3 py-1 rounded-xl border border-slate-700 transition-colors cursor-pointer">
              ⟳ 刷新样本库
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
                <div>报文: #{{ s.packet.id }} | 规约: <strong class="text-indigo-400">{{ s.packet.protocol }}</strong> | 长度: {{ s.packet.length }} 字节</div>
                <div>端点: {{ s.packet.src_ip }}:{{ s.packet.src_port }} ➔ {{ s.packet.dst_ip }}:{{ s.packet.dst_port }}</div>
              </div>
              <div class="flex items-center gap-2 text-xs">
                <button @click="$emit('selectAsA', s.packet)"
                  class="flex-1 bg-blue-600/20 hover:bg-blue-600/30 text-blue-300 border border-blue-500/30 py-1 rounded-lg transition-colors cursor-pointer font-semibold">
                  设为基准报文 A
                </button>
                <button @click="$emit('selectAsB', s.packet)"
                  class="flex-1 bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 border border-indigo-500/30 py-1 rounded-lg transition-colors cursor-pointer font-semibold">
                  设为比对报文 B
                </button>
                <button @click="doDeleteSample(s.id)"
                  class="bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 px-2 py-1 rounded-lg transition-colors cursor-pointer">
                  🗑️
                </button>
              </div>
            </div>

            <div v-if="storedSamples.length === 0" class="col-span-2 p-12 text-center text-slate-500 text-xs">
              样本库为空。您可以在上方点击【存为样本】将抓获的特征报文持久化归档。
            </div>
          </div>
        </div>

        <!-- 模式四：逐字节波线与差分波率分析 (Byte Waveform & Mutation Rate Analysis) -->
        <div v-show="activeMode === 'wave'" class="h-full overflow-y-auto bg-slate-950 p-5 space-y-4 custom-scrollbar">
          <!-- 1. 顶部五维波形统计指标卡片 -->
          <div v-if="diffResult?.waveform_metrics" class="grid grid-cols-2 md:grid-cols-5 gap-3">
            <!-- 指标 1: 余弦相似度 -->
            <div class="bg-slate-900/90 border border-slate-800 rounded-xl p-3 flex flex-col justify-between">
              <span class="text-[10px] text-slate-400 font-sans">余弦几何相似度 (Cosine)</span>
              <div class="flex items-baseline justify-between mt-1">
                <span class="text-lg font-bold font-mono text-cyan-400">
                  {{ (diffResult.waveform_metrics.cosine_similarity * 100).toFixed(1) }}%
                </span>
                <span class="text-[10px] text-slate-500 font-mono">形态几何</span>
              </div>
              <div class="w-full bg-slate-800 h-1.5 rounded-full mt-2 overflow-hidden">
                <div class="h-full bg-cyan-500 rounded-full" :style="{ width: `${Math.max(0, diffResult.waveform_metrics.cosine_similarity * 100)}%` }"></div>
              </div>
            </div>

            <!-- 指标 2: 皮尔逊相关系数 -->
            <div class="bg-slate-900/90 border border-slate-800 rounded-xl p-3 flex flex-col justify-between">
              <span class="text-[10px] text-slate-400 font-sans">皮尔逊相关性 (Pearson r)</span>
              <div class="flex items-baseline justify-between mt-1">
                <span class="text-lg font-bold font-mono" :class="diffResult.waveform_metrics.pearson_correlation >= 0.8 ? 'text-emerald-400' : diffResult.waveform_metrics.pearson_correlation >= 0.3 ? 'text-amber-400' : 'text-rose-400'">
                  {{ diffResult.waveform_metrics.pearson_correlation.toFixed(3) }}
                </span>
                <span class="text-[10px] text-slate-500 font-mono">线性协同</span>
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
                  <span>报文 A (#{{ diffResult?.packet_a_id }})</span>
                </span>
                <span class="flex items-center gap-1.5 text-[11px] text-purple-400">
                  <span class="w-2.5 h-1 bg-purple-400 rounded-full inline-block"></span>
                  <span>报文 B (#{{ diffResult?.packet_b_id }})</span>
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
          <button @click="$emit('close')"
            class="bg-slate-800 hover:bg-slate-700 text-slate-200 px-4 py-1.5 rounded-xl border border-slate-700 transition-colors cursor-pointer font-semibold">
            关闭视窗
          </button>
        </div>
      </div>

    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted, onUnmounted, nextTick } from 'vue';
import { notifySuccess, notifyInfo, notifyError } from '../composables/useNotification';
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

const props = defineProps<{
  isOpen: boolean;
  packetA: any | null;
  packetB: any | null;
}>();

const emit = defineEmits(['close', 'selectAsA', 'selectAsB', 'appendLog']);

const activeMode = ref<'hex' | 'fields' | 'wave' | 'samples'>('hex');
const diffResult = ref<DualPacketDiffResult | null>(null);
const storedSamples = ref<StoredPacketSample[]>([]);

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

async function runCompare() {
  if (!props.packetA || !props.packetB) return;
  try {
    const res = await invoke<DualPacketDiffResult>('compare_two_packets_cmd', {
      packetA: props.packetA,
      packetB: props.packetB
    });
    diffResult.value = res;
  } catch (e: any) {
    console.error('双报文深度差分失败:', e);
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

async function doSaveSample(packet: any, slot: 'A' | 'B') {
  const defaultName = `样本_#${packet.id}_${packet.protocol}_${slot}`;
  const name = prompt('请输入该报文样本归档名称:', defaultName);
  if (!name) return;
  try {
    await invoke('save_packet_sample_cmd', {
      name: name.trim(),
      packet
    });
    await loadStoredSamples();
    emit('appendLog', `[DIFF] ✓ 报文 #${packet.id} 已固化为特征样本: ${name}`);
    notifySuccess('特征样本固化成功', `报文 #${packet.id} 已成功归档为样本: ${name}`);
  } catch (e: any) {
    notifyError('保存特征样本受阻', e);
  }
}

async function doDeleteSample(id: string) {
  if (!confirm('确定要删除此份历史报文样本吗？')) return;
  try {
    await invoke('delete_packet_sample_cmd', { id });
    await loadStoredSamples();
    notifyInfo('特征样本已移除', '该样本已从本地样本库中安全删除');
  } catch (e: any) {
    notifyError('删除特征样本受阻', e);
  }
}

function swapPackets() {
  if (!props.packetA || !props.packetB) return;
  const tempA = props.packetA;
  emit('selectAsA', props.packetB);
  emit('selectAsB', tempA);
}

function exportDiffReport() {
  if (!diffResult.value) return;
  const res = diffResult.value;
  const timeStr = new Date().toISOString().replace(/T/, ' ').replace(/\..+/, '');

  let md = `# Omni-Probe 双报文协议与 Hex 差分分析报告\n\n`;
  md += `- **分析生成时间**: ${timeStr}\n`;
  md += `- **基准报文 A**: #${res.packet_a_id} (${props.packetA?.protocol || 'N/A'}) - ${props.packetA?.src_ip}:${props.packetA?.src_port} ➔ ${props.packetA?.dst_ip}:${props.packetA?.dst_port} (${res.total_bytes_a} 字节)\n`;
  md += `- **比对报文 B**: #${res.packet_b_id} (${props.packetB?.protocol || 'N/A'}) - ${props.packetB?.src_ip}:${props.packetB?.src_port} ➔ ${props.packetB?.dst_ip}:${props.packetB?.dst_port} (${res.total_bytes_b} 字节)\n`;
  md += `- **比对结论**: ${res.summary}\n`;
  md += `- **突变字节数**: ${res.mutated_bytes_count} / ${Math.max(res.total_bytes_a, res.total_bytes_b)} (突变率: ${res.mutation_rate_percent.toFixed(2)}%)\n\n`;

  md += `## 1. 协议树逐字段比对清单\n\n`;
  md += `| 规约分层 | 协议字段 | 报文 A 取值 | 报文 B 取值 | 比对状态 |\n`;
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
  md += `### 报文 A (基准):\n\`\`\`\n`;
  if (res.hex_diff_a?.hex_rows) {
    res.hex_diff_a.hex_rows.forEach(r => {
      const hexStr = r.cells.map(c => c.hex).join(' ');
      md += `${r.offset}  ${hexStr.padEnd(48, ' ')}  |${r.ascii_repr}|\n`;
    });
  }
  md += `\`\`\`\n\n`;

  md += `### 报文 B (比对):\n\`\`\`\n`;
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
  a.download = `packet_diff_#${res.packet_a_id}_vs_#${res.packet_b_id}_${Date.now()}.md`;
  a.click();
  URL.revokeObjectURL(url);
  notifySuccess('差分分析报告已导出', `已成功生成报文 #${res.packet_a_id} 与 #${res.packet_b_id} 的 Markdown 报告`);
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

  // 2. 网格线与标尺 (0, 64, 128, 192, 255)
  ctx.strokeStyle = 'rgba(51, 65, 85, 0.4)';
  ctx.lineWidth = 1;
  ctx.fillStyle = '#64748b';
  ctx.font = '10px monospace';

  const padL = 36;
  const padR = 16;
  const padT = 16;
  const padB = 24;
  const plotW = W - padL - padR;
  const plotH = H - padT - padB;

  const yVals = [0, 64, 128, 192, 255];
  for (const v of yVals) {
    const y = padT + plotH - (v / 255) * plotH;
    ctx.beginPath();
    ctx.moveTo(padL, y);
    ctx.lineTo(W - padR, y);
    ctx.stroke();
    ctx.fillText(String(v), 6, y + 3);
  }

  const points = diffResult.value?.waveform_metrics?.waveform_points || [];
  if (points.length === 0) {
    ctx.fillStyle = '#64748b';
    ctx.font = '12px sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('暂无载荷波形点阵数据', W / 2, H / 2);
    return;
  }

  const stepX = plotW / Math.max(1, points.length - 1);
  const toX = (i: number) => padL + i * stepX;
  const toY = (val: number) => padT + plotH - (val / 255) * plotH;

  // 3. 绘制报文 A 波形 (青蓝 #38bdf8)
  ctx.strokeStyle = '#38bdf8';
  ctx.lineWidth = 2;
  ctx.beginPath();
  points.forEach((p, idx) => {
    const x = toX(idx);
    const y = toY(p.val_a);
    if (idx === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  });
  ctx.stroke();

  // 4. 绘制报文 B 波形 (亮紫 #c084fc)
  ctx.strokeStyle = '#c084fc';
  ctx.lineWidth = 2;
  ctx.beginPath();
  points.forEach((p, idx) => {
    const x = toX(idx);
    const y = toY(p.val_b);
    if (idx === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  });
  ctx.stroke();

  // 5. 绘制变异点光斑
  points.forEach((p, idx) => {
    if (p.is_mutated) {
      const x = toX(idx);
      const yA = toY(p.val_a);
      const yB = toY(p.val_b);

      ctx.fillStyle = '#f43f5e';
      ctx.beginPath();
      ctx.arc(x, yA, 2.5, 0, Math.PI * 2);
      ctx.fill();

      ctx.beginPath();
      ctx.arc(x, yB, 2.5, 0, Math.PI * 2);
      ctx.fill();
    }
  });

  // 6. 十字标尺
  if (hoverPoint.value) {
    const hp = hoverPoint.value;
    const x = toX(hp.offset);
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.7)';
    ctx.setLineDash([3, 3]);
    ctx.beginPath();
    ctx.moveTo(x, padT);
    ctx.lineTo(x, H - padB);
    ctx.stroke();
    ctx.setLineDash([]);

    ctx.fillStyle = '#38bdf8';
    ctx.beginPath();
    ctx.arc(x, toY(hp.val_a), 4, 0, Math.PI * 2);
    ctx.fill();

    ctx.fillStyle = '#c084fc';
    ctx.beginPath();
    ctx.arc(x, toY(hp.val_b), 4, 0, Math.PI * 2);
    ctx.fill();
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

  ctx.fillStyle = '#020617';
  ctx.fillRect(0, 0, W, H);

  const padL = 36;
  const padR = 16;
  const padT = 12;
  const padB = 20;
  const plotW = W - padL - padR;
  const plotH = H - padT - padB;

  ctx.strokeStyle = 'rgba(51, 65, 85, 0.4)';
  ctx.lineWidth = 1;
  ctx.fillStyle = '#64748b';
  ctx.font = '9px monospace';

  const dVals = [0, 64, 128, 255];
  for (const v of dVals) {
    const y = padT + plotH - (v / 255) * plotH;
    ctx.beginPath();
    ctx.moveTo(padL, y);
    ctx.lineTo(W - padR, y);
    ctx.stroke();
    ctx.fillText(String(v), 8, y + 3);
  }

  // 128 强突变警戒红虚线
  const y128 = padT + plotH - (128 / 255) * plotH;
  ctx.strokeStyle = 'rgba(244, 63, 94, 0.6)';
  ctx.setLineDash([4, 4]);
  ctx.beginPath();
  ctx.moveTo(padL, y128);
  ctx.lineTo(W - padR, y128);
  ctx.stroke();
  ctx.setLineDash([]);

  const points = diffResult.value?.waveform_metrics?.waveform_points || [];
  if (points.length === 0) return;

  const colW = Math.max(1, (plotW / points.length) - 1);
  const stepX = plotW / points.length;

  points.forEach((p, idx) => {
    const absD = Math.abs(p.delta);
    const barH = (absD / 255) * plotH;
    const x = padL + idx * stepX;
    const y = padT + plotH - barH;

    if (absD === 0) {
      ctx.fillStyle = 'rgba(51, 65, 85, 0.5)';
      ctx.fillRect(x, padT + plotH - 2, Math.max(1, colW), 2);
    } else if (absD <= 64) {
      ctx.fillStyle = '#f59e0b';
      ctx.fillRect(x, y, Math.max(1, colW), Math.max(2, barH));
    } else if (absD <= 128) {
      ctx.fillStyle = '#f97316';
      ctx.fillRect(x, y, Math.max(1, colW), Math.max(2, barH));
    } else {
      ctx.fillStyle = '#f43f5e';
      ctx.fillRect(x, y, Math.max(1, colW), Math.max(2, barH));
    }
  });

  if (hoverDelta.value) {
    const idx = hoverDelta.value.offset;
    const x = padL + idx * stepX;
    ctx.strokeStyle = '#ffffff';
    ctx.lineWidth = 1.5;
    ctx.strokeRect(x - 1, padT, Math.max(2, colW + 2), plotH);
  }
}

function onWaveMouseMove(e: MouseEvent) {
  const canvas = diffWaveCanvas.value;
  if (!canvas || !diffResult.value?.waveform_metrics?.waveform_points) return;
  const rect = canvas.getBoundingClientRect();
  const mouseX = e.clientX - rect.left;
  const padL = 36;
  const padR = 16;
  const plotW = rect.width - padL - padR;
  const points = diffResult.value.waveform_metrics.waveform_points;
  if (points.length <= 1) return;

  const relX = Math.max(0, Math.min(plotW, mouseX - padL));
  const idx = Math.round((relX / plotW) * (points.length - 1));
  hoverPoint.value = points[idx] || null;
  drawDiffWaveform();
}

function onDeltaMouseMove(e: MouseEvent) {
  const canvas = deltaSpectrumCanvas.value;
  if (!canvas || !diffResult.value?.waveform_metrics?.waveform_points) return;
  const rect = canvas.getBoundingClientRect();
  const mouseX = e.clientX - rect.left;
  const padL = 36;
  const padR = 16;
  const plotW = rect.width - padL - padR;
  const points = diffResult.value.waveform_metrics.waveform_points;
  if (points.length === 0) return;

  const relX = Math.max(0, Math.min(plotW, mouseX - padL));
  const idx = Math.min(points.length - 1, Math.floor((relX / plotW) * points.length));
  hoverDelta.value = points[idx] || null;
  drawDeltaSpectrum();
}

function onDeltaSpectrumClick() {
  if (!hoverDelta.value) return;
  const off = hoverDelta.value.offset;
  activeMode.value = 'hex';
  // 切换到 Hex 模式后，触发滚动对齐至该行
  nextTick(() => {
    const rowIndex = Math.floor(off / 16);
    const targetScroll = rowIndex * 26;
    if (hexScrollA.value) hexScrollA.value.scrollTop = targetScroll;
    if (hexScrollB.value) hexScrollB.value.scrollTop = targetScroll;
  });
}

function renderAllCharts() {
  if (activeMode.value === 'wave') {
    nextTick(() => {
      drawDiffWaveform();
      drawDeltaSpectrum();
    });
  }
}

watch([activeMode, diffResult], () => {
  renderAllCharts();
});

watch(() => [props.packetA, props.packetB, props.isOpen], () => {
  if (props.isOpen && props.packetA && props.packetB) {
    runCompare();
  }
}, { immediate: true });

onMounted(() => {
  loadStoredSamples();
  window.addEventListener('resize', renderAllCharts);
});

onUnmounted(() => {
  window.removeEventListener('resize', renderAllCharts);
});
</script>

<style scoped>
.custom-scrollbar::-webkit-scrollbar {
  width: 6px;
  height: 6px;
}
.custom-scrollbar::-webkit-scrollbar-track {
  background: rgba(15, 23, 42, 0.6);
}
.custom-scrollbar::-webkit-scrollbar-thumb {
  background: rgba(51, 65, 85, 0.8);
  border-radius: 9999px;
}
.custom-scrollbar::-webkit-scrollbar-thumb:hover {
  background: rgba(71, 85, 105, 1);
}
</style>
