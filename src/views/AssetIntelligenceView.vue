<template>
  <div class="flex-1 flex flex-col gap-2.5 overflow-hidden min-w-0">
    <!-- 顶部工具栏 (真 Liquid Glass 单行有序对齐) -->
    <div class="ui-nav-glass rounded-2xl px-4 py-2.5 flex items-center justify-between shrink-0 gap-3 flex-wrap">
      <span class="lens-edge-lip" aria-hidden="true"></span>
      <div class="flex items-center gap-3 min-w-0 shrink-0">
        <h2 class="text-[13px] font-semibold flex items-center gap-2 whitespace-nowrap" style="color: var(--text-primary);">
          <AppIcon name="radar" :size="15" class="text-[var(--accent-primary)] shrink-0" />
          <span>资产感知与拓扑</span>
        </h2>
        <span class="ui-pill px-2 py-0.5 rounded-full text-[11px] ui-num shrink-0 whitespace-nowrap">
          <strong class="font-semibold" style="color: var(--text-primary);">{{ assets.length }}</strong> 节点
        </span>

        <!-- 视口布局模式分段选择器 -->
        <div class="glass-pill p-0.5 rounded-xl hidden xl:flex items-center gap-0.5">
          <button
            @click="viewLayout = 'split'"
            :class="[
              'px-2.5 py-1 rounded-lg text-xs font-medium transition-all cursor-pointer flex items-center gap-1 whitespace-nowrap',
              viewLayout === 'split' ? 'bg-[var(--accent-primary)] text-white shadow-xs' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
            ]"
            title="左右均衡对照 (清单 + 拓扑)"
          >
            <AppIcon name="scale" :size="13" />
            <span>分屏</span>
          </button>
          <button
            @click="viewLayout = 'topology'"
            :class="[
              'px-2.5 py-1 rounded-lg text-xs font-medium transition-all cursor-pointer flex items-center gap-1 whitespace-nowrap',
              viewLayout === 'topology' ? 'bg-[var(--accent-primary)] text-white shadow-xs' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
            ]"
            title="全景工业拓扑图"
          >
            <AppIcon name="radar" :size="13" />
            <span>拓扑</span>
          </button>
          <button
            @click="viewLayout = 'table'"
            :class="[
              'px-2.5 py-1 rounded-lg text-xs font-medium transition-all cursor-pointer flex items-center gap-1 whitespace-nowrap',
              viewLayout === 'table' ? 'bg-[var(--accent-primary)] text-white shadow-xs' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
            ]"
            title="全屏资产数据台账"
          >
            <AppIcon name="document" :size="13" />
            <span>台账</span>
          </button>
          <button
            @click="switchToHierarchyLayout"
            :class="[
              'px-2.5 py-1 rounded-lg text-xs font-medium transition-all cursor-pointer flex items-center gap-1 whitespace-nowrap',
              viewLayout === 'hierarchy' ? 'bg-[var(--accent-primary)] text-white shadow-xs' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
            ]"
            title="SNMP/CIDR 万级资产层次化钻取聚合拓扑"
          >
            <AppIcon name="layers" :size="13" />
            <span>分层</span>
          </button>
        </div>
      </div>

      <div class="flex items-center gap-1.5 flex-1 justify-end min-w-0 flex-wrap text-xs">
        <input
          v-model="searchQuery"
          placeholder="过滤 IP / MAC / 厂商 / 端口..."
          class="ui-input flex-1 min-w-[140px] max-w-[230px] px-2.5 py-1 text-xs"
        />

        <button @click="$emit('refreshAssets')" class="ui-btn-secondary px-2.5 py-1 text-xs">
          <AppIcon name="refresh" :size="13" />
          <span class="hidden 2xl:inline">刷新</span>
        </button>

        <button @click="$emit('scanAssets')" :disabled="scanning" class="ui-btn-primary px-3 py-1 text-xs">
          <AppIcon name="radar" :size="13" :class="{ 'animate-spin': scanning }" />
          <span>全网扫描</span>
        </button>

        <button @click="$emit('probeAllPorts')" :disabled="probingAll" class="ui-btn-secondary px-2.5 py-1 text-xs">
          <AppIcon name="zap" :size="13" :class="{ 'animate-spin': probingAll }" />
          <span>探活</span>
        </button>

        <button @click="openTargetBannerScan('')" class="ui-btn-secondary px-2.5 py-1 text-xs" title="打开 CIDR 网段与全连接 Banner 并发扫描工作台">
          <AppIcon name="radar" :size="13" class="text-sky-500" />
          <span>CIDR/Banner 扫描</span>
        </button>

        <button
          @click="showDiffWorkbench = !showDiffWorkbench"
          :class="[
            'text-xs px-2.5 py-1 rounded-lg font-medium transition-all flex items-center gap-1 cursor-pointer border whitespace-nowrap',
            showDiffWorkbench ? 'bg-[var(--accent-primary)] text-white border-transparent' : 'ui-btn-secondary'
          ]"
        >
          <AppIcon name="activity" :size="13" />
          <span>快照</span>
          <span
            v-if="snapshotList.length > 0"
            class="px-1.5 py-0.5 rounded-full text-[11px] ui-num font-semibold bg-[var(--accent-primary-soft)] text-[var(--accent-primary-text)]"
          >
            {{ snapshotList.length }}
          </span>
        </button>

        <button @click="$emit('clearAssets')" class="ui-btn-danger px-3 py-1 text-xs">
          <AppIcon name="trash" :size="13" />
          <span>清空</span>
        </button>
      </div>
    </div>

    <!-- 资产快照与多维差分比对工作台 (稳态实体内容衬底) -->
    <div v-if="showDiffWorkbench" class="ui-content-card p-3.5 flex flex-col gap-3 shrink-0 select-text">
      <div class="flex items-center justify-between border-b pb-2.5 flex-wrap gap-2" style="border-color: var(--border-subtle);">
        <div class="flex items-center gap-2 min-w-0">
          <span class="text-[13px] font-semibold flex items-center gap-1.5" style="color: var(--text-primary);">
            <span class="w-2 h-2 rounded-full bg-indigo-500 shrink-0"></span>
            <span>全网资产快照持久化与基线差分审计工作台</span>
          </span>
          <span class="text-xs hidden lg:inline" style="color: var(--text-muted);">
            支持历史快照持久化、任意两版本比对、高危端口变动与 MAC 漂移审计
          </span>
        </div>

        <div class="flex items-center gap-2 text-xs">
          <input
            v-model="newSnapshotName"
            placeholder="快照备注名称 (可选)"
            class="ui-input w-48 px-2.5 py-1 text-xs"
          />
          <button @click="doSaveSnapshot" :disabled="isSavingSnapshot" class="ui-btn-primary px-3 py-1 text-xs">
            <AppIcon v-if="isSavingSnapshot" name="refresh" :size="13" class="animate-spin" />
            <AppIcon v-else name="archive" :size="13" />
            <span>保存当前快照</span>
          </button>
          <button @click="showDiffWorkbench = false" title="收起快照工作台" class="ui-btn-secondary w-7 h-7 p-0 justify-center">
            <AppIcon name="close" :size="14" />
          </button>
        </div>
      </div>

      <!-- 差分比对参数选择器 -->
      <div class="ui-sub-card grid grid-cols-1 md:grid-cols-4 gap-2.5 items-center text-xs p-2.5">
        <div>
          <label class="text-[11px] font-semibold block mb-1" style="color: var(--text-muted);">基准版本 (Base Snapshot)</label>
          <select v-model="selectedBaseSnapshotId" class="ui-input w-full px-2 py-1.5 text-xs ui-num">
            <option v-for="s in snapshotList" :key="s.id" :value="s.id">
              {{ s.name }} ({{ s.total_assets }} 资产 / {{ s.timestamp_str }})
            </option>
            <option v-if="snapshotList.length === 0" value="">请先保存至少一份快照</option>
          </select>
        </div>

        <div>
          <label class="text-[11px] font-semibold block mb-1" style="color: var(--text-muted);">对比目标 (Target Snapshot)</label>
          <select v-model="selectedTargetSnapshotId" class="ui-input w-full px-2 py-1.5 text-xs ui-num">
            <option value="CURRENT_REALTIME">当前实时感知资产 ({{ assets.length }} 节点)</option>
            <option v-for="s in snapshotList" :key="s.id" :value="s.id">
              {{ s.name }} ({{ s.total_assets }} 资产 / {{ s.timestamp_str }})
            </option>
          </select>
        </div>

        <div class="flex items-end gap-1.5 h-full">
          <button
            @click="doCompareSnapshots"
            :disabled="!selectedBaseSnapshotId || isComparing"
            class="ui-btn-primary flex-1 px-3 py-1.5 text-xs justify-center"
          >
            <AppIcon v-if="isComparing" name="refresh" :size="13" class="animate-spin" />
            <AppIcon v-else name="search" :size="13" />
            <span>执行多维差分比对</span>
          </button>
          <button @click="loadSnapshots" title="刷新快照清单" class="ui-btn-secondary px-2.5 py-1.5">
            <AppIcon name="refresh" :size="14" />
          </button>
          <button
            v-if="selectedBaseSnapshotId"
            @click="doDeleteSnapshot(selectedBaseSnapshotId)"
            title="删除选中的基准快照"
            class="ui-btn-danger px-2.5 py-1.5"
          >
            <AppIcon name="trash" :size="14" />
          </button>
        </div>

        <!-- 差异过滤条件 -->
        <div v-if="diffReport">
          <label class="text-[11px] font-semibold block mb-1" style="color: var(--text-muted);">差分项快速过滤</label>
          <div class="flex gap-1 flex-wrap">
            <button
              @click="diffFilter = 'ALL'"
              :class="['px-2 py-0.5 rounded-lg text-[11px] font-semibold border transition-all cursor-pointer',
                diffFilter === 'ALL' ? 'bg-indigo-600 text-white border-indigo-600' : 'ui-pill']"
            >
              全部 ({{ diffReport.items.length }})
            </button>
            <button
              @click="diffFilter = 'HIGH'"
              :class="['px-2 py-0.5 rounded-lg text-[11px] font-semibold border transition-all cursor-pointer',
                diffFilter === 'HIGH' ? 'bg-rose-600 text-white border-rose-600' : 'border-rose-500/30 text-rose-600 dark:text-rose-400 bg-rose-500/10']"
            >
              高危 ({{ diffReport.high_risk_count }})
            </button>
            <button
              @click="diffFilter = 'ADDED'"
              :class="['px-2 py-0.5 rounded-lg text-[11px] font-semibold border transition-all cursor-pointer',
                diffFilter === 'ADDED' ? 'bg-emerald-600 text-white border-emerald-600' : 'border-emerald-500/30 text-emerald-600 dark:text-emerald-400 bg-emerald-500/10']"
            >
              新增 ({{ diffReport.added_count }})
            </button>
            <button
              @click="diffFilter = 'MODIFIED'"
              :class="['px-2 py-0.5 rounded-lg text-[11px] font-semibold border transition-all cursor-pointer',
                diffFilter === 'MODIFIED' ? 'bg-amber-600 text-white border-amber-600' : 'border-amber-500/30 text-amber-600 dark:text-amber-400 bg-amber-500/10']"
            >
              变动 ({{ diffReport.modified_count }})
            </button>
          </div>
        </div>
      </div>

      <!-- 差分比对报告面板 -->
      <div v-if="diffReport" class="flex flex-col gap-2">
        <div class="grid grid-cols-2 md:grid-cols-5 gap-2 text-xs">
          <div class="bg-indigo-500/10 border border-indigo-500/25 p-2.5 rounded-xl">
            <div class="text-[11px] text-indigo-600 dark:text-indigo-300 font-semibold">基准 vs 目标资产数</div>
            <div class="text-sm font-bold ui-num mt-0.5" style="color: var(--text-primary);">{{ diffReport.total_base }} → {{ diffReport.total_target }}</div>
          </div>
          <div class="bg-emerald-500/10 border border-emerald-500/25 p-2.5 rounded-xl">
            <div class="text-[11px] text-emerald-600 dark:text-emerald-300 font-semibold">新上线未知资产</div>
            <div class="text-sm font-bold text-emerald-600 dark:text-emerald-400 ui-num mt-0.5">+{{ diffReport.added_count }} 节点</div>
          </div>
          <div class="ui-sub-card p-2.5 rounded-xl">
            <div class="text-[11px] font-semibold" style="color: var(--text-muted);">离线失联资产</div>
            <div class="text-sm font-bold ui-num mt-0.5" style="color: var(--text-secondary);">-{{ diffReport.removed_count }} 节点</div>
          </div>
          <div class="bg-amber-500/10 border border-amber-500/25 p-2.5 rounded-xl">
            <div class="text-[11px] text-amber-600 dark:text-amber-300 font-semibold">端口/属性漂移</div>
            <div class="text-sm font-bold text-amber-600 dark:text-amber-400 ui-num mt-0.5">~{{ diffReport.modified_count }} 节点</div>
          </div>
          <div class="bg-rose-500/10 border border-rose-500/25 p-2.5 rounded-xl">
            <div class="text-[11px] text-rose-600 dark:text-rose-300 font-semibold">高危变动风险</div>
            <div class="text-sm font-bold text-rose-600 dark:text-rose-400 ui-num mt-0.5 flex items-center gap-1">
              <AppIcon name="alert" :size="14" />
              <span>{{ diffReport.high_risk_count }} 项</span>
            </div>
          </div>
        </div>

        <div class="max-h-56 overflow-auto custom-scrollbar border rounded-xl" style="border-color: var(--border-subtle); background: var(--surface-content-alt);">
          <table class="w-full text-left text-xs border-collapse table-fixed">
            <thead class="ui-table-head sticky top-0 z-10">
              <tr>
                <th class="p-2.5 w-[18%]">节点 IP</th>
                <th class="p-2.5 w-[12%]">差分类型</th>
                <th class="p-2.5 w-[16%]">MAC 状态</th>
                <th class="p-2.5 w-[14%]">角色变动</th>
                <th class="p-2.5 w-[22%]">开放端口差分</th>
                <th class="p-2.5 w-[18%]">风险等级与审计说明</th>
              </tr>
            </thead>
            <tbody class="divide-y text-xs" style="--tw-divide-opacity: 1; border-color: var(--border-subtle);">
              <tr
                v-for="item in filteredDiffItems"
                :key="item.ip"
                :class="['transition-colors hover:bg-[var(--surface-hover)]', item.risk_level === 'HIGH' ? 'bg-rose-500/5' : '']"
              >
                <td class="p-2 font-semibold ui-num truncate" style="color: var(--text-primary);" :title="item.ip">{{ item.ip }}</td>
                <td class="p-2 truncate">
                  <span :class="['px-1.5 py-0.5 rounded text-[11px] font-semibold',
                    item.diff_type === 'ADDED' ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300' :
                    item.diff_type === 'REMOVED' ? 'bg-slate-500/15 text-slate-600 dark:text-slate-300' :
                    'bg-amber-500/15 text-amber-700 dark:text-amber-300']">
                    {{ item.diff_type === 'ADDED' ? '+ 新增' : item.diff_type === 'REMOVED' ? '- 下线' : '~ 变更' }}
                  </span>
                </td>
                <td class="p-2 truncate font-mono text-[11px]" :title="item.target_mac || item.base_mac || 'N/A'">
                  <div v-if="item.is_mac_drift" class="text-rose-600 dark:text-rose-400 font-semibold flex items-center gap-1">
                    <AppIcon name="alert" :size="12" />
                    <span class="line-through opacity-60">{{ item.base_mac }}</span>
                    <span>→ {{ item.target_mac }}</span>
                  </div>
                  <div v-else style="color: var(--text-secondary);">
                    {{ item.target_mac || item.base_mac || 'N/A' }}
                  </div>
                </td>
                <td class="p-2 truncate" style="color: var(--text-secondary);">
                  <span v-if="item.base_role && item.target_role && item.base_role !== item.target_role">
                    {{ item.base_role }} → {{ item.target_role }}
                  </span>
                  <span v-else>{{ item.target_role || item.base_role || '终端设备' }}</span>
                </td>
                <td class="p-2 truncate">
                  <div class="flex items-center gap-1 flex-wrap">
                    <span
                      v-if="item.port_diff?.added_ports && item.port_diff.added_ports.length > 0"
                      class="px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 text-[11px] font-semibold ui-num"
                    >
                      +{{ item.port_diff.added_ports.join(',') }}
                    </span>
                    <span
                      v-if="item.port_diff?.closed_ports && item.port_diff.closed_ports.length > 0"
                      class="px-1.5 py-0.5 rounded bg-rose-500/15 text-rose-700 dark:text-rose-300 text-[11px] font-semibold ui-num line-through"
                    >
                      -{{ item.port_diff.closed_ports.join(',') }}
                    </span>
                    <span
                      v-if="(!item.port_diff || (item.port_diff.added_ports.length === 0 && item.port_diff.closed_ports.length === 0))"
                      class="text-[11px]"
                      style="color: var(--text-muted);"
                    >
                      无端口变动
                    </span>
                  </div>
                </td>
                <td class="p-2 truncate">
                  <div class="flex items-center gap-1.5 truncate" :title="item.risk_desc">
                    <span :class="['px-1.5 py-0.5 rounded text-[11px] font-semibold shrink-0',
                      item.risk_level === 'HIGH' ? 'bg-rose-600 text-white' :
                      item.risk_level === 'MEDIUM' ? 'bg-amber-500 text-white' :
                      'bg-slate-500/20 text-[var(--text-secondary)]']">
                      {{ item.risk_level === 'HIGH' ? '高危' : item.risk_level === 'MEDIUM' ? '中危' : '正常' }}
                    </span>
                    <span class="truncate text-[11px]" style="color: var(--text-secondary);">{{ item.risk_desc }}</span>
                  </div>
                </td>
              </tr>
              <tr v-if="filteredDiffItems.length === 0">
                <td colspan="6" class="p-6 text-center text-xs" style="color: var(--text-muted);">
                  暂无匹配的差分记录（基准与对比版本在当前过滤条件下完全一致）
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- 主体：视口自适应调度 -->
    <div v-if="viewLayout === 'hierarchy'" class="flex-1 ui-content-card p-4 flex flex-col gap-3 overflow-hidden min-h-0 text-xs select-text">
      <div class="flex items-center justify-between border-b pb-2.5 flex-wrap gap-2 shrink-0" style="border-color: var(--border-subtle);">
        <div class="flex items-center gap-2.5 flex-wrap">
          <span class="font-semibold text-[13px] flex items-center gap-1.5" style="color: var(--text-primary);">
            <AppIcon name="layers" :size="15" class="text-blue-500" />
            <span>CIDR 分层聚合拓扑下钻 (Zone → /16 → /24 → Host)</span>
          </span>
          <span class="ui-pill px-2 py-0.5 text-[11px] ui-num">沉淀主机: {{ hierarchyViewport?.total_ingested_hosts ?? 0 }}</span>
          <span class="px-2 py-0.5 rounded-lg bg-blue-500/12 text-blue-600 dark:text-sky-300 text-[11px] ui-num font-medium">可视节点: {{ hierarchyViewport?.rendered_node_count ?? 0 }}</span>
          <span class="px-2 py-0.5 rounded-lg bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 text-[11px] ui-num font-medium">压缩率: {{ (hierarchyViewport?.compression_ratio ?? 0).toFixed(1) }}%</span>
        </div>
        <div class="flex items-center gap-2 flex-wrap">
          <input
            v-model="switchLocateIp"
            placeholder="交换机端口定位 (输入 IP)..."
            class="ui-input px-2.5 py-1 text-xs w-48"
          />
          <button @click="locateSwitchPort" :disabled="!switchLocateIp.trim()" class="ui-btn-primary px-2.5 py-1 text-xs">
            定位物理端口
          </button>
          <button @click="collapseAllHierarchy" class="ui-btn-secondary px-2.5 py-1 text-xs">
            全部折叠
          </button>
          <button @click="fetchHierarchyViewport" class="ui-btn-secondary px-2.5 py-1 text-xs">
            <AppIcon name="refresh" :size="13" />
            <span>刷新</span>
          </button>
        </div>
      </div>

      <div v-if="switchPortLocResult" class="px-3 py-2 rounded-xl bg-indigo-500/10 border border-indigo-500/25 text-indigo-700 dark:text-indigo-200 text-xs shrink-0">
        {{ switchPortLocResult }}
      </div>

      <div class="flex-1 grid grid-cols-12 gap-3 overflow-hidden min-h-0">
        <div class="col-span-7 overflow-y-auto custom-scrollbar space-y-2 pr-1">
          <EmptyState
            v-if="!hierarchyViewport || hierarchyViewport.visible_nodes.length === 0"
            icon="layers"
            title="暂无分层拓扑节点数据"
            description="触发全网资产扫描或启动网卡嗅探后将自动构建层级树。"
          />
          <div
            v-for="node in hierarchyViewport?.visible_nodes || []"
            :key="node.node_id"
            class="ui-sub-card p-3 flex items-center justify-between gap-2 transition-colors hover:bg-[var(--surface-hover)]"
          >
            <div>
              <div class="flex items-center gap-2">
                <span class="px-1.5 py-0.5 rounded text-[11px] font-semibold bg-blue-500/15 text-blue-600 dark:text-sky-300 border border-blue-500/25">{{ node.level }}</span>
                <span class="font-semibold text-[13px]" style="color: var(--text-primary);">{{ node.label }}</span>
                <span v-if="node.cidr_prefix" class="ui-num text-xs" style="color: var(--text-muted);">[{{ node.cidr_prefix }}]</span>
              </div>
              <div class="text-[11px] mt-1 flex gap-3 ui-num" style="color: var(--text-muted);">
                <span>下辖主机: <b style="color: var(--text-primary);">{{ node.host_count }}</b></span>
                <span>总流数: <b style="color: var(--text-primary);">{{ node.total_flows }}</b></span>
                <span>吞吐: <b class="text-emerald-600 dark:text-emerald-400">{{ (node.total_in_bytes + node.total_out_bytes).toLocaleString() }} B</b></span>
                <span v-if="node.total_alerts > 0" class="text-rose-600 dark:text-rose-400 font-semibold">告警: {{ node.total_alerts }}</span>
              </div>
            </div>
            <div class="flex items-center gap-1.5 shrink-0" v-if="node.level !== 'Host'">
              <button @click="drillDownNode(node.node_id)" class="ui-btn-primary px-2.5 py-1 text-[11px]">
                <AppIcon name="chevron-down" :size="12" />
                <span>下钻</span>
              </button>
              <button @click="rollUpNode(node.node_id)" class="ui-btn-secondary px-2.5 py-1 text-[11px]">
                <AppIcon name="chevron-up" :size="12" />
                <span>折叠</span>
              </button>
            </div>
          </div>
        </div>

        <div class="col-span-5 overflow-y-auto custom-scrollbar border rounded-xl p-3" style="border-color: var(--border-subtle); background: var(--surface-content-alt);">
          <div class="font-semibold text-[13px] mb-2" style="color: var(--text-primary);">聚合骨干通信边 ({{ hierarchyViewport?.visible_edges.length ?? 0 }})</div>
          <div v-if="!hierarchyViewport || hierarchyViewport.visible_edges.length === 0" class="text-xs py-8 text-center" style="color: var(--text-muted);">
            尚无跨节点聚合流量边
          </div>
          <div
            v-for="edge in hierarchyViewport?.visible_edges || []"
            :key="edge.edge_id"
            class="py-2 px-2.5 mb-1.5 rounded-lg border text-[11px]"
            :class="edge.contains_threat ? 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-200' : 'ui-sub-card'"
          >
            <div class="font-semibold truncate ui-num">{{ edge.source_node_id }} → {{ edge.target_node_id }}</div>
            <div class="flex justify-between mt-0.5 ui-num" style="color: var(--text-muted);">
              <span>流次数: {{ edge.flow_count }}</span>
              <span>总量: {{ edge.total_bytes.toLocaleString() }} B</span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div v-else class="flex-1 flex gap-2.5 overflow-hidden min-h-0">
      <!-- 左侧：局域网资产清单表格 (实体稳态衬底，分屏时不溢出横向滚动) -->
      <div
        v-show="viewLayout === 'split' || viewLayout === 'table'"
        :class="['ui-content-card flex flex-col overflow-hidden min-h-0 transition-all duration-200',
          viewLayout === 'table' ? 'w-full flex-1' : 'flex-1 min-w-0']"
      >
        <div class="px-4 py-2 border-b flex items-center justify-between text-xs font-semibold shrink-0 flex-wrap gap-2" style="border-color: var(--border-subtle); color: var(--text-primary);">
          <div class="flex items-center gap-2 min-w-0">
            <span class="truncate">局域网资产清单 ({{ filteredAssets.length }} / {{ assets.length }})</span>
            <span class="text-[11px] font-normal hidden xl:inline" style="color: var(--text-muted);">基于 ARP 侦测、流量沉淀与非阻塞探活</span>
          </div>

          <div class="flex items-center gap-1 glass-pill p-0.5 rounded-xl text-[11px]">
            <button
              @click="activeRoleCategory = 'ALL'"
              :class="['px-2 py-0.5 rounded-lg font-medium transition-all cursor-pointer',
                activeRoleCategory === 'ALL' ? 'bg-[var(--accent-primary)] text-white shadow-xs' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]']"
            >
              全部 ({{ assets.length }})
            </button>
            <button
              @click="activeRoleCategory = 'GATEWAY'"
              :class="['px-2 py-0.5 rounded-lg font-medium transition-all cursor-pointer',
                activeRoleCategory === 'GATEWAY' ? 'bg-[var(--accent-primary)] text-white shadow-xs' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]']"
            >
              网关 ({{ gatewayCount }})
            </button>
            <button
              @click="activeRoleCategory = 'CONTROLLER'"
              :class="['px-2 py-0.5 rounded-lg font-medium transition-all cursor-pointer',
                activeRoleCategory === 'CONTROLLER' ? 'bg-[var(--accent-primary)] text-white shadow-xs' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]']"
            >
              控制/服务 ({{ controllerCount }})
            </button>
            <button
              @click="activeRoleCategory = 'TERMINAL'"
              :class="['px-2 py-0.5 rounded-lg font-medium transition-all cursor-pointer',
                activeRoleCategory === 'TERMINAL' ? 'bg-[var(--accent-primary)] text-white shadow-xs' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]']"
            >
              终端 ({{ terminalCount }})
            </button>
            <button
              @click="activeRoleCategory = 'THREAT'"
              :class="['px-2 py-0.5 rounded-lg font-medium transition-all cursor-pointer',
                activeRoleCategory === 'THREAT' ? 'bg-rose-600 text-white shadow-xs' : 'text-rose-600 dark:text-rose-400 hover:bg-rose-500/10']"
            >
              高危 ({{ threatCount }})
            </button>
          </div>
        </div>

        <div class="flex-1 overflow-auto custom-scrollbar select-text bg-transparent">
          <table class="w-full text-left text-xs border-collapse table-fixed">
            <thead class="ui-table-head sticky top-0 z-10 select-none">
              <tr>
                <th class="p-2.5" :class="viewLayout === 'table' ? 'w-[20%]' : 'w-[27%]'">主机 IP & 名称</th>
                <th v-if="viewLayout === 'table'" class="p-2.5 w-[14%]">物理 MAC</th>
                <th class="p-2.5" :class="viewLayout === 'table' ? 'w-[14%]' : 'hidden xl:table-cell w-[16%]'">硬件厂商</th>
                <th class="p-2.5" :class="viewLayout === 'table' ? 'w-[11%]' : 'w-[17%]'">网络角色</th>
                <th class="p-2.5" :class="viewLayout === 'table' ? 'w-[11%]' : 'w-[15%]'">业务规约</th>
                <th class="p-2.5" :class="viewLayout === 'table' ? 'w-[12%]' : 'w-[18%]'">开放端口</th>
                <th v-if="viewLayout === 'table'" class="p-2.5 w-[8%]">末次活跃</th>
                <th class="p-2.5 text-center" :class="viewLayout === 'table' ? 'w-[10%]' : 'w-[110px]'">操作</th>
              </tr>
            </thead>
            <tbody class="divide-y" style="border-color: var(--border-subtle);">
              <tr v-for="asset in filteredAssets" :key="asset.ip" class="hover:bg-[var(--surface-hover)] transition-colors">
                <!-- IP 与主机名 -->
                <td class="p-2.5 font-semibold" style="color: var(--text-primary);">
                  <div class="flex items-center gap-1.5 flex-nowrap truncate">
                    <span
                      @click="openIpDossier(asset.ip)"
                      class="truncate cursor-pointer hover:underline transition-colors ui-num text-blue-600 dark:text-sky-400"
                      title="点击查阅 IP 全息画像档案"
                    >
                      {{ asset.ip }}
                    </span>
                    <span
                      v-if="asset.hostname"
                      class="px-1.5 py-0.5 rounded text-[11px] font-normal bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 border border-emerald-500/25 shrink-0 truncate max-w-[76px]"
                      :title="asset.hostname"
                    >
                      {{ asset.hostname }}
                    </span>
                    <span
                      v-else-if="asset.zone_name"
                      class="px-1.5 py-0.5 rounded text-[11px] font-normal bg-indigo-500/12 text-indigo-700 dark:text-indigo-300 border border-indigo-500/25 shrink-0 truncate max-w-[76px]"
                      :title="asset.geo_summary || asset.zone_name"
                    >
                      {{ asset.zone_name }}
                    </span>
                  </div>
                </td>

                <!-- MAC (仅全表展示，分屏模式下点击行/档案查阅以防止横向挤压) -->
                <td v-if="viewLayout === 'table'" class="p-2.5 text-[11px] truncate font-mono ui-num" style="color: var(--text-secondary);">
                  {{ asset.mac || 'N/A' }}
                </td>

                <!-- 厂商 -->
                <td class="p-2.5 truncate text-[11px]" :class="viewLayout === 'table' ? '' : 'hidden xl:table-cell'" style="color: var(--text-secondary);" :title="asset.vendor">
                  {{ asset.vendor || '通用网络终端' }}
                </td>

                <!-- 角色 -->
                <td class="p-2.5 truncate">
                  <span :class="['px-1.5 py-0.5 rounded text-[11px] font-semibold uppercase truncate inline-block max-w-full', roleBadgeColor(asset.role)]">
                    {{ asset.role }}
                  </span>
                </td>

                <!-- 规约协议 -->
                <td class="p-2.5 truncate">
                  <div class="flex gap-1 flex-nowrap truncate">
                    <span
                      v-for="pr in asset.protocols.slice(0, 2)"
                      :key="pr"
                      :class="['px-1.5 py-0.5 rounded font-semibold text-[11px] shrink-0 border',
                        pr.includes('HONEYPOT') ? 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-500/30' : 'ui-pill']"
                    >
                      {{ pr }}
                    </span>
                    <span v-if="asset.protocols.length > 2" class="text-[11px] font-semibold ui-num" style="color: var(--text-muted);">
                      +{{ asset.protocols.length - 2 }}
                    </span>
                  </div>
                </td>

                <!-- 开放端口 -->
                <td class="p-2.5 truncate">
                  <div class="flex items-center gap-1 flex-nowrap truncate">
                    <span
                      v-for="port in asset.ports.slice(0, 3)"
                      :key="port"
                      class="px-1.5 py-0.5 rounded-md bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 border border-emerald-500/25 text-[11px] font-semibold ui-num shrink-0"
                    >
                      :{{ port }}
                    </span>
                    <span v-if="asset.ports.length > 3" class="text-[11px] font-semibold ui-num" style="color: var(--text-muted);">
                      +{{ asset.ports.length - 3 }}
                    </span>
                    <button
                      v-if="asset.ports.length === 0"
                      @click="$emit('probeSinglePort', asset.ip)"
                      class="text-[11px] px-1.5 py-0.5 rounded-md bg-amber-500/12 hover:bg-amber-500/20 text-amber-700 dark:text-amber-300 border border-amber-500/25 transition-colors cursor-pointer flex items-center gap-1 font-medium shrink-0"
                    >
                      <AppIcon name="zap" :size="11" />
                      <span>探活</span>
                    </button>
                  </div>
                </td>

                <!-- 末次活跃时间 -->
                <td v-if="viewLayout === 'table'" class="p-2.5 text-[11px] truncate ui-num" style="color: var(--text-muted);">
                  {{ new Date(asset.last_seen_ts).toLocaleTimeString('zh-CN', { hour12: false }) }}
                </td>

                <!-- 操作组合按钮 -->
                <td class="p-2 text-center truncate">
                  <div class="flex items-center justify-center gap-1">
                    <button
                      @click="$emit('probeSinglePort', asset.ip)"
                      class="p-1.5 rounded-lg glass-pill hover:text-amber-500 transition-all cursor-pointer"
                      style="color: var(--text-secondary);"
                      title="端口快速探活"
                    >
                      <AppIcon name="zap" :size="13" />
                    </button>
                    <button
                      @click="openTargetBannerScan(asset.ip)"
                      class="p-1.5 rounded-lg glass-pill hover:text-sky-500 transition-all cursor-pointer"
                      style="color: var(--text-secondary);"
                      title="并发端口区间与 Banner 深度扫描"
                    >
                      <AppIcon name="radar" :size="13" />
                    </button>
                    <button
                      @click="$emit('filterTraffic', asset.ip)"
                      class="p-1.5 rounded-lg glass-pill hover:text-blue-500 transition-all cursor-pointer"
                      style="color: var(--text-secondary);"
                      title="穿透至流量分析监控看板过滤该 IP"
                    >
                      <AppIcon name="search" :size="13" />
                    </button>
                    <button
                      @click="openIpDossier(asset.ip)"
                      class="p-1.5 rounded-lg glass-pill hover:text-indigo-500 transition-all cursor-pointer"
                      style="color: var(--text-secondary);"
                      title="打开该 IP 全息画像档案"
                    >
                      <AppIcon name="folder" :size="13" />
                    </button>
                    <button
                      @click="openTraceroute(asset.ip)"
                      class="p-1.5 rounded-lg glass-pill hover:text-emerald-500 transition-all cursor-pointer"
                      style="color: var(--text-secondary);"
                      title="启动测地线可视路由追踪，探测路由中转链路"
                    >
                      <AppIcon name="globe" :size="13" />
                    </button>
                    <button
                      @click="addAssetToDiffQueue(asset)"
                      class="p-1.5 rounded-lg glass-pill hover:text-purple-500 transition-all cursor-pointer"
                      style="color: var(--text-secondary);"
                      title="将资产开放端口/规约指纹加入全局多组比对队列"
                    >
                      <AppIcon name="scale" :size="13" />
                    </button>
                  </div>
                </td>
              </tr>
              <tr v-if="filteredAssets.length === 0">
                <td :colspan="viewLayout === 'table' ? 8 : 6" class="p-10 text-center">
                  <EmptyState
                    icon="radar"
                    title="暂无匹配的局域网资产记录"
                    description="点击顶部【全网扫描】探测当前局域网在线节点，或放宽搜索过滤条件。"
                  />
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- 右侧：工业网络拓扑地图 (实体稳态衬底，不再双层模糊锁黑) -->
      <div
        v-show="viewLayout === 'split' || viewLayout === 'topology'"
        :class="['ui-content-card flex flex-col overflow-hidden min-h-0 transition-all duration-200',
          viewLayout === 'topology' ? 'w-full flex-1' : 'flex-1 min-w-0']"
      >
        <div class="px-4 py-2 border-b flex items-center justify-between text-xs font-semibold shrink-0" style="border-color: var(--border-subtle); color: var(--text-primary);">
          <div class="flex items-center gap-2">
            <span>工业网络拓扑图</span>
            <span class="px-2 py-0.5 rounded-full text-[11px] font-medium bg-blue-500/12 text-blue-600 dark:text-sky-300 border border-blue-500/25">
              多层次网状 &amp; 同心雷达
            </span>
          </div>
          <button
            @click="viewLayout = viewLayout === 'topology' ? 'split' : 'topology'"
            :title="viewLayout === 'topology' ? '还原为分屏视图' : '放大独占拓扑全景'"
            class="ui-btn-secondary text-[11px] px-2.5 py-1"
          >
            <AppIcon :name="viewLayout === 'topology' ? 'minimize' : 'layers'" :size="12" />
            <span>{{ viewLayout === 'topology' ? '还原分屏' : '拓扑全景' }}</span>
          </button>
        </div>
        <div class="flex-1 relative overflow-hidden">
          <TopologyMap :packets="packets" :assets="assets" />
        </div>
      </div>
    </div>

    <!-- 全网 IP 全息画像与行为溯源控制台 -->
    <IpDossierModal
      :isOpen="dossierVisible"
      :targetIp="selectedDossierIp"
      :packets="packets"
      :assets="assets"
      @close="dossierVisible = false"
      @filterTraffic="$emit('filterTraffic', $event)"
      @drillDown="selectedDossierIp = $event"
    />

    <!-- 测地线可视路由追踪工作台 -->
    <GeodesicTracerouteModal
      :isOpen="isTracerouteOpen"
      :initialTarget="tracerouteTarget"
      @close="isTracerouteOpen = false"
    />

    <!-- 主动网段与端口 Banner 扫描模态框 -->
    <TargetProbeModal
      :isOpen="targetProbeOpen"
      :defaultIp="targetProbeIp"
      defaultPort="top25"
      @close="closeTargetBannerScan"
    />
  </div>
</template>

<script setup lang="ts">
import { notifySuccess, notifyInfo, notifyError } from '../composables/useNotification';
import { uiConfirm } from '../composables/useConfirmDialog';
import { ref, computed, onMounted, defineAsyncComponent } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import TopologyMap from '../components/TopologyMap.vue';
import IpDossierModal from '../components/IpDossierModal.vue';
import GeodesicTracerouteModal from '../components/GeodesicTracerouteModal.vue';
import AppIcon from '../components/AppIcon.vue';
import EmptyState from '../components/EmptyState.vue';
import { useUniversalDiff } from '../composables/useUniversalDiff';

const TargetProbeModal = defineAsyncComponent(() => import('../components/TargetProbeModal.vue'));

const diffBus = useUniversalDiff();

function addAssetToDiffQueue(asset: DiscoveredAsset) {
  const portStr = (asset.ports || []).slice().sort((a, b) => a - b).join(',');
  const protoStr = (asset.protocols || []).join(',');
  const summary = `IP=${asset.ip};MAC=${asset.mac || 'N/A'};ROLE=${asset.role};VENDOR=${asset.vendor || 'GENERIC'};PORTS=[${portStr}];PROTOS=[${protoStr}]`;
  diffBus.addToQueue({
    id: `ASSET_${asset.ip}`,
    label: `[资产] ${asset.ip}${asset.hostname ? ` (${asset.hostname})` : ''}`,
    protocol: asset.role || 'ASSET',
    src: asset.ip,
    dst: asset.mac || asset.zone_name || '-',
    format: 'ASCII',
    isRawText: true,
    payloadHex: '',
    rawText: summary,
    length: summary.length,
    extraFields: {
      ip: asset.ip,
      mac: asset.mac || '-',
      role: asset.role,
      vendor: asset.vendor || '-',
      scope: asset.scope || '-',
      ports: portStr || '-',
      protocols: protoStr || '-',
      packet_count: String(asset.packet_count)
    }
  }, `资产 ${asset.ip}`, false);
}

interface DiscoveredAsset {
  ip: string;
  mac: string;
  role: string;
  scope: string;
  vendor: string;
  first_seen_ts: number;
  last_seen_ts: number;
  packet_count: number;
  protocols: string[];
  ports: number[];
  zone_name?: string;
  geo_summary?: string;
  hostname?: string;
}

export interface AssetSnapshotSummary {
  id: string;
  name: string;
  timestamp: number;
  timestamp_str: string;
  total_assets: number;
  total_open_ports: number;
}

export interface AssetPortDiff {
  added_ports: number[];
  closed_ports: number[];
  has_high_risk_change: boolean;
}

export interface AssetDiffItem {
  ip: string;
  diff_type: string;
  base_mac?: string;
  target_mac?: string;
  is_mac_drift: boolean;
  base_vendor?: string;
  target_vendor?: string;
  base_role?: string;
  target_role?: string;
  port_diff?: AssetPortDiff;
  base_ports: number[];
  target_ports: number[];
  risk_level: string;
  risk_desc: string;
}

export interface AssetDiffReport {
  base_name: string;
  base_time: string;
  target_name: string;
  target_time: string;
  total_base: number;
  total_target: number;
  added_count: number;
  removed_count: number;
  modified_count: number;
  high_risk_count: number;
  items: AssetDiffItem[];
}

const props = defineProps<{
  assets: DiscoveredAsset[];
  packets: any[];
  scanning?: boolean;
  probingAll?: boolean;
}>();

const emit = defineEmits(['refreshAssets', 'scanAssets', 'probeAllPorts', 'probeSinglePort', 'clearAssets', 'filterTraffic', 'appendLog']);

const targetProbeOpen = ref(false);
const targetProbeIp = ref('');

function openTargetBannerScan(ip: string) {
  targetProbeIp.value = ip;
  targetProbeOpen.value = true;
}

function closeTargetBannerScan() {
  targetProbeOpen.value = false;
  emit('refreshAssets');
}

// 视口布局控制与角色分类
const viewLayout = ref<'split' | 'topology' | 'table' | 'hierarchy'>('split');

interface SuperNode {
  node_id: string;
  label: string;
  level: string;
  parent_id?: string | null;
  cidr_prefix?: string | null;
  is_collapsed: boolean;
  host_count: number;
  total_in_bytes: number;
  total_out_bytes: number;
  total_flows: number;
  total_alerts: number;
  high_risk_hosts: number;
}
interface AggregatedEdge {
  edge_id: string;
  source_node_id: string;
  target_node_id: string;
  flow_count: number;
  total_bytes: number;
  contains_threat: boolean;
}
interface TopologyViewPortResult {
  visible_nodes: SuperNode[];
  visible_edges: AggregatedEdge[];
  total_ingested_hosts: number;
  rendered_node_count: number;
  compression_ratio: number;
}
interface PhysicalPortLocation {
  target_ip: string;
  target_mac: string;
  switch_id: string;
  switch_ip: string;
  switch_name: string;
  if_index: number;
  if_name: string;
  vlan_id: number;
}

const hierarchyViewport = ref<TopologyViewPortResult | null>(null);
const switchLocateIp = ref('');
const switchPortLocResult = ref('');

async function fetchHierarchyViewport() {
  try {
    hierarchyViewport.value = await invoke<TopologyViewPortResult>('get_hierarchical_topology_viewport_cmd', { maxBudget: 64 });
  } catch (e) {
    console.error('加载分层拓扑失败:', e);
  }
}

async function switchToHierarchyLayout() {
  viewLayout.value = 'hierarchy';
  await fetchHierarchyViewport();
}

async function drillDownNode(nodeId: string) {
  await invoke<boolean>('drill_down_topology_node_cmd', { nodeId });
  await fetchHierarchyViewport();
}

async function rollUpNode(nodeId: string) {
  await invoke<boolean>('roll_up_topology_node_cmd', { nodeId });
  await fetchHierarchyViewport();
}

async function collapseAllHierarchy() {
  await invoke<boolean>('collapse_all_topology_cmd');
  await fetchHierarchyViewport();
}

async function locateSwitchPort() {
  const ip = switchLocateIp.value.trim();
  if (!ip) return;
  try {
    const res = await invoke<PhysicalPortLocation | null>('locate_asset_switch_port_cmd', { ip, mac: null });
    switchPortLocResult.value = res
      ? `已定位至交换机 [${res.switch_name} (${res.switch_ip})] 物理端口 ${res.if_name} (VLAN ${res.vlan_id}) | MAC: ${res.target_mac}`
      : `未在已登记 SNMP Bridge-MIB 转发表中匹配到 ${ip} 的物理接入端口`;
  } catch (e) {
    switchPortLocResult.value = `查询失败: ${String(e)}`;
  }
}
const activeRoleCategory = ref<string>('ALL');

const searchQuery = ref('');
const dossierVisible = ref(false);
const selectedDossierIp = ref('');

// 快照与差分比对工作台状态
const showDiffWorkbench = ref(false);
const newSnapshotName = ref('');
const isSavingSnapshot = ref(false);
const isComparing = ref(false);
const snapshotList = ref<AssetSnapshotSummary[]>([]);
const selectedBaseSnapshotId = ref('');
const selectedTargetSnapshotId = ref('CURRENT_REALTIME');
const diffReport = ref<AssetDiffReport | null>(null);
const diffFilter = ref<'ALL' | 'HIGH' | 'ADDED' | 'MODIFIED'>('ALL');

// 资产角色快速分类统计
const gatewayCount = computed(() =>
  props.assets.filter(a => a.role.includes('ROUTER') || a.role.includes('GATEWAY') || a.ip.endsWith('.1') || a.ip.endsWith('.254')).length
);

const controllerCount = computed(() =>
  props.assets.filter(a =>
    a.role.includes('PLC') ||
    a.role.includes('SERVER') ||
    a.role.includes('CENTER') ||
    a.protocols.some(p => ['MODBUS', 'S7COMM', 'IEC104', 'MQTT', 'OPCUA'].includes(p.toUpperCase()))
  ).length
);

const terminalCount = computed(() =>
  props.assets.filter(a =>
    !a.role.includes('ROUTER') &&
    !a.role.includes('GATEWAY') &&
    !a.role.includes('PLC') &&
    !a.role.includes('SERVER')
  ).length
);

const threatCount = computed(() =>
  props.assets.filter(a =>
    a.protocols.some(p => p.includes('HONEYPOT')) ||
    (a.ports && a.ports.some(p => [22, 23, 3389, 502].includes(p)))
  ).length
);

async function loadSnapshots() {
  try {
    const res = await invoke<AssetSnapshotSummary[]>('list_asset_snapshots_cmd');
    snapshotList.value = res || [];
    if (snapshotList.value.length > 0 && !selectedBaseSnapshotId.value) {
      selectedBaseSnapshotId.value = snapshotList.value[0].id;
    }
  } catch (e: any) {
    console.error('获取资产快照列表失败:', e);
  }
}

async function doSaveSnapshot() {
  isSavingSnapshot.value = true;
  try {
    const res = await invoke<AssetSnapshotSummary>('save_asset_snapshot_cmd', {
      name: newSnapshotName.value.trim() || undefined
    });
    newSnapshotName.value = '';
    await loadSnapshots();
    selectedBaseSnapshotId.value = res.id;
    emit('appendLog', `[ASSET] ✓ 成功保存全网资产快照: ${res.name} (含 ${res.total_assets} 节点)`);
    notifySuccess('资产快照保存成功', `已归档全网资产快照: ${res.name} (共 ${res.total_assets} 个节点)`);
  } catch (e: any) {
    notifyError('保存资产快照受阻', e);
  } finally {
    isSavingSnapshot.value = false;
  }
}

async function doDeleteSnapshot(id: string) {
  const confirmed = await uiConfirm(`确定要删除此份历史快照 (${id}) 吗？`, {
    title: '确认移除历史快照',
    confirmText: '确认删除',
    danger: true,
  });
  if (!confirmed) return;
  try {
    await invoke('delete_asset_snapshot_cmd', { id });
    await loadSnapshots();
    if (selectedBaseSnapshotId.value === id) {
      selectedBaseSnapshotId.value = snapshotList.value[0]?.id || '';
    }
    if (diffReport.value) diffReport.value = null;
    emit('appendLog', `[ASSET] 已移除历史快照 ${id}`);
    notifyInfo('资产快照已移除', `历史资产快照 ${id} 已被删除`);
  } catch (e: any) {
    notifyError('删除快照受阻', e);
  }
}

async function doCompareSnapshots() {
  if (!selectedBaseSnapshotId.value) return;
  isComparing.value = true;
  try {
    const targetId = selectedTargetSnapshotId.value === 'CURRENT_REALTIME' ? null : selectedTargetSnapshotId.value;
    const res = await invoke<AssetDiffReport>('compare_asset_snapshots_cmd', {
      baseId: selectedBaseSnapshotId.value,
      targetId
    });
    diffReport.value = res;
    emit('appendLog', `[ASSET] 资产差分比对完成: 基准 ${res.base_name} vs ${res.target_name} | 发现 ${res.added_count} 新增 / ${res.modified_count} 变动 / ${res.high_risk_count} 高危`);
    notifySuccess('资产差分比对完成', `基准 [${res.base_name}] vs [${res.target_name}]：新增 ${res.added_count}，变动 ${res.modified_count}，高危 ${res.high_risk_count}`);
  } catch (e: any) {
    notifyError('资产差分比对受阻', e);
  } finally {
    isComparing.value = false;
  }
}

const filteredDiffItems = computed(() => {
  if (!diffReport.value) return [];
  let list = diffReport.value.items;
  if (diffFilter.value === 'HIGH') {
    list = list.filter(i => i.risk_level === 'HIGH');
  } else if (diffFilter.value === 'ADDED') {
    list = list.filter(i => i.diff_type === 'ADDED');
  } else if (diffFilter.value === 'MODIFIED') {
    list = list.filter(i => i.diff_type === 'MODIFIED');
  }
  return list;
});

function openIpDossier(ip: string) {
  if (!ip) return;
  selectedDossierIp.value = ip;
  dossierVisible.value = true;
}

const isTracerouteOpen = ref(false);
const tracerouteTarget = ref('');
function openTraceroute(ip: string) {
  if (!ip) return;
  tracerouteTarget.value = ip;
  isTracerouteOpen.value = true;
}

const filteredAssets = computed(() => {
  let list = props.assets;

  // 1. 角色分类快速过滤
  if (activeRoleCategory.value === 'GATEWAY') {
    list = list.filter(a => a.role.includes('ROUTER') || a.role.includes('GATEWAY') || a.ip.endsWith('.1') || a.ip.endsWith('.254'));
  } else if (activeRoleCategory.value === 'CONTROLLER') {
    list = list.filter(a =>
      a.role.includes('PLC') ||
      a.role.includes('SERVER') ||
      a.role.includes('CENTER') ||
      a.protocols.some(p => ['MODBUS', 'S7COMM', 'IEC104', 'MQTT', 'OPCUA'].includes(p.toUpperCase()))
    );
  } else if (activeRoleCategory.value === 'TERMINAL') {
    list = list.filter(a =>
      !a.role.includes('ROUTER') &&
      !a.role.includes('GATEWAY') &&
      !a.role.includes('PLC') &&
      !a.role.includes('SERVER')
    );
  } else if (activeRoleCategory.value === 'THREAT') {
    list = list.filter(a =>
      a.protocols.some(p => p.includes('HONEYPOT')) ||
      (a.ports && a.ports.some(p => [22, 23, 3389, 502].includes(p)))
    );
  }

  // 2. 文本搜索过滤
  if (searchQuery.value.trim()) {
    const q = searchQuery.value.toLowerCase().trim();
    list = list.filter(a =>
      a.ip.toLowerCase().includes(q) ||
      (a.mac && a.mac.toLowerCase().includes(q)) ||
      (a.vendor && a.vendor.toLowerCase().includes(q)) ||
      (a.role && a.role.toLowerCase().includes(q)) ||
      (a.zone_name && a.zone_name.toLowerCase().includes(q)) ||
      (a.geo_summary && a.geo_summary.toLowerCase().includes(q)) ||
      (a.hostname && a.hostname.toLowerCase().includes(q)) ||
      a.protocols.some(p => p.toLowerCase().includes(q)) ||
      a.ports.some(p => String(p).includes(q))
    );
  }
  return list;
});

function roleBadgeColor(role: string): string {
  if (role.includes('ROUTER') || role.includes('GATEWAY')) {
    return 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/25';
  }
  if (role.includes('SERVER') || role.includes('CENTER')) {
    return 'bg-blue-500/15 text-blue-700 dark:text-sky-300 border border-blue-500/25';
  }
  if (role.includes('PLC') || role.includes('RTU')) {
    return 'bg-teal-500/15 text-teal-700 dark:text-teal-300 border border-teal-500/25';
  }
  return 'bg-slate-500/12 text-slate-700 dark:text-slate-300 border border-slate-500/20';
}

onMounted(() => {
  loadSnapshots();
});
</script>
