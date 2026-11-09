<template>
  <div class="flex-1 flex flex-col gap-2.5 overflow-hidden min-w-0">
    <!-- 顶部工具栏 (毛玻璃风格统一) -->
    <div class="bg-white/75 backdrop-blur-xl rounded-2xl border border-white/60 shadow-sm px-4 py-2 flex items-center justify-between shrink-0 gap-3 flex-wrap">
      <div class="flex items-center gap-3">
        <h2 class="text-xs font-bold text-slate-800 flex items-center gap-2">
          <span>局域网资产全息感知与拓扑态势 (Asset & Topology Intelligence)</span>
        </h2>
        <span class="text-[11px] font-mono text-slate-400">
          发现资产: <strong class="text-slate-800">{{ assets.length }}</strong> 节点
        </span>
      </div>

      <div class="flex items-center gap-2 flex-wrap text-xs">
        <!-- 视口布局模式分段选择器 -->
        <div class="bg-slate-100 p-0.5 rounded-xl border border-slate-200/80 flex items-center gap-0.5">
          <button @click="viewLayout = 'split'"
            :class="['px-2.5 py-1 rounded-lg text-xs font-semibold transition-all cursor-pointer flex items-center gap-1',
              viewLayout === 'split' ? 'bg-white text-blue-700 shadow-2xs font-bold' : 'text-slate-600 hover:text-slate-900']"
            title="左右均衡对照 (清单 + 拓扑)">
            <span>⚖️ 均衡分屏</span>
          </button>
          <button @click="viewLayout = 'topology'"
            :class="['px-2.5 py-1 rounded-lg text-xs font-semibold transition-all cursor-pointer flex items-center gap-1',
              viewLayout === 'topology' ? 'bg-white text-blue-700 shadow-2xs font-bold' : 'text-slate-600 hover:text-slate-900']"
            title="全景工业拓扑雷达大图">
            <span>🎯 拓扑全景</span>
          </button>
          <button @click="viewLayout = 'table'"
            :class="['px-2.5 py-1 rounded-lg text-xs font-semibold transition-all cursor-pointer flex items-center gap-1',
              viewLayout === 'table' ? 'bg-white text-blue-700 shadow-2xs font-bold' : 'text-slate-600 hover:text-slate-900']"
            title="全屏资产高密度数据台账">
            <span>📋 资产台账</span>
          </button>
        </div>

        <input v-model="searchQuery" placeholder="过滤 IP / MAC / 厂商 / 角色 / 端口"
          class="w-52 bg-white/80 border border-slate-200/80 rounded-xl px-2.5 py-1 text-xs text-slate-700 focus:outline-none focus:ring-2 focus:ring-blue-500/30 font-mono shadow-2xs">
        <button @click="$emit('refreshAssets')"
          class="bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs px-3 py-1 rounded-xl font-semibold cursor-pointer transition-all active:scale-95">
          刷新资产
        </button>
        <button @click="$emit('scanAssets')" :disabled="scanning"
          class="bg-blue-600 hover:bg-blue-700 text-white text-xs px-3.5 py-1 rounded-xl font-semibold shadow-sm transition-all flex items-center gap-1.5 cursor-pointer disabled:opacity-40 active:scale-95">
          <span v-if="scanning" class="animate-spin">⏳</span>
          <span>全网深度扫描</span>
        </button>
        <button @click="$emit('probeAllPorts')" :disabled="probingAll"
          class="bg-emerald-600 hover:bg-emerald-700 text-white text-xs px-3.5 py-1 rounded-xl font-semibold shadow-sm transition-all flex items-center gap-1.5 cursor-pointer disabled:opacity-40 active:scale-95">
          <span v-if="probingAll" class="animate-spin">⚡</span>
          <span>全网端口探活</span>
        </button>
        <!-- 资产快照与差分比对工作台入口 -->
        <button @click="showDiffWorkbench = !showDiffWorkbench"
          :class="['text-xs px-3.5 py-1 rounded-xl font-semibold shadow-sm transition-all flex items-center gap-1.5 cursor-pointer active:scale-95 border',
            showDiffWorkbench ? 'bg-indigo-600 text-white border-indigo-500 shadow-indigo-200' : 'bg-white/80 hover:bg-white text-indigo-700 border-indigo-200 shadow-2xs']">
          <span>📊 快照与差分对比</span>
          <span v-if="snapshotList.length > 0" class="px-1.5 py-0.2 rounded-full text-[10px] bg-indigo-100 text-indigo-800 font-mono font-bold">
            {{ snapshotList.length }}
          </span>
        </button>
        <!-- B9: clear_discovered_assets_cmd 真实资产清空 -->
        <button @click="$emit('clearAssets')"
          class="bg-rose-500/10 hover:bg-rose-500/20 text-rose-700 border border-rose-300/60 text-xs px-3 py-1 rounded-xl font-semibold transition-all cursor-pointer shadow-2xs active:scale-95">
          清空资产
        </button>
      </div>
    </div>

    <!-- 资产快照与多维差分比对工作台 (Apple Glassmorphism Workbench) -->
    <div v-if="showDiffWorkbench" class="bg-white/80 backdrop-blur-xl rounded-2xl border border-indigo-100 shadow-sm p-3.5 flex flex-col gap-3 shrink-0">
      <div class="flex items-center justify-between border-b border-slate-200/60 pb-2.5 flex-wrap gap-2">
        <div class="flex items-center gap-2">
          <span class="text-xs font-bold text-indigo-950 flex items-center gap-1.5">
            <span class="w-2 h-2 rounded-full bg-indigo-600 animate-pulse"></span>
            <span>全网资产快照持久化与基线差分审计工作台</span>
          </span>
          <span class="text-[11px] text-slate-500">
            支持历史快照持久化、任意两版本比对、高危端口突变与 MAC 漂移审计
          </span>
        </div>

        <!-- 快照创建操作栏 -->
        <div class="flex items-center gap-2 text-xs">
          <input v-model="newSnapshotName" placeholder="快照备注名称 (可选)"
            class="w-48 bg-white border border-slate-200 rounded-xl px-2.5 py-1 text-xs text-slate-700 focus:outline-none focus:ring-2 focus:ring-indigo-500/30 shadow-2xs">
          <button @click="doSaveSnapshot" :disabled="isSavingSnapshot"
            class="bg-indigo-600 hover:bg-indigo-700 text-white text-xs px-3 py-1 rounded-xl font-semibold shadow-2xs transition-all flex items-center gap-1 cursor-pointer disabled:opacity-40 active:scale-95">
            <span v-if="isSavingSnapshot" class="animate-spin">⏳</span>
            <span v-else>💾</span>
            <span>拍摄保存当前快照</span>
          </button>
          <button @click="showDiffWorkbench = false" title="收起快照工作台"
            class="w-7 h-7 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-500 hover:text-slate-800 flex items-center justify-center transition-colors cursor-pointer text-xs font-bold">
            ✕
          </button>
        </div>
      </div>

      <!-- 差分比对参数选择器 -->
      <div class="grid grid-cols-1 md:grid-cols-4 gap-2.5 items-center text-xs bg-slate-50/70 p-2.5 rounded-xl border border-slate-200/60">
        <div>
          <label class="text-[10px] font-bold text-slate-500 uppercase block mb-1">基准版本 (Base Snapshot)</label>
          <select v-model="selectedBaseSnapshotId"
            class="w-full bg-white border border-slate-200 rounded-xl px-2 py-1 text-xs font-mono text-slate-800 focus:outline-none focus:ring-2 focus:ring-indigo-500/30 shadow-2xs">
            <option v-for="s in snapshotList" :key="s.id" :value="s.id">
              {{ s.name }} ({{ s.total_assets }} 资产 / {{ s.timestamp_str }})
            </option>
            <option v-if="snapshotList.length === 0" value="">请先保存至少一份快照</option>
          </select>
        </div>

        <div>
          <label class="text-[10px] font-bold text-slate-500 uppercase block mb-1">对比目标 (Target Snapshot)</label>
          <select v-model="selectedTargetSnapshotId"
            class="w-full bg-white border border-slate-200 rounded-xl px-2 py-1 text-xs font-mono text-slate-800 focus:outline-none focus:ring-2 focus:ring-indigo-500/30 shadow-2xs">
            <option value="CURRENT_REALTIME">当前实时感知资产 ({{ assets.length }} 节点)</option>
            <option v-for="s in snapshotList" :key="s.id" :value="s.id">
              {{ s.name }} ({{ s.total_assets }} 资产 / {{ s.timestamp_str }})
            </option>
          </select>
        </div>

        <div class="flex items-end gap-2">
          <button @click="doCompareSnapshots" :disabled="!selectedBaseSnapshotId || isComparing"
            class="flex-1 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white text-xs px-3.5 py-1.5 rounded-xl font-bold shadow-sm transition-all flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-40 active:scale-95">
            <span v-if="isComparing" class="animate-spin">⏳</span>
            <span v-else>🔍</span>
            <span>执行多维差分比对</span>
          </button>
          <button @click="loadSnapshots" title="刷新快照清单"
            class="bg-white hover:bg-slate-100 text-slate-700 border border-slate-200 px-2.5 py-1.5 rounded-xl transition-all cursor-pointer shadow-2xs active:scale-95">
            ⟳
          </button>
          <button v-if="selectedBaseSnapshotId" @click="doDeleteSnapshot(selectedBaseSnapshotId)" title="删除选中的基准快照"
            class="bg-rose-50 hover:bg-rose-100 text-rose-700 border border-rose-200 px-2.5 py-1.5 rounded-xl transition-all cursor-pointer shadow-2xs active:scale-95">
            🗑️
          </button>
        </div>

        <!-- 差异过滤条件 -->
        <div v-if="diffReport">
          <label class="text-[10px] font-bold text-slate-500 uppercase block mb-1">差分项快速过滤</label>
          <div class="flex gap-1">
            <button @click="diffFilter = 'ALL'"
              :class="['px-2 py-0.5 rounded-lg text-[10px] font-bold border transition-all cursor-pointer',
                diffFilter === 'ALL' ? 'bg-indigo-600 text-white border-indigo-600' : 'bg-white text-slate-600 border-slate-200']">
              全部 ({{ diffReport.items.length }})
            </button>
            <button @click="diffFilter = 'HIGH'"
              :class="['px-2 py-0.5 rounded-lg text-[10px] font-bold border transition-all cursor-pointer',
                diffFilter === 'HIGH' ? 'bg-rose-600 text-white border-rose-600' : 'bg-white text-rose-700 border-rose-200']">
              高危告警 ({{ diffReport.high_risk_count }})
            </button>
            <button @click="diffFilter = 'ADDED'"
              :class="['px-2 py-0.5 rounded-lg text-[10px] font-bold border transition-all cursor-pointer',
                diffFilter === 'ADDED' ? 'bg-emerald-600 text-white border-emerald-600' : 'bg-white text-emerald-700 border-emerald-200']">
              新增 ({{ diffReport.added_count }})
            </button>
            <button @click="diffFilter = 'MODIFIED'"
              :class="['px-2 py-0.5 rounded-lg text-[10px] font-bold border transition-all cursor-pointer',
                diffFilter === 'MODIFIED' ? 'bg-amber-600 text-white border-amber-600' : 'bg-white text-amber-700 border-amber-200']">
              变动 ({{ diffReport.modified_count }})
            </button>
          </div>
        </div>
      </div>

      <!-- 差分比对报告面板 -->
      <div v-if="diffReport" class="flex flex-col gap-2">
        <!-- 统计摘要卡片 -->
        <div class="grid grid-cols-2 md:grid-cols-5 gap-2 text-xs">
          <div class="bg-indigo-50/80 border border-indigo-200/80 p-2 rounded-xl">
            <div class="text-[10px] text-indigo-600 font-bold uppercase">基准 vs 目标资产数</div>
            <div class="text-sm font-bold text-indigo-950 font-mono">{{ diffReport.total_base }} ➔ {{ diffReport.total_target }}</div>
          </div>
          <div class="bg-emerald-50/80 border border-emerald-200/80 p-2 rounded-xl">
            <div class="text-[10px] text-emerald-600 font-bold uppercase">新上线未知资产</div>
            <div class="text-sm font-bold text-emerald-800 font-mono">+{{ diffReport.added_count }} 节点</div>
          </div>
          <div class="bg-slate-100 border border-slate-200 p-2 rounded-xl">
            <div class="text-[10px] text-slate-500 font-bold uppercase">离线失联资产</div>
            <div class="text-sm font-bold text-slate-700 font-mono">-{{ diffReport.removed_count }} 节点</div>
          </div>
          <div class="bg-amber-50/80 border border-amber-200/80 p-2 rounded-xl">
            <div class="text-[10px] text-amber-600 font-bold uppercase">端口/属性漂移</div>
            <div class="text-sm font-bold text-amber-800 font-mono">~{{ diffReport.modified_count }} 节点</div>
          </div>
          <div class="bg-rose-50/80 border border-rose-200/80 p-2 rounded-xl">
            <div class="text-[10px] text-rose-600 font-bold uppercase">高危变动风险</div>
            <div class="text-sm font-bold text-rose-700 font-mono">🚨 {{ diffReport.high_risk_count }} 项</div>
          </div>
        </div>

        <!-- 差分明细表格 -->
        <div class="max-h-56 overflow-auto custom-scrollbar border border-slate-200/80 rounded-xl bg-white shadow-2xs">
          <table class="w-full text-left text-xs font-mono border-collapse table-fixed">
            <thead class="bg-slate-100/90 border-b border-slate-200 text-[10px] font-bold text-slate-500 uppercase sticky top-0 z-10">
              <tr>
                <th class="p-2 w-[18%]">节点 IP</th>
                <th class="p-2 w-[12%]">差分类型</th>
                <th class="p-2 w-[16%]">MAC 状态</th>
                <th class="p-2 w-[14%]">角色变动</th>
                <th class="p-2 w-[22%]">开放端口差分</th>
                <th class="p-2 w-[18%]">风险等级与审计说明</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-100 text-[11px]">
              <tr v-for="item in filteredDiffItems" :key="item.ip"
                :class="['hover:bg-slate-50/80 transition-colors',
                  item.risk_level === 'HIGH' ? 'bg-rose-50/40' : '']">
                <td class="p-2 font-bold text-slate-800 truncate" :title="item.ip">{{ item.ip }}</td>
                <td class="p-2 truncate">
                  <span :class="['px-1.5 py-0.5 rounded text-[9px] font-bold uppercase',
                    item.diff_type === 'ADDED' ? 'bg-emerald-100 text-emerald-800 border border-emerald-200' :
                    item.diff_type === 'REMOVED' ? 'bg-slate-200 text-slate-700 border border-slate-300' :
                    'bg-amber-100 text-amber-800 border border-amber-200']">
                    {{ item.diff_type === 'ADDED' ? '+ 新增' : item.diff_type === 'REMOVED' ? '- 下线' : '~ 变更' }}
                  </span>
                </td>
                <td class="p-2 truncate" :title="item.target_mac || item.base_mac || 'N/A'">
                  <div v-if="item.is_mac_drift" class="text-rose-600 font-bold flex items-center gap-1">
                    <span>⚠️ 漂移:</span>
                    <span class="line-through text-slate-400 text-[10px]">{{ item.base_mac }}</span>
                    <span>➔ {{ item.target_mac }}</span>
                  </div>
                  <div v-else class="text-slate-600">
                    {{ item.target_mac || item.base_mac || 'N/A' }}
                  </div>
                </td>
                <td class="p-2 text-slate-600 truncate">
                  <span v-if="item.base_role && item.target_role && item.base_role !== item.target_role">
                    {{ item.base_role }} ➔ {{ item.target_role }}
                  </span>
                  <span v-else>{{ item.target_role || item.base_role || '终端设备' }}</span>
                </td>
                <td class="p-2 truncate">
                  <div class="flex items-center gap-1 flex-wrap">
                    <span v-if="item.port_diff?.added_ports && item.port_diff.added_ports.length > 0"
                      class="px-1.5 py-0.2 rounded bg-emerald-100 text-emerald-800 text-[10px] font-bold border border-emerald-200">
                      +{{ item.port_diff.added_ports.join(',') }}
                    </span>
                    <span v-if="item.port_diff?.closed_ports && item.port_diff.closed_ports.length > 0"
                      class="px-1.5 py-0.2 rounded bg-rose-100 text-rose-800 text-[10px] font-bold border border-rose-200 line-through">
                      -{{ item.port_diff.closed_ports.join(',') }}
                    </span>
                    <span v-if="(!item.port_diff || (item.port_diff.added_ports.length === 0 && item.port_diff.closed_ports.length === 0))" class="text-slate-400 text-[10px]">
                      无端口变动
                    </span>
                  </div>
                </td>
                <td class="p-2 truncate">
                  <div class="flex items-center gap-1 truncate" :title="item.risk_desc">
                    <span :class="['px-1.5 py-0.2 rounded text-[9px] font-bold shrink-0',
                      item.risk_level === 'HIGH' ? 'bg-rose-600 text-white' :
                      item.risk_level === 'MEDIUM' ? 'bg-amber-500 text-white' :
                      'bg-slate-200 text-slate-700']">
                      {{ item.risk_level === 'HIGH' ? '高危' : item.risk_level === 'MEDIUM' ? '中危' : '正常' }}
                    </span>
                    <span class="truncate text-[10px] text-slate-700">{{ item.risk_desc }}</span>
                  </div>
                </td>
              </tr>
              <tr v-if="filteredDiffItems.length === 0">
                <td colspan="6" class="p-6 text-center text-slate-400 text-xs">
                  暂无匹配的差分记录（基准与对比版本在当前过滤条件下完全一致）
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- 主体：视口自适应调度 (分屏对照 / 拓扑全屏 / 资产台账) -->
    <div class="flex-1 flex gap-2.5 overflow-hidden min-h-0">
      <!-- 左侧：局域网资产清单表格 (毛玻璃风格统一) -->
      <div
        v-show="viewLayout === 'split' || viewLayout === 'table'"
        :class="['bg-white/75 backdrop-blur-xl rounded-2xl border border-white/60 shadow-sm flex flex-col overflow-hidden min-h-0 transition-all duration-200',
          viewLayout === 'table' ? 'w-full flex-1' : 'flex-1 min-w-0']"
      >
        <div class="px-4 py-2 border-b border-slate-200/50 bg-white/40 backdrop-blur-md flex items-center justify-between text-xs font-bold text-slate-700 shrink-0 flex-wrap gap-2">
          <div class="flex items-center gap-2">
            <span>局域网资产清单 ({{ filteredAssets.length }} / {{ assets.length }})</span>
            <span class="text-[10px] text-slate-400 font-normal hidden lg:inline">基于 ARP 侦测、物理流量沉淀与非阻塞探活</span>
          </div>

          <!-- 资产角色分类筛选胶囊 -->
          <div class="flex items-center gap-1 bg-slate-100/90 p-0.5 rounded-xl border border-slate-200/60 text-[10px]">
            <button @click="activeRoleCategory = 'ALL'"
              :class="['px-2 py-0.5 rounded-lg font-semibold transition-all cursor-pointer',
                activeRoleCategory === 'ALL' ? 'bg-white text-slate-900 shadow-2xs font-bold' : 'text-slate-500 hover:text-slate-800']">
              全部 ({{ assets.length }})
            </button>
            <button @click="activeRoleCategory = 'GATEWAY'"
              :class="['px-2 py-0.5 rounded-lg font-semibold transition-all cursor-pointer',
                activeRoleCategory === 'GATEWAY' ? 'bg-white text-indigo-700 shadow-2xs font-bold' : 'text-slate-500 hover:text-indigo-700']">
              网关 ({{ gatewayCount }})
            </button>
            <button @click="activeRoleCategory = 'CONTROLLER'"
              :class="['px-2 py-0.5 rounded-lg font-semibold transition-all cursor-pointer',
                activeRoleCategory === 'CONTROLLER' ? 'bg-white text-blue-700 shadow-2xs font-bold' : 'text-slate-500 hover:text-blue-700']">
              控制/服务 ({{ controllerCount }})
            </button>
            <button @click="activeRoleCategory = 'TERMINAL'"
              :class="['px-2 py-0.5 rounded-lg font-semibold transition-all cursor-pointer',
                activeRoleCategory === 'TERMINAL' ? 'bg-white text-slate-700 shadow-2xs font-bold' : 'text-slate-500 hover:text-slate-700']">
              现场终端 ({{ terminalCount }})
            </button>
            <button @click="activeRoleCategory = 'THREAT'"
              :class="['px-2 py-0.5 rounded-lg font-semibold transition-all cursor-pointer',
                activeRoleCategory === 'THREAT' ? 'bg-rose-600 text-white shadow-2xs font-bold' : 'text-rose-600 hover:bg-rose-50']">
              风险/蜜罐 ({{ threatCount }})
            </button>
          </div>
        </div>

        <div class="flex-1 overflow-auto custom-scrollbar">
          <table class="w-full text-left text-xs font-mono border-collapse table-fixed min-w-[820px]">
            <thead class="bg-slate-100/80 border-b border-slate-200/70 text-[10px] font-bold text-slate-500 uppercase sticky top-0 z-10 select-none">
              <tr>
                <th class="p-2.5 w-[22%] min-w-[170px]">主机 IPv4 & 名称</th>
                <th class="p-2.5 w-[15%] min-w-[125px]">物理 MAC</th>
                <th class="p-2.5 w-[14%] min-w-[115px]">硬件厂商画像</th>
                <th class="p-2.5 w-[12%] min-w-[95px]">网络角色</th>
                <th class="p-2.5 w-[10%] min-w-[85px]">业务规约</th>
                <th class="p-2.5 w-[11%] min-w-[95px]">开放端口</th>
                <th class="p-2.5 w-[8%] min-w-[75px]">末次活跃</th>
                <th class="p-2.5 w-[8%] min-w-[95px] text-center">操作</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-100">
              <tr v-for="asset in filteredAssets" :key="asset.ip" class="hover:bg-blue-50/30 transition-colors">
                <!-- IP 与主机名 -->
                <td class="p-2.5 font-bold text-slate-800">
                  <div class="flex items-center gap-1.5 flex-nowrap truncate">
                    <span
                      @click="openIpDossier(asset.ip)"
                      class="truncate cursor-pointer hover:text-blue-600 hover:underline transition-colors font-mono"
                      title="点击查阅 IP 全息画像档案"
                    >
                      {{ asset.ip }}
                    </span>
                    <span v-if="asset.hostname"
                      class="px-1.5 py-0.2 rounded text-[9px] font-normal bg-emerald-50 text-emerald-700 border border-emerald-200 shrink-0 truncate max-w-[80px]"
                      :title="asset.hostname">
                      {{ asset.hostname }}
                    </span>
                    <span v-else-if="asset.zone_name"
                      class="px-1.5 py-0.2 rounded text-[9px] font-normal bg-indigo-50 text-indigo-700 border border-indigo-200 shrink-0 truncate max-w-[80px]"
                      :title="asset.geo_summary || asset.zone_name">
                      {{ asset.zone_name }}
                    </span>
                  </div>
                </td>

                <!-- MAC -->
                <td class="p-2.5 text-slate-500 text-[11px] truncate font-mono">{{ asset.mac || 'N/A' }}</td>

                <!-- 厂商 -->
                <td class="p-2.5 text-slate-600 truncate text-[11px]" :title="asset.vendor">{{ asset.vendor || '通用网络终端' }}</td>

                <!-- 角色 -->
                <td class="p-2.5 truncate">
                  <span :class="['px-1.5 py-0.5 rounded text-[9px] font-bold uppercase truncate inline-block max-w-full', roleBadgeColor(asset.role)]">
                    {{ asset.role }}
                  </span>
                </td>

                <!-- 规约协议 -->
                <td class="p-2.5 truncate">
                  <div class="flex gap-1 flex-nowrap truncate">
                    <span v-for="pr in asset.protocols.slice(0, 2)" :key="pr"
                      :class="['px-1.5 py-0.2 rounded font-bold text-[9px] shrink-0 border',
                        pr.includes('HONEYPOT') ? 'bg-rose-50 text-rose-700 border-rose-200' : 'bg-slate-100 text-slate-700 border-slate-200']">
                      {{ pr }}
                    </span>
                    <span v-if="asset.protocols.length > 2" class="text-[9px] text-slate-400 font-bold">
                      +{{ asset.protocols.length - 2 }}
                    </span>
                  </div>
                </td>

                <!-- 开放端口 -->
                <td class="p-2.5 truncate">
                  <div class="flex items-center gap-1 flex-nowrap truncate">
                    <span v-for="port in asset.ports.slice(0, 3)" :key="port"
                      class="px-1.5 py-0.2 rounded-md bg-emerald-500/10 text-emerald-800 border border-emerald-300/60 text-[9px] font-bold shadow-2xs shrink-0">
                      :{{ port }}
                    </span>
                    <span v-if="asset.ports.length > 3" class="text-[9px] text-slate-400 font-bold">
                      +{{ asset.ports.length - 3 }}
                    </span>
                    <button v-if="asset.ports.length === 0" @click="$emit('probeSinglePort', asset.ip)"
                      class="text-[9px] px-1.5 py-0.2 rounded-md bg-amber-500/10 hover:bg-amber-500/20 text-amber-800 border border-amber-300/60 transition-colors cursor-pointer flex items-center gap-0.5 font-semibold shrink-0">
                      <span>⚡ 探活</span>
                    </button>
                  </div>
                </td>

                <!-- 末次活跃时间 -->
                <td class="p-2.5 text-slate-500 text-[11px] truncate font-mono">
                  {{ new Date(asset.last_seen_ts).toLocaleTimeString('zh-CN', { hour12: false }) }}
                </td>

                <!-- 操作组合按钮 -->
                <td class="p-2.5 text-center truncate">
                  <div class="flex items-center justify-center gap-1">
                    <button @click="$emit('probeSinglePort', asset.ip)"
                      class="text-[10px] px-1.5 py-0.5 rounded-lg bg-slate-100 hover:bg-amber-100 text-slate-700 hover:text-amber-800 border border-slate-200 transition-all cursor-pointer font-semibold shadow-2xs"
                      title="端口探活">
                      ⚡
                    </button>
                    <button @click="$emit('filterTraffic', asset.ip)"
                      class="text-[10px] px-1.5 py-0.5 rounded-lg bg-blue-50 hover:bg-blue-100 text-blue-700 border border-blue-200 transition-all cursor-pointer font-semibold shadow-2xs"
                      title="穿透至流量分析大屏过滤该 IP">
                      🔍
                    </button>
                    <button @click="openIpDossier(asset.ip)"
                      class="text-[10px] px-1.5 py-0.5 rounded-lg bg-purple-50 hover:bg-purple-100 text-purple-700 border border-purple-200 transition-all cursor-pointer font-semibold shadow-2xs"
                      title="打开该 IP 全息画像档案">
                      📁
                    </button>
                    <button @click="openTraceroute(asset.ip)"
                      class="text-[10px] px-1.5 py-0.5 rounded-lg bg-cyan-50 hover:bg-cyan-100 text-cyan-700 border border-cyan-200 transition-all cursor-pointer font-semibold shadow-2xs"
                      title="启动测地线可视路由追踪，探测地球大圆航线">
                      🌐
                    </button>
                  </div>
                </td>
              </tr>
              <tr v-if="filteredAssets.length === 0">
                <td colspan="8" class="p-12 text-center text-slate-400 text-xs">
                  暂无匹配的局域网资产记录，点击右上角【全网深度扫描】发起探测
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- 右侧：工业拓扑雷达地图 (毛玻璃风格统一) -->
      <div
        v-show="viewLayout === 'split' || viewLayout === 'topology'"
        :class="['bg-white/75 backdrop-blur-xl rounded-2xl border border-white/60 shadow-sm flex flex-col overflow-hidden min-h-0 transition-all duration-200',
          viewLayout === 'topology' ? 'w-full flex-1' : 'flex-1 min-w-0']"
      >
        <div class="px-4 py-2 border-b border-slate-200/50 bg-white/40 backdrop-blur-md flex items-center justify-between text-xs font-bold text-slate-700 shrink-0">
          <div class="flex items-center gap-2">
            <span>工业网络拓扑雷达 (Topology Intelligence)</span>
            <span class="px-2 py-0.2 rounded-full text-[10px] font-mono bg-blue-50 text-blue-700 border border-blue-200 font-semibold">
              多层次网状 & 同心圆雷达
            </span>
          </div>
          <button
            @click="viewLayout = viewLayout === 'topology' ? 'split' : 'topology'"
            :title="viewLayout === 'topology' ? '还原为分屏视图' : '放大独占拓扑全景'"
            class="text-[10px] px-2 py-0.5 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-600 border border-slate-200 transition-all cursor-pointer font-semibold"
          >
            {{ viewLayout === 'topology' ? '❐ 还原分屏' : '⛶ 拓扑全屏' }}
          </button>
        </div>
        <div class="flex-1 bg-slate-950 relative overflow-hidden">
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

    <!-- 测地线可视路由追踪工作台 (TASK-43) -->
    <GeodesicTracerouteModal
      :isOpen="isTracerouteOpen"
      :initialTarget="tracerouteTarget"
      @close="isTracerouteOpen = false"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import TopologyMap from '../components/TopologyMap.vue';
import IpDossierModal from '../components/IpDossierModal.vue';
import GeodesicTracerouteModal from '../components/GeodesicTracerouteModal.vue';

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

// 视口布局控制与角色分类
const viewLayout = ref<'split' | 'topology' | 'table'>('split');
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
  } catch (e: any) {
    alert(`保存快照失败: ${e}`);
  } finally {
    isSavingSnapshot.value = false;
  }
}

async function doDeleteSnapshot(id: string) {
  if (!confirm(`确定要删除此份历史快照 (${id}) 吗？`)) return;
  try {
    await invoke('delete_asset_snapshot_cmd', { id });
    await loadSnapshots();
    if (selectedBaseSnapshotId.value === id) {
      selectedBaseSnapshotId.value = snapshotList.value[0]?.id || '';
    }
    if (diffReport.value) diffReport.value = null;
    emit('appendLog', `[ASSET] 已移除历史快照 ${id}`);
  } catch (e: any) {
    alert(`删除快照失败: ${e}`);
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
  } catch (e: any) {
    alert(`差分比对失败: ${e}`);
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
  if (role.includes('ROUTER') || role.includes('GATEWAY')) return 'bg-amber-100 text-amber-900 border border-amber-200';
  if (role.includes('SERVER') || role.includes('CENTER')) return 'bg-blue-100 text-blue-900 border border-blue-200';
  if (role.includes('PLC') || role.includes('RTU')) return 'bg-teal-100 text-teal-900 border border-teal-200';
  return 'bg-slate-100 text-slate-700';
}

onMounted(() => {
  loadSnapshots();
});
</script>
