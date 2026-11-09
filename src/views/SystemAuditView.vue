<template>
  <div class="flex-1 flex flex-col gap-2.5 overflow-hidden min-w-0">
    <!-- 顶部状态栏 (毛玻璃风格统一) -->
    <div class="bg-white/75 backdrop-blur-xl rounded-2xl border border-white/60 shadow-sm px-4 py-2 flex items-center justify-between shrink-0 gap-3 flex-wrap">
      <div class="flex items-center gap-3">
        <h2 class="text-xs font-bold text-slate-800 flex items-center gap-2">
          <span>安全审计、等保合规与系统引擎</span>
        </h2>
        <div class="h-4 w-[1px] bg-slate-300/60"></div>
        
        <!-- 当前三员分立身份标签与切换按钮 -->
        <div class="flex items-center gap-2 bg-slate-100/80 px-2.5 py-1 rounded-xl border border-slate-200/70 text-xs">
          <span class="text-slate-400 font-medium">当前操作员:</span>
          <span class="font-bold font-mono" :class="roleBadgeColor">{{ currentUser.role_title }}</span>
          <button @click="openSwitchRoleModal"
            class="text-[10px] text-blue-600 hover:text-blue-800 font-semibold underline cursor-pointer ml-1">
            切换身份
          </button>
          <button @click="openChangePwdModal"
            class="text-[10px] text-indigo-600 hover:text-indigo-800 font-semibold underline cursor-pointer ml-1">
            修改口令
          </button>
        </div>

        <div class="h-4 w-[1px] bg-slate-300/60"></div>

        <!-- 司法存证双核操作：手动封存 + 证据链验真 -->
        <div class="flex items-center gap-1.5">
          <button @click="manualSeal" :disabled="sealing"
            class="bg-rose-500/10 hover:bg-rose-500/20 text-rose-700 border border-rose-300/60 text-xs px-2.5 py-1 rounded-xl font-bold transition-all flex items-center gap-1 cursor-pointer disabled:opacity-40 shadow-2xs active:scale-95">
            <span v-if="sealing" class="animate-spin">⏳</span>
            <span>🔒 手动司法封存</span>
          </button>

          <button @click="verifyEvidenceChain" :disabled="verifying"
            class="bg-purple-500/10 hover:bg-purple-500/20 text-purple-700 border border-purple-300/60 text-xs px-2.5 py-1 rounded-xl font-bold transition-all flex items-center gap-1 cursor-pointer disabled:opacity-40 shadow-2xs active:scale-95">
            <span v-if="verifying" class="animate-spin">⏳</span>
            <span>🛡️ 证据链验真</span>
          </button>
        </div>
      </div>

      <!-- 选项卡切换 (等保 2/3 全量覆盖) -->
      <div class="flex bg-slate-200/60 backdrop-blur-md p-1 rounded-xl text-xs font-semibold border border-white/40 shadow-inner flex-wrap gap-1">
        <button v-for="tab in subTabs" :key="tab.id" @click="changeTab(tab.id)"
          :class="['px-2 py-1 rounded-lg transition-all cursor-pointer text-[11px]',
            currentTab === tab.id ? 'bg-white text-blue-700 shadow-sm font-bold' : 'text-slate-600 hover:text-slate-900']">
          {{ tab.label }}
        </button>
      </div>
    </div>

    <!-- 主体内容容器 (毛玻璃风格统一) -->
    <div class="flex-1 bg-white/75 backdrop-blur-xl rounded-2xl border border-white/60 shadow-sm overflow-hidden flex flex-col">

      <!-- ============================================================ -->
      <!-- 选项卡 1：等保 2.0 / 3.0 合规态势驾驶舱 -->
      <!-- ============================================================ -->
      <div v-if="currentTab === 'compliance'" class="h-full flex flex-col gap-3 overflow-y-auto custom-scrollbar p-4">
        <div class="flex items-center justify-between border-b border-slate-200/50 pb-3 shrink-0">
          <div>
            <h3 class="text-xs font-bold text-slate-800">网络安全等级保护 2.0 / 3.0 (GB/T 22239-2019) 合规态势驾驶舱</h3>
            <p class="text-[11px] text-slate-400 mt-0.5">工控扩展指标、三员分立正交控制、基线漂移阻击与集中式日志存证差距分析</p>
          </div>
          <div class="text-right text-[11px] font-mono text-slate-500">
            基准标准：GB/T 22239-2019 / GB/T 28448-2019
          </div>
        </div>

        <!-- 等保等级符合度指标卡片 -->
        <div class="grid grid-cols-1 md:grid-cols-3 gap-3 shrink-0">
          <div class="bg-gradient-to-br from-emerald-50 to-teal-50/50 p-3.5 rounded-xl border border-emerald-200/80 shadow-2xs">
            <div class="flex items-center justify-between">
              <span class="text-xs font-bold text-emerald-900">等保二级 (Level 2)</span>
              <span class="px-2 py-0.5 rounded-full bg-emerald-600 text-white font-mono font-bold text-[10px]">88.5% 合规</span>
            </div>
            <div class="w-full bg-emerald-200/60 rounded-full h-1.5 mt-2.5 overflow-hidden">
              <div class="bg-emerald-600 h-1.5 rounded-full" style="width: 88.5%"></div>
            </div>
            <p class="text-[11px] text-emerald-700 mt-2">身份鉴别、访问控制、安全审计、网络架构隔离已全面达标</p>
          </div>

          <div class="bg-gradient-to-br from-blue-50 to-indigo-50/50 p-3.5 rounded-xl border border-blue-200/80 shadow-2xs">
            <div class="flex items-center justify-between">
              <span class="text-xs font-bold text-blue-900">等保三级 (Level 3 - 核心达标)</span>
              <span class="px-2 py-0.5 rounded-full bg-blue-600 text-white font-mono font-bold text-[10px]">95.2% 合规</span>
            </div>
            <div class="w-full bg-blue-200/60 rounded-full h-1.5 mt-2.5 overflow-hidden">
              <div class="bg-blue-600 h-1.5 rounded-full" style="width: 95.2%"></div>
            </div>
            <p class="text-[11px] text-blue-700 mt-2">三员分立、RFC 5424 集中外发、工控基线白名单自学习已完全就绪</p>
          </div>

          <div class="bg-gradient-to-br from-slate-50 to-amber-50/50 p-3.5 rounded-xl border border-amber-200/80 shadow-2xs">
            <div class="flex items-center justify-between">
              <span class="text-xs font-bold text-slate-800">等保四级 (Level 4 - 差距演进)</span>
              <span class="px-2 py-0.5 rounded-full bg-amber-600 text-white font-mono font-bold text-[10px]">28.0% 演进中</span>
            </div>
            <div class="w-full bg-slate-200 rounded-full h-1.5 mt-2.5 overflow-hidden">
              <div class="bg-amber-500 h-1.5 rounded-full" style="width: 28%"></div>
            </div>
            <p class="text-[11px] text-slate-600 mt-2">缺少：硬件密码机 HSM 抗量子加密卡、形式化验证系统内核</p>
          </div>
        </div>

        <!-- 详细测评项检查矩阵表格 -->
        <div class="flex-1 overflow-auto custom-scrollbar border border-slate-200/70 rounded-xl bg-white/60">
          <table class="w-full text-left text-xs font-mono border-collapse">
            <thead class="bg-slate-100/80 border-b border-slate-200/70 text-[10px] font-bold text-slate-500 uppercase sticky top-0 z-10">
              <tr>
                <th class="p-2.5">测评项标准条款</th>
                <th class="p-2.5">对应等保等级</th>
                <th class="p-2.5">安全控制要求</th>
                <th class="p-2.5">Omni-Probe 探针系统实现程度</th>
                <th class="p-2.5 text-center">符合状态</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-100">
              <tr v-for="(item, idx) in complianceItems" :key="idx" class="hover:bg-white/80 transition-colors">
                <td class="p-2.5 font-bold text-slate-700">{{ item.clause }}</td>
                <td class="p-2.5"><span class="px-2 py-0.5 rounded-md font-bold text-[10px]" :class="item.levelBadge">{{ item.level }}</span></td>
                <td class="p-2.5 text-slate-600">{{ item.requirement }}</td>
                <td class="p-2.5 text-slate-700">{{ item.implementation }}</td>
                <td class="p-2.5 text-center">
                  <span class="px-2 py-0.5 rounded-full font-bold text-[10px]" :class="item.statusBadge">
                    {{ item.status }}
                  </span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- ============================================================ -->
      <!-- 选项卡 2：三员分立访问控制与操作审计追踪 (RBAC) -->
      <!-- ============================================================ -->
      <div v-else-if="currentTab === 'rbac'" class="h-full flex flex-col gap-3 overflow-hidden p-4">
        <div class="flex items-center justify-between border-b border-slate-200/50 pb-3 shrink-0 flex-wrap gap-2">
          <div>
            <h3 class="text-xs font-bold text-slate-800">等保三级 (8.1.4.1/8.1.4.4) 三员分立访问控制与管理审计链</h3>
            <p class="text-[11px] text-slate-400 mt-0.5">系统管理员、安全管理员、安全审计员权限正交隔离；禁止任何角色物理篡改审计存证</p>
          </div>
          <button @click="loadAdminAuditTrail" class="text-xs text-blue-600 hover:text-blue-800 font-semibold cursor-pointer">
            🔄 刷新操作审计链
          </button>
        </div>

        <!-- 三员分立身份现状卡片 -->
        <div class="grid grid-cols-1 md:grid-cols-3 gap-3 shrink-0">
          <div :class="['p-3 rounded-xl border transition-all', currentUser.role === 'SysAdmin' ? 'bg-indigo-50/80 border-indigo-300 ring-2 ring-indigo-200' : 'bg-slate-50/60 border-slate-200/80']">
            <div class="flex items-center justify-between">
              <span class="font-bold text-xs text-slate-800">系统管理员 (SysAdmin)</span>
              <span v-if="currentUser.role === 'SysAdmin'" class="px-2 py-0.5 rounded-full bg-indigo-600 text-white text-[9px] font-bold">当前会话</span>
            </div>
            <p class="text-[10px] text-slate-500 mt-1">口令: admin@123</p>
            <div class="mt-2 text-[10px] text-slate-600 space-y-1">
              <div>• 硬件物理接口配置 (网卡/串口/USB)</div>
              <div>• 探针引擎抓包/停止控制</div>
              <div>• 数据落盘与存储路径配置</div>
            </div>
          </div>

          <div :class="['p-3 rounded-xl border transition-all', currentUser.role === 'SecAdmin' ? 'bg-emerald-50/80 border-emerald-300 ring-2 ring-emerald-200' : 'bg-slate-50/60 border-slate-200/80']">
            <div class="flex items-center justify-between">
              <span class="font-bold text-xs text-slate-800">安全管理员 (SecAdmin)</span>
              <span v-if="currentUser.role === 'SecAdmin'" class="px-2 py-0.5 rounded-full bg-emerald-600 text-white text-[9px] font-bold">当前会话</span>
            </div>
            <p class="text-[10px] text-slate-500 mt-1">口令: sec@123</p>
            <div class="mt-2 text-[10px] text-slate-600 space-y-1">
              <div>• 工业通信基线白名单自学习模式切换</div>
              <div>• 安全域划分与 CIDR 网段访问控制规则</div>
              <div>• 威胁防御限流与主动诱捕蜜罐配置</div>
            </div>
          </div>

          <div :class="['p-3 rounded-xl border transition-all', currentUser.role === 'AuditAdmin' ? 'bg-purple-50/80 border-purple-300 ring-2 ring-purple-200' : 'bg-slate-50/60 border-slate-200/80']">
            <div class="flex items-center justify-between">
              <span class="font-bold text-xs text-slate-800">安全审计员 (AuditAdmin)</span>
              <span v-if="currentUser.role === 'AuditAdmin'" class="px-2 py-0.5 rounded-full bg-purple-600 text-white text-[9px] font-bold">当前会话</span>
            </div>
            <p class="text-[10px] text-slate-500 mt-1">口令: audit@123</p>
            <div class="mt-2 text-[10px] text-slate-600 space-y-1">
              <div>• 独立审查系统/内核日志与管理审计流</div>
              <div>• 司法哈希封条验真与合规报告存证</div>
              <div>• 独享日志处置与清理权限 (等保8.1.4.4)</div>
            </div>
          </div>
        </div>

        <!-- 管理操作审计流水表格 -->
        <div class="flex-1 flex flex-col min-h-0">
          <div class="text-[11px] font-bold text-slate-700 mb-1.5 flex items-center justify-between">
            <span>管理员操作抗抵赖审计流水 ({{ adminAuditTrail.length }} 条记录)</span>
            <span class="text-[10px] text-slate-400 font-mono">任何配置更改与越权阻断均已同步广播至 Syslog</span>
          </div>
          <div class="flex-1 overflow-auto custom-scrollbar border border-slate-200/70 rounded-xl bg-white/60">
            <table class="w-full text-left text-xs font-mono border-collapse">
              <thead class="bg-slate-100/80 border-b border-slate-200/70 text-[10px] font-bold text-slate-500 uppercase sticky top-0 z-10">
                <tr>
                  <th class="p-2">序号</th>
                  <th class="p-2">时间戳</th>
                  <th class="p-2">操作者</th>
                  <th class="p-2">所属角色</th>
                  <th class="p-2">管理行为</th>
                  <th class="p-2">审计详情</th>
                  <th class="p-2 text-center">状态</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-100">
                <tr v-for="rec in adminAuditTrail" :key="rec.id" class="hover:bg-white/80 transition-colors">
                  <td class="p-2 text-slate-400">#{{ rec.id }}</td>
                  <td class="p-2 text-slate-500">{{ rec.timestamp }}</td>
                  <td class="p-2 font-bold text-slate-700">{{ rec.operator }}</td>
                  <td class="p-2"><span class="px-1.5 py-0.5 rounded bg-slate-100 font-bold text-[10px]">{{ rec.role }}</span></td>
                  <td class="p-2 font-bold text-indigo-700">{{ rec.action }}</td>
                  <td class="p-2 text-slate-600 truncate max-w-xs" :title="rec.details">{{ rec.details }}</td>
                  <td class="p-2 text-center">
                    <span :class="['px-2 py-0.5 rounded-full text-[10px] font-bold', rec.status === 'SUCCESS' ? 'bg-emerald-100 text-emerald-800' : 'bg-rose-100 text-rose-800']">
                      {{ rec.status }}
                    </span>
                  </td>
                </tr>
                <tr v-if="adminAuditTrail.length === 0">
                  <td colspan="7" class="p-8 text-center text-slate-400 text-xs">
                    暂无管理操作审计流水
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- ============================================================ -->
      <!-- 选项卡 3：工业通信基线白名单自学习与漂移检测 -->
      <!-- ============================================================ -->
      <div v-else-if="currentTab === 'baseline'" class="h-full flex flex-col gap-3 overflow-hidden p-4">
        <div class="flex items-center justify-between border-b border-slate-200/50 pb-3 shrink-0 flex-wrap gap-2">
          <div>
            <h3 class="text-xs font-bold text-slate-800">等保三级工控扩展 (G.4.2/G.4.3) 工业通信基线白名单自学习引擎</h3>
            <p class="text-[11px] text-slate-400 mt-0.5">被动收敛全网物理/逻辑通信拓扑基线；严格阻击未授权新会话与高危工控写控制指令</p>
          </div>
          <div class="flex items-center gap-2">
            <!-- 模式切换单选组 -->
            <div class="flex bg-slate-200/80 p-0.5 rounded-xl text-[11px] font-bold border border-slate-300/50">
              <button @click="changeBaselineMode('LEARNING')"
                :class="['px-2.5 py-1 rounded-lg transition-all cursor-pointer', baselineStatus.mode === 'LEARNING' ? 'bg-emerald-600 text-white shadow-sm' : 'text-slate-600 hover:text-slate-900']">
                自学习模式 (Learning)
              </button>
              <button @click="changeBaselineMode('ENFORCING')"
                :class="['px-2.5 py-1 rounded-lg transition-all cursor-pointer', baselineStatus.mode === 'ENFORCING' ? 'bg-rose-600 text-white shadow-sm' : 'text-slate-600 hover:text-slate-900']">
                严格审计模式 (Enforcing)
              </button>
              <button @click="changeBaselineMode('DISABLED')"
                :class="['px-2.5 py-1 rounded-lg transition-all cursor-pointer', baselineStatus.mode === 'DISABLED' ? 'bg-slate-400 text-white shadow-sm' : 'text-slate-600 hover:text-slate-900']">
                已停用
              </button>
            </div>
            <button @click="persistBaseline"
              class="bg-emerald-600 hover:bg-emerald-700 text-white text-xs px-2.5 py-1 rounded-xl font-bold cursor-pointer transition-all shadow-2xs">
              💾 固化基线至磁盘
            </button>
            <button @click="resetBaselineRules"
              class="bg-rose-500/10 hover:bg-rose-500/20 text-rose-700 border border-rose-300/60 text-xs px-2.5 py-1 rounded-xl font-bold cursor-pointer transition-all">
              重置基线规则
            </button>
          </div>
        </div>

        <!-- 基线指标仪表盘 -->
        <div class="grid grid-cols-1 md:grid-cols-4 gap-3 shrink-0">
          <div class="bg-slate-50/80 p-2.5 rounded-xl border border-slate-200/80">
            <span class="text-[10px] text-slate-500 font-bold uppercase">当前基线模式</span>
            <div class="text-sm font-bold font-mono mt-1" :class="baselineStatus.mode === 'ENFORCING' ? 'text-rose-600' : 'text-emerald-600'">
              {{ baselineStatus.mode === 'LEARNING' ? '自学习模式 (收敛中)' : (baselineStatus.mode === 'ENFORCING' ? '严格审计模式 (实时阻击)' : '已停用') }}
            </div>
          </div>
          <div class="bg-slate-50/80 p-2.5 rounded-xl border border-slate-200/80">
            <span class="text-[10px] text-slate-500 font-bold uppercase">已收敛白名单规则</span>
            <div class="text-sm font-bold font-mono text-indigo-700 mt-1">{{ baselineRules.length }} 条合法通信对</div>
          </div>
          <div class="bg-slate-50/80 p-2.5 rounded-xl border border-slate-200/80">
            <span class="text-[10px] text-slate-500 font-bold uppercase">捕获合规漂移违规</span>
            <div class="text-sm font-bold font-mono text-rose-600 mt-1">{{ baselineDriftEvents.length }} 起越权事件</div>
          </div>
          <div class="bg-slate-50/80 p-2.5 rounded-xl border border-slate-200/80">
            <span class="text-[10px] text-slate-500 font-bold uppercase">基线自学习启动时间</span>
            <div class="text-xs font-mono text-slate-600 mt-1 truncate">{{ baselineStatus.learning_started_at || '待启动' }}</div>
          </div>
        </div>

        <!-- 规则与漂移违规上下分割 -->
        <div class="flex-1 grid grid-cols-1 lg:grid-cols-2 gap-3 min-h-0">
          <div class="flex flex-col min-h-0 border border-slate-200/70 rounded-xl bg-white/60 p-2.5">
            <div class="text-[11px] font-bold text-slate-700 mb-1.5 flex items-center justify-between">
              <span>已收敛合法通信基线 ({{ baselineRules.length }})</span>
              <button @click="loadBaselineRules" class="text-[10px] text-blue-600 hover:text-blue-800 font-semibold cursor-pointer">刷新</button>
            </div>
            <div class="flex-1 overflow-auto custom-scrollbar">
              <table class="w-full text-left text-xs font-mono border-collapse">
                <thead class="bg-slate-100/80 border-b border-slate-200/70 text-[10px] font-bold text-slate-500 uppercase sticky top-0 z-10">
                  <tr>
                    <th class="p-1.5">通信链路 (源 ➔ 宿)</th>
                    <th class="p-1.5">规约/端口</th>
                    <th class="p-1.5">动作基线</th>
                    <th class="p-1.5 text-right">命中次数</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-slate-100 text-[11px]">
                  <tr v-for="r in baselineRules" :key="r.id" class="hover:bg-white/80">
                    <td class="p-1.5 font-bold text-slate-700 truncate max-w-[140px]" :title="`${r.src_ip} ➔ ${r.dst_ip}`">
                      {{ r.src_ip }} ➔ {{ r.dst_ip }}
                    </td>
                    <td class="p-1.5 text-slate-500">{{ r.protocol }}:{{ r.dst_port }}</td>
                    <td class="p-1.5">
                      <span :class="['px-1.5 py-0.2 rounded font-bold text-[9px]', r.action_type === 'WRITE_ALLOWED' ? 'bg-amber-100 text-amber-800' : 'bg-emerald-100 text-emerald-800']">
                        {{ r.action_type === 'WRITE_ALLOWED' ? '允许写控制' : '严格只读查询' }}
                      </span>
                    </td>
                    <td class="p-1.5 text-right font-bold text-indigo-600">{{ r.hit_count }}</td>
                  </tr>
                  <tr v-if="baselineRules.length === 0">
                    <td colspan="4" class="p-6 text-center text-slate-400 text-xs">
                      基线学习中，接收到工控网络报文后将自动收敛规则
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <div class="flex flex-col min-h-0 border border-slate-200/70 rounded-xl bg-white/60 p-2.5">
            <div class="text-[11px] font-bold text-slate-700 mb-1.5 flex items-center justify-between">
              <span class="text-rose-700">实时通信漂移与高危指令告警 ({{ baselineDriftEvents.length }})</span>
              <button @click="loadBaselineDriftEvents" class="text-[10px] text-blue-600 hover:text-blue-800 font-semibold cursor-pointer">刷新</button>
            </div>
            <div class="flex-1 overflow-auto custom-scrollbar">
              <table class="w-full text-left text-xs font-mono border-collapse">
                <thead class="bg-rose-50/70 border-b border-rose-200/70 text-[10px] font-bold text-rose-800 uppercase sticky top-0 z-10">
                  <tr>
                    <th class="p-1.5">时间</th>
                    <th class="p-1.5">违规类型</th>
                    <th class="p-1.5">会话链路</th>
                    <th class="p-1.5">告警详情</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-slate-100 text-[11px]">
                  <tr v-for="ev in baselineDriftEvents" :key="ev.id" class="hover:bg-rose-50/40">
                    <td class="p-1.5 text-slate-400 text-[10px]">{{ ev.timestamp.split(' ')[1] }}</td>
                    <td class="p-1.5">
                      <span class="px-1.5 py-0.2 rounded font-bold text-[9px] bg-rose-100 text-rose-800">
                        {{ ev.drift_type }}
                      </span>
                    </td>
                    <td class="p-1.5 text-slate-700">{{ ev.src_ip }} ➔ :{{ ev.dst_port }}</td>
                    <td class="p-1.5 text-slate-600 truncate max-w-[160px]" :title="ev.description">
                      {{ ev.description }}
                    </td>
                  </tr>
                  <tr v-if="baselineDriftEvents.length === 0">
                    <td colspan="4" class="p-6 text-center text-slate-400 text-xs">
                      当前基线状态良好，未检测到违规漂移事件
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>

      <!-- ============================================================ -->
      <!-- 选项卡 4：安全区域划分与 CIDR 资产规则 (等保 8.1.2.1/8.1.2.2) -->
      <!-- ============================================================ -->
      <div v-else-if="currentTab === 'zones'" class="h-full flex flex-col gap-3 overflow-hidden p-4">
        <div class="flex items-center justify-between border-b border-slate-200/50 pb-3 shrink-0 flex-wrap gap-2">
          <div>
            <h3 class="text-xs font-bold text-slate-800">等保三级 (8.1.2.1/8.1.2.2) 安全区域划分与 CIDR 网段规则管理</h3>
            <p class="text-[11px] text-slate-400 mt-0.5">严格定义生产控制区(安全区I)、生产非控制区(安全区II)、管理信息大区(安全区III)等网络边界</p>
          </div>
          <div class="flex items-center gap-2">
            <button @click="loadCidrRules" class="bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs px-3 py-1 rounded-xl font-semibold cursor-pointer">
              重新加载
            </button>
            <button @click="saveCidrRules" class="bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white text-xs px-3.5 py-1 rounded-xl font-bold cursor-pointer shadow-sm">
              保存区域规则
            </button>
          </div>
        </div>

        <!-- 快速添加新网段规则栏 -->
        <div class="bg-slate-50/80 p-3 rounded-xl border border-slate-200/80 shrink-0 flex items-center gap-2 flex-wrap text-xs">
          <span class="font-bold text-slate-700 text-[11px]">添加网段:</span>
          <input v-model="newCidr" placeholder="网段 CIDR (如 192.168.10.0/24)" class="w-48 bg-white border border-slate-200 rounded-lg px-2.5 py-1 text-xs font-mono">
          <input v-model="newZoneName" placeholder="安全区域名称 (如 生产控制大区-安全区I)" class="w-56 bg-white border border-slate-200 rounded-lg px-2.5 py-1 text-xs">
          <select v-model="newSecLevel" class="bg-white border border-slate-200 rounded-lg px-2 py-1 text-xs font-semibold">
            <option value="核心生产">核心生产 (安全区I)</option>
            <option value="关键业务">关键业务 (安全区II)</option>
            <option value="生产管理">生产管理 (安全区III)</option>
            <option value="办公外网">办公外网 (安全区IV)</option>
            <option value="外部公网">外部公网</option>
          </select>
          <input v-model="newDescription" placeholder="归属说明/用途" class="flex-1 min-w-[120px] bg-white border border-slate-200 rounded-lg px-2.5 py-1 text-xs">
          <button @click="addCidrRule" class="bg-indigo-600 hover:bg-indigo-700 text-white px-3 py-1 rounded-lg font-bold cursor-pointer transition-all">
            + 添加规则
          </button>
        </div>

        <!-- CIDR 网段规则表格 -->
        <div class="flex-1 overflow-auto custom-scrollbar border border-slate-200/70 rounded-xl bg-white/60">
          <table class="w-full text-left text-xs font-mono border-collapse">
            <thead class="bg-slate-100/80 border-b border-slate-200/70 text-[10px] font-bold text-slate-500 uppercase sticky top-0 z-10">
              <tr>
                <th class="p-2.5">CIDR 网段</th>
                <th class="p-2.5">安全区域名称</th>
                <th class="p-2.5">安全等级</th>
                <th class="p-2.5">责任归属说明</th>
                <th class="p-2.5 text-center">操作</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-100">
              <tr v-for="(rule, idx) in cidrRules" :key="idx" class="hover:bg-white/80 transition-colors">
                <td class="p-2.5 font-bold text-indigo-700">
                  <input v-model="rule.cidr" class="bg-transparent border-b border-transparent focus:border-indigo-400 outline-none w-full">
                </td>
                <td class="p-2.5 font-bold text-slate-700">
                  <input v-model="rule.zone_name" class="bg-transparent border-b border-transparent focus:border-indigo-400 outline-none w-full">
                </td>
                <td class="p-2.5">
                  <span class="px-2 py-0.5 rounded-md font-bold text-[10px] bg-slate-100 text-slate-800">{{ rule.security_level }}</span>
                </td>
                <td class="p-2.5 text-slate-600">
                  <input v-model="rule.description" class="bg-transparent border-b border-transparent focus:border-indigo-400 outline-none w-full">
                </td>
                <td class="p-2.5 text-center">
                  <button @click="removeCidrRule(idx)" class="text-rose-500 hover:text-rose-700 font-bold text-xs cursor-pointer">
                    删除
                  </button>
                </td>
              </tr>
              <tr v-if="cidrRules.length === 0">
                <td colspan="5" class="p-8 text-center text-slate-400 text-xs">
                  尚未配置任何 CIDR 安全区域规则
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- ============================================================ -->
      <!-- 选项卡 5：RFC 5424 Syslog 集中式审计日志外发配置 -->
      <!-- ============================================================ -->
      <div v-else-if="currentTab === 'syslog'" class="h-full flex flex-col gap-3 overflow-y-auto custom-scrollbar p-4">
        <div class="flex items-center justify-between border-b border-slate-200/50 pb-3 shrink-0 flex-wrap gap-2">
          <div>
            <h3 class="text-xs font-bold text-slate-800">等保三级 (8.1.4.3) 集中式日志备份与 RFC 5424 Syslog 外发引擎</h3>
            <p class="text-[11px] text-slate-400 mt-0.5">严格遵循 RFC 5424 标准规范，异步 UDP / TCP 外发至企业 SIEM / SOC 集中日志审计中心</p>
          </div>
          <div class="flex items-center gap-2">
            <button @click="loadSyslogConfig" class="bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs px-3 py-1 rounded-xl font-semibold cursor-pointer">
              重新加载
            </button>
            <button @click="saveSyslogConfig" class="bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white text-xs px-3.5 py-1 rounded-xl font-bold cursor-pointer shadow-sm">
              保存配置
            </button>
          </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-3 gap-3 shrink-0">
          <div class="space-y-1 bg-slate-50/80 p-3 rounded-xl border border-slate-200/80">
            <label class="text-[11px] font-bold text-slate-700 block">集中外发主开关</label>
            <label class="flex items-center gap-2 cursor-pointer mt-1.5">
              <input type="checkbox" v-model="syslogCfg.enabled" class="accent-blue-600 w-4 h-4">
              <span class="text-xs font-bold" :class="syslogCfg.enabled ? 'text-emerald-700' : 'text-slate-400'">
                {{ syslogCfg.enabled ? '已启用集中外发' : '已停用集中外发' }}
              </span>
            </label>
          </div>

          <div class="space-y-1 bg-slate-50/80 p-3 rounded-xl border border-slate-200/80">
            <label class="text-[11px] font-bold text-slate-700 block">远程 SIEM/SOC 服务器 IP</label>
            <input v-model="syslogCfg.server_ip" placeholder="192.168.1.200"
              class="w-full bg-white border border-slate-200 rounded-lg px-2.5 py-1 text-xs font-mono shadow-2xs">
          </div>

          <div class="space-y-1 bg-slate-50/80 p-3 rounded-xl border border-slate-200/80">
            <label class="text-[11px] font-bold text-slate-700 block">服务端口与传输协议</label>
            <div class="flex gap-2">
              <input v-model.number="syslogCfg.server_port" type="number" min="1" max="65535"
                class="w-24 bg-white border border-slate-200 rounded-lg px-2.5 py-1 text-xs font-mono shadow-2xs">
              <select v-model="syslogCfg.protocol" class="flex-1 bg-white border border-slate-200 rounded-lg px-2 py-1 text-xs font-mono shadow-2xs">
                <option value="UDP">UDP (低开销)</option>
                <option value="TCP">TCP (可靠传输)</option>
              </select>
            </div>
          </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-3 gap-3 shrink-0">
          <div class="space-y-1 bg-slate-50/80 p-3 rounded-xl border border-slate-200/80">
            <label class="text-[11px] font-bold text-slate-700 block">Syslog Facility (设施)</label>
            <select v-model.number="syslogCfg.facility" class="w-full bg-white border border-slate-200 rounded-lg px-2.5 py-1 text-xs font-mono shadow-2xs">
              <option :value="1">1: user-level messages</option>
              <option :value="16">16: local0 (标准工业审计)</option>
              <option :value="17">17: local1</option>
              <option :value="18">18: local2</option>
            </select>
          </div>

          <div class="space-y-1 bg-slate-50/80 p-3 rounded-xl border border-slate-200/80">
            <label class="text-[11px] font-bold text-slate-700 block">最低外发严重性 (Min Severity)</label>
            <select v-model.number="syslogCfg.min_severity" class="w-full bg-white border border-slate-200 rounded-lg px-2.5 py-1 text-xs font-mono shadow-2xs">
              <option :value="3">3: Error 及以上</option>
              <option :value="4">4: Warning 及以上</option>
              <option :value="5">5: Notice 及以上</option>
              <option :value="6">6: Informational 及以上 (推荐)</option>
              <option :value="7">7: Debug (全部日志)</option>
            </select>
          </div>

          <div class="space-y-1 bg-slate-50/80 p-3 rounded-xl border border-slate-200/80">
            <label class="text-[11px] font-bold text-slate-700 block">应用标识名 (APP-NAME)</label>
            <input v-model="syslogCfg.app_name" placeholder="OmniProbe"
              class="w-full bg-white border border-slate-200 rounded-lg px-2.5 py-1 text-xs font-mono shadow-2xs">
          </div>
        </div>

        <!-- 联调测试控制台 -->
        <div class="bg-slate-50/80 p-3 rounded-xl border border-slate-200/80 space-y-2">
          <div class="text-[11px] font-bold text-slate-700 flex items-center justify-between">
            <span>RFC 5424 连通性测试与审计报文模拟</span>
            <span class="text-[10px] text-slate-400 font-mono">已外发审计报文总计: {{ syslogCfg.sent_count }} 条</span>
          </div>
          <div class="flex gap-2">
            <input v-model="syslogTestMsg" placeholder="输入测试审计报文内容..."
              class="flex-1 bg-white border border-slate-200 rounded-lg px-2.5 py-1.5 text-xs font-mono shadow-2xs">
            <button @click="testSendSyslog" :disabled="syslogTesting"
              class="bg-indigo-600 hover:bg-indigo-700 text-white text-xs px-4 py-1.5 rounded-xl font-bold cursor-pointer disabled:opacity-40 transition-all">
              <span v-if="syslogTesting">发送中...</span>
              <span v-else>立即发送测试报文</span>
            </button>
          </div>
          <div v-if="syslogTestResult" class="text-[11px] font-mono p-2 rounded bg-white border border-slate-200" :class="syslogTestResult.includes('失败') ? 'text-rose-600' : 'text-emerald-600'">
            {{ syslogTestResult }}
          </div>
        </div>
      </div>

      <!-- ============================================================ -->
      <!-- 选项卡 6：蜜罐主动防御 -->
      <!-- ============================================================ -->
      <div v-else-if="currentTab === 'honeypot'" class="h-full flex flex-col gap-3 overflow-hidden p-4">
        <div class="flex items-center justify-between border-b border-slate-200/50 pb-3 shrink-0 gap-3 flex-wrap">
          <div>
            <h3 class="text-xs font-bold text-slate-800">工业级轻量高熵诱捕蜜罐矩阵</h3>
            <p class="text-[11px] text-slate-400 mt-0.5">多端口低交互虚拟蜜罐，诱捕异常刺探并实时记录攻击载荷</p>
          </div>
          <div class="flex items-center gap-2 flex-wrap">
            <input v-model.number="newPort" type="number" min="1" max="65535" placeholder="端口如 1883"
              class="w-24 bg-white/80 border border-slate-200/80 rounded-xl px-2 py-1 text-xs font-mono shadow-2xs">
            <select v-model="newProto" class="bg-white/80 border border-slate-200/80 rounded-xl px-2 py-1 text-xs font-mono shadow-2xs">
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
            </select>
            <button @click="addPort" :disabled="!isValidNewPort"
              class="bg-indigo-600 hover:bg-indigo-700 text-white text-xs px-3 py-1 rounded-xl font-semibold cursor-pointer disabled:opacity-40 transition-all active:scale-95">
              添加监听
            </button>
            <button v-if="!honeypotRunning" @click="startHoneypot" :disabled="honeypotPorts.length === 0"
              class="bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-700 hover:to-teal-700 text-white text-xs px-3.5 py-1 rounded-xl font-semibold cursor-pointer disabled:opacity-40 shadow-sm transition-all active:scale-95">
              启动蜜罐
            </button>
            <button v-else @click="stopHoneypot"
              class="bg-rose-500/10 hover:bg-rose-500/20 text-rose-700 border border-rose-300/60 text-xs px-3.5 py-1 rounded-xl font-semibold cursor-pointer transition-all active:scale-95">
              停止蜜罐
            </button>
          </div>
        </div>

        <!-- 诱饵端口清单管理 -->
        <div class="shrink-0 flex items-center gap-1.5 flex-wrap text-xs">
          <span class="text-[11px] text-slate-500 font-semibold">诱饵端口矩阵 ({{ honeypotPorts.length }}):</span>
          <span v-for="(hp, idx) in honeypotPorts" :key="`${hp.port}-${hp.proto}`"
            class="px-2 py-0.5 rounded-lg bg-indigo-500/10 text-indigo-800 border border-indigo-300/60 text-[10px] font-bold font-mono flex items-center gap-1 shadow-2xs">
            :{{ hp.port }}/{{ hp.proto.toUpperCase()}}
            <button @click="removePort(idx)"
              class="w-3.5 h-3.5 rounded-full flex items-center justify-center text-indigo-400 hover:text-rose-600 hover:bg-rose-500/10 transition-colors cursor-pointer font-bold leading-none">✕</button>
          </span>
          <span v-if="honeypotPorts.length === 0" class="text-[10px] text-slate-400">尚未配置诱饵端口</span>
        </div>

        <div class="flex-1 overflow-auto custom-scrollbar">
          <table class="w-full text-left text-xs font-mono border-collapse">
            <thead class="bg-slate-100/70 border-b border-slate-200/60 text-[10px] font-bold text-slate-500 uppercase sticky top-0 z-10">
              <tr>
                <th class="p-2">时间戳</th>
                <th class="p-2">传输层</th>
                <th class="p-2">诱捕规约</th>
                <th class="p-2">源 IP (异常刺探)</th>
                <th class="p-2">目标蜜罐端口</th>
                <th class="p-2">载荷长度</th>
                <th class="p-2">Shannon 熵</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-100">
              <tr v-for="p in honeypotPackets" :key="p.id" class="hover:bg-white/70 transition-colors">
                <td class="p-2 text-slate-400">{{ p.timestamp }}</td>
                <td class="p-2"><span class="px-1.5 py-0.2 rounded bg-slate-100 font-bold text-[10px]">{{ p.transport }}</span></td>
                <td class="p-2 font-bold text-amber-700">{{ p.protocol }}</td>
                <td class="p-2 font-bold text-rose-700">{{ p.src_ip }}:{{ p.src_port }}</td>
                <td class="p-2 text-indigo-700 font-bold">:{{ p.dst_port }}</td>
                <td class="p-2">{{ p.length }}B</td>
                <td class="p-2 text-rose-600 font-bold">{{ p.entropy.toFixed(2) }}</td>
              </tr>
              <tr v-if="honeypotPackets.length === 0">
                <td colspan="7" class="p-12 text-center text-slate-400 text-xs">
                  暂无蜜罐触发事件，配置诱饵端口后点击【启动蜜罐】开始诱捕
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- ============================================================ -->
      <!-- 选项卡 7：系统运行日志 (受等保三级只读保护) -->
      <!-- ============================================================ -->
      <div v-else-if="currentTab === 'logs'" class="h-full flex flex-col gap-2.5 overflow-hidden p-4">
        <div class="flex items-center justify-between shrink-0">
          <span class="text-xs font-bold text-slate-700">内核与系统运行日志审计 ({{ systemLogs.length }} 行)</span>
          <div class="flex items-center gap-2">
            <span class="text-[10px] text-slate-400">受等保三级(8.1.4.4)保护: 仅安全审计员可处置日志</span>
            <button @click="handleClearLogs" class="text-slate-400 hover:text-rose-600 text-xs px-2 py-1 rounded cursor-pointer transition-colors">
              清空日志
            </button>
          </div>
        </div>
        <div class="flex-1 bg-slate-950 rounded-xl p-3 font-mono text-[11px] leading-relaxed text-emerald-400 overflow-auto custom-scrollbar select-all">
          <div v-for="(log, idx) in systemLogs" :key="idx" class="hover:bg-slate-900/80 px-1 rounded">
            {{ log }}
          </div>
          <div v-if="systemLogs.length === 0" class="text-slate-600 italic">
            暂无系统运行日志
          </div>
        </div>
      </div>

      <!-- ============================================================ -->
      <!-- 选项卡 8：引擎配置、Prometheus 指标与系统参数 -->
      <!-- ============================================================ -->
      <div v-else-if="currentTab === 'config'" class="h-full flex flex-col overflow-hidden">
        <div class="flex items-center justify-between px-4 py-2.5 border-b border-slate-200/50 bg-white/40 backdrop-blur-md shrink-0 gap-3 flex-wrap">
          <span class="text-xs font-bold text-slate-700">引擎配置、Prometheus 可观测性与系统参数</span>
          <div class="flex items-center gap-2">
            <button @click="loadConfig" :disabled="configLoading"
              class="bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs px-3 py-1 rounded-xl font-semibold cursor-pointer disabled:opacity-40 transition-all active:scale-95">
              <span v-if="configLoading" class="animate-spin">⏳ </span>重新加载
            </button>
            <button @click="saveConfig" :disabled="configSaving || !cfg"
              class="bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white text-xs px-3.5 py-1 rounded-xl font-bold cursor-pointer disabled:opacity-40 shadow-sm transition-all active:scale-95">
              <span v-if="configSaving" class="animate-spin">⏳ </span>保存并持久化
            </button>
          </div>
        </div>

        <div v-if="cfg" class="flex-1 overflow-auto custom-scrollbar p-4 space-y-4">
          <!-- Prometheus 监控指标服务状态 (等保三级 8.1.2.5 集中监控) -->
          <div class="bg-gradient-to-r from-slate-50 to-indigo-50/40 rounded-xl border border-indigo-100 p-3 flex items-center justify-between">
            <div class="flex items-center gap-3">
              <div class="w-8 h-8 rounded-xl bg-indigo-600 text-white flex items-center justify-center font-bold text-xs shadow-sm">
                P
              </div>
              <div>
                <div class="text-xs font-bold text-slate-800">Prometheus 工业监控指标服务 (RFC 集中监控)</div>
                <div class="text-[10px] text-slate-500 font-mono mt-0.5">
                  抓取端点: <span class="text-indigo-700 font-bold">http://127.0.0.1:{{ cfg.enterprise_features.fleet_management.enabled ? cfg.enterprise_features.fleet_management.api_port : 9091 }}/metrics</span>
                </div>
              </div>
            </div>
            <span class="px-2.5 py-1 rounded-full bg-emerald-100 text-emerald-800 text-[10px] font-bold">
              ✓ 服务运行中
            </span>
          </div>

          <!-- 运行时热更新区 -->
          <div class="bg-white/60 backdrop-blur-md rounded-xl border border-white/80 shadow-2xs p-3.5 space-y-3">
            <div class="text-[11px] font-bold text-slate-800 flex items-center gap-1.5">
              <span class="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
              运行时热更新 (立即生效，无需重启探针)
            </div>
            <div class="grid grid-cols-1 lg:grid-cols-3 gap-3">
              <div class="space-y-1.5 p-2.5 rounded-xl bg-slate-50/70 border border-slate-100">
                <div class="text-[10px] font-bold text-slate-500 uppercase">令牌桶防御限流</div>
                <div class="flex items-center gap-2">
                  <input v-model.number="throttleCapacity" type="number" min="1" max="1000" title="容量 (Capacity)"
                    class="w-16 bg-white/80 border border-slate-200/80 rounded-lg px-2 py-1 text-xs font-mono shadow-2xs">
                  <span class="text-[10px] text-slate-400">容量 /</span>
                  <input v-model.number="throttleFillRate" type="number" min="1" max="1000" title="填充速率 (Fill Rate /s)"
                    class="w-16 bg-white/80 border border-slate-200/80 rounded-lg px-2 py-1 text-xs font-mono shadow-2xs">
                  <span class="text-[10px] text-slate-400">每秒</span>
                </div>
                <button @click="applyThrottle"
                  class="w-full bg-emerald-600 hover:bg-emerald-700 text-white text-[11px] px-2 py-1 rounded-lg font-bold cursor-pointer transition-all active:scale-95">
                  热更新限流参数
                </button>
              </div>

              <div class="space-y-1.5 p-2.5 rounded-xl bg-slate-50/70 border border-slate-100">
                <div class="text-[10px] font-bold text-slate-500 uppercase flex items-center justify-between">
                  <span>云端流式上报</span>
                  <span class="flex items-center gap-1">
                    <span class="w-1.5 h-1.5 rounded-full" :class="cloudRunning ? 'bg-emerald-500 animate-pulse' : 'bg-slate-300'"></span>
                    <span :class="cloudRunning ? 'text-emerald-700 font-bold' : 'text-slate-400'">{{ cloudRunning ? '推送中' : '未启动' }}</span>
                  </span>
                </div>
                <input v-model="cloudWebhookUrl" placeholder="http://127.0.0.1:9090/ingest"
                  class="w-full bg-white/80 border border-slate-200/80 rounded-lg px-2 py-1 text-xs font-mono shadow-2xs">
                <div class="flex gap-1.5">
                  <button v-if="!cloudRunning" @click="startCloud"
                    class="flex-1 bg-blue-600 hover:bg-blue-700 text-white text-[11px] px-2 py-1 rounded-lg font-bold cursor-pointer transition-all active:scale-95">
                    启动推送
                  </button>
                  <button v-else @click="stopCloud"
                    class="flex-1 bg-rose-500/10 hover:bg-rose-500/20 text-rose-700 border border-rose-300/60 text-[11px] px-2 py-1 rounded-lg font-bold cursor-pointer transition-all active:scale-95">
                    停止推送
                  </button>
                </div>
              </div>

              <div class="space-y-1.5 p-2.5 rounded-xl bg-slate-50/70 border border-slate-100">
                <div class="text-[10px] font-bold text-slate-500 uppercase">DPI 动态字典热重载</div>
                <input v-model="dpiSigPath" placeholder="protocol_signatures.json"
                  class="w-full bg-white/80 border border-slate-200/80 rounded-lg px-2 py-1 text-xs font-mono shadow-2xs">
                <button @click="reloadDpi"
                  class="w-full bg-purple-600 hover:purple-700 text-white text-[11px] px-2 py-1 rounded-lg font-bold cursor-pointer transition-all active:scale-95">
                  重载规约字典
                </button>
              </div>
            </div>
          </div>

          <!-- 持久化配置区 -->
          <div class="bg-white/60 backdrop-blur-md rounded-xl border border-white/80 shadow-2xs p-3.5 space-y-3">
            <div class="text-[11px] font-bold text-slate-800 flex items-center gap-1.5">
              <span class="w-1.5 h-1.5 rounded-full bg-blue-500"></span>
              持久化配置 (保存后写入 config.json，部分配置项重启探针后生效)
            </div>

            <div class="grid grid-cols-2 lg:grid-cols-3 gap-3 text-xs">
              <div class="space-y-1">
                <label class="font-bold text-slate-600 block text-[11px]">TCP 组帧超时 (秒)</label>
                <input v-model.number="cfg.tcp_framing_timeout" type="number" step="0.01" min="0.01"
                  class="w-full bg-white/80 border border-slate-200/80 rounded-lg p-1.5 font-mono shadow-2xs">
              </div>
              <div class="space-y-1">
                <label class="font-bold text-slate-600 block text-[11px]">司法封条周期 (秒)</label>
                <input v-model.number="cfg.sealing_interval_secs" type="number" min="5"
                  class="w-full bg-white/80 border border-slate-200/80 rounded-lg p-1.5 font-mono shadow-2xs">
              </div>
              <div class="space-y-1">
                <label class="font-bold text-slate-600 block text-[11px]">日志级别</label>
                <select v-model="cfg.logging.level"
                  class="w-full bg-white/80 border border-slate-200/80 rounded-lg p-1.5 font-mono shadow-2xs">
                  <option value="DEBUG">DEBUG</option>
                  <option value="INFO">INFO</option>
                  <option value="WARN">WARN</option>
                  <option value="ERROR">ERROR</option>
                </select>
              </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-2 gap-3 text-xs">
              <div class="space-y-1.5 p-2.5 rounded-xl bg-slate-50/70 border border-slate-100">
                <div class="text-[10px] font-bold text-slate-500 uppercase">日志体系 (logging)</div>
                <input v-model="cfg.logging.file" placeholder="listener.log"
                  class="w-full bg-white/80 border border-slate-200/80 rounded-lg px-2 py-1 font-mono text-[11px] shadow-2xs">
              </div>
              <div class="space-y-1.5 p-2.5 rounded-xl bg-slate-50/70 border border-slate-100">
                <div class="text-[10px] font-bold text-slate-500 uppercase">数据落盘 (data_storage)</div>
                <div class="grid grid-cols-2 gap-2">
                  <input v-model="cfg.data_storage.file" placeholder="received_data.jsonl"
                    class="bg-white/80 border border-slate-200/80 rounded-lg px-2 py-1 font-mono text-[11px] shadow-2xs">
                  <input v-model="cfg.data_storage.pcap_file" placeholder="capture.pcap"
                    class="bg-white/80 border border-slate-200/80 rounded-lg px-2 py-1 font-mono text-[11px] shadow-2xs">
                </div>
                <label class="flex items-center gap-1.5 cursor-pointer text-[11px] text-slate-600">
                  <input type="checkbox" v-model="cfg.data_storage.enable_pcap" class="accent-blue-600">
                  <span class="font-semibold">启用 PCAP 全量落盘存证</span>
                </label>
              </div>
            </div>

            <!-- 企业特性 -->
            <div class="grid grid-cols-1 lg:grid-cols-3 gap-3 text-xs">
              <div class="space-y-1.5 p-2.5 rounded-xl bg-slate-50/70 border border-slate-100">
                <div class="text-[10px] font-bold text-slate-500 uppercase">舰队管理</div>
                <label class="flex items-center gap-1.5 cursor-pointer text-[11px] text-slate-600">
                  <input type="checkbox" v-model="cfg.enterprise_features.fleet_management.enabled" class="accent-blue-600">
                  <span class="font-semibold">启用</span>
                </label>
                <div class="flex items-center gap-1.5">
                  <span class="text-[10px] text-slate-400">API 端口:</span>
                  <input v-model.number="cfg.enterprise_features.fleet_management.api_port" type="number" min="1" max="65535"
                    class="w-20 bg-white/80 border border-slate-200/80 rounded-lg px-2 py-1 font-mono text-[11px] shadow-2xs">
                </div>
              </div>
              <div class="space-y-1.5 p-2.5 rounded-xl bg-slate-50/70 border border-slate-100">
                <div class="text-[10px] font-bold text-slate-500 uppercase">威胁防御</div>
                <label class="flex items-center gap-1.5 cursor-pointer text-[11px] text-slate-600">
                  <input type="checkbox" v-model="cfg.enterprise_features.threat_defense.enabled" class="accent-blue-600">
                  <span class="font-semibold">启用</span>
                </label>
                <div class="flex items-center gap-1.5">
                  <span class="text-[10px] text-slate-400">阈值 pps:</span>
                  <input v-model.number="cfg.enterprise_features.threat_defense.max_packets_per_sec" type="number" min="1" step="0.1"
                    class="w-20 bg-white/80 border border-slate-200/80 rounded-lg px-2 py-1 font-mono text-[11px] shadow-2xs">
                </div>
                <label class="flex items-center gap-1.5 cursor-pointer text-[11px] text-slate-600">
                  <input type="checkbox" v-model="cfg.enterprise_features.threat_defense.auto_drop_connection" class="accent-blue-600">
                  <span class="font-semibold">超限自动断连</span>
                </label>
              </div>
              <div class="space-y-1.5 p-2.5 rounded-xl bg-slate-50/70 border border-slate-100">
                <div class="text-[10px] font-bold text-slate-500 uppercase">云端上报</div>
                <label class="flex items-center gap-1.5 cursor-pointer text-[11px] text-slate-600">
                  <input type="checkbox" v-model="cfg.enterprise_features.cloud_streaming.enabled" class="accent-blue-600">
                  <span class="font-semibold">启用</span>
                </label>
                <input v-model="cfg.enterprise_features.cloud_streaming.webhook_url" placeholder="http://127.0.0.1:9090/ingest"
                  class="w-full bg-white/80 border border-slate-200/80 rounded-lg px-2 py-1 font-mono text-[11px] shadow-2xs">
              </div>
            </div>
          </div>
        </div>

        <div v-else class="flex-1 flex flex-col items-center justify-center text-slate-400 text-xs gap-2">
          <span v-if="configLoadError" class="text-rose-600 font-bold">{{ configLoadError }}</span>
          <span v-else>正在从 config.json 加载探针配置...</span>
          <button v-if="configLoadError" @click="loadConfig"
            class="px-3 py-1 rounded-xl bg-blue-600 hover:bg-blue-700 text-white font-bold cursor-pointer transition-all">重试加载</button>
        </div>
      </div>

    </div>

    <!-- 三员身份切换模态框 -->
    <div v-if="showRoleModal" class="fixed inset-0 bg-slate-900/40 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div class="bg-white rounded-2xl border border-slate-200 shadow-2xl p-5 max-w-sm w-full space-y-4">
        <div class="flex items-center justify-between border-b border-slate-100 pb-2.5">
          <h4 class="text-xs font-bold text-slate-800">等保三级 三员身份切换认证</h4>
          <button @click="showRoleModal = false" class="text-slate-400 hover:text-slate-600 font-bold text-xs cursor-pointer">✕</button>
        </div>

        <div class="space-y-3 text-xs">
          <div>
            <label class="block font-bold text-slate-600 mb-1">目标三员角色</label>
            <select v-model="targetRole" class="w-full bg-slate-50 border border-slate-200 rounded-xl p-2 font-semibold text-slate-800">
              <option value="SysAdmin">系统管理员 (SysAdmin - 初始口令: admin@123)</option>
              <option value="SecAdmin">安全管理员 (SecAdmin - 初始口令: sec@123)</option>
              <option value="AuditAdmin">安全审计员 (AuditAdmin - 初始口令: audit@123)</option>
            </select>
          </div>

          <div>
            <label class="block font-bold text-slate-600 mb-1">操作员授权口令</label>
            <input v-model="rolePassword" type="password" placeholder="请输入对应角色的口令"
              class="w-full bg-slate-50 border border-slate-200 rounded-xl p-2 font-mono">
          </div>

          <div v-if="roleSwitchError" class="text-rose-600 text-[11px] font-bold">
            {{ roleSwitchError }}
          </div>
        </div>

        <div class="flex justify-end gap-2 pt-2">
          <button @click="showRoleModal = false" class="px-3 py-1.5 rounded-xl text-xs text-slate-500 hover:bg-slate-100 font-semibold cursor-pointer">
            取消
          </button>
          <button @click="confirmSwitchRole" class="px-4 py-1.5 rounded-xl text-xs bg-blue-600 hover:bg-blue-700 text-white font-bold cursor-pointer shadow-sm">
            确认切换
          </button>
        </div>
      </div>
    </div>

    <!-- 司法证据链验真报告弹窗 -->
    <div v-if="showVerifyModal" class="fixed inset-0 bg-slate-900/40 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div class="bg-white rounded-2xl border border-slate-200 shadow-2xl p-5 max-w-2xl w-full space-y-4 max-h-[85vh] flex flex-col">
        <div class="flex items-center justify-between border-b border-slate-100 pb-2.5 shrink-0">
          <div class="flex items-center gap-2">
            <h4 class="text-xs font-bold text-slate-800">司法证据链完整性验真报告 (等保三级 8.1.4.4)</h4>
            <span :class="['px-2 py-0.5 rounded-full text-[10px] font-bold',
              verifyReport?.overall_status === 'PASS' ? 'bg-emerald-100 text-emerald-800' :
              (verifyReport?.overall_status === 'APPENDED' ? 'bg-blue-100 text-blue-800' : 'bg-rose-100 text-rose-800')]">
              {{ verifyReport?.overall_status === 'PASS' ? '✓ 完全匹配通过' :
                 (verifyReport?.overall_status === 'APPENDED' ? '✓ 正常追加存证' : '🚨 检测到可疑篡改') }}
            </span>
          </div>
          <button @click="showVerifyModal = false" class="text-slate-400 hover:text-slate-600 font-bold text-xs cursor-pointer">✕</button>
        </div>

        <div v-if="verifyReport" class="flex-1 overflow-y-auto custom-scrollbar space-y-3 text-xs font-mono">
          <div class="bg-slate-50 p-2.5 rounded-xl border border-slate-200 text-slate-600 space-y-1">
            <div>核验时间: <span class="font-bold text-slate-800">{{ verifyReport.verified_at }}</span></div>
            <div>最后封存时间: <span class="font-bold text-slate-800">{{ verifyReport.last_sealed_at }}</span> (触发原因: {{ verifyReport.last_seal_reason }})</div>
            <div>核验结论: <span class="font-bold text-indigo-700">{{ verifyReport.summary }}</span></div>
          </div>

          <div class="space-y-2">
            <div v-for="item in verifyReport.items" :key="item.file_name" class="p-2.5 rounded-xl border border-slate-200 bg-white space-y-1">
              <div class="flex items-center justify-between">
                <span class="font-bold text-slate-800 text-xs">{{ item.file_name }}</span>
                <span :class="['px-2 py-0.2 rounded font-bold text-[10px]',
                  item.status === 'MATCH' ? 'bg-emerald-100 text-emerald-800' :
                  (item.status === 'APPENDED' ? 'bg-blue-100 text-blue-800' : 'bg-rose-100 text-rose-800')]">
                  {{ item.status }}
                </span>
              </div>
              <div class="text-[10px] text-slate-500 break-all">
                <div>封存 SHA-256: <span class="text-slate-700">{{ item.expected_hash }}</span> ({{ item.sealed_size }} 字节)</div>
                <div>实测 SHA-256: <span class="text-slate-700">{{ item.current_hash }}</span> ({{ item.current_size }} 字节)</div>
              </div>
              <div class="text-[10px] text-slate-600 font-sans mt-0.5">{{ item.details }}</div>
            </div>
          </div>
        </div>

        <div class="flex justify-end pt-2 border-t border-slate-100 shrink-0">
          <button @click="showVerifyModal = false" class="px-4 py-1.5 rounded-xl text-xs bg-slate-900 text-white font-bold cursor-pointer hover:bg-slate-800 shadow-sm">
            关闭报告
          </button>
        </div>
      </div>
    </div>

    <!-- 修改操作口令模态框 (等保三级 8.1.1.1 复杂度强制) -->
    <div v-if="showChangePwdModal" class="fixed inset-0 bg-slate-900/40 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div class="bg-white rounded-2xl border border-slate-200 shadow-2xl p-5 max-w-sm w-full space-y-4">
        <div class="flex items-center justify-between border-b border-slate-100 pb-2.5">
          <h4 class="text-xs font-bold text-slate-800">修改操作员授权口令 (等保三级复杂度)</h4>
          <button @click="showChangePwdModal = false" class="text-slate-400 hover:text-slate-600 font-bold text-xs cursor-pointer">✕</button>
        </div>

        <div class="space-y-3 text-xs">
          <div>
            <label class="block font-bold text-slate-600 mb-1">目标角色</label>
            <div class="p-2 bg-slate-50 border border-slate-200 rounded-xl font-bold text-slate-800">
              {{ currentUser.role_title }}
            </div>
          </div>

          <div>
            <label class="block font-bold text-slate-600 mb-1">原授权口令</label>
            <input v-model="oldPassword" type="password" placeholder="请输入当前原口令"
              class="w-full bg-slate-50 border border-slate-200 rounded-xl p-2 font-mono">
          </div>

          <div>
            <label class="block font-bold text-slate-600 mb-1">新授权口令</label>
            <input v-model="newPassword" type="password" placeholder="至少8位，含大小写字母与数字"
              class="w-full bg-slate-50 border border-slate-200 rounded-xl p-2 font-mono">
          </div>

          <div v-if="changePwdError" class="text-rose-600 text-[11px] font-bold">
            {{ changePwdError }}
          </div>
          <div v-if="changePwdSuccess" class="text-emerald-600 text-[11px] font-bold">
            {{ changePwdSuccess }}
          </div>
        </div>

        <div class="flex justify-end gap-2 pt-2">
          <button @click="showChangePwdModal = false" class="px-3 py-1.5 rounded-xl text-xs text-slate-500 hover:bg-slate-100 font-semibold cursor-pointer">
            取消
          </button>
          <button @click="confirmChangePassword" class="px-4 py-1.5 rounded-xl text-xs bg-indigo-600 hover:bg-indigo-700 text-white font-bold cursor-pointer shadow-sm">
            确认修改并固化
          </button>
        </div>
      </div>
    </div>

  </div>
</template>

<script setup lang="ts">
import { notifySuccess, notifyWarning } from '../composables/useNotification';
import { ref, computed, onMounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';

interface CurrentUser {
  role: string;
  role_title: string;
  username: string;
  login_time: string;
  permissions: string[];
}

interface AdminAuditRecord {
  id: number;
  timestamp: string;
  operator: string;
  role: string;
  action: string;
  details: string;
  status: string;
}

interface BaselineStatus {
  mode: string;
  total_rules: number;
  drift_events_count: number;
  learning_started_at: string;
}

interface BaselineRule {
  id: string;
  src_ip: string;
  dst_ip: string;
  protocol: string;
  dst_port: number;
  action_type: string;
  first_learned: string;
  last_seen: string;
  hit_count: number;
}

interface BaselineDriftEvent {
  id: number;
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  protocol: string;
  dst_port: number;
  drift_type: string;
  description: string;
  severity: string;
}

interface CidrAssetRule {
  cidr: string;
  zone_name: string;
  security_level: string;
  description: string;
}

interface SyslogConfig {
  enabled: boolean;
  server_ip: string;
  server_port: number;
  protocol: string;
  facility: number;
  min_severity: number;
  app_name: string;
  sent_count: number;
}

interface HoneypotRecord {
  id: number;
  timestamp: string;
  transport: string;
  protocol: string;
  src_ip: string;
  dst_port: number;
  src_port: number;
  length: number;
  entropy: number;
}

interface FileIntegrityResult {
  file_name: string;
  expected_hash: string;
  current_hash: string;
  sealed_size: number;
  current_size: number;
  status: string;
  details: string;
}

interface EvidenceVerificationReport {
  verified_at: string;
  last_sealed_at: string;
  last_seal_reason: string;
  overall_status: string;
  seal_file_exists: boolean;
  items: FileIntegrityResult[];
  summary: string;
}

defineProps<{
  systemLogs: string[];
  honeypotPackets: HoneypotRecord[];
}>();

const emit = defineEmits(['clearLogs', 'appendLog']);

function log(msg: string) {
  emit('appendLog', msg);
}

// 8 大子选项卡 (等保 2/3 全量覆盖)
const subTabs = [
  { id: 'compliance', label: '等保合规大屏' },
  { id: 'rbac', label: '三员分立控制' },
  { id: 'baseline', label: '工业基线白名单' },
  { id: 'zones', label: '安全区域(CIDR)' },
  { id: 'syslog', label: 'Syslog 集中外发' },
  { id: 'honeypot', label: '蜜罐主动防御' },
  { id: 'logs', label: '运行日志审计' },
  { id: 'config', label: '引擎配置参数' },
];
const currentTab = ref('compliance');

function changeTab(tabId: string) {
  currentTab.value = tabId;
  if (tabId === 'rbac') {
    loadCurrentUser();
    loadAdminAuditTrail();
  } else if (tabId === 'baseline') {
    loadBaselineStatus();
    loadBaselineRules();
    loadBaselineDriftEvents();
  } else if (tabId === 'zones') {
    loadCidrRules();
  } else if (tabId === 'syslog') {
    loadSyslogConfig();
  }
}

// ============================================================
// 1. 等保测评矩阵数据 (对齐 GB/T 22239-2019 标准条款)
// ============================================================
const complianceItems = [
  {
    clause: '8.1.1.1 身份鉴别',
    level: '二级/三级',
    levelBadge: 'bg-blue-100 text-blue-800',
    requirement: '应对登录用户进行身份标识和鉴别，口令复杂度校验',
    implementation: '三员分立独立口令校验与密码复杂度要求',
    status: '已符合',
    statusBadge: 'bg-emerald-100 text-emerald-800',
  },
  {
    clause: '8.1.2.1 结构安全与区域划分',
    level: '等保三级',
    levelBadge: 'bg-indigo-100 text-indigo-800',
    requirement: '应保证网络架构的业务逻辑合理划分，生产控制、非控制与管理大区隔离',
    implementation: 'CIDR 安全区域划分引擎与最长前缀掩码位运算隔离规则',
    status: '已符合',
    statusBadge: 'bg-emerald-100 text-emerald-800',
  },
  {
    clause: '8.1.2.2 边界访问控制',
    level: '等保三级',
    levelBadge: 'bg-indigo-100 text-indigo-800',
    requirement: '应在网络边界部署访问控制策略，限制非授权跨域通信',
    implementation: '通信基线与安全域白名单联动，自动拦截跨域越权违规',
    status: '已符合',
    statusBadge: 'bg-emerald-100 text-emerald-800',
  },
  {
    clause: '8.1.4.1 三员分立访问控制',
    level: '等保三级',
    levelBadge: 'bg-indigo-100 text-indigo-800',
    requirement: '重构管理员权限，实现系统管理员、安全管理员、安全审计员权限隔离',
    implementation: 'RBAC 模块严格实现三员权限正交隔离与切换口令认证',
    status: '已符合',
    statusBadge: 'bg-emerald-100 text-emerald-800',
  },
  {
    clause: '8.1.4.3 集中式日志备份',
    level: '等保三级',
    levelBadge: 'bg-indigo-100 text-indigo-800',
    requirement: '应将所有审计记录集中备份至独立的日志服务器或 SIEM',
    implementation: '标准 RFC 5424 Syslog UDP/TCP 集中异步外发引擎',
    status: '已符合',
    statusBadge: 'bg-emerald-100 text-emerald-800',
  },
  {
    clause: '8.1.4.4 审计记录保护与验真',
    level: '等保三级',
    levelBadge: 'bg-indigo-100 text-indigo-800',
    requirement: '定期对审计记录进行安全备份与司法验真，禁止非审计员处置日志',
    implementation: 'SHA-256 司法证据链周期封条 + 按需实测哈希比对验真引擎',
    status: '已符合',
    statusBadge: 'bg-emerald-100 text-emerald-800',
  },
  {
    clause: 'G.4.2 工业通信访问控制',
    level: '工控三级扩展',
    levelBadge: 'bg-purple-100 text-purple-800',
    requirement: '在工业控制网络建立通信基线白名单，实时检测非法连接与跨域访问',
    implementation: 'BaselineLearning 引擎支持自动收敛通信对与严格审计模式',
    status: '已符合',
    statusBadge: 'bg-emerald-100 text-emerald-800',
  },
  {
    clause: 'G.4.3 工控功能码与指令审计',
    level: '工控三级扩展',
    levelBadge: 'bg-purple-100 text-purple-800',
    requirement: '对工业控制协议高危写指令（如写寄存器、下装程序）进行功能码级检测',
    implementation: 'DPI 引擎对 Modbus/IEC104 功能码细分 (FC 0x05/0x06/0x10 写指令审计)',
    status: '已符合',
    statusBadge: 'bg-emerald-100 text-emerald-800',
  },
  {
    clause: '9.1.4.1 硬件级可信根与抗量子',
    level: '等保四级',
    levelBadge: 'bg-amber-100 text-amber-800',
    requirement: '要求采用国家密码管理局认证的硬件安全密码机 (HSM) 与物理可信计算芯片',
    implementation: '当前采用软件级国密/SHA256哈希算法，待接入 PCIe HSM 硬件卡',
    status: '部分符合',
    statusBadge: 'bg-amber-100 text-amber-800',
  }
];

// ============================================================
// 2. 三员分立 (RBAC) 状态与操作
// ============================================================
const currentUser = ref<CurrentUser>({
  role: 'SecAdmin',
  role_title: '安全管理员 (SecAdmin)',
  username: 'sec_admin',
  login_time: '',
  permissions: [],
});

const adminAuditTrail = ref<AdminAuditRecord[]>([]);
const showRoleModal = ref(false);
const targetRole = ref('SecAdmin');
const rolePassword = ref('');
const roleSwitchError = ref('');

const roleBadgeColor = computed(() => {
  switch (currentUser.value.role) {
    case 'SysAdmin': return 'text-indigo-700';
    case 'SecAdmin': return 'text-emerald-700';
    case 'AuditAdmin': return 'text-purple-700';
    default: return 'text-slate-700';
  }
});

async function loadCurrentUser() {
  try {
    currentUser.value = await invoke<CurrentUser>('get_current_user_cmd');
  } catch (e) {
    log(`[ERROR] 获取当前操作员信息失败: ${e}`);
  }
}

async function loadAdminAuditTrail() {
  try {
    adminAuditTrail.value = await invoke<AdminAuditRecord[]>('get_admin_audit_trail_cmd');
  } catch (e) {
    log(`[ERROR] 获取管理员审计流失败: ${e}`);
  }
}

function openSwitchRoleModal() {
  targetRole.value = currentUser.value.role;
  rolePassword.value = '';
  roleSwitchError.value = '';
  showRoleModal.value = true;
}

async function confirmSwitchRole() {
  if (!rolePassword.value.trim()) {
    roleSwitchError.value = '请输入授权口令';
    return;
  }
  try {
    const updated = await invoke<CurrentUser>('switch_user_role_cmd', {
      targetRole: targetRole.value,
      password: rolePassword.value.trim(),
    });
    currentUser.value = updated;
    showRoleModal.value = false;
    log(`[RBAC] 成功切换身份为: ${updated.role_title}`);
    loadAdminAuditTrail();
  } catch (e) {
    roleSwitchError.value = String(e);
    log(`[RBAC] 身份切换被拦截: ${e}`);
  }
}

const showChangePwdModal = ref(false);
const oldPassword = ref('');
const newPassword = ref('');
const changePwdError = ref('');
const changePwdSuccess = ref('');

function openChangePwdModal() {
  oldPassword.value = '';
  newPassword.value = '';
  changePwdError.value = '';
  changePwdSuccess.value = '';
  showChangePwdModal.value = true;
}

async function confirmChangePassword() {
  changePwdError.value = '';
  changePwdSuccess.value = '';
  if (!oldPassword.value.trim() || !newPassword.value.trim()) {
    changePwdError.value = '原口令与新口令均不能为空';
    return;
  }
  try {
    const res = await invoke<string>('change_role_password_cmd', {
      targetRole: currentUser.value.role,
      oldPassword: oldPassword.value.trim(),
      newPassword: newPassword.value.trim(),
    });
    changePwdSuccess.value = res;
    log(`[RBAC] ${res}`);
    loadAdminAuditTrail();
    setTimeout(() => {
      showChangePwdModal.value = false;
    }, 1500);
  } catch (e) {
    changePwdError.value = String(e);
    log(`[RBAC] 修改口令失败: ${e}`);
  }
}

async function handleClearLogs() {
  try {
    await invoke('clear_logs');
    emit('clearLogs');
    log('[AUDIT] 安全审计员已合规清空运行日志');
    loadAdminAuditTrail();
  } catch (e) {
    log(`[SECURITY-BLOCK] ${e}`);
    notifyWarning('等保三级安全合规拦截', `${e}。如需处置审计日志，请先在顶部点击【切换身份】切换至安全审计员 (AuditAdmin，口令 audit@123)。`);
    loadAdminAuditTrail();
  }
}

// ============================================================
// 3. 司法证据链手动封存与验真 (8.1.4.4)
// ============================================================
const sealing = ref(false);
const verifying = ref(false);
const showVerifyModal = ref(false);
const verifyReport = ref<EvidenceVerificationReport | null>(null);

async function manualSeal() {
  if (sealing.value) return;
  sealing.value = true;
  try {
    const res = await invoke<string>('manual_seal_cmd');
    log(res);
    loadAdminAuditTrail();
  } catch (e) {
    log(`[ERROR] 手动封存失败: ${e}`);
  } finally {
    sealing.value = false;
  }
}

async function verifyEvidenceChain() {
  if (verifying.value) return;
  verifying.value = true;
  try {
    const rep = await invoke<EvidenceVerificationReport>('verify_evidence_chain_cmd');
    verifyReport.value = rep;
    showVerifyModal.value = true;
    log(`[FORENSICS] 司法证据链验真完成: ${rep.overall_status} - ${rep.summary}`);
    loadAdminAuditTrail();
  } catch (e) {
    log(`[ERROR] 证据链验真失败: ${e}`);
  } finally {
    verifying.value = false;
  }
}

// ============================================================
// 4. 安全区域划分与 CIDR 网段规则 (8.1.2.1/8.1.2.2)
// ============================================================
const cidrRules = ref<CidrAssetRule[]>([]);
const newCidr = ref('');
const newZoneName = ref('');
const newSecLevel = ref('核心生产');
const newDescription = ref('');

async function loadCidrRules() {
  try {
    cidrRules.value = await invoke<CidrAssetRule[]>('get_cidr_rules_cmd');
    log(`[ZONE] 已加载 ${cidrRules.value.length} 条 CIDR 安全区域规则`);
  } catch (e) {
    log(`[ERROR] 加载 CIDR 规则失败: ${e}`);
  }
}

function addCidrRule() {
  if (!newCidr.value.trim() || !newZoneName.value.trim()) {
    notifyWarning('输入校验未通过', '网段 CIDR 与安全区域名称不能为空，请填写后再添加');
    return;
  }
  cidrRules.value.push({
    cidr: newCidr.value.trim(),
    zone_name: newZoneName.value.trim(),
    security_level: newSecLevel.value,
    description: newDescription.value.trim() || '自定义安全域划分',
  });
  newCidr.value = '';
  newZoneName.value = '';
  newDescription.value = '';
}

function removeCidrRule(idx: number) {
  cidrRules.value.splice(idx, 1);
}

async function saveCidrRules() {
  try {
    const count = await invoke<number>('save_cidr_rules_cmd', { rules: cidrRules.value });
    log(`[ZONE] 成功保存并生效 ${count} 条 CIDR 安全区域规则`);
    loadAdminAuditTrail();
  } catch (e) {
    log(`[ERROR] 保存 CIDR 规则失败: ${e}`);
  }
}

// ============================================================
// 5. 工业通信基线白名单自学习与漂移检测
// ============================================================
const baselineStatus = ref<BaselineStatus>({
  mode: 'LEARNING',
  total_rules: 0,
  drift_events_count: 0,
  learning_started_at: '',
});
const baselineRules = ref<BaselineRule[]>([]);
const baselineDriftEvents = ref<BaselineDriftEvent[]>([]);

async function loadBaselineStatus() {
  try {
    baselineStatus.value = await invoke<BaselineStatus>('get_baseline_status_cmd');
  } catch (e) {
    log(`[ERROR] 获取基线状态失败: ${e}`);
  }
}

async function loadBaselineRules() {
  try {
    baselineRules.value = await invoke<BaselineRule[]>('get_baseline_rules_cmd');
  } catch (e) {
    log(`[ERROR] 获取基线白名单失败: ${e}`);
  }
}

async function loadBaselineDriftEvents() {
  try {
    baselineDriftEvents.value = await invoke<BaselineDriftEvent[]>('get_baseline_drift_events_cmd');
  } catch (e) {
    log(`[ERROR] 获取基线漂移事件失败: ${e}`);
  }
}

async function changeBaselineMode(mode: string) {
  try {
    await invoke('set_baseline_mode_cmd', { mode });
    baselineStatus.value.mode = mode;
    log(`[BASELINE] 已将工业通信基线工作模式切换为: ${mode}`);
    loadBaselineStatus();
    loadAdminAuditTrail();
  } catch (e) {
    log(`[ERROR] 切换基线模式失败: ${e}`);
  }
}

async function persistBaseline() {
  try {
    const count = await invoke<number>('persist_baseline_rules_cmd');
    log(`[BASELINE] 成功将 ${count} 条通信基线规则固化持久化至磁盘 (baseline_rules.json)`);
    notifySuccess('通信基线规则已固化', `成功将 ${count} 条通信基线规则固化持久化至磁盘，系统重启后将自动加载恢复`);
    loadAdminAuditTrail();
  } catch (e) {
    log(`[ERROR] 固化基线失败: ${e}`);
  }
}

async function resetBaselineRules() {
  if (!confirm('确认重置所有已学习的工业通信基线白名单与漂移事件吗？此操作将记录管理员审计流。')) {
    return;
  }
  try {
    await invoke('clear_baseline_rules_cmd');
    log('[BASELINE] 已清空通信白名单规则与漂移事件');
    loadBaselineStatus();
    loadBaselineRules();
    loadBaselineDriftEvents();
    loadAdminAuditTrail();
  } catch (e) {
    log(`[ERROR] 重置基线失败: ${e}`);
  }
}

// ============================================================
// 6. RFC 5424 Syslog 集中外发管理
// ============================================================
const syslogCfg = ref<SyslogConfig>({
  enabled: false,
  server_ip: '127.0.0.1',
  server_port: 514,
  protocol: 'UDP',
  facility: 16,
  min_severity: 6,
  app_name: 'OmniProbe',
  sent_count: 0,
});
const syslogTestMsg = ref('Omni-Probe 工业全能探针 RFC 5424 集中审计联调测试');
const syslogTesting = ref(false);
const syslogTestResult = ref('');

async function loadSyslogConfig() {
  try {
    syslogCfg.value = await invoke<SyslogConfig>('get_syslog_config_cmd');
  } catch (e) {
    log(`[ERROR] 加载 Syslog 配置失败: ${e}`);
  }
}

async function saveSyslogConfig() {
  try {
    const res = await invoke<string>('save_syslog_config_cmd', { config: syslogCfg.value });
    log(`[SYSLOG] ${res}`);
    loadAdminAuditTrail();
  } catch (e) {
    log(`[ERROR] 保存 Syslog 配置失败: ${e}`);
  }
}

async function testSendSyslog() {
  if (!syslogTestMsg.value.trim()) return;
  syslogTesting.value = true;
  syslogTestResult.value = '';
  try {
    const res = await invoke<string>('test_send_syslog_cmd', { message: syslogTestMsg.value.trim() });
    syslogTestResult.value = `✓ 发送成功: ${res}`;
    log(`[SYSLOG] ${res}`);
    loadSyslogConfig();
  } catch (e) {
    syslogTestResult.value = `✕ 发送失败: ${e}`;
    log(`[ERROR] Syslog 测试失败: ${e}`);
  } finally {
    syslogTesting.value = false;
  }
}

// ============================================================
// 7. 蜜罐主动防御管理
// ============================================================
const newPort = ref(1883);
const newProto = ref('tcp');
const honeypotRunning = ref(false);
const honeypotPorts = ref<Array<{ port: number; proto: string }>>([
  { port: 1883, proto: 'tcp' },
  { port: 502, proto: 'tcp' },
]);

const isValidNewPort = computed(() =>
  Number.isInteger(newPort.value) && newPort.value >= 1 && newPort.value <= 65535
);

function addPort() {
  if (!isValidNewPort.value) {
    log('[HONEYPOT] 无效端口：请输入 1-65535 范围内的整数端口');
    return;
  }
  if (honeypotPorts.value.some(hp => hp.port === newPort.value && hp.proto === newProto.value)) {
    log(`[HONEYPOT] 诱饵端口 :${newPort.value}/${newProto.value.toUpperCase()} 已存在于矩阵中`);
    return;
  }
  honeypotPorts.value.push({ port: newPort.value, proto: newProto.value });
}

function removePort(idx: number) {
  honeypotPorts.value.splice(idx, 1);
}

async function startHoneypot() {
  try {
    const res = await invoke<string>('start_honeypot_cmd', {
      ports: honeypotPorts.value.map(hp => ({ port: hp.port, proto: hp.proto }))
    });
    honeypotRunning.value = true;
    log(res);
  } catch (e) {
    log(`[ERROR] 蜜罐启动失败: ${e}`);
  }
}

async function stopHoneypot() {
  try {
    const res = await invoke<string>('stop_honeypot_cmd');
    honeypotRunning.value = false;
    log(res);
  } catch (e) {
    log(`[ERROR] 蜜罐停止失败: ${e}`);
  }
}

// ============================================================
// 8. config.json 读写体系
// ============================================================
interface ServerEntry { host: string; port: number; protocol: string; }
interface ActiveProbeEntry { host: string; port: number; protocol: string; reconnect_interval: number; }
interface SerialProbeEntry { port: string; baud_rate: number; }
interface LoggingConfig { level: string; file: string; }
interface DataStorageConfig { mode: string; file: string; pcap_file: string; enable_pcap: boolean; }
interface EnterpriseFeatures {
  fleet_management: { enabled: boolean; api_port: number };
  threat_defense: { enabled: boolean; max_packets_per_sec: number; auto_drop_connection: boolean };
  cloud_streaming: { enabled: boolean; webhook_url: string };
}
interface ProbeConfig {
  servers: ServerEntry[];
  active_probes: ActiveProbeEntry[];
  serial_probes: SerialProbeEntry[];
  logging: LoggingConfig;
  data_storage: DataStorageConfig;
  tcp_framing_timeout: number;
  sealing_interval_secs: number;
  enterprise_features: EnterpriseFeatures;
}

const cfg = ref<ProbeConfig | null>(null);
const configLoading = ref(false);
const configSaving = ref(false);
const configLoadError = ref('');
const throttleCapacity = ref(50);
const throttleFillRate = ref(50);
const cloudRunning = ref(false);
const cloudWebhookUrl = ref('');
const dpiSigPath = ref('protocol_signatures.json');

async function loadConfig() {
  configLoading.value = true;
  configLoadError.value = '';
  try {
    const loaded = await invoke<ProbeConfig>('get_config_cmd');
    cfg.value = loaded;
    throttleCapacity.value = 50;
    throttleFillRate.value = 50;
    cloudWebhookUrl.value = loaded.enterprise_features.cloud_streaming.webhook_url || '';
    log('[CONFIG] 已从 config.json 加载探针配置');
  } catch (e) {
    configLoadError.value = `配置加载失败: ${e}`;
    log(`[ERROR] 配置加载失败: ${e}`);
  } finally {
    configLoading.value = false;
  }
}

async function saveConfig() {
  if (!cfg.value) return;
  configSaving.value = true;
  try {
    const res = await invoke<string>('save_config_cmd', { cfg: cfg.value });
    log(res);
  } catch (e) {
    log(`[ERROR] 配置保存失败: ${e}`);
  } finally {
    configSaving.value = false;
  }
}

async function applyThrottle() {
  try {
    const res = await invoke<string>('update_throttle_config_cmd', {
      capacity: Number(throttleCapacity.value),
      fillRate: Number(throttleFillRate.value)
    });
    log(res);
  } catch (e) {
    log(`[ERROR] 限流参数热更新失败: ${e}`);
  }
}

async function startCloud() {
  if (!cloudWebhookUrl.value.trim()) {
    log('[CLOUD] 启动失败: Webhook URL 不能为空');
    return;
  }
  try {
    const res = await invoke<string>('start_cloud_streaming_cmd', { webhookUrl: cloudWebhookUrl.value.trim() });
    cloudRunning.value = true;
    log(res);
  } catch (e) {
    log(`[ERROR] 云端推送启动失败: ${e}`);
  }
}

async function stopCloud() {
  try {
    const res = await invoke<string>('stop_cloud_streaming_cmd');
    cloudRunning.value = false;
    log(res);
  } catch (e) {
    log(`[ERROR] 云端推送停止失败: ${e}`);
  }
}

async function reloadDpi() {
  try {
    const res = await invoke<string>('reload_dpi_signatures_cmd', {
      path: dpiSigPath.value.trim() || null
    });
    log(res);
  } catch (e) {
    log(`[ERROR] DPI 字典重载失败: ${e}`);
  }
}

onMounted(() => {
  loadConfig();
  loadCurrentUser();
  loadBaselineStatus();
  loadCidrRules();
  loadSyslogConfig();
});
</script>
