<template>
  <div class="flex-1 flex flex-col gap-2.5 overflow-hidden min-w-0">
    <!-- 顶部状态栏 (真 Liquid Glass 控制层) -->
    <div class="ui-nav-glass rounded-2xl px-4 py-2.5 flex items-center justify-between shrink-0 gap-3 flex-wrap">
      <span class="lens-edge-lip" aria-hidden="true"></span>
      <div class="flex items-center gap-3 flex-wrap">
        <h2 class="text-[13px] font-semibold flex items-center gap-2 whitespace-nowrap" style="color: var(--text-primary);">
          <AppIcon name="shield" :size="15" class="text-[var(--accent-primary)] shrink-0" />
          <span>安全审计与等保合规引擎</span>
        </h2>
        <div class="h-4 w-[1px]" style="background: var(--border-strong);"></div>

        <!-- 当前三员分立身份标签与切换按钮 -->
        <div class="ui-pill rounded-xl flex items-center gap-2 px-2.5 py-1 text-xs whitespace-nowrap">
          <span style="color: var(--text-muted);">操作员:</span>
          <span class="font-semibold ui-num" :class="roleBadgeColor">{{ currentUser.role_title }}</span>
          <button
            @click="openSwitchRoleModal"
            class="text-[11px] text-[var(--accent-primary-text)] hover:underline font-semibold cursor-pointer ml-1"
          >
            切换身份
          </button>
          <button
            @click="openChangePwdModal"
            class="text-[11px] text-[var(--text-secondary)] hover:underline font-medium cursor-pointer ml-0.5"
          >
            改口令
          </button>
        </div>

        <!-- 司法存证双核操作 -->
        <div class="flex items-center gap-1.5">
          <button @click="manualSeal" :disabled="sealing" class="ui-btn-secondary px-2.5 py-1 text-xs">
            <AppIcon v-if="sealing" name="refresh" :size="13" class="animate-spin" />
            <AppIcon v-else name="lock" :size="13" />
            <span>司法封存</span>
          </button>

          <button @click="verifyEvidenceChain" :disabled="verifying" class="ui-btn-secondary px-2.5 py-1 text-xs">
            <AppIcon v-if="verifying" name="refresh" :size="13" class="animate-spin" />
            <AppIcon v-else name="shield" :size="13" />
            <span>链路验真</span>
          </button>
        </div>
      </div>

      <!-- 选项卡切换 (统一 Apple 主选中胶囊) -->
      <div class="glass-pill p-1 rounded-xl text-xs font-medium flex flex-wrap gap-0.5">
        <button
          v-for="tab in subTabs"
          :key="tab.id"
          @click="changeTab(tab.id)"
          :class="['px-2.5 py-1 rounded-lg transition-all cursor-pointer text-[11px] whitespace-nowrap',
            currentTab === tab.id ? 'bg-[var(--accent-primary)] text-white shadow-xs font-semibold' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]']"
        >
          {{ tab.label }}
        </button>
      </div>
    </div>

    <!-- 主体内容容器 (稳态实体衬底) -->
    <div class="flex-1 ui-content-card overflow-hidden flex flex-col select-text">

      <!-- ============================================================ -->
      <!-- 选项卡 1：等保 2.0 / 3.0 合规态势驾驶舱 -->
      <!-- ============================================================ -->
      <div v-if="currentTab === 'compliance'" class="h-full flex flex-col gap-3 overflow-y-auto custom-scrollbar p-4">
        <div class="flex items-center justify-between border-b pb-3 shrink-0 flex-wrap gap-2" style="border-color: var(--border-subtle);">
          <div>
            <h3 class="text-[13px] font-semibold" style="color: var(--text-primary);">网络安全等级保护 2.0 / 3.0 (GB/T 22239-2019) 合规态势面板</h3>
            <p class="text-[11px] mt-0.5" style="color: var(--text-muted);">工控扩展指标、三员分立正交控制、基线漂移阻击与集中式日志存证差距分析</p>
          </div>
          <div class="text-right text-[11px] ui-num" style="color: var(--text-muted);">
            基准标准：GB/T 22239-2019 / GB/T 28448-2019
          </div>
        </div>

        <!-- 等保等级符合度实测指标卡片 -->
        <div class="grid grid-cols-1 md:grid-cols-3 gap-3 shrink-0">
          <div class="bg-emerald-500/8 p-3.5 rounded-xl border border-emerald-500/25">
            <div class="flex items-center justify-between">
              <span class="text-xs font-semibold text-emerald-700 dark:text-emerald-300">等保二级 (Level 2 · 运行实测)</span>
              <span class="px-2 py-0.5 rounded-full bg-emerald-600 text-white ui-num font-semibold text-[11px]">{{ level2ComplianceRate }}% 就绪</span>
            </div>
            <div class="w-full bg-emerald-500/20 rounded-full h-1.5 mt-2.5 overflow-hidden">
              <div class="bg-emerald-600 h-1.5 rounded-full transition-all" :style="{ width: level2ComplianceRate + '%' }"></div>
            </div>
            <p class="text-[11px] text-emerald-700 dark:text-emerald-300 mt-2 ui-num">
              基于当前已配置项 ({{ satisfiedCount }}/{{ totalAuditCount }} 项核心控制点已激活)
            </p>
          </div>

          <div class="bg-blue-500/8 p-3.5 rounded-xl border border-blue-500/25">
            <div class="flex items-center justify-between">
              <span class="text-xs font-semibold text-blue-700 dark:text-sky-300">等保三级 (Level 3 · 运行实测)</span>
              <span class="px-2 py-0.5 rounded-full bg-blue-600 text-white ui-num font-semibold text-[11px]">{{ level3ComplianceRate }}% 就绪</span>
            </div>
            <div class="w-full bg-blue-500/20 rounded-full h-1.5 mt-2.5 overflow-hidden">
              <div class="bg-blue-600 h-1.5 rounded-full transition-all" :style="{ width: level3ComplianceRate + '%' }"></div>
            </div>
            <p class="text-[11px] text-blue-700 dark:text-sky-300 mt-2 ui-num">
              {{ syslogCfg.enabled ? 'Syslog 已启用' : 'Syslog 未启用' }} · CIDR {{ cidrRules.length }} 条 · 基线 {{ baselineRules.length }} 条
            </p>
          </div>

          <div class="bg-amber-500/8 p-3.5 rounded-xl border border-amber-500/25">
            <div class="flex items-center justify-between">
              <span class="text-xs font-semibold" style="color: var(--text-primary);">等保四级 (Level 4 · 硬件可信根)</span>
              <span class="px-2 py-0.5 rounded-full bg-amber-600 text-white ui-num font-semibold text-[11px]">
                {{ hasHsmHardware ? `${level4ComplianceRate}% 就绪` : `${level4ComplianceRate}% · 无物理 HSM` }}
              </span>
            </div>
            <div class="w-full bg-amber-500/20 rounded-full h-1.5 mt-2.5 overflow-hidden">
              <div class="bg-amber-500 h-1.5 rounded-full transition-all" :style="{ width: level4ComplianceRate + '%' }"></div>
            </div>
            <p class="text-[11px] mt-2" style="color: var(--text-secondary);">
              {{ hasHsmHardware ? '已接入认证级物理 HSM 硬件密码卡' : '当前仅启用软件 SM3 + SHA-256 + PBKDF2 摘要，硬件 HSM 未接入' }}
            </p>
          </div>
        </div>

        <!-- 详细测评项检查矩阵表格 -->
        <div class="flex-1 overflow-auto custom-scrollbar border rounded-xl" style="border-color: var(--border-subtle); background: var(--surface-content-alt);">
          <table class="w-full text-left text-xs border-collapse">
            <thead class="ui-table-head sticky top-0 z-10 select-none">
              <tr>
                <th class="p-2.5">测评项标准条款</th>
                <th class="p-2.5 whitespace-nowrap w-32">对应等保等级</th>
                <th class="p-2.5">安全控制要求</th>
                <th class="p-2.5">探针系统实现程度</th>
                <th class="p-2.5 text-center whitespace-nowrap">符合状态</th>
                <th class="p-2.5 text-center whitespace-nowrap w-20">比对</th>
              </tr>
            </thead>
            <tbody class="divide-y" style="border-color: var(--border-subtle);">
              <tr v-for="(item, idx) in complianceItems" :key="idx" class="hover:bg-[var(--surface-hover)] transition-colors">
                <td class="p-2.5 font-semibold" style="color: var(--text-primary);">{{ item.clause }}</td>
                <td class="p-2.5 whitespace-nowrap">
                  <span class="px-2 py-0.5 rounded-md font-semibold text-[11px] whitespace-nowrap inline-block" :class="item.levelBadge">{{ item.level }}</span>
                </td>
                <td class="p-2.5" style="color: var(--text-secondary);">{{ item.requirement }}</td>
                <td class="p-2.5" style="color: var(--text-primary);">{{ item.implementation }}</td>
                <td class="p-2.5 text-center whitespace-nowrap">
                  <span class="px-2 py-0.5 rounded-full font-semibold text-[11px] whitespace-nowrap inline-block" :class="item.statusBadge">
                    {{ item.status }}
                  </span>
                </td>
                <td class="p-2.5 text-center whitespace-nowrap">
                  <button @click="addComplianceToDiffQueue(item)" class="px-2 py-0.5 rounded-lg bg-emerald-500/12 hover:bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border border-emerald-500/25 text-[11px] font-semibold cursor-pointer" title="加入多组基线条款比对队列">
                    + 入队
                  </button>
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
        <div class="flex items-center justify-between border-b pb-3 shrink-0 flex-wrap gap-2" style="border-color: var(--border-subtle);">
          <div>
            <h3 class="text-[13px] font-semibold" style="color: var(--text-primary);">等保三级 (8.1.4.1/8.1.4.4) 三员分立访问控制与管理审计链</h3>
            <p class="text-[11px] mt-0.5" style="color: var(--text-muted);">系统管理员、安全管理员、安全审计员权限正交隔离；禁止任何角色物理篡改审计存证</p>
          </div>
          <button @click="loadAdminAuditTrail" class="ui-btn-secondary px-3 py-1 text-xs">
            <AppIcon name="refresh" :size="13" />
            <span>刷新审计链</span>
          </button>
        </div>

        <!-- 首次初始化待改密与一次性本地凭单提醒（绝不在前端展示任何明文口令） -->
        <div
          v-if="!rbacSecurity.all_credentials_hardened"
          class="px-3.5 py-2.5 rounded-xl border border-amber-500/35 bg-amber-500/10 flex items-center justify-between gap-3 shrink-0 flex-wrap"
        >
          <div class="text-[11.5px] leading-relaxed" style="color: var(--text-primary);">
            <span class="font-semibold text-amber-700 dark:text-amber-300">安全加固提示：</span>
            <span>角色 {{ rbacSecurity.pending_password_change_roles.join('、') }} 尚未完成高强度口令更新。</span>
            <span v-if="rbacSecurity.bootstrap_credentials_file" class="ui-num" style="color: var(--text-secondary);">
              一次性初始凭单路径: <code class="px-1.5 py-0.5 rounded bg-[var(--surface-input)]">{{ rbacSecurity.bootstrap_credentials_file }}</code>（改密完成后自动销毁）
            </span>
          </div>
          <button @click="openChangePwdModal" class="ui-btn-primary px-3 py-1 text-[11px] shrink-0">
            立即加固当前角色口令
          </button>
        </div>

        <!-- 三员分立身份现状卡片 -->
        <div class="grid grid-cols-1 md:grid-cols-3 gap-3 shrink-0">
          <div :class="['p-3.5 rounded-xl border transition-all', currentUser.role === 'SysAdmin' ? 'bg-indigo-500/12 border-indigo-500/40' : 'ui-sub-card']">
            <div class="flex items-center justify-between">
              <span class="font-semibold text-xs" style="color: var(--text-primary);">系统管理员 (SysAdmin)</span>
              <span v-if="currentUser.role === 'SysAdmin'" class="px-2 py-0.5 rounded-full bg-indigo-600 text-white text-[11px] font-semibold">当前会话</span>
            </div>
            <p class="text-[11px] mt-1 ui-num" :class="pendingRoleSet.has('SysAdmin') ? 'text-amber-600 dark:text-amber-400 font-semibold' : 'text-emerald-600 dark:text-emerald-400'">
              {{ pendingRoleSet.has('SysAdmin') ? '状态: 待首次改密加固' : `鉴权: ${rbacSecurity.algorithm} (${rbacSecurity.iterations.toLocaleString()}轮)` }}
            </p>
            <div class="mt-2 text-[11px] space-y-1" style="color: var(--text-secondary);">
              <div>• 硬件物理接口配置 (网卡/串口/USB)</div>
              <div>• 探针引擎抓包/停止控制</div>
              <div>• 数据落盘与存储路径配置</div>
            </div>
          </div>

          <div :class="['p-3.5 rounded-xl border transition-all', currentUser.role === 'SecAdmin' ? 'bg-emerald-500/12 border-emerald-500/40' : 'ui-sub-card']">
            <div class="flex items-center justify-between">
              <span class="font-semibold text-xs" style="color: var(--text-primary);">安全管理员 (SecAdmin)</span>
              <span v-if="currentUser.role === 'SecAdmin'" class="px-2 py-0.5 rounded-full bg-emerald-600 text-white text-[11px] font-semibold">当前会话</span>
            </div>
            <p class="text-[11px] mt-1 ui-num" :class="pendingRoleSet.has('SecAdmin') ? 'text-amber-600 dark:text-amber-400 font-semibold' : 'text-emerald-600 dark:text-emerald-400'">
              {{ pendingRoleSet.has('SecAdmin') ? '状态: 待首次改密加固' : `鉴权: ${rbacSecurity.algorithm} (${rbacSecurity.iterations.toLocaleString()}轮)` }}
            </p>
            <div class="mt-2 text-[11px] space-y-1" style="color: var(--text-secondary);">
              <div>• 工业通信基线白名单自学习模式切换</div>
              <div>• 安全域划分与 CIDR 网段访问控制规则</div>
              <div>• 威胁防御限流与主动诱捕蜜罐配置</div>
            </div>
          </div>

          <div :class="['p-3.5 rounded-xl border transition-all', currentUser.role === 'AuditAdmin' ? 'bg-purple-500/12 border-purple-500/40' : 'ui-sub-card']">
            <div class="flex items-center justify-between">
              <span class="font-semibold text-xs" style="color: var(--text-primary);">安全审计员 (AuditAdmin)</span>
              <span v-if="currentUser.role === 'AuditAdmin'" class="px-2 py-0.5 rounded-full bg-purple-600 text-white text-[11px] font-semibold">当前会话</span>
            </div>
            <p class="text-[11px] mt-1 ui-num" :class="pendingRoleSet.has('AuditAdmin') ? 'text-amber-600 dark:text-amber-400 font-semibold' : 'text-emerald-600 dark:text-emerald-400'">
              {{ pendingRoleSet.has('AuditAdmin') ? '状态: 待首次改密加固' : `鉴权: ${rbacSecurity.algorithm} (${rbacSecurity.iterations.toLocaleString()}轮)` }}
            </p>
            <div class="mt-2 text-[11px] space-y-1" style="color: var(--text-secondary);">
              <div>• 独立审查系统/内核日志与管理审计流</div>
              <div>• 司法哈希封条验真与合规报告存证</div>
              <div>• 独享日志处置与清理权限 (等保8.1.4.4)</div>
            </div>
          </div>
        </div>

        <!-- 管理操作审计流水表格 -->
        <div class="flex-1 flex flex-col min-h-0">
          <div class="text-xs font-semibold mb-1.5 flex items-center justify-between" style="color: var(--text-primary);">
            <span class="ui-num">管理员操作抗抵赖审计流水 ({{ adminAuditTrail.length }} 条记录)</span>
            <span class="text-[11px]" style="color: var(--text-muted);">任何配置更改与越权阻断均已同步广播至 Syslog</span>
          </div>
          <div class="flex-1 overflow-auto custom-scrollbar border rounded-xl" style="border-color: var(--border-subtle); background: var(--surface-content-alt);">
            <table class="w-full text-left text-xs border-collapse">
              <thead class="ui-table-head sticky top-0 z-10 select-none">
                <tr>
                  <th class="p-2.5">序号</th>
                  <th class="p-2.5">时间戳</th>
                  <th class="p-2.5">操作者</th>
                  <th class="p-2.5">所属角色</th>
                  <th class="p-2.5">管理行为</th>
                  <th class="p-2.5">审计详情</th>
                  <th class="p-2.5 text-center">状态</th>
                </tr>
              </thead>
              <tbody class="divide-y" style="border-color: var(--border-subtle);">
                <tr v-for="rec in adminAuditTrail" :key="rec.id" class="hover:bg-[var(--surface-hover)] transition-colors">
                  <td class="p-2 ui-num" style="color: var(--text-muted);">#{{ rec.id }}</td>
                  <td class="p-2 ui-num" style="color: var(--text-secondary);">{{ rec.timestamp }}</td>
                  <td class="p-2 font-semibold" style="color: var(--text-primary);">{{ rec.operator }}</td>
                  <td class="p-2"><span class="ui-pill px-1.5 py-0.5 font-semibold text-[11px]">{{ rec.role }}</span></td>
                  <td class="p-2 font-semibold text-indigo-600 dark:text-indigo-300">{{ rec.action }}</td>
                  <td class="p-2 truncate max-w-xs" style="color: var(--text-secondary);" :title="rec.details">{{ rec.details }}</td>
                  <td class="p-2 text-center">
                    <span :class="['px-2 py-0.5 rounded-full text-[11px] font-semibold', rec.status === 'SUCCESS' ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300' : 'bg-rose-500/15 text-rose-700 dark:text-rose-300']">
                      {{ rec.status }}
                    </span>
                  </td>
                </tr>
                <tr v-if="adminAuditTrail.length === 0">
                  <td colspan="7" class="p-8 text-center text-xs" style="color: var(--text-muted);">
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
        <div class="flex items-center justify-between border-b pb-3 shrink-0 flex-wrap gap-2" style="border-color: var(--border-subtle);">
          <div>
            <h3 class="text-[13px] font-semibold" style="color: var(--text-primary);">等保三级工控扩展 (G.4.2/G.4.3) 工业通信基线白名单自学习引擎</h3>
            <p class="text-[11px] mt-0.5" style="color: var(--text-muted);">被动收敛全网物理/逻辑通信拓扑基线；严格阻击未授权新会话与高危工控写控制指令</p>
          </div>
          <div class="flex items-center gap-2 flex-wrap">
            <div class="glass-pill flex p-0.5 rounded-xl text-[11px] font-semibold">
              <button
                @click="changeBaselineMode('LEARNING')"
                :class="['px-2.5 py-1 rounded-lg transition-all cursor-pointer', baselineStatus.mode === 'LEARNING' ? 'bg-emerald-600 text-white shadow-xs' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]']"
              >
                自学习模式 (Learning)
              </button>
              <button
                @click="changeBaselineMode('ENFORCING')"
                :class="['px-2.5 py-1 rounded-lg transition-all cursor-pointer', baselineStatus.mode === 'ENFORCING' ? 'bg-rose-600 text-white shadow-xs' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]']"
              >
                严格审计模式 (Enforcing)
              </button>
              <button
                @click="changeBaselineMode('DISABLED')"
                :class="['px-2.5 py-1 rounded-lg transition-all cursor-pointer', baselineStatus.mode === 'DISABLED' ? 'bg-slate-600 text-white shadow-xs' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]']"
              >
                已停用
              </button>
            </div>
            <button @click="persistBaseline" class="ui-btn-primary bg-emerald-600 hover:bg-emerald-500 px-3 py-1 text-xs">
              <AppIcon name="archive" :size="13" />
              <span>固化基线至磁盘</span>
            </button>
            <button @click="resetBaselineRules" class="ui-btn-danger px-3 py-1 text-xs">
              重置基线规则
            </button>
          </div>
        </div>

        <!-- 基线指标仪表盘 -->
        <div class="grid grid-cols-1 md:grid-cols-4 gap-3 shrink-0">
          <div class="ui-sub-card p-3">
            <span class="text-[11px] font-semibold" style="color: var(--text-muted);">当前基线模式</span>
            <div class="text-sm font-semibold mt-1" :class="baselineStatus.mode === 'ENFORCING' ? 'text-rose-600 dark:text-rose-400' : 'text-emerald-600 dark:text-emerald-400'">
              {{ baselineStatus.mode === 'LEARNING' ? '自学习模式 (收敛中)' : (baselineStatus.mode === 'ENFORCING' ? '严格审计模式 (实时阻击)' : '已停用') }}
            </div>
          </div>
          <div class="ui-sub-card p-3">
            <span class="text-[11px] font-semibold" style="color: var(--text-muted);">已收敛白名单规则</span>
            <div class="text-sm font-semibold ui-num text-indigo-600 dark:text-indigo-300 mt-1">{{ baselineRules.length }} 条合法通信对</div>
          </div>
          <div class="ui-sub-card p-3">
            <span class="text-[11px] font-semibold" style="color: var(--text-muted);">捕获合规漂移违规</span>
            <div class="text-sm font-semibold ui-num text-rose-600 dark:text-rose-400 mt-1">{{ baselineDriftEvents.length }} 起越权事件</div>
          </div>
          <div class="ui-sub-card p-3">
            <span class="text-[11px] font-semibold" style="color: var(--text-muted);">基线自学习启动时间</span>
            <div class="text-xs ui-num mt-1 truncate" style="color: var(--text-secondary);">{{ baselineStatus.learning_started_at || '待启动' }}</div>
          </div>
        </div>

        <!-- 宏观节假日/工作日无监督日态基线栏 -->
        <div class="bg-indigo-500/8 border border-indigo-500/25 rounded-xl p-2.5 flex flex-wrap items-center justify-between gap-2 text-xs shrink-0">
          <div class="flex items-center gap-2.5 flex-wrap">
            <span class="font-semibold text-indigo-700 dark:text-indigo-300 flex items-center gap-1.5">
              <AppIcon name="activity" :size="13" />
              <span>宏观日历基线日态推断:</span>
            </span>
            <span class="px-2 py-0.5 rounded-lg bg-indigo-500/15 text-indigo-700 dark:text-indigo-300 font-semibold">
              {{ macroCalendarStatus?.inferred_regime || '待同步' }}
            </span>
            <span v-if="macroCalendarStatus" class="ui-num text-[11px]" style="color: var(--text-secondary);">
              置信度: <b>{{ (macroCalendarStatus.confidence_score * 100).toFixed(1) }}%</b> | 工作日后验: {{ (macroCalendarStatus.posterior_workday_prob * 100).toFixed(1) }}%
            </span>
            <span v-if="macroCalendarStatus" class="text-[11px] truncate max-w-md" style="color: var(--text-muted);" :title="macroCalendarStatus.evidence_summary">
              {{ macroCalendarStatus.evidence_summary }}
            </span>
          </div>
          <div class="flex items-center gap-1.5 flex-wrap">
            <input v-model="statutoryDateInput" type="date" class="ui-input px-2 py-1 text-[11px]" />
            <select v-model="statutoryRegimeType" class="ui-input px-2 py-1 text-[11px]">
              <option value="HOLIDAY">法定节假日 (Holiday)</option>
              <option value="COMPENSATORY">调休补班工作日</option>
              <option value="WORKDAY">标准工作日</option>
              <option value="WEEKEND">标准双休日</option>
            </select>
            <button @click="submitStatutoryDate" class="ui-btn-primary px-2.5 py-1 text-[11px]">
              登记法定日程
            </button>
            <button @click="loadMacroCalendarStatus" class="ui-btn-secondary px-2 py-1 text-[11px]" title="刷新状态">
              <AppIcon name="refresh" :size="12" />
            </button>
          </div>
        </div>

        <!-- 规则与漂移违规上下分割 -->
        <div class="flex-1 grid grid-cols-1 lg:grid-cols-2 gap-3 min-h-0">
          <div class="flex flex-col min-h-0 border rounded-xl p-2.5" style="border-color: var(--border-subtle); background: var(--surface-content-alt);">
            <div class="text-xs font-semibold mb-1.5 flex items-center justify-between" style="color: var(--text-primary);">
              <span class="ui-num">已收敛合法通信基线 ({{ baselineRules.length }})</span>
              <button @click="loadBaselineRules" class="text-[11px] text-blue-600 dark:text-sky-400 hover:underline font-medium cursor-pointer">刷新</button>
            </div>
            <div class="flex-1 overflow-auto custom-scrollbar">
              <table class="w-full text-left text-xs border-collapse">
                <thead class="ui-table-head sticky top-0 z-10 select-none">
                  <tr>
                    <th class="p-2">通信链路 (源 → 宿)</th>
                    <th class="p-2">规约/端口</th>
                    <th class="p-2">动作基线</th>
                    <th class="p-2 text-right">命中次数</th>
                  </tr>
                </thead>
                <tbody class="divide-y text-[11px]" style="border-color: var(--border-subtle);">
                  <tr v-for="r in baselineRules" :key="r.id" class="hover:bg-[var(--surface-hover)]">
                    <td class="p-2 font-semibold ui-num truncate max-w-[140px]" style="color: var(--text-primary);" :title="`${r.src_ip} -> ${r.dst_ip}`">
                      {{ r.src_ip }} → {{ r.dst_ip }}
                    </td>
                    <td class="p-2 ui-num" style="color: var(--text-secondary);">{{ r.protocol }}:{{ r.dst_port }}</td>
                    <td class="p-2">
                      <span :class="['px-1.5 py-0.5 rounded font-semibold text-[11px]', r.action_type === 'WRITE_ALLOWED' ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300' : 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300']">
                        {{ r.action_type === 'WRITE_ALLOWED' ? '允许写控制' : '严格只读查询' }}
                      </span>
                    </td>
                    <td class="p-2 text-right font-semibold ui-num text-indigo-600 dark:text-indigo-300">{{ r.hit_count }}</td>
                  </tr>
                  <tr v-if="baselineRules.length === 0">
                    <td colspan="4" class="p-6 text-center text-xs" style="color: var(--text-muted);">
                      基线学习中，接收到工控网络报文后将自动收敛规则
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <div class="flex flex-col min-h-0 border rounded-xl p-2.5" style="border-color: var(--border-subtle); background: var(--surface-content-alt);">
            <div class="text-xs font-semibold mb-1.5 flex items-center justify-between">
              <span class="text-rose-600 dark:text-rose-400 ui-num">实时通信漂移与高危指令告警 ({{ baselineDriftEvents.length }})</span>
              <button @click="loadBaselineDriftEvents" class="text-[11px] text-blue-600 dark:text-sky-400 hover:underline font-medium cursor-pointer">刷新</button>
            </div>
            <div class="flex-1 overflow-auto custom-scrollbar">
              <table class="w-full text-left text-xs border-collapse">
                <thead class="ui-table-head sticky top-0 z-10 select-none">
                  <tr>
                    <th class="p-2">时间</th>
                    <th class="p-2">违规类型</th>
                    <th class="p-2">会话链路</th>
                    <th class="p-2">告警详情</th>
                    <th class="p-2 w-16 text-center">比对</th>
                  </tr>
                </thead>
                <tbody class="divide-y text-[11px]" style="border-color: var(--border-subtle);">
                  <tr v-for="ev in baselineDriftEvents" :key="ev.id" class="hover:bg-rose-500/8">
                    <td class="p-2 ui-num" style="color: var(--text-muted);">{{ ev.timestamp.split(' ')[1] }}</td>
                    <td class="p-2">
                      <span class="px-1.5 py-0.5 rounded font-semibold text-[11px] bg-rose-500/15 text-rose-700 dark:text-rose-300">
                        {{ ev.drift_type }}
                      </span>
                    </td>
                    <td class="p-2 ui-num font-medium" style="color: var(--text-primary);">{{ ev.src_ip }} → :{{ ev.dst_port }}</td>
                    <td class="p-2 truncate max-w-[160px]" style="color: var(--text-secondary);" :title="ev.description">
                      {{ ev.description }}
                    </td>
                    <td class="p-2 text-center">
                      <button @click="addDriftToDiffQueue(ev)" class="px-1.5 py-0.5 rounded bg-emerald-500/12 hover:bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border border-emerald-500/25 text-[11px] font-semibold cursor-pointer">+入队</button>
                    </td>
                  </tr>
                  <tr v-if="baselineDriftEvents.length === 0">
                    <td colspan="5" class="p-6 text-center text-xs" style="color: var(--text-muted);">
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
        <div class="flex items-center justify-between border-b pb-3 shrink-0 flex-wrap gap-2" style="border-color: var(--border-subtle);">
          <div>
            <h3 class="text-[13px] font-semibold" style="color: var(--text-primary);">等保三级 (8.1.2.1/8.1.2.2) 安全区域划分与 CIDR 网段规则管理</h3>
            <p class="text-[11px] mt-0.5" style="color: var(--text-muted);">严格定义生产控制区(安全区I)、生产非控制区(安全区II)、管理信息大区(安全区III)等网络边界</p>
          </div>
          <div class="flex items-center gap-2">
            <button @click="loadCidrRules" class="ui-btn-secondary px-3 py-1 text-xs">重新加载</button>
            <button @click="saveCidrRules" class="ui-btn-primary px-3.5 py-1 text-xs">保存区域规则</button>
          </div>
        </div>

        <!-- 快速添加新网段规则栏 -->
        <div class="ui-sub-card p-3 shrink-0 flex items-center gap-2 flex-wrap text-xs">
          <span class="font-semibold text-[11px]" style="color: var(--text-secondary);">添加网段:</span>
          <input v-model="newCidr" placeholder="网段 CIDR (如 192.168.10.0/24)" class="ui-input w-48 px-2.5 py-1 text-xs font-mono" />
          <input v-model="newZoneName" placeholder="安全区域名称 (如 生产控制大区-安全区I)" class="ui-input w-56 px-2.5 py-1 text-xs" />
          <select v-model="newSecLevel" class="ui-input px-2 py-1 text-xs font-medium">
            <option value="核心生产">核心生产 (安全区I)</option>
            <option value="关键业务">关键业务 (安全区II)</option>
            <option value="生产管理">生产管理 (安全区III)</option>
            <option value="办公外网">办公外网 (安全区IV)</option>
            <option value="外部公网">外部公网</option>
          </select>
          <input v-model="newDescription" placeholder="归属说明/用途" class="ui-input flex-1 min-w-[120px] px-2.5 py-1 text-xs" />
          <button @click="addCidrRule" class="ui-btn-primary px-3 py-1 text-xs">
            <AppIcon name="plus" :size="13" />
            <span>添加规则</span>
          </button>
        </div>

        <!-- CIDR 网段规则表格 -->
        <div class="flex-1 overflow-auto custom-scrollbar border rounded-xl" style="border-color: var(--border-subtle); background: var(--surface-content-alt);">
          <table class="w-full text-left text-xs border-collapse">
            <thead class="ui-table-head sticky top-0 z-10 select-none">
              <tr>
                <th class="p-2.5">CIDR 网段</th>
                <th class="p-2.5">安全区域名称</th>
                <th class="p-2.5">安全等级</th>
                <th class="p-2.5">责任归属说明</th>
                <th class="p-2.5 text-center">操作</th>
              </tr>
            </thead>
            <tbody class="divide-y" style="border-color: var(--border-subtle);">
              <tr v-for="(rule, idx) in cidrRules" :key="idx" class="hover:bg-[var(--surface-hover)] transition-colors">
                <td class="p-2.5 font-semibold text-indigo-600 dark:text-indigo-300 ui-num">
                  <input v-model="rule.cidr" class="bg-transparent border-b border-transparent focus:border-blue-500 outline-none w-full" />
                </td>
                <td class="p-2.5 font-semibold" style="color: var(--text-primary);">
                  <input v-model="rule.zone_name" class="bg-transparent border-b border-transparent focus:border-blue-500 outline-none w-full" />
                </td>
                <td class="p-2.5">
                  <span class="ui-pill px-2 py-0.5 font-semibold text-[11px]">{{ rule.security_level }}</span>
                </td>
                <td class="p-2.5" style="color: var(--text-secondary);">
                  <input v-model="rule.description" class="bg-transparent border-b border-transparent focus:border-blue-500 outline-none w-full" />
                </td>
                <td class="p-2.5 text-center">
                  <button @click="removeCidrRule(idx)" class="text-rose-600 dark:text-rose-400 hover:underline font-semibold text-xs cursor-pointer">
                    删除
                  </button>
                </td>
              </tr>
              <tr v-if="cidrRules.length === 0">
                <td colspan="5" class="p-8 text-center text-xs" style="color: var(--text-muted);">
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
        <div class="flex items-center justify-between border-b pb-3 shrink-0 flex-wrap gap-2" style="border-color: var(--border-subtle);">
          <div>
            <h3 class="text-[13px] font-semibold" style="color: var(--text-primary);">等保三级 (8.1.4.3) 集中式日志备份与 RFC 5424 Syslog 外发引擎</h3>
            <p class="text-[11px] mt-0.5" style="color: var(--text-muted);">严格遵循 RFC 5424 标准规范，异步 UDP / TCP 外发至企业 SIEM / SOC 集中日志审计中心</p>
          </div>
          <div class="flex items-center gap-2">
            <button @click="loadSyslogConfig" class="ui-btn-secondary px-3 py-1 text-xs">重新加载</button>
            <button @click="saveSyslogConfig" class="ui-btn-primary px-3.5 py-1 text-xs">保存配置</button>
          </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-3 gap-3 shrink-0">
          <div class="space-y-1 ui-sub-card p-3">
            <label class="text-[11px] font-semibold block" style="color: var(--text-secondary);">集中外发主开关</label>
            <label class="flex items-center gap-2 cursor-pointer mt-1.5">
              <input type="checkbox" v-model="syslogCfg.enabled" class="accent-blue-600 w-4 h-4" />
              <span class="text-xs font-semibold" :class="syslogCfg.enabled ? 'text-emerald-600 dark:text-emerald-400' : 'text-[var(--text-muted)]'">
                {{ syslogCfg.enabled ? '已启用集中外发' : '已停用集中外发' }}
              </span>
            </label>
          </div>

          <div class="space-y-1 ui-sub-card p-3">
            <label class="text-[11px] font-semibold block" style="color: var(--text-secondary);">远程 SIEM/SOC 服务器 IP</label>
            <input v-model="syslogCfg.server_ip" placeholder="192.168.1.200" class="ui-input w-full px-2.5 py-1.5 text-xs font-mono" />
          </div>

          <div class="space-y-1 ui-sub-card p-3">
            <label class="text-[11px] font-semibold block" style="color: var(--text-secondary);">服务端口与传输协议</label>
            <div class="flex gap-2">
              <input v-model.number="syslogCfg.server_port" type="number" min="1" max="65535" class="ui-input w-24 px-2.5 py-1.5 text-xs ui-num" />
              <select v-model="syslogCfg.protocol" class="ui-input flex-1 px-2 py-1.5 text-xs">
                <option value="UDP">UDP (低开销)</option>
                <option value="TCP">TCP (可靠传输)</option>
              </select>
            </div>
          </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-3 gap-3 shrink-0">
          <div class="space-y-1 ui-sub-card p-3">
            <label class="text-[11px] font-semibold block" style="color: var(--text-secondary);">Syslog Facility (设施)</label>
            <select v-model.number="syslogCfg.facility" class="ui-input w-full px-2.5 py-1.5 text-xs">
              <option :value="1">1: user-level messages</option>
              <option :value="16">16: local0 (标准工业审计)</option>
              <option :value="17">17: local1</option>
              <option :value="18">18: local2</option>
            </select>
          </div>

          <div class="space-y-1 ui-sub-card p-3">
            <label class="text-[11px] font-semibold block" style="color: var(--text-secondary);">最低外发严重性 (Min Severity)</label>
            <select v-model.number="syslogCfg.min_severity" class="ui-input w-full px-2.5 py-1.5 text-xs">
              <option :value="3">3: Error 及以上</option>
              <option :value="4">4: Warning 及以上</option>
              <option :value="5">5: Notice 及以上</option>
              <option :value="6">6: Informational 及以上 (推荐)</option>
              <option :value="7">7: Debug (全部日志)</option>
            </select>
          </div>

          <div class="space-y-1 ui-sub-card p-3">
            <label class="text-[11px] font-semibold block" style="color: var(--text-secondary);">应用标识名 (APP-NAME)</label>
            <input v-model="syslogCfg.app_name" placeholder="OmniProbe" class="ui-input w-full px-2.5 py-1.5 text-xs font-mono" />
          </div>
        </div>

        <!-- 联调测试控制台 -->
        <div class="ui-sub-card p-3 space-y-2">
          <div class="text-xs font-semibold flex items-center justify-between" style="color: var(--text-primary);">
            <span>RFC 5424 连通性测试与审计报文模拟</span>
            <span class="text-[11px] ui-num" style="color: var(--text-muted);">已外发审计报文总计: {{ syslogCfg.sent_count }} 条</span>
          </div>
          <div class="flex gap-2">
            <input v-model="syslogTestMsg" placeholder="输入测试审计报文内容..." class="ui-input flex-1 px-2.5 py-1.5 text-xs" />
            <button @click="testSendSyslog" :disabled="syslogTesting" class="ui-btn-primary px-4 py-1.5 text-xs">
              <span v-if="syslogTesting">发送中...</span>
              <span v-else>立即发送测试报文</span>
            </button>
          </div>
          <div
            v-if="syslogTestResult"
            class="text-xs font-mono p-2.5 rounded-lg border"
            style="background: var(--surface-content); border-color: var(--border-subtle);"
            :class="syslogTestResult.includes('失败') ? 'text-rose-600 dark:text-rose-400' : 'text-emerald-600 dark:text-emerald-400'"
          >
            {{ syslogTestResult }}
          </div>
        </div>
      </div>

      <!-- ============================================================ -->
      <!-- 选项卡 6：蜜罐主动防御 -->
      <!-- ============================================================ -->
      <div v-else-if="currentTab === 'honeypot'" class="h-full flex flex-col gap-3 overflow-hidden p-4">
        <div class="flex items-center justify-between border-b pb-3 shrink-0 gap-3 flex-wrap" style="border-color: var(--border-subtle);">
          <div>
            <h3 class="text-[13px] font-semibold" style="color: var(--text-primary);">工业级轻量高熵诱捕蜜罐矩阵</h3>
            <p class="text-[11px] mt-0.5" style="color: var(--text-muted);">多端口低交互虚拟蜜罐，诱捕异常刺探并实时记录攻击载荷</p>
          </div>
          <div class="flex items-center gap-2 flex-wrap">
            <input v-model.number="newPort" type="number" min="1" max="65535" placeholder="端口如 1883" class="ui-input w-24 px-2 py-1 text-xs ui-num" />
            <select v-model="newProto" class="ui-input px-2 py-1 text-xs">
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
            </select>
            <button @click="addPort" :disabled="!isValidNewPort" class="ui-btn-primary px-3 py-1 text-xs">添加监听</button>
            <button
              v-if="!honeypotRunning"
              @click="startHoneypot"
              :disabled="honeypotPorts.length === 0"
              class="ui-btn-primary bg-emerald-600 hover:bg-emerald-500 px-3.5 py-1 text-xs"
            >
              启动蜜罐
            </button>
            <button v-else @click="stopHoneypot" class="ui-btn-danger px-3.5 py-1 text-xs">停止蜜罐</button>
          </div>
        </div>

        <!-- 诱饵端口清单管理 -->
        <div class="shrink-0 flex items-center gap-1.5 flex-wrap text-xs">
          <span class="text-[11px] font-semibold" style="color: var(--text-muted);">诱饵端口矩阵 ({{ honeypotPorts.length }}):</span>
          <span
            v-for="(hp, idx) in honeypotPorts"
            :key="`${hp.port}-${hp.proto}`"
            class="px-2 py-0.5 rounded-lg bg-indigo-500/12 text-indigo-700 dark:text-indigo-300 border border-indigo-500/25 text-[11px] font-semibold ui-num flex items-center gap-1.5"
          >
            :{{ hp.port }}/{{ hp.proto.toUpperCase() }}
            <button
              @click="removePort(idx)"
              class="w-4 h-4 rounded-full flex items-center justify-center hover:text-rose-500 hover:bg-rose-500/15 transition-colors cursor-pointer"
              title="移除监听"
            >
              <AppIcon name="close" :size="11" />
            </button>
          </span>
          <span v-if="honeypotPorts.length === 0" class="text-[11px]" style="color: var(--text-muted);">尚未配置诱饵端口</span>
        </div>

        <div class="flex-1 overflow-auto custom-scrollbar border rounded-xl" style="border-color: var(--border-subtle); background: var(--surface-content-alt);">
          <table class="w-full text-left text-xs border-collapse">
            <thead class="ui-table-head sticky top-0 z-10 select-none">
              <tr>
                <th class="p-2.5">时间戳</th>
                <th class="p-2.5">传输层</th>
                <th class="p-2.5">诱捕规约</th>
                <th class="p-2.5">源 IP (异常刺探)</th>
                <th class="p-2.5">目标蜜罐端口</th>
                <th class="p-2.5">载荷长度</th>
                <th class="p-2.5">Shannon 熵</th>
              </tr>
            </thead>
            <tbody class="divide-y" style="border-color: var(--border-subtle);">
              <tr v-for="p in honeypotPackets" :key="p.id" class="hover:bg-[var(--surface-hover)] transition-colors">
                <td class="p-2 ui-num" style="color: var(--text-muted);">{{ p.timestamp }}</td>
                <td class="p-2"><span class="ui-pill px-1.5 py-0.5 font-semibold text-[11px]">{{ p.transport }}</span></td>
                <td class="p-2 font-semibold text-amber-600 dark:text-amber-300">{{ p.protocol }}</td>
                <td class="p-2 font-semibold text-rose-600 dark:text-rose-400 ui-num">{{ p.src_ip }}:{{ p.src_port }}</td>
                <td class="p-2 text-indigo-600 dark:text-indigo-300 font-semibold ui-num">:{{ p.dst_port }}</td>
                <td class="p-2 ui-num">{{ p.length }} B</td>
                <td class="p-2 text-rose-600 dark:text-rose-400 font-semibold ui-num">{{ p.entropy.toFixed(2) }}</td>
              </tr>
              <tr v-if="honeypotPackets.length === 0">
                <td colspan="7" class="p-12 text-center text-xs" style="color: var(--text-muted);">
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
          <span class="text-xs font-semibold ui-num" style="color: var(--text-primary);">内核与系统运行日志审计 ({{ systemLogs.length }} 行)</span>
          <div class="flex items-center gap-2">
            <span class="text-[11px]" style="color: var(--text-muted);">受等保三级(8.1.4.4)保护: 仅安全审计员可处置日志</span>
            <button @click="handleClearLogs" class="ui-btn-danger px-2.5 py-1 text-xs">清空日志</button>
          </div>
        </div>
        <div
          class="flex-1 rounded-xl p-3 font-mono text-xs leading-relaxed overflow-auto custom-scrollbar select-text border"
          style="background: var(--surface-input); border-color: var(--border-subtle); color: var(--text-primary);"
        >
          <div
            v-for="(logLine, idx) in systemLogs"
            :key="idx"
            :class="[
              'hover:bg-[var(--surface-hover)] px-1.5 py-0.5 rounded flex items-center justify-between gap-2 group',
              logLine.includes('[ERROR]') || logLine.includes('FATAL') || logLine.includes('失败')
                ? 'text-rose-600 dark:text-rose-400'
                : logLine.includes('[WARN]') || logLine.includes('告警')
                  ? 'text-amber-600 dark:text-amber-300'
                  : 'text-[var(--text-secondary)]'
            ]"
          >
            <span class="truncate">{{ logLine }}</span>
            <button @click="addSystemLogToDiffQueue(logLine, idx)" class="opacity-0 group-hover:opacity-100 px-1.5 py-0.2 rounded bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 text-[11px] font-sans font-semibold shrink-0 cursor-pointer transition-opacity">
              + 入队
            </button>
          </div>
          <div v-if="systemLogs.length === 0" class="italic" style="color: var(--text-muted);">
            暂无系统运行日志
          </div>
        </div>
      </div>

      <!-- ============================================================ -->
      <!-- 选项卡 8：引擎配置、Prometheus 指标与系统参数 -->
      <!-- ============================================================ -->
      <div v-else-if="currentTab === 'config'" class="h-full flex flex-col overflow-hidden">
        <div class="flex items-center justify-between px-4 py-2.5 border-b shrink-0 gap-3 flex-wrap" style="border-color: var(--border-subtle);">
          <span class="text-[13px] font-semibold" style="color: var(--text-primary);">引擎配置、Prometheus 可观测性与系统参数</span>
          <div class="flex items-center gap-2">
            <button @click="loadConfig" :disabled="configLoading" class="ui-btn-secondary px-3 py-1 text-xs">
              <AppIcon name="refresh" :size="13" :class="{ 'animate-spin': configLoading }" />
              <span>重新加载</span>
            </button>
            <button @click="saveConfig" :disabled="configSaving || !cfg" class="ui-btn-primary px-3.5 py-1 text-xs">
              <AppIcon v-if="configSaving" name="refresh" :size="13" class="animate-spin" />
              <AppIcon v-else name="archive" :size="13" />
              <span>保存并持久化</span>
            </button>
          </div>
        </div>

        <div v-if="cfg" class="flex-1 overflow-auto custom-scrollbar p-4 space-y-4">
          <!-- Prometheus 监控指标服务状态 -->
          <div class="bg-indigo-500/8 rounded-xl border border-indigo-500/25 p-3 flex items-center justify-between gap-3 flex-wrap">
            <div class="flex items-center gap-3">
              <div class="w-8 h-8 rounded-xl bg-indigo-600 text-white flex items-center justify-center font-bold text-xs shrink-0">
                P
              </div>
              <div>
                <div class="text-xs font-semibold" style="color: var(--text-primary);">Prometheus 工业监控指标服务 (RFC 集中监控)</div>
                <div class="text-[11px] ui-num mt-0.5" style="color: var(--text-muted);">
                  抓取端点: <span class="text-indigo-600 dark:text-indigo-300 font-semibold">http://127.0.0.1:{{ cfg.enterprise_features.fleet_management.enabled ? cfg.enterprise_features.fleet_management.api_port : 9091 }}/metrics</span>
                </div>
              </div>
            </div>
            <span class="px-2.5 py-1 rounded-full bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 text-[11px] font-semibold flex items-center gap-1">
              <AppIcon name="check" :size="12" />
              <span>服务运行中</span>
            </span>
          </div>

          <!-- 运行时热更新区 -->
          <div class="ui-sub-card p-3.5 space-y-3">
            <div class="text-xs font-semibold flex items-center gap-1.5" style="color: var(--text-primary);">
              <span class="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
              <span>运行时热更新 (立即生效，无需重启探针)</span>
            </div>
            <div class="grid grid-cols-1 lg:grid-cols-3 gap-3">
              <div class="space-y-2 p-3 rounded-xl border" style="background: var(--surface-content); border-color: var(--border-subtle);">
                <div class="text-[11px] font-semibold" style="color: var(--text-muted);">令牌桶防御限流</div>
                <div class="flex items-center gap-2">
                  <input v-model.number="throttleCapacity" type="number" min="1" max="1000" title="容量 (Capacity)" class="ui-input w-16 px-2 py-1 text-xs ui-num" />
                  <span class="text-[11px]" style="color: var(--text-muted);">容量 /</span>
                  <input v-model.number="throttleFillRate" type="number" min="1" max="1000" title="填充速率 (Fill Rate /s)" class="ui-input w-16 px-2 py-1 text-xs ui-num" />
                  <span class="text-[11px]" style="color: var(--text-muted);">每秒</span>
                </div>
                <button @click="applyThrottle" class="ui-btn-primary bg-emerald-600 hover:bg-emerald-500 w-full py-1 text-xs justify-center">
                  热更新限流参数
                </button>
              </div>

              <div class="space-y-2 p-3 rounded-xl border" style="background: var(--surface-content); border-color: var(--border-subtle);">
                <div class="text-[11px] font-semibold flex items-center justify-between" style="color: var(--text-muted);">
                  <span>云端流式上报</span>
                  <span class="flex items-center gap-1">
                    <span class="w-1.5 h-1.5 rounded-full" :class="cloudRunning ? 'bg-emerald-500' : 'bg-slate-400'"></span>
                    <span :class="cloudRunning ? 'text-emerald-600 dark:text-emerald-400 font-semibold' : ''">{{ cloudRunning ? '推送中' : '未启动' }}</span>
                  </span>
                </div>
                <input v-model="cloudWebhookUrl" placeholder="http://127.0.0.1:9090/ingest" class="ui-input w-full px-2 py-1 text-xs font-mono" />
                <div class="flex gap-1.5">
                  <button v-if="!cloudRunning" @click="startCloud" class="ui-btn-primary flex-1 py-1 text-xs justify-center">启动推送</button>
                  <button v-else @click="stopCloud" class="ui-btn-danger flex-1 py-1 text-xs justify-center">停止推送</button>
                </div>
              </div>

              <div class="space-y-2 p-3 rounded-xl border" style="background: var(--surface-content); border-color: var(--border-subtle);">
                <div class="text-[11px] font-semibold" style="color: var(--text-muted);">DPI 动态字典热重载</div>
                <input v-model="dpiSigPath" placeholder="protocol_signatures.json" class="ui-input w-full px-2 py-1 text-xs font-mono" />
                <button @click="reloadDpi" class="ui-btn-primary bg-indigo-600 hover:bg-indigo-500 w-full py-1 text-xs justify-center">重载规约字典</button>
              </div>
            </div>
          </div>

          <!-- 持久化配置区 -->
          <div class="ui-sub-card p-3.5 space-y-3">
            <div class="text-xs font-semibold flex items-center gap-1.5" style="color: var(--text-primary);">
              <span class="w-1.5 h-1.5 rounded-full bg-blue-500"></span>
              <span>持久化配置 (保存后写入 config.json，部分配置项重启探针后生效)</span>
            </div>

            <div class="grid grid-cols-2 lg:grid-cols-3 gap-3 text-xs">
              <div class="space-y-1">
                <label class="font-semibold block text-[11px]" style="color: var(--text-secondary);">TCP 组帧超时 (秒)</label>
                <input v-model.number="cfg.tcp_framing_timeout" type="number" step="0.01" min="0.01" class="ui-input w-full p-1.5 text-xs ui-num" />
              </div>
              <div class="space-y-1">
                <label class="font-semibold block text-[11px]" style="color: var(--text-secondary);">司法封条周期 (秒)</label>
                <input v-model.number="cfg.sealing_interval_secs" type="number" min="5" class="ui-input w-full p-1.5 text-xs ui-num" />
              </div>
              <div class="space-y-1">
                <label class="font-semibold block text-[11px]" style="color: var(--text-secondary);">日志级别</label>
                <select v-model="cfg.logging.level" class="ui-input w-full p-1.5 text-xs">
                  <option value="DEBUG">DEBUG</option>
                  <option value="INFO">INFO</option>
                  <option value="WARN">WARN</option>
                  <option value="ERROR">ERROR</option>
                </select>
              </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-2 gap-3 text-xs">
              <div class="space-y-1.5 p-2.5 rounded-xl border" style="background: var(--surface-content); border-color: var(--border-subtle);">
                <div class="text-[11px] font-semibold" style="color: var(--text-muted);">日志体系 (logging)</div>
                <input v-model="cfg.logging.file" placeholder="listener.log" class="ui-input w-full px-2 py-1 font-mono text-xs" />
              </div>
              <div class="space-y-1.5 p-2.5 rounded-xl border" style="background: var(--surface-content); border-color: var(--border-subtle);">
                <div class="text-[11px] font-semibold" style="color: var(--text-muted);">数据落盘 (data_storage)</div>
                <div class="grid grid-cols-2 gap-2">
                  <input v-model="cfg.data_storage.file" placeholder="received_data.jsonl" class="ui-input px-2 py-1 font-mono text-xs" />
                  <input v-model="cfg.data_storage.pcap_file" placeholder="capture.pcap" class="ui-input px-2 py-1 font-mono text-xs" />
                </div>
                <label class="flex items-center gap-1.5 cursor-pointer text-[11px]" style="color: var(--text-secondary);">
                  <input type="checkbox" v-model="cfg.data_storage.enable_pcap" class="accent-blue-600" />
                  <span class="font-medium">启用 PCAP 全量落盘存证</span>
                </label>
              </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-3 gap-3 text-xs">
              <div class="space-y-1.5 p-2.5 rounded-xl border" style="background: var(--surface-content); border-color: var(--border-subtle);">
                <div class="text-[11px] font-semibold" style="color: var(--text-muted);">集群协同管理</div>
                <label class="flex items-center gap-1.5 cursor-pointer text-[11px]" style="color: var(--text-secondary);">
                  <input type="checkbox" v-model="cfg.enterprise_features.fleet_management.enabled" class="accent-blue-600" />
                  <span class="font-medium">启用</span>
                </label>
                <div class="flex items-center gap-1.5">
                  <span class="text-[11px]" style="color: var(--text-muted);">API 端口:</span>
                  <input v-model.number="cfg.enterprise_features.fleet_management.api_port" type="number" min="1" max="65535" class="ui-input w-20 px-2 py-1 ui-num text-xs" />
                </div>
              </div>
              <div class="space-y-1.5 p-2.5 rounded-xl border" style="background: var(--surface-content); border-color: var(--border-subtle);">
                <div class="text-[11px] font-semibold" style="color: var(--text-muted);">威胁防御</div>
                <label class="flex items-center gap-1.5 cursor-pointer text-[11px]" style="color: var(--text-secondary);">
                  <input type="checkbox" v-model="cfg.enterprise_features.threat_defense.enabled" class="accent-blue-600" />
                  <span class="font-medium">启用</span>
                </label>
                <div class="flex items-center gap-1.5">
                  <span class="text-[11px]" style="color: var(--text-muted);">阈值 pps:</span>
                  <input v-model.number="cfg.enterprise_features.threat_defense.max_packets_per_sec" type="number" min="1" step="0.1" class="ui-input w-20 px-2 py-1 ui-num text-xs" />
                </div>
                <label class="flex items-center gap-1.5 cursor-pointer text-[11px]" style="color: var(--text-secondary);">
                  <input type="checkbox" v-model="cfg.enterprise_features.threat_defense.auto_drop_connection" class="accent-blue-600" />
                  <span class="font-medium">超限自动断连</span>
                </label>
              </div>
              <div class="space-y-1.5 p-2.5 rounded-xl border" style="background: var(--surface-content); border-color: var(--border-subtle);">
                <div class="text-[11px] font-semibold" style="color: var(--text-muted);">云端上报</div>
                <label class="flex items-center gap-1.5 cursor-pointer text-[11px]" style="color: var(--text-secondary);">
                  <input type="checkbox" v-model="cfg.enterprise_features.cloud_streaming.enabled" class="accent-blue-600" />
                  <span class="font-medium">启用</span>
                </label>
                <input v-model="cfg.enterprise_features.cloud_streaming.webhook_url" placeholder="http://127.0.0.1:9090/ingest" class="ui-input w-full px-2 py-1 font-mono text-xs" />
              </div>
            </div>
          </div>
        </div>

        <div v-else class="flex-1 flex flex-col items-center justify-center text-xs gap-2" style="color: var(--text-muted);">
          <span v-if="configLoadError" class="text-rose-600 dark:text-rose-400 font-semibold">{{ configLoadError }}</span>
          <span v-else>正在从 config.json 加载探针配置...</span>
          <button v-if="configLoadError" @click="loadConfig" class="ui-btn-primary px-3 py-1 text-xs">重试加载</button>
        </div>
      </div>

    </div>

    <!-- 三员身份切换模态框 -->
    <div v-if="showRoleModal" class="ui-modal-backdrop fixed inset-0 z-50 flex items-center justify-center p-4">
      <div class="ui-modal-surface rounded-2xl p-5 max-w-sm w-full space-y-4">
        <div class="flex items-center justify-between border-b pb-2.5" style="border-color: var(--border-subtle);">
          <h4 class="text-[13px] font-semibold" style="color: var(--text-primary);">等保三级 三员身份切换认证</h4>
          <button @click="showRoleModal = false" class="p-1 rounded-lg hover:bg-[var(--surface-hover)] cursor-pointer" style="color: var(--text-secondary);">
            <AppIcon name="close" :size="14" />
          </button>
        </div>

        <div class="space-y-3 text-xs">
          <div>
            <label class="block font-semibold mb-1" style="color: var(--text-secondary);">目标三员角色</label>
            <select v-model="targetRole" class="ui-input w-full p-2 text-xs">
              <option value="SysAdmin">系统管理员 (SysAdmin · 接口与引擎运维)</option>
              <option value="SecAdmin">安全管理员 (SecAdmin · 策略与边界管控)</option>
              <option value="AuditAdmin">安全审计员 (AuditAdmin · 日志与取证验真)</option>
            </select>
          </div>

          <div>
            <label class="block font-semibold mb-1" style="color: var(--text-secondary);">操作员授权口令</label>
            <input v-model="rolePassword" type="password" placeholder="请输入对应角色的口令" class="ui-input w-full p-2 font-mono text-xs" />
          </div>

          <div v-if="roleSwitchError" class="text-rose-600 dark:text-rose-400 text-[11px] font-semibold">
            {{ roleSwitchError }}
          </div>
        </div>

        <div class="flex justify-end gap-2 pt-2">
          <button @click="showRoleModal = false" class="ui-btn-secondary px-3 py-1.5 text-xs">取消</button>
          <button @click="confirmSwitchRole" class="ui-btn-primary px-4 py-1.5 text-xs">确认切换</button>
        </div>
      </div>
    </div>

    <!-- 司法证据链验真报告弹窗 -->
    <div v-if="showVerifyModal" class="ui-modal-backdrop fixed inset-0 z-50 flex items-center justify-center p-4">
      <div class="ui-modal-surface rounded-2xl p-5 max-w-2xl w-full space-y-4 max-h-[85vh] flex flex-col select-text">
        <div class="flex items-center justify-between border-b pb-2.5 shrink-0" style="border-color: var(--border-subtle);">
          <div class="flex items-center gap-2">
            <h4 class="text-[13px] font-semibold" style="color: var(--text-primary);">司法证据链完整性验真报告 (等保三级 8.1.4.4)</h4>
            <span
              :class="['px-2 py-0.5 rounded-full text-[11px] font-semibold',
                !verifyReport ? 'ui-pill' :
                (verifyReport.overall_status === 'PASS' ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300' :
                (verifyReport.overall_status === 'APPENDED' ? 'bg-blue-500/15 text-blue-700 dark:text-sky-300' : 'bg-rose-500/15 text-rose-700 dark:text-rose-300'))]"
            >
              {{ !verifyReport ? '待触发核验' :
                 (verifyReport.overall_status === 'PASS' ? '完全匹配通过' :
                 (verifyReport.overall_status === 'APPENDED' ? '正常追加存证' : '检测到可疑篡改')) }}
            </span>
          </div>
          <button @click="showVerifyModal = false" class="p-1 rounded-lg hover:bg-[var(--surface-hover)] cursor-pointer" style="color: var(--text-secondary);">
            <AppIcon name="close" :size="14" />
          </button>
        </div>

        <div v-if="verifyReport" class="flex-1 overflow-y-auto custom-scrollbar space-y-3 text-xs">
          <div class="ui-sub-card p-3 space-y-1" style="color: var(--text-secondary);">
            <div>核验时间: <span class="font-semibold ui-num" style="color: var(--text-primary);">{{ verifyReport.verified_at }}</span></div>
            <div>最后封存时间: <span class="font-semibold ui-num" style="color: var(--text-primary);">{{ verifyReport.last_sealed_at }}</span> (触发原因: {{ verifyReport.last_seal_reason }})</div>
            <div>核验结论: <span class="font-semibold text-indigo-600 dark:text-indigo-300">{{ verifyReport.summary }}</span></div>
          </div>

          <div class="space-y-2">
            <div v-for="item in verifyReport.items" :key="item.file_name" class="ui-sub-card p-3 space-y-1">
              <div class="flex items-center justify-between">
                <span class="font-semibold text-xs" style="color: var(--text-primary);">{{ item.file_name }}</span>
                <span
                  :class="['px-2 py-0.5 rounded font-semibold text-[11px]',
                    item.status === 'MATCH' ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300' :
                    (item.status === 'APPENDED' ? 'bg-blue-500/15 text-blue-700 dark:text-sky-300' : 'bg-rose-500/15 text-rose-700 dark:text-rose-300')]"
                >
                  {{ item.status }}
                </span>
              </div>
              <div class="text-[11px] font-mono break-all" style="color: var(--text-muted);">
                <div>封存 SHA-256: <span style="color: var(--text-secondary);">{{ item.expected_hash }}</span> ({{ item.sealed_size }} 字节)</div>
                <div>实测 SHA-256: <span style="color: var(--text-secondary);">{{ item.current_hash }}</span> ({{ item.current_size }} 字节)</div>
              </div>
              <div class="text-[11px] mt-0.5" style="color: var(--text-secondary);">{{ item.details }}</div>
            </div>
          </div>
        </div>

        <div class="flex justify-end pt-2 border-t shrink-0" style="border-color: var(--border-subtle);">
          <button @click="showVerifyModal = false" class="ui-btn-primary px-4 py-1.5 text-xs">关闭报告</button>
        </div>
      </div>
    </div>

    <!-- 修改操作口令模态框 -->
    <div v-if="showChangePwdModal" class="ui-modal-backdrop fixed inset-0 z-50 flex items-center justify-center p-4">
      <div class="ui-modal-surface rounded-2xl p-5 max-w-sm w-full space-y-4">
        <div class="flex items-center justify-between border-b pb-2.5" style="border-color: var(--border-subtle);">
          <h4 class="text-[13px] font-semibold" style="color: var(--text-primary);">修改操作员授权口令 (等保三级复杂度)</h4>
          <button @click="showChangePwdModal = false" class="p-1 rounded-lg hover:bg-[var(--surface-hover)] cursor-pointer" style="color: var(--text-secondary);">
            <AppIcon name="close" :size="14" />
          </button>
        </div>

        <div class="space-y-3 text-xs">
          <div>
            <label class="block font-semibold mb-1" style="color: var(--text-secondary);">目标角色</label>
            <div class="ui-sub-card p-2 font-semibold" style="color: var(--text-primary);">
              {{ currentUser.role_title }}
            </div>
          </div>

          <div>
            <label class="block font-semibold mb-1" style="color: var(--text-secondary);">原授权口令</label>
            <input v-model="oldPassword" type="password" placeholder="请输入当前原口令" class="ui-input w-full p-2 font-mono text-xs" />
          </div>

          <div>
            <label class="block font-semibold mb-1" style="color: var(--text-secondary);">新授权口令</label>
            <input v-model="newPassword" type="password" placeholder="至少8位，含大小写字母与数字" class="ui-input w-full p-2 font-mono text-xs" />
          </div>

          <div v-if="changePwdError" class="text-rose-600 dark:text-rose-400 text-[11px] font-semibold">{{ changePwdError }}</div>
          <div v-if="changePwdSuccess" class="text-emerald-600 dark:text-emerald-400 text-[11px] font-semibold">{{ changePwdSuccess }}</div>
        </div>

        <div class="flex justify-end gap-2 pt-2">
          <button @click="showChangePwdModal = false" class="ui-btn-secondary px-3 py-1.5 text-xs">取消</button>
          <button @click="confirmChangePassword" class="ui-btn-primary px-4 py-1.5 text-xs">确认修改并固化</button>
        </div>
      </div>
    </div>

  </div>
</template>

<script setup lang="ts">
import { notifySuccess, notifyWarning } from '../composables/useNotification';
import { uiConfirm } from '../composables/useConfirmDialog';
import { ref, computed, onMounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import AppIcon from '../components/AppIcon.vue';
import { useUniversalDiff } from '../composables/useUniversalDiff';

const diffBus = useUniversalDiff();

function addComplianceToDiffQueue(item: any) {
  const raw = `${item.clause} | ${item.level} | ${item.status} | ${item.implementation}`;
  diffBus.addToQueue({
    id: `AUDIT_CMP_${item.clause}`,
    label: `[等保条款] ${item.clause}`,
    protocol: 'DJCP-LEVEL3',
    src: item.level,
    dst: item.status,
    format: 'ASCII',
    isRawText: true,
    payloadHex: '',
    rawText: raw,
    length: raw.length,
    extraFields: {
      clause: item.clause,
      level: item.level,
      status: item.status,
      requirement: item.requirement
    }
  }, `等保 ${item.clause}`, false);
}

function addDriftToDiffQueue(ev: any) {
  const raw = `${ev.drift_type} | ${ev.src_ip} -> :${ev.dst_port} | ${ev.description}`;
  diffBus.addToQueue({
    id: `DRIFT_${ev.id}`,
    label: `[基线漂移] ${ev.drift_type} #${ev.id}`,
    timestamp: ev.timestamp,
    protocol: 'BASELINE-DRIFT',
    src: ev.src_ip,
    dst: String(ev.dst_port),
    format: 'ASCII',
    isRawText: true,
    payloadHex: '',
    rawText: raw,
    length: raw.length,
    extraFields: {
      drift_type: ev.drift_type,
      severity: ev.severity || '-',
      description: ev.description
    }
  }, `漂移 #${ev.id}`, false);
}

function addSystemLogToDiffQueue(logLine: string, idx: number) {
  diffBus.addToQueue({
    id: `SYSLOG_${idx}`,
    label: `[系统日志 #${idx + 1}]`,
    protocol: 'SYSLOG-AUDIT',
    src: 'Kernel/Audit',
    dst: 'Sentinel-Vault',
    format: 'ASCII',
    isRawText: true,
    payloadHex: '',
    rawText: logLine,
    length: logLine.length
  }, `审计日志 #${idx + 1}`, false);
}

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

const emit = defineEmits(['clearLogs', 'appendLog', 'complianceUpdated']);

interface RbacSecurityStatus {
  pending_password_change_roles: string[];
  all_credentials_hardened: boolean;
  bootstrap_credentials_file: string | null;
  algorithm: string;
  iterations: number;
  active_roles_count: number;
}

interface AuditComplianceSnapshot {
  rbac_security: RbacSecurityStatus;
  cidr_rule_count: number;
  baseline_mode: string;
  baseline_rule_count: number;
  syslog_enabled: boolean;
  syslog_configured: boolean;
  ics_acl_rule_count: number;
  has_hsm_hardware: boolean;
  admin_audit_count: number;
  level3_rate_pct: number;
  level2_rate_pct: number;
  level4_rate_pct: number;
}

const rbacSecurity = ref<RbacSecurityStatus>({
  pending_password_change_roles: ['SysAdmin', 'SecAdmin', 'AuditAdmin'],
  all_credentials_hardened: false,
  bootstrap_credentials_file: null,
  algorithm: 'PBKDF2-HMAC-SHA256',
  iterations: 100000,
  active_roles_count: 3,
});
const icsAclRuleCount = ref(0);
const hasHsmHardware = ref(false);
const pendingRoleSet = computed(() => new Set(rbacSecurity.value.pending_password_change_roles || []));

async function loadAuditSnapshot() {
  try {
    const snap = await invoke<AuditComplianceSnapshot>('get_audit_compliance_snapshot_cmd');
    rbacSecurity.value = snap.rbac_security;
    icsAclRuleCount.value = snap.ics_acl_rule_count;
    hasHsmHardware.value = snap.has_hsm_hardware;
    emit('complianceUpdated');
  } catch (e) {
    log(`[ERROR] 获取等保实测快照失败: ${e}`);
  }
}

function log(msg: string) {
  emit('appendLog', msg);
}

// 8 大子选项卡 (等保 2/3 全量覆盖)
const subTabs = [
  { id: 'compliance', label: '等保合规总览' },
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
  loadAuditSnapshot();
  if (tabId === 'rbac') {
    loadCurrentUser();
    loadAdminAuditTrail();
  } else if (tabId === 'baseline') {
    loadBaselineStatus();
    loadBaselineRules();
    loadBaselineDriftEvents();
    loadMacroCalendarStatus();
  } else if (tabId === 'zones') {
    loadCidrRules();
  } else if (tabId === 'syslog') {
    loadSyslogConfig();
  }
}

// ============================================================
// 1. 等保测评实测状态矩阵 (动态绑定真实后端配置与运行证据，绝不静态编造)
// ============================================================
interface DynamicComplianceRow {
  clause: string;
  level: string;
  levelBadge: string;
  requirement: string;
  implementation: string;
  status: string;
  statusBadge: string;
  satisfied: boolean;
}

const complianceItems = computed<DynamicComplianceRow[]>(() => {
  const hasCidr = cidrRules.value.length > 0;
  const isBaselineActive = baselineStatus.value.mode !== 'DISABLED';
  const hasBaselineRules = baselineRules.value.length > 0;
  const isEnforcingBoundary = baselineStatus.value.mode === 'ENFORCING' && hasCidr;
  const isSyslogActive = syslogCfg.value.enabled && Boolean(syslogCfg.value.server_ip);
  const verifyPassed = verifyReport.value?.overall_status === 'PASS' || verifyReport.value?.overall_status === 'APPENDED';
  const credsHardened = rbacSecurity.value.all_credentials_hardened;
  const pendingList = rbacSecurity.value.pending_password_change_roles || [];
  const hasIcsRules = icsAclRuleCount.value > 0;

  return [
    {
      clause: '8.1.1.1 身份鉴别',
      level: '二级/三级',
      levelBadge: 'bg-blue-500/15 text-blue-700 dark:text-sky-300',
      requirement: '应对登录用户进行身份标识和鉴别，消除出厂默认口令并强制复杂度校验',
      implementation: credsHardened
        ? `当前角色 (${currentUser.value.role}) · 全角色已启用 ${rbacSecurity.value.algorithm}`
        : `待首次改密加固角色: ${pendingList.join(', ') || '全部三员'}`,
      status: credsHardened ? '已加固' : '待首次改密',
      statusBadge: credsHardened ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300' : 'bg-rose-500/15 text-rose-700 dark:text-rose-300',
      satisfied: Boolean(currentUser.value.role) && credsHardened,
    },
    {
      clause: '8.1.2.1 结构安全与区域划分',
      level: '等保三级',
      levelBadge: 'bg-indigo-500/15 text-indigo-700 dark:text-indigo-300',
      requirement: '应保证网络架构的业务逻辑合理划分，生产控制、非控制与管理大区隔离',
      implementation: `已配置 ${cidrRules.value.length} 条 CIDR 掩码区域规则`,
      status: hasCidr ? '已配置' : '待划分区域',
      statusBadge: hasCidr ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300' : 'bg-amber-500/15 text-amber-700 dark:text-amber-300',
      satisfied: hasCidr,
    },
    {
      clause: '8.1.2.2 边界访问控制',
      level: '等保三级',
      levelBadge: 'bg-indigo-500/15 text-indigo-700 dark:text-indigo-300',
      requirement: '应在网络边界部署访问控制策略，限制非授权跨域通信',
      implementation: `当前基线策略模式: ${baselineStatus.value.mode} | 规则 ${cidrRules.value.length} 条`,
      status: isEnforcingBoundary ? '严格阻断中' : '观察/学习中',
      statusBadge: isEnforcingBoundary ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300' : 'bg-amber-500/15 text-amber-700 dark:text-amber-300',
      satisfied: isEnforcingBoundary,
    },
    {
      clause: '8.1.4.1 三员分立访问控制',
      level: '等保三级',
      levelBadge: 'bg-indigo-500/15 text-indigo-700 dark:text-indigo-300',
      requirement: '重构管理员权限，实现系统管理员、安全管理员、安全审计员权限与独立凭据隔离',
      implementation: credsHardened
        ? `RBAC 三员权责隔离已激活 (审计流水 ${adminAuditTrail.value.length} 条)`
        : `权限模型已挂载，尚有 ${pendingList.length} 名操作员未脱离初始化口令`,
      status: credsHardened ? '合规隔离' : '口令待加固',
      statusBadge: credsHardened ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300' : 'bg-amber-500/15 text-amber-700 dark:text-amber-300',
      satisfied: rbacSecurity.value.active_roles_count >= 3 && credsHardened,
    },
    {
      clause: '8.1.4.3 集中式日志备份',
      level: '等保三级',
      levelBadge: 'bg-indigo-500/15 text-indigo-700 dark:text-indigo-300',
      requirement: '应将所有审计记录集中备份至独立的日志服务器或 SIEM',
      implementation: isSyslogActive
        ? `RFC 5424 Syslog 外发至 ${syslogCfg.value.server_ip}:${syslogCfg.value.server_port} (${syslogCfg.value.protocol})`
        : 'Syslog 外发开关当前关闭',
      status: isSyslogActive ? '运行中' : '未启用',
      statusBadge: isSyslogActive ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300' : 'bg-rose-500/15 text-rose-700 dark:text-rose-300',
      satisfied: isSyslogActive,
    },
    {
      clause: '8.1.4.4 审计记录保护与验真',
      level: '等保三级',
      levelBadge: 'bg-indigo-500/15 text-indigo-700 dark:text-indigo-300',
      requirement: '定期对审计记录进行安全备份与司法验真，禁止非审计员处置日志',
      implementation: verifyReport.value ? `最近核验: ${verifyReport.value.verified_at} (${verifyReport.value.overall_status})` : '本次会话尚未触发司法双哈希核验',
      status: verifyPassed ? '验真通过' : '待核验',
      statusBadge: verifyPassed ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300' : 'bg-amber-500/15 text-amber-700 dark:text-amber-300',
      satisfied: verifyPassed,
    },
    {
      clause: 'G.4.2 工业通信访问控制',
      level: '工控三级扩展',
      levelBadge: 'bg-purple-500/15 text-purple-700 dark:text-purple-300',
      requirement: '在工业控制网络建立通信基线白名单，实时检测非法连接与跨域访问',
      implementation: `模式: ${baselineStatus.value.mode} | 已收敛 ${baselineRules.value.length} 条基线`,
      status: isBaselineActive && hasBaselineRules ? '基线生效' : (isBaselineActive ? '收敛待填充' : '已停用'),
      statusBadge: isBaselineActive && hasBaselineRules ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300' : 'bg-amber-500/15 text-amber-700 dark:text-amber-300',
      satisfied: isBaselineActive && hasBaselineRules,
    },
    {
      clause: 'G.4.3 工控功能码与指令审计',
      level: '工控三级扩展',
      levelBadge: 'bg-purple-500/15 text-purple-700 dark:text-purple-300',
      requirement: '对工业控制协议高危写指令（如写寄存器、下装程序）进行功能码级检测',
      implementation: hasIcsRules
        ? `ICS-ACL 细粒度规则集已载入 ${icsAclRuleCount.value} 条 · 联动 DPI/DSL 实时解析`
        : 'ICS-ACL 引擎当前规则数为 0',
      status: hasIcsRules ? '规则生效中' : '未配置规则',
      statusBadge: hasIcsRules ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300' : 'bg-amber-500/15 text-amber-700 dark:text-amber-300',
      satisfied: hasIcsRules,
    },
    {
      clause: '9.1.4.1 硬件级可信根与抗量子',
      level: '等保四级',
      levelBadge: 'bg-amber-500/15 text-amber-700 dark:text-amber-300',
      requirement: '要求采用国家密码管理局认证的硬件安全密码机 (HSM) 与物理可信计算芯片',
      implementation: hasHsmHardware.value
        ? '已检测到兼容硬件密码模块并纳入可信根验证'
        : '当前仅启用软件 SM3 + SHA-256 摘要算法，未接入物理 HSM 硬件密码卡',
      status: hasHsmHardware.value ? 'HSM 就绪' : '缺少硬件 HSM',
      statusBadge: hasHsmHardware.value ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300' : 'bg-slate-500/15 text-slate-600 dark:text-slate-300',
      satisfied: hasHsmHardware.value,
    }
  ];
});

const level3AndUnderItems = computed(() => complianceItems.value.filter((i) => !i.level.includes('四级')));
const totalAuditCount = computed(() => level3AndUnderItems.value.length);
const satisfiedCount = computed(() => level3AndUnderItems.value.filter((i) => i.satisfied).length);
const level3ComplianceRate = computed(() => {
  const total = totalAuditCount.value;
  if (total === 0) return '0.0';
  return ((satisfiedCount.value / total) * 100).toFixed(1);
});
const level2Items = computed(() => complianceItems.value.filter((i) => i.level.includes('二级') || i.clause.startsWith('8.1.4') || i.clause.startsWith('8.1.2.1')));
const level2ComplianceRate = computed(() => {
  const list = level2Items.value;
  if (list.length === 0) return '0.0';
  return ((list.filter((i) => i.satisfied).length / list.length) * 100).toFixed(1);
});
const level4Items = computed(() => complianceItems.value.filter((i) => i.level.includes('四级')));
const level4ComplianceRate = computed(() => {
  const list = level4Items.value;
  if (list.length === 0) return '0.0';
  return ((list.filter((i) => i.satisfied).length / list.length) * 100).toFixed(1);
});

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
    case 'SysAdmin': return 'text-indigo-600 dark:text-indigo-300';
    case 'SecAdmin': return 'text-emerald-600 dark:text-emerald-300';
    case 'AuditAdmin': return 'text-purple-600 dark:text-purple-300';
    default: return 'text-[var(--text-primary)]';
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
    loadAuditSnapshot();
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
    notifyWarning('等保三级安全合规拦截', `${e}。请先在顶部点击【切换身份】以安全审计员 (AuditAdmin) 身份授权验证后执行。`);
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
    loadAuditSnapshot();
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

interface DayRegimeInferenceResult {
  inferred_regime: string;
  posterior_workday_prob: number;
  log_likelihood_ratio: number;
  confidence_score: number;
  evidence_summary: string;
}
const macroCalendarStatus = ref<DayRegimeInferenceResult | null>(null);
const statutoryDateInput = ref(new Date().toISOString().slice(0, 10));
const statutoryRegimeType = ref<'HOLIDAY' | 'COMPENSATORY' | 'WORKDAY' | 'WEEKEND'>('HOLIDAY');

async function loadMacroCalendarStatus() {
  try {
    macroCalendarStatus.value = await invoke<DayRegimeInferenceResult>('get_macro_calendar_baseline_status_cmd');
  } catch (e) {
    log(`[ERROR] 获取宏观日历基线日态失败: ${e}`);
  }
}

async function submitStatutoryDate() {
  if (!statutoryDateInput.value) return;
  try {
    await invoke<boolean>('import_statutory_calendar_date_cmd', {
      dateStr: statutoryDateInput.value,
      regimeType: statutoryRegimeType.value,
    });
    log(`[MACRO-BASELINE] 已登记法定日程: ${statutoryDateInput.value} -> ${statutoryRegimeType.value}`);
    await loadMacroCalendarStatus();
  } catch (e) {
    log(`[ERROR] 登记法定日程失败: ${e}`);
  }
}

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
    loadAuditSnapshot();
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
  const confirmed = await uiConfirm(
    '确认重置所有已学习的工业通信基线白名单与漂移事件吗？此操作将记录管理员审计流。',
    { title: '确认重置通信基线', confirmText: '确认重置', danger: true }
  );
  if (!confirmed) {
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
    loadAuditSnapshot();
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
    syslogTestResult.value = `发送成功: ${res}`;
    log(`[SYSLOG] ${res}`);
    loadSyslogConfig();
  } catch (e) {
    syslogTestResult.value = `发送失败: ${e}`;
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
  loadAuditSnapshot();
  loadConfig();
  loadCurrentUser();
  loadAdminAuditTrail();
  loadBaselineStatus();
  loadBaselineRules();
  loadMacroCalendarStatus();
  loadCidrRules();
  loadSyslogConfig();
});
</script>
