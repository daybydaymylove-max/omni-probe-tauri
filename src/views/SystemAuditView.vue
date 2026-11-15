<template>
  <div class="flex-1 flex flex-col gap-2.5 overflow-hidden min-w-0">
    <!-- 顶部状态栏 (真 Liquid Glass 控制层) -->
    <div class="ui-nav-glass rounded-2xl px-4 py-2.5 flex items-center justify-between shrink-0 gap-3 flex-wrap">
      <span class="lens-edge-lip" aria-hidden="true"></span>
      <div class="flex items-center gap-3 flex-wrap">
        <h2 class="text-[13px] font-semibold flex items-center gap-2 whitespace-nowrap" style="color: var(--text-primary);">
          <AppIcon name="shield" :size="15" class="text-[var(--accent-primary)] shrink-0" />
          <span>{{ locale === 'en-US' ? 'Security Audit & Compliance Engine' : '安全审计与等保合规引擎' }}</span>
        </h2>
        <div class="h-4 w-[1px]" style="background: var(--border-strong);"></div>

        <!-- 当前三员分立身份标签与切换按钮 -->
        <div class="ui-pill rounded-xl flex items-center gap-2 px-2.5 py-1 text-xs whitespace-nowrap">
          <span style="color: var(--text-muted);">{{ locale === 'en-US' ? 'Operator:' : '操作员:' }}</span>
          <span class="font-semibold ui-num" :class="roleBadgeColor">{{ currentUser.role_title }}</span>
          <button
            @click="openSwitchRoleModal"
            class="text-[11px] text-[var(--accent-primary-text)] hover:underline font-semibold cursor-pointer ml-1"
          >
            {{ locale === 'en-US' ? 'Switch Role' : '切换身份' }}
          </button>
          <button
            @click="openChangePwdModal"
            class="text-[11px] text-[var(--text-secondary)] hover:underline font-medium cursor-pointer ml-0.5"
          >
            {{ locale === 'en-US' ? 'Change Pwd' : '改口令' }}
          </button>
        </div>

        <!-- 司法存证双核操作 -->
        <div class="flex items-center gap-1.5">
          <button @click="manualSeal" :disabled="sealing" class="ui-btn-secondary px-2.5 py-1 text-xs">
            <AppIcon v-if="sealing" name="refresh" :size="13" class="animate-spin" />
            <AppIcon v-else name="lock" :size="13" />
            <span>{{ locale === 'en-US' ? 'Legal Seal' : '司法封存' }}</span>
          </button>

          <button @click="verifyEvidenceChain" :disabled="verifying" class="ui-btn-secondary px-2.5 py-1 text-xs">
            <AppIcon v-if="verifying" name="refresh" :size="13" class="animate-spin" />
            <AppIcon v-else name="shield" :size="13" />
            <span>{{ locale === 'en-US' ? 'Verify Chain' : '链路验真' }}</span>
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
      <!-- 选项卡 1：等保 2.0 / 3.0 合规态势驾驶舱 (GB/T 22239-2019 现场核查引擎) -->
      <!-- ============================================================ -->
      <div v-if="currentTab === 'compliance'" class="h-full flex flex-col gap-3 overflow-y-auto custom-scrollbar p-4">
        <!-- 顶部视角与标准导航栏 -->
        <div class="flex items-center justify-between border-b pb-3 shrink-0 flex-wrap gap-2" style="border-color: var(--border-subtle);">
          <div>
            <h3 class="text-[13px] font-semibold flex items-center gap-2" style="color: var(--text-primary);">
              <AppIcon name="shield" :size="15" class="text-[var(--accent-primary)]" />
              <span>{{ locale === 'en-US' ? 'Cybersecurity MLPS 2.0 / 3.0 (GB/T 22239) Field Audit Console' : '网络安全等级保护 2.0 / 3.0 (GB/T 22239-2019) 现场测评核查控制台' }}</span>
              <span class="text-[10px] px-2 py-0.5 rounded-full bg-[var(--accent-primary-alpha)] text-[var(--accent-primary-text)] font-semibold border border-[var(--accent-primary-alpha)]">
                GB/T 22239-2019 / GB/T 28448-2019
              </span>
            </h3>
            <p class="text-[11px] mt-0.5" style="color: var(--text-muted);">
              {{ compliancePerspective === 'target' 
                ? (locale === 'en-US' ? 'Target Network/ICS Field MLPS Audit: Linked probe port scanning, plaintext protocol audit, whitelist and ICS function codes' : '被测目标网络/工控设备现场等保测评：联动探针端口探测、明文协议审计、通信白名单与工控功能码验证') : (locale === 'en-US' ? 'Probe Self-Defense Baseline: RBAC tri-role orthogonal isolation, PBKDF2 anti-bruteforce, SM3+SHA-256 forensics & centralized Syslog' : '探针系统自身安全防御基线：三员分立正交隔离、PBKDF2 口令防暴破、国密 SM3+SHA-256 司法存证与集中式日志外发') }}
            </p>
          </div>

          <!-- 双视角切换胶囊 -->
          <div class="glass-pill p-1 rounded-xl text-xs font-semibold flex items-center gap-1">
            <button
              @click="compliancePerspective = 'target'"
              :class="['px-3 py-1 rounded-lg transition-all cursor-pointer text-[11px] flex items-center gap-1.5',
                compliancePerspective === 'target' ? 'bg-[var(--accent-primary)] text-white shadow-xs' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]']"
            >
              <AppIcon name="target" :size="12" />
              <span>{{ locale === 'en-US' ? 'Target Network Field Audit' : '被测目标网络现场等保测评' }}</span>
            </button>
            <button
              @click="compliancePerspective = 'probe_self'"
              :class="['px-3 py-1 rounded-lg transition-all cursor-pointer text-[11px] flex items-center gap-1.5',
                compliancePerspective === 'probe_self' ? 'bg-[var(--accent-primary)] text-white shadow-xs' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]']"
            >
              <AppIcon name="shield" :size="12" />
              <span>{{ locale === 'en-US' ? 'Probe Self-Defense Baseline' : '探针自身安全防御基线' }}</span>
            </button>
          </div>
        </div>

        <!-- ========================================================== -->
        <!-- 视角 A: 被测目标网络/工控系统现场等保测评 (实战核心) -->
        <!-- ========================================================== -->
        <template v-if="compliancePerspective === 'target'">
          <!-- 目标配置与探活控制栏 -->
          <div class="ui-sub-card p-3 rounded-xl flex items-center justify-between gap-3 flex-wrap">
            <div class="flex items-center gap-3 flex-wrap flex-1 min-w-[280px]">
              <div class="flex items-center gap-1.5 text-xs">
                <span class="font-semibold whitespace-nowrap" style="color: var(--text-secondary);">{{ locale === 'en-US' ? 'Target IP:' : '被测目标 IP:' }}</span>
                <input
                  v-model="targetAssessment.targetIp.value"
                  type="text"
                  :placeholder="locale === 'en-US' ? 'e.g. 192.168.1.1 or 10.0.0.1' : '如 192.168.1.1 或 10.0.0.1'"
                  class="ui-input px-2.5 py-1 text-xs font-mono w-40"
                />
              </div>

              <div class="flex items-center gap-1.5 text-xs">
                <span class="font-semibold whitespace-nowrap" style="color: var(--text-secondary);">{{ locale === 'en-US' ? 'Baseline Level:' : '测评基准等级:' }}</span>
                <select
                  v-model="targetAssessment.targetLevel.value"
                  class="ui-input px-2.5 py-1 text-xs"
                >
                  <option value="等保二级 (GB/T 22239-2019 第7章)">{{ locale === 'en-US' ? 'MLPS Level 2 (GB/T 22239 Ch.7)' : '等保二级 (Level 2 · 第7章)' }}</option>
                  <option value="等保三级 (GB/T 22239-2019 第8章)">{{ locale === 'en-US' ? 'MLPS Level 3 (GB/T 22239 Ch.8)' : '等保三级 (Level 3 · 第8章)' }}</option>
                  <option value="工控系统扩展附录 G (ICS)">{{ locale === 'en-US' ? 'ICS Security Extension (App. G)' : '工控系统安全扩展 (附录 G - ICS)' }}</option>
                  <option value="云计算安全扩展附录 E (Cloud)">{{ locale === 'en-US' ? 'Cloud Security Extension (App. E)' : '云计算安全扩展 (附录 E - Cloud)' }}</option>
                  <option value="物联网安全扩展附录 F (IoT)">{{ locale === 'en-US' ? 'IoT Security Extension (App. F)' : '物联网安全扩展 (附录 F - IoT)' }}</option>
                </select>
              </div>

              <!-- 快捷载入本地网关/已发现资产 -->
              <button
                @click="quickSelectGatewayAsTarget"
                class="ui-btn-secondary px-2.5 py-1 text-[11px]"
                :title="locale === 'en-US' ? 'Quick load LAN gateway or active assets as audit target' : '快捷载入局域网网关或活跃资产作为被测目标'"
              >
                <AppIcon name="refresh" :size="11" />
                <span>{{ locale === 'en-US' ? 'Load Gateway/Assets' : '载入网关/资产' }}</span>
              </button>
            </div>

            <div class="flex items-center gap-2 flex-wrap">
              <button
                @click="openDeviceConfigModal"
                class="ui-btn-secondary px-3 py-1.5 text-xs font-semibold flex items-center gap-1.5"
                :title="locale === 'en-US' ? 'Import switch/router/firewall config text for MLPS baseline check and inject evidence' : '导入交换机/路由器/防火墙配置文本进行等保基线核查并注入证据'"
              >
                <AppIcon name="cpu" :size="13" />
                <span>{{ locale === 'en-US' ? 'Device Config Audit' : '设备配置核查' }}</span>
              </button>

              <button
                @click="runHostBaselineAudit"
                :disabled="isAuditingHostBaseline"
                class="ui-btn-secondary px-3 py-1.5 text-xs font-semibold flex items-center gap-1.5"
                :title="locale === 'en-US' ? 'Audit host GB/T 22239 Secure Computing Environment (SCE) auth, password, lockout & timeout' : '一键对当前主机进行 GB/T 22239 安全计算环境 (SCE) 身份鉴别、口令、锁定、超时实测'"
              >
                <AppIcon v-if="isAuditingHostBaseline" name="refresh" :size="13" class="animate-spin" />
                <AppIcon v-else name="shield" :size="13" />
                <span>{{ isAuditingHostBaseline ? (locale === 'en-US' ? 'Auditing Host...' : '主机核查中...') : (locale === 'en-US' ? 'Deep Host Baseline Audit' : '主机基线深度核查') }}</span>
              </button>

              <button
                @click="runProbeComplianceScan"
                :disabled="targetAssessment.isProbing.value"
                class="ui-btn-primary px-3 py-1.5 text-xs font-semibold flex items-center gap-1.5"
              >
                <AppIcon v-if="targetAssessment.isProbing.value" name="refresh" :size="13" class="animate-spin" />
                <AppIcon v-else name="search" :size="13" />
                <span>{{ targetAssessment.isProbing.value ? (locale === 'en-US' ? 'Probing...' : '现场探活中...') : (locale === 'en-US' ? 'Start Field Probe Audit' : '启动探针现场探活核查') }}</span>
              </button>

              <button
                @click="openExportReportModal"
                class="ui-btn-secondary px-3 py-1.5 text-xs font-semibold flex items-center gap-1.5"
              >
                <AppIcon name="file" :size="13" />
                <span>{{ locale === 'en-US' ? 'Export GB Report (MD)' : '导出 GB 测评报告 (MD)' }}</span>
              </button>

              <button
                @click="targetAssessment.resetToDefault"
                class="p-1.5 rounded-lg hover:bg-[var(--surface-hover)] text-[var(--text-muted)] hover:text-[var(--text-primary)] cursor-pointer"
                :title="locale === 'en-US' ? 'Reset field assessment data to initial baseline' : '重置现场测评数据为初始基线'"
              >
                <AppIcon name="refresh" :size="13" />
              </button>
            </div>
          </div>

          <!-- 探活即时状态提示条 (如果有) -->
          <div
            v-if="targetAssessment.probeStatusMessage.value"
            class="px-3 py-1.5 rounded-lg text-[11px] ui-num flex items-center justify-between border"
            :class="targetAssessment.isProbing.value ? 'bg-sky-500/10 border-sky-500/25 text-sky-700 dark:text-sky-300' : 'bg-emerald-500/10 border-emerald-500/25 text-emerald-700 dark:text-emerald-300'"
          >
            <span class="flex items-center gap-1.5">
              <AppIcon :name="targetAssessment.isProbing.value ? 'refresh' : 'check'" :size="12" :class="{ 'animate-spin': targetAssessment.isProbing.value }" />
              <span>{{ targetAssessment.probeStatusMessage.value }}</span>
            </span>
            <span class="text-[10px] text-[var(--text-muted)]">{{ locale === 'en-US' ? 'Evidence chain auto-injected' : '证据链已自动注入' }}</span>
          </div>

          <!-- 等保测评核心指标综合看板 -->
          <div class="grid grid-cols-1 md:grid-cols-3 gap-3 shrink-0">
            <!-- 综合符合率卡片 -->
            <div class="bg-indigo-500/8 p-3.5 rounded-xl border border-indigo-500/25 flex flex-col justify-between">
              <div class="flex items-center justify-between">
                <span class="text-xs font-semibold text-indigo-700 dark:text-indigo-300">{{ locale === 'en-US' ? 'Overall Compliance Rate (GB/T 22239)' : '现场综合符合率 (GB/T 22239)' }}</span>
                <span class="px-2 py-0.5 rounded-full bg-indigo-600 text-white ui-num font-semibold text-[11px]">
                  {{ targetAssessment.metrics.value.overallScorePct }}%
                </span>
              </div>
              <div class="w-full bg-indigo-500/20 rounded-full h-1.5 mt-2.5 overflow-hidden">
                <div class="bg-indigo-600 h-1.5 rounded-full transition-all" :style="{ width: targetAssessment.metrics.value.overallScorePct + '%' }"></div>
              </div>
              <div class="flex items-center justify-between text-[11px] mt-2.5 ui-num text-[var(--text-secondary)]">
                <span class="text-emerald-700 dark:text-emerald-300">{{ locale === 'en-US' ? 'Compliant: ' : '符合: ' }}{{ targetAssessment.metrics.value.compliantCount }}</span>
                <span class="text-amber-700 dark:text-amber-300">{{ locale === 'en-US' ? 'Partial: ' : '部分符合: ' }}{{ targetAssessment.metrics.value.partialCount }}</span>
                <span class="text-rose-700 dark:text-rose-300">{{ locale === 'en-US' ? 'Non-compliant: ' : '不符合: ' }}{{ targetAssessment.metrics.value.nonCompliantCount }}</span>
                <span class="text-[var(--text-muted)]">{{ locale === 'en-US' ? 'Pending: ' : '待核验: ' }}{{ targetAssessment.metrics.value.pendingCount }}</span>
              </div>
            </div>

            <!-- 控制域分类达标卡片 (5大类) -->
            <div class="bg-slate-500/8 p-3.5 rounded-xl border border-[var(--border-subtle)] col-span-1 md:col-span-2">
              <div class="flex items-center justify-between mb-2">
                <span class="text-xs font-semibold" style="color: var(--text-primary);">{{ locale === 'en-US' ? '5 Security Control Domains Compliance Distribution' : '五大安全控制域实测达标分布' }}</span>
                <span class="text-[11px] ui-num" style="color: var(--text-muted);">{{ locale === 'en-US' ? `Total ${targetAssessment.metrics.value.totalCount} clauses` : `共 ${targetAssessment.metrics.value.totalCount} 项实测条款` }}</span>
              </div>
              <div class="grid grid-cols-2 sm:grid-cols-5 gap-2 text-xs ui-num">
                <div
                  v-for="cat in targetAssessment.metrics.value.categories"
                  :key="cat.category"
                  class="p-2 rounded-lg ui-sub-card border flex flex-col justify-between"
                  style="border-color: var(--border-subtle);"
                >
                  <div class="text-[11px] font-semibold truncate" :title="cat.label" style="color: var(--text-secondary);">
                    {{ cat.category }} · {{ cat.label.slice(0, 4) }}
                  </div>
                  <div class="text-sm font-bold mt-1 text-[var(--accent-primary-text)]">
                    {{ cat.scorePct }}%
                  </div>
                  <div class="text-[10px] text-[var(--text-muted)] mt-0.5">
                    {{ cat.compliant }}/{{ cat.total - cat.na }} {{ locale === 'en-US' ? 'compliant' : '项符合' }}
                  </div>
                </div>
              </div>
            </div>
          </div>

          <!-- 控制域筛选与状态过滤 Tab -->
          <div class="flex items-center justify-between gap-2 flex-wrap border-b pb-2 shrink-0" style="border-color: var(--border-subtle);">
            <!-- 控制域分类过滤 -->
            <div class="glass-pill p-0.5 rounded-xl text-xs font-medium flex flex-wrap gap-0.5">
              <button
                @click="targetAssessment.activeCategoryFilter.value = 'ALL'"
                :class="['px-2.5 py-1 rounded-lg transition-all cursor-pointer text-[11px]',
                  targetAssessment.activeCategoryFilter.value === 'ALL' ? 'bg-[var(--accent-primary)] text-white shadow-xs font-semibold' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]']"
              >
                {{ locale === 'en-US' ? 'All Domains' : '全部控制域' }} ({{ targetAssessment.metrics.value.totalCount }})
              </button>
              <button
                v-for="cat in targetAssessment.metrics.value.categories"
                :key="'filter-' + cat.category"
                @click="targetAssessment.activeCategoryFilter.value = cat.category"
                :class="['px-2 py-1 rounded-lg transition-all cursor-pointer text-[11px]',
                  targetAssessment.activeCategoryFilter.value === cat.category ? 'bg-[var(--accent-primary)] text-white shadow-xs font-semibold' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]']"
              >
                {{ cat.label.slice(0, 6) }} ({{ cat.total }})
              </button>
            </div>

            <!-- 状态过滤 (只看缺陷项等) -->
            <div class="flex items-center gap-1 text-xs">
              <span class="text-[11px]" style="color: var(--text-muted);">{{ locale === 'en-US' ? 'Status Filter:' : '状态筛选:' }}</span>
              <select
                v-model="targetAssessment.activeStatusFilter.value"
                class="ui-input px-2 py-0.5 text-[11px]"
              >
                <option value="ALL">{{ locale === 'en-US' ? 'All Statuses' : '全部状态' }}</option>
                <option value="DEFECTS">{{ locale === 'en-US' ? '⚠️ Defect Items Only (Non/Partial)' : '⚠️ 仅看缺陷项 (不符合/部分符合)' }}</option>
                <option value="PENDING">{{ locale === 'en-US' ? '⏳ Pending Verification Only' : '⏳ 仅看待核验项' }}</option>
                <option value="COMPLIANT">{{ locale === 'en-US' ? '✅ Compliant Only' : '✅ 仅看已符合项' }}</option>
                <option value="NON_COMPLIANT">{{ locale === 'en-US' ? '❌ Non-compliant Only' : '❌ 仅看不符合项' }}</option>
              </select>
            </div>
          </div>

          <!-- GB/T 22239-2019 现场实测核查矩阵表格 -->
          <div class="flex-1 overflow-auto custom-scrollbar border rounded-xl" style="border-color: var(--border-subtle); background: var(--surface-content-alt);">
            <table class="w-full text-left text-xs border-collapse">
              <thead class="ui-table-head sticky top-0 z-10 select-none">
                <tr>
                  <th class="p-2.5 whitespace-nowrap w-28">{{ locale === 'en-US' ? 'Standard Clause' : '标准条款' }}</th>
                  <th class="p-2.5 whitespace-nowrap w-36">{{ locale === 'en-US' ? 'Control Item' : '控制项名称' }}</th>
                  <th class="p-2.5">{{ locale === 'en-US' ? 'Standard Requirement' : '国家标准要求原文' }}</th>
                  <th class="p-2.5">{{ locale === 'en-US' ? 'Field Probe Evidence Chain' : '探针现场实测证据链' }}</th>
                  <th class="p-2.5 text-center whitespace-nowrap w-28">{{ locale === 'en-US' ? 'Verdict' : '符合性判定' }}</th>
                  <th class="p-2.5 text-center whitespace-nowrap w-28">{{ locale === 'en-US' ? 'Action' : '操作' }}</th>
                </tr>
              </thead>
              <tbody class="divide-y" style="border-color: var(--border-subtle);">
                <tr
                  v-for="item in targetAssessment.filteredItems.value"
                  :key="item.id"
                  class="hover:bg-[var(--surface-hover)] transition-colors"
                >
                  <td class="p-2.5 font-mono text-[11px] whitespace-nowrap">
                    <span class="font-bold text-[var(--accent-primary-text)]">[{{ item.id }}]</span>
                    <div class="text-[10px] text-[var(--text-muted)] truncate max-w-[120px]" :title="item.clause">{{ item.clause.replace('GB/T 22239-2019 ', '') }}</div>
                  </td>
                  <td class="p-2.5 font-semibold" style="color: var(--text-primary);">
                    <div>{{ item.title }}</div>
                    <span class="inline-block mt-0.5 px-1.5 py-0.2 rounded text-[10px] font-normal ui-pill" style="color: var(--text-muted);">
                      {{ item.categoryLabel }}
                    </span>
                  </td>
                  <td class="p-2.5 max-w-xs text-[11px] leading-relaxed" style="color: var(--text-secondary);" :title="item.requirement">
                    {{ item.requirement }}
                  </td>
                  <td class="p-2.5 text-[11px] leading-relaxed">
                    <div
                      class="p-1.5 rounded-lg font-mono text-[11px] break-all border"
                      :class="item.status === 'NON_COMPLIANT' ? 'bg-rose-500/10 border-rose-500/25 text-rose-700 dark:text-rose-300' :
                        (item.status === 'PARTIAL' ? 'bg-amber-500/10 border-amber-500/25 text-amber-700 dark:text-amber-300' :
                        (item.status === 'COMPLIANT' ? 'bg-emerald-500/10 border-emerald-500/25 text-emerald-700 dark:text-emerald-300' : 'bg-[var(--surface-input)] border-transparent text-[var(--text-muted)]'))"
                    >
                      {{ item.evidence }}
                    </div>
                  </td>
                  <td class="p-2.5 text-center whitespace-nowrap">
                    <select
                      :value="item.status"
                      @change="(e) => targetAssessment.updateItemStatus(item.id, (e.target as HTMLSelectElement).value as any)"
                      class="px-2 py-1 rounded-md text-[11px] font-semibold border cursor-pointer"
                      :class="item.status === 'COMPLIANT' ? 'bg-emerald-500/15 border-emerald-500/35 text-emerald-700 dark:text-emerald-300' :
                        (item.status === 'PARTIAL' ? 'bg-amber-500/15 border-amber-500/35 text-amber-700 dark:text-amber-300' :
                        (item.status === 'NON_COMPLIANT' ? 'bg-rose-500/15 border-rose-500/35 text-rose-700 dark:text-rose-300' :
                        (item.status === 'NA' ? 'bg-slate-500/15 border-slate-500/35 text-slate-600 dark:text-slate-400' : 'bg-blue-500/15 border-blue-500/35 text-blue-700 dark:text-sky-300')))"
                    >
                      <option value="COMPLIANT">{{ locale === 'en-US' ? '✅ Compliant' : '✅ 符合' }}</option>
                      <option value="PARTIAL">{{ locale === 'en-US' ? '⚠️ Partially Compliant' : '⚠️ 部分符合' }}</option>
                      <option value="NON_COMPLIANT">{{ locale === 'en-US' ? '❌ Non-compliant' : '❌ 不符合' }}</option>
                      <option value="NA">{{ locale === 'en-US' ? '⚪ Not Applicable' : '⚪ 不适用' }}</option>
                      <option value="PENDING">{{ locale === 'en-US' ? '⏳ Pending Verification' : '⏳ 待核验' }}</option>
                    </select>
                  </td>
                  <td class="p-2.5 text-center whitespace-nowrap space-x-1">
                    <button
                      @click="openEditEvidenceModal(item)"
                      class="px-2 py-0.5 rounded-lg bg-[var(--surface-input)] hover:bg-[var(--surface-hover)] border border-[var(--border-subtle)] text-[11px] font-medium cursor-pointer"
                      :title="locale === 'en-US' ? 'Fine-tune field evidence' : '手动微调现场实测证据与整改建议'"
                    >
                      {{ locale === 'en-US' ? 'Edit Evidence' : '编辑证据' }}
                    </button>
                    <button
                      @click="addComplianceToDiffQueue(item)"
                      class="px-2 py-0.5 rounded-lg bg-emerald-500/12 hover:bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border border-emerald-500/25 text-[11px] font-semibold cursor-pointer"
                      :title="locale === 'en-US' ? 'Enqueue to diff' : '加入多组基线条款比对工作台'"
                    >
                      {{ locale === 'en-US' ? '+ Enqueue' : '+ 入队' }}
                    </button>
                  </td>
                </tr>
                <tr v-if="targetAssessment.filteredItems.value.length === 0">
                  <td colspan="6" class="p-8 text-center text-xs" style="color: var(--text-muted);">
                    {{ locale === 'en-US' ? 'No assessment clauses match current filters' : '暂无符合筛选条件的测评条款' }}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </template>

        <!-- ========================================================== -->
        <!-- 视角 B: 探针自身安全防御基线 (设备内生安全合规保障) -->
        <!-- ========================================================== -->
        <template v-else>
          <div class="px-3.5 py-2.5 rounded-xl border border-indigo-500/25 bg-indigo-500/8 flex items-center justify-between gap-3 shrink-0 flex-wrap">
            <div class="text-[11.5px] leading-relaxed" style="color: var(--text-primary);">
              <span class="font-semibold text-indigo-700 dark:text-indigo-300">{{ locale === 'en-US' ? 'Probe Intrinsic Security Principle:' : '探针内生安全准则：' }}</span>
              <span>{{ locale === 'en-US' ? 'As cybersecurity field assessment equipment, probe must meet strict anti-tampering, anti-abuse and non-repudiation baselines to ensure legal validity of audit data.' : '探针作为网络安全现场测评作业装备，自身必须满足严密的防篡改、防滥用与抗抵赖存证基线，确保测评数据法律有效性。' }}</span>
            </div>
            <div class="flex items-center gap-2">
              <button @click="changeTab('rbac')" class="ui-btn-secondary px-2.5 py-1 text-[11px]">{{ locale === 'en-US' ? 'Config RBAC Tri-Role' : '配置三员分立' }}</button>
              <button @click="changeTab('syslog')" class="ui-btn-secondary px-2.5 py-1 text-[11px]">{{ locale === 'en-US' ? 'Config Syslog' : '配置 Syslog' }}</button>
            </div>
          </div>

          <!-- 等保等级符合度实测指标卡片 (原探针自身指标) -->
          <div class="grid grid-cols-1 md:grid-cols-3 gap-3 shrink-0">
            <div class="bg-emerald-500/8 p-3.5 rounded-xl border border-emerald-500/25">
              <div class="flex items-center justify-between">
                <span class="text-xs font-semibold text-emerald-700 dark:text-emerald-300">{{ locale === 'en-US' ? 'Probe Level 2 Baseline (Operational)' : '探针二级基线 (Level 2 · 运行实测)' }}</span>
                <span class="px-2 py-0.5 rounded-full bg-emerald-600 text-white ui-num font-semibold text-[11px]">{{ level2ComplianceRate }}% {{ locale === 'en-US' ? 'Ready' : '就绪' }}</span>
              </div>
              <div class="w-full bg-emerald-500/20 rounded-full h-1.5 mt-2.5 overflow-hidden">
                <div class="bg-emerald-600 h-1.5 rounded-full transition-all" :style="{ width: level2ComplianceRate + '%' }"></div>
              </div>
              <p class="text-[11px] text-emerald-700 dark:text-emerald-300 mt-2 ui-num">
                {{ locale === 'en-US' ? `Based on active controls (${satisfiedCount}/${totalAuditCount} controls active)` : `基于当前已配置项 (${satisfiedCount}/${totalAuditCount} 项核心控制点已激活)` }}
              </p>
            </div>

            <div class="bg-blue-500/8 p-3.5 rounded-xl border border-blue-500/25">
              <div class="flex items-center justify-between">
                <span class="text-xs font-semibold text-blue-700 dark:text-sky-300">{{ locale === 'en-US' ? 'Probe Level 3 Baseline (Operational)' : '探针三级基线 (Level 3 · 运行实测)' }}</span>
                <span class="px-2 py-0.5 rounded-full bg-blue-600 text-white ui-num font-semibold text-[11px]">{{ level3ComplianceRate }}% {{ locale === 'en-US' ? 'Ready' : '就绪' }}</span>
              </div>
              <div class="w-full bg-blue-500/20 rounded-full h-1.5 mt-2.5 overflow-hidden">
                <div class="bg-blue-600 h-1.5 rounded-full transition-all" :style="{ width: level3ComplianceRate + '%' }"></div>
              </div>
              <p class="text-[11px] text-blue-700 dark:text-sky-300 mt-2 ui-num">
                {{ syslogCfg.enabled ? (locale === 'en-US' ? 'Syslog Enabled' : 'Syslog 已启用') : (locale === 'en-US' ? 'Syslog Disabled' : 'Syslog 未启用') }} · {{ locale === 'en-US' ? `CIDR ${cidrRules.length} rules` : `CIDR ${cidrRules.length} 条` }} · {{ locale === 'en-US' ? `Baseline ${baselineRules.length} rules` : `基线 ${baselineRules.length} 条` }}
              </p>
            </div>

            <div class="bg-amber-500/8 p-3.5 rounded-xl border border-amber-500/25">
              <div class="flex items-center justify-between">
                <span class="text-xs font-semibold" style="color: var(--text-primary);">{{ locale === 'en-US' ? 'Hardware HSM (Level 4 · Physical RoT)' : '硬件密码卡 (Level 4 · 物理可信根)' }}</span>
                <span class="px-2 py-0.5 rounded-full bg-amber-600 text-white ui-num font-semibold text-[11px]">
                  {{ hasHsmHardware ? `${level4ComplianceRate}% ${locale === 'en-US' ? 'Ready' : '就绪'}` : `${level4ComplianceRate}% · ${locale === 'en-US' ? 'No Physical HSM' : '无物理 HSM'}` }}
                </span>
              </div>
              <div class="w-full bg-amber-500/20 rounded-full h-1.5 mt-2.5 overflow-hidden">
                <div class="bg-amber-500 h-1.5 rounded-full transition-all" :style="{ width: level4ComplianceRate + '%' }"></div>
              </div>
              <p class="text-[11px] mt-2" style="color: var(--text-secondary);">
                {{ hasHsmHardware ? (locale === 'en-US' ? 'Certified physical HSM hardware module attached' : '已接入认证级物理 HSM 硬件密码卡') : (locale === 'en-US' ? 'Software SM3 + SHA-256 + PBKDF2 active; physical HSM not attached' : '当前仅启用软件 SM3 + SHA-256 + PBKDF2 摘要，硬件 HSM 未接入') }}
              </p>
            </div>
          </div>

          <!-- 详细测评项检查矩阵表格 (探针自身) -->
          <div class="flex-1 overflow-auto custom-scrollbar border rounded-xl" style="border-color: var(--border-subtle); background: var(--surface-content-alt);">
            <table class="w-full text-left text-xs border-collapse">
              <thead class="ui-table-head sticky top-0 z-10 select-none">
                <tr>
                  <th class="p-2.5">{{ locale === 'en-US' ? 'Standard Clause' : '测评项标准条款' }}</th>
                  <th class="p-2.5 whitespace-nowrap w-32">{{ locale === 'en-US' ? 'MLPS Level' : '对应等保等级' }}</th>
                  <th class="p-2.5">{{ locale === 'en-US' ? 'Security Requirement' : '安全控制要求' }}</th>
                  <th class="p-2.5">{{ locale === 'en-US' ? 'Probe Implementation' : '探针系统实现程度' }}</th>
                  <th class="p-2.5 text-center whitespace-nowrap">{{ locale === 'en-US' ? 'Compliance Status' : '符合状态' }}</th>
                  <th class="p-2.5 text-center whitespace-nowrap w-20">{{ locale === 'en-US' ? 'Compare' : '比对' }}</th>
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
                    <button @click="addComplianceToDiffQueue(item)" class="px-2 py-0.5 rounded-lg bg-emerald-500/12 hover:bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border border-emerald-500/25 text-[11px] font-semibold cursor-pointer" :title="locale === 'en-US' ? 'Enqueue to diff' : '加入多组基线条款比对队列'">
                      {{ locale === 'en-US' ? '+ Enqueue' : '+ 入队' }}
                    </button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </template>
      </div>

      <!-- ============================================================ -->
      <!-- 选项卡 2：三员分立访问控制与操作审计追踪 (RBAC) -->
      <!-- ============================================================ -->
      <div v-else-if="currentTab === 'rbac'" class="h-full flex flex-col gap-3 overflow-hidden p-4">
        <div class="flex items-center justify-between border-b pb-3 shrink-0 flex-wrap gap-2" style="border-color: var(--border-subtle);">
          <div>
            <h3 class="text-[13px] font-semibold" style="color: var(--text-primary);">{{ locale === 'en-US' ? 'MLPS Level 3 (8.1.4.1/8.1.4.4) RBAC Tri-Role Access Control & Audit Chain' : '等保三级 (8.1.4.1/8.1.4.4) 三员分立访问控制与管理审计链' }}</h3>
            <p class="text-[11px] mt-0.5" style="color: var(--text-muted);">{{ locale === 'en-US' ? 'SysAdmin, SecAdmin, and AuditAdmin privileges orthogonally isolated; no role can tamper with forensic evidence' : '系统管理员、安全管理员、安全审计员权限正交隔离；禁止任何角色物理篡改审计存证' }}</p>
          </div>
          <button @click="loadAdminAuditTrail" class="ui-btn-secondary px-3 py-1 text-xs">
            <AppIcon name="refresh" :size="13" />
            <span>{{ locale === 'en-US' ? 'Refresh Audit Chain' : '刷新审计链' }}</span>
          </button>
        </div>

        <!-- 首次初始化待改密与一次性本地凭单提醒（绝不在前端展示任何明文口令） -->
        <div
          v-if="!rbacSecurity.all_credentials_hardened"
          class="px-3.5 py-2.5 rounded-xl border border-amber-500/35 bg-amber-500/10 flex items-center justify-between gap-3 shrink-0 flex-wrap"
        >
          <div class="text-[11.5px] leading-relaxed" style="color: var(--text-primary);">
            <span class="font-semibold text-amber-700 dark:text-amber-300">{{ locale === 'en-US' ? 'Security Hardening Notice:' : '安全加固提示：' }}</span>
            <span>{{ locale === 'en-US' ? `Roles ${rbacSecurity.pending_password_change_roles.join(', ')} have not updated to high-entropy passwords.` : `角色 ${rbacSecurity.pending_password_change_roles.join('、')} 尚未完成高强度口令更新。` }}</span>
            <span v-if="rbacSecurity.bootstrap_credentials_file" class="ui-num" style="color: var(--text-secondary);">
              {{ locale === 'en-US' ? 'One-time bootstrap credentials path: ' : '一次性初始凭单路径: ' }}<code class="px-1.5 py-0.5 rounded bg-[var(--surface-input)]">{{ rbacSecurity.bootstrap_credentials_file }}</code>{{ locale === 'en-US' ? ' (destroyed upon password update)' : '（改密完成后自动销毁）' }}
            </span>
          </div>
          <button @click="openChangePwdModal" class="ui-btn-primary px-3 py-1 text-[11px] shrink-0">
            {{ locale === 'en-US' ? 'Harden Current Role Password' : '立即加固当前角色口令' }}
          </button>
        </div>

        <!-- 三员分立身份现状卡片 -->
        <div class="grid grid-cols-1 md:grid-cols-3 gap-3 shrink-0">
          <div :class="['p-3.5 rounded-xl border transition-all', currentUser.role === 'SysAdmin' ? 'bg-indigo-500/12 border-indigo-500/40' : 'ui-sub-card']">
            <div class="flex items-center justify-between">
              <span class="font-semibold text-xs" style="color: var(--text-primary);">{{ locale === 'en-US' ? 'System Administrator (SysAdmin)' : '系统管理员 (SysAdmin)' }}</span>
              <span v-if="currentUser.role === 'SysAdmin'" class="px-2 py-0.5 rounded-full bg-indigo-600 text-white text-[11px] font-semibold">{{ locale === 'en-US' ? 'Current Session' : '当前会话' }}</span>
            </div>
            <p class="text-[11px] mt-1 ui-num" :class="pendingRoleSet.has('SysAdmin') ? 'text-amber-600 dark:text-amber-400 font-semibold' : 'text-emerald-600 dark:text-emerald-400'">
              {{ pendingRoleSet.has('SysAdmin') ? (locale === 'en-US' ? 'Status: Pending First Hardening' : '状态: 待首次改密加固') : (locale === 'en-US' ? `Auth: ${rbacSecurity.algorithm} (${rbacSecurity.iterations.toLocaleString()} iters)` : `鉴权: ${rbacSecurity.algorithm} (${rbacSecurity.iterations.toLocaleString()}轮)`) }}
            </p>
            <div class="mt-2 text-[11px] space-y-1" style="color: var(--text-secondary);">
              <div>• {{ locale === 'en-US' ? 'Hardware physical bus config (NIC/Serial/USB)' : '硬件物理接口配置 (网卡/串口/USB)' }}</div>
              <div>• {{ locale === 'en-US' ? 'Probe capture start/stop control' : '探针引擎抓包/停止控制' }}</div>
              <div>• {{ locale === 'en-US' ? 'Storage path & disk persistence config' : '数据落盘与存储路径配置' }}</div>
            </div>
          </div>

          <div :class="['p-3.5 rounded-xl border transition-all', currentUser.role === 'SecAdmin' ? 'bg-emerald-500/12 border-emerald-500/40' : 'ui-sub-card']">
            <div class="flex items-center justify-between">
              <span class="font-semibold text-xs" style="color: var(--text-primary);">{{ locale === 'en-US' ? 'Security Administrator (SecAdmin)' : '安全管理员 (SecAdmin)' }}</span>
              <span v-if="currentUser.role === 'SecAdmin'" class="px-2 py-0.5 rounded-full bg-emerald-600 text-white text-[11px] font-semibold">{{ locale === 'en-US' ? 'Current Session' : '当前会话' }}</span>
            </div>
            <p class="text-[11px] mt-1 ui-num" :class="pendingRoleSet.has('SecAdmin') ? 'text-amber-600 dark:text-amber-400 font-semibold' : 'text-emerald-600 dark:text-emerald-400'">
              {{ pendingRoleSet.has('SecAdmin') ? (locale === 'en-US' ? 'Status: Pending First Hardening' : '状态: 待首次改密加固') : (locale === 'en-US' ? `Auth: ${rbacSecurity.algorithm} (${rbacSecurity.iterations.toLocaleString()} iters)` : `鉴权: ${rbacSecurity.algorithm} (${rbacSecurity.iterations.toLocaleString()}轮)`) }}
            </p>
            <div class="mt-2 text-[11px] space-y-1" style="color: var(--text-secondary);">
              <div>• {{ locale === 'en-US' ? 'OT baseline whitelist self-learning mode switch' : '工业通信基线白名单自学习模式切换' }}</div>
              <div>• {{ locale === 'en-US' ? 'Security zones & CIDR subnet access rules' : '安全域划分与 CIDR 网段访问控制规则' }}</div>
              <div>• {{ locale === 'en-US' ? 'Threat rate limiting & active honeypot config' : '威胁防御限流与主动诱捕蜜罐配置' }}</div>
            </div>
          </div>

          <div :class="['p-3.5 rounded-xl border transition-all', currentUser.role === 'AuditAdmin' ? 'bg-purple-500/12 border-purple-500/40' : 'ui-sub-card']">
            <div class="flex items-center justify-between">
              <span class="font-semibold text-xs" style="color: var(--text-primary);">{{ locale === 'en-US' ? 'Security Auditor (AuditAdmin)' : '安全审计员 (AuditAdmin)' }}</span>
              <span v-if="currentUser.role === 'AuditAdmin'" class="px-2 py-0.5 rounded-full bg-purple-600 text-white text-[11px] font-semibold">{{ locale === 'en-US' ? 'Current Session' : '当前会话' }}</span>
            </div>
            <p class="text-[11px] mt-1 ui-num" :class="pendingRoleSet.has('AuditAdmin') ? 'text-amber-600 dark:text-amber-400 font-semibold' : 'text-emerald-600 dark:text-emerald-400'">
              {{ pendingRoleSet.has('AuditAdmin') ? (locale === 'en-US' ? 'Status: Pending First Hardening' : '状态: 待首次改密加固') : (locale === 'en-US' ? `Auth: ${rbacSecurity.algorithm} (${rbacSecurity.iterations.toLocaleString()} iters)` : `鉴权: ${rbacSecurity.algorithm} (${rbacSecurity.iterations.toLocaleString()}轮)`) }}
            </p>
            <div class="mt-2 text-[11px] space-y-1" style="color: var(--text-secondary);">
              <div>• {{ locale === 'en-US' ? 'Review system/kernel logs & admin audit trails' : '独立审查系统/内核日志与管理审计流' }}</div>
              <div>• {{ locale === 'en-US' ? 'Forensic hash seal verification & formal reports' : '司法哈希封条验真与合规报告存证' }}</div>
              <div>• {{ locale === 'en-US' ? 'Exclusive log disposal & purge authority (8.1.4.4)' : '独享日志处置与清理权限 (等保8.1.4.4)' }}</div>
            </div>
          </div>
        </div>

        <!-- 管理操作审计流水表格 -->
        <div class="flex-1 flex flex-col min-h-0">
          <div class="text-xs font-semibold mb-1.5 flex items-center justify-between" style="color: var(--text-primary);">
            <span class="ui-num">{{ locale === 'en-US' ? `Admin Non-repudiation Audit Trail (${adminAuditTrail.length} records)` : `管理员操作抗抵赖审计流水 (${adminAuditTrail.length} 条记录)` }}</span>
            <span class="text-[11px]" style="color: var(--text-muted);">{{ locale === 'en-US' ? 'All config modifications and blocked access attempts broadcast to Syslog' : '任何配置更改与越权阻断均已同步广播至 Syslog' }}</span>
          </div>
          <div class="flex-1 overflow-auto custom-scrollbar border rounded-xl" style="border-color: var(--border-subtle); background: var(--surface-content-alt);">
            <table class="w-full text-left text-xs border-collapse">
              <thead class="ui-table-head sticky top-0 z-10 select-none">
                <tr>
                  <th class="p-2.5">{{ locale === 'en-US' ? 'No.' : '序号' }}</th>
                  <th class="p-2.5">{{ locale === 'en-US' ? 'Timestamp' : '时间戳' }}</th>
                  <th class="p-2.5">{{ locale === 'en-US' ? 'Operator' : '操作者' }}</th>
                  <th class="p-2.5">{{ locale === 'en-US' ? 'Role' : '所属角色' }}</th>
                  <th class="p-2.5">{{ locale === 'en-US' ? 'Action' : '管理行为' }}</th>
                  <th class="p-2.5">{{ locale === 'en-US' ? 'Audit Details' : '审计详情' }}</th>
                  <th class="p-2.5 text-center">{{ locale === 'en-US' ? 'Status' : '状态' }}</th>
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
                    {{ locale === 'en-US' ? 'No admin audit records yet' : '暂无管理操作审计流水' }}
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
            <h3 class="text-[13px] font-semibold" style="color: var(--text-primary);">{{ locale === 'en-US' ? 'MLPS Level 3 ICS Extension (G.4.2/G.4.3) OT Baseline Whitelist Engine' : '等保三级工控扩展 (G.4.2/G.4.3) 工业通信基线白名单自学习引擎' }}</h3>
            <p class="text-[11px] mt-0.5" style="color: var(--text-muted);">{{ locale === 'en-US' ? 'Passively converges network physical/logical topology baseline; blocks unauthorized sessions and high-risk ICS write commands' : '被动收敛全网物理/逻辑通信拓扑基线；严格阻击未授权新会话与高危工控写控制指令' }}</p>
          </div>
          <div class="flex items-center gap-2 flex-wrap">
            <div class="glass-pill flex p-0.5 rounded-xl text-[11px] font-semibold">
              <button
                @click="changeBaselineMode('LEARNING')"
                :class="['px-2.5 py-1 rounded-lg transition-all cursor-pointer', baselineStatus.mode === 'LEARNING' ? 'bg-emerald-600 text-white shadow-xs' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]']"
              >
                {{ locale === 'en-US' ? 'Learning Mode' : '自学习模式 (Learning)' }}
              </button>
              <button
                @click="changeBaselineMode('ENFORCING')"
                :class="['px-2.5 py-1 rounded-lg transition-all cursor-pointer', baselineStatus.mode === 'ENFORCING' ? 'bg-rose-600 text-white shadow-xs' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]']"
              >
                {{ locale === 'en-US' ? 'Enforcing Mode' : '严格审计模式 (Enforcing)' }}
              </button>
              <button
                @click="changeBaselineMode('DISABLED')"
                :class="['px-2.5 py-1 rounded-lg transition-all cursor-pointer', baselineStatus.mode === 'DISABLED' ? 'bg-slate-600 text-white shadow-xs' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]']"
              >
                {{ locale === 'en-US' ? 'Disabled' : '已停用' }}
              </button>
            </div>
            <button @click="persistBaseline" class="ui-btn-primary bg-emerald-600 hover:bg-emerald-500 px-3 py-1 text-xs">
              <AppIcon name="archive" :size="13" />
              <span>{{ locale === 'en-US' ? 'Persist to Disk' : '固化基线至磁盘' }}</span>
            </button>
            <button @click="resetBaselineRules" class="ui-btn-danger px-3 py-1 text-xs">
              {{ locale === 'en-US' ? 'Reset Rules' : '重置基线规则' }}
            </button>
          </div>
        </div>

        <!-- 基线指标仪表盘 -->
        <div class="grid grid-cols-1 md:grid-cols-4 gap-3 shrink-0">
          <div class="ui-sub-card p-3">
            <span class="text-[11px] font-semibold" style="color: var(--text-muted);">{{ locale === 'en-US' ? 'Current Baseline Mode' : '当前基线模式' }}</span>
            <div class="text-sm font-semibold mt-1" :class="baselineStatus.mode === 'ENFORCING' ? 'text-rose-600 dark:text-rose-400' : 'text-emerald-600 dark:text-emerald-400'">
              {{ baselineStatus.mode === 'LEARNING' ? (locale === 'en-US' ? 'Learning Mode (Converging)' : '自学习模式 (收敛中)') : (baselineStatus.mode === 'ENFORCING' ? (locale === 'en-US' ? 'Enforcing Mode (Active Blocking)' : '严格审计模式 (实时阻击)') : (locale === 'en-US' ? 'Disabled' : '已停用')) }}
            </div>
          </div>
          <div class="ui-sub-card p-3">
            <span class="text-[11px] font-semibold" style="color: var(--text-muted);">{{ locale === 'en-US' ? 'Converged Whitelist Rules' : '已收敛白名单规则' }}</span>
            <div class="text-sm font-semibold ui-num text-indigo-600 dark:text-indigo-300 mt-1">{{ baselineRules.length }} {{ locale === 'en-US' ? 'legal links' : '条合法通信对' }}</div>
          </div>
          <div class="ui-sub-card p-3">
            <span class="text-[11px] font-semibold" style="color: var(--text-muted);">{{ locale === 'en-US' ? 'Detected Baseline Drifts' : '捕获合规漂移违规' }}</span>
            <div class="text-sm font-semibold ui-num text-rose-600 dark:text-rose-400 mt-1">{{ baselineDriftEvents.length }} {{ locale === 'en-US' ? 'drift events' : '起越权事件' }}</div>
          </div>
          <div class="ui-sub-card p-3">
            <span class="text-[11px] font-semibold" style="color: var(--text-muted);">{{ locale === 'en-US' ? 'Learning Start Time' : '基线自学习启动时间' }}</span>
            <div class="text-xs ui-num mt-1 truncate" style="color: var(--text-secondary);">{{ baselineStatus.learning_started_at || (locale === 'en-US' ? 'Pending' : '待启动') }}</div>
          </div>
        </div>

        <!-- 宏观节假日/工作日无监督日态基线栏 -->
        <div class="bg-indigo-500/8 border border-indigo-500/25 rounded-xl p-2.5 flex flex-wrap items-center justify-between gap-2 text-xs shrink-0">
          <div class="flex items-center gap-2.5 flex-wrap">
            <span class="font-semibold text-indigo-700 dark:text-indigo-300 flex items-center gap-1.5">
              <AppIcon name="activity" :size="13" />
              <span>{{ locale === 'en-US' ? 'Macro Calendar Regime Inference:' : '宏观日历基线日态推断:' }}</span>
            </span>
            <span class="px-2 py-0.5 rounded-lg bg-indigo-500/15 text-indigo-700 dark:text-indigo-300 font-semibold">
              {{ macroCalendarStatus?.inferred_regime || (locale === 'en-US' ? 'Pending' : '待同步') }}
            </span>
            <span v-if="macroCalendarStatus" class="ui-num text-[11px]" style="color: var(--text-secondary);">
              {{ locale === 'en-US' ? 'Confidence: ' : '置信度: ' }}<b>{{ (macroCalendarStatus.confidence_score * 100).toFixed(1) }}%</b> | {{ locale === 'en-US' ? 'Workday Posterior: ' : '工作日后验: ' }}{{ (macroCalendarStatus.posterior_workday_prob * 100).toFixed(1) }}%
            </span>
            <span v-if="macroCalendarStatus" class="text-[11px] truncate max-w-md" style="color: var(--text-muted);" :title="macroCalendarStatus.evidence_summary">
              {{ macroCalendarStatus.evidence_summary }}
            </span>
          </div>
          <div class="flex items-center gap-1.5 flex-wrap">
            <input v-model="statutoryDateInput" type="date" class="ui-input px-2 py-1 text-[11px]" />
            <select v-model="statutoryRegimeType" class="ui-input px-2 py-1 text-[11px]">
              <option value="HOLIDAY">{{ locale === 'en-US' ? 'Statutory Holiday (Holiday)' : '法定节假日 (Holiday)' }}</option>
              <option value="COMPENSATORY">{{ locale === 'en-US' ? 'Compensatory Workday' : '调休补班工作日' }}</option>
              <option value="WORKDAY">{{ locale === 'en-US' ? 'Standard Workday' : '标准工作日' }}</option>
              <option value="WEEKEND">{{ locale === 'en-US' ? 'Standard Weekend' : '标准双休日' }}</option>
            </select>
            <button @click="submitStatutoryDate" class="ui-btn-primary px-2.5 py-1 text-[11px]">
              {{ locale === 'en-US' ? 'Register Schedule' : '登记法定日程' }}
            </button>
            <button @click="loadMacroCalendarStatus" class="ui-btn-secondary px-2 py-1 text-[11px]" :title="locale === 'en-US' ? 'Refresh Status' : '刷新状态'">
              <AppIcon name="refresh" :size="12" />
            </button>
          </div>
        </div>

        <!-- 规则与漂移违规上下分割 -->
        <div class="flex-1 grid grid-cols-1 lg:grid-cols-2 gap-3 min-h-0">
          <div class="flex flex-col min-h-0 border rounded-xl p-2.5" style="border-color: var(--border-subtle); background: var(--surface-content-alt);">
            <div class="text-xs font-semibold mb-1.5 flex items-center justify-between" style="color: var(--text-primary);">
              <span class="ui-num">{{ locale === 'en-US' ? `Converged Communication Baseline (${baselineRules.length})` : `已收敛合法通信基线 (${baselineRules.length})` }}</span>
              <button @click="loadBaselineRules" class="text-[11px] text-blue-600 dark:text-sky-400 hover:underline font-medium cursor-pointer">{{ locale === 'en-US' ? 'Refresh' : '刷新' }}</button>
            </div>
            <div class="flex-1 overflow-auto custom-scrollbar">
              <table class="w-full text-left text-xs border-collapse">
                <thead class="ui-table-head sticky top-0 z-10 select-none">
                  <tr>
                    <th class="p-2">{{ locale === 'en-US' ? 'Link (Src → Dst)' : '通信链路 (源 → 宿)' }}</th>
                    <th class="p-2">{{ locale === 'en-US' ? 'Protocol/Port' : '规约/端口' }}</th>
                    <th class="p-2">{{ locale === 'en-US' ? 'Action Baseline' : '动作基线' }}</th>
                    <th class="p-2 text-right">{{ locale === 'en-US' ? 'Hits' : '命中次数' }}</th>
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
                        {{ r.action_type === 'WRITE_ALLOWED' ? (locale === 'en-US' ? 'Write Allowed' : '允许写控制') : (locale === 'en-US' ? 'Strict Read-Only' : '严格只读查询') }}
                      </span>
                    </td>
                    <td class="p-2 text-right font-semibold ui-num text-indigo-600 dark:text-indigo-300">{{ r.hit_count }}</td>
                  </tr>
                  <tr v-if="baselineRules.length === 0">
                    <td colspan="4" class="p-6 text-center text-xs" style="color: var(--text-muted);">
                      {{ locale === 'en-US' ? 'Baseline learning in progress; rules converge automatically as packets arrive' : '基线学习中，接收到工控网络报文后将自动收敛规则' }}
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <div class="flex flex-col min-h-0 border rounded-xl p-2.5" style="border-color: var(--border-subtle); background: var(--surface-content-alt);">
            <div class="text-xs font-semibold mb-1.5 flex items-center justify-between">
              <span class="text-rose-600 dark:text-rose-400 ui-num">{{ locale === 'en-US' ? `Real-time Baseline Drift & High-risk Command Alarms (${baselineDriftEvents.length})` : `实时通信漂移与高危指令告警 (${baselineDriftEvents.length})` }}</span>
              <button @click="loadBaselineDriftEvents" class="text-[11px] text-blue-600 dark:text-sky-400 hover:underline font-medium cursor-pointer">{{ locale === 'en-US' ? 'Refresh' : '刷新' }}</button>
            </div>
            <div class="flex-1 overflow-auto custom-scrollbar">
              <table class="w-full text-left text-xs border-collapse">
                <thead class="ui-table-head sticky top-0 z-10 select-none">
                  <tr>
                    <th class="p-2">{{ locale === 'en-US' ? 'Time' : '时间' }}</th>
                    <th class="p-2">{{ locale === 'en-US' ? 'Violation Type' : '违规类型' }}</th>
                    <th class="p-2">{{ locale === 'en-US' ? 'Session Link' : '会话链路' }}</th>
                    <th class="p-2">{{ locale === 'en-US' ? 'Alarm Details' : '告警详情' }}</th>
                    <th class="p-2 w-16 text-center">{{ locale === 'en-US' ? 'Diff' : '比对' }}</th>
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
                      <button @click="addDriftToDiffQueue(ev)" class="px-1.5 py-0.5 rounded bg-emerald-500/12 hover:bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border border-emerald-500/25 text-[11px] font-semibold cursor-pointer">{{ locale === 'en-US' ? '+ Enqueue' : '+入队' }}</button>
                    </td>
                  </tr>
                  <tr v-if="baselineDriftEvents.length === 0">
                    <td colspan="5" class="p-6 text-center text-xs" style="color: var(--text-muted);">
                      {{ locale === 'en-US' ? 'Baseline status nominal; no drift violations detected' : '当前基线状态良好，未检测到违规漂移事件' }}
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
            <h3 class="text-[13px] font-semibold" style="color: var(--text-primary);">{{ locale === 'en-US' ? 'MLPS Level 3 (8.1.2.1/8.1.2.2) Security Zone Partition & CIDR Subnet Rules' : '等保三级 (8.1.2.1/8.1.2.2) 安全区域划分与 CIDR 网段规则管理' }}</h3>
            <p class="text-[11px] mt-0.5" style="color: var(--text-muted);">{{ locale === 'en-US' ? 'Strictly define network boundaries: Zone I (Control), Zone II (Non-control), Zone III (Management), etc.' : '严格定义生产控制区(安全区I)、生产非控制区(安全区II)、管理信息大区(安全区III)等网络边界' }}</p>
          </div>
          <div class="flex items-center gap-2">
            <button @click="loadCidrRules" class="ui-btn-secondary px-3 py-1 text-xs">{{ locale === 'en-US' ? 'Reload' : '重新加载' }}</button>
            <button @click="saveCidrRules" class="ui-btn-primary px-3.5 py-1 text-xs">{{ locale === 'en-US' ? 'Save Zone Rules' : '保存区域规则' }}</button>
          </div>
        </div>

        <!-- 快速添加新网段规则栏 -->
        <div class="ui-sub-card p-3 shrink-0 flex items-center gap-2 flex-wrap text-xs">
          <span class="font-semibold text-[11px]" style="color: var(--text-secondary);">{{ locale === 'en-US' ? 'Add Subnet:' : '添加网段:' }}</span>
          <input v-model="newCidr" :placeholder="locale === 'en-US' ? 'Subnet CIDR (e.g. 192.168.10.0/24)' : '网段 CIDR (如 192.168.10.0/24)'" class="ui-input w-48 px-2.5 py-1 text-xs font-mono" />
          <input v-model="newZoneName" :placeholder="locale === 'en-US' ? 'Security Zone Name (e.g. Control Zone I)' : '安全区域名称 (如 生产控制大区-安全区I)'" class="ui-input w-56 px-2.5 py-1 text-xs" />
          <select v-model="newSecLevel" class="ui-input px-2 py-1 text-xs font-medium">
            <option value="核心生产">{{ locale === 'en-US' ? 'Core Production (Zone I)' : '核心生产 (安全区I)' }}</option>
            <option value="关键业务">{{ locale === 'en-US' ? 'Key Business (Zone II)' : '关键业务 (安全区II)' }}</option>
            <option value="生产管理">{{ locale === 'en-US' ? 'Production Mgmt (Zone III)' : '生产管理 (安全区III)' }}</option>
            <option value="办公外网">{{ locale === 'en-US' ? 'Office External (Zone IV)' : '办公外网 (安全区IV)' }}</option>
            <option value="外部公网">{{ locale === 'en-US' ? 'External Public Net' : '外部公网' }}</option>
          </select>
          <input v-model="newDescription" :placeholder="locale === 'en-US' ? 'Description / Purpose' : '归属说明/用途'" class="ui-input flex-1 min-w-[120px] px-2.5 py-1 text-xs" />
          <button @click="addCidrRule" class="ui-btn-primary px-3 py-1 text-xs">
            <AppIcon name="plus" :size="13" />
            <span>{{ locale === 'en-US' ? 'Add Rule' : '添加规则' }}</span>
          </button>
        </div>

        <!-- CIDR 网段规则表格 -->
        <div class="flex-1 overflow-auto custom-scrollbar border rounded-xl" style="border-color: var(--border-subtle); background: var(--surface-content-alt);">
          <table class="w-full text-left text-xs border-collapse">
            <thead class="ui-table-head sticky top-0 z-10 select-none">
              <tr>
                <th class="p-2.5">{{ locale === 'en-US' ? 'CIDR Subnet' : 'CIDR 网段' }}</th>
                <th class="p-2.5">{{ locale === 'en-US' ? 'Zone Name' : '安全区域名称' }}</th>
                <th class="p-2.5">{{ locale === 'en-US' ? 'Security Level' : '安全等级' }}</th>
                <th class="p-2.5">{{ locale === 'en-US' ? 'Description' : '责任归属说明' }}</th>
                <th class="p-2.5 text-center">{{ locale === 'en-US' ? 'Action' : '操作' }}</th>
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
                    {{ locale === 'en-US' ? 'Delete' : '删除' }}
                  </button>
                </td>
              </tr>
              <tr v-if="cidrRules.length === 0">
                <td colspan="5" class="p-8 text-center text-xs" style="color: var(--text-muted);">
                  {{ locale === 'en-US' ? 'No CIDR security zone rules configured yet' : '尚未配置任何 CIDR 安全区域规则' }}
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
            <h3 class="text-[13px] font-semibold" style="color: var(--text-primary);">{{ locale === 'en-US' ? 'MLPS Level 3 (8.1.4.3) Centralized Log Backup & RFC 5424 Syslog Engine' : '等保三级 (8.1.4.3) 集中式日志备份与 RFC 5424 Syslog 外发引擎' }}</h3>
            <p class="text-[11px] mt-0.5" style="color: var(--text-muted);">{{ locale === 'en-US' ? 'Complies with RFC 5424; asynchronously forwards via UDP/TCP to enterprise SIEM/SOC log centers' : '严格遵循 RFC 5424 标准规范，异步 UDP / TCP 外发至企业 SIEM / SOC 集中日志审计中心' }}</p>
          </div>
          <div class="flex items-center gap-2">
            <button @click="loadSyslogConfig" class="ui-btn-secondary px-3 py-1 text-xs">{{ locale === 'en-US' ? 'Reload' : '重新加载' }}</button>
            <button @click="saveSyslogConfig" class="ui-btn-primary px-3.5 py-1 text-xs">{{ locale === 'en-US' ? 'Save Config' : '保存配置' }}</button>
          </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-3 gap-3 shrink-0">
          <div class="space-y-1 ui-sub-card p-3">
            <label class="text-[11px] font-semibold block" style="color: var(--text-secondary);">{{ locale === 'en-US' ? 'Centralized Forwarding Switch' : '集中外发主开关' }}</label>
            <label class="flex items-center gap-2 cursor-pointer mt-1.5">
              <input type="checkbox" v-model="syslogCfg.enabled" class="accent-blue-600 w-4 h-4" />
              <span class="text-xs font-semibold" :class="syslogCfg.enabled ? 'text-emerald-600 dark:text-emerald-400' : 'text-[var(--text-muted)]'">
                {{ syslogCfg.enabled ? (locale === 'en-US' ? 'Forwarding Enabled' : '已启用集中外发') : (locale === 'en-US' ? 'Forwarding Disabled' : '已停用集中外发') }}
              </span>
            </label>
          </div>

          <div class="space-y-1 ui-sub-card p-3">
            <label class="text-[11px] font-semibold block" style="color: var(--text-secondary);">{{ locale === 'en-US' ? 'Remote SIEM/SOC Server IP' : '远程 SIEM/SOC 服务器 IP' }}</label>
            <input v-model="syslogCfg.server_ip" placeholder="192.168.1.200" class="ui-input w-full px-2.5 py-1.5 text-xs font-mono" />
          </div>

          <div class="space-y-1 ui-sub-card p-3">
            <label class="text-[11px] font-semibold block" style="color: var(--text-secondary);">{{ locale === 'en-US' ? 'Port & Transport Protocol' : '服务端口与传输协议' }}</label>
            <div class="flex gap-2">
              <input v-model.number="syslogCfg.server_port" type="number" min="1" max="65535" class="ui-input w-24 px-2.5 py-1.5 text-xs ui-num" />
              <select v-model="syslogCfg.protocol" class="ui-input flex-1 px-2 py-1.5 text-xs">
                <option value="UDP">{{ locale === 'en-US' ? 'UDP (Low Overhead)' : 'UDP (低开销)' }}</option>
                <option value="TCP">{{ locale === 'en-US' ? 'TCP (Reliable)' : 'TCP (可靠传输)' }}</option>
              </select>
            </div>
          </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-3 gap-3 shrink-0">
          <div class="space-y-1 ui-sub-card p-3">
            <label class="text-[11px] font-semibold block" style="color: var(--text-secondary);">{{ locale === 'en-US' ? 'Syslog Facility' : 'Syslog Facility (设施)' }}</label>
            <select v-model.number="syslogCfg.facility" class="ui-input w-full px-2.5 py-1.5 text-xs">
              <option :value="1">1: user-level messages</option>
              <option :value="16">{{ locale === 'en-US' ? '16: local0 (Standard Industrial Audit)' : '16: local0 (标准工业审计)' }}</option>
              <option :value="17">17: local1</option>
              <option :value="18">18: local2</option>
            </select>
          </div>

          <div class="space-y-1 ui-sub-card p-3">
            <label class="text-[11px] font-semibold block" style="color: var(--text-secondary);">{{ locale === 'en-US' ? 'Min Severity Threshold' : '最低外发严重性 (Min Severity)' }}</label>
            <select v-model.number="syslogCfg.min_severity" class="ui-input w-full px-2.5 py-1.5 text-xs">
              <option :value="3">{{ locale === 'en-US' ? '3: Error and above' : '3: Error 及以上' }}</option>
              <option :value="4">{{ locale === 'en-US' ? '4: Warning and above' : '4: Warning 及以上' }}</option>
              <option :value="5">{{ locale === 'en-US' ? '5: Notice and above' : '5: Notice 及以上' }}</option>
              <option :value="6">{{ locale === 'en-US' ? '6: Informational and above (Recommended)' : '6: Informational 及以上 (推荐)' }}</option>
              <option :value="7">{{ locale === 'en-US' ? '7: Debug (All Logs)' : '7: Debug (全部日志)' }}</option>
            </select>
          </div>

          <div class="space-y-1 ui-sub-card p-3">
            <label class="text-[11px] font-semibold block" style="color: var(--text-secondary);">{{ locale === 'en-US' ? 'App Name (APP-NAME)' : '应用标识名 (APP-NAME)' }}</label>
            <input v-model="syslogCfg.app_name" placeholder="OmniProbe" class="ui-input w-full px-2.5 py-1.5 text-xs font-mono" />
          </div>
        </div>

        <!-- 联调测试控制台 -->
        <div class="ui-sub-card p-3 space-y-2">
          <div class="text-xs font-semibold flex items-center justify-between" style="color: var(--text-primary);">
            <span>{{ locale === 'en-US' ? 'RFC 5424 Connectivity Test & Audit Packet Simulation' : 'RFC 5424 连通性测试与审计报文模拟' }}</span>
            <span class="text-[11px] ui-num" style="color: var(--text-muted);">{{ locale === 'en-US' ? `Total Sent Syslogs: ${syslogCfg.sent_count}` : `已外发审计报文总计: ${syslogCfg.sent_count} 条` }}</span>
          </div>
          <div class="flex gap-2">
            <input v-model="syslogTestMsg" :placeholder="locale === 'en-US' ? 'Enter test audit message content...' : '输入测试审计报文内容...'" class="ui-input flex-1 px-2.5 py-1.5 text-xs" />
            <button @click="testSendSyslog" :disabled="syslogTesting" class="ui-btn-primary px-4 py-1.5 text-xs">
              <span v-if="syslogTesting">{{ locale === 'en-US' ? 'Sending...' : '发送中...' }}</span>
              <span v-else>{{ locale === 'en-US' ? 'Send Test Message Now' : '立即发送测试报文' }}</span>
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
            <h3 class="text-[13px] font-semibold" style="color: var(--text-primary);">{{ locale === 'en-US' ? 'Industrial Lightweight High-Entropy Honeypot Matrix' : '工业级轻量高熵诱捕蜜罐矩阵' }}</h3>
            <p class="text-[11px] mt-0.5" style="color: var(--text-muted);">{{ locale === 'en-US' ? 'Multi-port low-interaction virtual honeypot to trap abnormal probes and record payloads' : '多端口低交互虚拟蜜罐，诱捕异常刺探并实时记录攻击载荷' }}</p>
          </div>
          <div class="flex items-center gap-2 flex-wrap">
            <input v-model.number="newPort" type="number" min="1" max="65535" :placeholder="locale === 'en-US' ? 'Port e.g. 1883' : '端口如 1883'" class="ui-input w-24 px-2 py-1 text-xs ui-num" />
            <select v-model="newProto" class="ui-input px-2 py-1 text-xs">
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
            </select>
            <button @click="addPort" :disabled="!isValidNewPort" class="ui-btn-primary px-3 py-1 text-xs">{{ locale === 'en-US' ? 'Add Port' : '添加监听' }}</button>
            <button
              v-if="!honeypotRunning"
              @click="startHoneypot"
              :disabled="honeypotPorts.length === 0"
              class="ui-btn-primary bg-emerald-600 hover:bg-emerald-500 px-3.5 py-1 text-xs"
            >
              {{ locale === 'en-US' ? 'Start Honeypot' : '启动蜜罐' }}
            </button>
            <button v-else @click="stopHoneypot" class="ui-btn-danger px-3.5 py-1 text-xs">{{ locale === 'en-US' ? 'Stop Honeypot' : '停止蜜罐' }}</button>
          </div>
        </div>

        <!-- 诱饵端口清单管理 -->
        <div class="shrink-0 flex items-center gap-1.5 flex-wrap text-xs">
          <span class="text-[11px] font-semibold" style="color: var(--text-muted);">{{ locale === 'en-US' ? `Decoy Port Matrix (${honeypotPorts.length}):` : `诱饵端口矩阵 (${honeypotPorts.length}):` }}</span>
          <span
            v-for="(hp, idx) in honeypotPorts"
            :key="`${hp.port}-${hp.proto}`"
            class="px-2 py-0.5 rounded-lg bg-indigo-500/12 text-indigo-700 dark:text-indigo-300 border border-indigo-500/25 text-[11px] font-semibold ui-num flex items-center gap-1.5"
          >
            :{{ hp.port }}/{{ hp.proto.toUpperCase() }}
            <button
              @click="removePort(idx)"
              class="w-4 h-4 rounded-full flex items-center justify-center hover:text-rose-500 hover:bg-rose-500/15 transition-colors cursor-pointer"
              :title="locale === 'en-US' ? 'Remove decoy port' : '移除监听'"
            >
              <AppIcon name="close" :size="11" />
            </button>
          </span>
          <span v-if="honeypotPorts.length === 0" class="text-[11px]" style="color: var(--text-muted);">{{ locale === 'en-US' ? 'No decoy ports configured' : '尚未配置诱饵端口' }}</span>
        </div>

        <div class="flex-1 overflow-auto custom-scrollbar border rounded-xl" style="border-color: var(--border-subtle); background: var(--surface-content-alt);">
          <table class="w-full text-left text-xs border-collapse">
            <thead class="ui-table-head sticky top-0 z-10 select-none">
              <tr>
                <th class="p-2.5">{{ locale === 'en-US' ? 'Timestamp' : '时间戳' }}</th>
                <th class="p-2.5">{{ locale === 'en-US' ? 'Transport' : '传输层' }}</th>
                <th class="p-2.5">{{ locale === 'en-US' ? 'Decoy Protocol' : '诱捕规约' }}</th>
                <th class="p-2.5">{{ locale === 'en-US' ? 'Source IP (Probe)' : '源 IP (异常刺探)' }}</th>
                <th class="p-2.5">{{ locale === 'en-US' ? 'Target Port' : '目标蜜罐端口' }}</th>
                <th class="p-2.5">{{ locale === 'en-US' ? 'Payload Len' : '载荷长度' }}</th>
                <th class="p-2.5">{{ locale === 'en-US' ? 'Shannon Entropy' : 'Shannon 熵' }}</th>
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
                  暂无蜜罐触发事件，配置诱饵端口后点击【{{ locale === 'en-US' ? 'Start Honeypot' : '启动蜜罐' }}】开始诱捕
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
          <span class="text-xs font-semibold ui-num" style="color: var(--text-primary);">{{ locale === 'en-US' ? `Kernel & System Runtime Audit Logs (${systemLogs.length} lines)` : `内核与系统运行日志审计 (${systemLogs.length} 行)` }}</span>
          <div class="flex items-center gap-2">
            <span class="text-[11px]" style="color: var(--text-muted);">{{ locale === 'en-US' ? 'Protected by MLPS Level 3 (8.1.4.4): Only AuditAdmin can dispose logs' : '受等保三级(8.1.4.4)保护: 仅安全审计员可处置日志' }}</span>
            <button @click="handleClearLogs" class="ui-btn-danger px-2.5 py-1 text-xs">{{ locale === 'en-US' ? 'Clear Logs' : '清空日志' }}</button>
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
              {{ locale === 'en-US' ? '+ Enqueue' : '+ 入队' }}
            </button>
          </div>
          <div v-if="systemLogs.length === 0" class="italic" style="color: var(--text-muted);">
            {{ locale === 'en-US' ? 'No system runtime logs yet' : '暂无系统运行日志' }}
          </div>
        </div>
      </div>

      <!-- ============================================================ -->
      <!-- 选项卡 8：引擎配置、Prometheus 指标与系统参数 -->
      <!-- ============================================================ -->
      <div v-else-if="currentTab === 'config'" class="h-full flex flex-col overflow-hidden">
        <div class="flex items-center justify-between px-4 py-2.5 border-b shrink-0 gap-3 flex-wrap" style="border-color: var(--border-subtle);">
          <span class="text-[13px] font-semibold" style="color: var(--text-primary);">{{ locale === 'en-US' ? 'Engine Configuration, Prometheus Observability & System Parameters' : '引擎配置、Prometheus 可观测性与系统参数' }}</span>
          <div class="flex items-center gap-2">
            <button @click="loadConfig" :disabled="configLoading" class="ui-btn-secondary px-3 py-1 text-xs">
              <AppIcon name="refresh" :size="13" :class="{ 'animate-spin': configLoading }" />
              <span>{{ locale === 'en-US' ? 'Reload' : '重新加载' }}</span>
            </button>
            <button @click="saveConfig" :disabled="configSaving || !cfg" class="ui-btn-primary px-3.5 py-1 text-xs">
              <AppIcon v-if="configSaving" name="refresh" :size="13" class="animate-spin" />
              <AppIcon v-else name="archive" :size="13" />
              <span>{{ locale === 'en-US' ? 'Save & Persist' : '保存并持久化' }}</span>
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
                <div class="text-xs font-semibold" style="color: var(--text-primary);">{{ locale === 'en-US' ? 'Prometheus Industrial Metrics Service (RFC Centralized Monitoring)' : 'Prometheus 工业监控指标服务 (RFC 集中监控)' }}</div>
                <div class="text-[11px] ui-num mt-0.5" style="color: var(--text-muted);">
                  {{ locale === 'en-US' ? 'Scrape Endpoint: ' : '抓取端点: ' }} <span class="text-indigo-600 dark:text-indigo-300 font-semibold">http://127.0.0.1:{{ cfg.enterprise_features.fleet_management.enabled ? cfg.enterprise_features.fleet_management.api_port : 9091 }}/metrics</span>
                </div>
              </div>
            </div>
            <span class="px-2.5 py-1 rounded-full bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 text-[11px] font-semibold flex items-center gap-1">
              <AppIcon name="check" :size="12" />
              <span>{{ locale === 'en-US' ? 'Service Running' : '服务运行中' }}</span>
            </span>
          </div>

          <!-- 运行时热更新区 -->
          <div class="ui-sub-card p-3.5 space-y-3">
            <div class="text-xs font-semibold flex items-center gap-1.5" style="color: var(--text-primary);">
              <span class="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
              <span>{{ locale === 'en-US' ? 'Runtime Hot Update (Takes effect immediately, no restart required)' : '运行时热更新 (立即生效，无需重启探针)' }}</span>
            </div>
            <div class="grid grid-cols-1 lg:grid-cols-3 gap-3">
              <div class="space-y-2 p-3 rounded-xl border" style="background: var(--surface-content); border-color: var(--border-subtle);">
                <div class="text-[11px] font-semibold" style="color: var(--text-muted);">{{ locale === 'en-US' ? 'Token Bucket Rate Limiter' : '令牌桶防御限流' }}</div>
                <div class="flex items-center gap-2">
                  <input v-model.number="throttleCapacity" type="number" min="1" max="1000" :title="locale === 'en-US' ? 'Capacity' : '容量 (Capacity)'" class="ui-input w-16 px-2 py-1 text-xs ui-num" />
                  <span class="text-[11px]" style="color: var(--text-muted);">{{ locale === 'en-US' ? 'Capacity /' : '容量 /' }}</span>
                  <input v-model.number="throttleFillRate" type="number" min="1" max="1000" :title="locale === 'en-US' ? 'Fill Rate (/s)' : '填充速率 (Fill Rate /s)'" class="ui-input w-16 px-2 py-1 text-xs ui-num" />
                  <span class="text-[11px]" style="color: var(--text-muted);">{{ locale === 'en-US' ? '/sec' : '每秒' }}</span>
                </div>
                <button @click="applyThrottle" class="ui-btn-primary bg-emerald-600 hover:bg-emerald-500 w-full py-1 text-xs justify-center">
                  {{ locale === 'en-US' ? 'Hot Update Rate Limiter' : '热更新限流参数' }}
                </button>
              </div>

              <div class="space-y-2 p-3 rounded-xl border" style="background: var(--surface-content); border-color: var(--border-subtle);">
                <div class="text-[11px] font-semibold flex items-center justify-between" style="color: var(--text-muted);">
                  <span>{{ locale === 'en-US' ? 'Cloud Ingestion Streaming' : '云端流式上报' }}</span>
                  <span class="flex items-center gap-1">
                    <span class="w-1.5 h-1.5 rounded-full" :class="cloudRunning ? 'bg-emerald-500' : 'bg-slate-400'"></span>
                    <span :class="cloudRunning ? 'text-emerald-600 dark:text-emerald-400 font-semibold' : ''">{{ cloudRunning ? (locale === 'en-US' ? 'Streaming' : '推送中') : (locale === 'en-US' ? 'Stopped' : '未启动') }}</span>
                  </span>
                </div>
                <input v-model="cloudWebhookUrl" placeholder="http://127.0.0.1:9090/ingest" class="ui-input w-full px-2 py-1 text-xs font-mono" />
                <div class="flex gap-1.5">
                  <button v-if="!cloudRunning" @click="startCloud" class="ui-btn-primary flex-1 py-1 text-xs justify-center">{{ locale === 'en-US' ? 'Start Streaming' : '启动推送' }}</button>
                  <button v-else @click="stopCloud" class="ui-btn-danger flex-1 py-1 text-xs justify-center">{{ locale === 'en-US' ? 'Stop Streaming' : '停止推送' }}</button>
                </div>
              </div>

              <div class="space-y-2 p-3 rounded-xl border" style="background: var(--surface-content); border-color: var(--border-subtle);">
                <div class="text-[11px] font-semibold" style="color: var(--text-muted);">{{ locale === 'en-US' ? 'DPI Dynamic Signatures Hot Reload' : 'DPI 动态字典热重载' }}</div>
                <input v-model="dpiSigPath" placeholder="protocol_signatures.json" class="ui-input w-full px-2 py-1 text-xs font-mono" />
                <button @click="reloadDpi" class="ui-btn-primary bg-indigo-600 hover:bg-indigo-500 w-full py-1 text-xs justify-center">{{ locale === 'en-US' ? 'Reload Signature Dictionary' : '重载规约字典' }}</button>
              </div>
            </div>
          </div>

          <!-- 持久化配置区 -->
          <div class="ui-sub-card p-3.5 space-y-3">
            <div class="text-xs font-semibold flex items-center gap-1.5" style="color: var(--text-primary);">
              <span class="w-1.5 h-1.5 rounded-full bg-blue-500"></span>
              <span>{{ locale === 'en-US' ? 'Persistent Config (Saved to config.json; some settings take effect after probe restart)' : '持久化配置 (保存后写入 config.json，部分配置项重启探针后生效)' }}</span>
            </div>

            <div class="grid grid-cols-2 lg:grid-cols-3 gap-3 text-xs">
              <div class="space-y-1">
                <label class="font-semibold block text-[11px]" style="color: var(--text-secondary);">{{ locale === 'en-US' ? 'TCP Framing Timeout (sec)' : 'TCP 组帧超时 (秒)' }}</label>
                <input v-model.number="cfg.tcp_framing_timeout" type="number" step="0.01" min="0.01" class="ui-input w-full p-1.5 text-xs ui-num" />
              </div>
              <div class="space-y-1">
                <label class="font-semibold block text-[11px]" style="color: var(--text-secondary);">{{ locale === 'en-US' ? 'Forensic Seal Interval (sec)' : '司法封条周期 (秒)' }}</label>
                <input v-model.number="cfg.sealing_interval_secs" type="number" min="5" class="ui-input w-full p-1.5 text-xs ui-num" />
              </div>
              <div class="space-y-1">
                <label class="font-semibold block text-[11px]" style="color: var(--text-secondary);">{{ locale === 'en-US' ? 'Log Level' : '日志级别' }}</label>
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
                <div class="text-[11px] font-semibold" style="color: var(--text-muted);">{{ locale === 'en-US' ? 'Logging Subsystem (logging)' : '日志体系 (logging)' }}</div>
                <input v-model="cfg.logging.file" placeholder="listener.log" class="ui-input w-full px-2 py-1 font-mono text-xs" />
              </div>
              <div class="space-y-1.5 p-2.5 rounded-xl border" style="background: var(--surface-content); border-color: var(--border-subtle);">
                <div class="text-[11px] font-semibold" style="color: var(--text-muted);">{{ locale === 'en-US' ? 'Data Storage (data_storage)' : '数据落盘 (data_storage)' }}</div>
                <div class="grid grid-cols-2 gap-2">
                  <input v-model="cfg.data_storage.file" placeholder="received_data.jsonl" class="ui-input px-2 py-1 font-mono text-xs" />
                  <input v-model="cfg.data_storage.pcap_file" placeholder="capture.pcap" class="ui-input px-2 py-1 font-mono text-xs" />
                </div>
                <label class="flex items-center gap-1.5 cursor-pointer text-[11px]" style="color: var(--text-secondary);">
                  <input type="checkbox" v-model="cfg.data_storage.enable_pcap" class="accent-blue-600" />
                  <span class="font-medium">{{ locale === 'en-US' ? 'Enable full PCAP disk forensic capture' : '启用 PCAP 全量落盘存证' }}</span>
                </label>
              </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-3 gap-3 text-xs">
              <div class="space-y-1.5 p-2.5 rounded-xl border" style="background: var(--surface-content); border-color: var(--border-subtle);">
                <div class="text-[11px] font-semibold" style="color: var(--text-muted);">{{ locale === 'en-US' ? 'Fleet Management' : '集群协同管理' }}</div>
                <label class="flex items-center gap-1.5 cursor-pointer text-[11px]" style="color: var(--text-secondary);">
                  <input type="checkbox" v-model="cfg.enterprise_features.fleet_management.enabled" class="accent-blue-600" />
                  <span class="font-medium">{{ locale === 'en-US' ? 'Enable' : '启用' }}</span>
                </label>
                <div class="flex items-center gap-1.5">
                  <span class="text-[11px]" style="color: var(--text-muted);">{{ locale === 'en-US' ? 'API Port:' : 'API 端口:' }}</span>
                  <input v-model.number="cfg.enterprise_features.fleet_management.api_port" type="number" min="1" max="65535" class="ui-input w-20 px-2 py-1 ui-num text-xs" />
                </div>
              </div>
              <div class="space-y-1.5 p-2.5 rounded-xl border" style="background: var(--surface-content); border-color: var(--border-subtle);">
                <div class="text-[11px] font-semibold" style="color: var(--text-muted);">{{ locale === 'en-US' ? 'Threat Defense' : '威胁防御' }}</div>
                <label class="flex items-center gap-1.5 cursor-pointer text-[11px]" style="color: var(--text-secondary);">
                  <input type="checkbox" v-model="cfg.enterprise_features.threat_defense.enabled" class="accent-blue-600" />
                  <span class="font-medium">{{ locale === 'en-US' ? 'Enable' : '启用' }}</span>
                </label>
                <div class="flex items-center gap-1.5">
                  <span class="text-[11px]" style="color: var(--text-muted);">{{ locale === 'en-US' ? 'Threshold pps:' : '阈值 pps:' }}</span>
                  <input v-model.number="cfg.enterprise_features.threat_defense.max_packets_per_sec" type="number" min="1" step="0.1" class="ui-input w-20 px-2 py-1 ui-num text-xs" />
                </div>
                <label class="flex items-center gap-1.5 cursor-pointer text-[11px]" style="color: var(--text-secondary);">
                  <input type="checkbox" v-model="cfg.enterprise_features.threat_defense.auto_drop_connection" class="accent-blue-600" />
                  <span class="font-medium">{{ locale === 'en-US' ? 'Auto Drop Connection on Limit' : '超限自动断连' }}</span>
                </label>
              </div>
              <div class="space-y-1.5 p-2.5 rounded-xl border" style="background: var(--surface-content); border-color: var(--border-subtle);">
                <div class="text-[11px] font-semibold" style="color: var(--text-muted);">{{ locale === 'en-US' ? 'Cloud Streaming' : '云端上报' }}</div>
                <label class="flex items-center gap-1.5 cursor-pointer text-[11px]" style="color: var(--text-secondary);">
                  <input type="checkbox" v-model="cfg.enterprise_features.cloud_streaming.enabled" class="accent-blue-600" />
                  <span class="font-medium">{{ locale === 'en-US' ? 'Enable' : '启用' }}</span>
                </label>
                <input v-model="cfg.enterprise_features.cloud_streaming.webhook_url" placeholder="http://127.0.0.1:9090/ingest" class="ui-input w-full px-2 py-1 font-mono text-xs" />
              </div>
            </div>
          </div>
        </div>

        <div v-else class="flex-1 flex flex-col items-center justify-center text-xs gap-2" style="color: var(--text-muted);">
          <span v-if="configLoadError" class="text-rose-600 dark:text-rose-400 font-semibold">{{ configLoadError }}</span>
          <span v-else>{{ locale === 'en-US' ? 'Loading probe config from config.json...' : '正在从 config.json 加载探针配置...' }}</span>
          <button v-if="configLoadError" @click="loadConfig" class="ui-btn-primary px-3 py-1 text-xs">{{ locale === 'en-US' ? 'Retry Loading' : '重试加载' }}</button>
        </div>
      </div>

    </div>

    <!-- 三员身份切换模态框 -->
    <div v-if="showRoleModal" class="ui-modal-backdrop fixed inset-0 z-50 flex items-center justify-center p-4">
      <div class="ui-modal-surface rounded-2xl p-5 max-w-sm w-full space-y-4">
        <div class="flex items-center justify-between border-b pb-2.5" style="border-color: var(--border-subtle);">
          <h4 class="text-[13px] font-semibold" style="color: var(--text-primary);">{{ locale === 'en-US' ? 'MLPS Level 3 Tri-Role Authentication' : '等保三级 三员身份切换认证' }}</h4>
          <button @click="showRoleModal = false" class="p-1 rounded-lg hover:bg-[var(--surface-hover)] cursor-pointer" style="color: var(--text-secondary);">
            <AppIcon name="close" :size="14" />
          </button>
        </div>

        <div class="space-y-3 text-xs">
          <div>
            <label class="block font-semibold mb-1" style="color: var(--text-secondary);">{{ locale === 'en-US' ? 'Target Tri-Role' : '目标三员角色' }}</label>
            <select v-model="targetRole" class="ui-input w-full p-2 text-xs">
              <option value="SysAdmin">{{ locale === 'en-US' ? 'System Admin (SysAdmin · Ops & Engine)' : '系统管理员 (SysAdmin · 接口与引擎运维)' }}</option>
              <option value="SecAdmin">{{ locale === 'en-US' ? 'Security Admin (SecAdmin · Policies & Boundaries)' : '安全管理员 (SecAdmin · 策略与边界管控)' }}</option>
              <option value="AuditAdmin">{{ locale === 'en-US' ? 'Audit Admin (AuditAdmin · Logs & Forensics)' : '安全审计员 (AuditAdmin · 日志与取证验真)' }}</option>
            </select>
          </div>

          <div>
            <label class="block font-semibold mb-1" style="color: var(--text-secondary);">{{ locale === 'en-US' ? 'Operator Authorization Password' : '操作员授权口令' }}</label>
            <input v-model="rolePassword" type="password" :placeholder="locale === 'en-US' ? 'Enter role password' : '请输入对应角色的口令'" class="ui-input w-full p-2 font-mono text-xs" />
          </div>

          <div v-if="roleSwitchError" class="text-rose-600 dark:text-rose-400 text-[11px] font-semibold">
            {{ roleSwitchError }}
          </div>
        </div>

        <div class="flex justify-end gap-2 pt-2">
          <button @click="showRoleModal = false" class="ui-btn-secondary px-3 py-1.5 text-xs">{{ locale === 'en-US' ? 'Cancel' : '取消' }}</button>
          <button @click="confirmSwitchRole" class="ui-btn-primary px-4 py-1.5 text-xs">{{ locale === 'en-US' ? 'Confirm Switch' : '确认切换' }}</button>
        </div>
      </div>
    </div>

    <!-- 司法证据链验真报告弹窗 -->
    <div v-if="showVerifyModal" class="ui-modal-backdrop fixed inset-0 z-50 flex items-center justify-center p-4">
      <div class="ui-modal-surface rounded-2xl p-5 max-w-2xl w-full space-y-4 max-h-[85vh] flex flex-col select-text">
        <div class="flex items-center justify-between border-b pb-2.5 shrink-0" style="border-color: var(--border-subtle);">
          <div class="flex items-center gap-2">
            <h4 class="text-[13px] font-semibold" style="color: var(--text-primary);">{{ locale === 'en-US' ? 'Forensic Evidence Chain Integrity Report (MLPS 8.1.4.4)' : '司法证据链完整性验真报告 (等保三级 8.1.4.4)' }}</h4>
            <span
              :class="['px-2 py-0.5 rounded-full text-[11px] font-semibold',
                !verifyReport ? 'ui-pill' :
                (verifyReport.overall_status === 'PASS' ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300' :
                (verifyReport.overall_status === 'APPENDED' ? 'bg-blue-500/15 text-blue-700 dark:text-sky-300' : 'bg-rose-500/15 text-rose-700 dark:text-rose-300'))]"
            >
              {{ !verifyReport ? (locale === 'en-US' ? 'Pending' : '待触发核验') :
                 (verifyReport.overall_status === 'PASS' ? (locale === 'en-US' ? 'Exact Match Passed' : '完全匹配通过') :
                 (verifyReport.overall_status === 'APPENDED' ? (locale === 'en-US' ? 'Legally Appended' : '正常追加存证') : (locale === 'en-US' ? 'Suspicious Tampering Detected' : '检测到可疑篡改'))) }}
            </span>
          </div>
          <button @click="showVerifyModal = false" class="p-1 rounded-lg hover:bg-[var(--surface-hover)] cursor-pointer" style="color: var(--text-secondary);">
            <AppIcon name="close" :size="14" />
          </button>
        </div>

        <div v-if="verifyReport" class="flex-1 overflow-y-auto custom-scrollbar space-y-3 text-xs">
          <div class="ui-sub-card p-3 space-y-1" style="color: var(--text-secondary);">
            <div>{{ locale === 'en-US' ? 'Verified At: ' : '核验时间: ' }}<span class="font-semibold ui-num" style="color: var(--text-primary);">{{ verifyReport.verified_at }}</span></div>
            <div>{{ locale === 'en-US' ? 'Last Sealed At: ' : '最后封存时间: ' }}<span class="font-semibold ui-num" style="color: var(--text-primary);">{{ verifyReport.last_sealed_at }}</span> ({{ locale === 'en-US' ? 'Reason: ' : '触发原因: ' }}{{ verifyReport.last_seal_reason }})</div>
            <div>{{ locale === 'en-US' ? 'Summary: ' : '核验结论: ' }}<span class="font-semibold text-indigo-600 dark:text-indigo-300">{{ verifyReport.summary }}</span></div>
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
                <div>{{ locale === 'en-US' ? 'Expected SHA-256: ' : '封存 SHA-256: ' }}<span style="color: var(--text-secondary);">{{ item.expected_hash }}</span> ({{ item.sealed_size }} {{ locale === 'en-US' ? 'bytes' : '字节' }})</div>
                <div>{{ locale === 'en-US' ? 'Actual SHA-256: ' : '实测 SHA-256: ' }}<span style="color: var(--text-secondary);">{{ item.current_hash }}</span> ({{ item.current_size }} {{ locale === 'en-US' ? 'bytes' : '字节' }})</div>
              </div>
              <div class="text-[11px] mt-0.5" style="color: var(--text-secondary);">{{ item.details }}</div>
            </div>
          </div>
        </div>

        <div class="flex justify-end pt-2 border-t shrink-0" style="border-color: var(--border-subtle);">
          <button @click="showVerifyModal = false" class="ui-btn-primary px-4 py-1.5 text-xs">{{ locale === 'en-US' ? 'Close Report' : '关闭报告' }}</button>
        </div>
      </div>
    </div>

    <!-- 修改操作口令模态框 -->
    <div v-if="showChangePwdModal" class="ui-modal-backdrop fixed inset-0 z-50 flex items-center justify-center p-4">
      <div class="ui-modal-surface rounded-2xl p-5 max-w-sm w-full space-y-4">
        <div class="flex items-center justify-between border-b pb-2.5" style="border-color: var(--border-subtle);">
          <h4 class="text-[13px] font-semibold" style="color: var(--text-primary);">{{ locale === 'en-US' ? 'Change Operator Password (MLPS Level 3 Entropy)' : '修改操作员授权口令 (等保三级复杂度)' }}</h4>
          <button @click="showChangePwdModal = false" class="p-1 rounded-lg hover:bg-[var(--surface-hover)] cursor-pointer" style="color: var(--text-secondary);">
            <AppIcon name="close" :size="14" />
          </button>
        </div>

        <div class="space-y-3 text-xs">
          <div>
            <label class="block font-semibold mb-1" style="color: var(--text-secondary);">{{ locale === 'en-US' ? 'Target Role' : '目标角色' }}</label>
            <div class="ui-sub-card p-2 font-semibold" style="color: var(--text-primary);">
              {{ currentUser.role_title }}
            </div>
          </div>

          <div>
            <label class="block font-semibold mb-1" style="color: var(--text-secondary);">{{ locale === 'en-US' ? 'Current Password' : '原授权口令' }}</label>
            <input v-model="oldPassword" type="password" :placeholder="locale === 'en-US' ? 'Enter current password' : '请输入当前原口令'" class="ui-input w-full p-2 font-mono text-xs" />
          </div>

          <div>
            <label class="block font-semibold mb-1" style="color: var(--text-secondary);">{{ locale === 'en-US' ? 'New Password' : '新授权口令' }}</label>
            <input v-model="newPassword" type="password" :placeholder="locale === 'en-US' ? 'At least 8 chars with uppercase, lowercase & digits' : '至少8位，含大小写字母与数字'" class="ui-input w-full p-2 font-mono text-xs" />
          </div>

          <div v-if="changePwdError" class="text-rose-600 dark:text-rose-400 text-[11px] font-semibold">{{ changePwdError }}</div>
          <div v-if="changePwdSuccess" class="text-emerald-600 dark:text-emerald-400 text-[11px] font-semibold">{{ changePwdSuccess }}</div>
        </div>

        <div class="flex justify-end gap-2 pt-2">
          <button @click="showChangePwdModal = false" class="ui-btn-secondary px-3 py-1.5 text-xs">{{ locale === 'en-US' ? 'Cancel' : '取消' }}</button>
          <button @click="confirmChangePassword" class="ui-btn-primary px-4 py-1.5 text-xs">{{ locale === 'en-US' ? 'Confirm & Persist' : '确认修改并固化' }}</button>
        </div>
      </div>
    </div>

    <!-- GB/T 22239-2019 等保测评现场核查报告预览与导出模态框 -->
    <div v-if="showReportModal" class="ui-modal-backdrop fixed inset-0 z-50 flex items-center justify-center p-4">
      <div class="ui-modal-surface rounded-2xl p-5 max-w-4xl w-full max-h-[88vh] flex flex-col space-y-3">
        <div class="flex items-center justify-between border-b pb-2.5 shrink-0" style="border-color: var(--border-subtle);">
          <div class="flex items-center gap-2">
            <AppIcon name="file" :size="16" class="text-[var(--accent-primary)]" />
            <h4 class="text-[13px] font-semibold" style="color: var(--text-primary);">
              {{ locale === 'en-US' ? 'National Standard MLPS 2.0/3.0 Field Assessment Report · Preview & Export' : '国家标准等保 2.0 / 3.0 现场测评核查大报告 · 预览与签章导出' }}
            </h4>
          </div>
          <button @click="showReportModal = false" class="p-1 rounded-lg hover:bg-[var(--surface-hover)] cursor-pointer" style="color: var(--text-secondary);">
            <AppIcon name="close" :size="14" />
          </button>
        </div>

        <!-- GB/T 28448-2019 官方标准测评裁决卡片 -->
        <div class="p-3 rounded-xl border shrink-0 space-y-1.5" :class="[
          targetAssessment.metrics.value.verdict.level === 'COMPLIANT'
            ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-800 dark:text-emerald-200'
            : targetAssessment.metrics.value.verdict.level === 'PARTIALLY_COMPLIANT'
            ? 'bg-amber-500/10 border-amber-500/40 text-amber-800 dark:text-amber-200'
            : 'bg-rose-500/10 border-rose-500/40 text-rose-800 dark:text-rose-200'
        ]">
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-2">
              <span class="text-xs font-bold uppercase tracking-wide">
                {{ locale === 'en-US' ? 'GB/T 28448-2019 Official Verdict:' : 'GB/T 28448-2019 标准测评结论裁决：' }}
              </span>
              <span class="px-2.5 py-0.5 rounded-full text-xs font-bold text-white shadow-sm" :class="[
                targetAssessment.metrics.value.verdict.level === 'COMPLIANT' ? 'bg-emerald-600' :
                targetAssessment.metrics.value.verdict.level === 'PARTIALLY_COMPLIANT' ? 'bg-amber-600' : 'bg-rose-600'
              ]">
                {{ targetAssessment.metrics.value.verdict.levelText }}
              </span>
            </div>
            <div class="text-[11px] font-mono opacity-80">
              {{ locale === 'en-US' ? `Overall Rate: ${targetAssessment.metrics.value.overallScorePct}% · Applicable: ${targetAssessment.metrics.value.applicableCount} clauses` : `综合达标率: ${targetAssessment.metrics.value.overallScorePct}% · 适用项: ${targetAssessment.metrics.value.applicableCount} 项` }}
            </div>
          </div>
          <div class="text-xs leading-relaxed">
            <span class="font-semibold">{{ locale === 'en-US' ? 'Verdict Basis: ' : '裁决依据：' }}</span>{{ targetAssessment.metrics.value.verdict.reason }}
          </div>
          <div v-if="targetAssessment.metrics.value.verdict.isVetoedByCriticalRisk" class="text-xs font-bold text-rose-700 dark:text-rose-300 flex items-center gap-1.5 pt-0.5">
            <span>{{ locale === 'en-US' ? '🚨 Veto Redline Triggered:' : '🚨 一票否决红线触发：' }}</span>
            <span>{{ locale === 'en-US' ? `Hit ${targetAssessment.metrics.value.verdict.criticalDefectCount} critical defects; adjudicated Non-Compliant according to MPS Section 5.` : `实测命中 ${targetAssessment.metrics.value.verdict.criticalDefectCount} 项严重高危缺陷，依据公安部第 5 节规约总体结论裁决为不合格！` }}</span>
          </div>
        </div>

        <div class="text-[11px] text-[var(--text-muted)] shrink-0 flex items-center justify-between">
          <span>{{ locale === 'en-US' ? 'Report solidified: Control domain score matrix, field evidence, PoAM defect list & signatory anti-counterfeit' : '报告已固化：控制域得分矩阵、现场探活证据链、PoAM 缺陷清单与四方责任签署防伪栏' }}</span>
          <span>GB/T 22239-2019 / GB/T 28448-2019</span>
        </div>

        <div class="flex-1 overflow-auto custom-scrollbar p-3 rounded-xl border font-mono text-xs leading-relaxed select-text" style="border-color: var(--border-subtle); background: var(--surface-input); color: var(--text-primary); white-space: pre-wrap;">
          {{ generatedReportMarkdown }}
        </div>

        <div class="flex justify-between items-center pt-2 border-t shrink-0" style="border-color: var(--border-subtle);">
          <div class="flex items-center gap-2">
            <button @click="printFormalReport" class="px-3 py-1.5 text-xs font-semibold rounded-lg bg-indigo-600 text-white hover:bg-indigo-700 transition-colors flex items-center gap-1.5 shadow-sm">
              <AppIcon name="print" :size="13" />
              <span>{{ locale === 'en-US' ? '🖨️ Print Formal Report (A4/PDF)' : '🖨️ 打印正式大报告 (A4/PDF)' }}</span>
            </button>
            <button @click="downloadReportHtmlFile" class="ui-btn-secondary px-3 py-1.5 text-xs font-semibold flex items-center gap-1.5">
              <AppIcon name="download" :size="13" />
              <span>{{ locale === 'en-US' ? '📥 Download Formal HTML Report' : '📥 下载正式 HTML 大报告' }}</span>
            </button>
          </div>
          <div class="flex items-center gap-2">
            <button @click="copyReportToClipboard" class="ui-btn-secondary px-3 py-1.5 text-xs font-semibold flex items-center gap-1.5">
              <AppIcon name="copy" :size="13" />
              <span>{{ locale === 'en-US' ? 'Copy Markdown' : '复制 Markdown' }}</span>
            </button>
            <button @click="downloadReportFile" class="ui-btn-secondary px-3 py-1.5 text-xs font-semibold flex items-center gap-1.5">
              <AppIcon name="download" :size="13" />
              <span>{{ locale === 'en-US' ? 'Download .md' : '下载 .md' }}</span>
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- 手动编辑现场测评证据与加固建议模态框 -->
    <div v-if="showEditEvidenceModal && editingItem" class="ui-modal-backdrop fixed inset-0 z-50 flex items-center justify-center p-4">
      <div class="ui-modal-surface rounded-2xl p-5 max-w-lg w-full space-y-4">
        <div class="flex items-center justify-between border-b pb-2.5" style="border-color: var(--border-subtle);">
          <div class="flex items-center gap-2">
            <AppIcon name="edit" :size="15" class="text-[var(--accent-primary)]" />
            <h4 class="text-[13px] font-semibold" style="color: var(--text-primary);">
              {{ locale === 'en-US' ? `Edit Audit Evidence & Verdict · [${editingItem.id}]` : `编辑测评证据与判定 · [${editingItem.id}]` }}
            </h4>
          </div>
          <button @click="showEditEvidenceModal = false" class="p-1 rounded-lg hover:bg-[var(--surface-hover)] cursor-pointer" style="color: var(--text-secondary);">
            <AppIcon name="close" :size="14" />
          </button>
        </div>

        <div class="space-y-3 text-xs">
          <div>
            <div class="text-[11px] text-[var(--text-muted)]">{{ editingItem.clause }} · {{ editingItem.categoryLabel }}</div>
            <div class="font-semibold text-sm mt-0.5" style="color: var(--text-primary);">{{ editingItem.title }}</div>
            <div class="text-[11px] text-[var(--text-secondary)] mt-1 leading-relaxed">{{ editingItem.requirement }}</div>
          </div>

          <div>
            <label class="block font-semibold mb-1" style="color: var(--text-secondary);">{{ locale === 'en-US' ? 'Compliance Verdict' : '符合性判定结论' }}</label>
            <select v-model="editFormStatus" class="ui-input w-full p-2 text-xs">
              <option value="COMPLIANT">{{ locale === 'en-US' ? '✅ Compliant (COMPLIANT)' : '✅ 符合 (COMPLIANT)' }}</option>
              <option value="PARTIAL">{{ locale === 'en-US' ? '⚠️ Partially Compliant (PARTIAL)' : '⚠️ 部分符合 (PARTIAL)' }}</option>
              <option value="NON_COMPLIANT">{{ locale === 'en-US' ? '❌ Non-compliant (NON_COMPLIANT)' : '❌ 不符合 (NON_COMPLIANT)' }}</option>
              <option value="NA">{{ locale === 'en-US' ? '⚪ Not Applicable (NA)' : '⚪ 不适用 (NA)' }}</option>
              <option value="PENDING">{{ locale === 'en-US' ? '⏳ Pending Verification (PENDING)' : '⏳ 待核验 (PENDING)' }}</option>
            </select>
          </div>

          <div>
            <label class="block font-semibold mb-1" style="color: var(--text-secondary);">{{ locale === 'en-US' ? 'Field Audit Evidence Chain' : '现场实测探活证据链 (Evidence)' }}</label>
            <textarea
              v-model="editFormEvidence"
              rows="3"
              :placeholder="locale === 'en-US' ? 'Enter field audit objective telemetry or credentials...' : '请输入现场探活客观数据或查验设备凭证...'"
              class="ui-input w-full p-2 text-xs font-mono leading-relaxed"
            ></textarea>
          </div>

          <div>
            <label class="block font-semibold mb-1" style="color: var(--text-secondary);">{{ locale === 'en-US' ? 'Remediation Recommendations' : '加固整改建议 (Remediation)' }}</label>
            <textarea
              v-model="editFormRemediation"
              rows="2"
              :placeholder="locale === 'en-US' ? 'Remediation recommendations for this gap...' : '针对该项差距给出的整改建议...'"
              class="ui-input w-full p-2 text-xs leading-relaxed"
            ></textarea>
          </div>
        </div>

        <div class="flex justify-end gap-2 pt-2 border-t" style="border-color: var(--border-subtle);">
          <button @click="showEditEvidenceModal = false" class="ui-btn-secondary px-3 py-1.5 text-xs">{{ locale === 'en-US' ? 'Cancel' : '取消' }}</button>
          <button @click="saveEditEvidence" class="ui-btn-primary px-4 py-1.5 text-xs">{{ locale === 'en-US' ? 'Save Changes' : '保存修改' }}</button>
        </div>
      </div>
    </div>

    <!-- 网络设备配置文件离线词法与等保基线核查模态框 -->
    <div v-if="showDeviceConfigModal" class="ui-modal-backdrop fixed inset-0 z-50 flex items-center justify-center p-4">
      <div class="ui-modal-surface rounded-2xl p-5 max-w-4xl w-full max-h-[90vh] flex flex-col space-y-3">
        <div class="flex items-center justify-between border-b pb-2.5 shrink-0" style="border-color: var(--border-subtle);">
          <div class="flex items-center gap-2">
            <AppIcon name="cpu" :size="16" class="text-[var(--accent-primary)]" />
            <h4 class="text-[13px] font-semibold" style="color: var(--text-primary);">
              {{ locale === 'en-US' ? 'Network Device Config Offline Baseline Audit Engine (Huawei / Cisco / H3C)' : '网络设备配置文件离线基线核查引擎 (Huawei / Cisco / H3C)' }}
            </h4>
          </div>
          <button @click="showDeviceConfigModal = false" class="p-1 rounded-lg hover:bg-[var(--surface-hover)] cursor-pointer" style="color: var(--text-secondary);">
            <AppIcon name="close" :size="14" />
          </button>
        </div>

        <!-- 切换采集模式 -->
        <div class="flex items-center justify-between gap-2 shrink-0 flex-wrap text-xs">
          <div class="flex items-center gap-1 glass-pill p-1 rounded-xl">
            <button
              @click="deviceCollectMode = 'online'"
              :class="[
                'px-3 py-1 rounded-lg text-xs font-semibold transition-all cursor-pointer flex items-center gap-1.5',
                deviceCollectMode === 'online' ? 'bg-[var(--accent-primary)] text-white shadow-xs' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
              ]"
            >
              <span>{{ locale === 'en-US' ? '⚡ Online Automated Collection (SSH/Telnet)' : '⚡ 在线自动化采集 (SSH/Telnet)' }}</span>
            </button>
            <button
              @click="deviceCollectMode = 'manual'"
              :class="[
                'px-3 py-1 rounded-lg text-xs font-semibold transition-all cursor-pointer flex items-center gap-1.5',
                deviceCollectMode === 'manual' ? 'bg-[var(--accent-primary)] text-white shadow-xs' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
              ]"
            >
              <span>{{ locale === 'en-US' ? 'Manual Text Paste / Sample Import' : '手动文本粘贴/样本导入' }}</span>
            </button>
          </div>
          <div v-if="deviceCollectMode === 'manual'" class="flex items-center gap-1.5">
            <button @click="loadDeviceConfigDemo('huawei')" class="ui-btn-secondary px-2.5 py-1 text-[11px]">{{ locale === 'en-US' ? 'Load Huawei Sample' : '载入华为合规样本' }}</button>
            <button @click="loadDeviceConfigDemo('cisco')" class="ui-btn-secondary px-2.5 py-1 text-[11px]">{{ locale === 'en-US' ? 'Load Cisco Defect Sample' : '载入思科缺陷样本' }}</button>
          </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-3 flex-1 min-h-0">
          <!-- 左侧：输入配置文本 或 在线采集表单 -->
          <div class="flex flex-col min-h-0 space-y-2">
            <!-- 模式 1: 在线自动化采集表单 -->
            <div v-if="deviceCollectMode === 'online'" class="ui-sub-card p-3 space-y-2.5 border rounded-xl flex-1 flex flex-col justify-between" style="background: var(--surface-input);">
              <div class="space-y-2 text-xs">
                <div class="font-semibold text-xs flex items-center gap-1.5" style="color: var(--text-primary);">
                  <AppIcon name="cpu" :size="14" class="text-[var(--accent-primary)]" />
                  <span>{{ locale === 'en-US' ? 'Switch/Router Credentials Online Batch Collector (No manual copy-paste)' : '交换机/路由器凭据在线批量采集 (无需手工登录拷贝)' }}</span>
                </div>
                <div class="grid grid-cols-3 gap-2">
                  <div class="col-span-2">
                    <label class="text-[10px] text-[var(--text-muted)]">{{ locale === 'en-US' ? 'Target Device IP:' : '目标设备 IP 地址:' }}</label>
                    <input v-model="remoteDeviceParams.host" class="ui-input w-full px-2 py-1 text-xs font-mono" placeholder="192.168.1.1" />
                  </div>
                  <div>
                    <label class="text-[10px] text-[var(--text-muted)]">{{ locale === 'en-US' ? 'Port:' : '端口:' }}</label>
                    <input v-model.number="remoteDeviceParams.port" type="number" class="ui-input w-full px-2 py-1 text-xs font-mono" />
                  </div>
                </div>
                <div class="grid grid-cols-2 gap-2">
                  <div>
                    <label class="text-[10px] text-[var(--text-muted)]">{{ locale === 'en-US' ? 'Protocol:' : '传输协议:' }}</label>
                    <select v-model="remoteDeviceParams.protocol" class="ui-input w-full px-2 py-1 text-xs font-mono">
                      <option value="SSH">{{ locale === 'en-US' ? 'SSH (Recommended Secure)' : 'SSH (推荐安全协议)' }}</option>
                      <option value="TELNET">{{ locale === 'en-US' ? 'Telnet (Legacy Compatibility)' : 'Telnet (工控老旧设备兼容)' }}</option>
                    </select>
                  </div>
                  <div>
                    <label class="text-[10px] text-[var(--text-muted)]">{{ locale === 'en-US' ? 'Username:' : '管理用户名:' }}</label>
                    <input v-model="remoteDeviceParams.username" class="ui-input w-full px-2 py-1 text-xs font-mono" placeholder="admin" />
                  </div>
                </div>
                <div class="grid grid-cols-2 gap-2">
                  <div>
                    <label class="text-[10px] text-[var(--text-muted)]">{{ locale === 'en-US' ? 'Password:' : '登录密码:' }}</label>
                    <input v-model="remoteDeviceParams.password" type="password" class="ui-input w-full px-2 py-1 text-xs" placeholder="••••••••" />
                  </div>
                  <div>
                    <label class="text-[10px] text-[var(--text-muted)]">{{ locale === 'en-US' ? 'Enable Password (Optional):' : '特权 Enable 密码 (可选):' }}</label>
                    <input v-model="remoteDeviceParams.enable_password" type="password" class="ui-input w-full px-2 py-1 text-xs" :placeholder="locale === 'en-US' ? 'Cisco privileged mode password' : '思科特权模式密码'" />
                  </div>
                </div>
                <div class="text-[11px] p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-800 dark:text-emerald-200">
                  {{ locale === 'en-US' ? 'System securely executes screen-length 0 temporary or terminal length 0 to suppress pagination, instantly extracting running config and running lexical Dissector.' : '系统将通过安全管道自动下发 screen-length 0 temporary 或 terminal length 0 抑制分页，瞬间提取完整配置文件并自动运行词法 Dissector。' }}
                </div>
              </div>
              <button
                @click="handleFetchRemoteDeviceConfig"
                :disabled="isCollectingRemoteDevice"
                class="ui-btn-primary w-full py-2 text-xs font-semibold flex items-center justify-center gap-1.5 shadow-sm"
              >
                <AppIcon v-if="isCollectingRemoteDevice" name="refresh" :size="13" class="animate-spin" />
                <AppIcon v-else name="search" :size="13" />
                <span>{{ isCollectingRemoteDevice ? (locale === 'en-US' ? 'Logging in and pulling config...' : '正在登录设备抓取配置中...') : (locale === 'en-US' ? '⚡ Collect Online & Audit' : '⚡ 立即在线登录抓取并核查') }}</span>
              </button>
            </div>

            <!-- 模式 2: 手动文本输入 -->
            <template v-else>
              <label class="text-[11px] font-semibold" style="color: var(--text-secondary);">{{ locale === 'en-US' ? 'Device Running Config Text (Raw Config):' : '设备运行配置文本 (Raw Config Text):' }}</label>
              <textarea
                v-model="deviceConfigText"
                :placeholder="locale === 'en-US' ? 'Paste switch/router config text (e.g. Huawei dis current or Cisco show run)...' : '请粘贴交换机或路由器的配置文本 (如华为 dis current 或思科 show run)...'"
                class="ui-input flex-1 p-2 text-xs font-mono resize-none leading-relaxed custom-scrollbar select-text"
              ></textarea>
              <div class="flex justify-end pt-1">
                <button @click="runDeviceConfigAnalysis" class="ui-btn-primary px-3 py-1.5 text-xs font-semibold flex items-center gap-1.5">
                  <AppIcon name="search" :size="13" />
                  <span>{{ locale === 'en-US' ? 'Run Dissector & Baseline Audit' : '执行词法解析与基线核查' }}</span>
                </button>
              </div>
            </template>
          </div>

          <!-- 右侧：分析结果与 8 项基线状态 -->
          <div class="flex flex-col min-h-0 space-y-1.5 border rounded-xl p-3 overflow-hidden" style="border-color: var(--border-subtle); background: var(--surface-input);">
            <template v-if="deviceConfigReport">
              <div class="flex items-center justify-between border-b pb-2 shrink-0" style="border-color: var(--border-subtle);">
                <div>
                  <div class="font-bold text-xs" style="color: var(--text-primary);">
                    {{ deviceConfigReport.hostname }} · {{ deviceConfigReport.vendorLabel }}
                  </div>
                  <div class="text-[10px] text-[var(--text-muted)]">{{ locale === 'en-US' ? `Analyzed: ${deviceConfigReport.totalLines} lines` : `分析行数: ${deviceConfigReport.totalLines} 行` }}</div>
                </div>
                <div class="text-right">
                  <div class="text-sm font-bold ui-num" :class="deviceConfigReport.complianceRatePct >= 80 ? 'text-emerald-700 dark:text-emerald-300' : 'text-rose-700 dark:text-rose-300'">
                    {{ deviceConfigReport.complianceRatePct }}%
                  </div>
                  <div class="text-[10px] text-[var(--text-muted)]">{{ locale === 'en-US' ? `Passed ${deviceConfigReport.passedCount} / Failed ${deviceConfigReport.failedCount}` : `通过 ${deviceConfigReport.passedCount} / 失败 ${deviceConfigReport.failedCount}` }}</div>
                </div>
              </div>

              <div class="flex-1 overflow-auto custom-scrollbar space-y-2 pr-1">
                <div
                  v-for="res in deviceConfigReport.results"
                  :key="res.ruleId"
                  class="p-2 rounded-lg border text-xs leading-relaxed"
                  :class="res.passed ? 'bg-emerald-500/8 border-emerald-500/25' : 'bg-rose-500/8 border-rose-500/25'"
                >
                  <div class="flex items-center justify-between font-semibold">
                    <span :class="res.passed ? 'text-emerald-700 dark:text-emerald-300' : 'text-rose-700 dark:text-rose-300'">
                      {{ res.passed ? '✅' : '❌' }} [{{ res.ruleId }}] {{ res.title }}
                    </span>
                    <span class="text-[10px] ui-pill px-1.5 py-0.2 rounded">{{ res.clause.replace('GB/T 22239-2019 ', '') }}</span>
                  </div>
                  <div class="text-[11px] mt-1 font-mono" style="color: var(--text-secondary);">
                    {{ res.evidence }}
                  </div>
                  <div v-if="!res.passed" class="text-[10px] text-amber-700 dark:text-amber-300 mt-0.5">
                    {{ locale === 'en-US' ? 'Remediation: ' : '整改建议: ' }}{{ res.remediation }}
                  </div>
                </div>
              </div>
            </template>
            <div v-else class="flex-1 flex flex-col items-center justify-center text-xs" style="color: var(--text-muted);">
              <AppIcon name="cpu" :size="32" class="opacity-30 mb-2" />
              <span>{{ locale === 'en-US' ? 'Enter config on the left and click Run Dissector' : '请在左侧输入配置并点击【执行词法解析】' }}</span>
            </div>
          </div>
        </div>

        <div class="flex justify-between items-center pt-2 border-t shrink-0" style="border-color: var(--border-subtle);">
          <span class="text-[11px] text-[var(--text-muted)]">{{ locale === 'en-US' ? 'Results map directly to SCN-03, SCE-01, SCE-06, SMC-02 clauses' : '核查结果可直接映射至 SCN-03、SCE-01、SCE-06、SMC-02 等条款' }}</span>
          <div class="flex items-center gap-2">
            <button @click="showDeviceConfigModal = false" class="ui-btn-secondary px-3 py-1.5 text-xs">{{ locale === 'en-US' ? 'Close' : '关闭' }}</button>
            <button
              @click="applyDeviceConfigToMatrix"
              :disabled="!deviceConfigReport"
              class="ui-btn-primary px-4 py-1.5 text-xs font-semibold"
            >
              {{ locale === 'en-US' ? 'Inject Config Audit Results into Matrix' : '将配置核查结果注入测评矩阵' }}
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- 主机安全计算环境 (SCE) 等保 2.0 基线实测模态框 -->
    <div v-if="showHostBaselineModal" class="ui-modal-backdrop fixed inset-0 z-50 flex items-center justify-center p-4">
      <div class="ui-modal-surface rounded-2xl p-5 max-w-4xl w-full max-h-[90vh] flex flex-col space-y-3">
        <div class="flex items-center justify-between border-b pb-2.5 shrink-0" style="border-color: var(--border-subtle);">
          <div class="flex items-center gap-2">
            <AppIcon name="shield" :size="16" class="text-emerald-600 dark:text-emerald-400" />
            <h4 class="text-[13px] font-semibold" style="color: var(--text-primary);">
              {{ locale === 'en-US' ? 'Host Secure Computing Environment (SCE) Baseline Audit Panel (GB/T 22239)' : '主机安全计算环境 (SCE) 等保基线实测面板 (GB/T 22239-2019)' }}
            </h4>
          </div>
          <button @click="showHostBaselineModal = false" class="p-1 rounded-lg hover:bg-[var(--surface-hover)] cursor-pointer" style="color: var(--text-secondary);">
            <AppIcon name="close" :size="14" />
          </button>
        </div>

        <template v-if="hostBaselineReport">
          <!-- 总体得分看板 -->
          <div class="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs shrink-0">
            <div class="ui-sub-card p-2.5">
              <div class="text-[10px]" style="color: var(--text-muted);">{{ locale === 'en-US' ? 'Hostname / OS' : '被测主机名 / 操作系统' }}</div>
              <div class="font-bold text-xs truncate mt-0.5" style="color: var(--text-primary);">
                {{ hostBaselineReport.hostname }} ({{ hostBaselineReport.os_name }})
              </div>
            </div>
            <div class="ui-sub-card p-2.5">
              <div class="text-[10px]" style="color: var(--text-muted);">{{ locale === 'en-US' ? 'SCE Compliance Rate' : 'SCE 基线合规达标率' }}</div>
              <div class="text-base font-bold ui-num mt-0.5" :class="hostBaselineReport.compliance_rate_pct >= 80 ? 'text-emerald-600 dark:text-emerald-400' : 'text-amber-600 dark:text-amber-400'">
                {{ hostBaselineReport.compliance_rate_pct }}%
              </div>
            </div>
            <div class="ui-sub-card p-2.5">
              <div class="text-[10px]" style="color: var(--text-muted);">{{ locale === 'en-US' ? 'Total Standard Checks' : '国标检查总项数' }}</div>
              <div class="text-base font-bold ui-num mt-0.5" style="color: var(--text-primary);">
                {{ locale === 'en-US' ? `Passed ${hostBaselineReport.passed_checks} / Defect ${hostBaselineReport.failed_checks} (${hostBaselineReport.total_checks} total)` : `通过 ${hostBaselineReport.passed_checks} / 缺陷 ${hostBaselineReport.failed_checks} (共 ${hostBaselineReport.total_checks} 项)` }}
              </div>
            </div>
            <div class="ui-sub-card p-2.5">
              <div class="text-[10px]" style="color: var(--text-muted);">{{ locale === 'en-US' ? 'Scan Timestamp' : '实测采集时间戳' }}</div>
              <div class="text-[11px] font-mono mt-0.5 truncate" style="color: var(--text-secondary);">
                {{ hostBaselineReport.scan_time }}
              </div>
            </div>
          </div>

          <!-- 逐项检查卡片列表 -->
          <div class="flex-1 overflow-auto custom-scrollbar space-y-2 pr-1">
            <div
              v-for="item in hostBaselineReport.items"
              :key="item.id"
              class="p-2.5 rounded-xl border text-xs leading-relaxed"
              :class="item.passed ? 'bg-emerald-500/8 border-emerald-500/25' : 'bg-rose-500/8 border-rose-500/25'"
            >
              <div class="flex items-center justify-between font-semibold">
                <span :class="item.passed ? 'text-emerald-700 dark:text-emerald-300' : 'text-rose-700 dark:text-rose-300'">
                  {{ item.passed ? '✅' : '❌' }} [{{ item.id }}] {{ item.title }}
                </span>
                <div class="flex items-center gap-1.5">
                  <span class="text-[10px] ui-pill px-1.5 py-0.2 rounded">{{ item.clause.replace('GB/T 22239-2019 ', '') }}</span>
                  <span
                    class="px-1.5 py-0.2 rounded text-[10px] font-bold"
                    :class="item.risk_level === 'CRITICAL' ? 'bg-rose-500/20 text-rose-700 dark:text-rose-300' : (item.risk_level === 'HIGH' ? 'bg-amber-500/20 text-amber-700 dark:text-amber-300' : 'bg-emerald-500/20 text-emerald-700 dark:text-emerald-300')"
                  >
                    {{ item.risk_level }}
                  </span>
                </div>
              </div>
              <div class="text-[11px] mt-1 space-y-0.5 font-mono" style="color: var(--text-secondary);">
                <div>{{ locale === 'en-US' ? 'Actual Value: ' : '实测采集状态: ' }}<b style="color: var(--text-primary);">{{ item.actual_value }}</b></div>
                <div>{{ locale === 'en-US' ? 'Standard Requirement: ' : '等保标准要求: ' }}{{ item.standard_requirement }}</div>
                <div class="text-[10px] opacity-90">{{ locale === 'en-US' ? 'Evidence: ' : '客观依据: ' }}{{ item.evidence }}</div>
              </div>
              <div v-if="!item.passed" class="text-[10px] text-amber-700 dark:text-amber-300 mt-1 font-sans">
                {{ locale === 'en-US' ? 'Remediation: ' : '整改建议: ' }}{{ item.remediation }}
              </div>
            </div>
          </div>
        </template>

        <div class="flex justify-between items-center pt-2 border-t shrink-0" style="border-color: var(--border-subtle);">
          <span class="text-[11px] text-[var(--text-muted)]">{{ locale === 'en-US' ? 'Evidence auto-injected into Level 3 SCE-01 (pwd), SCE-02 (lockout), SCE-03 (guest), SCE-06 (timeout)' : '实测证据链将自动注入等保三级 SCE-01 (口令)、SCE-02 (锁定)、SCE-03 (Guest)、SCE-06 (超时) 等条款' }}</span>
          <div class="flex items-center gap-2">
            <button @click="showHostBaselineModal = false" class="ui-btn-secondary px-3 py-1.5 text-xs">{{ locale === 'en-US' ? 'Close' : '关闭' }}</button>
            <button
              @click="applyHostBaselineToMatrix"
              :disabled="!hostBaselineReport"
              class="ui-btn-primary bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-1.5 text-xs font-semibold shadow-xs"
            >
              {{ locale === 'en-US' ? 'Inject Host SCE Evidence into Matrix' : '将主机基线实测证据注入测评矩阵' }}
            </button>
          </div>
        </div>
      </div>
    </div>

  </div>
</template>

<script setup lang="ts">
import { notifySuccess, notifyWarning, notifyError } from '../composables/useNotification';
import { uiConfirm } from '../composables/useConfirmDialog';
import { ref, computed, onMounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import AppIcon from '../components/AppIcon.vue';
import { useI18n } from '../i18n';

const { locale } = useI18n();
import { useUniversalDiff } from '../composables/useUniversalDiff';
import {
  useTargetComplianceAssessment,
  generateGbMarkdownReport,
  generateGbFormalAuditReportHtml,
  type TargetComplianceItem,
  type ComplianceStatus,
  type ProbeContext,
} from '../composables/useTargetComplianceAssessment';
import {
  dissectNetworkDeviceConfig,
  type DeviceConfigAnalysisReport,
} from '../utils/networkDeviceConfigDissector';
import type { HostBaselineReport } from '../composables/useTargetComplianceAssessment';

const diffBus = useUniversalDiff();

// 双视角切换：'target' (被测目标现场测评) vs 'probe_self' (探针自身安全防御基线)
const compliancePerspective = ref<'target' | 'probe_self'>('target');

// 被测目标网络/工控设备等保现场测评状态机
const targetAssessment = useTargetComplianceAssessment();

// 主机安全计算环境 (SCE) 等保基线实测状态机
const showHostBaselineModal = ref(false);
const isAuditingHostBaseline = ref(false);
const hostBaselineReport = ref<HostBaselineReport | null>(null);

async function runHostBaselineAudit() {
  isAuditingHostBaseline.value = true;
  try {
    const report = await invoke<HostBaselineReport>('audit_host_baseline_local_cmd');
    hostBaselineReport.value = report;
    showHostBaselineModal.value = true;
    notifySuccess(locale.value === 'en-US' ? `Host baseline audit completed: ${report.hostname} (${report.os_name}), compliance rate ${report.compliance_rate_pct}%` : `主机基线实测完成: ${report.hostname} (${report.os_name})，合规率 ${report.compliance_rate_pct}%`);
  } catch (e) {
    notifyError(locale.value === 'en-US' ? 'Host baseline audit failed' : '主机基线审计失败', String(e));
  } finally {
    isAuditingHostBaseline.value = false;
  }
}

function applyHostBaselineToMatrix() {
  if (!hostBaselineReport.value) return;
  targetAssessment.applyHostBaselineReport(hostBaselineReport.value);
  showHostBaselineModal.value = false;
  notifySuccess(locale.value === 'en-US' ? `Host [${hostBaselineReport.value.hostname}] SCE evidence injected into MLPS matrix` : `已将 [${hostBaselineReport.value.hostname}] 主机 SCE 实测证据注入等保矩阵`);
}

// 设备配置文件离线基线核查状态机
const showDeviceConfigModal = ref(false);
const deviceConfigText = ref('');
const deviceConfigReport = ref<DeviceConfigAnalysisReport | null>(null);
const deviceCollectMode = ref<'online' | 'manual'>('manual');
const remoteDeviceParams = ref({
  host: '192.168.1.1',
  port: 22,
  protocol: 'SSH',
  username: 'admin',
  password: '',
  enable_password: '',
  timeout_secs: 15,
});
const isCollectingRemoteDevice = ref(false);

async function handleFetchRemoteDeviceConfig() {
  const host = remoteDeviceParams.value.host.trim();
  if (!host) {
    notifyWarning(locale.value === 'en-US' ? 'Please enter a valid target network device IP address' : '请输入合法的目标网络设备 IP 地址');
    return;
  }
  isCollectingRemoteDevice.value = true;
  try {
    const output = await invoke<string>('fetch_remote_device_config_cmd', {
      params: {
        host,
        port: Number(remoteDeviceParams.value.port),
        protocol: remoteDeviceParams.value.protocol,
        username: remoteDeviceParams.value.username.trim(),
        password: remoteDeviceParams.value.password || null,
        enable_password: remoteDeviceParams.value.enable_password || null,
        vendor_hint: null,
        timeout_secs: Number(remoteDeviceParams.value.timeout_secs),
      },
    });
    deviceConfigText.value = output;
    runDeviceConfigAnalysis();
    notifySuccess(locale.value === 'en-US' ? 'Remote device config fetched successfully' : '远程网络设备配置抓取成功', locale.value === 'en-US' ? `Extracted ${output.split('\n').length} lines from ${host} and completed baseline analysis` : `从 ${host} 提取到 ${output.split('\n').length} 行配置并完成基线分析`);
  } catch (e) {
    notifyError(locale.value === 'en-US' ? 'Failed to fetch remote device config' : '远程设备配置抓取失败', String(e));
  } finally {
    isCollectingRemoteDevice.value = false;
  }
}

function openDeviceConfigModal() {
  showDeviceConfigModal.value = true;
}

function runDeviceConfigAnalysis() {
  const text = deviceConfigText.value.trim();
  if (!text) {
    notifyWarning(locale.value === 'en-US' ? 'Please enter or paste switch/router config text first' : '请先输入或粘贴交换机/路由器配置文件内容');
    return;
  }
  deviceConfigReport.value = dissectNetworkDeviceConfig(text);
  notifySuccess(locale.value === 'en-US' ? `Config dissection complete: Detected ${deviceConfigReport.value.vendorLabel}, compliance rate ${deviceConfigReport.value.complianceRatePct}%` : `配置解析完成: 检测到 ${deviceConfigReport.value.vendorLabel}，基线合规率 ${deviceConfigReport.value.complianceRatePct}%`);
}

function loadDeviceConfigDemo(type: 'huawei' | 'cisco') {
  if (type === 'huawei') {
    deviceConfigText.value = `#
sysname CORE-SW-01
#
ssh server protocol-version 2
undo telnet server enable
#
local-user admin password irreversible-cipher $1a$u/2134kjahsd$
local-user admin service-type ssh
local-user secadmin password irreversible-cipher $1a$lkasd91823$
local-user secadmin service-type ssh
#
account login-failed threshold 5
#
snmp-agent sys-info version v3
snmp-agent group v3 admin_group privacy
#
info-center loghost 192.168.10.250
#
user-interface vty 0 4
 authentication-mode aaa
 user-role network-admin
 idle-timeout 10 0
 protocol inbound ssh
#
return`;
  } else {
    deviceConfigText.value = `!
version 15.2
hostname EDGE-ROUTER-01
!
enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0
username admin password 0 Cisco123!
!
ip http server
telnet server enable
!
snmp-server community public RO
snmp-server community private RW
!
line vty 0 4
 transport input all
 exec-timeout 0 0
 login local
!
end`;
  }
  runDeviceConfigAnalysis();
}

function applyDeviceConfigToMatrix() {
  if (!deviceConfigReport.value) return;
  targetAssessment.applyDeviceConfigReport(deviceConfigReport.value);
  showDeviceConfigModal.value = false;
  notifySuccess(locale.value === 'en-US' ? `Device [${deviceConfigReport.value.hostname}] config evidence chain injected into matrix` : `已将 [${deviceConfigReport.value.hostname}] 设备配置实测证据链注入测评矩阵`);
}

// 报告导出与编辑证据模态框状态
const showReportModal = ref(false);
const generatedReportMarkdown = ref('');
const showEditEvidenceModal = ref(false);
const editingItem = ref<TargetComplianceItem | null>(null);
const editFormStatus = ref<ComplianceStatus>('COMPLIANT');
const editFormEvidence = ref('');
const editFormRemediation = ref('');

async function quickSelectGatewayAsTarget() {
  try {
    const assets = await invoke<any[]>('get_discovered_assets_cmd');
    if (assets && assets.length > 0) {
      const lanAsset = assets.find((a: any) => a.scope === '局域网内网' && a.ip !== '127.0.0.1') || assets[0];
      if (lanAsset && lanAsset.ip) {
        targetAssessment.targetIp.value = lanAsset.ip;
        notifySuccess(locale.value === 'en-US' ? `Auto-loaded discovered asset: ${lanAsset.ip}` : `已自动载入现场发现资产: ${lanAsset.ip}`);
        return;
      }
    }
    targetAssessment.targetIp.value = '192.168.1.1';
    notifySuccess(locale.value === 'en-US' ? 'Loaded default industrial gateway IP: 192.168.1.1' : '已载入常用工业网关基准 IP: 192.168.1.1');
  } catch (e) {
    targetAssessment.targetIp.value = '192.168.1.1';
    notifySuccess(locale.value === 'en-US' ? 'Loaded default gateway IP: 192.168.1.1' : '已载入默认网关 IP: 192.168.1.1');
  }
}

async function runProbeComplianceScan() {
  const ip = targetAssessment.targetIp.value.trim();
  if (!ip) {
    notifyWarning(locale.value === 'en-US' ? 'Please enter a valid target host or gateway IP' : '请输入合法的被测目标主机或网关 IP 地址');
    return;
  }

  targetAssessment.isProbing.value = true;
  targetAssessment.probeStatusMessage.value = locale.value === 'en-US' ? `Executing ICMP ping and core port live scan against ${ip}...` : `正在对目标 ${ip} 执行 ICMP 测活与核心端口深度探活...`;
  log(`[COMPLIANCE] 启动对目标 ${ip} 的等保 2.0 / 3.0 现场探针探活核查...`);

  try {
    // 1. ICMP Ping 测活与时延获取
    let pingAlive = false;
    let pingRtt: number | null = null;
    try {
      const pingRes: any = await invoke('run_icmp_ping_cmd', { targetIp: ip, timeoutMs: 2000 });
      if (pingRes && pingRes.success) {
        pingAlive = true;
        pingRtt = pingRes.rtt_ms ?? null;
      }
    } catch (e) {
      log(`[COMPLIANCE] ICMP 探测异常或禁 Ping: ${e}`);
    }

    // 2. TCP 端口深度探测
    let openPorts: number[] = [];
    try {
      openPorts = await invoke<number[]>('probe_asset_ports_cmd', { ip });
    } catch (e) {
      log(`[COMPLIANCE] 目标端口探测返回: ${e}`);
    }

    // 3. 构建探活上下文并注入评估模型
    const probeCtx: ProbeContext = {
      targetIp: ip,
      pingAlive,
      pingRttMs: pingRtt,
      openPorts: openPorts || [],
      cidrRuleCount: cidrRules.value.length,
      baselineMode: baselineStatus.value.mode,
      baselineRuleCount: baselineRules.value.length,
      syslogEnabled: syslogCfg.value.enabled,
      syslogServer: syslogCfg.value.server_ip ? `${syslogCfg.value.server_ip}:${syslogCfg.value.server_port}` : '',
      icsAclRuleCount: icsAclRuleCount.value,
      evidenceChainPassed: verifyReport.value?.overall_status === 'PASS' || verifyReport.value?.overall_status === 'APPENDED',
      rbacHardened: rbacSecurity.value.all_credentials_hardened,
    };

    targetAssessment.applyProbeTelemetry(probeCtx);

    const openSummary = openPorts.length > 0 ? (locale.value === 'en-US' ? `Open Ports: [${openPorts.join(', ')}]` : `开放端口: [${openPorts.join(', ')}]`) : (locale.value === 'en-US' ? 'No common open ports detected' : '未检出常规开放端口');
    const pingSummary = pingAlive ? (locale.value === 'en-US' ? `RTT ${pingRtt?.toFixed(1) || '<1'}ms` : `响应时延 ${pingRtt?.toFixed(1) || '<1'}ms`) : (locale.value === 'en-US' ? 'ICMP Timeout' : 'ICMP 超时');
    targetAssessment.probeStatusMessage.value = locale.value === 'en-US' ? `Probe complete: ${pingSummary} · ${openSummary} · Evidence mapped` : `探活完成: ${pingSummary} · ${openSummary} · 已自动映射测评证据链`;
    notifySuccess(locale.value === 'en-US' ? `Target ${ip} field probe complete, assessment evidence updated` : `目标 ${ip} 探针现场探活完成，测评证据已更新`);
    log(`[COMPLIANCE] 现场探针探活完成: ${targetAssessment.probeStatusMessage.value}`);
  } catch (err: any) {
    targetAssessment.probeStatusMessage.value = locale.value === 'en-US' ? `Field probe failed: ${err?.message || err}` : `现场探针探活失败: ${err?.message || err}`;
    notifyWarning(locale.value === 'en-US' ? `Field probe failed: ${err?.message || err}` : `现场探针探活失败: ${err?.message || err}`);
    log(`[ERROR] 探针合规探活失败: ${err}`);
  } finally {
    targetAssessment.isProbing.value = false;
  }
}

function openExportReportModal() {
  generatedReportMarkdown.value = generateGbMarkdownReport({
    targetIp: targetAssessment.targetIp.value.trim() || '127.0.0.1',
    targetLevel: targetAssessment.targetLevel.value,
    inspectorName: currentUser.value.username,
    inspectorRole: currentUser.value.role_title,
    items: targetAssessment.items.value,
    metrics: targetAssessment.metrics.value,
  });
  showReportModal.value = true;
}

function copyReportToClipboard() {
  if (navigator.clipboard) {
    navigator.clipboard.writeText(generatedReportMarkdown.value);
    notifySuccess(locale.value === 'en-US' ? 'Assessment report Markdown copied to clipboard' : '测评报告 Markdown 已成功复制至剪贴板');
  }
}

function downloadReportFile() {
  const blob = new Blob([generatedReportMarkdown.value], { type: 'text/markdown;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  const fileName = `DJCP_Assessment_Report_${targetAssessment.targetIp.value.replace(/[^0-9a-zA-Z]/g, '_')}_${new Date().toISOString().slice(0, 10)}.md`;
  a.download = fileName;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  notifySuccess(locale.value === 'en-US' ? `Report downloaded: ${fileName}` : `报告已下载: ${fileName}`);
}

function printFormalReport() {
  const htmlContent = generateGbFormalAuditReportHtml({
    targetIp: targetAssessment.targetIp.value.trim() || '127.0.0.1',
    targetLevel: targetAssessment.targetLevel.value,
    inspectorName: currentUser.value.username,
    inspectorRole: currentUser.value.role_title,
    items: targetAssessment.items.value,
    metrics: targetAssessment.metrics.value,
  });

  const printWindow = window.open('', '_blank');
  if (printWindow) {
    printWindow.document.open();
    printWindow.document.write(htmlContent);
    printWindow.document.close();
    printWindow.focus();
    setTimeout(() => {
      printWindow.print();
    }, 400);
    notifySuccess(locale.value === 'en-US' ? 'Invoked standard MLPS report print dialog' : '已唤起公安部标准等保大报告打印管道');
  } else {
    notifyWarning(locale.value === 'en-US' ? 'Popup blocked by browser, please allow popups and retry' : '弹窗被浏览器拦截，请允许弹出窗口后重试');
  }
}

function downloadReportHtmlFile() {
  const htmlContent = generateGbFormalAuditReportHtml({
    targetIp: targetAssessment.targetIp.value.trim() || '127.0.0.1',
    targetLevel: targetAssessment.targetLevel.value,
    inspectorName: currentUser.value.username,
    inspectorRole: currentUser.value.role_title,
    items: targetAssessment.items.value,
    metrics: targetAssessment.metrics.value,
  });

  const blob = new Blob([htmlContent], { type: 'text/html;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  const fileName = `DJCP_Official_Audit_Report_${targetAssessment.targetIp.value.replace(/[^0-9a-zA-Z]/g, '_')}_${new Date().toISOString().slice(0, 10)}.html`;
  a.download = fileName;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  notifySuccess(locale.value === 'en-US' ? `Formal MLPS HTML report downloaded: ${fileName}` : `正式等保 HTML 大报告已下载: ${fileName}`);
}

function openEditEvidenceModal(item: TargetComplianceItem) {
  editingItem.value = item;
  editFormStatus.value = item.status;
  editFormEvidence.value = item.evidence;
  editFormRemediation.value = item.remediation;
  showEditEvidenceModal.value = true;
}

function saveEditEvidence() {
  if (!editingItem.value) return;
  targetAssessment.updateItemStatus(editingItem.value.id, editFormStatus.value, editFormEvidence.value.trim());
  editingItem.value.remediation = editFormRemediation.value.trim();
  showEditEvidenceModal.value = false;
  notifySuccess(locale.value === 'en-US' ? `Clause [${editingItem.value.id}] evidence updated and solidified` : `条款 [${editingItem.value.id}] 评测证据已更新并固化`);
}

function addComplianceToDiffQueue(item: any) {
  const code = item.id || item.clause;
  const name = item.title || item.level;
  const detail = item.evidence || item.implementation || '';
  const raw = `${code} | ${name} | ${item.status} | ${detail}`;
  diffBus.addToQueue({
    id: `AUDIT_CMP_${code}`,
    label: locale.value === 'en-US' ? `[MLPS Clause] ${code}` : `[等保条款] ${code}`,
    protocol: 'GB/T 22239-2019',
    src: item.level || '等保三级',
    dst: item.status,
    format: 'ASCII',
    isRawText: true,
    payloadHex: '',
    rawText: raw,
    length: raw.length,
    extraFields: {
      clause: item.clause,
      title: item.title || '',
      level: item.level,
      status: item.status,
      requirement: item.requirement || '',
      evidence: detail,
    }
  }, `等保 ${code}`, false);
}

function addDriftToDiffQueue(ev: any) {
  const raw = `${ev.drift_type} | ${ev.src_ip} -> :${ev.dst_port} | ${ev.description}`;
  diffBus.addToQueue({
    id: `DRIFT_${ev.id}`,
    label: locale.value === 'en-US' ? `[Baseline Drift] ${ev.drift_type} #${ev.id}` : `[基线漂移] ${ev.drift_type} #${ev.id}`,
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
    label: locale.value === 'en-US' ? `[System Log #${idx + 1}]` : `[系统日志 #${idx + 1}]`,
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
const subTabs = computed(() => [
  { id: 'compliance', label: locale.value === 'en-US' ? 'Compliance Overview' : '等保合规总览' },
  { id: 'rbac', label: locale.value === 'en-US' ? 'RBAC Tri-Role' : '三员分立控制' },
  { id: 'baseline', label: locale.value === 'en-US' ? 'OT Baseline Whitelist' : '工业基线白名单' },
  { id: 'zones', label: locale.value === 'en-US' ? 'Security Zones (CIDR)' : '安全区域(CIDR)' },
  { id: 'syslog', label: locale.value === 'en-US' ? 'Syslog Export' : 'Syslog 集中外发' },
  { id: 'honeypot', label: locale.value === 'en-US' ? 'Deception / Honeypot' : '蜜罐主动防御' },
  { id: 'logs', label: locale.value === 'en-US' ? 'Runtime Audit Logs' : '运行日志审计' },
  { id: 'config', label: locale.value === 'en-US' ? 'Engine Config' : '引擎配置参数' },
]);
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
      status: isBaselineActive && hasBaselineRules ? (locale.value === 'en-US' ? 'Baseline Active' : '基线生效') : (isBaselineActive ? (locale.value === 'en-US' ? 'Converging' : '收敛待填充') : (locale.value === 'en-US' ? 'Disabled' : '已停用')),
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
    roleSwitchError.value = locale.value === 'en-US' ? 'Please enter authorization password' : '请输入授权口令';
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
    changePwdError.value = locale.value === 'en-US' ? 'Old and new passwords cannot be empty' : '原口令与新口令均不能为空';
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
    notifyWarning(locale.value === 'en-US' ? 'MLPS Level 3 Compliance Intercept' : '等保三级安全合规拦截', locale.value === 'en-US' ? `${e}. Please click Switch Role at top to authenticate as AuditAdmin first.` : `${e}。请先在顶部点击【切换身份】以安全审计员 (AuditAdmin) 身份授权验证后执行。`);
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
    notifyWarning(locale.value === 'en-US' ? 'Input Validation Failed' : '输入校验未通过', locale.value === 'en-US' ? 'Subnet CIDR and Security Zone Name cannot be empty' : '网段 CIDR 与安全区域名称不能为空，请填写后再添加');
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
    log(`[MACRO-BASELINE] 已{{ locale === 'en-US' ? 'Register Schedule' : '登记法定日程' }}: ${statutoryDateInput.value} -> ${statutoryRegimeType.value}`);
    await loadMacroCalendarStatus();
  } catch (e) {
    log(`[ERROR] {{ locale === 'en-US' ? 'Register Schedule' : '登记法定日程' }}失败: ${e}`);
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
    notifySuccess(locale.value === 'en-US' ? 'Communication baseline rules persisted' : '通信基线规则已固化', locale.value === 'en-US' ? `Successfully persisted ${count} baseline rules to disk; restored automatically on restart` : `成功将 ${count} 条通信基线规则固化持久化至磁盘，系统重启后将自动加载恢复`);
    loadAdminAuditTrail();
  } catch (e) {
    log(`[ERROR] 固化基线失败: ${e}`);
  }
}

async function resetBaselineRules() {
  const confirmed = await uiConfirm(
    locale.value === 'en-US' ? 'Confirm resetting all learned OT communication baseline rules and drift events? This action is audited.' : '确认重置所有已学习的工业通信基线白名单与漂移事件吗？此操作将记录管理员审计流。',
    { title: locale.value === 'en-US' ? 'Confirm Reset Baseline' : '确认重置通信基线', confirmText: locale.value === 'en-US' ? 'Confirm Reset' : '确认重置', danger: true }
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
