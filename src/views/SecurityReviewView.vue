<template>
  <div class="h-full flex flex-col gap-2.5 overflow-hidden font-sans">

    <!-- 1. 顶部操作栏与四维综合监控核心指标看板 (真 Liquid Glass 控制层) -->
    <section class="ui-nav-glass rounded-2xl p-3.5 shrink-0 flex flex-col gap-3" style="color: var(--text-primary);">
      <span class="lens-edge-lip" aria-hidden="true"></span>

      <!-- 1.1 标题与工具操作区 -->
      <div class="flex items-center justify-between gap-3 flex-wrap">
        <div class="flex items-center gap-2.5 min-w-0">
          <div class="w-8 h-8 rounded-xl bg-[var(--accent-primary-soft)] text-[var(--accent-primary-text)] flex items-center justify-center border border-[var(--accent-primary)]/20 shrink-0">
            <AppIcon name="shield" :size="16" />
          </div>
          <div class="min-w-0">
            <div class="flex items-center gap-2 flex-wrap">
              <h2 class="text-[13px] font-semibold tracking-tight" style="color: var(--text-primary);">四维合规安全审查与数据脱敏清洗工作台</h2>
              <span class="ui-pill px-2 py-0.5 rounded-full text-[11px] font-medium">
                GB/T 22239 等保三级 · GB/T 43697 · 国家秘密法
              </span>
            </div>
            <p class="text-[11px] mt-0.5 truncate" style="color: var(--text-muted);">
              工控越权写指令 · DNS/ICMP 隐蔽隧道 · PII 分类分级 · 涉密红头公文 · 闭环逆向零残余脱敏
            </p>
          </div>
        </div>

        <div class="flex items-center gap-2 flex-wrap">
          <button @click="showVpnDetectorModal = true" class="ui-btn-secondary px-3 py-1.5 text-xs text-rose-700 dark:text-rose-300 border-rose-500/30">
            <AppIcon name="radar" :size="14" class="text-rose-500" />
            <span>VPN/代理隧道侦测</span>
          </button>

          <button @click="generateComprehensiveReport" :disabled="isGeneratingReport" class="ui-btn-primary px-3 py-1.5 text-xs">
            <AppIcon name="document" :size="14" />
            <span>{{ isGeneratingReport ? '生成报告中...' : '出具综合勘验报告' }}</span>
          </button>

          <button @click="refreshAllData" class="ui-btn-secondary px-3 py-1.5 text-xs">
            <AppIcon name="refresh" :size="14" />
            <span>刷新底账</span>
          </button>

          <button @click="clearCurrentAuditRecords" class="ui-btn-danger px-3 py-1.5 text-xs">
            <AppIcon name="trash" :size="14" />
            <span>清空记录</span>
          </button>
        </div>
      </div>

      <!-- 1.2 四大审查维度核心指标卡片 -->
      <div class="grid grid-cols-2 lg:grid-cols-4 gap-2.5">
        <div
          @click="activeTab = 'network'"
          :class="[
            'p-2.5 rounded-xl border transition-all cursor-pointer flex items-center justify-between gap-2',
            activeTab === 'network' ? 'bg-blue-500/10 border-blue-500/35 shadow-2xs' : 'ui-sub-card hover:bg-[var(--surface-hover)]'
          ]"
        >
          <div class="min-w-0">
            <div class="text-[11px] font-semibold flex items-center gap-1.5" style="color: var(--text-muted);">
              <span class="w-1.5 h-1.5 rounded-full bg-blue-500 shrink-0"></span>
              <span>1. 网络安全审查</span>
            </div>
            <div class="text-base ui-num font-bold mt-0.5" style="color: var(--text-primary);">
              {{ (networkStats?.total_events ?? 0).toLocaleString() }} <span class="text-[11px] font-normal" style="color: var(--text-muted);">起违规事件</span>
            </div>
            <div class="text-[11px] ui-num truncate mt-0.5" style="color: var(--text-muted);">
              工控越权 {{ networkStats?.industrial_write_violations ?? 0 }} · DNS隧道 {{ networkStats?.dns_tunnel_count ?? 0 }}
            </div>
          </div>
          <span
            class="px-2 py-0.5 rounded text-[11px] font-semibold shrink-0"
            :class="(networkStats?.total_events ?? 0) > 0 ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300' : 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300'"
          >
            {{ (networkStats?.total_events ?? 0) > 0 ? '需核验' : '正常受控' }}
          </span>
        </div>

        <div
          @click="activeTab = 'data_sec'"
          :class="[
            'p-2.5 rounded-xl border transition-all cursor-pointer flex items-center justify-between gap-2',
            activeTab === 'data_sec' ? 'bg-indigo-500/10 border-indigo-500/35 shadow-2xs' : 'ui-sub-card hover:bg-[var(--surface-hover)]'
          ]"
        >
          <div class="min-w-0">
            <div class="text-[11px] font-semibold flex items-center gap-1.5" style="color: var(--text-muted);">
              <span class="w-1.5 h-1.5 rounded-full bg-indigo-500 shrink-0"></span>
              <span>2. 数据安全审查</span>
            </div>
            <div class="text-base ui-num font-bold mt-0.5" style="color: var(--text-primary);">
              {{ (dataSecSummary?.total_sensitive_hits ?? 0).toLocaleString() }} <span class="text-[11px] font-normal" style="color: var(--text-muted);">笔敏感命中</span>
            </div>
            <div class="text-[11px] ui-num truncate mt-0.5" style="color: var(--text-muted);">
              核心 {{ dataSecSummary?.core_data_hits ?? 0 }} · 重要 {{ dataSecSummary?.important_data_hits ?? 0 }} · PII {{ dataSecSummary?.pii_hits ?? 0 }}
            </div>
          </div>
          <span
            class="px-2 py-0.5 rounded text-[11px] font-semibold shrink-0"
            :class="(dataSecSummary?.total_sensitive_hits ?? 0) > 0 ? 'bg-rose-500/15 text-rose-700 dark:text-rose-300' : 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300'"
          >
            {{ (dataSecSummary?.total_sensitive_hits ?? 0) > 0 ? '检出泄露' : '未见明文' }}
          </span>
        </div>

        <div
          @click="activeTab = 'confidential'"
          :class="[
            'p-2.5 rounded-xl border transition-all cursor-pointer flex items-center justify-between gap-2',
            activeTab === 'confidential' ? 'bg-amber-500/10 border-amber-500/35 shadow-2xs' : 'ui-sub-card hover:bg-[var(--surface-hover)]'
          ]"
        >
          <div class="min-w-0">
            <div class="text-[11px] font-semibold flex items-center gap-1.5" style="color: var(--text-muted);">
              <span class="w-1.5 h-1.5 rounded-full bg-amber-500 shrink-0"></span>
              <span>3. 保密安全审查</span>
            </div>
            <div class="text-base ui-num font-bold mt-0.5" style="color: var(--text-primary);">
              {{ secrecyTotalFindingsCount.toLocaleString() }} <span class="text-[11px] font-normal" style="color: var(--text-muted);">项定密与取证异常</span>
            </div>
            <div class="text-[11px] truncate mt-0.5" style="color: var(--text-muted);">
              USB历史痕迹 · 公文解构 · 一机两用 · 标密外联
            </div>
          </div>
          <span
            class="px-2 py-0.5 rounded text-[11px] font-semibold shrink-0"
            :class="secrecyVerdict.isVetoed ? 'bg-rose-500/15 text-rose-700 dark:text-rose-300' : 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300'"
          >
            {{ secrecyVerdict.isVetoed ? '触发一票否决' : secrecyTotalFindingsCount > 0 ? '密级预警' : '合规受控' }}
          </span>
        </div>

        <div
          @click="activeTab = 'sanitizer'"
          :class="[
            'p-2.5 rounded-xl border transition-all cursor-pointer flex items-center justify-between gap-2',
            activeTab === 'sanitizer' ? 'bg-emerald-500/10 border-emerald-500/35 shadow-2xs' : 'ui-sub-card hover:bg-[var(--surface-hover)]'
          ]"
        >
          <div class="min-w-0">
            <div class="text-[11px] font-semibold flex items-center gap-1.5" style="color: var(--text-muted);">
              <span class="w-1.5 h-1.5 rounded-full bg-emerald-500 shrink-0"></span>
              <span>4. 脱敏清洗审查</span>
            </div>
            <div class="text-base ui-num font-bold mt-0.5" style="color: var(--text-primary);">
              {{ sanitizationPolicies.length }} <span class="text-[11px] font-normal" style="color: var(--text-muted);">套标准策略模板</span>
            </div>
            <div class="text-[11px] truncate mt-0.5" style="color: var(--text-muted);">
              闭环逆向复测 · 出具密码学防篡改凭单
            </div>
          </div>
          <span
            class="px-2 py-0.5 rounded text-[11px] font-semibold shrink-0"
            :class="auditProof
              ? (auditProof.is_fully_compliant
                ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300'
                : 'bg-rose-500/15 text-rose-700 dark:text-rose-300')
              : (sanitizationPolicies.length > 0
                ? 'bg-sky-500/15 text-sky-700 dark:text-sky-300'
                : 'bg-slate-500/15 text-[var(--text-muted)]')"
          >
            {{
              auditProof
                ? (auditProof.is_fully_compliant ? '核验通过' : '存在残留')
                : (sanitizationPolicies.length > 0 ? '待自测核验' : '未加载策略')
            }}
          </span>
        </div>
      </div>
    </section>

    <!-- 1.3 离线规则库智能感知与一键执行横幅 (系统情景自适应架构层) -->
    <!-- 场景 A: 检测到本地存在离线安装包，但尚未完成初次解包与 CVE 聚合库构建 -->
    <div
      v-if="ruleAssetsHealth?.smart_status?.status_code === 'NEEDS_INITIAL_EXTRACTION'"
      class="shrink-0 p-3 rounded-2xl border flex items-center justify-between gap-3 flex-wrap bg-amber-500/10 border-amber-500/40 text-amber-900 dark:text-amber-200 shadow-xs"
    >
      <div class="flex items-center gap-2.5 min-w-0">
        <div class="w-8 h-8 rounded-xl bg-amber-500/20 text-amber-600 dark:text-amber-400 flex items-center justify-center shrink-0 border border-amber-500/30 animate-pulse">
          <AppIcon name="shield" :size="16" />
        </div>
        <div class="min-w-0">
          <div class="font-semibold text-xs flex items-center gap-2 flex-wrap">
            <span class="text-amber-700 dark:text-amber-300 font-bold">💡 智能感知提示：{{ ruleAssetsHealth.smart_status.status_title }}</span>
            <span class="px-2 py-0.5 rounded-full text-[10px] bg-amber-500/25 text-amber-800 dark:text-amber-200 font-semibold">
              包体积 {{ formatBytes(ruleAssetsHealth.smart_status.archive_size_bytes) }} · 待构建
            </span>
          </div>
          <p class="text-[11px] opacity-90 mt-0.5 leading-snug">
            {{ ruleAssetsHealth.smart_status.status_description }}
            <b class="text-amber-800 dark:text-amber-300 ml-1">Suricata 引擎调用前需进行一次解压展开与 CVE 聚合提取，之后即可零开销就地调用。</b>
          </p>
        </div>
      </div>
      <div class="flex items-center gap-2 shrink-0 flex-wrap">
        <button
          @click="handleSmartSyncArchive()"
          :disabled="isSmartSyncing || isExtractingLocal"
          class="ui-btn-primary bg-amber-600 hover:bg-amber-500 text-white px-3.5 py-1.5 text-xs flex items-center gap-1.5 shadow-sm font-semibold"
        >
          <AppIcon name="shield" :size="13" />
          <span>{{ isSmartSyncing ? '正在智能解包并聚合 CVE (秒级)...' : '⚡ 立即智能解包并构建生效' }}</span>
        </button>
        <button
          @click="isRuleAssetsModalOpen = true; showOfflineManualHelp = true"
          class="ui-btn-secondary px-3 py-1.5 text-xs border-amber-500/30 flex items-center gap-1"
        >
          <AppIcon name="document" :size="12" />
          <span>脱网部署说明</span>
        </button>
        <button
          @click="isRuleAssetsModalOpen = true; showOfflineManualHelp = false"
          class="ui-btn-secondary px-3 py-1.5 text-xs border-amber-500/30"
        >
          <span>规则底账 ({{ ruleAssetsHealth.total_assets }})</span>
        </button>
      </div>
    </div>

    <!-- 场景 B: 检测到本地离线规则压缩包被更新 (安装包时间晚于已解压规则库) -->
    <div
      v-else-if="ruleAssetsHealth?.smart_status?.status_code === 'UPDATE_AVAILABLE'"
      class="shrink-0 p-3 rounded-2xl border flex items-center justify-between gap-3 flex-wrap bg-sky-500/10 border-sky-500/40 text-sky-900 dark:text-sky-200 shadow-xs"
    >
      <div class="flex items-center gap-2.5 min-w-0">
        <div class="w-8 h-8 rounded-xl bg-sky-500/20 text-sky-600 dark:text-sky-400 flex items-center justify-center shrink-0 border border-sky-500/30">
          <AppIcon name="refresh" :size="16" />
        </div>
        <div class="min-w-0">
          <div class="font-semibold text-xs flex items-center gap-2 flex-wrap">
            <span class="text-sky-700 dark:text-sky-300 font-bold">🔄 智能感知提示：{{ ruleAssetsHealth.smart_status.status_title }}</span>
            <span class="px-2 py-0.5 rounded-full text-[10px] bg-sky-500/25 text-sky-800 dark:text-sky-200 font-semibold">
              新包拷入时间: {{ ruleAssetsHealth.smart_status.archive_mtime_str }}
            </span>
          </div>
          <p class="text-[11px] opacity-90 mt-0.5 leading-snug">
            {{ ruleAssetsHealth.smart_status.status_description }}
            <span class="opacity-80 ml-1">建议一键执行智能同步更新，引擎将增量解压最新分类规则并重新生成 6,000+ 条 CVE 聚合库热重载生效。</span>
          </p>
        </div>
      </div>
      <div class="flex items-center gap-2 shrink-0 flex-wrap">
        <button
          @click="handleSmartSyncArchive()"
          :disabled="isSmartSyncing || isExtractingLocal"
          class="ui-btn-primary bg-sky-600 hover:bg-sky-500 text-white px-3.5 py-1.5 text-xs flex items-center gap-1.5 shadow-sm font-semibold"
        >
          <AppIcon name="refresh" :size="13" />
          <span>{{ isSmartSyncing ? '正在同步更新最新规则...' : '⚡ 立即智能同步更新' }}</span>
        </button>
        <button
          @click="isRuleAssetsModalOpen = true"
          class="ui-btn-secondary px-3 py-1.5 text-xs border-sky-500/30"
        >
          <span>智能诊断看板</span>
        </button>
      </div>
    </div>

    <!-- 场景 C: 离线规则库已是最新状态，引擎就地零开销直接调用 (无需重复解压) -->
    <div
      v-else-if="ruleAssetsHealth?.smart_status?.status_code === 'UP_TO_DATE' || (ruleAssetsHealth && ruleAssetsHealth.all_ready)"
      class="shrink-0 px-3.5 py-2 rounded-xl border flex items-center justify-between gap-2 flex-wrap text-xs bg-emerald-500/10 border-emerald-500/30 text-emerald-900 dark:text-emerald-200"
    >
      <div class="flex items-center gap-2 min-w-0">
        <span class="w-2 h-2 rounded-full bg-emerald-500 shrink-0"></span>
        <span class="font-semibold shrink-0 text-emerald-800 dark:text-emerald-300">✅ 离线规则库已处于最新状态 (零开销直读模式)</span>
        <span class="text-[11px] opacity-85 truncate">
          当前运行: <b>{{ ruleAssetsHealth?.active_library_name }}</b> ({{ ruleAssetsHealth?.active_rule_count }} 条规则 / {{ ruleAssetsHealth?.active_cve_count }} 条 CVE 签名) · 本地规则库与压缩包完全同步，<b>调用时就地内存直读，无需重复解压</b>
        </span>
      </div>
      <div class="flex items-center gap-2 shrink-0">
        <button
          @click="handleSmartSyncArchive()"
          :disabled="isSmartSyncing"
          class="ui-btn-secondary px-2.5 py-1 text-[11px] flex items-center gap-1"
          title="如本地规则文件异常，可点击强制重新从压缩包解压并构建 CVE 聚合库"
        >
          <AppIcon name="refresh" :size="11" />
          <span>{{ isSmartSyncing ? '重新构建中...' : '强制重新构建' }}</span>
        </button>
        <button
          @click="isRuleAssetsModalOpen = true"
          class="ui-btn-secondary px-2.5 py-1 text-[11px]"
        >
          <span>规则底账 ({{ ruleAssetsHealth?.total_assets }})</span>
        </button>
      </div>
    </div>

    <!-- 场景 D: 缺少规则且无本地压缩包 -->
    <div
      v-else-if="ruleAssetsHealth && !ruleAssetsHealth.all_ready"
      class="shrink-0 p-3 rounded-2xl border flex items-center justify-between gap-3 flex-wrap bg-amber-500/10 border-amber-500/35 text-amber-900 dark:text-amber-200"
    >
      <div class="flex items-center gap-2.5 min-w-0">
        <div class="w-8 h-8 rounded-xl bg-amber-500/20 text-amber-600 dark:text-amber-400 flex items-center justify-center shrink-0 border border-amber-500/30">
          <AppIcon name="shield" :size="16" />
        </div>
        <div class="min-w-0">
          <div class="font-semibold text-xs flex items-center gap-2 flex-wrap">
            <span>离线规则库资产自检告警：检测到当前缺失全量 CVE 离线规则库</span>
            <span class="px-2 py-0.5 rounded-full text-[10px] bg-amber-500/25 text-amber-800 dark:text-amber-300 font-semibold">
              缺少 {{ ruleAssetsHealth.missing_assets }} 项关键离线资产
            </span>
          </div>
          <p class="text-[11px] opacity-90 mt-0.5 leading-snug">
            当前仅运行基础工业核心基线 ({{ ruleAssetsHealth.active_rule_count }} 条)。官方全量 52,975 条入侵特征及 6,264 条 CVE 漏洞利用签名未就绪，脱机环境无法离线阻断深度 CVE 攻击。建议一键在线同步下载，或在脱网环境下导入本地离线包。
          </p>
        </div>
      </div>
      <div class="flex items-center gap-2 shrink-0 flex-wrap">
        <button
          @click="handleSyncRules()"
          :disabled="isSyncingRules"
          class="ui-btn-primary bg-amber-600 hover:bg-amber-500 text-white px-3.5 py-1.5 text-xs flex items-center gap-1.5 shadow-sm"
        >
          <AppIcon name="refresh" :size="12" />
          <span>{{ isSyncingRules ? '正在在线拉取并构建 (5.2万条)...' : '一键在线下载并构建全量库' }}</span>
        </button>
        <button
          @click="isRuleAssetsModalOpen = true; showOfflineManualHelp = true"
          class="ui-btn-secondary px-3 py-1.5 text-xs border-amber-500/30 flex items-center gap-1"
        >
          <AppIcon name="document" :size="12" />
          <span>导入本地 .tar.gz / 离线说明</span>
        </button>
        <button
          @click="isRuleAssetsModalOpen = true; showOfflineManualHelp = false"
          class="ui-btn-secondary px-3 py-1.5 text-xs border-amber-500/30"
        >
          <span>规则底账</span>
        </button>
      </div>
    </div>

    <!-- 2. 主视口：五大维度工作区 (稳态实体衬底) -->
    <div class="flex-1 overflow-hidden flex flex-col min-h-0 ui-content-card p-3 select-text">

      <!-- 2.0 标签页胶囊导航切换器 -->
      <div class="flex items-center justify-between border-b pb-2 mb-2.5 shrink-0 flex-wrap gap-2" style="border-color: var(--border-subtle);">
        <div class="flex items-center gap-1 glass-pill p-1 rounded-xl flex-wrap">
          <button
            @click="activeTab = 'network'"
            :class="[
              'px-3 py-1 rounded-lg text-xs font-semibold transition-all cursor-pointer flex items-center gap-1.5',
              activeTab === 'network' ? 'bg-[var(--accent-primary)] text-white shadow-xs' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
            ]"
          >
            <span>网络安全审查</span>
            <span :class="['px-1.5 py-0.5 rounded-full text-[11px] ui-num', activeTab === 'network' ? 'bg-white/20 text-white' : 'bg-[var(--surface-glass-pill)] text-[var(--text-secondary)]']">{{ networkEvents.length }}</span>
          </button>

          <button
            @click="activeTab = 'data_sec'"
            :class="[
              'px-3 py-1 rounded-lg text-xs font-semibold transition-all cursor-pointer flex items-center gap-1.5',
              activeTab === 'data_sec' ? 'bg-[var(--accent-primary)] text-white shadow-xs' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
            ]"
          >
            <span>数据安全审查 (分类分级)</span>
            <span :class="['px-1.5 py-0.5 rounded-full text-[11px] ui-num', activeTab === 'data_sec' ? 'bg-white/20 text-white' : 'bg-[var(--surface-glass-pill)] text-[var(--text-secondary)]']">{{ sensitiveFindings.length }}</span>
          </button>

          <button
            @click="activeTab = 'confidential'"
            :class="[
              'px-3 py-1 rounded-lg text-xs font-semibold transition-all cursor-pointer flex items-center gap-1.5',
              activeTab === 'confidential' ? 'bg-[var(--accent-primary)] text-white shadow-xs' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
            ]"
          >
            <span>保密安全审查 (法定公文)</span>
            <span :class="['px-1.5 py-0.5 rounded-full text-[11px] ui-num', activeTab === 'confidential' ? 'bg-white/20 text-white' : 'bg-[var(--surface-glass-pill)] text-[var(--text-secondary)]']">{{ confidentialityAlerts.length }}</span>
          </button>

          <button
            @click="activeTab = 'sanitizer'"
            :class="[
              'px-3 py-1 rounded-lg text-xs font-semibold transition-all cursor-pointer flex items-center gap-1.5',
              activeTab === 'sanitizer' ? 'bg-[var(--accent-primary)] text-white shadow-xs' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
            ]"
          >
            <span>数据脱敏清洗与闭环核验</span>
            <span :class="['px-1.5 py-0.5 rounded-full text-[11px] ui-num', activeTab === 'sanitizer' ? 'bg-white/20 text-white' : 'bg-[var(--surface-glass-pill)] text-[var(--text-secondary)]']">ISO/GB</span>
          </button>

          <button
            @click="switchToEnginesTab"
            :class="[
              'px-3 py-1 rounded-lg text-xs font-semibold transition-all cursor-pointer flex items-center gap-1.5',
              activeTab === 'engines' ? 'bg-[var(--accent-primary)] text-white shadow-xs' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
            ]"
          >
            <span>深度规则引擎 &amp; 脚本沙箱</span>
            <span :class="['px-1.5 py-0.5 rounded-full text-[11px] ui-num', activeTab === 'engines' ? 'bg-white/20 text-white' : 'bg-[var(--surface-glass-pill)] text-[var(--text-secondary)]']">
              {{ (suricataMetrics?.total_hits ?? 0) + (glushkovMetrics?.total_threat_hits ?? 0) }}
            </span>
          </button>
        </div>

        <div class="text-[11px]" style="color: var(--text-muted);">
          <span v-if="activeTab === 'network'">检测 Modbus/S7/SL651 越权写指令、DNS 信息熵香农隧道 (H&gt;4.2)、ICMP 隐匿通道</span>
          <span v-else-if="activeTab === 'data_sec'">GB/T 43697 数据四级分类分级、身份证 ISO 7064 与银行卡 Luhn 算法真值校验</span>
          <span v-else-if="activeTab === 'confidential'">Aho-Corasick 多模式自动机扫描法定绝密/机密/秘密标密词与红头发文字号</span>
          <span v-else-if="activeTab === 'sanitizer'">提供掩码脱敏、HMAC-SHA256 假名化及脱敏后敏感零残余二次逆向复测</span>
          <span v-else-if="activeTab === 'engines'">Suricata 工业 DSL、Glushkov 位并行正则自动机与受限 Gas 脚本虚拟机</span>
        </div>
      </div>

      <!-- ======================================================== -->
      <!-- TAB 1: 网络安全审查 -->
      <!-- ======================================================== -->
      <div v-if="activeTab === 'network'" class="flex-1 overflow-hidden flex flex-col gap-2 min-h-0">
        <div class="flex items-center justify-between gap-2 shrink-0 flex-wrap">
          <div class="flex items-center gap-1.5 text-xs flex-wrap">
            <span class="font-medium" style="color: var(--text-muted);">事件过滤:</span>
            <button
              v-for="t in networkEventFilterOptions"
              :key="t.key"
              @click="networkFilterType = t.key"
              :class="[
                'px-2.5 py-1 rounded-lg text-[11px] font-medium transition-all cursor-pointer',
                networkFilterType === t.key ? 'bg-blue-600 text-white shadow-2xs' : 'ui-pill hover:bg-[var(--surface-hover)]'
              ]"
            >
              {{ t.label }}
            </button>
          </div>
          <div class="flex items-center gap-2">
            <button
              @click="showVpnDetectorModal = true"
              class="ui-btn-secondary px-2.5 py-1 text-[11px] font-semibold text-rose-700 dark:text-rose-300 border-rose-500/30"
              title="启动终端本地+链路DPI+DFI/MSS+机房/DNS错位四维 VPN 隧道侦测"
            >
              VPN/代理隧道深度侦测
            </button>
            <span class="text-[11px] ui-num" style="color: var(--text-muted);">共显示 {{ filteredNetworkEvents.length }} 笔网络安全事件</span>
          </div>
        </div>

        <!-- 工业专有解包插件生态状态栏 -->
        <div class="ui-sub-card px-3 py-2 flex items-center justify-between gap-3 text-xs shrink-0 flex-wrap">
          <div class="flex items-center gap-2 min-w-0">
            <span class="w-2 h-2 rounded-full bg-emerald-500 shrink-0"></span>
            <span class="font-semibold shrink-0" style="color: var(--text-primary);">工控专有与长尾解包插件生态:</span>
            <span class="text-[11px] truncate" style="color: var(--text-secondary);">已装载 {{ industrialPlugins.length }} 种原生/声明式解包器 (SEMI HSMS、横河 Vnet/IP、霍尼韦尔 FTE、施耐德 UMAS、倍福 ADS 等)</span>
          </div>
          <button @click="showPluginDrawer = !showPluginDrawer" class="ui-btn-secondary px-2.5 py-1 text-[11px] shrink-0">
            <span>{{ showPluginDrawer ? '收起解包器清单' : '查看已载入解包插件' }}</span>
            <AppIcon :name="showPluginDrawer ? 'chevron-up' : 'chevron-down'" :size="12" />
          </button>
        </div>

        <!-- Windows 内核态 WFP (fwpuclnt.dll) + XDP 在线阻断实况条 -->
        <div class="ui-sub-card px-3 py-2 flex flex-col gap-2 text-xs shrink-0">
          <div class="flex items-center justify-between gap-2 flex-wrap">
            <div class="flex items-center gap-2 min-w-0 flex-wrap">
              <span
                class="w-2 h-2 rounded-full shrink-0"
                :class="wfpStatus?.engine_connected ? 'bg-emerald-500' : wfpStatus?.permission_denied ? 'bg-amber-500' : 'bg-slate-400'"
              ></span>
              <span class="font-semibold shrink-0" style="color: var(--text-primary);">内核 WFP + XDP 双层过滤:</span>
              <span class="text-[11px]" style="color: var(--text-secondary);">
                {{ wfpStatus?.engine_connected
                  ? `fwpuclnt.dll 内核会话已就绪 · 当前激活 ${wfpStatus.active_rules?.length ?? 0} 条系统级入/出站阻断规则`
                  : wfpStatus?.permission_denied
                    ? '当前进程非管理员权限 (ERROR_ACCESS_DENIED)，阻断操作将降级为 XDP 前端丢弃 + 代理拦截'
                    : (wfpStatus?.last_message || '正在探测 Windows Filtering Platform 内核会话能力...') }}
              </span>
            </div>
            <div class="flex items-center gap-1.5 shrink-0">
              <input
                v-model="manualWfpTarget"
                type="text"
                placeholder="IPv4 / CIDR (如 192.168.1.99)"
                class="px-2.5 py-1 rounded-lg border text-[11px] w-56 ui-num"
                style="background: var(--surface-input); border-color: var(--border-subtle); color: var(--text-primary);"
              />
              <button
                @click="triggerManualWfpBlock"
                class="ui-btn-primary px-2.5 py-1 text-[11px] shrink-0"
                :disabled="!manualWfpTarget.trim()"
              >
                内核阻断
              </button>
              <button @click="fetchWfpStatus" class="ui-btn-secondary px-2 py-1 text-[11px] shrink-0" title="刷新 WFP 内核过滤状态">
                <AppIcon name="refresh" :size="12" />
              </button>
            </div>
          </div>

          <div v-if="wfpStatus && (wfpStatus.active_rules?.length ?? 0) > 0" class="flex items-center gap-1.5 flex-wrap pt-1 border-t" style="border-color: var(--border-subtle);">
            <span class="text-[11px]" style="color: var(--text-muted);">生效中规则 (点击解除):</span>
            <button
              v-for="rule in wfpStatus.active_rules"
              :key="rule.cidr_normalized"
              @click="unblockWfpTarget(rule.cidr_normalized)"
              class="px-2 py-0.5 rounded-lg border text-[11px] ui-num flex items-center gap-1.5 cursor-pointer bg-rose-500/10 border-rose-500/30 text-rose-700 dark:text-rose-300 hover:bg-rose-500/20 transition-colors"
              :title="`原因: ${rule.reason || '安全审查拦截'} | 点击从 WFP 内核与 XDP 黑名单移除`"
            >
              <span>{{ rule.cidr_normalized }}</span>
              <span class="opacity-75">{{ rule.outbound_filter_id > 0 ? `#${rule.outbound_filter_id}` : 'XDP' }}</span>
              <span class="font-bold">×</span>
            </button>
          </div>
        </div>

        <!-- 解包器详情抽屉 -->
        <div v-if="showPluginDrawer" class="p-3 ui-sub-card grid grid-cols-2 md:grid-cols-5 gap-2 shrink-0 max-h-48 overflow-y-auto custom-scrollbar">
          <div
            v-for="plug in industrialPlugins"
            :key="plug.id"
            class="p-2.5 rounded-lg border flex flex-col justify-between text-[11px]"
            style="background: var(--surface-content); border-color: var(--border-subtle);"
          >
            <div>
              <div class="flex items-center justify-between gap-1 mb-1">
                <span class="font-semibold truncate" style="color: var(--text-primary);" :title="plug.name">{{ plug.name }}</span>
                <span
                  class="px-1.5 py-0.5 rounded text-[11px] shrink-0"
                  :class="plug.plugin_type === 'NATIVE_RUST_CORE' ? 'bg-indigo-500/15 text-indigo-700 dark:text-indigo-300' : 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300'"
                >
                  {{ plug.plugin_type === 'NATIVE_RUST_CORE' ? 'Rust' : 'JSON' }}
                </span>
              </div>
              <div class="truncate" style="color: var(--text-secondary);" :title="plug.vendor">厂商: {{ plug.vendor }}</div>
              <div class="ui-num mt-0.5" style="color: var(--text-muted);">端口: {{ plug.default_ports?.join(', ') || '任意' }}</div>
            </div>
            <div class="mt-1.5 pt-1 border-t flex items-center justify-between" style="border-color: var(--border-subtle); color: var(--text-muted);">
              <span class="truncate" :title="plug.category">{{ plug.category }}</span>
              <span class="text-rose-600 dark:text-rose-400 font-medium shrink-0">越权审计</span>
            </div>
          </div>
        </div>

        <!-- 事件列表表格 -->
        <div class="flex-1 overflow-auto custom-scrollbar border rounded-xl" style="border-color: var(--border-subtle); background: var(--surface-content-alt);">
          <table class="w-full text-left text-xs border-collapse">
            <thead class="ui-table-head sticky top-0 z-10 select-none">
              <tr>
                <th class="py-2 px-3">事件 ID</th>
                <th class="py-2 px-3">时间戳</th>
                <th class="py-2 px-3">事件分类</th>
                <th class="py-2 px-3">危害等级</th>
                <th class="py-2 px-3">通信双方 (源 → 宿)</th>
                <th class="py-2 px-3">规约/协议</th>
                <th class="py-2 px-3">技术勘验摘要与判定依据</th>
                <th class="py-2 px-3 text-right">操作</th>
              </tr>
            </thead>
            <tbody class="divide-y text-xs" style="border-color: var(--border-subtle);">
              <tr v-for="evt in filteredNetworkEvents" :key="evt.id" class="hover:bg-[var(--surface-hover)] transition-colors">
                <td class="py-2 px-3 ui-num" style="color: var(--text-muted);">#{{ evt.id }}</td>
                <td class="py-2 px-3 ui-num whitespace-nowrap" style="color: var(--text-secondary);">{{ evt.timestamp }}</td>
                <td class="py-2 px-3">
                  <span
                    class="px-1.5 py-0.5 rounded text-[11px] font-semibold"
                    :class="{
                      'bg-purple-500/15 text-purple-700 dark:text-purple-300': evt.event_type === 'INDUSTRIAL_WRITE_VIOLATION',
                      'bg-rose-500/15 text-rose-700 dark:text-rose-300': evt.event_type === 'DNS_COVERT_TUNNEL',
                      'bg-amber-500/15 text-amber-700 dark:text-amber-300': evt.event_type === 'ICMP_COVERT_TUNNEL',
                      'bg-blue-500/15 text-blue-700 dark:text-sky-300': evt.event_type === 'CROSS_ZONE_VIOLATION',
                    }"
                  >
                    {{ formatNetworkEventType(evt.event_type) }}
                  </span>
                </td>
                <td class="py-2 px-3">
                  <span
                    class="px-1.5 py-0.5 rounded text-[11px] font-semibold"
                    :class="{
                      'bg-rose-600 text-white': evt.severity === 'CRITICAL',
                      'bg-amber-500 text-white': evt.severity === 'HIGH',
                      'bg-yellow-500/20 text-yellow-700 dark:text-yellow-300': evt.severity === 'MEDIUM',
                      'ui-pill': evt.severity === 'LOW',
                    }"
                  >
                    {{ evt.severity }}
                  </span>
                </td>
                <td class="py-2 px-3 whitespace-nowrap ui-num">
                  <span class="font-semibold" style="color: var(--text-primary);">{{ evt.src_ip }}:{{ evt.src_port }}</span>
                  <span class="mx-1" style="color: var(--text-muted);">→</span>
                  <span class="font-semibold" style="color: var(--text-primary);">{{ evt.dst_ip }}:{{ evt.dst_port }}</span>
                </td>
                <td class="py-2 px-3 font-semibold" style="color: var(--text-primary);">{{ evt.protocol }}</td>
                <td class="py-2 px-3 max-w-md truncate" style="color: var(--text-secondary);" :title="evt.summary">
                  {{ evt.summary }}
                </td>
                <td class="py-2 px-3 text-right whitespace-nowrap space-x-1.5">
                  <button @click="blockIpAddress(evt.src_ip, evt.summary)" class="ui-btn-danger px-2 py-0.5 text-[11px]">
                    一键阻断
                  </button>
                  <button @click="selectedDetailJson = evt.detail_json; isDetailModalOpen = true" class="ui-btn-secondary px-2 py-0.5 text-[11px]">
                    勘验 JSON
                  </button>
                  <button @click="addNetworkEventToDiffQueue(evt)" class="px-2 py-0.5 rounded bg-emerald-500/12 hover:bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border border-emerald-500/25 text-[11px] font-semibold cursor-pointer">
                    + 入队
                  </button>
                </td>
              </tr>
              <tr v-if="filteredNetworkEvents.length === 0">
                <td colspan="8" class="text-center py-12">
                  <EmptyState icon="shield" title="暂无越权工控指令或隐蔽隧道事件" />
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- ======================================================== -->
      <!-- TAB 2: 数据安全审查 -->
      <!-- ======================================================== -->
      <div v-else-if="activeTab === 'data_sec'" class="flex-1 overflow-hidden flex flex-col gap-2.5 min-h-0">
        <div class="grid grid-cols-2 lg:grid-cols-4 gap-2 shrink-0">
          <div class="p-2.5 rounded-xl bg-rose-500/8 border border-rose-500/25 flex items-center justify-between">
            <div>
              <div class="text-[11px] font-semibold text-rose-700 dark:text-rose-300">核心数据 (最高防护等级)</div>
              <div class="text-sm ui-num font-bold mt-0.5" style="color: var(--text-primary);">
                {{ dataSecSummary.core_data_hits }} <span class="text-[11px] font-normal" style="color: var(--text-muted);">笔</span>
              </div>
            </div>
            <span class="text-[11px] font-semibold text-rose-700 dark:text-rose-300 bg-rose-500/15 px-1.5 py-0.5 rounded">L4</span>
          </div>

          <div class="p-2.5 rounded-xl bg-amber-500/8 border border-amber-500/25 flex items-center justify-between">
            <div>
              <div class="text-[11px] font-semibold text-amber-700 dark:text-amber-300">重要数据 (关键业务载荷)</div>
              <div class="text-sm ui-num font-bold mt-0.5" style="color: var(--text-primary);">
                {{ dataSecSummary.important_data_hits }} <span class="text-[11px] font-normal" style="color: var(--text-muted);">笔</span>
              </div>
            </div>
            <span class="text-[11px] font-semibold text-amber-700 dark:text-amber-300 bg-amber-500/15 px-1.5 py-0.5 rounded">L3</span>
          </div>

          <div class="p-2.5 rounded-xl bg-indigo-500/8 border border-indigo-500/25 flex items-center justify-between">
            <div>
              <div class="text-[11px] font-semibold text-indigo-700 dark:text-indigo-300">敏感个人信息 (PII 校验)</div>
              <div class="text-sm ui-num font-bold mt-0.5" style="color: var(--text-primary);">
                {{ dataSecSummary.pii_hits }} <span class="text-[11px] font-normal" style="color: var(--text-muted);">笔</span>
              </div>
            </div>
            <span class="text-[11px] font-semibold text-indigo-700 dark:text-indigo-300 bg-indigo-500/15 px-1.5 py-0.5 rounded">PII</span>
          </div>

          <div class="ui-sub-card p-2.5 flex items-center justify-between">
            <div>
              <div class="text-[11px] font-semibold" style="color: var(--text-secondary);">会话流式还原文件</div>
              <div class="text-sm ui-num font-bold mt-0.5" style="color: var(--text-primary);">
                {{ reconstructedFiles.length }} <span class="text-[11px] font-normal" style="color: var(--text-muted);">个检材</span>
              </div>
            </div>
            <span class="ui-pill text-[11px] font-semibold px-1.5 py-0.5">MIME</span>
          </div>
        </div>

        <div class="flex-1 grid grid-cols-1 lg:grid-cols-2 gap-2.5 overflow-hidden min-h-0">
          <!-- 左侧：敏感数据明细列表 -->
          <div class="border rounded-xl overflow-hidden flex flex-col" style="border-color: var(--border-subtle); background: var(--surface-content-alt);">
            <div class="p-2.5 border-b text-xs font-semibold flex items-center justify-between shrink-0" style="border-color: var(--border-subtle); color: var(--text-primary);">
              <span class="ui-num">敏感数据流动流水 ({{ sensitiveFindings.length }})</span>
              <span class="text-[11px]" style="color: var(--text-muted);">GB/T 43697 规则</span>
            </div>
            <div class="flex-1 overflow-auto custom-scrollbar">
              <table class="w-full text-left text-xs border-collapse">
                <thead class="ui-table-head sticky top-0 select-none">
                  <tr>
                    <th class="py-2 px-2.5">规则分类</th>
                    <th class="py-2 px-2.5">通信端点</th>
                    <th class="py-2 px-2.5">脱敏样本预览</th>
                    <th class="py-2 px-2.5">判定依据</th>
                    <th class="py-2 px-2.5 text-right">操作</th>
                  </tr>
                </thead>
                <tbody class="divide-y text-xs" style="border-color: var(--border-subtle);">
                  <tr v-for="item in sensitiveFindings" :key="item.id" class="hover:bg-[var(--surface-hover)]">
                    <td class="py-2 px-2.5 whitespace-nowrap">
                      <span class="font-semibold" style="color: var(--text-primary);">{{ item.rule_name }}</span>
                      <div class="text-[11px]" style="color: var(--text-muted);">{{ item.category_code }}</div>
                    </td>
                    <td class="py-2 px-2.5 whitespace-nowrap ui-num" style="color: var(--text-secondary);">
                      {{ item.src_ip }} → {{ item.dst_ip }}
                    </td>
                    <td class="py-2 px-2.5 font-semibold text-indigo-600 dark:text-indigo-300 font-mono whitespace-nowrap">
                      {{ item.matched_sample_masked }}
                    </td>
                    <td class="py-2 px-2.5 text-[11px] max-w-xs truncate" style="color: var(--text-secondary);" :title="item.context_summary">
                      {{ item.context_summary }}
                    </td>
                    <td class="py-2 px-2.5 text-right whitespace-nowrap space-x-1">
                      <button @click="inspectFindingDetail(item)" class="ui-btn-secondary px-2 py-0.5 text-[11px]">
                        勘验详情
                      </button>
                      <button @click="addSensitiveFindingToDiffQueue(item)" class="px-2 py-0.5 rounded bg-emerald-500/12 hover:bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border border-emerald-500/25 text-[11px] font-semibold cursor-pointer">
                        + 入队
                      </button>
                    </td>
                  </tr>
                  <tr v-if="sensitiveFindings.length === 0">
                    <td colspan="5" class="text-center py-8 text-xs" style="color: var(--text-muted);">
                      未检出符合触发条件的敏感数据流明文
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <!-- 右侧：会话流式还原文件清单 -->
          <div class="border rounded-xl overflow-hidden flex flex-col" style="border-color: var(--border-subtle); background: var(--surface-content-alt);">
            <div class="p-2.5 border-b text-xs font-semibold flex items-center justify-between shrink-0" style="border-color: var(--border-subtle); color: var(--text-primary);">
              <span class="ui-num">会话流式还原与传输载荷文件 ({{ reconstructedFiles.length }})</span>
              <span class="text-[11px]" style="color: var(--text-muted);">10MB 有界截断</span>
            </div>
            <div class="flex-1 overflow-auto custom-scrollbar">
              <table class="w-full text-left text-xs border-collapse">
                <thead class="ui-table-head sticky top-0 select-none">
                  <tr>
                    <th class="py-2 px-2.5">还原文件名</th>
                    <th class="py-2 px-2.5">MIME 类型</th>
                    <th class="py-2 px-2.5">体积大小</th>
                    <th class="py-2 px-2.5">密级判定</th>
                    <th class="py-2 px-2.5">SHA256 哈希</th>
                    <th class="py-2 px-2.5 text-right">操作</th>
                  </tr>
                </thead>
                <tbody class="divide-y text-xs" style="border-color: var(--border-subtle);">
                  <tr v-for="f in reconstructedFiles" :key="f.id" class="hover:bg-[var(--surface-hover)]">
                    <td class="py-2 px-2.5 font-semibold whitespace-nowrap" style="color: var(--text-primary);">
                      {{ f.filename }}
                    </td>
                    <td class="py-2 px-2.5 text-[11px]" style="color: var(--text-secondary);">{{ f.mime_type }}</td>
                    <td class="py-2 px-2.5 ui-num whitespace-nowrap" style="color: var(--text-primary);">{{ formatBytes(f.size_bytes) }}</td>
                    <td class="py-2 px-2.5">
                      <span
                        class="px-1.5 py-0.5 rounded text-[11px] font-semibold"
                        :class="f.classification === 'CORE_DATA' ? 'bg-rose-500/15 text-rose-700 dark:text-rose-300' : 'bg-blue-500/15 text-blue-700 dark:text-sky-300'"
                      >
                        {{ f.classification }}
                      </span>
                    </td>
                    <td class="py-2 px-2.5 font-mono text-[11px] truncate max-w-[120px]" style="color: var(--text-muted);" :title="f.sha256_hash">
                      {{ f.sha256_hash.substring(0, 16) }}...
                    </td>
                    <td class="py-2 px-2.5 text-right whitespace-nowrap">
                      <button @click="inspectFileDetail(f)" class="ui-btn-secondary px-2 py-0.5 text-[11px]">
                        检材详情
                      </button>
                    </td>
                  </tr>
                  <tr v-if="reconstructedFiles.length === 0">
                    <td colspan="6" class="text-center py-8 text-xs" style="color: var(--text-muted);">
                      暂无还原网络传输文件 (支持 PDF/Office/JSON/XML 流)
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>

      <!-- ======================================================== -->
      <!-- TAB 3: 保密安全审查 (BMB17/BMB20/BMB22 实测取证与勘验) -->
      <!-- ======================================================== -->
      <div v-else-if="activeTab === 'confidential'" class="flex-1 overflow-hidden flex flex-col gap-2 min-h-0">
        <!-- 保密合规规则库状态条与 BMB 视角切换 -->
        <div class="ui-sub-card p-2 flex items-center justify-between text-xs flex-wrap gap-2 shrink-0">
          <div class="flex items-center gap-2">
            <span class="w-2 h-2 rounded-full bg-emerald-500"></span>
            <span class="font-semibold" style="color: var(--text-primary);">保密审查 BMB 标准实测平台 (v2.2)</span>
            <span class="text-[11px]" style="color: var(--text-muted);">BMB17-2006 · BMB20-2007 · BMB22-2007 · GB/T 9704-2012</span>
          </div>
          <div class="flex items-center gap-1.5 flex-wrap">
            <button
              @click="secrecySubView = 'overview'"
              :class="secrecySubView === 'overview' ? 'ui-tab-pill-active text-amber-700 dark:text-amber-300' : 'ui-tab-pill'"
              class="px-2.5 py-1 rounded-lg text-[11px] font-semibold cursor-pointer transition-colors"
            >
              网流告警与公文送检 ({{ confidentialityAlerts.length }})
            </button>
            <button
              @click="secrecySubView = 'usb'"
              :class="secrecySubView === 'usb' ? 'ui-tab-pill-active text-amber-700 dark:text-amber-300' : 'ui-tab-pill'"
              class="px-2.5 py-1 rounded-lg text-[11px] font-semibold cursor-pointer transition-colors"
            >
              USB 历史痕迹 ({{ usbForensicsReport ? usbForensicsReport.total_devices_found : '未核' }})
            </button>
            <button
              @click="secrecySubView = 'docs'"
              :class="secrecySubView === 'docs' ? 'ui-tab-pill-active text-amber-700 dark:text-amber-300' : 'ui-tab-pill'"
              class="px-2.5 py-1 rounded-lg text-[11px] font-semibold cursor-pointer transition-colors"
            >
              复合文档穿透 ({{ dissectReport ? dissectReport.hit_files_count : '未扫' }})
            </button>
            <button
              @click="secrecySubView = 'dualhomed'"
              :class="secrecySubView === 'dualhomed' ? 'ui-tab-pill-active text-amber-700 dark:text-amber-300' : 'ui-tab-pill'"
              class="px-2.5 py-1 rounded-lg text-[11px] font-semibold cursor-pointer transition-colors"
            >
              一机两用排查 ({{ dualHomedReport ? dualHomedReport.risk_level : '未检' }})
            </button>
            <button
              @click="secrecySubView = 'history'"
              :class="secrecySubView === 'history' ? 'ui-tab-pill-active text-amber-700 dark:text-amber-300' : 'ui-tab-pill'"
              class="px-2.5 py-1 rounded-lg text-[11px] font-semibold cursor-pointer transition-colors"
            >
              历史外联 ({{ networkHistoryReport ? (networkHistoryReport.suspicious_mobile_hotspots.length + networkHistoryReport.historic_rndis_devices.length) : '未检' }})
            </button>
            <button
              @click="secrecySubView = 'ole2'"
              :class="secrecySubView === 'ole2' ? 'ui-tab-pill-active text-amber-700 dark:text-amber-300' : 'ui-tab-pill'"
              class="px-2.5 py-1 rounded-lg text-[11px] font-semibold cursor-pointer transition-colors"
            >
              OLE2 / 扇区 ({{ ole2Report ? (ole2Report.ole2_hits.length + ole2Report.slack_hits.length) : '未扫' }})
            </button>
            <button
              @click="secrecySubView = 'osusage'"
              :class="secrecySubView === 'osusage' ? 'ui-tab-pill-active text-amber-700 dark:text-amber-300' : 'ui-tab-pill'"
              class="px-2.5 py-1 rounded-lg text-[11px] font-semibold cursor-pointer transition-colors"
            >
              LNK / 打印痕迹 ({{ osUsageReport ? osUsageReport.total_lnk_parsed : '未审' }})
            </button>
            <button
              @click="secrecySubView = 'apptrace'"
              :class="secrecySubView === 'apptrace' ? 'ui-tab-pill-active text-amber-700 dark:text-amber-300' : 'ui-tab-pill'"
              class="px-2.5 py-1 rounded-lg text-[11px] font-semibold cursor-pointer transition-colors"
            >
              浏览器 / IM 外发 ({{ appTraceReport ? (appTraceReport.suspicious_downloads.length + appTraceReport.chat_file_hits.length) : '未审' }})
            </button>
          </div>
        </div>

        <!-- 四联 BMB 现场物理取证操作卡栏 -->
        <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-2 shrink-0">
          <!-- 卡 1: USBSTOR 历史插拔痕迹取证 -->
          <div class="ui-sub-card p-2.5 flex flex-col justify-between gap-1.5">
            <div class="flex items-center justify-between gap-2">
              <span class="text-xs font-semibold" style="color: var(--text-primary);">1. USB 历史插拔痕迹</span>
              <span
                v-if="usbForensicsReport"
                class="px-1.5 py-0.5 rounded text-[10px] font-semibold ui-num"
                :class="usbForensicsReport.has_critical_violation ? 'bg-rose-500/15 text-rose-700 dark:text-rose-300' : 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300'"
              >
                {{ usbForensicsReport.has_critical_violation ? `违规 ${usbForensicsReport.unauthorized_device_count} 个` : '合规洁净' }}
              </span>
            </div>
            <div class="text-[11px] truncate" style="color: var(--text-muted);">
              {{ usbForensicsReport ? usbForensicsReport.summary_conclusion : '读取注册表 USBSTOR 与 setupapi 安装日志' }}
            </div>
            <div class="flex items-center gap-1.5 pt-0.5">
              <button @click="runSecrecyUsbHistoryAudit" :disabled="isAuditingUsbHistory" class="ui-btn-primary bg-amber-600 hover:bg-amber-500 px-2.5 py-1 text-[11px] flex-1">
                {{ isAuditingUsbHistory ? '提取中...' : '提取历史 USB 痕迹' }}
              </button>
              <button v-if="usbForensicsReport" @click="secrecySubView = 'usb'" class="ui-btn-secondary px-2 py-1 text-[11px]">明细</button>
            </div>
          </div>

          <!-- 卡 2: 复合公文 (DOCX/OFD/PDF/ZIP) 穿透检索 -->
          <div class="ui-sub-card p-2.5 flex flex-col justify-between gap-1.5">
            <div class="flex items-center justify-between gap-2">
              <span class="text-xs font-semibold" style="color: var(--text-primary);">2. 复合公文穿透扫描</span>
              <span
                v-if="dissectReport"
                class="px-1.5 py-0.5 rounded text-[10px] font-semibold ui-num"
                :class="dissectReport.hit_files_count > 0 ? 'bg-rose-500/15 text-rose-700 dark:text-rose-300' : 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300'"
              >
                {{ dissectReport.hit_files_count > 0 ? `命中 ${dissectReport.hit_files_count} 份` : `扫 ${dissectReport.scanned_files_count} 洁净` }}
              </span>
            </div>
            <div class="flex items-center gap-1">
              <input
                v-model="dissectTargetPath"
                placeholder="输入待扫描目录或点击选择..."
                class="ui-input px-2 py-0.5 text-[11px] font-mono flex-1 min-w-0"
              />
              <button @click="pickAndSetDissectFolder" class="ui-btn-secondary px-2 py-0.5 text-[11px] shrink-0" title="选择本地文件夹">选目录</button>
            </div>
            <div class="flex items-center gap-1.5 pt-0.5">
              <button @click="runDocumentDissectAudit" :disabled="!dissectTargetPath.trim() || isDissectingDocs" class="ui-btn-primary bg-amber-600 hover:bg-amber-500 px-2.5 py-1 text-[11px] flex-1">
                {{ isDissectingDocs ? '二进制解构中...' : '穿透扫描标密文档' }}
              </button>
              <button v-if="dissectReport" @click="secrecySubView = 'docs'" class="ui-btn-secondary px-2 py-1 text-[11px]">明细</button>
            </div>
          </div>

          <!-- 卡 3: 双网卡“一机两用”核查 -->
          <div class="ui-sub-card p-2.5 flex flex-col justify-between gap-1.5">
            <div class="flex items-center justify-between gap-2">
              <span class="text-xs font-semibold" style="color: var(--text-primary);">3. “一机两用”路由核查</span>
              <span
                v-if="dualHomedReport"
                class="px-1.5 py-0.5 rounded text-[10px] font-semibold ui-num"
                :class="dualHomedReport.is_dual_homed_violation ? 'bg-rose-600 text-white' : dualHomedReport.risk_level === 'HIGH' ? 'bg-amber-500/20 text-amber-700 dark:text-amber-300' : 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300'"
              >
                {{ dualHomedReport.risk_level }}
              </span>
            </div>
            <div class="text-[11px] truncate" style="color: var(--text-muted);" :title="dualHomedReport?.reason">
              {{ dualHomedReport ? dualHomedReport.reason : '探测有线/无线双激活及公私网路由桥接' }}
            </div>
            <div class="flex items-center gap-1.5 pt-0.5">
              <button @click="runDualHomedNetworkAudit" :disabled="isAuditingDualHomed" class="ui-btn-primary bg-amber-600 hover:bg-amber-500 px-2.5 py-1 text-[11px] flex-1">
                {{ isAuditingDualHomed ? '路由检测中...' : '检测一机两用双联' }}
              </button>
              <button v-if="dualHomedReport" @click="secrecySubView = 'dualhomed'" class="ui-btn-secondary px-2 py-1 text-[11px]">明细</button>
            </div>
          </div>

          <!-- 卡 4: BMB 标准 A4 保密勘验正式大报告 -->
          <div class="ui-sub-card p-2.5 flex flex-col justify-between gap-1.5 border-rose-500/20">
            <div class="flex items-center justify-between gap-2">
              <span class="text-xs font-semibold" style="color: var(--text-primary);">4. BMB 现场勘验大报告</span>
              <span
                class="px-1.5 py-0.5 rounded text-[10px] font-semibold"
                :class="secrecyVerdict.code === 'QUALIFIED' ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300' : secrecyVerdict.code === 'CONDITIONALLY_QUALIFIED' ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300' : 'bg-rose-600 text-white'"
              >
                {{ secrecyVerdict.label }}
              </span>
            </div>
            <div class="text-[11px] truncate font-mono" style="color: var(--text-muted);">
              编号 {{ secrecyDigest.reportId }} · SM3 保全
            </div>
            <button @click="openSecrecyFormalReportModal" class="ui-btn-primary px-2.5 py-1 text-[11px] w-full flex items-center justify-center gap-1">
              <AppIcon name="report" :size="12" />
              <span>出具 BMB 勘验 A4 正式报告</span>
            </button>
          </div>
        </div>

        <!-- 第 2 阶段扩展四联深度取证操作卡栏 -->
        <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-2 shrink-0">
          <!-- 卡 5: 历史外联与手机 USB 共享痕迹 -->
          <div class="ui-sub-card p-2.5 flex flex-col justify-between gap-1.5">
            <div class="flex items-center justify-between gap-2">
              <span class="text-xs font-semibold" style="color: var(--text-primary);">5. 历史 Wi-Fi / RNDIS 外联</span>
              <span
                v-if="networkHistoryReport"
                class="px-1.5 py-0.5 rounded text-[10px] font-semibold ui-num"
                :class="networkHistoryReport.has_historic_violation ? 'bg-rose-500/15 text-rose-700 dark:text-rose-300' : 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300'"
              >
                {{ networkHistoryReport.has_historic_violation ? '检出外联痕迹' : '历史洁净' }}
              </span>
            </div>
            <div class="text-[11px] truncate" style="color: var(--text-muted);" :title="networkHistoryReport?.summary_conclusion">
              {{ networkHistoryReport ? networkHistoryReport.summary_conclusion : '解析 WlanSvc 配置 XML、USB RNDIS 共享及拨号记录' }}
            </div>
            <div class="flex items-center gap-1.5 pt-0.5">
              <button @click="runNetworkHistoryAudit" :disabled="isAuditingNetworkHistory" class="ui-btn-primary bg-indigo-600 hover:bg-indigo-500 px-2.5 py-1 text-[11px] flex-1">
                {{ isAuditingNetworkHistory ? '取证扫描中...' : '排查历史外联痕迹' }}
              </button>
              <button v-if="networkHistoryReport" @click="secrecySubView = 'history'" class="ui-btn-secondary px-2 py-1 text-[11px]">明细</button>
            </div>
          </div>

          <!-- 卡 6: OLE2 老式文档解构与扇区残片扫描 -->
          <div class="ui-sub-card p-2.5 flex flex-col justify-between gap-1.5">
            <div class="flex items-center justify-between gap-2">
              <span class="text-xs font-semibold" style="color: var(--text-primary);">6. OLE2 与磁盘残片检索</span>
              <span
                v-if="ole2Report"
                class="px-1.5 py-0.5 rounded text-[10px] font-semibold ui-num"
                :class="(ole2Report.ole2_hits.length + ole2Report.slack_hits.length) > 0 ? 'bg-rose-500/15 text-rose-700 dark:text-rose-300' : 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300'"
              >
                {{ (ole2Report.ole2_hits.length + ole2Report.slack_hits.length) > 0 ? `命中 ${ole2Report.ole2_hits.length}+${ole2Report.slack_hits.length}` : '洁净' }}
              </span>
            </div>
            <div class="flex items-center gap-1">
              <input
                v-model="ole2RawSlackTarget"
                placeholder="可选残片目标(如 \\.\D: 或镜像文件)"
                class="ui-input px-2 py-0.5 text-[11px] font-mono flex-1 min-w-0"
              />
            </div>
            <div class="flex items-center gap-1.5 pt-0.5">
              <button @click="runOle2AndSlackAudit" :disabled="isDissectingOle2" class="ui-btn-primary bg-indigo-600 hover:bg-indigo-500 px-2.5 py-1 text-[11px] flex-1">
                {{ isDissectingOle2 ? 'CFBF 解析中...' : '扫描 DOC/XLS 与残片' }}
              </button>
              <button v-if="ole2Report" @click="secrecySubView = 'ole2'" class="ui-btn-secondary px-2 py-1 text-[11px]">明细</button>
            </div>
          </div>

          <!-- 卡 7: 操作系统使用轨迹 (.lnk / .SHD / 开关机) -->
          <div class="ui-sub-card p-2.5 flex flex-col justify-between gap-1.5">
            <div class="flex items-center justify-between gap-2">
              <span class="text-xs font-semibold" style="color: var(--text-primary);">7. OS 行为与打印留痕</span>
              <span
                v-if="osUsageReport"
                class="px-1.5 py-0.5 rounded text-[10px] font-semibold ui-num"
                :class="osUsageReport.secrecy_named_access_count > 0 ? 'bg-rose-500/15 text-rose-700 dark:text-rose-300' : 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300'"
              >
                {{ `LNK ${osUsageReport.total_lnk_parsed} · 打印 ${osUsageReport.print_spooler_jobs.length}` }}
              </span>
            </div>
            <div class="text-[11px] truncate" style="color: var(--text-muted);">
              {{ osUsageReport ? `可移动打开 ${osUsageReport.suspicious_u_disk_file_count} 项 · 涉密命名 ${osUsageReport.secrecy_named_access_count} 项` : '解析 Recent 快捷方式、Spooler 脱机与开关机日志' }}
            </div>
            <div class="flex items-center gap-1.5 pt-0.5">
              <button @click="runOsUsageAudit" :disabled="isAuditingOsUsage" class="ui-btn-primary bg-indigo-600 hover:bg-indigo-500 px-2.5 py-1 text-[11px] flex-1">
                {{ isAuditingOsUsage ? '轨迹还原中...' : '提取操作与打印痕迹' }}
              </button>
              <button v-if="osUsageReport" @click="secrecySubView = 'osusage'" class="ui-btn-secondary px-2 py-1 text-[11px]">明细</button>
            </div>
          </div>

          <!-- 卡 8: 浏览器下载 SQLite 与即时通信目录审计 -->
          <div class="ui-sub-card p-2.5 flex flex-col justify-between gap-1.5">
            <div class="flex items-center justify-between gap-2">
              <span class="text-xs font-semibold" style="color: var(--text-primary);">8. 浏览器与 IM 外发审计</span>
              <span
                v-if="appTraceReport"
                class="px-1.5 py-0.5 rounded text-[10px] font-semibold ui-num"
                :class="(appTraceReport.suspicious_downloads.length + appTraceReport.chat_file_hits.length) > 0 ? 'bg-rose-500/15 text-rose-700 dark:text-rose-300' : 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300'"
              >
                {{ (appTraceReport.suspicious_downloads.length + appTraceReport.chat_file_hits.length) > 0 ? `命中 ${appTraceReport.suspicious_downloads.length + appTraceReport.chat_file_hits.length} 条` : '洁净' }}
              </span>
            </div>
            <div class="text-[11px] truncate" style="color: var(--text-muted);">
              {{ appTraceReport ? `下载 ${appTraceReport.total_downloads_checked} 条 · IM 文件 ${appTraceReport.chat_files_checked} 份` : '无锁解析 Chrome/Edge/Firefox 历史与微信钉钉缓存' }}
            </div>
            <div class="flex items-center gap-1.5 pt-0.5">
              <button @click="runAppTracesAudit" :disabled="isAuditingAppTraces" class="ui-btn-primary bg-indigo-600 hover:bg-indigo-500 px-2.5 py-1 text-[11px] flex-1">
                {{ isAuditingAppTraces ? '库解析中...' : '审计浏览器与聊天传输' }}
              </button>
              <button v-if="appTraceReport" @click="secrecySubView = 'apptrace'" class="ui-btn-secondary px-2 py-1 text-[11px]">明细</button>
            </div>
          </div>
        </div>

        <!-- 子视图 1: 原有网流告警流水 + 即席静态公文扫描器 -->
        <template v-if="secrecySubView === 'overview'">
          <!-- 上半部分：保密告警流水表 -->
          <div class="flex-1 border rounded-xl overflow-hidden flex flex-col min-h-0">
            <div class="p-2.5 border-b text-xs font-semibold flex items-center justify-between shrink-0" style="border-color: var(--border-subtle); color: var(--text-primary); background: var(--surface-content-alt);">
              <div class="flex items-center gap-2">
                <span>涉密公文与违规外联安全警报流水</span>
                <span class="px-1.5 py-0.5 rounded-full text-[11px] bg-rose-500/15 text-rose-700 dark:text-rose-300 ui-num font-semibold">{{ confidentialityAlerts.length }} 笔</span>
              </div>
              <span class="text-[11px]" style="color: var(--text-muted);">国家秘密法法定标志 · 红头公文字号 · 高危外联阻断</span>
            </div>

            <div class="flex-1 overflow-auto custom-scrollbar" style="background: var(--surface-content-alt);">
              <table class="w-full text-left text-xs border-collapse">
                <thead class="ui-table-head sticky top-0 select-none">
                  <tr>
                    <th class="py-2 px-3">告警 ID</th>
                    <th class="py-2 px-3">时间</th>
                    <th class="py-2 px-3">告警分类</th>
                    <th class="py-2 px-3">法定定密等级</th>
                    <th class="py-2 px-3">命中特征实体/字号</th>
                    <th class="py-2 px-3">审查判定说明</th>
                    <th class="py-2 px-3 text-right">操作</th>
                  </tr>
                </thead>
                <tbody class="divide-y text-xs" style="border-color: var(--border-subtle);">
                  <tr v-for="alt in confidentialityAlerts" :key="alt.id" class="hover:bg-[var(--surface-hover)]">
                    <td class="py-2 px-3 ui-num" style="color: var(--text-muted);">#{{ alt.id }}</td>
                    <td class="py-2 px-3 ui-num whitespace-nowrap" style="color: var(--text-secondary);">{{ alt.timestamp }}</td>
                    <td class="py-2 px-3 font-semibold" style="color: var(--text-primary);">{{ alt.alert_category }}</td>
                    <td class="py-2 px-3">
                      <span
                        class="px-1.5 py-0.5 rounded text-[11px] font-semibold"
                        :class="{
                          'bg-rose-700 text-white': alt.secrecy_level === 'TOP_SECRET',
                          'bg-rose-500 text-white': alt.secrecy_level === 'CONFIDENTIAL',
                          'bg-amber-500 text-white': alt.secrecy_level === 'SECRET',
                          'ui-pill': alt.secrecy_level === 'HIGH_RISK' || alt.secrecy_level === 'INTERNAL'
                        }"
                      >
                        {{ alt.secrecy_level }}
                      </span>
                    </td>
                    <td class="py-2 px-3 font-semibold text-rose-600 dark:text-rose-400 whitespace-nowrap">{{ alt.target_entity }}</td>
                    <td class="py-2 px-3 max-w-lg truncate" style="color: var(--text-secondary);" :title="alt.summary">{{ alt.summary }}</td>
                    <td class="py-2 px-3 text-right whitespace-nowrap space-x-1.5">
                      <button
                        v-if="alt.alert_category === 'ILLEGAL_EGRESS'"
                        @click="blockEgressTarget(alt.target_entity, alt.summary)"
                        class="ui-btn-danger px-2 py-0.5 text-[11px]"
                      >
                        阻断外联
                      </button>
                      <button @click="selectedDetailJson = alt.detail_json; isDetailModalOpen = true" class="ui-btn-secondary px-2 py-0.5 text-[11px]">
                        勘验 JSON
                      </button>
                      <button @click="addConfidentialAlertToDiffQueue(alt)" class="px-2 py-0.5 rounded bg-emerald-500/12 hover:bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border border-emerald-500/25 text-[11px] font-semibold cursor-pointer">
                        + 入队
                      </button>
                    </td>
                  </tr>
                  <tr v-if="confidentialityAlerts.length === 0">
                    <td colspan="7" class="text-center py-8 text-xs" style="color: var(--text-muted);">
                      网络通信与硬件总线暂未触发涉密合规与违规外联警报
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <!-- 下半部分：即时公文档案保密合规静态扫描器 -->
          <div class="flex-1 ui-sub-card p-3 flex flex-col min-h-0">
            <div class="flex items-center justify-between pb-2 border-b shrink-0 flex-wrap gap-2" style="border-color: var(--border-subtle);">
              <div class="flex items-center gap-2">
                <span class="w-2 h-2 rounded-full bg-amber-500"></span>
                <span class="text-xs font-semibold" style="color: var(--text-primary);">涉密红头公文与文档即时静态扫描验算器</span>
                <span class="text-[11px]" style="color: var(--text-muted);">Aho-Corasick 多模式自动机线性匹配</span>
              </div>
              <button @click="runStaticConfidentialityScan" :disabled="!scanInputText.trim() || isScanningText" class="ui-btn-primary bg-amber-600 hover:bg-amber-500 px-3 py-1 text-xs">
                {{ isScanningText ? '扫描验算中...' : '立即执行保密静态扫描' }}
              </button>
            </div>

            <div class="flex-1 grid grid-cols-1 lg:grid-cols-2 gap-3 pt-2.5 overflow-hidden min-h-0">
              <div class="flex flex-col min-h-0">
                <label class="text-[11px] font-semibold mb-1" style="color: var(--text-muted);">待验算公文档案 / 邮件草稿 / 代码或文本载荷:</label>
                <textarea
                  v-model="scanInputText"
                  placeholder="粘贴待审查的公文草稿文本、发文通知或通信载荷... 例如：国务院办公厅发[2024]12号通知，本件属于机密★20年..."
                  class="ui-input flex-1 w-full p-2.5 font-mono text-xs resize-none custom-scrollbar"
                ></textarea>
              </div>

              <div class="flex flex-col min-h-0 rounded-xl border p-3 overflow-auto custom-scrollbar" style="background: var(--surface-content); border-color: var(--border-subtle);">
                <div class="text-[11px] font-semibold mb-1.5 flex items-center justify-between" style="color: var(--text-muted);">
                  <span>保密合规技术审查勘验结论:</span>
                  <span v-if="confidentialScanResult" class="ui-num">检材体积: {{ confidentialScanResult.scanned_bytes }} 字节</span>
                </div>

                <div v-if="confidentialScanResult" class="space-y-2 text-xs">
                  <div
                    class="p-2.5 rounded-lg border"
                    :class="confidentialScanResult.is_secret ? 'bg-rose-500/10 border-rose-500/25 text-rose-700 dark:text-rose-200' : 'bg-emerald-500/10 border-emerald-500/25 text-emerald-700 dark:text-emerald-200'"
                  >
                    <div class="font-semibold flex items-center gap-2 flex-wrap">
                      <AppIcon :name="confidentialScanResult.is_secret ? 'alert' : 'check'" :size="14" />
                      <span>{{ confidentialScanResult.is_secret ? '检出涉密与红头特征' : '未见标密违规特征' }}</span>
                      <span v-if="confidentialScanResult.is_secret" class="px-1.5 py-0.5 rounded text-[11px] bg-rose-500/20 font-mono">
                        最高定密等级: {{ confidentialScanResult.highest_level }}
                      </span>
                    </div>
                    <p class="text-[11px] mt-1">{{ confidentialScanResult.recommendation }}</p>
                  </div>

                  <div v-if="confidentialScanResult.hit_markers.length > 0">
                    <div class="text-[11px] font-semibold" style="color: var(--text-muted);">命中法定秘密标识:</div>
                    <div class="flex flex-wrap gap-1 mt-1">
                      <span
                        v-for="m in confidentialScanResult.hit_markers"
                        :key="m"
                        class="px-2 py-0.5 rounded-md bg-rose-500/15 text-rose-700 dark:text-rose-300 font-mono font-semibold text-[11px]"
                      >
                        {{ m }}
                      </span>
                    </div>
                  </div>

                  <div v-if="confidentialScanResult.document_signatures.length > 0">
                    <div class="text-[11px] font-semibold" style="color: var(--text-muted);">命中红头公文发文字号:</div>
                    <div class="flex flex-wrap gap-1 mt-1">
                      <span
                        v-for="s in confidentialScanResult.document_signatures"
                        :key="s"
                        class="px-2 py-0.5 rounded-md bg-amber-500/15 text-amber-700 dark:text-amber-300 font-mono font-semibold text-[11px]"
                      >
                        {{ s }}
                      </span>
                    </div>
                  </div>
                </div>

                <div v-else class="flex-1 flex flex-col items-center justify-center text-xs" style="color: var(--text-muted);">
                  <span>在左侧粘贴文本并点击“立即执行保密静态扫描”</span>
                </div>
              </div>
            </div>
          </div>
        </template>

        <!-- 子视图 2: USB 历史插拔痕迹与非涉密介质取证明细 -->
        <div v-else-if="secrecySubView === 'usb'" class="flex-1 border rounded-xl overflow-hidden flex flex-col min-h-0" style="border-color: var(--border-subtle); background: var(--surface-content-alt);">
          <div class="p-2.5 border-b text-xs flex items-center justify-between flex-wrap gap-2 shrink-0" style="border-color: var(--border-subtle);">
            <div class="flex items-center gap-2">
              <span class="font-semibold" style="color: var(--text-primary);">涉密终端 USBSTOR 历史插拔痕迹与盘符映射取证表</span>
              <span v-if="usbForensicsReport" class="text-[11px] font-mono" style="color: var(--text-muted);">
                主机: {{ usbForensicsReport.scanned_host }} · 扫描时间: {{ usbForensicsReport.scan_time }}
              </span>
            </div>
            <button @click="runSecrecyUsbHistoryAudit" :disabled="isAuditingUsbHistory" class="ui-btn-secondary px-2.5 py-1 text-[11px]">
              {{ isAuditingUsbHistory ? '重新提取中...' : '刷新 USB 物理取证' }}
            </button>
          </div>
          <div class="flex-1 overflow-auto custom-scrollbar">
            <table v-if="usbForensicsReport && usbForensicsReport.devices.length > 0" class="w-full text-left text-xs border-collapse">
              <thead class="ui-table-head sticky top-0 select-none">
                <tr>
                  <th class="py-2 px-3">友好设备名称</th>
                  <th class="py-2 px-3">VID / PID</th>
                  <th class="py-2 px-3">物理唯一序列号</th>
                  <th class="py-2 px-3">历史盘符</th>
                  <th class="py-2 px-3">首次 / 末次接入时间戳</th>
                  <th class="py-2 px-3">证据来源</th>
                  <th class="py-2 px-3">BMB22 合规裁决</th>
                </tr>
              </thead>
              <tbody class="divide-y text-xs" style="border-color: var(--border-subtle);">
                <tr v-for="dev in usbForensicsReport.devices" :key="dev.device_id + dev.serial_number" class="hover:bg-[var(--surface-hover)]">
                  <td class="py-2 px-3 font-semibold" style="color: var(--text-primary);" :title="dev.device_id">{{ dev.device_name }}</td>
                  <td class="py-2 px-3 font-mono ui-num" style="color: var(--text-secondary);">{{ dev.vendor_id }} : {{ dev.product_id }}</td>
                  <td class="py-2 px-3 font-mono text-[11px]" style="color: var(--text-secondary);">{{ dev.serial_number }}</td>
                  <td class="py-2 px-3 font-mono font-semibold" style="color: var(--text-primary);">{{ dev.assigned_drive_letter }}</td>
                  <td class="py-2 px-3 font-mono text-[11px] ui-num" style="color: var(--text-secondary);">
                    <div>首: {{ dev.first_installed_time }}</div>
                    <div>末: {{ dev.last_arrival_time }}</div>
                  </td>
                  <td class="py-2 px-3 font-mono text-[11px]" style="color: var(--text-muted);">{{ dev.evidence_source }}</td>
                  <td class="py-2 px-3">
                    <span class="px-2 py-0.5 rounded text-[11px] font-semibold" :class="dev.is_whitelisted ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300' : 'bg-rose-600 text-white'">
                      {{ dev.is_whitelisted ? '授权白名单' : '非授权违规介质' }}
                    </span>
                  </td>
                </tr>
              </tbody>
            </table>
            <div v-else class="p-8 text-center text-xs" style="color: var(--text-muted);">
              {{ usbForensicsReport ? usbForensicsReport.summary_conclusion : '点击上方“提取历史 USB 痕迹”以物理穿透注册表 USBSTOR 与 MountedDevices。' }}
            </div>
          </div>
        </div>

        <!-- 子视图 3: 复合公文 (DOCX/OFD/PDF/ZIP) 穿透解构明细 -->
        <div v-else-if="secrecySubView === 'docs'" class="flex-1 border rounded-xl overflow-hidden flex flex-col min-h-0" style="border-color: var(--border-subtle); background: var(--surface-content-alt);">
          <div class="p-2.5 border-b text-xs flex items-center justify-between flex-wrap gap-2 shrink-0" style="border-color: var(--border-subtle);">
            <div class="flex items-center gap-2">
              <span class="font-semibold" style="color: var(--text-primary);">复合文档二进制穿透解构与法定标密检索清单</span>
              <span v-if="dissectReport" class="text-[11px] font-mono" style="color: var(--text-muted);">
                已解构 {{ dissectReport.scanned_files_count }} 份文档 · 耗时 {{ dissectReport.duration_ms }} ms · 加密/阻塞 {{ dissectReport.encrypted_or_blocked_count }} 份
              </span>
            </div>
            <div v-if="dissectReport && dissectReport.warnings.length > 0" class="text-[11px] text-amber-600 dark:text-amber-400">
              预警: {{ dissectReport.warnings[0] }}
            </div>
          </div>
          <div class="flex-1 overflow-auto custom-scrollbar">
            <table v-if="dissectReport && dissectReport.hits.length > 0" class="w-full text-left text-xs border-collapse">
              <thead class="ui-table-head sticky top-0 select-none">
                <tr>
                  <th class="py-2 px-3">文件路径 (含嵌套层级)</th>
                  <th class="py-2 px-3">格式</th>
                  <th class="py-2 px-3">标密等级</th>
                  <th class="py-2 px-3">命中标识与发文字号</th>
                  <th class="py-2 px-3">SM3 摘要 (前16位)</th>
                  <th class="py-2 px-3">脱敏内容摘要</th>
                </tr>
              </thead>
              <tbody class="divide-y text-xs" style="border-color: var(--border-subtle);">
                <tr v-for="hit in dissectReport.hits" :key="hit.file_path + (hit.nested_path || '')" class="hover:bg-[var(--surface-hover)]">
                  <td class="py-2 px-3 font-mono text-[11px] max-w-xs break-all" style="color: var(--text-primary);">
                    {{ hit.file_path }}<span v-if="hit.nested_path" class="text-amber-600 dark:text-amber-400"> -> [{{ hit.nested_path }}]</span>
                  </td>
                  <td class="py-2 px-3 font-mono">{{ hit.file_type }}</td>
                  <td class="py-2 px-3">
                    <span class="px-1.5 py-0.5 rounded text-[11px] font-semibold" :class="hit.secrecy_level === 'ENCRYPTED_FILE' || hit.secrecy_level === 'ZIP_BOMB_BLOCKED' ? 'bg-amber-500/20 text-amber-700 dark:text-amber-300' : 'bg-rose-600 text-white'">
                      {{ hit.secrecy_level }}
                    </span>
                  </td>
                  <td class="py-2 px-3 font-semibold text-rose-600 dark:text-rose-400">
                    {{ [...hit.matched_markers, ...hit.document_signatures].join('、') || '-' }}
                  </td>
                  <td class="py-2 px-3 font-mono text-[11px]" style="color: var(--text-muted);" :title="hit.sm3_hash">{{ hit.sm3_hash.slice(0, 16) }}...</td>
                  <td class="py-2 px-3 text-[11px] max-w-sm truncate" style="color: var(--text-secondary);" :title="hit.snippet_preview">{{ hit.snippet_preview }}</td>
                </tr>
              </tbody>
            </table>
            <div v-else class="p-8 text-center text-xs" style="color: var(--text-muted);">
              {{ dissectReport ? `目标目录 "${dissectReport.target_folder}" 已扫描 ${dissectReport.scanned_files_count} 份文件，未命中法定涉密标识文档。` : '请在上方“复合公文穿透扫描”卡片选择或输入本地目录执行扫描。' }}
            </div>
          </div>
        </div>

        <!-- 子视图 4: “一机两用”物理网络与路由交叉核查明细 -->
        <div v-else-if="secrecySubView === 'dualhomed'" class="flex-1 border rounded-xl overflow-hidden flex flex-col min-h-0" style="border-color: var(--border-subtle); background: var(--surface-content-alt);">
          <div class="p-2.5 border-b text-xs flex items-center justify-between flex-wrap gap-2 shrink-0" style="border-color: var(--border-subtle);">
            <div class="flex items-center gap-2 flex-wrap">
              <span class="font-semibold" style="color: var(--text-primary);">宿主机“一机两用”双网连通性与路由表穿透核查</span>
              <span v-if="dualHomedReport && dualHomedReport.wireless_ssid" class="px-2 py-0.5 rounded bg-rose-500/15 text-rose-700 dark:text-rose-300 font-mono text-[11px]">
                关联热点 SSID: {{ dualHomedReport.wireless_ssid }}
              </span>
            </div>
            <button @click="runDualHomedNetworkAudit" :disabled="isAuditingDualHomed" class="ui-btn-secondary px-2.5 py-1 text-[11px]">
              {{ isAuditingDualHomed ? '检测中...' : '刷新接口与路由核查' }}
            </button>
          </div>
          <div v-if="dualHomedReport" class="p-2.5 border-b text-xs shrink-0" :class="dualHomedReport.is_dual_homed_violation ? 'bg-rose-500/10 text-rose-700 dark:text-rose-200' : dualHomedReport.risk_level === 'HIGH' ? 'bg-amber-500/10 text-amber-800 dark:text-amber-200' : 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-200'" style="border-color: var(--border-subtle);">
            <b>裁决说明 [{{ dualHomedReport.risk_level }}]：</b>{{ dualHomedReport.reason }}
          </div>
          <div class="flex-1 overflow-auto custom-scrollbar">
            <table v-if="dualHomedReport && dualHomedReport.interfaces.length > 0" class="w-full text-left text-xs border-collapse">
              <thead class="ui-table-head sticky top-0 select-none">
                <tr>
                  <th class="py-2 px-3">网卡适配器名称</th>
                  <th class="py-2 px-3">链路物理分类</th>
                  <th class="py-2 px-3">当前状态</th>
                  <th class="py-2 px-3">IPv4 地址列表</th>
                  <th class="py-2 px-3">默认网关</th>
                  <th class="py-2 px-3">网络边界归属</th>
                </tr>
              </thead>
              <tbody class="divide-y text-xs" style="border-color: var(--border-subtle);">
                <tr v-for="nic in dualHomedReport.interfaces" :key="nic.name" class="hover:bg-[var(--surface-hover)]">
                  <td class="py-2 px-3 font-semibold" style="color: var(--text-primary);">{{ nic.name }}</td>
                  <td class="py-2 px-3 font-mono">{{ nic.if_type }}</td>
                  <td class="py-2 px-3">
                    <span class="px-1.5 py-0.5 rounded text-[11px] font-semibold" :class="nic.is_up ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300' : 'ui-pill'">
                      {{ nic.is_up ? 'UP 已连接' : 'DOWN' }}
                    </span>
                  </td>
                  <td class="py-2 px-3 font-mono ui-num" style="color: var(--text-secondary);">{{ nic.ip_addresses.join(', ') || '-' }}</td>
                  <td class="py-2 px-3 font-mono ui-num" style="color: var(--text-secondary);">{{ nic.gateway_addresses.join(', ') || '-' }}</td>
                  <td class="py-2 px-3">
                    <span v-if="nic.is_connected_to_public" class="text-rose-600 dark:text-rose-400 font-semibold">公网路由暴露</span>
                    <span v-else-if="nic.is_connected_to_private" class="text-emerald-600 dark:text-emerald-400">内网私网段</span>
                    <span v-else style="color: var(--text-muted);">未配置地址</span>
                  </td>
                </tr>
              </tbody>
            </table>
            <div v-else class="p-8 text-center text-xs" style="color: var(--text-muted);">
              点击上方“检测一机两用双联”提取宿主机全部网卡接口与系统默认网关路由。
            </div>
          </div>
        </div>

        <!-- 子视图 5: 历史外联与手机共享网络取证明细 -->
        <div v-else-if="secrecySubView === 'history'" class="flex-1 border rounded-xl overflow-hidden flex flex-col min-h-0" style="border-color: var(--border-subtle); background: var(--surface-content-alt);">
          <div class="p-2.5 border-b flex items-center justify-between text-xs shrink-0" style="border-color: var(--border-subtle);">
            <div class="flex items-center gap-2">
              <span class="font-semibold" style="color: var(--text-primary);">历史无线 Wi-Fi 配置、USB RNDIS 共享及拨号连接取证</span>
              <span v-if="networkHistoryReport" class="text-[11px] ui-num" style="color: var(--text-muted);">
                Wi-Fi {{ networkHistoryReport.total_wifi_profiles_found }} 项 · 可疑热点 {{ networkHistoryReport.suspicious_mobile_hotspots.length }} 项 · RNDIS {{ networkHistoryReport.historic_rndis_devices.length }} 台
              </span>
            </div>
            <button @click="runNetworkHistoryAudit" :disabled="isAuditingNetworkHistory" class="ui-btn-secondary px-2.5 py-1 text-[11px]">重新排查</button>
          </div>
          <div class="flex-1 overflow-auto custom-scrollbar p-2.5 space-y-3">
            <template v-if="networkHistoryReport">
              <div v-if="networkHistoryReport.degrade_notes.length > 0" class="p-2 rounded-lg bg-amber-500/10 border border-amber-500/25 text-[11px] text-amber-800 dark:text-amber-300">
                <b>降级与权限说明：</b>{{ networkHistoryReport.degrade_notes.join('；') }}
              </div>
              <div v-if="networkHistoryReport.historic_rndis_devices.length > 0" class="p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-xs text-rose-700 dark:text-rose-300">
                <b>检出历史手机 USB 网络共享 (RNDIS / Apple Mobile) 设备实例：</b>
                <ul class="list-disc ml-4 mt-1 font-mono text-[11px]">
                  <li v-for="(dev, idx) in networkHistoryReport.historic_rndis_devices" :key="idx">{{ dev }}</li>
                </ul>
              </div>
              <div v-if="networkHistoryReport.historic_dialup_connections.length > 0" class="p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-xs">
                <b>检出历史拨号 / VPN 连接配置：</b> {{ networkHistoryReport.historic_dialup_connections.join('、') }}
              </div>
              <table v-if="networkHistoryReport.all_wifi_profiles.length > 0" class="w-full text-left text-xs border-collapse">
                <thead class="ui-table-head sticky top-0">
                  <tr>
                    <th class="py-1.5 px-2.5">配置文件名</th>
                    <th class="py-1.5 px-2.5">无线 SSID</th>
                    <th class="py-1.5 px-2.5">认证 / 加密方式</th>
                    <th class="py-1.5 px-2.5">配置末次修改时间</th>
                    <th class="py-1.5 px-2.5 text-center">风险特征</th>
                  </tr>
                </thead>
                <tbody class="divide-y" style="border-color: var(--border-subtle);">
                  <tr v-for="(w, idx) in networkHistoryReport.all_wifi_profiles" :key="idx" class="hover:bg-[var(--surface-hover)]">
                    <td class="py-1.5 px-2.5 font-semibold">{{ w.profile_name }}</td>
                    <td class="py-1.5 px-2.5 font-mono">{{ w.ssid }}</td>
                    <td class="py-1.5 px-2.5">{{ w.auth_type }} / {{ w.cipher }}</td>
                    <td class="py-1.5 px-2.5 ui-num">{{ w.last_modified_time }}</td>
                    <td class="py-1.5 px-2.5 text-center">
                      <span class="px-1.5 py-0.5 rounded text-[11px] font-semibold" :class="w.is_mobile_hotspot_feature ? 'bg-rose-500/15 text-rose-700 dark:text-rose-300' : 'ui-pill'">
                        {{ w.is_mobile_hotspot_feature ? '手机热点特征' : '常规无线配置' }}
                      </span>
                    </td>
                  </tr>
                </tbody>
              </table>
              <div v-if="networkHistoryReport.historic_network_profiles.length > 0">
                <div class="text-[11px] font-semibold mb-1" style="color: var(--text-muted);">NetworkList 注册表历史网络连接列表：</div>
                <table class="w-full text-left text-xs border-collapse">
                  <thead class="ui-table-head">
                    <tr>
                      <th class="py-1.5 px-2.5">网络配置名称</th>
                      <th class="py-1.5 px-2.5">网络类型 (Category)</th>
                      <th class="py-1.5 px-2.5">末次连接时间</th>
                    </tr>
                  </thead>
                  <tbody class="divide-y" style="border-color: var(--border-subtle);">
                    <tr v-for="(n, idx) in networkHistoryReport.historic_network_profiles" :key="idx">
                      <td class="py-1.5 px-2.5 font-semibold">{{ n.profile_name }}</td>
                      <td class="py-1.5 px-2.5">{{ n.network_category }}</td>
                      <td class="py-1.5 px-2.5 ui-num">{{ n.last_connected_time }}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <div v-if="networkHistoryReport.all_wifi_profiles.length === 0 && networkHistoryReport.historic_network_profiles.length === 0 && networkHistoryReport.historic_rndis_devices.length === 0" class="p-6 text-center text-xs text-emerald-600 dark:text-emerald-400">
                未在注册表、WlanSvc 与网络配置库中检出任何非授权外联历史痕迹。
              </div>
            </template>
            <div v-else class="p-8 text-center text-xs" style="color: var(--text-muted);">点击上方“排查历史外联痕迹”启动全量 WlanSvc、USB RNDIS 与拨号配置取证。</div>
          </div>
        </div>

        <!-- 子视图 6: 老旧 OLE2 与磁盘空闲扇区残片检索明细 -->
        <div v-else-if="secrecySubView === 'ole2'" class="flex-1 border rounded-xl overflow-hidden flex flex-col min-h-0" style="border-color: var(--border-subtle); background: var(--surface-content-alt);">
          <div class="p-2.5 border-b flex items-center justify-between text-xs shrink-0" style="border-color: var(--border-subtle);">
            <div class="flex items-center gap-2">
              <span class="font-semibold" style="color: var(--text-primary);">OLE2 复合二进制文档 (.doc/.xls/.ppt) 及扇区残片取证明细</span>
              <span v-if="ole2Report" class="text-[11px] ui-num" style="color: var(--text-muted);">
                解构 {{ ole2Report.scanned_ole2_files }} 份 · OLE2 命中 {{ ole2Report.ole2_hits.length }} 份 · 扇区 {{ ole2Report.slack_scanned_bytes }} Bytes (残片命中 {{ ole2Report.slack_hits.length }})
              </span>
            </div>
            <button @click="runOle2AndSlackAudit" :disabled="isDissectingOle2" class="ui-btn-secondary px-2.5 py-1 text-[11px]">重新扫描</button>
          </div>
          <div class="flex-1 overflow-auto custom-scrollbar p-2.5 space-y-3">
            <template v-if="ole2Report">
              <div v-if="ole2Report.warnings.length > 0" class="p-2 rounded-lg bg-amber-500/10 border border-amber-500/25 text-[11px] text-amber-800 dark:text-amber-300">
                <b>解析提示：</b>{{ ole2Report.warnings.join('；') }}
              </div>
              <table v-if="ole2Report.ole2_hits.length > 0" class="w-full text-left text-xs border-collapse">
                <thead class="ui-table-head sticky top-0">
                  <tr>
                    <th class="py-1.5 px-2.5">文件路径与 CFBF 子流</th>
                    <th class="py-1.5 px-2.5 text-center">定密判定</th>
                    <th class="py-1.5 px-2.5">命中标志词 / 文号</th>
                    <th class="py-1.5 px-2.5">SM3 哈希与脱敏摘要</th>
                  </tr>
                </thead>
                <tbody class="divide-y" style="border-color: var(--border-subtle);">
                  <tr v-for="(h, idx) in ole2Report.ole2_hits" :key="idx" class="hover:bg-[var(--surface-hover)]">
                    <td class="py-1.5 px-2.5 font-mono text-[11px]">
                      <div class="font-semibold">{{ h.file_path }}</div>
                      <div style="color: var(--text-muted);">流: {{ h.sub_stream_name }}</div>
                    </td>
                    <td class="py-1.5 px-2.5 text-center"><span class="px-1.5 py-0.5 rounded bg-rose-600 text-white text-[10px] font-semibold">{{ h.secrecy_level }}</span></td>
                    <td class="py-1.5 px-2.5 font-semibold">{{ [...h.matched_markers, ...h.document_signatures].join('、') || '-' }}</td>
                    <td class="py-1.5 px-2.5 text-[11px]">
                      <div class="font-mono" style="color: var(--text-muted);">SM3: {{ h.sm3_hash.slice(0, 20) }}...</div>
                      <div class="truncate max-w-md" :title="h.snippet_preview">{{ h.snippet_preview }}</div>
                    </td>
                  </tr>
                </tbody>
              </table>
              <table v-if="ole2Report.slack_hits.length > 0" class="w-full text-left text-xs border-collapse">
                <thead class="ui-table-head">
                  <tr>
                    <th class="py-1.5 px-2.5">卷 / 镜像目标</th>
                    <th class="py-1.5 px-2.5">物理字节偏移</th>
                    <th class="py-1.5 px-2.5">命中标密关键词</th>
                    <th class="py-1.5 px-2.5">残片文本脱敏窗口</th>
                  </tr>
                </thead>
                <tbody class="divide-y" style="border-color: var(--border-subtle);">
                  <tr v-for="(s, idx) in ole2Report.slack_hits" :key="idx">
                    <td class="py-1.5 px-2.5 font-mono">{{ s.drive_letter }}</td>
                    <td class="py-1.5 px-2.5 font-mono">0x{{ s.sector_offset.toString(16).toUpperCase() }}</td>
                    <td class="py-1.5 px-2.5 font-semibold text-rose-600 dark:text-rose-400">{{ s.matched_marker }}</td>
                    <td class="py-1.5 px-2.5 text-[11px]">{{ s.snippet_preview }}</td>
                  </tr>
                </tbody>
              </table>
              <div v-if="ole2Report.ole2_hits.length === 0 && ole2Report.slack_hits.length === 0" class="p-6 text-center text-xs text-emerald-600 dark:text-emerald-400">
                目录 {{ ole2Report.target_folder }} 内 OLE2 二进制流及对应扇区检索未命中法定涉密标密词。
              </div>
            </template>
            <div v-else class="p-8 text-center text-xs" style="color: var(--text-muted);">填写复合文档扫描目录（与可选残片路径）后点击“扫描 DOC/XLS 与残片”。</div>
          </div>
        </div>

        <!-- 子视图 7: OS 操作痕迹 (.lnk / Spooler .SHD / 开关机时间线) -->
        <div v-else-if="secrecySubView === 'osusage'" class="flex-1 border rounded-xl overflow-hidden flex flex-col min-h-0" style="border-color: var(--border-subtle); background: var(--surface-content-alt);">
          <div class="p-2.5 border-b flex items-center justify-between text-xs shrink-0" style="border-color: var(--border-subtle);">
            <div class="flex items-center gap-2">
              <span class="font-semibold" style="color: var(--text-primary);">OS 快捷方式 (.lnk)、Spooler 打印影子及开关机事件时间线</span>
              <span v-if="osUsageReport" class="text-[11px] ui-num" style="color: var(--text-muted);">
                快捷方式 {{ osUsageReport.total_lnk_parsed }} 条 · 打印作业 {{ osUsageReport.print_spooler_jobs.length }} 项 · 开关机事件 {{ osUsageReport.system_boot_history.length }} 条
              </span>
            </div>
            <button @click="runOsUsageAudit" :disabled="isAuditingOsUsage" class="ui-btn-secondary px-2.5 py-1 text-[11px]">重新提取</button>
          </div>
          <div class="flex-1 overflow-auto custom-scrollbar p-2.5 space-y-3">
            <template v-if="osUsageReport">
              <div v-if="osUsageReport.degrade_notes.length > 0" class="p-2 rounded-lg bg-amber-500/10 border border-amber-500/25 text-[11px] text-amber-800 dark:text-amber-300">
                <b>提示与降级记录：</b>{{ osUsageReport.degrade_notes.join('；') }}
              </div>
              <div v-if="osUsageReport.system_boot_history.length > 0" class="p-2 rounded-lg border text-[11px] font-mono space-y-0.5 max-h-28 overflow-auto custom-scrollbar" style="border-color: var(--border-subtle);">
                <div class="font-semibold font-sans mb-1" style="color: var(--text-primary);">最近系统开关机审计时间线：</div>
                <div v-for="(b, idx) in osUsageReport.system_boot_history.slice(0, 15)" :key="idx" style="color: var(--text-secondary);">{{ b }}</div>
              </div>
              <table v-if="osUsageReport.recent_files.length > 0" class="w-full text-left text-xs border-collapse">
                <thead class="ui-table-head sticky top-0">
                  <tr>
                    <th class="py-1.5 px-2.5">快捷方式名</th>
                    <th class="py-1.5 px-2.5">MS-SHLLINK 真实目标路径</th>
                    <th class="py-1.5 px-2.5">介质类型</th>
                    <th class="py-1.5 px-2.5">末次访问时间</th>
                    <th class="py-1.5 px-2.5 text-center">风险标签</th>
                  </tr>
                </thead>
                <tbody class="divide-y" style="border-color: var(--border-subtle);">
                  <tr v-for="(f, idx) in osUsageReport.recent_files" :key="idx" class="hover:bg-[var(--surface-hover)]">
                    <td class="py-1.5 px-2.5 font-semibold">{{ f.shortcut_name }}</td>
                    <td class="py-1.5 px-2.5 font-mono text-[11px] break-all">{{ f.target_real_path }}</td>
                    <td class="py-1.5 px-2.5">{{ f.drive_type }}</td>
                    <td class="py-1.5 px-2.5 ui-num">{{ f.target_last_access_time }}</td>
                    <td class="py-1.5 px-2.5 text-center space-x-1">
                      <span v-if="f.is_removable_media_target" class="px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-700 dark:text-amber-300 text-[10px] font-semibold">可移动盘</span>
                      <span v-if="f.is_secrecy_named" class="px-1.5 py-0.5 rounded bg-rose-600 text-white text-[10px] font-semibold">涉密命名</span>
                      <span v-if="!f.is_removable_media_target && !f.is_secrecy_named" class="ui-pill text-[10px]">本地常规</span>
                    </td>
                  </tr>
                </tbody>
              </table>
              <table v-if="osUsageReport.print_spooler_jobs.length > 0" class="w-full text-left text-xs border-collapse">
                <thead class="ui-table-head">
                  <tr>
                    <th class="py-1.5 px-2.5">作业号</th>
                    <th class="py-1.5 px-2.5">打印文档标题</th>
                    <th class="py-1.5 px-2.5">打印机队列</th>
                    <th class="py-1.5 px-2.5">提交时间</th>
                    <th class="py-1.5 px-2.5 text-center">判定</th>
                  </tr>
                </thead>
                <tbody class="divide-y" style="border-color: var(--border-subtle);">
                  <tr v-for="(j, idx) in osUsageReport.print_spooler_jobs" :key="idx">
                    <td class="py-1.5 px-2.5 font-mono">{{ j.job_id }}</td>
                    <td class="py-1.5 px-2.5 font-semibold">{{ j.document_name }}</td>
                    <td class="py-1.5 px-2.5">{{ j.printer_name }}</td>
                    <td class="py-1.5 px-2.5 ui-num">{{ j.submit_time }}</td>
                    <td class="py-1.5 px-2.5 text-center">
                      <span class="px-1.5 py-0.5 rounded text-[10px] font-semibold" :class="j.is_secrecy_suspicious ? 'bg-rose-600 text-white' : 'ui-pill'">
                        {{ j.is_secrecy_suspicious ? '涉密嫌疑' : '常规打印' }}
                      </span>
                    </td>
                  </tr>
                </tbody>
              </table>
            </template>
            <div v-else class="p-8 text-center text-xs" style="color: var(--text-muted);">点击上方“提取操作与打印痕迹”解析系统 Recent 快捷方式、Spooler 与事件日志。</div>
          </div>
        </div>

        <!-- 子视图 8: 浏览器下载 SQLite 与即时通信外发轨迹明细 -->
        <div v-else-if="secrecySubView === 'apptrace'" class="flex-1 border rounded-xl overflow-hidden flex flex-col min-h-0" style="border-color: var(--border-subtle); background: var(--surface-content-alt);">
          <div class="p-2.5 border-b flex items-center justify-between text-xs shrink-0" style="border-color: var(--border-subtle);">
            <div class="flex items-center gap-2">
              <span class="font-semibold" style="color: var(--text-primary);">浏览器下载 SQLite3 历史与微信/企业微信/钉钉传输目录审计</span>
              <span v-if="appTraceReport" class="text-[11px] ui-num" style="color: var(--text-muted);">
                下载记录 {{ appTraceReport.total_downloads_checked }} 条 (可疑 {{ appTraceReport.suspicious_downloads.length }}) · IM 文件 {{ appTraceReport.chat_files_checked }} 份 (命中 {{ appTraceReport.chat_file_hits.length }})
              </span>
            </div>
            <button @click="runAppTracesAudit" :disabled="isAuditingAppTraces" class="ui-btn-secondary px-2.5 py-1 text-[11px]">重新审计</button>
          </div>
          <div class="flex-1 overflow-auto custom-scrollbar p-2.5 space-y-3">
            <template v-if="appTraceReport">
              <div v-if="appTraceReport.degrade_notes.length > 0" class="p-2 rounded-lg bg-amber-500/10 border border-amber-500/25 text-[11px] text-amber-800 dark:text-amber-300">
                <b>库锁与降级说明：</b>{{ appTraceReport.degrade_notes.join('；') }}
              </div>
              <table v-if="appTraceReport.suspicious_downloads.length > 0 || appTraceReport.recent_downloads_sample.length > 0" class="w-full text-left text-xs border-collapse">
                <thead class="ui-table-head sticky top-0">
                  <tr>
                    <th class="py-1.5 px-2.5">浏览器</th>
                    <th class="py-1.5 px-2.5">落盘目标路径</th>
                    <th class="py-1.5 px-2.5">下载来源 URL</th>
                    <th class="py-1.5 px-2.5">下载时间</th>
                    <th class="py-1.5 px-2.5 text-center">命中标识</th>
                  </tr>
                </thead>
                <tbody class="divide-y" style="border-color: var(--border-subtle);">
                  <tr v-for="(d, idx) in [...appTraceReport.suspicious_downloads, ...appTraceReport.recent_downloads_sample]" :key="idx" class="hover:bg-[var(--surface-hover)]">
                    <td class="py-1.5 px-2.5 font-semibold">{{ d.browser_type }}</td>
                    <td class="py-1.5 px-2.5 font-mono text-[11px] break-all">{{ d.target_file_path }}</td>
                    <td class="py-1.5 px-2.5 font-mono text-[11px] max-w-xs truncate" :title="d.original_url">{{ d.original_url }}</td>
                    <td class="py-1.5 px-2.5 ui-num whitespace-nowrap">{{ d.download_time }}</td>
                    <td class="py-1.5 px-2.5 text-center">
                      <span class="px-1.5 py-0.5 rounded text-[10px] font-semibold" :class="d.is_suspicious_secrecy ? 'bg-rose-600 text-white' : 'ui-pill'">
                        {{ d.is_suspicious_secrecy ? (d.matched_marker || '涉密命中') : '常规样本' }}
                      </span>
                    </td>
                  </tr>
                </tbody>
              </table>
              <table v-if="appTraceReport.chat_file_hits.length > 0" class="w-full text-left text-xs border-collapse">
                <thead class="ui-table-head">
                  <tr>
                    <th class="py-1.5 px-2.5">通信软件</th>
                    <th class="py-1.5 px-2.5">传输文件名</th>
                    <th class="py-1.5 px-2.5">物理路径</th>
                    <th class="py-1.5 px-2.5 text-right">字节数</th>
                    <th class="py-1.5 px-2.5 text-center">涉密关键字</th>
                  </tr>
                </thead>
                <tbody class="divide-y" style="border-color: var(--border-subtle);">
                  <tr v-for="(c, idx) in appTraceReport.chat_file_hits" :key="idx">
                    <td class="py-1.5 px-2.5 font-semibold">{{ c.app_name }}</td>
                    <td class="py-1.5 px-2.5 font-semibold text-rose-600 dark:text-rose-400">{{ c.file_name }}</td>
                    <td class="py-1.5 px-2.5 font-mono text-[11px] break-all">{{ c.file_path }}</td>
                    <td class="py-1.5 px-2.5 text-right ui-num">{{ c.file_size }}</td>
                    <td class="py-1.5 px-2.5 text-center"><span class="px-1.5 py-0.5 rounded bg-rose-600 text-white text-[10px] font-semibold">{{ c.hit_secrecy_marker || '命中' }}</span></td>
                  </tr>
                </tbody>
              </table>
              <div v-if="appTraceReport.suspicious_downloads.length === 0 && appTraceReport.recent_downloads_sample.length === 0 && appTraceReport.chat_file_hits.length === 0" class="p-6 text-center text-xs text-emerald-600 dark:text-emerald-400">
                已查验全部可读浏览器 SQLite 下载库及即时通信缓存目录，未检出含涉密关键词记录。
              </div>
            </template>
            <div v-else class="p-8 text-center text-xs" style="color: var(--text-muted);">点击上方“审计浏览器与聊天传输”进行纯 Rust SQLite3 B-Tree 及通信文件扫描。</div>
          </div>
        </div>
      </div>

      <!-- ======================================================== -->
      <!-- TAB 4: 数据脱敏清洗审查 -->
      <!-- ======================================================== -->
      <div v-else-if="activeTab === 'sanitizer'" class="flex-1 overflow-hidden flex flex-col gap-2.5 min-h-0">
        <div class="ui-sub-card flex items-center justify-between gap-3 p-2.5 shrink-0 flex-wrap">
          <div class="flex items-center gap-2">
            <span class="text-xs font-semibold" style="color: var(--text-primary);">脱敏标准策略:</span>
            <select v-model="selectedPolicyId" class="ui-input px-2.5 py-1 text-xs">
              <option v-for="p in sanitizationPolicies" :key="p.policy_id" :value="p.policy_id">
                {{ p.name }} ({{ p.policy_id }})
              </option>
            </select>
          </div>

          <div class="flex items-center gap-2">
            <span class="text-xs font-semibold" style="color: var(--text-primary);">确定性散列加盐 (Salt):</span>
            <input v-model="hmacSalt" placeholder="默认工业主盐值..." class="ui-input px-2 py-1 font-mono text-xs w-48" />
          </div>

          <button @click="executeSanitization" :disabled="!rawSanitizeText.trim() || isSanitizing" class="ui-btn-primary bg-emerald-600 hover:bg-emerald-500 px-3.5 py-1.5 text-xs">
            {{ isSanitizing ? '清洗脱敏中...' : '执行工业级脱敏清洗' }}
          </button>
        </div>

        <div class="flex-1 grid grid-cols-1 lg:grid-cols-2 gap-3 overflow-hidden min-h-0">
          <div class="ui-sub-card flex flex-col p-2.5 min-h-0">
            <div class="flex items-center justify-between pb-1.5 mb-1.5 border-b shrink-0" style="border-color: var(--border-subtle);">
              <span class="text-xs font-semibold" style="color: var(--text-primary);">清洗前原始待脱敏文本:</span>
              <button @click="fillSampleText" class="text-[11px] text-blue-600 dark:text-sky-400 hover:underline cursor-pointer font-semibold">
                载入涉密与 PII 综合检材用例
              </button>
            </div>
            <textarea
              v-model="rawSanitizeText"
              placeholder="在此粘贴包含居民身份证、银行卡、手机号、私钥、涉密公文发文等待脱敏清洗内容..."
              class="ui-input flex-1 w-full p-2.5 font-mono text-xs resize-none custom-scrollbar"
            ></textarea>
          </div>

          <div class="ui-sub-card flex flex-col p-2.5 min-h-0">
            <div class="flex items-center justify-between pb-1.5 mb-1.5 border-b shrink-0 gap-2" style="border-color: var(--border-subtle);">
              <span class="text-xs font-semibold" style="color: var(--text-primary);">清洗后脱敏成果 (已处理 {{ sanitizeResult?.matched_replacements_count || 0 }} 处):</span>
              <div v-if="sanitizeResult" class="flex items-center gap-2">
                <button @click="compareSanitizationBeforeAfter" class="px-2 py-0.5 rounded bg-indigo-500/12 hover:bg-indigo-500/20 text-indigo-700 dark:text-indigo-300 border border-indigo-500/25 text-[11px] font-semibold cursor-pointer">
                  对比脱敏前后差异
                </button>
                <button @click="copyToClipboard(sanitizeResult.sanitized_content)" class="text-[11px] text-emerald-600 dark:text-emerald-400 hover:underline cursor-pointer font-semibold">
                  复制脱敏文本
                </button>
              </div>
            </div>
            <textarea
              readonly
              :value="sanitizeResult?.sanitized_content || ''"
              placeholder="脱敏清洗成果将实时在此输出..."
              class="ui-input flex-1 w-full p-2.5 font-mono text-xs resize-none custom-scrollbar"
            ></textarea>
          </div>
        </div>

        <!-- 底栏：脱敏合规审查闭环验证卡片 -->
        <div class="p-3 bg-indigo-500/8 border border-indigo-500/25 rounded-xl flex items-center justify-between shrink-0 flex-wrap gap-3">
          <div class="space-y-1">
            <div class="flex items-center gap-2">
              <span class="w-2 h-2 rounded-full bg-emerald-500"></span>
              <span class="text-xs font-semibold" style="color: var(--text-primary);">闭环合规验证器 (Sanitization Verifier)</span>
              <span class="text-[11px] px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 font-semibold">零敏感残余逆向复验</span>
            </div>
            <p class="text-[11px]" style="color: var(--text-secondary);">
              将清洗后成果自动回灌至数据安全与保密审查引擎进行二次反向探查，当且仅当敏感残余为 0 时出具防篡改审计凭单。
            </p>
          </div>

          <button @click="verifyComplianceProof" :disabled="!sanitizeResult || isVerifying" class="ui-btn-primary bg-emerald-600 hover:bg-emerald-500 px-3.5 py-1.5 text-xs">
            {{ isVerifying ? '执行逆向复测中...' : '执行闭环合规验证' }}
          </button>
        </div>

        <div v-if="auditProof" class="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-xl flex items-center justify-between shrink-0 flex-wrap gap-3">
          <div class="flex items-center gap-3">
            <div class="w-8 h-8 rounded-xl bg-emerald-600 text-white flex items-center justify-center shrink-0">
              <AppIcon name="check" :size="16" />
            </div>
            <div>
              <div class="text-xs font-semibold flex items-center gap-2" style="color: var(--text-primary);">
                <span>{{ auditProof.verdict }}</span>
                <span class="text-[11px] ui-num text-emerald-700 dark:text-emerald-300 bg-emerald-500/15 px-1.5 py-0.5 rounded">
                  凭单 #{{ auditProof.proof_id }}
                </span>
              </div>
              <div class="text-[11px] font-mono mt-0.5" style="color: var(--text-secondary);">
                原始哈希: {{ auditProof.original_sha256.substring(0, 16) }}... → 脱敏后哈希: {{ auditProof.sanitized_sha256.substring(0, 16) }}...
              </div>
            </div>
          </div>
          <div class="text-right text-[11px] ui-num text-emerald-700 dark:text-emerald-300">
            <div>核验时间: {{ auditProof.verified_at }}</div>
            <div class="font-semibold mt-0.5">残余敏感特征: {{ auditProof.residual_sensitive_hits }} 处 (完全合规)</div>
          </div>
        </div>
      </div>

      <!-- ======================================================== -->
      <!-- TAB 5: Suricata / Glushkov / 沙箱脚本 -->
      <!-- ======================================================== -->
      <div v-else-if="activeTab === 'engines'" class="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-3 overflow-hidden min-h-0 text-xs">
        <div class="lg:col-span-4 flex flex-col gap-2 ui-sub-card p-3 overflow-hidden min-h-0">
          <div class="flex items-center justify-between">
            <span class="font-semibold text-blue-600 dark:text-sky-300">Suricata DSL 两阶段引擎</span>
            <div class="flex items-center gap-1">
              <button @click="reloadSuricataFromDisk" class="ui-btn-secondary px-2 py-0.5 text-[11px]" title="从本地 data/suricata_rules.rules 重新热载">
                <AppIcon name="refresh" :size="11" />
                <span>磁盘热重载</span>
              </button>
              <button @click="loadSuricataFileTextToEditor" class="ui-btn-secondary px-2 py-0.5 text-[11px]" title="读取本地持久化规则全文至编辑器">
                <span>载入全文</span>
              </button>
            </div>
          </div>
          <!-- 规则分类库按需热切换器与官方同步 -->
          <div class="flex flex-col gap-1.5 p-2 rounded-lg border bg-[var(--surface-content)]" style="border-color: var(--border-subtle);">
            <div class="flex items-center justify-between text-[11px]">
              <span class="font-semibold text-[var(--text-secondary)]">探针绑定的规则库:</span>
              <button
                @click="handleSyncRules()"
                :disabled="isSyncingRules"
                class="ui-btn-secondary px-2 py-0.5 text-[10px] text-amber-700 dark:text-amber-300 border-amber-500/30 flex items-center gap-1"
                title="在线从官方 Emerging Threats 规则源拉取全量 5.2 万条规则并构建 CVE 聚合库"
              >
                <AppIcon name="refresh" :size="10" />
                <span>{{ isSyncingRules ? '正在在线拉取...' : '官方全量源同步' }}</span>
              </button>
            </div>
            <select
              v-model="selectedRuleFileName"
              @change="handleSwitchRuleFile(selectedRuleFileName)"
              class="ui-input w-full py-1 px-2 text-[11px] font-sans rounded bg-[var(--surface-input)]"
            >
              <option v-for="rf in availableRuleFiles" :key="rf.file_name" :value="rf.file_name">
                {{ rf.display_name }} {{ rf.is_active ? '● [当前运行]' : '' }}
              </option>
            </select>
            <div class="flex items-center justify-between text-[10px]" style="color: var(--text-muted);">
              <span class="truncate max-w-[200px]" :title="suricataFileInfo?.file_path">文件: {{ suricataFileInfo?.file_path?.split(/[\\/]/).pop() || 'suricata_rules.rules' }}</span>
              <span class="font-mono">{{ formatBytes(suricataFileInfo?.file_size_bytes || 0) }} · {{ suricataMetrics?.total_rules ?? 0 }} 条规则</span>
            </div>
          </div>
          <div class="grid grid-cols-3 gap-1.5 text-[11px]">
            <div class="p-2 rounded-lg border" style="background: var(--surface-content); border-color: var(--border-subtle);">
              <div style="color: var(--text-muted);">已编规则</div>
              <div class="font-semibold ui-num text-sm" style="color: var(--text-primary);">{{ suricataMetrics?.total_rules ?? 0 }}</div>
            </div>
            <div class="p-2 rounded-lg border" style="background: var(--surface-content); border-color: var(--border-subtle);">
              <div style="color: var(--text-muted);">扫过载荷</div>
              <div class="font-semibold ui-num text-sm" style="color: var(--text-primary);">{{ suricataMetrics?.total_packets_scanned ?? 0 }}</div>
            </div>
            <div class="p-2 rounded-lg border" style="background: var(--surface-content); border-color: var(--border-subtle);">
              <div style="color: var(--text-muted);">告警命中</div>
              <div class="font-semibold ui-num text-rose-600 dark:text-rose-400 text-sm">{{ suricataMetrics?.total_hits ?? 0 }}</div>
            </div>
          </div>
          <textarea
            v-model="suricataRuleInput"
            rows="3"
            placeholder='追加或编辑 DSL 规则: alert tcp any any -> any 502 (msg:"Custom Modbus Alert"; content:"|00 00|"; sid:900901; rev:1;)'
            class="ui-input w-full p-2 font-mono text-[11px] resize-none"
          ></textarea>
          <div class="grid grid-cols-2 gap-1.5">
            <button @click="loadCustomSuricataRules" :disabled="!suricataRuleInput.trim()" class="ui-btn-primary py-1.5 text-xs justify-center">
              内存热编译
            </button>
            <button @click="saveSuricataRulesToDisk" :disabled="!suricataRuleInput.trim()" class="ui-btn-secondary border-emerald-500/40 text-emerald-700 dark:text-emerald-300 hover:bg-emerald-500/10 py-1.5 text-xs justify-center">
              落盘并应用
            </button>
          </div>
          <div class="flex-1 overflow-y-auto custom-scrollbar space-y-1 text-[11px]">
            <div v-if="(suricataMetrics?.recent_hits?.length ?? 0) === 0" class="text-center py-4" style="color: var(--text-muted);">
              暂无实时 Suricata 规则告警命中
            </div>
            <div v-for="(h, i) in suricataMetrics?.recent_hits || []" :key="i" class="p-2 rounded bg-rose-500/12 border border-rose-500/25 text-rose-700 dark:text-rose-200">
              <div class="font-semibold">[SID:{{ h.signature_id }}] {{ h.name }}</div>
              <div class="truncate opacity-80">{{ h.description }}</div>
            </div>
          </div>
        </div>

        <div class="lg:col-span-4 flex flex-col gap-2 ui-sub-card p-3 overflow-hidden min-h-0">
          <div class="flex items-center justify-between">
            <span class="font-semibold text-indigo-600 dark:text-indigo-300">Glushkov 位并行正则自动机</span>
            <button @click="resetGlushkovMetrics" class="ui-btn-secondary px-2 py-0.5 text-[11px]">计数清零</button>
          </div>
          <div class="grid grid-cols-2 gap-1.5 text-[11px]">
            <div class="p-2 rounded-lg border" style="background: var(--surface-content); border-color: var(--border-subtle);">
              <div style="color: var(--text-muted);">预置工业正则规则</div>
              <div class="font-semibold ui-num text-indigo-600 dark:text-indigo-300 text-sm">{{ glushkovMetrics?.compiled_rules_count ?? 0 }} 条</div>
            </div>
            <div class="p-2 rounded-lg border" style="background: var(--surface-content); border-color: var(--border-subtle);">
              <div style="color: var(--text-muted);">累计扫包 / 威胁命中</div>
              <div class="font-semibold ui-num text-sm" style="color: var(--text-primary);">{{ glushkovMetrics?.total_scanned_packets ?? 0 }} / <span class="text-amber-600 dark:text-amber-300">{{ glushkovMetrics?.total_threat_hits ?? 0 }}</span></div>
            </div>
          </div>
          <textarea
            v-model="glushkovTestHex"
            rows="3"
            placeholder="输入十六进制载荷验证位并行自动机即时扫描 (如 247b6a6e64693a6c646170)"
            class="ui-input w-full p-2 font-mono text-[11px] resize-none"
          ></textarea>
          <button @click="runGlushkovScan" :disabled="!glushkovTestHex.trim()" class="ui-btn-primary bg-indigo-600 hover:bg-indigo-500 w-full py-1.5 text-xs justify-center">
            执行 Glushkov 自动机扫描
          </button>
          <div class="flex-1 overflow-y-auto custom-scrollbar space-y-1 text-[11px]">
            <div v-if="glushkovScanMatches.length === 0" class="text-center py-4" style="color: var(--text-muted);">
              等待手工验证载荷或抓包自动命中结果
            </div>
            <div v-for="(m, i) in glushkovScanMatches" :key="i" class="p-2 rounded bg-indigo-500/12 border border-indigo-500/25 text-indigo-700 dark:text-indigo-200">
              <div class="font-semibold">#{{ m.rule_id }} · {{ m.rule_name }} ({{ m.threat_class }})</div>
              <div class="opacity-80 ui-num">结束偏移: {{ m.match_end_offset }} | Snippet: {{ m.snippet }}</div>
            </div>
          </div>
        </div>

        <div class="lg:col-span-4 flex flex-col gap-2 ui-sub-card p-3 overflow-hidden min-h-0">
          <div class="flex items-center justify-between">
            <span class="font-semibold text-emerald-600 dark:text-emerald-300">沙箱安全分析脚本虚拟机</span>
            <span class="text-[11px] ui-num" style="color: var(--text-muted);">Gas限额:10,000 | 内存:256KB</span>
          </div>
          <textarea
            v-model="auditScriptSource"
            rows="5"
            placeholder='编写检测脚本: event on_packet(pkt) { let p = pkt["payload"]; if (pkt["len"]>=8 && extract_u8(p,7)==5) { alert("Write Coil", "HIGH", "ICS"); return true; } return false; }'
            class="ui-input w-full p-2 font-mono text-[11px] resize-none text-emerald-700 dark:text-emerald-300"
          ></textarea>
          <input
            v-model="auditScriptHex"
            placeholder="传入样本报文十六进制载荷 (如 00010000000601050000ff00)..."
            class="ui-input w-full px-2.5 py-1.5 font-mono text-[11px]"
          />
          <button @click="runAuditScript" :disabled="!auditScriptSource.trim()" class="ui-btn-primary bg-emerald-600 hover:bg-emerald-500 w-full py-1.5 text-xs justify-center">
            在隔离沙箱中执行脚本
          </button>
          <div v-if="auditScriptResult" class="flex-1 overflow-y-auto custom-scrollbar p-2.5 rounded-lg border text-[11px] font-mono space-y-1" style="background: var(--surface-input); border-color: var(--border-subtle); color: var(--text-primary);">
            <div>事件加载: <b class="text-emerald-600 dark:text-emerald-300">{{ auditScriptResult.events_loaded }}</b> | 返回值: <b class="text-blue-600 dark:text-sky-300">{{ auditScriptResult.return_value }}</b></div>
            <div v-if="auditScriptResult.alerts.length > 0" class="text-rose-600 dark:text-rose-400 font-semibold">产生告警 ({{ auditScriptResult.alerts.length }}): {{ auditScriptResult.alerts.map((a) => a.name).join(', ') }}</div>
            <div v-for="(l, idx) in auditScriptResult.logs" :key="idx" style="color: var(--text-secondary);">&gt; {{ l }}</div>
          </div>
        </div>
      </div>
    </div>

    <!-- 2.9 规则库资产全景健康度与自动更新勘验模态框 -->
    <div v-if="isRuleAssetsModalOpen" class="ui-modal-backdrop fixed inset-0 z-50 flex items-center justify-center p-4">
      <div class="ui-modal-surface rounded-2xl w-full max-w-4xl flex flex-col max-h-[90vh] overflow-hidden select-text">
        <div class="px-4 py-3 border-b flex items-center justify-between" style="border-color: var(--border-subtle);">
          <div class="flex items-center gap-2">
            <div class="w-7 h-7 rounded-lg bg-[var(--accent-primary-soft)] text-[var(--accent-primary-text)] flex items-center justify-center">
              <AppIcon name="shield" :size="15" />
            </div>
            <div>
              <h3 class="text-[13px] font-semibold" style="color: var(--text-primary);">全系统离线规则库资产健康自检与更新中枢</h3>
              <p class="text-[10px]" style="color: var(--text-muted);">
                监测工业核心基线、全量 CVE 漏洞聚合库、ET Open 54 分类离线库、国家秘密法公文规约与 GB/T 43697 数据凭证
              </p>
            </div>
          </div>
          <button @click="isRuleAssetsModalOpen = false" class="p-1 rounded-lg hover:bg-[var(--surface-hover)] cursor-pointer" style="color: var(--text-secondary);">
            <AppIcon name="close" :size="14" />
          </button>
        </div>

        <div class="p-4 flex-1 overflow-auto custom-scrollbar space-y-3 text-xs" style="background: var(--surface-content-alt);">
          <!-- 规则引擎智能感知与解压状态决策看板 -->
          <div
            v-if="ruleAssetsHealth?.smart_status"
            class="ui-sub-card p-3 space-y-2.5 border"
            :class="ruleAssetsHealth.smart_status.status_code === 'UP_TO_DATE'
              ? 'border-emerald-500/30 bg-emerald-500/5'
              : (ruleAssetsHealth.smart_status.status_code === 'UPDATE_AVAILABLE'
                ? 'border-sky-500/30 bg-sky-500/5'
                : 'border-amber-500/30 bg-amber-500/5')"
          >
            <div class="flex items-center justify-between flex-wrap gap-2">
              <div class="flex items-center gap-2">
                <span
                  class="w-2.5 h-2.5 rounded-full"
                  :class="ruleAssetsHealth.smart_status.status_code === 'UP_TO_DATE'
                    ? 'bg-emerald-500'
                    : (ruleAssetsHealth.smart_status.status_code === 'UPDATE_AVAILABLE'
                      ? 'bg-sky-500'
                      : 'bg-amber-500 animate-pulse')"
                ></span>
                <span class="font-bold text-xs" style="color: var(--text-primary);">
                  系统智能感知与决策：{{ ruleAssetsHealth.smart_status.status_title }}
                </span>
                <span
                  class="px-2 py-0.5 rounded text-[10px] font-semibold"
                  :class="ruleAssetsHealth.smart_status.status_code === 'UP_TO_DATE'
                    ? 'bg-emerald-500/20 text-emerald-800 dark:text-emerald-300'
                    : (ruleAssetsHealth.smart_status.status_code === 'UPDATE_AVAILABLE'
                      ? 'bg-sky-500/20 text-sky-800 dark:text-sky-300'
                      : 'bg-amber-500/20 text-amber-800 dark:text-amber-300')"
                >
                  {{ ruleAssetsHealth.smart_status.status_code }}
                </span>
              </div>
              <button
                v-if="ruleAssetsHealth.smart_status.can_execute"
                @click="handleSmartSyncArchive()"
                :disabled="isSmartSyncing"
                class="ui-btn-primary px-3 py-1 text-xs flex items-center gap-1.5 shadow-xs font-semibold"
                :class="ruleAssetsHealth.smart_status.status_code === 'UPDATE_AVAILABLE'
                  ? 'bg-sky-600 hover:bg-sky-500'
                  : (ruleAssetsHealth.smart_status.status_code === 'UP_TO_DATE'
                    ? 'bg-emerald-600 hover:bg-emerald-500'
                    : 'bg-amber-600 hover:bg-amber-500')"
              >
                <AppIcon :name="ruleAssetsHealth.smart_status.status_code === 'UPDATE_AVAILABLE' ? 'refresh' : 'shield'" :size="12" />
                <span>{{ isSmartSyncing ? '正在智能执行中...' : (ruleAssetsHealth.smart_status.status_code === 'UP_TO_DATE' ? '强制重新构建' : '⚡ 立即智能同步并生效') }}</span>
              </button>
            </div>

            <!-- 本地源与已展开库左右比对矩阵 -->
            <div class="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px]">
              <div class="p-2.5 rounded-lg border bg-[var(--surface-content)]" style="border-color: var(--border-subtle);">
                <div class="font-semibold text-[11px] flex items-center justify-between" style="color: var(--text-secondary);">
                  <span>📦 本地离线安装包源 (.tar.gz)</span>
                  <span class="font-mono" :class="ruleAssetsHealth.smart_status.archive_exists ? 'text-emerald-600 dark:text-emerald-400' : 'text-amber-600 dark:text-amber-400'">
                    {{ ruleAssetsHealth.smart_status.archive_exists ? '已检测到' : '未检测到' }}
                  </span>
                </div>
                <div class="mt-1 space-y-0.5" style="color: var(--text-muted);">
                  <div>文件路径: <span class="font-mono select-all text-[10px]" style="color: var(--text-secondary);">{{ ruleAssetsHealth.smart_status.archive_path || 'data/emerging.rules.tar.gz (未放置)' }}</span></div>
                  <div>文件体积: <span class="ui-num font-mono" style="color: var(--text-primary);">{{ formatBytes(ruleAssetsHealth.smart_status.archive_size_bytes) }}</span></div>
                  <div>文件修改时间: <span class="font-mono" style="color: var(--text-primary);">{{ ruleAssetsHealth.smart_status.archive_mtime_str }}</span></div>
                </div>
              </div>

              <div class="p-2.5 rounded-lg border bg-[var(--surface-content)]" style="border-color: var(--border-subtle);">
                <div class="font-semibold text-[11px] flex items-center justify-between" style="color: var(--text-secondary);">
                  <span>📂 已展开规则库运行态 (data/rules/)</span>
                  <span class="font-mono" :class="ruleAssetsHealth.smart_status.cve_aggregated_exists ? 'text-emerald-600 dark:text-emerald-400' : 'text-amber-600 dark:text-amber-400'">
                    {{ ruleAssetsHealth.smart_status.extracted_files_count }} 个分类规则
                  </span>
                </div>
                <div class="mt-1 space-y-0.5" style="color: var(--text-muted);">
                  <div>CVE 聚合特征库: <span class="font-mono" :class="ruleAssetsHealth.smart_status.cve_aggregated_exists ? 'text-emerald-600 dark:text-emerald-400 font-semibold' : 'text-amber-600 dark:text-amber-400'">{{ ruleAssetsHealth.smart_status.cve_aggregated_exists ? '已生成 (6,264 条独立 CVE)' : '未生成' }}</span></div>
                  <div>展开库最新时间: <span class="font-mono" style="color: var(--text-primary);">{{ ruleAssetsHealth.smart_status.latest_extracted_mtime_str }}</span></div>
                  <div>当前调用模式: <span class="font-semibold text-emerald-700 dark:text-emerald-300">内存零开销就地直读 (无需重复解压)</span></div>
                </div>
              </div>
            </div>

            <!-- 业务原理解释与操作建议 -->
            <div class="p-2 rounded-lg bg-[var(--surface-input)] border text-[11px] leading-relaxed" style="border-color: var(--border-subtle);">
              <div class="font-semibold flex items-center gap-1.5" style="color: var(--text-primary);">
                <span>💡 架构设计答疑：在 /data 下有完整离线文件，调用时是否需要解压安装？</span>
              </div>
              <p class="mt-1" style="color: var(--text-secondary);">
                <b>回答：初次部署或检测到更新时需解压构建一次，日常运行零开销直接调用，无需重复解压！</b><br />
                Suricata 规则引擎在启动与数据包深度特征检测时，读取并就地解析的是纯文本规则（<code class="px-1 py-0.2 rounded bg-black/10 dark:bg-white/10 font-mono">.rules</code>）以构建硬件级 Aho-Corasick 多模模式树。因此，<code class="px-1 py-0.2 rounded bg-black/10 dark:bg-white/10 font-mono">.tar.gz</code> 压缩包仅作为离线交付与网络分发介质。当用户将规则包放入 <code class="px-1 py-0.2 rounded bg-black/10 dark:bg-white/10 font-mono">data/</code> 目录时，系统会自动感知并提示一键解包构建；构建完成后，日常调用零时延直读，无需重复解压，系统亦会持续智能比对文件时间戳，确保规则版本绝对受控。
              </p>
            </div>
          </div>

          <!-- 总体健康度卡片 -->
          <div class="grid grid-cols-2 md:grid-cols-4 gap-2">
            <div class="ui-sub-card p-2.5">
              <div class="text-[11px]" style="color: var(--text-muted);">离线规则资产项</div>
              <div class="text-base font-bold ui-num mt-0.5" style="color: var(--text-primary);">
                {{ ruleAssetsHealth?.ready_assets ?? 0 }} / {{ ruleAssetsHealth?.total_assets ?? 0 }} 项就绪
              </div>
            </div>
            <div class="ui-sub-card p-2.5">
              <div class="text-[11px]" style="color: var(--text-muted);">当前运行规则库</div>
              <div class="text-sm font-semibold truncate mt-0.5 text-blue-600 dark:text-sky-300" :title="ruleAssetsHealth?.active_library_name">
                {{ ruleAssetsHealth?.active_library_name ?? '基础基线' }}
              </div>
            </div>
            <div class="ui-sub-card p-2.5">
              <div class="text-[11px]" style="color: var(--text-muted);">活跃规则条数</div>
              <div class="text-base font-bold ui-num mt-0.5 text-emerald-600 dark:text-emerald-400">
                {{ (ruleAssetsHealth?.active_rule_count ?? 0).toLocaleString() }} 条
              </div>
            </div>
            <div class="ui-sub-card p-2.5">
              <div class="text-[11px]" style="color: var(--text-muted);">全网 CVE 覆盖</div>
              <div class="text-base font-bold ui-num mt-0.5 text-purple-600 dark:text-purple-300">
                {{ (ruleAssetsHealth?.active_cve_count ?? 0).toLocaleString() }} 处签名
              </div>
            </div>
          </div>

          <!-- 资产明细列表 -->
          <div class="ui-sub-card p-3 space-y-2">
            <div class="font-semibold text-xs flex items-center justify-between" style="color: var(--text-primary);">
              <span>五大离线规则库资产健康明细清单</span>
              <button @click="fetchRuleAssetsHealth" class="ui-btn-secondary px-2 py-0.5 text-[11px] flex items-center gap-1">
                <AppIcon name="refresh" :size="10" />
                <span>刷新自检状态</span>
              </button>
            </div>
            <div class="space-y-1.5">
              <div
                v-for="asset in ruleAssetsHealth?.assets || []"
                :key="asset.id"
                class="p-2.5 rounded-xl border flex items-center justify-between gap-3 flex-wrap"
                :class="asset.status === 'Active' ? 'bg-blue-500/10 border-blue-500/30' : (asset.status === 'Ready' ? 'bg-[var(--surface-content)] border-[var(--border-subtle)]' : 'bg-amber-500/10 border-amber-500/35')"
              >
                <div class="min-w-0 flex-1">
                  <div class="flex items-center gap-2 flex-wrap">
                    <span class="font-semibold text-xs" style="color: var(--text-primary);">{{ asset.name }}</span>
                    <span
                      class="px-1.5 py-0.5 rounded text-[10px] font-semibold"
                      :class="asset.status === 'Active' ? 'bg-blue-500/20 text-blue-700 dark:text-sky-300' : (asset.status === 'Ready' ? 'bg-emerald-500/20 text-emerald-700 dark:text-emerald-300' : 'bg-amber-500/20 text-amber-800 dark:text-amber-300')"
                    >
                      {{ asset.status === 'Active' ? '● 正在运行' : (asset.status === 'Ready' ? '就绪' : '缺失/待下载') }}
                    </span>
                    <span class="text-[10px] ui-num font-mono" style="color: var(--text-muted);">
                      {{ formatBytes(asset.file_size_bytes) }} · {{ asset.rule_count.toLocaleString() }} 规则 {{ asset.cve_count > 0 ? `(${asset.cve_count.toLocaleString()} CVE)` : '' }}
                    </span>
                  </div>
                  <div class="text-[11px] mt-0.5 font-mono truncate" style="color: var(--text-secondary);" :title="asset.file_path">
                    路径: {{ asset.file_path }}
                  </div>
                  <div class="text-[11px] mt-1" :class="asset.exists ? 'text-[var(--text-muted)]' : 'text-amber-700 dark:text-amber-300 font-medium'">
                    {{ asset.recommendation }}
                  </div>
                </div>

                <div class="flex items-center gap-1.5 shrink-0">
                  <button
                    v-if="asset.category === 'cve' || asset.category === 'suricata'"
                    @click="handleSwitchRuleFile(asset.file_path.split(/[\\/]/).pop() || '')"
                    :disabled="!asset.exists || asset.is_active"
                    class="ui-btn-secondary px-2.5 py-1 text-[11px]"
                  >
                    {{ asset.is_active ? '当前活跃' : '切换为此库' }}
                  </button>
                  <button
                    v-if="!asset.exists && asset.download_url"
                    @click="handleSyncRules()"
                    :disabled="isSyncingRules"
                    class="ui-btn-primary bg-amber-600 hover:bg-amber-500 px-2.5 py-1 text-[11px]"
                  >
                    立即下载
                  </button>
                </div>
              </div>
            </div>
          </div>

          <!-- 在线源与镜像配置 -->
          <div class="ui-sub-card p-3 space-y-2">
            <div class="font-semibold text-xs" style="color: var(--text-primary);">官方规则下载更新源配置</div>
            <div class="flex items-center gap-2 flex-wrap">
              <input
                v-model="customMirrorUrl"
                :placeholder="ruleAssetsHealth?.default_mirror_url || 'https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz'"
                class="ui-input flex-1 px-2.5 py-1.5 font-mono text-xs"
              />
              <button
                @click="handleSyncRules(customMirrorUrl)"
                :disabled="isSyncingRules"
                class="ui-btn-primary px-3 py-1.5 text-xs flex items-center gap-1.5 shrink-0"
              >
                <AppIcon name="download" :size="13" />
                <span>{{ isSyncingRules ? '正在在线拉取并构建 (5.2万条)...' : '全量同步并热重载' }}</span>
              </button>
            </div>
            <p class="text-[10px]" style="color: var(--text-muted);">
              说明: 留空时默认直连官方 Proofpoint ET Open 官方源。在涉密脱机隔离网或企业内网环境下，可配置内网 Nexus / 镜像 HTTP 地址一键同步。
            </p>
          </div>

          <!-- 脱网与隔离环境：手动导入本地规则安装包 (.tar.gz) -->
          <div class="ui-sub-card p-3 space-y-2.5 border-emerald-500/30 bg-emerald-500/5">
            <div class="flex items-center justify-between">
              <div class="font-semibold text-xs flex items-center gap-1.5" style="color: var(--text-primary);">
                <span class="w-2 h-2 rounded-full bg-emerald-500"></span>
                <span>脱网与涉密隔离网环境：手动导入本地规则安装包 (.tar.gz)</span>
              </div>
              <button
                @click="showOfflineManualHelp = !showOfflineManualHelp"
                class="ui-btn-secondary px-2 py-0.5 text-[11px] text-emerald-700 dark:text-emerald-300"
              >
                <span>{{ showOfflineManualHelp ? '收起离线说明' : '查看脱网部署说明' }}</span>
              </button>
            </div>

            <!-- 检测到本地已有包提示 -->
            <div
              v-if="ruleAssetsHealth?.local_archive_detected"
              class="p-2 rounded-lg bg-emerald-500/15 border border-emerald-500/35 flex items-center justify-between gap-2 text-xs flex-wrap"
            >
              <div class="text-[11px] text-emerald-800 dark:text-emerald-200">
                <span>已在本地检测到就绪包：</span>
                <b class="font-mono">{{ ruleAssetsHealth.local_archive_detected }}</b>
                <span class="ml-1 opacity-80">({{ formatBytes(ruleAssetsHealth.local_archive_size_bytes || 0) }})</span>
              </div>
              <button
                @click="handleExtractLocalArchive(ruleAssetsHealth.local_archive_detected)"
                :disabled="isExtractingLocal"
                class="ui-btn-primary bg-emerald-600 hover:bg-emerald-500 text-white px-3 py-1 text-xs shadow-xs"
              >
                <span>{{ isExtractingLocal ? '正在解压提取...' : '一键直接解压并热重载' }}</span>
              </button>
            </div>

            <!-- 手动选取或输入路径 -->
            <div class="flex items-center gap-2 flex-wrap">
              <button
                @click="handleBrowseLocalArchive"
                class="ui-btn-secondary px-3 py-1.5 text-xs flex items-center gap-1 shrink-0"
                title="打开 Windows 原生文件选择器选取本地 .tar.gz 规则包"
              >
                <AppIcon name="document" :size="13" />
                <span>选择本地文件...</span>
              </button>
              <input
                v-model="manualLocalArchivePath"
                placeholder="或直接在此输入/粘贴本地规则包绝对路径 (如 E:\rules\emerging.rules.tar.gz)..."
                class="ui-input flex-1 px-2.5 py-1.5 font-mono text-xs"
              />
              <button
                @click="handleExtractLocalArchive()"
                :disabled="isExtractingLocal || (!manualLocalArchivePath.trim() && !ruleAssetsHealth?.local_archive_detected)"
                class="ui-btn-primary bg-emerald-600 hover:bg-emerald-500 text-white px-3 py-1.5 text-xs flex items-center gap-1.5 shrink-0"
              >
                <AppIcon name="shield" :size="13" />
                <span>{{ isExtractingLocal ? '正在解压提取中...' : '解压并构建离线库' }}</span>
              </button>
            </div>

            <!-- 离线手动部署与解压实操指南 -->
            <div v-if="showOfflineManualHelp" class="p-3 rounded-xl border bg-[var(--surface-input)] space-y-2 text-[11px]" style="border-color: var(--border-subtle);">
              <div class="font-semibold text-emerald-700 dark:text-emerald-300">【脱网环境离线手动部署与规则加载使用说明】</div>
              <ol class="list-decimal list-inside space-y-1 leading-relaxed" style="color: var(--text-secondary);">
                <li>
                  <b style="color: var(--text-primary);">步骤 1（官方下载）</b>：在具备外网访问权限的主机上，直接在浏览器中下载官方全量规则归档包：<br />
                  <span class="font-mono text-blue-600 dark:text-sky-300 break-all select-all">https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz</span>
                  <span class="ml-1 opacity-75">(文件体积约 5.4MB，涵盖 54 个分类规则)</span>
                </li>
                <li>
                  <b style="color: var(--text-primary);">步骤 2（U盘拷入与放置）</b>：将下载好的 <code class="px-1 py-0.5 rounded bg-black/10 dark:bg-white/10 font-mono">emerging.rules.tar.gz</code> 通过合规 U 盘拷贝至内网目标机器：
                  <ul class="list-disc list-inside ml-4 mt-0.5 opacity-90">
                    <li>方式 A (推荐)：直接拷贝并放置在程序所在目录下的 <code class="px-1 py-0.5 rounded bg-black/10 dark:bg-white/10 font-mono">data/</code> 文件夹内（系统会自动检测并提示一键解压）；</li>
                    <li>方式 B：放置在任意本地目录（如桌面或移动硬盘），点击上方的【选择本地文件...】按钮浏览选取。</li>
                  </ul>
                </li>
                <li>
                  <b style="color: var(--text-primary);">步骤 3（点击解压构建）</b>：点击【解压并构建离线库】。系统内置的纯 Rust 流式解包引擎会自动将其解压为 54 个分类规则文件，并在解压完成后自动扫描提炼出包含全部 6,264 条 CVE 漏洞利用特征的专用库 <code class="px-1 py-0.5 rounded bg-black/10 dark:bg-white/10 font-mono">cve_all_signatures.rules</code>，无需外网亦无需安装解压软件。
                </li>
                <li>
                  <b style="color: var(--text-primary);">步骤 4（即时生效与按需切换）</b>：解压完成后探针引擎自动热重载生效。使用者还可在工作台下拉菜单中按需切换加载特定分类规则（如特定 Web 应用漏洞、工控 SCADA 威胁签名等）。
                </li>
              </ol>
            </div>
          </div>
        </div>

        <div class="px-4 py-2.5 border-t flex justify-end" style="border-color: var(--border-subtle);">
          <button @click="isRuleAssetsModalOpen = false" class="ui-btn-secondary px-3 py-1.5 text-xs">关闭</button>
        </div>
      </div>
    </div>

    <!-- 3. 全局 JSON 详情勘验弹窗 -->
    <div v-if="isDetailModalOpen" class="ui-modal-backdrop fixed inset-0 z-50 flex items-center justify-center p-4">
      <div class="ui-modal-surface rounded-2xl w-full max-w-2xl flex flex-col max-h-[85vh] overflow-hidden select-text">
        <div class="px-4 py-3 border-b flex items-center justify-between" style="border-color: var(--border-subtle);">
          <h3 class="text-[13px] font-semibold" style="color: var(--text-primary);">技术审查证据 JSON 详情</h3>
          <button @click="isDetailModalOpen = false" class="p-1 rounded-lg hover:bg-[var(--surface-hover)] cursor-pointer" style="color: var(--text-secondary);">
            <AppIcon name="close" :size="14" />
          </button>
        </div>
        <div class="p-3.5 flex-1 overflow-auto custom-scrollbar font-mono text-xs" style="background: var(--surface-input); color: var(--text-primary);">
          <pre class="text-emerald-700 dark:text-emerald-400">{{ formatJson(selectedDetailJson) }}</pre>
        </div>
        <div class="px-4 py-2.5 border-t flex justify-end" style="border-color: var(--border-subtle);">
          <button @click="isDetailModalOpen = false" class="ui-btn-secondary px-3 py-1.5 text-xs">关闭</button>
        </div>
      </div>
    </div>

    <!-- 4. 四维综合安全勘验技术报告模态框 -->
    <div v-if="isReportModalOpen" class="ui-modal-backdrop fixed inset-0 z-50 flex items-center justify-center p-4">
      <div class="ui-modal-surface rounded-2xl w-full max-w-4xl flex flex-col max-h-[90vh] overflow-hidden select-text">
        <div class="px-4 py-3 border-b flex items-center justify-between" style="border-color: var(--border-subtle);">
          <div class="flex items-center gap-2 flex-wrap">
            <span class="w-2.5 h-2.5 rounded-full bg-indigo-500"></span>
            <h3 class="text-sm font-semibold" style="color: var(--text-primary);">四维安全合规审查与脱敏清洗综合勘验技术报告</h3>
            <span class="text-[11px] text-indigo-700 dark:text-indigo-300 bg-indigo-500/15 px-2 py-0.5 rounded font-semibold">
              GB/T 22239 等保三级 · 工业级标准
            </span>
          </div>
          <button @click="isReportModalOpen = false" class="p-1 rounded-lg hover:bg-[var(--surface-hover)] cursor-pointer" style="color: var(--text-secondary);">
            <AppIcon name="close" :size="14" />
          </button>
        </div>

        <div class="p-4 flex-1 overflow-auto custom-scrollbar text-xs space-y-3" style="background: var(--surface-content-alt);">
          <div v-if="auditReport">
            <div class="ui-sub-card p-3 space-y-1.5">
              <div class="text-xs font-semibold ui-num" style="color: var(--text-primary);">【审查勘验证明编号】 {{ auditReport.report_id }}</div>
              <div class="text-[11px] ui-num" style="color: var(--text-muted);">出具时间: {{ auditReport.generated_at }} | 勘验主体: 网络探针合规审查核心引擎</div>
              <div class="mt-2 text-xs leading-relaxed bg-indigo-500/10 p-2.5 rounded-lg border border-indigo-500/20" style="color: var(--text-primary);">
                <span class="font-semibold text-indigo-700 dark:text-indigo-300">综合合规结论与整改意见：</span><br />
                {{ auditReport.overall_compliance_verdict }}
              </div>
            </div>

            <div class="grid grid-cols-2 md:grid-cols-4 gap-2 mt-2">
              <div class="ui-sub-card p-2.5">
                <div class="text-[11px] font-semibold" style="color: var(--text-muted);">网络安全事件</div>
                <div class="text-lg font-bold ui-num mt-0.5" style="color: var(--text-primary);">{{ auditReport.network_audit_metrics.total_events }}</div>
              </div>
              <div class="ui-sub-card p-2.5">
                <div class="text-[11px] font-semibold" style="color: var(--text-muted);">敏感数据命中</div>
                <div class="text-lg font-bold ui-num mt-0.5" style="color: var(--text-primary);">{{ auditReport.data_security_metrics.total_sensitive_hits }}</div>
              </div>
              <div class="ui-sub-card p-2.5">
                <div class="text-[11px] font-semibold" style="color: var(--text-muted);">涉密合规告警</div>
                <div class="text-lg font-bold ui-num mt-0.5" style="color: var(--text-primary);">{{ auditReport.confidentiality_metrics.total_alerts }}</div>
              </div>
              <div class="ui-sub-card p-2.5">
                <div class="text-[11px] font-semibold" style="color: var(--text-muted);">闭环验证通过率</div>
                <div class="text-lg font-bold ui-num text-emerald-600 dark:text-emerald-400 mt-0.5">{{ auditReport.sanitization_metrics.verification_pass_rate }}</div>
              </div>
            </div>

            <div class="mt-3">
              <div class="text-[11px] font-semibold mb-1" style="color: var(--text-muted);">勘验技术报告原始 JSON 结构化底账:</div>
              <pre class="p-3 rounded-xl border text-[11px] font-mono overflow-auto max-h-60 custom-scrollbar text-emerald-700 dark:text-emerald-400" style="background: var(--surface-input); border-color: var(--border-subtle);">{{ JSON.stringify(auditReport, null, 2) }}</pre>
            </div>
          </div>
        </div>

        <div class="px-4 py-3 border-t flex items-center justify-between flex-wrap gap-2" style="border-color: var(--border-subtle);">
          <span class="text-[11px]" style="color: var(--text-muted);">报告符合司法与等保电子证据保全规范</span>
          <div class="flex items-center gap-2">
            <button @click="copyReportMarkdown" class="ui-btn-secondary px-3 py-1.5 text-xs">复制 Markdown 报告</button>
            <button @click="downloadReportJson" class="ui-btn-primary px-3 py-1.5 text-xs">导出 JSON 报告文件</button>
          </div>
        </div>
      </div>
    </div>

    <VpnTunnelDetectorModal :isOpen="showVpnDetectorModal" @close="showVpnDetectorModal = false" />

    <!-- ======================================================== -->
    <!-- BMB 保密现场勘验技术大报告 (A4 矢量打印 / SM3 保全) 模态框 -->
    <!-- ======================================================== -->
    <div v-if="isSecrecyReportModalOpen" class="ui-modal-backdrop fixed inset-0 z-50 flex items-center justify-center p-4">
      <div class="ui-modal-surface rounded-2xl w-full max-w-4xl max-h-[90vh] flex flex-col overflow-hidden">
        <div class="px-4 py-3 border-b flex items-center justify-between shrink-0" style="border-color: var(--border-subtle);">
          <div class="flex items-center gap-2">
            <AppIcon name="report" :size="16" class="text-rose-500" />
            <h4 class="text-xs font-semibold" style="color: var(--text-primary);">
              涉及国家秘密信息系统保密安全现场勘验技术报告 (BMB17 / BMB20 / BMB22)
            </h4>
          </div>
          <button @click="isSecrecyReportModalOpen = false" class="p-1 rounded-lg hover:bg-[var(--surface-hover)] cursor-pointer" style="color: var(--text-secondary);">
            <AppIcon name="close" :size="15" />
          </button>
        </div>

        <div class="p-4 flex-1 overflow-auto custom-scrollbar space-y-3">
          <!-- 基本信息填写栏 -->
          <div class="grid grid-cols-1 md:grid-cols-4 gap-2">
            <div>
              <label class="text-[11px] font-semibold block mb-1" style="color: var(--text-muted);">被检查单位名称:</label>
              <input v-model="secrecyUnitName" class="ui-input w-full px-2.5 py-1 text-xs" />
            </div>
            <div>
              <label class="text-[11px] font-semibold block mb-1" style="color: var(--text-muted);">受检信息系统/终端:</label>
              <input v-model="secrecySystemName" class="ui-input w-full px-2.5 py-1 text-xs" />
            </div>
            <div>
              <label class="text-[11px] font-semibold block mb-1" style="color: var(--text-muted);">涉密等级定位:</label>
              <select v-model="secrecyClassification" class="ui-input w-full px-2.5 py-1 text-xs">
                <option value="秘密级">秘密级</option>
                <option value="机密级">机密级</option>
                <option value="绝密级">绝密级</option>
                <option value="非涉密终端自查">非涉密终端自查</option>
              </select>
            </div>
            <div>
              <label class="text-[11px] font-semibold block mb-1" style="color: var(--text-muted);">保密检查负责人:</label>
              <input v-model="secrecyInspectorName" class="ui-input w-full px-2.5 py-1 text-xs" />
            </div>
          </div>

          <!-- 法定裁决与 SM3/SHA-256 物证摘要框 -->
          <div
            class="p-3 rounded-xl border text-xs space-y-1.5"
            :class="secrecyVerdict.code === 'QUALIFIED' ? 'bg-emerald-500/10 border-emerald-500/35' : secrecyVerdict.code === 'CONDITIONALLY_QUALIFIED' ? 'bg-amber-500/10 border-amber-500/35' : 'bg-rose-500/10 border-rose-500/35'"
          >
            <div class="flex items-center justify-between flex-wrap gap-2">
              <div class="flex items-center gap-2">
                <span class="font-bold" style="color: var(--text-primary);">勘验法定综合裁决：</span>
                <span
                  class="px-2.5 py-0.5 rounded-full text-xs font-bold text-white"
                  :class="secrecyVerdict.code === 'QUALIFIED' ? 'bg-emerald-600' : secrecyVerdict.code === 'CONDITIONALLY_QUALIFIED' ? 'bg-amber-600' : 'bg-rose-600'"
                >
                  {{ secrecyVerdict.label }}
                </span>
              </div>
              <span class="font-mono text-[11px]" style="color: var(--text-muted);">报告编号: {{ secrecyDigest.reportId }}</span>
            </div>
            <p class="text-[11px] leading-relaxed" style="color: var(--text-secondary);">{{ secrecyVerdict.summaryText }}</p>
            <div class="p-2 rounded bg-[var(--surface-input)] font-mono text-[10px] break-all" style="color: var(--text-muted);">
              <div>SM3 (国密电子物证指纹): {{ secrecyDigest.sm3Hex }}</div>
              <div>SHA-256 (规范化载荷 {{ secrecyDigest.canonicalByteLength }} B): {{ secrecyDigest.sha256Hex }}</div>
            </div>
          </div>

          <!-- Markdown 底稿预览 -->
          <div>
            <div class="text-[11px] font-semibold mb-1" style="color: var(--text-muted);">BMB 保密现场勘验技术报告文本底稿预览 (四方签章 / USB / 文档 / 一机两用明细):</div>
            <pre class="p-3 rounded-xl border text-[11px] font-mono overflow-auto max-h-64 custom-scrollbar whitespace-pre-wrap select-text" style="background: var(--surface-input); border-color: var(--border-subtle); color: var(--text-primary);">{{ secrecyReportMarkdownPreview }}</pre>
          </div>
        </div>

        <div class="px-4 py-3 border-t flex items-center justify-between flex-wrap gap-2 shrink-0" style="border-color: var(--border-subtle);">
          <div class="flex items-center gap-2">
            <button @click="printSecrecyFormalReport" class="ui-btn-primary px-3 py-1.5 text-xs flex items-center gap-1.5">
              <AppIcon name="print" :size="13" />
              <span>打印 A4 正式勘验报告 (PDF)</span>
            </button>
            <button @click="downloadSecrecyFormalReportHtml" class="ui-btn-secondary px-3 py-1.5 text-xs flex items-center gap-1.5">
              <AppIcon name="download" :size="13" />
              <span>导出 A4 HTML 大报告</span>
            </button>
          </div>
          <button @click="copySecrecyFormalReportMarkdown" class="ui-btn-secondary px-3 py-1.5 text-xs">
            复制 Markdown 报告
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, defineAsyncComponent } from 'vue';
import { notifySuccess, notifyWarning, notifyError } from '../composables/useNotification';
import { invoke } from '@tauri-apps/api/core';
import AppIcon from '../components/AppIcon.vue';
import EmptyState from '../components/EmptyState.vue';
import { useUniversalDiff } from '../composables/useUniversalDiff';
import { saveTextViaNativeDesktop } from '../composables/useDesktopSave';
import {
  evaluateSecrecyBmbVerdict,
  buildCanonicalSecrecyDigest,
  generateSecrecyFormalReportMarkdown,
  generateSecrecyFormalReportHtml,
  type SecrecyUsbAuditReport,
  type SecrecyDissectBatchReport,
  type DualHomedAuditVerdict,
  type SecrecyNetworkHistoryReport,
  type SecrecyDeepContentReport,
  type SecrecyOsUsageReport,
  type SecrecyAppTraceReport,
  type SecrecyClassificationLevel,
  type SecrecyReportParams,
} from '../composables/useSecrecyFormalReport';

const VpnTunnelDetectorModal = defineAsyncComponent(() => import('../components/VpnTunnelDetectorModal.vue'));
const showVpnDetectorModal = ref(false);

const diffBus = useUniversalDiff();

function addNetworkEventToDiffQueue(evt: NetworkAuditEvent) {
  const payload = typeof evt.detail_json === 'string' && evt.detail_json ? evt.detail_json : `${evt.event_type} ${evt.src_ip}:${evt.src_port} -> ${evt.dst_ip}:${evt.dst_port} | ${evt.summary}`;
  diffBus.addToQueue({
    id: `SEC_NET_${evt.id}`,
    label: `[安全事件] #${evt.id} ${evt.protocol}`,
    timestamp: evt.timestamp,
    protocol: evt.protocol || 'SEC-EVENT',
    src: `${evt.src_ip}:${evt.src_port}`,
    dst: `${evt.dst_ip}:${evt.dst_port}`,
    format: 'ASCII',
    isRawText: true,
    payloadHex: '',
    rawText: payload,
    length: payload.length,
    extraFields: { event_type: evt.event_type, severity: evt.severity, summary: evt.summary }
  }, `违规事件 #${evt.id}`, false);
}

function addSensitiveFindingToDiffQueue(item: SensitiveDataFinding) {
  const raw = `${item.rule_name} (${item.category_code}) | ${item.src_ip} -> ${item.dst_ip} | ${item.matched_sample_masked} | ${item.context_summary}`;
  diffBus.addToQueue({
    id: `SEC_DATA_${item.id}`,
    label: `[涉敏发现] ${item.rule_name}`,
    protocol: item.category_code || 'DLP',
    src: item.src_ip,
    dst: item.dst_ip,
    format: 'ASCII',
    isRawText: true,
    payloadHex: '',
    rawText: raw,
    length: raw.length,
    extraFields: { rule_name: item.rule_name, masked: item.matched_sample_masked }
  }, `涉敏 #${item.id}`, false);
}

function addConfidentialAlertToDiffQueue(alt: ConfidentialityAlert) {
  const payload = typeof alt.detail_json === 'string' && alt.detail_json ? alt.detail_json : `${alt.alert_category} | ${alt.secrecy_level} | ${alt.target_entity} | ${alt.summary}`;
  diffBus.addToQueue({
    id: `SEC_CONF_${alt.id}`,
    label: `[密级预警] ${alt.secrecy_level} #${alt.id}`,
    timestamp: alt.timestamp,
    protocol: alt.alert_category,
    src: alt.target_entity,
    dst: alt.secrecy_level,
    format: 'ASCII',
    isRawText: true,
    payloadHex: '',
    rawText: payload,
    length: payload.length,
    extraFields: { secrecy_level: alt.secrecy_level, target_entity: alt.target_entity, summary: alt.summary }
  }, `定密 #${alt.id}`, false);
}

function compareSanitizationBeforeAfter() {
  if (!sanitizeResult.value) return;
  const orig = rawSanitizeText.value || '';
  const cleaned = sanitizeResult.value.sanitized_content || '';
  diffBus.openUniversalDiff(
    {
      id: 'SAN_BEFORE',
      label: `[脱敏前原文] (${orig.length}B)`,
      protocol: 'SANITIZE-RAW',
      src: 'Raw-Input',
      dst: sanitizeResult.value.policy_id,
      format: 'ASCII',
      isRawText: true,
      payloadHex: '',
      rawText: orig,
      length: orig.length
    },
    {
      id: 'SAN_AFTER',
      label: `[脱敏后成果] (${cleaned.length}B)`,
      protocol: 'SANITIZE-CLEAN',
      src: sanitizeResult.value.policy_id,
      dst: 'Cleaned-Output',
      format: 'ASCII',
      isRawText: true,
      payloadHex: '',
      rawText: cleaned,
      length: cleaned.length,
      extraFields: {
        replaced_count: String(sanitizeResult.value.matched_replacements_count),
        sha256: sanitizeResult.value.content_sha256
      }
    },
    'hex'
  );
}

// 五维审查 Tab 类型
type AuditTabType = 'network' | 'data_sec' | 'confidential' | 'sanitizer' | 'engines';
const activeTab = ref<AuditTabType>('network');

interface SuricataThreatHit {
  signature_id: number;
  name: string;
  category: string;
  severity: string;
  match_start: number;
  match_end: number;
  matched_bytes_hex: string;
  description: string;
}
interface SuricataDslMetrics {
  total_rules: number;
  total_packets_scanned: number;
  total_hits: number;
  recent_hits: SuricataThreatHit[];
  rule_file_path?: string;
  is_loaded_from_disk?: boolean;
}
interface SuricataRuleFileInfo {
  file_path: string;
  file_size_bytes: number;
  total_rules: number;
  is_loaded_from_disk: boolean;
  last_modified: string;
}
interface GlushkovEngineMetrics {
  total_scanned_packets: number;
  total_scanned_bytes: number;
  total_threat_hits: number;
  active_stream_contexts: number;
  compiled_rules_count: number;
  scan_throughput_mbps: number;
}
interface GlushkovMatch {
  rule_id: number;
  rule_name: string;
  threat_class: string;
  match_end_offset: number;
  snippet: string;
}
interface ScriptExecutionSummary {
  events_loaded: number;
  return_value: string;
  alerts: SuricataThreatHit[];
  logs: string[];
}

// 规则库资产健康管理模型
interface RuleLibraryAsset {
  id: string;
  name: string;
  category: string;
  file_path: string;
  exists: boolean;
  file_size_bytes: number;
  rule_count: number;
  cve_count: number;
  last_modified: string;
  status: string;
  is_active: boolean;
  download_url?: string;
  recommendation: string;
}

interface RuleArchiveSmartStatus {
  archive_exists: boolean;
  archive_path: string | null;
  archive_size_bytes: number;
  archive_mtime: number;
  archive_mtime_str: string;
  rules_dir_exists: boolean;
  rules_dir_path: string | null;
  extracted_files_count: number;
  latest_extracted_mtime: number;
  latest_extracted_mtime_str: string;
  cve_aggregated_exists: boolean;
  status_code: 'UP_TO_DATE' | 'UPDATE_AVAILABLE' | 'NEEDS_INITIAL_EXTRACTION' | 'ARCHIVE_MISSING';
  status_title: string;
  status_description: string;
  recommendation: string;
  can_execute: boolean;
}

interface RuleAssetsHealthOverview {
  all_ready: boolean;
  total_assets: number;
  ready_assets: number;
  missing_assets: number;
  active_rule_count: number;
  active_cve_count: number;
  active_library_name: string;
  assets: RuleLibraryAsset[];
  default_mirror_url: string;
  local_archive_detected?: string;
  local_archive_size_bytes?: number;
  smart_status?: RuleArchiveSmartStatus | null;
}

interface AvailableRuleFile {
  file_name: string;
  display_name: string;
  file_size_bytes: number;
  rule_count: number;
  cve_count: number;
  is_active: boolean;
  last_modified: string;
}

interface SyncRuleResult {
  success: boolean;
  message: string;
  total_files_extracted: number;
  total_rules_extracted: number;
  total_cve_rules: number;
  duration_ms: number;
  archive_size_bytes: number;
  active_rules_loaded: number;
  current_active_file: string;
}

const suricataMetrics = ref<SuricataDslMetrics | null>(null);
const suricataFileInfo = ref<SuricataRuleFileInfo | null>(null);
const suricataRuleInput = ref('');
const glushkovMetrics = ref<GlushkovEngineMetrics | null>(null);
const glushkovTestHex = ref('');
const glushkovScanMatches = ref<GlushkovMatch[]>([]);
const auditScriptSource = ref('');
const auditScriptHex = ref('');
const auditScriptResult = ref<ScriptExecutionSummary | null>(null);

// 离线规则库健康监控与自动更新管理状态
const ruleAssetsHealth = ref<RuleAssetsHealthOverview | null>(null);
const availableRuleFiles = ref<AvailableRuleFile[]>([]);
const selectedRuleFileName = ref<string>('suricata_rules.rules');
const isSyncingRules = ref<boolean>(false);
const isRuleAssetsModalOpen = ref<boolean>(false);
const customMirrorUrl = ref<string>('');
const manualLocalArchivePath = ref<string>('');
const isExtractingLocal = ref<boolean>(false);
const isSmartSyncing = ref<boolean>(false);
const showOfflineManualHelp = ref<boolean>(false);

async function handleSmartSyncArchive() {
  isSmartSyncing.value = true;
  try {
    const res = await invoke<SyncRuleResult>('smart_sync_rules_archive_cmd');
    notifySuccess('智能感知与构建执行完成', res.message);
    await fetchDeepEngines();
    await fetchRuleAssetsHealth();
  } catch (e) {
    notifyError('智能解包执行失败', `请检查本地文件完整性: ${String(e)}`);
  } finally {
    isSmartSyncing.value = false;
  }
}

async function handleBrowseLocalArchive() {
  try {
    const selected = await invoke<string | null>('browse_local_rules_archive_file_cmd');
    if (selected) {
      manualLocalArchivePath.value = selected;
      notifySuccess('已选取规则安装包', `文件: ${selected}`);
    }
  } catch (e) {
    console.error('浏览本地规则包失败:', e);
  }
}

async function handleExtractLocalArchive(targetPath?: string) {
  isExtractingLocal.value = true;
  try {
    const res = await invoke<SyncRuleResult>('import_and_extract_local_rules_archive_cmd', {
      archivePath: targetPath || (manualLocalArchivePath.value.trim() ? manualLocalArchivePath.value.trim() : null),
    });
    notifySuccess('本地规则包解压构建完成', res.message);
    await fetchDeepEngines();
    await fetchRuleAssetsHealth();
  } catch (e) {
    notifyError('解压本地安装包失败', `请核验文件路径或规约格式: ${String(e)}`);
  } finally {
    isExtractingLocal.value = false;
  }
}

async function fetchRuleAssetsHealth() {
  try {
    const health = await invoke<RuleAssetsHealthOverview>('check_rule_assets_health_cmd');
    ruleAssetsHealth.value = health;
    const files = await invoke<AvailableRuleFile[]>('list_available_rule_files_cmd');
    availableRuleFiles.value = files;
    const active = files.find(f => f.is_active);
    if (active) {
      selectedRuleFileName.value = active.file_name;
    }
  } catch (e) {
    console.error('获取规则资产健康状态失败:', e);
  }
}

async function handleSwitchRuleFile(fileName: string) {
  if (!fileName) return;
  try {
    const info = await invoke<SuricataRuleFileInfo>('switch_active_suricata_rule_file_cmd', { fileName });
    suricataFileInfo.value = info;
    notifySuccess('规则库切换成功', `已切换探针运行规则库为 ${fileName} (加载 ${info.total_rules} 条规则)`);
    await fetchDeepEngines();
    await fetchRuleAssetsHealth();
  } catch (e) {
    notifyError('切换规则库失败', e);
  }
}

async function handleSyncRules(mirrorUrl?: string) {
  isSyncingRules.value = true;
  try {
    const res = await invoke<SyncRuleResult>('download_and_sync_suricata_rules_cmd', {
      mirrorUrl: mirrorUrl || (customMirrorUrl.value.trim() ? customMirrorUrl.value.trim() : null),
    });
    notifySuccess('全量规则库下载与构建完成', res.message);
    await fetchDeepEngines();
    await fetchRuleAssetsHealth();
  } catch (e) {
    notifyError('在线下载规则库失败', `请检查网络连通性或代理配置: ${String(e)}`);
  } finally {
    isSyncingRules.value = false;
  }
}

async function fetchDeepEngines() {
  try {
    const [suri, glu, fileInfo] = await Promise.all([
      invoke<SuricataDslMetrics>('get_suricata_dsl_metrics_cmd'),
      invoke<GlushkovEngineMetrics>('get_glushkov_engine_metrics_cmd'),
      invoke<SuricataRuleFileInfo>('get_suricata_rule_file_info_cmd').catch(() => null),
    ]);
    suricataMetrics.value = suri;
    glushkovMetrics.value = glu;
    if (fileInfo) suricataFileInfo.value = fileInfo;
  } catch (e) {
    console.error('获取深度规则引擎状态失败:', e);
  }
}

async function switchToEnginesTab() {
  activeTab.value = 'engines';
  await fetchDeepEngines();
}

async function loadCustomSuricataRules() {
  if (!suricataRuleInput.value.trim()) return;
  try {
    const loaded = await invoke<number>('load_suricata_dsl_rules_cmd', { rulesText: suricataRuleInput.value });
    notifySuccess('Suricata 规则热编译完成', `成功加载 ${loaded} 条工业 DSL 规则`);
    suricataRuleInput.value = '';
    await fetchDeepEngines();
  } catch (e) {
    notifyError('Suricata 规则编译失败', e);
  }
}

async function reloadSuricataFromDisk() {
  try {
    const info = await invoke<SuricataRuleFileInfo>('reload_suricata_rules_from_disk_cmd');
    suricataFileInfo.value = info;
    notifySuccess('本地规则库热重载成功', `已完整加载 ${info.total_rules} 条工业规则 (${formatBytes(info.file_size_bytes)})`);
    await fetchDeepEngines();
  } catch (e) {
    notifyError('本地规则库热重载失败', e);
  }
}

async function loadSuricataFileTextToEditor() {
  try {
    const text = await invoke<string>('read_suricata_rule_file_text_cmd');
    suricataRuleInput.value = text;
    notifySuccess('本地规则全文已载入', '已将磁盘 rules 文件全量载入到编辑器中');
  } catch (e) {
    notifyError('读取本地规则文件失败', e);
  }
}

async function saveSuricataRulesToDisk() {
  if (!suricataRuleInput.value.trim()) return;
  try {
    const info = await invoke<SuricataRuleFileInfo>('save_suricata_rules_to_disk_cmd', {
      rulesText: suricataRuleInput.value,
    });
    suricataFileInfo.value = info;
    notifySuccess('规则已持久化到磁盘', `成功保存并装载 ${info.total_rules} 条规则到 ${info.file_path}`);
    await fetchDeepEngines();
  } catch (e) {
    notifyError('保存规则文件到磁盘失败', e);
  }
}

async function runGlushkovScan() {
  const cleaned = glushkovTestHex.value.trim().replace(/\s+/g, '');
  if (!cleaned) return;
  try {
    glushkovScanMatches.value = await invoke<GlushkovMatch[]>('scan_payload_glushkov_cmd', { payloadHex: cleaned });
    await fetchDeepEngines();
  } catch (e) {
    notifyError('Glushkov 正则扫描失败', e);
  }
}

async function resetGlushkovMetrics() {
  try {
    await invoke('reset_glushkov_engine_metrics_cmd');
    await fetchDeepEngines();
  } catch (e) {
    notifyError('重置 Glushkov 统计失败', e);
  }
}

async function runAuditScript() {
  if (!auditScriptSource.value.trim()) return;
  try {
    auditScriptResult.value = await invoke<ScriptExecutionSummary>('evaluate_audit_script_cmd', {
      scriptSource: auditScriptSource.value,
      sampleHex: auditScriptHex.value.trim().replace(/\s+/g, ''),
    });
  } catch (e) {
    notifyError('脚本沙箱执行中止', e);
  }
}

// ============================================================
// 1. 网络安全审查数据模型与状态
// ============================================================
interface NetworkAuditEvent {
  id: number;
  timestamp: string;
  timestamp_ns: number;
  event_type: string;
  severity: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  summary: string;
  detail_json: string;
}

interface NetworkAuditStatistics {
  total_events: number;
  industrial_write_violations: number;
  dns_tunnel_count: number;
  icmp_tunnel_count: number;
  cross_zone_violations: number;
}

const networkEvents = ref<NetworkAuditEvent[]>([]);
const networkStats = ref<NetworkAuditStatistics>({
  total_events: 0,
  industrial_write_violations: 0,
  dns_tunnel_count: 0,
  icmp_tunnel_count: 0,
  cross_zone_violations: 0,
});

const networkFilterType = ref<string>('ALL');
const networkEventFilterOptions = [
  { key: 'ALL', label: '全部事件' },
  { key: 'INDUSTRIAL_WRITE_VIOLATION', label: '工控写越权' },
  { key: 'DNS_COVERT_TUNNEL', label: 'DNS隐蔽隧道' },
  { key: 'ICMP_COVERT_TUNNEL', label: 'ICMP载荷通道' },
];

const filteredNetworkEvents = computed(() => {
  if (networkFilterType.value === 'ALL') {
    return networkEvents.value;
  }
  return networkEvents.value.filter(e => e.event_type === networkFilterType.value);
});

function formatNetworkEventType(t: string): string {
  switch (t) {
    case 'INDUSTRIAL_WRITE_VIOLATION': return '工控写越权';
    case 'DNS_COVERT_TUNNEL': return 'DNS隐蔽隧道';
    case 'ICMP_COVERT_TUNNEL': return 'ICMP异常通道';
    case 'CROSS_ZONE_VIOLATION': return '跨安全域违规';
    default: return t;
  }
}

// 工业专有与长尾解包插件元信息
interface IndustrialPluginMeta {
  id: string;
  name: string;
  vendor: string;
  category: string;
  default_ports: number[];
  plugin_type: string;
}

const industrialPlugins = ref<IndustrialPluginMeta[]>([]);
const showPluginDrawer = ref<boolean>(false);

// ============================================================
// 2. 数据安全审查数据模型与状态
// ============================================================
interface SensitiveDataFinding {
  id: number;
  timestamp: string;
  rule_id: string;
  rule_name: string;
  category_code: string;
  severity: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  matched_sample_masked: string;
  match_count: number;
  context_summary: string;
}

interface ReconstructedFileItem {
  id: number;
  timestamp: string;
  filename: string;
  file_extension: string;
  mime_type: string;
  size_bytes: number;
  sha256_hash: string;
  src_ip: string;
  dst_ip: string;
  protocol: string;
  classification: string;
  is_truncated: boolean;
}

interface DataSecuritySummary {
  total_scanned_flows: number;
  total_sensitive_hits: number;
  core_data_hits: number;
  important_data_hits: number;
  pii_hits: number;
  general_data_hits: number;
  reconstructed_files_count: number;
  category_distribution: Record<string, number>;
}

const sensitiveFindings = ref<SensitiveDataFinding[]>([]);
const reconstructedFiles = ref<ReconstructedFileItem[]>([]);
const dataSecSummary = ref<DataSecuritySummary>({
  total_scanned_flows: 0,
  total_sensitive_hits: 0,
  core_data_hits: 0,
  important_data_hits: 0,
  pii_hits: 0,
  general_data_hits: 0,
  reconstructed_files_count: 0,
  category_distribution: {},
});

// ============================================================
// 3. 保密安全审查数据模型与状态
// ============================================================
interface ConfidentialityAlert {
  id: number;
  timestamp: string;
  timestamp_ns: number;
  alert_category: string;
  secrecy_level: string;
  src_ip: string;
  dst_ip: string;
  target_entity: string;
  summary: string;
  detail_json: string;
}

interface ConfidentialityScanReport {
  is_secret: boolean;
  highest_level: string;
  hit_markers: string[];
  document_signatures: string[];
  scanned_bytes: number;
  recommendation: string;
}

const confidentialityAlerts = ref<ConfidentialityAlert[]>([]);
const scanInputText = ref('');
const isScanningText = ref(false);
const confidentialScanResult = ref<ConfidentialityScanReport | null>(null);

// BMB17/BMB20/BMB22 专项现场取证状态机与 A4 报告参数
const secrecySubView = ref<
  'overview' | 'usb' | 'docs' | 'dualhomed' | 'history' | 'ole2' | 'osusage' | 'apptrace'
>('overview');
const usbForensicsReport = ref<SecrecyUsbAuditReport | null>(null);
const isAuditingUsbHistory = ref(false);
const dissectTargetPath = ref('');
const dissectReport = ref<SecrecyDissectBatchReport | null>(null);
const isDissectingDocs = ref(false);
const dualHomedReport = ref<DualHomedAuditVerdict | null>(null);
const isAuditingDualHomed = ref(false);
const networkHistoryReport = ref<SecrecyNetworkHistoryReport | null>(null);
const isAuditingNetworkHistory = ref(false);
const ole2RawSlackTarget = ref('');
const ole2Report = ref<SecrecyDeepContentReport | null>(null);
const isDissectingOle2 = ref(false);
const osUsageReport = ref<SecrecyOsUsageReport | null>(null);
const isAuditingOsUsage = ref(false);
const appTraceReport = ref<SecrecyAppTraceReport | null>(null);
const isAuditingAppTraces = ref(false);

const isSecrecyReportModalOpen = ref(false);
const secrecyUnitName = ref('受检单位涉密信息化部门');
const secrecySystemName = ref('终端办公计算机及内网工作站');
const secrecyClassification = ref<SecrecyClassificationLevel>('秘密级');
const secrecyInspectorName = ref('保密安全核查工程师');
const secrecyInspectionTimeIso = ref(new Date().toISOString());

const secrecyReportParams = computed<SecrecyReportParams>(() => ({
  targetUnitName: secrecyUnitName.value,
  systemName: secrecySystemName.value,
  systemClassification: secrecyClassification.value,
  inspectorName: secrecyInspectorName.value,
  inspectionTimeIso: secrecyInspectionTimeIso.value,
  usbReport: usbForensicsReport.value,
  dissectReport: dissectReport.value,
  dualHomedReport: dualHomedReport.value,
  networkAlerts: confidentialityAlerts.value.map((a) => ({
    timestamp: Date.parse(a.timestamp) || Date.now(),
    source: a.alert_category,
    destination: a.target_entity,
    level: a.secrecy_level,
    matchedKeywords: [a.target_entity],
    documentSignatures: [],
    snippet: a.summary,
  })),
  networkHistoryReport: networkHistoryReport.value,
  ole2Report: ole2Report.value,
  osUsageReport: osUsageReport.value,
  appTraceReport: appTraceReport.value,
}));

const secrecyVerdict = computed(() => evaluateSecrecyBmbVerdict(secrecyReportParams.value));
const secrecyDigest = computed(() => buildCanonicalSecrecyDigest(secrecyReportParams.value, secrecyVerdict.value));
const secrecyReportMarkdownPreview = computed(() => generateSecrecyFormalReportMarkdown(secrecyReportParams.value));

const secrecyTotalFindingsCount = computed(() => {
  const usbViolations = usbForensicsReport.value?.unauthorized_device_count ?? 0;
  const docHits = dissectReport.value?.hit_files_count ?? 0;
  const dualViolation = dualHomedReport.value?.is_dual_homed_violation ? 1 : 0;
  const hisViolation =
    (networkHistoryReport.value?.suspicious_mobile_hotspots.length ?? 0) +
    (networkHistoryReport.value?.historic_rndis_devices.length ?? 0);
  const ole2Hits =
    (ole2Report.value?.ole2_hits.length ?? 0) + (ole2Report.value?.slack_hits.length ?? 0);
  const osHits = osUsageReport.value?.secrecy_named_access_count ?? 0;
  const appHits =
    (appTraceReport.value?.suspicious_downloads.length ?? 0) +
    (appTraceReport.value?.chat_file_hits.length ?? 0);
  return confidentialityAlerts.value.length + usbViolations + docHits + dualViolation + hisViolation + ole2Hits + osHits + appHits;
});

async function runSecrecyUsbHistoryAudit() {
  isAuditingUsbHistory.value = true;
  try {
    const rep = await invoke<SecrecyUsbAuditReport>('audit_secrecy_usb_history_cmd');
    usbForensicsReport.value = rep;
    secrecySubView.value = 'usb';
    if (rep.has_critical_violation) {
      notifyWarning('检出非授权历史 USB 接入痕迹', rep.summary_conclusion);
    } else {
      notifySuccess('USB 历史取证核验完成', rep.summary_conclusion);
    }
  } catch (e: unknown) {
    notifyError('USB 历史取证执行失败', String(e));
  } finally {
    isAuditingUsbHistory.value = false;
  }
}

async function pickAndSetDissectFolder() {
  try {
    const chosen = await invoke<string | null>('pick_native_folder_dialog_cmd', {
      title: '选择待复合公文穿透扫描目录',
    });
    if (chosen) {
      dissectTargetPath.value = chosen;
      await runDocumentDissectAudit();
    }
  } catch (e: unknown) {
    notifyError('打开目录选择器失败', String(e));
  }
}

async function runDocumentDissectAudit() {
  const folder = dissectTargetPath.value.trim();
  if (!folder) return;
  isDissectingDocs.value = true;
  try {
    const rep = await invoke<SecrecyDissectBatchReport>('dissect_secrecy_documents_in_path_cmd', {
      targetPath: folder,
    });
    dissectReport.value = rep;
    secrecySubView.value = 'docs';
    if (rep.hit_files_count > 0) {
      notifyWarning(`穿透检出 ${rep.hit_files_count} 份涉密标密或保护文件`, `已扫描目录 ${rep.target_folder} 共 ${rep.scanned_files_count} 份文档`);
    } else {
      notifySuccess('复合文档穿透扫描完成', `已扫描 ${rep.scanned_files_count} 份文件，未命中涉密标密特征`);
    }
  } catch (e: unknown) {
    notifyError('复合文档解构失败', String(e));
  } finally {
    isDissectingDocs.value = false;
  }
}

async function runDualHomedNetworkAudit() {
  isAuditingDualHomed.value = true;
  try {
    const verdict = await invoke<DualHomedAuditVerdict>('audit_dual_homed_network_cmd');
    dualHomedReport.value = verdict;
    secrecySubView.value = 'dualhomed';
    if (verdict.is_dual_homed_violation) {
      notifyError('触发 BMB22 一机两用严重违规', verdict.reason);
    } else if (verdict.risk_level === 'HIGH') {
      notifyWarning('存在无线通信接口预警', verdict.reason);
    } else {
      notifySuccess('网络接口一机两用排查合规', verdict.reason);
    }
  } catch (e: unknown) {
    notifyError('双网卡一机两用检测失败', String(e));
  } finally {
    isAuditingDualHomed.value = false;
  }
}

async function runNetworkHistoryAudit() {
  isAuditingNetworkHistory.value = true;
  try {
    const rep = await invoke<SecrecyNetworkHistoryReport>('audit_secrecy_network_history_cmd');
    networkHistoryReport.value = rep;
    secrecySubView.value = 'history';
    if (rep.has_historic_violation) {
      notifyWarning('检出历史手机热点或 RNDIS 共享外联痕迹', rep.summary_conclusion);
    } else {
      notifySuccess('历史外联与网络配置取证完成', rep.summary_conclusion);
    }
  } catch (e: unknown) {
    notifyError('历史外联取证执行失败', String(e));
  } finally {
    isAuditingNetworkHistory.value = false;
  }
}

async function runOle2AndSlackAudit() {
  let folder = dissectTargetPath.value.trim();
  if (!folder) {
    try {
      const chosen = await invoke<string | null>('pick_native_folder_dialog_cmd', {
        title: '选择待扫描 OLE2 老式文档 (DOC/XLS/PPT) 目录',
      });
      if (!chosen) return;
      dissectTargetPath.value = chosen;
      folder = chosen;
    } catch (e: unknown) {
      notifyError('打开目录选择器失败', String(e));
      return;
    }
  }
  isDissectingOle2.value = true;
  try {
    const slackTrimmed = ole2RawSlackTarget.value.trim();
    const rep = await invoke<SecrecyDeepContentReport>('dissect_secrecy_ole2_and_slack_cmd', {
      targetPath: folder,
      rawSlackTarget: slackTrimmed ? slackTrimmed : null,
    });
    ole2Report.value = rep;
    secrecySubView.value = 'ole2';
    const totalHits = rep.ole2_hits.length + rep.slack_hits.length;
    if (totalHits > 0) {
      notifyWarning(`检出 ${rep.ole2_hits.length} 份 OLE2 涉密公文及 ${rep.slack_hits.length} 处扇区残片`, `已解构 ${rep.scanned_ole2_files} 份复合文件`);
    } else {
      notifySuccess('OLE2 二进制流及扇区残片检索洁净', `共解构 ${rep.scanned_ole2_files} 份文档，扫描 ${rep.slack_scanned_bytes} Bytes`);
    }
  } catch (e: unknown) {
    notifyError('OLE2 与扇区残片检索失败', String(e));
  } finally {
    isDissectingOle2.value = false;
  }
}

async function runOsUsageAudit() {
  isAuditingOsUsage.value = true;
  try {
    const rep = await invoke<SecrecyOsUsageReport>('audit_secrecy_os_usage_cmd');
    osUsageReport.value = rep;
    secrecySubView.value = 'osusage';
    if (rep.secrecy_named_access_count > 0 || rep.print_spooler_jobs.some((j) => j.is_secrecy_suspicious)) {
      notifyWarning('检出涉密命名快捷方式访问或可疑打印作业', `共解析 ${rep.total_lnk_parsed} 条快捷方式`);
    } else {
      notifySuccess('系统操作轨迹与打印留痕审计完成', `解析 ${rep.total_lnk_parsed} 条快捷方式，${rep.print_spooler_jobs.length} 条打印作业`);
    }
  } catch (e: unknown) {
    notifyError('操作系统轨迹审计失败', String(e));
  } finally {
    isAuditingOsUsage.value = false;
  }
}

async function runAppTracesAudit() {
  isAuditingAppTraces.value = true;
  try {
    const rep = await invoke<SecrecyAppTraceReport>('audit_secrecy_app_traces_cmd');
    appTraceReport.value = rep;
    secrecySubView.value = 'apptrace';
    const hitCount = rep.suspicious_downloads.length + rep.chat_file_hits.length;
    if (hitCount > 0) {
      notifyWarning(`检出 ${rep.suspicious_downloads.length} 条浏览器涉密下载及 ${rep.chat_file_hits.length} 份 IM 传输命中`, `共核验下载 ${rep.total_downloads_checked} 条`);
    } else {
      notifySuccess('浏览器下载与即时通信轨迹审计洁净', `共核验下载 ${rep.total_downloads_checked} 条、IM 文件 ${rep.chat_files_checked} 份`);
    }
  } catch (e: unknown) {
    notifyError('应用外发轨迹审计失败', String(e));
  } finally {
    isAuditingAppTraces.value = false;
  }
}

function openSecrecyFormalReportModal() {
  secrecyInspectionTimeIso.value = new Date().toISOString();
  isSecrecyReportModalOpen.value = true;
}

function printSecrecyFormalReport() {
  const htmlContent = generateSecrecyFormalReportHtml(secrecyReportParams.value);
  const printWin = window.open('', '_blank');
  if (printWin) {
    printWin.document.open();
    printWin.document.write(htmlContent);
    printWin.document.close();
    printWin.focus();
    setTimeout(() => {
      printWin.print();
    }, 350);
    notifySuccess('已拉起 BMB 保密现场勘验 A4 报告打印窗口');
  } else {
    notifyWarning('打印弹窗被浏览器拦截，请允许弹出窗口或使用 HTML 导出功能');
  }
}

async function downloadSecrecyFormalReportHtml() {
  const htmlContent = generateSecrecyFormalReportHtml(secrecyReportParams.value);
  const safeReportNo = secrecyDigest.value.reportId;
  await saveTextViaNativeDesktop(
    `${safeReportNo}_BMB_Secrecy_Inspection_Report.html`,
    htmlContent,
    'BMB 保密安全勘验报告 (*.html)',
    '*.html',
    '导出 BMB 保密安全现场勘验 A4 报告',
  );
}

function copySecrecyFormalReportMarkdown() {
  copyToClipboard(secrecyReportMarkdownPreview.value);
  notifySuccess('已复制 BMB 保密现场勘验 Markdown 底稿至剪贴板');
}

// ============================================================
// 4. 数据脱敏清洗审查数据模型与状态
// ============================================================
interface SanitizationPolicyRule {
  policy_id: string;
  name: string;
  description: string;
  mask_algorithm: string;
  preserve_prefix_len: number;
  preserve_suffix_len: number;
  mask_char: string;
  deterministic_salt: string;
}

interface SanitizationResult {
  policy_id: string;
  original_len: number;
  sanitized_len: number;
  matched_replacements_count: number;
  sanitized_content: string;
  content_sha256: string;
}

interface SanitizationAuditProof {
  proof_id: string;
  verified_at: string;
  policy_id: string;
  original_sha256: string;
  sanitized_sha256: string;
  residual_sensitive_hits: number;
  is_fully_compliant: boolean;
  verdict: string;
}

const sanitizationPolicies = ref<SanitizationPolicyRule[]>([]);
const selectedPolicyId = ref('POL-01-GB-COMPLIANCE');
const hmacSalt = ref('');
const rawSanitizeText = ref('');
const isSanitizing = ref(false);
const sanitizeResult = ref<SanitizationResult | null>(null);

const isVerifying = ref(false);
const auditProof = ref<SanitizationAuditProof | null>(null);

// 详情弹窗与报告模态框
const isDetailModalOpen = ref(false);
const selectedDetailJson = ref('');

const isGeneratingReport = ref(false);
const isReportModalOpen = ref(false);
const auditReport = ref<any | null>(null);

// 全局 Toast 提示状态
function showToast(msg: string) {
  if (msg.includes('失败')) {
    notifyError('防火墙规则阻断受阻', msg);
  } else if (msg.includes('已经')) {
    notifyWarning('防火墙规则已存在', msg);
  } else {
    notifySuccess('防火墙规则阻断生效', msg);
  }
}

// 工业防火墙联动规则数据模型
interface FirewallRule {
  id: string;
  name: string;
  enabled: boolean;
  target_domain: string;
  methods: string[];
  path_pattern: string;
  keyword_regex: string;
  action: string;
  block_status_code: number;
  block_message: string;
}

interface WfpKernelRule {
  target: string;
  cidr_normalized: string;
  reason: string;
  inbound_filter_id: number;
  outbound_filter_id: number;
  created_at: string;
  enforcement_mode: string;
}

interface WfpBlockOutcome {
  success: boolean;
  kernel_enforced: boolean;
  permission_denied: boolean;
  target: string;
  cidr_normalized: string;
  inbound_filter_id: number;
  outbound_filter_id: number;
  message: string;
}

interface WfpStatusReport {
  os_supported: boolean;
  engine_connected: boolean;
  permission_denied: boolean;
  last_status_code: number;
  last_message: string;
  active_rules: WfpKernelRule[];
}

const wfpStatus = ref<WfpStatusReport | null>(null);
const manualWfpTarget = ref('');

function isValidIpv4OrCidr(target: string): boolean {
  const trimmed = target.trim();
  const match = trimmed.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/);
  if (!match) return false;
  for (let i = 1; i <= 4; i++) {
    const octet = Number(match[i]);
    if (octet < 0 || octet > 255) return false;
  }
  if (match[5] !== undefined) {
    const prefix = Number(match[5]);
    if (prefix < 0 || prefix > 32) return false;
  }
  return true;
}

async function fetchWfpStatus() {
  try {
    wfpStatus.value = await invoke<WfpStatusReport>('get_wfp_status_cmd');
  } catch (e) {
    wfpStatus.value = {
      os_supported: false,
      engine_connected: false,
      permission_denied: false,
      last_status_code: 0,
      last_message: `WFP 内核过滤状态查询失败: ${String(e)}`,
      active_rules: [],
    };
  }
}

async function unblockWfpTarget(target: string) {
  try {
    const msg = await invoke<string>('wfp_unblock_ip_cmd', { target });
    await fetchWfpStatus();
    notifySuccess('WFP / XDP 阻断已解除', msg);
  } catch (e) {
    notifyError('解除内核阻断失败', String(e));
  }
}

async function triggerManualWfpBlock() {
  const target = manualWfpTarget.value.trim();
  if (!target) return;
  await blockIpAddress(target, '安全审查控制台人工下发阻断');
  manualWfpTarget.value = '';
}

async function applyWfpAndNotify(target: string, reason: string, appRuleSaved: boolean) {
  if (!isValidIpv4OrCidr(target)) {
    if (appRuleSaved) {
      notifyWarning(
        '已写入应用代理阻断名单',
        `目标 ${target} 非纯 IPv4/CIDR 地址，已同步至 HTTP 代理规则拦截；WFP 内核层仅拦截 IPv4/CIDR 端点`
      );
    }
    return;
  }
  const wfpRes = await invoke<WfpBlockOutcome>('wfp_block_ip_cmd', { target: target.trim(), reason });
  await fetchWfpStatus();
  if (wfpRes.kernel_enforced) {
    notifySuccess('WFP 内核 + XDP 三层阻断生效', wfpRes.message);
  } else if (wfpRes.permission_denied) {
    notifyWarning('WFP 内核提权受限，已降级前端 XDP + 代理拦截', wfpRes.message);
  } else if (!wfpRes.success) {
    notifyError('WFP 内核规则校验拦截', wfpRes.message);
  } else {
    notifyWarning('XDP 前端丢弃 + 代理规则已激活', wfpRes.message);
  }
}

async function blockIpAddress(ip: string, reason: string) {
  try {
    const cleanTarget = ip.trim();
    const rules = await invoke<FirewallRule[]>('get_firewall_rules_cmd');
    const existing = rules.find(r => r.target_domain === cleanTarget);
    if (!existing) {
      const newRule: FirewallRule = {
        id: `BLK-${Date.now().toString(36).toUpperCase()}`,
        name: `安全审查阻断: ${cleanTarget}`,
        enabled: true,
        target_domain: cleanTarget,
        methods: [],
        path_pattern: '.*',
        keyword_regex: '',
        action: 'BLOCK',
        block_status_code: 403,
        block_message: `工业探针安全审查核心已阻断该通信端点 (${reason})`,
      };
      rules.push(newRule);
      await invoke('save_firewall_rules_cmd', { rules });
    }
    await applyWfpAndNotify(cleanTarget, reason, true);
  } catch (e) {
    console.error('blockIpAddress error:', e);
    showToast(`阻断失败: ${String(e)}`);
  }
}

async function blockEgressTarget(target: string, reason: string) {
  try {
    const cleanTarget = target.trim();
    const rules = await invoke<FirewallRule[]>('get_firewall_rules_cmd');
    const existing = rules.find(r => r.target_domain === cleanTarget);
    if (!existing) {
      const newRule: FirewallRule = {
        id: `EGRESS-BLK-${Date.now().toString(36).toUpperCase()}`,
        name: `保密合规外联阻断: ${cleanTarget}`,
        enabled: true,
        target_domain: cleanTarget,
        methods: [],
        path_pattern: '.*',
        keyword_regex: '',
        action: 'BLOCK',
        block_status_code: 403,
        block_message: `国家秘密法与保密合规防护: 严禁涉密主机访问非法外联渠道 (${reason})`,
      };
      rules.push(newRule);
      await invoke('save_firewall_rules_cmd', { rules });
    }
    await applyWfpAndNotify(cleanTarget, reason, true);
  } catch (e) {
    console.error('blockEgressTarget error:', e);
    showToast(`阻断失败: ${String(e)}`);
  }
}

function inspectFindingDetail(item: SensitiveDataFinding) {
  selectedDetailJson.value = JSON.stringify({
    title: "GB/T 43697 数据安全分类分级敏感数据检验证据",
    rule_name: item.rule_name,
    category_code: item.category_code,
    severity: item.severity,
    endpoints: `${item.src_ip}:${item.src_port} -> ${item.dst_ip}:${item.dst_port}`,
    masked_sample: item.matched_sample_masked,
    match_count: item.match_count,
    context_summary: item.context_summary,
    timestamp: item.timestamp,
    compliance_standard: "GB/T 43697-2024 数据安全技术 数据分类分级规则"
  }, null, 2);
  isDetailModalOpen.value = true;
}

function inspectFileDetail(f: ReconstructedFileItem) {
  selectedDetailJson.value = JSON.stringify({
    title: "网络会话流式还原检材文件物证元数据",
    filename: f.filename,
    mime_type: f.mime_type,
    file_extension: f.file_extension,
    size_bytes: f.size_bytes,
    sha256_hash: f.sha256_hash,
    endpoints: `${f.src_ip} -> ${f.dst_ip}`,
    protocol: f.protocol,
    classification: f.classification,
    is_truncated_10mb: f.is_truncated,
    timestamp: f.timestamp,
    forensic_integrity: "真实物理 SHA-256 哈希防篡改指纹保全"
  }, null, 2);
  isDetailModalOpen.value = true;
}

// ============================================================
// 数据加载与交互函数
// ============================================================

async function fetchNetworkAudit() {
  try {
    const events = await invoke<NetworkAuditEvent[]>('get_network_audit_events_cmd', { limit: 200 });
    networkEvents.value = events;
    const stats = await invoke<NetworkAuditStatistics>('get_network_audit_statistics_cmd');
    networkStats.value = stats;
  } catch (e) {
    console.error('fetchNetworkAudit error:', e);
  }
}

async function fetchDataSecurityAudit() {
  try {
    const summary = await invoke<DataSecuritySummary>('get_data_security_summary_cmd');
    dataSecSummary.value = summary;
    const findings = await invoke<SensitiveDataFinding[]>('get_sensitive_findings_cmd', { limit: 300 });
    sensitiveFindings.value = findings;
    const files = await invoke<ReconstructedFileItem[]>('get_reconstructed_files_cmd', { limit: 100 });
    reconstructedFiles.value = files;
  } catch (e) {
    console.error('fetchDataSecurityAudit error:', e);
  }
}

async function fetchConfidentialityAudit() {
  try {
    const alerts = await invoke<ConfidentialityAlert[]>('get_confidentiality_alerts_cmd', { limit: 200 });
    confidentialityAlerts.value = alerts;
  } catch (e) {
    console.error('fetchConfidentialityAudit error:', e);
  }
}

async function fetchSanitizationPolicies() {
  try {
    const pols = await invoke<SanitizationPolicyRule[]>('get_sanitization_policies_cmd');
    sanitizationPolicies.value = pols;
    if (pols.length > 0 && !selectedPolicyId.value) {
      selectedPolicyId.value = pols[0].policy_id;
    }
  } catch (e) {
    console.error('fetchSanitizationPolicies error:', e);
  }
}

async function fetchIndustrialPlugins() {
  try {
    const list = await invoke<IndustrialPluginMeta[]>('get_industrial_plugins_info_cmd');
    industrialPlugins.value = list;
  } catch (e) {
    console.error('fetchIndustrialPlugins error:', e);
  }
}

async function refreshAllData() {
  await Promise.all([
    fetchNetworkAudit(),
    fetchDataSecurityAudit(),
    fetchConfidentialityAudit(),
    fetchSanitizationPolicies(),
    fetchIndustrialPlugins(),
    fetchWfpStatus(),
  ]);
}

async function clearCurrentAuditRecords() {
  try {
    await invoke('clear_network_audit_events_cmd');
    await invoke('clear_data_security_records_cmd');
    await invoke('clear_confidentiality_alerts_cmd');
    await refreshAllData();
  } catch (e) {
    console.error('clearCurrentAuditRecords error:', e);
  }
}

// 静态文本保密合规扫描
async function runStaticConfidentialityScan() {
  if (!scanInputText.value.trim()) return;
  isScanningText.value = true;
  try {
    const res = await invoke<ConfidentialityScanReport>('scan_confidentiality_text_cmd', {
      content: scanInputText.value,
    });
    confidentialScanResult.value = res;
  } catch (e) {
    console.error('runStaticConfidentialityScan error:', e);
  } finally {
    isScanningText.value = false;
  }
}

// 执行脱敏清洗
async function executeSanitization() {
  if (!rawSanitizeText.value.trim()) return;
  isSanitizing.value = true;
  auditProof.value = null;
  try {
    const res = await invoke<SanitizationResult>('apply_data_sanitization_cmd', {
      inputText: rawSanitizeText.value,
      policyId: selectedPolicyId.value,
    });
    sanitizeResult.value = res;
  } catch (e) {
    console.error('executeSanitization error:', e);
  } finally {
    isSanitizing.value = false;
  }
}

// 闭环合规验证
async function verifyComplianceProof() {
  if (!sanitizeResult.value) return;
  isVerifying.value = true;
  try {
    const proof = await invoke<SanitizationAuditProof>('verify_sanitization_compliance_cmd', {
      sanitizedText: sanitizeResult.value.sanitized_content,
    });
    auditProof.value = proof;
  } catch (e) {
    console.error('verifyComplianceProof error:', e);
  } finally {
    isVerifying.value = false;
  }
}

// 载入样例检材
function fillSampleText() {
  rawSanitizeText.value = `【中共中央办公厅发[2024]88号通知】
关于印发《国家水利枢纽核心控制业务调度拓扑》的秘密★10年公文。
各省调度自动化中心主站：
请各测站管理员核对以下运维人员登记信息：
调度员张伟，身份证号：110101199003072394，移动电话：13800138000，电子邮箱：zhangwei_admin@water.gov.cn。
紧急备用资金划拨结算账号：6222020200112233445（中国工商银行牡丹灵通卡）。
私钥配置段落如下：
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Yh...[REDACTED TEST PRIVATE KEY KEYWORD]...
-----END RSA PRIVATE KEY-----
云管平台调度鉴权凭据：AKIDabc1234567890abcdef1234567890`;
}

// 出具综合勘验报告
async function generateComprehensiveReport() {
  isGeneratingReport.value = true;
  try {
    const rep = await invoke<any>('generate_comprehensive_audit_report_cmd');
    auditReport.value = rep;
    isReportModalOpen.value = true;
  } catch (e) {
    console.error('generateComprehensiveReport error:', e);
  } finally {
    isGeneratingReport.value = false;
  }
}

function copyReportMarkdown() {
  if (!auditReport.value) return;
  const md = `# 四维安全合规审查与数据脱敏清洗综合勘验技术报告
- **报告编号**: ${auditReport.value.report_id}
- **勘验时间**: ${auditReport.value.generated_at}
- **综合评定**: ${auditReport.value.overall_compliance_verdict}

## 1. 网络安全审查指标 (等保三级)
- 审查事件总数: ${auditReport.value.network_audit_metrics.total_events}
- 工控写指令越权: ${auditReport.value.network_audit_metrics.industrial_write_violations}
- DNS隐蔽高熵隧道: ${auditReport.value.network_audit_metrics.dns_tunnel_count}
- ICMP异常通道: ${auditReport.value.network_audit_metrics.icmp_tunnel_count}

## 2. 数据安全审查指标 (GB/T 43697)
- 敏感数据流总命中: ${auditReport.value.data_security_metrics.total_sensitive_hits}
- 核心数据: ${auditReport.value.data_security_metrics.core_data_hits}
- 重要数据: ${auditReport.value.data_security_metrics.important_data_hits}
- 敏感个人信息 (PII): ${auditReport.value.data_security_metrics.pii_hits}
- 还原传输文件数: ${auditReport.value.data_security_metrics.reconstructed_files_count}

## 3. 保密合规审查指标
- 涉密公文与外联告警总数: ${auditReport.value.confidentiality_metrics.total_alerts}
- 法定密级检出: ${auditReport.value.confidentiality_metrics.secret_marker_alerts}
- 红头公文字号: ${auditReport.value.confidentiality_metrics.red_header_doc_alerts}

## 4. 数据脱敏清洗与闭环审查指标
- 已生效脱敏策略模板: ${auditReport.value.sanitization_metrics.active_policies_count}
- 闭环逆向复测通过率: ${auditReport.value.sanitization_metrics.verification_pass_rate}
`;
  copyToClipboard(md);
}

async function downloadReportJson() {
  if (!auditReport.value) return;
  await saveTextViaNativeDesktop(
    `comprehensive_security_audit_report_${Date.now()}.json`,
    JSON.stringify(auditReport.value, null, 2),
    '安全勘验报告 JSON (*.json)',
    '*.json',
    '导出综合安全合规勘验报告'
  );
}

function copyToClipboard(text: string) {
  navigator.clipboard.writeText(text);
}

function formatJson(jsonStr: string): string {
  try {
    return JSON.stringify(JSON.parse(jsonStr), null, 2);
  } catch (err) {
    console.debug('[SecurityReviewView] formatJson non-JSON payload fallback:', err);
    return jsonStr;
  }
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

onMounted(() => {
  refreshAllData();
  fetchDeepEngines();
  fetchRuleAssetsHealth();
});
</script>

<style scoped>
.custom-scrollbar::-webkit-scrollbar {
  width: 5px;
  height: 5px;
}
.custom-scrollbar::-webkit-scrollbar-track {
  background: transparent;
}
.custom-scrollbar::-webkit-scrollbar-thumb {
  background: rgba(148, 163, 184, 0.4);
  border-radius: 4px;
}
.custom-scrollbar::-webkit-scrollbar-thumb:hover {
  background: rgba(100, 116, 139, 0.6);
}
</style>
