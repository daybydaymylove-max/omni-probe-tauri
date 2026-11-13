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
              {{ networkStats.total_events.toLocaleString() }} <span class="text-[11px] font-normal" style="color: var(--text-muted);">起违规事件</span>
            </div>
            <div class="text-[11px] ui-num truncate mt-0.5" style="color: var(--text-muted);">
              工控越权 {{ networkStats.industrial_write_violations }} · DNS隧道 {{ networkStats.dns_tunnel_count }}
            </div>
          </div>
          <span
            class="px-2 py-0.5 rounded text-[11px] font-semibold shrink-0"
            :class="networkStats.total_events > 0 ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300' : 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300'"
          >
            {{ networkStats.total_events > 0 ? '需核验' : '正常受控' }}
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
              {{ dataSecSummary.total_sensitive_hits.toLocaleString() }} <span class="text-[11px] font-normal" style="color: var(--text-muted);">笔敏感命中</span>
            </div>
            <div class="text-[11px] ui-num truncate mt-0.5" style="color: var(--text-muted);">
              核心 {{ dataSecSummary.core_data_hits }} · 重要 {{ dataSecSummary.important_data_hits }} · PII {{ dataSecSummary.pii_hits }}
            </div>
          </div>
          <span
            class="px-2 py-0.5 rounded text-[11px] font-semibold shrink-0"
            :class="dataSecSummary.total_sensitive_hits > 0 ? 'bg-rose-500/15 text-rose-700 dark:text-rose-300' : 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300'"
          >
            {{ dataSecSummary.total_sensitive_hits > 0 ? '检出泄露' : '未见明文' }}
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
              {{ confidentialityAlerts.length.toLocaleString() }} <span class="text-[11px] font-normal" style="color: var(--text-muted);">次定密与外联</span>
            </div>
            <div class="text-[11px] truncate mt-0.5" style="color: var(--text-muted);">
              涉密公文特征 · 红头发文字号 · 违规外联
            </div>
          </div>
          <span
            class="px-2 py-0.5 rounded text-[11px] font-semibold shrink-0"
            :class="confidentialityAlerts.length > 0 ? 'bg-rose-500/15 text-rose-700 dark:text-rose-300' : 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300'"
          >
            {{ confidentialityAlerts.length > 0 ? '密级预警' : '合规受控' }}
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
                  ? `fwpuclnt.dll 内核会话已就绪 · 当前激活 ${wfpStatus.active_rules.length} 条系统级入/出站阻断规则`
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

          <div v-if="wfpStatus && wfpStatus.active_rules.length > 0" class="flex items-center gap-1.5 flex-wrap pt-1 border-t" style="border-color: var(--border-subtle);">
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
      <!-- TAB 3: 保密安全审查 -->
      <!-- ======================================================== -->
      <div v-else-if="activeTab === 'confidential'" class="flex-1 overflow-hidden flex flex-col gap-2.5 min-h-0">
        <!-- 上半部分：保密告警流水表 -->
        <div class="h-1/2 border rounded-xl overflow-hidden flex flex-col shrink-0" style="border-color: var(--border-subtle); background: var(--surface-content-alt);">
          <div class="p-2.5 border-b text-xs font-semibold flex items-center justify-between shrink-0" style="border-color: var(--border-subtle); color: var(--text-primary);">
            <div class="flex items-center gap-2">
              <span>涉密公文与违规外联安全警报流水</span>
              <span class="px-1.5 py-0.5 rounded-full text-[11px] bg-rose-500/15 text-rose-700 dark:text-rose-300 ui-num font-semibold">{{ confidentialityAlerts.length }} 笔</span>
            </div>
            <span class="text-[11px]" style="color: var(--text-muted);">国家秘密法法定标志 · 红头公文字号 · 高危外联阻断</span>
          </div>

          <div class="flex-1 overflow-auto custom-scrollbar">
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
            <button @click="fetchDeepEngines" class="ui-btn-secondary px-2 py-0.5 text-[11px]">
              <AppIcon name="refresh" :size="11" />
              <span>刷新</span>
            </button>
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
            placeholder='追加 DSL 规则: alert tcp any any -> any 502 (msg:"Custom Modbus Alert"; content:"|00 00|"; sid:900901; rev:1;)'
            class="ui-input w-full p-2 font-mono text-[11px] resize-none"
          ></textarea>
          <button @click="loadCustomSuricataRules" :disabled="!suricataRuleInput.trim()" class="ui-btn-primary w-full py-1.5 text-xs justify-center">
            热编译并装载 Suricata 规则
          </button>
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

const suricataMetrics = ref<SuricataDslMetrics | null>(null);
const suricataRuleInput = ref('');
const glushkovMetrics = ref<GlushkovEngineMetrics | null>(null);
const glushkovTestHex = ref('');
const glushkovScanMatches = ref<GlushkovMatch[]>([]);
const auditScriptSource = ref('');
const auditScriptHex = ref('');
const auditScriptResult = ref<ScriptExecutionSummary | null>(null);

async function fetchDeepEngines() {
  try {
    const [suri, glu] = await Promise.all([
      invoke<SuricataDslMetrics>('get_suricata_dsl_metrics_cmd'),
      invoke<GlushkovEngineMetrics>('get_glushkov_engine_metrics_cmd'),
    ]);
    suricataMetrics.value = suri;
    glushkovMetrics.value = glu;
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
