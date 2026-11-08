<template>
  <div class="h-full flex flex-col gap-2.5 overflow-hidden font-sans">
    
    <!-- 1. 顶部操作栏与四维态势核心指标看板 (Top Header & Action Bar) -->
    <section class="glass-surface backdrop-blur-2xl rounded-2xl border border-white/10 p-3 shadow-xl text-slate-200 shrink-0 flex flex-col gap-2.5">
      
      <!-- 1.1 标题与工具操作区 -->
      <div class="flex items-center justify-between gap-3">
        <div class="flex items-center gap-2.5">
          <div class="w-8 h-8 rounded-xl bg-indigo-600/10 text-indigo-600 flex items-center justify-center border border-indigo-500/20 shadow-2xs">
            <svg class="w-4 h-4 fill-none stroke-current stroke-2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
            </svg>
          </div>
          <div>
            <div class="flex items-center gap-2">
              <h2 class="text-xs font-bold text-white tracking-tight">四维合规安全审查与数据脱敏清洗工作台</h2>
              <span class="px-1.5 py-0.5 rounded-full text-[9px] font-mono bg-indigo-500/10 text-indigo-700 border border-indigo-500/20 font-bold">
                GB/T 22239 等保三级 · GB/T 43697 · 国家秘密法
              </span>
            </div>
            <p class="text-[10px] text-slate-400 font-mono mt-0.5">
              工控越权写指令 · DNS/ICMP 隐蔽隧道 · PII 分类分级 · 涉密红头公文 · 闭环逆向零残余脱敏
            </p>
          </div>
        </div>

        <div class="flex items-center gap-2">
          <!-- 一键出具综合勘验报告按钮 -->
          <button @click="generateComprehensiveReport" :disabled="isGeneratingReport"
            class="px-2.5 py-1.5 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white text-[11px] font-medium flex items-center gap-1.5 transition-all cursor-pointer shadow-xs disabled:opacity-50">
            <svg class="w-3.5 h-3.5 fill-none stroke-current stroke-2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
            </svg>
            <span>{{ isGeneratingReport ? '生成报告中...' : '出具综合勘验技术报告' }}</span>
          </button>

          <!-- 刷新全部数据 -->
          <button @click="refreshAllData"
            class="px-2.5 py-1.5 rounded-xl bg-white/5 hover:bg-white/10 text-slate-300 hover:text-white text-[11px] font-medium flex items-center gap-1.5 transition-all cursor-pointer border border-white/10 shadow-2xs">
            <svg class="w-3.5 h-3.5 fill-none stroke-current stroke-2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182m0-4.991v4.99" />
            </svg>
            <span>刷新审查底账</span>
          </button>

          <!-- 清空当前底账数据 -->
          <button @click="clearCurrentAuditRecords"
            class="px-2.5 py-1.5 rounded-xl bg-rose-50 hover:bg-rose-100 text-rose-700 text-[11px] font-medium flex items-center gap-1 transition-all cursor-pointer border border-rose-200/60 shadow-2xs">
            <svg class="w-3.5 h-3.5 fill-none stroke-current stroke-2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 013.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0" />
            </svg>
            <span>清空审计记录</span>
          </button>
        </div>
      </div>

      <!-- 1.2 四大审查维度核心指标卡片 -->
      <div class="grid grid-cols-4 gap-2.5">
        <!-- 维度 1: 网络安全审查 -->
        <div @click="activeTab = 'network'"
          :class="[
            'p-2.5 rounded-xl border transition-all cursor-pointer flex items-center justify-between',
            activeTab === 'network' ? 'bg-blue-500/10 border-blue-500/30 shadow-xs' : 'bg-slate-900/60 border-white/10 hover:bg-slate-800/60'
          ]">
          <div>
            <div class="text-[10px] font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1.5">
              <span class="w-1.5 h-1.5 rounded-full bg-blue-500"></span>
              <span>1. 网络安全审查</span>
            </div>
            <div class="text-base font-mono font-bold text-white mt-0.5">
              {{ networkStats.total_events.toLocaleString() }} <span class="text-[10px] font-normal text-slate-400">起违规事件</span>
            </div>
            <div class="text-[9px] font-mono text-slate-400 mt-0.5">
              工控越权 {{ networkStats.industrial_write_violations }} · DNS隧道 {{ networkStats.dns_tunnel_count }}
            </div>
          </div>
          <div class="text-right">
            <span class="px-1.5 py-0.5 rounded text-[9px] font-bold"
              :class="networkStats.total_events > 0 ? 'bg-amber-100 text-amber-800' : 'bg-emerald-100 text-emerald-800'">
              {{ networkStats.total_events > 0 ? '需核验' : '正常受控' }}
            </span>
          </div>
        </div>

        <!-- 维度 2: 数据安全审查 -->
        <div @click="activeTab = 'data_sec'"
          :class="[
            'p-2.5 rounded-xl border transition-all cursor-pointer flex items-center justify-between',
            activeTab === 'data_sec' ? 'bg-indigo-500/10 border-indigo-500/30 shadow-xs' : 'bg-slate-900/60 border-white/10 hover:bg-slate-800/60'
          ]">
          <div>
            <div class="text-[10px] font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1.5">
              <span class="w-1.5 h-1.5 rounded-full bg-indigo-500"></span>
              <span>2. 数据安全审查</span>
            </div>
            <div class="text-base font-mono font-bold text-white mt-0.5">
              {{ dataSecSummary.total_sensitive_hits.toLocaleString() }} <span class="text-[10px] font-normal text-slate-400">笔敏感命中</span>
            </div>
            <div class="text-[9px] font-mono text-slate-400 mt-0.5">
              核心 {{ dataSecSummary.core_data_hits }} · 重要 {{ dataSecSummary.important_data_hits }} · PII {{ dataSecSummary.pii_hits }}
            </div>
          </div>
          <div class="text-right">
            <span class="px-1.5 py-0.5 rounded text-[9px] font-bold"
              :class="dataSecSummary.total_sensitive_hits > 0 ? 'bg-rose-100 text-rose-800' : 'bg-emerald-100 text-emerald-800'">
              {{ dataSecSummary.total_sensitive_hits > 0 ? '检出泄露' : '未见明文' }}
            </span>
          </div>
        </div>

        <!-- 维度 3: 保密安全审查 -->
        <div @click="activeTab = 'confidential'"
          :class="[
            'p-2.5 rounded-xl border transition-all cursor-pointer flex items-center justify-between',
            activeTab === 'confidential' ? 'bg-amber-500/10 border-amber-500/30 shadow-xs' : 'bg-slate-900/60 border-white/10 hover:bg-slate-800/60'
          ]">
          <div>
            <div class="text-[10px] font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1.5">
              <span class="w-1.5 h-1.5 rounded-full bg-amber-500"></span>
              <span>3. 保密安全审查</span>
            </div>
            <div class="text-base font-mono font-bold text-white mt-0.5">
              {{ confidentialityAlerts.length.toLocaleString() }} <span class="text-[10px] font-normal text-slate-400">次定密与外联告警</span>
            </div>
            <div class="text-[9px] font-mono text-slate-400 mt-0.5">
              涉密公文特征 · 红头发文字号 · 违规外联
            </div>
          </div>
          <div class="text-right">
            <span class="px-1.5 py-0.5 rounded text-[9px] font-bold"
              :class="confidentialityAlerts.length > 0 ? 'bg-rose-100 text-rose-800' : 'bg-emerald-100 text-emerald-800'">
              {{ confidentialityAlerts.length > 0 ? '密级预警' : '合规受控' }}
            </span>
          </div>
        </div>

        <!-- 维度 4: 数据脱敏清洗审查 -->
        <div @click="activeTab = 'sanitizer'"
          :class="[
            'p-2.5 rounded-xl border transition-all cursor-pointer flex items-center justify-between',
            activeTab === 'sanitizer' ? 'bg-emerald-500/10 border-emerald-500/30 shadow-xs' : 'bg-slate-900/60 border-white/10 hover:bg-slate-800/60'
          ]">
          <div>
            <div class="text-[10px] font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1.5">
              <span class="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
              <span>4. 脱敏清洗审查</span>
            </div>
            <div class="text-base font-mono font-bold text-white mt-0.5">
              {{ sanitizationPolicies.length }} <span class="text-[10px] font-normal text-slate-400">套标准策略模板</span>
            </div>
            <div class="text-[9px] font-mono text-slate-400 mt-0.5">
              闭环逆向复测 · 出具密码学防篡改凭单
            </div>
          </div>
          <div class="text-right">
            <span class="px-1.5 py-0.5 rounded text-[9px] font-bold bg-emerald-100 text-emerald-800">
              闭环验证就绪
            </span>
          </div>
        </div>
      </div>
    </section>

    <!-- 2. 主视口：四大维度微胶囊标签页内容 (Segmented Views) -->
    <div class="flex-1 overflow-hidden flex flex-col min-h-0 glass-surface backdrop-blur-2xl rounded-2xl border border-white/10 p-3 shadow-xl text-slate-200">
      
      <!-- 2.0 标签页微胶囊导航切换器 -->
      <div class="flex items-center justify-between border-b border-white/10 pb-2 mb-2.5 shrink-0">
        <div class="flex items-center gap-1 bg-black/60 p-1 rounded-xl border border-white/10">
          <button @click="activeTab = 'network'"
            :class="[
              'px-3 py-1 rounded-lg text-xs font-bold transition-all cursor-pointer flex items-center gap-1.5',
              activeTab === 'network' ? 'bg-white text-blue-700 shadow-2xs' : 'text-slate-600 hover:text-slate-900'
            ]">
            <span>网络安全审查</span>
            <span class="px-1 py-0.2 rounded-full text-[9px] bg-slate-200 text-slate-700">{{ networkEvents.length }}</span>
          </button>

          <button @click="activeTab = 'data_sec'"
            :class="[
              'px-3 py-1 rounded-lg text-xs font-bold transition-all cursor-pointer flex items-center gap-1.5',
              activeTab === 'data_sec' ? 'bg-white text-indigo-700 shadow-2xs' : 'text-slate-600 hover:text-slate-900'
            ]">
            <span>数据安全审查 (分类分级)</span>
            <span class="px-1 py-0.2 rounded-full text-[9px] bg-slate-200 text-slate-700">{{ sensitiveFindings.length }}</span>
          </button>

          <button @click="activeTab = 'confidential'"
            :class="[
              'px-3 py-1 rounded-lg text-xs font-bold transition-all cursor-pointer flex items-center gap-1.5',
              activeTab === 'confidential' ? 'bg-white text-amber-700 shadow-2xs' : 'text-slate-600 hover:text-slate-900'
            ]">
            <span>保密安全审查 (法定公文)</span>
            <span class="px-1 py-0.2 rounded-full text-[9px] bg-slate-200 text-slate-700">{{ confidentialityAlerts.length }}</span>
          </button>

          <button @click="activeTab = 'sanitizer'"
            :class="[
              'px-3 py-1 rounded-lg text-xs font-bold transition-all cursor-pointer flex items-center gap-1.5',
              activeTab === 'sanitizer' ? 'bg-white text-emerald-700 shadow-2xs' : 'text-slate-600 hover:text-slate-900'
            ]">
            <span>数据脱敏清洗与闭环核验证</span>
            <span class="px-1 py-0.2 rounded-full text-[9px] bg-emerald-100 text-emerald-800">ISO/GB</span>
          </button>
        </div>

        <!-- 当前标签页上下文微说明 -->
        <div class="text-[11px] font-mono text-slate-400">
          <span v-if="activeTab === 'network'">检测 Modbus/S7/SL651 越权写指令、DNS 信息熵香农隧道 (H>4.2)、ICMP 隐匿通道</span>
          <span v-else-if="activeTab === 'data_sec'">GB/T 43697 数据四级分类分级、身份证 ISO 7064 与银行卡 Luhn 算法真值校验</span>
          <span v-else-if="activeTab === 'confidential'">Aho-Corasick 多模式自动机扫描法定绝密/机密/秘密标密词与红头发文字号</span>
          <span v-else-if="activeTab === 'sanitizer'">提供掩码脱敏、HMAC-SHA256 假名化及脱敏后敏感零残余二次逆向复测</span>
        </div>
      </div>

      <!-- ======================================================== -->
      <!-- TAB 1: 网络安全审查 (工控指令越权 / DNS隐蔽隧道 / ICMP载荷) -->
      <!-- ======================================================== -->
      <div v-if="activeTab === 'network'" class="flex-1 overflow-hidden flex flex-col gap-2 min-h-0">
        <!-- 过滤器与统计指示栏 -->
        <div class="flex items-center justify-between gap-2 shrink-0">
          <div class="flex items-center gap-1.5 text-xs">
            <span class="text-slate-500 font-medium">事件过滤:</span>
            <button v-for="t in networkEventFilterOptions" :key="t.key" @click="networkFilterType = t.key"
              :class="[
                'px-2 py-0.5 rounded-md text-[11px] font-medium transition-all cursor-pointer',
                networkFilterType === t.key ? 'bg-slate-800 text-white shadow-2xs' : 'bg-slate-100 hover:bg-slate-200 text-slate-600'
              ]">
              {{ t.label }}
            </button>
          </div>
          <span class="text-[11px] font-mono text-slate-400">共显示 {{ filteredNetworkEvents.length }} 笔网络安全事件</span>
        </div>

        <!-- 工业专有与长尾长规约解包插件生态状态栏 -->
        <div class="px-3 py-2 rounded-xl bg-slate-900/60 border border-white/10 flex items-center justify-between gap-3 text-xs shrink-0 shadow-2xs">
          <div class="flex items-center gap-2">
            <span class="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            <span class="font-bold text-slate-700">工控专有与长尾解包插件生态:</span>
            <span class="font-mono text-slate-500 text-[11px]">已装载 {{ industrialPlugins.length }} 种原生/声明式解包器 (SEMI HSMS、横河 Vnet/IP、霍尼韦尔 FTE、施耐德 UMAS、倍福 ADS 等)</span>
          </div>
          <button @click="showPluginDrawer = !showPluginDrawer"
            class="px-2 py-0.5 rounded-lg bg-indigo-50 hover:bg-indigo-100 text-indigo-700 font-medium text-[11px] border border-indigo-200/60 transition-all cursor-pointer flex items-center gap-1">
            <span>{{ showPluginDrawer ? '收起解包器清单' : '查看已载入解包插件' }}</span>
            <svg class="w-3 h-3 transition-transform" :class="showPluginDrawer ? 'rotate-180' : ''" viewBox="0 0 20 20" fill="currentColor">
              <path fill-rule="evenodd" d="M5.23 7.21a.75.75 0 011.06.02L10 11.168l3.71-3.938a.75.75 0 111.08 1.04l-4.25 4.5a.75.75 0 01-1.08 0l-4.25-4.5a.75.75 0 01.02-1.06z" clip-rule="evenodd" />
            </svg>
          </button>
        </div>

        <!-- 解包器详情抽屉 -->
        <div v-if="showPluginDrawer" class="p-3 bg-white border border-slate-200/80 rounded-xl shadow-xs grid grid-cols-2 md:grid-cols-5 gap-2 shrink-0 max-h-48 overflow-y-auto custom-scrollbar">
          <div v-for="plug in industrialPlugins" :key="plug.id"
            class="p-2 rounded-lg border border-slate-100 bg-slate-50/50 flex flex-col justify-between text-[10px]">
            <div>
              <div class="flex items-center justify-between gap-1 mb-1">
                <span class="font-bold text-slate-100 truncate" :title="plug.name">{{ plug.name }}</span>
                <span class="px-1 py-0.2 rounded text-[8px] font-mono shrink-0"
                  :class="plug.plugin_type === 'NATIVE_RUST_CORE' ? 'bg-indigo-100 text-indigo-800' : 'bg-emerald-100 text-emerald-800'">
                  {{ plug.plugin_type === 'NATIVE_RUST_CORE' ? 'Rust内核' : 'JSON扩展' }}
                </span>
              </div>
              <div class="text-slate-500 truncate" :title="plug.vendor">厂商: {{ plug.vendor }}</div>
              <div class="text-slate-400 font-mono mt-0.5">端口: {{ plug.default_ports?.join(', ') || '任意' }}</div>
            </div>
            <div class="mt-1 pt-1 border-t border-slate-200/50 flex items-center justify-between text-slate-400">
              <span class="truncate" :title="plug.category">{{ plug.category }}</span>
              <span class="text-rose-600 font-mono font-medium shrink-0">越权审计</span>
            </div>
          </div>
        </div>

        <!-- 事件列表表格 (有界滚动) -->
        <div class="flex-1 overflow-auto custom-scrollbar border border-white/10 rounded-xl glass-surface">
          <table class="w-full text-left text-xs border-collapse">
            <thead class="bg-black/40 text-slate-400 font-mono text-[10px] sticky top-0 z-10 border-b border-white/10">
              <tr>
                <th class="py-2 px-3">事件 ID</th>
                <th class="py-2 px-3">时间戳</th>
                <th class="py-2 px-3">事件分类</th>
                <th class="py-2 px-3">危害等级</th>
                <th class="py-2 px-3">通信双方 (源 ➔ 宿)</th>
                <th class="py-2 px-3">规约/协议</th>
                <th class="py-2 px-3">技术勘验摘要与判定依据</th>
                <th class="py-2 px-3 text-right">操作</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-100 font-mono text-[11px]">
              <tr v-for="evt in filteredNetworkEvents" :key="evt.id" class="hover:bg-blue-50/40 transition-colors">
                <td class="py-2 px-3 text-slate-500">#{{ evt.id }}</td>
                <td class="py-2 px-3 text-slate-600 whitespace-nowrap">{{ evt.timestamp }}</td>
                <td class="py-2 px-3">
                  <span class="px-1.5 py-0.5 rounded text-[10px] font-bold"
                    :class="{
                      'bg-purple-100 text-purple-800': evt.event_type === 'INDUSTRIAL_WRITE_VIOLATION',
                      'bg-rose-100 text-rose-800': evt.event_type === 'DNS_COVERT_TUNNEL',
                      'bg-amber-100 text-amber-800': evt.event_type === 'ICMP_COVERT_TUNNEL',
                      'bg-blue-100 text-blue-800': evt.event_type === 'CROSS_ZONE_VIOLATION',
                    }">
                    {{ formatNetworkEventType(evt.event_type) }}
                  </span>
                </td>
                <td class="py-2 px-3">
                  <span class="px-1.5 py-0.5 rounded text-[9px] font-bold"
                    :class="{
                      'bg-rose-600 text-white': evt.severity === 'CRITICAL',
                      'bg-amber-500 text-white': evt.severity === 'HIGH',
                      'bg-yellow-400 text-yellow-900': evt.severity === 'MEDIUM',
                      'bg-slate-200 text-slate-700': evt.severity === 'LOW',
                    }">
                    {{ evt.severity }}
                  </span>
                </td>
                <td class="py-2 px-3 whitespace-nowrap">
                  <span class="text-slate-800 font-bold">{{ evt.src_ip }}:{{ evt.src_port }}</span>
                  <span class="text-slate-400 mx-1">➔</span>
                  <span class="text-slate-800 font-bold">{{ evt.dst_ip }}:{{ evt.dst_port }}</span>
                </td>
                <td class="py-2 px-3 font-bold text-slate-700">{{ evt.protocol }}</td>
                <td class="py-2 px-3 text-slate-700 max-w-md truncate" :title="evt.summary">
                  {{ evt.summary }}
                </td>
                <td class="py-2 px-3 text-right whitespace-nowrap space-x-1.5">
                  <button @click="blockIpAddress(evt.src_ip, evt.summary)"
                    class="px-2 py-0.5 rounded bg-rose-50 hover:bg-rose-100 text-rose-700 text-[10px] font-bold border border-rose-200/80 transition-all cursor-pointer">
                    一键阻断
                  </button>
                  <button @click="selectedDetailJson = evt.detail_json; isDetailModalOpen = true"
                    class="px-2 py-0.5 rounded bg-slate-100 hover:bg-slate-200 text-slate-700 text-[10px] transition-all cursor-pointer">
                    勘验 JSON
                  </button>
                </td>
              </tr>
              <tr v-if="filteredNetworkEvents.length === 0">
                <td colspan="8" class="text-center py-12 text-slate-400 font-sans">
                  <div class="flex flex-col items-center justify-center gap-1.5">
                    <svg class="w-8 h-8 text-slate-300 stroke-current fill-none" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <span>暂无捕获到越权工控指令或隐蔽隧道网络安全事件</span>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- ======================================================== -->
      <!-- TAB 2: 数据安全审查 (GB/T 43697 分类分级 / PII / 流式还原文件) -->
      <!-- ======================================================== -->
      <div v-else-if="activeTab === 'data_sec'" class="flex-1 overflow-hidden flex flex-col gap-2.5 min-h-0">
        <!-- 分类分级多维概览指示条 -->
        <div class="grid grid-cols-4 gap-2 shrink-0">
          <div class="p-2 rounded-xl bg-rose-50/70 border border-rose-200/60 flex items-center justify-between">
            <div>
              <div class="text-[9px] font-bold text-rose-700 uppercase">核心数据 (最高防护等级)</div>
              <div class="text-sm font-mono font-bold text-rose-900 mt-0.5">
                {{ dataSecSummary.core_data_hits }} <span class="text-[9px] font-normal">笔</span>
              </div>
            </div>
            <span class="text-[10px] font-mono text-rose-600 bg-rose-100 px-1 rounded">L4</span>
          </div>

          <div class="p-2 rounded-xl bg-amber-50/70 border border-amber-200/60 flex items-center justify-between">
            <div>
              <div class="text-[9px] font-bold text-amber-700 uppercase">重要数据 (关键业务载荷)</div>
              <div class="text-sm font-mono font-bold text-amber-900 mt-0.5">
                {{ dataSecSummary.important_data_hits }} <span class="text-[9px] font-normal">笔</span>
              </div>
            </div>
            <span class="text-[10px] font-mono text-amber-600 bg-amber-100 px-1 rounded">L3</span>
          </div>

          <div class="p-2 rounded-xl bg-indigo-50/70 border border-indigo-200/60 flex items-center justify-between">
            <div>
              <div class="text-[9px] font-bold text-indigo-700 uppercase">敏感个人信息 (PII 严格校验)</div>
              <div class="text-sm font-mono font-bold text-indigo-900 mt-0.5">
                {{ dataSecSummary.pii_hits }} <span class="text-[9px] font-normal">笔</span>
              </div>
            </div>
            <span class="text-[10px] font-mono text-indigo-600 bg-indigo-100 px-1 rounded">PII</span>
          </div>

          <div class="p-2 rounded-xl bg-slate-50/70 border border-slate-200/60 flex items-center justify-between">
            <div>
              <div class="text-[9px] font-bold text-slate-700 uppercase">会话流式还原文件</div>
              <div class="text-sm font-mono font-bold text-slate-900 mt-0.5">
                {{ reconstructedFiles.length }} <span class="text-[9px] font-normal">个检材</span>
              </div>
            </div>
            <span class="text-[10px] font-mono text-slate-600 bg-slate-200 px-1 rounded">MIME</span>
          </div>
        </div>

        <!-- 敏感信息检出流水与还原文件双切分栏 -->
        <div class="flex-1 grid grid-cols-2 gap-2.5 overflow-hidden min-h-0">
          <!-- 左侧：敏感数据明细列表 -->
          <div class="border border-white/10 rounded-xl overflow-hidden flex flex-col glass-surface">
            <div class="p-2 bg-black/30 border-b border-white/10 text-xs font-bold text-slate-200 flex items-center justify-between shrink-0">
              <span>敏感数据流动流水 ({{ sensitiveFindings.length }})</span>
              <span class="text-[10px] font-mono text-slate-400">GB/T 43697 规则</span>
            </div>
            <div class="flex-1 overflow-auto custom-scrollbar">
              <table class="w-full text-left text-xs border-collapse">
                <thead class="bg-black/40 text-slate-400 font-mono text-[10px] sticky top-0 border-b border-white/10">
                  <tr>
                    <th class="py-1.5 px-2.5">规则分类</th>
                    <th class="py-1.5 px-2.5">通信端点</th>
                    <th class="py-1.5 px-2.5">脱敏样本预览</th>
                    <th class="py-1.5 px-2.5">判定依据</th>
                    <th class="py-1.5 px-2.5 text-right">操作</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-slate-100 font-mono text-[11px]">
                  <tr v-for="item in sensitiveFindings" :key="item.id" class="hover:bg-slate-50">
                    <td class="py-1.5 px-2.5 whitespace-nowrap">
                      <span class="font-bold text-slate-800">{{ item.rule_name }}</span>
                      <div class="text-[9px] text-slate-400">{{ item.category_code }}</div>
                    </td>
                    <td class="py-1.5 px-2.5 whitespace-nowrap text-slate-600">
                      {{ item.src_ip }} ➔ {{ item.dst_ip }}
                    </td>
                    <td class="py-1.5 px-2.5 font-bold text-indigo-700 whitespace-nowrap">
                      {{ item.matched_sample_masked }}
                    </td>
                    <td class="py-1.5 px-2.5 text-slate-500 text-[10px] max-w-xs truncate" :title="item.context_summary">
                      {{ item.context_summary }}
                    </td>
                    <td class="py-1.5 px-2.5 text-right whitespace-nowrap">
                      <button @click="inspectFindingDetail(item)"
                        class="px-2 py-0.5 rounded bg-indigo-50 hover:bg-indigo-100 text-indigo-700 text-[10px] transition-all cursor-pointer">
                        勘验详情
                      </button>
                    </td>
                  </tr>
                  <tr v-if="sensitiveFindings.length === 0">
                    <td colspan="5" class="text-center py-8 text-slate-400 font-sans">
                      未检出符合触发条件的敏感数据流明文
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <!-- 右侧：会话流式还原文件清单 -->
          <div class="border border-white/10 rounded-xl overflow-hidden flex flex-col glass-surface">
            <div class="p-2 bg-black/30 border-b border-white/10 text-xs font-bold text-slate-200 flex items-center justify-between shrink-0">
              <span>会话流式还原与传输载荷文件 ({{ reconstructedFiles.length }})</span>
              <span class="text-[10px] font-mono text-slate-400">10MB 有界截断</span>
            </div>
            <div class="flex-1 overflow-auto custom-scrollbar">
              <table class="w-full text-left text-xs border-collapse">
                <thead class="bg-black/40 text-slate-400 font-mono text-[10px] sticky top-0 border-b border-white/10">
                  <tr>
                    <th class="py-1.5 px-2.5">还原文件名</th>
                    <th class="py-1.5 px-2.5">MIME 类型</th>
                    <th class="py-1.5 px-2.5">体积大小</th>
                    <th class="py-1.5 px-2.5">密级判定</th>
                    <th class="py-1.5 px-2.5">SHA256 哈希</th>
                    <th class="py-1.5 px-2.5 text-right">操作</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-slate-100 font-mono text-[11px]">
                  <tr v-for="f in reconstructedFiles" :key="f.id" class="hover:bg-slate-50">
                    <td class="py-1.5 px-2.5 font-bold text-slate-800 whitespace-nowrap">
                      {{ f.filename }}
                    </td>
                    <td class="py-1.5 px-2.5 text-slate-500 text-[10px]">{{ f.mime_type }}</td>
                    <td class="py-1.5 px-2.5 text-slate-700 whitespace-nowrap">{{ formatBytes(f.size_bytes) }}</td>
                    <td class="py-1.5 px-2.5">
                      <span class="px-1.5 py-0.5 rounded text-[9px] font-bold"
                        :class="f.classification === 'CORE_DATA' ? 'bg-rose-100 text-rose-800' : 'bg-blue-100 text-blue-800'">
                        {{ f.classification }}
                      </span>
                    </td>
                    <td class="py-1.5 px-2.5 font-mono text-[9px] text-slate-400 truncate max-w-[120px]" :title="f.sha256_hash">
                      {{ f.sha256_hash.substring(0, 16) }}...
                    </td>
                    <td class="py-1.5 px-2.5 text-right whitespace-nowrap">
                      <button @click="inspectFileDetail(f)"
                        class="px-2 py-0.5 rounded bg-slate-100 hover:bg-slate-200 text-slate-700 text-[10px] transition-all cursor-pointer">
                        检材详情
                      </button>
                    </td>
                  </tr>
                  <tr v-if="reconstructedFiles.length === 0">
                    <td colspan="6" class="text-center py-8 text-slate-400 font-sans">
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
      <!-- TAB 3: 保密安全审查 (法定标密公文 / 红头发文字号 / 违规外联 / 静态扫描) -->
      <!-- ======================================================== -->
      <div v-else-if="activeTab === 'confidential'" class="flex-1 overflow-hidden flex flex-col gap-2.5 min-h-0">
        <!-- 上半部分：保密告警流水表 -->
        <div class="h-1/2 border border-white/10 rounded-xl overflow-hidden flex flex-col glass-surface shrink-0">
          <div class="p-2 bg-black/30 border-b border-white/10 text-xs font-bold text-slate-200 flex items-center justify-between shrink-0">
            <div class="flex items-center gap-1.5">
              <span>涉密公文与违规外联安全警报流水</span>
              <span class="px-1.5 py-0.2 rounded-full text-[9px] bg-rose-100 text-rose-800 font-mono font-bold">{{ confidentialityAlerts.length }} 笔</span>
            </div>
            <span class="text-[10px] font-mono text-slate-400">国家秘密法法定标志 · 红头公文字号 · 高危外联阻断</span>
          </div>

          <div class="flex-1 overflow-auto custom-scrollbar">
            <table class="w-full text-left text-xs border-collapse">
              <thead class="bg-black/40 text-slate-400 font-mono text-[10px] sticky top-0 border-b border-white/10">
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
              <tbody class="divide-y divide-slate-100 font-mono text-[11px]">
                <tr v-for="alt in confidentialityAlerts" :key="alt.id" class="hover:bg-amber-50/40">
                  <td class="py-2 px-3 text-slate-500">#{{ alt.id }}</td>
                  <td class="py-2 px-3 text-slate-600 whitespace-nowrap">{{ alt.timestamp }}</td>
                  <td class="py-2 px-3 font-bold text-slate-800">{{ alt.alert_category }}</td>
                  <td class="py-2 px-3">
                    <span class="px-1.5 py-0.5 rounded text-[10px] font-bold"
                      :class="{
                        'bg-rose-700 text-white': alt.secrecy_level === 'TOP_SECRET',
                        'bg-rose-500 text-white': alt.secrecy_level === 'CONFIDENTIAL',
                        'bg-amber-500 text-white': alt.secrecy_level === 'SECRET',
                        'bg-slate-200 text-slate-700': alt.secrecy_level === 'HIGH_RISK' || alt.secrecy_level === 'INTERNAL'
                      }">
                      {{ alt.secrecy_level }}
                    </span>
                  </td>
                  <td class="py-2 px-3 font-bold text-rose-700 whitespace-nowrap">{{ alt.target_entity }}</td>
                  <td class="py-2 px-3 text-slate-700 max-w-lg truncate" :title="alt.summary">{{ alt.summary }}</td>
                  <td class="py-2 px-3 text-right whitespace-nowrap space-x-1.5">
                    <button v-if="alt.alert_category === 'ILLEGAL_EGRESS'"
                      @click="blockEgressTarget(alt.target_entity, alt.summary)"
                      class="px-2 py-0.5 rounded bg-rose-50 hover:bg-rose-100 text-rose-700 text-[10px] font-bold border border-rose-200/80 transition-all cursor-pointer">
                      阻断外联
                    </button>
                    <button @click="selectedDetailJson = alt.detail_json; isDetailModalOpen = true"
                      class="px-2 py-0.5 rounded bg-slate-100 hover:bg-slate-200 text-slate-700 text-[10px] transition-all cursor-pointer">
                      勘验 JSON
                    </button>
                  </td>
                </tr>
                <tr v-if="confidentialityAlerts.length === 0">
                  <td colspan="7" class="text-center py-8 text-slate-400 font-sans">
                    网络通信与硬件总线暂未触发涉密合规与违规外联警报
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- 下半部分：即时公文档案保密合规静态扫描器 -->
        <div class="flex-1 border border-slate-200/70 rounded-xl overflow-hidden flex flex-col bg-black/30 p-3 min-h-0">
          <div class="flex items-center justify-between pb-2 border-b border-slate-200/70 shrink-0">
            <div class="flex items-center gap-2">
              <span class="w-2 h-2 rounded-full bg-amber-500"></span>
              <span class="text-xs font-bold text-slate-800">涉密红头公文与文档即时静态扫描验算器</span>
              <span class="text-[10px] font-mono text-slate-400">Aho-Corasick 多模式自动机线性匹配</span>
            </div>
            <button @click="runStaticConfidentialityScan" :disabled="!scanInputText.trim() || isScanningText"
              class="px-3 py-1 rounded-lg bg-amber-600 hover:bg-amber-700 text-white text-xs font-bold transition-all cursor-pointer shadow-xs disabled:opacity-50">
              {{ isScanningText ? '扫描验算中...' : '立即执行保密静态扫描' }}
            </button>
          </div>

          <div class="flex-1 grid grid-cols-2 gap-3 pt-2.5 overflow-hidden min-h-0">
            <!-- 文本输入框 -->
            <div class="flex flex-col min-h-0">
              <label class="text-[10px] font-bold text-slate-500 mb-1">待验算公文档案 / 邮件草稿 / 代码或文本载荷:</label>
              <textarea v-model="scanInputText"
                placeholder="粘贴待审查的公文草稿文本、发文通知或通信载荷... 例如：国务院办公厅发[2024]12号通知，本件属于机密★20年..."
                class="flex-1 w-full p-2.5 rounded-xl border border-slate-200 bg-white font-mono text-xs focus:ring-2 focus:ring-amber-500/30 focus:border-amber-500 outline-none resize-none custom-scrollbar"></textarea>
            </div>

            <!-- 扫描报告出具区 -->
            <div class="flex flex-col min-h-0 bg-white rounded-xl border border-slate-200 p-2.5 overflow-auto custom-scrollbar">
              <div class="text-[10px] font-bold text-slate-500 mb-1 flex items-center justify-between">
                <span>保密合规技术审查勘验结论:</span>
                <span v-if="confidentialScanResult" class="font-mono text-slate-400">检材体积: {{ confidentialScanResult.scanned_bytes }} 字节</span>
              </div>

              <div v-if="confidentialScanResult" class="space-y-2 text-xs">
                <div class="p-2 rounded-lg" :class="confidentialScanResult.is_secret ? 'bg-rose-50 border border-rose-200 text-rose-800' : 'bg-emerald-50 border border-emerald-200 text-emerald-800'">
                  <div class="font-bold flex items-center gap-1.5">
                    <span>{{ confidentialScanResult.is_secret ? '⚠️ 检出涉密与红头特征' : '✅ 未见标密违规特征' }}</span>
                    <span v-if="confidentialScanResult.is_secret" class="px-1.5 py-0.2 rounded text-[10px] bg-rose-200 text-rose-900 font-mono">
                      最高定密等级: {{ confidentialScanResult.highest_level }}
                    </span>
                  </div>
                  <p class="text-[11px] mt-1">{{ confidentialScanResult.recommendation }}</p>
                </div>

                <div v-if="confidentialScanResult.hit_markers.length > 0">
                  <div class="text-[10px] font-bold text-slate-400 uppercase">命中法定秘密标识:</div>
                  <div class="flex flex-wrap gap-1 mt-1">
                    <span v-for="m in confidentialScanResult.hit_markers" :key="m"
                      class="px-2 py-0.5 rounded-md bg-rose-100 text-rose-800 font-mono font-bold text-[10px]">
                      {{ m }}
                    </span>
                  </div>
                </div>

                <div v-if="confidentialScanResult.document_signatures.length > 0">
                  <div class="text-[10px] font-bold text-slate-400 uppercase">命中红头公文发文字号:</div>
                  <div class="flex flex-wrap gap-1 mt-1">
                    <span v-for="s in confidentialScanResult.document_signatures" :key="s"
                      class="px-2 py-0.5 rounded-md bg-amber-100 text-amber-800 font-mono font-bold text-[10px]">
                      {{ s }}
                    </span>
                  </div>
                </div>
              </div>

              <div v-else class="flex-1 flex flex-col items-center justify-center text-slate-400 text-xs font-sans">
                <span>在左侧粘贴文本并点击“立即执行保密静态扫描”</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- ======================================================== -->
      <!-- TAB 4: 数据脱敏清洗审查与闭环“零残余”验证 -->
      <!-- ======================================================== -->
      <div v-else-if="activeTab === 'sanitizer'" class="flex-1 overflow-hidden flex flex-col gap-2.5 min-h-0">
        <!-- 上栏：策略选择与参数配置 -->
        <div class="flex items-center justify-between gap-3 bg-black/40 p-2.5 rounded-xl border border-white/10 shrink-0">
          <div class="flex items-center gap-2">
            <span class="text-xs font-bold text-slate-200">脱敏标准策略:</span>
            <select v-model="selectedPolicyId"
              class="px-2.5 py-1 rounded-lg border border-slate-300 bg-white text-xs font-medium text-slate-800 outline-none">
              <option v-for="p in sanitizationPolicies" :key="p.policy_id" :value="p.policy_id">
                {{ p.name }} ({{ p.policy_id }})
              </option>
            </select>
          </div>

          <div class="flex items-center gap-2">
            <span class="text-xs font-bold text-slate-200">确定性散列加盐 (Salt):</span>
            <input v-model="hmacSalt" placeholder="默认工业主盐值..."
              class="px-2 py-1 rounded-lg border border-slate-300 bg-white font-mono text-xs w-48 outline-none" />
          </div>

          <button @click="executeSanitization" :disabled="!rawSanitizeText.trim() || isSanitizing"
            class="px-3.5 py-1.5 rounded-xl bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-bold transition-all cursor-pointer shadow-xs disabled:opacity-50">
            {{ isSanitizing ? '清洗脱敏中...' : '执行工业级脱敏清洗' }}
          </button>
        </div>

        <!-- 中栏：输入与输出双比对工作台 -->
        <div class="flex-1 grid grid-cols-2 gap-3 overflow-hidden min-h-0">
          <!-- 原始清洗检材输入 -->
          <div class="flex flex-col border border-white/10 rounded-xl p-2.5 glass-surface min-h-0">
            <div class="flex items-center justify-between pb-1.5 mb-1.5 border-b border-slate-100 shrink-0">
              <span class="text-xs font-bold text-slate-200">清洗前原始待脱敏文本:</span>
              <button @click="fillSampleText" class="text-[10px] text-indigo-600 hover:underline cursor-pointer font-bold">
                载入涉密与 PII 综合检材用例
              </button>
            </div>
            <textarea v-model="rawSanitizeText"
              placeholder="在此粘贴包含居民身份证、银行卡、手机号、私钥、涉密公文发文等待脱敏清洗内容..."
              class="flex-1 w-full p-2 rounded-lg font-mono text-xs text-slate-800 border border-slate-100 bg-black/40 text-slate-200 border-white/10 outline-none resize-none custom-scrollbar"></textarea>
          </div>

          <!-- 清洗脱敏成果 -->
          <div class="flex flex-col border border-white/10 rounded-xl p-2.5 glass-surface min-h-0">
            <div class="flex items-center justify-between pb-1.5 mb-1.5 border-b border-slate-100 shrink-0">
              <span class="text-xs font-bold text-slate-200">清洗后脱敏成果 (已处理 {{ sanitizeResult?.matched_replacements_count || 0 }} 处):</span>
              <button v-if="sanitizeResult" @click="copyToClipboard(sanitizeResult.sanitized_content)"
                class="text-[10px] text-emerald-700 hover:underline cursor-pointer font-bold">
                复制脱敏文本
              </button>
            </div>
            <textarea readonly :value="sanitizeResult?.sanitized_content || ''"
              placeholder="脱敏清洗成果将实时在此输出..."
              class="flex-1 w-full p-2 rounded-lg font-mono text-xs text-slate-800 border border-slate-100 bg-emerald-50/20 outline-none resize-none custom-scrollbar"></textarea>
          </div>
        </div>

        <!-- 底栏：脱敏合规审查闭环“零残余”验证卡片 (Highlight Feature) -->
        <div class="p-3 bg-gradient-to-r from-slate-900 to-slate-800 rounded-xl text-white shadow-md flex items-center justify-between shrink-0">
          <div class="space-y-1">
            <div class="flex items-center gap-2">
              <span class="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse"></span>
              <span class="text-xs font-bold tracking-tight">闭环合规验证器 (Sanitization Verifier)</span>
              <span class="text-[9px] font-mono px-1.5 py-0.2 rounded bg-white/20 text-emerald-300 font-bold">零敏感残余逆向复验</span>
            </div>
            <p class="text-[10px] font-mono text-slate-300">
              将清洗后成果自动回灌至数据安全与保密审查引擎进行二次反向探查，当且仅当敏感残余为 0 时出具防篡改审计凭单。
            </p>
          </div>

          <div class="flex items-center gap-3">
            <button @click="verifyComplianceProof" :disabled="!sanitizeResult || isVerifying"
              class="px-3 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-600 text-slate-950 text-xs font-bold transition-all cursor-pointer shadow-xs disabled:opacity-40">
              {{ isVerifying ? '执行逆向复测中...' : '执行闭环合规验证' }}
            </button>
          </div>
        </div>

        <!-- 闭环核验证书卡片展示 -->
        <div v-if="auditProof" class="p-3 bg-emerald-50 border border-emerald-300/80 rounded-xl flex items-center justify-between shrink-0">
          <div class="flex items-center gap-3">
            <div class="w-9 h-9 rounded-xl bg-emerald-600 text-white flex items-center justify-center font-bold text-sm shadow-xs shrink-0">
              ✓
            </div>
            <div>
              <div class="text-xs font-bold text-emerald-950 flex items-center gap-2">
                <span>{{ auditProof.verdict }}</span>
                <span class="text-[10px] font-mono text-emerald-700 bg-emerald-200/60 px-1.5 py-0.2 rounded">
                  凭单 #{{ auditProof.proof_id }}
                </span>
              </div>
              <div class="text-[10px] font-mono text-emerald-800 mt-0.5">
                原始哈希: {{ auditProof.original_sha256.substring(0, 16) }}... ➔ 脱敏后哈希: {{ auditProof.sanitized_sha256.substring(0, 16) }}...
              </div>
            </div>
          </div>
          <div class="text-right text-[10px] font-mono text-emerald-700">
            <div>核验时间: {{ auditProof.verified_at }}</div>
            <div class="font-bold text-emerald-900 mt-0.5">残余敏感特征: {{ auditProof.residual_sensitive_hits }} 处 (完全合规)</div>
          </div>
        </div>
      </div>
    </div>

    <!-- 3. 全局 JSON 详情勘验弹窗 -->
    <div v-if="isDetailModalOpen" class="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 backdrop-blur-xs p-4">
      <div class="glass-surface rounded-2xl border border-white/20 shadow-2xl text-slate-200 w-full max-w-2xl flex flex-col max-h-[85vh] overflow-hidden">
        <div class="p-3 bg-black/40 border-b border-white/10 flex items-center justify-between">
          <h3 class="text-xs font-bold text-slate-800">技术审查证据 JSON 详情</h3>
          <button @click="isDetailModalOpen = false" class="text-slate-400 hover:text-slate-700 text-sm cursor-pointer">✕</button>
        </div>
        <div class="p-3 flex-1 overflow-auto custom-scrollbar font-mono text-xs bg-slate-900 text-emerald-400">
          <pre>{{ formatJson(selectedDetailJson) }}</pre>
        </div>
        <div class="p-2.5 bg-black/40 border-t border-white/10 flex justify-end">
          <button @click="isDetailModalOpen = false" class="px-3 py-1 rounded-lg bg-white/10 hover:bg-white/20 text-slate-200 text-xs font-medium cursor-pointer">
            关闭
          </button>
        </div>
      </div>
    </div>

    <!-- 4. 四维综合安全勘验技术报告模态框 -->
    <div v-if="isReportModalOpen" class="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 backdrop-blur-xs p-4">
      <div class="glass-surface rounded-2xl border border-white/20 shadow-2xl text-slate-200 w-full max-w-4xl flex flex-col max-h-[90vh] overflow-hidden">
        <div class="p-3.5 bg-indigo-50 border-b border-indigo-200/80 flex items-center justify-between">
          <div class="flex items-center gap-2">
            <span class="w-3 h-3 rounded-full bg-indigo-600"></span>
            <h3 class="text-sm font-bold text-indigo-950">四维安全合规审查与脱敏清洗综合勘验技术报告</h3>
            <span class="text-[10px] font-mono text-indigo-700 bg-indigo-200/60 px-2 py-0.5 rounded font-bold">
              GB/T 22239 等保三级 · 工业级标准
            </span>
          </div>
          <button @click="isReportModalOpen = false" class="text-slate-400 hover:text-slate-700 text-sm cursor-pointer">✕</button>
        </div>

        <div class="p-4 flex-1 overflow-auto custom-scrollbar font-mono text-xs bg-slate-50 space-y-3">
          <div v-if="auditReport">
            <div class="bg-white p-3 rounded-xl border border-slate-200 space-y-1.5">
              <div class="text-xs font-bold text-slate-800">【审查勘验证明编号】 {{ auditReport.report_id }}</div>
              <div class="text-slate-500 text-[11px]">出具时间: {{ auditReport.generated_at }} | 勘验主体: 工业全能网络探针合规审查核心引擎</div>
              <div class="mt-2 text-slate-700 text-xs leading-relaxed font-sans bg-indigo-50/50 p-2.5 rounded-lg border border-indigo-100">
                <span class="font-bold text-indigo-900">综合合规结论与整改意见：</span><br />
                {{ auditReport.overall_compliance_verdict }}
              </div>
            </div>

            <!-- 四大维度统计概览 -->
            <div class="grid grid-cols-4 gap-2 mt-2">
              <div class="bg-white p-2.5 rounded-xl border border-slate-200">
                <div class="text-[10px] text-slate-400 font-bold uppercase">网络安全事件</div>
                <div class="text-lg font-bold text-slate-900 mt-0.5">{{ auditReport.network_audit_metrics.total_events }}</div>
              </div>
              <div class="bg-white p-2.5 rounded-xl border border-slate-200">
                <div class="text-[10px] text-slate-400 font-bold uppercase">敏感数据命中</div>
                <div class="text-lg font-bold text-slate-900 mt-0.5">{{ auditReport.data_security_metrics.total_sensitive_hits }}</div>
              </div>
              <div class="bg-white p-2.5 rounded-xl border border-slate-200">
                <div class="text-[10px] text-slate-400 font-bold uppercase">涉密合规告警</div>
                <div class="text-lg font-bold text-slate-900 mt-0.5">{{ auditReport.confidentiality_metrics.total_alerts }}</div>
              </div>
              <div class="bg-white p-2.5 rounded-xl border border-slate-200">
                <div class="text-[10px] text-slate-400 font-bold uppercase">闭环验证通过率</div>
                <div class="text-lg font-bold text-emerald-600 mt-0.5">{{ auditReport.sanitization_metrics.verification_pass_rate }}</div>
              </div>
            </div>

            <!-- 原始 JSON 报告预览 -->
            <div class="mt-3">
              <div class="text-[11px] font-bold text-slate-500 mb-1">勘验技术报告原始 JSON 结构化底账:</div>
              <pre class="p-3 rounded-xl bg-slate-900 text-emerald-400 text-[10px] overflow-auto max-h-60 custom-scrollbar">{{ JSON.stringify(auditReport, null, 2) }}</pre>
            </div>
          </div>
        </div>

        <div class="p-3 bg-white border-t border-slate-200 flex items-center justify-between">
          <span class="text-[10px] text-slate-400 font-mono">报告符合司法与等保电子证据保全规范</span>
          <div class="flex items-center gap-2">
            <button @click="copyReportMarkdown" class="px-3 py-1.5 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-medium cursor-pointer">
              复制 Markdown 报告
            </button>
            <button @click="downloadReportJson" class="px-3 py-1.5 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-medium cursor-pointer shadow-xs">
              导出 JSON 报告文件
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- 5. 全局操作反馈 Toast 浮层 -->
    <div v-if="toastVisible" class="fixed bottom-6 right-6 z-50 flex items-center gap-2.5 px-4 py-2.5 bg-slate-900/90 text-white rounded-xl shadow-xl backdrop-blur-md border border-slate-700/60 font-mono text-xs transition-all">
      <span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
      <span>{{ toastMessage }}</span>
    </div>

  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';

// 四大维度 Tab 类型
type AuditTabType = 'network' | 'data_sec' | 'confidential' | 'sanitizer';
const activeTab = ref<AuditTabType>('network');

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
const toastVisible = ref(false);
const toastMessage = ref('');
let toastTimer: any = null;

function showToast(msg: string) {
  toastMessage.value = msg;
  toastVisible.value = true;
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    toastVisible.value = false;
  }, 3500);
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

async function blockIpAddress(ip: string, reason: string) {
  try {
    const rules = await invoke<FirewallRule[]>('get_firewall_rules_cmd');
    const existing = rules.find(r => r.target_domain === ip);
    if (existing) {
      showToast(`端点 ${ip} 已经在防火墙拦截名单中`);
      return;
    }
    const newRule: FirewallRule = {
      id: `BLK-${Date.now().toString(36).toUpperCase()}`,
      name: `安全审查阻断: ${ip}`,
      enabled: true,
      target_domain: ip,
      methods: [],
      path_pattern: '.*',
      keyword_regex: '',
      action: 'BLOCK',
      block_status_code: 403,
      block_message: `工业探针安全审查核心已阻断该恶意通信端点 (${reason})`,
    };
    rules.push(newRule);
    await invoke('save_firewall_rules_cmd', { rules });
    showToast(`端点 ${ip} 已成功写入底层防火墙拦截名单并阻断！`);
  } catch (e) {
    console.error('blockIpAddress error:', e);
    showToast(`阻断失败: ${String(e)}`);
  }
}

async function blockEgressTarget(target: string, reason: string) {
  try {
    const rules = await invoke<FirewallRule[]>('get_firewall_rules_cmd');
    const existing = rules.find(r => r.target_domain === target);
    if (existing) {
      showToast(`目标 ${target} 已经在违规外联拦截名单中`);
      return;
    }
    const newRule: FirewallRule = {
      id: `EGRESS-BLK-${Date.now().toString(36).toUpperCase()}`,
      name: `保密合规外联阻断: ${target}`,
      enabled: true,
      target_domain: target,
      methods: [],
      path_pattern: '.*',
      keyword_regex: '',
      action: 'BLOCK',
      block_status_code: 403,
      block_message: `国家秘密法与保密合规防护: 严禁涉密主机访问非法外联渠道 (${reason})`,
    };
    rules.push(newRule);
    await invoke('save_firewall_rules_cmd', { rules });
    showToast(`已成功将违规外联目标 ${target} 纳入防火墙阻断！`);
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

function downloadReportJson() {
  if (!auditReport.value) return;
  const blob = new Blob([JSON.stringify(auditReport.value, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `comprehensive_security_audit_report_${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

function copyToClipboard(text: string) {
  navigator.clipboard.writeText(text);
}

function formatJson(jsonStr: string): string {
  try {
    return JSON.stringify(JSON.parse(jsonStr), null, 2);
  } catch {
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
