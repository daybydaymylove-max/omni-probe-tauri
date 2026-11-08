<template>
  <div class="h-full flex flex-col gap-2.5 overflow-hidden font-sans">
    
    <!-- 1. 顶部操作栏与态势指标看板 (Top Metrics & Action Bar) -->
    <section class="bg-white/80 backdrop-blur-xl rounded-2xl border border-white/70 p-3 shadow-xs shrink-0 flex flex-col gap-2.5">
      
      <!-- 1.1 标题与工具操作区 -->
      <div class="flex items-center justify-between gap-3">
        <div class="flex items-center gap-2.5">
          <div class="w-8 h-8 rounded-xl bg-blue-600/10 text-blue-600 flex items-center justify-center border border-blue-500/20 shadow-2xs">
            <svg class="w-4 h-4 fill-none stroke-current stroke-2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 013 12c0-.778.099-1.533.284-2.253" />
            </svg>
          </div>
          <div>
            <div class="flex items-center gap-2">
              <h2 class="text-xs font-bold text-slate-800 tracking-tight">全息上网行为监测与外联合规审计</h2>
              <span class="px-1.5 py-0.5 rounded-full text-[9px] font-mono bg-blue-500/10 text-blue-700 border border-blue-500/20 font-bold">
                RFC 6066 SNI & RFC 1035 DNS
              </span>
            </div>
            <p class="text-[10px] text-slate-400 font-mono mt-0.5">
              零解密 HTTPS 域名提取 · DNS 动态关联反查 · 9 大类合规行为识别
            </p>
          </div>
        </div>

        <div class="flex items-center gap-2">
          <!-- 查看 DNS 映射表按钮 -->
          <button @click="showDnsModal = true"
            class="px-2.5 py-1.5 rounded-xl bg-slate-100 hover:bg-slate-200/80 text-slate-700 text-[11px] font-medium flex items-center gap-1.5 transition-all cursor-pointer border border-slate-200 shadow-2xs">
            <svg class="w-3.5 h-3.5 fill-none stroke-current stroke-2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
            </svg>
            <span>DNS 关联映射表 ({{ dnsCacheList.length }})</span>
          </button>

          <!-- 导出日志下拉/按钮 -->
          <div class="flex items-center rounded-xl bg-slate-100 border border-slate-200 p-0.5 text-[11px]">
            <button @click="exportLogs('csv')" title="导出为 CSV 表格文件"
              class="px-2 py-1 rounded-lg hover:bg-white text-slate-600 hover:text-slate-900 transition-all font-medium cursor-pointer">
              导出 CSV
            </button>
            <span class="text-slate-300">|</span>
            <button @click="exportLogs('json')" title="导出为 JSON 结构化底账"
              class="px-2 py-1 rounded-lg hover:bg-white text-slate-600 hover:text-slate-900 transition-all font-medium cursor-pointer">
              导出 JSON
            </button>
          </div>

          <!-- 清空当前日志 -->
          <button @click="clearLogs"
            class="px-2.5 py-1.5 rounded-xl bg-rose-50 hover:bg-rose-100 text-rose-700 text-[11px] font-medium flex items-center gap-1 transition-all cursor-pointer border border-rose-200/60 shadow-2xs">
            <svg class="w-3.5 h-3.5 fill-none stroke-current stroke-2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 013.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0" />
            </svg>
            <span>清空审计流水</span>
          </button>
        </div>
      </div>

      <!-- 1.2 态势五大关键核心指标卡片 (KPI Summary Cards) -->
      <div class="grid grid-cols-5 gap-2.5">
        <div class="bg-slate-50/80 rounded-xl p-2.5 border border-slate-200/60 flex items-center justify-between">
          <div>
            <div class="text-[10px] font-bold text-slate-400 uppercase tracking-wider">总审计访问数</div>
            <div class="text-base font-mono font-bold text-slate-800 mt-0.5">
              {{ stats.total_requests.toLocaleString() }}
            </div>
          </div>
          <div class="w-7 h-7 rounded-lg bg-blue-500/10 text-blue-600 flex items-center justify-center font-mono text-xs">
            REQ
          </div>
        </div>

        <div class="bg-slate-50/80 rounded-xl p-2.5 border border-slate-200/60 flex items-center justify-between">
          <div>
            <div class="text-[10px] font-bold text-slate-400 uppercase tracking-wider">活跃审计终端</div>
            <div class="text-base font-mono font-bold text-slate-800 mt-0.5">
              {{ stats.unique_clients }} <span class="text-[10px] font-normal text-slate-400">台</span>
            </div>
          </div>
          <div class="w-7 h-7 rounded-lg bg-indigo-500/10 text-indigo-600 flex items-center justify-center font-mono text-xs">
            IP
          </div>
        </div>

        <div class="bg-slate-50/80 rounded-xl p-2.5 border border-slate-200/60 flex items-center justify-between">
          <div>
            <div class="text-[10px] font-bold text-slate-400 uppercase tracking-wider">独立访问域名</div>
            <div class="text-base font-mono font-bold text-slate-800 mt-0.5">
              {{ stats.unique_domains }} <span class="text-[10px] font-normal text-slate-400">个</span>
            </div>
          </div>
          <div class="w-7 h-7 rounded-lg bg-teal-500/10 text-teal-600 flex items-center justify-center font-mono text-xs">
            DOM
          </div>
        </div>

        <div class="rounded-xl p-2.5 border flex items-center justify-between transition-all"
          :class="stats.high_risk_count > 0 ? 'bg-rose-50/90 border-rose-300 shadow-xs' : 'bg-slate-50/80 border-slate-200/60'">
          <div>
            <div class="text-[10px] font-bold uppercase tracking-wider"
              :class="stats.high_risk_count > 0 ? 'text-rose-600' : 'text-slate-400'">
              高危违规外联
            </div>
            <div class="text-base font-mono font-bold mt-0.5"
              :class="stats.high_risk_count > 0 ? 'text-rose-700 animate-pulse' : 'text-slate-800'">
              {{ stats.high_risk_count }} <span class="text-[10px] font-normal">次</span>
            </div>
          </div>
          <div class="w-7 h-7 rounded-lg flex items-center justify-center font-mono text-xs"
            :class="stats.high_risk_count > 0 ? 'bg-rose-500 text-white' : 'bg-slate-200 text-slate-500'">
            {{ stats.high_risk_count > 0 ? '!' : 'OK' }}
          </div>
        </div>

        <div class="bg-slate-50/80 rounded-xl p-2.5 border border-slate-200/60 flex items-center justify-between">
          <div>
            <div class="text-[10px] font-bold text-slate-400 uppercase tracking-wider">DNS 动态缓存</div>
            <div class="text-base font-mono font-bold text-slate-800 mt-0.5">
              {{ dnsCacheList.length }} <span class="text-[10px] font-normal text-slate-400">条</span>
            </div>
          </div>
          <div class="w-7 h-7 rounded-lg bg-amber-500/10 text-amber-600 flex items-center justify-center font-mono text-xs">
            DNS
          </div>
        </div>
      </div>
    </section>

    <!-- 2. 中间分析栏：分类占比分布与 Top 热门排行 (Behavior Categories & Top Rankings) -->
    <section class="grid grid-cols-3 gap-2.5 shrink-0" style="height: 180px;">
      
      <!-- 2.1 行为分类多维占比分布 -->
      <div class="bg-white/80 backdrop-blur-xl rounded-2xl border border-white/70 p-3 shadow-xs flex flex-col overflow-hidden">
        <div class="flex items-center justify-between mb-2">
          <span class="text-xs font-bold text-slate-800">行为分类分布占比</span>
          <span class="text-[10px] font-mono text-slate-400">{{ Object.keys(stats.category_distribution || {}).length }} 类</span>
        </div>
        
        <div class="flex-1 overflow-y-auto custom-scrollbar space-y-1.5 pr-1">
          <div v-for="(count, catName) in sortedCategories" :key="catName"
            class="flex items-center justify-between text-[11px] group">
            <div class="flex items-center gap-1.5 truncate max-w-[130px]">
              <span class="w-2 h-2 rounded-full shrink-0" :class="getCategoryDotColor(catName as string)"></span>
              <span class="text-slate-700 font-medium truncate">{{ catName }}</span>
            </div>
            <div class="flex items-center gap-2 shrink-0 font-mono">
              <div class="w-20 bg-slate-100 rounded-full h-1.5 overflow-hidden">
                <div class="h-full rounded-full transition-all duration-500"
                  :class="getCategoryBarColor(catName as string)"
                  :style="{ width: calculateCategoryPercent(count as number) + '%' }"></div>
              </div>
              <span class="text-slate-600 w-8 text-right font-bold">{{ count }}</span>
              <span class="text-[10px] text-slate-400 w-8 text-right">{{ calculateCategoryPercent(count as number) }}%</span>
            </div>
          </div>
          <div v-if="Object.keys(stats.category_distribution || {}).length === 0"
            class="h-full flex items-center justify-center text-xs text-slate-400 font-mono">
            暂无分类分布数据
          </div>
        </div>
      </div>

      <!-- 2.2 Top 10 热门访问域名 -->
      <div class="bg-white/80 backdrop-blur-xl rounded-2xl border border-white/70 p-3 shadow-xs flex flex-col overflow-hidden">
        <div class="flex items-center justify-between mb-2">
          <span class="text-xs font-bold text-slate-800">热门访问域名 TOP 10</span>
          <span class="text-[10px] font-mono text-slate-400">按频次排序</span>
        </div>
        
        <div class="flex-1 overflow-y-auto custom-scrollbar space-y-1.5 pr-1">
          <div v-for="(item, idx) in stats.top_domains" :key="item.name"
            class="flex items-center justify-between text-[11px] hover:bg-slate-50 px-1.5 py-0.5 rounded-lg transition-colors">
            <div class="flex items-center gap-2 truncate max-w-[160px]">
              <span class="w-4 text-[10px] font-mono font-bold text-slate-400 text-center">{{ idx + 1 }}</span>
              <span class="text-slate-700 font-medium font-mono truncate" :title="item.name">{{ item.name }}</span>
            </div>
            <div class="flex items-center gap-1.5 shrink-0 font-mono">
              <span class="px-1.5 py-0.2 rounded text-[9px] bg-slate-100 text-slate-600 border border-slate-200">
                {{ item.sub_label }}
              </span>
              <span class="font-bold text-slate-800 w-8 text-right">{{ item.count }}</span>
            </div>
          </div>
          <div v-if="stats.top_domains.length === 0"
            class="h-full flex items-center justify-center text-xs text-slate-400 font-mono">
            暂无域名访问排行
          </div>
        </div>
      </div>

      <!-- 2.3 Top 10 活跃内网终端 -->
      <div class="bg-white/80 backdrop-blur-xl rounded-2xl border border-white/70 p-3 shadow-xs flex flex-col overflow-hidden">
        <div class="flex items-center justify-between mb-2">
          <span class="text-xs font-bold text-slate-800">活跃审计终端 TOP 10</span>
          <span class="text-[10px] font-mono text-slate-400">按请求量排序</span>
        </div>
        
        <div class="flex-1 overflow-y-auto custom-scrollbar space-y-1.5 pr-1">
          <div v-for="(item, idx) in stats.top_clients" :key="item.name"
            class="flex items-center justify-between text-[11px] hover:bg-slate-50 px-1.5 py-0.5 rounded-lg transition-colors">
            <div class="flex items-center gap-2 truncate max-w-[160px]">
              <span class="w-4 text-[10px] font-mono font-bold text-slate-400 text-center">{{ idx + 1 }}</span>
              <span class="text-slate-700 font-medium font-mono truncate" :title="item.name">{{ item.name }}</span>
            </div>
            <div class="flex items-center gap-1.5 shrink-0 font-mono">
              <span class="text-[9px] text-slate-400 truncate max-w-[60px]" :title="item.sub_label">
                {{ item.sub_label }}
              </span>
              <span class="font-bold text-blue-700 w-8 text-right">{{ item.count }}</span>
            </div>
          </div>
          <div v-if="stats.top_clients.length === 0"
            class="h-full flex items-center justify-center text-xs text-slate-400 font-mono">
            暂无终端活动排行
          </div>
        </div>
      </div>

    </section>

    <!-- 3. 下半部：实时上网行为审计流水表 (Audit Flow Stream Table) -->
    <section class="flex-1 bg-white/80 backdrop-blur-xl rounded-2xl border border-white/70 p-3 shadow-xs flex flex-col overflow-hidden min-h-0">
      
      <!-- 3.1 过滤与检索控制器 -->
      <div class="flex items-center justify-between gap-3 mb-2.5 shrink-0">
        <div class="flex items-center gap-2 flex-1">
          
          <!-- 分类筛选器 -->
          <div class="flex items-center gap-1.5">
            <span class="text-[11px] font-bold text-slate-500">分类:</span>
            <select v-model="filterCategory" @change="fetchLogs"
              class="px-2 py-1 rounded-xl bg-slate-100/90 border border-slate-200 text-slate-700 text-[11px] outline-none font-medium">
              <option value="ALL">全部行为分类</option>
              <option value="DEV_TECH">技术研发</option>
              <option value="OFFICE_PRODUCTIVITY">协同办公</option>
              <option value="VIDEO_STREAMING">流媒体视频</option>
              <option value="SOCIAL_MEDIA">社交网络</option>
              <option value="RECRUITMENT">求职招聘</option>
              <option value="SHOPPING_FINANCE">电商金融</option>
              <option value="GAMING_ENTERTAINMENT">游戏娱乐</option>
              <option value="CLOUD_INFRA">云基础设施</option>
              <option value="SECURITY_RISK">高危违规外联</option>
              <option value="OTHER_INTERNET">常规互联网</option>
            </select>
          </div>

          <!-- 风险等级筛选器 -->
          <div class="flex items-center gap-1.5">
            <span class="text-[11px] font-bold text-slate-500">风险:</span>
            <select v-model="filterRisk" @change="fetchLogs"
              class="px-2 py-1 rounded-xl bg-slate-100/90 border border-slate-200 text-slate-700 text-[11px] outline-none font-medium">
              <option value="ALL">全部风险等级</option>
              <option value="NORMAL">正常合规</option>
              <option value="ATTENTION">需重点关注</option>
              <option value="HIGH_RISK">🚨 违规高危</option>
            </select>
          </div>

          <!-- 终端 IP 检索 -->
          <div class="flex items-center gap-1.5 flex-1 max-w-xs">
            <span class="text-[11px] font-bold text-slate-500">IP:</span>
            <input v-model="filterIp" @input="fetchLogs"
              placeholder="搜索终端 IP / 目标 IP..."
              class="w-full px-2.5 py-1 rounded-xl bg-slate-100/90 border border-slate-200 text-slate-700 text-[11px] outline-none font-mono focus:border-blue-500 transition-colors" />
          </div>

        </div>

        <div class="flex items-center gap-2">
          <!-- 实时滚屏开关 -->
          <label class="flex items-center gap-1.5 text-[11px] text-slate-600 font-medium cursor-pointer select-none">
            <input type="checkbox" v-model="autoScroll" class="rounded text-blue-600 focus:ring-0 cursor-pointer" />
            <span>实时自动滚动</span>
          </label>

          <span class="text-[11px] font-mono text-slate-400">
            当前显示: {{ auditLogs.length }} 条
          </span>
        </div>
      </div>

      <!-- 3.2 审计流水数据表格 (Apple Glassmorphism Style) -->
      <div ref="tableContainer" class="flex-1 overflow-y-auto custom-scrollbar border border-slate-100 rounded-xl">
        <table class="w-full text-left border-collapse text-[11px] font-mono">
          <thead class="sticky top-0 bg-slate-50/95 backdrop-blur-md text-slate-500 font-semibold border-b border-slate-200/80 z-10 select-none">
            <tr>
              <th class="py-2 px-2.5 w-12 text-center">ID</th>
              <th class="py-2 px-2.5 w-36">时间</th>
              <th class="py-2 px-2.5 w-32">客户端终端</th>
              <th class="py-2 px-2.5">访问域名 / 目标地址</th>
              <th class="py-2 px-2.5 w-24">请求协议</th>
              <th class="py-2 px-2.5 w-28">行为分类</th>
              <th class="py-2 px-2.5 w-24 text-center">风险等级</th>
              <th class="py-2 px-2.5 w-36">目的端 & 归属地</th>
              <th class="py-2 px-2.5 w-16 text-center">操作</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-100">
            <tr v-for="log in auditLogs" :key="log.id"
              :class="[
                'hover:bg-blue-50/40 transition-colors group cursor-pointer',
                log.risk_level === 'HIGH_RISK' ? 'bg-rose-50/40' : (log.risk_level === 'ATTENTION' ? 'bg-amber-50/30' : '')
              ]"
              @click="openLogDetail(log)">
              
              <!-- ID -->
              <td class="py-1.5 px-2.5 text-center text-slate-400">{{ log.id }}</td>

              <!-- 时间 -->
              <td class="py-1.5 px-2.5 text-slate-600 truncate">{{ log.timestamp.split(' ')[1] || log.timestamp }}</td>

              <!-- 客户端终端 -->
              <td class="py-1.5 px-2.5">
                <div class="font-bold text-slate-800 flex items-center gap-1">
                  <span>{{ log.client_ip }}</span>
                  <button @click.stop="$emit('filterTraffic', log.client_ip)" title="一键穿透至流量分析大屏过滤该客户端 IP"
                    class="px-1 py-0.2 bg-blue-50 hover:bg-blue-100 text-blue-700 border border-blue-200 rounded text-[9px] font-sans transition-colors cursor-pointer">
                    🔍
                  </button>
                  <button @click.stop="$emit('openDossier', log.client_ip)" title="打开该客户端 IP 全息画像档案"
                    class="px-1 py-0.2 bg-purple-50 hover:bg-purple-100 text-purple-700 border border-purple-200 rounded text-[9px] font-sans transition-colors cursor-pointer">
                    📁
                  </button>
                </div>
                <div class="text-[9px] text-slate-400 font-normal">{{ log.client_mac || '未知MAC' }}</div>
              </td>

              <!-- 访问域名 -->
              <td class="py-1.5 px-2.5">
                <div class="font-bold text-slate-800 flex items-center gap-1.5">
                  <span class="truncate max-w-sm" :title="log.domain">{{ log.domain }}</span>
                </div>
                <div class="text-[9px] text-slate-400 truncate max-w-sm font-sans" :title="log.url">
                  {{ log.url }}
                </div>
              </td>

              <!-- 请求协议与方法 -->
              <td class="py-1.5 px-2.5">
                <span class="px-1.5 py-0.5 rounded text-[10px] font-bold border"
                  :class="getProtocolBadgeClass(log.protocol)">
                  {{ log.protocol }}
                </span>
                <span class="ml-1 text-[9px] text-slate-400 font-bold">{{ log.method }}</span>
              </td>

              <!-- 行为分类 -->
              <td class="py-1.5 px-2.5 font-sans">
                <span class="px-2 py-0.5 rounded-full text-[10px] font-medium border inline-flex items-center gap-1"
                  :class="getCategoryBadgeClass(log.category_code)">
                  <span class="w-1.5 h-1.5 rounded-full" :class="getCategoryDotClass(log.category_code)"></span>
                  {{ log.category }}
                </span>
              </td>

              <!-- 风险等级 -->
              <td class="py-1.5 px-2.5 text-center">
                <span v-if="log.risk_level === 'HIGH_RISK'"
                  class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-rose-500 text-white shadow-2xs animate-pulse font-sans">
                  🚨 违规外联
                </span>
                <span v-else-if="log.risk_level === 'ATTENTION'"
                  class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-amber-100 text-amber-800 border border-amber-300 font-sans">
                  重点关注
                </span>
                <span v-else
                  class="px-2 py-0.5 rounded-full text-[10px] font-medium bg-emerald-50 text-emerald-700 border border-emerald-200 font-sans">
                  正常合规
                </span>
              </td>

              <!-- 目的端与归属地 -->
              <td class="py-1.5 px-2.5">
                <div class="text-slate-700 flex items-center gap-1">
                  <span>{{ log.remote_ip }}:{{ log.remote_port }}</span>
                  <button @click.stop="$emit('filterTraffic', log.remote_ip)" title="一键穿透至流量分析大屏过滤该目的端 IP"
                    class="px-1 py-0.2 bg-blue-50 hover:bg-blue-100 text-blue-700 border border-blue-200 rounded text-[9px] font-sans transition-colors cursor-pointer">
                    🔍
                  </button>
                  <button @click.stop="$emit('openDossier', log.remote_ip)" title="打开该目的端 IP 全息画像档案"
                    class="px-1 py-0.2 bg-purple-50 hover:bg-purple-100 text-purple-700 border border-purple-200 rounded text-[9px] font-sans transition-colors cursor-pointer">
                    📁
                  </button>
                </div>
                <div class="text-[9px] text-slate-400 truncate font-sans">{{ log.geo_summary || '公网通信' }}</div>
              </td>

              <!-- 操作 -->
              <td class="py-1.5 px-2.5 text-center">
                <button @click.stop="openLogDetail(log)"
                  class="px-2 py-0.5 rounded-md bg-white hover:bg-slate-100 text-slate-600 border border-slate-200 text-[10px] font-sans font-medium transition-colors shadow-2xs">
                  详情
                </button>
              </td>

            </tr>

            <tr v-if="auditLogs.length === 0">
              <td colspan="9" class="py-12 text-center text-slate-400 font-mono text-xs">
                暂无上网行为审计记录（启动网卡嗅探或等待终端外网 HTTP/HTTPS/DNS 流量）
              </td>
            </tr>
          </tbody>
        </table>
      </div>

    </section>

    <!-- 4. DNS 动态关联映射表抽屉/弹窗 (DNS Cache Modal) -->
    <div v-if="showDnsModal"
      class="fixed inset-0 bg-slate-900/40 backdrop-blur-sm z-50 flex items-center justify-center p-6">
      <div class="bg-white rounded-2xl shadow-2xl border border-white/80 w-full max-w-3xl max-h-[80vh] flex flex-col overflow-hidden">
        
        <div class="px-5 py-4 border-b border-slate-100 flex items-center justify-between bg-slate-50/50">
          <div class="flex items-center gap-2.5">
            <div class="w-8 h-8 rounded-xl bg-amber-500/10 text-amber-600 flex items-center justify-center font-mono font-bold text-xs">
              DNS
            </div>
            <div>
              <h3 class="text-xs font-bold text-slate-800">DNS 动态双向映射底账 (RFC 1035 A/AAAA)</h3>
              <p class="text-[10px] text-slate-400 font-mono mt-0.5">
                自动提取终端 DNS 解析记录，构建 IP 与域名反查拓扑库，实现无域名流量关联审计
              </p>
            </div>
          </div>
          <button @click="showDnsModal = false"
            class="w-6 h-6 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-400 hover:text-slate-700 flex items-center justify-center text-xs font-bold cursor-pointer">
            ✕
          </button>
        </div>

        <div class="flex-1 overflow-y-auto custom-scrollbar p-5">
          <table class="w-full text-left border-collapse text-[11px] font-mono">
            <thead class="bg-slate-50 text-slate-500 font-semibold border-b border-slate-200">
              <tr>
                <th class="py-2 px-3">解析域名</th>
                <th class="py-2 px-3">解析所得 IP 清单</th>
                <th class="py-2 px-3 w-16 text-center">TTL</th>
                <th class="py-2 px-3 w-28">请求终端</th>
                <th class="py-2 px-3 w-36">最后解析时间</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-100">
              <tr v-for="item in dnsCacheList" :key="item.domain" class="hover:bg-slate-50/80">
                <td class="py-2 px-3 font-bold text-slate-800">{{ item.domain }}</td>
                <td class="py-2 px-3">
                  <div class="flex flex-wrap gap-1">
                    <span v-for="ip in item.resolved_ips" :key="ip"
                      class="px-1.5 py-0.2 rounded bg-slate-100 text-slate-700 border border-slate-200 text-[10px]">
                      {{ ip }}
                    </span>
                  </div>
                </td>
                <td class="py-2 px-3 text-center text-slate-500">{{ item.ttl_secs }}s</td>
                <td class="py-2 px-3 text-slate-600">{{ item.client_ip }}</td>
                <td class="py-2 px-3 text-slate-400">{{ item.resolved_time }}</td>
              </tr>
              <tr v-if="dnsCacheList.length === 0">
                <td colspan="5" class="py-8 text-center text-slate-400 font-mono">
                  当前尚未捕获到 DNS 解析响应
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <div class="px-5 py-3 border-t border-slate-100 bg-slate-50/50 flex justify-end">
          <button @click="showDnsModal = false"
            class="px-4 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-900 text-white text-xs font-medium cursor-pointer">
            关闭
          </button>
        </div>

      </div>
    </div>

    <!-- 5. 审计流水单条详细分析弹窗 (Log Detail Modal) -->
    <div v-if="selectedLog"
      class="fixed inset-0 bg-slate-900/40 backdrop-blur-sm z-50 flex items-center justify-center p-6">
      <div class="bg-white rounded-2xl shadow-2xl border border-white/80 w-full max-w-2xl max-h-[85vh] flex flex-col overflow-hidden font-sans">
        
        <div class="px-5 py-4 border-b border-slate-100 flex items-center justify-between bg-slate-50/50">
          <div class="flex items-center gap-2.5">
            <div class="w-8 h-8 rounded-xl flex items-center justify-center font-bold text-xs"
              :class="selectedLog.risk_level === 'HIGH_RISK' ? 'bg-rose-500 text-white' : 'bg-blue-500/10 text-blue-600'">
              #{{ selectedLog.id }}
            </div>
            <div>
              <h3 class="text-xs font-bold text-slate-800">上网行为审计事件明细</h3>
              <p class="text-[10px] text-slate-400 font-mono mt-0.5">
                时间: {{ selectedLog.timestamp }} · 协议: {{ selectedLog.protocol }}
              </p>
            </div>
          </div>
          <button @click="selectedLog = null"
            class="w-6 h-6 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-400 hover:text-slate-700 flex items-center justify-center text-xs font-bold cursor-pointer">
            ✕
          </button>
        </div>

        <div class="flex-1 overflow-y-auto custom-scrollbar p-5 space-y-4">
          
          <!-- 风险与行为评估卡片 -->
          <div class="p-3 rounded-xl border flex items-start gap-3"
            :class="selectedLog.risk_level === 'HIGH_RISK' ? 'bg-rose-50/80 border-rose-200 text-rose-900' : 'bg-slate-50 border-slate-200 text-slate-800'">
            <div class="text-xl">
              {{ selectedLog.risk_level === 'HIGH_RISK' ? '🚨' : (selectedLog.risk_level === 'ATTENTION' ? '⚠️' : '🛡️') }}
            </div>
            <div class="flex-1">
              <div class="flex items-center gap-2">
                <span class="text-xs font-bold">{{ selectedLog.category }}</span>
                <span class="text-[10px] font-mono px-1.5 py-0.2 rounded font-bold"
                  :class="selectedLog.risk_level === 'HIGH_RISK' ? 'bg-rose-200 text-rose-800' : 'bg-slate-200 text-slate-700'">
                  {{ selectedLog.risk_level }}
                </span>
              </div>
              <p class="text-[11px] mt-1 text-slate-600">
                {{ selectedLog.risk_desc }}
              </p>
            </div>
          </div>

          <!-- 核心字段网格 -->
          <div class="grid grid-cols-2 gap-3 text-[11px] font-mono">
            
            <div class="bg-slate-50 p-2.5 rounded-xl border border-slate-200/70">
              <span class="text-[9px] font-bold text-slate-400 uppercase tracking-wider block mb-1">源客户端信息</span>
              <div class="text-slate-800 font-bold">{{ selectedLog.client_ip }}</div>
              <div class="text-slate-500 text-[10px] mt-0.5">MAC: {{ selectedLog.client_mac || '未知' }}</div>
            </div>

            <div class="bg-slate-50 p-2.5 rounded-xl border border-slate-200/70">
              <span class="text-[9px] font-bold text-slate-400 uppercase tracking-wider block mb-1">目的服务器画像</span>
              <div class="text-slate-800 font-bold">{{ selectedLog.remote_ip }}:{{ selectedLog.remote_port }}</div>
              <div class="text-slate-500 text-[10px] mt-0.5 font-sans">{{ selectedLog.geo_summary || '公网通信' }}</div>
            </div>

          </div>

          <!-- 访问目标详情 -->
          <div class="bg-slate-50 p-3 rounded-xl border border-slate-200/70 space-y-2 text-[11px] font-mono">
            <div>
              <span class="text-[9px] font-bold text-slate-400 uppercase tracking-wider block mb-0.5">访问域名 (Host / SNI)</span>
              <div class="text-slate-800 font-bold break-all">{{ selectedLog.domain }}</div>
            </div>
            <div>
              <span class="text-[9px] font-bold text-slate-400 uppercase tracking-wider block mb-0.5">完整 URL / 请求路径</span>
              <div class="text-slate-700 break-all bg-white p-2 rounded-lg border border-slate-200 text-[10px]">
                {{ selectedLog.url }}
              </div>
            </div>
            <div v-if="selectedLog.user_agent">
              <span class="text-[9px] font-bold text-slate-400 uppercase tracking-wider block mb-0.5">User-Agent 客户端指纹</span>
              <div class="text-slate-600 break-all bg-white p-2 rounded-lg border border-slate-200 text-[10px]">
                {{ selectedLog.user_agent }}
              </div>
            </div>
          </div>

        </div>

        <div class="px-5 py-3 border-t border-slate-100 bg-slate-50/50 flex justify-end">
          <button @click="selectedLog = null"
            class="px-4 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-900 text-white text-xs font-medium cursor-pointer">
            关闭
          </button>
        </div>

      </div>
    </div>

  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, nextTick } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';

const emit = defineEmits(['filterTraffic', 'openDossier']);

// 接口定义
export interface WebAccessLog {
  id: number;
  timestamp: string;
  timestamp_ms: number;
  client_ip: string;
  client_mac: string;
  client_hostname?: string;
  domain: string;
  url: string;
  method: string;
  protocol: string;
  category: string;
  category_code: string;
  risk_level: string;
  risk_desc: string;
  remote_ip: string;
  remote_port: number;
  geo_summary: string;
  user_agent?: string;
  bytes_sent: number;
  bytes_received: number;
}

export interface TopEntityItem {
  name: string;
  count: number;
  sub_label: string;
}

export interface WebAuditStatistics {
  total_requests: number;
  unique_clients: number;
  unique_domains: number;
  high_risk_count: number;
  category_distribution: Record<string, number>;
  top_domains: TopEntityItem[];
  top_clients: TopEntityItem[];
}

export interface DnsCacheItem {
  domain: string;
  resolved_ips: string[];
  resolved_time: string;
  ttl_secs: number;
  client_ip: string;
}

// 状态管理
const auditLogs = ref<WebAccessLog[]>([]);
const stats = ref<WebAuditStatistics>({
  total_requests: 0,
  unique_clients: 0,
  unique_domains: 0,
  high_risk_count: 0,
  category_distribution: {},
  top_domains: [],
  top_clients: [],
});
const dnsCacheList = ref<DnsCacheItem[]>([]);

// 过滤控制
const filterCategory = ref('ALL');
const filterRisk = ref('ALL');
const filterIp = ref('');
const autoScroll = ref(true);

// 弹窗与选中
const selectedLog = ref<WebAccessLog | null>(null);
const showDnsModal = ref(false);
const tableContainer = ref<HTMLElement | null>(null);

let unlistenWebLog: (() => void) | null = null;
let pollTimer: number | null = null;

// 分类排序
const sortedCategories = computed(() => {
  const dist = stats.value.category_distribution || {};
  return Object.entries(dist)
    .sort((a, b) => (b[1] as number) - (a[1] as number))
    .reduce((acc, [k, v]) => {
      acc[k] = v;
      return acc;
    }, {} as Record<string, number>);
});

const calculateCategoryPercent = (count: number) => {
  if (!stats.value.total_requests || stats.value.total_requests === 0) return 0;
  return Math.round((count / stats.value.total_requests) * 100);
};

// 颜色映射辅助函数
const getCategoryDotColor = (name: string) => {
  if (name.includes('研发')) return 'bg-blue-500';
  if (name.includes('办公')) return 'bg-indigo-500';
  if (name.includes('视频')) return 'bg-purple-500';
  if (name.includes('社交')) return 'bg-cyan-500';
  if (name.includes('招聘')) return 'bg-amber-500';
  if (name.includes('金融') || name.includes('电商')) return 'bg-emerald-500';
  if (name.includes('游戏')) return 'bg-orange-500';
  if (name.includes('违规') || name.includes('高危')) return 'bg-rose-500';
  return 'bg-slate-400';
};

const getCategoryBarColor = (name: string) => {
  if (name.includes('研发')) return 'bg-blue-500';
  if (name.includes('办公')) return 'bg-indigo-500';
  if (name.includes('视频')) return 'bg-purple-500';
  if (name.includes('社交')) return 'bg-cyan-500';
  if (name.includes('招聘')) return 'bg-amber-500';
  if (name.includes('金融') || name.includes('电商')) return 'bg-emerald-500';
  if (name.includes('游戏')) return 'bg-orange-500';
  if (name.includes('违规') || name.includes('高危')) return 'bg-rose-500';
  return 'bg-slate-400';
};

const getCategoryBadgeClass = (code: string) => {
  switch (code) {
    case 'DEV_TECH':
      return 'bg-blue-50 text-blue-700 border-blue-200';
    case 'OFFICE_PRODUCTIVITY':
      return 'bg-indigo-50 text-indigo-700 border-indigo-200';
    case 'VIDEO_STREAMING':
      return 'bg-purple-50 text-purple-700 border-purple-200';
    case 'SOCIAL_MEDIA':
      return 'bg-cyan-50 text-cyan-700 border-cyan-200';
    case 'RECRUITMENT':
      return 'bg-amber-50 text-amber-700 border-amber-200';
    case 'SHOPPING_FINANCE':
      return 'bg-emerald-50 text-emerald-700 border-emerald-200';
    case 'GAMING_ENTERTAINMENT':
      return 'bg-orange-50 text-orange-700 border-orange-200';
    case 'SECURITY_RISK':
      return 'bg-rose-100 text-rose-800 border-rose-300 font-bold';
    default:
      return 'bg-slate-100 text-slate-700 border-slate-200';
  }
};

const getCategoryDotClass = (code: string) => {
  switch (code) {
    case 'DEV_TECH': return 'bg-blue-500';
    case 'OFFICE_PRODUCTIVITY': return 'bg-indigo-500';
    case 'VIDEO_STREAMING': return 'bg-purple-500';
    case 'SOCIAL_MEDIA': return 'bg-cyan-500';
    case 'RECRUITMENT': return 'bg-amber-500';
    case 'SHOPPING_FINANCE': return 'bg-emerald-500';
    case 'GAMING_ENTERTAINMENT': return 'bg-orange-500';
    case 'SECURITY_RISK': return 'bg-rose-600 animate-pulse';
    default: return 'bg-slate-400';
  }
};

const getProtocolBadgeClass = (proto: string) => {
  if (proto.includes('TLS') || proto.includes('HTTPS')) {
    return 'bg-emerald-50 text-emerald-700 border-emerald-200';
  }
  if (proto.includes('HTTP')) {
    return 'bg-blue-50 text-blue-700 border-blue-200';
  }
  if (proto.includes('DNS')) {
    return 'bg-amber-50 text-amber-700 border-amber-200';
  }
  return 'bg-slate-100 text-slate-700 border-slate-200';
};

// 后端 API 调用
const fetchLogs = async () => {
  try {
    const res = await invoke<WebAccessLog[]>('get_web_access_logs_cmd', {
      limit: 300,
      categoryFilter: filterCategory.value === 'ALL' ? null : filterCategory.value,
      riskFilter: filterRisk.value === 'ALL' ? null : filterRisk.value,
      clientIpFilter: filterIp.value.trim() ? filterIp.value.trim() : null,
    });
    auditLogs.value = res || [];
  } catch (e) {
    console.error('获取上网行为审计日志失败:', e);
  }
};

const fetchStats = async () => {
  try {
    const res = await invoke<WebAuditStatistics>('get_web_audit_statistics_cmd');
    if (res) {
      stats.value = res;
    }
  } catch (e) {
    console.error('获取上网行为多维统计失败:', e);
  }
};

const fetchDnsCache = async () => {
  try {
    const res = await invoke<DnsCacheItem[]>('get_dns_cache_table_cmd');
    dnsCacheList.value = res || [];
  } catch (e) {
    console.error('获取 DNS 关联映射表失败:', e);
  }
};

const clearLogs = async () => {
  try {
    await invoke('clear_web_access_logs_cmd');
    auditLogs.value = [];
    await fetchStats();
  } catch (e) {
    console.error('清空审计日志失败:', e);
  }
};

const exportLogs = async (fmt: 'csv' | 'json') => {
  try {
    const content = await invoke<string>('export_web_access_logs_cmd', { format: fmt });
    const blob = new Blob([content], { type: fmt === 'csv' ? 'text/csv;charset=utf-8;' : 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `web_activity_audit_${Date.now()}.${fmt}`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  } catch (e) {
    console.error(`导出 ${fmt} 失败:`, e);
  }
};

const openLogDetail = (log: WebAccessLog) => {
  selectedLog.value = log;
};

onMounted(async () => {
  await fetchLogs();
  await fetchStats();
  await fetchDnsCache();

  // 监听后端推送的实时 web-access-log 事件
  unlistenWebLog = await listen<WebAccessLog>('web-access-log', (event) => {
    const log = event.payload;
    // 检查是否符合当前筛选
    const matchCat = filterCategory.value === 'ALL' || log.category_code === filterCategory.value;
    const matchRisk = filterRisk.value === 'ALL' || log.risk_level === filterRisk.value;
    const matchIp = !filterIp.value.trim() || log.client_ip.includes(filterIp.value.trim());

    if (matchCat && matchRisk && matchIp) {
      auditLogs.value.unshift(log);
      if (auditLogs.value.length > 500) {
        auditLogs.value.pop();
      }
      if (autoScroll.value && tableContainer.value) {
        nextTick(() => {
          if (tableContainer.value) {
            tableContainer.value.scrollTop = 0;
          }
        });
      }
    }
  });

  // 定时每 3 秒刷新统计与 DNS 缓存
  pollTimer = window.setInterval(() => {
    fetchStats();
    fetchDnsCache();
  }, 3000);
});

onUnmounted(() => {
  if (unlistenWebLog) {
    unlistenWebLog();
    unlistenWebLog = null;
  }
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
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
  background: rgba(148, 163, 184, 0.25);
  border-radius: 9999px;
}
.custom-scrollbar::-webkit-scrollbar-thumb:hover {
  background: rgba(148, 163, 184, 0.45);
}
</style>
