<template>
  <div class="h-full flex flex-col gap-2.5 overflow-hidden font-sans">

    <!-- 1. 顶部操作栏与态势指标看板 (真 Liquid Glass 控制层) -->
    <section class="ui-nav-glass rounded-2xl p-3.5 shrink-0 flex flex-col gap-3" style="color: var(--text-primary);">
      <span class="lens-edge-lip" aria-hidden="true"></span>

      <!-- 1.1 标题与工具操作区 -->
      <div class="flex items-center justify-between gap-3 flex-wrap">
        <div class="flex items-center gap-2.5 min-w-0">
          <div class="w-8 h-8 rounded-xl bg-[var(--accent-primary-soft)] text-[var(--accent-primary-text)] flex items-center justify-center border border-[var(--accent-primary)]/20 shrink-0">
            <AppIcon name="globe" :size="16" />
          </div>
          <div class="min-w-0">
            <div class="flex items-center gap-2 flex-wrap">
              <h2 class="text-[13px] font-semibold tracking-tight" style="color: var(--text-primary);">全息上网行为监测与外联合规审计</h2>
              <span class="ui-pill px-2 py-0.5 rounded-full text-[11px] font-medium">
                RFC 6066 SNI · RFC 1035 DNS
              </span>
            </div>
            <p class="text-[11px] mt-0.5 truncate" style="color: var(--text-muted);">
              零解密 HTTPS 域名提取 · DNS 动态关联反查 · 9 大类合规行为识别
            </p>
          </div>
        </div>

        <div class="flex items-center gap-2 flex-wrap">
          <button @click="showDnsModal = true" class="ui-btn-secondary px-3 py-1.5 text-xs">
            <AppIcon name="document" :size="14" />
            <span class="ui-num">DNS 关联映射 ({{ dnsCacheList.length }})</span>
          </button>

          <div class="glass-pill flex items-center rounded-xl p-0.5 text-xs">
            <button @click="exportLogs('csv')" title="导出为 CSV 表格文件" class="px-2.5 py-1 rounded-lg hover:bg-[var(--surface-hover)] transition-all font-medium cursor-pointer" style="color: var(--text-primary);">
              导出 CSV
            </button>
            <span class="opacity-30">|</span>
            <button @click="exportLogs('json')" title="导出为 JSON 结构化底账" class="px-2.5 py-1 rounded-lg hover:bg-[var(--surface-hover)] transition-all font-medium cursor-pointer" style="color: var(--text-primary);">
              导出 JSON
            </button>
          </div>

          <button @click="clearLogs" class="ui-btn-danger px-3 py-1.5 text-xs">
            <AppIcon name="trash" :size="14" />
            <span>清空流水</span>
          </button>
        </div>
      </div>

      <!-- 1.2 核心指标卡片 (Apple Bento 5 列净数字风，去除大写方块标签) -->
      <div class="grid grid-cols-2 md:grid-cols-5 gap-2.5">
        <div class="ui-sub-card p-3 flex items-center justify-between gap-2">
          <div>
            <div class="text-[11px] font-medium" style="color: var(--text-muted);">总审计访问数</div>
            <div class="text-lg ui-num font-bold mt-0.5 leading-tight" style="color: var(--text-primary);">
              {{ stats.total_requests.toLocaleString() }}
            </div>
          </div>
          <div class="w-8 h-8 rounded-xl bg-[var(--accent-primary-soft)] text-[var(--accent-primary-text)] flex items-center justify-center shrink-0">
            <AppIcon name="activity" :size="15" />
          </div>
        </div>

        <div class="ui-sub-card p-3 flex items-center justify-between gap-2">
          <div>
            <div class="text-[11px] font-medium" style="color: var(--text-muted);">活跃审计终端</div>
            <div class="text-lg ui-num font-bold mt-0.5 leading-tight" style="color: var(--text-primary);">
              {{ stats.unique_clients }} <span class="text-[11px] font-normal" style="color: var(--text-muted);">台</span>
            </div>
          </div>
          <div class="w-8 h-8 rounded-xl bg-[var(--surface-glass-pill)] text-[var(--text-secondary)] flex items-center justify-center shrink-0">
            <AppIcon name="cpu" :size="15" />
          </div>
        </div>

        <div class="ui-sub-card p-3 flex items-center justify-between gap-2">
          <div>
            <div class="text-[11px] font-medium" style="color: var(--text-muted);">独立访问域名</div>
            <div class="text-lg ui-num font-bold mt-0.5 leading-tight" style="color: var(--text-primary);">
              {{ stats.unique_domains }} <span class="text-[11px] font-normal" style="color: var(--text-muted);">个</span>
            </div>
          </div>
          <div class="w-8 h-8 rounded-xl bg-[var(--surface-glass-pill)] text-[var(--text-secondary)] flex items-center justify-center shrink-0">
            <AppIcon name="globe" :size="15" />
          </div>
        </div>

        <div
          class="rounded-xl p-3 border flex items-center justify-between gap-2 transition-all"
          :class="stats.high_risk_count > 0 ? 'bg-rose-500/10 border-rose-500/35' : 'ui-sub-card'"
        >
          <div>
            <div class="text-[11px] font-medium" :class="stats.high_risk_count > 0 ? 'text-rose-600 dark:text-rose-400' : ''" :style="stats.high_risk_count > 0 ? {} : { color: 'var(--text-muted)' }">
              高危违规外联
            </div>
            <div class="text-lg ui-num font-bold mt-0.5 leading-tight" :class="stats.high_risk_count > 0 ? 'text-rose-600 dark:text-rose-400' : ''" :style="stats.high_risk_count > 0 ? {} : { color: 'var(--text-primary)' }">
              {{ stats.high_risk_count }} <span class="text-[11px] font-normal">次</span>
            </div>
          </div>
          <div
            class="w-8 h-8 rounded-xl flex items-center justify-center shrink-0"
            :class="stats.high_risk_count > 0 ? 'bg-rose-500/15 text-rose-600 dark:text-rose-400' : 'bg-emerald-500/12 text-emerald-600 dark:text-emerald-400'"
          >
            <AppIcon :name="stats.high_risk_count > 0 ? 'alert' : 'check'" :size="15" />
          </div>
        </div>

        <div class="ui-sub-card p-3 flex items-center justify-between gap-2">
          <div>
            <div class="text-[11px] font-medium" style="color: var(--text-muted);">DNS 动态缓存</div>
            <div class="text-lg ui-num font-bold mt-0.5 leading-tight" style="color: var(--text-primary);">
              {{ dnsCacheList.length }} <span class="text-[11px] font-normal" style="color: var(--text-muted);">条</span>
            </div>
          </div>
          <div class="w-8 h-8 rounded-xl bg-[var(--surface-glass-pill)] text-[var(--text-secondary)] flex items-center justify-center shrink-0">
            <AppIcon name="database" :size="15" />
          </div>
        </div>
      </div>
    </section>

    <!-- 2. 中间分析栏：分类占比分布与 Top 热门排行 (实体稳态衬底) -->
    <section class="grid grid-cols-1 lg:grid-cols-3 gap-2.5 shrink-0 select-text" style="min-height: 170px; max-height: 200px;">
      <!-- 2.1 行为分类多维占比分布 -->
      <div class="ui-content-card p-3 flex flex-col overflow-hidden">
        <div class="flex items-center justify-between mb-2">
          <span class="text-xs font-semibold" style="color: var(--text-primary);">行为分类分布占比</span>
          <span class="text-[11px] ui-num" style="color: var(--text-muted);">{{ Object.keys(stats.category_distribution || {}).length }} 类</span>
        </div>

        <div class="flex-1 overflow-y-auto custom-scrollbar space-y-1.5 pr-1">
          <div v-for="(count, catName) in sortedCategories" :key="catName" class="flex items-center justify-between text-xs group">
            <div class="flex items-center gap-1.5 truncate max-w-[140px]">
              <span class="w-2 h-2 rounded-full shrink-0" :class="getCategoryDotColor(catName as string)"></span>
              <span class="font-medium truncate" style="color: var(--text-primary);">{{ catName }}</span>
            </div>
            <div class="flex items-center gap-2 shrink-0 ui-num text-[11px]">
              <div class="w-20 rounded-full h-1.5 overflow-hidden" style="background: var(--surface-input);">
                <div class="h-full rounded-full transition-all duration-500" :class="getCategoryBarColor(catName as string)" :style="{ width: calculateCategoryPercent(count as number) + '%' }"></div>
              </div>
              <span class="w-8 text-right font-semibold" style="color: var(--text-primary);">{{ count }}</span>
              <span class="w-9 text-right" style="color: var(--text-muted);">{{ calculateCategoryPercent(count as number) }}%</span>
            </div>
          </div>
          <div v-if="Object.keys(stats.category_distribution || {}).length === 0" class="h-full flex items-center justify-center text-xs" style="color: var(--text-muted);">
            暂无分类分布数据
          </div>
        </div>
      </div>

      <!-- 2.2 Top 10 热门访问域名 -->
      <div class="ui-content-card p-3 flex flex-col overflow-hidden">
        <div class="flex items-center justify-between mb-2">
          <span class="text-xs font-semibold" style="color: var(--text-primary);">热门访问域名 TOP 10</span>
          <span class="text-[11px]" style="color: var(--text-muted);">按频次排序</span>
        </div>

        <div class="flex-1 overflow-y-auto custom-scrollbar space-y-1 pr-1">
          <div v-for="(item, idx) in stats.top_domains" :key="item.name" class="flex items-center justify-between text-xs hover:bg-[var(--surface-hover)] px-1.5 py-0.5 rounded-lg transition-colors">
            <div class="flex items-center gap-2 truncate max-w-[170px]">
              <span class="w-4 text-[11px] ui-num font-semibold text-center" style="color: var(--text-muted);">{{ idx + 1 }}</span>
              <span class="font-medium font-mono truncate" style="color: var(--text-primary);" :title="item.name">{{ item.name }}</span>
            </div>
            <div class="flex items-center gap-1.5 shrink-0 ui-num">
              <span class="ui-pill px-1.5 py-0.5 text-[11px]">{{ item.sub_label }}</span>
              <span class="font-semibold w-8 text-right" style="color: var(--text-primary);">{{ item.count }}</span>
            </div>
          </div>
          <div v-if="stats.top_domains.length === 0" class="h-full flex items-center justify-center text-xs" style="color: var(--text-muted);">
            暂无域名访问排行
          </div>
        </div>
      </div>

      <!-- 2.3 Top 10 活跃内网终端 -->
      <div class="ui-content-card p-3 flex flex-col overflow-hidden">
        <div class="flex items-center justify-between mb-2">
          <span class="text-xs font-semibold" style="color: var(--text-primary);">活跃审计终端 TOP 10</span>
          <span class="text-[11px]" style="color: var(--text-muted);">按请求量排序</span>
        </div>

        <div class="flex-1 overflow-y-auto custom-scrollbar space-y-1 pr-1">
          <div v-for="(item, idx) in stats.top_clients" :key="item.name" class="flex items-center justify-between text-xs hover:bg-[var(--surface-hover)] px-1.5 py-0.5 rounded-lg transition-colors">
            <div class="flex items-center gap-2 truncate max-w-[170px]">
              <span class="w-4 text-[11px] ui-num font-semibold text-center" style="color: var(--text-muted);">{{ idx + 1 }}</span>
              <span class="font-medium ui-num truncate" style="color: var(--text-primary);" :title="item.name">{{ item.name }}</span>
            </div>
            <div class="flex items-center gap-1.5 shrink-0 ui-num">
              <span class="text-[11px] truncate max-w-[70px]" style="color: var(--text-muted);" :title="item.sub_label">{{ item.sub_label }}</span>
              <span class="font-semibold text-blue-600 dark:text-sky-400 w-8 text-right">{{ item.count }}</span>
            </div>
          </div>
          <div v-if="stats.top_clients.length === 0" class="h-full flex items-center justify-center text-xs" style="color: var(--text-muted);">
            暂无终端活动排行
          </div>
        </div>
      </div>
    </section>

    <!-- 3. 下半部：实时上网行为审计流水表 (实体稳态衬底) -->
    <section class="flex-1 ui-content-card p-3 flex flex-col overflow-hidden min-h-0 select-text">
      <div class="flex items-center justify-between gap-3 mb-2.5 shrink-0 flex-wrap">
        <div class="flex items-center gap-2.5 flex-1 flex-wrap">
          <div class="flex items-center gap-1.5 shrink-0 whitespace-nowrap">
            <span class="text-xs font-semibold shrink-0" style="color: var(--text-muted);">分类:</span>
            <select v-model="filterCategory" @change="fetchLogs" class="ui-input w-auto px-2.5 py-1 text-xs cursor-pointer">
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

          <div class="flex items-center gap-1.5 shrink-0 whitespace-nowrap">
            <span class="text-xs font-semibold shrink-0" style="color: var(--text-muted);">风险:</span>
            <select v-model="filterRisk" @change="fetchLogs" class="ui-input w-auto px-2.5 py-1 text-xs cursor-pointer">
              <option value="ALL">全部风险等级</option>
              <option value="NORMAL">正常合规</option>
              <option value="ATTENTION">需重点关注</option>
              <option value="HIGH_RISK">违规高危</option>
            </select>
          </div>

          <div class="flex items-center gap-1.5 flex-1 min-w-[180px] max-w-xs">
            <span class="text-xs font-semibold shrink-0 whitespace-nowrap" style="color: var(--text-muted);">IP:</span>
            <input v-model="filterIp" @input="fetchLogs" placeholder="搜索终端 IP / 目标 IP..." class="ui-input w-full px-2.5 py-1 text-xs font-mono" />
          </div>
        </div>

        <div class="flex items-center gap-3">
          <label class="flex items-center gap-1.5 text-xs font-medium cursor-pointer select-none" style="color: var(--text-secondary);">
            <input type="checkbox" v-model="autoScroll" class="rounded accent-blue-600 focus:ring-0 cursor-pointer" />
            <span>实时自动滚动</span>
          </label>

          <span class="text-[11px] ui-num" style="color: var(--text-muted);">
            当前显示: {{ auditLogs.length }} 条
          </span>
        </div>
      </div>

      <div ref="tableContainer" class="flex-1 overflow-y-auto custom-scrollbar border rounded-xl" style="border-color: var(--border-subtle); background: var(--surface-content-alt);">
        <table class="w-full text-left border-collapse text-xs">
          <thead class="ui-table-head sticky top-0 z-10 select-none">
            <tr>
              <th class="py-2 px-2.5 w-12 text-center">ID</th>
              <th class="py-2 px-2.5 w-32">时间</th>
              <th class="py-2 px-2.5 w-40">客户端终端</th>
              <th class="py-2 px-2.5">访问域名 / 目标地址</th>
              <th class="py-2 px-2.5 w-24">请求协议</th>
              <th class="py-2 px-2.5 w-28">行为分类</th>
              <th class="py-2 px-2.5 w-24 text-center">风险等级</th>
              <th class="py-2 px-2.5 w-40">目的端 &amp; 归属地</th>
              <th class="py-2 px-2.5 w-16 text-center">操作</th>
            </tr>
          </thead>
          <tbody class="divide-y" style="border-color: var(--border-subtle);">
            <tr
              v-for="log in auditLogs"
              :key="log.id"
              :class="[
                'hover:bg-[var(--surface-hover)] transition-colors group cursor-pointer',
                log.risk_level === 'HIGH_RISK' ? 'bg-rose-500/8' : (log.risk_level === 'ATTENTION' ? 'bg-amber-500/8' : '')
              ]"
              @click="openLogDetail(log)"
            >
              <td class="py-2 px-2.5 text-center ui-num" style="color: var(--text-muted);">{{ log.id }}</td>
              <td class="py-2 px-2.5 ui-num truncate" style="color: var(--text-secondary);">{{ log.timestamp.split(' ')[1] || log.timestamp }}</td>
              <td class="py-2 px-2.5">
                <div class="font-semibold ui-num flex items-center gap-1" style="color: var(--text-primary);">
                  <span>{{ log.client_ip }}</span>
                  <button @click.stop="$emit('filterTraffic', log.client_ip)" title="过滤该客户端 IP" class="p-1 rounded hover:bg-[var(--surface-hover)] text-blue-600 dark:text-sky-400 cursor-pointer">
                    <AppIcon name="search" :size="12" />
                  </button>
                  <button @click.stop="$emit('openDossier', log.client_ip)" title="打开 IP 全息档案" class="p-1 rounded hover:bg-[var(--surface-hover)] text-purple-600 dark:text-purple-300 cursor-pointer">
                    <AppIcon name="folder" :size="12" />
                  </button>
                </div>
                <div class="text-[11px] font-mono" style="color: var(--text-muted);">{{ log.client_mac || '未知 MAC' }}</div>
              </td>

              <td class="py-2 px-2.5">
                <div class="font-semibold flex items-center gap-1.5" style="color: var(--text-primary);">
                  <span class="truncate max-w-sm" :title="log.domain">{{ log.domain }}</span>
                </div>
                <div class="text-[11px] truncate max-w-sm" style="color: var(--text-muted);" :title="log.url">{{ log.url }}</div>
              </td>

              <td class="py-2 px-2.5">
                <span class="px-1.5 py-0.5 rounded text-[11px] font-semibold border" :class="getProtocolBadgeClass(log.protocol)">
                  {{ log.protocol }}
                </span>
                <span class="ml-1 text-[11px] font-semibold" style="color: var(--text-muted);">{{ log.method }}</span>
              </td>

              <td class="py-2 px-2.5">
                <span class="px-2 py-0.5 rounded-full text-[11px] font-medium border inline-flex items-center gap-1.5" :class="getCategoryBadgeClass(log.category_code)">
                  <span class="w-1.5 h-1.5 rounded-full" :class="getCategoryDotClass(log.category_code)"></span>
                  {{ log.category }}
                </span>
              </td>

              <td class="py-2 px-2.5 text-center">
                <span v-if="log.risk_level === 'HIGH_RISK'" class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold bg-rose-600 text-white">
                  <AppIcon name="alert" :size="11" />
                  <span>违规外联</span>
                </span>
                <span v-else-if="log.risk_level === 'ATTENTION'" class="px-2 py-0.5 rounded-full text-[11px] font-semibold bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/25">
                  重点关注
                </span>
                <span v-else class="px-2 py-0.5 rounded-full text-[11px] font-medium bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 border border-emerald-500/25">
                  正常合规
                </span>
              </td>

              <td class="py-2 px-2.5">
                <div class="flex items-center gap-1 ui-num" style="color: var(--text-primary);">
                  <span>{{ log.remote_ip }}:{{ log.remote_port }}</span>
                  <button @click.stop="$emit('filterTraffic', log.remote_ip)" title="过滤该目的端 IP" class="p-1 rounded hover:bg-[var(--surface-hover)] text-blue-600 dark:text-sky-400 cursor-pointer">
                    <AppIcon name="search" :size="12" />
                  </button>
                  <button @click.stop="$emit('openDossier', log.remote_ip)" title="打开该目的端 IP 全息档案" class="p-1 rounded hover:bg-[var(--surface-hover)] text-purple-600 dark:text-purple-300 cursor-pointer">
                    <AppIcon name="folder" :size="12" />
                  </button>
                </div>
                <div class="text-[11px] truncate" style="color: var(--text-muted);">{{ log.geo_summary || '公网通信' }}</div>
              </td>

              <td class="py-2 px-2.5 text-center">
                <div class="flex items-center justify-center gap-1">
                  <button @click.stop="openLogDetail(log)" class="ui-btn-secondary px-2 py-0.5 text-[11px]">详情</button>
                  <button @click.stop="addWebLogToDiffQueue(log)" class="px-1.5 py-0.5 rounded bg-emerald-500/12 hover:bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border border-emerald-500/25 text-[11px] font-semibold cursor-pointer" title="加入全局多组比对队列">+</button>
                </div>
              </td>
            </tr>

            <tr v-if="auditLogs.length === 0">
              <td colspan="9" class="py-12 text-center text-xs" style="color: var(--text-muted);">
                暂无上网行为审计记录（启动网卡嗅探或等待终端外网 HTTP/HTTPS/DNS 流量）
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <!-- 4. DNS 动态关联映射表弹窗 -->
    <div v-if="showDnsModal" class="ui-modal-backdrop fixed inset-0 z-50 flex items-center justify-center p-6">
      <div class="ui-modal-surface rounded-2xl w-full max-w-3xl max-h-[80vh] flex flex-col overflow-hidden select-text">
        <div class="px-5 py-4 border-b flex items-center justify-between" style="border-color: var(--border-subtle);">
          <div class="flex items-center gap-2.5">
            <div class="w-8 h-8 rounded-xl bg-amber-500/12 text-amber-600 dark:text-amber-300 flex items-center justify-center font-mono font-bold text-xs">
              DNS
            </div>
            <div>
              <h3 class="text-[13px] font-semibold" style="color: var(--text-primary);">DNS 动态双向映射底账 (RFC 1035 A/AAAA)</h3>
              <p class="text-[11px] mt-0.5" style="color: var(--text-muted);">
                自动提取终端 DNS 解析记录，构建 IP 与域名反查拓扑库，实现无域名流量关联审计
              </p>
            </div>
          </div>
          <button @click="showDnsModal = false" class="p-1.5 rounded-lg hover:bg-[var(--surface-hover)] cursor-pointer" style="color: var(--text-secondary);">
            <AppIcon name="close" :size="14" />
          </button>
        </div>

        <div class="flex-1 overflow-y-auto custom-scrollbar p-5">
          <table class="w-full text-left border-collapse text-xs">
            <thead class="ui-table-head select-none">
              <tr>
                <th class="py-2 px-3">解析域名</th>
                <th class="py-2 px-3">解析所得 IP 清单</th>
                <th class="py-2 px-3 w-16 text-center">TTL</th>
                <th class="py-2 px-3 w-28">请求终端</th>
                <th class="py-2 px-3 w-36">最后解析时间</th>
              </tr>
            </thead>
            <tbody class="divide-y" style="border-color: var(--border-subtle);">
              <tr v-for="item in dnsCacheList" :key="item.domain" class="hover:bg-[var(--surface-hover)]">
                <td class="py-2 px-3 font-semibold font-mono" style="color: var(--text-primary);">{{ item.domain }}</td>
                <td class="py-2 px-3">
                  <div class="flex flex-wrap gap-1">
                    <span v-for="ip in item.resolved_ips" :key="ip" class="ui-pill px-1.5 py-0.5 text-[11px] ui-num">
                      {{ ip }}
                    </span>
                  </div>
                </td>
                <td class="py-2 px-3 text-center ui-num" style="color: var(--text-secondary);">{{ item.ttl_secs }}s</td>
                <td class="py-2 px-3 ui-num" style="color: var(--text-secondary);">{{ item.client_ip }}</td>
                <td class="py-2 px-3 ui-num" style="color: var(--text-muted);">{{ item.resolved_time }}</td>
              </tr>
              <tr v-if="dnsCacheList.length === 0">
                <td colspan="5" class="py-8 text-center text-xs" style="color: var(--text-muted);">当前尚未捕获到 DNS 解析响应</td>
              </tr>
            </tbody>
          </table>
        </div>

        <div class="px-5 py-3 border-t flex justify-end" style="border-color: var(--border-subtle);">
          <button @click="showDnsModal = false" class="ui-btn-primary px-4 py-1.5 text-xs">关闭</button>
        </div>
      </div>
    </div>

    <!-- 5. 审计流水单条详细分析弹窗 -->
    <div v-if="selectedLog" class="ui-modal-backdrop fixed inset-0 z-50 flex items-center justify-center p-6">
      <div class="ui-modal-surface rounded-2xl w-full max-w-2xl max-h-[85vh] flex flex-col overflow-hidden select-text">
        <div class="px-5 py-4 border-b flex items-center justify-between" style="border-color: var(--border-subtle);">
          <div class="flex items-center gap-2.5">
            <div
              class="w-8 h-8 rounded-xl flex items-center justify-center font-semibold text-xs ui-num"
              :class="selectedLog.risk_level === 'HIGH_RISK' ? 'bg-rose-600 text-white' : 'bg-blue-500/12 text-blue-600 dark:text-sky-400'"
            >
              #{{ selectedLog.id }}
            </div>
            <div>
              <h3 class="text-[13px] font-semibold" style="color: var(--text-primary);">上网行为审计事件明细</h3>
              <p class="text-[11px] ui-num mt-0.5" style="color: var(--text-muted);">
                时间: {{ selectedLog.timestamp }} · 协议: {{ selectedLog.protocol }}
              </p>
            </div>
          </div>
          <button @click="selectedLog = null" class="p-1.5 rounded-lg hover:bg-[var(--surface-hover)] cursor-pointer" style="color: var(--text-secondary);">
            <AppIcon name="close" :size="14" />
          </button>
        </div>

        <div class="flex-1 overflow-y-auto custom-scrollbar p-5 space-y-4">
          <div
            class="p-3 rounded-xl border flex items-start gap-3"
            :class="selectedLog.risk_level === 'HIGH_RISK' ? 'bg-rose-500/10 border-rose-500/30 text-rose-700 dark:text-rose-200' : 'ui-sub-card'"
          >
            <AppIcon
              :name="selectedLog.risk_level === 'HIGH_RISK' || selectedLog.risk_level === 'ATTENTION' ? 'alert' : 'shield'"
              :size="18"
              class="mt-0.5 shrink-0"
              :class="selectedLog.risk_level === 'HIGH_RISK' ? 'text-rose-500' : (selectedLog.risk_level === 'ATTENTION' ? 'text-amber-500' : 'text-emerald-500')"
            />
            <div class="flex-1">
              <div class="flex items-center gap-2">
                <span class="text-xs font-semibold" style="color: var(--text-primary);">{{ selectedLog.category }}</span>
                <span class="text-[11px] px-1.5 py-0.5 rounded font-semibold" :class="selectedLog.risk_level === 'HIGH_RISK' ? 'bg-rose-500/20 text-rose-700 dark:text-rose-300' : 'ui-pill'">
                  {{ selectedLog.risk_level }}
                </span>
              </div>
              <p class="text-xs mt-1" style="color: var(--text-secondary);">{{ selectedLog.risk_desc }}</p>
            </div>
          </div>

          <div class="grid grid-cols-2 gap-3 text-xs">
            <div class="ui-sub-card p-3">
              <span class="text-[11px] font-semibold block mb-1" style="color: var(--text-muted);">源客户端信息</span>
              <div class="font-semibold ui-num" style="color: var(--text-primary);">{{ selectedLog.client_ip }}</div>
              <div class="text-[11px] mt-0.5 font-mono" style="color: var(--text-secondary);">MAC: {{ selectedLog.client_mac || '未知' }}</div>
            </div>

            <div class="ui-sub-card p-3">
              <span class="text-[11px] font-semibold block mb-1" style="color: var(--text-muted);">目的服务器画像</span>
              <div class="font-semibold ui-num" style="color: var(--text-primary);">{{ selectedLog.remote_ip }}:{{ selectedLog.remote_port }}</div>
              <div class="text-[11px] mt-0.5" style="color: var(--text-secondary);">{{ selectedLog.geo_summary || '公网通信' }}</div>
            </div>
          </div>

          <div class="ui-sub-card p-3 space-y-2 text-xs">
            <div>
              <span class="text-[11px] font-semibold block mb-0.5" style="color: var(--text-muted);">访问域名 (Host / SNI)</span>
              <div class="font-semibold font-mono break-all" style="color: var(--text-primary);">{{ selectedLog.domain }}</div>
            </div>
            <div>
              <span class="text-[11px] font-semibold block mb-0.5" style="color: var(--text-muted);">完整 URL / 请求路径</span>
              <div class="break-all p-2 rounded-lg border text-[11px] font-mono" style="background: var(--surface-content); border-color: var(--border-subtle); color: var(--text-primary);">
                {{ selectedLog.url }}
              </div>
            </div>
            <div v-if="selectedLog.user_agent">
              <span class="text-[11px] font-semibold block mb-0.5" style="color: var(--text-muted);">User-Agent 客户端指纹</span>
              <div class="break-all p-2 rounded-lg border text-[11px] font-mono" style="background: var(--surface-content); border-color: var(--border-subtle); color: var(--text-secondary);">
                {{ selectedLog.user_agent }}
              </div>
            </div>
          </div>
        </div>

        <div class="px-5 py-3 border-t flex items-center justify-end gap-2" style="border-color: var(--border-subtle);">
          <button v-if="selectedLog" @click="addWebLogToDiffQueue(selectedLog)" class="ui-btn-secondary px-3 py-1.5 text-xs">
            + 加入多组比对队列
          </button>
          <button @click="selectedLog = null" class="ui-btn-primary px-4 py-1.5 text-xs">关闭</button>
        </div>
      </div>
    </div>

  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, nextTick } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import AppIcon from '../components/AppIcon.vue';
import { useUniversalDiff } from '../composables/useUniversalDiff';
import { saveTextViaNativeDesktop } from '../composables/useDesktopSave';

const diffBus = useUniversalDiff();

function addWebLogToDiffQueue(log: WebAccessLog) {
  const payload = `${log.method} ${log.protocol}://${log.domain}${log.url} | UA=${log.user_agent || '-'} | Risk=${log.risk_level} | TX=${log.bytes_sent}B RX=${log.bytes_received}B`;
  diffBus.addToQueue({
    id: `WEB_${log.id}`,
    label: `[外联] ${log.domain} (${log.method})`,
    timestamp: log.timestamp,
    protocol: log.protocol || 'HTTP/DNS',
    src: log.client_ip,
    dst: `${log.remote_ip}:${log.remote_port}`,
    format: 'ASCII',
    isRawText: true,
    payloadHex: '',
    rawText: payload,
    length: payload.length,
    extraFields: {
      domain: log.domain,
      url: log.url,
      category: log.category,
      risk_level: log.risk_level,
      geo_summary: log.geo_summary || '-',
      client_mac: log.client_mac || '-'
    }
  }, `外联 #${log.id} ${log.domain}`, false);
}

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
      return 'bg-blue-500/12 text-blue-700 dark:text-sky-300 border-blue-500/25';
    case 'OFFICE_PRODUCTIVITY':
      return 'bg-indigo-500/12 text-indigo-700 dark:text-indigo-300 border-indigo-500/25';
    case 'VIDEO_STREAMING':
      return 'bg-purple-500/12 text-purple-700 dark:text-purple-300 border-purple-500/25';
    case 'SOCIAL_MEDIA':
      return 'bg-cyan-500/12 text-cyan-700 dark:text-cyan-300 border-cyan-500/25';
    case 'RECRUITMENT':
      return 'bg-amber-500/12 text-amber-700 dark:text-amber-300 border-amber-500/25';
    case 'SHOPPING_FINANCE':
      return 'bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 border-emerald-500/25';
    case 'GAMING_ENTERTAINMENT':
      return 'bg-orange-500/12 text-orange-700 dark:text-orange-300 border-orange-500/25';
    case 'SECURITY_RISK':
      return 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-500/30 font-semibold';
    default:
      return 'ui-pill';
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
    case 'SECURITY_RISK': return 'bg-rose-600';
    default: return 'bg-slate-400';
  }
};

const getProtocolBadgeClass = (proto: string) => {
  if (proto.includes('TLS') || proto.includes('HTTPS')) {
    return 'bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 border-emerald-500/25';
  }
  if (proto.includes('HTTP')) {
    return 'bg-blue-500/12 text-blue-700 dark:text-sky-300 border-blue-500/25';
  }
  if (proto.includes('DNS')) {
    return 'bg-amber-500/12 text-amber-700 dark:text-amber-300 border-amber-500/25';
  }
  return 'ui-pill';
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
    await saveTextViaNativeDesktop(
      `web_activity_audit_${Date.now()}.${fmt}`,
      content,
      fmt === 'csv' ? 'CSV 表格 (*.csv)' : 'JSON 日志 (*.json)',
      `*.${fmt}`,
      '导出网络访问审计记录'
    );
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
