<template>
  <div class="h-full flex flex-col gap-2.5 overflow-hidden font-sans">

    <!-- 1. 顶部控制栏 (真 Liquid Glass 控制层) -->
    <section class="ui-nav-glass rounded-2xl p-3.5 shrink-0 flex flex-col gap-3" style="color: var(--text-primary);">
      <span class="lens-edge-lip" aria-hidden="true"></span>

      <!-- 1.1 标题与代理主开关 -->
      <div class="flex items-center justify-between gap-3 flex-wrap">
        <div class="flex items-center gap-2.5 min-w-0">
          <div class="w-8 h-8 rounded-xl bg-[var(--accent-primary-soft)] text-[var(--accent-primary-text)] flex items-center justify-center border border-[var(--accent-primary)]/20 shrink-0">
            <AppIcon name="lock" :size="16" />
          </div>
          <div class="min-w-0">
            <div class="flex items-center gap-2 flex-wrap">
              <h2 class="text-[13px] font-semibold tracking-tight" style="color: var(--text-primary);">网络流量全息解密与调试透视</h2>
              <span class="ui-pill px-2 py-0.5 rounded-full text-[11px] font-medium">
                透明透传 · 无损解密
              </span>
            </div>
            <p class="text-[11px] mt-0.5 truncate" style="color: var(--text-muted);">
              双向通信透明穿透 · 应用层明文解密 · NSS 密钥动态关联
            </p>
          </div>
        </div>

        <!-- 代理控制与配置 (strict nowrap) -->
        <div class="flex items-center gap-2 flex-wrap shrink-0">
          <div class="ui-pill rounded-xl flex items-center gap-1.5 px-2 py-1 shrink-0 whitespace-nowrap">
            <span class="text-[11px] font-semibold whitespace-nowrap shrink-0" style="color: var(--text-muted);">监听端口</span>
            <input
              v-model.number="proxyPort"
              :disabled="proxyStatus.is_running"
              type="number"
              min="1024"
              max="65535"
              class="ui-input w-20 px-2 py-0.5 text-xs ui-num text-center shrink-0"
            />
            <button
              @click="toggleProxy"
              :class="proxyStatus.is_running ? 'ui-btn-danger px-3 py-1 text-xs' : 'ui-btn-primary px-3 py-1 text-xs'"
            >
              <span class="w-1.5 h-1.5 rounded-full shrink-0" :class="proxyStatus.is_running ? 'bg-current' : 'bg-white'"></span>
              <span>{{ proxyStatus.is_running ? '停止代理' : '启动代理解密' }}</span>
            </button>
          </div>

          <button @click="showCaModal = true" class="ui-btn-secondary px-3 py-1.5 text-xs">
            <AppIcon name="shield" :size="14" />
            <span>CA 根证书</span>
          </button>

          <button @click="showPassiveModal = true" class="ui-btn-secondary px-3 py-1.5 text-xs">
            <AppIcon name="key" :size="14" />
            <span>被动解密</span>
          </button>

          <button @click="clearDecryptedLogs" class="ui-btn-danger px-3 py-1.5 text-xs">
            <span>清空流水</span>
          </button>
        </div>
      </div>

      <!-- 1.2 核心运行指标卡片 (去方块角标 Bento 卡片) -->
      <div class="grid grid-cols-2 lg:grid-cols-4 gap-2.5">
        <div class="ui-sub-card p-3 flex items-center justify-between gap-2">
          <div class="min-w-0">
            <div class="text-[11px] font-medium" style="color: var(--text-muted);">代理解密服务</div>
            <div
              class="text-sm font-semibold ui-num mt-1 flex items-center gap-1.5 truncate"
              :class="proxyStatus.is_running ? 'text-emerald-600 dark:text-emerald-400' : 'text-[var(--text-secondary)]'"
            >
              <span class="w-2 h-2 rounded-full shrink-0" :class="proxyStatus.is_running ? 'bg-emerald-500' : 'bg-slate-400'"></span>
              <span class="truncate">{{ proxyStatus.is_running ? `监听端口 :${proxyStatus.listen_port}` : '未启动' }}</span>
            </div>
          </div>
          <span class="ui-pill text-[11px] px-2 py-0.5 rounded-full shrink-0">HTTP/S</span>
        </div>

        <div class="ui-sub-card p-3 flex items-center justify-between gap-2">
          <div>
            <div class="text-[11px] font-medium" style="color: var(--text-muted);">累计解密会话</div>
            <div class="text-lg ui-num font-bold mt-0.5 leading-tight" style="color: var(--text-primary);">
              {{ proxyStatus.total_requests.toLocaleString() }}
            </div>
          </div>
          <div class="w-8 h-8 rounded-xl bg-[var(--accent-primary-soft)] text-[var(--accent-primary-text)] flex items-center justify-center shrink-0">
            <AppIcon name="lock" :size="15" />
          </div>
        </div>

        <div class="ui-sub-card p-3 flex items-center justify-between gap-2">
          <div>
            <div class="text-[11px] font-medium" style="color: var(--text-muted);">通信传输模式</div>
            <div
              class="text-sm font-semibold mt-1 flex items-center gap-1.5"
              :class="!proxyStatus.is_running
                ? 'text-[var(--text-secondary)]'
                : proxyStatus.active_blocking_enforced
                  ? 'text-amber-600 dark:text-amber-400'
                  : 'text-emerald-600 dark:text-emerald-400'"
            >
              <span
                class="w-2 h-2 rounded-full"
                :class="!proxyStatus.is_running
                  ? 'bg-slate-400'
                  : proxyStatus.active_blocking_enforced
                    ? 'bg-amber-500'
                    : 'bg-emerald-500'"
              ></span>
              <span>
                {{
                  !proxyStatus.is_running
                    ? '本地旁路待命'
                    : proxyStatus.active_blocking_enforced
                      ? '策略阻断生效'
                      : 'MITM 透明镜像'
                }}
              </span>
            </div>
          </div>
          <span class="ui-pill text-[11px] px-2 py-0.5 rounded-full shrink-0 ui-num">
            {{
              !proxyStatus.is_running
                ? '未挂载代理'
                : proxyStatus.active_blocking_enforced
                  ? `已阻断 ${proxyStatus.blocked_requests}`
                  : '只读审计'
            }}
          </span>
        </div>

        <div class="ui-sub-card p-3 flex items-center justify-between gap-2">
          <div class="truncate min-w-0">
            <div class="text-[11px] font-medium" style="color: var(--text-muted);">SSLKEYLOGFILE 密钥库</div>
            <div class="text-xs ui-num font-semibold mt-1 truncate" style="color: var(--text-primary);" :title="keylogStatus.active_file_path || '未加载'">
              {{ keylogStatus.total_keys }} 组密钥 (匹配 {{ keylogStatus.matched_sessions_count }})
            </div>
          </div>
          <button
            @click="triggerKeylogSelect"
            class="ui-btn-secondary px-2.5 py-1 text-[11px] shrink-0"
          >
            导入 KeyLog
          </button>
        </div>
      </div>

      <!-- 1.3 协议解密通道切换栏 (统一苹果蓝主选中色) -->
      <div class="flex items-center justify-between pt-2 border-t flex-wrap gap-2" style="border-color: var(--border-subtle);">
        <div class="glass-pill inline-flex items-center p-1 rounded-xl text-xs font-medium flex-wrap gap-1">
          <button
            @click="activeProtocolTab = 'tls'"
            :class="[
              'px-3 py-1 rounded-lg transition-all cursor-pointer flex items-center gap-1.5 whitespace-nowrap',
              activeProtocolTab === 'tls' ? 'bg-[var(--accent-primary)] text-white shadow-xs font-semibold' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
            ]"
          >
            <span>TLS / HTTP 明文流水</span>
            <span class="px-1.5 py-0.5 rounded-full text-[11px] ui-num" :class="activeProtocolTab === 'tls' ? 'bg-white/20 text-white' : 'bg-[var(--surface-glass-pill)]'">{{ decryptedLogs.length }}</span>
          </button>
          <button
            @click="switchToQuicTab"
            :class="[
              'px-3 py-1 rounded-lg transition-all cursor-pointer flex items-center gap-1.5 whitespace-nowrap',
              activeProtocolTab === 'quic' ? 'bg-[var(--accent-primary)] text-white shadow-xs font-semibold' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
            ]"
          >
            <span>QUIC / HTTP/3 自动解密流</span>
            <span class="px-1.5 py-0.5 rounded-full text-[11px] ui-num" :class="activeProtocolTab === 'quic' ? 'bg-white/20 text-white' : 'bg-[var(--surface-glass-pill)]'">{{ quicTelemetry.total_quic_packets_decrypted }}</span>
          </button>
          <button
            @click="switchToFingerprintTab"
            :class="[
              'px-3 py-1 rounded-lg transition-all cursor-pointer flex items-center gap-1.5 whitespace-nowrap',
              activeProtocolTab === 'fingerprint' ? 'bg-[var(--accent-primary)] text-white shadow-xs font-semibold' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
            ]"
          >
            <span>TLS 指纹 (JA3/JA4 &amp; C2 碰撞)</span>
            <span
              class="px-1.5 py-0.5 rounded-full text-[11px] ui-num font-semibold"
              :class="tlsFpTelemetry.threat_hit_count > 0 ? 'bg-rose-600 text-white' : 'bg-black/15 dark:bg-white/15'"
            >
              {{ tlsFpTelemetry.total_client_hellos }}
            </span>
          </button>
        </div>

        <div v-if="activeProtocolTab === 'quic'" class="flex items-center gap-3 text-[11px] ui-num" style="color: var(--text-muted);">
          <span>RFC 9001 Initial 自动派生: <b class="text-indigo-600 dark:text-indigo-300">{{ quicTelemetry.initial_auto_decrypted_count }}</b> 帧</span>
          <span>活跃重组流: <b class="text-emerald-600 dark:text-emerald-400">{{ quicTelemetry.total_active_streams }}</b> 条</span>
          <button @click="fetchQuicState" class="ui-btn-secondary px-2.5 py-1 text-[11px]">
            <AppIcon name="refresh" :size="12" />
            <span>刷新 QUIC</span>
          </button>
        </div>
        <div v-else-if="activeProtocolTab === 'fingerprint'" class="flex items-center gap-3 text-[11px] ui-num" style="color: var(--text-muted);">
          <span>内置威胁指纹库: <b style="color: var(--text-primary);">{{ tlsFpTelemetry.builtin_threat_signatures }}</b> 类</span>
          <span>恶意 C2 碰撞命中: <b :class="tlsFpTelemetry.threat_hit_count > 0 ? 'text-rose-600 dark:text-rose-400' : 'text-emerald-600 dark:text-emerald-400'">{{ tlsFpTelemetry.threat_hit_count }}</b> 次</span>
          <button @click="fetchTlsFingerprints" class="ui-btn-secondary px-2.5 py-1 text-[11px]">
            <AppIcon name="refresh" :size="12" />
            <span>刷新指纹</span>
          </button>
        </div>
      </div>
    </section>

    <!-- 2. 主分析区：TLS 流水工作台 (实体稳态衬底) -->
    <section v-if="activeProtocolTab === 'tls'" class="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-2.5 overflow-hidden min-h-0 select-text">

      <!-- 2.1 左侧解密流量流水表 -->
      <div class="lg:col-span-5 ui-content-card p-3 flex flex-col overflow-hidden min-h-0">
        <div class="flex items-center justify-between gap-2 mb-2 shrink-0">
          <input
            v-model="filterKeyword"
            placeholder="搜索 URL / 域名 / 请求方法..."
            class="ui-input flex-1 px-2.5 py-1.5 text-xs"
          />
          <span class="text-[11px] ui-num shrink-0" style="color: var(--text-muted);">
            {{ filteredLogs.length }} / {{ decryptedLogs.length }} 会话
          </span>
        </div>

        <div class="flex-1 overflow-y-auto custom-scrollbar border rounded-xl" style="border-color: var(--border-subtle); background: var(--surface-content-alt);">
          <table class="w-full text-left border-collapse text-xs">
            <thead class="ui-table-head sticky top-0 z-10 select-none">
              <tr>
                <th class="py-2 px-2 w-10 text-center">ID</th>
                <th class="py-2 px-2 w-16">方法</th>
                <th class="py-2 px-2">请求目标 &amp; 路径</th>
                <th class="py-2 px-2 w-14 text-center">状态</th>
                <th class="py-2 px-2 w-16 text-right">大小</th>
              </tr>
            </thead>
            <tbody class="divide-y" style="border-color: var(--border-subtle);">
              <tr
                v-for="item in filteredLogs"
                :key="item.id"
                @click="selectedItem = item"
                :class="[
                  'hover:bg-[var(--surface-hover)] transition-colors cursor-pointer',
                  selectedItem?.id === item.id ? 'bg-blue-500/12 font-semibold' : ''
                ]"
              >
                <td class="py-2 px-2 text-center ui-num" style="color: var(--text-muted);">{{ item.id }}</td>
                <td class="py-2 px-2 font-semibold font-mono text-[11px]" :class="getMethodColor(item.method)">
                  {{ item.method }}
                </td>
                <td class="py-2 px-2 truncate max-w-[160px]">
                  <div class="truncate font-medium" style="color: var(--text-primary);" :title="item.host">{{ item.host }}</div>
                  <div class="text-[11px] truncate font-mono" style="color: var(--text-muted);" :title="item.path">{{ item.path }}</div>
                </td>
                <td class="py-2 px-2 text-center">
                  <span
                    v-if="item.response_status >= 200 && item.response_status < 300"
                    class="px-1.5 py-0.5 rounded text-[11px] font-semibold ui-num bg-emerald-500/15 text-emerald-700 dark:text-emerald-300"
                  >
                    {{ item.response_status }}
                  </span>
                  <span
                    v-else-if="item.response_status >= 300 && item.response_status < 400"
                    class="px-1.5 py-0.5 rounded text-[11px] font-semibold ui-num bg-blue-500/15 text-blue-700 dark:text-sky-300"
                  >
                    {{ item.response_status }}
                  </span>
                  <span
                    v-else
                    class="ui-pill px-1.5 py-0.5 text-[11px] font-semibold ui-num"
                  >
                    {{ item.response_status }}
                  </span>
                </td>
                <td class="py-2 px-2 text-right ui-num text-[11px]" style="color: var(--text-muted);">
                  {{ formatBytes(item.bytes_total) }}
                </td>
              </tr>
              <tr v-if="filteredLogs.length === 0">
                <td colspan="5" class="py-12 text-center text-xs" style="color: var(--text-muted);">
                  暂无解密流量记录 (请确保客户端/浏览器已配置代理 http://127.0.0.1:{{ proxyPort }})
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- 2.2 右侧双栏明文 HTTP 深度结构化查看器 -->
      <div class="lg:col-span-7 ui-content-card p-3 flex flex-col overflow-hidden min-h-0">
        <div v-if="selectedItem" class="flex-1 flex flex-col overflow-hidden gap-3 min-h-0">
          <!-- 选中项摘要条 -->
          <div class="ui-sub-card flex items-center justify-between p-2.5 text-xs shrink-0 flex-wrap gap-2">
            <div class="flex items-center gap-2 truncate min-w-0">
              <span class="px-2 py-0.5 rounded text-white font-semibold bg-purple-600 text-[11px] shrink-0">
                {{ selectedItem.method }}
              </span>
              <span class="font-semibold font-mono truncate" style="color: var(--text-primary);" :title="selectedItem.full_url">
                {{ selectedItem.full_url }}
              </span>
            </div>
            <div class="flex items-center gap-1.5 shrink-0 flex-wrap">
              <span class="ui-num text-[11px]" style="color: var(--text-muted);">{{ selectedItem.timestamp }}</span>
              <span class="px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 font-semibold text-[11px]">
                全面放行解密
              </span>
              <button
                @click="compareDecryptedReqResp(selectedItem)"
                class="ui-btn-primary px-2.5 py-1 text-[11px]"
                title="对比此笔会话解密请求体与响应体的差分与波形"
              >
                <AppIcon name="scale" :size="12" />
                <span>请求 vs 响应</span>
              </button>
              <button
                @click="setDiffSlotA(selectedItem)"
                class="px-2 py-1 rounded-lg bg-blue-500/12 hover:bg-blue-500/20 text-blue-700 dark:text-sky-300 border border-blue-500/25 font-semibold text-[11px] cursor-pointer transition-colors"
                title="将此会话明文载荷存入全局比对槽位 A"
              >
                设为 A
              </button>
              <button
                @click="setDiffSlotB(selectedItem)"
                class="px-2 py-1 rounded-lg bg-purple-500/12 hover:bg-purple-500/20 text-purple-700 dark:text-purple-300 border border-purple-500/25 font-semibold text-[11px] cursor-pointer transition-colors"
                title="将此会话明文载荷存入全局比对槽位 B 并启动比对"
              >
                设为 B
              </button>
              <button
                @click="addDecryptedToDiffQueue(selectedItem)"
                class="px-2 py-1 rounded-lg bg-emerald-500/12 hover:bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border border-emerald-500/25 font-semibold text-[11px] cursor-pointer transition-colors"
                title="加入全局多组 Center-Star 比对队列"
              >
                + 入队比对
              </button>
            </div>
          </div>

          <!-- 上下分屏：请求明文与响应明文 -->
          <div class="flex-1 grid grid-rows-2 gap-2.5 overflow-hidden min-h-0">
            <div class="border rounded-xl p-3 flex flex-col overflow-hidden min-h-0" style="border-color: var(--border-subtle); background: var(--surface-content-alt);">
              <div class="flex items-center justify-between mb-1.5 shrink-0 border-b pb-1.5" style="border-color: var(--border-subtle);">
                <span class="text-xs font-semibold" style="color: var(--text-primary);">HTTP 请求明文 (Request Headers &amp; Payload)</span>
                <span class="text-[11px] ui-num" style="color: var(--text-muted);">{{ Object.keys(selectedItem.request_headers).length }} 个头部</span>
              </div>

              <div class="flex-1 overflow-y-auto custom-scrollbar font-mono text-[11px] space-y-2">
                <div class="ui-sub-card space-y-0.5 p-2.5">
                  <div v-for="(v, k) in selectedItem.request_headers" :key="k" class="flex gap-2">
                    <span class="shrink-0 font-semibold" style="color: var(--text-muted);">{{ k }}:</span>
                    <span class="break-all" style="color: var(--text-primary);">{{ v }}</span>
                  </div>
                </div>

                <div v-if="selectedItem.request_body_snippet">
                  <div class="text-[11px] font-semibold mb-1" style="color: var(--text-muted);">请求载荷主体 (Payload Body)</div>
                  <pre class="p-2.5 rounded-lg overflow-x-auto text-[11px] leading-relaxed whitespace-pre-wrap border text-emerald-700 dark:text-emerald-400" style="background: var(--surface-input); border-color: var(--border-subtle);">{{ formatPayload(selectedItem.request_body_snippet) }}</pre>
                </div>
              </div>
            </div>

            <div class="border rounded-xl p-3 flex flex-col overflow-hidden min-h-0" style="border-color: var(--border-subtle); background: var(--surface-content-alt);">
              <div class="flex items-center justify-between mb-1.5 shrink-0 border-b pb-1.5" style="border-color: var(--border-subtle);">
                <span class="text-xs font-semibold" style="color: var(--text-primary);">HTTP 响应明文 (Response Headers &amp; Body)</span>
                <span class="text-[11px] ui-num" style="color: var(--text-muted);">状态码: {{ selectedItem.response_status }}</span>
              </div>

              <div class="flex-1 overflow-y-auto custom-scrollbar font-mono text-[11px] space-y-2">
                <pre class="p-2.5 rounded-lg overflow-x-auto text-[11px] leading-relaxed whitespace-pre-wrap border" style="background: var(--surface-input); border-color: var(--border-subtle); color: var(--text-primary);">{{ selectedItem.response_body_snippet || '(空响应体)' }}</pre>
              </div>
            </div>
          </div>
        </div>

        <div v-else class="h-full flex items-center justify-center">
          <EmptyState
            icon="search"
            title="未选择解密流量记录"
            description="在左侧列表中点击任意流量记录，即可在此查看双向完整解密明文。"
          />
        </div>
      </div>
    </section>

    <!-- 3. 模态弹窗：CA 根证书配置与安装向导 -->
    <div v-if="showCaModal" class="ui-modal-backdrop fixed inset-0 z-50 flex items-center justify-center p-6">
      <div class="ui-modal-surface rounded-2xl w-full max-w-xl flex flex-col overflow-hidden font-sans select-text">
        <div class="px-5 py-4 border-b flex items-center justify-between" style="border-color: var(--border-subtle);">
          <div class="flex items-center gap-2.5">
            <div class="w-8 h-8 rounded-xl bg-purple-500/12 text-purple-600 dark:text-purple-300 flex items-center justify-center font-bold text-xs">
              CA
            </div>
            <div>
              <h3 class="text-[13px] font-semibold" style="color: var(--text-primary);">Omni-Probe 专属受信任根证书 (Root CA)</h3>
              <p class="text-[11px] mt-0.5" style="color: var(--text-muted);">
                用于拦截 HTTPS CONNECT 隧道并动态签发目标域名中间证书以实现应用层解密
              </p>
            </div>
          </div>
          <button @click="showCaModal = false" class="p-1.5 rounded-lg hover:bg-[var(--surface-hover)] cursor-pointer" style="color: var(--text-secondary);">
            <AppIcon name="close" :size="14" />
          </button>
        </div>

        <div class="p-5 space-y-3 overflow-y-auto max-h-[60vh] text-xs">
          <div class="p-3 bg-amber-500/10 border border-amber-500/25 rounded-xl text-amber-800 dark:text-amber-200 text-xs leading-relaxed">
            <strong>Windows 信任安装方法：</strong> 将下方 PEM 证书复制并保存为 <code>omni_probe_ca.crt</code>，双击打开 → 点击“安装证书” → 选择“本地计算机” → 放置在“受信任的根证书颁发机构”。
          </div>

          <div>
            <div class="flex items-center justify-between mb-1.5">
              <span class="text-[11px] font-semibold" style="color: var(--text-muted);">根证书 PEM 文本</span>
              <button @click="copyCaPem" class="text-purple-600 dark:text-purple-300 hover:underline text-[11px] font-medium cursor-pointer">
                一键复制 PEM
              </button>
            </div>
            <textarea
              :value="caCertPem"
              readonly
              rows="8"
              class="ui-input w-full p-2.5 text-[11px] font-mono select-text"
            ></textarea>
          </div>
        </div>

        <div class="px-5 py-3 border-t flex justify-end" style="border-color: var(--border-subtle);">
          <button @click="showCaModal = false" class="ui-btn-primary px-4 py-1.5 text-xs">完成</button>
        </div>
      </div>
    </div>

    <!-- 被动流式解密透视弹窗 -->
    <div v-if="showPassiveModal" class="ui-modal-backdrop fixed inset-0 flex items-center justify-center z-50 p-4">
      <div class="ui-modal-surface rounded-2xl max-w-3xl w-full max-h-[85vh] flex flex-col overflow-hidden select-text">
        <div class="p-3.5 border-b flex items-center justify-between" style="border-color: var(--border-subtle);">
          <div class="flex items-center gap-2 flex-wrap">
            <h3 class="text-sm font-semibold" style="color: var(--text-primary);">被动 TLS 记录层流式解密器</h3>
            <span class="px-2 py-0.5 rounded text-[11px] bg-indigo-500/15 text-indigo-700 dark:text-indigo-300 font-semibold border border-indigo-500/25">
              RFC 8446 / RFC 5246 · 对齐 Wireshark
            </span>
          </div>
          <button @click="showPassiveModal = false" class="p-1.5 rounded-lg hover:bg-[var(--surface-hover)] cursor-pointer" style="color: var(--text-secondary);">
            <AppIcon name="close" :size="14" />
          </button>
        </div>

        <div class="p-4 flex-1 overflow-y-auto custom-scrollbar text-xs space-y-3" style="color: var(--text-secondary);">
          <div class="p-3 bg-indigo-500/10 rounded-xl border border-indigo-500/25 text-xs leading-relaxed" style="color: var(--text-primary);">
            <span class="font-semibold">工作原理：</span>输入 TCP 重组后的 Client 原始 TLS 字节流与 Server 原始 TLS 字节流，系统自动提取 32 字节 ClientRandom 并检索 NSS 密钥库，执行 HKDF/PRF 密钥派生与 AEAD 流式解密。
          </div>

          <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label class="text-[11px] font-semibold block mb-1" style="color: var(--text-muted);">客户端 TCP 载荷 (Hex):</label>
              <textarea
                v-model="passiveClientHex"
                rows="5"
                placeholder="例如: 16030300bc010000b80303...170303..."
                class="ui-input w-full p-2 text-[11px] font-mono resize-none"
              ></textarea>
            </div>
            <div>
              <label class="text-[11px] font-semibold block mb-1" style="color: var(--text-muted);">服务端 TCP 载荷 (Hex):</label>
              <textarea
                v-model="passiveServerHex"
                rows="5"
                placeholder="例如: 160303007a020000760303...170303..."
                class="ui-input w-full p-2 text-[11px] font-mono resize-none"
              ></textarea>
            </div>
          </div>

          <div class="flex items-center justify-between pt-1">
            <span class="text-[11px] ui-num" style="color: var(--text-muted);">
              当前 NSS 密钥库已就绪: {{ keylogStatus.total_keys }} 组密钥
            </span>
            <button @click="executePassiveDecrypt" :disabled="passiveLoading" class="ui-btn-primary px-4 py-2 text-xs">
              <span>{{ passiveLoading ? '正在解密中...' : '执行被动 AEAD 解密' }}</span>
            </button>
          </div>

          <div v-if="passiveResults.length > 0" class="space-y-2 pt-2">
            <div class="text-xs font-semibold" style="color: var(--text-primary);">
              解密还原出的应用层明文记录 ({{ passiveResults.length }} 条):
            </div>

            <div v-for="(item, idx) in passiveResults" :key="idx" class="ui-sub-card p-2.5 flex flex-col gap-1.5">
              <div class="flex items-center justify-between text-[11px] ui-num">
                <span class="font-semibold text-indigo-600 dark:text-indigo-300">
                  #{{ item.sequence_number }} · {{ item.direction }}
                </span>
                <span style="color: var(--text-muted);">{{ item.tls_version }} | {{ item.cipher_suite }} | {{ item.plaintext_len }} 字节</span>
              </div>
              <pre class="p-2.5 rounded-lg text-[11px] overflow-x-auto whitespace-pre-wrap select-text font-mono leading-relaxed border text-emerald-700 dark:text-emerald-400" style="background: var(--surface-input); border-color: var(--border-subtle);">{{ item.plaintext_utf8 || item.plaintext_hex }}</pre>
            </div>
          </div>
        </div>

        <div class="p-3 border-t flex justify-end" style="border-color: var(--border-subtle);">
          <button @click="showPassiveModal = false" class="ui-btn-secondary px-4 py-1.5 text-xs">关闭</button>
        </div>
      </div>
    </div>

    <!-- QUIC / HTTP/3 工作台视图 -->
    <section v-if="activeProtocolTab === 'quic'" class="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-2.5 overflow-hidden min-h-0 select-text">
      <div class="lg:col-span-5 ui-content-card p-3 flex flex-col overflow-hidden min-h-0">
        <div class="flex items-center justify-between mb-2 shrink-0">
          <div class="text-[13px] font-semibold" style="color: var(--text-primary);">QUIC / HTTP/3 多流重组列表</div>
          <span class="text-[11px] ui-num" style="color: var(--text-muted);">{{ quicStreams.length }} 条流</span>
        </div>
        <div class="flex-1 overflow-y-auto custom-scrollbar border rounded-xl" style="border-color: var(--border-subtle); background: var(--surface-content-alt);">
          <table class="w-full text-left border-collapse text-xs">
            <thead class="ui-table-head sticky top-0 select-none">
              <tr>
                <th class="py-2 px-2.5">Stream ID</th>
                <th class="py-2 px-2.5">状态</th>
                <th class="py-2 px-2.5 text-right">重组字节</th>
                <th class="py-2 px-2.5 text-right">H3 帧数</th>
              </tr>
            </thead>
            <tbody class="divide-y" style="border-color: var(--border-subtle);">
              <tr
                v-for="stream in quicStreams"
                :key="stream.stream_id"
                @click="selectedQuicStream = stream"
                :class="[
                  'hover:bg-[var(--surface-hover)] cursor-pointer transition-colors',
                  selectedQuicStream?.stream_id === stream.stream_id ? 'bg-indigo-500/12 font-semibold' : ''
                ]"
              >
                <td class="py-2 px-2.5 text-indigo-600 dark:text-indigo-300 font-semibold ui-num">#{{ stream.stream_id }}</td>
                <td class="py-2 px-2.5">
                  <span
                    :class="stream.is_complete ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300' : 'bg-amber-500/15 text-amber-700 dark:text-amber-300'"
                    class="px-1.5 py-0.5 rounded text-[11px] font-semibold"
                  >
                    {{ stream.is_complete ? 'FIN_COMPLETE' : 'STREAMING' }}
                  </span>
                </td>
                <td class="py-2 px-2.5 text-right ui-num" style="color: var(--text-secondary);">{{ formatBytes(stream.bytes_assembled) }}</td>
                <td class="py-2 px-2.5 text-right ui-num text-indigo-600 dark:text-indigo-300 font-semibold">{{ stream.http3_frames.length }}</td>
              </tr>
              <tr v-if="quicStreams.length === 0">
                <td colspan="4" class="py-12 px-4 text-center text-xs leading-relaxed" style="color: var(--text-muted);">
                  暂无已解密 QUIC / HTTP/3 会话流。<br />
                  捕获 UDP 443 Initial 报文时将自动派生 RFC 9001 初始密钥并解密入库；也可在右侧粘贴十六进制载荷手工解码。
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <div class="lg:col-span-7 ui-content-card p-3 flex flex-col gap-3 overflow-hidden min-h-0">
        <div class="ui-sub-card p-3 flex flex-col gap-2 shrink-0">
          <div class="flex items-center justify-between gap-2 flex-wrap">
            <span class="text-xs font-semibold" style="color: var(--text-primary);">RFC 9001 QUIC Initial 单包 AEAD 解密与首部去保护验证</span>
            <button @click="executeManualQuicDecrypt" :disabled="quicManualLoading" class="ui-btn-primary px-3 py-1 text-xs">
              {{ quicManualLoading ? '解密中...' : '执行 QUIC Initial 解密' }}
            </button>
          </div>
          <textarea
            v-model="manualQuicHex"
            rows="2"
            placeholder="粘贴 UDP 443 原始 QUIC Initial 载荷十六进制字节流 (例如 c00000000108...)..."
            class="ui-input w-full p-2 text-[11px] font-mono resize-none"
          ></textarea>
          <div v-if="manualQuicResult" class="p-2.5 rounded-lg border text-[11px] font-mono space-y-1 max-h-36 overflow-y-auto custom-scrollbar" style="background: var(--surface-input); border-color: var(--border-subtle);">
            <div class="flex items-center justify-between text-emerald-600 dark:text-emerald-400 font-semibold">
              <span>包类型: {{ manualQuicResult.packet_type }} | Packet Number: {{ manualQuicResult.packet_number }} (PN长: {{ manualQuicResult.pn_bytes_len }}B)</span>
              <span>解密帧数: {{ manualQuicResult.parsed_frames.length }}</span>
            </div>
            <div style="color: var(--text-muted);">Header Hex: {{ bytesToHexSnippet(manualQuicResult.header_bytes) }}</div>
            <div class="text-blue-600 dark:text-sky-300">QUIC 明文帧: {{ manualQuicResult.parsed_frames.map(formatRustEnum).join(' · ') || '空/Padding' }}</div>
          </div>
        </div>

        <div class="flex-1 flex flex-col overflow-hidden min-h-0 border rounded-xl" style="border-color: var(--border-subtle); background: var(--surface-content-alt);">
          <div class="px-3 py-2 border-b flex items-center justify-between shrink-0" style="border-color: var(--border-subtle);">
            <span class="text-xs font-semibold" style="color: var(--text-primary);">
              {{ selectedQuicStream ? `Stream #${selectedQuicStream.stream_id} HTTP/3 应用层帧解析 (RFC 9114)` : 'HTTP/3 应用层帧解析详情' }}
            </span>
            <span v-if="selectedQuicStream" class="text-[11px] ui-num" style="color: var(--text-muted);">
              共 {{ selectedQuicStream.http3_frames.length }} 帧 · {{ selectedQuicStream.bytes_assembled }} 字节
            </span>
          </div>
          <div class="flex-1 overflow-y-auto p-3 space-y-2 custom-scrollbar">
            <div v-if="!selectedQuicStream" class="h-full flex items-center justify-center text-xs" style="color: var(--text-muted);">
              请从左侧列表中选择一条 QUIC 重组流以观察解析出的 HTTP/3 帧结构
            </div>
            <div v-else-if="selectedQuicStream.http3_frames.length === 0" class="p-4 text-center text-xs" style="color: var(--text-muted);">
              该流当前尚无完整 HTTP/3 应用帧（可能仍处于 CRYPTO 握手阶段或等待后续 STREAM 分片）
            </div>
            <div v-else v-for="(h3, idx) in selectedQuicStream.http3_frames" :key="idx" class="ui-sub-card p-2.5 text-xs font-mono">
              <div class="text-indigo-600 dark:text-indigo-300 font-semibold">#{{ idx + 1 }} · {{ formatRustEnum(h3) }}</div>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- TLS JA3/JA4 指纹与已知 C2 威胁实时碰撞视图 -->
    <section v-if="activeProtocolTab === 'fingerprint'" class="flex-1 ui-content-card p-3 flex flex-col overflow-hidden min-h-0 select-text">
      <div class="flex items-center justify-between mb-2 shrink-0">
        <div class="text-[13px] font-semibold" style="color: var(--text-primary);">TLS ClientHello 原生 JA3 / JA4 指纹采集与恶意家族碰撞日志</div>
        <span class="text-[11px] ui-num" style="color: var(--text-muted);">累计分析 {{ tlsFpTelemetry.total_client_hellos }} 次握手 (保留最新 {{ tlsFpTelemetry.recent_sessions.length }} 条)</span>
      </div>
      <div class="flex-1 overflow-y-auto custom-scrollbar border rounded-xl" style="border-color: var(--border-subtle); background: var(--surface-content-alt);">
        <table class="w-full text-left border-collapse text-xs">
          <thead class="ui-table-head sticky top-0 select-none">
            <tr>
              <th class="py-2 px-3">捕获时间</th>
              <th class="py-2 px-3">通信五元组 (源 → 宿)</th>
              <th class="py-2 px-3">JA3 MD5 指纹</th>
              <th class="py-2 px-3">FoxIO JA4 指纹</th>
              <th class="py-2 px-3 text-right">恶意家族碰撞</th>
            </tr>
          </thead>
          <tbody class="divide-y" style="border-color: var(--border-subtle);">
            <tr
              v-for="(s, idx) in tlsFpTelemetry.recent_sessions"
              :key="idx"
              :class="s.is_threat ? 'bg-rose-500/8 font-semibold' : 'hover:bg-[var(--surface-hover)]'"
            >
              <td class="py-2 px-3 ui-num" style="color: var(--text-muted);">{{ s.timestamp }}</td>
              <td class="py-2 px-3 ui-num" style="color: var(--text-primary);">{{ s.src_ip }}:{{ s.src_port }} → {{ s.dst_ip }}:{{ s.dst_port }}</td>
              <td class="py-2 px-3 font-mono text-indigo-600 dark:text-indigo-300">{{ s.ja3_hash }}</td>
              <td class="py-2 px-3 font-mono text-blue-600 dark:text-sky-300">{{ s.ja4_string }}</td>
              <td class="py-2 px-3 text-right">
                <span v-if="s.is_threat" class="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-rose-600 text-white text-[11px] font-semibold">
                  <AppIcon name="alert" :size="12" />
                  <span>{{ s.threat_name }}</span>
                </span>
                <span v-else class="px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 text-[11px]">
                  常规指纹
                </span>
              </td>
            </tr>
            <tr v-if="tlsFpTelemetry.recent_sessions.length === 0">
              <td colspan="5" class="py-12 text-center text-xs" style="color: var(--text-muted);">
                尚未在真实 TCP 抓包流中捕获到 TLS ClientHello (0x16 0x03) 握手报文；启动网卡嗅探后将自动计算 JA3 / JA4 指纹。
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue';
import { useUniversalDiff } from '../composables/useUniversalDiff';
import { notifySuccess, notifyWarning, notifyError } from '../composables/useNotification';
import { uiPrompt } from '../composables/useConfirmDialog';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import AppIcon from '../components/AppIcon.vue';
import EmptyState from '../components/EmptyState.vue';

export interface DecryptedTlsPayload {
  stream_id: string;
  direction: string;
  sequence_number: number;
  tls_version: string;
  cipher_suite: string;
  plaintext_utf8: string;
  plaintext_hex: string;
  plaintext_len: number;
  timestamp: string;
}

export interface DecryptedTrafficRecord {
  id: number;
  timestamp: string;
  client_ip: string;
  method: string;
  host: string;
  path: string;
  full_url: string;
  request_headers: Record<string, string>;
  request_body_snippet: string;
  response_status: number;
  response_headers: Record<string, string>;
  response_body_snippet: string;
  is_blocked: boolean;
  block_reason?: string;
  traffic_type: string;
  bytes_total: number;
}

export interface ProxyStatus {
  is_running: boolean;
  listen_port: number;
  total_requests: number;
  blocked_requests: number;
  ca_cert_path: string;
  active_blocking_enforced: boolean;
}

export interface TlsKeyLogStatus {
  total_keys: number;
  active_file_path?: string;
  last_imported_time?: string;
  matched_sessions_count: number;
}

export interface QuicTelemetry {
  total_quic_packets_decrypted: number;
  total_active_streams: number;
  initial_auto_decrypted_count: number;
}

export type RustSerializedEnum = string | Record<string, Record<string, unknown> | unknown[] | string | number>;

export interface QuicStreamSummary {
  stream_id: number;
  bytes_assembled: number;
  is_complete: boolean;
  http3_frames: RustSerializedEnum[];
}

export interface DecryptedQuicPacket {
  packet_type: string;
  packet_number: number;
  pn_bytes_len: number;
  header_bytes: number[];
  payload_bytes: number[];
  parsed_frames: RustSerializedEnum[];
}

export interface TlsFingerprintSessionRecord {
  timestamp: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  ja3_hash: string;
  ja4_string: string;
  is_threat: boolean;
  threat_name?: string | null;
}

export interface TlsFingerprintTelemetry {
  total_client_hellos: number;
  threat_hit_count: number;
  builtin_threat_signatures: number;
  recent_sessions: TlsFingerprintSessionRecord[];
}

// 响应式状态
const proxyPort = ref(8899);
const proxyStatus = ref<ProxyStatus>({
  is_running: false,
  listen_port: 8899,
  total_requests: 0,
  blocked_requests: 0,
  ca_cert_path: '',
  active_blocking_enforced: false,
});
const keylogStatus = ref<TlsKeyLogStatus>({
  total_keys: 0,
  matched_sessions_count: 0,
});
// 全局通用数据比对总线
const diffBus = useUniversalDiff();

function compareDecryptedReqResp(item: DecryptedTrafficRecord) {
  const reqBody = item.request_body_snippet || JSON.stringify(item.request_headers);
  const respBody = item.response_body_snippet || '';
  const reqItem = {
    id: `DEC_REQ_${item.id}`,
    label: `[解密请求] ${item.method} ${item.full_url}`,
    timestamp: item.timestamp,
    protocol: 'HTTP/TLS_REQ',
    src: '客户端代理',
    dst: item.host || '目标服务器',
    format: 'ASCII',
    isRawText: true,
    payloadHex: '',
    rawText: reqBody,
    length: reqBody.length,
    extraFields: { method: item.method, host: item.host, path: item.path }
  };
  const respItem = {
    id: `DEC_RESP_${item.id}`,
    label: `[解密响应] 状态码 ${item.response_status}`,
    timestamp: item.timestamp,
    protocol: 'HTTP/TLS_RESP',
    src: item.host || '目标服务器',
    dst: '客户端代理',
    format: 'ASCII',
    isRawText: true,
    payloadHex: '',
    rawText: respBody,
    length: respBody.length,
    extraFields: { response_status: String(item.response_status), content_type: item.response_headers?.['content-type'] || item.response_headers?.['Content-Type'] || item.traffic_type || '-' }
  };
  diffBus.openUniversalDiff(reqItem, respItem, 'hex');
}

function buildDecryptedSessionItem(item: DecryptedTrafficRecord) {
  const text = item.response_body_snippet || item.request_body_snippet || JSON.stringify(item.request_headers);
  return {
    id: `DEC_${item.id}`,
    label: `[解密会话] ${item.method} ${item.host}${item.path}`,
    timestamp: item.timestamp,
    protocol: 'DECRYPTED_TLS',
    src: '代理通道',
    dst: item.host || '-',
    format: 'ASCII',
    isRawText: true,
    payloadHex: '',
    rawText: text,
    length: text.length,
    extraFields: {
      method: item.method,
      status: String(item.response_status),
      host: item.host,
      bytes_total: String(item.bytes_total)
    }
  };
}

function setDiffSlotA(item: DecryptedTrafficRecord) {
  diffBus.setSlotA(buildDecryptedSessionItem(item), `解密 #${item.id}`);
}

function setDiffSlotB(item: DecryptedTrafficRecord) {
  diffBus.setSlotB(buildDecryptedSessionItem(item), `解密 #${item.id}`);
  if (diffBus.slotA.value) {
    diffBus.compareSlots();
  }
}

function addDecryptedToDiffQueue(item: DecryptedTrafficRecord) {
  diffBus.addToQueue(buildDecryptedSessionItem(item), `解密 #${item.id} ${item.method}`, false);
}

const decryptedLogs = ref<DecryptedTrafficRecord[]>([]);
const selectedItem = ref<DecryptedTrafficRecord | null>(null);

const filterKeyword = ref('');
const showCaModal = ref(false);
const caCertPem = ref('');

// 被动流式解密状态
const showPassiveModal = ref(false);
const passiveClientHex = ref('');
const passiveServerHex = ref('');
const passiveLoading = ref(false);
const passiveResults = ref<DecryptedTlsPayload[]>([]);

// QUIC / HTTP/3 工作台状态
const activeProtocolTab = ref<'tls' | 'quic' | 'fingerprint'>('tls');
const quicTelemetry = ref<QuicTelemetry>({
  total_quic_packets_decrypted: 0,
  total_active_streams: 0,
  initial_auto_decrypted_count: 0,
});
const tlsFpTelemetry = ref<TlsFingerprintTelemetry>({
  total_client_hellos: 0,
  threat_hit_count: 0,
  builtin_threat_signatures: 0,
  recent_sessions: [],
});
const quicStreams = ref<QuicStreamSummary[]>([]);
const selectedQuicStream = ref<QuicStreamSummary | null>(null);
const manualQuicHex = ref('');
const manualQuicResult = ref<DecryptedQuicPacket | null>(null);
const quicManualLoading = ref(false);

const formatRustEnum = (val: RustSerializedEnum): string => {
  if (typeof val === 'string') return val;
  if (val && typeof val === 'object') {
    return Object.entries(val)
      .map(([k, v]) => `${k}: ${typeof v === 'object' ? JSON.stringify(v) : String(v)}`)
      .join(', ');
  }
  return String(val);
};

const bytesToHexSnippet = (bytes: number[]): string => {
  const slice = bytes.slice(0, 64);
  const hex = slice.map((b) => b.toString(16).padStart(2, '0')).join(' ');
  return bytes.length > 64 ? `${hex} ... (${bytes.length}B)` : hex;
};

const fetchQuicState = async () => {
  try {
    const [tel, streams] = await Promise.all([
      invoke<QuicTelemetry>('get_quic_telemetry_cmd'),
      invoke<QuicStreamSummary[]>('get_quic_streams_cmd'),
    ]);
    quicTelemetry.value = tel;
    quicStreams.value = streams;
    if (selectedQuicStream.value) {
      const updated = streams.find((s) => s.stream_id === selectedQuicStream.value?.stream_id);
      if (updated) selectedQuicStream.value = updated;
    }
  } catch (e) {
    console.error('获取 QUIC 状态失败:', e);
  }
};

const switchToQuicTab = async () => {
  activeProtocolTab.value = 'quic';
  await fetchQuicState();
};

const fetchTlsFingerprints = async () => {
  try {
    tlsFpTelemetry.value = await invoke<TlsFingerprintTelemetry>('get_tls_fingerprint_telemetry_cmd');
  } catch (e) {
    console.error('获取 TLS 指纹统计失败:', e);
  }
};

const switchToFingerprintTab = async () => {
  activeProtocolTab.value = 'fingerprint';
  await fetchTlsFingerprints();
};

const executeManualQuicDecrypt = async () => {
  const cleaned = manualQuicHex.value.trim().replace(/\s+/g, '');
  if (!cleaned || cleaned.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(cleaned)) {
    notifyWarning('十六进制输入无效', '请输入偶数位合法十六进制 QUIC UDP 原始载荷');
    return;
  }
  const packetBytes: number[] = [];
  for (let i = 0; i < cleaned.length; i += 2) {
    packetBytes.push(parseInt(cleaned.slice(i, i + 2), 16));
  }
  quicManualLoading.value = true;
  try {
    manualQuicResult.value = await invoke<DecryptedQuicPacket>('inspect_and_decrypt_quic_packet_cmd', {
      packetBytes,
    });
    notifySuccess('QUIC Initial AEAD 解密成功', `Packet #${manualQuicResult.value.packet_number} | 解出 ${manualQuicResult.value.parsed_frames.length} 帧`);
    await fetchQuicState();
  } catch (e) {
    notifyError('QUIC 解密失败', e);
  } finally {
    quicManualLoading.value = false;
  }
};

const executePassiveDecrypt = async () => {
  if (!passiveClientHex.value.trim() || !passiveServerHex.value.trim()) {
    notifyWarning('输入参数不完整', '请同时输入客户端与服务端 TCP 载荷十六进制数据');
    return;
  }
  passiveLoading.value = true;
  try {
    passiveResults.value = await invoke<DecryptedTlsPayload[]>('decrypt_stream_with_keylog_cmd', {
      clientHex: passiveClientHex.value.trim().replace(/\s+/g, ''),
      serverHex: passiveServerHex.value.trim().replace(/\s+/g, ''),
      streamId: 'MANUAL_PASSIVE_STREAM',
    });
    if (passiveResults.value.length === 0) {
      notifyWarning('解密未命中', '未解密出应用层明文记录，请检查 ClientHello 是否完整以及 NSS 密钥库中是否存在对应的 ClientRandom 密钥。');
    }
  } catch (e) {
    notifyError('被动解密执行受阻', e);
  } finally {
    passiveLoading.value = false;
  }
};

let unlistenTraffic: (() => void) | null = null;
let pollTimer: number | null = null;

const filteredLogs = computed(() => {
  return decryptedLogs.value.filter(item => {
    if (filterKeyword.value.trim()) {
      const kw = filterKeyword.value.trim().toLowerCase();
      const matchUrl = item.full_url.toLowerCase().includes(kw);
      const matchMethod = item.method.toLowerCase().includes(kw);
      const matchHost = item.host.toLowerCase().includes(kw);
      if (!matchUrl && !matchMethod && !matchHost) {
        return false;
      }
    }
    return true;
  });
});

const formatBytes = (bytes: number) => {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
};

const getMethodColor = (m: string) => {
  switch (m.toUpperCase()) {
    case 'GET': return 'text-blue-600 dark:text-sky-400';
    case 'POST': return 'text-emerald-600 dark:text-emerald-400';
    case 'PUT': return 'text-amber-600 dark:text-amber-400';
    case 'DELETE': return 'text-rose-600 dark:text-rose-400';
    case 'CONNECT': return 'text-purple-600 dark:text-purple-300';
    default: return 'text-[var(--text-secondary)]';
  }
};

const formatPayload = (snippet: string) => {
  try {
    const obj = JSON.parse(snippet);
    return JSON.stringify(obj, null, 2);
  } catch (err) {
    console.debug('[TrafficDecryptionView] formatPayload non-JSON text fallback:', err);
    return snippet;
  }
};

// 后端交互
const fetchStatus = async () => {
  try {
    proxyStatus.value = await invoke<ProxyStatus>('get_proxy_status_cmd');
    keylogStatus.value = await invoke<TlsKeyLogStatus>('get_keylog_status_cmd');
  } catch (e) {
    console.error('获取代理状态失败:', e);
  }
};

const fetchLogs = async () => {
  try {
    decryptedLogs.value = await invoke<DecryptedTrafficRecord[]>('get_decrypted_traffic_logs_cmd', { limit: 300 });
  } catch (e) {
    console.error('获取解密日志失败:', e);
  }
};

const fetchCaPem = async () => {
  try {
    caCertPem.value = await invoke<string>('get_ca_cert_pem_cmd');
  } catch (e) {
    console.error('获取 CA 证书失败:', e);
  }
};

const toggleProxy = async () => {
  try {
    if (proxyStatus.value.is_running) {
      await invoke('stop_tls_proxy_cmd');
    } else {
      await invoke('start_tls_proxy_cmd', { port: proxyPort.value });
    }
    await fetchStatus();
  } catch (e) {
    console.error('切换代理状态失败:', e);
  }
};

const clearDecryptedLogs = async () => {
  try {
    await invoke('clear_decrypted_traffic_logs_cmd');
    decryptedLogs.value = [];
    selectedItem.value = null;
  } catch (e) {
    console.error('清空解密日志失败:', e);
  }
};

const copyCaPem = () => {
  navigator.clipboard.writeText(caCertPem.value);
  notifySuccess('根证书已复制', 'CA 根证书 PEM 文本已成功复制到系统剪贴板');
};

const triggerKeylogSelect = async () => {
  const path = await uiPrompt(
    '请输入 NSS SSLKEYLOGFILE 密钥日志文件的绝对路径 (如 Windows: C:\\keys\\sslkeylog.log 或 Linux/macOS: /path/to/sslkeylog.log):',
    '',
    {
      title: '导入 SSLKEYLOGFILE 密钥库',
      placeholder: 'C:\\keys\\sslkeylog.log',
      confirmText: '导入密钥库',
    }
  );
  if (path && path.trim()) {
    try {
      const count = await invoke<number>('load_sslkeylog_file_cmd', { filePath: path.trim() });
      notifySuccess('SSL 密钥导入成功', `成功导入 ${count} 组 SSL/TLS 会话主密钥`);
      await fetchStatus();
    } catch (e) {
      notifyError('导入 SSL 会话密钥受阻', e);
    }
  }
};

onMounted(async () => {
  await fetchStatus();
  await fetchLogs();
  await fetchCaPem();
  await fetchQuicState();
  await fetchTlsFingerprints();

  unlistenTraffic = await listen<DecryptedTrafficRecord>('decrypted-traffic', (event) => {
    decryptedLogs.value.unshift(event.payload);
    if (decryptedLogs.value.length > 500) {
      decryptedLogs.value.pop();
    }
    proxyStatus.value.total_requests += 1;
  });

  pollTimer = window.setInterval(() => {
    fetchStatus();
    if (activeProtocolTab.value === 'quic') {
      fetchQuicState();
    } else if (activeProtocolTab.value === 'fingerprint') {
      fetchTlsFingerprints();
    }
  }, 3000);
});

onUnmounted(() => {
  if (unlistenTraffic) {
    unlistenTraffic();
    unlistenTraffic = null;
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
