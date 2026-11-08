<template>
  <div class="h-full flex flex-col gap-2.5 overflow-hidden font-sans">
    
    <!-- 1. 顶部控制栏：代理解密服务、CA 根证书与 NSS 密钥日志状态 -->
    <section class="bg-white/80 backdrop-blur-xl rounded-2xl border border-white/70 p-3 shadow-xs shrink-0 flex flex-col gap-2.5">
      
      <!-- 1.1 标题与代理主开关 -->
      <div class="flex items-center justify-between gap-3">
        <div class="flex items-center gap-2.5">
          <div class="w-8 h-8 rounded-xl bg-purple-600/10 text-purple-600 flex items-center justify-center border border-purple-500/20 shadow-2xs">
            <svg class="w-4 h-4 fill-none stroke-current stroke-2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" d="M13.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H3.75A2.25 2.25 0 001.5 12v6.75a2.25 2.25 0 002.25 2.25z" />
            </svg>
          </div>
          <div>
            <div class="flex items-center gap-2">
              <h2 class="text-xs font-bold text-slate-800 tracking-tight">网络流量全息解密与调试透视</h2>
              <span class="px-1.5 py-0.5 rounded-full text-[9px] font-mono bg-emerald-500/10 text-emerald-700 border border-emerald-500/20 font-bold">
                全面放行 · 全量解密比对
              </span>
            </div>
            <p class="text-[10px] text-slate-400 font-mono mt-0.5">
              双向通信透明穿透 · 应用层明文无损解密 · 数据深度比对基础 · NSS 密钥关联
            </p>
          </div>
        </div>

        <!-- 代理控制与配置 -->
        <div class="flex items-center gap-2">
          
          <!-- 端口输入与启停 -->
          <div class="flex items-center gap-1.5 bg-slate-100/90 rounded-xl p-1 border border-slate-200">
            <span class="text-[10px] font-mono font-bold text-slate-500 pl-1.5">端口:</span>
            <input v-model.number="proxyPort" :disabled="proxyStatus.is_running"
              type="number" min="1024" max="65535"
              class="w-16 px-1.5 py-0.5 text-xs font-mono bg-white border border-slate-200 rounded-lg text-slate-800 outline-none" />
            
            <button @click="toggleProxy"
              :class="[
                'px-3 py-1 rounded-lg text-[11px] font-bold transition-all cursor-pointer shadow-2xs flex items-center gap-1',
                proxyStatus.is_running
                  ? 'bg-rose-500 hover:bg-rose-600 text-white'
                  : 'bg-emerald-600 hover:bg-emerald-700 text-white'
              ]">
              <span class="w-1.5 h-1.5 rounded-full"
                :class="proxyStatus.is_running ? 'bg-white animate-pulse' : 'bg-white/60'"></span>
              <span>{{ proxyStatus.is_running ? '停止代理解密' : '启动代理解密' }}</span>
            </button>
          </div>

          <!-- CA 根证书导出与安装指南按钮 -->
          <button @click="showCaModal = true"
            class="px-2.5 py-1.5 rounded-xl bg-slate-100 hover:bg-slate-200/80 text-slate-700 text-[11px] font-medium flex items-center gap-1.5 transition-all cursor-pointer border border-slate-200 shadow-2xs">
            <svg class="w-3.5 h-3.5 fill-none stroke-current stroke-2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
            </svg>
            <span>CA 根证书配置</span>
          </button>

          <!-- 清空流水 -->
          <button @click="clearDecryptedLogs"
            class="px-2.5 py-1.5 rounded-xl bg-slate-100 hover:bg-rose-50 text-slate-600 hover:text-rose-700 text-[11px] font-medium transition-all cursor-pointer border border-slate-200 shadow-2xs">
            清空流水
          </button>

          <!-- 被动流式解密 (Wireshark 级) -->
          <button @click="showPassiveModal = true"
            class="px-2.5 py-1.5 rounded-xl bg-indigo-50 hover:bg-indigo-100 text-indigo-700 text-[11px] font-medium flex items-center gap-1.5 transition-all cursor-pointer border border-indigo-200 shadow-2xs">
            <svg class="w-3.5 h-3.5 fill-none stroke-current stroke-2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z" />
            </svg>
            <span>被动流式解密 (Wireshark 级)</span>
          </button>

        </div>
      </div>

      <!-- 1.2 态势核心运行指标卡片 -->
      <div class="grid grid-cols-4 gap-2.5">
        
        <div class="bg-slate-50/80 rounded-xl p-2.5 border border-slate-200/60 flex items-center justify-between">
          <div>
            <div class="text-[10px] font-bold text-slate-400 uppercase tracking-wider">代理解密服务状态</div>
            <div class="text-sm font-mono font-bold mt-0.5 flex items-center gap-1.5"
              :class="proxyStatus.is_running ? 'text-emerald-700' : 'text-slate-500'">
              <span class="w-2 h-2 rounded-full"
                :class="proxyStatus.is_running ? 'bg-emerald-500 animate-pulse' : 'bg-slate-400'"></span>
              <span>{{ proxyStatus.is_running ? `全面放行监听 (:${proxyStatus.listen_port})` : '未启动' }}</span>
            </div>
          </div>
          <div class="text-[10px] font-mono text-slate-400 bg-white px-2 py-1 rounded-lg border border-slate-200">
            HTTP/HTTPS
          </div>
        </div>

        <div class="bg-slate-50/80 rounded-xl p-2.5 border border-slate-200/60 flex items-center justify-between">
          <div>
            <div class="text-[10px] font-bold text-slate-400 uppercase tracking-wider">累计解密分析会话</div>
            <div class="text-base font-mono font-bold text-slate-800 mt-0.5">
              {{ proxyStatus.total_requests.toLocaleString() }}
            </div>
          </div>
          <div class="w-7 h-7 rounded-lg bg-blue-500/10 text-blue-600 flex items-center justify-center font-mono text-xs">
            DEC
          </div>
        </div>

        <div class="bg-slate-50/80 rounded-xl p-2.5 border border-slate-200/60 flex items-center justify-between">
          <div>
            <div class="text-[10px] font-bold text-slate-400 uppercase tracking-wider">通信传输控制模式</div>
            <div class="text-sm font-mono font-bold text-emerald-700 mt-0.5 flex items-center gap-1.5">
              <span class="w-2 h-2 rounded-full bg-emerald-500"></span>
              <span>100% 透明放行</span>
            </div>
          </div>
          <div class="text-[10px] font-mono text-emerald-700 bg-emerald-50 px-2 py-1 rounded-lg border border-emerald-200">
            零截断
          </div>
        </div>

        <!-- NSS Key Log 文件状态 -->
        <div class="bg-slate-50/80 rounded-xl p-2.5 border border-slate-200/60 flex items-center justify-between">
          <div class="truncate mr-2">
            <div class="text-[10px] font-bold text-slate-400 uppercase tracking-wider">SSLKEYLOGFILE 密钥库</div>
            <div class="text-xs font-mono font-bold text-slate-800 mt-0.5 truncate"
              :title="keylogStatus.active_file_path || '未加载'">
              {{ keylogStatus.total_keys }} 组密钥 (匹配 {{ keylogStatus.matched_sessions_count }})
            </div>
          </div>
          <button @click="triggerKeylogSelect"
            class="px-2 py-1 rounded-lg bg-purple-50 hover:bg-purple-100 text-purple-700 text-[10px] font-mono shrink-0 border border-purple-200 cursor-pointer">
            导入 KeyLog
          </button>
        </div>

      </div>
    </section>

    <!-- 2. 主分析区：左侧解密流水列表 + 右侧双栏报文结构化深度查看器 -->
    <section class="flex-1 grid grid-cols-12 gap-2.5 overflow-hidden min-h-0">
      
      <!-- 2.1 左侧解密流量流水表 (5 列宽度) -->
      <div class="col-span-5 bg-white/80 backdrop-blur-xl rounded-2xl border border-white/70 p-3 shadow-xs flex flex-col overflow-hidden min-h-0">
        
        <!-- 过滤控制栏 -->
        <div class="flex items-center justify-between gap-2 mb-2 shrink-0">
          <div class="flex items-center gap-1.5 flex-1">
            <input v-model="filterKeyword"
              placeholder="搜索 URL / 域名 / 请求方法..."
              class="w-full px-2.5 py-1 rounded-xl bg-slate-100 border border-slate-200 text-slate-700 text-[11px] outline-none font-mono focus:border-purple-500" />
          </div>
          <span class="text-[10px] font-mono text-slate-400 shrink-0">
            {{ filteredLogs.length }} / {{ decryptedLogs.length }} 会话
          </span>
        </div>

        <!-- 数据表格 -->
        <div class="flex-1 overflow-y-auto custom-scrollbar border border-slate-100 rounded-xl">
          <table class="w-full text-left border-collapse text-[11px] font-mono">
            <thead class="sticky top-0 bg-slate-50/95 backdrop-blur-md text-slate-500 font-semibold border-b border-slate-200 z-10 select-none">
              <tr>
                <th class="py-1.5 px-2 w-10 text-center">ID</th>
                <th class="py-1.5 px-2 w-14">方法</th>
                <th class="py-1.5 px-2">请求目标 & 路径</th>
                <th class="py-1.5 px-2 w-14 text-center">状态</th>
                <th class="py-1.5 px-2 w-16 text-right">大小</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-100">
              <tr v-for="item in filteredLogs" :key="item.id"
                @click="selectedItem = item"
                :class="[
                  'hover:bg-purple-50/50 transition-colors cursor-pointer',
                  selectedItem?.id === item.id ? 'bg-purple-50/80 font-semibold' : ''
                ]">
                <td class="py-1.5 px-2 text-center text-slate-400">{{ item.id }}</td>
                <td class="py-1.5 px-2 font-bold" :class="getMethodColor(item.method)">
                  {{ item.method }}
                </td>
                <td class="py-1.5 px-2 truncate max-w-[160px]">
                  <div class="text-slate-800 truncate" :title="item.host">{{ item.host }}</div>
                  <div class="text-[9px] text-slate-400 truncate" :title="item.path">{{ item.path }}</div>
                </td>
                <td class="py-1.5 px-2 text-center">
                  <span v-if="item.response_status >= 200 && item.response_status < 300"
                    class="px-1.5 py-0.2 rounded text-[9px] font-bold bg-emerald-100 text-emerald-800">
                    {{ item.response_status }}
                  </span>
                  <span v-else-if="item.response_status >= 300 && item.response_status < 400"
                    class="px-1.5 py-0.2 rounded text-[9px] font-bold bg-blue-100 text-blue-800">
                    {{ item.response_status }}
                  </span>
                  <span v-else
                    class="px-1.5 py-0.2 rounded text-[9px] font-bold bg-slate-200 text-slate-700">
                    {{ item.response_status }}
                  </span>
                </td>
                <td class="py-1.5 px-2 text-right text-slate-500 text-[10px]">
                  {{ formatBytes(item.bytes_total) }}
                </td>
              </tr>
              <tr v-if="filteredLogs.length === 0">
                <td colspan="5" class="py-12 text-center text-slate-400 font-mono text-xs">
                  暂无解密流量记录 (请确保客户端/浏览器已配置代理 http://127.0.0.1:{{ proxyPort }})
                </td>
              </tr>
            </tbody>
          </table>
        </div>

      </div>

      <!-- 2.2 右侧双栏明文 HTTP 深度结构化查看器 (7 列宽度) -->
      <div class="col-span-7 bg-white/80 backdrop-blur-xl rounded-2xl border border-white/70 p-3 shadow-xs flex flex-col overflow-hidden min-h-0">
        
        <div v-if="selectedItem" class="flex-1 flex flex-col overflow-hidden gap-3 min-h-0">
          
          <!-- 选中项摘要条 -->
          <div class="flex items-center justify-between p-2.5 rounded-xl border border-slate-200 bg-slate-50/80 text-[11px] font-mono shrink-0">
            <div class="flex items-center gap-2 truncate">
              <span class="px-2 py-0.5 rounded text-white font-bold bg-purple-600">
                {{ selectedItem.method }}
              </span>
              <span class="font-bold text-slate-800 truncate" :title="selectedItem.full_url">
                {{ selectedItem.full_url }}
              </span>
            </div>
            <div class="flex items-center gap-2 shrink-0">
              <span class="text-slate-400">{{ selectedItem.timestamp }}</span>
              <span class="px-2 py-0.5 rounded bg-emerald-100 text-emerald-800 font-bold text-[10px]">
                全面放行解密
              </span>
            </div>
          </div>

          <!-- 上下分屏：请求明文与响应明文 -->
          <div class="flex-1 grid grid-rows-2 gap-2.5 overflow-hidden min-h-0">
            
            <!-- 上屏：解密后的请求头与请求体 -->
            <div class="border border-slate-200 rounded-xl p-2.5 flex flex-col bg-white overflow-hidden min-h-0">
              <div class="flex items-center justify-between mb-1.5 shrink-0 border-b border-slate-100 pb-1">
                <span class="text-[11px] font-bold text-slate-700">HTTP 请求明文 (Request Headers & Payload)</span>
                <span class="text-[10px] font-mono text-slate-400">{{ Object.keys(selectedItem.request_headers).length }} 个头部</span>
              </div>
              
              <div class="flex-1 overflow-y-auto custom-scrollbar font-mono text-[10px] space-y-2">
                <!-- Headers -->
                <div class="space-y-0.5 bg-slate-50 p-2 rounded-lg border border-slate-100">
                  <div v-for="(v, k) in selectedItem.request_headers" :key="k" class="flex gap-2">
                    <span class="text-slate-500 shrink-0 font-bold">{{ k }}:</span>
                    <span class="text-slate-800 break-all">{{ v }}</span>
                  </div>
                </div>

                <!-- Request Body -->
                <div v-if="selectedItem.request_body_snippet">
                  <div class="text-[9px] font-bold text-slate-400 uppercase tracking-wider mb-1">请求载荷主体 (Payload Body)</div>
                  <pre class="bg-slate-900 text-emerald-400 p-2 rounded-lg overflow-x-auto text-[10px] leading-relaxed whitespace-pre-wrap">{{ formatPayload(selectedItem.request_body_snippet) }}</pre>
                </div>
              </div>
            </div>

            <!-- 下屏：解密后的响应头与响应体 -->
            <div class="border border-slate-200 rounded-xl p-2.5 flex flex-col bg-white overflow-hidden min-h-0">
              <div class="flex items-center justify-between mb-1.5 shrink-0 border-b border-slate-100 pb-1">
                <span class="text-[11px] font-bold text-slate-700">HTTP 响应明文 (Response Headers & Body)</span>
                <span class="text-[10px] font-mono text-slate-400">状态码: {{ selectedItem.response_status }}</span>
              </div>

              <div class="flex-1 overflow-y-auto custom-scrollbar font-mono text-[10px] space-y-2">
                <!-- Response Body -->
                <pre class="p-2 rounded-lg overflow-x-auto text-[10px] leading-relaxed whitespace-pre-wrap bg-slate-900 text-slate-200">{{ selectedItem.response_body_snippet || '(空响应体)' }}</pre>
              </div>
            </div>

          </div>

        </div>

        <div v-else class="h-full flex flex-col items-center justify-center text-slate-400 font-mono text-xs gap-2">
          <div class="w-10 h-10 rounded-2xl bg-slate-100 flex items-center justify-center text-lg">
            🔍
          </div>
          <div>在左侧列表中点击任意流量记录，即可在此查看双向完整解密明文</div>
        </div>

      </div>

    </section>

    <!-- 3. 模态弹窗：CA 根证书配置与安装向导 -->
    <div v-if="showCaModal"
      class="fixed inset-0 bg-slate-900/40 backdrop-blur-sm z-50 flex items-center justify-center p-6">
      <div class="bg-white rounded-2xl shadow-2xl border border-white/80 w-full max-w-xl flex flex-col overflow-hidden font-sans">
        
        <div class="px-5 py-4 border-b border-slate-100 flex items-center justify-between bg-slate-50/50">
          <div class="flex items-center gap-2.5">
            <div class="w-8 h-8 rounded-xl bg-purple-500/10 text-purple-600 flex items-center justify-center font-bold text-xs">
              CA
            </div>
            <div>
              <h3 class="text-xs font-bold text-slate-800">Omni-Probe 专属受信任根证书 (Root CA)</h3>
              <p class="text-[10px] text-slate-400 font-mono mt-0.5">
                用于拦截 HTTPS CONNECT 隧道并动态签发目标域名中间证书以实现应用层解密
              </p>
            </div>
          </div>
          <button @click="showCaModal = false"
            class="w-6 h-6 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-400 hover:text-slate-700 flex items-center justify-center text-xs font-bold cursor-pointer">
            ✕
          </button>
        </div>

        <div class="p-5 space-y-3 overflow-y-auto max-h-[60vh] font-mono text-[11px]">
          <div class="p-3 bg-amber-50 border border-amber-200 rounded-xl text-amber-800 text-[11px] font-sans">
            <strong>Windows 信任安装方法：</strong> 将下方 PEM 证书复制并保存为 <code>omni_probe_ca.crt</code>，双击打开 → 点击“安装证书” → 选择“本地计算机” → 放置在“受信任的根证书颁发机构”。
          </div>

          <div>
            <div class="flex items-center justify-between mb-1">
              <span class="text-[10px] font-bold text-slate-500">根证书 PEM 文本</span>
              <button @click="copyCaPem" class="text-purple-600 hover:underline text-[10px] cursor-pointer">
                一键复制 PEM
              </button>
            </div>
            <textarea :value="caCertPem" readonly rows="8"
              class="w-full p-2 bg-slate-50 border border-slate-200 rounded-xl text-[10px] font-mono outline-none select-all"></textarea>
          </div>
        </div>

        <div class="px-5 py-3 border-t border-slate-100 bg-slate-50/50 flex justify-end">
          <button @click="showCaModal = false"
            class="px-4 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-900 text-white text-xs font-medium cursor-pointer">
            完成
          </button>
        </div>

      </div>
    </div>

    <!-- 被动流式解密透视弹窗 (Wireshark 级) -->
    <div v-if="showPassiveModal"
      class="fixed inset-0 bg-slate-900/40 backdrop-blur-xs flex items-center justify-center z-50 p-4">
      <div class="bg-white rounded-2xl max-w-3xl w-full max-h-[85vh] flex flex-col shadow-2xl border border-slate-200 overflow-hidden">
        
        <div class="p-3.5 border-b border-slate-200 flex items-center justify-between bg-slate-50/80">
          <div class="flex items-center gap-2">
            <h3 class="text-sm font-bold text-slate-800">被动 TLS 记录层流式解密器</h3>
            <span class="px-2 py-0.5 rounded text-[10px] font-mono bg-indigo-50 text-indigo-700 font-bold border border-indigo-200">
              RFC 8446 / RFC 5246 · 对齐 Wireshark
            </span>
          </div>
          <button @click="showPassiveModal = false" class="text-slate-400 hover:text-slate-600 text-base font-bold cursor-pointer">
            ✕
          </button>
        </div>

        <div class="p-4 flex-1 overflow-y-auto custom-scrollbar font-mono text-xs text-slate-700 space-y-3">
          
          <div class="p-2.5 bg-indigo-50/60 rounded-xl border border-indigo-100 text-[11px] text-indigo-900 leading-relaxed">
            <span class="font-bold">工作原理：</span>输入 TCP 重组后的 Client 原始 TLS 字节流（包含 ClientHello 与 Encrypted Application Data）与 Server 原始 TLS 字节流（包含 ServerHello 与 Encrypted Application Data），系统自动提取 32 字节 ClientRandom 并检索 NSS 密钥库，执行 HKDF/PRF 密钥派生与 AEAD 流式解密。
          </div>

          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="text-[10px] font-bold text-slate-500 block mb-1">客户端 TCP 载荷 (Hex):</label>
              <textarea v-model="passiveClientHex" rows="5"
                placeholder="例如: 16030300bc010000b80303...170303..."
                class="w-full p-2 rounded-xl bg-slate-50 border border-slate-200 text-[10px] font-mono outline-none resize-none focus:border-indigo-500"></textarea>
            </div>
            <div>
              <label class="text-[10px] font-bold text-slate-500 block mb-1">服务端 TCP 载荷 (Hex):</label>
              <textarea v-model="passiveServerHex" rows="5"
                placeholder="例如: 160303007a020000760303...170303..."
                class="w-full p-2 rounded-xl bg-slate-50 border border-slate-200 text-[10px] font-mono outline-none resize-none focus:border-indigo-500"></textarea>
            </div>
          </div>

          <div class="flex items-center justify-between pt-1">
            <span class="text-[10px] text-slate-400">
              当前 NSS 密钥库已就绪: {{ keylogStatus.total_keys }} 组密钥
            </span>
            <button @click="executePassiveDecrypt" :disabled="passiveLoading"
              class="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl font-bold transition-all shadow-xs cursor-pointer flex items-center gap-1.5">
              <span>{{ passiveLoading ? '正在解密中...' : '执行被动 AEAD 解密' }}</span>
            </button>
          </div>

          <!-- 解密结果展示 -->
          <div v-if="passiveResults.length > 0" class="space-y-2 pt-2">
            <div class="text-[11px] font-bold text-slate-800">
              解密还原出的应用层明文记录 ({{ passiveResults.length }} 条):
            </div>
            
            <div v-for="(item, idx) in passiveResults" :key="idx"
              class="p-2.5 rounded-xl border border-slate-200 bg-slate-50 flex flex-col gap-1">
              <div class="flex items-center justify-between text-[10px]">
                <span class="font-bold text-indigo-700">
                  #{{ item.sequence_number }} · {{ item.direction }}
                </span>
                <span class="text-slate-400">{{ item.tls_version }} | {{ item.cipher_suite }} | {{ item.plaintext_len }} 字节</span>
              </div>
              <pre class="bg-slate-900 text-emerald-400 p-2.5 rounded-lg text-[10px] overflow-x-auto whitespace-pre-wrap select-text font-mono leading-relaxed">{{ item.plaintext_utf8 || item.plaintext_hex }}</pre>
            </div>
          </div>

        </div>

        <div class="p-3 border-t border-slate-200 flex justify-end bg-slate-50/80">
          <button @click="showPassiveModal = false"
            class="px-4 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-900 text-white text-xs font-medium cursor-pointer">
            关闭
          </button>
        </div>

      </div>
    </div>

  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';

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

const executePassiveDecrypt = async () => {
  if (!passiveClientHex.value.trim() || !passiveServerHex.value.trim()) {
    alert('请同时输入客户端与服务端 TCP 载荷十六进制数据');
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
      alert('未解密出应用层明文记录，请检查 ClientHello 是否完整以及 NSS 密钥库中是否存在对应的 ClientRandom 密钥。');
    }
  } catch (e) {
    alert(`被动解密失败: ${e}`);
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
    case 'GET': return 'text-blue-600';
    case 'POST': return 'text-emerald-600';
    case 'PUT': return 'text-amber-600';
    case 'DELETE': return 'text-rose-600';
    case 'CONNECT': return 'text-purple-600';
    default: return 'text-slate-700';
  }
};

const formatPayload = (snippet: string) => {
  try {
    const obj = JSON.parse(snippet);
    return JSON.stringify(obj, null, 2);
  } catch {
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
  alert('CA 根证书 PEM 已复制到剪贴板！');
};

const triggerKeylogSelect = async () => {
  const path = prompt('请输入 NSS SSLKEYLOGFILE 密钥日志文件的绝对路径 (如 Windows: C:\\keys\\sslkeylog.log 或 Linux/macOS: /path/to/sslkeylog.log):');
  if (path && path.trim()) {
    try {
      const count = await invoke<number>('load_sslkeylog_file_cmd', { filePath: path.trim() });
      alert(`成功导入 ${count} 组 SSL 会话密钥！`);
      await fetchStatus();
    } catch (e) {
      alert(`导入失败: ${e}`);
    }
  }
};

onMounted(async () => {
  await fetchStatus();
  await fetchLogs();
  await fetchCaPem();

  unlistenTraffic = await listen<DecryptedTrafficRecord>('decrypted-traffic', (event) => {
    decryptedLogs.value.unshift(event.payload);
    if (decryptedLogs.value.length > 500) {
      decryptedLogs.value.pop();
    }
    proxyStatus.value.total_requests += 1;
  });

  pollTimer = window.setInterval(() => {
    fetchStatus();
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
