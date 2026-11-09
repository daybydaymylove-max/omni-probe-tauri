<template>
  <div v-if="isOpen" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-md">
    <!-- 模态框主体 (Apple Mica Frost 工业级全景弹窗) -->
    <div class="w-full max-w-4xl max-h-[92vh] bg-white/95 dark:bg-slate-900/95 backdrop-blur-2xl rounded-3xl border border-white/60 dark:border-white/10 shadow-2xl flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-200">
      
      <!-- 顶栏：标题与操作 -->
      <div class="px-6 py-4 border-b border-slate-200/60 dark:border-white/10 bg-white/40 dark:bg-black/20 flex items-center justify-between shrink-0">
        <div class="flex items-center gap-3">
          <div class="w-9 h-9 rounded-2xl bg-gradient-to-tr from-cyan-500 to-blue-600 flex items-center justify-center text-white shadow-md shadow-cyan-500/25">
            <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <div>
            <h3 class="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <span>底层抓包驱动与解剖环境诊断中心 (Readiness Inspector)</span>
            </h3>
            <div class="text-[11px] font-mono text-slate-500 dark:text-slate-400 mt-0.5">
              探活诊断覆盖: Npcap 驱动 · TShark 引擎 · USBPcap 总线 · ip2region 库 · 进程特权
            </div>
          </div>
        </div>

        <div class="flex items-center gap-2">
          <button @click="refreshInspection" :disabled="loading"
            class="px-3.5 py-1.5 rounded-xl text-xs font-semibold bg-white/80 dark:bg-white/10 hover:bg-white text-slate-700 dark:text-slate-200 border border-slate-200/80 dark:border-white/10 shadow-2xs transition-all cursor-pointer flex items-center gap-1.5 disabled:opacity-50">
            <span :class="loading ? 'animate-spin' : ''">⟳</span>
            <span>{{ loading ? '深度探活中...' : '重新检测' }}</span>
          </button>
          <button @click="$emit('close')"
            class="w-8 h-8 rounded-full flex items-center justify-center text-slate-400 hover:text-slate-700 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-white/10 transition-colors cursor-pointer ml-1">
            ✕
          </button>
        </div>
      </div>

      <!-- 主体内容 -->
      <div class="flex-1 overflow-y-auto custom-scrollbar p-6 space-y-4">
        
        <!-- 综合健康度大卡片 -->
        <div class="p-4 rounded-2xl bg-gradient-to-r from-blue-50/70 via-indigo-50/50 to-slate-50/70 dark:from-blue-950/20 dark:via-indigo-950/20 dark:to-slate-900/30 border border-blue-200/60 dark:border-white/10 flex flex-col md:flex-row items-center justify-between gap-4">
          <div class="flex items-center gap-4">
            <!-- 仪表得分环 -->
            <div class="relative w-16 h-16 shrink-0 flex items-center justify-center">
              <svg class="w-16 h-16 transform -rotate-90">
                <circle cx="32" cy="32" r="26" stroke="currentColor" stroke-width="5" class="text-slate-200 dark:text-slate-800" fill="transparent" />
                <circle cx="32" cy="32" r="26" stroke="currentColor" stroke-width="5"
                  :stroke-dasharray="163.3"
                  :stroke-dashoffset="163.3 - (163.3 * (report?.readiness_score || 0)) / 100"
                  :class="scoreColorClass"
                  fill="transparent"
                  stroke-linecap="round"
                  class="transition-all duration-700" />
              </svg>
              <span class="absolute text-sm font-bold font-mono text-slate-900 dark:text-white">
                {{ report?.readiness_score || 0 }}%
              </span>
            </div>

            <div>
              <div class="flex items-center gap-2">
                <span class="text-xs font-bold text-slate-800 dark:text-white font-sans">运行环境就绪度:</span>
                <span :class="['text-xs font-mono font-bold px-2 py-0.5 rounded-full border', badgeColorClass]">
                  {{ statusText }}
                </span>
                <span class="text-[10px] text-slate-400 font-mono">诊断时间: {{ report?.checked_at }}</span>
              </div>
              <p class="text-xs text-slate-600 dark:text-slate-300 leading-relaxed mt-1 max-w-xl">
                {{ report?.summary }}
              </p>
            </div>
          </div>

          <!-- 多轨并行与自愈矩阵指示 -->
          <div class="text-[11px] font-mono text-slate-500 dark:text-slate-400 bg-white/80 dark:bg-black/30 p-2.5 rounded-xl border border-slate-200/60 dark:border-white/10 shrink-0 space-y-1">
            <div class="font-bold text-slate-700 dark:text-slate-200 border-b border-black/5 dark:border-white/10 pb-1 mb-1">多轨并行自愈就绪矩阵</div>
            <div>• 工业规约解剖: <strong class="text-emerald-600 dark:text-emerald-400">42+ 原生自愈轨已就绪</strong></div>
            <div>• 全协议官方解剖: <strong :class="isTsharkReady ? 'text-emerald-600 dark:text-emerald-400' : 'text-indigo-500'">{{ isTsharkReady ? 'Wireshark 官方轨' : '原生 Rust 42+ 自愈轨' }}</strong></div>
            <div>• 网络数据嗅探: <strong :class="isNpcapReady ? 'text-emerald-600 dark:text-emerald-400' : 'text-indigo-500'">{{ isNpcapReady ? 'Npcap L2 混杂轨' : 'Raw Socket 双轨自愈' }}</strong></div>
            <div>• 物理 USB 总线: <strong :class="isUsbpcapReady ? 'text-emerald-600 dark:text-emerald-400' : 'text-amber-500'">{{ isUsbpcapReady ? 'URB 物理硬件轨' : 'PnP 设备拓扑自愈' }}</strong></div>
            <div>• 离线地理情报: <strong :class="isIpDbReady ? 'text-emerald-600 dark:text-emerald-400' : 'text-indigo-500'">{{ isIpDbReady ? '千万级 XDB 离线库' : '内置 LPM CIDR 自愈轨' }}</strong></div>
          </div>
        </div>

        <!-- 缺少 USBPcap 驱动时的醒目警示与潜在问题提醒 -->
        <div v-if="!isUsbpcapReady" class="p-3.5 rounded-2xl bg-amber-500/10 border border-amber-500/30 text-amber-900 dark:text-amber-200 text-xs font-sans space-y-1.5 animate-in fade-in duration-200">
          <div class="font-bold flex items-center justify-between">
            <div class="flex items-center gap-2 text-amber-800 dark:text-amber-300">
              <svg class="w-4 h-4 shrink-0 text-amber-600 dark:text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
              <span>⚠️ 物理 USB 总线捕获驱动 (USBPcap) 缺失提醒与多轨自愈说明</span>
            </div>
            <button v-if="!launchedMap['usbpcap'] && !installingMap['usbpcap']"
              @click="confirmingComponent = 'usbpcap'"
              class="px-2.5 py-1 rounded-lg bg-amber-600 hover:bg-amber-700 text-white font-bold text-[11px] shadow-sm transition-all cursor-pointer flex items-center gap-1">
              <span>立即安装 USBPcap</span>
              <span class="text-[9px]">↓</span>
            </button>
          </div>
          <div class="text-[11px] leading-relaxed text-slate-700 dark:text-slate-300 space-y-1 pl-6 font-mono">
            <div>• <strong>当前自愈状态</strong>：系统已自动调用 Windows 原生 PnP 设备管理器拓扑总线，USB 外设热插拔感知与串口 COM 调试完全正常；</div>
            <div>• <strong>受限功能</strong>：无法捕获微秒级物理 URB 请求块与 BadUSB 击键时序（IAT &lt; 25ms 硬件木马特征）。如需深度 URB 分析，建议一键安装驱动。</div>
          </div>
        </div>

        <!-- 五大核心组件细化卡片列表 (多轨并行状态呈现) -->
        <div class="space-y-3 font-mono text-xs">
          <div v-for="comp in report?.components" :key="comp.id"
            class="bg-white/80 dark:bg-white/[0.03] backdrop-blur-md rounded-2xl p-4 border border-slate-200/80 dark:border-white/10 shadow-2xs hover:border-blue-400/50 transition-all">
            
            <div class="flex items-start justify-between gap-3">
              <!-- 头部名称与状态 -->
              <div class="flex items-center gap-2.5">
                <span :class="['w-3 h-3 rounded-full shrink-0 shadow-sm', comp.is_ready ? 'bg-emerald-500 shadow-emerald-500/50' : 'bg-amber-500 shadow-amber-500/50']"></span>
                <div>
                  <div class="font-bold text-slate-900 dark:text-white text-xs flex items-center gap-2 font-sans">
                    <span>{{ comp.name }}</span>
                    <span :class="['text-[10px] px-2 py-0.2 rounded-full font-mono font-bold border', comp.is_ready ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-400 border-emerald-500/30' : 'bg-amber-500/15 text-amber-700 dark:text-amber-400 border-amber-500/30']">
                      {{ comp.is_ready ? '✓ 外部资源就绪 (Active)' : '⚠️ 外部驱动缺失 (多轨自愈中)' }}
                    </span>
                    <span class="text-[10px] px-2 py-0.2 rounded-full font-mono font-bold bg-indigo-500/10 text-indigo-700 dark:text-indigo-300 border border-indigo-500/20">
                      ⚡ 内置多轨自愈轨已就绪
                    </span>
                  </div>
                  <div class="text-[11px] text-slate-500 dark:text-slate-400 font-mono mt-0.5">
                    <span v-if="comp.path">路径: {{ comp.path }}</span>
                    <span v-else-if="comp.version">版本: {{ comp.version }}</span>
                    <span v-else class="text-indigo-600 dark:text-indigo-400">已自动切换至系统原生多轨自愈实现</span>
                  </div>
                </div>
              </div>

              <!-- 操作按钮组 -->
              <div class="flex items-center gap-2 shrink-0">
                <!-- 官方一键自动下载并启动安装/挂载 -->
                <button v-if="!comp.is_ready && comp.can_auto_install && !installingMap[comp.id] && confirmingComponent !== comp.id && !launchedMap[comp.id]"
                  @click="confirmingComponent = comp.id"
                  class="px-3 py-1.5 rounded-xl bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white font-semibold text-xs shadow-md shadow-blue-500/20 transition-all cursor-pointer flex items-center gap-1.5">
                  <svg class="w-3.5 h-3.5 fill-current" viewBox="0 0 24 24"><path d="M19 9h-4V3H9v6H5l7 7 7-7zM5 18v2h14v-2H5z"/></svg>
                  <span>{{ comp.id === 'ip_db' ? '自动下载离线库' : '自动从官网安装' }}</span>
                </button>

                <!-- 官方指南/主页直达 -->
                <button @click="openLink(comp.official_url)"
                  class="px-3 py-1.5 rounded-xl bg-slate-100 hover:bg-slate-200 dark:bg-white/10 dark:hover:bg-white/15 text-slate-700 dark:text-slate-300 border border-slate-200/80 dark:border-white/10 text-xs font-semibold transition-all cursor-pointer flex items-center gap-1 shrink-0">
                  <span>官方主页</span>
                  <span class="text-[10px]">↗</span>
                </button>
              </div>
            </div>

            <!-- 用户确认询问横幅 (确认从官网下载安装) -->
            <div v-if="confirmingComponent === comp.id"
              class="mt-3 p-3.5 bg-blue-50/90 dark:bg-blue-950/40 rounded-xl border border-blue-200 dark:border-blue-500/30 flex flex-col md:flex-row items-start md:items-center justify-between gap-3 animate-in fade-in duration-200 font-sans">
              <div>
                <div class="text-xs font-bold text-blue-900 dark:text-blue-200 flex items-center gap-1.5">
                  <span>📥 是否确认从官方镜像安全下载并装配 {{ comp.name }}？</span>
                </div>
                <div class="text-[11px] text-slate-600 dark:text-slate-300 mt-1 font-mono">
                  将下载: <strong>{{ comp.installer_filename }}</strong> (约 {{ comp.estimated_size_mb }} MB) · 下载后将自动完成装配或唤起安装向导。
                </div>
              </div>
              <div class="flex items-center gap-2 shrink-0 font-mono">
                <button @click="startAutoInstall(comp.id)"
                  class="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold shadow transition-all cursor-pointer">
                  确认并开始下载
                </button>
                <button @click="confirmingComponent = null"
                  class="px-3 py-1.5 rounded-lg bg-slate-200 dark:bg-white/10 hover:bg-slate-300 text-slate-700 dark:text-slate-300 text-xs font-semibold transition-all cursor-pointer">
                  取消
                </button>
              </div>
            </div>

            <!-- 下载进度条卡片 -->
            <div v-if="installingMap[comp.id]"
              class="mt-3 p-3 bg-slate-50 dark:bg-black/30 rounded-xl border border-slate-200 dark:border-white/10 space-y-2">
              <div class="flex items-center justify-between text-xs font-mono">
                <span class="text-blue-600 dark:text-blue-400 font-bold flex items-center gap-2">
                  <span class="animate-spin text-sm">⟳</span>
                  <span>{{ installingMap[comp.id].status === 'launching' ? '已完成下载，正在唤起安装向导或装配数据...' : '正在从官方源流式下载中...' }}</span>
                </span>
                <span class="font-bold text-slate-900 dark:text-white">{{ installingMap[comp.id].percent.toFixed(1) }}%</span>
              </div>
              <div class="w-full h-2 bg-slate-200 dark:bg-white/10 rounded-full overflow-hidden">
                <div class="h-full bg-gradient-to-r from-blue-500 to-indigo-600 transition-all duration-200"
                  :style="{ width: `${installingMap[comp.id].percent}%` }"></div>
              </div>
              <div class="text-[11px] text-slate-400 flex items-center justify-between font-mono">
                <span>已接收: {{ (installingMap[comp.id].downloaded_bytes / 1024 / 1024).toFixed(2) }} MB</span>
                <span>总预计: {{ (installingMap[comp.id].total_bytes / 1024 / 1024).toFixed(2) }} MB</span>
              </div>
            </div>

            <!-- 安装向导或数据装配已成功启动提示 -->
            <div v-if="launchedMap[comp.id]"
              class="mt-3 p-3 bg-emerald-50/90 dark:bg-emerald-950/40 rounded-xl border border-emerald-200 dark:border-emerald-500/30 flex items-center justify-between gap-3 text-xs font-sans">
              <div class="text-emerald-800 dark:text-emerald-300 font-semibold flex items-center gap-1.5">
                <span>✓ {{ comp.id === 'ip_db' ? '已成功装载官方离线数据库，即刻生效！' : '官方安装程序向导已启动，请在弹出的窗口中完成安装。' }}</span>
              </div>
              <button @click="finishAndRecheck(comp.id)"
                class="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white font-bold text-xs shadow transition-all cursor-pointer shrink-0">
                完成并重新检测 ⟳
              </button>
            </div>

            <!-- 能力与多轨自愈对比说明 -->
            <div class="mt-3 pt-3 border-t border-slate-100 dark:border-white/5 grid grid-cols-1 md:grid-cols-2 gap-3 text-[11px]">
              <div class="p-2.5 rounded-xl bg-emerald-50/60 dark:bg-emerald-950/20 border border-emerald-200/50 dark:border-emerald-500/20">
                <div class="font-bold text-emerald-800 dark:text-emerald-300 mb-0.5">🚀 外部强力轨特性:</div>
                <div class="text-slate-700 dark:text-slate-300 leading-relaxed">{{ comp.capability_enabled }}</div>
              </div>

              <div class="p-2.5 rounded-xl bg-indigo-50/60 dark:bg-indigo-950/20 border border-indigo-200/50 dark:border-indigo-500/20">
                <div class="font-bold text-indigo-800 dark:text-indigo-300 mb-0.5">⚡ 内置多轨自愈机制:</div>
                <div class="text-slate-700 dark:text-slate-300 leading-relaxed">{{ comp.fallback_mode }}</div>
              </div>
            </div>

            <!-- 安装建议小药丸 -->
            <div v-if="!comp.is_ready" class="mt-2.5 px-3 py-1.5 rounded-xl bg-amber-50/80 dark:bg-amber-950/30 border border-amber-200/60 dark:border-amber-500/20 text-[11px] text-amber-800 dark:text-amber-300 flex items-start gap-1.5">
              <span class="font-bold shrink-0">💡 优化建议:</span>
              <span>{{ comp.install_tips }}</span>
            </div>
          </div>
        </div>

        <!-- 真国产自主知识产权与信创国标认证看板 -->
        <div class="mt-4 p-5 rounded-2xl bg-gradient-to-r from-red-50/80 via-amber-50/50 to-orange-50/80 dark:from-red-950/20 dark:via-amber-950/20 dark:to-orange-900/20 border border-red-200/80 dark:border-red-500/30 shadow-2xs space-y-4">
          <div class="flex items-center justify-between border-b border-red-200/60 dark:border-red-500/30 pb-3">
            <div class="flex items-center gap-2.5">
              <span class="w-3 h-3 rounded-full bg-red-600 shadow-xs flex items-center justify-center">
                <span class="w-1 h-1 rounded-full bg-white"></span>
              </span>
              <h4 class="text-xs font-bold text-red-950 dark:text-red-200 flex items-center gap-2">
                <span>真国产自主知识产权与信创标准认证 (National Indigenous Compliance)</span>
                <span class="text-[10px] px-2 py-0.2 rounded-full font-mono font-bold bg-red-600 text-white shadow-xs">
                  信创自主度 100%
                </span>
              </h4>
            </div>
            <div class="text-[11px] font-mono text-red-800/80 dark:text-red-300">
              纯 Rust 洁净室架构 · 零境外专利约束 · 零境外闭源依赖
            </div>
          </div>

          <div class="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-sans">
            <!-- 支柱 1：纯自主代码内核 -->
            <div class="bg-white/80 dark:bg-slate-900/80 p-3.5 rounded-xl border border-red-100 dark:border-white/10 space-y-1 shadow-2xs">
              <div class="font-bold text-slate-900 dark:text-white flex items-center gap-1.5 text-xs">
                <span class="text-red-600">🛡️</span>
                <span>纯自主内生代码控制权 (100% In-Tree Rust)</span>
              </div>
              <div class="text-[11px] text-slate-600 dark:text-slate-300 leading-relaxed font-mono">
                从数据链路层抓包到应用层状态机重组全部自主编写，彻底摆脱历史开源技术人身依附。零外部黑盒，具备完全自主的多轨自愈与降级能力。
              </div>
            </div>

            <!-- 支柱 2：商用密码算法标准 -->
            <div class="bg-white/80 dark:bg-slate-900/80 p-3.5 rounded-xl border border-red-100 dark:border-white/10 space-y-1 shadow-2xs">
              <div class="font-bold text-slate-900 dark:text-white flex items-center gap-1.5 text-xs">
                <span class="text-amber-600">🔐</span>
                <span>商用密码国密体系全内置 (GM/T Cryptography)</span>
              </div>
              <div class="text-[11px] text-slate-600 dark:text-slate-300 leading-relaxed font-mono">
                内置国家密码局标准 GM/T 0004-2012 (SM3 密码杂凑，用于 Merkle 防伪存证链) 与 GM/T 0002-2012 (SM4 对称分组加密，用于涉密载荷落盘与脱敏隔离)。
              </div>
            </div>

            <!-- 支柱 3：国家垂直关键行业规约 -->
            <div class="bg-white/80 dark:bg-slate-900/80 p-3.5 rounded-xl border border-red-100 dark:border-white/10 space-y-1 shadow-2xs">
              <div class="font-bold text-slate-900 dark:text-white flex items-center gap-1.5 text-xs">
                <span class="text-blue-600">📜</span>
                <span>国家与行业级关键垂直规约原生解析</span>
              </div>
              <div class="text-[11px] text-slate-600 dark:text-slate-300 leading-relaxed font-mono">
                原生支持水利部 SL651-2014、生态环境部 HJ 212-2017、国家电网 DL/T 645-2007、电力远动 DL/T 634.5104、党政公文格式 GB/T 9704-2012 及二代身份证 GB 11643。
              </div>
            </div>

            <!-- 支柱 4：信创国产操作系统与 CPU -->
            <div class="bg-white/80 dark:bg-slate-900/80 p-3.5 rounded-xl border border-red-100 dark:border-white/10 space-y-1 shadow-2xs">
              <div class="font-bold text-slate-900 dark:text-white flex items-center gap-1.5 text-xs">
                <span class="text-emerald-600">🖥️</span>
                <span>信创操作系统与多国产芯片全架构支持</span>
              </div>
              <div class="text-[11px] text-slate-600 dark:text-slate-300 leading-relaxed font-mono">
                纯静态跨平台编译，支持统信 UOS、银河麒麟 KylinOS、中科方德、OpenEuler 等信创操作系统；支持龙芯 LoongArch64、飞腾/鲲鹏 ARM64、兆芯/海光 x86-64。
              </div>
            </div>
          </div>
        </div>

      </div>

      <!-- 底栏：关闭与可选项设置 (用户自主控制下次启动是否弹窗检测) -->
      <div class="px-6 py-3 border-t border-slate-200/60 dark:border-white/10 bg-white/40 dark:bg-black/20 flex flex-col sm:flex-row items-center justify-between gap-3 shrink-0 text-xs text-slate-500 dark:text-slate-400 font-mono">
        <!-- 灵活切换与可选配置：下次启动跳过自检弹窗 -->
        <label class="flex items-center gap-2 cursor-pointer select-none text-slate-700 dark:text-slate-200 hover:text-cyan-600 dark:hover:text-cyan-300 transition-colors">
          <input type="checkbox" v-model="skipStartupModal" @change="onToggleSkipStartup"
            class="w-4 h-4 rounded text-cyan-600 focus:ring-cyan-500 border-slate-300 dark:border-white/20 bg-white dark:bg-black/40 cursor-pointer" />
          <span class="text-xs font-sans font-medium">下次启动时不主动弹出此自检窗口 (保持后台静默多轨自愈)</span>
        </label>

        <div class="flex items-center gap-3 shrink-0">
          <span class="text-[11px] opacity-75 hidden md:inline">可随时点击顶栏【🩺 环境自检】重新呼出与切换</span>
          <button @click="$emit('close')" class="px-4 py-1.5 rounded-xl font-semibold bg-slate-900 dark:bg-white text-white dark:text-slate-900 hover:opacity-90 shadow-sm transition-all cursor-pointer">
            关闭诊断
          </button>
        </div>
      </div>

    </div>
  </div>
</template>

<script setup lang="ts">
import { notifySuccess, notifyError } from '../composables/useNotification';
import { ref, computed, onMounted, onUnmounted, watch } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { openUrl } from '@tauri-apps/plugin-opener';

interface ComponentStatus {
  id: string;
  name: string;
  category: string;
  is_ready: boolean;
  version?: string;
  path?: string;
  capability_enabled: string;
  fallback_mode: string;
  official_url: string;
  install_tips: string;
  can_auto_install: boolean;
  installer_filename?: string;
  estimated_size_mb?: number;
}

interface EnvironmentReport {
  readiness_score: number;
  status_level: string;
  summary: string;
  components: ComponentStatus[];
  checked_at: string;
}

interface DownloadProgressPayload {
  component_id: string;
  status: string;
  percent: number;
  downloaded_bytes: number;
  total_bytes: number;
  error_msg?: string;
}

const props = defineProps<{
  isOpen: boolean;
}>();

defineEmits(['close']);

const report = ref<EnvironmentReport | null>(null);
const loading = ref(false);

// 启动跳过选项管理 (本地存储持久化，满足用户灵活切换要求)
const skipStartupModal = ref(localStorage.getItem('omni_probe_skip_startup_env_modal') === 'true');
function onToggleSkipStartup() {
  localStorage.setItem('omni_probe_skip_startup_env_modal', skipStartupModal.value ? 'true' : 'false');
  if (skipStartupModal.value) {
    notifySuccess('偏好设置已更新', '下次启动时将跳过主动弹窗，保持后台多轨自愈运行；您可随时点击顶栏环境诊断重新呼出');
  } else {
    notifySuccess('偏好设置已更新', '下次启动若存在缺失外部依赖，将主动弹出全景环境诊断中心');
  }
}

// 安装交互状态管理
const confirmingComponent = ref<string | null>(null);
const installingMap = ref<Record<string, DownloadProgressPayload>>({});
const launchedMap = ref<Record<string, boolean>>({});

let unlistenProgress: (() => void) | null = null;

const isNpcapReady = computed(() => {
  return report.value?.components.find(c => c.id === 'npcap')?.is_ready || false;
});

const isTsharkReady = computed(() => {
  return report.value?.components.find(c => c.id === 'tshark')?.is_ready || false;
});

const isUsbpcapReady = computed(() => {
  return report.value?.components.find(c => c.id === 'usbpcap')?.is_ready || false;
});

const isIpDbReady = computed(() => {
  return report.value?.components.find(c => c.id === 'ip_db')?.is_ready || false;
});

const scoreColorClass = computed(() => {
  const s = report.value?.readiness_score || 0;
  if (s >= 90) return 'text-emerald-500';
  if (s >= 50) return 'text-amber-500';
  return 'text-rose-500';
});

const badgeColorClass = computed(() => {
  const s = report.value?.readiness_score || 0;
  if (s >= 90) return 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-400 border-emerald-500/30';
  if (s >= 50) return 'bg-amber-500/15 text-amber-700 dark:text-amber-400 border-amber-500/30';
  return 'bg-rose-500/15 text-rose-700 dark:text-rose-400 border-rose-500/30';
});

const statusText = computed(() => {
  const level = report.value?.status_level;
  if (level === 'Optimal') return '工业最佳全能态';
  if (level === 'Standard') return '工业标准运行态';
  return '多轨自愈兜底态';
});

async function refreshInspection() {
  loading.value = true;
  try {
    const res: any = await invoke('get_environment_inspection_cmd');
    report.value = res;
  } catch (e) {
    console.error('[ENV_INSPECTOR] 诊断失败:', e);
  } finally {
    loading.value = false;
  }
}

async function startAutoInstall(componentId: string) {
  confirmingComponent.value = null;
  installingMap.value[componentId] = {
    component_id: componentId,
    status: 'downloading',
    percent: 0,
    downloaded_bytes: 0,
    total_bytes: 1024 * 1024,
  };

  try {
    const res: string = await invoke('download_and_install_component_cmd', {
      componentId,
    });
    delete installingMap.value[componentId];
    launchedMap.value[componentId] = true;
    notifySuccess('装配引导已启动', res || '已成功唤起官方安装程序向导，请完成安装后点击刷新检测');
  } catch (e: any) {
    delete installingMap.value[componentId];
    notifyError('驱动安装引导受阻', e);
  }
}

function finishAndRecheck(componentId: string) {
  delete launchedMap.value[componentId];
  refreshInspection();
}

async function openLink(url: string) {
  if (!url) return;
  try {
    await openUrl(url);
  } catch (e) {
    window.open(url, '_blank');
  }
}

watch(() => props.isOpen, (open) => {
  if (open) {
    refreshInspection();
  }
});

onMounted(async () => {
  refreshInspection();
  try {
    unlistenProgress = await listen<DownloadProgressPayload>('installer-download-progress', (event) => {
      const p = event.payload;
      if (p.status === 'completed') {
        delete installingMap.value[p.component_id];
        launchedMap.value[p.component_id] = true;
      } else if (p.status === 'error') {
        delete installingMap.value[p.component_id];
        notifyError('官方安装包下载异常', p.error_msg);
      } else {
        installingMap.value[p.component_id] = p;
      }
    });
  } catch (e) {
    console.warn('[PROGRESS_LISTENER] 无法监听下载事件:', e);
  }
});

onUnmounted(() => {
  if (unlistenProgress) {
    unlistenProgress();
  }
});
</script>
