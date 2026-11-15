/**
 * Omni-Probe 工业级轻量高性能响应式多语言引擎 (i18n Engine)
 *
 * 核心设计考量:
 * 1. 零外部重型依赖: 基于 Vue 3 原生 shallowRef 与 computed 构建，无包体积死重；
 * 2. 毫秒级动态切换: 语言切换时整树响应式刷新，无需重启或重新挂载 DOM；
 * 3. 优雅降级与防御性编程: 严密防御 3 类极限边界条件（空 Key、深层路径断裂、畸形插值参数）；
 * 4. 时空复杂度:
 *    - 寻址时间复杂度: O(D)，D 为键深度（通常 <= 4），近乎常数级寻址；
 *    - 空间复杂度: O(1)，复用全局单例静态字典引用，无额外堆分配。
 */

import { shallowRef, computed } from 'vue';
import zhCN from './locales/zh-CN';
import enUS from './locales/en-US';

export type SupportedLocale = 'zh-CN' | 'en-US';

export const SUPPORTED_LOCALES: { code: SupportedLocale; label: string }[] = [
  { code: 'zh-CN', label: '简体中文 (Simplified Chinese)' },
  { code: 'en-US', label: 'English (US International)' },
];

const STORAGE_KEY = 'omni_probe_locale';

/**
 * 自动探测宿主操作系统的默认语言环境
 */
function detectSystemLocale(): SupportedLocale {
  if (typeof window === 'undefined' || !window.navigator) {
    return 'zh-CN';
  }
  const sysLang = (window.navigator.language || '').toLowerCase();
  return sysLang.startsWith('zh') ? 'zh-CN' : 'en-US';
}

/**
 * 读取本地持久化语言，缺失时使用系统默认探活结果
 */
function getInitialLocale(): SupportedLocale {
  try {
    if (typeof window !== 'undefined' && typeof window.localStorage !== 'undefined' && window.localStorage) {
      const saved = window.localStorage.getItem(STORAGE_KEY);
      if (saved === 'zh-CN' || saved === 'en-US') {
        return saved;
      }
    }
  } catch {
    // 降级防御：脱机沙箱或受限环境
  }
  return detectSystemLocale();
}

// 响应式语言状态单例
const currentLocale = shallowRef<SupportedLocale>(getInitialLocale());

// 静态字典注册表
const dictionaries: Record<SupportedLocale, typeof zhCN> = {
  'zh-CN': zhCN,
  'en-US': enUS,
};

/**
 * 深层对象属性寻址 (Safe Nested Property Resolver)
 * 时间复杂度: O(D)
 * 极限防御: 中途遇到 null/undefined/基本类型直接短路返回 undefined，杜绝空指针异常
 */
function resolvePath(obj: unknown, path: string): string | undefined {
  if (!obj || typeof obj !== 'object' || !path) {
    return undefined;
  }
  const parts = path.split('.');
  let current: unknown = obj;
  for (const part of parts) {
    if (current && typeof current === 'object' && part in (current as Record<string, unknown>)) {
      current = (current as Record<string, unknown>)[part];
    } else {
      return undefined;
    }
  }
  return typeof current === 'string' ? current : undefined;
}

/**
 * 模板参数插值处理器 (Template Interpolation Engine)
 * 语法: 支持 {paramName} 形式占位符
 */
function interpolate(template: string, params?: Record<string, string | number>): string {
  if (!params || Object.keys(params).length === 0) {
    return template;
  }
  return template.replace(/\{([a-zA-Z0-9_-]+)\}/g, (match, key) => {
    if (key in params && params[key] !== undefined && params[key] !== null) {
      return String(params[key]);
    }
    return match;
  });
}

/**
 * 国际化翻译核心主入口 (t function)
 *
 * @param key 键路径，如 'nav.traffic' 或 'preferences.appearance.title'
 * @param params 可选动态参数字典，如 { count: 5, version: '0.3.7' }
 * @returns 本地化字符串；若未命中则回退默认语言，最后回退 key 本身
 */
export function t(key: string, params?: Record<string, string | number>): string {
  // 极限边界防御 1: 空 Key 直接返回
  if (!key || typeof key !== 'string') {
    return '';
  }

  const activeDict = dictionaries[currentLocale.value] || dictionaries['zh-CN'];
  let rawText = resolvePath(activeDict, key);

  // 极限边界防御 2: 若当前语言未命中，自动回退到简体中文 (Fallback)
  if (rawText === undefined && currentLocale.value !== 'zh-CN') {
    rawText = resolvePath(dictionaries['zh-CN'], key);
  }

  // 极限边界防御 3: 全局未命中时返回 Key 原文
  if (rawText === undefined) {
    return key;
  }

  return interpolate(rawText, params);
}

/**
 * 切换系统显示语言并执行持久化存储
 */
export function setLocale(locale: SupportedLocale): void {
  if (locale !== 'zh-CN' && locale !== 'en-US') {
    return;
  }
  currentLocale.value = locale;
  try {
    if (typeof window !== 'undefined' && typeof window.localStorage !== 'undefined' && window.localStorage) {
      window.localStorage.setItem(STORAGE_KEY, locale);
    }
  } catch {
    // 降级防御：脱机沙箱或受限环境
  }
}

/**
 * 响应式只读当前语言
 */
export const activeLocale = computed(() => currentLocale.value);

/**
 * 组合式 API (Composable Hook)
 */
export function useI18n() {
  return {
    locale: activeLocale,
    setLocale,
    t,
    supportedLocales: SUPPORTED_LOCALES,
  };
}

export default {
  locale: activeLocale,
  setLocale,
  t,
  useI18n,
};
