import { describe, it, expect, beforeEach } from 'vitest';
import { t, setLocale, activeLocale } from '../index';

describe('Omni-Probe i18n 响应式国际化引擎', () => {
  beforeEach(() => {
    setLocale('zh-CN');
  });

  it('常规基础翻译：zh-CN 与 en-US 状态切换验证', () => {
    expect(activeLocale.value).toBe('zh-CN');
    expect(t('nav.traffic')).toBe('全息流量分析');
    expect(t('common.confirm')).toBe('确认');

    setLocale('en-US');
    expect(activeLocale.value).toBe('en-US');
    expect(t('nav.traffic')).toBe('Live Traffic Analysis');
    expect(t('common.confirm')).toBe('Confirm');
  });

  it('模板参数插值功能验证', () => {
    setLocale('zh-CN');
    expect(t('topbar.threatCutting', { count: 3 })).toBe('3 告警 · 切断');

    setLocale('en-US');
    expect(t('topbar.threatCutting', { count: 5 })).toBe('5 Alerts · Cutoff');
    expect(t('preferences.updates.newVersionTitle', { version: '0.3.7' })).toBe('New Version Available: 0.3.7');
  });

  it('极限边界用例 1: 空 Key、非法入参防御', () => {
    expect(t('')).toBe('');
    // @ts-expect-error 测试非法非 string 入参
    expect(t(null)).toBe('');
    // @ts-expect-error 测试 undefined 入参
    expect(t(undefined)).toBe('');
  });

  it('极限边界用例 2: 深层不存在的键路径优雅降级回退', () => {
    // 根本不存在的 key 应当返回 key 本身
    expect(t('non.existent.deep.path')).toBe('non.existent.deep.path');

    // 英文未命中时应回退到简体中文
    setLocale('en-US');
    expect(t('nav.hardware')).toBe('Physical Hardware Bus');
  });

  it('极限边界用例 3: 缺少插值参数或多余参数的容错防护', () => {
    setLocale('zh-CN');
    // 参数为空对象时应保留原始模板字符不报错
    expect(t('topbar.threatCutting', {})).toBe('{count} 告警 · 切断');
    // 包含额外无用参数时不影响正常渲染
    expect(t('topbar.threatCutting', { count: 12, dummy: 'test' })).toBe('12 告警 · 切断');
  });

  it('极限边界用例 4: fallback 默认文本机制验证', () => {
    expect(t('missing.unknown.key', undefined, '自定义后备文本')).toBe('自定义后备文本');
    expect(t('', undefined, '空Key后备文本')).toBe('空Key后备文本');
    // 当 key 命中时，应当使用词典翻译而非 fallback
    expect(t('common.confirm', undefined, '忽略的后备文本')).toBe('确认');
  });

  it('环境检查器就绪通知多语言覆盖验证', () => {
    setLocale('zh-CN');
    expect(t('envInspector.missingComponentsNotice', { missing: 'Npcap' })).toContain('可选外置组件未完全就绪');
    setLocale('en-US');
    expect(t('envInspector.missingComponentsNotice', { missing: 'Npcap' })).toContain('Optional external components are not fully ready');
  });
});
