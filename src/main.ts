import { createApp } from 'vue';
import './style.css';
import App from './App.vue';

// ============================================================
// 原生系统应用环境守卫：彻底剔除网页浏览器行为与快捷键穿透
// ============================================================

// 1. 全局禁用网页默认右键上下文菜单（允许在可编辑输入框中正常复制粘贴）
window.addEventListener('contextmenu', (e: MouseEvent) => {
  const target = e.target as HTMLElement;
  const isInput = target && (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable);
  if (!isInput) {
    e.preventDefault();
  }
});

// 2. 彻底拦截网页刷新与浏览器专有快捷键（F5、Ctrl+R、Ctrl+F、Ctrl+P、Ctrl+U 等）
window.addEventListener('keydown', (e: KeyboardEvent) => {
  if (e.key === 'F5') {
    e.preventDefault();
    return;
  }
  if ((e.ctrlKey || e.metaKey) && (e.key === 'r' || e.key === 'R')) {
    e.preventDefault();
    return;
  }
  if ((e.ctrlKey || e.metaKey) && (e.key === 'f' || e.key === 'F')) {
    e.preventDefault();
    return;
  }
  if ((e.ctrlKey || e.metaKey) && (e.key === 'p' || e.key === 'P')) {
    e.preventDefault();
    return;
  }
  if ((e.ctrlKey || e.metaKey) && (e.key === 'u' || e.key === 'U')) {
    e.preventDefault();
    return;
  }
});

// 3. 全局禁止非文本元素的原生拖拽 ghost 影子
window.addEventListener('dragstart', (e: DragEvent) => {
  const target = e.target as HTMLElement;
  if (target && target.tagName !== 'INPUT' && target.tagName !== 'TEXTAREA') {
    e.preventDefault();
  }
});

// 4. 主题交由 App.vue 依据系统偏好与用户设置动态协同 (不再强锁死暗黑根类)
createApp(App).mount('#app');
