<template>
  <div
    class="fixed top-14 right-6 z-50 flex flex-col gap-2.5 max-w-md w-[92vw] sm:w-[420px] pointer-events-none"
    role="region"
    aria-label="系统运行提示通知"
  >
    <TransitionGroup
      enter-active-class="transition duration-300 ease-out transform"
      enter-from-class="translate-x-8 opacity-0 scale-95"
      enter-to-class="translate-x-0 opacity-100 scale-100"
      leave-active-class="transition duration-250 ease-in transform"
      leave-from-class="translate-x-0 opacity-100 scale-100"
      leave-to-class="translate-x-8 opacity-0 scale-95"
      move-class="transition-all duration-300 ease-in-out"
    >
      <div
        v-for="item in notifications"
        :key="item.id"
        class="pointer-events-auto relative overflow-hidden ui-modal-surface rounded-2xl p-3.5 transition-all duration-200 select-none"
        :class="themeClasses(item.type)"
        @mouseenter="pauseTimer(item.id)"
        @mouseleave="resumeTimer(item.id)"
      >
        <span class="lens-edge-lip" aria-hidden="true"></span>
        <div class="flex items-start gap-3">
          <!-- 状态指示图标 -->
          <div
            class="flex-shrink-0 w-8 h-8 rounded-xl flex items-center justify-center"
            :class="iconBgClasses(item.type)"
          >
            <!-- 成功 -->
            <svg
              v-if="item.type === 'success'"
              class="w-4 h-4 text-emerald-600 dark:text-emerald-400"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7" />
            </svg>
            <!-- 提示 -->
            <svg
              v-else-if="item.type === 'info'"
              class="w-4 h-4 text-sky-600 dark:text-sky-400"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <!-- 警告 -->
            <svg
              v-else-if="item.type === 'warning'"
              class="w-4 h-4 text-amber-600 dark:text-amber-400"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            <!-- 错误 -->
            <svg
              v-else
              class="w-4 h-4 text-rose-600 dark:text-rose-400"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>

          <!-- 内容主体 -->
          <div class="flex-1 min-w-0 pr-1">
            <div class="flex items-center gap-2">
              <span class="font-bold text-xs tracking-wide text-(--text-primary)">
                {{ item.title }}
              </span>
              <!-- 风暴去重计数胶囊 -->
              <span
                v-if="item.count > 1"
                class="ui-pill px-1.5 py-0.2 rounded-full text-[11px] ui-num font-mono-code font-bold tracking-tight text-(--text-primary)"
              >
                ×{{ item.count }}
              </span>
            </div>

            <p
              v-if="item.message"
              class="mt-1 text-xs text-(--text-secondary) leading-relaxed break-words select-text"
            >
              {{ item.message }}
            </p>

            <!-- 快捷处置按钮 -->
            <div v-if="item.action" class="mt-2.5">
              <button
                @click="handleAction(item)"
                class="px-2.5 py-1 text-[11px] font-medium rounded-lg transition-all duration-150 active:scale-95 cursor-pointer"
                :class="actionButtonClasses(item.type)"
              >
                {{ item.action.label }}
              </button>
            </div>
          </div>

          <!-- 手动关闭按钮 -->
          <button
            @click="removeNotification(item.id)"
            class="ui-btn-secondary flex-shrink-0 p-1 rounded-lg cursor-pointer"
            aria-label="关闭当前提示"
          >
            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <!-- 底部微光自动倒计时进度条 -->
        <div class="absolute bottom-0 left-0 right-0 h-[2px] bg-(--border-subtle) overflow-hidden">
          <div
            class="h-full transition-all duration-100 ease-linear"
            :class="progressBarClasses(item.type)"
            :style="{ width: `${getProgress(item.id)}%` }"
          />
        </div>
      </div>
    </TransitionGroup>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue';
import {
  useNotification,
  type NotificationType,
  type NotificationItem,
} from '../composables/useNotification';

const { notifications, removeNotification } = useNotification();

// 进度与倒计时状态
const timers = new Map<string, { start: number; duration: number; remaining: number; paused: boolean }>();
const progresses = ref<Record<string, number>>({});
let tickInterval: any = null;

function themeClasses(type: NotificationType): string {
  switch (type) {
    case 'success':
      return 'border-emerald-500/40 shadow-emerald-500/10';
    case 'info':
      return 'border-sky-500/40 shadow-sky-500/10';
    case 'warning':
      return 'border-amber-500/40 shadow-amber-500/10';
    case 'error':
      return 'border-rose-500/40 shadow-rose-500/10';
  }
}

function iconBgClasses(type: NotificationType): string {
  switch (type) {
    case 'success':
      return 'bg-emerald-500/15 border border-emerald-500/30';
    case 'info':
      return 'bg-sky-500/15 border border-sky-500/30';
    case 'warning':
      return 'bg-amber-500/15 border border-amber-500/30';
    case 'error':
      return 'bg-rose-500/15 border border-rose-500/30';
  }
}

function actionButtonClasses(type: NotificationType): string {
  switch (type) {
    case 'success':
      return 'bg-emerald-600 hover:bg-emerald-700 text-white';
    case 'info':
      return 'bg-sky-600 hover:bg-sky-700 text-white';
    case 'warning':
      return 'bg-amber-600 hover:bg-amber-700 text-white';
    case 'error':
      return 'bg-rose-600 hover:bg-rose-700 text-white';
  }
}

function progressBarClasses(type: NotificationType): string {
  switch (type) {
    case 'success':
      return 'bg-emerald-500 dark:bg-emerald-400';
    case 'info':
      return 'bg-sky-500 dark:bg-sky-400';
    case 'warning':
      return 'bg-amber-500 dark:bg-amber-400';
    case 'error':
      return 'bg-rose-500 dark:bg-rose-400';
  }
}

function getProgress(id: string): number {
  return progresses.value[id] !== undefined ? progresses.value[id] : 100;
}

function pauseTimer(id: string) {
  const t = timers.get(id);
  if (t && !t.paused) {
    t.paused = true;
    const elapsed = Date.now() - t.start;
    t.remaining = Math.max(0, t.duration - elapsed);
  }
}

function resumeTimer(id: string) {
  const t = timers.get(id);
  if (t && t.paused) {
    t.paused = false;
    t.start = Date.now() - (t.duration - t.remaining);
  }
}

function handleAction(item: NotificationItem) {
  if (item.action?.onClick) {
    item.action.onClick();
  }
  removeNotification(item.id);
}

onMounted(() => {
  // 每 50ms 刷新倒计时与销毁判定
  tickInterval = setInterval(() => {
    const now = Date.now();
    const activeIds = new Set(notifications.value.map((n) => n.id));

    // 清理已移除项的计时器
    for (const [id] of timers) {
      if (!activeIds.has(id)) {
        timers.delete(id);
        delete progresses.value[id];
      }
    }

    // 更新或初始化活动项
    for (const item of notifications.value) {
      let t = timers.get(item.id);
      if (!t) {
        t = {
          start: now,
          duration: item.duration,
          remaining: item.duration,
          paused: false,
        };
        timers.set(item.id, t);
      }

      if (!t.paused) {
        const elapsed = now - t.start;
        const remaining = Math.max(0, t.duration - elapsed);
        const pct = Math.max(0, Math.min(100, (remaining / t.duration) * 100));
        progresses.value[item.id] = pct;

        if (remaining <= 0) {
          removeNotification(item.id);
          timers.delete(item.id);
          delete progresses.value[item.id];
        }
      }
    }
  }, 50);
});

onUnmounted(() => {
  if (tickInterval) {
    clearInterval(tickInterval);
  }
  timers.clear();
});
</script>
