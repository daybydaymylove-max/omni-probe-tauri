<template>
  <div class="w-full h-full flex flex-col items-center justify-center p-6 text-center select-none">
    <div
      class="w-11 h-11 rounded-[12px] flex items-center justify-center mb-3"
      style="background: var(--surface-elevated); border: 1px solid var(--border-subtle); color: var(--text-secondary);"
    >
      <AppIcon :name="icon" :size="20" :stroke-width="1.6" />
    </div>
    <h3 class="text-[13px] font-semibold text-[var(--text-primary)] tracking-tight">
      {{ title }}
    </h3>
    <p v-if="description" class="text-[12px] text-[var(--text-secondary)] max-w-[400px] mt-1 leading-relaxed">
      {{ description }}
    </p>
    <div v-if="$slots.actions" class="mt-4 flex items-center gap-2">
      <slot name="actions" />
    </div>
  </div>
</template>

<script setup lang="ts">
import AppIcon from './AppIcon.vue';

withDefaults(
  defineProps<{
    icon?: string;
    title: string;
    description?: string;
  }>(),
  {
    icon: 'radar',
    description: '',
  }
);
</script>
