import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import tailwindcss from '@tailwindcss/vite';

const host = process.env.TAURI_DEV_HOST;

export default defineConfig({
  base: './',
  plugins: [vue(), tailwindcss()],
  clearScreen: false,
  build: {
    chunkSizeWarningLimit: 600,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('node_modules')) {
            if (id.includes('echarts') || id.includes('zrender')) {
              return 'vendor-echarts';
            }
            if (id.includes('@tauri-apps')) {
              return 'vendor-tauri';
            }
            if (id.includes('/vue/') || id.includes('@vue')) {
              return 'vendor-vue';
            }
            return 'vendor-libs';
          }
        },
      },
    },
  },
  server: {
    port: 1420,
    strictPort: true,
    host: host || '0.0.0.0',
    hmr: host ? { protocol: 'ws', host, port: 1421 } : undefined,
    watch: { ignored: ['**/src-tauri/**'] },
  },
});
