import { fileURLToPath, URL } from 'node:url'

import vue from '@vitejs/plugin-vue'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  // Relative base so the bundle can be served from any mount point
  // (the .NET host serves it straight out of wwwroot).
  base: './',
  plugins: [vue()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    // The Clash API enables permissive CORS, so the dev server talks to
    // http://127.0.0.1:9090 directly. No proxy is needed.
    cors: true,
  },
  build: {
    // Publish straight into the backend static root.
    outDir: '../src/Clash.Server/wwwroot',
    emptyOutDir: true,
    chunkSizeWarningLimit: 2000,
    sourcemap: false,
  },
})
