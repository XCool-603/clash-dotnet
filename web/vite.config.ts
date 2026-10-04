import { fileURLToPath, URL } from 'node:url'

import vue from '@vitejs/plugin-vue'
import { defineConfig } from 'vite'
import AutoImport from 'unplugin-auto-import/vite'
import Components from 'unplugin-vue-components/vite'

/**
 * Components that Element Plus ships inside a parent's module rather than as
 * their own entry point: `ElOption` lives in `components/select`, `ElFormItem`
 * in `components/form`, and so on. Anything not listed here is its own module,
 * named after the component in kebab case.
 */
const PARENT_MODULE: Record<string, string> = {
  ElButtonGroup: 'button',
  ElCheckboxButton: 'checkbox',
  ElCheckboxGroup: 'checkbox',
  ElDescriptionsItem: 'descriptions',
  ElDropdownItem: 'dropdown',
  ElDropdownMenu: 'dropdown',
  ElFormItem: 'form',
  ElOption: 'select',
  ElOptionGroup: 'select',
  ElRadioButton: 'radio',
  ElRadioGroup: 'radio',
}

const kebab = (name: string): string =>
  name.slice(2).replace(/([a-z0-9])([A-Z])/g, '$1-$2').toLowerCase()

/**
 * Resolves an Element Plus component to its own module instead of the library's
 * barrel.
 *
 * The stock resolver answers `element-plus/es` for everything, and that barrel
 * cannot be tree-shaken: its module scope calls `makeInstaller()` over every
 * component in the library, so importing one name evaluates all of them. That
 * single detail is the difference between a ~150 kB dependency and a ~800 kB
 * one, and it is invisible in the source because both spellings look the same.
 *
 * A wrong entry here fails the build rather than silently bloating it: Rollup
 * cannot resolve a name that the named module does not export.
 */
function elementPlusComponent(name: string) {
  if (!name.startsWith('El')) return undefined

  const module = PARENT_MODULE[name] ?? kebab(name)
  return {
    name,
    from: `element-plus/es/components/${module}/index`,
    // Each component carries its own stylesheet, including the sub-components.
    sideEffects: `element-plus/es/components/${kebab(name)}/style/css`,
  }
}

/** The same treatment for the imperative APIs, which no template mentions. */
function elementPlusApi(name: string) {
  if (name !== 'ElMessage' && name !== 'ElMessageBox' && name !== 'ElNotification' && name !== 'ElLoading') {
    return undefined
  }

  const module = kebab(name)
  return {
    name,
    from: `element-plus/es/components/${module}/index`,
    sideEffects: `element-plus/es/components/${module}/style/css`,
  }
}

// https://vite.dev/config/
export default defineConfig({
  // Relative base so the bundle can be served from any mount point
  // (the .NET host serves it straight out of wwwroot).
  base: './',
  plugins: [
    vue(),
    AutoImport({
      resolvers: [elementPlusApi],
      // Generated inside src/ so the existing tsconfig include picks it up.
      dts: 'src/auto-imports.d.ts',
    }),
    Components({
      resolvers: [elementPlusComponent],
      dts: 'src/components.d.ts',
    }),
  ],
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
    sourcemap: false,
    rollupOptions: {
      output: {
        // Split the vendors so a view change does not invalidate them, and so
        // the browser can fetch them in parallel with the entry chunk. The
        // order of these tests matters: `vue-echarts` contains `vue`.
        manualChunks(id) {
          if (!id.includes('node_modules')) return undefined
          if (id.includes('echarts') || id.includes('zrender')) return 'echarts'
          if (id.includes('element-plus')) return 'element-plus'
          if (id.includes('/vue/') || id.includes('vue-router') || id.includes('pinia') || id.includes('@vue/')) {
            return 'vue'
          }
          return 'vendor'
        },
      },
    },
  },
})
