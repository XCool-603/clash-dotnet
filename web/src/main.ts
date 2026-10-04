import { createApp } from 'vue'
import { createPinia } from 'pinia'

// Element Plus components and their styles are resolved on demand by the
// plugins in vite.config.ts, so there is no library-wide registration or
// stylesheet import here. Only the dark-mode CSS variables are global, because
// they are read by components that are not themselves imported by name.
import 'element-plus/theme-chalk/dark/css-vars.css'
import './styles/index.scss'

import App from './App.vue'
import router from './router'

createApp(App).use(createPinia()).use(router).mount('#app')
