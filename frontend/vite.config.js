import { defineConfig, loadEnv } from 'vite'
import vue from '@vitejs/plugin-vue'
import { resolve } from 'path'

// 改成函数形式导出，这样才能获取 mode (运行模式)
export default defineConfig(({ mode }) => {
  // 加载当前环境的所有变量 (包括 docker-compose 注入的 VITE_API_BASE_URL)
  const env = loadEnv(mode, process.cwd(), '')

  return {
    plugins: [vue()],
    server: {
      // 必须开启 0.0.0.0，否则 Docker 端口映射无法生效 (宿主机访问不了)
      // 对本地开发无副作用，本地依然可以用 localhost:3000 访问
      host: '0.0.0.0', 
      port: 3000,
      proxy: {
        '/api': {
          // 【核心魔法】
          // 优先使用环境变量 (Docker场景 -> http://backend:8000)
          // 如果没有环境变量 (本地场景 -> http://127.0.0.1:8000)
          target: env.VITE_API_BASE_URL || 'http://127.0.0.1:8000',
          changeOrigin: true,
          // 如果你的后端接口路径里本身不带 /api，需要取消下面这行的注释来去掉前缀
          // rewrite: (path) => path.replace(/^\/api/, '') 
        }
      }
    },
    resolve: {
      alias: {
        '@': resolve(__dirname, 'src')
      }
    }
  }
})