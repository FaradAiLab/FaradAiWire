import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const devPort = Number(process.env.FARADAI_WIRE_WEB_DEV_PORT) || 19418
const adminPort = Number(process.env.FARADAI_WIRE_ADMIN_PORT || process.env.ADMIN_PORT) || 19415
const adminTarget = `http://127.0.0.1:${adminPort}`

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  base: '/',
  server: {
    port: devPort,
    proxy: {
      '/admin': {
        target: adminTarget,
        changeOrigin: true,
      },
      '/api': {
        target: adminTarget,
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
})
