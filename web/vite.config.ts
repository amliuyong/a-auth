import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import legacy from '@vitejs/plugin-legacy';

// 前端交互页(consent/登录/恢复)。dev 下 /api 与后端端点由部署层同源代理;
// 本地开发可用 VITE_API_BASE 指向后端(如真机 API Gateway 域名)。
export default defineConfig({
  plugins: [
    react(),
    legacy({
      targets: ['ie >= 11'],
      additionalLegacyPolyfills: ['whatwg-fetch'],
    }),
  ],
  server: { port: 5173 },
  build: { outDir: 'dist', sourcemap: true },
});
