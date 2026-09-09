import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig(({ command }) => ({
  plugins: [react()],
  base: command === 'build' ? '/static/' : '/',
  resolve: {
    alias: {
      '@': path.resolve(import.meta.dirname, './src'),
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
  server: {
    proxy: {
      '/api': { target: 'http://localhost:8001', changeOrigin: true },
      '/accounts': { target: 'http://localhost:8001', changeOrigin: true },
      // Only proxy the report *endpoints* (/reports/<uuid>/csv|pdf/) to Django —
      // a regex key (leading ^) so the bare /reports SPA page is served by Vite,
      // not forwarded to the backend. (Production works via Django's SPA catch-all.)
      '^/reports/.+': { target: 'http://localhost:8001', changeOrigin: true },
    },
  },
}));
