import { defineConfig } from 'vite'

const securityHeaders = {
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Embedder-Policy': 'require-corp',
}

export default defineConfig(({ command }) => ({
  root: 'src',
  base: command === 'build' ? '/duneSlideDemo/' : '/',
  build: { outDir: '../dist', emptyOutDir: true, target: 'esnext' },
  worker: { format: 'es' },
  server:  { headers: securityHeaders },
  preview: { headers: securityHeaders },
}))
