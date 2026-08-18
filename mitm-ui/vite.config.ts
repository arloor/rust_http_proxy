import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const env = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env ?? {}

function basicAuthHeader(raw: string | undefined): Record<string, string> {
  const credential = raw?.trim()
  if (!credential) return {}
  const bytes = new TextEncoder().encode(credential)
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return { Authorization: `Basic ${btoa(binary)}` }
}

const mitmDevProxy = {
  target: env.MITM_DEV_PROXY_TARGET || 'https://127.0.0.1:444',
  changeOrigin: true,
  secure: false,
  headers: basicAuthHeader(env.MITM_DEV_PROXY_USER),
}

export default defineConfig({
  base: '/mitm/',
  plugins: [react()],
  server: {
    proxy: {
      '/mitm/api': mitmDevProxy,
      '/mitm/ca.crt': mitmDevProxy,
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
})
