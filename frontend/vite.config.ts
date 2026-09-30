import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

function hasServiceRoleKey(value: string | undefined): boolean {
  if (!value) return false
  if (value.toLowerCase().startsWith('sb_secret_')) return true
  const parts = value.split('.')
  if (parts.length !== 3) return false
  try {
    const payload = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    const claims = JSON.parse(Buffer.from(payload, 'base64').toString('utf8')) as { role?: unknown }
    return claims.role === 'service_role'
  } catch {
    return false
  }
}

export default defineConfig(({ mode, command }) => {
  const frontendEnv = loadEnv(mode, process.cwd(), 'VITE_')
  if (hasServiceRoleKey(frontendEnv.VITE_SUPABASE_ANON_KEY)) {
    throw new Error('Unsafe frontend configuration: VITE_SUPABASE_ANON_KEY must contain a public anon or publishable key. Never place a service-role or secret key in frontend environment variables.')
  }
  if (command === 'build' && frontendEnv.VITE_API_URL) {
    try {
      const apiHost = new URL(frontendEnv.VITE_API_URL).hostname.toLowerCase()
      const normalizedHost = apiHost.replace(/\.$/, '')
      if (normalizedHost === 'localhost' || normalizedHost.endsWith('.localhost') || normalizedHost.startsWith('127.') || normalizedHost === '[::1]' || normalizedHost === '::1') {
        throw new Error('Invalid production API configuration: VITE_API_URL cannot point to localhost. Set it to the deployed backend origin.')
      }
    } catch (error) {
      if (error instanceof Error && error.message.startsWith('Invalid production API configuration:')) throw error
      throw new Error('Invalid production API configuration: VITE_API_URL must be an absolute backend URL.')
    }
  }

  return {
    plugins: [react(), tailwindcss()],
    server: {
      port: 5173,
      proxy: {
        '/api': { target: 'http://127.0.0.1:8000', changeOrigin: true },
      },
    },
  }
})
