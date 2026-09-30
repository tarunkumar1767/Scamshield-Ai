import { createClient, type Session, type User } from '@supabase/supabase-js'

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL?.trim()
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY?.trim()

function isValidSupabaseUrl(value: string | undefined): value is string {
  if (!value) return false
  try {
    const parsed = new URL(value)
    const isLocalDevelopmentHost = import.meta.env.DEV && ['localhost', '127.0.0.1'].includes(parsed.hostname)
    return (parsed.protocol === 'https:' || (parsed.protocol === 'http:' && isLocalDevelopmentHost))
      && Boolean(parsed.hostname)
      && !parsed.username
      && !parsed.password
      && parsed.pathname === '/'
      && !parsed.search
      && !parsed.hash
  } catch {
    return false
  }
}

function isPublicSupabaseKey(value: string | undefined): boolean {
  if (!value || value.toLowerCase().startsWith('sb_secret_')) return false
  if (value.toLowerCase().startsWith('sb_publishable_')) return true

  const parts = value.split('.')
  if (parts.length !== 3) return false
  try {
    const payload = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    const claims = JSON.parse(atob(payload + '='.repeat((4 - payload.length % 4) % 4))) as { role?: unknown }
    return claims.role === 'anon'
  } catch {
    return false
  }
}

export const supabaseConfigurationMessage = !supabaseUrl
  ? 'Add VITE_SUPABASE_URL to the frontend environment settings to enable real accounts.'
  : !isValidSupabaseUrl(supabaseUrl)
    ? 'VITE_SUPABASE_URL must be a valid Supabase project base URL, such as https://<project-ref>.supabase.co, without a path or query.'
    : !supabaseAnonKey
      ? 'Add VITE_SUPABASE_ANON_KEY to the frontend environment settings to enable real accounts.'
      : !isPublicSupabaseKey(supabaseAnonKey)
        ? 'VITE_SUPABASE_ANON_KEY must be the public anon or publishable key. Never use a service-role or secret key in the frontend.'
        : ''

export const isSupabaseConfigured = supabaseConfigurationMessage === ''

export const supabase = isSupabaseConfigured
  ? createClient(supabaseUrl!, supabaseAnonKey!, {
      auth: {
        autoRefreshToken: true,
        persistSession: true,
        detectSessionInUrl: true,
      },
    })
  : null

export type AppUser = {
  id: string
  email: string
  displayName: string
  isDemo: boolean
}

export function toAppUser(user: User | null | undefined): AppUser | null {
  if (!user) return null
  const metadata = user.user_metadata as Record<string, unknown> | undefined
  const displayName = typeof metadata?.full_name === 'string' ? metadata.full_name.trim() : ''
  return {
    id: user.id,
    email: user.email || '',
    displayName: displayName || user.email?.split('@')[0] || 'ScamShield user',
    isDemo: false,
  }
}

export function toAppSessionUser(session: Session | null | undefined) {
  return toAppUser(session?.user)
}

export function friendlyAuthError(error: { code?: string; message?: string } | null | undefined, intent: 'login' | 'signup' | 'reset' | 'password' = 'login') {
  const code = error?.code?.toLowerCase() || ''
  const message = error?.message?.toLowerCase() || ''
  if (code.includes('invalid_credentials') || message.includes('invalid login credentials')) return 'That email and password combination was not recognized. Check them and try again.'
  if (code.includes('email_not_confirmed') || message.includes('email not confirmed')) return 'Please verify your email using the link we sent before signing in.'
  if (code.includes('user_already_exists') || message.includes('already registered')) return 'An account may already exist for this email. Try signing in instead.'
  if (code.includes('weak_password') || message.includes('password should be')) return 'Choose a stronger password with at least 8 characters.'
  if (code.includes('invalid_email') || message.includes('invalid email')) return 'Enter a valid email address and try again.'
  if (message.includes('rate limit') || message.includes('too many requests')) return 'Too many attempts were made. Wait a few minutes, then try again.'
  if (message.includes('fetch') || message.includes('network') || message.includes('offline')) return 'We could not reach the authentication service. Check your connection and try again.'
  if (intent === 'signup') return 'We could not create the account. Check your details and try again.'
  if (intent === 'reset') return 'We could not send the reset email. Check the address and try again.'
  if (intent === 'password') return 'We could not update the password. The reset link may have expired; request a new one.'
  return 'We could not sign you in. Check your details and try again.'
}
