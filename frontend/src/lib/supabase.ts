import { createClient, type Session, type User } from '@supabase/supabase-js'

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL?.trim()
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY?.trim()

export const isSupabaseConfigured = Boolean(supabaseUrl && supabaseAnonKey)

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
