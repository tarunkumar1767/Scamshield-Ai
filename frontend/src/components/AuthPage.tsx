import { useEffect, useState, type FormEvent } from 'react'
import { ArrowLeft, ArrowRight, CheckCircle2, Eye, EyeOff, LockKeyhole, Mail, Shield, ShieldCheck, Sparkles, UserRound } from 'lucide-react'

export type AuthMode = 'login' | 'signup' | 'forgot-password' | 'reset-password'
export type AuthFormValues = { email: string; password: string; fullName: string }
export type AuthReply = { error?: string; message?: string }

type Props = {
  mode: AuthMode
  configured: boolean
  demoEnabled: boolean
  resetAllowed: boolean
  notice?: string
  onSubmit: (mode: AuthMode, values: AuthFormValues) => Promise<AuthReply>
  onDemo: () => void
  onNavigate: (mode: AuthMode | 'landing') => void
}

const copy: Record<AuthMode, { title: string; description: string; submit: string }> = {
  login: { title: 'Welcome Back', description: 'Sign in to your ScamShield AI account.', submit: 'Sign In' },
  signup: { title: 'Create your account', description: 'Save your scam checks in an account-scoped workspace on this browser.', submit: 'Create Account' },
  'forgot-password': { title: 'Reset your password', description: 'We’ll send a secure reset link to the email on your account.', submit: 'Send reset link' },
  'reset-password': { title: 'Choose a new password', description: 'Use a strong password you have not used elsewhere.', submit: 'Update password' },
}

export default function AuthPage({ mode, configured, demoEnabled, resetAllowed, onSubmit, onDemo, onNavigate, notice }: Props) {
  const [email, setEmail] = useState('')
  const [fullName, setFullName] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  useEffect(() => {
    setError('')
    setSuccess('')
    setPassword('')
    setConfirmPassword('')
  }, [mode])

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError('')
    setSuccess('')
    const normalizedEmail = email.trim()
    if ((mode === 'login' || mode === 'signup' || mode === 'forgot-password') && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
      setError('Enter a valid email address.')
      return
    }
    if ((mode === 'signup' || mode === 'reset-password') && password.length < 8) {
      setError('Choose a password with at least 8 characters.')
      return
    }
    if (mode === 'reset-password' && !resetAllowed) {
      setError('This reset link is missing or has expired. Request a new password reset email.')
      return
    }
    if ((mode === 'login' || mode === 'signup' || mode === 'reset-password') && !password) {
      setError('Enter your password to continue.')
      return
    }
    if ((mode === 'signup' || mode === 'reset-password') && password !== confirmPassword) {
      setError('The passwords do not match.')
      return
    }
    if (!configured && mode !== 'reset-password') {
      setError('Supabase is not configured. Use the clearly labeled local demo or add your Supabase environment values.')
      return
    }

    setBusy(true)
    try {
      const reply = await onSubmit(mode, { email: normalizedEmail, password, fullName: fullName.trim() })
      if (reply.error) setError(reply.error)
      else {
        setSuccess(reply.message || 'Done.')
        setPassword('')
        setConfirmPassword('')
      }
    } finally {
      setBusy(false)
    }
  }

  const activeCopy = copy[mode]
  const showEmail = mode !== 'reset-password'
  const showPasswordFields = mode === 'login' || mode === 'signup' || mode === 'reset-password'
  const showConfirm = mode === 'signup' || mode === 'reset-password'

  return <main className="relative flex min-h-screen items-center justify-center overflow-hidden px-4 py-8 sm:px-6">
    <div aria-hidden="true" className="pointer-events-none absolute -left-44 top-[-100px] h-[420px] w-[420px] rounded-full bg-cyan-400/[0.06] blur-[120px]" />
    <div aria-hidden="true" className="pointer-events-none absolute -right-40 bottom-[-150px] h-[420px] w-[420px] rounded-full bg-blue-500/[0.07] blur-[130px]" />
    <div className="relative grid w-full max-w-5xl overflow-hidden rounded-[26px] border border-white/[0.08] bg-[#0c1524] shadow-2xl shadow-black/40 lg:grid-cols-[.92fr_1.08fr]">
      <section className="hidden flex-col justify-between border-r border-white/[0.06] bg-gradient-to-br from-cyan-300/[0.055] via-transparent to-blue-500/[0.04] p-9 lg:flex xl:p-11">
        <div>
          <button onClick={() => onNavigate('landing')} className="inline-flex items-center gap-3 text-left" aria-label="Return to ScamShield landing page">
            <span className="grid h-10 w-10 place-items-center rounded-xl border border-cyan-300/20 bg-cyan-300/10 text-cyan-200"><Shield size={20}/></span>
            <span className="text-base font-semibold tracking-tight text-slate-100">ScamShield <span className="text-cyan-200">AI</span></span>
          </button>
          <div className="mt-16 max-w-sm">
            <span className="grid h-12 w-12 place-items-center rounded-2xl border border-cyan-200/15 bg-cyan-200/[0.06] text-cyan-100"><ShieldCheck size={22}/></span>
            <h1 className="mt-6 text-3xl font-semibold leading-tight tracking-tight text-slate-100">A calmer way to check the unexpected.</h1>
            <p className="mt-4 text-sm leading-7 text-slate-400">Review suspicious messages, screenshots, and links. Your saved scan history stays separated by account in this browser.</p>
          </div>
        </div>
        <div className="flex items-center gap-2 text-[11px] text-slate-500"><LockKeyhole size={13} className="text-cyan-200/80"/>{configured ? 'Authentication is handled by Supabase Auth.' : 'Connect Supabase to enable real account authentication.'}</div>
      </section>

      <section className="min-w-0 p-5 sm:p-8 lg:p-10 xl:p-12">
        <div className="mb-8 flex items-center justify-between lg:hidden">
          <button onClick={() => onNavigate('landing')} className="inline-flex items-center gap-2.5 text-left"><span className="grid h-9 w-9 place-items-center rounded-xl border border-cyan-300/20 bg-cyan-300/10 text-cyan-200"><Shield size={18}/></span><span className="text-sm font-semibold">ScamShield <span className="text-cyan-200">AI</span></span></button>
          <span className="rounded-full border border-cyan-200/10 bg-cyan-200/[0.04] px-2.5 py-1 text-[9px] text-cyan-100">Secure access</span>
        </div>
        <button onClick={() => onNavigate('landing')} className="mb-7 inline-flex items-center gap-1.5 text-[10px] text-slate-500 transition hover:text-slate-300"><ArrowLeft size={13}/>Public landing page</button>
        <div className="mb-6">
          <p className="mb-2 text-[9px] font-semibold uppercase tracking-[.2em] text-cyan-200/70">ScamShield account</p>
          <h2 className="text-2xl font-semibold tracking-tight text-slate-100">{activeCopy.title}</h2>
          <p className="mt-2 max-w-md text-[11px] leading-5 text-slate-400">{activeCopy.description}</p>
        </div>

        {!configured && <div role="status" className="mb-5 rounded-xl border border-amber-200/15 bg-amber-200/[0.045] p-3.5">
          <p className="flex items-center gap-2 text-[10px] font-semibold text-amber-100"><Sparkles size={13}/>Supabase is not configured</p>
          <p className="mt-1.5 text-[10px] leading-5 text-slate-400">Add <code className="text-slate-200">VITE_SUPABASE_URL</code> and <code className="text-slate-200">VITE_SUPABASE_ANON_KEY</code> to <code className="text-slate-200">frontend/.env</code> to enable real accounts.</p>
          {demoEnabled && <p className="mt-1.5 text-[10px] leading-5 text-amber-100/80">Local demo access is only for development: it creates no account, is not real authentication, and ends when this page reloads.</p>}
        </div>}

        {mode === 'reset-password' && !resetAllowed && <div role="status" className="mb-5 rounded-xl border border-amber-200/15 bg-amber-200/[0.045] p-3 text-[10px] leading-5 text-amber-100">Open the password reset link from your email in this browser. If the link expired, request a new one.</div>}
        {error && <div role="alert" className="mb-4 rounded-lg border border-rose-200/15 bg-rose-200/[0.045] px-3 py-2.5 text-[10px] leading-5 text-rose-100">{error}</div>}
        {notice && <div role="status" className="mb-4 rounded-lg border border-emerald-200/15 bg-emerald-200/[0.045] px-3 py-2.5 text-[10px] leading-5 text-emerald-100">{notice}</div>}
        {success && <div role="status" className="mb-4 flex items-start gap-2 rounded-lg border border-emerald-200/15 bg-emerald-200/[0.045] px-3 py-2.5 text-[10px] leading-5 text-emerald-100"><CheckCircle2 size={14} className="mt-0.5 shrink-0"/>{success}</div>}

        <form onSubmit={submit} className="space-y-4">
          {mode === 'signup' && <label className="block"><span className="mb-1.5 block text-[10px] font-medium text-slate-300">Full Name</span><span className="relative block"><UserRound size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500"/><input autoComplete="name" value={fullName} onChange={event => setFullName(event.target.value)} disabled={!configured || busy} className="w-full rounded-lg border border-white/[0.09] bg-[#08111f] py-3 pl-9 pr-3 text-xs text-slate-100 outline-none transition placeholder:text-slate-600 focus:border-cyan-200/30 disabled:opacity-50" placeholder="Your name" required/></span></label>}
          {showEmail && <label className="block"><span className="mb-1.5 block text-[10px] font-medium text-slate-300">Email address</span><span className="relative block"><Mail size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500"/><input type="email" autoComplete="email" inputMode="email" value={email} onChange={event => setEmail(event.target.value)} disabled={!configured || busy} className="w-full rounded-lg border border-white/[0.09] bg-[#08111f] py-3 pl-9 pr-3 text-xs text-slate-100 outline-none transition placeholder:text-slate-600 focus:border-cyan-200/30 disabled:opacity-50" placeholder="you@example.com" required/></span></label>}
          {showPasswordFields && <label className="block"><span className="mb-1.5 block text-[10px] font-medium text-slate-300">{mode === 'reset-password' ? 'New password' : 'Password'}</span><span className="relative block"><LockKeyhole size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500"/><input type={showPassword ? 'text' : 'password'} autoComplete={mode === 'login' ? 'current-password' : 'new-password'} value={password} onChange={event => setPassword(event.target.value)} disabled={(!configured && mode !== 'reset-password') || busy || (mode === 'reset-password' && !resetAllowed)} className="w-full rounded-lg border border-white/[0.09] bg-[#08111f] py-3 pl-9 pr-10 text-xs text-slate-100 outline-none transition placeholder:text-slate-600 focus:border-cyan-200/30 disabled:opacity-50" placeholder={mode === 'login' ? 'Enter your password' : 'At least 8 characters'} required minLength={mode === 'login' ? undefined : 8}/><button type="button" onClick={() => setShowPassword(value => !value)} aria-label={showPassword ? 'Hide password' : 'Show password'} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300">{showPassword ? <EyeOff size={14}/> : <Eye size={14}/>}</button></span>{mode !== 'login' && <span className="mt-1.5 block text-[9px] text-slate-600">Use at least 8 characters.</span>}</label>}
          {showConfirm && <label className="block"><span className="mb-1.5 block text-[10px] font-medium text-slate-300">Confirm password</span><span className="relative block"><LockKeyhole size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500"/><input type={showPassword ? 'text' : 'password'} autoComplete="new-password" value={confirmPassword} onChange={event => setConfirmPassword(event.target.value)} disabled={!configured || busy || (mode === 'reset-password' && !resetAllowed)} className="w-full rounded-lg border border-white/[0.09] bg-[#08111f] py-3 pl-9 pr-3 text-xs text-slate-100 outline-none transition placeholder:text-slate-600 focus:border-cyan-200/30 disabled:opacity-50" placeholder="Enter it again" required minLength={8}/></span></label>}
          <button type="submit" disabled={busy || (!configured && mode !== 'reset-password') || (mode === 'reset-password' && !resetAllowed)} className="flex w-full items-center justify-center gap-2 rounded-lg bg-cyan-200 px-4 py-3 text-xs font-semibold text-slate-950 transition hover:bg-cyan-100 disabled:cursor-not-allowed disabled:opacity-50">{busy ? 'Please wait…' : activeCopy.submit}{!busy && <ArrowRight size={14}/>}</button>
        </form>

        <div className="mt-4 flex flex-wrap items-center justify-between gap-3 text-[10px]">
          {mode === 'login' && <><button onClick={() => onNavigate('forgot-password')} className="text-cyan-200 hover:text-cyan-100">Forgot password?</button><span className="text-slate-500">Don’t have an account? <button onClick={() => onNavigate('signup')} className="font-medium text-slate-200 hover:text-cyan-100">Create one</button></span></>}
          {mode === 'signup' && <span className="text-slate-500">Already have an account? <button onClick={() => onNavigate('login')} className="font-medium text-cyan-200 hover:text-cyan-100">Sign In</button></span>}
          {mode === 'forgot-password' && <button onClick={() => onNavigate('login')} className="text-cyan-200 hover:text-cyan-100">Back to sign in</button>}
          {mode === 'reset-password' && !resetAllowed && <button onClick={() => onNavigate('forgot-password')} className="text-cyan-200 hover:text-cyan-100">Request a new link</button>}
        </div>

        {demoEnabled && !configured && <div className="mt-7 border-t border-white/[0.07] pt-5"><div className="mb-3 text-center text-[9px] text-slate-600">LOCAL DEVELOPMENT ONLY</div><button onClick={onDemo} className="flex w-full items-center justify-center gap-2 rounded-lg border border-cyan-200/15 bg-cyan-200/[0.035] px-4 py-3 text-[11px] font-medium text-cyan-100 transition hover:bg-cyan-200/[0.07]"><Sparkles size={14}/>Continue with local demo</button></div>}
        <p className="mt-7 text-center text-[9px] leading-5 text-slate-600">{configured ? 'Your password is sent directly to Supabase Auth. ScamShield does not store passwords or authentication tokens itself.' : 'The local demo does not collect a password or create an account.'}</p>
      </section>
    </div>
  </main>
}
