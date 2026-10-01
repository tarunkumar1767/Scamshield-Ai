import { useEffect, useMemo, useRef, useState } from 'react'
import {
  Activity, AlertTriangle, ArrowDownRight, ArrowRight, ArrowUpRight, BadgeCheck, Bell, Check, CheckCircle2,
  ChevronRight, CircleHelp, Clock3, ExternalLink, Eye, FileImage, Globe2, History, Home, Link2, LoaderCircle,
  LockKeyhole, LogOut, Menu, MessageSquareText, Search, Shield, ShieldAlert, ShieldCheck, Sparkles, Trash2,
  UploadCloud, UserRound, X, Zap,
} from 'lucide-react'
import { createWorker } from 'tesseract.js'
import AuthPage, { type AuthFormValues, type AuthMode, type AuthReply } from './components/AuthPage'
import { friendlyAuthError, isSupabaseConfigured, supabase, supabaseConfigurationMessage, toAppSessionUser, type AppUser } from './lib/supabase'

type ScanResult = {
  risk_level: string
  risk_score?: number
  score?: number
  category?: string
  summary?: string
  red_flags?: string[]
  evidence?: { quote: string; reason: string }[]
  recommended_actions?: string[]
  safety_tips?: string[]
  demo_mode?: boolean
  analysis_source?: 'ai' | 'demo' | 'fallback'
  fallback_reason?: 'AI_CONFIGURATION_MISSING' | 'AI_AUTH_FAILED' | 'AI_MODEL_ERROR' | 'AI_RATE_LIMITED' | 'AI_QUOTA_EXCEEDED' | 'AI_TIMEOUT' | 'AI_NETWORK_ERROR' | 'AI_PROVIDER_ERROR' | null
  indicators?: string[]
  assessment_type?: string
  url?: string
  protocol?: string
  domain?: string
  port?: number | null
  path?: string
  query_parameters?: { key: string; value: string }[]
  findings?: { code: string; title: string; severity: string; explanation: string; evidence: string }[]
  explanation?: string
}
type ScanKind = 'message' | 'screenshot' | 'url'
type HistoryItem = {
  id: string
  createdAt: string
  kind: ScanKind
  riskLevel: string
  riskScore: number
  category: string
  summary: string
  result: ScanResult
}
type Page = 'landing' | 'login' | 'signup' | 'forgot-password' | 'reset-password' | 'dashboard' | 'scanner' | 'screenshot' | 'url' | 'history' | 'safety'
function normalizeApiUrl(value: string | undefined): string {
  if (!value?.trim()) return ''
  try {
    const parsed = new URL(value.trim())
    if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname || parsed.username || parsed.password || parsed.search || parsed.hash) return ''
    const path = parsed.pathname.replace(/\/+$/, '').replace(/\/api$/i, '')
    return `${parsed.origin}${path}`
  } catch {
    return ''
  }
}

const API_URL = normalizeApiUrl(import.meta.env.VITE_API_URL)
const HISTORY_KEY = 'scamshield.scan-history'
const SAFETY_CHECKLIST_KEY = 'scamshield.safety-checklist'
const LOCAL_DEMO_ENABLED = import.meta.env.DEV && import.meta.env.VITE_DEMO_MODE !== 'false'
const routeToPage: Record<string, Page> = { '/': 'landing', '/login': 'login', '/signup': 'signup', '/forgot-password': 'forgot-password', '/reset-password': 'reset-password', '/dashboard': 'dashboard', '/scanner': 'scanner', '/message-scanner': 'scanner', '/screenshot-scanner': 'screenshot', '/url-checker': 'url', '/history': 'history', '/safety-center': 'safety' }
const pageToRoute: Record<Page, string> = { landing: '/', login: '/login', signup: '/signup', 'forgot-password': '/forgot-password', 'reset-password': '/reset-password', dashboard: '/dashboard', scanner: '/message-scanner', screenshot: '/screenshot-scanner', url: '/url-checker', history: '/history', safety: '/safety-center' }
const protectedPages = new Set<Page>(['dashboard', 'scanner', 'screenshot', 'url', 'history', 'safety'])
const authPages = new Set<Page>(['login', 'signup', 'forgot-password', 'reset-password'])

const nav = [
  { page: 'dashboard' as Page, label: 'Overview', icon: Home, group: 'Workspace' },
  { page: 'scanner' as Page, label: 'Message scanner', icon: MessageSquareText, group: 'Workspace' },
  { page: 'screenshot' as Page, label: 'Screenshot scanner', icon: FileImage, group: 'Workspace' },
  { page: 'url' as Page, label: 'URL checker', icon: Link2, group: 'Workspace' },
  { page: 'history' as Page, label: 'Scan history', icon: History, group: 'Personal' },
  { page: 'safety' as Page, label: 'Safety center', icon: ShieldCheck, group: 'Personal' },
]

function redactSensitiveText(value: unknown, limit = 500): string {
  if (typeof value !== 'string') return ''
  return value
    .replace(/\b(password|passcode|one[- ]time(?: password)?|otp|pin|cvv|cvc|security code|verification code)(\s*(?:(?:is|was|:|=)\s*|\s+))([\w@#$%^&*+!.-]{4,})/gi, (match, label: string, separator: string, secret: string) => {
      const generic = /^(?:passcodes?|passwords?|codes?|number|details|requested|required|never|share|phrase|token|verification|card|or|are|must|with|from|to|and|is|was|like|someone|anyone|your|their|the|a|an|should|one|time)$/i.test(secret)
      return !/[:=]|\bis\b|\bwas\b/i.test(separator) && generic ? match : `${label}${separator}[redacted]`
    })
    .replace(/\b(cvv|cvc|pin|otp|passcode|verification code)\s*(?:(?:is|was|:|=)\s*|\s+)(\d{3,8})\b/gi, '$1 [redacted]')
    .replace(/\b(?:\d[ -]?){13,19}\b/g, '[redacted payment number]')
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, limit)
}
function safeResult(result: ScanResult): ScanResult {
  const safe: ScanResult = {
    risk_level: redactSensitiveText(result.risk_level, 20) || 'unknown',
    risk_score: Number.isFinite(result.risk_score) ? result.risk_score : Number.isFinite(result.score) ? result.score : 0,
    score: Number.isFinite(result.score) ? result.score : undefined,
    category: redactSensitiveText(result.category, 100) || undefined,
    summary: redactSensitiveText(result.summary, 240) || undefined,
    red_flags: result.red_flags?.slice(0, 20).map(item => redactSensitiveText(item, 180)).filter(Boolean),
    evidence: result.evidence?.slice(0, 20).map(item => ({ quote: redactSensitiveText(item.quote, 180), reason: redactSensitiveText(item.reason, 240) })),
    recommended_actions: result.recommended_actions?.slice(0, 20).map(item => redactSensitiveText(item, 300)).filter(Boolean),
    safety_tips: result.safety_tips?.slice(0, 20).map(item => redactSensitiveText(item, 300)).filter(Boolean),
    demo_mode: result.analysis_source === 'fallback' ? undefined : result.demo_mode,
    analysis_source: result.analysis_source,
    fallback_reason: ['AI_CONFIGURATION_MISSING', 'AI_AUTH_FAILED', 'AI_MODEL_ERROR', 'AI_RATE_LIMITED', 'AI_QUOTA_EXCEEDED', 'AI_TIMEOUT', 'AI_NETWORK_ERROR', 'AI_PROVIDER_ERROR'].includes(result.fallback_reason || '') ? result.fallback_reason : undefined,
    indicators: result.indicators?.slice(0, 20).map(item => redactSensitiveText(item, 180)).filter(Boolean),
    assessment_type: result.assessment_type,
    protocol: redactSensitiveText(result.protocol, 20) || undefined,
    domain: redactSensitiveText(result.domain, 253) || undefined,
    port: result.port,
    path: redactSensitiveText(result.path, 500) || undefined,
    query_parameters: result.query_parameters?.slice(0, 40).map(param => ({
      key: redactSensitiveText(param.key, 100),
      value: /password|passcode|token|secret|session|auth|otp|pin|cvv|code|key/i.test(param.key)
        ? '[redacted]'
        : redactSensitiveText(param.value, 200),
    })),
    findings: result.findings?.slice(0, 30).map(finding => ({
      code: redactSensitiveText(finding.code, 80), title: redactSensitiveText(finding.title, 180),
      severity: redactSensitiveText(finding.severity, 20), explanation: redactSensitiveText(finding.explanation, 300),
      evidence: redactSensitiveText(finding.evidence, 240),
    })),
    explanation: redactSensitiveText(result.explanation, 500) || undefined,
  }
  return safe
}
function makeHistoryItem(raw: any): HistoryItem | null {
  if (!raw || typeof raw !== 'object' || !raw.result || typeof raw.result !== 'object') return null
  const kind: ScanKind = ['message', 'screenshot', 'url'].includes(raw.kind) ? raw.kind : 'message'
  const result = safeResult(raw.result as ScanResult)
  const riskScore = Number.isFinite(raw.riskScore) ? raw.riskScore : result.risk_score ?? result.score ?? 0
  const summary = redactSensitiveText(raw.summary || result.summary || result.explanation, 240) || 'Analysis completed.'
  return {
    id: typeof raw.id === 'string' && raw.id ? raw.id : makeId(),
    createdAt: typeof raw.createdAt === 'string' && Number.isFinite(Date.parse(raw.createdAt)) ? raw.createdAt : new Date().toISOString(),
    kind,
    riskLevel: redactSensitiveText(raw.riskLevel || result.risk_level, 20) || 'unknown',
    riskScore: Math.max(0, Math.min(100, riskScore)),
    category: redactSensitiveText(raw.category || result.category || (kind === 'url' ? 'URL structure' : 'Message assessment'), 100),
    summary,
    result,
  }
}
function makeId() { return typeof crypto !== 'undefined' && 'randomUUID' in crypto ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(36).slice(2)}` }
function historyKeyFor(user: AppUser | null) { return user ? `${HISTORY_KEY}:${user.id}` : null }
function readHistory(key: string): HistoryItem[] {
  try {
    const parsed = JSON.parse(localStorage.getItem(key) || '[]')
    if (!Array.isArray(parsed)) return []
    const clean = parsed.map(makeHistoryItem).filter((item): item is HistoryItem => item !== null)
      .sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt)).slice(0, 100)
    if (JSON.stringify(parsed) !== JSON.stringify(clean)) localStorage.setItem(key, JSON.stringify(clean))
    return clean
  } catch { return [] }
}
function persistHistory(items: HistoryItem[], key: string | null) { if (!key) return; try { localStorage.setItem(key, JSON.stringify(items)) } catch { /* The current session remains usable if browser storage is unavailable. */ } }
function riskTone(risk: string) { const normalized = risk.trim().toLowerCase().replace(/[_-]+/g, ' '); return normalized.includes('critical') || normalized.includes('high') ? 'rose' : normalized.includes('medium') || normalized === 'low risk' ? 'amber' : 'emerald' }
function kindLabel(kind: ScanKind) { return kind === 'url' ? 'URL' : kind === 'screenshot' ? 'Screenshot' : 'Message' }
function formatDate(value: string) { const date = new Date(value); return Number.isFinite(date.getTime()) ? date.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : 'Date unavailable' }

export default function AppNew() {
  const [page, setPage] = useState<Page>(() => routeToPage[window.location.pathname] || 'landing')
  const [authUser, setAuthUser] = useState<AppUser | null>(null)
  const [authReady, setAuthReady] = useState(!isSupabaseConfigured)
  const [recoveryActive, setRecoveryActive] = useState(false)
  const [authNotice, setAuthNotice] = useState('')
  const [history, setHistory] = useState<HistoryItem[]>([])
  const [historyOwner, setHistoryOwner] = useState<string | null>(null)
  const [messagePrefill, setMessagePrefill] = useState('')
  const [apiOnline, setApiOnline] = useState<boolean | null>(null)
  const [menuOpen, setMenuOpen] = useState(false)
  const [selectedHistoryItem, setSelectedHistoryItem] = useState<HistoryItem | null>(null)
  const storageKey = historyKeyFor(authUser)

  useEffect(() => {
    const onPop = () => { setPage(routeToPage[window.location.pathname] || 'landing'); setMenuOpen(false) }
    window.addEventListener('popstate', onPop)
    return () => window.removeEventListener('popstate', onPop)
  }, [])
  useEffect(() => {
    if (!supabase) { setAuthReady(true); return }
    let active = true
    const { data: { subscription } } = supabase.auth.onAuthStateChange((event, session) => {
      if (!active) return
      if (event === 'PASSWORD_RECOVERY') {
        setRecoveryActive(true)
        setPage('reset-password')
        window.history.replaceState({}, '', pageToRoute['reset-password'])
      }
      if (event === 'SIGNED_OUT') { setAuthUser(null); setRecoveryActive(false) }
      else if (session) setAuthUser(toAppSessionUser(session))
      if (event === 'INITIAL_SESSION') setAuthReady(true)
    })
    void supabase.auth.getSession().then(({ data, error }) => {
      if (!active) return
      if (!error) setAuthUser(toAppSessionUser(data.session))
      setAuthReady(true)
    }).catch(() => { if (active) setAuthReady(true) })
    return () => { active = false; subscription.unsubscribe() }
  }, [])
  useEffect(() => {
    let live = true
    if (import.meta.env.PROD && !API_URL) { setApiOnline(false); return () => { live = false } }
    fetch(`${API_URL}/api/health`).then(r => { if (live) setApiOnline(r.ok) }).catch(() => { if (live) setApiOnline(false) })
    return () => { live = false }
  }, [])
  useEffect(() => {
    setHistory(storageKey ? readHistory(storageKey) : [])
    setHistoryOwner(storageKey)
    setSelectedHistoryItem(null)
  }, [storageKey])

  useEffect(() => {
    if (!authReady) return
    if (protectedPages.has(page) && !authUser) { navigate('login', true); return }
    if (authUser && authPages.has(page) && !(page === 'reset-password' && recoveryActive)) navigate('dashboard', true)
  }, [authReady, authUser, page, recoveryActive])

  function navigate(next: Page, replace = false) {
    if (replace) window.history.replaceState({}, '', pageToRoute[next])
    else window.history.pushState({}, '', pageToRoute[next])
    setPage(next); setMenuOpen(false); window.scrollTo({ top: 0, behavior: 'smooth' })
  }
  function go(next: Page) { navigate(next) }
  function openAuth(mode: AuthMode | 'landing') { navigate(mode === 'landing' ? 'landing' : mode) }
  function analyzeExample(example: string) { setMessagePrefill(example); go('scanner') }
  function save(kind: ScanKind, result: ScanResult) {
    if (!storageKey) return
    const item = makeHistoryItem({ id: makeId(), createdAt: new Date().toISOString(), kind, result })
    if (!item || visibleHistory.some(existing => existing.id === item.id)) return
    const next = [item, ...visibleHistory].slice(0, 100)
    setHistory(next)
    setHistoryOwner(storageKey)
    persistHistory(next, storageKey)
  }
  function clearHistory() { setHistory([]); setHistoryOwner(storageKey); setSelectedHistoryItem(null); persistHistory([], storageKey) }
  function removeHistory(id: string) { const next = visibleHistory.filter(item => item.id !== id); setHistory(next); setHistoryOwner(storageKey); if (selectedHistoryItem?.id === id) setSelectedHistoryItem(null); persistHistory(next, storageKey) }

  async function submitAuth(mode: AuthMode, values: AuthFormValues): Promise<AuthReply> {
    if (!supabase) return { error: 'Supabase is not configured. Use local demo access for development or add your Supabase environment values.' }
    try {
      if (mode === 'signup') {
        const { data, error } = await supabase.auth.signUp({ email: values.email, password: values.password, options: { data: { full_name: values.fullName } } })
        if (error) return { error: friendlyAuthError(error, 'signup') }
        if (data.session) {
          setAuthUser(toAppSessionUser(data.session)); setAuthNotice(''); setRecoveryActive(false); navigate('dashboard')
          return { message: 'Your account is ready.' }
        }
        return { message: 'Account created. Check your email for the verification link, then sign in.' }
      }
      if (mode === 'login') {
        const { data, error } = await supabase.auth.signInWithPassword({ email: values.email, password: values.password })
        if (error) return { error: friendlyAuthError(error, 'login') }
        if (!data.session) return { error: 'Sign in did not complete. Verify your email and try again.' }
        setAuthUser(toAppSessionUser(data.session)); setAuthNotice(''); setRecoveryActive(false); navigate('dashboard')
        return { message: 'Signed in.' }
      }
      if (mode === 'forgot-password') {
        const { error } = await supabase.auth.resetPasswordForEmail(values.email, { redirectTo: `${window.location.origin}/reset-password` })
        if (error) return { error: friendlyAuthError(error, 'reset') }
        return { message: 'If an account exists for this address, a password reset link is on its way.' }
      }
      const { error } = await supabase.auth.updateUser({ password: values.password })
      if (error) return { error: friendlyAuthError(error, 'password') }
      const { error: signOutError } = await supabase.auth.signOut()
      if (signOutError) return { error: 'Your password was updated, but we could not end the recovery session. Sign out and sign in again.' }
      setAuthUser(null); setRecoveryActive(false); setAuthNotice('Password updated. Sign in with your new password.'); navigate('login', true)
      return { message: 'Password updated.' }
    } catch {
      return { error: 'The authentication service could not be reached. Check your connection and try again.' }
    }
  }

  function enterDemo() {
    if (!LOCAL_DEMO_ENABLED || isSupabaseConfigured) return
    setAuthUser({ id: 'local-demo', email: '', displayName: 'Demo User', isDemo: true })
    setAuthReady(true); setAuthNotice(''); setRecoveryActive(false); navigate('dashboard')
  }

  async function signOut() {
    setAuthNotice('')
    if (!authUser?.isDemo && supabase) {
      try {
        const { error } = await supabase.auth.signOut()
        if (error) { setAuthNotice('We could not complete sign out. Please try again.'); return }
      } catch { setAuthNotice('We could not complete sign out. Please try again.'); return }
    }
    setAuthUser(null); setRecoveryActive(false); setSelectedHistoryItem(null); navigate('login', true)
  }

  const visibleHistory = historyOwner === storageKey && storageKey ? history : []
  const inRecovery = page === 'reset-password' && recoveryActive
  const riskCounts = {
    high: visibleHistory.filter(item => /high|critical/i.test(item.riskLevel)).length,
    medium: visibleHistory.filter(item => /medium/i.test(item.riskLevel)).length,
    low: visibleHistory.filter(item => /low|safe/i.test(item.riskLevel)).length,
  }

  if (!authReady && page !== 'landing') return <WorkspaceLoading />
  if (authPages.has(page)) return <AuthPage key={page} mode={page as AuthMode} configured={isSupabaseConfigured} configurationMessage={supabaseConfigurationMessage} demoEnabled={LOCAL_DEMO_ENABLED} resetAllowed={inRecovery} onSubmit={submitAuth} onDemo={enterDemo} onNavigate={openAuth} notice={authNotice} />

  return <div className="min-h-screen text-slate-100">
    {page === 'landing' ? <Landing go={go} signedIn={Boolean(authUser)} user={authUser} onSignOut={() => void signOut()} /> : !authUser ? <WorkspaceLoading /> : <div className="min-h-screen lg:flex">
      <aside className="hidden w-[258px] shrink-0 flex-col border-r border-white/[0.07] bg-[#0a1220] px-5 py-6 lg:flex">
        <Brand go={go} />
        <div className="mt-10 space-y-6">{['Workspace', 'Personal'].map(group => <div key={group}><p className="mb-2 px-3 text-[10px] font-semibold uppercase tracking-[.18em] text-slate-600">{group}</p><div className="space-y-1">{nav.filter(item => item.group === group).map(item => <NavButton key={item.page} item={item} active={page === item.page} go={go} />)}</div></div>)}</div>
        <div className="mt-auto rounded-2xl border border-cyan-300/10 bg-gradient-to-br from-cyan-300/[0.09] to-blue-500/[0.03] p-4"><div className="mb-2 flex h-8 w-8 items-center justify-center rounded-lg bg-cyan-300/10 text-cyan-200"><ShieldCheck size={16}/></div><p className="text-xs font-medium text-slate-200">Stay one step ahead</p><p className="mt-1 text-[11px] leading-5 text-slate-500">Take a moment to check before you click.</p><button onClick={() => go('safety')} className="mt-3 inline-flex items-center gap-1 text-[11px] font-medium text-cyan-200 hover:text-cyan-100">Safety tips <ArrowRight size={12}/></button></div>
        <div className="mt-5 flex items-center gap-2 px-2 text-[10px] text-slate-600"><span className={`h-1.5 w-1.5 rounded-full ${apiOnline ? 'bg-emerald-300' : apiOnline === false ? 'bg-rose-300' : 'bg-amber-300'}`}/>{apiOnline ? 'Scanner service connected' : apiOnline === false ? 'Scanner service offline' : 'Checking scanner service'}</div>
      </aside>
      <div className="min-w-0 flex-1">
        <header className="sticky top-0 z-20 flex h-[70px] items-center justify-between border-b border-white/[0.07] bg-[#0a1120]/90 px-5 backdrop-blur-xl md:px-8">
          <div className="flex items-center gap-3 lg:hidden"><button aria-label="Open navigation" onClick={() => setMenuOpen(true)} className="rounded-lg border border-white/10 p-2 text-slate-300"><Menu size={18}/></button><Brand go={go} compact /></div>
          <div className="hidden text-sm text-slate-400 lg:block">{nav.find(item => item.page === page)?.label ?? 'Your personal scam protection workspace'}</div>
          <div className="ml-auto flex min-w-0 items-center gap-2 sm:gap-3"><div className="hidden items-center gap-2 rounded-full border border-white/[0.08] bg-white/[0.025] px-3 py-1.5 text-[11px] text-slate-400 sm:flex"><span className={`h-1.5 w-1.5 rounded-full ${apiOnline ? 'bg-emerald-300' : apiOnline === false ? 'bg-rose-300' : 'bg-amber-300'}`}/>{apiOnline ? 'Service online' : apiOnline === false ? 'Service offline' : 'Connecting'}</div><button onClick={() => go('history')} aria-label="Open scan history" className="rounded-lg border border-white/[0.08] p-2 text-slate-400 hover:bg-white/5"><Bell size={16}/></button><div className="hidden min-w-0 text-right sm:block"><p className="max-w-40 truncate text-[10px] font-medium text-slate-200">{authUser.displayName}</p><p className="max-w-40 truncate text-[9px] text-slate-500">{authUser.isDemo ? 'Local demo · not authenticated' : authUser.email}</p></div><span className="grid h-8 w-8 shrink-0 place-items-center rounded-full bg-gradient-to-br from-cyan-200 to-blue-400 text-slate-950"><UserRound size={15}/></span><button onClick={() => void signOut()} aria-label="Sign out" title="Sign out" className="rounded-lg border border-white/[0.08] p-2 text-slate-400 hover:border-rose-200/20 hover:bg-rose-200/[0.04] hover:text-rose-100"><LogOut size={15}/></button></div>
        </header>
        {menuOpen && <div className="fixed inset-0 z-40 bg-black/60 lg:hidden" onClick={() => setMenuOpen(false)}><div className="h-full w-[290px] border-r border-white/10 bg-[#0a1220] p-5" onClick={e => e.stopPropagation()}><div className="flex items-center justify-between"><Brand go={go} compact/><button aria-label="Close navigation" onClick={() => setMenuOpen(false)} className="text-slate-400"><X size={18}/></button></div><div className="mt-8 space-y-1">{nav.map(item => <NavButton key={item.page} item={item} active={page === item.page} go={go} />)}</div></div></div>}
        {authNotice && <div role="status" className="mx-5 mt-4 rounded-lg border border-amber-200/15 bg-amber-200/[0.04] px-3 py-2 text-[10px] text-amber-100 md:mx-8">{authNotice}</div>}
        {authUser.isDemo && <div className="mx-5 mt-3 rounded-lg border border-amber-200/15 bg-amber-200/[0.04] px-3 py-2 text-[10px] text-amber-100 md:mx-8">Local development demo session — this is not real authentication and does not secure an account.</div>}
        <main className="mx-auto max-w-[1320px] px-5 py-8 md:px-8 md:py-10">
          {page === 'dashboard' && <DashboardPage history={visibleHistory} riskCounts={riskCounts} go={go} onDetails={setSelectedHistoryItem} />}
          {page === 'scanner' && <Scanner kind="message" initialMessage={messagePrefill} onPrefillConsumed={() => setMessagePrefill('')} onSave={save} />}
          {page === 'screenshot' && <Scanner kind="screenshot" onSave={save} />}
          {page === 'url' && <Scanner kind="url" onSave={save} />}
          {page === 'history' && <HistoryPageV2 history={visibleHistory} clear={clearHistory} remove={removeHistory} onDetails={setSelectedHistoryItem} />}
          {page === 'safety' && <SafetyCenter onAnalyzeExample={analyzeExample} go={go} />}
        </main>
      </div>
    </div>}
    {selectedHistoryItem && authUser && historyOwner === storageKey && <HistoryDetails item={selectedHistoryItem} close={() => setSelectedHistoryItem(null)} />}
  </div>
}

function WorkspaceLoading() { return <main className="grid min-h-screen place-items-center bg-[#080f1b] text-slate-300"><div className="flex items-center gap-3 text-xs"><LoaderCircle size={16} className="animate-spin text-cyan-200"/>Loading your secure workspace…</div></main> }

function Brand({ go, compact = false }: { go: (page: Page) => void; compact?: boolean }) { return <button onClick={() => go('landing')} className="inline-flex items-center gap-3 text-left"><span className="grid h-10 w-10 place-items-center rounded-xl border border-cyan-300/20 bg-cyan-300/10 text-cyan-200"><Shield size={20}/></span><span className={`${compact ? 'text-base' : 'text-[16px]'} font-semibold tracking-tight text-slate-100`}>ScamShield <span className="text-cyan-200">AI</span></span></button> }
function NavButton({ item, active, go }: { item: typeof nav[number]; active: boolean; go: (page: Page) => void }) { const Icon = item.icon; return <button onClick={() => go(item.page)} className={`group flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-left text-[12px] transition ${active ? 'border border-cyan-200/10 bg-cyan-200/[0.08] text-cyan-100' : 'border border-transparent text-slate-400 hover:bg-white/[0.035] hover:text-slate-200'}`}><Icon size={16} className={active ? 'text-cyan-200' : 'text-slate-500 group-hover:text-slate-300'}/>{item.label}{active && <span className="ml-auto h-1.5 w-1.5 rounded-full bg-cyan-200"/>}</button> }

function PageTitle({ eyebrow, title, description, action }: { eyebrow: string; title: string; description: string; action?: React.ReactNode }) { return <div className="mb-8 flex flex-col justify-between gap-5 sm:flex-row sm:items-end"><div><p className="mb-2 text-[10px] font-semibold uppercase tracking-[.2em] text-cyan-200/70">{eyebrow}</p><h1 className="text-2xl font-semibold tracking-tight text-slate-100 md:text-[30px]">{title}</h1><p className="mt-2 max-w-2xl text-[13px] leading-6 text-slate-400">{description}</p></div>{action}</div> }
function Panel({ children, className = '' }: { children: React.ReactNode; className?: string }) { return <section className={`rounded-2xl border border-white/[0.075] bg-[#101a2a]/85 ${className}`}>{children}</section> }
function Label({ children, htmlFor }: { children: React.ReactNode; htmlFor: string }) { return <label htmlFor={htmlFor} className="mb-2 block text-[11px] font-medium text-slate-300">{children}</label> }
function EmptyState({ title, description, icon: Icon }: { title: string; description: string; icon: typeof Search }) { return <div className="rounded-xl border border-dashed border-white/[0.09] px-4 py-10 text-center"><span className="mx-auto grid h-10 w-10 place-items-center rounded-xl bg-white/[0.04] text-slate-500"><Icon size={18}/></span><p className="mt-3 text-xs font-medium text-slate-300">{title}</p><p className="mt-1 text-[10px] text-slate-600">{description}</p></div> }

function Scanner({ kind, onSave, initialMessage = '', onPrefillConsumed }: { kind: ScanKind; onSave: (kind: ScanKind, result: ScanResult) => void; initialMessage?: string; onPrefillConsumed?: () => void }) {
  const isScreenshot = kind === 'screenshot'; const isUrl = kind === 'url'
  const [value, setValue] = useState(initialMessage); const [result, setResult] = useState<ScanResult | null>(null); const [busy, setBusy] = useState(false); const [ocrBusy, setOcrBusy] = useState(false); const [ocrProgress, setOcrProgress] = useState<number | null>(null); const [ocrStatus, setOcrStatus] = useState(''); const [error, setError] = useState(''); const [fileName, setFileName] = useState(''); const [imagePreview, setImagePreview] = useState(''); const fileRef = useRef<HTMLInputElement>(null); const scanInProgress = useRef(false); const lastSavedSubmission = useRef('')
  useEffect(() => { if (!imagePreview) return; return () => URL.revokeObjectURL(imagePreview) }, [imagePreview])
  useEffect(() => { if (kind === 'message' && initialMessage) { setValue(initialMessage); setResult(null); setError(''); onPrefillConsumed?.() } }, [kind, initialMessage, onPrefillConsumed])
  async function runScan() {
    const content = value.trim(); if (!content || scanInProgress.current) return
    if (import.meta.env.PROD && !API_URL) {
      setError('The backend URL is missing or invalid. Set VITE_API_URL in Vercel to the Render service URL, then rebuild the frontend.')
      return
    }
    let submittedContent = content
    if (isUrl) {
      try {
        const explicitScheme = content.match(/^([a-z][a-z\d+.-]*):\/\//i)?.[1]?.toLowerCase()
        if (explicitScheme && !['http', 'https'].includes(explicitScheme)) throw new Error()
        const parsed = new URL(explicitScheme ? content : `https://${content}`)
        if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname) throw new Error()
        submittedContent = parsed.href
        setValue(submittedContent)
      } catch { setError('Enter a valid HTTP or HTTPS address, such as https://example.com.'); return }
    }
    if (lastSavedSubmission.current === submittedContent) return
    scanInProgress.current = true; setBusy(true); setError(''); setResult(null)
    try {
      const endpoint = kind === 'url' ? '/api/analyze/url' : kind === 'screenshot' ? '/api/analyze/image' : '/api/analyze/message'
      const requestBody = kind === 'url' ? { url: submittedContent } : kind === 'screenshot' ? { extracted_text: submittedContent } : { message: submittedContent }
      const response = await fetch(`${API_URL}${endpoint}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody),
      })
      if (!response.ok) {
        const payload = await response.json().catch(() => null) as { detail?: { code?: string } | string } | null
        const code = typeof payload?.detail === 'object' && payload.detail ? payload.detail.code : undefined
        if (import.meta.env.DEV) console.warn('[ScamShield] Analysis request failed', { status: response.status, code })
        const providerMessages: Record<string, string> = {
          AI_CONFIGURATION_MISSING: 'AI_API_KEY and AI_MODEL must be set in the backend environment while DEMO_MODE=false.',
          AI_RATE_LIMITED: 'The AI provider is temporarily rate limiting requests. Please retry shortly.',
          AI_QUOTA_EXCEEDED: 'The AI provider account has reached its usage limit. Check its quota or billing settings; retrying alone will not resolve this.',
          AI_AUTH_FAILED: 'The AI provider rejected its credentials. Check AI_API_KEY in the backend environment.',
          AI_MODEL_ERROR: 'The configured AI model or provider endpoint was not found. Check AI_MODEL and AI_API_BASE_URL.',
          AI_TIMEOUT: 'The AI provider timed out. Please retry shortly.',
          AI_NETWORK_ERROR: 'The backend could not reach the AI provider. Check AI_API_BASE_URL and try again.',
          AI_PROVIDER_ERROR: 'The AI provider returned an unsupported response or rejected the configuration. Check the backend provider settings.',
          AI_FALLBACK: 'AI provider temporarily unavailable — showing fallback safety analysis.',
          ai_configuration_missing: 'AI_API_KEY or AI_MODEL is missing from the backend environment. Set both on Render, or enable DEMO_MODE.',
          ai_configuration_invalid: 'AI_API_KEY must be an AI-provider credential, not a Supabase URL or key. Check the Render environment settings.',
          ai_authentication_failed: 'The AI provider rejected its credentials. Check AI_API_KEY in Render environment settings.',
          ai_model_or_endpoint_not_found: 'The AI model or endpoint was not found. Check AI_MODEL and AI_API_BASE_URL in Render.',
          ai_rate_limited: 'The AI provider is rate limiting requests. Wait briefly and try again.',
          ai_provider_timeout: 'The AI provider did not respond in time. Try again shortly.',
          ai_provider_unavailable: 'The AI provider is temporarily unavailable. Try again shortly.',
          ai_provider_unreachable: 'The backend could not reach the AI provider. Check AI_API_BASE_URL and try again.',
          ai_provider_invalid_response: 'The AI provider returned an unsupported response. Check the model and JSON response settings.',
          ai_provider_request_rejected: 'The AI provider rejected the request. Check AI_API_BASE_URL and model compatibility.',
          ai_provider_error: 'AI analysis is temporarily unavailable. Check the backend configuration or try again shortly.',
        }
        if (response.status === 400) setError('The backend rejected this request. Check the submitted content and try again.')
        else if (response.status === 401) setError('The analysis service did not authorize this request. Check the backend deployment configuration.')
        else if (response.status === 422) setError(isUrl ? 'Enter a valid HTTP or HTTPS address and try again.' : 'The submitted text could not be analyzed. Check its length and try again.')
        else if (response.status === 429) setError('Too many analysis requests were sent. Wait a moment and try again.')
        else if (response.status === 500) setError('The backend encountered an unexpected error. Try again shortly.')
        else if (response.status === 503) setError((code && providerMessages[code]) || 'AI analysis is temporarily unavailable. Check the AI configuration or try again shortly.')
        else setError('The analysis request could not be completed. Try again.')
        return
      }
      const data: ScanResult = safeResult(await response.json() as ScanResult); setResult(data); lastSavedSubmission.current = submittedContent; onSave(kind, data)
    }
    catch (error) {
      if (import.meta.env.DEV) console.warn('[ScamShield] Analysis network request failed', { errorType: error instanceof Error ? error.name : 'UnknownError' })
      setError('Could not connect to the analysis service. Check the backend URL and connection, then try again.')
    } finally { scanInProgress.current = false; setBusy(false) }
  }
  async function readImage(file?: File) {
    if (!file) return
    lastSavedSubmission.current = ''
    const validMimeTypes = ['image/png', 'image/jpeg', 'image/webp']
    const validExtension = /\.(png|jpe?g|webp)$/i.test(file.name)
    if (!validExtension || (file.type !== '' && !validMimeTypes.includes(file.type.toLowerCase()))) {
      setError('Unsupported image type. Choose a PNG, JPG, JPEG, or WEBP file.')
      setFileName(''); setImagePreview(''); setValue(''); setResult(null); setOcrStatus(''); setOcrProgress(null)
      if (fileRef.current) fileRef.current.value = ''
      return
    }
    if (file.size === 0 || file.size > 10 * 1024 * 1024) {
      setError(file.size === 0 ? 'This image file is empty. Choose another screenshot.' : 'This image is larger than 10 MB. Choose a smaller screenshot.')
      setFileName(''); setImagePreview(''); setValue(''); setResult(null); setOcrStatus(''); setOcrProgress(null)
      if (fileRef.current) fileRef.current.value = ''
      return
    }

    try {
      const decodedImage = await createImageBitmap(file)
      decodedImage.close()
    } catch {
      setError('This file could not be decoded as an image. Choose a valid PNG, JPG, JPEG, or WEBP screenshot.')
      setFileName(''); setImagePreview(''); setValue(''); setResult(null); setOcrStatus(''); setOcrProgress(null)
      if (fileRef.current) fileRef.current.value = ''
      return
    }

    setError(''); setResult(null); setValue(''); setOcrStatus('Preparing OCR…'); setOcrProgress(null)
    setFileName(file.name); setImagePreview(URL.createObjectURL(file)); setOcrBusy(true)
    let worker: Awaited<ReturnType<typeof createWorker>> | undefined
    try {
      worker = await createWorker('eng', undefined, {
        logger: message => {
          setOcrStatus(message.status === 'recognizing text' ? 'Reading text from screenshot…' : `${message.status.replace(/[_-]/g, ' ')}…`)
          if (message.status === 'recognizing text') setOcrProgress(Math.max(0, Math.min(100, Math.round(message.progress * 100))))
        },
      })
      const { data } = await worker.recognize(file)
      const extracted = data.text.trim()
      setValue(extracted); lastSavedSubmission.current = ''
      if (!extracted) { setError('No readable text was found. Try a clearer screenshot with larger text.'); setOcrStatus('OCR finished without finding text.') }
      else { setOcrProgress(100); setOcrStatus('Text extracted. Review it below, then analyze when ready.') }
    } catch {
      setError('OCR could not read this image. Check your connection and try a clearer screenshot.')
      setOcrStatus('OCR could not complete.')
    } finally {
      if (worker) { try { await worker.terminate() } catch { /* Preserve the OCR result if cleanup fails. */ } }
      setOcrBusy(false)
    }
  }
  function clearImage() {
    setImagePreview(''); setFileName(''); setValue(''); lastSavedSubmission.current = ''; setResult(null); setError(''); setOcrStatus(''); setOcrProgress(null)
    if (fileRef.current) fileRef.current.value = ''
  }
  const title = isUrl ? 'Check a suspicious link' : isScreenshot ? 'Scan a screenshot' : 'Scan a message'
  const description = isUrl ? 'Review the URL structure for warning signs. The checker does not visit or crawl the submitted address.' : isScreenshot ? 'Upload a message screenshot. OCR extracts its text for review before scanning.' : 'Paste the message as it appeared so you can review possible warning signs.'
  return <><PageTitle eyebrow={isUrl ? 'Link protection' : isScreenshot ? 'Image analysis' : 'Message protection'} title={title} description={description}/>
    <div className="grid items-start gap-5 xl:grid-cols-[minmax(0,1.25fr)_minmax(280px,.75fr)]"><Panel className="p-5 md:p-7"><div className="mb-5 flex items-center gap-3"><span className="grid h-10 w-10 place-items-center rounded-xl border border-cyan-200/10 bg-cyan-200/[0.07] text-cyan-100">{isUrl ? <Globe2 size={18}/> : isScreenshot ? <FileImage size={18}/> : <MessageSquareText size={18}/>}</span><div><h2 className="text-sm font-semibold">{isUrl ? 'Website address' : isScreenshot ? 'Screenshot upload' : 'Message content'}</h2><p className="mt-1 text-[10px] text-slate-500">{isScreenshot ? 'OCR runs in your browser. Confirm extracted text before sending it.' : 'Your scan uses the configured backend service.'}</p></div></div>
      {isScreenshot && <><input ref={fileRef} type="file" accept=".png,.jpg,.jpeg,.webp,image/png,image/jpeg,image/webp" className="hidden" onChange={e => void readImage(e.target.files?.[0])}/>{imagePreview ? <div className="mb-4 overflow-hidden rounded-xl border border-white/[0.08] bg-[#0b1321]"><div className="flex max-h-72 items-center justify-center bg-black/20 p-2"><img src={imagePreview} alt={`Preview of ${fileName}`} className="max-h-64 max-w-full rounded-lg object-contain"/></div><div className="flex items-center justify-between gap-3 border-t border-white/[0.06] px-3 py-2.5"><span className="min-w-0 truncate text-[10px] text-slate-400">{fileName}</span><button onClick={clearImage} disabled={ocrBusy} className="shrink-0 rounded-md border border-white/10 px-2.5 py-1.5 text-[9px] text-slate-400 hover:bg-white/5 disabled:opacity-50">Remove image</button></div></div> : <button onClick={() => fileRef.current?.click()} disabled={ocrBusy} className="mb-4 flex w-full flex-col items-center rounded-xl border border-dashed border-cyan-200/20 bg-cyan-200/[0.025] px-5 py-8 text-center transition hover:bg-cyan-200/[0.05] disabled:opacity-60"><span className="mb-3 grid h-11 w-11 place-items-center rounded-xl bg-cyan-200/10 text-cyan-100"><UploadCloud size={19}/></span><span className="text-xs font-medium text-slate-200">Choose a screenshot to upload</span><span className="mt-1.5 text-[10px] text-slate-500">PNG, JPG, JPEG, or WEBP · Up to 10 MB</span></button>}{ocrBusy && <div role="status" aria-live="polite" className="mb-4 rounded-lg border border-cyan-200/10 bg-cyan-200/[0.035] p-3"><div className="mb-2 flex items-center justify-between gap-3 text-[10px] text-cyan-100"><span className="flex items-center gap-2"><LoaderCircle className="animate-spin" size={13}/>{ocrStatus}</span><span>{ocrProgress === null ? 'Working' : `${ocrProgress}%`}</span></div><div className="h-1.5 overflow-hidden rounded-full bg-white/[0.06]"><div className={`h-full rounded-full bg-cyan-200 transition-all duration-300 ${ocrProgress === null ? 'w-1/3 animate-pulse' : ''}`} style={ocrProgress === null ? undefined : { width: `${ocrProgress}%` }}/></div></div>}{!ocrBusy && ocrStatus && !error && <p role="status" className="mb-4 text-[10px] text-emerald-200">{ocrStatus}</p>}</>}
      <Label htmlFor="scan-content">{isUrl ? 'Website URL' : isScreenshot ? 'Extracted text' : 'Message to check'}</Label>{isUrl ? <input id="scan-content" type="url" inputMode="url" autoComplete="url" value={value} onChange={e => { setValue(e.target.value); lastSavedSubmission.current = ''; setResult(null); setError('') }} maxLength={8192} placeholder="https://example.com/offer" className="w-full rounded-xl border border-white/[0.08] bg-[#0b1321] p-4 text-[12px] leading-6 text-slate-200 outline-none placeholder:text-slate-600 focus:border-cyan-200/30"/> : <textarea id="scan-content" value={value} onChange={e => { setValue(e.target.value); lastSavedSubmission.current = ''; setResult(null) }} rows={9} maxLength={20000} placeholder={isScreenshot ? 'Extracted screenshot text will appear here…' : 'Paste a suspicious email, text, or direct message here…'} className="w-full resize-y rounded-xl border border-white/[0.08] bg-[#0b1321] p-4 text-[12px] leading-6 text-slate-200 outline-none placeholder:text-slate-600 focus:border-cyan-200/30"/>}
      <div className="mt-2 flex items-center justify-between text-[9px] text-slate-600"><span>{isUrl ? 'Only the URL text is analyzed; the destination is never opened.' : isScreenshot ? 'Review OCR text before scanning.' : 'Scans are limited to 20,000 characters.'}</span><span>{value.length.toLocaleString()} / {isUrl ? '8,192' : '20,000'}</span></div>
      {error && <p role="alert" className={`mt-3 rounded-lg px-3 py-2 text-[11px] ${error.startsWith('Text extracted') ? 'bg-emerald-200/[0.06] text-emerald-200' : 'bg-rose-200/[0.06] text-rose-200'}`}>{error}</p>}
      <div className="mt-5 flex flex-wrap items-center justify-between gap-3"><p className="flex items-center gap-1.5 text-[10px] text-slate-500"><LockKeyhole size={12}/>{isUrl ? 'Local structural analysis only' : 'Your history stays in this browser'}</p><button onClick={() => void runScan()} disabled={!value.trim() || busy || ocrBusy} className="inline-flex items-center gap-2 rounded-lg bg-cyan-200 px-4 py-2.5 text-[11px] font-semibold text-slate-950 transition hover:bg-cyan-100 disabled:cursor-not-allowed disabled:opacity-40">{busy ? <LoaderCircle className="animate-spin" size={14}/> : <ShieldCheck size={14}/>} {busy ? 'Checking…' : isUrl ? 'Analyze URL' : isScreenshot ? 'Analyze extracted text' : 'Analyze content'} <ArrowUpRight size={13}/></button></div>
      {result && <>{isUrl && <URLResultDetails result={result}/>}<FallbackNotice result={result}/><ResultCard result={result}/></>}
    </Panel><div className="space-y-4"><Panel className="p-5"><h3 className="text-xs font-semibold">What the scan does</h3><ul className="mt-4 space-y-3 text-[10px] leading-5 text-slate-400"><li className="flex gap-2"><Check size={13} className="mt-1 shrink-0 text-cyan-200"/>{isUrl ? 'Parses the protocol, hostname, port, path, and query locally.' : 'Looks for common pressure tactics and suspicious wording.'}</li><li className="flex gap-2"><Check size={13} className="mt-1 shrink-0 text-cyan-200"/>{isUrl ? 'Uses structural heuristics and never visits or crawls the destination.' : isScreenshot ? 'Extracts text locally in your browser with Tesseract.js.' : 'Uses the configured scan API to return an assessment.'}</li><li className="flex gap-2"><Check size={13} className="mt-1 shrink-0 text-cyan-200"/>{isUrl ? 'A finding is not confirmation that a URL is malicious.' : 'Keeps a local record in this browser so you can revisit results.'}</li></ul><div className="mt-4 rounded-lg border border-amber-200/10 bg-amber-200/[0.035] p-3 text-[10px] leading-5 text-amber-100/70">{isUrl ? 'Heuristics can miss threats and can flag legitimate URL patterns.' : 'A scan is a helpful signal, not proof that a message or site is safe.'}</div></Panel><Panel className="p-5"><div className="flex items-center gap-2 text-slate-300"><CircleHelp size={15} className="text-cyan-200"/><h3 className="text-xs font-semibold">Before you submit</h3></div><p className="mt-3 text-[10px] leading-5 text-slate-500">{isUrl ? 'Do not open a suspicious link just to test it. Verify the intended site using a trusted channel.' : 'Remove passwords, verification codes, and personal details. Never open suspicious links just to test them.'}</p></Panel></div></div>
  </>
}
function URLResultDetails({ result }: { result: ScanResult }) { const severityClass: Record<string, string> = { high: 'border-rose-200/15 bg-rose-200/[0.04] text-rose-100', medium: 'border-amber-200/15 bg-amber-200/[0.04] text-amber-100', low: 'border-cyan-200/10 bg-cyan-200/[0.025] text-slate-300' }; return <div className="mt-5 space-y-3"><section className="rounded-xl border border-white/[0.08] bg-[#0b1321] p-4"><h3 className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">Parsed URL structure</h3><div className="mt-3 grid gap-3 sm:grid-cols-2"><div><p className="text-[9px] text-slate-600">Protocol</p><p className="mt-1 break-all text-[10px] text-slate-200">{result.protocol || '—'}</p></div><div><p className="text-[9px] text-slate-600">Domain</p><p className="mt-1 break-all text-[10px] text-slate-200">{result.domain || '—'}</p></div><div><p className="text-[9px] text-slate-600">Port</p><p className="mt-1 text-[10px] text-slate-200">{result.port ?? 'Not specified'}</p></div><div><p className="text-[9px] text-slate-600">Path</p><p className="mt-1 break-all text-[10px] text-slate-200">{result.path || '/'}</p></div></div>{result.query_parameters && <div className="mt-3 border-t border-white/[0.06] pt-3"><p className="text-[9px] text-slate-600">Query parameters</p>{result.query_parameters.length ? <div className="mt-1.5 space-y-1.5">{result.query_parameters.map((param,index) => <p key={`${param.key}-${index}`} className="break-all text-[10px] text-slate-300"><span className="text-cyan-100">{param.key}</span><span className="text-slate-600"> = </span>{param.value || <span className="italic text-slate-600">(empty)</span>}</p>)}</div> : <p className="mt-1.5 text-[10px] text-slate-500">None</p>}</div>}</section><section className="rounded-xl border border-white/[0.08] bg-[#0b1321] p-4"><div className="flex items-center justify-between gap-3"><h3 className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">Structural findings</h3><span className="rounded-full bg-white/[0.04] px-2 py-1 text-[9px] text-slate-500">Heuristic only</span></div><p className="mt-2 text-[10px] leading-5 text-slate-400">{result.explanation || 'The analysis checks URL structure only. It does not confirm maliciousness.'}</p>{result.findings?.length ? <div className="mt-3 space-y-2">{result.findings.map(finding => <div key={finding.code} className={`rounded-lg border p-3 ${severityClass[finding.severity] || severityClass.low}`}><div className="flex flex-wrap items-center justify-between gap-2"><h4 className="text-[10px] font-semibold">{finding.title}</h4><span className="rounded-full bg-black/15 px-2 py-0.5 text-[8px] uppercase tracking-wide">{finding.severity} signal</span></div><p className="mt-1.5 text-[10px] leading-5 opacity-80">{finding.explanation}</p><p className="mt-1 break-all font-mono text-[9px] opacity-60">Evidence: {finding.evidence}</p></div>)}</div> : <p className="mt-3 rounded-lg border border-emerald-200/10 bg-emerald-200/[0.025] p-3 text-[10px] text-emerald-100">No listed structural indicators were found. This does not prove the URL is safe.</p>}<p className="mt-3 border-t border-white/[0.06] pt-3 text-[9px] leading-4 text-amber-100/60">This is heuristic analysis, not a reputation lookup or confirmed maliciousness verdict. The submitted URL was not visited.</p></section></div> }

function ResultCard({ result }: { result: ScanResult }) {
  const tone = riskTone(result.risk_level)
  const normalizedRisk = result.risk_level.trim().toLowerCase()
  const flags = result.red_flags || result.indicators || []
  const score = result.risk_score ?? result.score ?? 0
  const headline = normalizedRisk.includes('critical') || normalizedRisk.includes('high')
    ? 'Potential warning signs found'
    : normalizedRisk.includes('medium') || normalizedRisk === 'low risk'
      ? 'Review before acting'
      : 'No strong warning signs found'
  const assessmentLabel = result.analysis_source === 'fallback'
    ? 'Fallback Risk Assessment'
    : result.assessment_type === 'heuristic'
      ? 'Heuristic Risk Assessment'
      : result.demo_mode === true
        ? 'Demo Risk Assessment'
        : 'AI Risk Assessment'

  return (
    <div className={`mt-5 rounded-xl border p-4 ${tone === 'rose' ? 'border-rose-200/15 bg-rose-200/[0.045]' : tone === 'amber' ? 'border-amber-200/15 bg-amber-200/[0.045]' : 'border-emerald-200/15 bg-emerald-200/[0.045]'}`}>
      <div className="flex flex-wrap items-center gap-2">
        <span className={tone === 'rose' ? 'text-rose-200' : tone === 'amber' ? 'text-amber-200' : 'text-emerald-200'}>
          {tone === 'rose' ? <AlertTriangle size={16}/> : <CheckCircle2 size={16}/>}
        </span>
        <h3 className="text-xs font-semibold">{headline}</h3>
        <span className="ml-auto rounded-full bg-black/20 px-2 py-1 text-[9px] text-slate-300">{assessmentLabel} · {score}/100</span>
      </div>
      {result.category && <p className="mt-2 text-[10px] font-medium text-cyan-100">{result.category}</p>}
      <p className="mt-2 text-[11px] leading-5 text-slate-300">{result.summary || result.explanation}</p>
      {flags.length > 0 && <div className="mt-3"><p className="mb-1.5 text-[9px] font-semibold uppercase tracking-wider text-slate-500">Red flags</p><div className="flex flex-wrap gap-1.5">{flags.map(item => <span key={item} className="rounded-md border border-white/[0.08] bg-black/15 px-2 py-1 text-[9px] text-slate-400">{item}</span>)}</div></div>}
      {result.evidence && result.evidence.length > 0 && <div className="mt-3 space-y-1.5">{result.evidence.map((item, index) => <blockquote key={`${item.quote}-${index}`} className="rounded-lg border-l-2 border-amber-200/30 bg-black/10 px-3 py-2 text-[10px] leading-5 text-slate-400"><span className="text-slate-200">“{item.quote}”</span> — {item.reason}</blockquote>)}</div>}
      {result.recommended_actions && <div className="mt-3"><p className="mb-1.5 text-[9px] font-semibold uppercase tracking-wider text-slate-500">Recommended next steps</p><ul className="space-y-1">{result.recommended_actions.map((item,index) => <li key={index} className="flex gap-2 text-[10px] leading-5 text-slate-400"><Check size={12} className="mt-1 shrink-0 text-cyan-200"/>{item}</li>)}</ul></div>}
      {result.safety_tips && result.safety_tips.length > 0 && <div className="mt-3 rounded-lg border border-cyan-200/[0.08] bg-cyan-200/[0.025] p-3"><p className="mb-1 text-[9px] font-semibold uppercase tracking-wider text-cyan-100/70">Safety tips</p>{result.safety_tips.map((item,index) => <p key={index} className="text-[10px] leading-5 text-slate-400">{item}</p>)}</div>}
      <p className="mt-3 text-[9px] text-slate-600">{result.analysis_source === 'fallback' ? 'Deterministic fallback · not AI-generated' : result.assessment_type === 'heuristic' ? 'Heuristic review · not a confirmed maliciousness verdict' : result.demo_mode === true ? 'Demo assessment · not an AI verdict' : 'Automated assessment'} · A score is not a probability or guarantee. Verify through a trusted channel.</p>
    </div>
  )
}

function FallbackNotice({ result }: { result: ScanResult }) {
  if (result.analysis_source !== 'fallback') return null
  const details: Record<string, string> = {
    AI_CONFIGURATION_MISSING: 'The provider configuration is incomplete.',
    AI_AUTH_FAILED: 'The provider rejected its credentials.',
    AI_MODEL_ERROR: 'The configured model or provider endpoint was unavailable.',
    AI_RATE_LIMITED: 'The provider is temporarily rate limiting requests.',
    AI_QUOTA_EXCEEDED: 'The provider account has reached its usage limit.',
    AI_TIMEOUT: 'The provider did not respond in time.',
    AI_NETWORK_ERROR: 'The backend could not reach the provider.',
    AI_PROVIDER_ERROR: 'The provider returned an unsupported response or could not complete the request.',
  }
  const detail = result.fallback_reason ? details[result.fallback_reason] || details.AI_PROVIDER_ERROR : details.AI_PROVIDER_ERROR
  return <div role="status" className="mt-5 rounded-xl border border-amber-200/15 bg-amber-200/[0.045] p-3 text-[11px] leading-5 text-amber-100">
    <p className="font-semibold">AI analysis unavailable — showing deterministic fallback assessment.</p>
    <p className="mt-1 text-amber-100/70">{detail} This result is not AI-generated.</p>
  </div>
}

function ActivityIcon({ item }: { item: HistoryItem }) { const tone = riskTone(item.result?.risk_level || 'low'); return <span className={`grid h-9 w-9 shrink-0 place-items-center rounded-xl ${tone === 'rose' ? 'bg-rose-200/10 text-rose-200' : 'bg-cyan-200/10 text-cyan-200'}`}>{item.kind === 'url' ? <Globe2 size={16}/> : item.kind === 'screenshot' ? <FileImage size={16}/> : <MessageSquareText size={16}/>}</span> }

function DashboardPage({ history, riskCounts, go, onDetails }: { history: HistoryItem[]; riskCounts: { high: number; medium: number; low: number }; go: (page: Page) => void; onDetails: (item: HistoryItem) => void }) {
  const quickScans: { kind: ScanKind; title: string; description: string; icon: typeof MessageSquareText }[] = [
    { kind: 'message', title: 'Message Scanner', description: 'Check an email, text, or DM', icon: MessageSquareText },
    { kind: 'screenshot', title: 'Screenshot Scanner', description: 'Extract and review image text', icon: FileImage },
    { kind: 'url', title: 'URL Checker', description: 'Inspect a link without opening it', icon: Globe2 },
  ]
  const destinations: Record<ScanKind, Page> = { message: 'scanner', screenshot: 'screenshot', url: 'url' }
  const stats = [
    { label: 'Total scans', value: history.length, icon: Activity, tone: 'cyan' },
    { label: 'High / Critical', value: riskCounts.high, icon: ShieldAlert, tone: 'rose' },
    { label: 'Medium risk', value: riskCounts.medium, icon: AlertTriangle, tone: 'amber' },
    { label: 'Low / Safe', value: riskCounts.low, icon: ShieldCheck, tone: 'emerald' },
  ]
  return <>
    <PageTitle eyebrow="Your workspace" title="Security overview" description="Start a scan or review the results saved in this browser." action={<button onClick={() => go('history')} className="inline-flex items-center gap-2 rounded-lg border border-white/10 px-3 py-2 text-[10px] text-slate-300 hover:bg-white/5"><History size={14}/>Scan history</button>} />
    <section aria-labelledby="quick-scan-title" className="mb-7">
      <div className="mb-3"><h2 id="quick-scan-title" className="text-sm font-semibold">Quick Scan</h2><p className="mt-1 text-[10px] text-slate-500">Choose what you want to check.</p></div>
      <div className="grid gap-3 sm:grid-cols-3">{quickScans.map(({ kind, title, description, icon: Icon }) => <button key={kind} onClick={() => go(destinations[kind])} className="group flex min-w-0 items-center gap-3 rounded-2xl border border-white/[0.075] bg-[#101a2a]/85 p-4 text-left transition hover:border-cyan-200/20 hover:bg-cyan-200/[0.035] sm:flex-col sm:items-start sm:p-5"><span className="grid h-10 w-10 shrink-0 place-items-center rounded-xl border border-cyan-200/10 bg-cyan-200/[0.06] text-cyan-100"><Icon size={18}/></span><span className="min-w-0 flex-1"><span className="block text-xs font-semibold text-slate-100">{title}</span><span className="mt-1 block text-[10px] leading-5 text-slate-500">{description}</span></span><ArrowRight size={15} className="shrink-0 text-slate-600 transition group-hover:translate-x-0.5 group-hover:text-cyan-100 sm:mt-2"/></button>)}</div>
    </section>
    <section aria-labelledby="security-overview-title" className="mb-7">
      <div className="mb-3"><h2 id="security-overview-title" className="text-sm font-semibold">Security Overview</h2><p className="mt-1 text-[10px] text-slate-500">Counts are based on scans saved locally.</p></div>
      <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">{stats.map(({ label, value, icon: Icon, tone }) => <Panel key={label} className="min-w-0 p-4 sm:p-5"><div className="flex items-start justify-between gap-2"><div><p className="text-[10px] leading-4 text-slate-400 sm:text-[11px]">{label}</p><p className="mt-2 text-2xl font-semibold tabular-nums text-slate-100">{value}</p></div><span className={`grid h-8 w-8 shrink-0 place-items-center rounded-lg ${tone === 'rose' ? 'bg-rose-300/10 text-rose-200' : tone === 'amber' ? 'bg-amber-200/10 text-amber-200' : tone === 'emerald' ? 'bg-emerald-200/10 text-emerald-200' : 'bg-cyan-200/10 text-cyan-200'}`}><Icon size={15}/></span></div></Panel>)}</div>
    </section>
    <Panel className="overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.06] px-4 py-4 sm:px-5"><div><h2 className="text-sm font-semibold">Recent Scans</h2><p className="mt-1 text-[10px] text-slate-500">Latest completed analyses from this browser.</p></div><button onClick={() => go('history')} className="text-[10px] text-cyan-200 hover:text-cyan-100">View all <ArrowRight size={12} className="ml-1 inline"/></button></div>
      {history.length === 0 ? <div className="p-4 sm:p-5"><EmptyState title="No scans yet" description="Completed message, screenshot, and URL analyses will appear here." icon={Search}/></div> : <div className="divide-y divide-white/[0.05]">{history.slice(0, 5).map(item => {
        const tone = riskTone(item.riskLevel)
        return <button key={item.id} onClick={() => onDetails(item)} className="flex w-full min-w-0 items-center gap-3 px-4 py-3 text-left transition hover:bg-white/[0.025] sm:px-5"><ActivityIcon item={item}/><span className="min-w-0 flex-1"><span className="flex flex-wrap items-center gap-x-2 gap-y-1"><span className="text-[11px] font-medium text-slate-200">{kindLabel(item.kind)} scan</span><span className="text-[9px] text-slate-600">{formatDate(item.createdAt)}</span></span><span className="mt-1 block truncate text-[10px] text-slate-500">{item.category} · {item.summary}</span></span><span className="flex shrink-0 flex-col items-end gap-1"><span className={`rounded-full px-2 py-1 text-[9px] ${tone === 'rose' ? 'bg-rose-300/[0.08] text-rose-200' : tone === 'amber' ? 'bg-amber-200/[0.08] text-amber-200' : 'bg-emerald-200/[0.08] text-emerald-200'}`}>{item.riskLevel}</span><span className="text-[9px] tabular-nums text-slate-500">{item.riskScore}/100</span></span></button>
      })}</div>}
    </Panel>
    <Panel className="mt-5 flex flex-col gap-4 p-5 sm:flex-row sm:items-center sm:justify-between"><div className="flex min-w-0 items-start gap-3"><span className="grid h-9 w-9 shrink-0 place-items-center rounded-xl bg-cyan-200/10 text-cyan-100"><ShieldCheck size={16}/></span><div><h2 className="text-xs font-semibold">Safety Center</h2><p className="mt-1 text-[10px] leading-5 text-slate-500">Learn how to recognize scams and protect your digital identity.</p></div></div><button onClick={() => go('safety')} className="inline-flex shrink-0 items-center gap-2 self-start rounded-lg border border-white/10 px-3 py-2 text-[10px] text-slate-300 transition hover:border-cyan-200/20 hover:bg-white/[0.03] sm:self-auto">Explore safety guidance <ArrowRight size={13}/></button></Panel>
  </>
}

function HistoryPageV2({ history, clear, remove, onDetails }: { history: HistoryItem[]; clear: () => void; remove: (id: string) => void; onDetails: (item: HistoryItem) => void }) {
  const [filter, setFilter] = useState<'all' | ScanKind>('all')
  const [confirmClear, setConfirmClear] = useState(false)
  const filtered = useMemo(() => history.filter(item => filter === 'all' || item.kind === filter), [history, filter])
  const filters: { value: 'all' | ScanKind; label: string }[] = [{ value: 'all', label: 'All' }, { value: 'message', label: 'Messages' }, { value: 'screenshot', label: 'Screenshots' }, { value: 'url', label: 'URLs' }]
  const clearAll = () => { if (history.length) setConfirmClear(true) }
  return <>
    <PageTitle eyebrow="Your activity" title="Scan History" description="Review saved analysis details. Only scan metadata and a sanitized result are stored on this device." action={<button onClick={clearAll} disabled={!history.length} className="inline-flex items-center gap-2 rounded-lg border border-rose-200/15 px-3 py-2 text-[10px] text-rose-200 hover:bg-rose-200/[0.05] disabled:cursor-not-allowed disabled:opacity-40"><Trash2 size={13}/>Clear All History</button>} />
    <Panel className="overflow-hidden">
      <div className="flex flex-col gap-3 border-b border-white/[0.06] p-4 sm:flex-row sm:items-center sm:justify-between sm:px-5"><p className="text-[11px] text-slate-400">{filtered.length} {filtered.length === 1 ? 'record' : 'records'}</p><div className="flex flex-wrap gap-1 rounded-lg bg-black/20 p-1">{filters.map(({ value, label }) => <button key={value} onClick={() => setFilter(value)} aria-pressed={filter === value} className={`rounded-md px-2.5 py-1.5 text-[9px] ${filter === value ? 'bg-white/[0.08] text-slate-100' : 'text-slate-500 hover:text-slate-300'}`}>{label}</button>)}</div></div>
      {filtered.length === 0 ? <div className="p-4 sm:p-5"><EmptyState title={history.length ? 'No scans in this category' : 'Your history is empty'} description={history.length ? 'Choose another filter to see saved analyses.' : 'Completed scans will appear here. Your messages and screenshots are not stored.'} icon={History}/></div> : <>
        <div className="space-y-3 p-3 sm:p-4 md:hidden">{filtered.map(item => <HistoryCard key={item.id} item={item} onDetails={onDetails} onRemove={remove}/>)}</div>
        <div className="hidden md:block"><table className="w-full table-fixed text-left"><thead className="bg-white/[0.02] text-[9px] uppercase tracking-wider text-slate-500"><tr><th className="w-[12%] px-3 py-3">Scan type</th><th className="w-[17%] px-2 py-3">Date / time</th><th className="w-[10%] px-2 py-3">Risk</th><th className="w-[7%] px-2 py-3">Score</th><th className="w-[14%] px-2 py-3">Category</th><th className="w-[25%] px-2 py-3">Summary</th><th className="w-[15%] px-2 py-3">Actions</th></tr></thead><tbody className="divide-y divide-white/[0.05]">{filtered.map(item => <tr key={item.id} className="align-middle"><td className="px-3 py-3 text-[10px] text-slate-200">{kindLabel(item.kind)}</td><td className="px-2 py-3 text-[9px] text-slate-500">{formatDate(item.createdAt)}</td><td className="px-2 py-3"><RiskBadge risk={item.riskLevel}/></td><td className="px-2 py-3 text-[10px] tabular-nums text-slate-300">{item.riskScore}</td><td className="truncate px-2 py-3 text-[10px] text-slate-400" title={item.category}>{item.category}</td><td className="truncate px-2 py-3 text-[10px] text-slate-500" title={item.summary}>{item.summary}</td><td className="px-2 py-3"><HistoryActions item={item} onDetails={onDetails} onRemove={remove}/></td></tr>)}</tbody></table></div>
      </>}
    </Panel>
    <p className="mt-3 text-[9px] leading-5 text-slate-600">History is stored in localStorage in this browser. Passwords, codes, full message text, and uploaded images are not saved.</p>
    {confirmClear && <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm" onMouseDown={() => setConfirmClear(false)}><section role="alertdialog" aria-modal="true" aria-labelledby="clear-history-title" onMouseDown={event => event.stopPropagation()} className="w-full max-w-md rounded-2xl border border-white/10 bg-[#0c1524] p-5 shadow-2xl"><span className="grid h-9 w-9 place-items-center rounded-xl bg-rose-200/10 text-rose-200"><Trash2 size={16}/></span><h2 id="clear-history-title" className="mt-4 text-sm font-semibold text-slate-100">Clear all scan history?</h2><p className="mt-2 text-[11px] leading-5 text-slate-400">This removes {history.length} saved {history.length === 1 ? 'record' : 'records'} from this browser. This cannot be undone.</p><div className="mt-5 flex justify-end gap-2"><button onClick={() => setConfirmClear(false)} className="rounded-lg border border-white/10 px-3 py-2 text-[10px] text-slate-300 hover:bg-white/5">Cancel</button><button onClick={() => { clear(); setConfirmClear(false) }} className="rounded-lg bg-rose-300 px-3 py-2 text-[10px] font-semibold text-slate-950 hover:bg-rose-200">Clear all</button></div></section></div>}
  </>
}

function RiskBadge({ risk }: { risk: string }) { const tone = riskTone(risk); return <span className={`inline-flex rounded-full px-2 py-1 text-[9px] capitalize ${tone === 'rose' ? 'bg-rose-200/[0.08] text-rose-200' : tone === 'amber' ? 'bg-amber-200/[0.08] text-amber-200' : 'bg-emerald-200/[0.08] text-emerald-200'}`}>{risk}</span> }
function HistoryActions({ item, onDetails, onRemove }: { item: HistoryItem; onDetails: (item: HistoryItem) => void; onRemove: (id: string) => void }) { return <div className="flex items-center gap-1"><button onClick={() => onDetails(item)} className="inline-flex items-center gap-1 rounded-md px-2 py-1.5 text-[9px] text-cyan-200 hover:bg-cyan-200/[0.06]" aria-label={`View details for ${kindLabel(item.kind)} scan`}><Eye size={12}/>View details</button><button onClick={() => onRemove(item.id)} className="rounded-md p-1.5 text-slate-500 hover:bg-rose-200/[0.06] hover:text-rose-200" aria-label={`Delete ${kindLabel(item.kind)} scan`}><Trash2 size={13}/></button></div> }
function HistoryCard({ item, onDetails, onRemove }: { item: HistoryItem; onDetails: (item: HistoryItem) => void; onRemove: (id: string) => void }) { return <article className="rounded-xl border border-white/[0.07] bg-[#0b1321]/80 p-3.5"><div className="flex items-start gap-3"><ActivityIcon item={item}/><div className="min-w-0 flex-1"><div className="flex flex-wrap items-center justify-between gap-2"><p className="text-[11px] font-medium text-slate-200">{kindLabel(item.kind)} scan</p><RiskBadge risk={item.riskLevel}/></div><p className="mt-1 text-[9px] text-slate-500">{formatDate(item.createdAt)}</p><p className="mt-3 text-[9px] uppercase tracking-wide text-slate-600">Score · Category</p><p className="mt-1 text-[10px] text-slate-300">{item.riskScore}/100 · {item.category}</p><p className="mt-2 break-words text-[10px] leading-5 text-slate-500">{item.summary}</p></div></div><div className="mt-3 flex justify-end border-t border-white/[0.05] pt-2"><HistoryActions item={item} onDetails={onDetails} onRemove={onRemove}/></div></article> }

function HistoryDetails({ item, close }: { item: HistoryItem; close: () => void }) {
  useEffect(() => { const onKey = (event: KeyboardEvent) => { if (event.key === 'Escape') close() }; window.addEventListener('keydown', onKey); return () => window.removeEventListener('keydown', onKey) }, [close])
  return <div className="fixed inset-0 z-50 flex items-end justify-center bg-black/70 p-0 backdrop-blur-sm sm:items-center sm:p-5" onMouseDown={close}><section role="dialog" aria-modal="true" aria-labelledby="history-detail-title" onMouseDown={event => event.stopPropagation()} className="max-h-[92vh] w-full max-w-3xl overflow-y-auto rounded-t-2xl border border-white/10 bg-[#0c1524] p-4 shadow-2xl sm:rounded-2xl sm:p-6"><div className="flex items-start gap-3"><div className="min-w-0 flex-1"><p className="text-[9px] font-semibold uppercase tracking-[.18em] text-cyan-200/70">Saved scan details</p><h2 id="history-detail-title" className="mt-1 text-lg font-semibold">{kindLabel(item.kind)} analysis</h2><p className="mt-1 text-[10px] text-slate-500">{formatDate(item.createdAt)}</p></div><button onClick={close} aria-label="Close scan details" className="rounded-lg border border-white/10 p-2 text-slate-400 hover:bg-white/5"><X size={15}/></button></div><div className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-4"><DetailStat label="Risk level"><RiskBadge risk={item.riskLevel}/></DetailStat><DetailStat label="Risk score">{item.riskScore}/100</DetailStat><DetailStat label="Category">{item.category}</DetailStat><DetailStat label="Scan type">{kindLabel(item.kind)}</DetailStat></div><div className="mt-3 rounded-xl border border-white/[0.07] bg-white/[0.02] p-3"><p className="text-[9px] uppercase tracking-wide text-slate-500">Summary</p><p className="mt-1 break-words text-[11px] leading-5 text-slate-300">{item.summary}</p></div>{item.kind === 'url' && <URLResultDetails result={item.result}/>}<ResultCard result={item.result}/></section></div>
}
function DetailStat({ label, children }: { label: string; children: React.ReactNode }) { return <div className="min-w-0 rounded-lg border border-white/[0.06] bg-white/[0.02] p-2.5"><p className="text-[8px] uppercase tracking-wide text-slate-600">{label}</p><div className="mt-1 break-words text-[10px] text-slate-200">{children}</div></div> }

function SafetySectionHeading({ eyebrow, title, description }: { eyebrow: string; title: string; description: string }) {
  return <div className="mb-4"><p className="text-[9px] font-semibold uppercase tracking-[.18em] text-cyan-200/65">{eyebrow}</p><h2 className="mt-1.5 text-base font-semibold tracking-tight text-slate-100">{title}</h2><p className="mt-1.5 max-w-2xl text-[11px] leading-5 text-slate-500">{description}</p></div>
}

function SafetyCenter({ onAnalyzeExample, go }: { onAnalyzeExample: (example: string) => void; go: (page: Page) => void }) {
  const neverShare = [
    { title: 'OTP', subtitle: 'One-time passcode', icon: LockKeyhole, body: 'A one-time code can approve sign-in, a payment, or a password reset. Never read it to someone who contacted you unexpectedly.' },
    { title: 'Password', subtitle: 'Account sign-in', icon: Shield, body: 'A password gives access to your account. Support staff should not need your password to help you.' },
    { title: 'PIN', subtitle: 'Personal identification number', icon: ShieldAlert, body: 'A PIN can authorize access or transactions. Keep it private, including from callers claiming to be support.' },
    { title: 'CVV', subtitle: 'Card security code', icon: LockKeyhole, body: 'The CVV helps authorize card payments. Do not share it in response to unexpected calls, texts, or emails.' },
    { title: 'Banking credentials', subtitle: 'Online banking access', icon: ShieldCheck, body: 'Online banking credentials can expose accounts and funds. Verify requests directly with your bank using a trusted channel.' },
    { title: 'Recovery codes', subtitle: 'Account recovery', icon: History, body: 'Recovery codes can bypass sign-in protections. Store them securely and never hand them to an unsolicited contact.' },
  ]
  const warningSigns = [
    { title: 'Unexpected urgency', icon: Clock3, body: '“Act now” pressure is meant to make you skip careful checks.' },
    { title: 'Threats or account suspension', icon: ShieldAlert, body: 'Threats of arrest, penalties, or account closure are common pressure tactics.' },
    { title: 'Requests for money', icon: Activity, body: 'Be cautious of gift cards, crypto, wire transfers, or “safe account” transfers.' },
    { title: 'Requests for OTP, password, or PIN', icon: LockKeyhole, body: 'A caller or message asking for sign-in secrets may be trying to take over an account.' },
    { title: 'Suspicious links', icon: Link2, body: 'Unexpected links can lead to lookalike pages or unwanted downloads.' },
    { title: 'Fake customer support', icon: CircleHelp, body: 'Impersonators may ask for remote access, payment, or verification codes.' },
    { title: 'Too-good-to-be-true offers', icon: Sparkles, body: 'Guaranteed returns and unusually large discounts deserve independent checks.' },
    { title: 'Unexpected job offers', icon: MessageSquareText, body: 'Be wary of instant offers, upfront fees, or requests to buy equipment with unusual payment methods.' },
    { title: 'Prize or lottery claims', icon: BadgeCheck, body: 'A surprise prize that requires a fee or sensitive information is a warning sign.' },
    { title: 'Impersonation of trusted organizations', icon: Shield, body: 'Logos and caller names can be copied. Check the actual address and contact the organization yourself.' },
  ]
  const responseSteps = [
    'Stop and don’t respond immediately.',
    'Don’t click suspicious links.',
    'Don’t send money or sensitive information.',
    'Verify the request through an independently verified official channel.',
    'Secure your account if credentials may have been exposed.',
    'Contact the relevant service or provider, or appropriate authorities, if necessary.',
  ]
  const examples = [
    { label: 'Banking / phishing', icon: ShieldAlert, message: 'URGENT: Your account will be suspended today. Click here to verify immediately.', why: 'It threatens account suspension and pushes you to click without time to verify. Check through your bank’s official app or a number you already trust.' },
    { label: 'Fake job offer', icon: MessageSquareText, message: 'You’re hired for a remote role! Pay a refundable onboarding fee by gift card today to secure your offer.', why: 'An upfront fee, gift card payment, and pressure to act are warning signs. Research the employer and confirm through its independently found careers site.' },
    { label: 'Prize / lottery scam', icon: BadgeCheck, message: 'You won our $10,000 lottery! Send your one-time code and a small release fee by midnight to claim.', why: 'Unexpected prizes that require a code or payment are suspicious. Never share a sign-in code to claim a prize.' },
  ]
  const checklistItems = [
    { id: 'unexpected', text: 'Did I receive this message unexpectedly?' },
    { id: 'urgency', text: 'Is the sender creating urgency?' },
    { id: 'sensitive', text: 'Are they asking for sensitive information?' },
    { id: 'money', text: 'Are they asking for money?' },
    { id: 'link', text: 'Is there a suspicious link?' },
    { id: 'verify', text: 'Can I independently verify the sender?' },
  ]
  const [checkedItems, setCheckedItems] = useState<string[]>(() => {
    try {
      const stored = JSON.parse(localStorage.getItem(SAFETY_CHECKLIST_KEY) || '[]')
      return Array.isArray(stored) ? stored.filter((item): item is string => checklistItems.some(check => check.id === item)) : []
    } catch { return [] }
  })
  const completeCount = checkedItems.length
  const completion = Math.round((completeCount / checklistItems.length) * 100)
  function toggleChecklist(id: string) {
    const next = checkedItems.includes(id) ? checkedItems.filter(item => item !== id) : [...checkedItems, id]
    setCheckedItems(next)
    try { localStorage.setItem(SAFETY_CHECKLIST_KEY, JSON.stringify(next)) } catch { /* Checklist remains usable for this page session. */ }
  }

  return <>
    <PageTitle eyebrow="Knowledge & prevention" title="Safety Center" description="Learn how to recognize scams and protect your digital identity." />
    <Panel className="mb-7 overflow-hidden p-5 sm:p-6 md:p-7">
      <div className="flex flex-col gap-5 sm:flex-row sm:items-center sm:justify-between">
        <div className="max-w-3xl"><div className="mb-3 inline-flex items-center gap-2 rounded-full border border-cyan-200/10 bg-cyan-200/[0.04] px-3 py-1.5 text-[9px] text-cyan-100"><ShieldCheck size={12}/>Practical guidance for everyday decisions</div><h2 className="text-xl font-semibold tracking-tight sm:text-2xl">Pause. Check. Protect.</h2><p className="mt-2 text-[11px] leading-5 text-slate-400">Small verification steps can interrupt common scam tactics. ScamShield AI is an informational tool, not a government, bank, police, or cybersecurity authority.</p></div>
        <button onClick={() => go('scanner')} className="inline-flex shrink-0 items-center justify-center gap-2 self-start rounded-lg bg-cyan-200 px-3.5 py-2.5 text-[10px] font-semibold text-slate-950 transition hover:bg-cyan-100 sm:self-center"><MessageSquareText size={14}/>Check a message</button>
      </div>
    </Panel>

    <section aria-labelledby="never-share-title" className="mb-8">
      <SafetySectionHeading eyebrow="Protect your information" title="Never Share" description="Keep these details private. Do not disclose them to someone who contacts you unexpectedly, even if they claim to represent a familiar organization." />
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">{neverShare.map(({ title, subtitle, icon: Icon, body }) => <Panel key={title} className="flex min-w-0 gap-3 p-4 transition-colors duration-200 hover:border-rose-200/15"><span className="grid h-9 w-9 shrink-0 place-items-center rounded-xl border border-rose-200/10 bg-rose-200/[0.045] text-rose-200"><Icon size={16}/></span><div className="min-w-0"><div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5"><h3 className="text-[11px] font-semibold text-slate-100">{title}</h3><span className="text-[9px] text-slate-600">{subtitle}</span></div><p className="mt-2 text-[10px] leading-5 text-slate-500">{body}</p></div></Panel>)}</div>
    </section>

    <section aria-labelledby="warning-signs-title" className="mb-8">
      <SafetySectionHeading eyebrow="Recognize common tactics" title="Common Scam Warning Signs" description="One sign alone does not prove a scam. Several signals together are a reason to slow down and verify." />
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">{warningSigns.map(({ title, icon: Icon, body }) => <Panel key={title} className="flex min-w-0 items-start gap-3 p-4 transition-colors duration-200 hover:border-amber-200/15"><span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-amber-200/[0.07] text-amber-200"><Icon size={15}/></span><div className="min-w-0"><h3 className="text-[10px] font-semibold text-slate-200">{title}</h3><p className="mt-1.5 text-[10px] leading-5 text-slate-500">{body}</p></div></Panel>)}</div>
    </section>

    <section aria-labelledby="suspect-scam-title" className="mb-8">
      <SafetySectionHeading eyebrow="Take a breath and protect yourself" title="What to Do If You Suspect a Scam" description="Use these steps to avoid pressure and regain control of the conversation." />
      <Panel className="p-4 sm:p-5"><ol className="grid gap-2.5 md:grid-cols-2">{responseSteps.map((step, index) => <li key={step} className="flex min-w-0 items-start gap-3 rounded-xl border border-white/[0.05] bg-white/[0.015] p-3"><span className="grid h-7 w-7 shrink-0 place-items-center rounded-lg border border-cyan-200/10 bg-cyan-200/[0.04] text-[10px] font-semibold text-cyan-100">{index + 1}</span><span className="pt-1 text-[10px] leading-5 text-slate-300">{step}</span></li>)}</ol></Panel>
    </section>

    <section aria-labelledby="demo-examples-title" className="mb-8">
      <SafetySectionHeading eyebrow="Learn with examples" title="Demo Scam Examples" description="These are fictional messages created for education. They do not refer to real organizations, offers, or incidents." />
      <div className="grid gap-3 lg:grid-cols-3">{examples.map(({ label, icon: Icon, message, why }) => <Panel key={label} className="flex min-w-0 flex-col p-4 sm:p-5"><div className="flex items-center gap-2"><span className="grid h-8 w-8 place-items-center rounded-lg bg-cyan-200/[0.06] text-cyan-100"><Icon size={15}/></span><div><p className="text-[10px] font-semibold text-slate-200">{label}</p><p className="text-[8px] uppercase tracking-wide text-slate-600">Fictional example</p></div></div><blockquote className="mt-4 rounded-lg border-l-2 border-amber-200/30 bg-black/15 px-3 py-3 text-[10px] leading-5 text-slate-300">“{message}”</blockquote><div className="mt-3 flex-1"><p className="text-[9px] font-semibold uppercase tracking-wide text-slate-600">Why it raises concern</p><p className="mt-1 text-[10px] leading-5 text-slate-500">{why}</p></div><button onClick={() => onAnalyzeExample(message)} className="mt-4 inline-flex items-center justify-center gap-2 self-start rounded-lg border border-cyan-200/15 px-3 py-2 text-[9px] font-medium text-cyan-100 transition hover:bg-cyan-200/[0.05]">Analyze This Example <ArrowRight size={12}/></button></Panel>)}</div>
    </section>

    <section aria-labelledby="checklist-title" className="mb-8">
      <SafetySectionHeading eyebrow="Before you act" title="Quick Safety Checklist" description="Use these questions to pause and assess the situation. Your selections stay in this browser." />
      <Panel className="grid gap-5 p-4 sm:p-5 md:grid-cols-[minmax(0,1fr)_220px] md:items-center">
        <div className="space-y-1">{checklistItems.map(({ id, text }) => <label key={id} className="flex cursor-pointer items-start gap-3 rounded-lg px-2.5 py-2.5 transition-colors hover:bg-white/[0.025]"><input type="checkbox" checked={checkedItems.includes(id)} onChange={() => toggleChecklist(id)} className="mt-0.5 h-4 w-4 shrink-0 accent-cyan-200"/><span className="text-[10px] leading-5 text-slate-300">{text}</span></label>)}</div>
        <div className="rounded-xl border border-white/[0.06] bg-black/10 p-4"><div className="flex items-end justify-between gap-2"><div><p className="text-[9px] font-semibold uppercase tracking-wide text-slate-500">Checklist progress</p><p className="mt-1 text-xl font-semibold tabular-nums text-slate-100">{completion}%</p></div><span className="text-[9px] text-slate-500">{completeCount} of {checklistItems.length}</span></div><div role="progressbar" aria-label="Checklist completion" aria-valuemin={0} aria-valuemax={checklistItems.length} aria-valuenow={completeCount} className="mt-3 h-2 overflow-hidden rounded-full bg-white/[0.07]"><div className="h-full rounded-full bg-gradient-to-r from-cyan-200 to-blue-300 transition-[width] duration-300" style={{ width: completion + '%' }}/></div><p className="mt-3 text-[9px] leading-4 text-slate-600">{completeCount === checklistItems.length ? 'You checked every item. Continue to verify through trusted channels.' : 'Check each question that applies. A completed checklist does not guarantee a message is safe.'}</p></div>
      </Panel>
    </section>

    <Panel className="border-amber-200/10 bg-amber-200/[0.025] p-4 sm:p-5"><div className="flex items-start gap-3"><span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-amber-200/10 text-amber-200"><AlertTriangle size={15}/></span><div><h2 className="text-[10px] font-semibold uppercase tracking-wide text-amber-100">Important Disclaimer</h2><p className="mt-2 text-[10px] leading-5 text-slate-400">ScamShield AI provides automated security guidance and heuristic analysis. It cannot guarantee that a message or URL is safe or malicious. When in doubt, verify through an official channel.</p></div></div></Panel>
  </>
}

function Landing({ go, signedIn, user, onSignOut }: { go: (page: Page) => void; signedIn: boolean; user: AppUser | null; onSignOut: () => void }) {
  const primaryPage: Page = signedIn ? 'dashboard' : 'signup'
  return <div className="min-h-screen overflow-hidden">
    <header className="relative z-10 mx-auto flex max-w-7xl items-center justify-between gap-4 px-5 py-5 md:px-10">
      <Brand go={go}/>
      <nav className="hidden items-center gap-6 md:flex">
        <a href="#how" className="text-xs text-slate-400 hover:text-slate-200">How it works</a>
        <button onClick={() => go('safety')} className="text-xs text-slate-400 hover:text-slate-200">Safety center</button>
        {signedIn ? <><span className="max-w-36 truncate text-[10px] text-slate-500">{user?.displayName}</span><button onClick={() => go('dashboard')} className="rounded-lg border border-white/10 px-3.5 py-2 text-xs text-slate-200 hover:bg-white/5">Open dashboard <ArrowUpRight size={13} className="ml-1 inline"/></button><button onClick={onSignOut} className="rounded-lg border border-white/10 p-2 text-slate-400 hover:bg-white/5" aria-label="Sign out"><LogOut size={14}/></button></> : <><button onClick={() => go('login')} className="text-xs text-slate-300 hover:text-cyan-100">Sign In</button><button onClick={() => go('signup')} className="rounded-lg bg-cyan-200 px-3.5 py-2 text-xs font-semibold text-slate-950 hover:bg-cyan-100">Get Started</button></>}
      </nav>
      <div className="flex items-center gap-2 md:hidden">{signedIn ? <><button onClick={() => go('dashboard')} className="rounded-lg border border-white/10 px-3 py-2 text-[10px] text-slate-200">Dashboard</button><button onClick={onSignOut} className="rounded-lg border border-white/10 p-2 text-slate-400" aria-label="Sign out"><LogOut size={14}/></button></> : <><button onClick={() => go('login')} className="rounded-lg border border-white/10 px-3 py-2 text-[10px] text-slate-200">Sign In</button><button onClick={() => go('signup')} className="rounded-lg bg-cyan-200 px-3 py-2 text-[10px] font-semibold text-slate-950">Get Started</button></>}</div>
    </header>
    <main>
      <section className="relative mx-auto max-w-7xl px-5 pb-16 pt-14 md:px-10 md:pb-24 md:pt-24">
        <div aria-hidden="true" className="pointer-events-none absolute -right-40 top-0 h-[520px] w-[520px] rounded-full bg-blue-500/[0.07] blur-[120px]"/>
        <div className="relative grid items-center gap-12 lg:grid-cols-[1.1fr_.9fr]">
          <div>
            <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-cyan-200/15 bg-cyan-200/[0.05] px-3 py-1.5 text-[10px] font-medium text-cyan-100"><span className="h-1.5 w-1.5 rounded-full bg-cyan-200"/>A calmer way to check the unexpected</div>
            <h1 className="max-w-2xl text-[42px] font-semibold leading-[1.08] tracking-[-.045em] text-slate-100 sm:text-5xl md:text-[62px]">Before you click,<br/>take a <span className="bg-gradient-to-r from-cyan-100 to-blue-300 bg-clip-text text-transparent">second look.</span></h1>
            <p className="mt-6 max-w-lg text-[13px] leading-7 text-slate-400 md:text-[14px]">Check suspicious messages, screenshots, and links for common warning signs. Make a more informed decision before you act.</p>
            <div className="mt-8 flex flex-wrap items-center gap-3"><button onClick={() => go(primaryPage)} className="rounded-xl bg-cyan-200 px-5 py-3 text-xs font-semibold text-slate-950 shadow-[0_8px_30px_rgba(103,232,249,.12)] transition hover:-translate-y-0.5 hover:bg-cyan-100">{signedIn ? 'Open your workspace' : 'Get Started'} <ArrowRight size={14} className="ml-2 inline"/></button><a href="#how" className="rounded-xl border border-white/[0.09] px-5 py-3 text-xs text-slate-300 hover:bg-white/[0.04]">See how it works</a></div>
            <div className="mt-7 flex flex-wrap items-center gap-x-5 gap-y-2 text-[10px] text-slate-500"><span className="inline-flex items-center gap-1.5"><LockKeyhole size={12} className="text-cyan-200/70"/>History separated by account</span><span className="inline-flex items-center gap-1.5"><CheckCircle2 size={12} className="text-cyan-200/70"/>Sign in to open your workspace</span></div>
          </div>
          <div className="relative mx-auto w-full max-w-[440px]"><div aria-hidden="true" className="absolute inset-8 rounded-full bg-cyan-200/[0.04] blur-3xl"/><div className="relative rounded-[26px] border border-white/[0.09] bg-[#0e192a]/90 p-5 shadow-2xl shadow-black/30 backdrop-blur md:p-6"><div className="mb-6 flex items-center justify-between"><div><div className="text-[11px] font-semibold">Quick safety check</div><div className="mt-1 text-[9px] text-slate-500">Your personal scan workspace</div></div><span className="grid h-9 w-9 place-items-center rounded-xl border border-cyan-200/10 bg-cyan-200/[0.06] text-cyan-100"><ShieldCheck size={17}/></span></div><div className="space-y-2.5">{[{ label: 'Message scanner', text: 'Check an email, text, or DM', icon: MessageSquareText, page: 'scanner' as Page },{ label: 'Screenshot scanner', text: 'Extract text from an image', icon: FileImage, page: 'screenshot' as Page },{ label: 'URL checker', text: 'Review an unexpected link', icon: Globe2, page: 'url' as Page }].map(({ label,text,icon:Icon,page }) => <button key={page} onClick={() => go(page)} className="flex w-full items-center gap-3 rounded-xl border border-white/[0.06] bg-white/[0.018] p-3.5 text-left transition hover:border-cyan-200/15 hover:bg-cyan-200/[0.035]"><span className="grid h-9 w-9 place-items-center rounded-lg bg-cyan-200/[0.07] text-cyan-100"><Icon size={16}/></span><span className="flex-1"><span className="block text-[11px] font-medium text-slate-200">{label}</span><span className="mt-1 block text-[9px] text-slate-500">{text}</span></span><ArrowUpRight size={14} className="text-slate-600"/></button>)}</div><div className="mt-5 flex items-start gap-2 rounded-xl border border-amber-200/[0.09] bg-amber-200/[0.025] p-3 text-[9px] leading-5 text-slate-400"><AlertTriangle size={13} className="mt-0.5 shrink-0 text-amber-200"/>Automated scans can miss scams. Verify unexpected requests independently.</div></div><div className="absolute -bottom-5 -left-4 hidden items-center gap-2 rounded-xl border border-white/[0.09] bg-[#111d2f] px-3 py-2.5 shadow-lg sm:flex"><span className="grid h-7 w-7 place-items-center rounded-lg bg-emerald-200/10 text-emerald-200"><CheckCircle2 size={14}/></span><span><span className="block text-[9px] font-medium">Your history</span><span className="block text-[8px] text-slate-500">Scoped on this browser</span></span></div></div>
        </div>
      </section>
      <section id="how" className="border-y border-white/[0.055] bg-white/[0.012]"><div className="mx-auto max-w-7xl px-5 py-16 md:px-10 md:py-20"><div className="max-w-xl"><p className="text-[10px] font-semibold uppercase tracking-[.2em] text-cyan-200/70">A clear next step</p><h2 className="mt-3 text-2xl font-semibold tracking-tight md:text-3xl">Check first. Choose confidently.</h2><p className="mt-3 text-[12px] leading-6 text-slate-400">A few simple steps help you understand common warning signs before you take action.</p></div><div className="mt-9 grid gap-3 md:grid-cols-3">{[{ n:'01',t:'Share what feels off',d:'Paste a message, extract screenshot text, or enter a URL you want to review.',icon:Search },{ n:'02',t:'Review the signals',d:'See the assessment and the language signals returned by the scan service.',icon:Activity },{ n:'03',t:'Verify independently',d:'Use a known official channel before sharing information, money, or access.',icon:BadgeCheck }].map(({n,t,d,icon:Icon}) => <Panel key={n} className="p-5"><div className="flex items-center justify-between"><span className="text-[10px] font-semibold tracking-widest text-cyan-200/60">{n}</span><Icon size={16} className="text-slate-500"/></div><h3 className="mt-6 text-xs font-semibold">{t}</h3><p className="mt-2 text-[10px] leading-5 text-slate-500">{d}</p></Panel>)}</div></div></section>
    </main>
    <footer className="mx-auto flex max-w-7xl flex-col gap-3 px-5 py-6 text-[9px] text-slate-600 sm:flex-row sm:items-center sm:justify-between md:px-10"><Brand go={go} compact/><p>ScamShield AI helps surface signals. It cannot guarantee that a message or website is safe.</p><button onClick={() => go('safety')} className="text-left hover:text-slate-400">Safety center <ArrowUpRight size={11} className="ml-1 inline"/></button></footer>
  </div>
}
