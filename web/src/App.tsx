import React, { useState, useEffect, useCallback, Suspense } from 'react'
import { Header } from './components/Header'
import { Navigation, TabId } from './components/Navigation'
import { HITLModal } from './components/HITLModal'
import { GatewayStatus, ThemeMode } from './types'
import { api } from './api'

// Lazy-loaded domain tabs for code-splitting and faster initial page paint
const OverviewTab = React.lazy(() =>
  import('./components/OverviewTab').then((m) => ({ default: m.OverviewTab }))
)
const ProtocolsTab = React.lazy(() =>
  import('./components/ProtocolsTab').then((m) => ({ default: m.ProtocolsTab }))
)
const AgentsTab = React.lazy(() =>
  import('./components/AgentsTab').then((m) => ({ default: m.AgentsTab }))
)
const SecurityGuardrailsTab = React.lazy(() =>
  import('./components/SecurityGuardrailsTab').then((m) => ({ default: m.SecurityGuardrailsTab }))
)
const AuditLogsTab = React.lazy(() =>
  import('./components/AuditLogsTab').then((m) => ({ default: m.AuditLogsTab }))
)

import { SettingsModal } from './components/SettingsModal'

const VALID_TABS: readonly TabId[] = [
  'overview',
  'protocols',
  'agents',
  'guardrails',
  'audit',
]

// Normalizes legacy or aliased hash routes to canonical tabs
const resolveCanonicalTab = (rawHash: string): TabId => {
  const clean = rawHash.replace('#', '')
  if (clean === 'tools') return 'protocols'
  if (clean === 'policy-packs' || clean === 'guards') return 'guardrails'
  if (VALID_TABS.includes(clean as TabId)) return clean as TabId
  return 'overview'
}

const getInitialTab = (): TabId => {
  if (typeof window !== 'undefined') {
    return resolveCanonicalTab(window.location.hash)
  }
  return 'overview'
}

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabId>(getInitialTab)
  const [status, setStatus] = useState<GatewayStatus | null>(null)
  const [isReloading, setIsReloading] = useState(false)
  const [isSettingsOpen, setIsSettingsOpen] = useState(false)
  const [settingsInitialTab, setSettingsInitialTab] = useState<'keys' | 'filters' | 'operational'>('keys')

  // Theme state with localStorage and OS preference sync
  const [themeMode, setThemeMode] = useState<ThemeMode>(() => {
    if (typeof window !== 'undefined') {
      const saved = localStorage.getItem('faradaiwire_theme') as ThemeMode
      if (saved === 'light' || saved === 'dark' || saved === 'system') return saved
    }
    return 'system'
  })

  const applyTheme = useCallback((mode: ThemeMode) => {
    if (typeof window === 'undefined') return
    const isDark =
      mode === 'dark' ||
      (mode === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches)

    if (isDark) {
      document.documentElement.classList.add('dark')
      document.documentElement.classList.remove('light')
    } else {
      document.documentElement.classList.add('light')
      document.documentElement.classList.remove('dark')
    }
  }, [])

  const handleThemeChange = useCallback((mode: ThemeMode) => {
    setThemeMode(mode)
    if (typeof window !== 'undefined') {
      localStorage.setItem('faradaiwire_theme', mode)
    }
    applyTheme(mode)
  }, [applyTheme])

  useEffect(() => {
    applyTheme(themeMode)

    if (typeof window === 'undefined') return
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)')
    const onMediaChange = () => {
      const current = localStorage.getItem('faradaiwire_theme')
      if (!current || current === 'system') {
        applyTheme('system')
      }
    }

    mediaQuery.addEventListener('change', onMediaChange)
    return () => mediaQuery.removeEventListener('change', onMediaChange)
  }, [themeMode, applyTheme])

  // Badge counts
  const [agentCount, setAgentCount] = useState(0)
  const [protocolCount, setProtocolCount] = useState(0)
  const [policyPackCount, setPolicyPackCount] = useState(0)

  // Sync hash with browser history and deep linking
  const handleTabChange = useCallback((tab: TabId) => {
    setActiveTab(tab)
    if (typeof window !== 'undefined') {
      window.location.hash = tab
    }
  }, [])

  useEffect(() => {
    const onHashChange = () => {
      const raw = window.location.hash.replace('#', '')
      if (raw === 'api-keys') {
        setSettingsInitialTab('keys')
        setIsSettingsOpen(true)
        return
      }
      if (raw === 'filters') {
        setSettingsInitialTab('filters')
        setIsSettingsOpen(true)
        return
      }
      if (raw === 'settings' || raw === 'operational' || raw === 'system-settings') {
        setSettingsInitialTab('operational')
        setIsSettingsOpen(true)
        return
      }
      const canonical = resolveCanonicalTab(raw)
      setActiveTab(canonical)
    }
    window.addEventListener('hashchange', onHashChange)
    return () => window.removeEventListener('hashchange', onHashChange)
  }, [])

  const fetchStatus = useCallback(async (signal?: AbortSignal) => {
    try {
      const s = await api.getStatus(signal)
      setStatus(s)
    } catch {
      // ignore aborted or network failure
    }
  }, [])

  const fetchCounts = useCallback(async (signal?: AbortSignal) => {
    try {
      const [aRes, pRes, packRes] = await Promise.all([
        api.getAgents(signal).catch(() => ({ agents: [] })),
        api.getProtocols(signal).catch(() => ({ protocols: [] })),
        api.getPolicyPacks(signal).catch(() => ({ packs: [] })),
      ])
      setAgentCount(aRes.agents?.length || 0)
      setProtocolCount(pRes.protocols?.length || 0)
      setPolicyPackCount(packRes.packs?.length || 0)
    } catch {
      // ignore
    }
  }, [])

  useEffect(() => {
    const controller = new AbortController()
    fetchStatus(controller.signal)
    fetchCounts(controller.signal)

    const timer = setInterval(() => {
      fetchStatus()
    }, 10000)

    return () => {
      controller.abort()
      clearInterval(timer)
    }
  }, [fetchStatus, fetchCounts])

  const handleReload = async () => {
    try {
      setIsReloading(true)
      await api.reloadGateway()
      await Promise.all([fetchStatus(), fetchCounts()])
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      alert(`Reload failed: ${msg}`)
    } finally {
      setIsReloading(false)
    }
  }

  const renderActiveTab = () => {
    switch (activeTab) {
      case 'overview':
        return <OverviewTab status={status} onRefresh={fetchStatus} />
      case 'protocols':
        return <ProtocolsTab />
      case 'agents':
        return <AgentsTab status={status} />
      case 'guardrails':
        return <SecurityGuardrailsTab />
      case 'audit':
        return <AuditLogsTab />
      default:
        return <OverviewTab status={status} onRefresh={fetchStatus} />
    }
  }

  return (
    <div className="min-h-screen flex flex-col bg-canvas text-primary selection:bg-cyan-500/20 selection:text-cyan-600 dark:selection:text-cyan-300 transition-colors duration-150">
      <Header
        status={status}
        onReload={handleReload}
        isReloading={isReloading}
        themeMode={themeMode}
        onThemeChange={handleThemeChange}
        onOpenSettings={() => {
          setSettingsInitialTab('keys')
          setIsSettingsOpen(true)
        }}
      />

      <Navigation
        activeTab={activeTab}
        onTabChange={handleTabChange}
        agentCount={agentCount}
        protocolCount={protocolCount}
        activeFilterCount={
          (status?.active_filters || []).filter((f) =>
            ['prefill_block', 'dlp', 'rate_limiting', 'loop_protection', 'guard', 'hitl', 'schema_validation'].includes(f)
          ).length
        }
        policyPackCount={policyPackCount}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto p-6">
        <Suspense
          fallback={
            <div className="glass-card p-12 text-center text-xs text-muted font-mono animate-pulse rounded-2xl flex flex-col items-center justify-center gap-3">
              <div className="w-5 h-5 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
              <span>Loading interface view...</span>
            </div>
          }
        >
          {renderActiveTab()}
        </Suspense>
      </main>

      <footer className="border-t border-subtle py-4 px-6 text-center text-xs text-muted font-mono flex flex-wrap items-center justify-between gap-4">
        <div>FaradAiWire Open Core · Hexagonal MCP AI Gateway</div>
        <div className="flex items-center gap-4">
          <span>Zero-Egress Guaranteed</span>
          <span>127.0.0.1:8095</span>
        </div>
      </footer>

      <SettingsModal
        isOpen={isSettingsOpen}
        onClose={() => setIsSettingsOpen(false)}
        status={status}
        onStatusChange={fetchStatus}
        initialTab={settingsInitialTab}
      />

      <HITLModal />
    </div>
  )
}
