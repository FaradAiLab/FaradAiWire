import React, { useState, useEffect, useCallback, useMemo } from 'react'
import {
  Sliders,
  Search,
  RotateCcw,
  Check,
  CheckCircle2,
  AlertCircle,
  Cpu,
  Clock,
  ShieldAlert,
  Wrench,
  Info,
  X,
  Gauge,
} from 'lucide-react'
import { SettingItem, SettingsResponse } from '../types'
import { api } from '../api'

const CATEGORY_CONFIG: Record<
  string,
  { label: string; icon: React.ComponentType<{ className?: string }>; description: string }
> = {
  limits: {
    label: 'Limits',
    icon: Gauge,
    description: 'Socket payloads, concurrent sessions, and protocol scale bounds.',
  },
  timeouts: {
    label: 'Timeouts',
    icon: Clock,
    description: 'Execution deadlines, HTTP/SSE idle intervals, and connection handshakes.',
  },
  guard: {
    label: 'Guard & Defenses',
    icon: ShieldAlert,
    description: 'Neural security model thresholds and governance confirmation timeouts.',
  },
  maintenance: {
    label: 'Maintenance',
    icon: Wrench,
    description: 'Session cleanup loops and background storage compaction routines.',
  },
}

function formatBytes(bytes: number): string {
  if (bytes >= 1024 * 1024 * 1024) {
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`
  }
  if (bytes >= 1024 * 1024) {
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  }
  if (bytes >= 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`
  }
  return `${bytes} B`
}

export const OperationalSettingsTab: React.FC = () => {
  const [settings, setSettings] = useState<SettingItem[]>([])
  const [categories, setCategories] = useState<string[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Filters
  const [selectedCategory, setSelectedCategory] = useState<string>('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [modifiedOnly, setModifiedOnly] = useState(false)

  // Local draft state for inputs before save
  const [drafts, setDrafts] = useState<Record<string, any>>({})
  const [savingKey, setSavingKey] = useState<string | null>(null)
  const [resettingKey, setResettingKey] = useState<string | null>(null)
  const [notification, setNotification] = useState<{
    type: 'success' | 'error'
    text: string
  } | null>(null)

  const fetchSettings = useCallback(async (signal?: AbortSignal) => {
    try {
      setLoading(true)
      setError(null)
      const res: SettingsResponse = await api.getSettings(signal)
      setSettings(res.settings || [])
      setCategories(res.categories || [])

      // Initialize drafts
      const initialDrafts: Record<string, any> = {}
      ;(res.settings || []).forEach((s) => {
        initialDrafts[s.key] = s.value
      })
      setDrafts(initialDrafts)
    } catch (err: unknown) {
      if (err instanceof Error && err.name === 'AbortError') return
      const msg = err instanceof Error ? err.message : String(err)
      setError(msg)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    const ac = new AbortController()
    fetchSettings(ac.signal)
    return () => ac.abort()
  }, [fetchSettings])

  // Clear notification after 4s
  useEffect(() => {
    if (!notification) return
    const timer = setTimeout(() => setNotification(null), 4000)
    return () => clearTimeout(timer)
  }, [notification])

  const handleDraftChange = (key: string, value: any) => {
    setDrafts((prev) => ({ ...prev, [key]: value }))
  }

  const handleSave = async (key: string) => {
    const target = settings.find((s) => s.key === key)
    if (!target) return

    let val = drafts[key]
    if (target.data_type === 'int') {
      val = parseInt(String(val), 10)
      if (isNaN(val)) {
        setNotification({ type: 'error', text: `Invalid integer value for ${key}` })
        return
      }
    } else if (target.data_type === 'float') {
      val = parseFloat(String(val))
      if (isNaN(val)) {
        setNotification({ type: 'error', text: `Invalid float value for ${key}` })
        return
      }
    } else if (target.data_type === 'bool') {
      val = Boolean(val)
    }

    try {
      setSavingKey(key)
      await api.updateSetting(key, val)
      setNotification({
        type: 'success',
        text: `Setting ${key} persisted to DuckDB and loaded into zero-I/O cache.`,
      })
      await fetchSettings()
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      setNotification({ type: 'error', text: `Failed to update ${key}: ${msg}` })
    } finally {
      setSavingKey(null)
    }
  }

  const handleReset = async (key: string) => {
    try {
      setResettingKey(key)
      await api.resetSetting(key)
      setNotification({
        type: 'success',
        text: `Setting ${key} reset to config.yaml baseline.`,
      })
      await fetchSettings()
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      setNotification({ type: 'error', text: `Failed to reset ${key}: ${msg}` })
    } finally {
      setResettingKey(null)
    }
  }

  // Filtered settings
  const filteredSettings = useMemo(() => {
    return settings.filter((item) => {
      // Category filter
      if (selectedCategory !== 'all' && item.category !== selectedCategory) {
        return false
      }
      // Modified only filter
      if (modifiedOnly && !item.is_overridden) {
        return false
      }
      // Search query
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase()
        const matchKey = item.key.toLowerCase().includes(q)
        const matchLabel = item.label.toLowerCase().includes(q)
        const matchDesc = item.description.toLowerCase().includes(q)
        const matchCategory = item.category.toLowerCase().includes(q)
        if (!matchKey && !matchLabel && !matchDesc && !matchCategory) {
          return false
        }
      }
      return true
    })
  }, [settings, selectedCategory, modifiedOnly, searchQuery])

  // Group by category
  const groupedSettings = useMemo(() => {
    const groups: Record<string, SettingItem[]> = {}
    filteredSettings.forEach((item) => {
      if (!groups[item.category]) {
        groups[item.category] = []
      }
      groups[item.category].push(item)
    })
    return groups
  }, [filteredSettings])

  const overriddenCount = settings.filter((s) => s.is_overridden).length

  return (
    <div className="space-y-6">
      {/* Header & Architecture Context Card */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-2xl bg-surface-elevated/40 border border-subtle">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-bold text-primary tracking-tight">
              Operational Parameters & Limits
            </h3>
            <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-medium bg-accent-primary/10 text-accent-primary border border-accent-primary/20">
              DuckDB Overlay
            </span>
            <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-medium bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
              0.04 ns Zero-I/O
            </span>
          </div>
          <p className="text-xs text-muted">
            Segmented runtime controls with fail-closed bounds. Overrides persist to local DuckDB without modifying <code className="font-mono text-primary bg-surface px-1 py-0.5 rounded border border-subtle">config.yaml</code>.
          </p>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={() => fetchSettings()}
            disabled={loading}
            className="px-3 py-1.5 rounded-xl border border-subtle bg-surface hover:bg-surface-elevated text-xs font-medium text-secondary hover:text-primary transition-colors flex items-center gap-1.5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent-primary"
            title="Refresh active settings"
          >
            <RotateCcw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Notification Toast */}
      {notification && (
        <div
          className={`p-3.5 rounded-xl text-xs flex items-center justify-between gap-3 animate-in fade-in duration-150 border ${
            notification.type === 'success'
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-800 dark:text-emerald-200'
              : 'bg-rose-500/10 border-rose-500/30 text-rose-800 dark:text-rose-200'
          }`}
        >
          <div className="flex items-center gap-2 min-w-0">
            {notification.type === 'success' ? (
              <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-500" />
            ) : (
              <AlertCircle className="w-4 h-4 shrink-0 text-rose-500" />
            )}
            <span className="truncate">{notification.text}</span>
          </div>
          <button
            type="button"
            onClick={() => setNotification(null)}
            className="p-1 rounded-lg hover:bg-black/5 dark:hover:bg-white/5 transition-colors shrink-0"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* VS Code Style Filter & Search Toolbar */}
      <div className="space-y-3">
        {/* Search Bar */}
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2.5">
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-muted pointer-events-none" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search settings (e.g. payload, timeout, threshold, cleanup)..."
              className="w-full pl-9 pr-9 py-2 rounded-xl bg-surface border border-subtle text-xs text-primary placeholder:text-muted focus:outline-none focus:ring-1 focus:ring-accent-primary focus:border-accent-primary transition-all font-mono"
            />
            {searchQuery && (
              <button
                type="button"
                onClick={() => setSearchQuery('')}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 p-1 text-muted hover:text-primary transition-colors"
                title="Clear search"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          {/* Modified Filter Toggle */}
          <button
            type="button"
            onClick={() => setModifiedOnly(!modifiedOnly)}
            className={`px-3 py-2 rounded-xl border text-xs font-medium transition-all flex items-center gap-1.5 shrink-0 ${
              modifiedOnly
                ? 'bg-accent-primary/10 border-accent-primary/30 text-accent-primary shadow-xs'
                : 'bg-surface border-subtle text-muted hover:text-primary hover:bg-surface-elevated'
            }`}
          >
            <span
              className={`w-2 h-2 rounded-full ${
                overriddenCount > 0 ? 'bg-accent-primary animate-pulse' : 'bg-gray-400'
              }`}
            />
            <span>Modified Only</span>
            <span className="ml-1 px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-surface-elevated border border-subtle">
              {overriddenCount}
            </span>
          </button>
        </div>

        {/* Category Segment Tabs */}
        <div className="flex flex-wrap items-center gap-1.5 p-1 rounded-xl bg-surface-elevated/40 border border-subtle">
          <button
            type="button"
            onClick={() => setSelectedCategory('all')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all flex items-center gap-1.5 ${
              selectedCategory === 'all'
                ? 'bg-surface shadow-xs text-accent-primary font-semibold border border-subtle'
                : 'text-muted hover:text-primary hover:bg-surface/50 border border-transparent'
            }`}
          >
            <Sliders className="w-3.5 h-3.5" />
            <span>All Categories</span>
            <span className="text-[10px] font-mono opacity-70">({settings.length})</span>
          </button>

          {categories.map((cat) => {
            const cfg = CATEGORY_CONFIG[cat] || {
              label: cat,
              icon: Cpu,
              description: '',
            }
            const Icon = cfg.icon
            const count = settings.filter((s) => s.category === cat).length
            const isSelected = selectedCategory === cat

            return (
              <button
                key={cat}
                type="button"
                onClick={() => setSelectedCategory(cat)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all flex items-center gap-1.5 ${
                  isSelected
                    ? 'bg-surface shadow-xs text-accent-primary font-semibold border border-subtle'
                    : 'text-muted hover:text-primary hover:bg-surface/50 border border-transparent'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{cfg.label}</span>
                <span className="text-[10px] font-mono opacity-70">({count})</span>
              </button>
            )
          })}
        </div>
      </div>

      {/* Main Settings List */}
      {loading && settings.length === 0 ? (
        <div className="p-12 text-center text-xs text-muted font-mono flex flex-col items-center justify-center gap-2">
          <div className="w-5 h-5 border-2 border-accent-primary border-t-transparent rounded-full animate-spin" />
          <span>Reading system settings registry...</span>
        </div>
      ) : error && settings.length === 0 ? (
        <div className="p-8 text-center text-xs text-rose-500 font-mono border border-rose-500/20 rounded-xl bg-rose-500/5">
          Failed to load settings: {error}
        </div>
      ) : filteredSettings.length === 0 ? (
        <div className="p-12 text-center text-xs text-muted border border-subtle rounded-2xl bg-surface-elevated/20 space-y-2">
          <Info className="w-6 h-6 mx-auto text-muted/60" />
          <div className="font-semibold text-primary">No matching operational settings</div>
          <div className="text-[11px] text-muted">
            {modifiedOnly
              ? 'No settings have been overridden in DuckDB. All values are currently inheriting YAML defaults.'
              : 'Try broadening your search term or selecting another category.'}
          </div>
        </div>
      ) : (
        <div className="space-y-6">
          {Object.entries(groupedSettings).map(([catKey, items]) => {
            const catMeta = CATEGORY_CONFIG[catKey] || {
              label: catKey,
              icon: Cpu,
              description: '',
            }
            const CatIcon = catMeta.icon

            return (
              <div key={catKey} className="space-y-3">
                {/* Category Header */}
                <div className="flex items-center gap-2 pb-1.5 border-b border-subtle">
                  <span className="p-1.5 rounded-lg bg-surface-elevated text-accent-primary border border-subtle">
                    <CatIcon className="w-4 h-4" />
                  </span>
                  <div>
                    <h4 className="text-xs font-bold text-primary uppercase tracking-wider font-mono">
                      {catMeta.label}
                    </h4>
                    <p className="text-[11px] text-muted">{catMeta.description}</p>
                  </div>
                </div>

                {/* Settings Cards in Category */}
                <div className="space-y-3">
                  {items.map((item) => {
                    const currentDraft = drafts[item.key] ?? item.value
                    const isDirty = String(currentDraft) !== String(item.value)
                    const isSaving = savingKey === item.key
                    const isResetting = resettingKey === item.key

                    return (
                      <div
                        key={item.key}
                        className={`p-4 rounded-xl border transition-all duration-150 ${
                          item.is_overridden
                            ? 'bg-surface border-accent-primary/30 shadow-xs'
                            : 'bg-surface/60 border-subtle hover:border-default hover:bg-surface'
                        }`}
                      >
                        <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                          {/* Left: Info, Key, Description */}
                          <div className="space-y-1.5 flex-1 min-w-0">
                            <div className="flex flex-wrap items-center gap-2">
                              <span className="text-xs font-semibold text-primary leading-tight">
                                {item.label}
                              </span>

                              <code className="px-1.5 py-0.5 rounded bg-surface-elevated border border-subtle text-[10px] font-mono text-muted">
                                {item.key}
                              </code>

                              {item.is_overridden ? (
                                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono font-medium bg-accent-primary/10 text-accent-primary border border-accent-primary/20">
                                  <span className="w-1.5 h-1.5 rounded-full bg-accent-primary" />
                                  Overridden (DuckDB)
                                </span>
                              ) : (
                                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono text-muted bg-surface-muted/60 border border-subtle">
                                  YAML Default
                                </span>
                              )}

                              {isDirty && (
                                <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-medium bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20">
                                  Unsaved Changes
                                </span>
                              )}
                            </div>

                            <p className="text-xs text-muted leading-relaxed">
                              {item.description}
                            </p>

                            {/* Constraints Metadata */}
                            <div className="flex flex-wrap items-center gap-3 pt-1 text-[11px] font-mono text-muted/80">
                              {item.min !== undefined && item.max !== undefined && (
                                <span>
                                  Bounds:{' '}
                                  <strong className="text-primary font-normal">
                                    {item.unit === 'bytes'
                                      ? `${formatBytes(item.min)} – ${formatBytes(item.max)}`
                                      : `${item.min} – ${item.max}`}
                                    {item.unit && item.unit !== 'bytes' ? ` ${item.unit}` : ''}
                                  </strong>
                                </span>
                              )}
                              {item.unit === 'bytes' && typeof currentDraft === 'number' && (
                                <span className="text-accent-primary font-semibold">
                                  ≈ {formatBytes(currentDraft)}
                                </span>
                              )}
                            </div>
                          </div>

                          {/* Right: Interactive Input & Controls */}
                          <div className="flex flex-col sm:items-end gap-2 shrink-0">
                            <div className="flex items-center gap-2">
                              {item.data_type === 'float' ? (
                                <div className="flex items-center gap-2.5">
                                  <input
                                    type="range"
                                    min={item.min ?? 0}
                                    max={item.max ?? 1}
                                    step={item.step ?? 0.05}
                                    value={currentDraft}
                                    onChange={(e) =>
                                      handleDraftChange(item.key, parseFloat(e.target.value))
                                    }
                                    className="w-24 sm:w-32 accent-accent-primary cursor-pointer"
                                  />
                                  <span className="w-12 text-right font-mono text-xs text-primary font-bold">
                                    {Number(currentDraft).toFixed(2)}
                                  </span>
                                </div>
                              ) : item.data_type === 'bool' ? (
                                <button
                                  type="button"
                                  onClick={() => handleDraftChange(item.key, !currentDraft)}
                                  className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus-visible:ring-2 focus-visible:ring-accent-primary ${
                                    currentDraft ? 'bg-accent-primary' : 'bg-surface-elevated'
                                  }`}
                                >
                                  <span
                                    className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow-lg ring-0 transition duration-200 ease-in-out ${
                                      currentDraft ? 'translate-x-4' : 'translate-x-0'
                                    }`}
                                  />
                                </button>
                              ) : (
                                <div className="flex items-center gap-1.5">
                                  <input
                                    type="number"
                                    min={item.min}
                                    max={item.max}
                                    value={currentDraft}
                                    onChange={(e) =>
                                      handleDraftChange(
                                        item.key,
                                        e.target.value === '' ? '' : Number(e.target.value)
                                      )
                                    }
                                    onKeyDown={(e) => {
                                      if (e.key === 'Enter' && isDirty) {
                                        handleSave(item.key)
                                      }
                                    }}
                                    className="w-28 sm:w-36 px-2.5 py-1.5 rounded-lg bg-surface border border-subtle text-xs font-mono text-primary text-right focus:outline-none focus:ring-1 focus:ring-accent-primary"
                                  />
                                  {item.unit && (
                                    <span className="text-[11px] font-mono text-muted uppercase">
                                      {item.unit}
                                    </span>
                                  )}
                                </div>
                              )}
                            </div>

                            {/* Action Buttons: Save & Reset */}
                            <div className="flex items-center gap-1.5">
                              {/* Reset to YAML baseline button */}
                              {item.is_overridden && (
                                <button
                                  type="button"
                                  onClick={() => handleReset(item.key)}
                                  disabled={isResetting || isSaving}
                                  className="px-2 py-1 rounded-lg border border-subtle bg-surface hover:bg-surface-elevated text-[11px] font-mono text-muted hover:text-primary transition-colors flex items-center gap-1 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-accent-primary"
                                  title="Reset setting override back to YAML baseline"
                                >
                                  <RotateCcw
                                    className={`w-3 h-3 ${isResetting ? 'animate-spin' : ''}`}
                                  />
                                  <span>Reset</span>
                                </button>
                              )}

                              {/* Save Changes button */}
                              {isDirty && (
                                <button
                                  type="button"
                                  onClick={() => handleSave(item.key)}
                                  disabled={isSaving || isResetting}
                                  className="px-2.5 py-1 rounded-lg bg-accent-primary hover:bg-accent-primary/90 text-white text-[11px] font-semibold transition-all flex items-center gap-1 shadow-xs focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-accent-primary"
                                >
                                  {isSaving ? (
                                    <div className="w-3 h-3 border border-white border-t-transparent rounded-full animate-spin" />
                                  ) : (
                                    <Check className="w-3 h-3" />
                                  )}
                                  <span>Save</span>
                                </button>
                              )}
                            </div>
                          </div>
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
