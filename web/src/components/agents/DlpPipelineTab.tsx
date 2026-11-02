import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react'
import {
  PolicyPack,
  ToolMetadata,
  AgentDlpConfig,
  CompiledAgentPolicy,
  DlpAction,
  CustomPattern,
  ToolExemption,
} from '../../types'
import { api } from '../../api'
import { Button } from '../ui/Button'
import { Badge } from '../ui/Badge'
import {
  ShieldCheck,
  Plus,
  Trash2,
  X,
  AlertCircle,
  Globe,
  Lock,
  RefreshCw,
  Sliders,
  ShieldAlert,
  ArrowRight,
  ArrowLeft,
  Search,
  Filter,
  ChevronLeft,
  ChevronRight,
  Layers,
} from 'lucide-react'

export interface DlpPipelineTabProps {
  agentName: string
  availablePacks: PolicyPack[]
  availableTools: ToolMetadata[]
  reloadToken?: number
  onSaveSuccess?: (msg: string) => void
  onSaveError?: (msg: string) => void
  onSavingChange?: (saving: boolean) => void
}

const isExternalTool = (tool: ToolMetadata): boolean => {
  const name = (tool.canonical_name || tool.name || '').toLowerCase()
  const protocol = (tool.protocol_id || tool.protocol_name || '').toLowerCase()
  const desc = (tool.description || '').toLowerCase()
  const egressKeywords = [
    'search', 'tavily', 'brave', 'google', 'web', 'fetch', 'http',
    'curl', 'browser', 'scrape', 'slack', 'mail', 'smtp', 'webhook',
    'external', 'download', 'upload', 'rest'
  ]
  return egressKeywords.some(
    (kw) => name.includes(kw) || protocol.includes(kw) || desc.includes(kw)
  )
}

type DlpSubView = 'rules' | 'exemptions' | 'patterns'

export const DlpPipelineTab: React.FC<DlpPipelineTabProps> = ({
  agentName,
  availablePacks,
  availableTools,
  reloadToken,
  onSaveSuccess,
  onSaveError,
  onSavingChange,
}) => {
  const [activeView, setActiveView] = useState<DlpSubView>('rules')
  const [config, setConfig] = useState<AgentDlpConfig>({
    agent_name: agentName,
    pack_ids: [],
    overrides: [],
    custom_patterns: [],
    tool_exemptions: {},
  })
  const [compiled, setCompiled] = useState<CompiledAgentPolicy | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [isPreviewing, setIsPreviewing] = useState(false)
  const [isSaving, setIsSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const initialLoadedRef = useRef(false)

  // Custom pattern input state
  const [customName, setCustomName] = useState('')
  const [customRegex, setCustomRegex] = useState('')
  const [customAction, setCustomAction] = useState<DlpAction>('mask')

  // Rules filtering & pagination state
  const [ruleSearch, setRuleSearch] = useState('')
  const [packFilter, setPackFilter] = useState<string>('all')
  const [actionFilter, setActionFilter] = useState<string>('all')
  const [bypassFilter, setBypassFilter] = useState<'all' | 'active' | 'bypassed'>('all')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)

  // Tool exemption filter state
  const [toolSearch, setToolSearch] = useState('')

  const fetchDlp = useCallback(async (signal?: AbortSignal) => {
    if (!agentName) return
    try {
      setIsLoading(true)
      setError(null)
      const res = await api.getAgentDLP(agentName, signal)
      setConfig(res.config || {
        agent_name: agentName,
        pack_ids: [],
        overrides: [],
        custom_patterns: [],
        tool_exemptions: {},
      })
      setCompiled(res.compiled || null)
      initialLoadedRef.current = true
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setIsLoading(false)
    }
  }, [agentName])

  useEffect(() => {
    const controller = new AbortController()
    fetchDlp(controller.signal)
    return () => controller.abort()
  }, [fetchDlp])

  // Reactive Debounced Live Preview
  useEffect(() => {
    if (!initialLoadedRef.current) return
    const controller = new AbortController()
    const timer = setTimeout(async () => {
      try {
        setIsPreviewing(true)
        const res = await api.previewAgentDLP(config, controller.signal)
        if (res?.compiled) {
          setCompiled(res.compiled)
        }
      } catch (err: unknown) {
        if ((err as Error)?.name !== 'AbortError') {
          // Keep preview failure non-blocking
        }
      } finally {
        setIsPreviewing(false)
      }
    }, 200)

    return () => {
      clearTimeout(timer)
      controller.abort()
    }
  }, [config])

  useEffect(() => {
    if (reloadToken && reloadToken > 0) {
      fetchDlp()
    }
  }, [reloadToken, fetchDlp])

  const handleSave = async () => {
    try {
      setIsSaving(true)
      if (onSavingChange) onSavingChange(true)
      setError(null)
      const res = await api.saveAgentDLP(agentName, config)
      setConfig(res.config)
      setCompiled(res.compiled)
      if (onSaveSuccess) {
        onSaveSuccess('DLP Policy compiled and hot-reloaded successfully. Checkpoint archived.')
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      setError(msg)
      if (onSaveError) {
        onSaveError(`DLP Save failed: ${msg}`)
      }
    } finally {
      setIsSaving(false)
      if (onSavingChange) onSavingChange(false)
    }
  }

  // Pack attachment helpers
  const handleAttachPack = (packId: string) => {
    if (!packId || config.pack_ids.includes(packId)) return
    setConfig((prev) => ({ ...prev, pack_ids: [...prev.pack_ids, packId] }))
  }

  const handleDetachPack = (packId: string) => {
    setConfig((prev) => ({
      ...prev,
      pack_ids: prev.pack_ids.filter((id) => id !== packId),
    }))
  }

  // Override helpers
  const handleToggleRuleBypass = (ruleId: string, currentBypassed: boolean) => {
    setConfig((prev) => {
      const existing = prev.overrides.find((o) => o.rule_id === ruleId)
      if (existing) {
        return {
          ...prev,
          overrides: prev.overrides.map((o) =>
            o.rule_id === ruleId ? { ...o, enabled: currentBypassed } : o
          ),
        }
      }
      return {
        ...prev,
        overrides: [
          ...prev.overrides,
          { rule_id: ruleId, action: 'mask', enabled: currentBypassed },
        ],
      }
    })
  }

  const handleChangeRuleAction = (ruleId: string, newAction: DlpAction) => {
    setConfig((prev) => {
      const existing = prev.overrides.find((o) => o.rule_id === ruleId)
      if (existing) {
        return {
          ...prev,
          overrides: prev.overrides.map((o) =>
            o.rule_id === ruleId ? { ...o, action: newAction } : o
          ),
        }
      }
      return {
        ...prev,
        overrides: [...prev.overrides, { rule_id: ruleId, action: newAction, enabled: true }],
      }
    })
  }

  // Custom pattern helpers
  const handleAddCustomPattern = () => {
    if (!customName.trim() || !customRegex.trim()) return
    try {
      new RegExp(customRegex)
    } catch {
      setError('Custom pattern regex is invalid')
      return
    }

    const newPat: CustomPattern = {
      name: customName.trim(),
      regex: customRegex.trim(),
      action: customAction,
    }
    setConfig((prev) => ({
      ...prev,
      custom_patterns: [...prev.custom_patterns, newPat],
    }))
    setCustomName('')
    setCustomRegex('')
  }

  const handleRemoveCustomPattern = (index: number) => {
    setConfig((prev) => ({
      ...prev,
      custom_patterns: prev.custom_patterns.filter((_, i) => i !== index),
    }))
  }

  // Directional Tool Exemption helper
  const handleToggleExemption = (toolName: string, direction: 'request' | 'response') => {
    setConfig((prev) => {
      const current = prev.tool_exemptions?.[toolName] || { request: false, response: false }
      const updated: ToolExemption = {
        ...current,
        [direction]: !current[direction],
      }
      const newExemptions = { ...(prev.tool_exemptions || {}) }
      if (!updated.request && !updated.response) {
        delete newExemptions[toolName]
      } else {
        newExemptions[toolName] = updated
      }
      return {
        ...prev,
        tool_exemptions: newExemptions,
      }
    })
  }

  const unattachedPacks = availablePacks.filter((p) => !config.pack_ids.includes(p.id))

  // Filtered Rules Calculation
  const filteredRules = useMemo(() => {
    if (!compiled?.effective_rules) return []

    return compiled.effective_rules.filter((rule) => {
      const override = config.overrides.find((o) => o.rule_id === rule.rule_id)
      const isBypassed = override ? !override.enabled : rule.is_bypassed
      const currentAction = override?.action || rule.effective_action

      // Text search
      if (ruleSearch.trim()) {
        const q = ruleSearch.toLowerCase()
        const matchName = rule.name.toLowerCase().includes(q)
        const matchId = rule.rule_id.toLowerCase().includes(q)
        const matchPacks = (rule.source_pack_ids || []).some((p) => p.toLowerCase().includes(q))
        if (!matchName && !matchId && !matchPacks) return false
      }

      // Pack filter
      if (packFilter !== 'all') {
        if (!(rule.source_pack_ids || []).includes(packFilter)) return false
      }

      // Action filter
      if (actionFilter !== 'all') {
        if (currentAction !== actionFilter) return false
      }

      // Bypass filter
      if (bypassFilter === 'active' && isBypassed) return false
      if (bypassFilter === 'bypassed' && !isBypassed) return false

      return true
    })
  }, [compiled, config.overrides, ruleSearch, packFilter, actionFilter, bypassFilter])

  // Reset page when filters change
  useEffect(() => {
    setPage(1)
  }, [ruleSearch, packFilter, actionFilter, bypassFilter, pageSize])

  const totalPages = Math.max(1, Math.ceil(filteredRules.length / pageSize))
  const paginatedRules = useMemo(() => {
    const start = (page - 1) * pageSize
    return filteredRules.slice(start, start + pageSize)
  }, [filteredRules, page, pageSize])

  // Filtered Tools for Exemption view
  const filteredTools = useMemo(() => {
    if (!toolSearch.trim()) return availableTools
    const q = toolSearch.toLowerCase()
    return availableTools.filter((t) => {
      const name = (t.canonical_name || t.name).toLowerCase()
      const desc = (t.description || '').toLowerCase()
      return name.includes(q) || desc.includes(q)
    })
  }, [availableTools, toolSearch])

  return (
    <div className="space-y-6 text-xs font-sans">
      {error && (
        <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-700 dark:text-rose-300 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-rose-500 shrink-0" />
            <span>{error}</span>
          </div>
          <Button variant="ghost" size="sm" onClick={() => fetchDlp()}>
            Retry
          </Button>
        </div>
      )}

      {/* Segmented View Switcher */}
      <div className="flex flex-wrap items-center justify-between gap-3 pb-2 border-b border-subtle">
        <div className="flex items-center gap-1.5 p-1 rounded-xl bg-surface border border-subtle shadow-xs">
          <button
            type="button"
            onClick={() => setActiveView('rules')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
              activeView === 'rules'
                ? 'bg-accent/15 text-accent font-semibold shadow-xs'
                : 'text-muted hover:text-primary hover:bg-subtle'
            }`}
          >
            <ShieldCheck className="w-3.5 h-3.5 text-accent" />
            <span>Compiled Rules</span>
            <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-accent/20 text-accent font-mono font-bold">
              {compiled?.effective_rules?.length || 0}
            </span>
          </button>

          <button
            type="button"
            onClick={() => setActiveView('exemptions')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
              activeView === 'exemptions'
                ? 'bg-accent/15 text-accent font-semibold shadow-xs'
                : 'text-muted hover:text-primary hover:bg-subtle'
            }`}
          >
            <Sliders className="w-3.5 h-3.5 text-accent" />
            <span>Tool DLP Exemptions</span>
            <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-surface text-muted border border-subtle font-mono">
              {Object.keys(config.tool_exemptions || {}).length}
            </span>
          </button>

          <button
            type="button"
            onClick={() => setActiveView('patterns')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
              activeView === 'patterns'
                ? 'bg-accent/15 text-accent font-semibold shadow-xs'
                : 'text-muted hover:text-primary hover:bg-subtle'
            }`}
          >
            <Plus className="w-3.5 h-3.5 text-accent" />
            <span>Custom Regex</span>
            <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-surface text-muted border border-subtle font-mono">
              {config.custom_patterns?.length || 0}
            </span>
          </button>
        </div>

        {isPreviewing && (
          <span className="flex items-center gap-1.5 text-xs text-accent font-sans">
            <RefreshCw className="w-3.5 h-3.5 animate-spin" /> Live Preview Recompiling...
          </span>
        )}
      </div>

      {/* VIEW 1: COMPILED RULES & POLICY PACKS */}
      {activeView === 'rules' && (
        <div className="space-y-5">
          {/* Attached Policy Packs Bar */}
          <div className="p-4 rounded-xl border border-subtle bg-surface/30 space-y-3">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-primary flex items-center gap-2 text-sm font-sans">
                <Layers className="w-4 h-4 text-accent" /> Attached Policy Packs ({config.pack_ids.length})
              </span>
              {unattachedPacks.length > 0 && (
                <select
                  aria-label="Attach policy pack"
                  onChange={(e) => {
                    handleAttachPack(e.target.value)
                    e.target.value = ''
                  }}
                  defaultValue=""
                  className="px-2.5 py-1 rounded-lg bg-surface border border-subtle text-primary text-xs focus:ring-1 focus:ring-accent focus:outline-none cursor-pointer"
                >
                  <option value="" disabled>+ Attach Policy Pack...</option>
                  {unattachedPacks.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name} ({p.id})
                    </option>
                  ))}
                </select>
              )}
            </div>

            {config.pack_ids.length === 0 ? (
              <div className="p-3 rounded-lg border border-dashed border-subtle text-center text-muted text-xs">
                No policy packs attached. Attach database, cloud, or regulatory packs to protect this agent.
              </div>
            ) : (
              <div className="flex flex-wrap gap-2">
                {config.pack_ids.map((packId) => {
                  const pack = availablePacks.find((p) => p.id === packId)
                  return (
                    <div
                      key={packId}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-accent/10 border border-accent/30 text-primary shadow-xs"
                    >
                      <span className="font-bold text-xs">{pack?.name || packId}</span>
                      <span className="text-[10px] text-accent font-mono font-medium">
                        ({pack?.rule_ids?.length || 0} rules)
                      </span>
                      <button
                        type="button"
                        onClick={() => handleDetachPack(packId)}
                        className="ml-1 text-muted hover:text-rose-500 transition-colors"
                        aria-label={`Detach ${pack?.name || packId}`}
                        title="Detach Pack"
                      >
                        <X className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  )
                })}
              </div>
            )}
          </div>

          {/* Section Header: Compiled Effective Rules Matrix */}
          <div className="flex items-center justify-between pt-1">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-accent" />
              <span className="font-semibold text-primary text-sm font-sans">
                Compiled Policy Rules Matrix
              </span>
              <span className="px-2 py-0.5 rounded-full text-xs bg-accent/10 text-accent font-mono font-medium">
                {compiled?.effective_rules?.length || 0} rules
              </span>
            </div>
            <span className="text-[11px] text-muted font-sans hidden sm:inline">
              Precedence: <strong className="text-rose-500 font-mono">BLOCK(3)</strong> &gt; <strong className="text-amber-500 font-mono">MASK(2)</strong> &gt; <strong className="text-cyan-500 font-mono">AUDIT(1)</strong>
            </span>
          </div>

          {/* Integrated Multi-Facet Filter Toolbar */}
          <div className="p-3.5 rounded-xl border border-subtle bg-surface/40 space-y-3">
            <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
              {/* Search Box */}
              <div className="relative flex-1">
                <Search className="w-3.5 h-3.5 text-muted absolute left-2.5 top-2.5" />
                <input
                  type="text"
                  placeholder="Search rules by name, ID, or regex..."
                  value={ruleSearch}
                  onChange={(e) => setRuleSearch(e.target.value)}
                  className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-surface border border-subtle text-xs text-primary focus:outline-none focus:ring-1 focus:ring-accent"
                />
              </div>

              {/* Source Pack Dropdown Filter */}
              <div className="flex items-center gap-2 shrink-0">
                <Filter className="w-3.5 h-3.5 text-muted" />
                <select
                  value={packFilter}
                  onChange={(e) => setPackFilter(e.target.value)}
                  className="px-2.5 py-1.5 rounded-lg bg-surface border border-subtle text-xs text-primary focus:outline-none focus:ring-1 focus:ring-accent cursor-pointer"
                  aria-label="Filter rules by pack"
                >
                  <option value="all">All Packs ({compiled?.effective_rules?.length || 0})</option>
                  {config.pack_ids.map((packId) => {
                    const pack = availablePacks.find((p) => p.id === packId)
                    return (
                      <option key={packId} value={packId}>
                        {pack?.name || packId}
                      </option>
                    )
                  })}
                </select>
              </div>

              {/* Action Filter Pills */}
              <div className="flex items-center gap-1 shrink-0 font-sans">
                {(['all', 'block', 'mask', 'audit'] as const).map((act) => (
                  <button
                    key={act}
                    type="button"
                    onClick={() => setActionFilter(act)}
                    className={`px-2.5 py-1 rounded-lg text-xs font-medium border transition-colors ${
                      actionFilter === act
                        ? 'bg-accent/15 text-accent border-accent/40 font-semibold'
                        : 'bg-surface text-muted border-subtle hover:text-primary'
                    }`}
                  >
                    {act.toUpperCase()}
                  </button>
                ))}
              </div>

              {/* Bypass Toggle Filter */}
              <div className="flex items-center gap-1 shrink-0">
                <button
                  type="button"
                  onClick={() =>
                    setBypassFilter(
                      bypassFilter === 'all'
                        ? 'active'
                        : bypassFilter === 'active'
                        ? 'bypassed'
                        : 'all'
                    )
                  }
                  className={`px-2.5 py-1 rounded-lg text-xs font-medium border transition-colors ${
                    bypassFilter !== 'all'
                      ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/40 font-semibold'
                      : 'bg-surface text-muted border-subtle hover:text-primary'
                  }`}
                >
                  {bypassFilter === 'all'
                    ? 'Status: All'
                    : bypassFilter === 'active'
                    ? 'Status: Active Only'
                    : 'Status: Bypassed Only'}
                </button>
              </div>
            </div>

            <div className="flex items-center justify-between text-[11px] text-muted border-t border-subtle pt-2 font-sans">
              <span>
                Showing <strong className="text-primary font-mono">{filteredRules.length}</strong> matching rules
              </span>
              {(ruleSearch || packFilter !== 'all' || actionFilter !== 'all' || bypassFilter !== 'all') && (
                <button
                  type="button"
                  onClick={() => {
                    setRuleSearch('')
                    setPackFilter('all')
                    setActionFilter('all')
                    setBypassFilter('all')
                  }}
                  className="text-accent hover:underline text-xs"
                >
                  Reset Filters
                </button>
              )}
            </div>
          </div>

          {/* Compiled Rules Data Table */}
          <div className="rounded-xl border border-subtle bg-surface/30 overflow-hidden shadow-xs">
            <div className="max-h-[460px] overflow-y-auto pr-1">
              <table className="w-full text-left border-collapse text-xs font-sans">
                <thead className="sticky top-0 z-20 shadow-xs">
                  <tr className="text-muted font-medium">
                    <th className="p-3 sticky top-0 bg-surface border-b border-subtle z-20">Rule Entity</th>
                    <th className="p-3 sticky top-0 bg-surface border-b border-subtle z-20">Source Pack</th>
                    <th className="p-3 sticky top-0 bg-surface border-b border-subtle z-20">Resolved</th>
                    <th className="p-3 sticky top-0 bg-surface border-b border-subtle z-20">Enforcement Override</th>
                    <th className="p-3 text-right sticky top-0 bg-surface border-b border-subtle z-20">Status / Bypass</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-subtle text-primary">
                  {paginatedRules.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="p-8 text-center text-muted">
                        {compiled?.effective_rules?.length === 0
                          ? 'No rules active. Attach policy packs above to populate the pipeline.'
                          : 'No rules matched the selected filters.'}
                      </td>
                    </tr>
                  ) : (
                    paginatedRules.map((rule) => {
                      const override = config.overrides.find((o) => o.rule_id === rule.rule_id)
                      const isBypassed = override ? !override.enabled : rule.is_bypassed
                      const currentAction = override?.action || rule.effective_action

                      return (
                        <tr
                          key={rule.rule_id}
                          className={`hover:bg-surface/60 transition-colors ${
                            isBypassed ? 'opacity-40 line-through bg-surface/10' : ''
                          }`}
                        >
                          <td className="p-3 font-medium text-primary">
                            <div className="font-bold text-xs">{rule.name}</div>
                            <span className="block text-[11px] text-muted font-mono mt-0.5">
                              {rule.rule_id}
                            </span>
                          </td>

                          <td className="p-3 text-muted text-xs font-mono">
                            {rule.source_pack_ids?.join(', ') || 'custom'}
                          </td>

                          <td className="p-3">
                            <Badge
                              variant={
                                rule.resolved_action === 'block'
                                  ? 'rose'
                                  : rule.resolved_action === 'mask'
                                  ? 'amber'
                                  : 'cyan'
                              }
                              size="sm"
                            >
                              {rule.resolved_action.toUpperCase()}
                            </Badge>
                          </td>

                          <td className="p-3">
                            <select
                              aria-label={`Enforcement action for ${rule.name}`}
                              value={currentAction}
                              onChange={(e) =>
                                handleChangeRuleAction(rule.rule_id, e.target.value as DlpAction)
                              }
                              disabled={isBypassed}
                              className="px-2.5 py-1 rounded-lg bg-surface border border-subtle text-xs font-mono text-primary focus:ring-1 focus:ring-accent focus:outline-none cursor-pointer"
                            >
                              <option value="mask">MASK</option>
                              <option value="block">BLOCK</option>
                              <option value="audit">AUDIT</option>
                            </select>
                          </td>

                          <td className="p-3 text-right">
                            <button
                              type="button"
                              onClick={() => handleToggleRuleBypass(rule.rule_id, isBypassed)}
                              className={`px-3 py-1 rounded-lg text-xs font-bold transition-all shadow-xs ${
                                isBypassed
                                  ? 'bg-rose-500/20 text-rose-700 dark:text-rose-300 border border-rose-500/40'
                                  : 'bg-surface text-primary hover:bg-subtle border border-subtle'
                              }`}
                            >
                              {isBypassed ? 'Bypassed' : 'Active'}
                            </button>
                          </td>
                        </tr>
                      )
                    })
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls Footer */}
            {filteredRules.length > 0 && (
              <div className="flex flex-col sm:flex-row items-center justify-between gap-3 p-3 border-t border-subtle bg-surface/50 text-xs text-muted font-sans">
                <div className="flex items-center gap-2">
                  <span>Show</span>
                  <select
                    value={pageSize}
                    onChange={(e) => setPageSize(Number(e.target.value))}
                    className="px-2 py-0.5 rounded bg-surface border border-subtle text-primary font-mono"
                    aria-label="Rules per page"
                  >
                    <option value={10}>10</option>
                    <option value={25}>25</option>
                    <option value={50}>50</option>
                    <option value={100}>100</option>
                  </select>
                  <span>
                    per page • Showing{' '}
                    <strong className="text-primary font-mono">
                      {(page - 1) * pageSize + 1}-
                      {Math.min(page * pageSize, filteredRules.length)}
                    </strong>{' '}
                    of <strong className="text-primary font-mono">{filteredRules.length}</strong>
                  </span>
                </div>

                <div className="flex items-center gap-1.5">
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => setPage((p) => Math.max(1, p - 1))}
                    disabled={page <= 1}
                    icon={<ChevronLeft className="w-3.5 h-3.5" />}
                  >
                    Previous
                  </Button>
                  <span className="px-2 text-xs font-mono text-primary">
                    Page {page} / {totalPages}
                  </span>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                    disabled={page >= totalPages}
                    icon={<ChevronRight className="w-3.5 h-3.5" />}
                  >
                    Next
                  </Button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* VIEW 2: DIRECTIONAL TOOL DLP EXEMPTIONS */}
      {activeView === 'exemptions' && (
        <div className="space-y-4">
          <div className="p-4 rounded-xl border border-subtle bg-surface/30">
            <span className="font-semibold text-primary flex items-center gap-1.5 text-sm font-sans">
              <Sliders className="w-4 h-4 text-accent" /> Directional Tool DLP Exemptions
            </span>
            <p className="text-xs text-muted font-sans mt-1">
              Selectively isolate tool parameters vs return values. By default, both incoming arguments and outgoing results are inspected for data loss prevention.
            </p>
          </div>

          {availableTools.length > 4 && (
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-muted absolute left-2.5 top-2.5" />
              <input
                type="text"
                placeholder="Filter tools by name or description..."
                value={toolSearch}
                onChange={(e) => setToolSearch(e.target.value)}
                className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-surface border border-subtle text-xs text-primary focus:outline-none focus:ring-1 focus:ring-accent"
              />
            </div>
          )}

          {availableTools.length === 0 ? (
            <p className="text-xs text-muted italic p-6 rounded-xl border border-dashed border-subtle text-center">
              No tools discovered for this agent. Discover tools in General Settings first.
            </p>
          ) : filteredTools.length === 0 ? (
            <div className="p-4 rounded-xl border border-dashed border-subtle text-center text-muted">
              No tools matched &quot;{toolSearch}&quot;.
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5 max-h-[460px] overflow-y-auto pr-1">
              {filteredTools.map((t) => {
                const name = t.canonical_name || t.name
                const exemption = config.tool_exemptions?.[name] || { request: false, response: false }
                const isExternal = isExternalTool(t)
                const hasExemption = exemption.request || exemption.response

                return (
                  <div
                    key={name}
                    className={`p-3.5 rounded-xl border transition-all ${
                      hasExemption
                        ? 'bg-surface border-accent/40 shadow-xs'
                        : 'bg-surface/40 border-subtle hover:border-default'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2 mb-2">
                      <div className="min-w-0">
                        <span className="font-bold text-primary truncate text-xs font-mono block">
                          {name}
                        </span>
                        {t.description && (
                          <p className="text-[11px] text-muted font-sans line-clamp-1 mt-0.5">
                            {t.description}
                          </p>
                        )}
                      </div>
                      <Badge
                        variant={isExternal ? 'amber' : 'cyan'}
                        size="sm"
                        icon={isExternal ? <Globe className="w-2.5 h-2.5" /> : <Lock className="w-2.5 h-2.5" />}
                      >
                        {isExternal ? 'External Egress' : 'Internal Enclave'}
                      </Badge>
                    </div>

                    <div className="flex items-center justify-between pt-2.5 border-t border-subtle text-xs font-sans">
                      <span className="text-muted">Bypass Scanning:</span>
                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={() => handleToggleExemption(name, 'request')}
                          className={`flex items-center gap-1 px-2.5 py-1 rounded-lg border font-mono text-[11px] transition-all ${
                            exemption.request
                              ? 'bg-amber-500/20 text-amber-800 dark:text-amber-300 border-amber-500/50 font-semibold'
                              : 'bg-surface text-muted border-subtle hover:text-primary'
                          }`}
                          title="Bypass DLP scanning for tool invocation arguments"
                          aria-label={`Toggle argument bypass for ${name}`}
                        >
                          <ArrowRight className="w-2.5 h-2.5" />
                          <span>Input (Args)</span>
                        </button>

                        <button
                          type="button"
                          onClick={() => handleToggleExemption(name, 'response')}
                          className={`flex items-center gap-1 px-2.5 py-1 rounded-lg border font-mono text-[11px] transition-all ${
                            exemption.response
                              ? 'bg-rose-500/20 text-rose-800 dark:text-rose-300 border-rose-500/50 font-semibold'
                              : 'bg-surface text-muted border-subtle hover:text-primary'
                          }`}
                          title="Bypass DLP scanning for tool execution output results"
                          aria-label={`Toggle result bypass for ${name}`}
                        >
                          <ArrowLeft className="w-2.5 h-2.5" />
                          <span>Output (Result)</span>
                        </button>
                      </div>
                    </div>

                    {isExternal && exemption.response && (
                      <div className="mt-2.5 p-2 rounded-lg bg-rose-500/10 border border-rose-500/30 text-[10px] text-rose-700 dark:text-rose-300 flex items-center gap-1.5 font-sans">
                        <ShieldAlert className="w-3.5 h-3.5 text-rose-500 shrink-0" />
                        <span>Output exemption on external tool exposes responses to uninspected egress.</span>
                      </div>
                    )}

                    {isExternal && exemption.request && !exemption.response && (
                      <div className="mt-2.5 p-2 rounded-lg bg-amber-500/10 border border-amber-500/30 text-[10px] text-amber-700 dark:text-amber-300 flex items-center gap-1.5 font-sans">
                        <AlertCircle className="w-3.5 h-3.5 text-amber-500 shrink-0" />
                        <span>Input args bypass DLP. Prompt injection could exfiltrate sensitive data.</span>
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          )}
        </div>
      )}

      {/* VIEW 3: AGENT-SCOPED CUSTOM REGEX PATTERNS */}
      {activeView === 'patterns' && (
        <div className="space-y-4">
          <div className="p-4 rounded-xl border border-subtle bg-surface/30">
            <span className="font-semibold text-primary text-sm font-sans block mb-1">
              Custom Agent Regex Patterns
            </span>
            <p className="text-xs text-muted font-sans">
              Add proprietary regex patterns specific to this agent (e.g., internal project IDs or specialized customer tokens).
            </p>
          </div>

          <div className="p-4 rounded-xl border border-subtle bg-surface/40 space-y-3">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
              <input
                type="text"
                placeholder="Pattern Name (e.g. Org Project Code)"
                value={customName}
                onChange={(e) => setCustomName(e.target.value)}
                className="px-3 py-1.5 rounded-lg bg-surface border border-subtle text-xs text-primary placeholder:text-muted focus:ring-1 focus:ring-accent focus:outline-none font-sans"
              />
              <input
                type="text"
                placeholder="Regex (e.g. (?i)PROJ-[0-9]{4})"
                value={customRegex}
                onChange={(e) => setCustomRegex(e.target.value)}
                className="px-3 py-1.5 rounded-lg bg-surface border border-subtle text-xs text-accent placeholder:text-muted focus:ring-1 focus:ring-accent focus:outline-none font-mono"
              />
              <div className="flex items-center gap-2">
                <select
                  aria-label="Custom pattern action"
                  value={customAction}
                  onChange={(e) => setCustomAction(e.target.value as DlpAction)}
                  className="flex-1 px-3 py-1.5 rounded-lg bg-surface border border-subtle text-xs text-primary focus:ring-1 focus:ring-accent focus:outline-none font-mono cursor-pointer"
                >
                  <option value="mask">MASK</option>
                  <option value="block">BLOCK</option>
                  <option value="audit">AUDIT</option>
                </select>
                <Button
                  type="button"
                  variant="primary"
                  size="sm"
                  onClick={handleAddCustomPattern}
                  disabled={!customName.trim() || !customRegex.trim()}
                  icon={<Plus className="w-3.5 h-3.5" />}
                >
                  Add
                </Button>
              </div>
            </div>
          </div>

          {config.custom_patterns.length === 0 ? (
            <div className="p-6 rounded-xl border border-dashed border-subtle text-center text-muted text-xs">
              No custom regex patterns defined for this agent yet.
            </div>
          ) : (
            <div className="space-y-2 max-h-[420px] overflow-y-auto pr-1">
              {config.custom_patterns.map((pat, idx) => (
                <div
                  key={idx}
                  className="flex items-center justify-between p-3 rounded-xl bg-surface/70 border border-subtle text-xs font-sans shadow-xs"
                >
                  <div className="flex items-center gap-3 truncate">
                    <span className="font-bold text-primary">{pat.name}</span>
                    <code className="text-accent font-mono text-xs truncate bg-accent/10 px-2 py-0.5 rounded">
                      {pat.regex}
                    </code>
                    <Badge
                      variant={pat.action === 'block' ? 'rose' : pat.action === 'mask' ? 'amber' : 'cyan'}
                      size="sm"
                    >
                      {pat.action.toUpperCase()}
                    </Badge>
                  </div>
                  <button
                    type="button"
                    aria-label={`Remove custom pattern ${pat.name}`}
                    onClick={() => handleRemoveCustomPattern(idx)}
                    className="p-1 text-muted hover:text-rose-500 transition-colors"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Hidden Save Trigger (invoked via sticky drawer footer) */}
      <button
        id="dlp-save-btn"
        type="button"
        className="hidden"
        onClick={handleSave}
        disabled={isSaving || isLoading}
      />
    </div>
  )
}
