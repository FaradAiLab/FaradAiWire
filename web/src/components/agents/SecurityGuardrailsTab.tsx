import React, { useEffect, useState } from 'react'
import { ToolMetadata, ToolGovernanceMode } from '../../types'
import { Badge } from '../ui/Badge'
import { Button } from '../ui/Button'
import { api } from '../../api'
import {
  Shield,
  ShieldAlert,
  AlertTriangle,
  Zap,
  UserCheck,
  Lock,
  Globe,
  Sparkles,
  Search,
} from 'lucide-react'

export interface SecurityGuardrailsTabProps {
  availableTools: ToolMetadata[]
  toolGovernance: Record<string, ToolGovernanceMode>
  onChangeGovernance: (toolName: string, mode: ToolGovernanceMode) => void
  onApplyRecommendedDefaults: (defaults: Record<string, ToolGovernanceMode>) => void
  routingMode: 'aggregated' | 'direct'
}

export const isExternalEgress = (tool: ToolMetadata): boolean => {
  const name = (tool.canonical_name || tool.name || '').toLowerCase()
  const proto = (tool.protocol_id || tool.protocol_name || '').toLowerCase()
  const desc = (tool.description || '').toLowerCase()

  const egressKeywords = [
    'search',
    'tavily',
    'brave',
    'google',
    'web',
    'fetch',
    'http',
    'curl',
    'browser',
    'scrape',
    'slack',
    'mail',
    'smtp',
    'webhook',
    'external',
    'download',
    'upload',
    'rest',
    'api',
  ]
  return egressKeywords.some(
    (kw) => name.includes(kw) || proto.includes(kw) || desc.includes(kw)
  )
}

export const isDestructiveTool = (tool: ToolMetadata): boolean => {
  const name = (tool.canonical_name || tool.name || '').toLowerCase()
  const desc = (tool.description || '').toLowerCase()
  const destructiveKeywords = [
    'exec',
    'bash',
    'cmd',
    'command',
    'delete',
    'drop',
    'format',
    'kill',
    'rm',
    'destroy',
    'truncate',
    'terminate',
  ]
  return destructiveKeywords.some((kw) => name.includes(kw) || desc.includes(kw))
}

export const getRecommendedMode = (tool: ToolMetadata): ToolGovernanceMode => {
  if (isDestructiveTool(tool)) {
    return 'guarded_block'
  }
  if (isExternalEgress(tool)) {
    return 'guarded_hitl'
  }
  return 'autonomous'
}

const MODE_CONFIGS: Record<
  ToolGovernanceMode,
  {
    label: string
    stageLabel: string
    badgeVariant: 'emerald' | 'rose' | 'amber' | 'indigo'
    borderClass: string
    stageClass: string
    icon: React.ReactNode
    shortDesc: string
  }
> = {
  autonomous: {
    label: 'Bypass AI Guard (Fast-Path)',
    stageLabel: 'AI Guard: Off',
    badgeVariant: 'emerald',
    borderClass: 'border-emerald-500/20 bg-emerald-950/5',
    stageClass: 'text-emerald-600 dark:text-emerald-400 bg-emerald-500/10 border-emerald-500/25',
    icon: <Zap className="w-3 h-3 text-emerald-500" />,
    shortDesc: 'Skips AI Guard inspection and executes immediately (<0.2ms L1 fast-path).',
  },
  guarded_block: {
    label: 'AI Guard ➔ Auto-Block',
    stageLabel: 'AI Guard: Active',
    badgeVariant: 'rose',
    borderClass: 'border-rose-500/20 bg-rose-950/5',
    stageClass: 'text-rose-600 dark:text-rose-400 bg-rose-500/10 border-rose-500/25',
    icon: <ShieldAlert className="w-3 h-3 text-rose-500" />,
    shortDesc: 'AI Guard inspects every call; detected threats are automatically blocked (-32004).',
  },
  guarded_hitl: {
    label: 'AI Guard ➔ Ask Human',
    stageLabel: 'AI Guard: Active',
    badgeVariant: 'amber',
    borderClass: 'border-amber-500/20 bg-amber-950/5',
    stageClass: 'text-amber-600 dark:text-amber-400 bg-amber-500/10 border-amber-500/25',
    icon: <UserCheck className="w-3 h-3 text-amber-500" />,
    shortDesc: 'AI Guard inspects every call; detected threats pause and request human approval.',
  },
  strict_always_hitl: {
    label: 'Always Ask Human (Strict HITL)',
    stageLabel: 'Manual Gate',
    badgeVariant: 'indigo',
    borderClass: 'border-indigo-500/20 bg-indigo-950/5',
    stageClass: 'text-indigo-600 dark:text-indigo-400 bg-indigo-500/10 border-indigo-500/25',
    icon: <Lock className="w-3 h-3 text-indigo-500" />,
    shortDesc: 'Requires explicit operator confirmation before every execution regardless of AI Guard.',
  },
}

export const SecurityGuardrailsTab: React.FC<SecurityGuardrailsTabProps> = ({
  availableTools,
  toolGovernance,
  onChangeGovernance,
  onApplyRecommendedDefaults,
  routingMode,
}) => {
  const [guardRunning, setGuardRunning] = useState<boolean | null>(null)
  const [activeModelName, setActiveModelName] = useState<string>('')
  const [filterQuery, setFilterQuery] = useState('')

  useEffect(() => {
    let mounted = true
    Promise.all([
      api.getGuardStatus().catch(() => null),
      api.getGuardModels().catch(() => ({ models: [] })),
    ]).then(([status, catalog]) => {
      if (!mounted) return
      setGuardRunning(Boolean(status?.running))
      const active = catalog?.models?.find((m) => m.is_active)
      if (active?.name) {
        setActiveModelName(active.name)
      } else if (status?.model_id) {
        setActiveModelName(status.model_id)
      }
    })
    return () => {
      mounted = false
    }
  }, [])

  // Resolve tool display name according to routing mode
  const getToolDisplayName = (t: ToolMetadata): string => {
    return routingMode === 'direct'
      ? t.raw_name || t.name
      : t.canonical_name || t.name
  }

  // Count stats
  const stats: Record<ToolGovernanceMode, number> = {
    autonomous: 0,
    guarded_block: 0,
    guarded_hitl: 0,
    strict_always_hitl: 0,
  }

  availableTools.forEach((t) => {
    const key = getToolDisplayName(t)
    const mode = toolGovernance[key] || getRecommendedMode(t)
    if (stats[mode] !== undefined) {
      stats[mode]++
    }
  })

  const [modeFilter, setModeFilter] = useState<ToolGovernanceMode | 'all'>('all')

  // Filter tools by search query and mode filter
  const filteredTools = availableTools.filter((t) => {
    const toolName = getToolDisplayName(t)
    const currentMode = toolGovernance[toolName] || getRecommendedMode(t)
    if (modeFilter !== 'all' && currentMode !== modeFilter) return false

    if (!filterQuery.trim()) return true
    const q = filterQuery.toLowerCase()
    const name = toolName.toLowerCase()
    const desc = (t.description || '').toLowerCase()
    return name.includes(q) || desc.includes(q)
  })

  const handleApplyDefaults = () => {
    const defaults: Record<string, ToolGovernanceMode> = {}
    availableTools.forEach((t) => {
      const key = getToolDisplayName(t)
      defaults[key] = getRecommendedMode(t)
    })
    onApplyRecommendedDefaults(defaults)
  }

  return (
    <div className="space-y-5 text-xs font-sans">
      {/* Active AI Guard Status Context Bar */}
      {guardRunning === true ? (
        <div className="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/25 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2.5 min-w-0">
            <Shield className="w-4 h-4 text-emerald-500 shrink-0" />
            <div className="min-w-0">
              <div className="font-semibold text-primary flex items-center gap-2 flex-wrap">
                <span>AI Guard Engine: {activeModelName || 'Online'}</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-600 dark:text-emerald-300 font-mono">
                  Active Inspection
                </span>
              </div>
              <p className="text-[11px] text-muted mt-0.5 truncate">
                Evaluating tool arguments and responses in real time. Select how AI Guard acts when a threat is detected below.
              </p>
            </div>
          </div>
        </div>
      ) : guardRunning === false ? (
        <div className="p-3.5 rounded-xl bg-amber-950/30 border border-amber-500/30 text-amber-300 text-xs flex items-start gap-3">
          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <div className="font-bold flex items-center gap-2">
              <span>AI Guard is in Standby</span>
              <span className="text-[9px] px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 font-mono">
                L1 Fallback Active
              </span>
            </div>
            <p className="text-[11px] text-amber-200/80 leading-relaxed font-sans">
              Tools set to <code className="text-amber-300 font-mono">AI Guard ➔ Auto-Block</code>{' '}
              or <code className="text-amber-300 font-mono">AI Guard ➔ Ask Human</code> gracefully
              fall back to L1 regex checks until an AI Guard model is activated.{' '}
              <code className="text-amber-300 font-mono">Always Ask Human</code> remains enforced.
            </p>
          </div>
        </div>
      ) : null}

      {/* AI Guard & Threat Actions Matrix Section */}
      <div className="space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <span className="font-semibold text-primary flex items-center gap-1.5 text-sm">
              <Shield className="w-4 h-4 text-accent" /> AI Guard & Threat Actions
            </span>
            <p className="text-[11px] text-muted font-sans mt-0.5">
              Choose which tools are inspected by AI Guard and whether threats are auto-blocked or escalated for human approval.
            </p>
          </div>

          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={handleApplyDefaults}
            disabled={availableTools.length === 0}
            icon={<Sparkles className="w-3.5 h-3.5 text-accent" />}
            className="shrink-0 text-accent border-accent/30 hover:bg-accent/10"
          >
            Apply Recommended Defaults
          </Button>
        </div>

        {/* Interactive Stats Filter Chips */}
        <div className="flex flex-wrap items-center gap-2 pt-1 font-sans">
          <button
            type="button"
            onClick={() => setModeFilter('all')}
            className={`px-2.5 py-1 rounded-lg text-xs font-medium border transition-colors ${
              modeFilter === 'all'
                ? 'bg-accent/15 text-accent border-accent/40 font-semibold'
                : 'bg-surface text-muted border-subtle hover:text-primary'
            }`}
          >
            All Tools ({availableTools.length})
          </button>
          <button
            type="button"
            onClick={() => setModeFilter(modeFilter === 'autonomous' ? 'all' : 'autonomous')}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium border transition-colors ${
              modeFilter === 'autonomous'
                ? 'bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border-emerald-500/50 font-semibold'
                : 'bg-surface text-muted border-subtle hover:text-primary'
            }`}
          >
            <Zap className="w-3 h-3 text-emerald-500" />
            <span>Bypass AI Guard ({stats.autonomous})</span>
          </button>
          <button
            type="button"
            onClick={() => setModeFilter(modeFilter === 'guarded_hitl' ? 'all' : 'guarded_hitl')}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium border transition-colors ${
              modeFilter === 'guarded_hitl'
                ? 'bg-amber-500/20 text-amber-700 dark:text-amber-300 border-amber-500/50 font-semibold'
                : 'bg-surface text-muted border-subtle hover:text-primary'
            }`}
          >
            <UserCheck className="w-3 h-3 text-amber-500" />
            <span>AI Guard ➔ Ask Human ({stats.guarded_hitl})</span>
          </button>
          <button
            type="button"
            onClick={() => setModeFilter(modeFilter === 'guarded_block' ? 'all' : 'guarded_block')}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium border transition-colors ${
              modeFilter === 'guarded_block'
                ? 'bg-rose-500/20 text-rose-700 dark:text-rose-300 border-rose-500/50 font-semibold'
                : 'bg-surface text-muted border-subtle hover:text-primary'
            }`}
          >
            <ShieldAlert className="w-3 h-3 text-rose-500" />
            <span>AI Guard ➔ Auto-Block ({stats.guarded_block})</span>
          </button>
          <button
            type="button"
            onClick={() => setModeFilter(modeFilter === 'strict_always_hitl' ? 'all' : 'strict_always_hitl')}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium border transition-colors ${
              modeFilter === 'strict_always_hitl'
                ? 'bg-indigo-500/20 text-indigo-700 dark:text-indigo-300 border-indigo-500/50 font-semibold'
                : 'bg-surface text-muted border-subtle hover:text-primary'
            }`}
          >
            <Lock className="w-3 h-3 text-indigo-500" />
            <span>Always Ask Human ({stats.strict_always_hitl})</span>
          </button>
        </div>

        {/* Search Bar if > 4 tools */}
        {availableTools.length > 4 && (
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-muted absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Filter tools by name or description..."
              value={filterQuery}
              onChange={(e) => setFilterQuery(e.target.value)}
              className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-surface border border-subtle text-xs text-primary focus:outline-none focus:ring-1 focus:ring-accent"
            />
          </div>
        )}

        {/* Tools List */}
        {availableTools.length === 0 ? (
          <div className="p-6 rounded-xl border border-dashed border-subtle text-center text-muted">
            Select protocols and click &quot;Query Tools&quot; in General Settings to populate and configure tools.
          </div>
        ) : filteredTools.length === 0 ? (
          <div className="p-4 rounded-xl border border-dashed border-subtle text-center text-muted">
            No tools matched the current filters.
          </div>
        ) : (
          <div className="space-y-2.5 max-h-[480px] overflow-y-auto pr-1.5">
            {filteredTools.map((t) => {
              const toolName = getToolDisplayName(t)
              const isEgress = isExternalEgress(t)
              const currentMode = toolGovernance[toolName] || getRecommendedMode(t)
              const modeCfg = MODE_CONFIGS[currentMode] || MODE_CONFIGS.autonomous

              return (
                <div
                  key={toolName}
                  className={`p-3.5 rounded-xl border bg-surface/40 transition-all ${modeCfg.borderClass} hover:border-accent/40 shadow-xs`}
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    {/* Left: Tool info & Boundary Badge */}
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-bold text-primary text-xs font-mono truncate">
                          {toolName}
                        </span>
                        {isEgress ? (
                          <Badge
                            variant="amber"
                            size="sm"
                            icon={<Globe className="w-2.5 h-2.5" />}
                          >
                            External Egress
                          </Badge>
                        ) : (
                          <Badge
                            variant="cyan"
                            size="sm"
                            icon={<Shield className="w-2.5 h-2.5" />}
                          >
                            Internal Enclave
                          </Badge>
                        )}
                        {t.protocol_id && (
                          <span className="text-[10px] text-muted font-mono">
                            ({t.protocol_id})
                          </span>
                        )}
                      </div>

                      {t.description && (
                        <p className="text-[11px] text-muted font-sans line-clamp-1 mt-1">
                          {t.description}
                        </p>
                      )}
                    </div>

                    {/* Right: AI Guard Stage Indicator + Action Dropdown */}
                    <div className="flex items-center gap-2 shrink-0">
                      <span
                        className={`hidden md:inline-flex items-center gap-1 px-2 py-1 rounded-md border text-[10px] font-semibold ${modeCfg.stageClass}`}
                        title={modeCfg.shortDesc}
                      >
                        {modeCfg.icon}
                        <span>{modeCfg.stageLabel}</span>
                      </span>
                      <label htmlFor={`gov-mode-${toolName}`} className="sr-only">
                        AI Guard Action for {toolName}
                      </label>
                      <select
                        id={`gov-mode-${toolName}`}
                        value={currentMode}
                        title={modeCfg.shortDesc}
                        onChange={(e) =>
                          onChangeGovernance(
                            toolName,
                            e.target.value as ToolGovernanceMode
                          )
                        }
                        className="px-2.5 py-1.5 rounded-lg bg-surface border border-subtle text-xs font-medium text-primary focus:outline-none focus:ring-1 focus:ring-accent cursor-pointer"
                      >
                        <option value="autonomous">⚡ Bypass AI Guard (Fast-Path)</option>
                        <option value="guarded_block">🛡️ AI Guard ➔ Auto-Block</option>
                        <option value="guarded_hitl">🙋 AI Guard ➔ Ask Human</option>
                        <option value="strict_always_hitl">🔒 Always Ask Human (Strict HITL)</option>
                      </select>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}
