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
    badgeVariant: 'emerald' | 'rose' | 'amber' | 'indigo'
    borderClass: string
    badgeClass: string
    icon: React.ReactNode
    shortDesc: string
  }
> = {
  autonomous: {
    label: 'Autonomous (Fast-Path)',
    badgeVariant: 'emerald',
    borderClass: 'border-emerald-500/20 bg-emerald-950/10',
    badgeClass: 'text-emerald-400 bg-emerald-950/40 border-emerald-500/30',
    icon: <Zap className="w-3 h-3 text-emerald-400" />,
    shortDesc: 'Bypasses Semantic Security Guard neural inspection and HITL gates (<0.2ms latency).',
  },
  guarded_block: {
    label: 'Guarded Auto-Block',
    badgeVariant: 'rose',
    borderClass: 'border-rose-500/20 bg-rose-950/10',
    badgeClass: 'text-rose-400 bg-rose-950/40 border-rose-500/30',
    icon: <ShieldAlert className="w-3 h-3 text-rose-400" />,
    shortDesc: 'Semantic Security Guard inspects every call; detected threats are automatically blocked (-32004).',
  },
  guarded_hitl: {
    label: 'Guarded HITL (Escalate)',
    badgeVariant: 'amber',
    borderClass: 'border-amber-500/20 bg-amber-950/10',
    badgeClass: 'text-amber-400 bg-amber-950/40 border-amber-500/30',
    icon: <UserCheck className="w-3 h-3 text-amber-400" />,
    shortDesc: 'Semantic Security Guard inspects every call; detected threats escalate to operator for approval.',
  },
  strict_always_hitl: {
    label: 'Strict Always HITL',
    badgeVariant: 'indigo',
    borderClass: 'border-indigo-500/20 bg-indigo-950/10',
    badgeClass: 'text-indigo-400 bg-indigo-950/40 border-indigo-500/30',
    icon: <Lock className="w-3 h-3 text-indigo-400" />,
    shortDesc: 'Mandatory operator confirmation before every call (unconditional dual-channel gate).',
  },
}

export const SecurityGuardrailsTab: React.FC<SecurityGuardrailsTabProps> = ({
  availableTools,
  toolGovernance,
  onChangeGovernance,
  onApplyRecommendedDefaults,
  routingMode,
}) => {
  const [slmRunning, setSlmRunning] = useState<boolean | null>(null)
  const [filterQuery, setFilterQuery] = useState('')

  useEffect(() => {
    let mounted = true
    api
      .getGuardStatus()
      .then((status) => {
        if (mounted) setSlmRunning(Boolean(status?.running))
      })
      .catch(() => {
        if (mounted) setSlmRunning(false)
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
    <div className="space-y-6 text-xs font-sans">
      {/* SLM Offline Warning Banner (Graceful Degradation Notice) */}
      {slmRunning === false && (
        <div className="p-3.5 rounded-xl bg-amber-950/30 border border-amber-500/30 text-amber-300 text-xs flex items-start gap-3">
          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <div className="font-bold flex items-center gap-2">
              <span>Semantic Security Guard is in Standby</span>
              <span className="text-[9px] px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 font-mono">
                L1 Fallback Active
              </span>
            </div>
            <p className="text-[11px] text-amber-200/80 leading-relaxed font-sans">
              Tools configured as <code className="text-amber-300 font-mono">Guarded Auto-Block</code>{' '}
              or <code className="text-amber-300 font-mono">Guarded HITL</code> will gracefully
              degrade to L1-Only regex pass-through to prevent alert fatigue. Tools set to{' '}
              <code className="text-amber-300 font-mono">Strict Always HITL</code> continue to prompt
              for human approval unconditionally.
            </p>
          </div>
        </div>
      )}

      {/* Tool Governance Matrix Section */}
      <div className="space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <span className="font-semibold text-primary flex items-center gap-1.5 text-sm">
              <Shield className="w-4 h-4 text-accent" /> Tool Governance & HITL Action Matrix
            </span>
            <p className="text-[11px] text-muted font-sans mt-0.5">
              Define per-tool operational security, neural inspection, and human approval gates.
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
            <span>Autonomous ({stats.autonomous})</span>
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
            <span>Guarded HITL ({stats.guarded_hitl})</span>
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
            <span>Guarded Block ({stats.guarded_block})</span>
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
            <span>Strict HITL ({stats.strict_always_hitl})</span>
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

        {/* Tools List - Clean Flowing Container (No Nested Scroll) */}
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
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
                    {/* Left: Tool info & Boundary Badge */}
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-bold text-primary text-xs truncate">
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
                        <p className="text-[11px] text-muted font-sans line-clamp-1 mt-0.5">
                          {t.description}
                        </p>
                      )}
                    </div>

                    {/* Right: Governance Dropdown */}
                    <div className="flex items-center gap-2 shrink-0">
                      <label htmlFor={`gov-mode-${toolName}`} className="sr-only">
                        Governance Mode for {toolName}
                      </label>
                      <select
                        id={`gov-mode-${toolName}`}
                        value={currentMode}
                        onChange={(e) =>
                          onChangeGovernance(
                            toolName,
                            e.target.value as ToolGovernanceMode
                          )
                        }
                        className="px-2.5 py-1.5 rounded-lg bg-surface border border-subtle text-xs font-mono text-primary focus:outline-none focus:ring-1 focus:ring-accent cursor-pointer"
                      >
                        <option value="autonomous">⚡ Autonomous (Fast-Path)</option>
                        <option value="guarded_block">🛡️ Guarded Auto-Block</option>
                        <option value="guarded_hitl">👤 Guarded HITL (Escalate)</option>
                        <option value="strict_always_hitl">🚨 Strict Always HITL</option>
                      </select>
                    </div>
                  </div>

                  {/* Mode explanation footer */}
                  <div className="mt-2 pt-2 border-t border-subtle flex items-center justify-between text-[10px] text-muted font-sans">
                    <span className="line-clamp-1">{modeCfg.shortDesc}</span>
                    <span className="hidden sm:inline font-mono shrink-0 text-muted pl-2">
                      mode: {currentMode}
                    </span>
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
