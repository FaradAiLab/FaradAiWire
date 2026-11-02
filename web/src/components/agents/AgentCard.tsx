import React, { useState } from 'react'
import {
  Bot,
  Copy,
  Check,
  Layers,
  Shield,
  Sliders,
  RefreshCw,
  History,
  Trash2,
  Sparkles,
  Repeat,
  AlertTriangle,
} from 'lucide-react'
import { AgentItem } from '../../types'
import { Badge } from '../ui/Badge'

export interface AgentCardProps {
  agent: AgentItem
  ingressHost: string
  ingressPort?: number
  syncing: boolean
  activeFilters?: string[]
  onEdit: (agent: AgentItem) => void
  onSync: (name: string) => void
  onRollback: (name: string) => void
  onDelete: (name: string) => void
  onConnectClient?: (agentName: string) => void
}

export const AgentCard: React.FC<AgentCardProps> = React.memo(
  ({
    agent,
    ingressHost,
    ingressPort = 8090,
    syncing,
    activeFilters = [],
    onEdit,
    onSync,
    onRollback,
    onDelete,
    onConnectClient,
  }) => {
    const [copied, setCopied] = useState(false)

    const effectiveCount = agent.effective_tools?.length ?? agent.tools?.length ?? 0
    const totalCount = agent.tools?.length ?? 0
    const isAggregated = agent.routing_mode === 'aggregated'
    const primaryIngressUrl = isAggregated
      ? `http://${ingressHost}:${ingressPort}/sse/${agent.name}`
      : `http://${ingressHost}:${ingressPort}/sse/${agent.name}/[protocol]`

    const handleCopy = () => {
      navigator.clipboard.writeText(primaryIngressUrl)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }

    return (
      <div className="bg-surface p-6 border border-subtle flex flex-col justify-between rounded-2xl shadow-sm hover:border-accent/40 hover:shadow-md transition-all">
        <div>
          <div className="flex items-start justify-between gap-2 mb-3">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-xl bg-accent/10 border border-accent/20 text-accent">
                <Bot className="w-5 h-5 shrink-0" />
              </div>
              <div>
                <h3 className="font-bold text-base text-primary font-mono">{agent.name}</h3>
                <div className="mt-0.5">
                  <Badge variant="indigo" size="sm">
                    {agent.routing_mode}
                  </Badge>
                </div>
              </div>
            </div>

            <Badge variant="emerald" size="sm">
              Active
            </Badge>
          </div>

          <p className="text-xs text-muted mb-4 line-clamp-2 leading-relaxed">
            {agent.config?.description || 'Autonomous security profile runtime proxy'}
          </p>

          {/* Attached Protocols Tags */}
          <div className="space-y-1.5 mb-4">
            <div className="text-[10px] font-mono text-muted uppercase tracking-wider flex items-center gap-1.5">
              <Layers className="w-3 h-3 text-accent" />
              <span>Attached Tool Sources ({agent.config?.protocols?.length || 0})</span>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {agent.config?.protocols && agent.config.protocols.length > 0 ? (
                agent.config.protocols.map((p) => (
                  <span
                    key={p.id || p.name}
                    className="px-2 py-0.5 rounded-md font-mono text-[10px] bg-canvas border border-subtle text-secondary"
                  >
                    {p.name || p.id}
                  </span>
                ))
              ) : (
                <span className="text-[11px] text-muted italic">No protocols attached</span>
              )}
            </div>
          </div>

          {/* Ingress Route Copy Widget - DUAL-TONE TELEMETRY INVARIANT */}
          <div className="space-y-1.5 mb-4">
            <div className="text-[10px] font-mono text-muted uppercase tracking-wider flex items-center justify-between">
              <span>Ingress Endpoint (:8090)</span>
              {copied && (
                <span className="text-emerald-600 dark:text-emerald-400 text-[10px] flex items-center gap-1 font-mono font-bold">
                  <Check className="w-3 h-3" /> Copied!
                </span>
              )}
            </div>
            <div className="flex items-center justify-between p-2 rounded-xl bg-[#0F172A] border border-[#1E293B] font-mono text-[11px] text-cyan-300 shadow-inner">
              <span className="truncate pr-2">{primaryIngressUrl}</span>
              <button
                type="button"
                onClick={handleCopy}
                className="p-1 rounded text-slate-400 hover:text-cyan-300 transition-colors shrink-0 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-accent"
                title="Copy Ingress URL"
                aria-label="Copy Ingress URL"
              >
                <Copy className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* Tool Scoping Status */}
          <div className="p-3 bg-canvas rounded-xl border border-subtle space-y-1 text-xs font-mono shadow-xs">
            <div className="flex items-center justify-between text-muted text-[11px]">
              <span>Layer 2 Scoped Tools:</span>
              <span className="text-accent font-bold">
                {effectiveCount} / {totalCount}
              </span>
            </div>
            {agent.config?.enabled_tools && agent.config.enabled_tools.length > 0 ? (
              <div className="text-[10px] text-emerald-600 dark:text-emerald-400 pt-1 border-t border-subtle flex items-center gap-1 font-medium">
                <Shield className="w-3 h-3" />
                Least-Privilege Scoping Active
              </div>
            ) : (
              <div className="text-[10px] text-muted pt-1 border-t border-subtle">
                All protocol tools permitted
              </div>
            )}

            {agent.config?.loop_protection && (
              <div className="text-[10px] pt-1 border-t border-subtle flex items-center justify-between">
                <span className="text-muted">Loop Safeguard:</span>
                {agent.config.loop_protection.enabled ? (
                  activeFilters.includes('loop_protection') ? (
                    <span className="text-emerald-800 dark:text-emerald-300 font-semibold flex items-center gap-1 font-mono">
                      <Repeat className="w-3 h-3 text-emerald-500" /> Active ({agent.config.loop_protection.max_repeat}x)
                    </span>
                  ) : (
                    <span className="text-amber-800 dark:text-amber-300 font-semibold flex items-center gap-1 font-mono" title="Cluster Master Killswitch is OFF in Gateway Settings">
                      <AlertTriangle className="w-3 h-3 text-amber-500" /> Suspended
                    </span>
                  )
                ) : (
                  <span className="text-muted font-mono">Bypassed</span>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Card Action Buttons */}
        <div className="mt-5 pt-4 border-t border-subtle flex items-center justify-between gap-2">
          <div className="flex items-center gap-1.5">
            {onConnectClient && (
              <button
                type="button"
                onClick={() => onConnectClient(agent.name)}
                className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-accent/15 hover:bg-accent/25 border border-accent/30 text-[11px] font-mono text-accent transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-accent shadow-xs"
                title="Connect MCP Client (Claude, Cursor, Windsurf)"
              >
                <Sparkles className="w-3 h-3 text-accent" />
                <span>Connect</span>
              </button>
            )}

            <button
              type="button"
              onClick={() => onEdit(agent)}
              className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-surface hover:bg-subtle border border-subtle text-[11px] font-mono text-primary transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-accent shadow-xs"
              title="Edit Profile Routing & Tools"
            >
              <Sliders className="w-3 h-3 text-accent" />
              <span>Edit</span>
            </button>

            <button
              type="button"
              onClick={() => onSync(agent.name)}
              disabled={syncing}
              className="p-1.5 rounded-lg text-muted hover:text-accent hover:bg-accent/10 transition-colors disabled:opacity-50 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-accent shadow-xs border border-subtle"
              title="Probe & Sync Tools"
              aria-label="Probe and Sync Tools"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${syncing ? 'animate-spin text-accent' : ''}`} />
            </button>

            <button
              type="button"
              onClick={() => onRollback(agent.name)}
              className="p-1.5 rounded-lg text-muted hover:text-amber-600 dark:hover:text-amber-400 hover:bg-amber-50 dark:hover:bg-amber-500/10 transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-amber-500 shadow-xs border border-subtle"
              title="Snapshot Rollback History"
              aria-label="Snapshot Rollback History"
            >
              <History className="w-3.5 h-3.5" />
            </button>
          </div>

          <button
            type="button"
            onClick={() => onDelete(agent.name)}
            className="p-1.5 rounded-lg text-muted hover:text-rose-600 dark:hover:text-rose-400 hover:bg-rose-50 dark:hover:bg-rose-500/10 transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-rose-500 shadow-xs border border-subtle"
            title="Delete Profile"
            aria-label="Delete Profile"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    )
  }
)

AgentCard.displayName = 'AgentCard'
