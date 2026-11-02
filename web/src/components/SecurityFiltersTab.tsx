import React, { useState, useEffect } from 'react'
import { Sliders, ShieldCheck, Shield, Lock, Activity, Repeat, UserCheck, FileCheck, CheckCircle2, AlertTriangle } from 'lucide-react'
import { GatewayStatus } from '../types'
import { api } from '../api'

interface SecurityFiltersTabProps {
  status: GatewayStatus | null
  onStatusChange: () => void
}

interface FilterDef {
  key: string
  name: string
  description: string
  icon: React.ComponentType<{ className?: string }>
  badge: string
}

const FILTER_DEFINITIONS: FilterDef[] = [
  {
    key: 'prefill_block',
    name: 'Prefill Attack Mitigation',
    description: 'Blocks unapproved assistant role prefilling injections designed to bypass guardrails.',
    icon: Lock,
    badge: 'LAYER 1 · INGRESS',
  },
  {
    key: 'dlp',
    name: 'Data Loss Prevention (DLP)',
    description: 'Zero-egress scanning that scrubs credentials, SSH keys, bearer tokens, and PII in real-time.',
    icon: ShieldCheck,
    badge: 'LAYER 2 · DLP INTEGRITY',
  },
  {
    key: 'rate_limiting',
    name: 'Ingress Rate Limiting',
    description: 'Token-bucket rate limiting per IP / client token to prevent denial-of-service and runaway costs.',
    icon: Activity,
    badge: 'LAYER 3 · TRAFFIC',
  },
  {
    key: 'loop_protection',
    name: 'Agent Loop Protection',
    description: 'Heuristic cycle detection that intercepts runaway recursive tool invocation loops.',
    icon: Repeat,
    badge: 'LAYER 4 · BEHAVIOR',
  },
  {
    key: 'guard',
    name: 'Semantic Security Guard',
    description: 'Zero-egress offline neural guard (Qwen3Guard-0.6B, Laya MLX, Granite Guardian) with full-duplex L1 cascade and Root Intent Isolation.',
    icon: Shield,
    badge: 'LAYER 5 · SEMANTIC GUARD',
  },
  {
    key: 'hitl',
    name: 'Human-in-the-Loop (HITL)',
    description: 'Requires explicit administrator confirmation before executing critical or destructive tools.',
    icon: UserCheck,
    badge: 'LAYER 6 · GOVERNANCE',
  },
  {
    key: 'schema_validation',
    name: 'Dynamic Schema Validation',
    description: 'Enforces JSON schema adherence against learned baseline shapes for all tool calls.',
    icon: FileCheck,
    badge: 'LAYER 7 · PROTOCOL',
  },
]

const KNOWN_FILTER_KEYS = new Set(FILTER_DEFINITIONS.map((f) => f.key))

export const SecurityFiltersTab: React.FC<SecurityFiltersTabProps> = ({ status, onStatusChange }) => {
  const [toggling, setToggling] = useState<string | null>(null)
  const [notification, setNotification] = useState<{ type: 'success' | 'error'; text: string } | null>(null)

  const isManaged = status?.runtime_mode === 'MANAGED'
  const [localActiveFilters, setLocalActiveFilters] = useState<Set<string>>(
    () => new Set((status?.active_filters || []).filter((k) => KNOWN_FILTER_KEYS.has(k)))
  )

  useEffect(() => {
    if (status?.active_filters) {
      setLocalActiveFilters(
        new Set(status.active_filters.filter((k) => KNOWN_FILTER_KEYS.has(k)))
      )
    }
  }, [status?.active_filters])

  const filterDefinitions = FILTER_DEFINITIONS

  const handleToggle = async (filterKey: string, currentEnabled: boolean) => {
    if (isManaged) {
      setNotification({
        type: 'error',
        text: 'Policy editing is locked: Gateway is running in corporate managed mode.',
      })
      return
    }

    const nextEnabled = !currentEnabled

    // Optimistic UI update: flip state immediately for zero-latency toggle feel
    setLocalActiveFilters((prev) => {
      const next = new Set(prev)
      if (nextEnabled) {
        next.add(filterKey)
      } else {
        next.delete(filterKey)
      }
      return next
    })

    try {
      setToggling(filterKey)
      setNotification(null)
      const res = await api.toggleFilter(filterKey, nextEnabled)
      setNotification({
        type: 'success',
        text: `Filter '${filterKey}' successfully ${res.enabled ? 'enabled' : 'disabled'}.`,
      })
      await onStatusChange()
    } catch (err: unknown) {
      // Rollback optimistic state on failure
      setLocalActiveFilters((prev) => {
        const next = new Set(prev)
        if (currentEnabled) {
          next.add(filterKey)
        } else {
          next.delete(filterKey)
        }
        return next
      })
      const msg = err instanceof Error ? err.message : String(err)
      setNotification({ type: 'error', text: `Failed to toggle ${filterKey}: ${msg}` })
    } finally {
      setToggling(null)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h2 className="text-xl font-bold text-primary flex items-center gap-2">
              <Sliders className="w-5 h-5 text-accent-primary" />
              Zero-Trust Security Filters
            </h2>
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-semibold bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
              {localActiveFilters.size}/7 Active
            </span>
          </div>
          <p className="text-xs text-muted mt-1">
            Toggle individual protection layers active in the FaradAiWire execution pipeline.
          </p>
        </div>

        {isManaged && (
          <div className="px-3 py-1.5 rounded-full text-xs font-semibold bg-amber-500/10 border border-amber-500/30 text-amber-800 dark:text-amber-300">
            Locked (Managed Mode)
          </div>
        )}
      </div>

      {notification && (
        <div
          className={`p-4 rounded-xl border flex items-center justify-between gap-3 text-sm ${
            notification.type === 'success'
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-800 dark:text-emerald-300'
              : 'bg-rose-500/10 border-rose-500/30 text-rose-800 dark:text-rose-300'
          }`}
        >
          <div className="flex items-center gap-2">
            {notification.type === 'success' ? <CheckCircle2 className="w-4 h-4 text-emerald-500" /> : <AlertTriangle className="w-4 h-4 text-rose-500" />}
            <span>{notification.text}</span>
          </div>
          <button onClick={() => setNotification(null)} className="text-xs hover:underline text-muted hover:text-primary">
            Dismiss
          </button>
        </div>
      )}

      {/* Filters Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {filterDefinitions.map((f) => {
          const isEnabled = localActiveFilters.has(f.key)
          const isPending = toggling === f.key
          const Icon = f.icon

          return (
            <div
              key={f.key}
              className={`p-5 rounded-2xl border transition-all bg-surface ${
                isEnabled
                  ? 'border-accent-primary/40 shadow-xs'
                  : 'border-subtle opacity-75'
              }`}
            >
              <div className="flex items-start justify-between gap-4">
                <div className="flex items-start gap-3">
                  <div
                    className={`w-9 h-9 rounded-xl flex items-center justify-center shrink-0 border ${
                      isEnabled
                        ? 'bg-cyan-500/10 border-cyan-500/30 text-accent-primary'
                        : 'bg-surface/50 border-subtle text-muted'
                    }`}
                  >
                    <Icon className="w-4 h-4" />
                  </div>
                  <div>
                    <span className="text-[10px] font-mono font-bold text-muted tracking-wider">
                      {f.badge}
                    </span>
                    <h3 className="font-bold text-sm text-primary">{f.name}</h3>
                    <p className="text-xs text-muted mt-1 leading-relaxed">{f.description}</p>
                  </div>
                </div>

                {/* Switch button */}
                <button
                  type="button"
                  onClick={() => handleToggle(f.key, isEnabled)}
                  disabled={isPending || isManaged}
                  className={`w-12 h-6 rounded-full transition-colors relative shrink-0 p-0.5 focus:outline-none focus:ring-2 focus:ring-accent-primary disabled:opacity-40 ${
                    isEnabled ? 'bg-accent-primary' : 'bg-gray-300 dark:bg-gray-700'
                  }`}
                  title={isEnabled ? 'Click to disable' : 'Click to enable'}
                  aria-label={`Toggle ${f.name}`}
                >
                  <div
                    className={`w-5 h-5 rounded-full bg-white transition-transform ${
                      isEnabled ? 'translate-x-6' : 'translate-x-0'
                    }`}
                  />
                </button>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
