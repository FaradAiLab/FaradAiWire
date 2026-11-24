import React, { useState, useEffect, useCallback } from 'react'
import { ChevronLeft, ChevronRight, KeyRound } from 'lucide-react'
import type { SecurityAuditRecord } from '../../types'
import { api } from '../../api'
import { PAGE_SIZE, formatSmartDate, toRFC3339LocalInput } from './formatters'

interface SecurityEventsPanelProps {
  refreshSignal: number
  onError: (msg: string | null) => void
}

export const SecurityEventsPanel: React.FC<SecurityEventsPanelProps> = ({
  refreshSignal,
  onError,
}) => {
  const [events, setEvents] = useState<SecurityAuditRecord[]>([])
  const [total, setTotal] = useState(0)
  const [offset, setOffset] = useState(0)
  const [eventType, setEventType] = useState('')
  const [actorID, setActorID] = useState('')
  const [outcome, setOutcome] = useState('')
  const [sinceInput, setSinceInput] = useState('')
  const [untilInput, setUntilInput] = useState('')
  const [loading, setLoading] = useState(false)

  const fetchSecurityEvents = useCallback(
    (signal?: AbortSignal) => {
      setLoading(true)
      onError(null)
      api
        .getSecurityAuditLogs(
          {
            limit: PAGE_SIZE,
            offset,
            event_type: eventType.trim() || undefined,
            actor_id: actorID.trim() || undefined,
            outcome: outcome || undefined,
            since: toRFC3339LocalInput(sinceInput),
            until: toRFC3339LocalInput(untilInput),
          },
          signal
        )
        .then((res) => {
          if (signal?.aborted) return
          setEvents(Array.isArray(res?.events) ? res.events : [])
          setTotal(typeof res?.total === 'number' ? res.total : 0)
        })
        .catch((err: unknown) => {
          if (signal?.aborted || (err instanceof Error && err.name === 'AbortError')) return
          setEvents([])
          onError(err instanceof Error ? err.message : 'Failed to query security audit events')
        })
        .finally(() => {
          if (!signal?.aborted) setLoading(false)
        })
    },
    [offset, eventType, actorID, outcome, sinceInput, untilInput, onError]
  )

  useEffect(() => {
    const controller = new AbortController()
    const timer = window.setTimeout(() => {
      fetchSecurityEvents(controller.signal)
    }, 150)
    return () => {
      window.clearTimeout(timer)
      controller.abort()
    }
  }, [fetchSecurityEvents, refreshSignal])

  return (
    <div id="audit-panel-security" role="tabpanel" aria-labelledby="audit-tab-security" className="space-y-4">
      <div className="flex flex-wrap items-center gap-3 bg-surface p-3 rounded-xl border border-subtle shadow-sm">
        <input
          type="text"
          aria-label="Filter security events by event type"
          placeholder="Event type (e.g. admin_auth_failed)"
          value={eventType}
          onChange={(e) => {
            setOffset(0)
            setEventType(e.target.value)
          }}
          className="flex-1 min-w-[200px] px-3 py-1.5 rounded-lg bg-canvas border border-subtle text-xs text-primary placeholder:text-muted focus:outline-none focus:border-accent focus-visible:ring-2 focus-visible:ring-accent/40 font-mono"
        />
        <input
          type="text"
          aria-label="Filter security events by actor ID"
          placeholder="Actor ID (e.g. local-operator)"
          value={actorID}
          onChange={(e) => {
            setOffset(0)
            setActorID(e.target.value)
          }}
          className="w-48 px-3 py-1.5 rounded-lg bg-canvas border border-subtle text-xs text-primary placeholder:text-muted focus:outline-none focus:border-accent focus-visible:ring-2 focus-visible:ring-accent/40 font-mono"
        />
        <select
          aria-label="Filter security events by outcome"
          value={outcome}
          onChange={(e) => {
            setOffset(0)
            setOutcome(e.target.value)
          }}
          className="px-3 py-1.5 rounded-lg bg-canvas border border-subtle text-xs text-primary focus:outline-none focus:border-accent focus-visible:ring-2 focus-visible:ring-accent/40 font-mono"
        >
          <option value="">Outcome: All</option>
          <option value="allowed">allowed</option>
          <option value="denied">denied</option>
          <option value="locked">locked</option>
        </select>
        <div className="flex items-center gap-1.5">
          <label htmlFor="sec-since" className="text-[11px] font-medium text-secondary">
            From
          </label>
          <input
            id="sec-since"
            type="datetime-local"
            value={sinceInput}
            onChange={(e) => {
              setOffset(0)
              setSinceInput(e.target.value)
            }}
            className="px-2.5 py-1.5 rounded-lg bg-canvas border border-subtle text-xs text-primary font-mono"
          />
        </div>
        <div className="flex items-center gap-1.5">
          <label htmlFor="sec-until" className="text-[11px] font-medium text-secondary">
            To
          </label>
          <input
            id="sec-until"
            type="datetime-local"
            value={untilInput}
            onChange={(e) => {
              setOffset(0)
              setUntilInput(e.target.value)
            }}
            className="px-2.5 py-1.5 rounded-lg bg-canvas border border-subtle text-xs text-primary font-mono"
          />
        </div>
      </div>

      <div className="bg-surface rounded-2xl border border-subtle shadow-sm flex flex-col h-[calc(100vh-300px)] min-h-[420px] max-h-[720px] overflow-hidden">
        <div className="flex-1 overflow-y-auto p-3 space-y-2" aria-busy={loading}>
          {loading ? (
            <div className="space-y-2.5">
              {Array.from({ length: 5 }).map((_, idx) => (
                <div
                  key={idx}
                  className="h-14 rounded-xl border border-subtle bg-canvas/70 animate-pulse motion-reduce:animate-none"
                />
              ))}
            </div>
          ) : events.length === 0 ? (
            <div className="h-full min-h-[240px] flex flex-col items-center justify-center text-secondary gap-2">
              <KeyRound className="w-8 h-8 text-muted" />
              <span className="text-xs">No control-plane security events found.</span>
            </div>
          ) : (
            events.map((sev) => {
              const outcomeLower = (sev.outcome || '').toLowerCase()
              const outcomeBadge =
                outcomeLower === 'allowed'
                  ? 'bg-emerald-50 text-emerald-800 border-emerald-300 dark:bg-emerald-950/60 dark:text-emerald-200 dark:border-emerald-700/50'
                  : outcomeLower === 'locked'
                  ? 'bg-amber-50 text-amber-900 border-amber-300 dark:bg-amber-950/60 dark:text-amber-200 dark:border-amber-700/50'
                  : 'bg-rose-50 text-rose-800 border-rose-300 dark:bg-rose-950/60 dark:text-rose-200 dark:border-rose-700/50'

              return (
                <div
                  key={sev.id}
                  className="p-3 rounded-xl border border-subtle bg-canvas/70 hover:bg-surface-elevated/60 transition-colors text-xs space-y-1.5"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`px-2 py-0.5 rounded font-mono text-[11px] font-bold uppercase border ${outcomeBadge}`}>
                        {sev.outcome}
                      </span>
                      <span className="font-mono font-bold text-primary">{sev.event_type}</span>
                      <span className="text-secondary font-mono">action={sev.action}</span>
                      {sev.resource_type && (
                        <span className="px-1.5 py-0.5 rounded bg-surface border border-subtle text-[11px] font-mono text-primary">
                          {sev.resource_type}
                          {sev.resource_id ? `:${sev.resource_id}` : ''}
                        </span>
                      )}
                    </div>
                    <span className="text-[11px] font-mono tabular-nums text-muted">
                      {formatSmartDate(sev.timestamp).display}
                    </span>
                  </div>

                  <div className="flex flex-wrap items-center gap-4 text-[11px] font-mono text-secondary">
                    <span>
                      actor=<strong className="text-primary">{sev.actor_id}</strong> ({sev.actor_role})
                    </span>
                    {sev.client_ip && <span>ip={sev.client_ip}</span>}
                    {sev.reason && <span>reason={sev.reason}</span>}
                    {sev.trace_id && <span>trace={sev.trace_id}</span>}
                    {sev.hash_version && <span>hash={sev.hash_version}</span>}
                  </div>
                </div>
              )
            })
          )}
        </div>

        <div className="shrink-0 flex items-center justify-between text-xs font-mono tabular-nums text-secondary bg-canvas/80 px-4 py-2.5 border-t border-subtle">
          <span>
            Showing {events.length} of {total} security event(s) (offset {offset})
          </span>
          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={offset === 0}
              onClick={() => setOffset((prev) => Math.max(0, prev - PAGE_SIZE))}
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg border border-subtle bg-surface hover:bg-surface-elevated text-primary disabled:opacity-40"
            >
              <ChevronLeft className="w-3.5 h-3.5" />
              <span>Prev</span>
            </button>
            <button
              type="button"
              disabled={offset + PAGE_SIZE >= total}
              onClick={() => setOffset((prev) => prev + PAGE_SIZE)}
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg border border-subtle bg-surface hover:bg-surface-elevated text-primary disabled:opacity-40"
            >
              <span>Next</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
