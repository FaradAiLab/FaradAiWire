import React from 'react'
import { Check, Clock, Copy, GitCompareArrows, ShieldCheck } from 'lucide-react'
import type { AuditEvent } from '../../types'
import { formatSmartDate, getEventTargetLabel } from './formatters'
import { hasMutationDiff } from './diff'
import { getVerdictStyle } from './verdictStyles'

interface AuditEventRowProps {
  event: AuditEvent
  rowKey: string
  isSelected: boolean
  copiedTrace: boolean
  onSelect: (rowKey: string, event: AuditEvent) => void
  onCopyTrace: (traceId: string, rowKey: string) => void
}

export const AuditEventRow: React.FC<AuditEventRowProps> = ({
  event,
  rowKey,
  isSelected,
  copiedTrace,
  onSelect,
  onCopyTrace,
}) => {
  const style = getVerdictStyle(event.decision || '')
  const Icon = style.icon
  const { display: dateDisplay, iso: fullIso } = formatSmartDate(event.timestamp)
  const target = getEventTargetLabel(event)
  const mutated = hasMutationDiff(event)
  const isCleanPass =
    event.matched_rule === 'pipeline' || (!event.matched_rule && event.decision === 'ALLOWED')

  const primaryRule =
    event.matched_rule && event.matched_rule !== 'pipeline'
      ? event.matched_rule
      : event.audited_rules && event.audited_rules.length > 0
      ? event.audited_rules[0]
      : null

  return (
    <div
      className={`relative flex items-stretch rounded-xl border transition-colors overflow-hidden ${
        isSelected
          ? 'border-sky-400 bg-sky-50/70 dark:border-sky-500/60 dark:bg-sky-950/35 shadow-sm'
          : 'border-subtle bg-canvas/60 hover:bg-surface-elevated/60 dark:bg-white/[0.02] dark:hover:bg-white/[0.05]'
      }`}
    >
      <span className={`w-1 shrink-0 ${style.stripe}`} aria-hidden="true" />

      <button
        type="button"
        aria-pressed={isSelected}
        onClick={() => onSelect(rowKey, event)}
        className="flex-1 min-w-0 text-left px-3 py-2.5 flex flex-col gap-1.5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent/60"
      >
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <div className="flex items-center gap-2 min-w-0 flex-wrap">
            <span
              className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-mono font-semibold border ${style.badge}`}
            >
              <Icon className="w-3 h-3 shrink-0" />
              <span>{style.label}</span>
            </span>

            <span
              className={`font-mono text-xs font-semibold px-1.5 py-0.5 rounded border truncate max-w-[220px] ${
                target.kind === 'tool'
                  ? 'bg-surface border-subtle text-primary'
                  : 'bg-sky-50/70 border-sky-200 text-sky-900 dark:bg-sky-950/40 dark:border-sky-800/50 dark:text-sky-200'
              }`}
              title={target.label}
            >
              {target.label}
            </span>

            {mutated && (
              <span
                className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[11px] font-mono font-semibold bg-amber-50 text-amber-900 border border-amber-300 dark:bg-amber-950/60 dark:text-amber-200 dark:border-amber-700/60"
                title="Payload modified or blocked (Diff available)"
              >
                <GitCompareArrows className="w-3 h-3" />
                <span>Δ</span>
              </span>
            )}
          </div>

          <div className="flex items-center gap-2 text-[11px] font-mono tabular-nums text-secondary shrink-0">
            {typeof event.latency_ms === 'number' && (
              <span>{event.latency_ms.toFixed(event.latency_ms < 10 ? 2 : 0)}ms</span>
            )}
            <span className="inline-flex items-center gap-1 text-muted" title={`ISO: ${fullIso}`}>
              <Clock className="w-3 h-3" />
              <span>{dateDisplay}</span>
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2 text-[11px] text-secondary flex-wrap">
          {event.agent && (
            <span className="font-mono font-medium text-primary">@{event.agent}</span>
          )}
          <span className="text-muted" aria-hidden="true">
            /
          </span>
          {isCleanPass ? (
            <span className="inline-flex items-center gap-1 text-emerald-700 dark:text-emerald-400 font-medium">
              <ShieldCheck className="w-3 h-3" />
              <span>Clean pass</span>
            </span>
          ) : primaryRule ? (
            <span className="font-mono text-secondary truncate max-w-[260px]" title={primaryRule}>
              rule:{primaryRule}
            </span>
          ) : (
            <span className="font-mono text-muted">{event.layer || 'pipeline'}</span>
          )}
          {event.error && (
            <span className="text-rose-700 dark:text-rose-300 truncate max-w-[280px]">
              · {event.error}
            </span>
          )}
        </div>
      </button>

      {event.trace_id && (
        <div className="flex items-center pr-2 border-l border-subtle/60">
          <button
            type="button"
            aria-label={`Copy trace ID ${event.trace_id}`}
            title={`Copy Trace ID: ${event.trace_id}`}
            onClick={() => onCopyTrace(event.trace_id || '', rowKey)}
            className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-[11px] font-mono text-secondary hover:text-primary hover:bg-surface border border-transparent hover:border-subtle transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/50"
          >
            {copiedTrace ? (
              <>
                <Check className="w-3 h-3 text-emerald-600 dark:text-emerald-400" />
                <span className="text-emerald-700 dark:text-emerald-300 font-semibold">Copied</span>
              </>
            ) : (
              <>
                <Copy className="w-3 h-3 text-muted" />
                <span>#{event.trace_id.substring(0, 8)}</span>
              </>
            )}
          </button>
        </div>
      )}
    </div>
  )
}
