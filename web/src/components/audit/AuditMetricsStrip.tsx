import React from 'react'
import { Cpu } from 'lucide-react'
import type { AuditQuerySummary } from '../../types'

interface AuditMetricsStripProps {
  summary: AuditQuerySummary
  selectedVerdict: string
  onSelectVerdict: (verdict: string) => void
  loadedCount: number
}

export const AuditMetricsStrip: React.FC<AuditMetricsStripProps> = ({
  summary,
  selectedVerdict,
  onSelectVerdict,
  loadedCount,
}) => {
  const items = [
    { id: 'ALL', label: 'All', count: summary.total, dot: 'bg-slate-400 dark:bg-slate-500' },
    { id: 'ALLOWED', label: 'Allowed', count: summary.allowed, dot: 'bg-emerald-500' },
    { id: 'MASKED', label: 'Masked', count: summary.masked, dot: 'bg-amber-500' },
    { id: 'AUDIT', label: 'Audit', count: summary.audit, dot: 'bg-purple-600' },
    { id: 'BLOCKED', label: 'Blocked', count: summary.blocked, dot: 'bg-rose-600' },
  ]

  const avgMs = Number.isFinite(summary.avg_latency_ms)
    ? summary.avg_latency_ms < 10 && summary.avg_latency_ms > 0
      ? summary.avg_latency_ms.toFixed(1)
      : String(Math.round(summary.avg_latency_ms))
    : '0'

  return (
    <div className="flex flex-wrap items-center justify-between gap-2 bg-surface px-3 py-2 rounded-xl border border-subtle shadow-sm">
      <div
        role="group"
        aria-label="Filter invocations by verdict"
        className="flex flex-wrap items-center gap-1.5"
      >
        {items.map((item) => {
          const active = selectedVerdict === item.id
          return (
            <button
              key={item.id}
              type="button"
              aria-pressed={active}
              onClick={() => onSelectVerdict(item.id)}
              className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/50 ${
                active
                  ? 'bg-sky-50 text-sky-900 border-sky-300 dark:bg-sky-500/15 dark:text-sky-200 dark:border-sky-400/40 font-semibold shadow-sm'
                  : 'bg-canvas/70 text-secondary border-subtle hover:bg-surface-elevated hover:text-primary'
              }`}
            >
              <span className={`w-2 h-2 rounded-full ${item.dot}`} aria-hidden="true" />
              <span>{item.label}</span>
              <span className="font-mono tabular-nums text-[11px] font-bold text-primary">
                {item.count.toLocaleString()}
              </span>
            </button>
          )
        })}
      </div>

      <div className="flex items-center gap-3 text-xs text-secondary font-mono tabular-nums">
        <span
          className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-canvas border border-subtle text-primary"
          title="Average execution latency across matching records"
        >
          <Cpu className="w-3.5 h-3.5 text-sky-600 dark:text-cyan-400" />
          <span>Avg {avgMs} ms</span>
        </span>
        <span className="text-[11px] font-sans text-muted hidden sm:inline">
          {loadedCount} loaded on page
        </span>
      </div>
    </div>
  )
}
