import React from 'react'
import { Columns, Eye, Rows } from 'lucide-react'
import type { AuditEvent } from '../../types'
import type { DiffLine, PayloadDiffSection } from './diff'
import { RedactedText } from './RedactedText'

interface PayloadDiffViewProps {
  event: AuditEvent
  sections: PayloadDiffSection[]
  diffLayout: 'unified' | 'split'
  onDiffLayoutChange: (layout: 'unified' | 'split') => void
}

function lineBgClass(kind: DiffLine['kind']) {
  if (kind === 'removed') {
    return 'bg-[#FEF2F2] text-[#991B1B] dark:bg-rose-950/45 dark:text-rose-200'
  }
  if (kind === 'added') {
    return 'bg-[#ECFDF5] text-[#065F46] dark:bg-emerald-950/45 dark:text-emerald-200'
  }
  return 'text-[#0F172A] dark:text-slate-200'
}

export const PayloadDiffView: React.FC<PayloadDiffViewProps> = ({
  event,
  sections,
  diffLayout,
  onDiffLayoutChange,
}) => {
  if (sections.length === 0) {
    const isClean = event.decision === 'ALLOWED' || event.decision === 'AUDIT'
    return (
      <div className="rounded-xl border border-slate-200 bg-slate-50 text-slate-800 dark:border-white/10 dark:bg-slate-900/60 dark:text-slate-200 p-4 space-y-1.5">
        <div className="text-xs font-semibold flex items-center gap-2 text-primary">
          <Eye className="w-4 h-4 text-purple-700 dark:text-purple-400" />
          <span>No Mutation Diff Recorded</span>
        </div>
        <p className="text-xs text-secondary leading-relaxed">
          {isClean
            ? 'This invocation passed filters unmodified (ALLOWED/AUDIT), so no payload transformation or security block diff exists.'
            : 'Request and response bytes were identical, or Local Full Payload Retention is disabled in Operational Settings.'}
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-2">
        <span className="text-xs text-secondary font-medium">
          Comparing unmasked raw payloads against sanitized or blocked outcomes
        </span>
        <div className="flex items-center gap-1 bg-canvas p-0.5 rounded-lg border border-subtle">
          <button
            type="button"
            aria-pressed={diffLayout === 'unified'}
            onClick={() => onDiffLayoutChange('unified')}
            className={`inline-flex items-center gap-1 px-2 py-1 rounded text-[11px] font-medium transition-colors ${
              diffLayout === 'unified'
                ? 'bg-surface text-sky-800 dark:text-accent shadow-xs font-semibold'
                : 'text-secondary hover:text-primary'
            }`}
            title="Unified diff view"
          >
            <Rows className="w-3 h-3" />
            <span>Unified</span>
          </button>
          <button
            type="button"
            aria-pressed={diffLayout === 'split'}
            onClick={() => onDiffLayoutChange('split')}
            className={`inline-flex items-center gap-1 px-2 py-1 rounded text-[11px] font-medium transition-colors ${
              diffLayout === 'split'
                ? 'bg-surface text-sky-800 dark:text-accent shadow-xs font-semibold'
                : 'text-secondary hover:text-primary'
            }`}
            title="Side-by-side split view"
          >
            <Columns className="w-3 h-3" />
            <span>Split</span>
          </button>
        </div>
      </div>

      {sections.map((section) => (
        <div
          key={section.id}
          className="rounded-xl border border-slate-200 dark:border-white/10 overflow-hidden bg-[#F4F6FA] dark:bg-[#0D1422]"
        >
          <div className="flex flex-wrap items-center justify-between gap-2 px-3 py-2 bg-surface border-b border-subtle">
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold text-primary">{section.title}</span>
              <span className="text-[11px] text-secondary">· {section.outcomeLabel}</span>
              {section.truncatedForDiff && (
                <span className="text-[11px] font-mono px-1.5 py-0.5 rounded bg-amber-50 text-amber-900 border border-amber-300 dark:bg-amber-950/60 dark:text-amber-200 dark:border-amber-700/60">
                  Bounded preview
                </span>
              )}
            </div>
            <div className="flex items-center gap-1.5 text-[11px] font-mono tabular-nums">
              <span className="px-1.5 py-0.5 rounded bg-rose-50 text-rose-800 border border-rose-200 dark:bg-rose-950/50 dark:text-rose-200 dark:border-rose-800/50">
                -{section.removedCount}
              </span>
              <span className="px-1.5 py-0.5 rounded bg-emerald-50 text-emerald-800 border border-emerald-200 dark:bg-emerald-950/50 dark:text-emerald-200 dark:border-emerald-800/50">
                +{section.addedCount}
              </span>
            </div>
          </div>

          {diffLayout === 'unified' ? (
            <div className="max-h-80 overflow-y-auto font-mono text-[11px] divide-y divide-slate-200/60 dark:divide-white/5">
              {section.lines.map((line, idx) => (
                <div key={idx} className={`flex items-start gap-2 px-2.5 py-0.5 ${lineBgClass(line.kind)}`}>
                  <span className="w-8 shrink-0 text-right text-muted select-none tabular-nums">
                    {line.oldLine ?? ''}
                  </span>
                  <span className="w-8 shrink-0 text-right text-muted select-none tabular-nums">
                    {line.newLine ?? ''}
                  </span>
                  <span className="w-3 shrink-0 font-bold select-none">
                    {line.kind === 'removed' ? '-' : line.kind === 'added' ? '+' : ' '}
                  </span>
                  <span className="flex-1 min-w-0">
                    {line.kind === 'added' ? (
                      <RedactedText text={line.text} />
                    ) : (
                      <span className="whitespace-pre-wrap break-words">{line.text}</span>
                    )}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-slate-200 dark:divide-white/10">
              <div className="max-h-80 overflow-y-auto">
                <div className="px-3 py-1.5 text-[11px] font-semibold text-rose-800 dark:text-rose-300 bg-rose-50/70 dark:bg-rose-950/30 border-b border-slate-200 dark:border-white/10">
                  {section.beforeLabel}
                </div>
                <div className="font-mono text-[11px]">
                  {section.lines
                    .filter((l) => l.kind !== 'added')
                    .map((line, idx) => (
                      <div key={idx} className={`flex items-start gap-2 px-2.5 py-0.5 ${lineBgClass(line.kind)}`}>
                        <span className="w-7 shrink-0 text-right text-muted select-none tabular-nums">
                          {line.oldLine ?? ''}
                        </span>
                        <span className="flex-1 min-w-0 whitespace-pre-wrap break-words">{line.text}</span>
                      </div>
                    ))}
                </div>
              </div>

              <div className="max-h-80 overflow-y-auto">
                <div className="px-3 py-1.5 text-[11px] font-semibold text-emerald-800 dark:text-emerald-300 bg-emerald-50/70 dark:bg-emerald-950/30 border-b border-slate-200 dark:border-white/10">
                  {section.afterLabel}
                </div>
                <div className="font-mono text-[11px]">
                  {section.lines
                    .filter((l) => l.kind !== 'removed')
                    .map((line, idx) => (
                      <div key={idx} className={`flex items-start gap-2 px-2.5 py-0.5 ${lineBgClass(line.kind)}`}>
                        <span className="w-7 shrink-0 text-right text-muted select-none tabular-nums">
                          {line.newLine ?? ''}
                        </span>
                        <span className="flex-1 min-w-0">
                          {line.kind === 'added' ? (
                            <RedactedText text={line.text} />
                          ) : (
                            <span className="whitespace-pre-wrap break-words">{line.text}</span>
                          )}
                        </span>
                      </div>
                    ))}
                </div>
              </div>
            </div>
          )}
        </div>
      ))}
    </div>
  )
}
