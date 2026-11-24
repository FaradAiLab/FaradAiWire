import React from 'react'
import { AlertTriangle, CheckCircle2 } from 'lucide-react'
import type { AuditVerifyResponse } from '../../types'
import { summarizeDuckDBVerify } from './formatters'

interface AuditStatusBannersProps {
  activeError: string | null
  showRetry: boolean
  verifyResult: AuditVerifyResponse | null
  onRetry: () => void
  onDismissError: () => void
  onDismissVerify: () => void
}

export const AuditStatusBanners: React.FC<AuditStatusBannersProps> = ({
  activeError,
  showRetry,
  verifyResult,
  onRetry,
  onDismissError,
  onDismissVerify,
}) => {
  return (
    <>
      {activeError && (
        <div
          role="alert"
          className="p-3.5 rounded-xl border bg-rose-50 text-rose-800 border-rose-200 dark:bg-rose-950/40 dark:border-rose-500/30 dark:text-rose-200 text-xs flex items-center justify-between gap-3"
        >
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{activeError}</span>
          </div>
          <div className="flex items-center gap-2">
            {showRetry && (
              <button
                type="button"
                onClick={onRetry}
                className="px-2 py-0.5 rounded bg-rose-100 hover:bg-rose-200 dark:bg-rose-900/50 font-semibold text-[11px]"
              >
                Retry
              </button>
            )}
            <button type="button" onClick={onDismissError} className="underline text-[11px]">
              Dismiss
            </button>
          </div>
        </div>
      )}

      {verifyResult && (
        <div
          role="status"
          aria-live="polite"
          className={`p-4 rounded-xl border text-xs flex flex-wrap items-center justify-between gap-3 shadow-sm ${
            verifyResult.valid
              ? 'bg-emerald-50 text-emerald-900 border-emerald-200 dark:bg-emerald-950/40 dark:border-emerald-500/30 dark:text-emerald-200'
              : 'bg-rose-50 text-rose-900 border-rose-200 dark:bg-rose-950/40 dark:border-rose-500/30 dark:text-rose-200'
          }`}
        >
          <div className="flex items-start gap-2.5">
            {verifyResult.valid ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0 mt-0.5" />
            ) : (
              <AlertTriangle className="w-4 h-4 text-rose-600 dark:text-rose-400 shrink-0 mt-0.5" />
            )}
            <div className="space-y-1 font-mono">
              <div className="font-bold">
                Audit Integrity: {verifyResult.valid ? 'VERIFIED (VALID)' : 'TAMPERING DETECTED'}
              </div>
              <div className="text-[11px] flex flex-wrap gap-3">
                {verifyResult.duckdb && (() => {
                  const dbStats = summarizeDuckDBVerify(verifyResult.duckdb)
                  return (
                    <span>
                      DuckDB checked={dbStats.checked} · v2_verified={dbStats.v2_verified} · legacy_v1={dbStats.legacy_v1}
                      {dbStats.tampered_ids.length > 0 ? ` · tampered_ids=[${dbStats.tampered_ids.join(', ')}]` : ''}
                    </span>
                  )
                })()}
                {verifyResult.jsonl && (
                  <span>
                    JSONL entries_checked={verifyResult.jsonl.entries_checked ?? 0} · segments={verifyResult.jsonl.segments_checked ?? 0}
                    {verifyResult.jsonl.broken_segments && verifyResult.jsonl.broken_segments.length > 0
                      ? ` · broken_segments=[${verifyResult.jsonl.broken_segments
                          .map((b) => `${b.segment}${b.line ? `:${b.line}` : ''} (${b.reason})`)
                          .join(', ')}]`
                      : ''}
                  </span>
                )}
              </div>
            </div>
          </div>
          <button type="button" onClick={onDismissVerify} className="text-[11px] underline">
            Dismiss
          </button>
        </div>
      )}
    </>
  )
}
