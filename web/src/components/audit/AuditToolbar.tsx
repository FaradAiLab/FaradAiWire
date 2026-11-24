import React from 'react'
import {
  ArrowDown,
  Download,
  KeyRound,
  Pause,
  Play,
  Radio,
  RefreshCw,
  ScrollText,
  ShieldCheck,
  Trash2,
} from 'lucide-react'
import type { AuditSubTab } from '../AuditLogsTab'

interface AuditToolbarProps {
  activeSubTab: AuditSubTab
  onSelectSubTab: (tab: AuditSubTab) => void
  isHistoricalMode: boolean
  isPaused: boolean
  isConnected: boolean
  liveFollow: boolean
  verifying: boolean
  exportingFormat: 'csv' | 'jsonl' | null
  onTogglePause: () => void
  onResumeLive: () => void
  onExport: (format: 'csv' | 'jsonl') => void
  onVerifyIntegrity: () => void
  onRefresh: () => void
  onToggleLiveFollow: () => void
  onClearScreen: () => void
}

export const AuditToolbar: React.FC<AuditToolbarProps> = ({
  activeSubTab,
  onSelectSubTab,
  isHistoricalMode,
  isPaused,
  isConnected,
  liveFollow,
  verifying,
  exportingFormat,
  onTogglePause,
  onResumeLive,
  onExport,
  onVerifyIntegrity,
  onRefresh,
  onToggleLiveFollow,
  onClearScreen,
}) => {
  const statusLabel = isHistoricalMode
    ? 'HISTORICAL'
    : isPaused
    ? 'PAUSED'
    : isConnected
    ? 'LIVE STREAM'
    : 'CONNECTING'

  const statusTone =
    isHistoricalMode || isPaused
      ? 'text-amber-600 dark:text-amber-400'
      : isConnected
      ? 'text-emerald-600 dark:text-emerald-400 animate-pulse motion-reduce:animate-none'
      : 'text-amber-600 dark:text-amber-400'

  return (
    <div className="flex flex-wrap items-start justify-between gap-4">
      <div className="space-y-2.5">
        <div>
          <h2 className="text-xl font-bold text-primary flex items-center gap-2 tracking-tight">
            <ScrollText className="w-5 h-5 text-accent" />
            <span>Audit & Security Console</span>
          </h2>
          <p className="text-xs text-secondary mt-1">
            MCP tool invocation telemetry, control-plane security events, cryptographic verification, and redacted export.
          </p>
        </div>

        <div
          role="tablist"
          aria-label="Audit Log Views"
          className="inline-flex items-center p-1 rounded-xl bg-surface border border-subtle shadow-sm"
        >
          <button
            id="audit-tab-invocations"
            type="button"
            role="tab"
            aria-selected={activeSubTab === 'invocations'}
            aria-controls="audit-panel-invocations"
            onClick={() => onSelectSubTab('invocations')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/50 ${
              activeSubTab === 'invocations'
                ? 'bg-sky-50 text-sky-800 border border-sky-300 dark:bg-sky-500/15 dark:text-sky-200 dark:border-sky-400/40 shadow-sm'
                : 'text-secondary hover:text-primary border border-transparent'
            }`}
          >
            <ScrollText className="w-3.5 h-3.5" />
            <span>Tool Invocations</span>
          </button>
          <button
            id="audit-tab-security"
            type="button"
            role="tab"
            aria-selected={activeSubTab === 'security'}
            aria-controls="audit-panel-security"
            onClick={() => onSelectSubTab('security')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/50 ${
              activeSubTab === 'security'
                ? 'bg-sky-50 text-sky-800 border border-sky-300 dark:bg-sky-500/15 dark:text-sky-200 dark:border-sky-400/40 shadow-sm'
                : 'text-secondary hover:text-primary border border-transparent'
            }`}
          >
            <KeyRound className="w-3.5 h-3.5" />
            <span>Security Events</span>
          </button>
        </div>
      </div>

      <div className="flex items-center gap-2 flex-wrap">
        {activeSubTab === 'invocations' && (
          <>
            <div
              role="status"
              aria-live="polite"
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-mono font-semibold bg-surface border border-subtle text-primary shadow-sm"
            >
              <Radio className={`w-3.5 h-3.5 ${statusTone}`} />
              <span>{statusLabel}</span>
            </div>

            <button
              type="button"
              onClick={isHistoricalMode ? onResumeLive : onTogglePause}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-surface hover:bg-surface-elevated text-primary border border-subtle transition-colors shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/50"
            >
              {isPaused || isHistoricalMode ? (
                <Play className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
              ) : (
                <Pause className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400" />
              )}
              <span>{isPaused || isHistoricalMode ? 'Resume Live' : 'Pause'}</span>
            </button>

            <button
              type="button"
              onClick={() => onExport('csv')}
              disabled={exportingFormat !== null}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-surface hover:bg-surface-elevated text-primary border border-subtle transition-colors shadow-sm disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/50"
              title="Download redacted CSV export (respects active filters)"
            >
              <Download className="w-3.5 h-3.5 text-sky-600 dark:text-cyan-400" />
              <span>{exportingFormat === 'csv' ? 'Exporting…' : 'Export CSV'}</span>
            </button>

            <button
              type="button"
              onClick={() => onExport('jsonl')}
              disabled={exportingFormat !== null}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-surface hover:bg-surface-elevated text-primary border border-subtle transition-colors shadow-sm disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/50"
              title="Download redacted JSONL export (respects active filters)"
            >
              <Download className="w-3.5 h-3.5 text-indigo-600 dark:text-indigo-400" />
              <span>{exportingFormat === 'jsonl' ? 'Exporting…' : 'Export JSONL'}</span>
            </button>
          </>
        )}

        <button
          type="button"
          onClick={onVerifyIntegrity}
          disabled={verifying}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-emerald-50 hover:bg-emerald-100 text-emerald-800 border border-emerald-300 dark:bg-emerald-950/50 dark:hover:bg-emerald-900/50 dark:text-emerald-200 dark:border-emerald-500/40 transition-colors shadow-sm disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500/50"
          title="Verify SHA-256 / HMAC-SHA256 tamper-evidence chains across DuckDB and JSONL"
        >
          <ShieldCheck className={`w-3.5 h-3.5 ${verifying ? 'animate-spin motion-reduce:animate-none' : ''}`} />
          <span>{verifying ? 'Verifying…' : 'Verify Integrity'}</span>
        </button>

        <button
          type="button"
          onClick={onRefresh}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-surface hover:bg-surface-elevated text-primary border border-subtle transition-colors shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/50"
          title="Refresh logs from DuckDB"
        >
          <RefreshCw className="w-3.5 h-3.5 text-accent" />
          <span>Refresh</span>
        </button>

        {activeSubTab === 'invocations' && (
          <>
            <button
              type="button"
              aria-pressed={liveFollow}
              onClick={onToggleLiveFollow}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold border transition-colors shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/50 ${
                liveFollow
                  ? 'bg-sky-50 border-sky-300 text-sky-800 dark:bg-sky-500/15 dark:text-sky-200 dark:border-sky-400/40'
                  : 'bg-surface border-subtle text-secondary hover:text-primary'
              }`}
              title="Prepend incoming live stream rows at top when viewing the top of the stream"
            >
              <ArrowDown className="w-3.5 h-3.5 rotate-180" />
              <span>Live Follow</span>
            </button>

            <button
              type="button"
              aria-label="Clear logs from screen"
              onClick={onClearScreen}
              className="p-2 rounded-xl text-secondary hover:text-rose-700 dark:hover:text-rose-300 hover:bg-rose-50 dark:hover:bg-rose-950/30 border border-subtle bg-surface transition-colors shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-500/50"
              title="Clear logs from screen"
            >
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          </>
        )}
      </div>
    </div>
  )
}
