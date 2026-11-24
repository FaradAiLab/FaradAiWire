import React, { useState, useEffect, useCallback, useRef } from 'react'
import { Pause, Play } from 'lucide-react'
import type { AuditVerifyResponse } from '../types'
import { api } from '../api'
import { PAGE_SIZE } from './audit/formatters'
import type { InspectorTab } from './audit/formatters'
import { useAuditStream } from './audit/useAuditStream'
import { AuditToolbar } from './audit/AuditToolbar'
import { AuditStatusBanners } from './audit/AuditStatusBanners'
import { AuditMetricsStrip } from './audit/AuditMetricsStrip'
import { AuditFilterBar } from './audit/AuditFilterBar'
import { AuditEventList } from './audit/AuditEventList'
import { AuditInspector } from './audit/AuditInspector'
import { SecurityEventsPanel } from './audit/SecurityEventsPanel'

export type AuditSubTab = 'invocations' | 'security'

export interface AuditLogsTabProps {
  initialSubTab?: AuditSubTab
  onSubTabChange?: (subTab: AuditSubTab) => void
}

export const AuditLogsTab: React.FC<AuditLogsTabProps> = ({
  initialSubTab = 'invocations',
  onSubTabChange,
}) => {
  const [activeSubTab, setActiveSubTab] = useState<AuditSubTab>(initialSubTab)
  const [activeTabs, setActiveTabs] = useState<Record<string, InspectorTab>>({})
  const [diffLayout, setDiffLayout] = useState<'unified' | 'split'>('unified')
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const [securityRefreshSignal, setSecurityRefreshSignal] = useState(0)

  const [verifying, setVerifying] = useState(false)
  const [verifyResult, setVerifyResult] = useState<AuditVerifyResponse | null>(null)
  const [verifyError, setVerifyError] = useState<string | null>(null)
  const [exportError, setExportError] = useState<string | null>(null)
  const [securityError, setSecurityError] = useState<string | null>(null)
  const [exportingFormat, setExportingFormat] = useState<'csv' | 'jsonl' | null>(null)
  const copyTimerRef = useRef<number | null>(null)

  const stream = useAuditStream({ enabled: activeSubTab === 'invocations' })

  useEffect(() => {
    if (initialSubTab) {
      setActiveSubTab(initialSubTab)
    }
  }, [initialSubTab])

  useEffect(() => {
    return () => {
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current)
      }
    }
  }, [])

  const handleSelectSubTab = (tab: AuditSubTab) => {
    setActiveSubTab(tab)
    stream.setQueryError(null)
    setSecurityError(null)
    onSubTabChange?.(tab)
  }

  const handleVerifyIntegrity = async () => {
    try {
      setVerifying(true)
      setVerifyError(null)
      setVerifyResult(await api.verifyAuditIntegrity())
    } catch (err: unknown) {
      setVerifyError(err instanceof Error ? err.message : String(err))
    } finally {
      setVerifying(false)
    }
  }

  const handleExport = async (format: 'csv' | 'jsonl') => {
    try {
      setExportingFormat(format)
      setExportError(null)
      await api.downloadAuditLogsExport(format, stream.buildServerFilterParams())
    } catch (err: unknown) {
      setExportError(err instanceof Error ? err.message : String(err))
    } finally {
      setExportingFormat(null)
    }
  }

  const copyToClipboard = useCallback((text: string, id: string) => {
    if (!navigator.clipboard?.writeText) return
    navigator.clipboard
      .writeText(text)
      .then(() => {
        setCopiedId(id)
        if (copyTimerRef.current !== null) {
          window.clearTimeout(copyTimerRef.current)
        }
        copyTimerRef.current = window.setTimeout(() => {
          setCopiedId(null)
          copyTimerRef.current = null
        }, 2000)
      })
      .catch(() => {
        // Clipboard permission denied or unavailable in non-secure context
      })
  }, [])

  const activeError =
    verifyError || exportError || (activeSubTab === 'invocations' ? stream.queryError : securityError)

  const hasActiveFilters = Boolean(
    stream.filterText.trim() ||
      stream.matchedRuleFilter.trim() ||
      stream.sinceInput ||
      stream.untilInput ||
      stream.selectedVerdict !== 'ALL'
  )

  const refreshActiveTab = () =>
    activeSubTab === 'invocations'
      ? stream.fetchHistoricalLogs()
      : setSecurityRefreshSignal((n) => n + 1)

  return (
    <div className="space-y-4">
      <AuditToolbar
        activeSubTab={activeSubTab}
        onSelectSubTab={handleSelectSubTab}
        isHistoricalMode={stream.isHistoricalMode}
        isPaused={stream.isPaused}
        isConnected={stream.isConnected}
        liveFollow={stream.liveFollow}
        verifying={verifying}
        exportingFormat={exportingFormat}
        onTogglePause={() => stream.setIsPaused(!stream.isPaused)}
        onResumeLive={stream.handleResumeLive}
        onExport={handleExport}
        onVerifyIntegrity={handleVerifyIntegrity}
        onRefresh={refreshActiveTab}
        onToggleLiveFollow={() => stream.setLiveFollow(!stream.liveFollow)}
        onClearScreen={stream.clearScreen}
      />

      <AuditStatusBanners
        activeError={activeError}
        showRetry={Boolean(stream.queryError || securityError)}
        verifyResult={verifyResult}
        onRetry={refreshActiveTab}
        onDismissError={() => {
          setVerifyError(null)
          setExportError(null)
          stream.setQueryError(null)
          setSecurityError(null)
        }}
        onDismissVerify={() => setVerifyResult(null)}
      />

      {activeSubTab === 'security' ? (
        <SecurityEventsPanel refreshSignal={securityRefreshSignal} onError={setSecurityError} />
      ) : (
        <div id="audit-panel-invocations" role="tabpanel" aria-labelledby="audit-tab-invocations" className="space-y-3">
          {stream.isHistoricalMode && (
            <div
              role="status"
              aria-live="polite"
              className="p-3 rounded-xl border border-amber-300 bg-amber-50 text-amber-900 dark:bg-amber-950/40 dark:border-amber-500/40 dark:text-amber-200 text-xs flex flex-wrap items-center justify-between gap-3 shadow-sm"
            >
              <div className="flex items-center gap-2">
                <Pause className="w-4 h-4 text-amber-700 dark:text-amber-400 shrink-0" />
                <span className="font-semibold">
                  Paused while viewing historical page (SSE live updates disabled so rows stay stable).
                </span>
              </div>
              <button
                type="button"
                onClick={stream.handleResumeLive}
                className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg bg-amber-600 hover:bg-amber-700 text-white font-semibold transition-colors"
              >
                <Play className="w-3 h-3" />
                <span>Resume Live</span>
              </button>
            </div>
          )}

          <AuditMetricsStrip
            summary={stream.summary}
            selectedVerdict={stream.selectedVerdict}
            onSelectVerdict={stream.setSelectedVerdict}
            loadedCount={stream.events.length}
          />

          <AuditFilterBar
            filterText={stream.filterText}
            matchedRuleFilter={stream.matchedRuleFilter}
            sinceInput={stream.sinceInput}
            untilInput={stream.untilInput}
            selectedVerdict={stream.selectedVerdict}
            onFilterTextChange={stream.setFilterText}
            onMatchedRuleChange={stream.setMatchedRuleFilter}
            onSinceChange={stream.setSinceInput}
            onUntilChange={stream.setUntilInput}
            onClearFilters={stream.clearFilters}
          />

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-stretch">
            <div className="lg:col-span-5 min-w-0">
              <AuditEventList
                events={stream.events}
                isLoading={stream.isLoading}
                selectedRowKey={stream.selectedRowKey}
                copiedId={copiedId}
                pendingNewCount={stream.pendingNewCount}
                offset={stream.offset}
                totalCount={stream.totalCount}
                hasActiveFilters={hasActiveFilters}
                listContainerRef={stream.listContainerRef}
                onScrollTopChange={stream.onListScroll}
                onJumpToTop={stream.jumpToTop}
                onSelectRow={stream.selectRow}
                onCopyTrace={(traceId, rowKey) => copyToClipboard(traceId, `trace-${rowKey}`)}
                onClearFilters={stream.clearFilters}
                onPrevPage={() => stream.setOffset((prev) => Math.max(0, prev - PAGE_SIZE))}
                onNextPage={() => stream.setOffset((prev) => prev + PAGE_SIZE)}
              />
            </div>

            <div className="lg:col-span-7 min-w-0">
              <AuditInspector
                event={stream.selectedEvent}
                rowKey={stream.selectedRowKey}
                activeTab={(stream.selectedRowKey && activeTabs[stream.selectedRowKey]) || 'payloads'}
                diffLayout={diffLayout}
                isLoadingDetail={stream.isLoadingDetail}
                detailError={stream.detailError}
                copiedId={copiedId}
                onTabChange={(rowKey, tab) => setActiveTabs((prev) => ({ ...prev, [rowKey]: tab }))}
                onDiffLayoutChange={setDiffLayout}
                onCopy={copyToClipboard}
                onRetryDetail={stream.retryDetail}
                onClose={stream.clearSelection}
              />
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
