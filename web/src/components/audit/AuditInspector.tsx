import React, { useEffect, useMemo, useRef } from 'react'
import {
  AlertTriangle,
  Check,
  Copy,
  FileCode2,
  FileText,
  GitCompareArrows,
  RefreshCw,
  ScrollText,
  ShieldAlert,
  Terminal,
  X,
} from 'lucide-react'
import type { AuditEvent } from '../../types'
import {
  InspectorTab,
  formatSmartDate,
  getCopyableContent,
  getEventTargetLabel,
  parsePayloadContent,
} from './formatters'
import { buildAuditDiffSections, countDiffChanges, formatDiffSectionsAsText } from './diff'
import { getVerdictStyle } from './verdictStyles'
import { PayloadLifecycleView } from './PayloadLifecycleView'
import { PayloadDiffView } from './PayloadDiffView'
import { InspectorMetaFooter } from './InspectorMetaFooter'

interface AuditInspectorProps {
  event: AuditEvent | null
  rowKey: string | null
  activeTab: InspectorTab
  diffLayout: 'unified' | 'split'
  isLoadingDetail: boolean
  detailError: string | null
  copiedId: string | null
  onTabChange: (rowKey: string, tab: InspectorTab) => void
  onDiffLayoutChange: (layout: 'unified' | 'split') => void
  onCopy: (text: string, copyId: string) => void
  onRetryDetail: (rowKey: string, event: AuditEvent) => void
  onClose: () => void
}

const CODE_BLOCK_CLS =
  'bg-[#F4F6FA] dark:bg-[#0D1422] text-slate-900 dark:text-cyan-200 border border-slate-200 dark:border-white/10 p-3.5 rounded-xl font-mono text-[11px] max-h-80 overflow-y-auto'

export const AuditInspector: React.FC<AuditInspectorProps> = ({
  event,
  rowKey,
  activeTab,
  diffLayout,
  isLoadingDetail,
  detailError,
  copiedId,
  onTabChange,
  onDiffLayoutChange,
  onCopy,
  onRetryDetail,
  onClose,
}) => {
  const drawerRef = useRef<HTMLDivElement>(null)
  const closeButtonRef = useRef<HTMLButtonElement>(null)
  const previousFocusRef = useRef<HTMLElement | null>(null)
  const isOpen = Boolean(event && rowKey)

  useEffect(() => {
    if (!isOpen) return
    const isDrawerMode =
      typeof window !== 'undefined' && !window.matchMedia('(min-width: 1024px)').matches

    if (isDrawerMode) {
      previousFocusRef.current =
        document.activeElement instanceof HTMLElement ? document.activeElement : null
      window.requestAnimationFrame(() => {
        closeButtonRef.current?.focus()
      })
    }

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose()
        return
      }
      if (isDrawerMode && e.key === 'Tab' && drawerRef.current) {
        const focusables = Array.from(
          drawerRef.current.querySelectorAll<HTMLElement>(
            'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
          )
        )
        if (focusables.length === 0) return
        const first = focusables[0]
        const last = focusables[focusables.length - 1]
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault()
          last.focus()
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault()
          first.focus()
        }
      }
    }

    window.addEventListener('keydown', onKeyDown)
    return () => {
      window.removeEventListener('keydown', onKeyDown)
      if (isDrawerMode && previousFocusRef.current && previousFocusRef.current.isConnected) {
        previousFocusRef.current.focus()
      }
      previousFocusRef.current = null
    }
  }, [isOpen, onClose])

  const diffSections = useMemo(() => (event ? buildAuditDiffSections(event) : []), [event])
  const diffChanges = useMemo(() => countDiffChanges(diffSections), [diffSections])
  const diffCopyText = useMemo(() => formatDiffSectionsAsText(diffSections), [diffSections])

  const renderContent = (isDrawer: boolean) => {
    if (!event || !rowKey) {
      return (
        <div className="h-full flex flex-col items-center justify-center text-center p-8 gap-2.5 text-secondary">
          <ScrollText className="w-9 h-9 text-muted" />
          <div className="text-sm font-semibold text-primary">Select an audit event to inspect</div>
          <p className="text-xs text-muted max-w-sm leading-relaxed">
            Click any record in the stream or use the up/down arrow keys to inspect full Request and Response payloads, Before/After diffs, and verification metadata without scrolling the list.
          </p>
        </div>
      )
    }

    const style = getVerdictStyle(event.decision || '')
    const Icon = style.icon
    const target = getEventTargetLabel(event)
    const { display: dateDisplay, iso: fullIso } = formatSmartDate(event.timestamp)
    const hasFourFields = Boolean(
      event.original_request || event.request || event.original_response || event.response
    )
    const parsedPayload = parsePayloadContent(event.payload_preview)
    const parsedReqJson = parsePayloadContent(event.request || event.original_request).formattedJson
    const parsedRespJson = parsePayloadContent(event.response || event.original_response).formattedJson
    const copyPayload = getCopyableContent(event, activeTab, diffCopyText)

    const tabs: { id: InspectorTab; label: string; icon: React.ReactNode; badge?: number }[] = [
      { id: 'payloads', label: 'Payloads', icon: <FileText className="w-3.5 h-3.5" /> },
      {
        id: 'diff',
        label: 'Diff',
        icon: <GitCompareArrows className="w-3.5 h-3.5" />,
        badge: diffChanges > 0 ? diffChanges : undefined,
      },
      { id: 'json', label: 'JSON', icon: <FileCode2 className="w-3.5 h-3.5" /> },
      { id: 'raw', label: 'Raw Log', icon: <Terminal className="w-3.5 h-3.5" /> },
    ]

    return (
      <div className="flex flex-col h-full overflow-hidden">
        {/* Inspector Header */}
        <div className="shrink-0 p-3.5 border-b border-subtle bg-canvas/60 space-y-2.5">
          <div className="flex items-start justify-between gap-2">
            <div className="flex items-center gap-2 flex-wrap min-w-0">
              <span
                className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-mono font-semibold border ${style.badge}`}
              >
                <Icon className="w-3 h-3" />
                <span>{style.label}</span>
              </span>
              <span className="font-mono text-xs font-bold text-primary truncate">{target.label}</span>
              {event.agent && (
                <span className="font-mono text-xs text-secondary">@{event.agent}</span>
              )}
            </div>

            <div className="flex items-center gap-2 shrink-0">
              <span className="text-[11px] font-mono tabular-nums text-muted" title={fullIso}>
                {dateDisplay}
              </span>
              <button
                ref={isDrawer ? closeButtonRef : undefined}
                type="button"
                aria-label="Close inspector"
                onClick={onClose}
                className="p-1 rounded-lg text-secondary hover:text-primary hover:bg-surface border border-transparent hover:border-subtle lg:hidden focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/50"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          {event.error && (
            <div className="px-3 py-2 rounded-lg bg-rose-50 border border-rose-200 text-rose-800 dark:bg-rose-950/50 dark:border-rose-700/50 dark:text-rose-200 text-xs flex items-start gap-2">
              <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5 text-rose-600 dark:text-rose-400" />
              <span className="font-mono break-words">{event.error}</span>
            </div>
          )}

          {/* Inspector Tabs + Copy */}
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <div
              role="tablist"
              aria-label="Audit record detail views"
              className="inline-flex items-center gap-1 bg-surface p-1 rounded-lg border border-subtle"
            >
              {tabs.map((tab) => {
                const selected = activeTab === tab.id
                return (
                  <button
                    key={tab.id}
                    id={`inspector-tab-${tab.id}`}
                    type="button"
                    role="tab"
                    aria-selected={selected}
                    aria-controls={`inspector-panel-${tab.id}`}
                    onClick={() => onTabChange(rowKey, tab.id)}
                    className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/50 ${
                      selected
                        ? 'bg-sky-50 text-sky-800 border border-sky-300 dark:bg-sky-500/15 dark:text-sky-200 dark:border-sky-400/40 font-semibold'
                        : 'text-secondary hover:text-primary border border-transparent'
                    }`}
                  >
                    {tab.icon}
                    <span>{tab.label}</span>
                    {tab.badge !== undefined && (
                      <span className="px-1.5 py-0.2 rounded-full text-[11px] font-mono font-semibold bg-amber-100 text-amber-900 dark:bg-amber-500/20 dark:text-amber-300 tabular-nums">
                        {tab.badge}
                      </span>
                    )}
                  </button>
                )
              })}
            </div>

            <button
              type="button"
              onClick={() => onCopy(copyPayload, `payload-${rowKey}-${activeTab}`)}
              className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium bg-surface hover:bg-surface-elevated text-primary border border-subtle transition-colors shadow-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/50"
            >
              {copiedId === `payload-${rowKey}-${activeTab}` ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
                  <span className="text-emerald-700 dark:text-emerald-300">Copied</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5 text-muted" />
                  <span>Copy Content</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Scrollable Inspector Body */}
        <div
          id={`inspector-panel-${activeTab}`}
          role="tabpanel"
          aria-labelledby={`inspector-tab-${activeTab}`}
          className="flex-1 overflow-y-auto p-4 space-y-3"
        >
          {isLoadingDetail && (
            <div className="space-y-2" aria-busy="true" aria-label="Loading full invocation detail">
              <div className="text-xs text-secondary">Loading full invocation payload from local vault…</div>
              <div className="h-24 rounded-xl bg-canvas animate-pulse motion-reduce:animate-none border border-subtle" />
            </div>
          )}

          {detailError && (
            <div
              role="alert"
              className="p-3 rounded-xl border border-amber-300 bg-amber-50 text-amber-900 dark:border-amber-700/60 dark:bg-amber-950/40 dark:text-amber-200 text-xs flex items-center justify-between gap-3"
            >
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>Detail load note: {detailError}</span>
              </div>
              <button
                type="button"
                onClick={() => onRetryDetail(rowKey, event)}
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-amber-100 hover:bg-amber-200 dark:bg-amber-900/60 font-semibold"
              >
                <RefreshCw className="w-3 h-3" />
                <span>Retry</span>
              </button>
            </div>
          )}

          {activeTab === 'payloads' && (
            <PayloadLifecycleView
              event={event}
              isLoadingDetail={isLoadingDetail}
              detailError={detailError}
            />
          )}

          {activeTab === 'diff' && (
            <PayloadDiffView
              event={event}
              sections={diffSections}
              diffLayout={diffLayout}
              onDiffLayoutChange={onDiffLayoutChange}
            />
          )}

          {activeTab === 'json' && (
            hasFourFields ? (
              <div className="space-y-3">
                <div className="space-y-1.5">
                  <div className="text-xs font-semibold text-sky-700 dark:text-sky-400">Request JSON</div>
                  <pre className={`${CODE_BLOCK_CLS} whitespace-pre-wrap break-words`}>
                    {parsedReqJson || 'null'}
                  </pre>
                </div>
                <div className="space-y-1.5">
                  <div className="text-xs font-semibold text-purple-700 dark:text-purple-400">Response JSON</div>
                  <pre className={`${CODE_BLOCK_CLS} whitespace-pre-wrap break-words`}>
                    {parsedRespJson || 'null'}
                  </pre>
                </div>
              </div>
            ) : (
              <pre className={`${CODE_BLOCK_CLS} whitespace-pre-wrap break-words`}>
                {parsedPayload.formattedJson || '(Empty payload)'}
              </pre>
            )
          )}

          {activeTab === 'raw' && (
            <pre className="bg-[#F4F6FA] dark:bg-[#0D1422] text-slate-900 dark:text-slate-200 border border-slate-200 dark:border-white/10 p-3.5 rounded-xl font-mono text-[11px] max-h-96 overflow-y-auto whitespace-pre-wrap break-words">
              {JSON.stringify(event, null, 2)}
            </pre>
          )}
        </div>

        <InspectorMetaFooter event={event} />
      </div>
    )
  }

  return (
    <>
      {/* Desktop Master-Detail Right Split Pane */}
      <div className="hidden lg:flex flex-col bg-surface rounded-2xl border border-subtle shadow-sm h-[calc(100vh-300px)] min-h-[460px] max-h-[780px] overflow-hidden">
        {renderContent(false)}
      </div>

      {/* Mobile / Tablet Slide-Over Drawer */}
      {event && (
        <div
          className="lg:hidden fixed inset-0 z-50 flex justify-end bg-slate-950/50 backdrop-blur-[1px]"
          role="dialog"
          aria-modal="true"
          aria-label="Audit Event Inspector"
        >
          <div className="fixed inset-0" onClick={onClose} aria-hidden="true" />
          <div
            ref={drawerRef}
            className="relative z-10 w-full max-w-xl bg-surface border-l border-subtle h-full flex flex-col shadow-2xl"
          >
            {renderContent(true)}
          </div>
        </div>
      )}
    </>
  )
}
