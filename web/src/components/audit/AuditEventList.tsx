import React from 'react'
import { ArrowUp, ChevronLeft, ChevronRight, Shield } from 'lucide-react'
import type { AuditEvent } from '../../types'
import { PAGE_SIZE, getRowKey } from './formatters'
import { AuditEventRow } from './AuditEventRow'

interface AuditEventListProps {
  events: AuditEvent[]
  isLoading: boolean
  selectedRowKey: string | null
  copiedId: string | null
  pendingNewCount: number
  offset: number
  totalCount: number
  hasActiveFilters: boolean
  listContainerRef: React.RefObject<HTMLDivElement>
  onScrollTopChange: (scrollTop: number) => void
  onJumpToTop: () => void
  onSelectRow: (rowKey: string, event: AuditEvent) => void
  onCopyTrace: (traceId: string, rowKey: string) => void
  onClearFilters: () => void
  onPrevPage: () => void
  onNextPage: () => void
}

export const AuditEventList: React.FC<AuditEventListProps> = ({
  events,
  isLoading,
  selectedRowKey,
  copiedId,
  pendingNewCount,
  offset,
  totalCount,
  hasActiveFilters,
  listContainerRef,
  onScrollTopChange,
  onJumpToTop,
  onSelectRow,
  onCopyTrace,
  onClearFilters,
  onPrevPage,
  onNextPage,
}) => {
  const currentPage = Math.floor(offset / PAGE_SIZE) + 1
  const totalPages = Math.max(1, Math.ceil(totalCount / PAGE_SIZE))

  const handleKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
    if (events.length === 0) return
    if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return
    if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return

    e.preventDefault()
    const currentIdx = selectedRowKey
      ? events.findIndex((ev, idx) => getRowKey(ev, idx) === selectedRowKey)
      : -1
    const nextIdx =
      e.key === 'ArrowDown'
        ? Math.min(events.length - 1, currentIdx + 1)
        : Math.max(0, currentIdx <= 0 ? 0 : currentIdx - 1)
    const targetEv = events[nextIdx]
    if (targetEv) {
      onSelectRow(getRowKey(targetEv, nextIdx), targetEv)
    }
  }

  return (
    <div
      onKeyDown={handleKeyDown}
      className="bg-surface rounded-2xl border border-subtle shadow-sm flex flex-col h-[calc(100vh-300px)] min-h-[460px] max-h-[780px] overflow-hidden"
    >
      {pendingNewCount > 0 && (
        <div className="px-3 pt-2.5 pb-1 shrink-0">
          <button
            type="button"
            onClick={onJumpToTop}
            className="w-full flex items-center justify-center gap-2 py-1.5 px-3 rounded-xl text-xs font-semibold bg-sky-50 hover:bg-sky-100 text-sky-900 border border-sky-300 dark:bg-sky-950/60 dark:hover:bg-sky-900/60 dark:text-sky-200 dark:border-sky-700/60 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/50"
          >
            <ArrowUp className="w-3.5 h-3.5" />
            <span>
              {pendingNewCount} new {pendingNewCount === 1 ? 'event' : 'events'} — Jump to top
            </span>
          </button>
        </div>
      )}

      <div
        ref={listContainerRef}
        onScroll={(e) => onScrollTopChange(e.currentTarget.scrollTop)}
        className="flex-1 overflow-y-auto p-3 space-y-2"
        aria-busy={isLoading && events.length === 0}
      >
        {isLoading && events.length === 0 ? (
          <div className="space-y-2.5" aria-label="Loading audit records">
            {Array.from({ length: 6 }).map((_, idx) => (
              <div
                key={idx}
                className="h-16 rounded-xl border border-subtle bg-canvas/70 animate-pulse motion-reduce:animate-none"
              />
            ))}
          </div>
        ) : events.length === 0 ? (
          <div className="h-full min-h-[280px] flex flex-col items-center justify-center text-secondary gap-2.5 text-center px-4">
            <Shield className="w-8 h-8 text-muted" />
            <div className="text-sm font-medium text-primary">No matching audit records</div>
            <p className="text-xs text-muted max-w-xs">
              {hasActiveFilters
                ? 'No tool invocations match the active search, verdict, rule, or time filters.'
                : 'New MCP tool calls and tools/list exchanges will appear at the top of this stream automatically.'}
            </p>
            {hasActiveFilters && (
              <button
                type="button"
                onClick={onClearFilters}
                className="mt-1 px-3 py-1.5 rounded-lg text-xs font-semibold bg-sky-50 text-sky-800 border border-sky-300 hover:bg-sky-100 dark:bg-sky-500/15 dark:hover:bg-sky-500/25 dark:text-sky-200 dark:border-sky-400/40 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/50"
              >
                Clear filters
              </button>
            )}
          </div>
        ) : (
          events.map((ev, idx) => {
            const key = getRowKey(ev, idx)
            return (
              <AuditEventRow
                key={key}
                event={ev}
                rowKey={key}
                isSelected={selectedRowKey === key}
                copiedTrace={copiedId === `trace-${key}`}
                onSelect={onSelectRow}
                onCopyTrace={onCopyTrace}
              />
            )
          })
        )}
      </div>

      {/* Sticky Always-Visible Pagination Footer */}
      <div className="shrink-0 flex items-center justify-between gap-2 text-xs font-mono tabular-nums text-secondary bg-canvas/80 px-3.5 py-2.5 border-t border-subtle">
        <span className="truncate">
          Page {currentPage} of {totalPages} · {events.length} shown ({totalCount.toLocaleString()} total)
        </span>
        <div className="flex items-center gap-1.5 shrink-0">
          <button
            type="button"
            disabled={offset === 0}
            onClick={onPrevPage}
            className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg border border-subtle bg-surface hover:bg-surface-elevated text-primary disabled:opacity-40 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/50"
          >
            <ChevronLeft className="w-3.5 h-3.5" />
            <span>Prev</span>
          </button>
          <button
            type="button"
            disabled={offset + PAGE_SIZE >= totalCount}
            onClick={onNextPage}
            className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg border border-subtle bg-surface hover:bg-surface-elevated text-primary disabled:opacity-40 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/50"
          >
            <span>Next</span>
            <ChevronRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </div>
  )
}
