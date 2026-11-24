import React from 'react'
import { Search, X } from 'lucide-react'

interface AuditFilterBarProps {
  filterText: string
  matchedRuleFilter: string
  sinceInput: string
  untilInput: string
  selectedVerdict: string
  onFilterTextChange: (value: string) => void
  onMatchedRuleChange: (value: string) => void
  onSinceChange: (value: string) => void
  onUntilChange: (value: string) => void
  onClearFilters: () => void
}

export const AuditFilterBar: React.FC<AuditFilterBarProps> = ({
  filterText,
  matchedRuleFilter,
  sinceInput,
  untilInput,
  selectedVerdict,
  onFilterTextChange,
  onMatchedRuleChange,
  onSinceChange,
  onUntilChange,
  onClearFilters,
}) => {
  const hasFilters = Boolean(
    filterText.trim() ||
      matchedRuleFilter.trim() ||
      sinceInput ||
      untilInput ||
      selectedVerdict !== 'ALL'
  )

  return (
    <div className="flex flex-wrap items-center gap-2.5 bg-surface p-2.5 rounded-xl border border-subtle shadow-sm">
      <div className="relative flex-1 min-w-[220px]">
        <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
        <input
          type="text"
          aria-label="Search tool invocation metadata"
          placeholder="Search tool, agent, rule, error, user, trace ID..."
          value={filterText}
          onChange={(e) => onFilterTextChange(e.target.value)}
          className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-canvas border border-subtle text-xs text-primary placeholder:text-muted focus:outline-none focus:border-accent focus-visible:ring-2 focus-visible:ring-accent/40 font-mono transition-colors"
        />
      </div>

      <input
        type="text"
        aria-label="Filter by matched security rule"
        placeholder="Rule (e.g. tckn, guard)"
        value={matchedRuleFilter}
        onChange={(e) => onMatchedRuleChange(e.target.value)}
        className="w-44 px-3 py-1.5 rounded-lg bg-canvas border border-subtle text-xs text-primary placeholder:text-muted focus:outline-none focus:border-accent focus-visible:ring-2 focus-visible:ring-accent/40 font-mono transition-colors"
      />

      <div className="flex items-center gap-1.5">
        <label htmlFor="audit-since-input" className="text-[11px] font-medium text-secondary">
          From
        </label>
        <input
          id="audit-since-input"
          type="datetime-local"
          value={sinceInput}
          onChange={(e) => onSinceChange(e.target.value)}
          className="px-2.5 py-1.5 rounded-lg bg-canvas border border-subtle text-xs text-primary focus:outline-none focus:border-accent focus-visible:ring-2 focus-visible:ring-accent/40 font-mono"
        />
      </div>

      <div className="flex items-center gap-1.5">
        <label htmlFor="audit-until-input" className="text-[11px] font-medium text-secondary">
          To
        </label>
        <input
          id="audit-until-input"
          type="datetime-local"
          value={untilInput}
          onChange={(e) => onUntilChange(e.target.value)}
          className="px-2.5 py-1.5 rounded-lg bg-canvas border border-subtle text-xs text-primary focus:outline-none focus:border-accent focus-visible:ring-2 focus-visible:ring-accent/40 font-mono"
        />
      </div>

      {hasFilters && (
        <button
          type="button"
          onClick={onClearFilters}
          className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-medium text-secondary hover:text-primary bg-canvas hover:bg-surface-elevated border border-subtle transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/50"
        >
          <X className="w-3.5 h-3.5" />
          <span>Reset</span>
        </button>
      )}
    </div>
  )
}
