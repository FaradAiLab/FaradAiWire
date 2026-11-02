import React, { useState, useMemo } from 'react'
import { DlpRule } from '../../types'
import { Badge } from '../ui/Badge'
import { Button } from '../ui/Button'
import { Search, Lock, Edit3, Trash2, Plus, Copy, Check, Play } from 'lucide-react'

export interface RulesCatalogListProps {
  rules: DlpRule[]
  activeRuleId?: string | null
  onCreateRule: () => void
  onEditRule: (rule: DlpRule) => void
  onDeleteRule: (rule: DlpRule) => void
  onTestRule?: (rule: DlpRule) => void
}

export const RulesCatalogList: React.FC<RulesCatalogListProps> = ({
  rules,
  activeRuleId,
  onCreateRule,
  onEditRule,
  onDeleteRule,
  onTestRule,
}) => {
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedCategory, setSelectedCategory] = useState<string>('all')
  const [copiedId, setCopiedId] = useState<string | null>(null)

  const categories = useMemo(() => {
    const cats = new Set<string>()
    rules.forEach((r) => {
      if (r.category) cats.add(r.category)
    })
    return ['all', ...Array.from(cats).sort()]
  }, [rules])

  const filteredRules = useMemo(() => {
    return rules.filter((r) => {
      const matchesCategory =
        selectedCategory === 'all' ||
        r.category.toLowerCase() === selectedCategory.toLowerCase()
      const search = searchTerm.toLowerCase().trim()
      const matchesSearch =
        !search ||
        r.id.toLowerCase().includes(search) ||
        r.name.toLowerCase().includes(search) ||
        (r.description && r.description.toLowerCase().includes(search)) ||
        r.regex.toLowerCase().includes(search)
      return matchesCategory && matchesSearch
    })
  }, [rules, selectedCategory, searchTerm])

  const handleCopyRegex = (id: string, regex: string) => {
    navigator.clipboard.writeText(regex)
    setCopiedId(id)
    setTimeout(() => setCopiedId(null), 1500)
  }

  const getActionBadge = (action: string) => {
    switch (action?.toLowerCase()) {
      case 'block':
        return <Badge variant="rose" size="sm">BLOCK</Badge>
      case 'hitl':
        return <Badge variant="amber" size="sm">HITL</Badge>
      case 'mask':
        return <Badge variant="amber" size="sm">MASK</Badge>
      case 'audit':
      default:
        return <Badge variant="cyan" size="sm">AUDIT</Badge>
    }
  }

  return (
    <div className="space-y-4">
      {/* Controls Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
        <div className="flex flex-1 items-center gap-2 max-w-md">
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
            <input
              type="text"
              placeholder="Search rules by ID, name, or regex pattern..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-9 pr-3 py-2 rounded-xl bg-surface border border-subtle text-xs text-primary placeholder:text-muted focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 font-mono"
            />
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="primary"
            size="sm"
            icon={<Plus className="w-4 h-4" />}
            onClick={onCreateRule}
          >
            Create Custom Rule
          </Button>
        </div>
      </div>

      {/* Category Filter Pills (WCAG High-Contrast Fix) */}
      <div className="flex items-center gap-1.5 overflow-x-auto pb-1">
        {categories.map((cat) => {
          const isSelected = selectedCategory === cat
          const count = cat === 'all' ? rules.length : rules.filter((r) => r.category === cat).length

          return (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat)}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors capitalize whitespace-nowrap flex items-center gap-1.5 ${
                isSelected
                  ? 'bg-cyan-600 text-white shadow-xs font-bold border border-cyan-700/20 dark:bg-cyan-600 dark:border-cyan-500/40'
                  : 'bg-surface text-secondary hover:text-primary hover:bg-surface-elevated border border-subtle'
              }`}
            >
              <span>{cat}</span>
              <span
                className={`text-[10px] px-1.5 py-0.2 rounded-full font-bold ${
                  isSelected
                    ? 'bg-white/25 text-white'
                    : 'bg-surface-muted text-muted'
                }`}
              >
                {count}
              </span>
            </button>
          )
        })}
      </div>

      {/* Rules Table */}
      <div className="glass-card overflow-hidden border border-subtle rounded-2xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono border-collapse">
            <thead>
              <tr className="border-b border-subtle bg-surface-elevated/40 text-muted">
                <th className="py-3 px-4 font-semibold min-w-[220px]">Rule Name & ID</th>
                <th className="py-3 px-4 font-semibold w-28">Category</th>
                <th className="py-3 px-4 font-semibold w-32">Default Action</th>
                <th className="py-3 px-4 font-semibold min-w-[280px]">Regex Pattern</th>
                <th className="py-3 px-4 font-semibold text-right w-28">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-subtle text-secondary">
              {filteredRules.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-12 text-center text-muted">
                    No DLP pattern rules match your search or filter.
                  </td>
                </tr>
              ) : (
                filteredRules.map((rule) => {
                  const isTested = activeRuleId === rule.id

                  return (
                    <tr
                      key={rule.id}
                      className={`transition-colors group ${
                        isTested
                          ? 'bg-cyan-50/80 dark:bg-cyan-950/40 border-l-4 border-l-cyan-600 dark:border-l-cyan-400 font-medium'
                          : 'hover:bg-surface-elevated/50'
                      }`}
                    >
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-bold text-primary">{rule.name}</span>
                          {isTested && (
                            <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-cyan-700 text-white dark:bg-cyan-500 dark:text-slate-950 shadow-xs animate-pulse">
                              <Play className="w-2.5 h-2.5 fill-current" /> TESTING
                            </span>
                          )}
                          {rule.is_builtin && (
                            <span title="Built-in Standard Rule (Immutable)">
                              <Lock className="w-3 h-3 text-muted" />
                            </span>
                          )}
                          {rule.cwe && (
                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-purple-50 dark:bg-purple-950/60 text-purple-700 dark:text-purple-300 border border-purple-200 dark:border-purple-800/40 font-mono font-semibold">
                              {rule.cwe}
                            </span>
                          )}
                          {rule.severity && (
                            <Badge
                              variant={
                                rule.severity === 'CRITICAL'
                                  ? 'rose'
                                  : rule.severity === 'HIGH' || rule.severity === 'MEDIUM'
                                  ? 'amber'
                                  : 'neutral'
                              }
                              size="sm"
                            >
                              {rule.severity}
                            </Badge>
                          )}
                        </div>
                        <span className="text-[11px] text-muted block mt-0.5">{rule.id}</span>
                        {rule.description && (
                          <p className="text-[11px] text-muted font-sans mt-0.5 max-w-sm line-clamp-1">
                            {rule.description}
                          </p>
                        )}
                      </td>

                      <td className="py-3 px-4">
                        <Badge variant="indigo" size="sm">
                          {rule.category}
                        </Badge>
                      </td>

                      <td className="py-3 px-4">
                        {getActionBadge(rule.default_action)}
                      </td>

                      {/* Full Uncut Regex Pattern Column with Screen Real Estate Utilization */}
                      <td className="py-3 px-4 min-w-[280px]">
                        <div className="flex items-center gap-2">
                          <code className="text-xs font-mono text-sky-900 dark:text-cyan-300 bg-sky-50/90 dark:bg-cyan-950/50 px-2.5 py-1 rounded-lg border border-sky-200 dark:border-cyan-500/30 break-all select-all font-semibold inline-block">
                            {rule.regex}
                          </code>
                          <button
                            type="button"
                            onClick={() => handleCopyRegex(rule.id, rule.regex)}
                            className="text-muted hover:text-primary p-1.5 rounded-md hover:bg-surface-elevated transition-colors shrink-0"
                            title="Copy exact regex"
                          >
                            {copiedId === rule.id ? (
                              <Check className="w-3.5 h-3.5 text-emerald-500" />
                            ) : (
                              <Copy className="w-3.5 h-3.5" />
                            )}
                          </button>
                        </div>
                      </td>

                      <td className="py-3 px-4 text-right">
                        <div className="flex items-center justify-end gap-1">
                          {onTestRule && (
                            <Button
                              variant={isTested ? 'primary' : 'ghost'}
                              size="sm"
                              onClick={() => onTestRule(rule)}
                              title={isTested ? 'Currently loaded in sandbox' : 'Test pattern in live sandbox'}
                              className={isTested ? 'shadow-xs' : 'text-cyan-600 hover:text-cyan-700 dark:text-cyan-400'}
                            >
                              <Play className="w-3 h-3 fill-current" />
                              <span className="hidden sm:inline text-[11px]">
                                {isTested ? 'Testing' : 'Test'}
                              </span>
                            </Button>
                          )}
                          {!rule.is_builtin && (
                            <>
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => onEditRule(rule)}
                                title="Edit custom rule"
                              >
                                <Edit3 className="w-3 h-3 text-muted hover:text-primary" />
                              </Button>
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => onDeleteRule(rule)}
                                title="Delete custom rule"
                                className="hover:text-rose-500"
                              >
                                <Trash2 className="w-3 h-3 text-rose-500" />
                              </Button>
                            </>
                          )}
                        </div>
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
