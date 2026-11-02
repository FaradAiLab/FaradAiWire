import React from 'react'
import { PolicyPack, DlpRule } from '../../types'
import { Modal } from '../ui/Modal'
import { Badge } from '../ui/Badge'
import { Button } from '../ui/Button'
import { ShieldCheck, Lock } from 'lucide-react'

export interface PackRulesViewModalProps {
  isOpen: boolean
  onClose: () => void
  pack: PolicyPack | null
  catalogRules: DlpRule[]
  onTestRule?: (rule: DlpRule) => void
}

export const PackRulesViewModal: React.FC<PackRulesViewModalProps> = ({
  isOpen,
  onClose,
  pack,
  catalogRules,
  onTestRule,
}) => {
  if (!pack) return null

  // Map rule_ids to catalog rule objects
  const rulesMap = new Map<string, DlpRule>()
  catalogRules.forEach((r) => rulesMap.set(r.id, r))

  const packRules = (pack.rule_ids || [])
    .map((id) => rulesMap.get(id))
    .filter((r): r is DlpRule => !!r)

  const getSeverityBadgeVariant = (severity?: string): 'rose' | 'amber' | 'neutral' => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL':
        return 'rose'
      case 'HIGH':
      case 'MEDIUM':
        return 'amber'
      default:
        return 'neutral'
    }
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={pack.name}
      subtitle={`Pack ID: ${pack.id} · Category: ${pack.category}`}
      icon={<ShieldCheck className="w-5 h-5" />}
      maxWidth="xl"
    >
      <div className="space-y-4">
        {pack.description && (
          <p className="text-xs text-secondary leading-relaxed font-sans bg-canvas p-3 rounded-xl border border-subtle">
            {pack.description}
          </p>
        )}

        <div className="flex items-center justify-between text-xs font-mono text-muted">
          <span>Active Rules in this Pack ({packRules.length})</span>
          {pack.is_builtin && (
            <span className="flex items-center gap-1 text-[11px] text-muted">
              <Lock className="w-3 h-3" /> Built-in Immutable Pack
            </span>
          )}
        </div>

        <div className="max-h-80 overflow-y-auto space-y-2.5 pr-1">
          {packRules.length === 0 ? (
            <p className="text-xs text-muted text-center py-8 font-mono">
              No rules are currently associated with this policy pack.
            </p>
          ) : (
            packRules.map((rule) => (
              <div
                key={rule.id}
                className="p-3.5 rounded-xl bg-canvas border border-subtle hover:border-strong transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono shadow-xs"
              >
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-bold text-primary font-mono">{rule.name}</span>
                    <Badge variant="indigo" size="sm">
                      {rule.category}
                    </Badge>
                    {rule.cwe && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded font-mono font-semibold bg-purple-50 dark:bg-purple-950/60 text-purple-700 dark:text-purple-300 border border-purple-200 dark:border-purple-800/40">
                        {rule.cwe}
                      </span>
                    )}
                    {rule.severity && (
                      <Badge variant={getSeverityBadgeVariant(rule.severity)} size="sm">
                        {rule.severity}
                      </Badge>
                    )}
                  </div>
                  <span className="text-[11px] text-muted block mt-0.5">{rule.id}</span>
                  <div className="mt-1.5">
                    <code className="text-[11px] font-mono text-sky-800 dark:text-cyan-300 bg-sky-50 dark:bg-cyan-950/40 px-2 py-0.5 rounded border border-sky-200 dark:border-cyan-500/30 break-all inline-block">
                      {rule.regex}
                    </code>
                  </div>
                </div>

                <div className="flex items-center gap-2 self-end sm:self-auto shrink-0">
                  <Badge
                    variant={
                      rule.default_action === 'block'
                        ? 'rose'
                        : rule.default_action === 'hitl' || rule.default_action === 'mask'
                        ? 'amber'
                        : 'cyan'
                    }
                    size="sm"
                  >
                    {rule.default_action}
                  </Badge>

                  {onTestRule && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        onClose()
                        onTestRule(rule)
                      }}
                    >
                      Test
                    </Button>
                  )}
                </div>
              </div>
            ))
          )}
        </div>

        <div className="flex justify-end pt-3 border-t border-subtle">
          <Button variant="secondary" size="md" onClick={onClose}>
            Close
          </Button>
        </div>
      </div>
    </Modal>
  )
}
