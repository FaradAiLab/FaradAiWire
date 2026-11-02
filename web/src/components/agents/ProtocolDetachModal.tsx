import React from 'react'
import { AlertTriangle, Database, X } from 'lucide-react'
import { Modal } from '../ui/Modal'
import { Button } from '../ui/Button'

export interface ProtocolDetachModalProps {
  isOpen: boolean
  onClose: () => void
  onConfirmDetach: () => void
  protocolName: string
  protocolId: string
  governanceRulesCount: number
  scopedToolsCount: number
  affectedTools: { name: string; mode?: string }[]
}

export const ProtocolDetachModal: React.FC<ProtocolDetachModalProps> = ({
  isOpen,
  onClose,
  onConfirmDetach,
  protocolName,
  protocolId,
  governanceRulesCount,
  scopedToolsCount,
  affectedTools,
}) => {
  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Detach Protocol (Rule Protection)"
      subtitle={`Confirm detaching "${protocolName}" protocol from agent`}
      icon={<AlertTriangle className="w-5 h-5 text-amber-400" />}
      maxWidth="md"
    >
      <div className="space-y-4">
        {/* Warning Banner */}
        <div className="p-3.5 rounded-xl bg-amber-50 dark:bg-amber-500/10 border border-amber-300 dark:border-amber-500/30 text-amber-900 dark:text-amber-200">
          <div className="flex items-start gap-2.5">
            <AlertTriangle className="w-4 h-4 text-amber-500 mt-0.5 shrink-0" />
            <div className="text-xs space-y-1">
              <p className="font-semibold text-amber-800 dark:text-amber-300">
                Active tool rules detected for this MCP protocol!
              </p>
              <p className="text-secondary leading-relaxed font-sans">
                <span className="font-mono font-bold text-primary">{protocolName}</span> ({protocolId}) has{' '}
                <span className="font-bold text-amber-700 dark:text-amber-300">{governanceRulesCount} governance/HITL rule(s)</span> and{' '}
                <span className="font-bold text-accent-primary">{scopedToolsCount} scoped tool(s)</span> configured.
              </p>
            </div>
          </div>
        </div>

        {/* Affected Tools List */}
        {affectedTools.length > 0 && (
          <div className="space-y-1.5">
            <label className="text-[11px] font-mono text-muted uppercase tracking-wider block">
              Affected Tools &amp; Governance Policies ({affectedTools.length})
            </label>
            <div className="max-h-40 overflow-y-auto space-y-1 pr-1 border border-subtle rounded-xl p-2 bg-canvas">
              {affectedTools.map((tool) => (
                <div
                  key={tool.name}
                  className="flex items-center justify-between p-2 rounded-lg bg-surface border border-subtle text-xs font-mono"
                >
                  <span className="truncate text-primary font-medium">{tool.name}</span>
                  {tool.mode && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded font-mono font-semibold bg-sky-50 dark:bg-cyan-950/60 border border-sky-200 dark:border-cyan-500/30 text-sky-800 dark:text-cyan-300 shrink-0">
                      {tool.mode}
                    </span>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Farad Ai Governance Retention Guarantee Note */}
        <div className="p-3 rounded-xl bg-sky-50 dark:bg-cyan-950/30 border border-sky-200 dark:border-cyan-500/20 text-sky-900 dark:text-cyan-300 text-xs">
          <div className="flex items-start gap-2">
            <Database className="w-4 h-4 text-accent-primary mt-0.5 shrink-0" />
            <div>
              <p className="font-semibold text-sky-950 dark:text-cyan-200 font-mono text-[11px]">
                Farad Ai Configuration Retention Memory
              </p>
              <p className="text-secondary text-[11px] mt-0.5 leading-relaxed font-sans">
                Detaching this protocol will not permanently delete your rules; they will be preserved in the agent&apos;s retained governance store.
                If you re-attach this protocol later, you can restore all previous rules with a single click.
              </p>
            </div>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center justify-end gap-2 pt-3 border-t border-subtle">
          <Button type="button" variant="ghost" size="md" onClick={onClose}>
            Cancel
          </Button>
          <Button
            type="button"
            variant="danger"
            size="md"
            onClick={() => {
              onConfirmDetach()
              onClose()
            }}
            icon={<X className="w-3.5 h-3.5" />}
          >
            Yes, Detach Protocol
          </Button>
        </div>
      </div>
    </Modal>
  )
}
