import React from 'react'
import { RotateCcw, ShieldCheck, X } from 'lucide-react'
import { Button } from '../ui/Button'
import { ToolGovernanceMode } from '../../types'

export interface ProtocolRestorationBannerProps {
  protocolId: string
  protocolName: string
  retainedRules: Record<string, ToolGovernanceMode>
  onRestore: (rules: Record<string, ToolGovernanceMode>) => void
  onDismiss: () => void
}

export const ProtocolRestorationBanner: React.FC<ProtocolRestorationBannerProps> = ({
  protocolId,
  protocolName,
  retainedRules,
  onRestore,
  onDismiss,
}) => {
  const ruleCount = Object.keys(retainedRules).length
  if (ruleCount === 0) return null

  return (
    <div className="p-3.5 rounded-2xl bg-gradient-to-r from-cyan-950/40 via-blue-950/30 to-indigo-950/40 border border-cyan-500/30 shadow-lg shadow-cyan-950/20 backdrop-blur-md animate-in fade-in duration-200">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-2.5">
          <div className="p-1.5 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 mt-0.5">
            <RotateCcw className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono font-bold text-xs text-cyan-200">
                Retained Governance Found (Configuration Retention)
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                {ruleCount} rule{ruleCount === 1 ? '' : 's'}
              </span>
            </div>
            <p className="text-xs text-gray-300 mt-1 leading-relaxed font-sans">
              Previously configured <span className="font-bold text-cyan-300">{ruleCount} governance rule{ruleCount === 1 ? '' : 's'}</span> are
              preserved for <span className="font-mono font-bold text-white">{protocolName}</span> ({protocolId}). You can restore your previous security policies with one click.
            </p>

            <div className="flex items-center gap-2 mt-3">
              <Button
                type="button"
                variant="primary"
                size="sm"
                onClick={() => onRestore(retainedRules)}
                icon={<ShieldCheck className="w-3.5 h-3.5" />}
              >
                Restore Previous Settings ({ruleCount})
              </Button>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={onDismiss}
              >
                Apply Fresh Defaults
              </Button>
            </div>
          </div>
        </div>

        <button
          type="button"
          onClick={onDismiss}
          className="text-gray-400 hover:text-gray-200 p-1 rounded-lg hover:bg-white/5 transition-colors"
          title="Dismiss banner"
        >
          <X className="w-4 h-4" />
        </button>
      </div>
    </div>
  )
}
