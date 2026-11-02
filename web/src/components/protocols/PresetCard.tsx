import React from 'react'
import { Terminal, Globe, Lock, Check } from 'lucide-react'
import { PresetMetadata } from '../../types'
import { Badge } from '../ui/Badge'
import { Button } from '../ui/Button'

export interface PresetCardProps {
  preset: PresetMetadata
  isInstalled: boolean
  onInstall: (preset: PresetMetadata) => void
}

export const PresetCard: React.FC<PresetCardProps> = React.memo(
  ({ preset, isInstalled, onInstall }) => {
    const isStdio = preset.type === 'stdio'

    return (
      <div className="bg-surface border border-subtle hover:border-accent-primary/40 rounded-2xl p-5 transition-all flex flex-col justify-between">
        <div>
          <div className="flex items-start justify-between gap-2 mb-2">
            <div className="flex items-center gap-2">
              {isStdio ? (
                <Terminal className="w-4 h-4 text-amber-500 dark:text-amber-400 shrink-0" />
              ) : (
                <Globe className="w-4 h-4 text-cyan-600 dark:text-cyan-400 shrink-0" />
              )}
              <h4 className="font-bold text-sm text-primary">{preset.name}</h4>
            </div>
            <Badge variant="neutral">{preset.category}</Badge>
          </div>

          <p className="text-xs text-muted line-clamp-2 leading-relaxed mb-3">
            {preset.description}
          </p>

          {preset.env_requirements && preset.env_requirements.length > 0 && (
            <div className="flex items-center gap-1.5 text-[10px] font-mono text-muted mb-2">
              <Lock className="w-3 h-3 text-accent-primary shrink-0" />
              <span className="truncate">Env: {preset.env_requirements.join(', ')}</span>
            </div>
          )}
        </div>

        <div className="mt-4 pt-3 border-t border-subtle flex items-center justify-between">
          <span className="text-[10px] font-mono text-accent-primary">{preset.id}</span>
          {isInstalled ? (
            <span className="flex items-center gap-1 text-[11px] font-mono text-emerald-600 dark:text-emerald-400 font-semibold">
              <Check className="w-3.5 h-3.5" />
              Installed
            </span>
          ) : (
            <Button
              variant="secondary"
              size="sm"
              onClick={() => onInstall(preset)}
              aria-label={`Install ${preset.name}`}
            >
              Install
            </Button>
          )}
        </div>
      </div>
    )
  }
)

PresetCard.displayName = 'PresetCard'
