import React from 'react'
import { SmartRecommendation } from '../../types'
import { Button } from '../ui/Button'
import { Badge } from '../ui/Badge'
import { Sparkles, ShieldCheck, Check } from 'lucide-react'

export interface SmartRecommendationCardProps {
  recommendations: SmartRecommendation[]
  attachedPackIds: string[]
  onAttachPack: (packId: string) => void
}

export const SmartRecommendationCard: React.FC<SmartRecommendationCardProps> = ({
  recommendations,
  attachedPackIds,
  onAttachPack,
}) => {
  if (recommendations.length === 0) return null

  const attachedSet = new Set(attachedPackIds)

  return (
    <div className="glass-card p-4 rounded-xl border border-sky-300 dark:border-cyan-500/30 bg-sky-50/40 dark:bg-cyan-950/20 space-y-3 relative overflow-hidden">
      <div className="flex items-center gap-2 text-sky-900 dark:text-cyan-300">
        <Sparkles className="w-4 h-4 text-accent-primary shrink-0" />
        <span className="text-xs font-bold font-mono uppercase tracking-wider">
          Smart Security Recommendations
        </span>
      </div>

      <p className="text-xs text-secondary leading-relaxed">
        Based on the MCP tools and backends attached to this agent, the following DLP policy packs are strongly recommended:
      </p>

      <div className="space-y-2">
        {recommendations.map((rec) => {
          const isAttached = attachedSet.has(rec.pack_id)
          return (
            <div
              key={rec.pack_id}
              className="p-3.5 rounded-xl bg-surface border border-subtle hover:border-strong transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 text-xs font-mono shadow-xs"
            >
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-emerald-500 shrink-0" />
                  <span className="font-bold text-primary">{rec.pack_name}</span>
                  <span className="text-[10px] text-muted">{rec.pack_id}</span>
                </div>
                <p className="text-[11px] text-muted font-sans mt-1">
                  {rec.rationale}
                </p>
                {rec.matched_tools && rec.matched_tools.length > 0 && (
                  <div className="flex items-center gap-1.5 mt-1.5 flex-wrap">
                    <span className="text-[10px] text-muted">Matched tools:</span>
                    {rec.matched_tools.slice(0, 4).map((tool) => (
                      <Badge key={tool} variant="neutral" size="sm">
                        {tool}
                      </Badge>
                    ))}
                    {rec.matched_tools.length > 4 && (
                      <span className="text-[10px] text-muted">
                        +{rec.matched_tools.length - 4} more
                      </span>
                    )}
                  </div>
                )}
              </div>

              <div className="self-end sm:self-auto shrink-0">
                {isAttached ? (
                  <Badge variant="emerald" size="sm" icon={<Check className="w-3 h-3" />}>
                    Attached
                  </Badge>
                ) : (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => onAttachPack(rec.pack_id)}
                  >
                    Attach Pack
                  </Button>
                )}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
