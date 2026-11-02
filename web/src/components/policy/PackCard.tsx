import React from 'react'
import { PolicyPack } from '../../types'
import { Badge } from '../ui/Badge'
import { Button } from '../ui/Button'
import { ShieldCheck, Lock, Edit3, Trash2, Layers } from 'lucide-react'

export interface PackCardProps {
  pack: PolicyPack
  onViewRules: (pack: PolicyPack) => void
  onEdit?: (pack: PolicyPack) => void
  onDelete?: (pack: PolicyPack) => void
}

export const PackCard: React.FC<PackCardProps> = ({
  pack,
  onViewRules,
  onEdit,
  onDelete,
}) => {
  const getCategoryColor = (cat: string): 'cyan' | 'indigo' | 'emerald' | 'amber' | 'neutral' => {
    switch (cat.toLowerCase()) {
      case 'compliance':
      case 'regional':
        return 'emerald'
      case 'cloud':
        return 'cyan'
      case 'database':
      case 'data':
        return 'indigo'
      case 'security':
        return 'amber'
      default:
        return 'neutral'
    }
  }

  return (
    <div className="bg-surface border border-subtle hover:border-default p-5 rounded-2xl flex flex-col justify-between transition-all relative overflow-hidden group shadow-xs">
      <div>
        <div className="flex items-start justify-between gap-3 mb-2">
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-accent-primary">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-primary font-mono tracking-wide flex items-center gap-2">
                {pack.name}
                {pack.is_builtin && (
                  <span title="Built-in System Pack (Immutable)">
                    <Lock className="w-3.5 h-3.5 text-muted" />
                  </span>
                )}
              </h3>
              <p className="text-xs text-muted font-mono mt-0.5">{pack.id}</p>
            </div>
          </div>

          <Badge variant={getCategoryColor(pack.category)} size="sm">
            {pack.category}
          </Badge>
        </div>

        <p className="text-xs text-muted mt-2 line-clamp-2 leading-relaxed">
          {pack.description || 'Standard governance policy pack for data protection.'}
        </p>

        <div className="mt-4 pt-3 border-t border-subtle flex items-center justify-between text-xs font-mono text-muted">
          <div className="flex items-center gap-1.5">
            <Layers className="w-3.5 h-3.5 text-accent-primary" />
            <span>
              <strong className="text-primary">{pack.rule_ids?.length || 0}</strong> Rules Active
            </span>
          </div>

          {pack.is_builtin ? (
            <span className="text-[10px] text-muted uppercase tracking-wider font-semibold">
              Standard
            </span>
          ) : (
            <span className="text-[10px] text-accent-primary uppercase tracking-wider font-semibold">
              Custom Pack
            </span>
          )}
        </div>
      </div>

      <div className="mt-5 pt-3 border-t border-subtle flex items-center justify-between gap-2">
        <Button
          variant="outline"
          size="sm"
          onClick={() => onViewRules(pack)}
          className="flex-1"
        >
          View Rules ({pack.rule_ids?.length || 0})
        </Button>

        {!pack.is_builtin && (
          <div className="flex items-center gap-1">
            {onEdit && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => onEdit(pack)}
                title="Edit Policy Pack"
                aria-label="Edit Policy Pack"
              >
                <Edit3 className="w-3.5 h-3.5" />
              </Button>
            )}
            {onDelete && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => onDelete(pack)}
                className="hover:text-rose-400 hover:bg-rose-500/10"
                title="Delete Policy Pack"
                aria-label="Delete Policy Pack"
              >
                <Trash2 className="w-3.5 h-3.5 text-rose-400" />
              </Button>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
