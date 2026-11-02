import React from 'react'
import { Terminal, Globe, Sliders, Trash2, Pencil } from 'lucide-react'
import { ProtocolItem } from '../../types'
import { Badge } from '../ui/Badge'

export interface ProtocolCardProps {
  protocol: ProtocolItem
  onOpenDrawer: (p: ProtocolItem) => void
  onEdit: (p: ProtocolItem) => void
  onDelete: (id: string, name: string) => void
}

export const ProtocolCard: React.FC<ProtocolCardProps> = React.memo(
  ({ protocol, onOpenDrawer, onEdit, onDelete }) => {
    const hasWhitelist = protocol.allowed_tools && protocol.allowed_tools.length > 0
    const isStdio = protocol.type === 'stdio'

    return (
      <div className="bg-surface border border-subtle hover:border-default rounded-2xl p-5 transition-all flex flex-col justify-between">
        <div>
          <div className="flex items-start justify-between gap-2 mb-2">
            <div className="flex items-center gap-2">
              <div
                className={`p-1.5 rounded-lg border ${
                  isStdio
                    ? 'bg-amber-500/10 border-amber-500/20 text-amber-500 dark:text-amber-400'
                    : 'bg-cyan-500/10 border-cyan-500/20 text-cyan-600 dark:text-cyan-400'
                }`}
              >
                {isStdio ? (
                  <Terminal className="w-4 h-4 shrink-0" />
                ) : (
                  <Globe className="w-4 h-4 shrink-0" />
                )}
              </div>
              <div>
                <h4 className="font-bold text-sm text-primary font-mono">{protocol.name}</h4>
                <span className="text-[10px] font-mono text-accent-primary">id: {protocol.id}</span>
              </div>
            </div>
            <Badge variant={isStdio ? 'amber' : 'cyan'}>{protocol.type}</Badge>
          </div>

          <p className="text-xs text-muted line-clamp-2 my-2">
            {protocol.description || 'Configured MCP protocol backend'}
          </p>

          <div className="text-[11px] font-mono bg-[#0F172A] p-2 rounded-lg border border-[#1E293B] text-cyan-400 truncate shadow-inner">
            {protocol.url_or_command || protocol.command}
          </div>
        </div>

        <div className="mt-4 pt-3 border-t border-subtle flex items-center justify-between text-xs">
          <button
            type="button"
            onClick={() => onOpenDrawer(protocol)}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-surface hover:bg-surface/80 border border-subtle text-[11px] font-mono text-primary transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent-primary"
            title="Configure Layer 1 Tool Whitelist"
          >
            <Sliders className="w-3.5 h-3.5 text-accent-primary" />
            <span>{hasWhitelist ? `${protocol.allowed_tools?.length} allowed` : 'All tools'}</span>
          </button>

          <div className="flex items-center gap-1.5">
            <button
              type="button"
              onClick={() => onEdit(protocol)}
              className="flex items-center gap-1 px-2 py-1 rounded-lg bg-surface hover:bg-surface/80 border border-subtle text-[11px] font-mono text-primary hover:text-accent-primary transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent-primary"
              title="Edit Protocol Configuration & Headers"
              aria-label={`Edit protocol ${protocol.name}`}
            >
              <Pencil className="w-3.5 h-3.5 text-accent-primary" />
              <span>Edit</span>
            </button>

            <button
              type="button"
              onClick={() => onDelete(protocol.id, protocol.name)}
              className="p-1.5 rounded-lg text-muted hover:text-rose-500 hover:bg-rose-500/10 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-500"
              title="Delete protocol"
              aria-label={`Delete protocol ${protocol.name}`}
            >
              <Trash2 className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    )
  }
)

ProtocolCard.displayName = 'ProtocolCard'
