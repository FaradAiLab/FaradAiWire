import React, { useState, useRef, useEffect } from 'react'
import { Search, Plus, Terminal, Globe, Server, ChevronDown } from 'lucide-react'
import { ProtocolItem } from '../../types'

export interface ProtocolSearchComboboxProps {
  protocols: ProtocolItem[]
  selectedProtocolIds: string[]
  onSelectProtocol: (protocolId: string) => void
  onOpenRegisterModal: () => void
}

export const ProtocolSearchCombobox: React.FC<ProtocolSearchComboboxProps> = ({
  protocols,
  selectedProtocolIds,
  onSelectProtocol,
  onOpenRegisterModal,
}) => {
  const [isOpen, setIsOpen] = useState(false)
  const [query, setQuery] = useState('')
  const containerRef = useRef<HTMLDivElement>(null)

  // Filter unattached protocols
  const selectedSet = new Set(selectedProtocolIds.map((id) => id.toLowerCase()))
  const unattached = protocols.filter(
    (p) => !selectedSet.has((p.protocol_id || p.id || p.name).toLowerCase())
  )

  const filtered = unattached.filter((p) => {
    const q = query.toLowerCase()
    return (
      p.name.toLowerCase().includes(q) ||
      p.id.toLowerCase().includes(q) ||
      (p.description && p.description.toLowerCase().includes(q)) ||
      p.type.toLowerCase().includes(q)
    )
  })

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setIsOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const getTypeIcon = (type: string) => {
    switch (type.toLowerCase()) {
      case 'stdio':
        return <Terminal className="w-3.5 h-3.5 text-amber-400" />
      case 'sse':
        return <Server className="w-3.5 h-3.5 text-cyan-400" />
      default:
        return <Globe className="w-3.5 h-3.5 text-indigo-400" />
    }
  }

  return (
    <div ref={containerRef} className="relative w-full">
      <div className="relative">
        <Search className="w-4 h-4 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
        <input
          type="text"
          placeholder="+ Attach Protocol from Catalog (Search: Context7, Tavily, Postgres, Github...)"
          value={query}
          onChange={(e) => {
            setQuery(e.target.value)
            setIsOpen(true)
          }}
          onFocus={() => setIsOpen(true)}
          className="w-full bg-surface border border-subtle rounded-xl pl-9 pr-8 py-2 text-xs text-primary placeholder-muted font-mono focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent transition-all"
        />
        <ChevronDown className="w-3.5 h-3.5 text-muted absolute right-3 top-1/2 -translate-y-1/2 pointer-events-none" />
      </div>

      {isOpen && (
        <div className="absolute top-full left-0 right-0 mt-1.5 z-40 bg-surface border border-subtle rounded-xl shadow-2xl backdrop-blur-xl overflow-hidden animate-in fade-in duration-150">
          <div className="max-h-72 overflow-y-auto divide-y divide-subtle">
            {filtered.length > 0 ? (
              filtered.map((p) => {
                const protoId = p.protocol_id || p.id || p.name
                return (
                  <button
                    key={p.id}
                    type="button"
                    onClick={() => {
                      onSelectProtocol(protoId)
                      setQuery('')
                      setIsOpen(false)
                    }}
                    className="w-full p-2.5 text-left flex items-start justify-between gap-2 hover:bg-accent/10 hover:text-accent transition-colors group"
                  >
                    <div className="flex items-start gap-2.5 truncate">
                      <div className="mt-0.5 p-1 rounded-lg bg-surface-muted group-hover:bg-accent/20 transition-colors">
                        {getTypeIcon(p.type)}
                      </div>
                      <div className="truncate">
                        <div className="flex items-center gap-1.5">
                          <span className="font-bold text-xs text-primary group-hover:text-accent font-mono">
                            {p.name}
                          </span>
                          <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-surface border border-subtle text-muted">
                            {p.type}
                          </span>
                        </div>
                        <p className="text-[10px] text-muted font-mono truncate mt-0.5">
                          {p.id} {p.description ? `• ${p.description}` : ''}
                        </p>
                      </div>
                    </div>
                    <span className="text-[10px] font-mono text-accent opacity-0 group-hover:opacity-100 transition-opacity shrink-0 flex items-center gap-1">
                      <Plus className="w-3 h-3" /> Attach
                    </span>
                  </button>
                )
              })
            ) : (
              <div className="p-3 text-center text-xs text-muted font-mono">
                {query ? 'No matching protocols found.' : 'All catalog protocols are already attached to this agent.'}
              </div>
            )}
          </div>

          {/* Quick Register Footer */}
          <div className="p-2 border-t border-subtle bg-surface-muted/30">
            <button
              type="button"
              onClick={() => {
                setIsOpen(false)
                onOpenRegisterModal()
              }}
              className="w-full py-1.5 px-3 rounded-lg bg-accent/10 border border-accent/30 hover:bg-accent/20 text-accent text-xs font-mono flex items-center justify-center gap-1.5 transition-colors"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>+ Register New Custom MCP Protocol...</span>
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
