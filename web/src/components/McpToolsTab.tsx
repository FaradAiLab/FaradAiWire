import React, { useState, useEffect, useMemo } from 'react'
import { Wrench, Search, RefreshCw, Layers } from 'lucide-react'
import { ToolMetadata } from '../types'
import { api } from '../api'

export const McpToolsTab: React.FC = () => {
  const [tools, setTools] = useState<ToolMetadata[]>([])
  const [loading, setLoading] = useState(false)
  const [filterText, setFilterText] = useState('')
  const [selectedTool, setSelectedTool] = useState<ToolMetadata | null>(null)

  const fetchTools = async () => {
    try {
      setLoading(true)
      const res = await api.getMCPTools()
      setTools(res.tools || [])
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchTools()
  }, [])

  const filteredTools = useMemo(() => {
    if (!filterText.trim()) return tools
    const term = filterText.toLowerCase()
    return tools.filter((t) => (
      (t.name && t.name.toLowerCase().includes(term)) ||
      (t.canonical_name && t.canonical_name.toLowerCase().includes(term)) ||
      (t.protocol_name && t.protocol_name.toLowerCase().includes(term)) ||
      (t.description && t.description.toLowerCase().includes(term))
    ))
  }, [tools, filterText])

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-primary flex items-center gap-2">
            <Wrench className="w-5 h-5 text-accent-primary" />
            MCP Tools Catalog
          </h2>
          <p className="text-xs text-muted mt-1">
            Live aggregated tool inventory discovered across all active protocols and agent manifests.
          </p>
        </div>

        <button
          type="button"
          onClick={fetchTools}
          disabled={loading}
          className="flex items-center gap-2 px-3 py-1.5 rounded-xl text-xs font-semibold bg-surface hover:bg-surface/80 text-primary border border-subtle transition-all disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-accent-primary' : ''}`} />
          <span>Refresh Tools</span>
        </button>
      </div>

      <div className="relative">
        <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
        <input
          type="text"
          aria-label="Search tools"
          placeholder="Search tools by name, protocol, or description..."
          value={filterText}
          onChange={(e) => setFilterText(e.target.value)}
          className="w-full pl-9 pr-3 py-2 rounded-xl bg-surface border border-subtle text-xs text-primary placeholder:text-muted focus:outline-none focus:ring-1 focus:ring-accent-primary font-mono"
        />
      </div>

      {loading && tools.length === 0 ? (
        <div className="p-12 text-center text-muted text-sm rounded-2xl bg-surface/50 border border-subtle font-mono">
          Loading MCP tools inventory...
        </div>
      ) : filteredTools.length === 0 ? (
        <div className="p-12 text-center text-muted text-sm rounded-2xl border border-dashed border-subtle font-mono">
          No tools discovered matching your search filter.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredTools.map((t, idx) => (
            <div
              key={idx}
              onClick={() => setSelectedTool(t)}
              className="bg-surface border border-subtle hover:border-default rounded-2xl p-4 cursor-pointer flex flex-col justify-between transition-all shadow-xs"
            >
              <div>
                <div className="flex items-center justify-between gap-2 mb-2">
                  <span className="font-mono text-xs font-bold text-accent-primary break-all">{t.name}</span>
                  {t.protocol_name && (
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-indigo-500/10 text-indigo-700 dark:text-indigo-300 border border-indigo-500/30 shrink-0">
                      {t.protocol_name}
                    </span>
                  )}
                </div>

                {t.canonical_name && t.canonical_name !== t.name && (
                  <div className="text-[11px] font-mono text-muted mb-2">
                    canonical: {t.canonical_name}
                  </div>
                )}

                <p className="text-xs text-muted line-clamp-3 leading-relaxed">
                  {t.description || 'No description provided by upstream MCP server.'}
                </p>
              </div>

              <div className="mt-4 pt-3 border-t border-subtle flex items-center justify-between text-[11px] text-muted">
                <span className="flex items-center gap-1 font-mono">
                  <Layers className="w-3 h-3 text-accent-primary" />
                  JSON Schema
                </span>
                <span className="text-accent-primary hover:underline">Inspect</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Schema Detail Modal */}
      {selectedTool && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-xs">
          <div className="w-full max-w-xl p-6 bg-surface border border-subtle shadow-2xl relative rounded-2xl max-h-[85vh] flex flex-col animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-start justify-between gap-4 mb-4">
              <div>
                <span className="text-[10px] font-mono text-accent-primary uppercase tracking-wider">
                  {selectedTool.protocol_name || 'MCP TOOL'}
                </span>
                <h3 className="text-lg font-bold text-primary font-mono">{selectedTool.name}</h3>
                {selectedTool.canonical_name && (
                  <div className="text-xs font-mono text-muted">Canonical: {selectedTool.canonical_name}</div>
                )}
              </div>
              <button
                type="button"
                onClick={() => setSelectedTool(null)}
                className="text-muted hover:text-primary p-1 rounded-lg transition-colors"
                aria-label="Close dialog"
              >
                ✕
              </button>
            </div>

            <p className="text-xs text-muted mb-4">{selectedTool.description || 'No description available.'}</p>

            {/* DUAL TONE INVARIANT: Schema Viewport */}
            <div className="flex-1 overflow-y-auto bg-[#0F172A] p-4 rounded-xl border border-[#1E293B] font-mono text-xs text-emerald-400 shadow-inner">
              <pre className="select-all">{JSON.stringify(selectedTool.inputSchema || {}, null, 2)}</pre>
            </div>

            <div className="mt-4 flex justify-end">
              <button
                type="button"
                onClick={() => setSelectedTool(null)}
                className="px-4 py-2 rounded-xl text-xs font-semibold bg-surface hover:bg-surface/80 border border-subtle text-primary transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
