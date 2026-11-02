import React, { useState, useEffect, useMemo, useCallback } from 'react'
import { Network, Sparkles, Plus, Search } from 'lucide-react'
import { ProtocolItem, PresetMetadata } from '../types'
import { api } from '../api'
import { Button } from './ui/Button'
import { ProtocolCard } from './protocols/ProtocolCard'
import { PresetCard } from './protocols/PresetCard'
import { InstallProtocolModal } from './protocols/InstallProtocolModal'
import { ToolWhitelistDrawer } from './protocols/ToolWhitelistDrawer'
import { InUseWarningModal } from './protocols/InUseWarningModal'

const CATEGORIES = ['All', 'DevOps', 'Data', 'Web', 'Productivity', 'Memory'] as const
type Category = (typeof CATEGORIES)[number]

export const ProtocolsTab: React.FC = () => {
  const [protocols, setProtocols] = useState<ProtocolItem[]>([])
  const [presets, setPresets] = useState<PresetMetadata[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Filters
  const [selectedCategory, setSelectedCategory] = useState<Category>('All')
  const [searchQuery, setSearchQuery] = useState('')

  // Modals state
  const [installModalOpen, setInstallModalOpen] = useState(false)
  const [presetToInstall, setPresetToInstall] = useState<PresetMetadata | null>(null)
  const [protocolToEdit, setProtocolToEdit] = useState<ProtocolItem | null>(null)
  const [drawerProtocol, setDrawerProtocol] = useState<ProtocolItem | null>(null)
  const [inUseWarning, setInUseWarning] = useState<{
    protocolName: string
    message: string
  } | null>(null)

  const fetchData = useCallback(async (signal?: AbortSignal) => {
    try {
      setLoading(true)
      setError(null)
      const [pRes, preRes] = await Promise.all([
        api.getProtocols(signal),
        api.getPresets(signal),
      ])
      setProtocols(pRes.protocols || [])
      setPresets(preRes.presets || [])
    } catch (err: unknown) {
      if (signal?.aborted) return
      const msg = err instanceof Error ? err.message : String(err)
      setError(msg)
    } finally {
      if (!signal?.aborted) {
        setLoading(false)
      }
    }
  }, [])

  useEffect(() => {
    const abortController = new AbortController()
    fetchData(abortController.signal)
    return () => abortController.abort()
  }, [fetchData])

  // Callbacks
  const handleOpenPresetInstall = useCallback((preset: PresetMetadata) => {
    setProtocolToEdit(null)
    setPresetToInstall(preset)
    setInstallModalOpen(true)
  }, [])

  const handleOpenCustomInstall = useCallback(() => {
    setProtocolToEdit(null)
    setPresetToInstall(null)
    setInstallModalOpen(true)
  }, [])

  const handleOpenEdit = useCallback((p: ProtocolItem) => {
    setProtocolToEdit(p)
    setPresetToInstall(null)
    setInstallModalOpen(true)
  }, [])

  const handleDelete = useCallback(
    async (id: string, name: string) => {
      if (!window.confirm(`Are you sure you want to delete protocol '${name}'?`)) return
      try {
        await api.deleteProtocol(id)
        fetchData()
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err)
        setInUseWarning({ protocolName: name, message: msg })
      }
    },
    [fetchData]
  )

  const handleOpenDrawer = useCallback((p: ProtocolItem) => {
    setDrawerProtocol(p)
  }, [])

  // Memoized filtered presets for performance
  const filteredPresets = useMemo(() => {
    const query = searchQuery.trim().toLowerCase()
    return presets.filter((p) => {
      const matchesCat =
        selectedCategory === 'All' || p.category.toLowerCase() === selectedCategory.toLowerCase()
      const matchesQ =
        !query ||
        p.name.toLowerCase().includes(query) ||
        p.id.toLowerCase().includes(query) ||
        (p.description && p.description.toLowerCase().includes(query))
      return matchesCat && matchesQ
    })
  }, [presets, selectedCategory, searchQuery])

  return (
    <div className="space-y-8">
      {/* Top Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-primary flex items-center gap-2">
            <Network className="w-5 h-5 text-accent-primary" />
            Tool Sources Catalog & Marketplace
          </h2>
          <p className="text-xs text-muted mt-1">
            Independent, credential-isolated Model Context Protocol tool sources with POSIX 0600
            storage.
          </p>
        </div>

        <Button
          variant="secondary"
          onClick={handleOpenCustomInstall}
          icon={<Plus className="w-4 h-4 text-accent-primary" />}
        >
          Custom Tool Source
        </Button>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-700 dark:text-rose-300 text-xs font-mono">
          {error}
        </div>
      )}

      {/* SECTION 1: Configured Protocols */}
      <div className="space-y-4">
        <div className="flex items-center justify-between border-b border-subtle pb-2">
          <h3 className="text-sm font-bold text-primary uppercase tracking-wider font-mono flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-accent-primary animate-pulse"></span>
            Configured Tool Sources ({protocols.length})
          </h3>
          <span className="text-[11px] font-mono text-muted">
            Perimeter Layer 1 Whitelist Scoping
          </span>
        </div>

        {loading && protocols.length === 0 ? (
          <div className="p-8 rounded-2xl bg-surface/50 border border-subtle text-center text-xs text-muted font-mono">Loading catalog...</div>
        ) : protocols.length === 0 ? (
          <div className="p-8 text-center text-xs text-muted border border-dashed border-subtle rounded-2xl bg-surface/30">
            No active tool sources configured yet. Explore the Marketplace below or register a custom
            source.
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {protocols.map((p) => (
              <ProtocolCard
                key={p.id}
                protocol={p}
                onOpenDrawer={handleOpenDrawer}
                onEdit={handleOpenEdit}
                onDelete={handleDelete}
              />
            ))}
          </div>
        )}
      </div>

      {/* SECTION 2: Preset Marketplace Hub */}
      <div className="space-y-5 pt-4">
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-subtle pb-3">
          <div>
            <h3 className="text-sm font-bold text-primary uppercase tracking-wider font-mono flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-accent-primary" />
              MCP Preset Marketplace ({presets.length} Curated Integrations)
            </h3>
            <p className="text-xs text-muted mt-0.5">
              Click &apos;Configure & Install&apos; on any standard preset to auto-populate connection
              parameters.
            </p>
          </div>

          {/* Search Input */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-muted absolute left-3 top-2.5" />
            <input
              type="text"
              aria-label="Search presets"
              placeholder="Search presets..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8 pr-3 py-1.5 rounded-xl bg-surface border border-subtle text-xs text-primary focus:outline-none focus:ring-1 focus:ring-accent-primary font-mono w-48 placeholder:text-muted"
            />
          </div>
        </div>

        {/* Category Filter Pills */}
        <div className="flex flex-wrap gap-2">
          {CATEGORIES.map((cat) => (
            <button
              key={cat}
              type="button"
              onClick={() => setSelectedCategory(cat)}
              className={`px-3 py-1 rounded-xl text-xs font-semibold font-mono transition-all ${
                selectedCategory === cat
                  ? 'bg-accent-primary text-white shadow-sm'
                  : 'bg-surface text-muted hover:bg-surface/80 hover:text-primary border border-subtle'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>

        {/* Preset Cards Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredPresets.map((preset) => (
            <PresetCard
              key={preset.id}
              preset={preset}
              isInstalled={protocols.some((p) => p.id === preset.id)}
              onInstall={handleOpenPresetInstall}
            />
          ))}
        </div>
      </div>

      {/* Modals & Drawers */}
      <InstallProtocolModal
        isOpen={installModalOpen}
        onClose={() => {
          setInstallModalOpen(false)
          setPresetToInstall(null)
          setProtocolToEdit(null)
        }}
        presetToInstall={presetToInstall}
        protocolToEdit={protocolToEdit}
        onSaved={fetchData}
      />

      <ToolWhitelistDrawer
        protocol={drawerProtocol}
        onClose={() => setDrawerProtocol(null)}
        onSaved={fetchData}
      />

      <InUseWarningModal warning={inUseWarning} onClose={() => setInUseWarning(null)} />
    </div>
  )
}
