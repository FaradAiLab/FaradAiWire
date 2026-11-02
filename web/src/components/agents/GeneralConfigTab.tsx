import React, { useState } from 'react'
import { ProtocolItem, ToolMetadata } from '../../types'
import { Input } from '../ui/Input'
import { Button } from '../ui/Button'
import { RefreshCw, Network, Wrench, X, FileCode } from 'lucide-react'
import { ProtocolSearchCombobox } from './ProtocolSearchCombobox'
import { QuickProtocolRegisterModal } from './QuickProtocolRegisterModal'
import { SchemaInspectorDrawer } from './SchemaInspectorDrawer'

export interface GeneralConfigTabProps {
  mode: 'create' | 'edit'
  agentName: string
  setAgentName: (name: string) => void
  description: string
  setDescription: (desc: string) => void
  routingMode: 'aggregated' | 'direct'
  setRoutingMode: (mode: 'aggregated' | 'direct') => void
  protocols: ProtocolItem[]
  selectedProtocols: string[]
  onToggleProtocol: (protoId: string) => void
  availableTools: ToolMetadata[]
  scopedTools: string[]
  onToggleToolScoping: (toolName: string) => void
  onDiscoverTools: () => void
  isDiscoveringTools: boolean
  onProtocolCreated?: (protocol: ProtocolItem) => void
}

export const GeneralConfigTab: React.FC<GeneralConfigTabProps> = ({
  mode,
  agentName,
  setAgentName,
  description,
  setDescription,
  routingMode,
  setRoutingMode,
  protocols,
  selectedProtocols,
  onToggleProtocol,
  availableTools,
  scopedTools,
  onToggleToolScoping,
  onDiscoverTools,
  isDiscoveringTools,
  onProtocolCreated,
}) => {
  const [isRegisterOpen, setIsRegisterOpen] = useState(false)
  const [inspectingTool, setInspectingTool] = useState<{
    name: string
    metadata?: ToolMetadata
  } | null>(null)

  const scopedToolsSet = new Set(scopedTools)

  return (
    <div className="space-y-5 text-xs">
      {/* Identity & Description */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <Input
          label="Profile Name"
          required
          placeholder="e.g. devops-assistant"
          value={agentName}
          disabled={mode === 'edit'}
          onChange={(e) => setAgentName(e.target.value)}
          helperText="Unique identifier matching URL pattern /sse/:profile."
          isMono
        />

        <Input
          label="Description"
          placeholder="e.g. Autonomous cloud operations profile"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
        />
      </div>

      {/* Routing Mode */}
      <div>
        <label className="block font-semibold text-primary mb-1.5 font-sans">Routing Mode</label>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <label
            className={`p-3 rounded-xl border cursor-pointer transition-all ${
              routingMode === 'aggregated'
                ? 'bg-accent/15 border-accent/40 text-accent font-semibold shadow-xs'
                : 'bg-canvas border-subtle text-muted hover:bg-subtle'
            }`}
          >
            <div className="flex items-center gap-2 mb-1">
              <input
                type="radio"
                name="routing"
                checked={routingMode === 'aggregated'}
                onChange={() => setRoutingMode('aggregated')}
                className="text-accent"
              />
              <span className="font-bold text-xs font-sans">Aggregated (Single Path)</span>
            </div>
            <p className="text-[10px] text-muted leading-relaxed font-sans">
              {'Unified endpoint `/sse/{profile}`. Tools namespaced as `protocol__tool`.'}
            </p>
          </label>

          <label
            className={`p-3 rounded-xl border cursor-pointer transition-all ${
              routingMode === 'direct'
                ? 'bg-accent/15 border-accent/40 text-accent font-semibold shadow-xs'
                : 'bg-canvas border-subtle text-muted hover:bg-subtle'
            }`}
          >
            <div className="flex items-center gap-2 mb-1">
              <input
                type="radio"
                name="routing"
                checked={routingMode === 'direct'}
                onChange={() => setRoutingMode('direct')}
                className="text-accent"
              />
              <span className="font-bold text-xs font-sans">Direct (Per-Protocol)</span>
            </div>
            <p className="text-[10px] text-muted leading-relaxed font-sans">
              {'Per-protocol paths `/sse/{profile}/{protocol}`. Raw tool names preserved.'}
            </p>
          </label>
        </div>
      </div>

      {/* MCP Tool Source Attachments */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <span className="font-semibold text-primary font-mono flex items-center gap-1.5">
            <Network className="w-4 h-4 text-accent" /> Attached MCP Protocols ({selectedProtocols.length})
          </span>
          <span className="text-[10px] text-muted font-mono">
            {protocols.length} available in catalog
          </span>
        </div>

        {/* Attached Protocol Cards List */}
        {selectedProtocols.length === 0 ? (
          <div className="p-3.5 text-center text-xs text-muted border border-dashed border-subtle rounded-xl font-mono bg-canvas">
            No MCP protocols attached to this agent yet. Attach from the catalog search below or register a new custom MCP.
          </div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {selectedProtocols.map((pId) => {
              const proto = protocols.find((p) => (p.protocol_id || p.id || p.name) === pId)
              const displayName = proto?.name || pId
              const protoType = proto?.type || 'stdio'

              return (
                <div
                  key={pId}
                  className="flex items-center justify-between p-2.5 rounded-xl border border-accent/30 bg-accent/10 text-primary group shadow-xs transition-all"
                >
                  <div className="flex items-center gap-2 truncate mr-2">
                    <span className="w-2 h-2 rounded-full bg-accent animate-pulse shrink-0" />
                    <div className="truncate">
                      <div className="font-bold text-xs font-mono truncate text-accent">
                        {displayName}
                      </div>
                      <span className="text-[10px] text-muted font-mono block truncate">
                        {pId} • <span className="text-accent/80">{protoType}</span>
                      </span>
                    </div>
                  </div>

                  <button
                    type="button"
                    onClick={() => onToggleProtocol(pId)}
                    className="p-1 rounded-lg text-muted hover:text-rose-500 hover:bg-rose-50 dark:hover:bg-rose-950/20 transition-colors shrink-0"
                    title={`Detach "${displayName}" protocol`}
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>
              )
            })}
          </div>
        )}

        {/* Searchable Combobox & Quick Register Action */}
        <ProtocolSearchCombobox
          protocols={protocols}
          selectedProtocolIds={selectedProtocols}
          onSelectProtocol={(id) => onToggleProtocol(id)}
          onOpenRegisterModal={() => setIsRegisterOpen(true)}
        />
      </div>

      {/* Layer 2 Tool Scoping */}
      <div className="space-y-2 pt-2 border-t border-subtle">
        <div className="flex items-center justify-between">
          <div>
            <span className="font-semibold text-primary font-sans flex items-center gap-1.5">
              <Wrench className="w-4 h-4 text-emerald-500" /> Layer 2 Tool Scoping
            </span>
            <p className="text-[10px] text-muted font-sans">
              Unchecked tools are hidden from client introspection (Least Privilege).
            </p>
          </div>

          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={onDiscoverTools}
            disabled={isDiscoveringTools || selectedProtocols.length === 0}
            isLoading={isDiscoveringTools}
            icon={<RefreshCw className="w-3 h-3" />}
          >
            {isDiscoveringTools ? 'Querying...' : 'Query Tools'}
          </Button>
        </div>

        {availableTools.length === 0 ? (
          <div className="p-4 text-center text-xs text-muted border border-dashed border-subtle rounded-xl bg-canvas">
            Select protocols and click &quot;Query Tools&quot; to discover exposed MCP capabilities.
          </div>
        ) : (
          <div className="space-y-1.5 max-h-[420px] overflow-y-auto pr-1">
            {availableTools.map((t) => {
              const toolName =
                routingMode === 'direct'
                  ? t.raw_name || t.name
                  : t.canonical_name || t.name
              const isChecked = scopedToolsSet.has(toolName)

              return (
                <div
                  key={toolName}
                  className="flex items-center justify-between p-2 rounded-xl bg-canvas hover:bg-subtle border border-subtle text-xs font-mono group transition-colors shadow-xs"
                >
                  <label className="flex items-center gap-2 truncate mr-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={isChecked}
                      onChange={() => onToggleToolScoping(toolName)}
                      className="text-accent rounded bg-surface border-subtle"
                    />
                    <span className="text-primary font-bold truncate">{toolName}</span>
                    {t.protocol_id && (
                      <span className="text-[9px] text-muted shrink-0">
                        ({t.protocol_id})
                      </span>
                    )}
                  </label>

                  <div className="flex items-center gap-2 shrink-0">
                    {t.description && (
                      <span className="text-[10px] text-muted truncate max-w-[200px] font-sans hidden sm:inline">
                        {t.description}
                      </span>
                    )}
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation()
                        setInspectingTool({ name: toolName, metadata: t })
                      }}
                      className="px-2 py-0.5 rounded bg-accent/15 border border-accent/30 text-accent hover:bg-accent/25 text-[10px] font-mono flex items-center gap-1 transition-colors"
                      title="Inspect & Pin Schema"
                    >
                      <FileCode className="w-3 h-3" />
                      <span>Schema</span>
                    </button>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* Inline Quick MCP Protocol Register Modal */}
      {isRegisterOpen && (
        <QuickProtocolRegisterModal
          isOpen={true}
          onClose={() => setIsRegisterOpen(false)}
          onSuccess={(newProto) => {
            if (onProtocolCreated) {
              onProtocolCreated(newProto)
            } else {
              onToggleProtocol(newProto.id)
            }
          }}
        />
      )}

      {/* Schema Inspector Drawer */}
      {inspectingTool && (
        <SchemaInspectorDrawer
          isOpen={true}
          onClose={() => setInspectingTool(null)}
          toolName={inspectingTool.name}
          toolMetadata={inspectingTool.metadata}
        />
      )}
    </div>
  )
}
