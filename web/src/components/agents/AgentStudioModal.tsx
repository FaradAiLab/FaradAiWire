import React, { useState, useEffect } from 'react'
import {
  AgentItem,
  ProtocolItem,
  ToolMetadata,
  PolicyPack,
  SmartRecommendation,
  ToolGovernanceMode,
  RateLimitOverride,
  LoopProtectionOverride,
} from '../../types'
import { api } from '../../api'
import { Drawer } from '../ui/Drawer'
import { Button } from '../ui/Button'
import { GeneralConfigTab } from './GeneralConfigTab'
import { DlpPipelineTab } from './DlpPipelineTab'
import { SecurityGuardrailsTab } from './SecurityGuardrailsTab'
import { PipelineTrafficTab } from './PipelineTrafficTab'
import { SmartRecommendationCard } from './SmartRecommendationCard'
import { ProtocolDetachModal } from './ProtocolDetachModal'
import { ProtocolRestorationBanner } from './ProtocolRestorationBanner'
import { AgentRollbackModal } from './AgentRollbackModal'
import { Bot, Sliders, ShieldCheck, ShieldAlert, History, CheckCircle2, X, Zap, AlertCircle, Activity } from 'lucide-react'

export interface AgentStudioModalProps {
  isOpen: boolean
  onClose: () => void
  mode: 'create' | 'edit'
  initialAgent?: AgentItem | null
  protocols: ProtocolItem[]
  onSuccess: () => void
  activeFilters?: string[]
}

type PrimaryTab = 'general' | 'dlp' | 'guardrails' | 'pipeline'

export const AgentStudioModal: React.FC<AgentStudioModalProps> = ({
  isOpen,
  onClose,
  mode,
  initialAgent,
  protocols,
  onSuccess,
  activeFilters = [],
}) => {
  const [activeTab, setActiveTab] = useState<PrimaryTab>('general')
  const [agentName, setAgentName] = useState('')
  const [description, setDescription] = useState('')
  const [routingMode, setRoutingMode] = useState<'aggregated' | 'direct'>('aggregated')
  const [selectedProtocols, setSelectedProtocols] = useState<string[]>([])
  const [scopedTools, setScopedTools] = useState<string[]>([])
  const [availableTools, setAvailableTools] = useState<ToolMetadata[]>([])
  const [localProtocols, setLocalProtocols] = useState<ProtocolItem[]>(protocols)
  const [discoveringTools, setDiscoveringTools] = useState(false)

  useEffect(() => {
    setLocalProtocols(protocols)
  }, [protocols])
  const [toolGovernance, setToolGovernance] = useState<Record<string, ToolGovernanceMode>>({})
  const [rateLimit, setRateLimit] = useState<RateLimitOverride>({ enabled: true, max_burst: 10, refill_rate: 2.0 })
  const [loopProtection, setLoopProtection] = useState<LoopProtectionOverride>({
    enabled: true,
    max_repeat: 3,
    window_seconds: 10,
    exclude_tools: [],
  })
  const [savingAgent, setSavingAgent] = useState(false)
  const [isDlpSaving, setIsDlpSaving] = useState(false)
  const [dlpReloadToken, setDlpReloadToken] = useState(0)
  const [banner, setBanner] = useState<{
    type: 'success' | 'error' | 'info'
    message: string
  } | null>(null)

  const showBanner = (type: 'success' | 'error' | 'info', message: string, ttlMs = 5000) => {
    setBanner({ type, message })
    if (ttlMs > 0) {
      setTimeout(() => {
        setBanner((current) => (current?.message === message ? null : current))
      }, ttlMs)
    }
  }

  // Governance Retention & Detach state
  const [detachTarget, setDetachTarget] = useState<{
    protocolId: string
    protocolName: string
    governanceRulesCount: number
    scopedToolsCount: number
    affectedTools: { name: string; mode?: string }[]
  } | null>(null)
  const [restoredProtocols, setRestoredProtocols] = useState<string[]>([])
  const [dismissedRestorations, setDismissedRestorations] = useState<string[]>([])
  const [isRollbackOpen, setIsRollbackOpen] = useState(false)

  // Policy packs & recommendations state
  const [availablePacks, setAvailablePacks] = useState<PolicyPack[]>([])
  const [recommendations, setRecommendations] = useState<SmartRecommendation[]>([])

  const populateFromAgent = (agent: AgentItem) => {
    setAgentName(agent.name)
    setDescription(agent.config?.description || '')
    const rMode = (agent.config?.routing_mode as 'aggregated' | 'direct') || 'aggregated'
    setRoutingMode(rMode)

    const pIds = (agent.config?.protocols || [])
      .map((p) => p.protocol_id || p.id || p.name)
      .filter((id): id is string => Boolean(id))
    setSelectedProtocols(pIds)

    const allTools = agent.tools || []
    setAvailableTools(allTools)

    if (agent.config?.enabled_tools && agent.config.enabled_tools.length > 0) {
      setScopedTools(agent.config.enabled_tools)
    } else {
      setScopedTools(
        allTools.map((t) => (rMode === 'direct' ? t.raw_name || t.name : t.canonical_name || t.name))
      )
    }

    setToolGovernance(agent.config?.tool_governance || {})
    setRateLimit(
      agent.config?.rate_limit
        ? {
            enabled: agent.config.rate_limit.enabled !== false,
            max_burst: agent.config.rate_limit.max_burst,
            refill_rate: agent.config.rate_limit.refill_rate,
          }
        : { enabled: true, max_burst: 10, refill_rate: 2.0 }
    )
    setLoopProtection(
      agent.config?.loop_protection || {
        enabled: true,
        max_repeat: 3,
        window_seconds: 10,
        exclude_tools: [],
      }
    )
  }

  const reloadFromRemote = async (targetName: string) => {
    try {
      const res = await api.getAgents()
      const found = (res.agents || []).find((a) => a.name === targetName)
      if (found) {
        populateFromAgent(found)
        return found
      }
    } catch {
      // ignore
    }
    return null
  }

  // Initialize form state
  useEffect(() => {
    if (!isOpen) return
    setActiveTab('general')
    setBanner(null)
    setDetachTarget(null)
    setRestoredProtocols([])
    setDismissedRestorations([])

    if (mode === 'edit' && initialAgent) {
      populateFromAgent(initialAgent)
    } else {
      setAgentName('')
      setDescription('')
      setRoutingMode('aggregated')
      setSelectedProtocols([])
      setScopedTools([])
      setAvailableTools([])
      setToolGovernance({})
      setRateLimit({ enabled: true, max_burst: 10, refill_rate: 2.0 })
      setLoopProtection({
        enabled: true,
        max_repeat: 3,
        window_seconds: 10,
        exclude_tools: [],
      })
    }
  }, [isOpen, mode, initialAgent])

  // Fetch available policy packs
  useEffect(() => {
    if (!isOpen) return
    api.getPolicyPacks()
      .then((res) => setAvailablePacks(res.packs || []))
      .catch(() => {})
  }, [isOpen])

  // Fetch smart recommendations whenever protocols change
  useEffect(() => {
    if (!isOpen || selectedProtocols.length === 0) {
      setRecommendations([])
      return
    }

    const timer = setTimeout(() => {
      api.getSmartRecommendations({
        agent_name: agentName,
        protocols: selectedProtocols,
        tools: availableTools.map((t) => t.raw_name || t.name),
        attached_packs: [],
      })
        .then((res) => setRecommendations(res.recommendations || []))
        .catch(() => {})
    }, 300)

    return () => clearTimeout(timer)
  }, [isOpen, selectedProtocols, availableTools, agentName])

  // Tool discovery
  const handleDiscoverTools = async () => {
    if (selectedProtocols.length === 0) return
    try {
      setDiscoveringTools(true)
      const toolsAccum: ToolMetadata[] = []

      for (const pId of selectedProtocols) {
        const proto = protocols.find((p) => p.id === pId)
        if (!proto) continue
        try {
          const res = await api.probeProtocol({
            type: proto.type,
            url: proto.url_or_command,
            command: proto.command || proto.url_or_command,
            args: proto.args,
            env: proto.env,
          })
          if (res.tools) {
            toolsAccum.push(
              ...res.tools.map((t) => ({
                ...t,
                raw_name: t.name,
                canonical_name: `${proto.id}__${t.name}`,
                protocol_id: proto.id,
              }))
            )
          }
        } catch {
          // Probe may fail if backend is not started
        }
      }

      setAvailableTools(toolsAccum)
      if (scopedTools.length === 0) {
        setScopedTools(
          toolsAccum.map((t) =>
            routingMode === 'direct' ? (t.raw_name || t.name) : (t.canonical_name || t.name)
          )
        )
      }
    } finally {
      setDiscoveringTools(false)
    }
  }

  // Toggles
  const handleToggleProtocol = (protoId: string) => {
    if (selectedProtocols.includes(protoId)) {
      // User is attempting to detach. Check if this protocol has configured tools or governance
      const proto = protocols.find((p) => (p.protocol_id || p.id || p.name) === protoId)
      const protoName = proto?.name || protoId
      const protoSlug = protoId.toLowerCase()

      const matchingTools = availableTools.filter(
        (t) =>
          t.protocol_id === protoId ||
          t.protocol_name === protoId ||
          (t.canonical_name && t.canonical_name.toLowerCase().startsWith(protoSlug + '__')) ||
          (t.name && t.name.toLowerCase().startsWith(protoSlug + '__'))
      )

      const affected = matchingTools
        .filter((t) => {
          const tName = t.canonical_name || t.name
          return Boolean(toolGovernance[tName]) || scopedTools.includes(tName)
        })
        .map((t) => {
          const tName = t.canonical_name || t.name
          return {
            name: tName,
            mode: toolGovernance[tName],
          }
        })

      if (affected.length > 0) {
        setDetachTarget({
          protocolId: protoId,
          protocolName: protoName,
          governanceRulesCount: affected.filter((a) => Boolean(a.mode)).length,
          scopedToolsCount: affected.length,
          affectedTools: affected,
        })
        return
      }

      // No configured rules on this protocol, detach directly
      setSelectedProtocols((prev) => prev.filter((id) => id !== protoId))
    } else {
      setSelectedProtocols((prev) => [...prev, protoId])
    }
  }

  const handleToggleToolScoping = (toolName: string) => {
    setScopedTools((prev) =>
      prev.includes(toolName) ? prev.filter((name) => name !== toolName) : [...prev, toolName]
    )
  }

  const handleChangeGovernance = (toolName: string, mode: ToolGovernanceMode) => {
    setToolGovernance((prev) => ({
      ...prev,
      [toolName]: mode,
    }))
  }

  const handleApplyRecommendedDefaults = (defaults: Record<string, ToolGovernanceMode>) => {
    setToolGovernance((prev) => ({
      ...prev,
      ...defaults,
    }))
  }

  // Save General Agent Config, Guardrails, or Pipeline & Traffic
  const handleSaveGeneral = async (
    e?: React.FormEvent,
    sourceTab: 'general' | 'guardrails' | 'pipeline' = 'general'
  ) => {
    if (e) e.preventDefault()
    if (!agentName.trim()) return

    const isAllToolsScoped =
      availableTools.length > 0 && scopedTools.length === availableTools.length

    const payload: Record<string, unknown> = {
      agent_name: agentName.trim(),
      description: description.trim(),
      routing_mode: routingMode,
      protocol_ids: selectedProtocols,
      enabled_tools: isAllToolsScoped ? undefined : scopedTools,
      tool_governance: Object.keys(toolGovernance).length > 0 ? toolGovernance : undefined,
      restore_retained_protocols: restoredProtocols.length > 0 ? restoredProtocols : undefined,
      rate_limit: rateLimit,
      loop_protection: loopProtection,
    }

    try {
      setSavingAgent(true)
      setBanner(null)
      if (mode === 'create') {
        await api.createAgent(payload)
        showBanner(
          'success',
          `Agent '${agentName}' registered successfully with snapshot checkpoint.`
        )
      } else {
        await api.updateAgent(agentName.trim(), payload)
        if (sourceTab === 'pipeline') {
          showBanner('success', 'Traffic rate limits & loop protection rules saved. Checkpoint archived.')
        } else if (sourceTab === 'guardrails') {
          showBanner('success', 'Guardrails & tool governance saved. Checkpoint archived.')
        } else {
          showBanner('success', 'General configuration & tool scoping saved. Checkpoint archived.')
        }
      }
      onSuccess() // In-place save: updates parent agent list without closing the drawer
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      showBanner('error', `Save failed: ${msg}`, 8000)
    } finally {
      setSavingAgent(false)
    }
  }

  return (
    <Drawer
      isOpen={isOpen}
      onClose={onClose}
      title={mode === 'create' ? 'Create Security Profile' : `Profile Studio: ${agentName}`}
      subtitle="Unified governance studio for profile routing, MCP tool scoping, and defense-in-depth pipeline."
      icon={<Bot className="w-5 h-5 text-accent" />}
      maxWidth="5xl"
      headerAction={
        mode === 'edit' && agentName ? (
          <Button
            type="button"
            variant="outline"
            size="sm"
            icon={<History className="w-3.5 h-3.5 text-accent" />}
            onClick={() => setIsRollbackOpen(true)}
            className="text-xs font-sans text-primary border-subtle hover:bg-subtle"
          >
            Revision History
          </Button>
        ) : undefined
      }
      subHeader={
        <div
          role="tablist"
          aria-label="Profile Studio Configuration Tabs"
          className="flex items-center gap-1.5 font-sans text-xs pb-3 overflow-x-auto no-scrollbar"
        >
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'general'}
            aria-controls="agent-tab-general"
            onClick={() => setActiveTab('general')}
            className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg font-semibold transition-colors shrink-0 whitespace-nowrap ${
              activeTab === 'general'
                ? 'bg-accent/15 text-accent border border-accent/30 font-semibold shadow-xs'
                : 'text-muted hover:text-primary hover:bg-subtle'
            }`}
          >
            <Sliders className="w-3.5 h-3.5" />
            <span>General Settings</span>
          </button>

          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'dlp'}
            aria-controls="agent-tab-dlp"
            onClick={() => setActiveTab('dlp')}
            className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg font-semibold transition-colors shrink-0 whitespace-nowrap ${
              activeTab === 'dlp'
                ? 'bg-accent/15 text-accent border border-accent/30 font-semibold shadow-xs'
                : 'text-muted hover:text-primary hover:bg-subtle'
            }`}
          >
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-500" />
            <span>DLP Pipeline & Policy Packs</span>
          </button>

          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'guardrails'}
            aria-controls="agent-tab-guardrails"
            onClick={() => setActiveTab('guardrails')}
            className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg font-semibold transition-colors shrink-0 whitespace-nowrap ${
              activeTab === 'guardrails'
                ? 'bg-accent/15 text-accent border border-accent/30 font-semibold shadow-xs'
                : 'text-muted hover:text-primary hover:bg-subtle'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5 text-amber-500" />
            <span>AI Guard & HITL</span>
          </button>

          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'pipeline'}
            aria-controls="agent-tab-pipeline"
            onClick={() => setActiveTab('pipeline')}
            className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg font-semibold transition-colors shrink-0 whitespace-nowrap ${
              activeTab === 'pipeline'
                ? 'bg-accent/15 text-accent border border-accent/30 font-semibold shadow-xs'
                : 'text-muted hover:text-primary hover:bg-subtle'
            }`}
          >
            <Activity className="w-3.5 h-3.5 text-cyan-400" />
            <span>Pipeline & Traffic</span>
          </button>
        </div>
      }
      footer={
        <div className="flex flex-col sm:flex-row items-center justify-between w-full gap-3 font-sans">
          <div className="text-xs text-muted flex items-center gap-1.5">
            <ShieldCheck className="w-4 h-4 text-emerald-500 shrink-0" />
            <span>Every configuration save creates an atomic rollback point.</span>
          </div>
          <div className="flex items-center gap-2">
            <Button type="button" variant="ghost" size="md" onClick={onClose}>
              Close
            </Button>
            {activeTab === 'general' && (
              <Button
                type="button"
                variant="primary"
                size="md"
                icon={<Sliders className="w-3.5 h-3.5" />}
                onClick={(e) => handleSaveGeneral(e, 'general')}
                isLoading={savingAgent}
                disabled={savingAgent || !agentName.trim()}
              >
                {mode === 'create' ? 'Create Agent' : 'Save General Config'}
              </Button>
            )}
            {activeTab === 'guardrails' && (
              <Button
                type="button"
                variant="primary"
                size="md"
                icon={<ShieldCheck className="w-3.5 h-3.5" />}
                onClick={(e) => handleSaveGeneral(e, 'guardrails')}
                isLoading={savingAgent}
                disabled={savingAgent || !agentName.trim()}
              >
                Save AI Guard Settings
              </Button>
            )}
            {activeTab === 'pipeline' && (
              <Button
                type="button"
                variant="primary"
                size="md"
                icon={<Activity className="w-3.5 h-3.5" />}
                onClick={(e) => handleSaveGeneral(e, 'pipeline')}
                isLoading={savingAgent}
                disabled={savingAgent || !agentName.trim()}
              >
                Save Pipeline Controls
              </Button>
            )}
            {activeTab === 'dlp' && (
              <Button
                type="button"
                variant="primary"
                size="md"
                icon={<Zap className="w-3.5 h-3.5" />}
                onClick={() => {
                  const dlpBtn = document.getElementById('dlp-save-btn') as HTMLButtonElement | null
                  dlpBtn?.click()
                }}
                isLoading={isDlpSaving}
                disabled={isDlpSaving || !agentName.trim()}
              >
                Save & Hot-Reload DLP
              </Button>
            )}
          </div>
        </div>
      }
    >
      <div className="space-y-4">
        {banner && (
          <div
            role="status"
            aria-live="polite"
            className={`p-3.5 rounded-xl border text-xs flex items-center justify-between gap-2 shadow-xs animate-in fade-in font-sans ${
              banner.type === 'success'
                ? 'bg-emerald-50 dark:bg-emerald-950/40 border-emerald-300 dark:border-emerald-500/30 text-emerald-800 dark:text-emerald-300'
                : banner.type === 'error'
                ? 'bg-rose-50 dark:bg-rose-950/40 border-rose-300 dark:border-rose-500/30 text-rose-800 dark:text-rose-300'
                : 'bg-sky-50 dark:bg-sky-950/40 border-sky-300 dark:border-sky-500/30 text-sky-800 dark:text-sky-300'
            }`}
          >
            <div className="flex items-center gap-2">
              {banner.type === 'success' && (
                <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
              )}
              {banner.type === 'error' && (
                <AlertCircle className="w-4 h-4 text-rose-600 dark:text-rose-400 shrink-0" />
              )}
              {banner.type === 'info' && (
                <Bot className="w-4 h-4 text-sky-600 dark:text-sky-400 shrink-0" />
              )}
              <span className="font-semibold">{banner.message}</span>
            </div>
            <button
              type="button"
              aria-label="Dismiss notification"
              onClick={() => setBanner(null)}
              className="opacity-70 hover:opacity-100 transition-opacity"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        )}

        {/* Tab 1: General Settings */}
        {activeTab === 'general' && (
          <form onSubmit={handleSaveGeneral} className="space-y-4">
            {/* Governance Retention Restoration Banners */}
            {initialAgent?.config?.retained_governance &&
              Object.entries(initialAgent.config.retained_governance).map(([pId, rules]) => {
                if (
                  selectedProtocols.includes(pId) &&
                  !dismissedRestorations.includes(pId) &&
                  Object.keys(rules).length > 0
                ) {
                  const proto = protocols.find((p) => (p.protocol_id || p.id || p.name) === pId)
                  return (
                    <ProtocolRestorationBanner
                      key={pId}
                      protocolId={pId}
                      protocolName={proto?.name || pId}
                      retainedRules={rules}
                      onRestore={(restoredRules) => {
                        setToolGovernance((prev) => ({ ...prev, ...restoredRules }))
                        setRestoredProtocols((prev) => [...prev, pId])
                        setDismissedRestorations((prev) => [...prev, pId])
                      }}
                      onDismiss={() => {
                        setDismissedRestorations((prev) => [...prev, pId])
                      }}
                    />
                  )
                }
                return null
              })}

            <SmartRecommendationCard
              recommendations={recommendations}
              attachedPackIds={[]}
              onAttachPack={() => {
                setActiveTab('dlp')
              }}
            />

            <GeneralConfigTab
              mode={mode}
              agentName={agentName}
              setAgentName={setAgentName}
              description={description}
              setDescription={setDescription}
              routingMode={routingMode}
              setRoutingMode={setRoutingMode}
              protocols={localProtocols}
              selectedProtocols={selectedProtocols}
              onToggleProtocol={handleToggleProtocol}
              availableTools={availableTools}
              scopedTools={scopedTools}
              onToggleToolScoping={handleToggleToolScoping}
              onDiscoverTools={handleDiscoverTools}
              isDiscoveringTools={discoveringTools}
              onProtocolCreated={(newProto) => {
                setLocalProtocols((prev) => [...prev, newProto])
                setSelectedProtocols((prev) => [...prev, newProto.id])
              }}
            />
          </form>
        )}

        {/* Tab 2: DLP Pipeline */}
        {activeTab === 'dlp' && (
          <div>
            {mode === 'create' && !agentName.trim() ? (
              <div className="p-6 text-center text-xs text-muted font-mono">
                Please specify an Agent Name in General Settings first.
              </div>
            ) : (
              <DlpPipelineTab
                agentName={agentName.trim() || 'default'}
                availablePacks={availablePacks}
                availableTools={availableTools}
                reloadToken={dlpReloadToken}
                onSaveSuccess={(msg) => {
                  showBanner('success', msg)
                  onSuccess()
                }}
                onSaveError={(msg) => {
                  showBanner('error', msg, 8000)
                }}
                onSavingChange={setIsDlpSaving}
              />
            )}
          </div>
        )}

        {/* Tab 3: Security Guardrails */}
        {activeTab === 'guardrails' && (
          <SecurityGuardrailsTab
            availableTools={availableTools}
            toolGovernance={toolGovernance}
            onChangeGovernance={handleChangeGovernance}
            onApplyRecommendedDefaults={handleApplyRecommendedDefaults}
            routingMode={routingMode}
          />
        )}

        {/* Tab 4: Pipeline & Traffic */}
        {activeTab === 'pipeline' && (
          <PipelineTrafficTab
            rateLimit={rateLimit}
            onChangeRateLimit={setRateLimit}
            loopProtection={loopProtection}
            onChangeLoopProtection={setLoopProtection}
            availableTools={availableTools}
            activeFilters={activeFilters}
          />
        )}
      </div>

      {detachTarget && (
        <ProtocolDetachModal
          isOpen={true}
          onClose={() => setDetachTarget(null)}
          onConfirmDetach={() => {
            if (detachTarget) {
              const pId = detachTarget.protocolId
              setSelectedProtocols((prev) => prev.filter((id) => id !== pId))
            }
          }}
          protocolName={detachTarget.protocolName}
          protocolId={detachTarget.protocolId}
          governanceRulesCount={detachTarget.governanceRulesCount}
          scopedToolsCount={detachTarget.scopedToolsCount}
          affectedTools={detachTarget.affectedTools}
        />
      )}

      {mode === 'edit' && agentName && (
        <AgentRollbackModal
          isOpen={isRollbackOpen}
          agentName={agentName}
          onClose={() => setIsRollbackOpen(false)}
          onSuccess={async (restoredArchive) => {
            setIsRollbackOpen(false)
            if (agentName) {
              await reloadFromRemote(agentName)
              setDlpReloadToken((prev) => prev + 1)
              showBanner(
                'success',
                `Configuration successfully restored to snapshot ${restoredArchive || ''}. Active form reloaded.`
              )
            }
            onSuccess()
          }}
        />
      )}
    </Drawer>
  )
}
