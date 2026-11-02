import React, { useState, useEffect, useCallback, useMemo, memo } from 'react'
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Zap,
  Power,
  Sliders,
  AlertTriangle,
  RefreshCw,
  Layers,
  X,
  Plus,
} from 'lucide-react'
import { GuardModel, GuardProcessStatus, GuardThreatAction } from '../types'
import { api } from '../api'
import { HostTelemetryBar } from './HostTelemetryBar'
import { BenchmarkLeaderboard } from './BenchmarkLeaderboard'
import { ModelConnectModal } from './ModelConnectModal'

// Recommended default critical tools that trigger immediate hard block
const PRESET_CRITICAL_TOOLS = [
  'execute_bash',
  'execute_command',
  'run_command',
  'drop_db',
  'delete_database',
  'format_disk',
]

// -----------------------------------------------------------------------------
// Action Policy Drawer / Modal Component
// -----------------------------------------------------------------------------
interface ActionPolicyModalProps {
  model: GuardModel
  onClose: () => void
  onSaved: () => void
}

const ActionPolicyModal: React.FC<ActionPolicyModalProps> = ({ model, onClose, onSaved }) => {
  const [defaultAction, setDefaultAction] = useState<GuardThreatAction>(model.default_action || 'hitl')

  const initialCriticalTools = useMemo(() => {
    try {
      const parsed = JSON.parse(model.critical_tools_json || '[]')
      return Array.isArray(parsed) ? parsed : []
    } catch {
      return []
    }
  }, [model.critical_tools_json])

  const [criticalTools, setCriticalTools] = useState<string[]>(initialCriticalTools)
  const [newToolInput, setNewToolInput] = useState('')
  const [isSaving, setIsSaving] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !isSaving) {
        onClose()
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [onClose, isSaving])

  const toggleTool = (tool: string) => {
    setCriticalTools((prev) =>
      prev.includes(tool) ? prev.filter((t) => t !== tool) : [...prev, tool]
    )
  }

  const handleAddCustomTool = (e: React.FormEvent) => {
    e.preventDefault()
    const trimmed = newToolInput.trim()
    if (trimmed && !criticalTools.includes(trimmed)) {
      setCriticalTools((prev) => [...prev, trimmed])
      setNewToolInput('')
    }
  }

  const handleSave = async () => {
    try {
      setIsSaving(true)
      setSaveError(null)
      await api.updateGuardPolicy(model.id, {
        default_action: defaultAction,
        critical_tools: criticalTools,
      })
      onSaved()
      onClose()
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      setSaveError(msg)
    } finally {
      setIsSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-in fade-in duration-200">
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="policy-modal-title"
        className="bg-surface border border-subtle rounded-2xl max-w-lg w-full p-6 shadow-2xl relative overflow-hidden flex flex-col gap-5 text-primary"
      >
        <div className="flex items-center justify-between border-b border-subtle pb-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-accent/10 border border-accent/30 rounded-xl text-accent">
              <Sliders className="w-5 h-5" />
            </div>
            <div>
              <h2 id="policy-modal-title" className="text-base font-bold text-primary">
                Action Policy: {model.name}
              </h2>
              <p className="text-xs text-muted font-mono">Model ID: {model.id}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close dialog"
            className="p-1.5 rounded-lg text-muted hover:text-primary hover:bg-subtle transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Default Action Selection */}
        <div className="space-y-2">
          <label className="text-xs font-semibold text-primary uppercase tracking-wider font-mono">
            Default Threat Action
          </label>
          <div className="grid grid-cols-2 gap-3">
            <button
              type="button"
              onClick={() => setDefaultAction('hitl')}
              className={`p-3 rounded-xl border text-left transition-all ${
                defaultAction === 'hitl'
                  ? 'bg-amber-50 dark:bg-amber-500/15 border-amber-300 dark:border-amber-500/50 text-amber-900 dark:text-amber-200 shadow-sm'
                  : 'bg-surface border-subtle text-muted hover:text-primary hover:border-subtle'
              }`}
            >
              <div className="flex items-center gap-2 font-bold text-xs">
                <AlertTriangle className="w-4 h-4 text-amber-500" />
                <span>HITL (Recommended)</span>
              </div>
              <p className="text-[11px] text-muted mt-1 leading-relaxed">
                Escalates threats to operator via TTY and Web Console modal with 60s fail-closed timer.
              </p>
            </button>

            <button
              type="button"
              onClick={() => setDefaultAction('block')}
              className={`p-3 rounded-xl border text-left transition-all ${
                defaultAction === 'block'
                  ? 'bg-rose-50 dark:bg-rose-500/15 border-rose-300 dark:border-rose-500/50 text-rose-900 dark:text-rose-200 shadow-sm'
                  : 'bg-surface border-subtle text-muted hover:text-primary hover:border-subtle'
              }`}
            >
              <div className="flex items-center gap-2 font-bold text-xs">
                <ShieldAlert className="w-4 h-4 text-rose-500" />
                <span>Auto-Block</span>
              </div>
              <p className="text-[11px] text-muted mt-1 leading-relaxed">
                Instantly terminates suspicious calls with error (-32000) without human prompting.
              </p>
            </button>
          </div>
        </div>

        {/* Critical Tools Auto-Block Overrides */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <label className="text-xs font-semibold text-primary uppercase tracking-wider font-mono">
              Critical Tools (Mandatory Hard Block)
            </label>
            <span className="text-[10px] text-muted font-mono">Bypasses HITL prompt</span>
          </div>

          <div className="bg-canvas border border-subtle rounded-xl p-3 max-h-48 overflow-y-auto space-y-1.5 scrollbar-thin">
            {/* Common Presets */}
            {PRESET_CRITICAL_TOOLS.map((tool) => {
              const isChecked = criticalTools.includes(tool)
              return (
                <label
                  key={tool}
                  className="flex items-center gap-2.5 p-1.5 rounded-lg hover:bg-subtle cursor-pointer text-xs font-mono transition-colors"
                >
                  <input
                    type="checkbox"
                    checked={isChecked}
                    onChange={() => toggleTool(tool)}
                    className="rounded border-subtle text-accent focus:ring-accent/40 bg-surface"
                  />
                  <span className={isChecked ? 'text-accent font-bold' : 'text-muted'}>
                    {tool}
                  </span>
                </label>
              )
            })}

            {/* Custom Tools not in presets */}
            {criticalTools
              .filter((t) => !PRESET_CRITICAL_TOOLS.includes(t))
              .map((tool) => (
                <div
                  key={tool}
                  className="flex items-center justify-between p-1.5 rounded-lg bg-accent/10 border border-accent/20 text-xs font-mono"
                >
                  <span className="text-accent font-semibold">{tool}</span>
                  <button
                    type="button"
                    onClick={() => toggleTool(tool)}
                    aria-label={`Remove ${tool}`}
                    className="text-muted hover:text-rose-500 transition-colors"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>
              ))}
          </div>

          {/* Add custom tool input */}
          <form onSubmit={handleAddCustomTool} className="flex gap-2 pt-1">
            <input
              type="text"
              value={newToolInput}
              onChange={(e) => setNewToolInput(e.target.value)}
              placeholder="Add tool name (e.g. custom_cli_exec)"
              className="flex-1 px-3 py-1.5 rounded-xl bg-canvas border border-subtle text-xs text-primary placeholder:text-muted focus:outline-none focus:border-accent font-mono"
            />
            <button
              type="submit"
              disabled={!newToolInput.trim()}
              className="px-3 py-1.5 rounded-xl bg-accent/15 hover:bg-accent/25 text-accent border border-accent/30 text-xs font-medium flex items-center gap-1 disabled:opacity-40 transition-colors shadow-sm"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Add</span>
            </button>
          </form>
        </div>

        {saveError && (
          <div className="p-2.5 bg-rose-50 dark:bg-rose-500/10 border border-rose-200 dark:border-rose-500/30 rounded-xl text-rose-700 dark:text-rose-300 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{saveError}</span>
          </div>
        )}

        {/* Modal Actions */}
        <div className="flex items-center justify-end gap-3 pt-2 border-t border-subtle">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 rounded-xl text-xs font-medium text-muted hover:text-primary hover:bg-subtle transition-colors"
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={isSaving}
            onClick={handleSave}
            className="px-4 py-2 rounded-xl text-xs font-semibold text-white bg-accent hover:bg-accent/90 transition-all shadow-sm flex items-center gap-1.5 disabled:opacity-50"
          >
            {isSaving ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                <span>Saving...</span>
              </>
            ) : (
              <span>Save Policy</span>
            )}
          </button>
        </div>
      </div>
    </div>
  )
}

// -----------------------------------------------------------------------------
// Streamlined Model Card Component
// -----------------------------------------------------------------------------
interface ModelCardProps {
  model: GuardModel
  isBusy: boolean
  onOpenConnect: (model: GuardModel) => void
  onDeactivate: (modelId: string) => void
  onConfigurePolicy: (model: GuardModel) => void
}

const ModelCard = memo<ModelCardProps>(
  ({ model, isBusy, onOpenConnect, onDeactivate, onConfigurePolicy }) => {
    const isActive = model.is_active

    // Formatted accuracy and FP rates
    const accuracyPct = (model.benchmark_accuracy * 100).toFixed(1)
    const fpPct = (model.benchmark_fp_rate * 100).toFixed(1)
    const ramGB = (model.ram_required_mb / 1024).toFixed(1)

    return (
      <div
        className={`bg-surface rounded-2xl p-5 border flex flex-col justify-between transition-all duration-200 relative overflow-hidden group shadow-sm ${
          isActive
            ? 'border-accent ring-1 ring-accent/30 shadow-md'
            : 'border-subtle hover:border-accent/40'
        }`}
      >
        {/* Top Active Glow Ribbon */}
        {isActive && (
          <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-accent via-indigo-500 to-emerald-400" />
        )}

        <div className="space-y-3">
          {/* Header Row: Title, Badges, and Status */}
          <div className="flex items-start justify-between gap-3">
            <div className="space-y-1">
              <div className="flex flex-wrap items-center gap-1.5">
                <h3 className="text-base font-bold text-primary group-hover:text-accent transition-colors">
                  {model.name}
                </h3>
                <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded-full bg-indigo-50 dark:bg-indigo-950/60 text-indigo-700 dark:text-indigo-300 border border-indigo-200 dark:border-indigo-500/30">
                  {model.parameter_size}
                </span>
                <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
                  Q4_K_M
                </span>
                {model.paradigm === 'decision_model' ? (
                  <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border border-cyan-500/20">
                    Decision Model
                  </span>
                ) : (
                  <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded-full bg-purple-500/10 text-purple-600 dark:text-purple-400 border border-purple-500/20">
                    Generative LLM
                  </span>
                )}
              </div>
            </div>

            {/* Dynamic Status Badge */}
            <div className="shrink-0">
              {isActive ? (
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-mono font-bold uppercase bg-emerald-50 dark:bg-emerald-950/70 text-emerald-800 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-500/40">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-ping" />
                  Active
                </span>
              ) : (
                <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-mono font-medium uppercase bg-subtle text-muted border border-subtle">
                  Standby
                </span>
              )}
            </div>
          </div>

          {/* Model Description */}
          <p className="text-xs text-muted leading-relaxed line-clamp-2">
            {model.description}
          </p>

          {/* Key Metric Highlights (Clean Single-Row Strip) */}
          <div className="flex items-center justify-between py-2 px-3 rounded-xl bg-canvas/60 border border-subtle text-xs font-mono">
            <div className="flex items-center gap-1">
              <span className="text-muted text-[10px]">Acc:</span>
              <span className="font-bold text-emerald-600 dark:text-emerald-400">{accuracyPct}%</span>
              <span className="text-muted text-[10px]">({fpPct}% FP)</span>
            </div>
            <div className="h-3 w-px bg-subtle" />
            <div className="flex items-center gap-1">
              <span className="text-muted text-[10px]">Lat:</span>
              <span className="font-semibold text-primary">{Math.round(model.benchmark_avg_latency_ms)}ms</span>
            </div>
            <div className="h-3 w-px bg-subtle" />
            <div className="flex items-center gap-1">
              <span className="text-muted text-[10px]">RAM:</span>
              <span className="font-bold text-accent">{ramGB} GB</span>
            </div>
          </div>
        </div>

        {/* Card Actions Footer */}
        <div className="pt-4 mt-3 border-t border-subtle flex items-center justify-between gap-2">
          {isActive ? (
            <>
              <div className="flex-1 flex items-center gap-2 px-2.5 py-1.5 rounded-xl text-xs font-mono font-semibold bg-emerald-500/10 border border-emerald-500/30 text-emerald-600 dark:text-emerald-400 min-w-0">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-ping shrink-0" />
                <span className="truncate">Connected: {model.endpoint_url || '127.0.0.1:11434'}</span>
              </div>
              <button
                type="button"
                onClick={() => onConfigurePolicy(model)}
                className="px-2.5 py-1.5 rounded-xl text-xs font-medium text-primary bg-surface hover:bg-subtle border border-subtle transition-colors flex items-center gap-1 shadow-xs shrink-0"
                title="Configure Action Policy"
              >
                <Sliders className="w-3.5 h-3.5 text-accent" />
                <span>Policy</span>
              </button>
              <button
                type="button"
                disabled={isBusy}
                onClick={() => onDeactivate(model.id)}
                className="px-2.5 py-1.5 rounded-xl text-xs font-semibold text-amber-800 dark:text-amber-300 bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/30 transition-all disabled:opacity-40 shrink-0 flex items-center gap-1"
                title="Deactivate Guard"
              >
                <Power className="w-3.5 h-3.5" />
                <span>Deactivate</span>
              </button>
            </>
          ) : (
            <>
              <button
                type="button"
                disabled={isBusy}
                onClick={() => onOpenConnect(model)}
                className="flex-1 flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold text-white bg-accent hover:bg-accent/90 transition-all shadow-sm disabled:opacity-50"
              >
                <Zap className="w-3.5 h-3.5" />
                <span>Setup & Connect</span>
              </button>
              <button
                type="button"
                onClick={() => onConfigurePolicy(model)}
                className="px-2.5 py-1.5 rounded-xl text-xs font-medium text-primary bg-surface hover:bg-subtle border border-subtle transition-colors flex items-center gap-1 shadow-xs shrink-0"
                title="Configure Action Policy"
              >
                <Sliders className="w-3.5 h-3.5 text-muted hover:text-accent" />
                <span>Policy</span>
              </button>
            </>
          )}
        </div>
      </div>
    )
  }
)

ModelCard.displayName = 'ModelCard'

// -----------------------------------------------------------------------------
// Main GuardsTab Component
// -----------------------------------------------------------------------------
export const GuardsTab: React.FC = () => {
  const [models, setModels] = useState<GuardModel[]>([])
  const [guardStatus, setGuardStatus] = useState<GuardProcessStatus | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [isActionPending, setIsActionPending] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)
  const [policyTargetModel, setPolicyTargetModel] = useState<GuardModel | null>(null)
  const [connectTargetModel, setConnectTargetModel] = useState<GuardModel | null>(null)
  const [dismissAdvisory, setDismissAdvisory] = useState(false)

  // Apple Silicon detection for hardware recommendation banner
  const isAppleSilicon = useMemo(() => {
    if (typeof navigator !== 'undefined') {
      return /Macintosh|Mac OS X/i.test(navigator.userAgent || navigator.platform)
    }
    return false
  }, [])

  // Fetch models catalog and runtime status
  const loadData = useCallback(async (signal?: AbortSignal) => {
    try {
      const [modelsRes, statusRes] = await Promise.all([
        api.getGuardModels(signal).catch(() => ({ models: [] })),
        api.getGuardStatus(signal).catch(() => null),
      ])
      setModels(modelsRes.models || [])
      setGuardStatus(statusRes)
      setActionError(null)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      setActionError(msg)
    } finally {
      setIsLoading(false)
    }
  }, [])

  useEffect(() => {
    const controller = new AbortController()
    loadData(controller.signal)
    return () => controller.abort()
  }, [loadData])

  // Real-time WebSocket listener for live progress and zero-downtime hot-swap status
  useEffect(() => {
    let ws: WebSocket | null = null
    let reconnectTimer: NodeJS.Timeout | null = null
    let isDisposed = false

    const connectWS = () => {
      if (isDisposed) return

      try {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
        const host = window.location.host || '127.0.0.1:8095'
        const wsUrl = `${protocol}//${host}/ws`

        ws = new WebSocket(wsUrl)

        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data)
            if (
              data.type === 'GUARD_STATUS_CHANGED' ||
              data.type === 'GUARD_MODEL_UPDATED' ||
              data.type === 'GUARD_INSTALL_PROGRESS'
            ) {
              loadData()
            }
          } catch {
            // ignore non-JSON frames
          }
        }

        ws.onclose = () => {
          if (!isDisposed) {
            reconnectTimer = setTimeout(connectWS, 3000)
          }
        }

        ws.onerror = () => {
          if (ws) ws.close()
        }
      } catch {
        if (!isDisposed) {
          reconnectTimer = setTimeout(connectWS, 3000)
        }
      }
    }

    connectWS()

    return () => {
      isDisposed = true
      if (reconnectTimer) clearTimeout(reconnectTimer)
      if (ws) ws.close()
    }
  }, [loadData])

  // Active Model Lookup
  const activeModel = useMemo(() => {
    return models.find((m) => m.is_active) || null
  }, [models])

  interface MismatchState {
    modelID: string
    params: { runtime_type: 'docker' | 'ollama'; endpoint_url: string; force?: boolean; context_window?: number }
    expected: string
    detected: string
  }
  const [mismatchPending, setMismatchPending] = useState<MismatchState | null>(null)
  const [isProbing, setIsProbing] = useState(false)
  const [probeResult, setProbeResult] = useState<string | null>(null)

  // Action handlers
  const handleConnect = async (
    modelID: string,
    params: { runtime_type: 'docker' | 'ollama'; endpoint_url: string; force?: boolean; context_window?: number }
  ) => {
    try {
      setIsActionPending(true)
      setActionError(null)
      const res = await api.connectGuardModel(modelID, params)
      if (res.model_mismatch && !params.force) {
        setMismatchPending({
          modelID,
          params,
          expected: res.expected_model || modelID,
          detected: res.detected_model || 'Unknown',
        })
        return
      }
      setMismatchPending(null)
      await loadData()
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      setActionError(msg)
      throw err
    } finally {
      setIsActionPending(false)
    }
  }

  const handleDeactivate = async (modelID?: string) => {
    try {
      setIsActionPending(true)
      setActionError(null)
      await api.deactivateGuardModel(modelID)
      await loadData()
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      setActionError(msg)
    } finally {
      setIsActionPending(false)
    }
  }

  const handleProbe = async () => {
    try {
      setIsProbing(true)
      setProbeResult(null)
      const status = await api.getGuardStatus()
      setGuardStatus(status)
      if (status && status.running) {
        setProbeResult('Connection Healthy (200 OK)')
      } else {
        setProbeResult('Service Unresponsive')
      }
      setTimeout(() => setProbeResult(null), 3500)
    } catch (err: unknown) {
      setProbeResult('Error: ' + (err instanceof Error ? err.message : String(err)))
      setTimeout(() => setProbeResult(null), 4000)
    } finally {
      setIsProbing(false)
    }
  }

  return (
    <div className="space-y-6 animate-in fade-in duration-300 pb-20">
      {/* ----------------------------------------------------------------- */}
      {/* 1. Active Shield Status Hero Banner */}
      {/* ----------------------------------------------------------------- */}
      <div
        className={`bg-surface rounded-2xl p-6 border shadow-sm relative overflow-hidden transition-all duration-300 ${
          activeModel && guardStatus?.running
            ? 'border-accent/40 ring-1 ring-accent/20'
            : 'border-subtle'
        }`}
      >
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
          <div className="flex items-start gap-4">
            <div
              className={`p-3 rounded-2xl border shrink-0 ${
                activeModel && guardStatus?.running
                  ? 'bg-accent/10 border-accent/30 text-accent shadow-sm'
                  : 'bg-subtle border-subtle text-muted'
              }`}
            >
              {activeModel && guardStatus?.running ? (
                <ShieldCheck className="w-8 h-8 text-accent" />
              ) : (
                <Shield className="w-8 h-8 text-muted" />
              )}
            </div>

            <div>
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-xs font-mono font-bold uppercase tracking-wider text-muted">
                  Runtime Security Mode
                </span>
                {activeModel && guardStatus?.running ? (
                  <>
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-500/30">
                      Dual-Tier Protected
                    </span>
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-medium bg-surface text-primary border border-subtle">
                      {activeModel.runtime_type === 'ollama' ? 'Ollama Local' : 'Docker Sidecar'}
                    </span>
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-mono text-muted bg-canvas border border-subtle">
                      {activeModel.endpoint_url || 'http://127.0.0.1:11434'}
                    </span>
                  </>
                ) : (
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase bg-amber-50 dark:bg-amber-950/60 text-amber-800 dark:text-amber-300 border border-amber-300 dark:border-amber-500/30">
                    L1 Static Only
                  </span>
                )}
              </div>

              <h2 className="text-xl font-bold text-primary mt-1">
                {activeModel && guardStatus?.running
                  ? `Active Shield: Fail-Fast Cascade with ${activeModel.name}`
                  : 'Active Shield: L1 Static Rules Only (Lightweight Mode)'}
              </h2>

              <p className="text-xs text-muted mt-1 max-w-2xl leading-relaxed">
                {activeModel && guardStatus?.running
                  ? `L1 deterministic regex & DLP rules provide instant fail-fast security (<0.2ms), while ${activeModel.name} conducts deep semantic evaluation for tool calls and prompts.`
                  : 'High-throughput deterministic regex and DLP rules are active (<0.2ms latency). Semantic security engine is on standby (resource-saver mode).'}
              </p>

              {probeResult && (
                <div className="mt-2 inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-mono bg-sky-50 dark:bg-sky-950/40 text-sky-700 dark:text-sky-300 border border-sky-300 dark:border-sky-500/30">
                  <Zap className="w-3.5 h-3.5" />
                  <span>{probeResult}</span>
                </div>
              )}
            </div>
          </div>

          {/* Action buttons on the banner */}
          <div className="flex items-center gap-2 shrink-0 self-end lg:self-center">
            {activeModel && (
              <>
                <button
                  type="button"
                  onClick={handleProbe}
                  disabled={isProbing}
                  className="px-3.5 py-2 rounded-xl text-xs font-medium text-primary bg-surface hover:bg-subtle border border-subtle transition-all flex items-center gap-1.5 shadow-sm"
                  title="Probe and verify endpoint health"
                >
                  <RefreshCw className={`w-3.5 h-3.5 text-accent ${isProbing ? 'animate-spin' : ''}`} />
                  <span>{isProbing ? 'Testing...' : 'Test Endpoint'}</span>
                </button>
                <button
                  type="button"
                  onClick={() => setPolicyTargetModel(activeModel)}
                  className="px-3.5 py-2 rounded-xl text-xs font-medium text-primary bg-surface hover:bg-subtle border border-subtle transition-all flex items-center gap-1.5 shadow-sm"
                  title="Configure Threat Action Policy"
                >
                  <Sliders className="w-3.5 h-3.5 text-accent" />
                  <span>Policy</span>
                </button>
                <button
                  type="button"
                  onClick={() => handleDeactivate(activeModel.id)}
                  disabled={isActionPending}
                  className="px-3.5 py-2 rounded-xl text-xs font-semibold text-rose-700 dark:text-rose-300 bg-rose-50 dark:bg-rose-500/10 hover:bg-rose-100 dark:hover:bg-rose-500/20 border border-rose-300 dark:border-rose-500/30 transition-all flex items-center gap-1.5 shadow-sm disabled:opacity-40"
                  title="Deactivate Semantic Guard"
                >
                  <Power className="w-3.5 h-3.5" />
                  <span>Deactivate</span>
                </button>
              </>
            )}
          </div>
        </div>
      </div>

      {/* ----------------------------------------------------------------- */}
      {/* 2. Single Hardware Optimization Notice (Only on Apple Silicon)    */}
      {/* ----------------------------------------------------------------- */}
      {isAppleSilicon && !dismissAdvisory && (
        <div className="p-3.5 rounded-2xl bg-amber-500/10 border border-amber-500/25 text-xs text-amber-900 dark:text-amber-200 flex items-center justify-between gap-3 animate-in fade-in duration-200">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded-lg bg-amber-500/20 text-amber-600 dark:text-amber-400 shrink-0">
              <Zap className="w-4 h-4" />
            </div>
            <p className="leading-relaxed">
              <strong>Apple Silicon Optimization:</strong> Local Ollama with Metal GPU acceleration is recommended for sub-20ms latency. Docker containers on macOS run under CPU emulation.
            </p>
          </div>
          <button
            type="button"
            onClick={() => setDismissAdvisory(true)}
            aria-label="Dismiss hardware optimization notice"
            className="p-1 rounded-lg hover:bg-amber-500/20 text-amber-700 dark:text-amber-300 transition-colors shrink-0"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Action Error Banner */}
      {actionError && (
        <div className="p-3 bg-rose-50 dark:bg-rose-500/15 border border-rose-200 dark:border-rose-500/30 rounded-xl text-rose-700 dark:text-rose-300 text-xs flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-500 shrink-0" />
            <span>{actionError}</span>
          </div>
          <button
            onClick={() => setActionError(null)}
            className="text-rose-600 dark:text-rose-400 hover:underline text-xs font-mono"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* ----------------------------------------------------------------- */}
      {/* 3. Benchmarked Model Cards Grid (Upper Tier)                      */}
      {/* ----------------------------------------------------------------- */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-primary uppercase tracking-wider font-mono flex items-center gap-2">
              <Layers className="w-4 h-4 text-accent" />
              <span>Benchmarked Security Guard Models</span>
            </h3>
            <p className="text-xs text-muted">
              Curated offline neural security guard models from Farad Ai Benchmark (FAB). Zero network egress guaranteed.
            </p>
          </div>

          <button
            onClick={() => loadData()}
            disabled={isLoading}
            className="p-2 rounded-xl text-muted hover:text-primary hover:bg-subtle border border-subtle transition-colors flex items-center gap-1.5 text-xs font-mono shadow-xs"
            title="Refresh Catalog"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-accent' : ''}`} />
            <span>Sync</span>
          </button>
        </div>

        {isLoading ? (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
            {[1, 2, 3].map((n) => (
              <div
                key={n}
                className="bg-surface rounded-2xl p-6 border border-subtle animate-pulse h-48 flex items-center justify-center text-xs text-muted font-mono"
              >
                Loading Model Catalog...
              </div>
            ))}
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
            {models.map((model) => (
              <ModelCard
                key={model.id}
                model={model}
                isBusy={isActionPending}
                onOpenConnect={(m) => setConnectTargetModel(m)}
                onDeactivate={handleDeactivate}
                onConfigurePolicy={(m) => setPolicyTargetModel(m)}
              />
            ))}
          </div>
        )}
      </div>

      {/* ----------------------------------------------------------------- */}
      {/* 4. FAB Benchmark Leaderboard & Hardware Matrix (Lower Tier)        */}
      {/* ----------------------------------------------------------------- */}
      <BenchmarkLeaderboard
        models={models}
        activeModelId={activeModel?.id}
      />


      {/* ----------------------------------------------------------------- */}
      {/* Model Deployment & Connect Pre-Flight Modal                       */}
      {/* ----------------------------------------------------------------- */}
      {connectTargetModel && (
        <ModelConnectModal
          model={connectTargetModel}
          isBusy={isActionPending}
          onClose={() => setConnectTargetModel(null)}
          onConnect={handleConnect}
        />
      )}

      {/* ----------------------------------------------------------------- */}
      {/* Action Policy Configuration Modal                                 */}
      {/* ----------------------------------------------------------------- */}
      {policyTargetModel && (
        <ActionPolicyModal
          model={policyTargetModel}
          onClose={() => setPolicyTargetModel(null)}
          onSaved={() => loadData()}
        />
      )}

      {/* ----------------------------------------------------------------- */}
      {/* Model Name Mismatch Confirmation Modal                            */}
      {/* ----------------------------------------------------------------- */}
      {mismatchPending && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs animate-in fade-in duration-200">
          <div className="bg-surface border border-subtle rounded-2xl max-w-md w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center gap-3 text-amber-500">
              <AlertTriangle className="w-6 h-6 shrink-0" />
              <h3 className="text-base font-bold text-primary">Model Identity Mismatch</h3>
            </div>
            <p className="text-xs text-muted leading-relaxed">
              The catalog expects model <strong className="text-primary font-mono">{mismatchPending.expected}</strong>, but the specified endpoint responded with <strong className="text-amber-500 font-mono">{mismatchPending.detected}</strong>.
            </p>
            <p className="text-xs text-muted leading-relaxed">
              FaradAiWire can operate with this model. Do you still wish to force connection and activate?
            </p>
            <div className="flex items-center justify-end gap-3 pt-3 border-t border-subtle">
              <button
                type="button"
                onClick={() => setMismatchPending(null)}
                className="px-4 py-2 rounded-xl text-xs font-medium text-muted hover:text-primary hover:bg-subtle transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => {
                  const pending = mismatchPending
                  setMismatchPending(null)
                  handleConnect(pending.modelID, { ...pending.params, force: true })
                }}
                className="px-4 py-2 rounded-xl text-xs font-semibold text-white bg-amber-600 hover:bg-amber-500 transition-all shadow-sm"
              >
                Force Connect & Activate
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ----------------------------------------------------------------- */}
      {/* Real-time Host Telemetry & Hardware Fit Footer Bar                */}
      {/* ----------------------------------------------------------------- */}
      <HostTelemetryBar activeModel={activeModel} />
    </div>
  )
}
