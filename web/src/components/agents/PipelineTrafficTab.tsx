import React, { useState } from 'react'
import { RateLimitOverride, LoopProtectionOverride, ToolMetadata } from '../../types'
import { Input } from '../ui/Input'
import { Badge, BadgeProps } from '../ui/Badge'

type StepVariant = NonNullable<BadgeProps['variant']>
import {
  Activity,
  Zap,
  Repeat,
  Shield,
  Sliders,
  CheckCircle2,
  AlertTriangle,
  Layers,
  Plus,
  X,
  FileCheck,
  EyeOff,
  UserCheck,
} from 'lucide-react'

export interface PipelineTrafficTabProps {
  rateLimit?: RateLimitOverride
  onChangeRateLimit: (rateLimit: RateLimitOverride) => void
  loopProtection?: LoopProtectionOverride
  onChangeLoopProtection: (loopProtection: LoopProtectionOverride) => void
  availableTools: ToolMetadata[]
  activeFilters?: string[]
}

export const PipelineTrafficTab: React.FC<PipelineTrafficTabProps> = ({
  rateLimit = { max_burst: 5, refill_rate: 1.0 },
  onChangeRateLimit,
  loopProtection = {
    enabled: true,
    max_repeat: 3,
    window_seconds: 10,
    exclude_tools: [],
  },
  onChangeLoopProtection,
  availableTools,
  activeFilters = [],
}) => {
  const [customToolInput, setCustomToolInput] = useState('')

  const isGlobalPrefillActive = activeFilters.includes('prefill_block')
  const isGlobalRateLimitActive = activeFilters.includes('rate_limiting')
  const isGlobalLoopActive = activeFilters.includes('loop_protection')
  const isGlobalSchemaActive = activeFilters.includes('schema_validation')
  const isGlobalDLPActive = activeFilters.includes('dlp')
  const isGlobalGuardActive = activeFilters.includes('guard')
  const isGlobalHITLActive = activeFilters.includes('hitl')

  const handleBurstChange = (val: number) => {
    onChangeRateLimit({
      ...rateLimit,
      max_burst: Math.max(0, val),
    })
  }

  const handleRefillChange = (val: number) => {
    onChangeRateLimit({
      ...rateLimit,
      refill_rate: Math.max(0, val),
    })
  }

  const handleToggleLoopEnabled = (enabled: boolean) => {
    onChangeLoopProtection({
      ...loopProtection,
      enabled,
    })
  }

  const handleMaxRepeatChange = (val: number) => {
    onChangeLoopProtection({
      ...loopProtection,
      max_repeat: Math.max(1, val),
    })
  }

  const handleWindowChange = (val: number) => {
    onChangeLoopProtection({
      ...loopProtection,
      window_seconds: Math.max(1, val),
    })
  }

  const handleAddExcludedTool = (toolName: string) => {
    const trimmed = toolName.trim()
    if (!trimmed) return
    const current = loopProtection.exclude_tools || []
    if (!current.includes(trimmed)) {
      onChangeLoopProtection({
        ...loopProtection,
        exclude_tools: [...current, trimmed],
      })
    }
    setCustomToolInput('')
  }

  const handleRemoveExcludedTool = (toolName: string) => {
    const current = loopProtection.exclude_tools || []
    onChangeLoopProtection({
      ...loopProtection,
      exclude_tools: current.filter((t) => t !== toolName),
    })
  }

  const excluded = loopProtection.exclude_tools || []

  // Execution rail blueprint steps
  const pipelineSteps = [
    {
      order: 5,
      name: 'Prefill Block',
      category: 'Ingress Guard',
      icon: <EyeOff className="w-4 h-4 text-purple-400" />,
      isActive: isGlobalPrefillActive,
      isSuspended: false,
      statusLabel: isGlobalPrefillActive ? 'Active' : 'Cluster Off',
      statusVariant: (isGlobalPrefillActive ? 'emerald' : 'neutral') as StepVariant,
      latency: '<0.1ms',
      desc: 'Blocks adversarial prompt injection and prefix forcing.',
    },
    {
      order: 10,
      name: 'Rate Limiting',
      category: 'Traffic Ingress',
      icon: <Zap className="w-4 h-4 text-cyan-400" />,
      isActive: isGlobalRateLimitActive,
      isSuspended: false,
      statusLabel: !isGlobalRateLimitActive
        ? 'Cluster Off'
        : rateLimit.max_burst > 0
        ? `${rateLimit.max_burst}t / ${rateLimit.refill_rate}rps`
        : 'Active',
      statusVariant: (isGlobalRateLimitActive ? 'cyan' : 'neutral') as StepVariant,
      latency: '<0.05ms',
      desc: 'Token-bucket rate limiter defending upstream backends against spikes.',
    },
    {
      order: 15,
      name: 'Loop Protection',
      category: 'Execution Guard',
      icon: <Repeat className="w-4 h-4 text-amber-400" />,
      isActive: isGlobalLoopActive && loopProtection.enabled,
      isSuspended: !isGlobalLoopActive && loopProtection.enabled,
      statusLabel: !isGlobalLoopActive
        ? (loopProtection.enabled ? 'Suspended' : 'Bypassed')
        : (loopProtection.enabled ? `${loopProtection.max_repeat}x / ${loopProtection.window_seconds}s` : 'Bypassed'),
      statusVariant: (!isGlobalLoopActive
        ? (loopProtection.enabled ? 'amber' : 'neutral')
        : (loopProtection.enabled ? 'emerald' : 'amber')) as StepVariant,
      latency: '<0.1ms',
      desc: 'Prevents infinite tool invocation loops and runaway recursion.',
    },
    {
      order: 30,
      name: 'Schema Validation',
      category: 'Contract Integrity',
      icon: <FileCheck className="w-4 h-4 text-emerald-400" />,
      isActive: isGlobalSchemaActive,
      isSuspended: false,
      statusLabel: isGlobalSchemaActive ? 'Active' : 'Cluster Off',
      statusVariant: (isGlobalSchemaActive ? 'emerald' : 'neutral') as StepVariant,
      latency: '<0.2ms',
      desc: 'Enforces JSON Schema pinning and input contract stability.',
    },
    {
      order: 50,
      name: 'DLP Masking',
      category: 'Full-Duplex (Req/Resp)',
      icon: <Shield className="w-4 h-4 text-blue-400" />,
      isActive: isGlobalDLPActive,
      isSuspended: false,
      statusLabel: isGlobalDLPActive ? 'Active' : 'Cluster Off',
      statusVariant: (isGlobalDLPActive ? 'emerald' : 'neutral') as StepVariant,
      latency: '<0.3ms',
      desc: 'Deterministic regex & pattern redaction for PII, tokens, and secrets.',
    },
    {
      order: 55,
      name: 'Semantic Security Guard',
      category: 'Full-Duplex Neural Guard',
      icon: <Activity className="w-4 h-4 text-indigo-400" />,
      isActive: isGlobalGuardActive,
      isSuspended: false,
      statusLabel: isGlobalGuardActive ? 'Active Engine' : 'Cluster Off',
      statusVariant: (isGlobalGuardActive ? 'emerald' : 'neutral') as StepVariant,
      latency: '<1.5ms',
      desc: 'Unified local neural guard deep inspection (Root Intent Isolation).',
    },
    {
      order: 70,
      name: 'HITL Gate',
      category: 'Egress Approval',
      icon: <UserCheck className="w-4 h-4 text-rose-400" />,
      isActive: isGlobalHITLActive,
      isSuspended: false,
      statusLabel: isGlobalHITLActive ? 'Dynamic' : 'Cluster Off',
      statusVariant: (isGlobalHITLActive ? 'emerald' : 'neutral') as StepVariant,
      latency: 'Human / Auto',
      desc: 'Dual-channel operator authorization for high-risk executions.',
    },
  ]

  return (
    <div className="space-y-6 font-sans">
      {/* Header Overview Card */}
      <div className="p-4 rounded-2xl bg-surface border border-subtle flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-xs">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-accent/10 border border-accent/20 flex items-center justify-center text-accent shrink-0">
            <Activity className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-primary">Pipeline & Traffic Controls</h3>
            <p className="text-xs text-muted">
              Configure per-agent ingress rate limits, recursion loop safeguards, and inspect the runtime execution rail.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="cyan" className="font-mono text-[10px]">
            ADR-0044 Enforced
          </Badge>
          {!isGlobalLoopActive && loopProtection.enabled ? (
            <Badge variant="amber" className="font-mono text-[10px] flex items-center gap-1">
              <AlertTriangle className="w-3 h-3 text-amber-500" />
              Loop: Suspended (Master Killswitch Engaged)
            </Badge>
          ) : (
            <Badge variant={loopProtection.enabled ? 'emerald' : 'amber'} className="font-mono text-[10px]">
              Loop: {loopProtection.enabled ? 'Active' : 'Bypassed'}
            </Badge>
          )}
        </div>
      </div>

      {/* Grid: Rate Limiting & Loop Protection */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Section 1: Ingress Rate Limiting */}
        <div className="p-4 rounded-2xl bg-surface border border-subtle flex flex-col justify-between space-y-4 shadow-xs">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-subtle">
              <span className="font-semibold text-primary flex items-center gap-2 text-xs">
                <Zap className="w-4 h-4 text-cyan-500" />
                Ingress Rate Limiting (Token-Bucket)
              </span>
              <span className="text-[10px] font-mono text-muted">Order: 10</span>
            </div>
            <p className="text-xs text-muted mt-2">
              Limits incoming tool execution request velocity for this agent. Protects target MCP tools from burst floods.
            </p>
            <div className="grid grid-cols-2 gap-3 mt-4">
              <Input
                label="Max Burst (Tokens)"
                type="number"
                min="0"
                max="1000"
                value={rateLimit.max_burst}
                onChange={(e) => handleBurstChange(parseInt(e.target.value) || 0)}
                placeholder="5"
                helperText="Maximum allowed burst request capacity."
                isMono
              />
              <Input
                label="Refill Rate (Tokens/sec)"
                type="number"
                min="0"
                step="0.5"
                max="500"
                value={rateLimit.refill_rate}
                onChange={(e) => handleRefillChange(parseFloat(e.target.value) || 0)}
                placeholder="1.0"
                helperText="Continuous token regeneration rate per second."
                isMono
              />
            </div>
          </div>
          <div className="p-2.5 rounded-xl bg-canvas border border-subtle text-[11px] text-muted flex items-center gap-2">
            <Sliders className="w-3.5 h-3.5 text-accent shrink-0" />
            <span>Effective limit: <strong>{rateLimit.refill_rate} req/s</strong> sustained, bursting up to <strong>{rateLimit.max_burst}</strong>.</span>
          </div>
        </div>

        {/* Section 2: Agent Loop Protection */}
        <div className="p-4 rounded-2xl bg-surface border border-subtle flex flex-col justify-between space-y-4 shadow-xs">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-subtle">
              <span className="font-semibold text-primary flex items-center gap-2 text-xs">
                <Repeat className="w-4 h-4 text-amber-500" />
                Infinite Loop & Recursion Protection
              </span>
              <span className="text-[10px] font-mono text-muted">Order: 15</span>
            </div>
            <div className="flex items-center justify-between mt-2">
              <p className="text-xs text-muted">
                Detects identical parameters invoked repeatedly within a sliding window.
              </p>
              <label htmlFor="loop-protection-toggle" className="relative inline-flex items-center cursor-pointer shrink-0 ml-3">
                <input
                  id="loop-protection-toggle"
                  type="checkbox"
                  aria-label="Toggle infinite loop and recursion protection"
                  checked={loopProtection.enabled}
                  onChange={(e) => handleToggleLoopEnabled(e.target.checked)}
                  className="sr-only peer"
                />
                <div className="w-8 h-4 bg-canvas border border-subtle peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-3 after:w-3 after:transition-all peer-checked:bg-emerald-500"></div>
              </label>
            </div>

            {!isGlobalLoopActive && loopProtection.enabled && (
              <div className="p-3 my-2.5 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-800 dark:text-amber-300 text-xs flex items-start gap-2.5">
                <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0 mt-0.5" />
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-bold">Gateway Master Killswitch Inactive</span>
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-900 dark:text-amber-200 uppercase font-semibold">
                      Suspended
                    </span>
                  </div>
                  <p className="text-[11px] leading-relaxed opacity-90">
                    Agent Loop Protection is currently turned OFF cluster-wide in Gateway Settings. Your profile policy limits below are safely preserved (Policy Intent) and will automatically take effect once the cluster filter is re-enabled.
                  </p>
                </div>
              </div>
            )}

            <div className="grid grid-cols-2 gap-3 mt-4">
              <Input
                label="Max Repeat Count"
                type="number"
                min="1"
                max="50"
                disabled={!loopProtection.enabled}
                value={loopProtection.max_repeat}
                onChange={(e) => handleMaxRepeatChange(parseInt(e.target.value) || 1)}
                placeholder="3"
                helperText="Allowed identical calls before triggering block."
                isMono
              />
              <Input
                label="Window Duration (Seconds)"
                type="number"
                min="1"
                max="3600"
                disabled={!loopProtection.enabled}
                value={loopProtection.window_seconds}
                onChange={(e) => handleWindowChange(parseInt(e.target.value) || 1)}
                placeholder="10"
                helperText="Sliding deduplication window time."
                isMono
              />
            </div>

            {/* Excluded Tools */}
            <div className="mt-3 space-y-1.5">
              <label htmlFor="custom-tool-exclude-input" className="block text-xs font-semibold text-primary">Excluded Tools (Bypass Loop Check)</label>
              <div className="flex flex-wrap gap-1.5 min-h-[32px] p-2 rounded-xl bg-canvas border border-subtle">
                {excluded.length === 0 ? (
                  <span className="text-[11px] text-muted italic">No tools excluded (all tools monitored)</span>
                ) : (
                  excluded.map((tool) => (
                    <span
                      key={tool}
                      className="inline-flex items-center gap-1 px-2 py-0.5 rounded-lg bg-surface border border-subtle text-[11px] font-mono text-primary"
                    >
                      {tool}
                      <button
                        type="button"
                        aria-label={`Remove ${tool} from loop protection excluded tools`}
                        onClick={() => handleRemoveExcludedTool(tool)}
                        className="text-muted hover:text-rose-400 transition-colors"
                      >
                        <X className="w-3 h-3" />
                      </button>
                    </span>
                  ))
                )}
              </div>
              <div className="flex gap-1.5 mt-1">
                <input
                  id="custom-tool-exclude-input"
                  type="text"
                  aria-label="Tool name to exclude from loop protection"
                  value={customToolInput}
                  onChange={(e) => setCustomToolInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      e.preventDefault()
                      handleAddExcludedTool(customToolInput)
                    }
                  }}
                  placeholder="Exclude tool name (e.g. ping)..."
                  className="flex-1 px-2.5 py-1 text-xs rounded-lg bg-canvas border border-subtle text-primary font-mono focus:outline-none focus:ring-1 focus:ring-accent"
                />
                <button
                  type="button"
                  aria-label="Add excluded tool"
                  onClick={() => handleAddExcludedTool(customToolInput)}
                  className="px-2.5 py-1 text-xs rounded-lg bg-subtle hover:bg-surface border border-subtle text-primary font-medium flex items-center gap-1 transition-colors"
                >
                  <Plus className="w-3 h-3" /> Add
                </button>
              </div>

              {/* Quick suggestion chips from available tools */}
              {availableTools && availableTools.length > 0 && (
                <div className="pt-1">
                  <span className="text-[10px] text-muted block mb-1">Quick add from discovered tools:</span>
                  <div className="flex flex-wrap gap-1 max-h-20 overflow-y-auto">
                    {availableTools
                      .filter((t) => !excluded.includes(t.canonical_name || t.name))
                      .slice(0, 8)
                      .map((t) => {
                        const name = t.canonical_name || t.name
                        return (
                          <button
                            key={name}
                            type="button"
                            aria-label={`Exclude ${name} from loop protection`}
                            onClick={() => handleAddExcludedTool(name)}
                            className="px-2 py-0.5 rounded-md bg-subtle/50 hover:bg-accent/15 border border-subtle text-[10px] font-mono text-muted hover:text-accent transition-colors"
                          >
                            + {name}
                          </button>
                        )
                      })}
                  </div>
                </div>
              )}
            </div>
          </div>

          <div className="p-2.5 rounded-xl bg-canvas border border-subtle text-[11px] text-muted flex items-center gap-2">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-500 shrink-0" />
            <span>
              {loopProtection.enabled
                ? `Blocks tool execution if repeated identical call exceeds ${loopProtection.max_repeat}x in ${loopProtection.window_seconds}s.`
                : 'Warning: Loop protection disabled. Agent is vulnerable to infinite recursion.'}
            </span>
          </div>
        </div>
      </div>

      {/* Section 3: Runtime Security Envelope Blueprint */}
      <div className="p-4 rounded-2xl bg-surface border border-subtle space-y-4 shadow-xs">
        <div className="flex items-center justify-between pb-3 border-b border-subtle">
          <div>
            <h4 className="text-xs font-semibold text-primary flex items-center gap-2">
              <Layers className="w-4 h-4 text-indigo-400" />
              Runtime Security Envelope Blueprint
            </h4>
            <p className="text-[11px] text-muted mt-0.5">
              Live sequential order of security layers executed on every MCP request & response in FaradAiWire.
            </p>
          </div>
          <Badge variant="indigo" className="font-mono text-[10px]">
            Full-Duplex Wire
          </Badge>
        </div>

        {/* Visual Pipeline Rail */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-7 gap-2 relative">
          {pipelineSteps.map((step) => (
            <div
              key={step.name}
              className={`p-3 rounded-xl border flex flex-col justify-between space-y-2 relative group transition-all min-w-0 overflow-hidden ${
                step.isActive
                  ? 'bg-canvas/90 border-subtle hover:border-accent/40 shadow-xs'
                  : step.isSuspended
                  ? 'bg-amber-500/5 border-amber-500/30'
                  : 'bg-canvas/40 border-dashed border-subtle/70 opacity-60'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="w-5 h-5 rounded-md bg-surface border border-subtle flex items-center justify-center text-[10px] font-mono text-muted font-bold shrink-0">
                  {step.order}
                </span>
                <span className="text-[9px] font-mono text-muted">{step.latency}</span>
              </div>
              <div className="space-y-1 min-w-0">
                <div className="flex items-center gap-1.5 min-w-0">
                  <span className="shrink-0">{step.icon}</span>
                  <span className="text-xs font-semibold text-primary truncate">{step.name}</span>
                </div>
                <p className="text-[10px] text-muted line-clamp-2 leading-relaxed">{step.desc}</p>
              </div>
              <div className="pt-2 border-t border-subtle flex flex-col gap-1 min-w-0">
                <span className="text-[9px] font-mono text-muted truncate block" title={step.category}>
                  {step.category}
                </span>
                <div className="flex items-center justify-between min-w-0 pt-0.5">
                  <Badge
                    variant={step.statusVariant}
                    size="sm"
                    className="text-[9px] px-1.5 py-0.5 truncate max-w-full font-mono"
                  >
                    {step.statusLabel}
                  </Badge>
                </div>
              </div>
            </div>
          ))}
        </div>

        <div className="p-3 rounded-xl bg-canvas border border-subtle flex items-center justify-between text-xs text-muted">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>
              All layers operate in-process with zero remote HTTP sidecars. Deterministic filters execute at Layer 1 (&lt;0.2ms), while the local Semantic Security Guard evaluates deep threats (&lt;1.5ms).
            </span>
          </div>
        </div>
      </div>
    </div>
  )
}
