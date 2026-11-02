import React, { useEffect, useState, useCallback, useMemo } from 'react'
import {
  Server,
  Activity,
  AlertTriangle,
  CheckCircle2,
  RefreshCw,
  Layers,
  Database,
  Cpu,
} from 'lucide-react'
import { GuardModel, HostResources } from '../types'
import { api } from '../api'

/**
 * Calculates GQA-scaled KV Cache RAM consumption in MB.
 * Formula: 2 (K+V) * NumLayers * NumKVHeads * HeadDim * 2 (FP16 bytes) * ContextTokens
 */
export function calculateKVCacheMB(model: GuardModel | null | undefined, tokens: number): number {
  if (!model) return 0
  const layers = model.num_layers || 32
  const kvHeads = model.num_kv_heads || 4
  const headDim = model.head_dim || 128
  const bytes = 2 * layers * kvHeads * headDim * 2 * tokens
  return Math.round(bytes / (1024 * 1024))
}

interface HostTelemetryBarProps {
  activeModel?: GuardModel | null
  selectedContextWindow?: number
}

export const HostTelemetryBar: React.FC<HostTelemetryBarProps> = ({
  activeModel,
  selectedContextWindow,
}) => {
  const [telemetry, setTelemetry] = useState<HostResources | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const effectiveContextWindow = useMemo(() => {
    return selectedContextWindow || activeModel?.context_window || 2048
  }, [selectedContextWindow, activeModel?.context_window])

  const fetchTelemetry = useCallback(async (signal?: AbortSignal) => {
    try {
      setLoading(true)
      const data = await api.getHostResources(signal)
      setTelemetry(data)
      setError(null)
    } catch (err: unknown) {
      if (err instanceof Error && err.name === 'AbortError') return
      setError('Telemetry offline')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    const controller = new AbortController()
    fetchTelemetry(controller.signal)

    const interval = setInterval(() => {
      // Pause polling if the tab is inactive
      if (document.hidden) return
      fetchTelemetry(controller.signal)
    }, 5000)

    return () => {
      controller.abort()
      clearInterval(interval)
    }
  }, [fetchTelemetry])

  // Computed RAM stats
  const ramStats = useMemo(() => {
    if (!telemetry || telemetry.total_bytes === 0) {
      return { usedGB: 0, totalGB: 0, pct: 0, availMB: 0 }
    }
    const usedGB = telemetry.used_bytes / (1024 * 1024 * 1024)
    const totalGB = telemetry.total_bytes / (1024 * 1024 * 1024)
    const availMB = telemetry.available_bytes / (1024 * 1024)
    const pct = Math.min(100, Math.round((telemetry.used_bytes / telemetry.total_bytes) * 100))
    return { usedGB, totalGB, pct, availMB }
  }, [telemetry])

  // Computed Swap stats
  const swapStats = useMemo(() => {
    if (!telemetry) return { usedMB: 0, isHealthy: true }
    const usedMB = Math.round(telemetry.swap_used_bytes / (1024 * 1024))
    return { usedMB, isHealthy: usedMB < 100 }
  }, [telemetry])

  // Computed Hardware Fit Check
  const hardwareFit = useMemo(() => {
    if (error || !telemetry) {
      return {
        status: 'idle' as const,
        label: error ? 'Telemetry Offline' : 'Probing Host...',
        colorClass: 'text-muted-foreground border-border bg-muted/40',
        details: error
          ? 'Host telemetry daemon unreachable; memory fit assessment suspended.'
          : 'Querying host memory and cgroup limits...',
      }
    }

    if (!activeModel) {
      return {
        status: 'idle' as const,
        label: 'No Active Model',
        colorClass: 'text-muted-foreground border-border bg-muted/40',
        details: 'Select or connect a guard model to run live memory fit assessment.',
      }
    }

    const kvMB = calculateKVCacheMB(activeModel, effectiveContextWindow)
    const weightsMB = activeModel.ram_required_mb || 0
    const totalRequiredMB = weightsMB + kvMB
    const availableMB = ramStats.availMB

    const headroomMB = availableMB - totalRequiredMB

    if (headroomMB >= 500) {
      return {
        status: 'ready' as const,
        label: 'Hardware Fit: Ready',
        colorClass: 'text-emerald-500 border-emerald-500/30 bg-emerald-500/10',
        details: `${totalRequiredMB} MB projected (${weightsMB} MB weights + ${kvMB} MB KV) • ${Math.round(headroomMB)} MB headroom`,
        headroomMB,
        totalRequiredMB,
      }
    } else if (headroomMB >= 0) {
      return {
        status: 'tight' as const,
        label: 'Hardware Fit: Tight (<500MB)',
        colorClass: 'text-amber-500 border-amber-500/30 bg-amber-500/10',
        details: `${totalRequiredMB} MB projected • Only ${Math.round(headroomMB)} MB headroom remaining`,
        headroomMB,
        totalRequiredMB,
      }
    } else {
      return {
        status: 'oom_risk' as const,
        label: 'Thrashing / OOM Risk',
        colorClass: 'text-rose-500 border-rose-500/30 bg-rose-500/10 animate-pulse',
        details: `Exceeds available RAM by ${Math.round(Math.abs(headroomMB))} MB (${totalRequiredMB} MB req vs ${Math.round(availableMB)} MB avail)`,
        headroomMB,
        totalRequiredMB,
      }
    }
  }, [error, telemetry, activeModel, effectiveContextWindow, ramStats.availMB])

  if (!telemetry && !error) {
    return null
  }

  return (
    <footer
      data-testid="host-telemetry-bar"
      className="fixed bottom-0 left-0 right-0 z-40 bg-card/95 backdrop-blur-md border-t border-border shadow-lg px-4 py-2 text-xs flex flex-wrap items-center justify-between gap-3"
    >
      {/* Left: Memory & CPU Host Telemetry */}
      <div className="flex flex-wrap items-center gap-4">
        {/* Host / Container Badge */}
        <div className="flex items-center gap-1.5 font-medium text-foreground">
          <Server className="w-3.5 h-3.5 text-primary" />
          <span>Host Telemetry</span>
          {telemetry?.cgroup_limited ? (
            <span
              className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-blue-500/15 text-blue-400 border border-blue-500/20"
              title="Memory limits constrained by Linux cgroup container quota"
            >
              cgroup Enforced
            </span>
          ) : (
            <span
              className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-muted text-muted-foreground border border-border"
              title="Using physical host OS resources"
            >
              OS Native
            </span>
          )}
        </div>

        {error ? (
          <div className="flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-medium text-amber-500 bg-amber-500/10 border border-amber-500/20">
            <AlertTriangle className="w-3 h-3" />
            <span>Telemetry Service Offline</span>
          </div>
        ) : (
          <>
            {/* RAM Bar */}
            <div className="flex items-center gap-2">
              <span className="text-muted-foreground">RAM:</span>
              <div
                role="progressbar"
                aria-label="Host RAM utilization"
                aria-valuenow={ramStats.pct}
                aria-valuemin={0}
                aria-valuemax={100}
                className="w-24 h-2 bg-secondary rounded-full overflow-hidden relative"
              >
                <div
                  className={`h-full transition-all duration-500 ${
                    ramStats.pct > 90
                      ? 'bg-rose-500'
                      : ramStats.pct > 75
                      ? 'bg-amber-500'
                      : 'bg-emerald-500'
                  }`}
                  style={{ width: `${ramStats.pct}%` }}
                />
              </div>
              <span className="font-mono text-[11px] text-foreground">
                {ramStats.usedGB.toFixed(1)} / {ramStats.totalGB.toFixed(1)} GB ({ramStats.pct}%)
              </span>
            </div>

            {/* Swap Usage */}
            <div className="flex items-center gap-1.5">
              <Database className="w-3.5 h-3.5 text-muted-foreground" />
              <span className="text-muted-foreground">Swap:</span>
              {swapStats.isHealthy ? (
                <span className="px-1.5 py-0.5 rounded text-[10px] font-mono text-emerald-500 bg-emerald-500/10 border border-emerald-500/20">
                  {swapStats.usedMB} MB (Safe)
                </span>
              ) : (
                <span
                  className="px-1.5 py-0.5 rounded text-[10px] font-mono text-amber-500 bg-amber-500/10 border border-amber-500/20 flex items-center gap-1"
                  title="Swap thrashing can cause model latency spikes"
                >
                  <AlertTriangle className="w-3 h-3" />
                  {swapStats.usedMB} MB Thrashing
                </span>
              )}
            </div>

            {/* CPU Load */}
            <div className="flex items-center gap-1.5">
              <Cpu className="w-3.5 h-3.5 text-muted-foreground" />
              <span className="text-muted-foreground">CPU:</span>
              <span className="font-mono text-foreground">
                {telemetry ? `${telemetry.cpu_percent.toFixed(0)}%` : '--'}
              </span>
            </div>
          </>
        )}
      </div>

      {/* Right: Hardware Fit & Model Projection */}
      <div className="flex flex-wrap items-center gap-3">
        {activeModel && (
          <div className="hidden sm:flex items-center gap-1.5 text-muted-foreground text-[11px]">
            <Layers className="w-3.5 h-3.5 text-primary" />
            <span className="font-medium text-foreground">{activeModel.name}</span>
            <span>(ctx {effectiveContextWindow})</span>
          </div>
        )}

        {/* Live Hardware Fit Badge */}
        <div
          className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-[11px] font-medium shadow-sm transition-colors ${hardwareFit.colorClass}`}
          title={hardwareFit.details}
        >
          {hardwareFit.status === 'ready' && <CheckCircle2 className="w-3.5 h-3.5" />}
          {hardwareFit.status === 'tight' && <AlertTriangle className="w-3.5 h-3.5" />}
          {hardwareFit.status === 'oom_risk' && <AlertTriangle className="w-3.5 h-3.5 text-rose-500" />}
          {hardwareFit.status === 'idle' && <Activity className="w-3.5 h-3.5" />}
          <span>{hardwareFit.label}</span>
        </div>

        {/* Refresh button */}
        <button
          onClick={() => fetchTelemetry()}
          disabled={loading}
          className="p-1 rounded hover:bg-muted text-muted-foreground hover:text-foreground transition-colors"
          title="Refresh Host Telemetry"
          aria-label="Refresh Host Telemetry"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>
    </footer>
  )
}
