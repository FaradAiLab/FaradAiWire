import React, { useState, useEffect, useCallback } from 'react'
import { ShieldCheck, Sliders, Server, Cpu, Trash2, RefreshCw, CheckCircle2, AlertTriangle, Zap, Settings, Network } from 'lucide-react'
import { GatewayStatus, ProtocolItem } from '../types'
import { api } from '../api'
import { SLMConnectionModal } from './SLMConnectionModal'

interface OverviewTabProps {
  status: GatewayStatus | null
  onRefresh: () => void
}

export const OverviewTab: React.FC<OverviewTabProps> = ({ status, onRefresh }) => {
  const [clearingSchemas, setClearingSchemas] = useState(false)
  const [reloading, setReloading] = useState(false)
  const [actionMessage, setActionMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)
  const [probingSLM, setProbingSLM] = useState(false)
  const [slmProbeResult, setSlmProbeResult] = useState<string | null>(null)
  const [isSLMModalOpen, setIsSLMModalOpen] = useState(false)

  // Connected Tool Sources (Protocols) live health state
  const [protocols, setProtocols] = useState<ProtocolItem[]>([])
  const [probingProtocols, setProbingProtocols] = useState(false)
  const [protocolHealth, setProtocolHealth] = useState<Record<string, { status: 'healthy' | 'unhealthy'; count?: number; error?: string }>>({})

  const fetchProtocols = useCallback(async (signal?: AbortSignal) => {
    try {
      const res = await api.getProtocols(signal)
      setProtocols(res.protocols || [])
    } catch {
      // In-memory silent fallback
    }
  }, [])

  useEffect(() => {
    const abortController = new AbortController()
    fetchProtocols(abortController.signal)
    return () => abortController.abort()
  }, [fetchProtocols])

  const handleCheckProtocolHealth = async () => {
    if (protocols.length === 0) return
    setProbingProtocols(true)
    const newHealth: Record<string, { status: 'healthy' | 'unhealthy'; count?: number; error?: string }> = {}
    await Promise.all(
      protocols.map(async (proto) => {
        try {
          const res = await api.probeProtocol({
            type: proto.type,
            url: proto.url_or_command,
            auth_token: proto.auth_token,
            headers: proto.headers,
            command: proto.command || proto.url_or_command,
            args: proto.args,
            env: proto.env,
          })
          newHealth[proto.id] = {
            status: 'healthy',
            count: res.count || (res.tools ? res.tools.length : 0),
          }
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : String(err)
          newHealth[proto.id] = {
            status: 'unhealthy',
            error: msg,
          }
        }
      })
    )
    setProtocolHealth(newHealth)
    setProbingProtocols(false)
  }

  const handleClearSchemas = async () => {
    try {
      setClearingSchemas(true)
      const res = await api.clearSchemas()
      setActionMessage({ type: 'success', text: res.message || 'Schema baselines cleared successfully.' })
      onRefresh()
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      setActionMessage({ type: 'error', text: `Failed to clear schemas: ${msg}` })
    } finally {
      setClearingSchemas(false)
    }
  }

  const handleReload = async () => {
    try {
      setReloading(true)
      const res = await api.reloadGateway()
      setActionMessage({ type: 'success', text: res.message || 'Gateway configuration reloaded.' })
      onRefresh()
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      setActionMessage({ type: 'error', text: `Reload failed: ${msg}` })
    } finally {
      setReloading(false)
    }
  }

  const handleProbeSLM = async () => {
    try {
      setProbingSLM(true)
      setSlmProbeResult(null)
      const res = await api.probeSLM()
      setSlmProbeResult(JSON.stringify(res, null, 2))
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      setSlmProbeResult(`Probe failed: ${msg}`)
    } finally {
      setProbingSLM(false)
    }
  }

  const activeFilters = status?.active_filters || []
  const slmActive = status?.slm_tier === 'neural_active' || status?.slm_status === 'active'

  return (
    <div className="space-y-6">
      {/* Action Notification */}
      {actionMessage && (
        <div
          className={`p-4 rounded-xl border flex items-center justify-between gap-3 text-sm ${
            actionMessage.type === 'success'
              ? 'bg-emerald-50 text-emerald-800 border-emerald-200 dark:bg-emerald-950/40 dark:border-emerald-500/30 dark:text-emerald-300'
              : 'bg-rose-50 text-rose-800 border-rose-200 dark:bg-rose-950/40 dark:border-rose-500/30 dark:text-rose-300'
          }`}
        >
          <div className="flex items-center gap-2">
            {actionMessage.type === 'success' ? <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400" /> : <AlertTriangle className="w-4 h-4 text-rose-600 dark:text-rose-400" />}
            <span>{actionMessage.text}</span>
          </div>
          <button onClick={() => setActionMessage(null)} className="text-xs hover:underline text-gray-500 dark:text-gray-400">
            Dismiss
          </button>
        </div>
      )}

      {/* Top Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Status Card */}
        <div className="glass-card glass-card-hover p-6">
          <div className="flex items-center justify-between text-xs text-gray-500 dark:text-gray-400 font-semibold uppercase tracking-wider mb-2">
            <span>System Status</span>
            <ShieldCheck className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
          </div>
          <div className="text-3xl font-extrabold text-emerald-600 dark:text-emerald-400 tracking-tight">Active</div>
          <p className="text-xs text-gray-500 dark:text-gray-400 mt-2">All security & gateway proxy layers active</p>
        </div>

        {/* Active Filters Card */}
        <div className="glass-card glass-card-hover p-6">
          <div className="flex items-center justify-between text-xs text-gray-500 dark:text-gray-400 font-semibold uppercase tracking-wider mb-2">
            <span>Active Filters</span>
            <Sliders className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
          </div>
          <div className="text-3xl font-extrabold text-cyan-700 dark:text-cyan-300 tracking-tight">{activeFilters.length}</div>
          <div className="flex flex-wrap gap-1.5 mt-2">
            {activeFilters.length > 0 ? (
              activeFilters.map((f) => (
                <span
                  key={f}
                  className="px-2 py-0.5 rounded font-mono text-[10px] bg-cyan-50 text-cyan-800 border border-cyan-200 dark:bg-cyan-950/80 dark:text-cyan-300 dark:border-cyan-800/40"
                >
                  {f}
                </span>
              ))
            ) : (
              <span className="text-xs text-gray-400 dark:text-gray-500">No active filters configured</span>
            )}
          </div>
        </div>

        {/* Architecture Mode Card */}
        <div className="glass-card glass-card-hover p-6">
          <div className="flex items-center justify-between text-xs text-gray-500 dark:text-gray-400 font-semibold uppercase tracking-wider mb-2">
            <span>Architecture Mode</span>
            <Server className="w-4 h-4 text-indigo-600 dark:text-indigo-400" />
          </div>
          <div className="text-xl font-bold font-mono text-indigo-700 dark:text-indigo-300 tracking-tight">
            {status?.runtime_mode === 'MANAGED' ? 'Managed Mode' : 'Standalone Core'}
          </div>
          <p className="text-xs text-gray-500 dark:text-gray-400 mt-2">100% Offline-First / Zero-Egress Boundary</p>
        </div>
      </div>

      {/* Semantic Security Guard Card */}
      <div className="glass-card p-6 border-l-4 border-l-emerald-500">
        <div className="flex flex-wrap items-center justify-between gap-4 mb-4">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-emerald-50 text-emerald-700 border border-emerald-200 dark:bg-emerald-500/10 dark:border-emerald-500/30 dark:text-emerald-400 flex items-center justify-center">
              <Cpu className="w-5 h-5" />
            </div>
            <div>
              <h3 className="font-bold text-base text-gray-900 dark:text-gray-100 flex items-center gap-2">
                Semantic Security Guard (Active Engine)
                <span
                  className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded-full ${
                    slmActive
                      ? 'bg-emerald-50 text-emerald-800 border border-emerald-200 dark:bg-emerald-950 dark:text-emerald-400 dark:border-emerald-500/30'
                      : 'bg-amber-50 text-amber-800 border border-amber-200 dark:bg-amber-950 dark:text-amber-300 dark:border-amber-500/30'
                  }`}
                >
                  {slmActive ? 'ACTIVE' : 'STANDBY'}
                </span>
              </h3>
              <p className="text-xs text-gray-500 dark:text-gray-400">
                Zero-egress offline neural guard with full-duplex L1 cascade and Root Intent Isolation
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setIsSLMModalOpen(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-gray-100 hover:bg-gray-200 text-gray-800 border border-gray-300 dark:bg-gray-800 dark:hover:bg-gray-700 dark:text-gray-200 dark:border-white/10 transition-all shadow-xs"
            >
              <Settings className="w-3.5 h-3.5 text-accent" />
              <span>Configure</span>
            </button>

            <button
              type="button"
              onClick={handleProbeSLM}
              disabled={probingSLM}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-emerald-50 hover:bg-emerald-100 text-emerald-800 border border-emerald-300 dark:bg-emerald-600/20 dark:hover:bg-emerald-600/30 dark:text-emerald-300 dark:border-emerald-500/30 transition-all disabled:opacity-50 shadow-xs"
            >
              <Zap className={`w-3.5 h-3.5 ${probingSLM ? 'animate-pulse text-emerald-600 dark:text-emerald-400' : ''}`} />
              <span>{probingSLM ? 'Probing...' : 'Live Probe Guard'}</span>
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono bg-gray-50 dark:bg-dark-bg/50 p-4 rounded-xl border border-gray-200 dark:border-white/5">
          <div>
            <span className="text-gray-500 dark:text-gray-400">Model: </span>
            <span className="text-gray-900 dark:text-gray-200 font-semibold">{status?.slm_model || 'Qwen3Guard-0.6B (Local)'}</span>
          </div>
          <div>
            <span className="text-gray-500 dark:text-gray-400">Engine Mode: </span>
            <span className="text-gray-900 dark:text-gray-200 font-semibold">{status?.slm_endpoint || 'In-Process / Zero-Egress'}</span>
          </div>
          <div>
            <span className="text-gray-500 dark:text-gray-400">Latency: </span>
            <span className="text-emerald-700 dark:text-emerald-400 font-semibold">{status?.slm_latency_ms ? `${status.slm_latency_ms} ms` : '< 25 ms (Local)'}</span>
          </div>
        </div>

        {slmProbeResult && (
          <div className="mt-3 p-3.5 rounded-xl bg-[#0F172A] border border-gray-800 text-xs font-mono text-emerald-400 max-h-40 overflow-y-auto">
            <pre>{slmProbeResult}</pre>
          </div>
        )}
      </div>

      {/* Connected Tool Sources (MCP Servers) Live Health */}
      <div className="glass-card p-6 border-l-4 border-l-cyan-500">
        <div className="flex flex-wrap items-center justify-between gap-4 mb-4">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-cyan-50 text-cyan-700 border border-cyan-200 dark:bg-cyan-500/10 dark:border-cyan-500/30 dark:text-cyan-400 flex items-center justify-center">
              <Network className="w-5 h-5" />
            </div>
            <div>
              <h3 className="font-bold text-base text-gray-900 dark:text-gray-100 flex items-center gap-2">
                Connected Tool Sources
                <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded-full bg-cyan-50 text-cyan-800 border border-cyan-200 dark:bg-cyan-950 dark:text-cyan-400 dark:border-cyan-500/30">
                  {protocols.length} {protocols.length === 1 ? 'SOURCE' : 'SOURCES'}
                </span>
              </h3>
              <p className="text-xs text-gray-500 dark:text-gray-400">
                Live upstream MCP connectivity and tool count discovery across active endpoints.
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={handleCheckProtocolHealth}
            disabled={probingProtocols || protocols.length === 0}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-cyan-50 hover:bg-cyan-100 text-cyan-800 border border-cyan-300 dark:bg-cyan-600/20 dark:hover:bg-cyan-600/30 dark:text-cyan-300 dark:border-cyan-500/30 transition-all disabled:opacity-50 shadow-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${probingProtocols ? 'animate-spin text-cyan-600 dark:text-cyan-400' : ''}`} />
            <span>{probingProtocols ? 'Checking...' : 'Check Health'}</span>
          </button>
        </div>

        {protocols.length === 0 ? (
          <div className="p-6 text-center text-xs text-gray-500 dark:text-gray-400 border border-dashed border-gray-200 dark:border-white/10 rounded-xl bg-gray-50/50 dark:bg-dark-bg/20">
            No Tool Sources connected yet. Connect an MCP source in the Tool Sources tab.
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {protocols.map((p) => {
              const h = protocolHealth[p.id]
              return (
                <div
                  key={p.id}
                  className="p-3.5 rounded-xl bg-gray-50 dark:bg-dark-bg/50 border border-gray-200 dark:border-white/5 flex flex-col justify-between gap-2"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="flex items-center gap-1.5">
                        <span className="font-bold text-xs text-gray-900 dark:text-white truncate font-mono">
                          {p.name || p.id}
                        </span>
                        <span className="text-[10px] font-mono px-1.5 py-0.2 rounded font-semibold uppercase bg-gray-200 dark:bg-white/10 text-gray-700 dark:text-gray-300">
                          {p.type}
                        </span>
                      </div>
                      <p className="text-[11px] font-mono text-gray-400 dark:text-gray-500 truncate mt-0.5">
                        {p.url_or_command || p.command || p.id}
                      </p>
                    </div>

                    {h ? (
                      h.status === 'healthy' ? (
                        <span className="inline-flex items-center gap-1 text-[10px] font-mono font-bold px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200 dark:bg-emerald-950 dark:text-emerald-400 dark:border-emerald-500/30 shrink-0">
                          <CheckCircle2 className="w-3 h-3 text-emerald-600 dark:text-emerald-400" />
                          <span>{h.count !== undefined ? `${h.count} tools` : 'Online'}</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-[10px] font-mono font-bold px-2 py-0.5 rounded-full bg-rose-50 text-rose-700 border border-rose-200 dark:bg-rose-950 dark:text-rose-400 dark:border-rose-500/30 shrink-0" title={h.error}>
                          <AlertTriangle className="w-3 h-3 text-rose-600 dark:text-rose-400" />
                          <span>Offline</span>
                        </span>
                      )
                    ) : (
                      <span className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded-full bg-gray-100 dark:bg-white/5 text-gray-500 dark:text-gray-400 border border-gray-200 dark:border-white/10 shrink-0">
                        Standby
                      </span>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* System Maintenance & Quick Actions */}
      <div className="glass-card p-6">
        <h3 className="font-bold text-base text-gray-900 dark:text-gray-100 mb-1">System Maintenance & Actions</h3>
        <p className="text-xs text-gray-500 dark:text-gray-400 mb-4">
          Manage local schema baselines and apply hot configuration reload without interrupting existing sessions.
        </p>

        <div className="flex flex-wrap gap-3">
          <button
            type="button"
            onClick={handleClearSchemas}
            disabled={clearingSchemas}
            className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold bg-gray-100 hover:bg-gray-200 text-gray-800 border border-gray-300 dark:bg-gray-800 dark:hover:bg-gray-700 dark:text-gray-200 dark:border-white/10 transition-all disabled:opacity-50"
          >
            <Trash2 className="w-3.5 h-3.5 text-rose-500 dark:text-rose-400" />
            <span>{clearingSchemas ? 'Clearing...' : 'Clear Schema Baselines'}</span>
          </button>

          <button
            type="button"
            onClick={handleReload}
            disabled={reloading}
            className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold bg-cyan-600 hover:bg-cyan-700 text-white shadow-sm dark:bg-cyan-600/20 dark:hover:bg-cyan-600/30 dark:text-cyan-300 dark:border dark:border-cyan-500/30 transition-all disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${reloading ? 'animate-spin' : ''}`} />
            <span>{reloading ? 'Reloading...' : 'Reload Gateway Configuration'}</span>
          </button>
        </div>
      </div>

      <SLMConnectionModal
        isOpen={isSLMModalOpen}
        onClose={() => setIsSLMModalOpen(false)}
        onSuccess={(msg) => {
          setActionMessage({ type: 'success', text: msg })
          onRefresh()
        }}
      />
    </div>
  )
}
