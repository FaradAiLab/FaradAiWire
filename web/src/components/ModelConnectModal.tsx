import React, { useState, useMemo, useEffect } from 'react'
import {
  X,
  Zap,
  Server,
  Terminal,
  Copy,
  Check,
  AlertTriangle,
  RefreshCw,
  Sliders,
  CheckCircle2,
} from 'lucide-react'
import { GuardModel } from '../types'
import { calculateKVCacheMB } from './HostTelemetryBar'

interface ModelConnectModalProps {
  model: GuardModel
  isBusy: boolean
  onClose: () => void
  onConnect: (
    modelId: string,
    params: {
      runtime_type: 'docker' | 'ollama'
      endpoint_url: string
      context_window: number
    }
  ) => Promise<void>
}

export const ModelConnectModal: React.FC<ModelConnectModalProps> = ({
  model,
  isBusy,
  onClose,
  onConnect,
}) => {
  const [runtimeType, setRuntimeType] = useState<'docker' | 'ollama'>(
    model.runtime_type || 'ollama'
  )

  const initialPort = useMemo(() => {
    if (model.endpoint_url) {
      try {
        const u = new URL(model.endpoint_url)
        if (u.port) return u.port
      } catch {}
    }
    return runtimeType === 'docker' ? '8088' : '11434'
  }, [model.endpoint_url, runtimeType])

  const [port, setPort] = useState<string>(initialPort)
  const [contextWindow, setContextWindow] = useState<number>(model.context_window || 2048)
  const [copied, setCopied] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Listen for Escape key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !isBusy) {
        onClose()
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [onClose, isBusy])

  const handleSwitchRuntime = (type: 'docker' | 'ollama') => {
    setRuntimeType(type)
    setPort(type === 'docker' ? '8088' : '11434')
  }

  const cleanPort = port.trim() || (runtimeType === 'docker' ? '8088' : '11434')
  const endpointURL = `http://127.0.0.1:${cleanPort}`

  const runCommand = useMemo(() => {
    if (runtimeType === 'docker') {
      const img = model.docker_image || `ghcr.io/faradailab/farad-ai-guard:${model.id}`
      return `docker run -d --name faradai-guard -p ${cleanPort}:8088 ${img}`
    }
    const ollamaSrc = model.ollama_source || `hf.co/faradailab/guard-${model.id}`
    return `ollama run ${ollamaSrc}`
  }, [runtimeType, cleanPort, model.docker_image, model.ollama_source, model.id])

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(runCommand)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {}
  }

  const kvCacheMB = useMemo(() => {
    return calculateKVCacheMB(model, contextWindow)
  }, [model, contextWindow])

  const totalProjectedRAM_GB = useMemo(() => {
    return ((model.ram_required_mb + kvCacheMB) / 1024).toFixed(2)
  }, [model.ram_required_mb, kvCacheMB])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    try {
      await onConnect(model.id, {
        runtime_type: runtimeType,
        endpoint_url: endpointURL,
        context_window: contextWindow,
      })
      onClose()
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      setError(msg)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-in fade-in duration-200">
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="connect-modal-title"
        className="bg-surface border border-subtle rounded-2xl max-w-lg w-full p-6 shadow-2xl relative overflow-hidden flex flex-col gap-5 text-primary"
      >
        {/* Modal Header */}
        <div className="flex items-start justify-between border-b border-subtle pb-4">
          <div>
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-lg bg-accent/10 border border-accent/20 text-accent">
                <Zap className="w-4 h-4" />
              </div>
              <h2 id="connect-modal-title" className="text-base font-bold text-primary">
                Deploy & Connect: {model.name}
              </h2>
            </div>
            <p className="text-xs text-muted mt-1">
              Verify local inference runtime and set connection parameters before activating semantic protection.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            disabled={isBusy}
            aria-label="Close dialog"
            className="p-1.5 rounded-lg text-muted hover:text-primary hover:bg-subtle transition-colors disabled:opacity-40"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Runtime Selection & Port Input */}
          <div className="space-y-2">
            <label className="text-xs font-semibold text-primary uppercase tracking-wider font-mono">
              Inference Runtime & Port
            </label>
            <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 bg-canvas/60 border border-subtle rounded-xl p-3">
              {/* Segmented Runtime Switcher */}
              <div className="flex items-center gap-1 p-0.5 rounded-lg bg-surface border border-subtle">
                <button
                  type="button"
                  onClick={() => handleSwitchRuntime('ollama')}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
                    runtimeType === 'ollama'
                      ? 'bg-accent/15 text-accent font-semibold shadow-xs'
                      : 'text-muted hover:text-primary'
                  }`}
                >
                  <Terminal className="w-3.5 h-3.5" />
                  <span>Ollama Local</span>
                </button>
                <button
                  type="button"
                  onClick={() => handleSwitchRuntime('docker')}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
                    runtimeType === 'docker'
                      ? 'bg-accent/15 text-accent font-semibold shadow-xs'
                      : 'text-muted hover:text-primary'
                  }`}
                >
                  <Server className="w-3.5 h-3.5" />
                  <span>Docker Sidecar</span>
                </button>
              </div>

              {/* Port Input */}
              <div className="flex items-center gap-2 text-xs font-mono">
                <span className="text-muted">Port:</span>
                <input
                  type="number"
                  min="1"
                  max="65535"
                  value={port}
                  onChange={(e) => setPort(e.target.value)}
                  className="w-24 px-2.5 py-1.5 rounded-lg bg-surface border border-subtle text-xs text-primary font-mono text-center focus:outline-none focus:border-accent"
                  placeholder={runtimeType === 'docker' ? '8088' : '11434'}
                />
              </div>
            </div>
          </div>

          {/* CLI Deployment Command */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <label className="text-xs font-semibold text-primary uppercase tracking-wider font-mono">
                Launch Command (Host Terminal)
              </label>
              <span className="text-[10px] text-muted font-mono">Pre-requisite</span>
            </div>
            <div className="relative group/code">
              <pre className="text-[11px] font-mono bg-canvas border border-subtle rounded-xl p-3 pr-12 text-primary overflow-x-auto whitespace-pre-wrap break-all select-all">
                <code>{runCommand}</code>
              </pre>
              <button
                type="button"
                onClick={handleCopy}
                className="absolute right-2 top-2 p-1.5 rounded-lg bg-surface/90 hover:bg-surface border border-subtle text-muted hover:text-primary transition-all shadow-xs"
                title="Copy Command to Clipboard"
                aria-label="Copy Command to Clipboard"
              >
                {copied ? (
                  <Check className="w-4 h-4 text-emerald-500" />
                ) : (
                  <Copy className="w-4 h-4" />
                )}
              </button>
            </div>
          </div>

          {/* Context Window & GQA KV Profiler */}
          <div className="space-y-2 bg-canvas/60 border border-subtle rounded-xl p-3">
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs font-semibold text-primary flex items-center gap-1.5">
                <Sliders className="w-3.5 h-3.5 text-accent" />
                <span>Context Window (PEP)</span>
              </span>
              <select
                id={`modal-ctx-${model.id}`}
                aria-label="Context Window tokens"
                value={contextWindow}
                onChange={(e) => setContextWindow(Number(e.target.value))}
                className="px-2.5 py-1.5 rounded-lg bg-surface border border-subtle text-xs text-primary font-mono focus:outline-none focus:border-accent"
              >
                <option value={1024}>1,024 Tokens</option>
                <option value={2048}>2,048 (PEP Optimal)</option>
                <option value={4096}>4,096 Tokens</option>
                <option value={8192}>8,192 Tokens</option>
                <option value={16384}>16,384 Tokens</option>
                <option value={32768}>32,768 Tokens</option>
              </select>
            </div>

            {/* GQA Footprint Metrics */}
            <div className="grid grid-cols-2 gap-2 text-[11px] font-mono pt-1">
              <div className="bg-surface border border-subtle rounded-lg p-2">
                <span className="text-muted text-[10px] uppercase block">GQA KV Cache</span>
                <span className="font-bold text-accent">~{kvCacheMB} MB</span>
                <span className="text-muted text-[10px] ml-1">
                  ({model.num_kv_heads || 4} heads)
                </span>
              </div>
              <div className="bg-surface border border-subtle rounded-lg p-2">
                <span className="text-muted text-[10px] uppercase block">Projected Total RAM</span>
                <span className="font-bold text-primary">{totalProjectedRAM_GB} GB</span>
                <span className="text-muted text-[10px] ml-1">(Weights + KV)</span>
              </div>
            </div>

            {contextWindow > 2048 && (
              <div className="text-[11px] text-amber-700 dark:text-amber-400 bg-amber-500/10 border border-amber-500/20 rounded-lg p-2 flex items-start gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                <span>Context exceeding 2,048 tokens increases TTFT and KV cache memory footprint.</span>
              </div>
            )}
          </div>

          {/* Pre-flight Guidance Notice */}
          <div className="p-2.5 rounded-xl bg-canvas border border-subtle text-xs text-muted flex items-start gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0 mt-0.5" />
            <p className="leading-relaxed">
              Pre-flight requirement: Ensure the model is running on <code className="text-primary font-mono">{endpointURL}</code> before activating. FaradAiWire probes the endpoint for model identity and latency before routing in-flight traffic.
            </p>
          </div>

          {error && (
            <div className="p-3 bg-rose-50 dark:bg-rose-500/15 border border-rose-200 dark:border-rose-500/30 rounded-xl text-rose-700 dark:text-rose-300 text-xs flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {/* Modal Actions */}
          <div className="flex items-center justify-end gap-3 pt-3 border-t border-subtle">
            <button
              type="button"
              onClick={onClose}
              disabled={isBusy}
              className="px-4 py-2 rounded-xl text-xs font-medium text-muted hover:text-primary hover:bg-subtle transition-colors disabled:opacity-40"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isBusy}
              className="px-4 py-2 rounded-xl text-xs font-semibold text-white bg-accent hover:bg-accent/90 transition-all shadow-sm flex items-center gap-1.5 disabled:opacity-50"
            >
              {isBusy ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Probing & Activating...</span>
                </>
              ) : (
                <>
                  <Zap className="w-3.5 h-3.5" />
                  <span>Test & Activate</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

