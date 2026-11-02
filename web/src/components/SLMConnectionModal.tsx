import React, { useState } from 'react'
import {
  X,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  Zap,
  Cpu,
  Server,
  Sliders,
  Globe,
} from 'lucide-react'
import { api } from '../api'

interface SLMConnectionModalProps {
  isOpen: boolean
  onClose: () => void
  onSuccess: (msg: string) => void
}

type DiscoveryMode = 'auto' | 'ollama' | 'docker' | 'custom'

interface ProbeResultState {
  detected: boolean
  provider?: string
  url?: string
  latency_ms?: number
  model?: string
  error?: string
}

export const SLMConnectionModal: React.FC<SLMConnectionModalProps> = ({
  isOpen,
  onClose,
  onSuccess,
}) => {
  const [mode, setMode] = useState<DiscoveryMode>('auto')
  const [ollamaURL, setOllamaURL] = useState('http://127.0.0.1:11434')
  const [dockerURL, setDockerURL] = useState('http://127.0.0.1:8088')
  const [customURL, setCustomURL] = useState('')
  const [isProbing, setIsProbing] = useState(false)
  const [probeResult, setProbeResult] = useState<ProbeResultState | null>(null)
  const [isSaving, setIsSaving] = useState(false)
  const [errorMsg, setErrorMsg] = useState<string | null>(null)

  if (!isOpen) return null

  const handleTestConnection = async () => {
    try {
      setIsProbing(true)
      setErrorMsg(null)
      setProbeResult(null)
      const res = await api.probeSLM()
      const data = res as Record<string, unknown>
      setProbeResult({
        detected: Boolean(data.detected),
        provider: String(data.detected_provider || 'none'),
        url: String(data.detected_url || ''),
        latency_ms: Number(data.latency_ms || 0),
        model: String(data.model_name || 'L1 Static Regex Fallback'),
      })
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      setErrorMsg(`Probe failed: ${msg}`)
      setProbeResult({
        detected: false,
        error: msg,
      })
    } finally {
      setIsProbing(false)
    }
  }

  const handleSave = async () => {
    try {
      setIsSaving(true)
      setErrorMsg(null)

      let effectiveClassifierURL = ''
      if (mode === 'custom') {
        effectiveClassifierURL = customURL.trim()
        if (!effectiveClassifierURL) {
          setErrorMsg('Custom URL is required in custom mode.')
          setIsSaving(false)
          return
        }
      } else if (mode === 'ollama') {
        effectiveClassifierURL = ollamaURL.trim()
      } else if (mode === 'docker') {
        effectiveClassifierURL = dockerURL.trim()
      }

      await api.configureSLM({
        mode,
        ollama_url: ollamaURL.trim(),
        docker_url: dockerURL.trim(),
        custom_url: customURL.trim(),
        classifier_url: effectiveClassifierURL,
      })

      onSuccess('Security guard connection configuration updated successfully.')
      onClose()
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      setErrorMsg(`Failed to save configuration: ${msg}`)
    } finally {
      setIsSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-in fade-in duration-200">
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="slm-modal-title"
        className="bg-surface border border-subtle rounded-2xl max-w-xl w-full p-6 shadow-2xl relative overflow-hidden flex flex-col gap-5 text-primary"
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b border-subtle pb-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-accent/10 border border-accent/20 flex items-center justify-center text-accent">
              <Sliders className="w-5 h-5" />
            </div>
            <div>
              <h2 id="slm-modal-title" className="text-base font-bold text-primary">
                Semantic Security Guard Connection
              </h2>
              <p className="text-xs text-muted">
                Configure decoupled Ollama, Docker container, or remote OpenAI-compatible provider
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg text-muted hover:text-primary hover:bg-subtle transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Mode Selector Tabs */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
          <button
            type="button"
            onClick={() => setMode('auto')}
            className={`p-3 rounded-xl border text-left transition-all ${
              mode === 'auto'
                ? 'border-accent bg-accent/10 text-primary font-bold shadow-xs ring-1 ring-accent/30'
                : 'border-subtle bg-surface hover:border-subtle/80 text-muted'
            }`}
          >
            <div className="flex items-center gap-1.5 text-xs font-semibold mb-1">
              <Zap className="w-3.5 h-3.5 text-amber-500" />
              <span>Auto-Detect</span>
            </div>
            <p className="text-[10px] text-muted leading-tight">Ollama / Docker dual probe</p>
          </button>

          <button
            type="button"
            onClick={() => setMode('ollama')}
            className={`p-3 rounded-xl border text-left transition-all ${
              mode === 'ollama'
                ? 'border-accent bg-accent/10 text-primary font-bold shadow-xs ring-1 ring-accent/30'
                : 'border-subtle bg-surface hover:border-subtle/80 text-muted'
            }`}
          >
            <div className="flex items-center gap-1.5 text-xs font-semibold mb-1">
              <Cpu className="w-3.5 h-3.5 text-indigo-500" />
              <span>🦙 Ollama</span>
            </div>
            <p className="text-[10px] text-muted leading-tight">Local Ollama daemon</p>
          </button>

          <button
            type="button"
            onClick={() => setMode('docker')}
            className={`p-3 rounded-xl border text-left transition-all ${
              mode === 'docker'
                ? 'border-accent bg-accent/10 text-primary font-bold shadow-xs ring-1 ring-accent/30'
                : 'border-subtle bg-surface hover:border-subtle/80 text-muted'
            }`}
          >
            <div className="flex items-center gap-1.5 text-xs font-semibold mb-1">
              <Server className="w-3.5 h-3.5 text-sky-500" />
              <span>🐳 Docker</span>
            </div>
            <p className="text-[10px] text-muted leading-tight">FaradAiGuard llama-server</p>
          </button>

          <button
            type="button"
            onClick={() => setMode('custom')}
            className={`p-3 rounded-xl border text-left transition-all ${
              mode === 'custom'
                ? 'border-accent bg-accent/10 text-primary font-bold shadow-xs ring-1 ring-accent/30'
                : 'border-subtle bg-surface hover:border-subtle/80 text-muted'
            }`}
          >
            <div className="flex items-center gap-1.5 text-xs font-semibold mb-1">
              <Globe className="w-3.5 h-3.5 text-emerald-500" />
              <span>Custom</span>
            </div>
            <p className="text-[10px] text-muted leading-tight">Remote GPU / OpenAI /v1</p>
          </button>
        </div>

        {/* Form Inputs based on Mode */}
        <div className="space-y-3 bg-canvas p-4 rounded-xl border border-subtle">
          {(mode === 'auto' || mode === 'ollama') && (
            <div>
              <label className="block text-xs font-semibold text-muted mb-1">
                Ollama Endpoint URL
              </label>
              <input
                type="text"
                value={ollamaURL}
                onChange={(e) => setOllamaURL(e.target.value)}
                placeholder="http://127.0.0.1:11434"
                className="w-full px-3 py-1.5 rounded-xl bg-surface border border-subtle text-xs text-primary font-mono focus:outline-none focus:border-accent"
              />
            </div>
          )}

          {(mode === 'auto' || mode === 'docker') && (
            <div>
              <label className="block text-xs font-semibold text-muted mb-1">
                Docker (llama-server) Container URL
              </label>
              <input
                type="text"
                value={dockerURL}
                onChange={(e) => setDockerURL(e.target.value)}
                placeholder="http://127.0.0.1:8088"
                className="w-full px-3 py-1.5 rounded-xl bg-surface border border-subtle text-xs text-primary font-mono focus:outline-none focus:border-accent"
              />
            </div>
          )}

          {mode === 'custom' && (
            <div>
              <label className="block text-xs font-semibold text-muted mb-1">
                Custom REST Endpoint (OpenAI /v1/chat/completions or /api/chat)
              </label>
              <input
                type="text"
                value={customURL}
                onChange={(e) => setCustomURL(e.target.value)}
                placeholder="http://remote-gpu:8000/v1"
                className="w-full px-3 py-1.5 rounded-xl bg-surface border border-subtle text-xs text-primary font-mono focus:outline-none focus:border-accent"
              />
            </div>
          )}
        </div>

        {/* Live Probe Results Box */}
        {probeResult && (
          <div
            className={`p-3.5 rounded-xl border text-xs font-mono flex items-start gap-2.5 ${
              probeResult.detected
                ? 'bg-emerald-50 dark:bg-emerald-950/30 border-emerald-300 dark:border-emerald-500/30 text-emerald-800 dark:text-emerald-300'
                : 'bg-amber-50 dark:bg-amber-950/30 border-amber-300 dark:border-amber-500/30 text-amber-800 dark:text-amber-300'
            }`}
          >
            {probeResult.detected ? (
              <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-600 dark:text-emerald-400 mt-0.5" />
            ) : (
              <AlertTriangle className="w-4 h-4 shrink-0 text-amber-600 dark:text-amber-400 mt-0.5" />
            )}
            <div className="flex-1">
              <div className="font-bold flex items-center justify-between">
                <span>
                  {probeResult.detected
                    ? `Connected: ${probeResult.provider?.toUpperCase()}`
                    : 'No Live Security Guard Provider Detected'}
                </span>
                {probeResult.latency_ms !== undefined && probeResult.latency_ms > 0 && (
                  <span className="text-[10px] font-normal px-2 py-0.5 rounded bg-black/10 dark:bg-white/10">
                    {probeResult.latency_ms} ms
                  </span>
                )}
              </div>
              <p className="text-[11px] mt-1 opacity-90">
                Model: <span className="font-semibold">{probeResult.model}</span>
                {probeResult.url && (
                  <>
                    {' '}• URL: <span className="underline">{probeResult.url}</span>
                  </>
                )}
              </p>
            </div>
          </div>
        )}

        {errorMsg && (
          <div className="p-2.5 bg-rose-50 dark:bg-rose-500/10 border border-rose-200 dark:border-rose-500/30 rounded-xl text-rose-700 dark:text-rose-300 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{errorMsg}</span>
          </div>
        )}

        {/* Footer Actions */}
        <div className="flex items-center justify-between pt-3 border-t border-subtle">
          <button
            type="button"
            disabled={isProbing}
            onClick={handleTestConnection}
            className="px-3.5 py-1.5 rounded-xl text-xs font-semibold text-accent bg-accent/10 hover:bg-accent/20 border border-accent/30 transition-all flex items-center gap-1.5 disabled:opacity-50"
          >
            <Zap className={`w-3.5 h-3.5 ${isProbing ? 'animate-pulse text-accent' : ''}`} />
            <span>{isProbing ? 'Probing...' : 'Test Connection'}</span>
          </button>

          <div className="flex items-center gap-2">
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
              className="px-5 py-2 rounded-xl text-xs font-semibold text-white bg-sky-600 hover:bg-sky-500 transition-all flex items-center gap-1.5 disabled:opacity-50 shadow-sm"
            >
              {isSaving ? (
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <CheckCircle2 className="w-3.5 h-3.5" />
              )}
              <span>Save & Apply</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
