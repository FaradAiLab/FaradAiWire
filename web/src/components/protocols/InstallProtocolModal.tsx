import React, { useState, useEffect } from 'react'
import { Network, Zap, CheckCircle2, XCircle, Trash2, Plus, AlertTriangle } from 'lucide-react'
import { PresetMetadata, ToolMetadata, ProtocolItem, ProtocolConfig } from '../../types'
import { api, ProbeError } from '../../api'
import { Modal } from '../ui/Modal'
import { Button } from '../ui/Button'
import { Input } from '../ui/Input'

export interface InstallProtocolModalProps {
  isOpen: boolean
  onClose: () => void
  presetToInstall?: PresetMetadata | null
  protocolToEdit?: ProtocolItem | null
  onSaved: () => void
}

export const InstallProtocolModal: React.FC<InstallProtocolModalProps> = ({
  isOpen,
  onClose,
  presetToInstall,
  protocolToEdit,
  onSaved,
}) => {
  const [protoId, setProtoId] = useState('')
  const [protoName, setProtoName] = useState('')
  const [protoDesc, setProtoDesc] = useState('')
  const [protoType, setProtoType] = useState<'sse' | 'stdio' | 'http'>('sse')
  const [protoUrl, setProtoUrl] = useState('')
  const [protoAuthToken, setProtoAuthToken] = useState('')
  const [protoHeaders, setProtoHeaders] = useState<{ key: string; value: string }[]>([])
  const [protoCommand, setProtoCommand] = useState('')
  const [protoArgs, setProtoArgs] = useState('')
  const [protoEnv, setProtoEnv] = useState<{ key: string; value: string }[]>([])
  const [saving, setSaving] = useState(false)

  // In-modal probe state
  const [probing, setProbing] = useState(false)
  const [probeResult, setProbeResult] = useState<{
    success: boolean
    message: string
    tools?: ToolMetadata[]
    statusCode?: number
    errorCode?: string
    remediation?: string
    transportMode?: string
  } | null>(null)

  useEffect(() => {
    if (protocolToEdit) {
      setProtoId(protocolToEdit.id)
      setProtoName(protocolToEdit.name)
      setProtoDesc(protocolToEdit.description || '')
      setProtoType(protocolToEdit.type === 'stdio' ? 'stdio' : protocolToEdit.type === 'http' ? 'http' : 'sse')
      setProtoUrl(protocolToEdit.url_or_command || '')
      setProtoAuthToken(protocolToEdit.auth_token || '')
      setProtoHeaders(
        protocolToEdit.headers
          ? Object.entries(protocolToEdit.headers).map(([key, value]) => ({ key, value: String(value) }))
          : []
      )
      setProtoCommand(protocolToEdit.command || (protocolToEdit.type === 'stdio' ? protocolToEdit.url_or_command || '' : ''))
      setProtoArgs(protocolToEdit.args ? protocolToEdit.args.join(' ') : '')
      setProtoEnv(
        protocolToEdit.env
          ? protocolToEdit.env.map((e: string) => {
              const [k, ...v] = e.split('=')
              return { key: k, value: v.join('=') }
            })
          : []
      )
    } else if (presetToInstall) {
      setProtoId(presetToInstall.id)
      setProtoName(presetToInstall.name)
      setProtoDesc(presetToInstall.description || '')
      setProtoType(presetToInstall.type === 'stdio' ? 'stdio' : presetToInstall.type === 'http' ? 'http' : 'sse')
      setProtoUrl(presetToInstall.url || '')
      setProtoAuthToken('')
      setProtoHeaders([])
      setProtoCommand(presetToInstall.command || '')
      setProtoArgs(presetToInstall.args ? presetToInstall.args.join(' ') : '')
      setProtoEnv(
        (presetToInstall.env_requirements || []).map((req) => ({
          key: req,
          value: '',
        }))
      )
    } else {
      setProtoId('')
      setProtoName('')
      setProtoDesc('')
      setProtoType('sse')
      setProtoUrl('')
      setProtoAuthToken('')
      setProtoHeaders([])
      setProtoCommand('')
      setProtoArgs('')
      setProtoEnv([])
    }
    setProbeResult(null)
  }, [presetToInstall, protocolToEdit, isOpen])

  const handleModalProbe = async () => {
    try {
      setProbing(true)
      setProbeResult(null)

      const envList = protoEnv
        .filter((e) => e.key.trim().length > 0)
        .map((e) => `${e.key.trim()}=${e.value.trim()}`)

      const argsList = protoArgs
        .split(' ')
        .map((s) => s.trim())
        .filter((s) => s.length > 0)

      const headersObj: Record<string, string> = {}
      protoHeaders.forEach((h) => {
        if (h.key.trim().length > 0) {
          headersObj[h.key.trim()] = h.value.trim()
        }
      })

      const res = await api.probeProtocol({
        id: protoId.trim() || undefined,
        type: protoType,
        url: (protoType === 'sse' || protoType === 'http') ? protoUrl.trim() : undefined,
        auth_token: (protoType === 'sse' || protoType === 'http') && protoAuthToken.trim() ? protoAuthToken.trim() : undefined,
        headers: (protoType === 'sse' || protoType === 'http') && Object.keys(headersObj).length > 0 ? headersObj : undefined,
        command: protoType === 'stdio' ? protoCommand.trim() : undefined,
        args: protoType === 'stdio' && argsList.length > 0 ? argsList : undefined,
        env: protoType === 'stdio' && envList.length > 0 ? envList : undefined,
      })

      const transportLabel = (res as Record<string, unknown>).transport_mode === 'streamable_http'
        ? 'Streamable HTTP'
        : (res as Record<string, unknown>).transport_mode === 'sse'
        ? 'SSE'
        : ''
      const badge = transportLabel ? ` via ${transportLabel}` : ''

      setProbeResult({
        success: true,
        message: `Probe successful! Discovered ${res.count} tool(s)${badge}.`,
        tools: res.tools || [],
        transportMode: (res as Record<string, unknown>).transport_mode as string | undefined,
      })
    } catch (err: unknown) {
      if (err instanceof ProbeError && err.errorCode === 'UPSTREAM_HTTP_ERROR') {
        setProbeResult({
          success: false,
          message: `HTTP ${err.statusCode} ${err.statusCode ? httpStatusLabel(err.statusCode) : 'Error'}`,
          statusCode: err.statusCode,
          errorCode: err.errorCode,
          remediation: err.remediation || 'Check the connection settings and try again.',
        })
      } else {
        const msg = err instanceof Error ? err.message : String(err)
        setProbeResult({
          success: false,
          message: `Probe failed: ${msg}`,
        })
      }
    } finally {
      setProbing(false)
    }
  }

  // Maps common HTTP status codes to short human-readable labels.
  const httpStatusLabel = (code: number): string => {
    const labels: Record<number, string> = {
      401: 'Unauthorized',
      403: 'Forbidden',
      404: 'Not Found',
      405: 'Method Not Allowed',
      429: 'Too Many Requests',
      500: 'Internal Server Error',
      502: 'Bad Gateway',
      503: 'Service Unavailable',
      504: 'Gateway Timeout',
    }
    return labels[code] || `Error`
  }

  const handleSaveProtocol = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!protoId.trim() || !protoName.trim()) return

    const envList = protoEnv
      .filter((e) => e.key.trim().length > 0)
      .map((e) => `${e.key.trim()}=${e.value.trim()}`)

    const argsList = protoArgs
      .split(' ')
      .map((s) => s.trim())
      .filter((s) => s.length > 0)

    const headersObj: Record<string, string> = {}
    protoHeaders.forEach((h) => {
      if (h.key.trim().length > 0) {
        headersObj[h.key.trim()] = h.value.trim()
      }
    })

    try {
      setSaving(true)
      const payload: Partial<ProtocolConfig> = {
        id: protoId.trim().toLowerCase(),
        name: protoName.trim(),
        description: protoDesc.trim(),
        type: protoType,
        url_or_command: (protoType === 'sse' || protoType === 'http') ? protoUrl.trim() : protoCommand.trim(),
        auth_token: (protoType === 'sse' || protoType === 'http') && protoAuthToken.trim() ? protoAuthToken.trim() : undefined,
        headers: (protoType === 'sse' || protoType === 'http') && Object.keys(headersObj).length > 0 ? headersObj : undefined,
        command: protoType === 'stdio' ? protoCommand.trim() : undefined,
        args: protoType === 'stdio' ? argsList : undefined,
        env: protoType === 'stdio' ? envList : undefined,
      }

      if (protocolToEdit) {
        await api.updateProtocol(protocolToEdit.id, payload)
      } else {
        await api.createProtocol(payload)
      }

      onSaved()
      onClose()
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      alert(`Failed to save protocol: ${msg}`)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={
        protocolToEdit
          ? `Edit Protocol: ${protoName || protoId}`
          : presetToInstall
          ? `Configure ${protoName}`
          : 'Register Custom MCP Server'
      }
      subtitle="Define transport parameters, secrets, and execute live connection probe before attaching."
      icon={<Network className="w-5 h-5 text-cyan-400" />}
      maxWidth="xl"
    >
      <form onSubmit={handleSaveProtocol} className="space-y-4 text-xs">
        <div className="grid grid-cols-2 gap-3">
          <Input
            label="Protocol ID"
            required
            placeholder="e.g. github or my-server"
            value={protoId}
            onChange={(e) => setProtoId(e.target.value)}
            disabled={!!presetToInstall || !!protocolToEdit}
            isMono
          />
          <Input
            label="Display Name"
            required
            placeholder="e.g. GitHub Workspace"
            value={protoName}
            onChange={(e) => setProtoName(e.target.value)}
          />
        </div>

        <Input
          label="Description"
          placeholder="Purpose of this MCP backend"
          value={protoDesc}
          onChange={(e) => setProtoDesc(e.target.value)}
        />

        <div>
          <label className="block text-xs font-semibold text-primary mb-1">Transport Type</label>
          <div className="flex gap-4">
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="radio"
                name="protoType"
                checked={protoType === 'sse' || protoType === 'http'}
                onChange={() => setProtoType('sse')}
                className="text-accent-primary focus:ring-accent-primary"
              />
              <span className="text-primary text-xs">Remote SSE (HTTP/S)</span>
            </label>
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="radio"
                name="protoType"
                checked={protoType === 'stdio'}
                onChange={() => setProtoType('stdio')}
                className="text-accent-primary focus:ring-accent-primary"
              />
              <span className="text-primary text-xs">Local Stdio Subprocess</span>
            </label>
          </div>
        </div>

        {(protoType === 'sse' || protoType === 'http') ? (
          <div className="space-y-3">
            <Input
              label="Remote SSE URL"
              type="url"
              required
              placeholder="https://mcp.context7.com/mcp"
              value={protoUrl}
              onChange={(e) => setProtoUrl(e.target.value)}
              isMono
            />

            <Input
              label="Authentication Token (Bearer)"
              type="password"
              placeholder="e.g. ctx7_live_... or ${CONTEXT7_API_KEY}"
              value={protoAuthToken}
              onChange={(e) => setProtoAuthToken(e.target.value)}
              isMono
            />

            {/* Custom HTTP Headers */}
            <div className="space-y-2 pt-1">
              <div className="flex items-center justify-between">
                <div>
                  <label className="text-xs font-semibold text-primary">Custom HTTP Headers</label>
                  <p className="text-[10px] text-muted">Optional custom headers forwarded upstream (e.g. X-API-Key, Context7-API-Key, Organization-Id)</p>
                </div>
                <button
                  type="button"
                  onClick={() => setProtoHeaders([...protoHeaders, { key: '', value: '' }])}
                  className="text-[11px] font-mono text-accent-primary hover:underline flex items-center gap-1"
                >
                  <Plus className="w-3 h-3" />
                  <span>Add Header</span>
                </button>
              </div>

              {protoHeaders.length === 0 ? (
                <div className="text-[11px] text-muted font-mono italic p-2 rounded-lg bg-surface/50 border border-subtle">
                  No custom headers configured. Add headers if your upstream endpoint requires non-standard authentication.
                </div>
              ) : (
                protoHeaders.map((hdr, i) => (
                  <div key={i} className="flex gap-2">
                    <input
                      type="text"
                      placeholder="Header Name (e.g. X-API-Key)"
                      value={hdr.key}
                      onChange={(e) => {
                        const copy = [...protoHeaders]
                        copy[i].key = e.target.value
                        setProtoHeaders(copy)
                      }}
                      className="w-1/2 px-2.5 py-1.5 rounded-lg bg-surface border border-subtle text-primary font-mono text-xs focus:outline-none focus:ring-1 focus:ring-accent-primary"
                    />
                    <input
                      type="password"
                      placeholder="Header Value"
                      value={hdr.value}
                      onChange={(e) => {
                        const copy = [...protoHeaders]
                        copy[i].value = e.target.value
                        setProtoHeaders(copy)
                      }}
                      className="w-1/2 px-2.5 py-1.5 rounded-lg bg-surface border border-subtle text-primary font-mono text-xs focus:outline-none focus:ring-1 focus:ring-accent-primary"
                    />
                    <button
                      type="button"
                      onClick={() => setProtoHeaders(protoHeaders.filter((_, idx) => idx !== i))}
                      className="p-1.5 text-muted hover:text-rose-500 transition-colors"
                      aria-label="Remove header"
                      title="Remove header"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            <Input
              label="Command Binary"
              required
              placeholder="e.g. npx, uvx, docker"
              value={protoCommand}
              onChange={(e) => setProtoCommand(e.target.value)}
              isMono
            />
            <Input
              label="Arguments (space-separated)"
              placeholder="-y @modelcontextprotocol/server-github"
              value={protoArgs}
              onChange={(e) => setProtoArgs(e.target.value)}
              isMono
            />

            {/* Environment Variables */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-xs font-semibold text-primary">Environment Variables</label>
                <button
                  type="button"
                  onClick={() => setProtoEnv([...protoEnv, { key: '', value: '' }])}
                  className="text-[11px] font-mono text-accent-primary hover:underline"
                >
                  + Add Variable
                </button>
              </div>
              {protoEnv.map((env, i) => (
                <div key={i} className="flex gap-2">
                  <input
                    type="text"
                    placeholder="VARIABLE_NAME"
                    value={env.key}
                    onChange={(e) => {
                      const copy = [...protoEnv]
                      copy[i].key = e.target.value
                      setProtoEnv(copy)
                    }}
                    className="w-1/2 px-2.5 py-1.5 rounded-lg bg-surface border border-subtle text-primary font-mono text-xs focus:outline-none focus:ring-1 focus:ring-accent-primary"
                  />
                  <input
                    type="password"
                    placeholder="Value"
                    value={env.value}
                    onChange={(e) => {
                      const copy = [...protoEnv]
                      copy[i].value = e.target.value
                      setProtoEnv(copy)
                    }}
                    className="w-1/2 px-2.5 py-1.5 rounded-lg bg-surface border border-subtle text-primary font-mono text-xs focus:outline-none focus:ring-1 focus:ring-accent-primary"
                  />
                  <button
                    type="button"
                    onClick={() => setProtoEnv(protoEnv.filter((_, idx) => idx !== i))}
                    className="p-1.5 text-muted hover:text-rose-500 transition-colors"
                    aria-label="Remove environment variable"
                    title="Remove variable"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Probe Test Connection Button & Result */}
        <div className="pt-2">
          <Button
            type="button"
            variant="secondary"
            size="sm"
            onClick={handleModalProbe}
            isLoading={probing}
            icon={<Zap className="w-3.5 h-3.5 text-accent-primary" />}
          >
            {probing ? 'Probing target...' : 'Test Connection'}
          </Button>

          {probeResult && (
            <div
              className={`mt-2 p-3 rounded-xl border text-xs font-mono ${
                probeResult.success
                  ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-800 dark:text-emerald-300'
                  : probeResult.errorCode === 'UPSTREAM_HTTP_ERROR'
                  ? 'bg-amber-500/10 border-amber-500/30 text-amber-800 dark:text-amber-200'
                  : 'bg-rose-500/10 border-rose-500/30 text-rose-800 dark:text-rose-300'
              }`}
            >
              <div className="flex items-center gap-2 font-bold">
                {probeResult.success ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                ) : probeResult.errorCode === 'UPSTREAM_HTTP_ERROR' ? (
                  <AlertTriangle className="w-4 h-4 text-amber-500" />
                ) : (
                  <XCircle className="w-4 h-4 text-rose-500" />
                )}
                <span>
                  {probeResult.errorCode === 'UPSTREAM_HTTP_ERROR'
                    ? `❌ ${probeResult.message}`
                    : probeResult.message}
                </span>
              </div>

              {probeResult.remediation && (
                <div className="mt-1.5 text-[11px] text-muted leading-relaxed pl-6">
                  💡 {probeResult.remediation}
                </div>
              )}

              {probeResult.tools && probeResult.tools.length > 0 && (
                <div className="mt-2 pt-2 border-t border-subtle space-y-1">
                  <div className="text-[10px] text-muted">Discovered Tools:</div>
                  <div className="flex flex-wrap gap-1">
                    {probeResult.tools.map((t) => (
                      <span
                        key={t.name}
                        className="px-2 py-0.5 rounded bg-[#0F172A] border border-[#1E293B] text-cyan-400 text-[10px] font-mono shadow-inner"
                      >
                        {t.name}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Modal Buttons */}
        <div className="flex justify-end gap-2 pt-4 border-t border-subtle">
          <Button type="button" variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" isLoading={saving}>
            {saving
              ? protocolToEdit
                ? 'Saving...'
                : 'Registering...'
              : protocolToEdit
              ? 'Save Changes'
              : 'Save & Register Protocol'}
          </Button>
        </div>
      </form>
    </Modal>
  )
}
