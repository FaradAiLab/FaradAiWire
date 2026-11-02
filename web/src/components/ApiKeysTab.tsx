import React, { useState, useEffect, useCallback, useMemo } from 'react'
import {
  Key,
  Plus,
  Trash2,
  Copy,
  Check,
  ShieldCheck,
  Eye,
  EyeOff,
  Sparkles,
  Layers,
  ArrowRight,
  Info,
} from 'lucide-react'
import { ApiKeyItem, CreatedApiKey, GatewayStatus } from '../types'
import { api } from '../api'
import { Badge } from './ui/Badge'
import { ClientConfigModal } from './ClientConfigModal'

export const ApiKeysTab: React.FC = () => {
  const [keys, setKeys] = useState<ApiKeyItem[]>([])
  const [agentNames, setAgentNames] = useState<string[]>([])
  const [gatewayStatus, setGatewayStatus] = useState<GatewayStatus | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Visibility toggle for tokens in table
  const [visibleKeyIds, setVisibleKeyIds] = useState<Set<string>>(new Set())
  const [copiedKeyId, setCopiedKeyId] = useState<string | null>(null)

  // Create Key Modal state
  const [isModalOpen, setIsModalOpen] = useState(false)
  const [keyName, setKeyName] = useState('')
  const [selectedAgent, setSelectedAgent] = useState<string>('*')
  const [isCreating, setIsCreating] = useState(false)
  const [createdKey, setCreatedKey] = useState<CreatedApiKey | null>(null)
  const [copiedCreatedToken, setCopiedCreatedToken] = useState(false)

  // Client Config Modal state
  const [clientModal, setClientModal] = useState<{
    isOpen: boolean
    token: string
    keyName: string
    agentName?: string
  }>({
    isOpen: false,
    token: '',
    keyName: '',
    agentName: '*',
  })

  const fetchData = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)
      const [keysRes, agentsRes, statusRes] = await Promise.all([
        api.getApiKeys(),
        api.getAgents().catch(() => ({ agents: [] })),
        api.getStatus().catch(() => null),
      ])
      setKeys(keysRes.keys || [])
      setAgentNames((agentsRes.agents || []).map((a) => a.name))
      if (statusRes) {
        setGatewayStatus(statusRes)
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      setError(msg)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchData()
  }, [fetchData])

  const toggleTokenVisibility = useCallback((id: string) => {
    setVisibleKeyIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) {
        next.delete(id)
      } else {
        next.add(id)
      }
      return next
    })
  }, [])

  const handleCopyText = useCallback((text: string, id: string) => {
    navigator.clipboard.writeText(text)
    setCopiedKeyId(id)
    setTimeout(() => setCopiedKeyId(null), 2000)
  }, [])

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!keyName.trim()) return

    try {
      setIsCreating(true)
      setError(null)
      const res = await api.createApiKey(keyName.trim(), selectedAgent, 'Developer')
      setCreatedKey(res)
      setKeyName('')
      setSelectedAgent('*')
      fetchData()
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      setError(`Failed to create API key: ${msg}`)
    } finally {
      setIsCreating(false)
    }
  }

  const handleRevoke = async (id: string, name: string) => {
    if (
      !window.confirm(
        `Are you sure you want to revoke API key '${name}'? Any external AI clients using this token will be disconnected immediately.`
      )
    ) {
      return
    }

    try {
      await api.revokeApiKey(id)
      fetchData()
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      alert(`Failed to revoke key: ${msg}`)
    }
  }

  const openClientConfig = useCallback(
    (keyItem: ApiKeyItem) => {
      setClientModal({
        isOpen: true,
        token: keyItem.raw_key || keyItem.key_prefix || '',
        keyName: keyItem.name,
        agentName: keyItem.agent_name || '*',
      })
    },
    []
  )

  const ingressPort = gatewayStatus?.ingress_port || 8090
  const ingressHost = gatewayStatus?.ingress_host || '127.0.0.1'

  // The unmasked token of the newly created key (fallback gracefully)
  const resolvedCreatedToken = useMemo(() => {
    if (!createdKey) return ''
    return createdKey.raw_key || createdKey.api_key || createdKey.key || ''
  }, [createdKey])

  return (
    <div className="space-y-6">
      {/* Header bar */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-primary flex items-center gap-2">
            <Key className="w-5 h-5 text-accent-primary" />
            Ingress API Keys & Client Scopes
          </h2>
          <p className="text-xs text-muted mt-1">
            Manage Bearer tokens scoped to specific Gateway Agents with local zero-trust secret
            persistence.
          </p>
        </div>

        <button
          type="button"
          onClick={() => {
            setCreatedKey(null)
            setSelectedAgent(agentNames.length > 0 ? agentNames[0] : '*')
            setIsModalOpen(true)
          }}
          className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-semibold bg-accent-primary hover:bg-accent-hover text-white shadow-sm transition-all"
        >
          <Plus className="w-4 h-4" />
          <span>Generate Ingress Key</span>
        </button>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-700 dark:text-rose-300 text-xs font-mono">
          {error}
        </div>
      )}

      {/* API Keys Table */}
      <div className="bg-surface border border-subtle rounded-2xl overflow-hidden shadow-xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-surface-elevated/40 border-b border-subtle uppercase text-muted font-mono text-[10px] tracking-wider whitespace-nowrap">
              <tr>
                <th className="py-2.5 px-3">Name / Client</th>
                <th className="py-2.5 px-3">Associated Profile</th>
                <th className="py-2.5 px-3">Ingress Token</th>
                <th className="py-2.5 px-3">Created Date</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-subtle font-mono text-primary text-xs">
              {loading && keys.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-muted">
                    Loading API keys...
                  </td>
                </tr>
              ) : keys.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-muted">
                    No ingress API keys configured. Click &apos;Generate Ingress Key&apos; to connect
                    Claude, Cursor, or Windsurf.
                  </td>
                </tr>
              ) : (
                keys.map((k) => {
                  const isVisible = visibleKeyIds.has(k.id)
                  const hasRaw = Boolean(k.raw_key)
                  const tokenText = hasRaw
                    ? isVisible
                      ? k.raw_key!
                      : `${k.key_prefix || 'faw_live_'}••••••••`
                    : `${k.key_prefix || 'faw_live_'}••••••`

                  return (
                    <tr key={k.id} className="hover:bg-surface/50 transition-colors">
                      {/* Name / Client */}
                      <td className="py-2.5 px-3 font-sans font-medium text-primary whitespace-nowrap">
                        <div className="flex items-center gap-2">
                          <span>{k.name}</span>
                          {k.role && (
                            <span className="text-[10px] font-mono text-muted">({k.role})</span>
                          )}
                        </div>
                      </td>

                      {/* Associated Profile Badge */}
                      <td className="py-2.5 px-3 font-sans whitespace-nowrap">
                        {k.agent_name && k.agent_name !== '*' ? (
                          <Badge variant="cyan" size="sm" icon={<Layers className="w-3 h-3" />}>
                            {k.agent_name}
                          </Badge>
                        ) : (
                          <Badge variant="indigo" size="sm">
                            All Profiles (*)
                          </Badge>
                        )}
                      </td>

                      {/* Token with Show/Hide & Copy */}
                      <td className="py-2.5 px-3 text-accent-primary whitespace-nowrap">
                        <div className="flex items-center gap-1.5">
                          <span className="truncate select-all text-xs font-mono">{tokenText}</span>

                          {hasRaw ? (
                            <div className="flex items-center gap-0.5 shrink-0">
                              <button
                                type="button"
                                onClick={() => toggleTokenVisibility(k.id)}
                                className="p-1 rounded text-muted hover:text-primary hover:bg-surface transition-colors"
                                title={isVisible ? 'Hide token' : 'Show full token'}
                                aria-label={isVisible ? 'Hide token' : 'Show full token'}
                              >
                                {isVisible ? (
                                  <EyeOff className="w-3.5 h-3.5" />
                                ) : (
                                  <Eye className="w-3.5 h-3.5" />
                                )}
                              </button>

                              <button
                                type="button"
                                onClick={() => handleCopyText(k.raw_key!, k.id)}
                                className="p-1 rounded text-muted hover:text-accent-primary hover:bg-surface transition-colors"
                                title="Copy token"
                                aria-label="Copy token"
                              >
                                {copiedKeyId === k.id ? (
                                  <Check className="w-3.5 h-3.5 text-emerald-500" />
                                ) : (
                                  <Copy className="w-3.5 h-3.5" />
                                )}
                              </button>
                            </div>
                          ) : (
                            <span className="text-[9px] px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-700 dark:text-amber-400 border border-amber-500/20 font-sans shrink-0">
                              Hash Only
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Created Date */}
                      <td className="py-2.5 px-3 text-muted font-sans whitespace-nowrap">
                        {k.created_at ? new Date(k.created_at).toLocaleDateString() : 'N/A'}
                      </td>

                      {/* Status */}
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        {k.revoked ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-sans font-medium bg-rose-500/10 text-rose-700 dark:text-rose-400 border border-rose-500/20">
                            <span className="w-1.5 h-1.5 rounded-full bg-rose-500" />
                            Revoked
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-sans font-medium bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border border-emerald-500/20">
                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                            Active
                          </span>
                        )}
                      </td>

                      {/* Actions */}
                      <td className="py-2.5 px-3 text-right whitespace-nowrap">
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            type="button"
                            onClick={() => openClientConfig(k)}
                            className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-accent-primary/10 hover:bg-accent-primary/20 border border-accent-primary/20 text-accent-primary text-[11px] font-sans font-medium transition-colors"
                            title="Generate client configs for Claude, Cursor, Windsurf"
                          >
                            <Sparkles className="w-3 h-3" />
                            <span>Connect Client</span>
                          </button>

                          <button
                            type="button"
                            onClick={() => handleRevoke(k.id, k.name)}
                            className="p-1 rounded-lg text-muted hover:text-rose-500 hover:bg-rose-500/10 transition-colors"
                            title="Revoke key"
                            aria-label={`Revoke key ${k.name}`}
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Interactive Quick Connect Guide */}
      <div className="bg-surface border border-subtle border-l-4 border-l-cyan-500 rounded-2xl p-6 shadow-xs">
        <div className="flex flex-wrap items-center justify-between gap-4 mb-3">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-accent-primary">
              <ShieldCheck className="w-5 h-5 shrink-0" />
            </div>
            <div>
              <h4 className="font-bold text-sm text-primary">
                Zero-Trust Ingress & Multi-Client Integration
              </h4>
              <p className="text-xs text-muted mt-0.5">
                FaradAiWire Ingress listens on port{' '}
                <span className="font-mono text-accent-primary font-semibold">:{ingressPort}</span>. Scoped
                keys route seamlessly into their assigned security profiles.
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={() => {
              const activeKey = keys.find((k) => !k.revoked)
              setClientModal({
                isOpen: true,
                token: activeKey?.raw_key || activeKey?.key_prefix || '',
                keyName: activeKey?.name || 'Default Key',
                agentName: activeKey?.agent_name || '*',
              })
            }}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-surface hover:bg-surface/80 border border-subtle text-xs font-semibold text-primary hover:text-accent-primary transition-colors"
          >
            <Sparkles className="w-4 h-4 text-accent-primary" />
            <span>Open Config Generator</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2">
          <div className="p-3.5 bg-surface-elevated/60 dark:bg-black/30 rounded-xl border border-subtle shadow-xs">
            <div className="text-[10px] font-mono uppercase text-muted tracking-wider mb-1">
              Root SSE Endpoint
            </div>
            <div className="font-mono text-xs text-accent-primary font-semibold truncate">
              http://{ingressHost}:{ingressPort}/sse
            </div>
            <p className="text-[11px] text-muted mt-1 leading-normal">
              Bearer key automatically resolves to its bound profile.
            </p>
          </div>

          <div className="p-3.5 bg-surface-elevated/60 dark:bg-black/30 rounded-xl border border-subtle shadow-xs">
            <div className="text-[10px] font-mono uppercase text-muted tracking-wider mb-1">
              Direct Profile Route
            </div>
            <div className="font-mono text-xs text-accent-primary font-semibold truncate">
              http://{ingressHost}:{ingressPort}/sse/{'{profile_name}'}
            </div>
            <p className="text-[11px] text-muted mt-1 leading-normal">
              Fail-closed isolation verifies key authorization.
            </p>
          </div>

          <div className="p-3.5 bg-surface-elevated/60 dark:bg-black/30 rounded-xl border border-subtle shadow-xs">
            <div className="text-[10px] font-mono uppercase text-muted tracking-wider mb-1">
              Supported Clients
            </div>
            <div className="text-xs text-secondary flex items-center gap-1.5 flex-wrap pt-0.5">
              <span className="px-1.5 py-0.5 rounded bg-surface border border-subtle font-mono text-[10px] text-secondary">Claude Desktop</span>
              <span className="px-1.5 py-0.5 rounded bg-surface border border-subtle font-mono text-[10px] text-secondary">Cursor</span>
              <span className="px-1.5 py-0.5 rounded bg-surface border border-subtle font-mono text-[10px] text-secondary">Windsurf</span>
              <span className="px-1.5 py-0.5 rounded bg-surface border border-subtle font-mono text-[10px] text-secondary">Gemini</span>
            </div>
          </div>
        </div>
      </div>

      {/* Create Key Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-xs">
          <div className="w-full max-w-lg p-6 bg-surface border border-subtle shadow-2xl relative rounded-2xl animate-in fade-in zoom-in-95 duration-150">
            <h3 className="text-lg font-bold text-primary mb-1 flex items-center gap-2">
              <Key className="w-5 h-5 text-accent-primary" />
              <span>Generate Ingress Key</span>
            </h3>
            <p className="text-xs text-muted mb-4">
              Create an authentication token and bind it to a specific security profile or allow global gateway
              access.
            </p>

            {!createdKey ? (
              <form onSubmit={handleCreate} className="space-y-4">
                {/* Key Name Input */}
                <div>
                  <label className="block text-xs font-semibold text-primary mb-1">
                    Client / Token Name
                  </label>
                  <input
                    type="text"
                    required
                    value={keyName}
                    onChange={(e) => setKeyName(e.target.value)}
                    placeholder="e.g. cursor-workstation-agent"
                    className="w-full px-3 py-2 rounded-xl bg-surface border border-subtle text-xs text-primary focus:outline-none focus:ring-1 focus:ring-accent-primary font-mono placeholder:text-muted"
                  />
                </div>

                {/* Associated Profile Selector */}
                <div>
                  <label className="block text-xs font-semibold text-primary mb-1">
                    Associated Profile Scope
                  </label>
                  <select
                    value={selectedAgent}
                    onChange={(e) => setSelectedAgent(e.target.value)}
                    className="w-full px-3 py-2 rounded-xl bg-surface border border-subtle text-xs text-primary focus:outline-none focus:ring-1 focus:ring-accent-primary font-mono"
                  >
                    <option value="*">* (All Profiles / Global Gateway Access)</option>
                    {agentNames.map((ag) => (
                      <option key={ag} value={ag}>
                        Profile: {ag}
                      </option>
                    ))}
                  </select>
                  <p className="text-[11px] text-muted mt-1.5 flex items-center gap-1">
                    <Info className="w-3.5 h-3.5 text-accent-primary shrink-0" />
                    <span>
                      {selectedAgent === '*'
                        ? 'Global key can access all current and future profiles across FaradAiWire.'
                        : `Key is dedicated to '${selectedAgent}'. Requests to root /sse automatically route to '${selectedAgent}'.`}
                    </span>
                  </p>
                </div>

                {/* Form Buttons */}
                <div className="flex justify-end gap-2 pt-2 border-t border-subtle">
                  <button
                    type="button"
                    onClick={() => setIsModalOpen(false)}
                    className="px-4 py-2 rounded-xl text-xs text-muted hover:text-primary hover:bg-surface/80 transition-colors"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={isCreating || !keyName.trim()}
                    className="px-4 py-2 rounded-xl text-xs font-semibold bg-accent-primary hover:bg-accent-hover text-white disabled:opacity-50 transition-all shadow-sm"
                  >
                    {isCreating ? 'Generating Token...' : 'Generate Key'}
                  </button>
                </div>
              </form>
            ) : (
              <div className="space-y-4">
                <div className="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-800 dark:text-emerald-300">
                  <div className="font-semibold flex items-center gap-1.5">
                    <ShieldCheck className="w-4 h-4 text-emerald-500" />
                    <span>Token Generated & Persisted</span>
                  </div>
                  <div className="text-[11px] text-emerald-700/80 dark:text-emerald-300/80 mt-1">
                    Your key is saved in <code className="font-mono bg-surface px-1 py-0.5 rounded border border-subtle">~/.faradaiwire/keys/api_keys.json</code> (0600 POSIX permissions). You can reveal or copy it anytime.
                  </div>
                </div>

                {/* Token Display Box (DUAL TONE INVARIANT) */}
                <div className="p-3.5 rounded-xl bg-[#0F172A] border border-cyan-500/40 font-mono text-xs text-cyan-300 break-all select-all flex items-center justify-between gap-2 shadow-inner">
                  <span className="font-semibold">{resolvedCreatedToken}</span>
                  <button
                    type="button"
                    onClick={() => {
                      navigator.clipboard.writeText(resolvedCreatedToken)
                      setCopiedCreatedToken(true)
                      setTimeout(() => setCopiedCreatedToken(false), 2000)
                    }}
                    className="p-1.5 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 shrink-0 transition-colors"
                    title="Copy token to clipboard"
                    aria-label="Copy token to clipboard"
                  >
                    {copiedCreatedToken ? (
                      <Check className="w-4 h-4 text-emerald-400" />
                    ) : (
                      <Copy className="w-4 h-4" />
                    )}
                  </button>
                </div>

                <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-subtle">
                  <button
                    type="button"
                    onClick={() => {
                      setIsModalOpen(false)
                      setClientModal({
                        isOpen: true,
                        token: resolvedCreatedToken,
                        keyName: createdKey.name,
                        agentName: createdKey.agent_name || '*',
                      })
                    }}
                    className="flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-semibold bg-accent-primary hover:bg-accent-hover text-white shadow-sm transition-all"
                  >
                    <Sparkles className="w-4 h-4" />
                    <span>Configure AI Clients Now</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => setIsModalOpen(false)}
                    className="px-4 py-2 rounded-xl text-xs font-semibold bg-surface hover:bg-surface/80 border border-subtle text-primary transition-colors"
                  >
                    Done
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Universal Client Configuration Modal */}
      <ClientConfigModal
        isOpen={clientModal.isOpen}
        onClose={() => setClientModal((prev) => ({ ...prev, isOpen: false }))}
        token={clientModal.token}
        keyName={clientModal.keyName}
        agentName={clientModal.agentName}
        availableAgents={agentNames}
        ingressPort={ingressPort}
        ingressHost={ingressHost}
      />
    </div>
  )
}
