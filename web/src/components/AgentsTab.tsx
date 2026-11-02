import React, { useState, useEffect, useCallback } from 'react'
import { Bot, Plus, CheckCircle2, AlertTriangle, X } from 'lucide-react'
import { AgentItem, ProtocolItem, GatewayStatus } from '../types'
import { api } from '../api'
import { Button } from './ui/Button'
import { AgentCard } from './agents/AgentCard'
import { AgentStudioModal } from './agents/AgentStudioModal'
import { AgentRollbackModal } from './agents/AgentRollbackModal'
import { SessionConflictModal } from './agents/SessionConflictModal'
import { ClientConfigModal } from './ClientConfigModal'

export interface AgentsTabProps {
  status?: GatewayStatus | null
}

export const AgentsTab: React.FC<AgentsTabProps> = ({ status: propStatus }) => {
  const [agents, setAgents] = useState<AgentItem[]>([])
  const [protocols, setProtocols] = useState<ProtocolItem[]>([])
  const [localStatus, setLocalStatus] = useState<GatewayStatus | null>(null)
  const status = propStatus || localStatus
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [notification, setNotification] = useState<{ type: 'success' | 'error'; text: string } | null>(null)
  const [syncingAgent, setSyncingAgent] = useState<string | null>(null)

  // Client Config Modal state
  const [clientModal, setClientModal] = useState<{
    isOpen: boolean
    token: string
    keyName: string
    agentName: string
  }>({
    isOpen: false,
    token: '',
    keyName: '',
    agentName: '*',
  })

  // Modal states
  const [studioModalOpen, setStudioModalOpen] = useState(false)
  const [studioMode, setStudioMode] = useState<'create' | 'edit'>('create')
  const [selectedAgentForEdit, setSelectedAgentForEdit] = useState<AgentItem | null>(null)
  const [rollbackAgentName, setRollbackAgentName] = useState<string | null>(null)
  const [sessionConflictAlert, setSessionConflictAlert] = useState<{
    agentName: string
    message: string
  } | null>(null)

  const fetchData = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)
      const [aRes, pRes, sRes] = await Promise.all([
        api.getAgents(),
        api.getProtocols(),
        api.getStatus().catch(() => null),
      ])
      setAgents(aRes.agents || [])
      setProtocols(pRes.protocols || [])
      if (sRes) setLocalStatus(sRes)
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

  // Card action handlers
  const handleOpenCreateModal = useCallback(() => {
    setStudioMode('create')
    setSelectedAgentForEdit(null)
    setStudioModalOpen(true)
  }, [])

  const handleOpenEditModal = useCallback((agent: AgentItem) => {
    setStudioMode('edit')
    setSelectedAgentForEdit(agent)
    setStudioModalOpen(true)
  }, [])

  const handleSyncTools = useCallback(
    async (name: string) => {
      try {
        setSyncingAgent(name)
        await api.syncAgentTools(name)
        fetchData()
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err)
        alert(`Sync failed: ${msg}`)
      } finally {
        setSyncingAgent(null)
      }
    },
    [fetchData]
  )

  const handleDeleteAgent = useCallback(
    async (name: string) => {
      if (!window.confirm(`Delete agent '${name}'? All current routing rules will be removed.`))
        return
      try {
        await api.deleteAgent(name)
        fetchData()
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err)
        setSessionConflictAlert({
          agentName: name,
          message: msg,
        })
      }
    },
    [fetchData]
  )

  const handleOpenRollback = useCallback((name: string) => {
    setRollbackAgentName(name)
  }, [])

  const handleConnectClient = useCallback(async (agentName: string) => {
    try {
      const keysRes = await api.getApiKeys()
      const existingKeys = (keysRes.keys || []).filter((k) => !k.revoked)
      // Look for a key specifically for this agent, or a global key '*'
      const matchingKey =
        existingKeys.find((k) => k.agent_name === agentName) ||
        existingKeys.find((k) => !k.agent_name || k.agent_name === '*')

      if (matchingKey) {
        setClientModal({
          isOpen: true,
          token: matchingKey.raw_key || matchingKey.key_prefix || '',
          keyName: matchingKey.name,
          agentName: agentName,
        })
      } else {
        // Automatically generate a dedicated key for this agent
        const newKey = await api.createApiKey(`${agentName}-client-key`, agentName, 'Developer')
        setClientModal({
          isOpen: true,
          token: newKey.raw_key || newKey.api_key || newKey.key || '',
          keyName: newKey.name,
          agentName: agentName,
        })
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      alert(`Could not prepare client connection: ${msg}`)
    }
  }, [])

  const ingressPort = status?.ingress_port || 8090
  const ingressHost =
    status?.ingress_host ||
    (typeof window !== 'undefined' && window.location.hostname
      ? window.location.hostname
      : '127.0.0.1')

  return (
    <div className="space-y-8">
      {/* Top Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-primary flex items-center gap-2">
            <Bot className="w-5 h-5 text-accent" />
            Profile Studio & Governance
          </h2>
          <p className="text-xs text-muted mt-1">
            Build and govern AI Security Profiles with dual-layer tool scoping, automatic snapshot
            archives, and fail-closed ingress routing.
          </p>
        </div>

        <Button
          onClick={handleOpenCreateModal}
          variant="primary"
          size="md"
          icon={<Plus className="w-4 h-4" />}
        >
          New Security Profile
        </Button>
      </div>

      {notification && (
        <div
          className={`p-3.5 rounded-xl border text-xs flex items-center justify-between gap-2 shadow-xs animate-in fade-in font-sans ${
            notification.type === 'success'
              ? 'bg-emerald-50 dark:bg-emerald-950/40 border-emerald-300 dark:border-emerald-500/30 text-emerald-800 dark:text-emerald-300'
              : 'bg-rose-50 dark:bg-rose-950/40 border-rose-300 dark:border-rose-500/30 text-rose-700 dark:text-rose-300'
          }`}
        >
          <div className="flex items-center gap-2">
            {notification.type === 'success' ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
            ) : (
              <AlertTriangle className="w-4 h-4 text-rose-600 dark:text-rose-400 shrink-0" />
            )}
            <span className="font-semibold">{notification.text}</span>
          </div>
          <button
            type="button"
            onClick={() => setNotification(null)}
            className="text-muted hover:text-primary transition-colors"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {error && (
        <div className="p-4 rounded-xl bg-rose-50 dark:bg-rose-950/40 border border-rose-300 dark:border-rose-500/30 text-rose-700 dark:text-rose-300 text-xs font-mono">
          {error}
        </div>
      )}

      {/* Agents Grid */}
      {loading && agents.length === 0 ? (
        <div className="bg-surface p-12 text-center text-xs text-muted border border-subtle rounded-2xl">
          Loading installed profiles...
        </div>
      ) : agents.length === 0 ? (
        <div className="bg-surface p-12 text-center text-xs text-muted border border-dashed border-subtle rounded-2xl">
          No security profiles configured yet. Click &apos;New Security Profile&apos; to scaffold routing policies and
          attach MCP tool sources.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {agents.map((agent) => (
            <AgentCard
              key={agent.name}
              agent={agent}
              ingressHost={ingressHost}
              ingressPort={ingressPort}
              syncing={syncingAgent === agent.name}
              activeFilters={status?.active_filters || []}
              onEdit={handleOpenEditModal}
              onSync={handleSyncTools}
              onRollback={handleOpenRollback}
              onDelete={handleDeleteAgent}
              onConnectClient={handleConnectClient}
            />
          ))}
        </div>
      )}

      {/* 4-Step Agent Studio Modal */}
      <AgentStudioModal
        isOpen={studioModalOpen}
        onClose={() => setStudioModalOpen(false)}
        mode={studioMode}
        initialAgent={selectedAgentForEdit}
        protocols={protocols}
        onSuccess={fetchData}
        activeFilters={status?.active_filters || []}
      />

      {/* Snapshot Rollback Modal */}
      <AgentRollbackModal
        isOpen={Boolean(rollbackAgentName)}
        agentName={rollbackAgentName}
        onClose={() => setRollbackAgentName(null)}
        onSuccess={(restoredArchive) => {
          fetchData()
          if (rollbackAgentName) {
            setNotification({
              type: 'success',
              text: `Agent '${rollbackAgentName}' successfully restored to snapshot ${restoredArchive || ''}. Gateway configuration hot-reloaded.`,
            })
            setTimeout(() => setNotification(null), 6000)
          }
        }}
      />

      {/* 409 Active Session Conflict Alert */}
      <SessionConflictModal
        conflict={sessionConflictAlert}
        onClose={() => setSessionConflictAlert(null)}
      />

      {/* Universal Client Configuration Modal */}
      <ClientConfigModal
        isOpen={clientModal.isOpen}
        onClose={() => setClientModal((prev) => ({ ...prev, isOpen: false }))}
        token={clientModal.token}
        keyName={clientModal.keyName}
        agentName={clientModal.agentName}
        availableAgents={agents.map((a) => a.name)}
        ingressPort={ingressPort}
        ingressHost={ingressHost}
      />
    </div>
  )
}
