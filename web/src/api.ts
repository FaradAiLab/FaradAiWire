import {
  GatewayStatus,
  ApiKeyItem,
  CreatedApiKey,
  AgentItem,
  ProtocolItem,
  PresetMetadata,
  ToolMetadata,
  AuditEvent,
  HITLApprovalRequest,
  GuardModel,
  GuardProcessStatus,
  GuardInstallProgress,
  GuardThreatAction,
  DlpRule,
  PolicyPack,
  AgentDlpConfig,
  CompiledAgentPolicy,
  SmartRecommendation,
  RecommendationRequest,
  ToolSchemaRecord,
  HostResources,
  SettingsResponse,
} from './types'

// ProbeError extends Error with structured diagnostic fields from the server.
export class ProbeError extends Error {
  errorCode?: string
  statusCode?: number
  remediation?: string

  constructor(message: string, errorCode?: string, statusCode?: number, remediation?: string) {
    super(message)
    this.name = 'ProbeError'
    this.errorCode = errorCode
    this.statusCode = statusCode
    this.remediation = remediation
  }
}

async function request<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
  })

  if (!res.ok) {
    let errMsg = `Request failed: ${res.status} ${res.statusText}`
    let errorCode: string | undefined
    let statusCode: number | undefined
    let remediation: string | undefined
    try {
      const data = await res.json()
      if (data.message) errMsg = data.message
      else if (data.error) errMsg = typeof data.error === 'string' ? data.error : JSON.stringify(data.error)
      errorCode = typeof data.error === 'string' ? data.error : undefined
      statusCode = typeof data.status_code === 'number' ? data.status_code : undefined
      remediation = typeof data.remediation === 'string' ? data.remediation : undefined
    } catch {
      // ignore
    }
    throw new ProbeError(errMsg, errorCode, statusCode, remediation)
  }

  return res.json()
}

export const api = {
  // Status & Telemetry
  getStatus: (signal?: AbortSignal) => request<GatewayStatus>('/admin/status', { signal }),
  getHostResources: (signal?: AbortSignal) => request<HostResources>('/admin/host/resources', { signal }),
  getSettings: (signal?: AbortSignal) => request<SettingsResponse>('/admin/settings', { signal }),
  updateSetting: (key: string, value: unknown) =>
    request<{ status: string; message: string; updated: Record<string, unknown> }>('/admin/settings', {
      method: 'POST',
      body: JSON.stringify({ key, value }),
    }),
  resetSetting: (key: string) =>
    request<{ status: string; message: string; key: string }>('/admin/settings/reset', {
      method: 'POST',
      body: JSON.stringify({ key }),
    }),
  clearSchemas: () => request<{ status: string; message: string }>('/admin/schemas/clear', { method: 'POST' }),
  reloadGateway: () => request<{ status: string; message: string }>('/admin/reload', { method: 'POST' }),
  getSchemas: (signal?: AbortSignal) => request<{ schemas: ToolSchemaRecord[] }>('/admin/schemas', { signal }),
  getSchema: (toolName: string, signal?: AbortSignal) =>
    request<ToolSchemaRecord>(`/admin/schemas/${toolName}`, { signal }),
  pinSchema: (toolName: string, pinned: boolean) =>
    request<{ status: string; tool_name: string; is_pinned: boolean }>(`/admin/schemas/${toolName}/pin`, {
      method: 'POST',
      body: JSON.stringify({ pinned }),
    }),

  // Filters
  toggleFilter: (filter: string, enabled: boolean) =>
    request<{ status: string; filter: string; enabled: boolean }>('/admin/config/toggle', {
      method: 'POST',
      body: JSON.stringify({ filter_name: filter, filter, enabled }),
    }),

  // SLM Neural Probe
  probeSLM: (signal?: AbortSignal) => request<Record<string, unknown>>('/admin/slm/probe', { signal }),
  configureSLM: (params: { classifier_url?: string; mode?: string; ollama_url?: string; docker_url?: string; custom_url?: string } | string) =>
    request<{ status: string; message: string }>('/admin/slm/configure', {
      method: 'POST',
      body: JSON.stringify(typeof params === 'string' ? { classifier_url: params } : params),
    }),

  // API Keys
  getApiKeys: (signal?: AbortSignal) => request<{ keys: ApiKeyItem[] }>('/admin/api-keys', { signal }),
  createApiKey: (name: string, agentName?: string, role?: string) =>
    request<CreatedApiKey>('/admin/api-keys', {
      method: 'POST',
      body: JSON.stringify({
        name,
        agent_name: agentName || '*',
        role: role || 'Developer',
      }),
    }),
  revokeApiKey: (id: string) =>
    request<{ status: string; message: string }>(`/admin/api-keys/${id}`, {
      method: 'DELETE',
    }),

  // Protocols
  getProtocols: (signal?: AbortSignal) => request<{ protocols: ProtocolItem[] }>('/admin/protocols', { signal }),
  getPresets: (signal?: AbortSignal) => request<{ presets: PresetMetadata[] }>('/admin/protocols/presets', { signal }),
  createProtocol: (proto: Partial<ProtocolItem>) =>
    request<{ status: string; protocol: ProtocolItem }>('/admin/protocols', {
      method: 'POST',
      body: JSON.stringify(proto),
    }),
  updateProtocol: (id: string, proto: Partial<ProtocolItem>) =>
    request<{ status: string; protocol: ProtocolItem }>(`/admin/protocols/${id}`, {
      method: 'PUT',
      body: JSON.stringify(proto),
    }),
  deleteProtocol: (id: string) =>
    request<{ status: string; message: string }>(`/admin/protocols/${id}`, {
      method: 'DELETE',
    }),
  probeProtocol: (
    probeReq: {
      type: string
      url?: string
      command?: string
      args?: string[]
      env?: string[]
      auth_token?: string
      headers?: Record<string, string>
    },
    signal?: AbortSignal
  ) =>
    request<{ status: string; count: number; tools: ToolMetadata[] }>('/admin/protocols/probe', {
      method: 'POST',
      body: JSON.stringify(probeReq),
      signal,
    }),

  // Agents
  getAgents: (signal?: AbortSignal) => request<{ agents: AgentItem[] }>('/admin/agents', { signal }),
  getAgent: (name: string, signal?: AbortSignal) => request<AgentItem>(`/admin/agents/${name}`, { signal }),
  createAgent: (agentPayload: Record<string, unknown>) =>
    request<{ status: string; agent: AgentItem }>('/admin/agents', {
      method: 'POST',
      body: JSON.stringify(agentPayload),
    }),
  updateAgent: (name: string, agentPayload: Record<string, unknown>) =>
    request<{ status: string; agent: AgentItem }>(`/admin/agents/${name}`, {
      method: 'PUT',
      body: JSON.stringify(agentPayload),
    }),
  deleteAgent: (name: string) =>
    request<{ status: string; message: string }>(`/admin/agents/${name}`, {
      method: 'DELETE',
    }),
  syncAgentTools: (agentName: string) =>
    request<{ status: string; tools: ToolMetadata[] }>('/admin/agents/sync-tools', {
      method: 'POST',
      body: JSON.stringify({ agent_name: agentName }),
    }),
  getAgentArchives: (agentName: string, signal?: AbortSignal) =>
    request<{ agent: string; archives: string[] }>(`/admin/agents/archives?agent=${agentName}`, { signal }),
  rollbackAgent: (agentName: string, timestamp: string) =>
    request<{ status: string; message: string }>('/admin/agents/rollback', {
      method: 'POST',
      body: JSON.stringify({ agent: agentName, timestamp }),
    }),

  // MCP Tools
  getMCPTools: (signal?: AbortSignal) => request<{ tools: ToolMetadata[] }>('/admin/mcp/tools', { signal }),

  // Audit Logs
  getAuditLogs: (signal?: AbortSignal) => request<{ events?: AuditEvent[]; logs?: any[] }>('/admin/audit-logs', { signal }),

  // Human-in-the-Loop Safety
  respondHITL: (callId: string, approved: boolean) =>
    request<{ status: string; call_id: string; approved: boolean }>('/admin/guards/hitl/respond', {
      method: 'POST',
      body: JSON.stringify({ call_id: callId, approved }),
    }),
  getPendingHITL: (signal?: AbortSignal) =>
    request<{ pending: HITLApprovalRequest[] }>('/admin/guards/hitl/pending', { signal }),

  // Security Guards & Zero-Downtime Hot-Swap
  getGuardModels: (signal?: AbortSignal) => request<{ models: GuardModel[] }>('/admin/guards/models', { signal }),
  getGuardModel: (id: string, signal?: AbortSignal) => request<GuardModel>(`/admin/guards/models/${id}`, { signal }),
  installGuardModel: (id: string) =>
    request<{ status: string; model_id: string; message: string }>(`/admin/guards/models/${id}/install`, {
      method: 'POST',
    }),
  connectGuardModel: (
    id: string,
    params: { runtime_type: string; endpoint_url: string; force?: boolean; context_window?: number }
  ) =>
    request<{
      status: string
      model_id: string
      endpoint_url: string
      runtime_type: string
      model_mismatch?: boolean
      expected_model?: string
      detected_model?: string
      latency_ms?: number
      message: string
      probe?: {
        alive: boolean
        latency_ms: number
        models_found: string[]
        model_matched: boolean
        detected_model?: string
        message: string
      }
    }>(`/admin/guards/models/${id}/connect`, {
      method: 'POST',
      body: JSON.stringify(params),
    }),
  getGuardProgress: (id: string, signal?: AbortSignal) =>
    request<GuardInstallProgress>(`/admin/guards/models/${id}/progress`, { signal }),
  activateGuardModel: (id: string) =>
    request<{ status: string; model_id: string; message: string }>(`/admin/guards/models/${id}/activate`, {
      method: 'POST',
    }),
  deactivateGuardModel: (id?: string) =>
    request<{ status: string; message: string }>(
      id ? `/admin/guards/models/${id}/deactivate` : '/admin/guards/models/deactivate',
      { method: 'POST' }
    ),
  uninstallGuardModel: (id: string) =>
    request<{ status: string; model_id: string; message: string }>(`/admin/guards/models/${id}`, {
      method: 'DELETE',
    }),
  updateGuardPolicy: (id: string, policy: { default_action: GuardThreatAction; critical_tools: string[] }) =>
    request<{ status: string; model_id: string; default_action: string; critical_tools: string[] }>(
      `/admin/guards/models/${id}/policy`,
      {
        method: 'POST',
        body: JSON.stringify(policy),
      }
    ),
  getGuardStatus: (signal?: AbortSignal) => request<GuardProcessStatus>('/admin/guards/status', { signal }),
 
  // DLP Catalog Rules
  getDlpRules: (category?: string, signal?: AbortSignal) =>
    request<{ rules: DlpRule[] }>(
      category ? `/admin/dlp/rules?category=${encodeURIComponent(category)}` : '/admin/dlp/rules',
      { signal }
    ),
  getDlpRule: (id: string, signal?: AbortSignal) =>
    request<{ rule: DlpRule }>(`/admin/dlp/rules/${encodeURIComponent(id)}`, { signal }),
  createDlpRule: (rule: Partial<DlpRule>) =>
    request<{ status: string; rule: DlpRule }>('/admin/dlp/rules', {
      method: 'POST',
      body: JSON.stringify(rule),
    }),
  updateDlpRule: (id: string, rule: Partial<DlpRule>) =>
    request<{ status: string; rule: DlpRule }>(`/admin/dlp/rules/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body: JSON.stringify(rule),
    }),
  deleteDlpRule: (id: string) =>
    request<{ status: string; id: string }>(`/admin/dlp/rules/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    }),

  // Policy Packs
  getPolicyPacks: (signal?: AbortSignal) =>
    request<{ packs: PolicyPack[] }>('/admin/policy-packs', { signal }),
  getPolicyPack: (id: string, signal?: AbortSignal) =>
    request<{ pack: PolicyPack }>(`/admin/policy-packs/${encodeURIComponent(id)}`, { signal }),
  createPolicyPack: (pack: Partial<PolicyPack>) =>
    request<{ status: string; pack: PolicyPack }>('/admin/policy-packs', {
      method: 'POST',
      body: JSON.stringify(pack),
    }),
  updatePolicyPack: (id: string, pack: Partial<PolicyPack>) =>
    request<{ status: string; pack: PolicyPack }>(`/admin/policy-packs/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body: JSON.stringify(pack),
    }),
  deletePolicyPack: (id: string) =>
    request<{ status: string; id: string }>(`/admin/policy-packs/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    }),

  // Smart Recommendations
  getSmartRecommendations: (req: RecommendationRequest, signal?: AbortSignal) =>
    request<{ recommendations: SmartRecommendation[] }>('/admin/policy-packs/recommend', {
      method: 'POST',
      body: JSON.stringify(req),
      signal,
    }),

  // Agent DLP Configuration
  getAgentDLP: (agentName: string, signal?: AbortSignal) =>
    request<{ agent_name: string; config: AgentDlpConfig; compiled: CompiledAgentPolicy }>(
      `/admin/agents/${encodeURIComponent(agentName)}/dlp`,
      { signal }
    ),
  saveAgentDLP: (agentName: string, config: AgentDlpConfig) =>
    request<{ status: string; agent_name: string; config: AgentDlpConfig; compiled: CompiledAgentPolicy }>(
      `/admin/agents/${encodeURIComponent(agentName)}/dlp`,
      {
        method: 'PUT',
        body: JSON.stringify(config),
      }
    ),
  previewAgentDLP: (config: AgentDlpConfig, signal?: AbortSignal) =>
    request<{ status: string; agent_name: string; compiled: CompiledAgentPolicy }>('/admin/policies/preview', {
      method: 'POST',
      body: JSON.stringify(config),
      signal,
    }),
}
