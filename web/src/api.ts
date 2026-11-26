import {
  GatewayStatus,
  ApiKeyItem,
  CreatedApiKey,
  AgentItem,
  ProtocolItem,
  PresetMetadata,
  ToolMetadata,
  AuditEvent,
  AuditQuerySummary,
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
  AnalyticsWindow,
  AnalyticsSummary,
  AuditLogsQueryParams,
  SecurityAuditQueryParams,
  SecurityAuditRecord,
  AuditVerifyResponse,
  ReadyzResponse,
} from './types'

export interface ExportNativeMCPRequest {
  client: string
  scope?: 'global' | 'project'
  client_os?: 'darwin' | 'linux' | 'windows'
}

export interface ExportWarning {
  code: string
  severity: 'warning' | 'info' | string
  server?: string
  message: string
}

export interface ExportCompanionFile {
  path_hint: string
  merge_hazard: boolean
  content: Record<string, unknown>
}

export interface ExportNativeMCPResponse {
  client: string
  scope: string
  target_path_hint: string
  merge_hazard: boolean
  config: Record<string, unknown>
  companion_files?: ExportCompanionFile[]
  warnings: ExportWarning[]
}

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

export interface ProbeProtocolRequest {
  id?: string
  type: string
  url?: string
  command?: string
  args?: string[]
  env?: string[]
  auth_token?: string
  headers?: Record<string, string>
}

export interface ProbeProgressEvent {
  message: string
  elapsed_ms: number
  timeout_sec: number
}

export interface ProbeProtocolResult {
  status: string
  count: number
  tools: ToolMetadata[]
  transport_mode?: string
}

export const ADMIN_UNAUTHORIZED_EVENT = 'faradaiwire:unauthorized'

function dispatchUnauthorizedIfNeeded(status: number): void {
  if (status === 401 && typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent(ADMIN_UNAUTHORIZED_EVENT))
  }
}

function toProbeError(data: unknown, fallbackMsg: string, httpStatus?: number): ProbeError {
  if (!data || typeof data !== 'object') {
    return new ProbeError(fallbackMsg, undefined, httpStatus)
  }
  const obj = data as Record<string, unknown>
  let errMsg = fallbackMsg
  if (typeof obj.message === 'string' && obj.message) {
    errMsg = obj.message
  } else if (obj.error) {
    errMsg = typeof obj.error === 'string' ? obj.error : JSON.stringify(obj.error)
  }
  const errorCode = typeof obj.error === 'string' ? obj.error : undefined
  const statusCode = typeof obj.status_code === 'number' ? obj.status_code : httpStatus
  const remediation = typeof obj.remediation === 'string' ? obj.remediation : undefined
  return new ProbeError(errMsg, errorCode, statusCode, remediation)
}

interface RequestOptions extends RequestInit {
  suppressUnauthorizedEvent?: boolean
}

async function request<T>(url: string, options?: RequestOptions): Promise<T> {
  const { suppressUnauthorizedEvent, ...fetchOptions } = options || {}
  const res = await fetch(url, {
    ...fetchOptions,
    headers: {
      'Content-Type': 'application/json',
      ...fetchOptions?.headers,
    },
  })

  if (!res.ok) {
    if (!suppressUnauthorizedEvent) {
      dispatchUnauthorizedIfNeeded(res.status)
    }
    const fallback = `Request failed: ${res.status} ${res.statusText}`
    let parsed: unknown = null
    try {
      parsed = await res.json()
    } catch {
      // ignore
    }
    throw toProbeError(parsed, fallback, res.status)
  }

  return res.json()
}

function buildQueryParams(params?: Record<string, string | number | boolean | undefined>): URLSearchParams {
  const sp = new URLSearchParams()
  if (!params) return sp
  for (const [key, val] of Object.entries(params)) {
    if (val === undefined || val === null || val === '') continue
    if (typeof val === 'boolean') {
      if (val) sp.set(key, '1')
    } else {
      sp.set(key, String(val))
    }
  }
  return sp
}

export const api = {
  // Admin Session Authentication (Non-Loopback / Containerized Gateway)
  loginAdminSession: (token: string) =>
    request<{ status: string; authenticated: boolean; role?: string }>('/admin/auth/session', {
      method: 'POST',
      body: JSON.stringify({ api_key: token, token }),
      suppressUnauthorizedEvent: true,
    }),
  logoutAdminSession: () =>
    request<{ status: string; authenticated: boolean }>('/admin/auth/logout', {
      method: 'POST',
      suppressUnauthorizedEvent: true,
    }),

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

  // AI Guard Probe & Configuration
  probeGuard: (signal?: AbortSignal) => request<Record<string, unknown>>('/admin/guards/probe', { signal }),
  configureGuard: (params: { mode?: string; ollama_url?: string; docker_url?: string; custom_url?: string } | string) =>
    request<{ status: string; message: string }>('/admin/guards/configure', {
      method: 'POST',
      body: JSON.stringify(typeof params === 'string' ? { custom_url: params } : params),
    }),

  // API Keys
  getApiKeys: (signal?: AbortSignal) => request<{ keys: ApiKeyItem[] }>('/admin/api-keys', { signal }),
  createApiKey: (name: string, agentName?: string, role?: string) =>
    request<CreatedApiKey>('/admin/api-keys', {
      method: 'POST',
      body: JSON.stringify({
        name,
        agent_name: agentName || '*',
        role: role || 'Agent',
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
  probeProtocol: (probeReq: ProbeProtocolRequest, signal?: AbortSignal) =>
    request<ProbeProtocolResult>('/admin/protocols/probe', {
      method: 'POST',
      body: JSON.stringify(probeReq),
      signal,
    }),

  probeProtocolStream: async (
    probeReq: ProbeProtocolRequest,
    onProgress?: (ev: ProbeProgressEvent) => void,
    signal?: AbortSignal
  ): Promise<ProbeProtocolResult> => {
    const res = await fetch('/admin/protocols/probe?stream=1', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'text/event-stream',
      },
      body: JSON.stringify(probeReq),
      signal,
    })

    if (!res.ok) {
      dispatchUnauthorizedIfNeeded(res.status)
      const fallback = `Request failed: ${res.status} ${res.statusText}`
      let parsed: unknown = null
      try {
        parsed = await res.json()
      } catch {
        // ignore
      }
      throw toProbeError(parsed, fallback, res.status)
    }

    const contentType = res.headers.get('content-type') || ''
    if (!contentType.includes('text/event-stream') || !res.body) {
      return res.json() as Promise<ProbeProtocolResult>
    }

    const reader = res.body.getReader()
    const decoder = new TextDecoder()
    let buffer = ''
    let finalResult: ProbeProtocolResult | null = null

    const processFrame = (frame: string) => {
      if (!frame.trim()) return
      let eventName = 'message'
      const dataLines: string[] = []
      for (const rawLine of frame.split(/\r?\n/)) {
        if (rawLine.startsWith('event:')) {
          eventName = rawLine.slice(6).trim()
        } else if (rawLine.startsWith('data:')) {
          dataLines.push(rawLine.slice(5).trimStart())
        }
      }
      if (dataLines.length === 0) return
      const payloadStr = dataLines.join('\n')
      let data: unknown
      try {
        data = JSON.parse(payloadStr)
      } catch {
        return
      }
      if (eventName === 'progress' && onProgress && data && typeof data === 'object') {
        onProgress(data as ProbeProgressEvent)
      } else if (eventName === 'result') {
        finalResult = data as ProbeProtocolResult
      } else if (eventName === 'error') {
        throw toProbeError(data, 'Probe failed')
      }
    }

    try {
      while (true) {
        const { value, done } = await reader.read()
        if (value) {
          buffer += decoder.decode(value, { stream: !done })
          let idx: number
          while ((idx = buffer.indexOf('\n\n')) !== -1) {
            const frame = buffer.slice(0, idx)
            buffer = buffer.slice(idx + 2)
            processFrame(frame)
          }
        }
        if (done) {
          buffer += decoder.decode()
          if (buffer.trim()) {
            processFrame(buffer)
          }
          break
        }
      }
    } finally {
      reader.releaseLock()
    }

    if (!finalResult) {
      throw new ProbeError('Probe stream ended without a result')
    }
    return finalResult
  },

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
  exportAgentNativeMCP: (
    agentName: string,
    payload: { client: string; scope?: 'global' | 'project'; client_os?: 'darwin' | 'linux' | 'windows' },
    signal?: AbortSignal
  ) =>
    request<ExportNativeMCPResponse>(`/admin/agents/${encodeURIComponent(agentName)}/export`, {
      method: 'POST',
      body: JSON.stringify(payload),
      signal,
    }),

  // MCP Tools
  getMCPTools: (signal?: AbortSignal) => request<{ tools: ToolMetadata[] }>('/admin/mcp/tools', { signal }),

  // Audit Logs, Analytics, Security Events & Integrity Verification
  getAuditLogs: (params?: AuditLogsQueryParams, signal?: AbortSignal) => {
    const qs = buildQueryParams({
      summary: params?.summary ?? true,
      limit: params?.limit,
      offset: params?.offset,
      decision: params?.decision,
      agent_name: params?.agent_name,
      tool_name: params?.tool_name,
      trace_id: params?.trace_id,
      matched_rule: params?.matched_rule,
      q: params?.q,
      since: params?.since,
      until: params?.until,
    }).toString()
    return request<{
      enabled?: boolean
      total?: number
      limit?: number
      offset?: number
      summary?: AuditQuerySummary
      events?: AuditEvent[]
      logs?: AuditEvent[]
    }>(
      `/admin/audit-logs${qs ? `?${qs}` : ''}`,
      { signal }
    )
  },
  getAuditLogsExportUrl: (format: 'csv' | 'jsonl', params?: AuditLogsQueryParams) => {
    const qs = buildQueryParams({
      format,
      decision: params?.decision,
      agent_name: params?.agent_name,
      tool_name: params?.tool_name,
      trace_id: params?.trace_id,
      matched_rule: params?.matched_rule,
      q: params?.q,
      since: params?.since,
      until: params?.until,
    }).toString()
    return `/admin/audit-logs/export?${qs}`
  },
  downloadAuditLogsExport: async (format: 'csv' | 'jsonl', params?: AuditLogsQueryParams) => {
    const url = api.getAuditLogsExportUrl(format, params)
    const res = await fetch(url, { credentials: 'include' })
    if (!res.ok) {
      dispatchUnauthorizedIfNeeded(res.status)
      throw new ProbeError(`Export failed: ${res.status} ${res.statusText}`, undefined, res.status)
    }
    const blob = await res.blob()
    const blobUrl = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = blobUrl
    anchor.download = format === 'csv' ? 'faradaiwire-audit.csv' : 'faradaiwire-audit.jsonl'
    document.body.appendChild(anchor)
    anchor.click()
    anchor.remove()
    URL.revokeObjectURL(blobUrl)
  },
  getAuditLogDetail: (id: string, signal?: AbortSignal) =>
    request<{ status: string; record: AuditEvent }>(`/admin/audit-logs/${encodeURIComponent(id)}`, { signal }),
  getSecurityAuditLogs: (params?: SecurityAuditQueryParams, signal?: AbortSignal) => {
    const qs = buildQueryParams({
      limit: params?.limit,
      offset: params?.offset,
      event_type: params?.event_type,
      actor_id: params?.actor_id,
      outcome: params?.outcome,
      since: params?.since,
      until: params?.until,
    }).toString()
    return request<{ enabled?: boolean; total: number; limit: number; offset: number; events: SecurityAuditRecord[] }>(
      `/admin/security-audit-logs${qs ? `?${qs}` : ''}`,
      { signal }
    )
  },
  getAnalyticsSummary: (window: AnalyticsWindow = '24h', signal?: AbortSignal) =>
    request<AnalyticsSummary>(`/admin/analytics/summary?window=${encodeURIComponent(window)}`, { signal }),
  verifyAuditIntegrity: (signal?: AbortSignal) =>
    request<AuditVerifyResponse>('/admin/audit/verify', { signal }),
  getReadyz: (signal?: AbortSignal) =>
    request<ReadyzResponse>('/admin/readyz', { signal }),

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
