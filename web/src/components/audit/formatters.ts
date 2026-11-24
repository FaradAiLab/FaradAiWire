import type {
  AuditEvent,
  AuditVerifyResponse,
} from '../../types.ts'

export type InspectorTab = 'payloads' | 'diff' | 'json' | 'raw'

export const PAGE_SIZE = 50
export const MAX_STREAM_ROWS = 500

const VERDICT_RANK: Record<string, number> = {
  PENDING: 0,
  ALLOWED: 1,
  AUDIT: 2,
  MASKED: 3,
  ERROR: 4,
  BLOCKED: 5,
  CRITICAL: 6,
}

export function mergeCompositeDecision(a?: string, b?: string): string {
  const ua = (a || '').toUpperCase()
  const ub = (b || '').toUpperCase()
  return (VERDICT_RANK[ub] ?? 0) >= (VERDICT_RANK[ua] ?? 0) ? ub || ua : ua
}

export function normalizeAuditEvent(raw: any): AuditEvent {
  if (!raw) {
    return {
      timestamp: new Date().toISOString(),
      event_type: 'UNKNOWN',
      severity: 'INFO',
    }
  }

  const rawDecision = (raw.decision || raw.action || '').toUpperCase()
  let decision = rawDecision
  let severity: 'DEBUG' | 'INFO' | 'WARN' | 'ERROR' | 'CRITICAL' | 'AUDIT' = raw.severity || 'INFO'

  if (rawDecision === 'CRITICAL' || raw.severity === 'CRITICAL') {
    severity = 'CRITICAL'
    decision = 'CRITICAL'
  } else if (rawDecision === 'AUDIT' || raw.severity === 'AUDIT') {
    severity = 'AUDIT'
    decision = 'AUDIT'
  } else if (rawDecision === 'BLOCKED' || rawDecision === 'DENIED') {
    severity = 'ERROR'
    decision = 'BLOCKED'
  } else if (rawDecision === 'ERROR' || raw.error_code || raw.error) {
    severity = 'ERROR'
    decision = rawDecision === 'ERROR' ? 'ERROR' : 'BLOCKED'
  } else if (rawDecision === 'MASKED' || raw.severity === 'WARN') {
    severity = 'WARN'
    decision = 'MASKED'
  } else if (rawDecision === 'PENDING') {
    severity = 'INFO'
    decision = 'PENDING'
  } else if (rawDecision === 'ALLOWED' || rawDecision === 'ALLOW' || raw.severity === 'INFO') {
    severity = 'INFO'
    decision = 'ALLOWED'
  } else {
    severity = raw.severity || 'INFO'
    decision = rawDecision || 'ALLOWED'
  }

  const event_type = raw.event_type || (raw.method ? `MCP ${raw.method}` : 'EVENT')
  const agent = raw.agent || raw.agent_name || raw.user_context?.agent_name || ''
  const layer = raw.layer || raw.filter_name || raw.path_type || ''
  const error =
    raw.error ||
    raw.error_message ||
    (decision === 'BLOCKED' ? raw.message || raw.matched_rule : undefined)

  const payload_preview =
    raw.raw_payload_preview ||
    raw.payload_preview ||
    raw.details?.raw_payload_preview ||
    raw.details?.payload_preview ||
    ''

  const original_payload =
    raw.original_payload_preview ||
    raw.original_payload ||
    raw.details?.original_payload_preview ||
    raw.details?.original_payload ||
    ''

  const matched_rule = raw.matched_rule || raw.details?.matched_rule || ''

  let audited_rules: string[] = []
  if (Array.isArray(raw.audited_rules)) {
    audited_rules = raw.audited_rules
  } else if (raw.details?.audited_rules && Array.isArray(raw.details.audited_rules)) {
    audited_rules = raw.details.audited_rules
  }

  let latency_ms: number | undefined = undefined
  if (typeof raw.latency_ms === 'number') {
    latency_ms = raw.latency_ms
  } else if (typeof raw.details?.latency_ms === 'number') {
    latency_ms = raw.details.latency_ms
  }

  let details = raw.details
  if (!details) {
    const extra: Record<string, unknown> = {}
    if (raw.message && decision !== 'BLOCKED') extra.message = raw.message
    if (matched_rule) extra.matched_rule = matched_rule
    if (audited_rules.length > 0) extra.audited_rules = audited_rules
    if (latency_ms !== undefined) extra.latency_ms = `${latency_ms}ms`
    if (raw.error_code) extra.error_code = raw.error_code
    if (raw.caller_role) extra.role = raw.caller_role
    if (payload_preview) extra.payload_preview = payload_preview
    if (original_payload) extra.original_payload = original_payload
    if (Object.keys(extra).length > 0) details = extra
  }

  return {
    id: raw.id || raw.trace_id,
    timestamp: raw.timestamp || new Date().toISOString(),
    trace_id: raw.trace_id,
    method: raw.method,
    event_type,
    severity,
    decision,
    layer,
    action: raw.action || decision,
    agent,
    client_session_id: raw.client_session_id,
    tool_name: raw.tool_name,
    phase: raw.phase,
    request_decision: raw.request_decision,
    response_decision: raw.response_decision,
    matched_rule,
    audited_rules,
    latency_ms,
    input_size_bytes: raw.input_size_bytes,
    output_size_bytes: raw.output_size_bytes,
    payload_preview,
    raw_payload_preview: payload_preview,
    original_payload,
    original_payload_preview: original_payload,
    original_request: raw.original_request,
    request: raw.request,
    original_response: raw.original_response,
    response: raw.response,
    error_message: raw.error_message,
    details,
    error,
    user_id: raw.user_id,
    client_ip: raw.client_ip,
    api_key_id: raw.api_key_id,
    human_approved: raw.human_approved,
    approved_by: raw.approved_by,
    approval_channel: raw.approval_channel,
    hash_version: raw.hash_version,
    integrity_hash: raw.integrity_hash,
  }
}

export function getRowKey(ev: AuditEvent, fallbackIdx = 0): string {
  return ev.id || ev.trace_id || `ev-${fallbackIdx}`
}

const PROTOCOL_METHOD_NAMES = new Set(['tools/list', 'tools/call', 'initialize', 'ping', 'response'])

export function getEventTargetLabel(ev: AuditEvent): { kind: 'tool' | 'method' | 'event'; label: string } {
  const toolName = (ev.tool_name || '').trim()
  if (toolName) {
    if (PROTOCOL_METHOD_NAMES.has(toolName) || toolName.includes('/')) {
      return { kind: 'method', label: `method:${toolName}` }
    }
    return { kind: 'tool', label: `tool:${toolName}` }
  }
  const method = (ev.method || '').trim()
  if (method) {
    return { kind: 'method', label: `method:${method}` }
  }
  return { kind: 'event', label: ev.event_type || 'EVENT' }
}

export function formatSmartDate(isoString: string): { display: string; iso: string } {
  try {
    const date = new Date(isoString)
    if (isNaN(date.getTime())) {
      return { display: isoString, iso: isoString }
    }
    const now = new Date()
    const isToday = date.toDateString() === now.toDateString()

    const yesterday = new Date(now)
    yesterday.setDate(yesterday.getDate() - 1)
    const isYesterday = date.toDateString() === yesterday.toDateString()

    const timeStr = date.toLocaleTimeString(undefined, {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    })

    if (isToday) {
      return { display: `Today, ${timeStr}`, iso: date.toISOString() }
    }
    if (isYesterday) {
      return { display: `Yesterday, ${timeStr}`, iso: date.toISOString() }
    }
    const dateStr = date.toLocaleDateString(undefined, {
      day: 'numeric',
      month: 'short',
    })
    return { display: `${dateStr}, ${timeStr}`, iso: date.toISOString() }
  } catch {
    return { display: isoString, iso: isoString }
  }
}

export function parsePayloadContent(raw: string | undefined): {
  displayText: string
  formattedJson: string
  isJson: boolean
} {
  if (!raw || !raw.trim()) {
    return {
      displayText: '(Empty payload)',
      formattedJson: '',
      isJson: false,
    }
  }

  try {
    const parsed = JSON.parse(raw)
    const formattedJson = JSON.stringify(parsed, null, 2)

    if (parsed && Array.isArray(parsed.content)) {
      const textParts = parsed.content
        .filter((item: any) => item && item.type === 'text' && typeof item.text === 'string')
        .map((item: any) => item.text)

      if (textParts.length > 0) {
        return {
          displayText: textParts.join('\n\n'),
          formattedJson,
          isJson: true,
        }
      }
    }

    if (parsed && parsed.name && parsed.arguments) {
      return {
        displayText: `Tool: ${parsed.name}\nArguments:\n${JSON.stringify(parsed.arguments, null, 2)}`,
        formattedJson,
        isJson: true,
      }
    }

    return {
      displayText: formattedJson,
      formattedJson,
      isJson: true,
    }
  } catch {
    return {
      displayText: raw,
      formattedJson: raw,
      isJson: false,
    }
  }
}

export function getCopyableContent(
  ev: AuditEvent,
  activeTab: InspectorTab,
  formattedDiffText?: string
): string {
  if (activeTab === 'raw') {
    return JSON.stringify(ev, null, 2)
  }

  if (activeTab === 'diff') {
    if (formattedDiffText && formattedDiffText.trim()) {
      return formattedDiffText
    }
    const blocks: string[] = []
    if (ev.original_request || ev.request) {
      blocks.push(`--- Original Request\n${ev.original_request || ''}\n+++ Dispatched Request\n${ev.request || ev.original_request || ''}`)
    }
    if (ev.original_response || ev.response) {
      blocks.push(`--- Original Response\n${ev.original_response || ''}\n+++ Final Response\n${ev.response || ev.original_response || ''}`)
    }
    if (blocks.length > 0) return blocks.join('\n\n')
    if (ev.original_payload || ev.payload_preview) {
      return `--- Original\n${ev.original_payload || ''}\n+++ Processed\n${ev.payload_preview || ''}`
    }
    return 'No mutation diff available.'
  }

  const hasFourFields = Boolean(ev.original_request || ev.request || ev.original_response || ev.response)

  if (activeTab === 'json') {
    if (hasFourFields) {
      const reqJson = parsePayloadContent(ev.request || ev.original_request).formattedJson || 'null'
      const respJson = parsePayloadContent(ev.response || ev.original_response).formattedJson || 'null'
      return JSON.stringify(
        {
          request: safeJsonOrString(reqJson),
          response: safeJsonOrString(respJson),
        },
        null,
        2
      )
    }
    const parsed = parsePayloadContent(ev.payload_preview)
    return parsed.formattedJson || ev.payload_preview || ''
  }

  // 'payloads'
  if (hasFourFields) {
    const sections: string[] = []
    if (ev.original_request) {
      sections.push(`=== Request (Original) ===\n${parsePayloadContent(ev.original_request).displayText}`)
    }
    if (ev.request && ev.request !== ev.original_request) {
      sections.push(`=== Request (Dispatched Upstream) ===\n${parsePayloadContent(ev.request).displayText}`)
    }
    if (ev.original_response) {
      sections.push(`=== Response (Original Upstream) ===\n${parsePayloadContent(ev.original_response).displayText}`)
    }
    if (ev.response && ev.response !== ev.original_response) {
      sections.push(`=== Response (Final Client) ===\n${parsePayloadContent(ev.response).displayText}`)
    }
    return sections.join('\n\n')
  }

  return parsePayloadContent(ev.payload_preview).displayText
}

function safeJsonOrString(raw: string): unknown {
  try {
    return JSON.parse(raw)
  } catch {
    return raw
  }
}

export function toRFC3339LocalInput(localVal: string): string | undefined {
  if (!localVal.trim()) return undefined
  const parsed = new Date(localVal)
  if (Number.isNaN(parsed.getTime())) return undefined
  return parsed.toISOString()
}

export interface DuckDBVerifyTotals {
  checked: number
  v2_verified: number
  legacy_v1: number
  tampered_ids: string[]
}

export function summarizeDuckDBVerify(
  duckdb: NonNullable<AuditVerifyResponse['duckdb']>
): DuckDBVerifyTotals {
  const tables = [
    duckdb.tool_audit_logs,
    duckdb.tool_audit_responses,
    duckdb.security_audit_logs,
  ].filter(Boolean)

  return tables.reduce<DuckDBVerifyTotals>(
    (acc, tbl) => ({
      checked: acc.checked + (tbl?.checked ?? 0),
      v2_verified: acc.v2_verified + (tbl?.v2_verified ?? 0),
      legacy_v1: acc.legacy_v1 + (tbl?.legacy_v1 ?? 0),
      tampered_ids: acc.tampered_ids.concat(tbl?.tampered_ids ?? []),
    }),
    { checked: 0, v2_verified: 0, legacy_v1: 0, tampered_ids: [] }
  )
}
