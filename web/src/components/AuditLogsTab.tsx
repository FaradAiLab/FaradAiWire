import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react'
import {
  ScrollText,
  Pause,
  Play,
  Trash2,
  ArrowDown,
  Search,
  Radio,
  ShieldCheck,
  ShieldAlert,
  Shield,
  Eye,
  Lock,
  Copy,
  Check,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  FileText,
  Columns,
  Rows,
  Sparkles,
  Clock,
  Layers,
  Cpu,
  RefreshCw,
  Download,
  AlertTriangle,
  CheckCircle2,
  KeyRound,
} from 'lucide-react'
import {
  AuditEvent,
  AuditLogsQueryParams,
  AuditVerifyResponse,
  SecurityAuditRecord,
} from '../types'
import { api } from '../api'

export type AuditSubTab = 'invocations' | 'security'

export interface AuditLogsTabProps {
  initialSubTab?: AuditSubTab
  onSubTabChange?: (subTab: AuditSubTab) => void
}

function normalizeAuditEvent(raw: any): AuditEvent {
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

const VERDICT_RANK: Record<string, number> = {
  PENDING: 0,
  ALLOWED: 1,
  AUDIT: 2,
  MASKED: 3,
  ERROR: 4,
  BLOCKED: 5,
  CRITICAL: 6,
}

function mergeCompositeDecision(a?: string, b?: string): string {
  const ua = (a || '').toUpperCase()
  const ub = (b || '').toUpperCase()
  return (VERDICT_RANK[ub] ?? 0) >= (VERDICT_RANK[ua] ?? 0) ? ub || ua : ua
}

function formatSmartDate(isoString: string): { display: string; iso: string } {
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
    } else if (isYesterday) {
      return { display: `Yesterday, ${timeStr}`, iso: date.toISOString() }
    } else {
      const dateStr = date.toLocaleDateString(undefined, {
        day: 'numeric',
        month: 'short',
      })
      return { display: `${dateStr}, ${timeStr}`, iso: date.toISOString() }
    }
  } catch {
    return { display: isoString, iso: isoString }
  }
}

function parsePayloadContent(raw: string | undefined): {
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

    // Case 1: MCP Tool Response with content array
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

    // Case 2: MCP Tool Call with name & arguments
    if (parsed && parsed.name && parsed.arguments) {
      return {
        displayText: `Tool: ${parsed.name}\nArguments:\n${JSON.stringify(parsed.arguments, null, 2)}`,
        formattedJson,
        isJson: true,
      }
    }

    // Default JSON
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

function renderHighlightedText(text: string) {
  // Regex to capture semantic placeholders e.g. [REDACTED:TCKN], [REDACTED:CREDIT_CARD], [REDACTED]
  const parts = text.split(/(\[REDACTED(?::[A-Za-z0-9_-]+)?\])/g)

  return (
    <span className="whitespace-pre-wrap leading-relaxed">
      {parts.map((part, i) => {
        if (/^\[REDACTED(?::[A-Za-z0-9_-]+)?\]$/.test(part)) {
          return (
            <span
              key={i}
              className="inline-flex items-center gap-1 px-1.5 py-0.5 mx-0.5 rounded text-[11px] font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40 shadow-sm"
              title="DLP Semantic Redaction"
            >
              <Lock className="w-2.5 h-2.5 text-amber-400" />
              {part}
            </span>
          )
        }
        return <span key={i}>{part}</span>
      })}
    </span>
  )
}

const PAGE_SIZE = 50

function toRFC3339LocalInput(localVal: string): string | undefined {
  if (!localVal.trim()) return undefined
  const parsed = new Date(localVal)
  if (Number.isNaN(parsed.getTime())) return undefined
  return parsed.toISOString()
}

interface DuckDBVerifyTotals {
  checked: number
  v2_verified: number
  legacy_v1: number
  tampered_ids: string[]
}

function summarizeDuckDBVerify(duckdb: NonNullable<AuditVerifyResponse['duckdb']>): DuckDBVerifyTotals {
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

export const AuditLogsTab: React.FC<AuditLogsTabProps> = ({
  initialSubTab = 'invocations',
  onSubTabChange,
}) => {
  const [activeSubTab, setActiveSubTab] = useState<AuditSubTab>(initialSubTab)
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [totalCount, setTotalCount] = useState(0)
  const [offset, setOffset] = useState(0)
  const [isConnected, setIsConnected] = useState(false)
  const [isPaused, setIsPaused] = useState(false)
  const [autoScroll, setAutoScroll] = useState(true)
  const [filterText, setFilterText] = useState('')
  const [matchedRuleFilter, setMatchedRuleFilter] = useState('')
  const [sinceInput, setSinceInput] = useState('')
  const [untilInput, setUntilInput] = useState('')
  const [selectedVerdict, setSelectedVerdict] = useState<string>('ALL')
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set())
  const [activeTabs, setActiveTabs] = useState<Record<string, 'text' | 'diff' | 'json' | 'raw'>>({})
  const [diffLayout, setDiffLayout] = useState<'split' | 'stacked'>('split')
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const [detailLoadingIds, setDetailLoadingIds] = useState<Set<string>>(new Set())
  const [loadedDetailIds, setLoadedDetailIds] = useState<Set<string>>(new Set())

  // Integrity Verification, Export & Query Error state
  const [verifying, setVerifying] = useState(false)
  const [verifyResult, setVerifyResult] = useState<AuditVerifyResponse | null>(null)
  const [verifyError, setVerifyError] = useState<string | null>(null)
  const [exportError, setExportError] = useState<string | null>(null)
  const [queryError, setQueryError] = useState<string | null>(null)
  const [exportingFormat, setExportingFormat] = useState<'csv' | 'jsonl' | null>(null)

  // Security Events sub-tab state
  const [securityEvents, setSecurityEvents] = useState<SecurityAuditRecord[]>([])
  const [securityTotal, setSecurityTotal] = useState(0)
  const [securityOffset, setSecurityOffset] = useState(0)
  const [secEventType, setSecEventType] = useState('')
  const [secActorID, setSecActorID] = useState('')
  const [secOutcome, setSecOutcome] = useState('')
  const [secSinceInput, setSecSinceInput] = useState('')
  const [secUntilInput, setSecUntilInput] = useState('')
  const [securityLoading, setSecurityLoading] = useState(false)

  const logContainerRef = useRef<HTMLDivElement>(null)
  const eventSourceRef = useRef<EventSource | null>(null)

  useEffect(() => {
    if (initialSubTab && initialSubTab !== activeSubTab) {
      setActiveSubTab(initialSubTab)
    }
  }, [initialSubTab, activeSubTab])

  const handleSelectSubTab = (tab: AuditSubTab) => {
    setActiveSubTab(tab)
    setQueryError(null)
    if (onSubTabChange) {
      onSubTabChange(tab)
    }
  }

  const isHistoricalMode = useMemo(() => {
    return offset > 0 || Boolean(sinceInput) || Boolean(untilInput)
  }, [offset, sinceInput, untilInput])

  const buildServerFilterParams = useCallback((): AuditLogsQueryParams => {
    return {
      summary: true,
      limit: PAGE_SIZE,
      offset,
      decision: selectedVerdict !== 'ALL' ? selectedVerdict : undefined,
      matched_rule: matchedRuleFilter.trim() || undefined,
      q: filterText.trim() || undefined,
      since: toRFC3339LocalInput(sinceInput),
      until: toRFC3339LocalInput(untilInput),
    }
  }, [offset, selectedVerdict, matchedRuleFilter, filterText, sinceInput, untilInput])

  // Historical logs query from DuckDB
  const fetchHistoricalLogs = useCallback(
    (signal?: AbortSignal) => {
      setLoadedDetailIds(new Set())
      setQueryError(null)
      api
        .getAuditLogs(buildServerFilterParams(), signal)
        .then((res) => {
          if (signal?.aborted) return
          const list = res?.events || res?.logs || []
          if (Array.isArray(list)) {
            setEvents(list.map(normalizeAuditEvent))
          }
          setTotalCount(typeof res?.total === 'number' ? res.total : list.length)
        })
        .catch((err: unknown) => {
          if (signal?.aborted || (err instanceof Error && err.name === 'AbortError')) {
            return
          }
          setQueryError(err instanceof Error ? err.message : 'Failed to query audit logs')
        })
    },
    [buildServerFilterParams]
  )

  const fetchSecurityEvents = useCallback(
    (signal?: AbortSignal) => {
      setSecurityLoading(true)
      setQueryError(null)
      api
        .getSecurityAuditLogs(
          {
            limit: PAGE_SIZE,
            offset: securityOffset,
            event_type: secEventType.trim() || undefined,
            actor_id: secActorID.trim() || undefined,
            outcome: secOutcome || undefined,
            since: toRFC3339LocalInput(secSinceInput),
            until: toRFC3339LocalInput(secUntilInput),
          },
          signal
        )
        .then((res) => {
          if (signal?.aborted) return
          setSecurityEvents(Array.isArray(res?.events) ? res.events : [])
          setSecurityTotal(typeof res?.total === 'number' ? res.total : 0)
        })
        .catch((err: unknown) => {
          if (signal?.aborted || (err instanceof Error && err.name === 'AbortError')) {
            return
          }
          setSecurityEvents([])
          setQueryError(err instanceof Error ? err.message : 'Failed to query security audit events')
        })
        .finally(() => {
          if (!signal?.aborted) {
            setSecurityLoading(false)
          }
        })
    },
    [securityOffset, secEventType, secActorID, secOutcome, secSinceInput, secUntilInput]
  )

  useEffect(() => {
    const abortController = new AbortController()
    const timer = window.setTimeout(() => {
      if (activeSubTab === 'invocations') {
        fetchHistoricalLogs(abortController.signal)
      } else {
        fetchSecurityEvents(abortController.signal)
      }
    }, 150)
    return () => {
      window.clearTimeout(timer)
      abortController.abort()
    }
  }, [activeSubTab, fetchHistoricalLogs, fetchSecurityEvents])

  // Setup SSE stream (automatically paused when viewing historical/paginated view or Security Events)
  useEffect(() => {
    if (isPaused || isHistoricalMode || activeSubTab !== 'invocations') {
      if (eventSourceRef.current) {
        eventSourceRef.current.close()
        eventSourceRef.current = null
      }
      setIsConnected(false)
      return
    }

    const es = new EventSource('/admin/audit-logs/events')
    eventSourceRef.current = es

    const handleBatch = (rawBatch: any) => {
      try {
        const list = Array.isArray(rawBatch) ? rawBatch : [rawBatch]
        const normalized = list.map(normalizeAuditEvent)
        const updatedKeys: string[] = []

        setEvents((prev) => {
          const next = [...prev]
          for (const item of normalized) {
            const key = item.id || item.trace_id
            const matchIdx = item.id
              ? next.findIndex((e) => e.id === item.id)
              : item.trace_id
              ? next.findIndex((e) => !e.id && e.trace_id === item.trace_id)
              : -1
            if (matchIdx >= 0 && (item.phase === 'response' || item.phase === 'complete')) {
              const existing = next[matchIdx]
              const mergedDec = mergeCompositeDecision(existing.request_decision || existing.decision, item.decision)
              const mergedRule =
                existing.matched_rule && item.matched_rule && existing.matched_rule !== item.matched_rule
                  ? `${existing.matched_rule},${item.matched_rule}`
                  : item.matched_rule || existing.matched_rule
              next[matchIdx] = {
                ...existing,
                decision: mergedDec,
                severity:
                  mergedDec === 'CRITICAL'
                    ? 'CRITICAL'
                    : mergedDec === 'BLOCKED' || mergedDec === 'ERROR'
                    ? 'ERROR'
                    : mergedDec === 'MASKED'
                    ? 'WARN'
                    : mergedDec === 'AUDIT'
                    ? 'AUDIT'
                    : existing.severity,
                response_decision: item.response_decision || item.decision,
                matched_rule: mergedRule,
                latency_ms: (existing.latency_ms || 0) + (item.latency_ms || 0),
                error: item.error || existing.error,
                error_message: item.error_message || existing.error_message,
                payload_preview: item.payload_preview || existing.payload_preview,
              }
              if (key) updatedKeys.push(key)
            } else if (matchIdx >= 0) {
              // Deduplicate repeated request-phase broadcasts for the same invocation ID
              next[matchIdx] = { ...next[matchIdx], ...item }
            } else {
              next.push(item)
            }
          }
          return next.slice(-500)
        })

        if (updatedKeys.length > 0) {
          setLoadedDetailIds((prev) => {
            const copy = new Set(prev)
            updatedKeys.forEach((k) => copy.delete(k))
            return copy
          })
        }
      } catch (err) {
        console.error('Failed to parse audit batch', err)
      }
    }

    es.onopen = () => {
      setIsConnected(true)
    }

    es.onerror = () => {
      setIsConnected(false)
    }

    es.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data)
        handleBatch(data)
      } catch {
        // ignore non-json heartbeats
      }
    }

    es.addEventListener('audit_batch', (e: MessageEvent) => {
      try {
        const data = JSON.parse(e.data)
        handleBatch(data)
      } catch {
        // ignore non-json
      }
    })

    return () => {
      es.close()
      eventSourceRef.current = null
    }
  }, [isPaused, isHistoricalMode, activeSubTab])

  const handleResumeLive = () => {
    setOffset(0)
    setSinceInput('')
    setUntilInput('')
    setMatchedRuleFilter('')
    setIsPaused(false)
  }

  const handleVerifyIntegrity = async () => {
    try {
      setVerifying(true)
      setVerifyError(null)
      const res = await api.verifyAuditIntegrity()
      setVerifyResult(res)
    } catch (err: unknown) {
      setVerifyError(err instanceof Error ? err.message : String(err))
    } finally {
      setVerifying(false)
    }
  }

  const handleExport = async (format: 'csv' | 'jsonl') => {
    try {
      setExportingFormat(format)
      setExportError(null)
      await api.downloadAuditLogsExport(format, buildServerFilterParams())
    } catch (err: unknown) {
      setExportError(err instanceof Error ? err.message : String(err))
    } finally {
      setExportingFormat(null)
    }
  }

  // Auto-scroll effect
  useEffect(() => {
    if (autoScroll && logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight
    }
  }, [events, autoScroll])

  const toggleRow = (rowKey: string, ev?: AuditEvent) => {
    const willExpand = !expandedIds.has(rowKey)
    setExpandedIds((prev) => {
      const next = new Set(prev)
      if (next.has(rowKey)) {
        next.delete(rowKey)
      } else {
        next.add(rowKey)
      }
      return next
    })

    const lookupId = ev?.id || ev?.trace_id
    if (willExpand && lookupId && !loadedDetailIds.has(rowKey) && !detailLoadingIds.has(rowKey)) {
      setDetailLoadingIds((prev) => new Set(prev).add(rowKey))
      api
        .getAuditLogDetail(lookupId)
        .then((res) => {
          if (res?.record) {
            const detailed = normalizeAuditEvent(res.record)
            setEvents((prev) =>
              prev.map((item) => {
                const itemKey = item.id || item.trace_id
                return itemKey === rowKey || item.id === lookupId ? { ...item, ...detailed } : item
              })
            )
          }
          setLoadedDetailIds((prev) => new Set(prev).add(rowKey))
        })
        .catch(() => {
          // Graceful fallback to summary payload already present in row
        })
        .finally(() => {
          setDetailLoadingIds((prev) => {
            const copy = new Set(prev)
            copy.delete(rowKey)
            return copy
          })
        })
    }
  }

  const setTabForEvent = (id: string, tab: 'text' | 'diff' | 'json' | 'raw') => {
    setActiveTabs((prev) => ({ ...prev, [id]: tab }))
  }

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopiedId(id)
      setTimeout(() => setCopiedId(null), 2000)
    })
  }

  // Metrics computation
  const metrics = useMemo(() => {
    let allowed = 0
    let masked = 0
    let audit = 0
    let blocked = 0
    let totalLatency = 0
    let latencyCount = 0

    events.forEach((ev) => {
      const dec = (ev.decision || '').toUpperCase()
      if (dec === 'BLOCKED' || dec === 'CRITICAL' || dec === 'ERROR' || ev.severity === 'ERROR' || ev.severity === 'CRITICAL') blocked++
      else if (dec === 'MASKED' || ev.severity === 'WARN') masked++
      else if (dec === 'AUDIT' || ev.severity === 'AUDIT') audit++
      else if (dec !== 'PENDING') allowed++

      if (typeof ev.latency_ms === 'number' && ev.latency_ms >= 0) {
        totalLatency += ev.latency_ms
        latencyCount++
      }
    })

    return {
      total: events.length,
      allowed,
      masked,
      audit,
      blocked,
      avgLatency: latencyCount > 0 ? Math.round(totalLatency / latencyCount) : 0,
    }
  }, [events])

  // Filtering
  const filteredEvents = useMemo(() => {
    const ruleQuery = matchedRuleFilter.trim().toLowerCase()
    return events.filter((ev) => {
      const dec = (ev.decision || '').toUpperCase()

      if (selectedVerdict !== 'ALL') {
        if (selectedVerdict === 'ALLOWED' && dec !== 'ALLOWED') return false
        if (selectedVerdict === 'MASKED' && dec !== 'MASKED') return false
        if (selectedVerdict === 'AUDIT' && dec !== 'AUDIT') return false
        if (selectedVerdict === 'BLOCKED' && dec !== 'BLOCKED' && dec !== 'ERROR' && dec !== 'CRITICAL') return false
      }

      if (ruleQuery) {
        const matched = (ev.matched_rule || '').toLowerCase().includes(ruleQuery)
        const audited = Boolean(ev.audited_rules && ev.audited_rules.some((r) => r.toLowerCase().includes(ruleQuery)))
        if (!matched && !audited) return false
      }

      if (!filterText.trim()) return true

      const searchLower = filterText.toLowerCase()
      return (
        (ev.event_type && ev.event_type.toLowerCase().includes(searchLower)) ||
        (ev.agent && ev.agent.toLowerCase().includes(searchLower)) ||
        (ev.tool_name && ev.tool_name.toLowerCase().includes(searchLower)) ||
        (ev.layer && ev.layer.toLowerCase().includes(searchLower)) ||
        (ev.matched_rule && ev.matched_rule.toLowerCase().includes(searchLower)) ||
        (ev.audited_rules && ev.audited_rules.some((r) => r.toLowerCase().includes(searchLower))) ||
        (ev.trace_id && ev.trace_id.toLowerCase().includes(searchLower)) ||
        (ev.payload_preview && ev.payload_preview.toLowerCase().includes(searchLower)) ||
        (ev.error && ev.error.toLowerCase().includes(searchLower))
      )
    })
  }, [events, selectedVerdict, matchedRuleFilter, filterText])

  const getVerdictStyle = (decision: string) => {
    switch (decision?.toUpperCase()) {
      case 'CRITICAL':
        return {
          badge:
            'bg-red-100 dark:bg-red-950/90 text-red-800 dark:text-red-200 border-red-300 dark:border-red-700/70 shadow-sm',
          indicator: 'bg-red-600',
          icon: ShieldAlert,
          label: 'CRITICAL',
        }
      case 'ERROR':
        return {
          badge:
            'bg-orange-50 dark:bg-orange-950/80 text-orange-800 dark:text-orange-300 border-orange-200 dark:border-orange-700/60 shadow-sm',
          indicator: 'bg-orange-500',
          icon: ShieldAlert,
          label: 'ERROR',
        }
      case 'BLOCKED':
        return {
          badge:
            'bg-rose-50 dark:bg-rose-950/80 text-rose-700 dark:text-rose-300 border-rose-200 dark:border-rose-700/50 shadow-sm',
          indicator: 'bg-rose-500',
          icon: ShieldAlert,
          label: 'BLOCKED',
        }
      case 'MASKED':
        return {
          badge:
            'bg-amber-50 dark:bg-amber-950/80 text-amber-800 dark:text-amber-300 border-amber-200 dark:border-amber-700/50 shadow-sm',
          indicator: 'bg-amber-500',
          icon: Lock,
          label: 'MASKED',
        }
      case 'AUDIT':
        return {
          badge:
            'bg-purple-50 dark:bg-purple-950/80 text-purple-700 dark:text-purple-300 border-purple-200 dark:border-purple-700/50 shadow-sm',
          indicator: 'bg-purple-500',
          icon: Eye,
          label: 'AUDIT',
        }
      case 'PENDING':
        return {
          badge:
            'bg-sky-50 dark:bg-sky-950/80 text-sky-700 dark:text-sky-300 border-sky-200 dark:border-sky-700/50 shadow-sm',
          indicator: 'bg-sky-500',
          icon: Clock,
          label: 'PENDING',
        }
      case 'ALLOWED':
      default:
        return {
          badge:
            'bg-emerald-50 dark:bg-emerald-950/80 text-emerald-800 dark:text-emerald-300 border-emerald-200 dark:border-emerald-700/50 shadow-sm',
          indicator: 'bg-emerald-500',
          icon: ShieldCheck,
          label: 'ALLOWED',
        }
    }
  }

  return (
    <div className="space-y-4">
      {/* 1. Header Toolbar + Sub-Tab Switcher */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="space-y-2">
          <div>
            <h2 className="text-xl font-bold text-primary flex items-center gap-2">
              <ScrollText className="w-5 h-5 text-accent" />
              Audit & Security Console
            </h2>
            <p className="text-xs text-muted mt-1">
              Real-time MCP tool invocation telemetry, control-plane security events, cryptographic chain verification, and redacted export.
            </p>
          </div>

          <div
            role="tablist"
            aria-label="Audit Log Views"
            className="inline-flex items-center p-1 rounded-xl bg-surface border border-subtle shadow-sm"
          >
            <button
              id="audit-tab-invocations"
              type="button"
              role="tab"
              aria-selected={activeSubTab === 'invocations'}
              aria-controls="audit-panel-invocations"
              onClick={() => handleSelectSubTab('invocations')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/50 ${
                activeSubTab === 'invocations'
                  ? 'bg-accent/15 text-accent border border-accent/30 shadow-sm'
                  : 'text-muted hover:text-primary'
              }`}
            >
              <ScrollText className="w-3.5 h-3.5" />
              <span>Tool Invocations</span>
            </button>
            <button
              id="audit-tab-security"
              type="button"
              role="tab"
              aria-selected={activeSubTab === 'security'}
              aria-controls="audit-panel-security"
              onClick={() => handleSelectSubTab('security')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/50 ${
                activeSubTab === 'security'
                  ? 'bg-accent/15 text-accent border border-accent/30 shadow-sm'
                  : 'text-muted hover:text-primary'
              }`}
            >
              <KeyRound className="w-3.5 h-3.5" />
              <span>Security Events</span>
            </button>
          </div>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          {activeSubTab === 'invocations' && (
            <>
              {/* Connection Status indicator */}
              <div
                role="status"
                aria-live="polite"
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-mono font-semibold bg-surface border border-subtle text-primary shadow-sm"
              >
                <Radio
                  className={`w-3.5 h-3.5 ${
                    isHistoricalMode || isPaused
                      ? 'text-amber-500'
                      : isConnected
                      ? 'text-emerald-500 animate-pulse motion-reduce:animate-none'
                      : 'text-amber-500 animate-bounce motion-reduce:animate-none'
                  }`}
                />
                <span>
                  {isHistoricalMode ? 'HISTORICAL' : isPaused ? 'PAUSED' : isConnected ? 'LIVE STREAM' : 'CONNECTING'}
                </span>
              </div>

              {/* Pause / Resume */}
              <button
                type="button"
                onClick={() => {
                  if (isHistoricalMode) {
                    handleResumeLive()
                  } else {
                    setIsPaused(!isPaused)
                  }
                }}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-surface hover:bg-subtle text-primary border border-subtle transition-colors shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/50"
              >
                {isPaused || isHistoricalMode ? (
                  <Play className="w-3.5 h-3.5 text-emerald-500" />
                ) : (
                  <Pause className="w-3.5 h-3.5 text-amber-500" />
                )}
                <span>{isPaused || isHistoricalMode ? 'Resume Live' : 'Pause'}</span>
              </button>

              {/* Export CSV & JSONL */}
              <button
                type="button"
                onClick={() => handleExport('csv')}
                disabled={exportingFormat !== null}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-surface hover:bg-subtle text-primary border border-subtle transition-colors shadow-sm disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/50"
                title="Download redacted CSV export (respects active filters)"
              >
                <Download className="w-3.5 h-3.5 text-cyan-500" />
                <span>{exportingFormat === 'csv' ? 'Exporting…' : 'Export CSV'}</span>
              </button>
              <button
                type="button"
                onClick={() => handleExport('jsonl')}
                disabled={exportingFormat !== null}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-surface hover:bg-subtle text-primary border border-subtle transition-colors shadow-sm disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/50"
                title="Download redacted JSONL export (respects active filters)"
              >
                <Download className="w-3.5 h-3.5 text-indigo-500" />
                <span>{exportingFormat === 'jsonl' ? 'Exporting…' : 'Export JSONL'}</span>
              </button>
            </>
          )}

          {/* Verify Integrity */}
          <button
            type="button"
            onClick={handleVerifyIntegrity}
            disabled={verifying}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-emerald-50 hover:bg-emerald-100 text-emerald-800 border border-emerald-300 dark:bg-emerald-950/50 dark:hover:bg-emerald-900/50 dark:text-emerald-300 dark:border-emerald-500/30 transition-colors shadow-sm disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500/50"
            title="Verify SHA-256 / HMAC-SHA256 tamper-evidence chains across DuckDB and JSONL"
          >
            <ShieldCheck className={`w-3.5 h-3.5 ${verifying ? 'animate-spin motion-reduce:animate-none' : ''}`} />
            <span>{verifying ? 'Verifying…' : 'Verify Integrity'}</span>
          </button>

          {/* Refresh from DuckDB */}
          <button
            type="button"
            onClick={() => (activeSubTab === 'invocations' ? fetchHistoricalLogs() : fetchSecurityEvents())}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-surface hover:bg-subtle text-primary border border-subtle transition-colors shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/50"
            title="Refresh logs from DuckDB"
          >
            <RefreshCw className="w-3.5 h-3.5 text-accent" />
            <span>Refresh</span>
          </button>

          {activeSubTab === 'invocations' && (
            <>
              {/* Auto Scroll */}
              <button
                type="button"
                aria-pressed={autoScroll}
                onClick={() => setAutoScroll(!autoScroll)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold border transition-colors shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/50 ${
                  autoScroll
                    ? 'bg-accent/15 border-accent/40 text-accent font-bold'
                    : 'bg-surface border-subtle text-muted hover:text-primary'
                }`}
              >
                <ArrowDown className="w-3.5 h-3.5" />
                <span>Auto-Scroll</span>
              </button>

              {/* Clear Logs */}
              <button
                type="button"
                aria-label="Clear logs from screen"
                onClick={() => setEvents([])}
                className="p-2 rounded-xl text-muted hover:text-rose-500 hover:bg-rose-50 dark:hover:bg-rose-950/30 border border-subtle transition-colors shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-500/50"
                title="Clear logs from screen"
              >
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            </>
          )}
        </div>
      </div>

      {/* Integrity Verification, Export & Query Error Banners */}
      {(verifyError || exportError || queryError) && (
        <div
          role="alert"
          className="p-3.5 rounded-xl border bg-rose-50 text-rose-800 border-rose-200 dark:bg-rose-950/40 dark:border-rose-500/30 dark:text-rose-300 text-xs flex items-center justify-between gap-3"
        >
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{verifyError || exportError || queryError}</span>
          </div>
          <div className="flex items-center gap-2">
            {queryError && (
              <button
                type="button"
                onClick={() => (activeSubTab === 'invocations' ? fetchHistoricalLogs() : fetchSecurityEvents())}
                className="px-2 py-0.5 rounded bg-rose-100 hover:bg-rose-200 dark:bg-rose-900/50 font-semibold text-[11px]"
              >
                Retry
              </button>
            )}
            <button
              type="button"
              onClick={() => {
                setVerifyError(null)
                setExportError(null)
                setQueryError(null)
              }}
              className="underline text-[11px]"
            >
              Dismiss
            </button>
          </div>
        </div>
      )}

      {verifyResult && (
        <div
          role="status"
          aria-live="polite"
          className={`p-4 rounded-xl border text-xs flex flex-wrap items-center justify-between gap-3 shadow-sm ${
            verifyResult.valid
              ? 'bg-emerald-50 text-emerald-900 border-emerald-200 dark:bg-emerald-950/40 dark:border-emerald-500/30 dark:text-emerald-200'
              : 'bg-rose-50 text-rose-900 border-rose-200 dark:bg-rose-950/40 dark:border-rose-500/30 dark:text-rose-200'
          }`}
        >
          <div className="flex items-start gap-2.5">
            {verifyResult.valid ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0 mt-0.5" />
            ) : (
              <AlertTriangle className="w-4 h-4 text-rose-600 dark:text-rose-400 shrink-0 mt-0.5" />
            )}
            <div className="space-y-1 font-mono">
              <div className="font-bold">
                Audit Integrity: {verifyResult.valid ? 'VERIFIED (VALID)' : 'TAMPERING DETECTED'}
              </div>
              <div className="text-[11px] flex flex-wrap gap-3">
                {verifyResult.duckdb && (() => {
                  const dbStats = summarizeDuckDBVerify(verifyResult.duckdb)
                  return (
                    <span>
                      DuckDB checked={dbStats.checked} · v2_verified={dbStats.v2_verified} · legacy_v1={dbStats.legacy_v1}
                      {dbStats.tampered_ids.length > 0
                        ? ` · tampered_ids=[${dbStats.tampered_ids.join(', ')}]`
                        : ''}
                    </span>
                  )
                })()}
                {verifyResult.jsonl && (
                  <span>
                    JSONL entries_checked={verifyResult.jsonl.entries_checked ?? 0} · segments={verifyResult.jsonl.segments_checked ?? 0}
                    {verifyResult.jsonl.broken_segments && verifyResult.jsonl.broken_segments.length > 0
                      ? ` · broken_segments=[${verifyResult.jsonl.broken_segments
                          .map((b) => `${b.segment}${b.line ? `:${b.line}` : ''} (${b.reason})`)
                          .join(', ')}]`
                      : ''}
                  </span>
                )}
              </div>
            </div>
          </div>
          <button type="button" onClick={() => setVerifyResult(null)} className="text-[11px] underline">
            Dismiss
          </button>
        </div>
      )}

      {activeSubTab === 'security' ? (
        <div id="audit-panel-security" role="tabpanel" aria-labelledby="audit-tab-security" className="space-y-4">
          {/* Security Events Filter Bar */}
          <div className="flex flex-wrap items-center gap-3 bg-surface p-3 rounded-xl border border-subtle shadow-sm">
            <input
              type="text"
              aria-label="Filter security events by event type"
              placeholder="Event type (e.g. admin_auth_failed)"
              value={secEventType}
              onChange={(e) => {
                setSecurityOffset(0)
                setSecEventType(e.target.value)
              }}
              className="flex-1 min-w-[200px] px-3 py-1.5 rounded-lg bg-canvas border border-subtle text-xs text-primary placeholder:text-muted focus:outline-none focus:border-accent focus-visible:ring-2 focus-visible:ring-accent/40 font-mono"
            />
            <input
              type="text"
              aria-label="Filter security events by actor ID"
              placeholder="Actor ID (e.g. local-operator)"
              value={secActorID}
              onChange={(e) => {
                setSecurityOffset(0)
                setSecActorID(e.target.value)
              }}
              className="w-48 px-3 py-1.5 rounded-lg bg-canvas border border-subtle text-xs text-primary placeholder:text-muted focus:outline-none focus:border-accent focus-visible:ring-2 focus-visible:ring-accent/40 font-mono"
            />
            <select
              aria-label="Filter security events by outcome"
              value={secOutcome}
              onChange={(e) => {
                setSecurityOffset(0)
                setSecOutcome(e.target.value)
              }}
              className="px-3 py-1.5 rounded-lg bg-canvas border border-subtle text-xs text-primary focus:outline-none focus:border-accent focus-visible:ring-2 focus-visible:ring-accent/40 font-mono"
            >
              <option value="">Outcome: All</option>
              <option value="allowed">allowed</option>
              <option value="denied">denied</option>
              <option value="locked">locked</option>
            </select>
            <input
              type="datetime-local"
              aria-label="Security events since"
              value={secSinceInput}
              onChange={(e) => {
                setSecurityOffset(0)
                setSecSinceInput(e.target.value)
              }}
              className="px-2.5 py-1.5 rounded-lg bg-canvas border border-subtle text-xs text-primary font-mono"
            />
            <input
              type="datetime-local"
              aria-label="Security events until"
              value={secUntilInput}
              onChange={(e) => {
                setSecurityOffset(0)
                setSecUntilInput(e.target.value)
              }}
              className="px-2.5 py-1.5 rounded-lg bg-canvas border border-subtle text-xs text-primary font-mono"
            />
          </div>

          <div className="bg-surface rounded-2xl p-3 h-[580px] overflow-y-auto space-y-2 border border-subtle shadow-sm">
            {securityLoading ? (
              <div className="h-full flex items-center justify-center text-xs text-muted font-mono">
                Loading security audit events...
              </div>
            ) : securityEvents.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center text-muted gap-2">
                <KeyRound className="w-8 h-8 text-muted" />
                <span className="text-xs">No control-plane security events found.</span>
              </div>
            ) : (
              securityEvents.map((sev) => {
                const outcomeLower = (sev.outcome || '').toLowerCase()
                const outcomeBadge =
                  outcomeLower === 'allowed'
                    ? 'bg-emerald-50 text-emerald-800 border-emerald-200 dark:bg-emerald-950/60 dark:text-emerald-300 dark:border-emerald-700/40'
                    : outcomeLower === 'locked'
                    ? 'bg-amber-50 text-amber-800 border-amber-200 dark:bg-amber-950/60 dark:text-amber-300 dark:border-amber-700/40'
                    : 'bg-rose-50 text-rose-800 border-rose-200 dark:bg-rose-950/60 dark:text-rose-300 dark:border-rose-700/40'

                return (
                  <div
                    key={sev.id}
                    className="p-3 rounded-xl border border-subtle bg-canvas/70 hover:bg-subtle/40 transition-colors text-xs space-y-1.5"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold uppercase border ${outcomeBadge}`}>
                          {sev.outcome}
                        </span>
                        <span className="font-mono font-bold text-primary">{sev.event_type}</span>
                        <span className="text-muted font-mono">
                          action={sev.action}
                        </span>
                        {sev.resource_type && (
                          <span className="px-1.5 py-0.5 rounded bg-subtle text-[11px] font-mono text-primary">
                            {sev.resource_type}
                            {sev.resource_id ? `:${sev.resource_id}` : ''}
                          </span>
                        )}
                      </div>
                      <span className="text-[11px] font-mono text-muted">
                        {formatSmartDate(sev.timestamp).display}
                      </span>
                    </div>

                    <div className="flex flex-wrap items-center gap-4 text-[11px] font-mono text-muted">
                      <span>
                        actor=<strong className="text-primary">{sev.actor_id}</strong> ({sev.actor_role})
                      </span>
                      {sev.client_ip && <span>ip={sev.client_ip}</span>}
                      {sev.reason && <span>reason={sev.reason}</span>}
                      {sev.trace_id && <span>trace={sev.trace_id}</span>}
                      {sev.hash_version && <span>hash={sev.hash_version}</span>}
                    </div>
                  </div>
                )
              })
            )}
          </div>

          {/* Security Events Pagination */}
          <div className="flex items-center justify-between text-xs font-mono text-muted bg-surface px-4 py-2.5 rounded-xl border border-subtle">
            <span>
              Showing {securityEvents.length} of {securityTotal} security event(s) (offset {securityOffset})
            </span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                disabled={securityOffset === 0}
                onClick={() => setSecurityOffset((prev) => Math.max(0, prev - PAGE_SIZE))}
                className="flex items-center gap-1 px-2.5 py-1 rounded-lg border border-subtle bg-canvas text-primary disabled:opacity-40"
              >
                <ChevronLeft className="w-3.5 h-3.5" />
                Prev
              </button>
              <button
                type="button"
                disabled={securityOffset + PAGE_SIZE >= securityTotal}
                onClick={() => setSecurityOffset((prev) => prev + PAGE_SIZE)}
                className="flex items-center gap-1 px-2.5 py-1 rounded-lg border border-subtle bg-canvas text-primary disabled:opacity-40"
              >
                Next
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>
      ) : (
        <div id="audit-panel-invocations" role="tabpanel" aria-labelledby="audit-tab-invocations" className="space-y-4">
          {/* Historical Mode SSE Auto-Pause Banner */}
          {isHistoricalMode && (
            <div
              role="status"
              aria-live="polite"
              className="p-3 rounded-xl border border-amber-300 bg-amber-50 text-amber-900 dark:bg-amber-950/40 dark:border-amber-500/40 dark:text-amber-200 text-xs flex flex-wrap items-center justify-between gap-3 shadow-sm"
            >
              <div className="flex items-center gap-2">
                <Pause className="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0" />
                <span className="font-semibold">
                  Paused while viewing historical page (SSE auto-append disabled so historical rows stay stable).
                </span>
              </div>
              <button
                type="button"
                onClick={handleResumeLive}
                className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-amber-600 hover:bg-amber-700 text-white font-semibold transition-colors"
              >
                <Play className="w-3 h-3" />
                <span>Resume Live</span>
              </button>
            </div>
          )}

          {/* 2. Live Telemetry KPI Metrics Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-2.5">
        <div className="bg-surface p-3 rounded-xl border border-subtle flex flex-col justify-between shadow-sm">
          <div className="text-[11px] font-medium text-muted flex items-center gap-1">
            <Layers className="w-3.5 h-3.5 text-muted" />
            Total Events
          </div>
          <div className="text-xl font-bold font-mono text-primary mt-1">{metrics.total}</div>
        </div>

        <div className="bg-surface p-3 rounded-xl border border-emerald-200 dark:border-emerald-500/20 bg-emerald-50/50 dark:bg-emerald-950/20 flex flex-col justify-between shadow-sm">
          <div className="text-[11px] font-medium text-emerald-700 dark:text-emerald-400 flex items-center gap-1">
            <ShieldCheck className="w-3.5 h-3.5" />
            Allowed
          </div>
          <div className="text-xl font-bold font-mono text-emerald-800 dark:text-emerald-300 mt-1">{metrics.allowed}</div>
        </div>

        <div className="bg-surface p-3 rounded-xl border border-amber-200 dark:border-amber-500/20 bg-amber-50/50 dark:bg-amber-950/20 flex flex-col justify-between shadow-sm">
          <div className="text-[11px] font-medium text-amber-700 dark:text-amber-400 flex items-center gap-1">
            <Lock className="w-3.5 h-3.5" />
            Masked
          </div>
          <div className="text-xl font-bold font-mono text-amber-800 dark:text-amber-300 mt-1">{metrics.masked}</div>
        </div>

        <div className="bg-surface p-3 rounded-xl border border-purple-200 dark:border-purple-500/20 bg-purple-50/50 dark:bg-purple-950/20 flex flex-col justify-between shadow-sm">
          <div className="text-[11px] font-medium text-purple-700 dark:text-purple-400 flex items-center gap-1">
            <Eye className="w-3.5 h-3.5" />
            Audit
          </div>
          <div className="text-xl font-bold font-mono text-purple-800 dark:text-purple-300 mt-1">{metrics.audit}</div>
        </div>

        <div className="bg-surface p-3 rounded-xl border border-rose-200 dark:border-rose-500/20 bg-rose-50/50 dark:bg-rose-950/20 flex flex-col justify-between shadow-sm">
          <div className="text-[11px] font-medium text-rose-700 dark:text-rose-400 flex items-center gap-1">
            <ShieldAlert className="w-3.5 h-3.5" />
            Blocked
          </div>
          <div className="text-xl font-bold font-mono text-rose-800 dark:text-rose-300 mt-1">{metrics.blocked}</div>
        </div>

        <div className="bg-surface p-3 rounded-xl border border-sky-200 dark:border-cyan-500/20 bg-sky-50/50 dark:bg-cyan-950/20 flex flex-col justify-between shadow-sm">
          <div className="text-[11px] font-medium text-sky-700 dark:text-cyan-400 flex items-center gap-1">
            <Cpu className="w-3.5 h-3.5" />
            Avg Latency
          </div>
          <div className="text-xl font-bold font-mono text-sky-800 dark:text-cyan-300 mt-1">{metrics.avgLatency} ms</div>
        </div>
      </div>

      {/* 3. Search & Filter Bar */}
      <div className="flex flex-wrap items-center gap-2.5 bg-surface p-2.5 rounded-xl border border-subtle shadow-sm">
        <div className="relative flex-1 min-w-[220px]">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
          <input
            type="text"
            aria-label="Search tool invocation metadata"
            placeholder="Metadata search (tool, agent, rule, error, user, trace ID)..."
            value={filterText}
            onChange={(e) => {
              setOffset(0)
              setFilterText(e.target.value)
            }}
            className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-canvas border border-subtle text-xs text-primary placeholder:text-muted focus:outline-none focus:border-accent focus-visible:ring-2 focus-visible:ring-accent/40 font-mono transition-colors"
          />
        </div>

        <input
          type="text"
          aria-label="Filter by matched security rule"
          placeholder="Matched rule (e.g. credit_card)"
          value={matchedRuleFilter}
          onChange={(e) => {
            setOffset(0)
            setMatchedRuleFilter(e.target.value)
          }}
          className="w-44 px-3 py-1.5 rounded-lg bg-canvas border border-subtle text-xs text-primary placeholder:text-muted focus:outline-none focus:border-accent focus-visible:ring-2 focus-visible:ring-accent/40 font-mono transition-colors"
        />

        <input
          type="datetime-local"
          aria-label="Filter since timestamp"
          value={sinceInput}
          onChange={(e) => {
            setOffset(0)
            setSinceInput(e.target.value)
          }}
          className="px-2.5 py-1.5 rounded-lg bg-canvas border border-subtle text-xs text-primary focus:outline-none focus:border-accent focus-visible:ring-2 focus-visible:ring-accent/40 font-mono"
        />

        <input
          type="datetime-local"
          aria-label="Filter until timestamp"
          value={untilInput}
          onChange={(e) => {
            setOffset(0)
            setUntilInput(e.target.value)
          }}
          className="px-2.5 py-1.5 rounded-lg bg-canvas border border-subtle text-xs text-primary focus:outline-none focus:border-accent focus-visible:ring-2 focus-visible:ring-accent/40 font-mono"
        />

        {/* Verdict Filter Buttons */}
        <div role="group" aria-label="Filter by verdict" className="flex items-center gap-1 bg-subtle/50 p-1 rounded-lg border border-subtle">
          {[
            { id: 'ALL', label: 'All' },
            { id: 'ALLOWED', label: 'Allowed' },
            { id: 'MASKED', label: 'Masked' },
            { id: 'AUDIT', label: 'Audit' },
            { id: 'BLOCKED', label: 'Blocked' },
          ].map((item) => (
            <button
              key={item.id}
              type="button"
              aria-pressed={selectedVerdict === item.id}
              onClick={() => {
                setOffset(0)
                setSelectedVerdict(item.id)
              }}
              className={`px-2.5 py-1 rounded-md text-[11px] font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/50 ${
                selectedVerdict === item.id
                  ? 'bg-accent/15 text-accent border border-accent/30 font-semibold'
                  : 'text-muted hover:text-primary'
              }`}
            >
              {item.label}
            </button>
          ))}
        </div>
      </div>

      {/* 4. Telemetry Events List */}
      <div
        ref={logContainerRef}
        className="bg-surface rounded-2xl p-3 h-[580px] overflow-y-auto space-y-2 border border-subtle shadow-sm dark:shadow-2xl"
      >
        {filteredEvents.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-muted gap-2.5">
            <Shield className="w-8 h-8 text-muted" />
            <span className="text-xs">No matching audit records found.</span>
            {(filterText.trim() ||
              matchedRuleFilter.trim() ||
              Boolean(sinceInput) ||
              Boolean(untilInput) ||
              selectedVerdict !== 'ALL') && (
              <button
                type="button"
                onClick={() => {
                  setOffset(0)
                  setFilterText('')
                  setMatchedRuleFilter('')
                  setSinceInput('')
                  setUntilInput('')
                  setSelectedVerdict('ALL')
                }}
                className="px-3 py-1 rounded-lg text-xs font-medium bg-accent/10 text-accent border border-accent/30 hover:bg-accent/20 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/50"
              >
                Clear filters
              </button>
            )}
          </div>
        ) : (
          filteredEvents.map((ev, idx) => {
            const rowKey = ev.id || ev.trace_id || `ev-${idx}`
            const isExpanded = expandedIds.has(rowKey)
            const activeTab = activeTabs[rowKey] || 'text'
            const style = getVerdictStyle(ev.decision || '')
            const Icon = style.icon
            const { display: dateDisplay, iso: fullIso } = formatSmartDate(ev.timestamp)

            const parsedPayload = parsePayloadContent(ev.payload_preview)
            const parsedOriginal = parsePayloadContent(ev.original_payload)
            const parsedOrigReq = parsePayloadContent(ev.original_request)
            const parsedSentReq = parsePayloadContent(ev.request || ev.original_request)
            const parsedOrigResp = parsePayloadContent(ev.original_response)
            const parsedFinalResp = parsePayloadContent(ev.response || ev.original_response)
            const hasFourFields = Boolean(ev.original_request || ev.request || ev.original_response || ev.response)
            const hasReqDiff = Boolean(ev.original_request && ev.request && ev.request !== ev.original_request)
            const hasRespDiff = Boolean(ev.original_response && ev.response && ev.response !== ev.original_response)
            const hasDiff =
              hasReqDiff ||
              hasRespDiff ||
              Boolean(ev.original_payload && ev.original_payload.trim() && ev.original_payload !== ev.payload_preview)
            const isLoadingDetail = detailLoadingIds.has(rowKey)

            // Normalize internal rule display
            const isCleanPass = ev.matched_rule === 'pipeline' || (!ev.matched_rule && ev.decision === 'ALLOWED')

            return (
              <div
                key={rowKey}
                className="rounded-xl border border-subtle bg-slate-50/70 hover:bg-slate-100/80 dark:bg-white/[0.02] dark:hover:bg-white/[0.04] transition-colors overflow-hidden"
              >
                {/* Collapsible Row Header */}
                <div
                  role="button"
                  tabIndex={0}
                  aria-expanded={isExpanded}
                  onClick={() => toggleRow(rowKey, ev)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault()
                      toggleRow(rowKey, ev)
                    }
                  }}
                  className="p-2.5 flex items-center gap-2.5 cursor-pointer select-none text-xs flex-wrap focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/50"
                >
                  {/* Expand Chevron */}
                  <span className="text-muted" aria-hidden="true">
                    {isExpanded ? (
                      <ChevronDown className="w-4 h-4 text-accent" />
                    ) : (
                      <ChevronRight className="w-4 h-4" />
                    )}
                  </span>

                  {/* Smart Date & Time */}
                  <div
                    className="font-mono text-[11px] text-muted flex items-center gap-1 min-w-[130px]"
                    title={`ISO Timestamp: ${fullIso}`}
                  >
                    <Clock className="w-3 h-3 text-muted" />
                    <span>{dateDisplay}</span>
                  </div>

                  {/* Decision Verdict Badge */}
                  <div
                    className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-mono font-bold border ${style.badge}`}
                  >
                    <Icon className="w-3 h-3" />
                    <span>{style.label}</span>
                  </div>

                  {/* Event Type / Tool Name */}
                  <div className="font-semibold text-primary font-mono text-[11px] flex items-center gap-1.5">
                    {ev.tool_name ? (
                      <span className="text-emerald-700 dark:text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded border border-emerald-500/20">
                        tool:{ev.tool_name}
                      </span>
                    ) : (
                      <span className="text-sky-600 dark:text-cyan-400">{ev.event_type}</span>
                    )}
                  </div>

                  {/* Agent */}
                  {ev.agent && (
                    <span className="text-indigo-600 dark:text-indigo-400 font-mono text-[11px] bg-indigo-500/10 px-1.5 py-0.5 rounded border border-indigo-500/20">
                      @{ev.agent}
                    </span>
                  )}

                  {/* Rule & Audit Badges */}
                  {isCleanPass ? (
                    <span className="text-[10px] font-mono text-emerald-700 dark:text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                      🛡️ Clean Pass
                    </span>
                  ) : ev.matched_rule ? (
                    <span className="text-[10px] font-mono text-amber-700 dark:text-amber-300 bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/20">
                      rule:{ev.matched_rule}
                    </span>
                  ) : null}

                  {ev.audited_rules && ev.audited_rules.length > 0 && (
                    <span className="text-[10px] font-mono text-purple-700 dark:text-purple-300 bg-purple-500/10 px-2 py-0.5 rounded border border-purple-500/20 flex items-center gap-1">
                      <Eye className="w-2.5 h-2.5" />
                      audited:{ev.audited_rules.join(', ')}
                    </span>
                  )}

                  {/* Latency */}
                  {typeof ev.latency_ms === 'number' && (
                    <span className="text-muted font-mono text-[10px] ml-auto">
                      {ev.latency_ms}ms
                    </span>
                  )}

                  {/* Trace ID */}
                  {ev.trace_id && (
                    <span
                      className="text-muted font-mono text-[10px] hidden md:inline cursor-pointer hover:text-accent transition-colors"
                      title={`Full Trace ID: ${ev.trace_id}`}
                      onClick={(e) => {
                        e.stopPropagation()
                        copyToClipboard(ev.trace_id || '', `trace-${rowKey}`)
                      }}
                    >
                      {copiedId === `trace-${rowKey}` ? (
                        <span className="text-emerald-600 dark:text-emerald-400 font-bold">Copied!</span>
                      ) : (
                        `#${ev.trace_id.substring(0, 8)}`
                      )}
                    </span>
                  )}
                </div>

                {/* Error Banner if Blocked */}
                {ev.error && (
                  <div className="px-3 py-1.5 bg-rose-50 dark:bg-rose-950/40 border-t border-rose-200 dark:border-rose-800/30 text-rose-700 dark:text-rose-300 text-[11px] font-mono flex items-center gap-2">
                    <ShieldAlert className="w-3.5 h-3.5 text-rose-500 flex-shrink-0" />
                    <span>{ev.error}</span>
                  </div>
                )}

                {/* Expanded Inspection Detail Drawer */}
                {isExpanded && (
                  <div className="p-3 bg-slate-100/70 dark:bg-black/60 border-t border-subtle space-y-3">
                    {/* Navigation Tabs */}
                    <div className="flex items-center justify-between flex-wrap gap-2 border-b border-subtle pb-2">
                      <div
                        role="tablist"
                        aria-label="Audit record detail views"
                        className="flex items-center gap-1 bg-surface p-1 rounded-lg border border-subtle"
                      >
                        <button
                          type="button"
                          role="tab"
                          aria-selected={activeTab === 'text'}
                          onClick={() => setTabForEvent(rowKey, 'text')}
                          className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-medium transition-colors ${
                            activeTab === 'text'
                              ? 'bg-accent/15 text-accent border border-accent/30 font-semibold'
                              : 'text-muted hover:text-primary'
                          }`}
                        >
                          <FileText className="w-3 h-3" />
                          <span>Readable Text</span>
                        </button>

                        <button
                          type="button"
                          role="tab"
                          aria-selected={activeTab === 'diff'}
                          onClick={() => setTabForEvent(rowKey, 'diff')}
                          className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-medium transition-colors ${
                            activeTab === 'diff'
                              ? 'bg-purple-500/20 text-purple-700 dark:text-purple-300 border border-purple-500/30 font-semibold'
                              : 'text-muted hover:text-primary'
                          }`}
                        >
                          <Sparkles className="w-3 h-3 text-purple-500" />
                          <span>Diff (Before / After)</span>
                          {hasDiff && (
                            <span className="w-1.5 h-1.5 rounded-full bg-purple-500 animate-pulse" />
                          )}
                        </button>

                        <button
                          type="button"
                          role="tab"
                          aria-selected={activeTab === 'json'}
                          onClick={() => setTabForEvent(rowKey, 'json')}
                          className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-medium transition-colors ${
                            activeTab === 'json'
                              ? 'bg-accent/15 text-accent border border-accent/30 font-semibold'
                              : 'text-muted hover:text-primary'
                          }`}
                        >
                          <span>JSON Tree</span>
                        </button>

                        <button
                          type="button"
                          role="tab"
                          aria-selected={activeTab === 'raw'}
                          onClick={() => setTabForEvent(rowKey, 'raw')}
                          className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-medium transition-colors ${
                            activeTab === 'raw'
                              ? 'bg-accent/15 text-accent border border-accent/30 font-semibold'
                              : 'text-muted hover:text-primary'
                          }`}
                        >
                          <span>Raw Log</span>
                        </button>
                      </div>

                      <div className="flex items-center gap-2">
                        {activeTab === 'diff' && hasDiff && (
                          <div className="flex items-center gap-1 bg-surface p-0.5 rounded border border-subtle">
                            <button
                              onClick={() => setDiffLayout('split')}
                              className={`p-1 rounded text-[10px] ${
                                diffLayout === 'split' ? 'bg-subtle text-accent' : 'text-muted'
                              }`}
                              title="Split view"
                            >
                              <Columns className="w-3 h-3" />
                            </button>
                            <button
                              onClick={() => setDiffLayout('stacked')}
                              className={`p-1 rounded text-[10px] ${
                                diffLayout === 'stacked' ? 'bg-subtle text-accent' : 'text-muted'
                              }`}
                              title="Stacked view"
                            >
                              <Rows className="w-3 h-3" />
                            </button>
                          </div>
                        )}

                        {/* Copy Button */}
                        <button
                          onClick={() =>
                            copyToClipboard(
                              activeTab === 'json'
                                ? parsedPayload.formattedJson
                                : ev.payload_preview || '',
                              `payload-${rowKey}`
                            )
                          }
                          className="flex items-center gap-1 px-2.5 py-1 rounded-md text-[10px] font-medium bg-surface hover:bg-subtle text-primary border border-subtle transition-colors shadow-sm"
                        >
                          {copiedId === `payload-${rowKey}` ? (
                            <>
                              <Check className="w-3 h-3 text-emerald-500" />
                              <span className="text-emerald-600 dark:text-emerald-400">Copied</span>
                            </>
                          ) : (
                            <>
                              <Copy className="w-3 h-3" />
                              <span>Copy Content</span>
                            </>
                          )}
                        </button>
                      </div>
                    </div>

                    {/* Tab Contents - DUAL-TONE TELEMETRY INVARIANT: ALWAYS #0F172A / slate-900 viewport */}
                    {isLoadingDetail && (
                      <div className="text-[11px] font-mono text-muted px-1">
                        Loading full 4-field invocation payload from local vault...
                      </div>
                    )}

                    {activeTab === 'text' && (
                      hasFourFields ? (
                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                          <div className="space-y-1.5">
                            <div className="flex items-center justify-between text-[10px] font-mono">
                              <span className="font-semibold text-sky-400">
                                1. Original Request {hasReqDiff ? '(Modified before upstream)' : ev.request_decision === 'BLOCKED' ? '(Blocked at ingress)' : '(Sent untouched)'}
                              </span>
                              {ev.request_decision && (
                                <span className="text-muted">req:{ev.request_decision}</span>
                              )}
                            </div>
                            <div className="bg-[#0F172A] p-3.5 rounded-xl border border-[#1E293B] font-mono text-xs text-slate-100 max-h-80 overflow-y-auto leading-relaxed shadow-inner">
                              {parsedOrigReq.displayText ? renderHighlightedText(parsedOrigReq.displayText) : <span className="text-slate-500">No request payload recorded</span>}
                            </div>
                            {hasReqDiff && (
                              <div className="space-y-1">
                                <div className="text-[10px] font-mono font-semibold text-emerald-400">2. Dispatched Request (Upstream)</div>
                                <div className="bg-[#0F172A] p-3 rounded-xl border border-emerald-900/40 font-mono text-xs text-slate-100 max-h-56 overflow-y-auto leading-relaxed">
                                  {renderHighlightedText(parsedSentReq.displayText)}
                                </div>
                              </div>
                            )}
                          </div>

                          <div className="space-y-1.5">
                            <div className="flex items-center justify-between text-[10px] font-mono">
                              <span className="font-semibold text-purple-400">
                                3. {ev.original_response ? 'Original Response (Upstream)' : 'Final Response (Client)'}
                              </span>
                              {ev.response_decision && (
                                <span className="text-muted">resp:{ev.response_decision}</span>
                              )}
                            </div>
                            <div className="bg-[#0F172A] p-3.5 rounded-xl border border-[#1E293B] font-mono text-xs text-slate-100 max-h-80 overflow-y-auto leading-relaxed shadow-inner">
                              {ev.original_response ? (
                                renderHighlightedText(parsedOrigResp.displayText)
                              ) : ev.response ? (
                                renderHighlightedText(parsedFinalResp.displayText)
                              ) : (
                                <span className="text-slate-500">Awaiting or no response payload</span>
                              )}
                            </div>
                            {hasRespDiff && (
                              <div className="space-y-1">
                                <div className="text-[10px] font-mono font-semibold text-amber-400">4. Final Response (Client)</div>
                                <div className="bg-[#0F172A] p-3 rounded-xl border border-amber-900/40 font-mono text-xs text-slate-100 max-h-56 overflow-y-auto leading-relaxed">
                                  {renderHighlightedText(parsedFinalResp.displayText)}
                                </div>
                              </div>
                            )}
                          </div>
                        </div>
                      ) : (
                        <div className="bg-[#0F172A] p-3.5 rounded-xl border border-[#1E293B] font-mono text-xs text-slate-100 max-h-80 overflow-y-auto leading-relaxed shadow-inner">
                          {renderHighlightedText(parsedPayload.displayText)}
                        </div>
                      )
                    )}

                    {activeTab === 'diff' && (
                      <div className="space-y-3">
                        {!hasDiff ? (
                          <div className="bg-purple-950/20 border border-purple-800/30 p-3 rounded-xl text-purple-300 text-xs font-mono space-y-1">
                            <div className="font-semibold flex items-center gap-1.5">
                              <Eye className="w-4 h-4 text-purple-400" />
                              No Mutation Diff Available
                            </div>
                            <p className="text-[11px] text-gray-400">
                              {ev.decision === 'ALLOWED'
                                ? 'No masking or modification was applied to this invocation.'
                                : 'Request and response were not mutated in-place, or Local Full Payload Capture is disabled in Operational Settings.'}
                            </p>
                          </div>
                        ) : hasReqDiff || hasRespDiff ? (
                          <div className="space-y-3">
                            {hasReqDiff && (
                              <div className={diffLayout === 'split' ? 'grid grid-cols-1 md:grid-cols-2 gap-2' : 'space-y-2'}>
                                <div className="space-y-1">
                                  <div className="text-[10px] font-mono font-semibold text-rose-400">Original Request (Raw)</div>
                                  <div className="bg-[#0F172A] p-3 rounded-xl border border-rose-900/40 font-mono text-[11px] text-slate-200 max-h-72 overflow-y-auto whitespace-pre-wrap leading-relaxed">
                                    {parsedOrigReq.displayText}
                                  </div>
                                </div>
                                <div className="space-y-1">
                                  <div className="text-[10px] font-mono font-semibold text-emerald-400">Sent Request (Filtered)</div>
                                  <div className="bg-[#0F172A] p-3 rounded-xl border border-emerald-900/40 font-mono text-[11px] text-slate-200 max-h-72 overflow-y-auto leading-relaxed">
                                    {renderHighlightedText(parsedSentReq.displayText)}
                                  </div>
                                </div>
                              </div>
                            )}
                            {hasRespDiff && (
                              <div className={diffLayout === 'split' ? 'grid grid-cols-1 md:grid-cols-2 gap-2' : 'space-y-2'}>
                                <div className="space-y-1">
                                  <div className="text-[10px] font-mono font-semibold text-rose-400">Original Response (Upstream Raw)</div>
                                  <div className="bg-[#0F172A] p-3 rounded-xl border border-rose-900/40 font-mono text-[11px] text-slate-200 max-h-72 overflow-y-auto whitespace-pre-wrap leading-relaxed">
                                    {parsedOrigResp.displayText}
                                  </div>
                                </div>
                                <div className="space-y-1">
                                  <div className="text-[10px] font-mono font-semibold text-emerald-400">Final Response (Client)</div>
                                  <div className="bg-[#0F172A] p-3 rounded-xl border border-emerald-900/40 font-mono text-[11px] text-slate-200 max-h-72 overflow-y-auto leading-relaxed">
                                    {renderHighlightedText(parsedFinalResp.displayText)}
                                  </div>
                                </div>
                              </div>
                            )}
                          </div>
                        ) : diffLayout === 'split' ? (
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                            {/* Original */}
                            <div className="space-y-1">
                              <div className="text-[10px] font-mono font-semibold text-rose-400 flex items-center gap-1">
                                <span>⚠️ Original Request (Raw / Unmasked)</span>
                              </div>
                              <div className="bg-[#0F172A] p-3 rounded-xl border border-rose-900/40 font-mono text-[11px] text-slate-200 max-h-80 overflow-y-auto whitespace-pre-wrap leading-relaxed">
                                {parsedOriginal.displayText}
                              </div>
                            </div>

                            {/* Masked */}
                            <div className="space-y-1">
                              <div className="text-[10px] font-mono font-semibold text-emerald-400 flex items-center gap-1">
                                <span>🔒 Processed / Masked Output</span>
                              </div>
                              <div className="bg-[#0F172A] p-3 rounded-xl border border-emerald-900/40 font-mono text-[11px] text-slate-200 max-h-80 overflow-y-auto leading-relaxed">
                                {renderHighlightedText(parsedPayload.displayText)}
                              </div>
                            </div>
                          </div>
                        ) : (
                          <div className="space-y-3">
                            <div className="space-y-1">
                              <div className="text-[10px] font-mono font-semibold text-rose-400">
                                ⚠️ Original Request (Raw / Unmasked)
                              </div>
                              <div className="bg-[#0F172A] p-3 rounded-xl border border-rose-900/40 font-mono text-[11px] text-slate-200 max-h-56 overflow-y-auto whitespace-pre-wrap leading-relaxed">
                                {parsedOriginal.displayText}
                              </div>
                            </div>
                            <div className="space-y-1">
                              <div className="text-[10px] font-mono font-semibold text-emerald-400">
                                🔒 Processed / Masked Output
                              </div>
                              <div className="bg-[#0F172A] p-3 rounded-xl border border-emerald-900/40 font-mono text-[11px] text-slate-200 max-h-56 overflow-y-auto leading-relaxed">
                                {renderHighlightedText(parsedPayload.displayText)}
                              </div>
                            </div>
                          </div>
                        )}
                      </div>
                    )}

                    {activeTab === 'json' && (
                      hasFourFields ? (
                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                          <div className="space-y-1">
                            <div className="text-[10px] font-mono font-semibold text-sky-400">Request JSON</div>
                            <div className="bg-[#0F172A] p-3 rounded-xl border border-[#1E293B] font-mono text-[11px] text-cyan-300 max-h-80 overflow-y-auto shadow-inner">
                              <pre className="whitespace-pre-wrap">{parsedSentReq.formattedJson || parsedOrigReq.formattedJson || 'null'}</pre>
                            </div>
                          </div>
                          <div className="space-y-1">
                            <div className="text-[10px] font-mono font-semibold text-purple-400">Response JSON</div>
                            <div className="bg-[#0F172A] p-3 rounded-xl border border-[#1E293B] font-mono text-[11px] text-cyan-300 max-h-80 overflow-y-auto shadow-inner">
                              <pre className="whitespace-pre-wrap">{parsedFinalResp.formattedJson || parsedOrigResp.formattedJson || 'null'}</pre>
                            </div>
                          </div>
                        </div>
                      ) : (
                        <div className="bg-[#0F172A] p-3 rounded-xl border border-[#1E293B] font-mono text-[11px] text-cyan-300 max-h-80 overflow-y-auto shadow-inner">
                          <pre className="whitespace-pre-wrap">{parsedPayload.formattedJson}</pre>
                        </div>
                      )
                    )}

                    {activeTab === 'raw' && (
                      <div className="bg-[#0F172A] p-3 rounded-xl border border-[#1E293B] font-mono text-[10px] text-slate-300 max-h-80 overflow-y-auto shadow-inner">
                        <pre className="whitespace-pre-wrap">
                          {JSON.stringify(ev, null, 2)}
                        </pre>
                      </div>
                    )}

                    {/* Metadata Footer */}
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2 border-t border-subtle text-[10px] font-mono text-muted">
                      <div>
                        <span className="text-muted/80">Layer:</span> {ev.layer || 'pipeline'}
                      </div>
                      <div>
                        <span className="text-muted/80">Client IP:</span>{' '}
                        {ev.client_ip || ev.client_session_id || 'localhost'}
                      </div>
                      <div>
                        <span className="text-muted/80">Trace ID:</span>{' '}
                        {ev.trace_id ? ev.trace_id.substring(0, 16) + '...' : 'none'}
                      </div>
                      <div>
                        <span className="text-muted/80">Latency:</span>{' '}
                        {ev.latency_ms !== undefined ? `${ev.latency_ms}ms` : '0ms'}
                      </div>
                      {ev.api_key_id && (
                        <div>
                          <span className="text-muted/80">API Key:</span> {ev.api_key_id}
                        </div>
                      )}
                      {ev.approved_by && (
                        <div>
                          <span className="text-muted/80">Approved By:</span> {ev.approved_by} ({ev.approval_channel || 'hitl'})
                        </div>
                      )}
                      {ev.hash_version && (
                        <div>
                          <span className="text-muted/80">Integrity:</span> {ev.hash_version}
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            )
          })
        )}
      </div>

      {/* Tool Invocations Pagination Bar */}
      <div className="flex items-center justify-between text-xs font-mono text-muted bg-surface px-4 py-2.5 rounded-xl border border-subtle">
        <span>
          Page {Math.floor(offset / PAGE_SIZE) + 1} · Showing {filteredEvents.length} rows ({totalCount} total stored)
        </span>
        <div className="flex items-center gap-2">
          <button
            type="button"
            disabled={offset === 0}
            onClick={() => setOffset((prev) => Math.max(0, prev - PAGE_SIZE))}
            className="flex items-center gap-1 px-2.5 py-1 rounded-lg border border-subtle bg-canvas text-primary disabled:opacity-40"
          >
            <ChevronLeft className="w-3.5 h-3.5" />
            Prev
          </button>
          <button
            type="button"
            disabled={offset + PAGE_SIZE >= totalCount}
            onClick={() => setOffset((prev) => prev + PAGE_SIZE)}
            className="flex items-center gap-1 px-2.5 py-1 rounded-lg border border-subtle bg-canvas text-primary disabled:opacity-40"
          >
            Next
            <ChevronRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
        </div>
      )}
    </div>
  )
}
