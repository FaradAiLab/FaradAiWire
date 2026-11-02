import React, { useState, useEffect, useRef, useMemo } from 'react'
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
  ChevronRight,
  FileText,
  Columns,
  Rows,
  Sparkles,
  Clock,
  Layers,
  Cpu,
  RefreshCw,
} from 'lucide-react'
import { AuditEvent } from '../types'
import { api } from '../api'

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

  if (rawDecision === 'AUDIT' || raw.severity === 'AUDIT') {
    severity = 'AUDIT'
    decision = 'AUDIT'
  } else if (rawDecision === 'BLOCKED' || rawDecision === 'DENIED' || raw.error_code || raw.error) {
    severity = 'ERROR'
    decision = 'BLOCKED'
  } else if (rawDecision === 'MASKED' || raw.severity === 'WARN') {
    severity = 'WARN'
    decision = 'MASKED'
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
  const error = raw.error || (decision === 'BLOCKED' ? raw.message : undefined)

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
    matched_rule,
    audited_rules,
    latency_ms,
    payload_preview,
    raw_payload_preview: payload_preview,
    original_payload,
    original_payload_preview: original_payload,
    details,
    error,
  }
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

export const AuditLogsTab: React.FC = () => {
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [isConnected, setIsConnected] = useState(false)
  const [isPaused, setIsPaused] = useState(false)
  const [autoScroll, setAutoScroll] = useState(true)
  const [filterText, setFilterText] = useState('')
  const [selectedVerdict, setSelectedVerdict] = useState<string>('ALL')
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set())
  const [activeTabs, setActiveTabs] = useState<Record<string, 'text' | 'diff' | 'json' | 'raw'>>({})
  const [diffLayout, setDiffLayout] = useState<'split' | 'stacked'>('split')
  const [copiedId, setCopiedId] = useState<string | null>(null)

  const logContainerRef = useRef<HTMLDivElement>(null)
  const eventSourceRef = useRef<EventSource | null>(null)

  // Initial load of historical logs from DuckDB
  const fetchHistoricalLogs = () => {
    api
      .getAuditLogs()
      .then((res: any) => {
        const list = res?.events || res?.logs || []
        if (Array.isArray(list) && list.length > 0) {
          setEvents(list.map(normalizeAuditEvent))
        }
      })
      .catch(() => {
        // Historical log engine (DuckDB) may be empty initially
      })
  }

  useEffect(() => {
    fetchHistoricalLogs()
  }, [])

  // Setup SSE stream
  useEffect(() => {
    if (isPaused) {
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
        setEvents((prev) => [...prev, ...normalized].slice(-500))
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
  }, [isPaused])

  // Auto-scroll effect
  useEffect(() => {
    if (autoScroll && logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight
    }
  }, [events, autoScroll])

  const toggleRow = (id: string) => {
    setExpandedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) {
        next.delete(id)
      } else {
        next.add(id)
      }
      return next
    })
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
      if (dec === 'BLOCKED' || ev.severity === 'ERROR') blocked++
      else if (dec === 'MASKED' || ev.severity === 'WARN') masked++
      else if (dec === 'AUDIT' || ev.severity === 'AUDIT') audit++
      else allowed++

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
    return events.filter((ev) => {
      const dec = (ev.decision || '').toUpperCase()

      if (selectedVerdict !== 'ALL') {
        if (selectedVerdict === 'ALLOWED' && dec !== 'ALLOWED') return false
        if (selectedVerdict === 'MASKED' && dec !== 'MASKED') return false
        if (selectedVerdict === 'AUDIT' && dec !== 'AUDIT') return false
        if (selectedVerdict === 'BLOCKED' && dec !== 'BLOCKED') return false
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
  }, [events, selectedVerdict, filterText])

  const getVerdictStyle = (decision: string) => {
    switch (decision?.toUpperCase()) {
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
      {/* 1. Header Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-primary flex items-center gap-2">
            <ScrollText className="w-5 h-5 text-accent" />
            Audit Telemetry Stream
          </h2>
          <p className="text-xs text-muted mt-1">
            Real-time SSE event stream, DLP security audit, semantic redaction, and MCP tool execution telemetry.
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          {/* Connection Status indicator */}
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-mono font-semibold bg-surface border border-subtle text-primary shadow-sm">
            <Radio
              className={`w-3.5 h-3.5 ${
                isConnected ? 'text-emerald-500 animate-pulse' : 'text-amber-500 animate-bounce'
              }`}
            />
            <span>{isPaused ? 'PAUSED' : isConnected ? 'LIVE STREAM' : 'CONNECTING'}</span>
          </div>

          {/* Pause / Resume */}
          <button
            onClick={() => setIsPaused(!isPaused)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-surface hover:bg-subtle text-primary border border-subtle transition-colors shadow-sm"
          >
            {isPaused ? (
              <Play className="w-3.5 h-3.5 text-emerald-500" />
            ) : (
              <Pause className="w-3.5 h-3.5 text-amber-500" />
            )}
            <span>{isPaused ? 'Resume' : 'Pause'}</span>
          </button>

          {/* Refresh from DuckDB */}
          <button
            onClick={fetchHistoricalLogs}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-surface hover:bg-subtle text-primary border border-subtle transition-colors shadow-sm"
            title="Refresh historical logs from DuckDB"
          >
            <RefreshCw className="w-3.5 h-3.5 text-accent" />
            <span>Refresh</span>
          </button>

          {/* Auto Scroll */}
          <button
            onClick={() => setAutoScroll(!autoScroll)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold border transition-colors shadow-sm ${
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
            onClick={() => setEvents([])}
            className="p-2 rounded-xl text-muted hover:text-rose-500 hover:bg-rose-50 dark:hover:bg-rose-950/30 border border-subtle transition-colors shadow-sm"
            title="Clear logs from screen"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

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
      <div className="flex flex-wrap items-center gap-3 bg-surface p-2.5 rounded-xl border border-subtle shadow-sm">
        <div className="relative flex-1 min-w-[240px]">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
          <input
            type="text"
            placeholder="Search: tool name, agent, rule (tckn, credit_card), trace ID, or payload..."
            value={filterText}
            onChange={(e) => setFilterText(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-canvas border border-subtle text-xs text-primary placeholder:text-muted focus:outline-none focus:border-accent font-mono transition-colors"
          />
        </div>

        {/* Verdict Filter Buttons */}
        <div className="flex items-center gap-1 bg-subtle/50 p-1 rounded-lg border border-subtle">
          {[
            { id: 'ALL', label: 'All' },
            { id: 'ALLOWED', label: 'Allowed' },
            { id: 'MASKED', label: 'Masked' },
            { id: 'AUDIT', label: 'Audit' },
            { id: 'BLOCKED', label: 'Blocked' },
          ].map((item) => (
            <button
              key={item.id}
              onClick={() => setSelectedVerdict(item.id)}
              className={`px-2.5 py-1 rounded-md text-[11px] font-medium transition-colors ${
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
          <div className="h-full flex flex-col items-center justify-center text-muted gap-2">
            <Shield className="w-8 h-8 text-muted animate-pulse" />
            <span className="text-xs font-mono">No matching telemetry events found...</span>
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
            const hasDiff = Boolean(
              ev.original_payload &&
                ev.original_payload.trim() &&
                ev.original_payload !== ev.payload_preview
            )

            // Normalize internal rule display
            const isCleanPass = ev.matched_rule === 'pipeline' || (!ev.matched_rule && ev.decision === 'ALLOWED')

            return (
              <div
                key={rowKey}
                className="rounded-xl border border-subtle bg-slate-50/70 hover:bg-slate-100/80 dark:bg-white/[0.02] dark:hover:bg-white/[0.04] transition-colors overflow-hidden"
              >
                {/* Collapsible Row Header */}
                <div
                  onClick={() => toggleRow(rowKey)}
                  className="p-2.5 flex items-center gap-2.5 cursor-pointer select-none text-xs flex-wrap"
                >
                  {/* Expand Chevron */}
                  <button className="text-muted hover:text-primary">
                    {isExpanded ? (
                      <ChevronDown className="w-4 h-4 text-accent" />
                    ) : (
                      <ChevronRight className="w-4 h-4" />
                    )}
                  </button>

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
                      <div className="flex items-center gap-1 bg-surface p-1 rounded-lg border border-subtle">
                        <button
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
                    {activeTab === 'text' && (
                      <div className="bg-[#0F172A] p-3.5 rounded-xl border border-[#1E293B] font-mono text-xs text-slate-100 max-h-80 overflow-y-auto leading-relaxed shadow-inner">
                        {renderHighlightedText(parsedPayload.displayText)}
                      </div>
                    )}

                    {activeTab === 'diff' && (
                      <div className="space-y-2">
                        {!hasDiff ? (
                          <div className="bg-purple-950/20 border border-purple-800/30 p-3 rounded-xl text-purple-300 text-xs font-mono space-y-1">
                            <div className="font-semibold flex items-center gap-1.5">
                              <Eye className="w-4 h-4 text-purple-400" />
                              No Diff Available
                            </div>
                            <p className="text-[11px] text-gray-400">
                              {ev.decision === 'ALLOWED'
                                ? 'No masking or modification was applied to this request.'
                                : 'Original unmasked payload was not retained. Enable `dlp.debug_retain_unmasked_diff: true` in your gateway configuration to compare original and masked payloads side-by-side.'}
                            </p>
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
                      <div className="bg-[#0F172A] p-3 rounded-xl border border-[#1E293B] font-mono text-[11px] text-cyan-300 max-h-80 overflow-y-auto shadow-inner">
                        <pre className="whitespace-pre-wrap">{parsedPayload.formattedJson}</pre>
                      </div>
                    )}

                    {activeTab === 'raw' && (
                      <div className="bg-[#0F172A] p-3 rounded-xl border border-[#1E293B] font-mono text-[10px] text-slate-300 max-h-80 overflow-y-auto shadow-inner">
                        <pre className="whitespace-pre-wrap">
                          {JSON.stringify(ev.details || ev, null, 2)}
                        </pre>
                      </div>
                    )}

                    {/* Metadata Footer */}
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2 border-t border-subtle text-[10px] font-mono text-muted">
                      <div>
                        <span className="text-muted/80">Layer:</span> {ev.layer || 'pipeline'}
                      </div>
                      <div>
                        <span className="text-muted/80">Client:</span>{' '}
                        {ev.client_session_id || 'localhost'}
                      </div>
                      <div>
                        <span className="text-muted/80">Trace ID:</span>{' '}
                        {ev.trace_id ? ev.trace_id.substring(0, 16) + '...' : 'none'}
                      </div>
                      <div>
                        <span className="text-muted/80">Latency:</span>{' '}
                        {ev.latency_ms !== undefined ? `${ev.latency_ms}ms` : '0ms'}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )
          })
        )}
      </div>
    </div>
  )
}
