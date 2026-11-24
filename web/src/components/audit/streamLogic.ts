import type { AuditEvent, AuditQuerySummary } from '../../types.ts'
import {
  MAX_STREAM_ROWS,
  getRowKey,
  mergeCompositeDecision,
  normalizeAuditEvent,
} from './formatters.ts'

export interface BatchMergeResult {
  nextEvents: AuditEvent[]
  updatedKeys: string[]
  newKeys: string[]
  newItems: AuditEvent[]
}

function severityFromDecision(dec: string, fallback: AuditEvent['severity']): AuditEvent['severity'] {
  if (dec === 'CRITICAL') return 'CRITICAL'
  if (dec === 'BLOCKED' || dec === 'ERROR') return 'ERROR'
  if (dec === 'MASKED') return 'WARN'
  if (dec === 'AUDIT') return 'AUDIT'
  return fallback
}

function findMatchingIndex(list: AuditEvent[], item: AuditEvent): number {
  if (item.id) {
    return list.findIndex((e) => e.id === item.id)
  }
  if (item.trace_id) {
    return list.findIndex((e) => !e.id && e.trace_id === item.trace_id)
  }
  return -1
}

function mergeRuleStrings(existingRule?: string, nextRule?: string): string {
  const tokens: string[] = []
  const seen = new Set<string>()
  for (const raw of [existingRule, nextRule]) {
    if (!raw) continue
    for (const part of raw.split(',')) {
      const trimmed = part.trim()
      if (!trimmed || seen.has(trimmed)) continue
      seen.add(trimmed)
      tokens.push(trimmed)
    }
  }
  return tokens.join(',')
}

function mergeUpdatedRow(existing: AuditEvent, item: AuditEvent): AuditEvent {
  if (item.phase === 'response' || item.phase === 'complete') {
    const mergedDec = mergeCompositeDecision(existing.request_decision || existing.decision, item.decision)
    const mergedRule = mergeRuleStrings(existing.matched_rule, item.matched_rule)
    return {
      ...existing,
      decision: mergedDec,
      severity: severityFromDecision(mergedDec, existing.severity),
      response_decision: item.response_decision || item.decision,
      matched_rule: mergedRule,
      latency_ms: (existing.latency_ms || 0) + (item.latency_ms || 0),
      error: item.error || existing.error,
      error_message: item.error_message || existing.error_message,
      payload_preview: item.payload_preview || existing.payload_preview,
    }
  }
  return { ...existing, ...item }
}

/**
 * Merges a live SSE batch into an existing newest-first (DESC) stream.
 * Updates existing rows in place and prepends brand-new rows at index 0,
 * evicting oldest tail records beyond maxRows.
 */
export function mergeAuditBatchDesc(
  prev: AuditEvent[],
  rawBatch: unknown[],
  maxRows = MAX_STREAM_ROWS
): BatchMergeResult {
  const normalized = rawBatch.map(normalizeAuditEvent)
  const next = [...prev]
  const updatedKeys: string[] = []
  const newKeys: string[] = []
  const toPrepend: AuditEvent[] = []

  for (const item of normalized) {
    const key = getRowKey(item)
    const existingIdx = findMatchingIndex(next, item)
    if (existingIdx >= 0) {
      next[existingIdx] = mergeUpdatedRow(next[existingIdx], item)
      if (item.phase === 'response' || item.phase === 'complete') {
        updatedKeys.push(key)
      }
      continue
    }

    const pendingIdx = findMatchingIndex(toPrepend, item)
    if (pendingIdx >= 0) {
      toPrepend[pendingIdx] = mergeUpdatedRow(toPrepend[pendingIdx], item)
      if (item.phase === 'response' || item.phase === 'complete') {
        updatedKeys.push(key)
      }
      continue
    }

    // Place newer batch items before older ones at index 0
    toPrepend.unshift(item)
    newKeys.push(key)
  }

  const combined = toPrepend.length > 0 ? [...toPrepend, ...next] : next
  return {
    nextEvents: combined.slice(0, maxRows),
    updatedKeys,
    newKeys,
    newItems: [...toPrepend].reverse(),
  }
}

export function applyHydratedDetail(
  prev: AuditEvent[],
  rowKey: string,
  lookupId: string,
  detailed: AuditEvent
): AuditEvent[] {
  return prev.map((item, idx) => {
    const itemKey = getRowKey(item, idx)
    if (itemKey === rowKey || (lookupId && item.id === lookupId)) {
      return {
        ...item,
        ...detailed,
        method: detailed.method || item.method,
        event_type: detailed.event_type !== 'EVENT' ? detailed.event_type : item.event_type,
      }
    }
    return item
  })
}

export function filterEventsClientSide(
  events: AuditEvent[],
  selectedVerdict: string,
  matchedRuleFilter: string,
  filterText: string
): AuditEvent[] {
  const ruleQuery = matchedRuleFilter.trim().toLowerCase()
  const searchLower = filterText.trim().toLowerCase()

  return events.filter((ev) => {
    const dec = (ev.decision || '').toUpperCase()

    if (selectedVerdict !== 'ALL') {
      if ((selectedVerdict === 'ALLOWED' || selectedVerdict === 'ALLOW') && dec !== 'ALLOWED' && dec !== 'ALLOW') {
        return false
      }
      if (selectedVerdict === 'MASKED' && dec !== 'MASKED') return false
      if (selectedVerdict === 'AUDIT' && dec !== 'AUDIT') return false
      if (selectedVerdict === 'BLOCKED' && dec !== 'BLOCKED' && dec !== 'ERROR' && dec !== 'CRITICAL') {
        return false
      }
    }

    if (ruleQuery) {
      const matched = (ev.matched_rule || '').toLowerCase().includes(ruleQuery)
      const audited = Boolean(ev.audited_rules?.some((r) => r.toLowerCase().includes(ruleQuery)))
      if (!matched && !audited) return false
    }

    if (!searchLower) return true

    return Boolean(
      ev.event_type?.toLowerCase().includes(searchLower) ||
        ev.method?.toLowerCase().includes(searchLower) ||
        ev.agent?.toLowerCase().includes(searchLower) ||
        ev.tool_name?.toLowerCase().includes(searchLower) ||
        ev.layer?.toLowerCase().includes(searchLower) ||
        ev.matched_rule?.toLowerCase().includes(searchLower) ||
        ev.audited_rules?.some((r) => r.toLowerCase().includes(searchLower)) ||
        ev.trace_id?.toLowerCase().includes(searchLower) ||
        ev.payload_preview?.toLowerCase().includes(searchLower) ||
        ev.error?.toLowerCase().includes(searchLower)
    )
  })
}

export function computeFallbackSummary(events: AuditEvent[], totalCount: number): AuditQuerySummary {
  let allowed = 0
  let masked = 0
  let audit = 0
  let blocked = 0
  let latencySum = 0
  let latencyCount = 0

  for (const ev of events) {
    const dec = (ev.decision || '').toUpperCase()
    if (dec === 'BLOCKED' || dec === 'CRITICAL' || dec === 'ERROR' || ev.severity === 'ERROR' || ev.severity === 'CRITICAL') {
      blocked++
    } else if (dec === 'MASKED' || ev.severity === 'WARN') {
      masked++
    } else if (dec === 'AUDIT' || ev.severity === 'AUDIT') {
      audit++
    } else if (dec !== 'PENDING') {
      allowed++
    }
    if (typeof ev.latency_ms === 'number' && ev.latency_ms >= 0) {
      latencySum += ev.latency_ms
      latencyCount++
    }
  }

  return {
    total: Math.max(totalCount, events.length),
    allowed,
    masked,
    audit,
    blocked,
    avg_latency_ms: latencyCount > 0 ? Math.round(latencySum / latencyCount) : 0,
  }
}
