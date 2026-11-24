import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  normalizeAuditEvent,
  getEventTargetLabel,
  getCopyableContent,
  parsePayloadContent,
  formatSmartDate,
  toRFC3339LocalInput,
  summarizeDuckDBVerify,
} from './formatters.ts'
import {
  mergeAuditBatchDesc,
  applyHydratedDetail,
  filterEventsClientSide,
  computeFallbackSummary,
} from './streamLogic.ts'

describe('formatters & normalization', () => {
  it('labels tools/list and legacy response rows as method rather than tool:response', () => {
    const evList = normalizeAuditEvent({
      id: 'inv-list-1',
      timestamp: '2026-11-24T00:00:00Z',
      method: 'tools/list',
      tool_name: 'tools/list',
      decision: 'ALLOWED',
    })
    assert.equal(evList.method, 'tools/list')
    assert.deepEqual(getEventTargetLabel(evList), { kind: 'method', label: 'method:tools/list' })

    const evLegacyResp = normalizeAuditEvent({
      id: 'inv-legacy-resp',
      timestamp: '2026-11-24T00:00:00Z',
      tool_name: 'response',
      decision: 'ALLOWED',
    })
    assert.deepEqual(getEventTargetLabel(evLegacyResp), { kind: 'method', label: 'method:response' })

    const evTool = normalizeAuditEvent({
      id: 'inv-tool-1',
      timestamp: '2026-11-24T00:00:00Z',
      tool_name: 'codegraph_explore',
      decision: 'ALLOWED',
    })
    assert.deepEqual(getEventTargetLabel(evTool), { kind: 'tool', label: 'tool:codegraph_explore' })
  })

  it('copies exact content for active inspector tab rather than truncated preview', () => {
    const ev = normalizeAuditEvent({
      id: 'inv-copy-1',
      timestamp: '2026-11-24T00:00:00Z',
      tool_name: 'query_db',
      decision: 'MASKED',
      payload_preview: 'truncated-preview',
      original_request: '{"query":"12345678901"}',
      request: '{"query":"[REDACTED:TCKN]"}',
      original_response: '{"ok":true}',
    })

    const payloadsCopy = getCopyableContent(ev, 'payloads')
    assert.match(payloadsCopy, /12345678901/)
    assert.match(payloadsCopy, /\[REDACTED:TCKN\]/)
    assert.doesNotMatch(payloadsCopy, /^truncated-preview$/)

    const jsonCopy = getCopyableContent(ev, 'json')
    assert.match(jsonCopy, /"query": "\[REDACTED:TCKN\]"/)

    const rawCopy = getCopyableContent(ev, 'raw')
    assert.match(rawCopy, /"id": "inv-copy-1"/)

    const diffCopy = getCopyableContent(ev, 'diff', '--- Request\n- 12345678901\n+ [REDACTED:TCKN]')
    assert.match(diffCopy, /\[REDACTED:TCKN\]/)
  })

  it('pretty-prints structured MCP payload content', () => {
    const parsed = parsePayloadContent('{"name":"read_file","arguments":{"path":"README.md"}}')
    assert.equal(parsed.isJson, true)
    assert.match(parsed.displayText, /Tool: read_file/)
    assert.match(parsed.displayText, /README\.md/)
  })
})

describe('streamLogic DESC chronology & zero-jump merging', () => {
  it('prepends newest SSE events at index 0 and evicts oldest beyond 500', () => {
    const initial = Array.from({ length: 500 }, (_, i) =>
      normalizeAuditEvent({
        id: `old-${i}`,
        timestamp: `2026-11-24T00:00:${String(i % 60).padStart(2, '0')}Z`,
        tool_name: 'old_tool',
        decision: 'ALLOWED',
      })
    )

    const { nextEvents, newKeys } = mergeAuditBatchDesc(initial, [
      {
        id: 'newest-1',
        timestamp: '2026-11-24T00:10:00Z',
        tool_name: 'new_tool',
        decision: 'ALLOWED',
      },
    ])

    assert.equal(nextEvents.length, 500)
    assert.equal(nextEvents[0].id, 'newest-1')
    assert.equal(nextEvents[499].id, 'old-498')
    assert.deepEqual(newKeys, ['newest-1'])
  })

  it('updates existing PENDING record in-place on response phase without duplicating or reordering', () => {
    const existing = [
      normalizeAuditEvent({
        id: 'inv-2',
        timestamp: '2026-11-24T00:01:00Z',
        tool_name: 'tool_b',
        decision: 'ALLOWED',
      }),
      normalizeAuditEvent({
        id: 'inv-1',
        timestamp: '2026-11-24T00:00:50Z',
        tool_name: 'tool_a',
        phase: 'request',
        decision: 'PENDING',
        request_decision: 'ALLOWED',
        latency_ms: 1,
      }),
    ]

    const { nextEvents, updatedKeys, newKeys } = mergeAuditBatchDesc(existing, [
      {
        id: 'inv-1',
        timestamp: '2026-11-24T00:00:51Z',
        tool_name: 'tool_a',
        phase: 'response',
        decision: 'MASKED',
        response_decision: 'MASKED',
        matched_rule: 'email',
        latency_ms: 4,
      },
    ])

    assert.equal(nextEvents.length, 2)
    assert.equal(nextEvents[1].id, 'inv-1')
    assert.equal(nextEvents[1].decision, 'MASKED')
    assert.equal(nextEvents[1].latency_ms, 5)
    assert.deepEqual(updatedKeys, ['inv-1'])
    assert.deepEqual(newKeys, [])
  })

  it('hydrates full 4-field detail onto matching row in place without changing order', () => {
    const rows = [
      normalizeAuditEvent({ id: 'inv-a', timestamp: '2026-11-24T00:01:00Z', decision: 'ALLOWED' }),
      normalizeAuditEvent({ id: 'inv-b', timestamp: '2026-11-24T00:00:00Z', decision: 'MASKED' }),
    ]
    const hydrated = normalizeAuditEvent({
      id: 'inv-b',
      timestamp: '2026-11-24T00:00:00Z',
      decision: 'MASKED',
      original_response: '{"email":"a@b.com"}',
      response: '{"email":"[REDACTED:EMAIL]"}',
    })

    const next = applyHydratedDetail(rows, 'inv-b', 'inv-b', hydrated)
    assert.equal(next[0].id, 'inv-a')
    assert.equal(next[1].original_response, '{"email":"a@b.com"}')
    assert.equal(next[1].response, '{"email":"[REDACTED:EMAIL]"}')
  })

  it('matches BLOCKED filter across BLOCKED, ERROR, and CRITICAL identically to SQL', () => {
    const list = [
      normalizeAuditEvent({ id: '1', timestamp: '2026-11-24T00:00:00Z', decision: 'ALLOWED' }),
      normalizeAuditEvent({ id: '2', timestamp: '2026-11-24T00:00:01Z', decision: 'BLOCKED' }),
      normalizeAuditEvent({ id: '3', timestamp: '2026-11-24T00:00:02Z', decision: 'ERROR' }),
      normalizeAuditEvent({ id: '4', timestamp: '2026-11-24T00:00:03Z', decision: 'CRITICAL' }),
    ]
    const blocked = filterEventsClientSide(list, 'BLOCKED', '', '')
    assert.deepEqual(
      blocked.map((e) => e.id),
      ['2', '3', '4']
    )
  })

  it('consolidates same-batch request+response without keeping stale PENDING in newItems', () => {
    const { nextEvents, newItems, newKeys, updatedKeys } = mergeAuditBatchDesc([], [
      {
        id: 'inv-same-batch',
        timestamp: '2026-11-24T00:02:00Z',
        tool_name: 'read_file',
        phase: 'request',
        decision: 'PENDING',
        request_decision: 'ALLOWED',
        matched_rule: 'email,tckn',
        latency_ms: 2,
      },
      {
        id: 'inv-same-batch',
        timestamp: '2026-11-24T00:02:01Z',
        tool_name: 'read_file',
        phase: 'response',
        decision: 'MASKED',
        response_decision: 'MASKED',
        matched_rule: 'email',
        latency_ms: 5,
      },
    ])

    assert.equal(nextEvents.length, 1)
    assert.equal(nextEvents[0].decision, 'MASKED')
    assert.equal(nextEvents[0].latency_ms, 7)
    assert.equal(nextEvents[0].matched_rule, 'email,tckn')
    assert.equal(newItems.length, 1)
    assert.equal(newItems[0].decision, 'MASKED')
    assert.equal(newItems[0].latency_ms, 7)
    assert.deepEqual(newKeys, ['inv-same-batch'])
    assert.deepEqual(updatedKeys, ['inv-same-batch'])
  })

  it('preserves chronological order in newItems when multiple new events arrive in one batch', () => {
    const firstMerge = mergeAuditBatchDesc([], [
      { id: 't1', timestamp: '2026-11-24T00:01:00Z', decision: 'ALLOWED' },
      { id: 't2', timestamp: '2026-11-24T00:02:00Z', decision: 'ALLOWED' },
      { id: 't3', timestamp: '2026-11-24T00:03:00Z', decision: 'ALLOWED' },
    ])

    assert.deepEqual(
      firstMerge.nextEvents.map((e) => e.id),
      ['t3', 't2', 't1']
    )
    assert.deepEqual(
      firstMerge.newItems.map((e) => e.id),
      ['t1', 't2', 't3']
    )

    // Replaying buffered newItems into empty stream retains newest-first order
    const flushed = mergeAuditBatchDesc([], firstMerge.newItems)
    assert.deepEqual(
      flushed.nextEvents.map((e) => e.id),
      ['t3', 't2', 't1']
    )
  })

  it('deduplicates comma-separated matched_rule tokens on response update', () => {
    const existing = [
      normalizeAuditEvent({
        id: 'inv-rule-dedup',
        timestamp: '2026-11-24T00:01:00Z',
        phase: 'request',
        decision: 'PENDING',
        matched_rule: 'email,tckn',
      }),
    ]

    const merged = mergeAuditBatchDesc(existing, [
      {
        id: 'inv-rule-dedup',
        timestamp: '2026-11-24T00:01:01Z',
        phase: 'response',
        decision: 'MASKED',
        matched_rule: 'email,credit_card',
      },
    ])

    assert.equal(merged.nextEvents[0].matched_rule, 'email,tckn,credit_card')
  })

  it('matches ALLOW alias and filters by audited_rules, method, and trace_id', () => {
    const list = [
      {
        ...normalizeAuditEvent({
          id: 'ev-allow',
          trace_id: 'tr-allow-99',
          method: 'tools/list',
          tool_name: 'tools/list',
          decision: 'ALLOWED',
          audited_rules: ['soft_pii_rule'],
        }),
        decision: 'ALLOW',
      },
      normalizeAuditEvent({
        id: 'ev-other',
        trace_id: 'tr-other',
        method: 'tools/call',
        tool_name: 'exec',
        decision: 'BLOCKED',
      }),
    ]

    const allowedMatches = filterEventsClientSide(list, 'ALLOWED', 'soft_pii', 'tools/list')
    assert.deepEqual(
      allowedMatches.map((e) => e.id),
      ['ev-allow']
    )

    const traceMatches = filterEventsClientSide(list, 'ALL', '', 'TR-ALLOW-99')
    assert.deepEqual(
      traceMatches.map((e) => e.id),
      ['ev-allow']
    )
  })

  it('computes fallback summary ignoring PENDING counts and invalid latencies while preserving totalCount', () => {
    const list = [
      normalizeAuditEvent({ id: '1', decision: 'ALLOWED', latency_ms: 10 }),
      normalizeAuditEvent({ id: '2', decision: 'MASKED', latency_ms: 20 }),
      normalizeAuditEvent({ id: '3', decision: 'AUDIT', latency_ms: 30 }),
      normalizeAuditEvent({ id: '4', decision: 'BLOCKED', latency_ms: -5 }),
      normalizeAuditEvent({ id: '5', decision: 'PENDING' }),
    ]
    const summary = computeFallbackSummary(list, 120)
    assert.deepEqual(summary, {
      total: 120,
      allowed: 1,
      masked: 1,
      audit: 1,
      blocked: 1,
      avg_latency_ms: 20,
    })
  })
})

describe('formatter utilities & edge cases', () => {
  it('formats Today, Yesterday, older dates, and falls back gracefully on invalid dates', () => {
    const now = new Date()
    const yesterday = new Date(now)
    yesterday.setDate(yesterday.getDate() - 1)
    const older = new Date('2025-01-15T10:20:30Z')

    assert.match(formatSmartDate(now.toISOString()).display, /^Today, /)
    assert.match(formatSmartDate(yesterday.toISOString()).display, /^Yesterday, /)
    const olderFormatted = formatSmartDate(older.toISOString())
    assert.doesNotMatch(olderFormatted.display, /^(Today|Yesterday), /)
    assert.equal(olderFormatted.iso, older.toISOString())

    assert.deepEqual(formatSmartDate('not-a-date'), {
      display: 'not-a-date',
      iso: 'not-a-date',
    })
  })

  it('converts local datetime inputs to RFC3339 or undefined when empty/invalid', () => {
    assert.equal(toRFC3339LocalInput('   '), undefined)
    assert.equal(toRFC3339LocalInput('invalid-date'), undefined)
    const iso = toRFC3339LocalInput('2026-11-24T10:30')
    assert.ok(iso && iso.endsWith('Z') && iso.includes('T'))
  })

  it('aggregates DuckDB verification totals across tables including optional tampered_ids', () => {
    const totals = summarizeDuckDBVerify({
      valid: false,
      hmac_enabled: true,
      tool_audit_logs: { checked: 10, v2_verified: 8, legacy_v1: 1, tampered_ids: ['t1'] },
      tool_audit_responses: { checked: 5, v2_verified: 5, legacy_v1: 0 },
      security_audit_logs: { checked: 2, v2_verified: 1, legacy_v1: 1, tampered_ids: ['s1'] },
    })
    assert.deepEqual(totals, {
      checked: 17,
      v2_verified: 14,
      legacy_v1: 2,
      tampered_ids: ['t1', 's1'],
    })
  })

  it('handles getCopyableContent edge cases for empty payloads, legacy diff, and ingress blocks', () => {
    const emptyEv = normalizeAuditEvent({ id: 'empty-1', timestamp: '2026-11-24T00:00:00Z' })
    assert.equal(getCopyableContent(emptyEv, 'payloads'), '(Empty payload)')
    assert.equal(getCopyableContent(emptyEv, 'diff'), 'No mutation diff available.')

    const legacyDiffEv = normalizeAuditEvent({
      id: 'leg-diff',
      timestamp: '2026-11-24T00:00:00Z',
      original_payload: 'raw-secret',
      payload_preview: '[REDACTED]',
    })
    assert.match(getCopyableContent(legacyDiffEv, 'diff'), /--- Original\nraw-secret/)

    const ingressBlockedEv = normalizeAuditEvent({
      id: 'blk-copy',
      timestamp: '2026-11-24T00:00:00Z',
      decision: 'BLOCKED',
      original_request: '{"cmd":"rm"}',
      response: '{"error":{"message":"Blocked"}}',
    })
    const copiedBlock = getCopyableContent(ingressBlockedEv, 'diff')
    assert.match(copiedBlock, /--- Original Request/)
    assert.match(copiedBlock, /--- Original Response/)
  })
})
