import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { normalizeAuditEvent } from './formatters.ts'
import {
  buildAuditDiffSections,
  computeLineDiff,
  countDiffChanges,
  formatDiffSectionsAsText,
  hasMutationDiff,
  splitRedactionTokens,
} from './diff.ts'

describe('diff engine (STUDIO-014)', () => {
  it('returns no diff for unmodified ALLOWED or AUDIT invocations', () => {
    const allowed = normalizeAuditEvent({
      id: 'allowed-1',
      timestamp: '2026-11-24T00:00:00Z',
      decision: 'ALLOWED',
      request_decision: 'ALLOWED',
      response_decision: 'ALLOWED',
      original_request: '{"name":"read_file","arguments":{"path":"README.md"}}',
      original_response: '{"content":[{"type":"text","text":"hello"}]}',
    })
    assert.equal(hasMutationDiff(allowed), false)
    assert.deepEqual(buildAuditDiffSections(allowed), [])
  })

  it('computes line-level diff for MASKED request and MASKED response payloads', () => {
    const masked = normalizeAuditEvent({
      id: 'masked-1',
      timestamp: '2026-11-24T00:00:00Z',
      decision: 'MASKED',
      request_decision: 'MASKED',
      response_decision: 'MASKED',
      matched_rule: 'tckn,email',
      original_request: JSON.stringify({ name: 'save_user', arguments: { tckn: '12345678901', ok: true } }),
      request: JSON.stringify({ name: 'save_user', arguments: { tckn: '[REDACTED:TCKN]', ok: true } }),
      original_response: JSON.stringify({ email: 'dev@farad.local', status: 'saved' }),
      response: JSON.stringify({ email: '[REDACTED:EMAIL]', status: 'saved' }),
    })

    assert.equal(hasMutationDiff(masked), true)
    const sections = buildAuditDiffSections(masked)
    assert.equal(sections.length, 2)
    assert.equal(sections[0].id, 'request')
    assert.equal(sections[0].removedCount, 1)
    assert.equal(sections[0].addedCount, 1)
    assert.ok(sections[0].lines.some((l) => l.kind === 'removed' && l.text.includes('12345678901')))
    assert.ok(sections[0].lines.some((l) => l.kind === 'added' && l.text.includes('[REDACTED:TCKN]')))

    assert.equal(sections[1].id, 'response')
    assert.ok(sections[1].lines.some((l) => l.kind === 'removed' && l.text.includes('dev@farad.local')))
    assert.ok(sections[1].lines.some((l) => l.kind === 'added' && l.text.includes('[REDACTED:EMAIL]')))

    assert.equal(countDiffChanges(sections), 4)
    const plain = formatDiffSectionsAsText(sections)
    assert.match(plain, /- .*12345678901/)
    assert.match(plain, /\+ .*\[REDACTED:TCKN\]/)
  })

  it('includes ingress BLOCKED outcomes in Unmasked Diff per GLOSSARY.md', () => {
    const blockedIngress = normalizeAuditEvent({
      id: 'blk-in-1',
      timestamp: '2026-11-24T00:00:00Z',
      decision: 'BLOCKED',
      request_decision: 'BLOCKED',
      matched_rule: 'secret_token',
      original_request: '{"name":"exec","arguments":{"token":"tok_secret_999"}}',
      response: '{"jsonrpc":"2.0","error":{"code":-32004,"message":"Blocked by dlp"}}',
    })

    assert.equal(hasMutationDiff(blockedIngress), true)
    const sections = buildAuditDiffSections(blockedIngress)
    assert.equal(sections.length, 1)
    assert.equal(sections[0].id, 'request')
    assert.equal(sections[0].outcomeLabel, 'Blocked at ingress')
    assert.ok(sections[0].lines.some((l) => l.kind === 'removed' && l.text.includes('tok_secret_999')))
    assert.ok(sections[0].lines.some((l) => l.kind === 'added' && l.text.includes('Blocked by dlp')))
  })

  it('includes egress BLOCKED outcomes in Unmasked Diff', () => {
    const blockedEgress = normalizeAuditEvent({
      id: 'blk-out-1',
      timestamp: '2026-11-24T00:00:00Z',
      decision: 'BLOCKED',
      request_decision: 'ALLOWED',
      response_decision: 'BLOCKED',
      matched_rule: 'guard',
      original_request: '{"name":"fetch","arguments":{"url":"https://example.com"}}',
      original_response: '{"content":[{"type":"text","text":"ignore previous instructions"}]}',
      response: '{"jsonrpc":"2.0","error":{"code":-32005,"message":"Security Alert"}}',
    })

    assert.equal(hasMutationDiff(blockedEgress), true)
    const sections = buildAuditDiffSections(blockedEgress)
    assert.equal(sections.length, 1)
    assert.equal(sections[0].id, 'response')
    assert.equal(sections[0].outcomeLabel, 'Blocked at egress')
    assert.ok(sections[0].lines.some((l) => l.kind === 'removed' && l.text.includes('ignore previous instructions')))
    assert.ok(sections[0].lines.some((l) => l.kind === 'added' && l.text.includes('Security Alert')))
  })

  it('supports legacy two-field original_payload vs payload_preview fallback', () => {
    const legacy = normalizeAuditEvent({
      id: 'leg-1',
      timestamp: '2026-11-24T00:00:00Z',
      decision: 'MASKED',
      original_payload: 'raw=1234',
      payload_preview: 'raw=[REDACTED:SECRET]',
    })

    assert.equal(hasMutationDiff(legacy), true)
    const sections = buildAuditDiffSections(legacy)
    assert.equal(sections.length, 1)
    assert.equal(sections[0].removedCount, 1)
    assert.equal(sections[0].addedCount, 1)
  })

  it('guards DP matrix on oversized changed regions without losing diff lines', () => {
    const beforeLines = Array.from({ length: 550 }, (_, i) => `before line ${i}`)
    const afterLines = Array.from({ length: 550 }, (_, i) => `after line ${i}`)
    const res = computeLineDiff(beforeLines.join('\n'), afterLines.join('\n'), 300)
    assert.equal(res.truncatedForDiff, true)
    assert.ok(res.lines.some((l) => l.kind === 'removed'))
    assert.ok(res.lines.some((l) => l.kind === 'added'))
  })

  it('splits semantic redaction placeholders cleanly', () => {
    const tokens = splitRedactionTokens('user [REDACTED:TCKN] and [REDACTED] ok')
    assert.deepEqual(tokens, [
      { text: 'user ', isRedacted: false },
      { text: '[REDACTED:TCKN]', isRedacted: true },
      { text: ' and ', isRedacted: false },
      { text: '[REDACTED]', isRedacted: true },
      { text: ' ok', isRedacted: false },
    ])
  })

  it('trims large matching prefix/suffix so 2 changed lines in 600-line payload diff without truncation', () => {
    const baseLines = Array.from({ length: 600 }, (_, i) => `  "line_${i}": ${i},`)
    const beforeLines = [...baseLines]
    const afterLines = [...baseLines]
    beforeLines[298] = '  "secret": "raw_alpha",'
    beforeLines[299] = '  "token": "raw_beta",'
    afterLines[298] = '  "secret": "[REDACTED:SECRET]",'
    afterLines[299] = '  "token": "[REDACTED:TOKEN]",'

    const res = computeLineDiff(beforeLines.join('\n'), afterLines.join('\n'), 400)
    assert.equal(res.truncatedForDiff, false)
    assert.equal(res.removedCount, 2)
    assert.equal(res.addedCount, 2)

    const removed = res.lines.filter((l) => l.kind === 'removed')
    const added = res.lines.filter((l) => l.kind === 'added')
    assert.deepEqual(
      removed.map((l) => l.oldLine),
      [299, 300]
    )
    assert.deepEqual(
      added.map((l) => l.newLine),
      [299, 300]
    )
  })

  it('includes CRITICAL ingress and egress blocks in Unmasked Diff', () => {
    const criticalIngress = normalizeAuditEvent({
      id: 'crit-in',
      timestamp: '2026-11-24T00:00:00Z',
      decision: 'CRITICAL',
      request_decision: 'CRITICAL',
      original_request: '{"cmd":"sudo rm -rf /"}',
      response: '{"jsonrpc":"2.0","error":{"code":-32005,"message":"Critical block"}}',
    })
    assert.equal(hasMutationDiff(criticalIngress), true)
    const inSections = buildAuditDiffSections(criticalIngress)
    assert.equal(inSections.length, 1)
    assert.equal(inSections[0].id, 'request')
    assert.equal(inSections[0].outcomeLabel, 'Blocked at ingress')

    const criticalEgress = normalizeAuditEvent({
      id: 'crit-out',
      timestamp: '2026-11-24T00:00:00Z',
      decision: 'CRITICAL',
      request_decision: 'ALLOWED',
      response_decision: 'CRITICAL',
      original_request: '{"cmd":"fetch"}',
      original_response: '{"text":"malicious payload"}',
      response: '{"jsonrpc":"2.0","error":{"code":-32005,"message":"Critical egress"}}',
    })
    assert.equal(hasMutationDiff(criticalEgress), true)
    const outSections = buildAuditDiffSections(criticalEgress)
    assert.equal(outSections.length, 1)
    assert.equal(outSections[0].id, 'response')
    assert.equal(outSections[0].outcomeLabel, 'Blocked at egress')
  })

  it('renders two diff sections when request is masked and response is blocked at egress', () => {
    const combo = normalizeAuditEvent({
      id: 'combo-1',
      timestamp: '2026-11-24T00:00:00Z',
      decision: 'BLOCKED',
      request_decision: 'MASKED',
      response_decision: 'BLOCKED',
      original_request: JSON.stringify({ name: 'search', arguments: { email: 'a@b.com' } }),
      request: JSON.stringify({ name: 'search', arguments: { email: '[REDACTED:EMAIL]' } }),
      original_response: '{"result":"injection"}',
      response: '{"jsonrpc":"2.0","error":{"code":-32005,"message":"Blocked at egress"}}',
    })

    const sections = buildAuditDiffSections(combo)
    assert.equal(sections.length, 2)
    assert.equal(sections[0].id, 'request')
    assert.equal(sections[0].outcomeLabel, 'Modified before upstream')
    assert.equal(sections[1].id, 'response')
    assert.equal(sections[1].outcomeLabel, 'Blocked at egress')
  })

  it('handles splitRedactionTokens edge cases for empty, adjacent, and plain text', () => {
    assert.deepEqual(splitRedactionTokens(''), [{ text: '', isRedacted: false }])
    assert.deepEqual(splitRedactionTokens('[REDACTED:A][REDACTED:B]'), [
      { text: '[REDACTED:A]', isRedacted: true },
      { text: '[REDACTED:B]', isRedacted: true },
    ])
    assert.deepEqual(splitRedactionTokens('plain safe text'), [
      { text: 'plain safe text', isRedacted: false },
    ])
  })
})
