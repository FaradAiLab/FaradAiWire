import type { AuditEvent } from '../../types.ts'
import { parsePayloadContent } from './formatters.ts'

export type DiffKind = 'context' | 'removed' | 'added'

export interface DiffLine {
  kind: DiffKind
  oldLine?: number
  newLine?: number
  text: string
}

export interface PayloadDiffSection {
  id: 'request' | 'response'
  title: string
  outcomeLabel: string
  beforeLabel: string
  afterLabel: string
  lines: DiffLine[]
  addedCount: number
  removedCount: number
  truncatedForDiff?: boolean
}

export interface RedactionToken {
  text: string
  isRedacted: boolean
}

const REDACTED_SPLIT_RE = /(\[REDACTED(?::[A-Za-z0-9_-]+)?\])/g
const REDACTED_MATCH_RE = /^\[REDACTED(?::[A-Za-z0-9_-]+)?\]$/

export function splitRedactionTokens(text: string): RedactionToken[] {
  if (!text) return [{ text: '', isRedacted: false }]
  return text
    .split(REDACTED_SPLIT_RE)
    .filter((part) => part.length > 0)
    .map((part) => ({
      text: part,
      isRedacted: REDACTED_MATCH_RE.test(part),
    }))
}

export function computeLineDiff(
  beforeText: string,
  afterText: string,
  maxChangedLines = 400
): { lines: DiffLine[]; addedCount: number; removedCount: number; truncatedForDiff: boolean } {
  const a = beforeText === '' ? [] : beforeText.split('\n')
  const b = afterText === '' ? [] : afterText.split('\n')

  let prefix = 0
  while (prefix < a.length && prefix < b.length && a[prefix] === b[prefix]) {
    prefix++
  }

  let suffix = 0
  while (
    suffix < a.length - prefix &&
    suffix < b.length - prefix &&
    a[a.length - 1 - suffix] === b[b.length - 1 - suffix]
  ) {
    suffix++
  }

  const lines: DiffLine[] = []
  for (let i = 0; i < prefix; i++) {
    lines.push({ kind: 'context', oldLine: i + 1, newLine: i + 1, text: a[i] })
  }

  const aMid = a.slice(prefix, a.length - suffix)
  const bMid = b.slice(prefix, b.length - suffix)
  let addedCount = 0
  let removedCount = 0
  let truncatedForDiff = false

  if (aMid.length > maxChangedLines || bMid.length > maxChangedLines || aMid.length * bMid.length > 160000) {
    truncatedForDiff = true
    const aCap = Math.min(aMid.length, maxChangedLines)
    const bCap = Math.min(bMid.length, maxChangedLines)
    for (let i = 0; i < aCap; i++) {
      lines.push({ kind: 'removed', oldLine: prefix + i + 1, text: aMid[i] })
      removedCount++
    }
    if (aMid.length > aCap) {
      lines.push({ kind: 'removed', text: `... (${aMid.length - aCap} more removed lines omitted)` })
    }
    for (let j = 0; j < bCap; j++) {
      lines.push({ kind: 'added', newLine: prefix + j + 1, text: bMid[j] })
      addedCount++
    }
    if (bMid.length > bCap) {
      lines.push({ kind: 'added', text: `... (${bMid.length - bCap} more added lines omitted)` })
    }
  } else if (aMid.length > 0 || bMid.length > 0) {
    const m = aMid.length
    const n = bMid.length
    const dp = Array.from({ length: m + 1 }, () => new Uint32Array(n + 1))

    for (let i = m - 1; i >= 0; i--) {
      for (let j = n - 1; j >= 0; j--) {
        if (aMid[i] === bMid[j]) {
          dp[i][j] = dp[i + 1][j + 1] + 1
        } else {
          dp[i][j] = dp[i + 1][j] >= dp[i][j + 1] ? dp[i + 1][j] : dp[i][j + 1]
        }
      }
    }

    let i = 0
    let j = 0
    while (i < m && j < n) {
      if (aMid[i] === bMid[j]) {
        lines.push({
          kind: 'context',
          oldLine: prefix + i + 1,
          newLine: prefix + j + 1,
          text: aMid[i],
        })
        i++
        j++
      } else if (dp[i + 1][j] >= dp[i][j + 1]) {
        lines.push({ kind: 'removed', oldLine: prefix + i + 1, text: aMid[i] })
        removedCount++
        i++
      } else {
        lines.push({ kind: 'added', newLine: prefix + j + 1, text: bMid[j] })
        addedCount++
        j++
      }
    }
    while (i < m) {
      lines.push({ kind: 'removed', oldLine: prefix + i + 1, text: aMid[i] })
      removedCount++
      i++
    }
    while (j < n) {
      lines.push({ kind: 'added', newLine: prefix + j + 1, text: bMid[j] })
      addedCount++
      j++
    }
  }

  for (let k = 0; k < suffix; k++) {
    const oldIdx = a.length - suffix + k
    const newIdx = b.length - suffix + k
    lines.push({ kind: 'context', oldLine: oldIdx + 1, newLine: newIdx + 1, text: a[oldIdx] })
  }

  return { lines, addedCount, removedCount, truncatedForDiff }
}

function classifyDiffFlags(ev: AuditEvent) {
  const decision = (ev.decision || '').toUpperCase()
  const reqDec = (ev.request_decision || '').toUpperCase()
  const respDec = (ev.response_decision || '').toUpperCase()
  const isBlocked = decision === 'BLOCKED' || decision === 'CRITICAL'

  const hasReqMaskDiff = Boolean(ev.original_request && ev.request && ev.request !== ev.original_request)
  const hasRespMaskDiff = Boolean(ev.original_response && ev.response && ev.response !== ev.original_response)
  const hasIngressBlockDiff = Boolean(
    !hasReqMaskDiff &&
      ev.original_request &&
      ev.response &&
      !ev.original_response &&
      (reqDec === 'BLOCKED' || isBlocked)
  )
  const hasEgressBlockDiff = Boolean(
    ev.original_response && ev.response && (respDec === 'BLOCKED' || isBlocked)
  )
  const hasLegacyDiff = Boolean(
    !hasReqMaskDiff &&
      !hasRespMaskDiff &&
      !hasIngressBlockDiff &&
      !hasEgressBlockDiff &&
      ev.original_payload &&
      ev.original_payload.trim() &&
      ev.original_payload !== ev.payload_preview
  )

  return {
    hasReqMaskDiff,
    hasRespMaskDiff,
    hasIngressBlockDiff,
    hasEgressBlockDiff,
    hasLegacyDiff,
  }
}

export function hasMutationDiff(ev: AuditEvent): boolean {
  const f = classifyDiffFlags(ev)
  return f.hasReqMaskDiff || f.hasRespMaskDiff || f.hasIngressBlockDiff || f.hasEgressBlockDiff || f.hasLegacyDiff
}

export function buildAuditDiffSections(ev: AuditEvent): PayloadDiffSection[] {
  const flags = classifyDiffFlags(ev)
  const sections: PayloadDiffSection[] = []

  if (flags.hasReqMaskDiff) {
    const before = parsePayloadContent(ev.original_request).displayText
    const after = parsePayloadContent(ev.request).displayText
    const diff = computeLineDiff(before, after)
    sections.push({
      id: 'request',
      title: 'Request Payload',
      outcomeLabel: 'Modified before upstream',
      beforeLabel: 'Original Request (Raw)',
      afterLabel: 'Dispatched Request (Filtered)',
      ...diff,
    })
  } else if (flags.hasIngressBlockDiff) {
    const before = parsePayloadContent(ev.original_request).displayText
    const after = parsePayloadContent(ev.response).displayText
    const diff = computeLineDiff(before, after)
    sections.push({
      id: 'request',
      title: 'Ingress Security Block',
      outcomeLabel: 'Blocked at ingress',
      beforeLabel: 'Original Request (Raw)',
      afterLabel: 'Blocked Error Response (Client)',
      ...diff,
    })
  }

  if (flags.hasRespMaskDiff || flags.hasEgressBlockDiff) {
    const before = parsePayloadContent(ev.original_response).displayText
    const after = parsePayloadContent(ev.response).displayText
    const diff = computeLineDiff(before, after)
    sections.push({
      id: 'response',
      title: flags.hasEgressBlockDiff ? 'Egress Security Block' : 'Response Payload',
      outcomeLabel: flags.hasEgressBlockDiff ? 'Blocked at egress' : 'Modified before client',
      beforeLabel: 'Original Response (Upstream Raw)',
      afterLabel: 'Final Response (Client)',
      ...diff,
    })
  }

  if (sections.length === 0 && flags.hasLegacyDiff) {
    const before = parsePayloadContent(ev.original_payload).displayText
    const after = parsePayloadContent(ev.payload_preview).displayText
    const diff = computeLineDiff(before, after)
    sections.push({
      id: 'request',
      title: 'Payload Mutation',
      outcomeLabel: 'Modified by filter',
      beforeLabel: 'Original Payload (Raw)',
      afterLabel: 'Processed Payload',
      ...diff,
    })
  }

  return sections
}

export function countDiffChanges(sections: PayloadDiffSection[]): number {
  return sections.reduce((sum, s) => sum + s.addedCount + s.removedCount, 0)
}

export function formatDiffSectionsAsText(sections: PayloadDiffSection[]): string {
  if (sections.length === 0) return ''
  return sections
    .map((sec) => {
      const header = `=== ${sec.title} (${sec.outcomeLabel}) ===\n--- ${sec.beforeLabel}\n+++ ${sec.afterLabel}`
      const body = sec.lines
        .map((line) => {
          const prefix = line.kind === 'removed' ? '- ' : line.kind === 'added' ? '+ ' : '  '
          return `${prefix}${line.text}`
        })
        .join('\n')
      return `${header}\n${body}`
    })
    .join('\n\n')
}
