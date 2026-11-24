import React from 'react'
import type { AuditEvent } from '../../types'
import { parsePayloadContent } from './formatters'
import { RedactedText } from './RedactedText'

interface PayloadLifecycleViewProps {
  event: AuditEvent
  isLoadingDetail?: boolean
  detailError?: string | null
}

const VIEWPORT_CLS =
  'bg-[#F4F6FA] dark:bg-[#0D1422] text-[#0F172A] dark:text-slate-100 border border-slate-200 dark:border-white/10 p-3.5 rounded-xl font-mono text-xs max-h-72 overflow-y-auto leading-relaxed'

export const PayloadLifecycleView: React.FC<PayloadLifecycleViewProps> = ({
  event,
  isLoadingDetail = false,
  detailError = null,
}) => {
  const hasFourFields = Boolean(
    event.original_request || event.request || event.original_response || event.response
  )

  if (!hasFourFields) {
    const legacy = parsePayloadContent(event.payload_preview)
    const fallbackLabel = isLoadingDetail
      ? 'Loading full payloads…'
      : detailError
      ? 'Summary preview (full detail unavailable)'
      : 'Legacy single-pane record'
    return (
      <div className="space-y-1.5">
        <div className="flex items-center justify-between text-xs gap-2">
          <span className="font-semibold text-primary">Captured Payload</span>
          <span className="text-[11px] font-mono text-secondary">{fallbackLabel}</span>
        </div>
        <div className={VIEWPORT_CLS}>
          <RedactedText text={legacy.displayText} />
        </div>
      </div>
    )
  }

  const parsedOrigReq = parsePayloadContent(event.original_request)
  const parsedSentReq = parsePayloadContent(event.request || event.original_request)
  const parsedOrigResp = parsePayloadContent(event.original_response)
  const parsedFinalResp = parsePayloadContent(event.response || event.original_response)

  const hasReqDiff = Boolean(
    event.original_request && event.request && event.request !== event.original_request
  )
  const isReqBlocked = (event.request_decision || '').toUpperCase() === 'BLOCKED'
  const hasRespDiff = Boolean(
    event.original_response && event.response && event.response !== event.original_response
  )
  const isRespBlocked = (event.response_decision || '').toUpperCase() === 'BLOCKED'

  const reqBadge = hasReqDiff
    ? {
        text: 'Modified before upstream',
        cls: 'bg-amber-50 text-amber-900 border-amber-300 dark:bg-amber-950/60 dark:text-amber-200 dark:border-amber-700/60',
      }
    : isReqBlocked
    ? {
        text: 'Blocked at ingress',
        cls: 'bg-rose-50 text-rose-800 border-rose-300 dark:bg-rose-950/60 dark:text-rose-200 dark:border-rose-700/60',
      }
    : {
        text: 'Unmodified · Forwarded as-is',
        cls: 'bg-slate-100 text-slate-700 border-slate-200 dark:bg-white/5 dark:text-slate-300 dark:border-white/10',
      }

  const respBadge = hasRespDiff
    ? {
        text: isRespBlocked ? 'Blocked at egress' : 'Masked before client',
        cls: isRespBlocked
          ? 'bg-rose-50 text-rose-800 border-rose-300 dark:bg-rose-950/60 dark:text-rose-200 dark:border-rose-700/60'
          : 'bg-amber-50 text-amber-900 border-amber-300 dark:bg-amber-950/60 dark:text-amber-200 dark:border-amber-700/60',
      }
    : event.response && !event.original_response
    ? {
        text: 'Error response returned',
        cls: 'bg-rose-50 text-rose-800 border-rose-300 dark:bg-rose-950/60 dark:text-rose-200 dark:border-rose-700/60',
      }
    : event.original_response || event.response
    ? {
        text: 'Unmodified · Delivered as-is',
        cls: 'bg-slate-100 text-slate-700 border-slate-200 dark:bg-white/5 dark:text-slate-300 dark:border-white/10',
      }
    : {
        text: 'Awaiting response',
        cls: 'bg-sky-50 text-sky-800 border-sky-200 dark:bg-sky-950/50 dark:text-sky-200 dark:border-sky-800/50',
      }

  return (
    <div className="space-y-4">
      {/* Request Stage */}
      <section className="space-y-2">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <h4 className="text-xs font-semibold text-sky-700 dark:text-sky-400">Request</h4>
            <span className={`px-2 py-0.5 rounded-md text-[11px] font-medium border ${reqBadge.cls}`}>
              {reqBadge.text}
            </span>
          </div>
          {event.request_decision && (
            <span className="text-[11px] font-mono text-secondary">
              req:{event.request_decision}
            </span>
          )}
        </div>

        <div className={VIEWPORT_CLS}>
          {event.original_request ? (
            <RedactedText text={parsedOrigReq.displayText} />
          ) : (
            <span className="text-muted">No request payload recorded</span>
          )}
        </div>

        {hasReqDiff && (
          <div className="space-y-1.5 pl-3 border-l-2 border-emerald-400 dark:border-emerald-600">
            <div className="text-[11px] font-semibold text-emerald-700 dark:text-emerald-400">
              Dispatched Request (Upstream)
            </div>
            <div className={VIEWPORT_CLS}>
              <RedactedText text={parsedSentReq.displayText} />
            </div>
          </div>
        )}
      </section>

      {/* Response Stage */}
      <section className="space-y-2">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <h4 className="text-xs font-semibold text-purple-700 dark:text-purple-400">Response</h4>
            <span className={`px-2 py-0.5 rounded-md text-[11px] font-medium border ${respBadge.cls}`}>
              {respBadge.text}
            </span>
          </div>
          {event.response_decision && (
            <span className="text-[11px] font-mono text-secondary">
              resp:{event.response_decision}
            </span>
          )}
        </div>

        <div className={VIEWPORT_CLS}>
          {event.original_response ? (
            <RedactedText text={parsedOrigResp.displayText} />
          ) : event.response ? (
            <RedactedText text={parsedFinalResp.displayText} />
          ) : (
            <span className="text-muted">Awaiting or no response payload</span>
          )}
        </div>

        {hasRespDiff && (
          <div className="space-y-1.5 pl-3 border-l-2 border-amber-400 dark:border-amber-600">
            <div className="text-[11px] font-semibold text-amber-800 dark:text-amber-300">
              Final Response (Delivered to Client)
            </div>
            <div className={VIEWPORT_CLS}>
              <RedactedText text={parsedFinalResp.displayText} />
            </div>
          </div>
        )}
      </section>
    </div>
  )
}
