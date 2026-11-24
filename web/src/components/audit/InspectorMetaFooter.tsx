import React from 'react'
import type { AuditEvent } from '../../types'

interface InspectorMetaFooterProps {
  event: AuditEvent
}

export const InspectorMetaFooter: React.FC<InspectorMetaFooterProps> = ({ event }) => {
  return (
    <div className="shrink-0 grid grid-cols-2 sm:grid-cols-4 gap-2 px-4 py-2.5 border-t border-subtle bg-canvas/80 text-[11px] font-mono text-secondary">
      <div className="truncate">
        <span className="text-muted">Layer:</span> {event.layer || 'pipeline'}
      </div>
      <div className="truncate">
        <span className="text-muted">Client:</span>{' '}
        {event.client_ip || event.client_session_id || 'localhost'}
      </div>
      <div className="truncate" title={event.trace_id || ''}>
        <span className="text-muted">Trace:</span>{' '}
        {event.trace_id ? `${event.trace_id.substring(0, 14)}…` : 'none'}
      </div>
      <div className="tabular-nums">
        <span className="text-muted">Latency:</span>{' '}
        {event.latency_ms !== undefined ? `${event.latency_ms}ms` : '0ms'}
      </div>
      {event.api_key_id && (
        <div className="truncate">
          <span className="text-muted">Key:</span> {event.api_key_id}
        </div>
      )}
      {event.approved_by && (
        <div className="truncate">
          <span className="text-muted">Approved:</span> {event.approved_by} ({event.approval_channel || 'hitl'})
        </div>
      )}
      {event.hash_version && (
        <div>
          <span className="text-muted">Hash:</span> {event.hash_version}
        </div>
      )}
    </div>
  )
}
