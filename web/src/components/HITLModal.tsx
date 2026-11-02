import React, { useState, useEffect, useCallback, memo } from 'react'
import { ShieldAlert, AlertTriangle, CheckCircle2, XCircle, Clock, Terminal, Cpu } from 'lucide-react'
import { HITLApprovalRequest } from '../types'
import { api } from '../api'

// Isolated CountdownTimer component to prevent unnecessary re-rendering of the entire modal
interface CountdownTimerProps {
  expiresAt: string
  onExpire: () => void
}

const CountdownTimer = memo<CountdownTimerProps>(({ expiresAt, onExpire }) => {
  const calculateRemaining = useCallback(() => {
    const expireTime = new Date(expiresAt).getTime()
    const now = Date.now()
    return Math.max(0, Math.ceil((expireTime - now) / 1000))
  }, [expiresAt])

  const [remaining, setRemaining] = useState<number>(calculateRemaining)

  useEffect(() => {
    setRemaining(calculateRemaining())
    const interval = setInterval(() => {
      const left = calculateRemaining()
      setRemaining(left)
      if (left <= 0) {
        clearInterval(interval)
        onExpire()
      }
    }, 1000)

    return () => clearInterval(interval)
  }, [calculateRemaining, onExpire])

  const isUrgent = remaining <= 15

  return (
    <div
      className={`flex items-center gap-2 px-3 py-1.5 rounded-lg font-mono text-xs font-semibold transition-colors ${
        isUrgent
          ? 'bg-rose-50 dark:bg-rose-500/20 text-rose-700 dark:text-rose-300 border border-rose-300 dark:border-rose-500/40 animate-pulse'
          : 'bg-amber-50 dark:bg-amber-500/10 text-amber-800 dark:text-amber-300 border border-amber-300 dark:border-amber-500/30'
      }`}
    >
      <Clock className="w-3.5 h-3.5" />
      <span>
        Auto-Denies in <span className="font-bold text-sm text-primary">{remaining}s</span>
      </span>
    </div>
  )
})

CountdownTimer.displayName = 'CountdownTimer'

export const HITLModal: React.FC = () => {
  const [activeRequest, setActiveRequest] = useState<HITLApprovalRequest | null>(null)
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false)
  const [actionError, setActionError] = useState<string | null>(null)

  // Initial fetch for any pending approvals
  const checkPending = useCallback(async () => {
    try {
      const res = await api.getPendingHITL()
      if (res && res.pending && res.pending.length > 0) {
        setActiveRequest(res.pending[0])
      }
    } catch {
      // Backend may be starting or offline
    }
  }, [])

  useEffect(() => {
    checkPending()
  }, [checkPending])

  // Real-time WebSocket connection to /ws for instantaneous approval broadcasting
  useEffect(() => {
    let ws: WebSocket | null = null
    let reconnectTimer: NodeJS.Timeout | null = null
    let isDisposed = false

    const connectWS = () => {
      if (isDisposed) return

      try {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
        const host = window.location.host || '127.0.0.1:8095'
        const wsUrl = `${protocol}//${host}/ws`

        ws = new WebSocket(wsUrl)

        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data)
            if (data.type === 'HITL_APPROVAL_REQUIRED') {
              setActiveRequest({
                call_id: data.call_id,
                tool_name: data.tool_name,
                arguments: data.arguments || {},
                risk_score: data.risk_score || 0,
                threat_domain: data.threat_domain || 'SEMANTIC_RISK',
                cwe: data.cwe || 'CWE-UNKNOWN',
                decision_engine: data.decision_engine || 'Semantic Security Guard',
                created_at: data.created_at,
                expires_at: data.expires_at,
              })
              setActionError(null)
            } else if (data.type === 'HITL_RESOLVED') {
              setActiveRequest((prev) => (prev?.call_id === data.call_id ? null : prev))
              setActionError(null)
            }
          } catch {
            // Ignore non-JSON heartbeat
          }
        }

        ws.onclose = () => {
          if (!isDisposed) {
            reconnectTimer = setTimeout(connectWS, 3000)
          }
        }

        ws.onerror = () => {
          if (ws) {
            ws.close()
          }
        }
      } catch {
        if (!isDisposed) {
          reconnectTimer = setTimeout(connectWS, 3000)
        }
      }
    }

    connectWS()

    return () => {
      isDisposed = true
      if (reconnectTimer) clearTimeout(reconnectTimer)
      if (ws) {
        ws.close()
      }
    }
  }, [])

  const handleRespond = async (approved: boolean) => {
    if (!activeRequest || isSubmitting) return

    try {
      setIsSubmitting(true)
      setActionError(null)
      await api.respondHITL(activeRequest.call_id, approved)
      setActiveRequest(null)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      setActionError(msg)
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleExpire = useCallback(() => {
    setActiveRequest(null)
  }, [])

  if (!activeRequest) {
    return null
  }

  const riskPct = Math.round(
    activeRequest.risk_score <= 1.0 ? activeRequest.risk_score * 100 : activeRequest.risk_score
  )

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-in fade-in duration-200">
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="hitl-title"
        className="bg-surface border border-rose-300 dark:border-rose-500/30 rounded-2xl max-w-xl w-full p-6 shadow-2xl relative overflow-hidden flex flex-col gap-5 text-primary"
      >
        {/* Glow Accent Top Banner */}
        <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-rose-500 via-amber-500 to-rose-500" />

        {/* Modal Header */}
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-rose-50 dark:bg-rose-500/10 border border-rose-200 dark:border-rose-500/30 rounded-xl text-rose-600 dark:text-rose-400">
              <ShieldAlert className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-rose-50 dark:bg-rose-500/20 text-rose-700 dark:text-rose-300 border border-rose-200 dark:border-rose-500/30 tracking-wider uppercase">
                  HITL Escalation
                </span>
                <span className="text-xs font-mono text-muted">{activeRequest.call_id}</span>
              </div>
              <h2 id="hitl-title" className="text-lg font-bold text-primary mt-1">
                Suspicious Tool Execution Intercepted
              </h2>
            </div>
          </div>

          <CountdownTimer expiresAt={activeRequest.expires_at} onExpire={handleExpire} />
        </div>

        {/* Threat Metric Badges */}
        <div className="grid grid-cols-3 gap-2.5 text-xs font-mono">
          <div className="bg-canvas border border-subtle rounded-xl p-2.5 flex flex-col gap-1 shadow-xs">
            <span className="text-muted text-[10px] uppercase tracking-wider flex items-center gap-1">
              <AlertTriangle className="w-3 h-3 text-rose-500" /> Threat Domain
            </span>
            <span className="font-semibold text-rose-700 dark:text-rose-300 truncate" title={activeRequest.threat_domain}>
              {activeRequest.threat_domain}
            </span>
          </div>

          <div className="bg-canvas border border-subtle rounded-xl p-2.5 flex flex-col gap-1 shadow-xs">
            <span className="text-muted text-[10px] uppercase tracking-wider flex items-center gap-1">
              <ShieldAlert className="w-3 h-3 text-amber-500" /> CWE / Risk
            </span>
            <span className="font-semibold text-amber-700 dark:text-amber-300">
              {activeRequest.cwe} · {riskPct}%
            </span>
          </div>

          <div className="bg-canvas border border-subtle rounded-xl p-2.5 flex flex-col gap-1 shadow-xs">
            <span className="text-muted text-[10px] uppercase tracking-wider flex items-center gap-1">
              <Cpu className="w-3 h-3 text-accent" /> Engine
            </span>
            <span className="font-semibold text-accent truncate" title={activeRequest.decision_engine}>
              {activeRequest.decision_engine}
            </span>
          </div>
        </div>

        {/* Target Tool and Arguments */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs font-mono">
            <div className="flex items-center gap-1.5 text-primary font-semibold">
              <Terminal className="w-3.5 h-3.5 text-accent" />
              <span>Target Tool:</span>
              <span className="text-sky-700 dark:text-cyan-300 bg-sky-50 dark:bg-cyan-950/40 px-2 py-0.5 rounded border border-sky-200 dark:border-cyan-500/20">
                {activeRequest.tool_name}
              </span>
            </div>
            <span className="text-muted text-[11px]">JSON-RPC Payload</span>
          </div>

          <div className="relative group">
            <pre className="bg-[#0F172A] border border-[#1E293B] rounded-xl p-3.5 text-xs font-mono text-slate-100 overflow-x-auto max-h-44 shadow-inner">
              {JSON.stringify(activeRequest.arguments, null, 2)}
            </pre>
          </div>
        </div>

        {/* Action Error Banner if request failed */}
        {actionError && (
          <div className="p-3 bg-rose-50 dark:bg-rose-500/15 border border-rose-200 dark:border-rose-500/30 rounded-xl text-rose-700 dark:text-rose-300 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-500 shrink-0" />
            <span>{actionError}</span>
          </div>
        )}

        {/* Confirmation Question */}
        <div className="text-xs text-muted bg-canvas border border-subtle rounded-xl p-3 text-center">
          Do you authorize this agent action to proceed to the upstream tool provider?
        </div>

        {/* Decision Actions */}
        <div className="flex items-center justify-end gap-3 pt-1">
          <button
            type="button"
            disabled={isSubmitting}
            onClick={() => handleRespond(false)}
            className="flex-1 flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl font-medium text-xs text-rose-700 dark:text-rose-300 bg-rose-50 dark:bg-rose-500/10 hover:bg-rose-100 dark:hover:bg-rose-500/20 border border-rose-300 dark:border-rose-500/30 transition-all hover:scale-[1.01] active:scale-[0.99] disabled:opacity-50 shadow-xs"
          >
            <XCircle className="w-4 h-4" />
            <span>Deny Request (-32000)</span>
          </button>

          <button
            type="button"
            disabled={isSubmitting}
            onClick={() => handleRespond(true)}
            className="flex-1 flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl font-medium text-xs text-white bg-emerald-600 hover:bg-emerald-500 shadow-sm transition-all hover:scale-[1.01] active:scale-[0.99] disabled:opacity-50"
          >
            {isSubmitting ? (
              <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
            ) : (
              <CheckCircle2 className="w-4 h-4" />
            )}
            <span>Approve Execution</span>
          </button>
        </div>
      </div>
    </div>
  )
}
