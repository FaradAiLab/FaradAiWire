import React, { useState, useCallback } from 'react'
import { Lock, KeyRound, Eye, EyeOff, Terminal, Copy, Check, AlertTriangle, Shield } from 'lucide-react'
import { api } from '../api'
import { Button } from './ui/Button'

export interface AuthGateModalProps {
  isOpen: boolean
  onAuthenticated: () => void
}

const DOCKER_TOKEN_RECOVERY_CMD = 'docker exec -it <container_name> faradaiwire token'
const LOCAL_TOKEN_RECOVERY_CMD = 'faradaiwire token'

export const AuthGateModal: React.FC<AuthGateModalProps> = ({ isOpen, onAuthenticated }) => {
  const [token, setToken] = useState('')
  const [showToken, setShowToken] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [copiedCmd, setCopiedCmd] = useState<'docker' | 'local' | null>(null)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    const clean = token.trim()
    if (!clean) {
      setError('Admin API Key is required.')
      return
    }

    try {
      setSubmitting(true)
      setError(null)
      await api.loginAdminSession(clean)
      setToken('')
      onAuthenticated()
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      setError(msg || 'Authentication failed. Ensure you are using an Admin-role API key.')
    } finally {
      setSubmitting(false)
    }
  }

  const handleCopyCmd = useCallback((cmd: string, kind: 'docker' | 'local') => {
    navigator.clipboard?.writeText(cmd)
    setCopiedCmd(kind)
    setTimeout(() => setCopiedCmd(null), 1800)
  }, [])

  const browserPort = typeof window !== 'undefined' ? window.location.port : ''

  if (!isOpen) return null

  return (
    <div
      className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/75 backdrop-blur-md"
      role="dialog"
      aria-modal="true"
      aria-labelledby="auth-gate-title"
    >
      <div className="w-full max-w-md p-6 rounded-2xl bg-surface border border-subtle shadow-2xl space-y-5">
        <div className="flex items-start gap-3 pb-3 border-b border-subtle">
          <div className="w-10 h-10 rounded-xl bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center shrink-0 text-cyan-400">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <h2 id="auth-gate-title" className="text-base font-bold text-primary font-mono">
              Admin Console Locked
            </h2>
            <p className="text-xs text-muted mt-0.5 leading-relaxed">
              Non-loopback and containerized gateways require an Admin Bootstrap Master Key to establish an{' '}
              <code className="font-mono text-[11px] text-primary">HttpOnly</code> session cookie.
            </p>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          {error && (
            <div className="p-3 rounded-xl bg-rose-50 dark:bg-rose-950/40 border border-rose-300 dark:border-rose-500/30 text-rose-700 dark:text-rose-300 text-xs flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          <div>
            <label htmlFor="admin-bootstrap-token" className="block text-xs font-semibold text-primary mb-1.5 font-mono">
              Admin API Key (faw_live_...)
            </label>
            <div className="relative">
              <KeyRound className="w-4 h-4 text-muted absolute left-3 top-2.5" />
              <input
                id="admin-bootstrap-token"
                type={showToken ? 'text' : 'password'}
                value={token}
                onChange={(e) => setToken(e.target.value)}
                placeholder="faw_live_..."
                autoComplete="current-password"
                autoFocus
                className="w-full pl-9 pr-10 py-2 rounded-xl bg-canvas border border-subtle text-xs font-mono text-primary placeholder:text-muted focus:outline-none focus:ring-2 focus:ring-accent-primary"
              />
              <button
                type="button"
                onClick={() => setShowToken((v) => !v)}
                className="absolute right-2.5 top-2 p-1 text-muted hover:text-primary transition-colors"
                aria-label={showToken ? 'Hide API key' : 'Show API key'}
              >
                {showToken ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>

          <Button
            type="submit"
            variant="primary"
            size="md"
            isLoading={submitting}
            disabled={submitting || !token.trim()}
            icon={<Lock className="w-4 h-4" />}
            className="w-full justify-center"
          >
            {submitting ? 'Verifying Key...' : 'Unlock Admin Console'}
          </Button>
        </form>

        {/* Zero-Bleed Token Recovery Hint */}
        <div className="p-3.5 rounded-xl bg-canvas border border-subtle space-y-2.5 text-[11px]">
          <div className="flex items-center gap-1.5 font-semibold text-primary font-mono">
            <Terminal className="w-3.5 h-3.5 text-cyan-400" />
            <span>Lost your token? Recover API Key &amp; Magic Link:</span>
          </div>

          <div className="space-y-1.5">
            <div className="text-[10px] text-muted font-mono uppercase tracking-wider">Docker / Container</div>
            <div className="flex items-center justify-between gap-2 p-2 rounded-lg bg-[#0F172A] border border-[#1E293B] font-mono text-cyan-300">
              <code className="truncate">{DOCKER_TOKEN_RECOVERY_CMD}</code>
              <button
                type="button"
                onClick={() => handleCopyCmd(DOCKER_TOKEN_RECOVERY_CMD, 'docker')}
                className="p-1 text-slate-400 hover:text-white shrink-0"
                title="Copy Docker token recovery command"
              >
                {copiedCmd === 'docker' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
            {browserPort && browserPort !== '19415' && (
              <p className="text-[10px] text-muted leading-relaxed">
                Mapped to host port <code className="text-primary font-mono">{browserPort}</code>? Add{' '}
                <code className="text-primary font-mono">--port {browserPort}</code> for a matching Magic Link.
              </p>
            )}
          </div>

          <div className="space-y-1.5">
            <div className="text-[10px] text-muted font-mono uppercase tracking-wider">Local Host / CLI</div>
            <div className="flex items-center justify-between gap-2 p-2 rounded-lg bg-[#0F172A] border border-[#1E293B] font-mono text-cyan-300">
              <code className="truncate">{LOCAL_TOKEN_RECOVERY_CMD}</code>
              <button
                type="button"
                onClick={() => handleCopyCmd(LOCAL_TOKEN_RECOVERY_CMD, 'local')}
                className="p-1 text-slate-400 hover:text-white shrink-0"
                title="Copy CLI token recovery command"
              >
                {copiedCmd === 'local' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
