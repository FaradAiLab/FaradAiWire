import React, { useState, useEffect, useMemo } from 'react'
import { Shield, X } from 'lucide-react'
import { ProtocolItem, ToolMetadata } from '../../types'
import { api } from '../../api'
import { Button } from '../ui/Button'

export interface ToolWhitelistDrawerProps {
  protocol: ProtocolItem | null
  onClose: () => void
  onSaved: () => void
}

export const ToolWhitelistDrawer: React.FC<ToolWhitelistDrawerProps> = ({
  protocol,
  onClose,
  onSaved,
}) => {
  const [loading, setLoading] = useState(false)
  const [tools, setTools] = useState<ToolMetadata[]>([])
  const [allowedTools, setAllowedTools] = useState<string[]>([])
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    if (!protocol) return

    setAllowedTools(protocol.allowed_tools || [])
    setTools([])
    setLoading(true)

    const abortController = new AbortController()

    api
      .probeProtocol(
        {
          type: protocol.type,
          url: protocol.url_or_command,
          auth_token: protocol.auth_token,
          headers: protocol.headers,
          command: protocol.command || protocol.url_or_command,
          args: protocol.args,
          env: protocol.env,
        },
        abortController.signal
      )
      .then((res) => {
        setTools(res.tools || [])
      })
      .catch((err) => {
        if (!abortController.signal.aborted) {
          console.warn('Probe failed for drawer tools:', err)
        }
      })
      .finally(() => {
        if (!abortController.signal.aborted) {
          setLoading(false)
        }
      })

    return () => abortController.abort()
  }, [protocol])

  // O(1) set lookup for performance
  const allowedSet = useMemo(() => new Set(allowedTools), [allowedTools])
  const isAllowAll = allowedTools.length === 0

  const handleSaveWhitelist = async () => {
    if (!protocol) return
    try {
      setSaving(true)
      await api.updateProtocol(protocol.id, {
        ...protocol,
        allowed_tools: allowedTools,
      })
      onSaved()
      onClose()
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      alert(`Failed to save tool whitelist: ${msg}`)
    } finally {
      setSaving(false)
    }
  }

  if (!protocol) return null

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end bg-black/70 backdrop-blur-xs transition-opacity animate-in fade-in duration-150"
      role="dialog"
      aria-modal="true"
      aria-label="Layer 1 Tool Whitelist Drawer"
    >
      <div className="w-full max-w-md bg-surface border-l border-subtle h-full p-6 flex flex-col justify-between shadow-2xl animate-in slide-in-from-right duration-200">
        <div className="space-y-4 overflow-y-auto">
          {/* Header */}
          <div className="flex items-center justify-between border-b border-subtle pb-3">
            <div>
              <h3 className="text-base font-bold text-primary flex items-center gap-2">
                <Shield className="w-4 h-4 text-accent-primary" />
                Layer 1 Tool Whitelist
              </h3>
              <p className="text-xs text-muted mt-0.5 font-mono">
                Protocol: {protocol.name} ({protocol.id})
              </p>
            </div>
            <button
              type="button"
              onClick={onClose}
              className="p-1 rounded-lg text-muted hover:text-primary hover:bg-surface/80 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent-primary"
              aria-label="Close drawer"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          <div className="p-3 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-xs text-primary leading-relaxed">
            Tools deselected here are intercepted at the perimeter layer with code{' '}
            <code className="text-accent-primary font-mono">-32004</code> and will never reach backend
            subprocesses or agents.
          </div>

          {/* Tools List */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-primary">Available Tools</span>
              <span className="text-[11px] font-mono text-muted">
                {!isAllowAll ? `${allowedTools.length} enabled` : 'All permitted'}
              </span>
            </div>

            {loading ? (
              <div className="p-8 text-center text-xs text-muted font-mono">
                Querying protocol tools...
              </div>
            ) : tools.length === 0 ? (
              <div className="p-8 text-center text-xs text-muted border border-dashed border-subtle rounded-xl font-mono">
                No tools discovered. Ensure the protocol server is running and reachable.
              </div>
            ) : (
              <div className="space-y-1.5 max-h-[60vh] overflow-y-auto pr-1">
                {tools.map((tool) => {
                  const isChecked = isAllowAll || allowedSet.has(tool.name)

                  return (
                    <label
                      key={tool.name}
                      className="flex items-start gap-2.5 p-2.5 rounded-xl bg-surface/60 hover:bg-surface border border-subtle cursor-pointer transition-colors"
                    >
                      <input
                        type="checkbox"
                        checked={isChecked}
                        onChange={(e) => {
                          if (e.target.checked) {
                            if (!isAllowAll) {
                              setAllowedTools([...allowedTools, tool.name])
                            }
                          } else {
                            if (isAllowAll) {
                              // Initialize whitelist with all EXCEPT this one
                              setAllowedTools(
                                tools.map((t) => t.name).filter((n) => n !== tool.name)
                              )
                            } else {
                              setAllowedTools(allowedTools.filter((n) => n !== tool.name))
                            }
                          }
                        }}
                        className="mt-0.5 text-accent-primary rounded bg-surface border-subtle focus:ring-accent-primary focus:ring-offset-surface"
                      />
                      <div className="min-w-0">
                        <div className="font-mono text-xs font-semibold text-primary">
                          {tool.name}
                        </div>
                        {tool.description && (
                          <p className="text-[11px] text-muted line-clamp-2 mt-0.5">
                            {tool.description}
                          </p>
                        )}
                      </div>
                    </label>
                  )
                })}
              </div>
            )}
          </div>
        </div>

        <div className="pt-4 border-t border-subtle flex gap-2">
          <Button
            type="button"
            variant="ghost"
            className="w-1/2"
            onClick={() => setAllowedTools([])}
          >
            Reset (Allow All)
          </Button>
          <Button
            type="button"
            variant="primary"
            className="w-1/2"
            onClick={handleSaveWhitelist}
            isLoading={saving}
          >
            {saving ? 'Saving...' : 'Save Whitelist'}
          </Button>
        </div>
      </div>
    </div>
  )
}
