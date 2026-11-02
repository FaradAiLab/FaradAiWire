import React, { useState, useEffect } from 'react'
import {
  Lock,
  Unlock,
  Copy,
  Check,
  FileCode,
  ShieldCheck,
  Hash,
  Loader2,
} from 'lucide-react'
import { Modal } from '../ui/Modal'
import { Button } from '../ui/Button'
import { ToolMetadata, ToolSchemaRecord } from '../../types'
import { api } from '../../api'

export interface SchemaInspectorDrawerProps {
  isOpen: boolean
  onClose: () => void
  toolName: string
  toolMetadata?: ToolMetadata
}

export const SchemaInspectorDrawer: React.FC<SchemaInspectorDrawerProps> = ({
  isOpen,
  onClose,
  toolName,
  toolMetadata,
}) => {
  const [record, setRecord] = useState<ToolSchemaRecord | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [copiedHash, setCopiedHash] = useState(false)
  const [copiedSchema, setCopiedSchema] = useState(false)
  const [togglingPin, setTogglingPin] = useState(false)

  useEffect(() => {
    if (!isOpen || !toolName) return
    setLoading(true)
    setError(null)

    api
      .getSchema(toolName)
      .then((res) => {
        setRecord(res)
      })
      .catch(() => {
        // Fall back to toolMetadata inputSchema if DB record is not yet captured
        if (toolMetadata?.inputSchema) {
          setRecord({
            tool_name: toolName,
            protocol_id: toolMetadata.protocol_id || toolMetadata.protocol_name,
            schema_json: toolMetadata.inputSchema,
            sha256_hash: 'uncaptured_live_schema',
            is_pinned: false,
          })
        } else {
          setError('No schema record found for this tool yet.')
        }
      })
      .finally(() => {
        setLoading(false)
      })
  }, [isOpen, toolName, toolMetadata])

  const handleTogglePin = async () => {
    if (!record) return
    try {
      setTogglingPin(true)
      const nextPin = !record.is_pinned
      const res = await api.pinSchema(toolName, nextPin)
      setRecord((prev) => (prev ? { ...prev, is_pinned: res.is_pinned } : null))
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setTogglingPin(false)
    }
  }

  const copyToClipboard = (text: string, setCopied: (v: boolean) => void) => {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  if (!isOpen) return null

  const schemaObj = (record?.schema_json || toolMetadata?.inputSchema || {}) as Record<string, unknown>
  const schemaProps = (schemaObj.properties || {}) as Record<string, Record<string, unknown>>
  const requiredFields = (Array.isArray(schemaObj.required) ? schemaObj.required : []) as string[]
  const schemaPretty = JSON.stringify(schemaObj, null, 2)

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Tool Schema Inspector"
      subtitle={`OWASP LLM05 Parameter Drift & Signature Protection • ${toolName}`}
      icon={<FileCode className="w-5 h-5 text-cyan-400" />}
      maxWidth="xl"
    >
      <div className="space-y-4">
        {loading ? (
          <div className="py-12 flex flex-col items-center justify-center gap-3 text-gray-400">
            <Loader2 className="w-6 h-6 animate-spin text-cyan-400" />
            <span className="text-xs font-mono">Fetching schema from database...</span>
          </div>
        ) : (
          <>
            {error && (
              <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs font-mono">
                {error}
              </div>
            )}

            {/* Status & Metadata Bar */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {/* Baseline SHA-256 Hash Card */}
              <div className="p-3 rounded-xl bg-surface border border-subtle space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono uppercase tracking-wider text-muted flex items-center gap-1">
                    <Hash className="w-3 h-3 text-accent-primary" /> Canonical Baseline SHA-256
                  </span>
                  {record?.sha256_hash && (
                    <button
                      type="button"
                      onClick={() => copyToClipboard(record.sha256_hash, setCopiedHash)}
                      className="text-muted hover:text-accent-primary transition-colors p-0.5 rounded"
                      title="Copy Hash"
                      aria-label="Copy Hash"
                    >
                      {copiedHash ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  )}
                </div>
                <p className="text-xs font-mono text-accent-primary truncate font-bold">
                  {record?.sha256_hash || 'Computing...'}
                </p>
              </div>

              {/* Pinning Protection Action Card */}
              <div className="p-3 rounded-xl bg-surface border border-subtle flex items-center justify-between">
                <div className="space-y-0.5">
                  <span className="text-[10px] font-mono uppercase tracking-wider text-muted flex items-center gap-1">
                    <ShieldCheck className="w-3 h-3 text-emerald-500" /> Baseline Pinning
                  </span>
                  <p className="text-xs font-mono text-primary font-semibold">
                    {record?.is_pinned ? (
                      <span className="text-emerald-600 dark:text-emerald-400 flex items-center gap-1">
                        <Lock className="w-3 h-3" /> Pinned (Protected)
                      </span>
                    ) : (
                      <span className="text-muted flex items-center gap-1">
                        <Unlock className="w-3 h-3" /> Unpinned (Dynamic)
                      </span>
                    )}
                  </p>
                </div>
                <Button
                  type="button"
                  variant={record?.is_pinned ? 'secondary' : 'outline'}
                  size="sm"
                  onClick={handleTogglePin}
                  isLoading={togglingPin}
                  icon={record?.is_pinned ? <Unlock className="w-3.5 h-3.5" /> : <Lock className="w-3.5 h-3.5 text-accent-primary" />}
                >
                  {record?.is_pinned ? 'Unpin Schema' : 'Pin Baseline'}
                </Button>
              </div>
            </div>

            {/* Parameters Breakdown Table */}
            <div className="space-y-1.5">
              <label className="text-[11px] font-mono text-muted uppercase tracking-wider block">
                Parameter Definitions ({Object.keys(schemaProps).length})
              </label>
              {Object.keys(schemaProps).length === 0 ? (
                <div className="p-3 text-center text-xs text-muted font-mono border border-dashed border-subtle rounded-xl">
                  This tool takes no parameters (empty schema).
                </div>
              ) : (
                <div className="border border-subtle rounded-xl overflow-hidden divide-y divide-subtle max-h-72 overflow-y-auto">
                  {Object.entries(schemaProps).map(([paramName, paramDef]) => {
                    const isRequired = requiredFields.includes(paramName)
                    const paramType = (paramDef.type as string) || 'any'
                    const paramDesc = (paramDef.description as string) || ''
                    return (
                      <div key={paramName} className="p-2.5 bg-surface/50 flex items-start justify-between gap-3 text-xs">
                        <div className="space-y-0.5">
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-bold text-primary">{paramName}</span>
                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-surface border border-subtle text-accent-primary">
                              {paramType}
                            </span>
                            {isRequired && (
                              <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-rose-500/10 border border-rose-500/30 text-rose-700 dark:text-rose-300 font-semibold">
                                required
                              </span>
                            )}
                          </div>
                          {paramDesc && <p className="text-[11px] text-muted font-sans">{paramDesc}</p>}
                        </div>
                      </div>
                    )
                  })}
                </div>
              )}
            </div>

            {/* Raw JSON Schema Preview (DUAL TONE INVARIANT) */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label className="text-[11px] font-mono text-muted uppercase tracking-wider">
                  Raw JSON Schema Definition
                </label>
                <button
                  type="button"
                  onClick={() => copyToClipboard(schemaPretty, setCopiedSchema)}
                  className="text-xs font-mono text-accent-primary hover:underline flex items-center gap-1 transition-colors"
                  aria-label="Copy JSON schema"
                >
                  {copiedSchema ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>Copy JSON</span>
                </button>
              </div>
              <pre className="p-3 rounded-xl bg-[#0F172A] border border-[#1E293B] text-[11px] font-mono text-cyan-300 max-h-80 overflow-y-auto leading-relaxed shadow-inner select-all">
                {schemaPretty}
              </pre>
            </div>
          </>
        )}

        {/* Footer */}
        <div className="flex items-center justify-end pt-3 border-t border-subtle">
          <Button type="button" variant="ghost" size="md" onClick={onClose}>
            Close
          </Button>
        </div>
      </div>
    </Modal>
  )
}
