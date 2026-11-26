import React, { useEffect, useState, useRef } from 'react'
import { X, FileCode } from 'lucide-react'
import { api, ExportNativeMCPResponse } from '../../api'
import { copyTextToClipboard } from '../../lib/clipboard'
import { Button } from '../ui/Button'
import {
  TARGET_CLIENTS,
  detectBrowserOS,
  downloadJsonFile,
  ExportPathHintBanner,
  ExportPreviewPanel,
  ExportWarningsList,
} from './ExportNativeMcpParts'

interface ExportNativeMcpModalProps {
  isOpen: boolean
  agentName: string | null
  onClose: () => void
}

export const ExportNativeMcpModal: React.FC<ExportNativeMcpModalProps> = ({ isOpen, agentName, onClose }) => {
  const [selectedClient, setSelectedClient] = useState('claude-code')
  const [selectedScope, setSelectedScope] = useState<'global' | 'project'>('project')
  const [activeTab, setActiveTab] = useState<'primary' | 'companion'>('primary')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [exportData, setExportData] = useState<ExportNativeMCPResponse | null>(null)
  const [copiedTab, setCopiedTab] = useState<'primary' | 'companion' | null>(null)
  const [copyError, setCopyError] = useState<string | null>(null)

  const dialogRef = useRef<HTMLDivElement>(null)
  const copyTimerRef = useRef<number | null>(null)

  const clientMeta = TARGET_CLIENTS.find((c) => c.id === selectedClient) || TARGET_CLIENTS[0]

  useEffect(() => {
    return () => {
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current)
      }
    }
  }, [])

  useEffect(() => {
    if (!isOpen) return
    dialogRef.current?.focus()
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [isOpen, onClose])

  useEffect(() => {
    if (!isOpen || !agentName) return
    const controller = new AbortController()

    ;(async () => {
      try {
        setLoading(true)
        setError(null)
        setCopyError(null)
        const res = await api.exportAgentNativeMCP(
          agentName,
          {
            client: selectedClient,
            scope: selectedScope,
            client_os: detectBrowserOS(),
          },
          controller.signal
        )
        if (controller.signal.aborted) return
        setExportData(res)
        if (!res.companion_files || res.companion_files.length === 0) {
          setActiveTab('primary')
        }
      } catch (err: unknown) {
        if (controller.signal.aborted || (err instanceof Error && err.name === 'AbortError')) return
        setError(err instanceof Error ? err.message : String(err))
      } finally {
        if (!controller.signal.aborted) {
          setLoading(false)
        }
      }
    })()

    return () => controller.abort()
  }, [isOpen, agentName, selectedClient, selectedScope])

  if (!isOpen || !agentName) return null

  const handleClientChange = (nextClient: string) => {
    const meta = TARGET_CLIENTS.find((c) => c.id === nextClient) || TARGET_CLIENTS[0]
    setSelectedClient(nextClient)
    if (!meta.scopes.includes(selectedScope)) {
      setSelectedScope(meta.defaultScope)
    }
    setActiveTab('primary')
  }

  const primaryJson = exportData ? JSON.stringify(exportData.config, null, 2) : ''
  const companionFile = exportData?.companion_files?.[0]
  const companionJson = companionFile ? JSON.stringify(companionFile.content, null, 2) : ''
  const displayedJson = activeTab === 'companion' && companionFile ? companionJson : primaryJson
  const displayedPathHint =
    activeTab === 'companion' && companionFile ? companionFile.path_hint : exportData?.target_path_hint || ''
  const displayedMergeHazard =
    activeTab === 'companion' && companionFile ? companionFile.merge_hazard : exportData?.merge_hazard || false

  const handleCopy = async () => {
    if (!displayedJson) return
    setCopyError(null)
    const ok = await copyTextToClipboard(displayedJson)
    if (!ok) {
      setCopyError('Clipboard copy is blocked by browser permissions. Please use Download instead.')
      return
    }
    setCopiedTab(activeTab)
    if (copyTimerRef.current !== null) {
      window.clearTimeout(copyTimerRef.current)
    }
    copyTimerRef.current = window.setTimeout(() => {
      setCopiedTab(null)
      copyTimerRef.current = null
    }, 2000)
  }

  const handleDownload = () => {
    if (!displayedJson) return
    const suffix = activeTab === 'companion' ? 'claude-settings.json' : `${selectedClient}.mcp.json`
    downloadJsonFile(`${agentName}-${suffix}`, displayedJson + '\n')
  }

  return (
    <div
      className="fixed inset-0 z-50 bg-slate-950/60 backdrop-blur-xs flex items-center justify-center p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="export-native-mcp-title"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
    >
      <div
        ref={dialogRef}
        tabIndex={-1}
        className="bg-surface border border-subtle rounded-2xl w-full max-w-3xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden focus:outline-none"
      >
        <div className="px-6 py-4 border-b border-subtle flex items-center justify-between gap-4">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-accent/10 border border-accent/20 text-accent">
              <FileCode className="w-4 h-4" />
            </div>
            <div>
              <h2 id="export-native-mcp-title" className="text-base font-bold text-primary">
                Export Native MCP Configuration
              </h2>
              <p className="text-xs text-muted font-mono">Profile: {agentName}</p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            aria-label="Close export modal"
            className="p-1.5 rounded-lg text-muted hover:text-primary hover:bg-subtle transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-6 space-y-4 overflow-y-auto">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label htmlFor="export-target-client" className="block text-xs font-semibold text-secondary mb-1.5">
                Target Client
              </label>
              <select
                id="export-target-client"
                value={selectedClient}
                onChange={(e) => handleClientChange(e.target.value)}
                className="w-full px-3 py-2 rounded-xl bg-canvas border border-subtle text-xs font-mono text-primary focus:outline-none focus:ring-1 focus:ring-accent"
              >
                {TARGET_CLIENTS.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.label}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <span className="block text-xs font-semibold text-secondary mb-1.5">Target Scope</span>
              <div className="flex gap-2">
                {(['project', 'global'] as const).map((sc) => {
                  const supported = clientMeta.scopes.includes(sc)
                  const active = selectedScope === sc
                  return (
                    <button
                      key={sc}
                      type="button"
                      disabled={!supported}
                      onClick={() => setSelectedScope(sc)}
                      className={`flex-1 px-3 py-2 rounded-xl border text-xs font-mono transition-colors ${
                        active
                          ? 'bg-accent/15 border-accent/40 text-accent font-semibold'
                          : 'bg-canvas border-subtle text-muted hover:text-primary'
                      } disabled:opacity-40 disabled:cursor-not-allowed`}
                    >
                      {sc}
                    </button>
                  )
                })}
              </div>
            </div>
          </div>

          {companionFile && (
            <div className="flex gap-2 border-b border-subtle pb-2">
              <button
                type="button"
                onClick={() => setActiveTab('primary')}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-colors ${
                  activeTab === 'primary' ? 'bg-accent text-white font-semibold' : 'text-muted hover:text-primary'
                }`}
              >
                MCP Servers ({exportData?.target_path_hint})
              </button>
              <button
                type="button"
                onClick={() => setActiveTab('companion')}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-colors ${
                  activeTab === 'companion' ? 'bg-accent text-white font-semibold' : 'text-muted hover:text-primary'
                }`}
              >
                Tool Permissions ({companionFile.path_hint})
              </button>
            </div>
          )}

          <ExportPathHintBanner pathHint={displayedPathHint} mergeHazard={displayedMergeHazard} />

          {error && (
            <div role="alert" className="p-3 rounded-xl bg-rose-50 dark:bg-rose-950/40 border border-rose-300 dark:border-rose-500/30 text-xs text-rose-700 dark:text-rose-300 font-mono">
              {error}
            </div>
          )}
          {copyError && (
            <div role="alert" className="p-3 rounded-xl bg-rose-50 dark:bg-rose-950/40 border border-rose-300 dark:border-rose-500/30 text-xs text-rose-700 dark:text-rose-300">
              {copyError}
            </div>
          )}

          <ExportPreviewPanel
            loading={loading}
            activeTab={activeTab}
            displayedJson={displayedJson}
            copied={copiedTab === activeTab}
            onCopy={handleCopy}
            onDownload={handleDownload}
          />

          <ExportWarningsList warnings={exportData?.warnings || []} />
        </div>

        <div className="px-6 py-3.5 border-t border-subtle flex justify-end">
          <Button variant="secondary" size="sm" onClick={onClose}>
            Close
          </Button>
        </div>
      </div>
    </div>
  )
}
