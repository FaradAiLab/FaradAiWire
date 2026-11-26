import React from 'react'
import { Copy, Check, Download, AlertTriangle, Info, ShieldAlert } from 'lucide-react'
import { ExportWarning } from '../../api'

export const TARGET_CLIENTS: Array<{
  id: string
  label: string
  scopes: Array<'global' | 'project'>
  defaultScope: 'global' | 'project'
}> = [
  { id: 'claude-code', label: 'Claude Code', scopes: ['project', 'global'], defaultScope: 'project' },
  { id: 'cursor', label: 'Cursor (Global)', scopes: ['global'], defaultScope: 'global' },
  { id: 'cursor-workspace', label: 'Cursor (Workspace)', scopes: ['project'], defaultScope: 'project' },
  { id: 'windsurf', label: 'Windsurf', scopes: ['global'], defaultScope: 'global' },
  { id: 'cline', label: 'Cline', scopes: ['global'], defaultScope: 'global' },
  { id: 'roo-code', label: 'Roo Code', scopes: ['global', 'project'], defaultScope: 'global' },
  { id: 'antigravity', label: 'Google Antigravity', scopes: ['global', 'project'], defaultScope: 'global' },
  { id: 'claude-desktop', label: 'Claude Desktop', scopes: ['global'], defaultScope: 'global' },
  { id: 'generic', label: 'Generic MCP JSON', scopes: ['project', 'global'], defaultScope: 'project' },
]

export function detectBrowserOS(): 'darwin' | 'linux' | 'windows' {
  if (typeof navigator === 'undefined') return 'linux'
  const platform = (navigator.platform || navigator.userAgent || '').toLowerCase()
  if (platform.includes('mac') || platform.includes('darwin')) return 'darwin'
  if (platform.includes('win')) return 'windows'
  return 'linux'
}

export function downloadJsonFile(filename: string, content: string) {
  const blob = new Blob([content], { type: 'application/json;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

export const ExportPathHintBanner: React.FC<{
  pathHint: string
  mergeHazard: boolean
}> = ({ pathHint, mergeHazard }) => {
  if (!pathHint) return null
  return (
    <div
      className={`p-3 rounded-xl border text-xs flex items-start gap-2.5 ${
        mergeHazard
          ? 'bg-amber-50 dark:bg-amber-950/30 border-amber-300 dark:border-amber-500/30 text-amber-900 dark:text-amber-200'
          : 'bg-canvas border-subtle text-secondary'
      }`}
    >
      {mergeHazard ? (
        <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5 text-amber-500" />
      ) : (
        <Info className="w-4 h-4 shrink-0 mt-0.5 text-accent" />
      )}
      <div className="space-y-1">
        <div className="font-mono font-semibold">Target Path Hint: {pathHint}</div>
        {mergeHazard ? (
          <p>
            This file stores additional non-MCP user settings. Do <strong>not</strong> replace the file—merge only the
            exported section manually.
          </p>
        ) : (
          <p className="text-muted">Secrets are replaced with dynamic placeholders (e.g. [GITHUB_TOKEN]).</p>
        )}
      </div>
    </div>
  )
}

export const ExportPreviewPanel: React.FC<{
  loading: boolean
  activeTab: 'primary' | 'companion'
  displayedJson: string
  copied: boolean
  onCopy: () => void
  onDownload: () => void
}> = ({ loading, activeTab, displayedJson, copied, onCopy, onDownload }) => {
  if (loading) {
    return (
      <div className="p-8 rounded-xl bg-[#0F172A] border border-[#1E293B] text-slate-400 text-xs font-mono text-center">
        Generating native MCP configuration...
      </div>
    )
  }

  return (
    <div className="rounded-xl bg-[#0F172A] border border-[#1E293B] overflow-hidden">
      <div className="px-4 py-2 border-b border-[#1E293B] flex items-center justify-between">
        <span className="text-[11px] font-mono text-slate-400">
          {activeTab === 'companion' ? 'Companion Permissions JSON' : 'Native MCP Config JSON'}
        </span>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={onCopy}
            className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-[11px] font-mono transition-colors"
          >
            {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
            <span>{copied ? 'Copied' : 'Copy'}</span>
          </button>
          <button
            type="button"
            onClick={onDownload}
            className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-[11px] font-mono transition-colors"
          >
            <Download className="w-3 h-3" />
            <span>Download</span>
          </button>
        </div>
      </div>
      <pre className="p-4 text-xs font-mono text-cyan-200 overflow-x-auto max-h-72 leading-relaxed">
        {displayedJson}
      </pre>
    </div>
  )
}

export const ExportWarningsList: React.FC<{ warnings: ExportWarning[] }> = ({ warnings }) => {
  const warningItems = warnings.filter((w) => w.severity === 'warning')
  const infoItems = warnings.filter((w) => w.severity !== 'warning')

  return (
    <>
      {warningItems.length > 0 && (
        <div className="space-y-2">
          {warningItems.map((w, idx) => (
            <div
              key={`${w.code}-${w.server || idx}`}
              className="p-3 rounded-xl bg-amber-50 dark:bg-amber-950/30 border border-amber-300 dark:border-amber-500/30 text-xs text-amber-900 dark:text-amber-200 flex items-start gap-2"
            >
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-amber-500" />
              <div>
                <span className="font-mono font-semibold">{w.code}</span>
                {w.server && <span className="font-mono ml-1.5 text-amber-700 dark:text-amber-300">[{w.server}]</span>}
                <p className="mt-0.5">{w.message}</p>
              </div>
            </div>
          ))}
        </div>
      )}

      {infoItems.length > 0 && (
        <div className="space-y-1.5">
          {infoItems.map((w, idx) => (
            <div
              key={`${w.code}-${idx}`}
              className="p-2.5 rounded-xl bg-canvas border border-subtle text-[11px] text-muted flex items-start gap-2"
            >
              <Info className="w-3.5 h-3.5 shrink-0 mt-0.5 text-accent" />
              <div>
                <span className="font-mono font-semibold text-secondary">{w.code}:</span> {w.message}
              </div>
            </div>
          ))}
        </div>
      )}
    </>
  )
}
