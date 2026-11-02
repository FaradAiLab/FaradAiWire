import React, { useState, useMemo, useCallback } from 'react'
import {
  Copy,
  Check,
  Terminal,
  Cpu,
  Laptop,
  Compass,
  Sparkles,
  FileCode,
  Folder,
  Layers,
  Key,
  Info,
} from 'lucide-react'
import { Modal } from './ui/Modal'
import { Badge } from './ui/Badge'

export type ClientId = 'claude-desktop' | 'cursor' | 'windsurf' | 'claude-cli' | 'antigravity'

export interface ClientConfigModalProps {
  isOpen: boolean
  onClose: () => void
  token: string
  keyName?: string
  agentName?: string
  availableAgents?: string[]
  ingressPort?: number
  ingressHost?: string
}

interface ClientMeta {
  id: ClientId
  label: string
  sublabel: string
  icon: React.ReactNode
  filePath: {
    mac: string
    win?: string
    linux?: string
  }
}

const CLIENTS: ClientMeta[] = [
  {
    id: 'claude-desktop',
    label: 'Claude Desktop',
    sublabel: 'Anthropic Desktop App',
    icon: <Laptop className="w-4 h-4 text-amber-400" />,
    filePath: {
      mac: '~/Library/Application Support/Claude/claude_desktop_config.json',
      win: '%APPDATA%\\Claude\\claude_desktop_config.json',
    },
  },
  {
    id: 'cursor',
    label: 'Cursor',
    sublabel: 'AI Code Editor',
    icon: <Cpu className="w-4 h-4 text-cyan-400" />,
    filePath: {
      mac: '.cursor/mcp.json (or Settings > Features > MCP)',
      win: '.cursor/mcp.json',
    },
  },
  {
    id: 'windsurf',
    label: 'Windsurf',
    sublabel: 'Codeium IDE',
    icon: <Compass className="w-4 h-4 text-emerald-400" />,
    filePath: {
      mac: '~/.codeium/windsurf/mcp_config.json',
      win: '%USERPROFILE%\\.codeium\\windsurf\\mcp_config.json',
    },
  },
  {
    id: 'claude-cli',
    label: 'Claude Code CLI',
    sublabel: 'Terminal Agent',
    icon: <Terminal className="w-4 h-4 text-indigo-400" />,
    filePath: {
      mac: 'Run command directly in your shell',
    },
  },
  {
    id: 'antigravity',
    label: 'Antigravity / Gemini',
    sublabel: 'Google Antigravity IDE',
    icon: <Sparkles className="w-4 h-4 text-violet-400" />,
    filePath: {
      mac: '~/.gemini/config/mcp_config.json',
      win: '%USERPROFILE%\\.gemini\\config\\mcp_config.json',
    },
  },
]

export const ClientConfigModal: React.FC<ClientConfigModalProps> = React.memo(
  ({
    isOpen,
    onClose,
    token,
    keyName,
    agentName,
    availableAgents = [],
    ingressPort = 8090,
    ingressHost = '127.0.0.1',
  }) => {
    const [selectedClient, setSelectedClient] = useState<ClientId>('claude-desktop')
    const [isFullFile, setIsFullFile] = useState(true)
    const [selectedAgent, setSelectedAgent] = useState<string>(() => {
      if (agentName && agentName !== '*') return agentName
      if (availableAgents.length > 0) return availableAgents[0]
      return '*'
    })
    const [copiedConfig, setCopiedConfig] = useState(false)
    const [copiedPath, setCopiedPath] = useState(false)
    const [copiedToken, setCopiedToken] = useState(false)

    // Synchronize agent if prop changes
    React.useEffect(() => {
      if (agentName && agentName !== '*') {
        setSelectedAgent(agentName)
      } else if (availableAgents.length > 0 && selectedAgent === '*') {
        setSelectedAgent(availableAgents[0])
      }
    }, [agentName, availableAgents, selectedAgent])

    const isWildcardKey = !agentName || agentName === '*'
    const effectiveAgent = selectedAgent === '*' ? '' : selectedAgent
    const serverKey = effectiveAgent ? `farad-ai-${effectiveAgent}` : 'farad-ai-wire'
    const endpointUrl = effectiveAgent
      ? `http://${ingressHost}:${ingressPort}/sse/${effectiveAgent}`
      : `http://${ingressHost}:${ingressPort}/sse`

    const isTokenMasked = !token || token.includes('••••••')
    const displayToken = isTokenMasked ? 'faw_live_YOUR_TOKEN_HERE' : token

    const activeClientMeta = useMemo(
      () => CLIENTS.find((c) => c.id === selectedClient) || CLIENTS[0],
      [selectedClient]
    )

    // Generate configuration snippet
    const configCode = useMemo(() => {
      switch (selectedClient) {
        case 'claude-desktop': {
          const serverBlock = {
            command: 'npx',
            args: ['-y', 'mcp-remote', endpointUrl, '--header', `Authorization: Bearer ${displayToken}`],
          }
          if (isFullFile) {
            return JSON.stringify({ mcpServers: { [serverKey]: serverBlock } }, null, 2)
          }
          return `"${serverKey}": ${JSON.stringify(serverBlock, null, 2)}`
        }

        case 'cursor': {
          const serverBlock = {
            url: endpointUrl,
            headers: {
              Authorization: `Bearer ${displayToken}`,
            },
          }
          if (isFullFile) {
            return JSON.stringify({ mcpServers: { [serverKey]: serverBlock } }, null, 2)
          }
          return `"${serverKey}": ${JSON.stringify(serverBlock, null, 2)}`
        }

        case 'windsurf': {
          const serverBlock = {
            serverUrl: endpointUrl,
            headers: {
              Authorization: `Bearer ${displayToken}`,
            },
          }
          if (isFullFile) {
            return JSON.stringify({ mcpServers: { [serverKey]: serverBlock } }, null, 2)
          }
          return `"${serverKey}": ${JSON.stringify(serverBlock, null, 2)}`
        }

        case 'claude-cli': {
          if (isFullFile) {
            return `# Run in your terminal:\nclaude mcp add ${serverKey} --transport sse "${endpointUrl}" --header "Authorization: Bearer ${displayToken}"`
          }
          return `claude mcp add ${serverKey} --transport sse "${endpointUrl}" --header "Authorization: Bearer ${displayToken}"`
        }

        case 'antigravity': {
          const serverBlock = {
            url: endpointUrl,
            headers: {
              Authorization: `Bearer ${displayToken}`,
            },
          }
          if (isFullFile) {
            return JSON.stringify({ mcpServers: { [serverKey]: serverBlock } }, null, 2)
          }
          return `"${serverKey}": ${JSON.stringify(serverBlock, null, 2)}`
        }

        default:
          return ''
      }
    }, [selectedClient, isFullFile, serverKey, endpointUrl, displayToken])

    const handleCopyConfig = useCallback(() => {
      navigator.clipboard.writeText(configCode)
      setCopiedConfig(true)
      setTimeout(() => setCopiedConfig(false), 2000)
    }, [configCode])

    const handleCopyPath = useCallback((path: string) => {
      navigator.clipboard.writeText(path)
      setCopiedPath(true)
      setTimeout(() => setCopiedPath(false), 2000)
    }, [])

    const handleCopyToken = useCallback(() => {
      if (!isTokenMasked && token) {
        navigator.clipboard.writeText(token)
        setCopiedToken(true)
        setTimeout(() => setCopiedToken(false), 2000)
      }
    }, [isTokenMasked, token])

    return (
      <Modal
        isOpen={isOpen}
        onClose={onClose}
        title="Client Connection Guide"
        subtitle="100% valid, pre-authenticated MCP client configurations ready to paste."
        icon={<Sparkles className="w-5 h-5 text-cyan-400" />}
        maxWidth="2xl"
      >
        <div className="space-y-5 text-xs">
          {/* Key & Agent Context Banner */}
          <div className="p-3.5 rounded-xl bg-canvas border border-subtle flex flex-wrap items-center justify-between gap-3 shadow-xs">
            <div className="flex items-center gap-2">
              <Key className="w-4 h-4 text-accent-primary shrink-0" />
              <div>
                <span className="text-muted">Active Token: </span>
                <span className="font-mono text-primary font-semibold">{keyName || 'API Key'}</span>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <span className="text-muted">Target Profile:</span>
              {isWildcardKey ? (
                <div className="flex items-center gap-1.5">
                  <select
                    value={selectedAgent}
                    onChange={(e) => setSelectedAgent(e.target.value)}
                    className="px-2.5 py-1 rounded-lg bg-surface border border-subtle text-accent-primary font-mono text-[11px] focus:outline-none focus:ring-1 focus:ring-accent-primary"
                  >
                    {availableAgents.map((ag) => (
                      <option key={ag} value={ag}>
                        {ag}
                      </option>
                    ))}
                    <option value="*">* (All Profiles / Root /sse)</option>
                  </select>
                  <Badge variant="indigo" size="sm">
                    Global Key
                  </Badge>
                </div>
              ) : (
                <Badge variant="cyan" size="sm" icon={<Layers className="w-3 h-3" />}>
                  {agentName}
                </Badge>
              )}
            </div>
          </div>

          {/* Legacy Hash Notice if token is masked */}
          {isTokenMasked && (
            <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-800 dark:text-amber-200 flex items-start gap-2.5">
              <Info className="w-4 h-4 shrink-0 mt-0.5 text-amber-500" />
              <div>
                <div className="font-semibold">Legacy Hash-Only Key</div>
                <div className="text-[11px] text-amber-700/80 dark:text-amber-300/80 mt-0.5">
                  This key was stored prior to local raw-token preservation. Replace{' '}
                  <code className="bg-surface px-1 py-0.5 rounded font-mono border border-subtle">faw_live_YOUR_TOKEN_HERE</code>{' '}
                  with your token, or generate a new key for 1-click reveal.
                </div>
              </div>
            </div>
          )}

          {/* Client Selection Tabs */}
          <div>
            <div className="text-[10px] font-mono text-muted uppercase tracking-wider mb-2">
              Select Client Application
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-2">
              {CLIENTS.map((client) => {
                const isSelected = client.id === selectedClient
                return (
                  <button
                    key={client.id}
                    type="button"
                    onClick={() => setSelectedClient(client.id)}
                    className={`flex flex-col items-center justify-center p-3 rounded-xl border text-center transition-all ${
                      isSelected
                        ? 'bg-cyan-500/10 border-accent-primary shadow-xs text-primary font-semibold'
                        : 'bg-surface/40 border-subtle hover:border-default text-muted hover:text-primary hover:bg-surface'
                    }`}
                  >
                    <div className="mb-1.5">{client.icon}</div>
                    <span className="font-semibold text-[11px] leading-tight">{client.label}</span>
                    <span className="text-[9px] text-muted mt-0.5 line-clamp-1">{client.sublabel}</span>
                  </button>
                )
              })}
            </div>
          </div>

          {/* File Location Hint */}
          <div className="p-3 rounded-xl bg-surface/60 border border-subtle flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 overflow-hidden">
              <Folder className="w-3.5 h-3.5 text-muted shrink-0" />
              <div className="truncate">
                <span className="text-muted">Config Path: </span>
                <span className="font-mono text-primary text-[11px]">
                  {activeClientMeta.filePath.mac}
                </span>
              </div>
            </div>
            <button
              type="button"
              onClick={() => handleCopyPath(activeClientMeta.filePath.mac)}
              className="p-1 px-2 rounded-lg bg-surface hover:bg-surface/80 border border-subtle text-primary hover:text-accent-primary transition-colors flex items-center gap-1 font-mono text-[10px] shrink-0"
              title="Copy path"
            >
              {copiedPath ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
              <span>{copiedPath ? 'Copied' : 'Copy Path'}</span>
            </button>
          </div>

          {/* Configuration Code Box (DUAL TONE INVARIANT) */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FileCode className="w-3.5 h-3.5 text-accent-primary" />
                <span className="font-mono text-[10px] uppercase text-muted tracking-wider">
                  Configuration Snippet
                </span>
              </div>

              {selectedClient !== 'claude-cli' && (
                <div className="flex items-center gap-1 p-0.5 rounded-lg bg-surface border border-subtle font-mono text-[10px]">
                  <button
                    type="button"
                    onClick={() => setIsFullFile(true)}
                    className={`px-2 py-0.5 rounded-md transition-colors ${
                      isFullFile
                        ? 'bg-accent-primary text-white font-semibold shadow-xs'
                        : 'text-muted hover:text-primary'
                    }`}
                  >
                    Full File
                  </button>
                  <button
                    type="button"
                    onClick={() => setIsFullFile(false)}
                    className={`px-2 py-0.5 rounded-md transition-colors ${
                      !isFullFile
                        ? 'bg-accent-primary text-white font-semibold shadow-xs'
                        : 'text-muted hover:text-primary'
                    }`}
                  >
                    Server Block Only
                  </button>
                </div>
              )}
            </div>

            <div className="relative group rounded-xl overflow-hidden border border-[#1E293B] bg-[#0F172A] shadow-inner">
              <pre className="p-4 font-mono text-[11px] leading-relaxed text-cyan-300 overflow-x-auto max-h-64 select-all">
                {configCode}
              </pre>

              <div className="absolute top-2.5 right-2.5 flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={handleCopyConfig}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-mono text-[11px] font-semibold shadow-lg transition-all"
                  title="Copy snippet"
                >
                  {copiedConfig ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-white" />
                      <span>Copied!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Copy Config</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>

          {/* Quick Raw Token Copy Box if available */}
          {!isTokenMasked && token && (
            <div className="p-2.5 rounded-xl bg-[#0F172A] border border-[#1E293B] shadow-inner flex items-center justify-between text-[11px] font-mono">
              <div className="flex items-center gap-2 truncate pr-2">
                <span className="text-slate-400">Raw Token:</span>
                <span className="text-cyan-300 truncate font-semibold">{token}</span>
              </div>
              <button
                type="button"
                onClick={handleCopyToken}
                className="p-1 px-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 hover:text-white transition-colors flex items-center gap-1 shrink-0"
              >
                {copiedToken ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>{copiedToken ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
          )}

          {/* Footer Actions */}
          <div className="pt-2 flex items-center justify-between border-t border-subtle">
            <span className="text-[10px] text-muted font-mono">
              Ingress endpoint listening on :{ingressPort}
            </span>
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-xl bg-surface hover:bg-surface/80 border border-subtle text-primary text-xs font-semibold transition-colors"
            >
              Done
            </button>
          </div>
        </div>
      </Modal>
    )
  }
)

ClientConfigModal.displayName = 'ClientConfigModal'
