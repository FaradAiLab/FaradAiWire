import React, { useState } from 'react'
import { Plus, Terminal, Globe, Server, Check } from 'lucide-react'
import { Modal } from '../ui/Modal'
import { Button } from '../ui/Button'
import { Input } from '../ui/Input'
import { ProtocolItem } from '../../types'
import { api } from '../../api'

export interface QuickProtocolRegisterModalProps {
  isOpen: boolean
  onClose: () => void
  onSuccess: (protocol: ProtocolItem) => void
}

export const QuickProtocolRegisterModal: React.FC<QuickProtocolRegisterModalProps> = ({
  isOpen,
  onClose,
  onSuccess,
}) => {
  const [id, setId] = useState('')
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [type, setType] = useState<'stdio' | 'sse' | 'http'>('stdio')
  const [command, setCommand] = useState('')
  const [url, setUrl] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    const cleanId = id.trim().toLowerCase()
    const cleanName = name.trim() || cleanId
    if (!cleanId) {
      setError('Protocol ID is required')
      return
    }

    try {
      setSaving(true)
      setError(null)

      let cmdArgs: string[] = []
      let mainCmd = ''

      if (type === 'stdio') {
        const parts = command.trim().split(/\s+/)
        mainCmd = parts[0] || ''
        cmdArgs = parts.slice(1)
      }

      const res = await api.createProtocol({
        id: cleanId,
        name: cleanName,
        description: description.trim(),
        type,
        command: type === 'stdio' ? mainCmd : undefined,
        args: type === 'stdio' ? cmdArgs : undefined,
        url_or_command: type === 'stdio' ? command.trim() : url.trim(),
      })

      if (res.protocol) {
        onSuccess(res.protocol)
        onClose()
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setSaving(false)
    }
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Register New MCP Protocol"
      subtitle="Define a new Model Context Protocol backend service in the catalog"
      icon={<Plus className="w-5 h-5 text-cyan-400" />}
      maxWidth="md"
    >
      <form onSubmit={handleSubmit} className="space-y-4">
        {error && (
          <div className="p-3 rounded-xl bg-rose-50 dark:bg-rose-950/40 border border-rose-300 dark:border-rose-500/30 text-rose-800 dark:text-rose-300 text-xs font-mono">
            {error}
          </div>
        )}

        <div className="grid grid-cols-2 gap-3">
          <Input
            label="Protocol ID (Slug)"
            placeholder="e.g. context7, tavily"
            value={id}
            onChange={(e) => setId(e.target.value.toLowerCase().replace(/[^a-z0-9_-]/g, ''))}
            required
          />
          <Input
            label="Display Name"
            placeholder="e.g. Context7 Docs"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </div>

        <Input
          label="Description"
          placeholder="e.g. Upstream MCP documentation search service"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
        />

        {/* Transport Type */}
        <div>
          <label className="block text-xs font-semibold text-primary mb-1.5 font-mono">Transport Type</label>
          <div className="grid grid-cols-3 gap-2">
            {[
              { id: 'stdio', label: 'Local Stdio', icon: <Terminal className="w-3.5 h-3.5" /> },
              { id: 'sse', label: 'Remote SSE', icon: <Server className="w-3.5 h-3.5" /> },
              { id: 'http', label: 'Stream HTTP', icon: <Globe className="w-3.5 h-3.5" /> },
            ].map((t) => (
              <button
                key={t.id}
                type="button"
                onClick={() => setType(t.id as any)}
                className={`flex items-center justify-center gap-1.5 py-2 px-3 rounded-xl border text-xs font-mono transition-all ${
                  type === t.id
                    ? 'bg-sky-50 dark:bg-cyan-950/40 border-sky-300 dark:border-cyan-500/40 text-sky-900 dark:text-cyan-200 font-bold shadow-xs'
                    : 'bg-surface border-subtle text-muted hover:text-primary hover:border-strong'
                }`}
              >
                {t.icon}
                <span>{t.label}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Command or URL input */}
        {type === 'stdio' ? (
          <Input
            label="Command & Arguments"
            placeholder="e.g. npx -y @modelcontextprotocol/server-filesystem /path"
            value={command}
            onChange={(e) => setCommand(e.target.value)}
            required
          />
        ) : (
          <Input
            label="Service URL"
            placeholder="e.g. http://127.0.0.1:8000/sse"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            required
          />
        )}

        <div className="flex items-center justify-end gap-2 pt-3 border-t border-subtle">
          <Button type="button" variant="ghost" size="md" onClick={onClose}>
            Cancel
          </Button>
          <Button
            type="submit"
            variant="primary"
            size="md"
            isLoading={saving}
            disabled={saving || !id.trim() || (type === 'stdio' ? !command.trim() : !url.trim())}
            icon={<Check className="w-4 h-4" />}
          >
            Save &amp; Attach to Agent
          </Button>
        </div>
      </form>
    </Modal>
  )
}
