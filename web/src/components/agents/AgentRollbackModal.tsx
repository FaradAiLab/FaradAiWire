import React, { useState, useEffect, useMemo } from 'react'
import { History, RotateCcw, CheckCircle2, Check } from 'lucide-react'
import { api } from '../../api'
import { Modal } from '../ui/Modal'
import { Button } from '../ui/Button'

export interface AgentRollbackModalProps {
  isOpen: boolean
  agentName: string | null
  onClose: () => void
  onSuccess: (restoredArchive?: string) => void
}

interface FormattedArchive {
  timestamp: string
  versionNumber: number
  label: string
  isLatest: boolean
}

export const formatArchiveLabel = (
  rawTimestamp: string,
  versionNumber: number,
  isLatest: boolean
): string => {
  let dateFormatted = rawTimestamp
  // Match ISO compact: 20261017T212250Z or 20261017T212250
  const isoMatch = rawTimestamp.match(/^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z?$/)
  // Match hyphenated: 20260926-120000
  const hyphenMatch = rawTimestamp.match(/^(\d{4})(\d{2})(\d{2})[-_](\d{2})(\d{2})(\d{2})Z?$/)
  const match = isoMatch || hyphenMatch

  if (match) {
    const [, year, month, day, hour, min, sec] = match
    dateFormatted = `${year}-${month}-${day} ${hour}:${min}:${sec} UTC`
  }

  const tag = isLatest ? ' (Latest)' : ''
  return `Version ${versionNumber}${tag} • ${dateFormatted}`
}

export const AgentRollbackModal: React.FC<AgentRollbackModalProps> = ({
  isOpen,
  agentName,
  onClose,
  onSuccess,
}) => {
  const [rawArchives, setRawArchives] = useState<string[]>([])
  const [selectedArchive, setSelectedArchive] = useState<string>('')
  const [rollingBack, setRollingBack] = useState(false)
  const [loadingArchives, setLoadingArchives] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [successInfo, setSuccessInfo] = useState<string | null>(null)

  useEffect(() => {
    if (!isOpen || !agentName) {
      setRawArchives([])
      setSelectedArchive('')
      setError(null)
      setSuccessInfo(null)
      return
    }

    let isMounted = true
    const fetchArchives = async () => {
      try {
        setLoadingArchives(true)
        setError(null)
        setSuccessInfo(null)
        const res = await api.getAgentArchives(agentName)
        if (isMounted) {
          const list = res.archives || []
          setRawArchives(list)
          if (list.length > 0) {
            // Default to newest archive
            const sortedDesc = [...list].sort((a, b) => b.localeCompare(a))
            setSelectedArchive(sortedDesc[0])
          }
        }
      } catch (err: unknown) {
        if (isMounted) {
          const msg = err instanceof Error ? err.message : String(err)
          setError(msg)
          setRawArchives([])
        }
      } finally {
        if (isMounted) {
          setLoadingArchives(false)
        }
      }
    }

    fetchArchives()
    return () => {
      isMounted = false
    }
  }, [isOpen, agentName])

  // Build formatted version list: chronological order assigns v1..vN, then reversed so Latest is at the top
  const formattedArchives: FormattedArchive[] = useMemo(() => {
    if (rawArchives.length === 0) return []
    // Chronological order: oldest = Version 1
    const chronological = [...rawArchives].sort((a, b) => a.localeCompare(b))
    const total = chronological.length

    const mapped = chronological.map((ts, index) => {
      const versionNumber = index + 1
      const isLatest = index === total - 1
      return {
        timestamp: ts,
        versionNumber,
        label: formatArchiveLabel(ts, versionNumber, isLatest),
        isLatest,
      }
    })

    // Return descending: newest version first at the top
    return mapped.reverse()
  }, [rawArchives])

  const handleExecuteRollback = async () => {
    if (!agentName || !selectedArchive) return
    try {
      setRollingBack(true)
      setError(null)
      const res = await api.rollbackAgent(agentName, selectedArchive)
      const matched = formattedArchives.find((a) => a.timestamp === selectedArchive)
      const label = matched ? matched.label : selectedArchive
      setSuccessInfo(res.message || `Agent '${agentName}' successfully rolled back to ${label}`)
      // Brief pause so the operator visually sees the confirmation banner before modal unmounts
      setTimeout(() => {
        onSuccess(selectedArchive)
        onClose()
      }, 750)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      setError(`Rollback failed: ${msg}`)
    } finally {
      setRollingBack(false)
    }
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={`Snapshot Rollback: ${agentName || ''}`}
      subtitle="Restore this agent to any previously saved configuration snapshot."
      icon={<History className="w-5 h-5 text-amber-500" />}
      maxWidth="md"
    >
      <div className="space-y-4">
        {error && (
          <div className="p-3 rounded-xl bg-rose-50 dark:bg-rose-950/40 border border-rose-300 dark:border-rose-500/30 text-rose-700 dark:text-rose-300 text-xs font-mono">
            {error}
          </div>
        )}

        {successInfo && (
          <div className="p-3.5 rounded-xl bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-300 dark:border-emerald-500/30 text-emerald-800 dark:text-emerald-300 text-xs flex items-center gap-2.5 font-sans animate-in fade-in">
            <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0 animate-pulse" />
            <span className="font-semibold">{successInfo}</span>
          </div>
        )}

        {loadingArchives ? (
          <div className="p-8 text-center text-xs text-muted font-mono">
            Scanning snapshot archives...
          </div>
        ) : formattedArchives.length === 0 ? (
          <div className="p-6 text-center text-xs text-muted border border-dashed border-subtle rounded-xl font-sans">
            No archived snapshots found for this agent yet.
          </div>
        ) : (
          <div className="space-y-3 font-sans">
            <div>
              <label className="block text-xs font-semibold text-primary mb-1.5">
                Select Revision Snapshot
              </label>
              <select
                value={selectedArchive}
                onChange={(e) => setSelectedArchive(e.target.value)}
                className="w-full px-3.5 py-2.5 rounded-xl bg-surface border border-subtle text-primary font-sans text-xs focus:outline-none focus:ring-1 focus:ring-accent cursor-pointer shadow-xs"
              >
                {formattedArchives.map((item) => (
                  <option key={item.timestamp} value={item.timestamp}>
                    {item.label}
                  </option>
                ))}
              </select>
            </div>

            {selectedArchive && (
              <div className="p-3 rounded-xl bg-surface-muted/40 border border-subtle text-xs space-y-1">
                <div className="flex items-center justify-between text-muted">
                  <span>Target Snapshot ID:</span>
                  <span className="font-mono text-accent font-semibold">{selectedArchive}</span>
                </div>
                <p className="text-[11px] text-muted leading-relaxed">
                  Restoring will atomically roll back all agent parameters, protocol attachments, and tool governance to this revision point.
                </p>
              </div>
            )}
          </div>
        )}

        <div className="flex justify-end gap-2 pt-3 border-t border-subtle font-sans">
          <Button type="button" variant="ghost" size="md" onClick={onClose} disabled={Boolean(successInfo)}>
            Cancel
          </Button>
          <Button
            type="button"
            variant="primary"
            size="md"
            disabled={rollingBack || Boolean(successInfo) || !selectedArchive || formattedArchives.length === 0}
            isLoading={rollingBack}
            onClick={handleExecuteRollback}
            className={`font-semibold shadow-xs ${
              successInfo
                ? '!bg-emerald-600 hover:!bg-emerald-500 text-white'
                : '!bg-amber-600 hover:!bg-amber-500 text-white'
            }`}
            icon={successInfo ? <Check className="w-3.5 h-3.5" /> : <RotateCcw className="w-3.5 h-3.5" />}
          >
            {rollingBack ? 'Restoring...' : successInfo ? 'Restored!' : 'Restore Snapshot'}
          </Button>
        </div>
      </div>
    </Modal>
  )
}
