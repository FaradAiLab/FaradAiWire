import React from 'react'
import { AlertTriangle } from 'lucide-react'
import { Modal } from '../ui/Modal'
import { Button } from '../ui/Button'

export interface SessionConflictModalProps {
  conflict: {
    agentName: string
    message: string
  } | null
  onClose: () => void
}

export const SessionConflictModal: React.FC<SessionConflictModalProps> = ({
  conflict,
  onClose,
}) => {
  return (
    <Modal
      isOpen={Boolean(conflict)}
      onClose={onClose}
      title="Cannot Delete Agent: Active Sessions"
      subtitle="Connected SSE clients are currently bound to this agent."
      icon={<AlertTriangle className="w-5 h-5 text-rose-400" />}
      maxWidth="md"
    >
      <div className="space-y-4">
        <p className="text-xs text-primary leading-relaxed font-sans">
          {conflict?.message}
        </p>

        <p className="text-xs text-muted bg-canvas p-3 rounded-xl font-mono border border-subtle leading-relaxed">
          Agent <span className="text-accent-primary font-bold">&apos;{conflict?.agentName}&apos;</span> currently has connected client sessions. Please disconnect all SSE clients before removing this agent.
        </p>

        <div className="flex justify-end pt-3 border-t border-subtle">
          <Button
            type="button"
            variant="danger"
            size="sm"
            onClick={onClose}
          >
            Understood
          </Button>
        </div>
      </div>
    </Modal>
  )
}
