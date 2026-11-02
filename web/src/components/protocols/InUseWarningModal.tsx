import React from 'react'
import { AlertTriangle } from 'lucide-react'
import { Modal } from '../ui/Modal'
import { Button } from '../ui/Button'

export interface InUseWarningModalProps {
  warning: { protocolName: string; message: string } | null
  onClose: () => void
}

export const InUseWarningModal: React.FC<InUseWarningModalProps> = ({ warning, onClose }) => {
  if (!warning) return null

  return (
    <Modal
      isOpen={!!warning}
      onClose={onClose}
      title="Cannot Delete Protocol: In Use"
      icon={<AlertTriangle className="w-5 h-5 text-rose-400" />}
      maxWidth="md"
    >
      <div className="space-y-4">
        <p className="text-xs text-primary leading-relaxed">{warning.message}</p>
        <p className="text-xs text-muted bg-surface/80 p-3 rounded-xl font-mono border border-subtle">
          Please detach protocol &apos;{warning.protocolName}&apos; from active agent configurations
          in the Agents tab before deleting.
        </p>
        <div className="flex justify-end pt-2">
          <Button variant="danger" size="md" onClick={onClose}>
            Understood
          </Button>
        </div>
      </div>
    </Modal>
  )
}
