import React, { useState, useEffect } from 'react'
import { DlpRule, DlpAction } from '../../types'
import { Modal } from '../ui/Modal'
import { Input } from '../ui/Input'
import { Button } from '../ui/Button'
import { FileCode, AlertCircle } from 'lucide-react'

export interface RuleEditorModalProps {
  isOpen: boolean
  onClose: () => void
  ruleToEdit?: DlpRule | null
  onSave: (rule: Partial<DlpRule>) => Promise<void>
}

export const RuleEditorModal: React.FC<RuleEditorModalProps> = ({
  isOpen,
  onClose,
  ruleToEdit,
  onSave,
}) => {
  const [id, setId] = useState('')
  const [name, setName] = useState('')
  const [category, setCategory] = useState('custom')
  const [regex, setRegex] = useState('')
  const [defaultAction, setDefaultAction] = useState<DlpAction>('mask')
  const [description, setDescription] = useState('')
  const [regexError, setRegexError] = useState<string | null>(null)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [submitError, setSubmitError] = useState<string | null>(null)

  useEffect(() => {
    if (ruleToEdit) {
      setId(ruleToEdit.id)
      setName(ruleToEdit.name)
      setCategory(ruleToEdit.category || 'custom')
      setRegex(ruleToEdit.regex)
      setDefaultAction(ruleToEdit.default_action)
      setDescription(ruleToEdit.description || '')
    } else {
      setId('')
      setName('')
      setCategory('custom')
      setRegex('')
      setDefaultAction('mask')
      setDescription('')
    }
    setRegexError(null)
    setSubmitError(null)
  }, [ruleToEdit, isOpen])

  const validateRegexInput = (val: string): boolean => {
    try {
      new RegExp(val)
      setRegexError(null)
      return true
    } catch (e: unknown) {
      setRegexError(e instanceof Error ? e.message : 'Invalid regex')
      return false
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!id.trim() || !name.trim() || !regex.trim()) {
      setSubmitError('ID, Name, and Regex are required.')
      return
    }
    if (!validateRegexInput(regex)) {
      return
    }

    try {
      setIsSubmitting(true)
      setSubmitError(null)
      await onSave({
        id: id.trim(),
        name: name.trim(),
        category: category.trim(),
        regex: regex.trim(),
        default_action: defaultAction,
        description: description.trim(),
      })
      onClose()
    } catch (err: unknown) {
      setSubmitError(err instanceof Error ? err.message : String(err))
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={ruleToEdit ? 'Edit DLP Pattern Rule' : 'Create Custom DLP Rule'}
      subtitle="Define regex pattern and enforcement action for data loss prevention"
      icon={<FileCode className="w-5 h-5" />}
      maxWidth="lg"
    >
      <form onSubmit={handleSubmit} className="space-y-4">
        {submitError && (
          <div className="p-3 rounded-xl bg-rose-50 dark:bg-rose-950/40 border border-rose-300 dark:border-rose-500/30 text-rose-800 dark:text-rose-300 text-xs font-mono flex items-start gap-2">
            <AlertCircle className="w-4 h-4 text-rose-500 shrink-0 mt-0.5" />
            <span>{submitError}</span>
          </div>
        )}

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <Input
            label="Rule ID"
            placeholder="e.g. custom:api-token"
            value={id}
            onChange={(e) => setId(e.target.value)}
            disabled={!!ruleToEdit}
            isMono
            required
            helperText="Alphanumeric, hyphen, colon or underscore"
          />

          <Input
            label="Rule Name"
            placeholder="e.g. Internal API Secret Token"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
          />
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <Input
            label="Category"
            placeholder="e.g. security, pii, cloud"
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            isMono
            required
          />

          <div>
            <label className="block text-xs font-semibold text-primary mb-1 font-mono">
              Default Action
            </label>
            <select
              value={defaultAction}
              onChange={(e) => setDefaultAction(e.target.value as DlpAction)}
              className="w-full px-3 py-2 rounded-xl bg-surface border border-subtle text-xs font-mono text-primary focus:outline-none focus-visible:ring-2 focus-visible:ring-accent-primary"
            >
              <option value="mask">MASK (Redact / Sanitize)</option>
              <option value="block">BLOCK (Immediate 403 Stop)</option>
              <option value="audit">AUDIT (Log & Allow)</option>
            </select>
          </div>
        </div>

        <div>
          <label className="block text-xs font-semibold text-primary mb-1 font-mono">
            Regular Expression (Regex)
          </label>
          <input
            type="text"
            value={regex}
            onChange={(e) => {
              setRegex(e.target.value)
              validateRegexInput(e.target.value)
            }}
            placeholder="e.g. (?i)secret_[a-z0-9]{32}"
            className={`w-full px-3 py-2 rounded-xl bg-surface border text-xs font-mono text-sky-800 dark:text-cyan-300 placeholder:text-muted focus:outline-none focus-visible:ring-2 focus-visible:ring-accent-primary ${
              regexError ? 'border-rose-500/50' : 'border-subtle hover:border-strong'
            }`}
            required
          />
          {regexError ? (
            <p className="text-[11px] text-rose-500 dark:text-rose-400 font-mono mt-1">{regexError}</p>
          ) : (
            <p className="text-[10px] text-muted font-mono mt-1">
              Supports standard Go and ECMAScript regex syntax.
            </p>
          )}
        </div>

        <div>
          <label className="block text-xs font-semibold text-primary mb-1 font-mono">
            Description
          </label>
          <textarea
            rows={2}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Explain why this rule exists and when it should trigger..."
            className="w-full px-3 py-2 rounded-xl bg-surface border border-subtle text-xs text-primary placeholder:text-muted focus:outline-none focus-visible:ring-2 focus-visible:ring-accent-primary"
          />
        </div>

        <div className="flex items-center justify-end gap-2 pt-3 border-t border-subtle">
          <Button variant="ghost" size="md" onClick={onClose} disabled={isSubmitting} type="button">
            Cancel
          </Button>
          <Button
            variant="primary"
            size="md"
            type="submit"
            isLoading={isSubmitting}
            disabled={!!regexError || !regex.trim()}
          >
            {ruleToEdit ? 'Save Changes' : 'Create Rule'}
          </Button>
        </div>
      </form>
    </Modal>
  )
}
