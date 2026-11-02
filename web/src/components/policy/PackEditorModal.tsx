import React, { useState, useEffect, useMemo } from 'react'
import { PolicyPack, DlpRule } from '../../types'
import { Modal } from '../ui/Modal'
import { Input } from '../ui/Input'
import { Button } from '../ui/Button'
import { Badge } from '../ui/Badge'
import { ShieldCheck, AlertCircle, Search } from 'lucide-react'

export interface PackEditorModalProps {
  isOpen: boolean
  onClose: () => void
  packToEdit?: PolicyPack | null
  availableRules: DlpRule[]
  onSave: (pack: Partial<PolicyPack>) => Promise<void>
}

export const PackEditorModal: React.FC<PackEditorModalProps> = ({
  isOpen,
  onClose,
  packToEdit,
  availableRules,
  onSave,
}) => {
  const [id, setId] = useState('')
  const [name, setName] = useState('')
  const [category, setCategory] = useState('compliance')
  const [description, setDescription] = useState('')
  const [selectedRuleIds, setSelectedRuleIds] = useState<string[]>([])
  const [ruleSearch, setRuleSearch] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [submitError, setSubmitError] = useState<string | null>(null)

  useEffect(() => {
    if (packToEdit) {
      setId(packToEdit.id)
      setName(packToEdit.name)
      setCategory(packToEdit.category || 'compliance')
      setDescription(packToEdit.description || '')
      setSelectedRuleIds(packToEdit.rule_ids || [])
    } else {
      setId('')
      setName('')
      setCategory('compliance')
      setDescription('')
      setSelectedRuleIds([])
    }
    setSubmitError(null)
    setRuleSearch('')
  }, [packToEdit, isOpen])

  const filteredRules = useMemo(() => {
    const s = ruleSearch.toLowerCase().trim()
    if (!s) return availableRules
    return availableRules.filter(
      (r) =>
        r.id.toLowerCase().includes(s) ||
        r.name.toLowerCase().includes(s) ||
        r.category.toLowerCase().includes(s)
    )
  }, [availableRules, ruleSearch])

  const toggleRule = (ruleId: string) => {
    setSelectedRuleIds((prev) =>
      prev.includes(ruleId) ? prev.filter((id) => id !== ruleId) : [...prev, ruleId]
    )
  }

  const handleSelectAll = () => {
    const allFilteredIds = filteredRules.map((r) => r.id)
    setSelectedRuleIds((prev) => Array.from(new Set([...prev, ...allFilteredIds])))
  }

  const handleDeselectAll = () => {
    const allFilteredIds = new Set(filteredRules.map((r) => r.id))
    setSelectedRuleIds((prev) => prev.filter((id) => !allFilteredIds.has(id)))
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!id.trim() || !name.trim()) {
      setSubmitError('ID and Name are required.')
      return
    }

    try {
      setIsSubmitting(true)
      setSubmitError(null)
      await onSave({
        id: id.trim(),
        name: name.trim(),
        category: category.trim(),
        description: description.trim(),
        rule_ids: selectedRuleIds,
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
      title={packToEdit ? 'Edit Policy Pack' : 'Create Custom Policy Pack'}
      subtitle="Bundle DLP rules into an enforceable compliance or domain package"
      icon={<ShieldCheck className="w-5 h-5" />}
      maxWidth="xl"
    >
      <form onSubmit={handleSubmit} className="space-y-4">
        {submitError && (
          <div className="p-3 rounded-xl bg-rose-950/40 border border-rose-500/30 text-rose-300 text-xs font-mono flex items-start gap-2">
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
            <span>{submitError}</span>
          </div>
        )}

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <Input
            label="Pack ID"
            placeholder="e.g. pack:custom-fintech"
            value={id}
            onChange={(e) => setId(e.target.value)}
            disabled={!!packToEdit}
            isMono
            required
            helperText="Format: pack:<identifier>"
          />

          <Input
            label="Pack Name"
            placeholder="e.g. Custom Fintech & PCI Set"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
          />
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <Input
            label="Category"
            placeholder="e.g. compliance, database, cloud"
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            isMono
            required
          />

          <Input
            label="Description"
            placeholder="Brief summary of pack purpose"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </div>

        {/* Rule Assignment Section */}
        <div className="pt-3 border-t border-subtle space-y-2">
          <div className="flex items-center justify-between">
            <div>
              <label className="block text-xs font-semibold text-primary font-mono">
                Included Rules ({selectedRuleIds.length} Selected)
              </label>
              <p className="text-[10px] text-muted font-mono">
                Select which catalog patterns will be bundled in this pack.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={handleSelectAll}
                className="text-[11px] text-accent-primary hover:underline font-mono"
              >
                Select All
              </button>
              <span className="text-muted">|</span>
              <button
                type="button"
                onClick={handleDeselectAll}
                className="text-[11px] text-muted hover:text-primary font-mono"
              >
                Deselect
              </button>
            </div>
          </div>

          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
            <input
              type="text"
              placeholder="Filter available rules..."
              value={ruleSearch}
              onChange={(e) => setRuleSearch(e.target.value)}
              className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-surface border border-subtle text-xs text-primary placeholder:text-muted focus:outline-none focus-visible:ring-1 focus-visible:ring-accent-primary font-mono"
            />
          </div>

          <div className="max-h-52 overflow-y-auto space-y-1.5 pr-1 border border-subtle rounded-xl p-2 bg-canvas">
            {filteredRules.length === 0 ? (
              <p className="text-xs text-muted text-center py-4 font-mono">
                No rules match your filter.
              </p>
            ) : (
              filteredRules.map((rule) => {
                const isSelected = selectedRuleIds.includes(rule.id)
                return (
                  <label
                    key={rule.id}
                    className={`flex items-center justify-between p-2 rounded-lg cursor-pointer transition-colors border text-xs font-mono select-none ${
                      isSelected
                        ? 'bg-sky-50 dark:bg-cyan-950/40 border-sky-300 dark:border-cyan-500/40 text-sky-900 dark:text-cyan-200'
                        : 'bg-surface border-subtle text-secondary hover:border-strong'
                    }`}
                  >
                    <div className="flex items-center gap-2.5 truncate mr-2">
                      <input
                        type="checkbox"
                        checked={isSelected}
                        onChange={() => toggleRule(rule.id)}
                        className="rounded border-subtle bg-surface text-accent-primary focus:ring-accent-primary h-4 w-4"
                      />
                      <span className="font-bold truncate text-primary">{rule.name}</span>
                      <span className="text-[10px] text-muted truncate">({rule.id})</span>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <Badge variant="neutral" size="sm">
                        {rule.category}
                      </Badge>
                      <Badge
                        variant={
                          rule.default_action === 'block'
                            ? 'rose'
                            : rule.default_action === 'mask'
                            ? 'amber'
                            : 'cyan'
                        }
                        size="sm"
                      >
                        {rule.default_action}
                      </Badge>
                    </div>
                  </label>
                )
              })
            )}
          </div>
        </div>

        <div className="flex items-center justify-end gap-2 pt-3 border-t border-subtle">
          <Button variant="ghost" size="md" onClick={onClose} disabled={isSubmitting} type="button">
            Cancel
          </Button>
          <Button variant="primary" size="md" type="submit" isLoading={isSubmitting}>
            {packToEdit ? 'Save Changes' : 'Create Policy Pack'}
          </Button>
        </div>
      </form>
    </Modal>
  )
}
