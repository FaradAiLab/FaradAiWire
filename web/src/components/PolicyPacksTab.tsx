import React, { useState, useEffect, useCallback } from 'react'
import { PolicyPack, DlpRule } from '../types'
import { api } from '../api'
import { PackCard } from './policy/PackCard'
import { RulesCatalogList } from './policy/RulesCatalogList'
import { RegexTesterCard } from './policy/RegexTesterCard'
import { RuleEditorModal } from './policy/RuleEditorModal'
import { PackEditorModal } from './policy/PackEditorModal'
import { PackRulesViewModal } from './policy/PackRulesViewModal'
import { Button } from './ui/Button'
import {
  ShieldCheck,
  Layers,
  Globe2,
  Database,
  Plus,
  RefreshCw,
  AlertCircle,
} from 'lucide-react'

export const PolicyPacksTab: React.FC = () => {
  const [activeSubTab, setActiveSubTab] = useState<'packs' | 'rules'>('packs')
  const [packs, setPacks] = useState<PolicyPack[]>([])
  const [rules, setRules] = useState<DlpRule[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Modals state
  const [selectedPackForRules, setSelectedPackForRules] = useState<PolicyPack | null>(null)
  const [isPackEditorOpen, setIsPackEditorOpen] = useState(false)
  const [packToEdit, setPackToEdit] = useState<PolicyPack | null>(null)
  const [isRuleEditorOpen, setIsRuleEditorOpen] = useState(false)
  const [ruleToEdit, setRuleToEdit] = useState<DlpRule | null>(null)
  const [testRule, setTestRule] = useState<DlpRule | null>(null)
  const sandboxRef = React.useRef<HTMLDivElement>(null)

  const fetchData = useCallback(async (signal?: AbortSignal) => {
    try {
      setIsLoading(true)
      setError(null)
      const [packsRes, rulesRes] = await Promise.all([
        api.getPolicyPacks(signal),
        api.getDlpRules(undefined, signal),
      ])
      setPacks(packsRes.packs || [])
      setRules(rulesRes.rules || [])
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setIsLoading(false)
    }
  }, [])

  useEffect(() => {
    const controller = new AbortController()
    fetchData(controller.signal)
    return () => controller.abort()
  }, [fetchData])

  // Handlers for Rule CRUD
  const handleSaveRule = async (ruleData: Partial<DlpRule>) => {
    if (ruleToEdit) {
      await api.updateDlpRule(ruleToEdit.id, ruleData)
    } else {
      await api.createDlpRule(ruleData)
    }
    await fetchData()
  }

  const handleDeleteRule = async (rule: DlpRule) => {
    if (!window.confirm(`Are you sure you want to delete custom rule "${rule.name}" (${rule.id})?`)) {
      return
    }
    try {
      await api.deleteDlpRule(rule.id)
      await fetchData()
    } catch (err: unknown) {
      alert(`Failed to delete rule: ${err instanceof Error ? err.message : String(err)}`)
    }
  }

  // Handlers for Pack CRUD
  const handleSavePack = async (packData: Partial<PolicyPack>) => {
    if (packToEdit) {
      await api.updatePolicyPack(packToEdit.id, packData)
    } else {
      await api.createPolicyPack(packData)
    }
    await fetchData()
  }

  const handleDeletePack = async (pack: PolicyPack) => {
    if (!window.confirm(`Are you sure you want to delete custom pack "${pack.name}" (${pack.id})?`)) {
      return
    }
    try {
      await api.deletePolicyPack(pack.id)
      await fetchData()
    } catch (err: unknown) {
      alert(`Failed to delete pack: ${err instanceof Error ? err.message : String(err)}`)
    }
  }

  const handleTestRuleInSandbox = (rule: DlpRule) => {
    setTestRule(rule)
    setActiveSubTab('rules')
    setTimeout(() => {
      sandboxRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }, 50)
  }

  // Derived stats
  const regionalCount = packs.filter((p) => p.category?.toLowerCase() === 'compliance').length
  const domainCount = packs.filter((p) => p.category?.toLowerCase() !== 'compliance').length

  return (
    <div className="space-y-6">
      {/* Header and KPI Stats */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-tight text-primary flex items-center gap-2.5">
            <ShieldCheck className="w-6 h-6 text-cyan-600 dark:text-cyan-400" />
            <span>Policy Packs & DLP Governance</span>
          </h1>
          <p className="text-xs text-muted font-mono mt-1">
            Pre-configured regional compliance sets, domain sanitizers, and zero-egress data leakage prevention.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="secondary"
            size="sm"
            icon={<RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />}
            onClick={() => fetchData()}
            disabled={isLoading}
          >
            Refresh
          </Button>

          {activeSubTab === 'packs' ? (
            <Button
              variant="primary"
              size="sm"
              icon={<Plus className="w-4 h-4" />}
              onClick={() => {
                setPackToEdit(null)
                setIsPackEditorOpen(true)
              }}
            >
              New Policy Pack
            </Button>
          ) : (
            <Button
              variant="primary"
              size="sm"
              icon={<Plus className="w-4 h-4" />}
              onClick={() => {
                setRuleToEdit(null)
                setIsRuleEditorOpen(true)
              }}
            >
              New DLP Rule
            </Button>
          )}
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 font-mono">
        <div className="bg-surface border border-subtle rounded-2xl p-4 shadow-xs">
          <div className="flex items-center gap-2 text-xs text-muted">
            <Layers className="w-4 h-4 text-accent-primary" />
            <span>Active Policy Packs</span>
          </div>
          <div className="text-2xl font-bold text-primary mt-2">{packs.length}</div>
          <p className="text-[10px] text-muted mt-0.5">Enforceable packages</p>
        </div>

        <div className="bg-surface border border-subtle rounded-2xl p-4 shadow-xs">
          <div className="flex items-center gap-2 text-xs text-muted">
            <ShieldCheck className="w-4 h-4 text-emerald-500" />
            <span>Catalog DLP Rules</span>
          </div>
          <div className="text-2xl font-bold text-primary mt-2">{rules.length}</div>
          <p className="text-[10px] text-muted mt-0.5">Pattern regex rules</p>
        </div>

        <div className="bg-surface border border-subtle rounded-2xl p-4 shadow-xs">
          <div className="flex items-center gap-2 text-xs text-muted">
            <Globe2 className="w-4 h-4 text-indigo-500" />
            <span>Regional Sets</span>
          </div>
          <div className="text-2xl font-bold text-primary mt-2">{regionalCount}</div>
          <p className="text-[10px] text-muted mt-0.5">KVKK, QCB, GDPR</p>
        </div>

        <div className="bg-surface border border-subtle rounded-2xl p-4 shadow-xs">
          <div className="flex items-center gap-2 text-xs text-muted">
            <Database className="w-4 h-4 text-amber-500" />
            <span>Domain Sanitizers</span>
          </div>
          <div className="text-2xl font-bold text-primary mt-2">{domainCount}</div>
          <p className="text-[10px] text-muted mt-0.5">Cloud Infra & Database</p>
        </div>
      </div>

      {/* Sub-Tabs Navigation */}
      <div className="border-b border-subtle flex items-center gap-2 font-mono text-xs">
        <button
          onClick={() => setActiveSubTab('packs')}
          className={`pb-2.5 px-3 font-semibold transition-colors border-b-2 ${
            activeSubTab === 'packs'
              ? 'border-accent-primary text-accent-primary'
              : 'border-transparent text-muted hover:text-primary'
          }`}
        >
          Policy Packs ({packs.length})
        </button>
        <button
          onClick={() => setActiveSubTab('rules')}
          className={`pb-2.5 px-3 font-semibold transition-colors border-b-2 ${
            activeSubTab === 'rules'
              ? 'border-accent-primary text-accent-primary'
              : 'border-transparent text-muted hover:text-primary'
          }`}
        >
          Rules Catalog & Live Sandbox ({rules.length})
        </button>
      </div>

      {/* Error State */}
      {error && (
        <div className="p-4 rounded-xl border border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-300 text-xs font-mono flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-rose-500 shrink-0" />
            <span>{error}</span>
          </div>
          <Button variant="ghost" size="sm" onClick={() => fetchData()}>
            Retry
          </Button>
        </div>
      )}

      {/* Loading Skeleton */}
      {isLoading && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 animate-pulse">
          {[1, 2, 3].map((i) => (
            <div key={i} className="glass-card h-48 rounded-2xl border border-white/5 bg-gray-900/40" />
          ))}
        </div>
      )}

      {/* Sub-Tab 1: Policy Packs Grid */}
      {!isLoading && activeSubTab === 'packs' && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {packs.map((pack) => (
            <PackCard
              key={pack.id}
              pack={pack}
              onViewRules={(p) => setSelectedPackForRules(p)}
              onEdit={(p) => {
                setPackToEdit(p)
                setIsPackEditorOpen(true)
              }}
              onDelete={handleDeletePack}
            />
          ))}
        </div>
      )}

      {/* Sub-Tab 2: Rules Catalog & Regex Tester */}
      {!isLoading && activeSubTab === 'rules' && (
        <div className="space-y-6">
          <div ref={sandboxRef}>
            <RegexTesterCard
              rules={rules}
              activeRule={testRule}
              onClearActiveRule={() => setTestRule(null)}
            />
          </div>

          <RulesCatalogList
            rules={rules}
            activeRuleId={testRule?.id}
            onCreateRule={() => {
              setRuleToEdit(null)
              setIsRuleEditorOpen(true)
            }}
            onEditRule={(r) => {
              setRuleToEdit(r)
              setIsRuleEditorOpen(true)
            }}
            onDeleteRule={handleDeleteRule}
            onTestRule={handleTestRuleInSandbox}
          />
        </div>
      )}

      {/* Modals */}
      <PackRulesViewModal
        isOpen={!!selectedPackForRules}
        onClose={() => setSelectedPackForRules(null)}
        pack={selectedPackForRules}
        catalogRules={rules}
        onTestRule={handleTestRuleInSandbox}
      />

      <PackEditorModal
        isOpen={isPackEditorOpen}
        onClose={() => setIsPackEditorOpen(false)}
        packToEdit={packToEdit}
        availableRules={rules}
        onSave={handleSavePack}
      />

      <RuleEditorModal
        isOpen={isRuleEditorOpen}
        onClose={() => setIsRuleEditorOpen(false)}
        ruleToEdit={ruleToEdit}
        onSave={handleSaveRule}
      />
    </div>
  )
}
