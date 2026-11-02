import React, { useState, useEffect } from 'react'
import { ShieldCheck, Sparkles, Binary } from 'lucide-react'
import { PolicyPacksTab } from './PolicyPacksTab'
import { GuardsTab } from './GuardsTab'

export type GuardrailSubTab = 'dlp' | 'guard'

export interface SecurityGuardrailsTabProps {
  initialSubTab?: GuardrailSubTab
  onSubTabChange?: (subTab: GuardrailSubTab) => void
}

export const SecurityGuardrailsTab: React.FC<SecurityGuardrailsTabProps> = ({
  initialSubTab = 'dlp',
  onSubTabChange,
}) => {
  const [activeSubTab, setActiveSubTab] = useState<GuardrailSubTab>(initialSubTab)

  useEffect(() => {
    if (initialSubTab && initialSubTab !== activeSubTab) {
      setActiveSubTab(initialSubTab)
    }
  }, [initialSubTab])

  const handleSelectSubTab = (tab: GuardrailSubTab) => {
    setActiveSubTab(tab)
    if (onSubTabChange) {
      onSubTabChange(tab)
    }
  }

  const handleKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
    if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
      e.preventDefault()
      const nextTab: GuardrailSubTab = activeSubTab === 'dlp' ? 'guard' : 'dlp'
      handleSelectSubTab(nextTab)
    }
  }

  return (
    <div className="space-y-6">
      {/* High-Impact Swiss Header & Segmented Controller */}
      <div className="bg-white/80 dark:bg-dark-surface/80 backdrop-blur-md border border-gray-200 dark:border-white/10 rounded-2xl p-5 shadow-sm transition-all">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2.5">
              <span className="p-2 rounded-xl bg-cyan-50 dark:bg-cyan-500/10 border border-cyan-200 dark:border-cyan-500/20 text-cyan-600 dark:text-cyan-400">
                <ShieldCheck className="w-5 h-5" />
              </span>
              <div>
                <h1 className="text-lg font-bold text-gray-900 dark:text-white tracking-tight flex items-center gap-2">
                  Security Guardrails
                  <span className="text-[11px] font-mono uppercase px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200 dark:bg-emerald-500/10 dark:text-emerald-300 dark:border-emerald-500/20 font-medium">
                    Defense-In-Depth
                  </span>
                </h1>
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
                  Multi-tier inspection pipeline pairing sub-millisecond regex & DLP policy packs with local neural semantic security guards.
                </p>
              </div>
            </div>
          </div>

          {/* Segmented Switcher Control */}
          <div
            role="tablist"
            aria-label="Security Guardrails Modes"
            onKeyDown={handleKeyDown}
            className="flex p-1 bg-gray-100 dark:bg-white/5 rounded-xl border border-gray-200 dark:border-white/10 self-start lg:self-auto shrink-0"
          >
            <button
              role="tab"
              id="tab-guardrails-dlp"
              aria-selected={activeSubTab === 'dlp'}
              aria-controls="panel-guardrails-dlp"
              tabIndex={activeSubTab === 'dlp' ? 0 : -1}
              onClick={() => handleSelectSubTab('dlp')}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-medium transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 ${
                activeSubTab === 'dlp'
                  ? 'bg-white dark:bg-dark-surface text-gray-900 dark:text-white shadow-sm border border-gray-200 dark:border-white/10 font-semibold'
                  : 'text-gray-500 dark:text-gray-400 hover:text-gray-800 dark:hover:text-gray-200 hover:bg-white/40 dark:hover:bg-white/5'
              }`}
            >
              <Binary className={`w-3.5 h-3.5 ${activeSubTab === 'dlp' ? 'text-cyan-600 dark:text-cyan-400' : 'text-gray-400'}`} />
              <span>DLP Policy Packs</span>
              <span className="hidden sm:inline-block text-[10px] font-mono px-1.5 py-0.5 rounded bg-gray-100 dark:bg-white/10 text-gray-600 dark:text-gray-300 ml-1">
                Deterministic
              </span>
            </button>

            <button
              role="tab"
              id="tab-guardrails-guard"
              aria-selected={activeSubTab === 'guard'}
              aria-controls="panel-guardrails-guard"
              tabIndex={activeSubTab === 'guard' ? 0 : -1}
              onClick={() => handleSelectSubTab('guard')}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-medium transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 ${
                activeSubTab === 'guard'
                  ? 'bg-white dark:bg-dark-surface text-gray-900 dark:text-white shadow-sm border border-gray-200 dark:border-white/10 font-semibold'
                  : 'text-gray-500 dark:text-gray-400 hover:text-gray-800 dark:hover:text-gray-200 hover:bg-white/40 dark:hover:bg-white/5'
              }`}
            >
              <Sparkles className={`w-3.5 h-3.5 ${activeSubTab === 'guard' ? 'text-indigo-600 dark:text-indigo-400' : 'text-gray-400'}`} />
              <span>Semantic Security Guard</span>
              <span className="hidden sm:inline-block text-[10px] font-mono px-1.5 py-0.5 rounded bg-indigo-50 text-indigo-700 dark:bg-indigo-500/20 dark:text-indigo-300 ml-1">
                Neural
              </span>
            </button>
          </div>
        </div>
      </div>

      {/* Tab Panels */}
      <div
        id="panel-guardrails-dlp"
        role="tabpanel"
        aria-labelledby="tab-guardrails-dlp"
        hidden={activeSubTab !== 'dlp'}
      >
        {activeSubTab === 'dlp' && <PolicyPacksTab />}
      </div>

      <div
        id="panel-guardrails-guard"
        role="tabpanel"
        aria-labelledby="tab-guardrails-guard"
        hidden={activeSubTab !== 'guard'}
      >
        {activeSubTab === 'guard' && <GuardsTab />}
      </div>
    </div>
  )
}
