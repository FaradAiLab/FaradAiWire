import React, { useState, useEffect, useRef } from 'react'
import { X, Key, Sliders, Settings, ChevronRight, ShieldCheck, Gauge } from 'lucide-react'
import { GatewayStatus } from '../types'
import { ApiKeysTab } from './ApiKeysTab'
import { SecurityFiltersTab } from './SecurityFiltersTab'
import { OperationalSettingsTab } from './OperationalSettingsTab'

export interface SettingsModalProps {
  isOpen: boolean
  onClose: () => void
  status: GatewayStatus | null
  onStatusChange: () => void
  initialTab?: 'keys' | 'filters' | 'operational'
}

const KNOWN_FALLBACK_FILTERS = new Set([
  'prefill_block',
  'dlp',
  'rate_limiting',
  'loop_protection',
  'guard',
  'hitl',
  'schema_validation',
])

export const SettingsModal: React.FC<SettingsModalProps> = ({
  isOpen,
  onClose,
  status,
  onStatusChange,
  initialTab = 'keys',
}) => {
  const [activeTab, setActiveTab] = useState<'keys' | 'filters' | 'operational'>(initialTab)
  const closeButtonRef = useRef<HTMLButtonElement>(null)
  const tabKeysRef = useRef<HTMLButtonElement>(null)
  const tabFiltersRef = useRef<HTMLButtonElement>(null)
  const tabOperationalRef = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    if (isOpen) {
      setActiveTab(initialTab)
      // Focus close button on initial open for accessibility
      setTimeout(() => closeButtonRef.current?.focus(), 50)
    }
  }, [isOpen, initialTab])

  // Escape key listener for accessible dismissal
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        onClose()
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [isOpen, onClose])

  const handleKeyDownTabs = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowRight') {
      e.preventDefault()
      if (activeTab === 'keys') {
        setActiveTab('filters')
        tabFiltersRef.current?.focus()
      } else if (activeTab === 'filters') {
        setActiveTab('operational')
        tabOperationalRef.current?.focus()
      } else {
        setActiveTab('keys')
        tabKeysRef.current?.focus()
      }
    } else if (e.key === 'ArrowUp' || e.key === 'ArrowLeft') {
      e.preventDefault()
      if (activeTab === 'operational') {
        setActiveTab('filters')
        tabFiltersRef.current?.focus()
      } else if (activeTab === 'filters') {
        setActiveTab('keys')
        tabKeysRef.current?.focus()
      } else {
        setActiveTab('operational')
        tabOperationalRef.current?.focus()
      }
    }
  }

  if (!isOpen) return null

  const activeFilterCount = (status?.active_filters || []).filter((f) => KNOWN_FALLBACK_FILTERS.has(f)).length
  const ingressPort = status?.ingress_port || 8090
  const ingressHost = status?.ingress_host || '127.0.0.1'

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-black/60 backdrop-blur-sm animate-in fade-in duration-150"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-labelledby="settings-modal-title"
    >
      <div
        className="w-full max-w-6xl h-[680px] max-h-[90vh] bg-surface border border-subtle rounded-2xl shadow-2xl flex flex-col overflow-hidden text-primary transition-all duration-150"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Modal Top Header */}
        <div className="px-6 py-4 border-b border-subtle flex items-center justify-between bg-surface-elevated/40 shrink-0">
          <div className="flex items-center gap-3">
            <span className="p-2 rounded-xl bg-accent-primary/10 border border-accent-primary/20 text-accent-primary">
              <Settings className="w-5 h-5" />
            </span>
            <div>
              <h2 id="settings-modal-title" className="text-base font-bold text-primary tracking-tight">
                Gateway Settings & Access Control
              </h2>
              <p className="text-xs text-muted">
                Manage workstation API tokens, fallback defenses, and dynamic operational parameters.
              </p>
            </div>
          </div>

          <button
            ref={closeButtonRef}
            type="button"
            onClick={onClose}
            aria-label="Close settings dialog"
            className="p-1.5 rounded-lg text-muted hover:text-primary hover:bg-surface-elevated transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent-primary"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Master-Detail Split Container */}
        <div className="flex flex-col md:flex-row flex-1 min-h-0 overflow-hidden">
          {/* Left Sidebar Navigation Rail */}
          <aside
            className="w-full md:w-60 lg:w-64 shrink-0 border-b md:border-b-0 md:border-r border-subtle bg-surface-elevated/25 p-3 md:p-4 flex flex-col justify-between overflow-y-auto"
            aria-label="Settings Categories"
          >
            <div className="space-y-1">
              <div className="px-2 pb-2 text-[10px] font-mono font-bold uppercase tracking-wider text-muted">
                Configuration
              </div>

              <div
                role="tablist"
                aria-orientation="vertical"
                className="space-y-1.5"
                onKeyDown={handleKeyDownTabs}
              >
                <button
                  ref={tabKeysRef}
                  role="tab"
                  id="tab-settings-keys"
                  aria-selected={activeTab === 'keys'}
                  aria-controls="panel-settings-keys"
                  tabIndex={activeTab === 'keys' ? 0 : -1}
                  onClick={() => setActiveTab('keys')}
                  className={`w-full flex items-center justify-between p-3 rounded-xl text-left transition-all group focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent-primary ${
                    activeTab === 'keys'
                      ? 'bg-surface shadow-xs border border-subtle text-accent-primary ring-1 ring-accent-primary/20'
                      : 'hover:bg-surface/60 text-secondary hover:text-primary border border-transparent'
                  }`}
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <div
                      className={`p-2 rounded-lg transition-colors ${
                        activeTab === 'keys'
                          ? 'bg-accent-primary/10 text-accent-primary'
                          : 'bg-surface-muted/60 text-muted group-hover:text-primary'
                      }`}
                    >
                      <Key className="w-4 h-4" />
                    </div>
                    <div className="truncate">
                      <div className="text-xs font-semibold leading-tight text-primary">
                        API & Access Keys
                      </div>
                      <div className="text-[11px] text-muted truncate mt-0.5">
                        Tokens & client scopes
                      </div>
                    </div>
                  </div>
                  <ChevronRight
                    className={`w-4 h-4 transition-transform shrink-0 ${
                      activeTab === 'keys'
                        ? 'text-accent-primary translate-x-0.5'
                        : 'text-muted/40 opacity-0 group-hover:opacity-100'
                    }`}
                  />
                </button>

                <button
                  ref={tabFiltersRef}
                  role="tab"
                  id="tab-settings-filters"
                  aria-selected={activeTab === 'filters'}
                  aria-controls="panel-settings-filters"
                  tabIndex={activeTab === 'filters' ? 0 : -1}
                  onClick={() => setActiveTab('filters')}
                  className={`w-full flex items-center justify-between p-3 rounded-xl text-left transition-all group focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent-primary ${
                    activeTab === 'filters'
                      ? 'bg-surface shadow-xs border border-subtle text-accent-primary ring-1 ring-accent-primary/20'
                      : 'hover:bg-surface/60 text-secondary hover:text-primary border border-transparent'
                  }`}
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <div
                      className={`p-2 rounded-lg transition-colors ${
                        activeTab === 'filters'
                          ? 'bg-accent-primary/10 text-accent-primary'
                          : 'bg-surface-muted/60 text-muted group-hover:text-primary'
                      }`}
                    >
                      <Sliders className="w-4 h-4" />
                    </div>
                    <div className="min-w-0">
                      <div className="text-xs font-semibold leading-tight text-primary">
                        Fallback Defenses
                      </div>
                      <div className="text-[11px] text-muted truncate mt-0.5 flex items-center gap-1.5">
                        <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${activeFilterCount > 0 ? 'bg-emerald-500' : 'bg-gray-400'}`} />
                        <span>{activeFilterCount} of 7 Active</span>
                      </div>
                    </div>
                  </div>
                  <ChevronRight
                    className={`w-4 h-4 transition-transform shrink-0 ${
                      activeTab === 'filters'
                        ? 'text-accent-primary translate-x-0.5'
                        : 'text-muted/40 opacity-0 group-hover:opacity-100'
                    }`}
                  />
                </button>

                <button
                  ref={tabOperationalRef}
                  role="tab"
                  id="tab-settings-operational"
                  aria-selected={activeTab === 'operational'}
                  aria-controls="panel-settings-operational"
                  tabIndex={activeTab === 'operational' ? 0 : -1}
                  onClick={() => setActiveTab('operational')}
                  className={`w-full flex items-center justify-between p-3 rounded-xl text-left transition-all group focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent-primary ${
                    activeTab === 'operational'
                      ? 'bg-surface shadow-xs border border-subtle text-accent-primary ring-1 ring-accent-primary/20'
                      : 'hover:bg-surface/60 text-secondary hover:text-primary border border-transparent'
                  }`}
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <div
                      className={`p-2 rounded-lg transition-colors ${
                        activeTab === 'operational'
                          ? 'bg-accent-primary/10 text-accent-primary'
                          : 'bg-surface-muted/60 text-muted group-hover:text-primary'
                      }`}
                    >
                      <Gauge className="w-4 h-4" />
                    </div>
                    <div className="min-w-0">
                      <div className="text-xs font-semibold leading-tight text-primary">
                        Operational Settings
                      </div>
                      <div className="text-[11px] text-muted truncate mt-0.5">
                        Limits, timeouts & guard
                      </div>
                    </div>
                  </div>
                  <ChevronRight
                    className={`w-4 h-4 transition-transform shrink-0 ${
                      activeTab === 'operational'
                        ? 'text-accent-primary translate-x-0.5'
                        : 'text-muted/40 opacity-0 group-hover:opacity-100'
                    }`}
                  />
                </button>
              </div>
            </div>

            {/* Sidebar Footer: Gateway Ingress & Health Status */}
            <div className="pt-4 mt-4 border-t border-subtle hidden md:block">
              <div className="p-3 rounded-xl bg-surface/80 border border-subtle text-xs space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono text-muted uppercase">Gateway Ingress</span>
                  <span className="flex items-center gap-1.5 text-[11px] font-mono font-semibold text-emerald-600 dark:text-emerald-400">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                    Active
                  </span>
                </div>
                <div className="font-mono text-[11px] text-secondary truncate">
                  {ingressHost}:{ingressPort}
                </div>
                <div className="text-[10px] text-muted flex items-center gap-1.5 pt-1 border-t border-subtle">
                  <ShieldCheck className="w-3.5 h-3.5 text-accent-primary shrink-0" />
                  <span>Zero-Egress Guaranteed</span>
                </div>
              </div>
            </div>
          </aside>

          {/* Right Main Content Panel (Scrolls independently, modal shell never resizes) */}
          <main className="flex-1 min-w-0 h-full overflow-y-auto p-4 sm:p-6 bg-surface">
            <div
              id="panel-settings-keys"
              role="tabpanel"
              aria-labelledby="tab-settings-keys"
              hidden={activeTab !== 'keys'}
              className="focus-visible:outline-none"
              tabIndex={0}
            >
              {activeTab === 'keys' && <ApiKeysTab />}
            </div>

            <div
              id="panel-settings-filters"
              role="tabpanel"
              aria-labelledby="tab-settings-filters"
              hidden={activeTab !== 'filters'}
              className="focus-visible:outline-none"
              tabIndex={0}
            >
              {activeTab === 'filters' && (
                <div className="space-y-5">
                  <div className="p-3.5 rounded-xl bg-amber-500/10 border border-amber-500/20 text-xs text-amber-800 dark:text-amber-300 flex items-start gap-2.5">
                    <span className="font-semibold shrink-0 mt-0.5">Note on Global Defenses:</span>
                    <span>
                      These settings represent cluster-wide emergency killswitches. Individual Security Profiles can customize their own granular inspection pipeline in Profile Studio.
                    </span>
                  </div>
                  <SecurityFiltersTab status={status} onStatusChange={onStatusChange} />
                </div>
              )}
            </div>

            <div
              id="panel-settings-operational"
              role="tabpanel"
              aria-labelledby="tab-settings-operational"
              hidden={activeTab !== 'operational'}
              className="focus-visible:outline-none"
              tabIndex={0}
            >
              {activeTab === 'operational' && <OperationalSettingsTab />}
            </div>
          </main>
        </div>
      </div>
    </div>
  )
}

