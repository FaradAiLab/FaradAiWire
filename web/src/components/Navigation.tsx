import React from 'react'
import { LayoutDashboard, Network, Bot, ScrollText, ShieldCheck } from 'lucide-react'

export type TabId = 'overview' | 'protocols' | 'agents' | 'guardrails' | 'audit'

interface NavigationProps {
  activeTab: TabId
  onTabChange: (tab: TabId) => void
  toolCount?: number
  agentCount?: number
  protocolCount?: number
  activeFilterCount?: number
  policyPackCount?: number
}

export const Navigation: React.FC<NavigationProps> = ({
  activeTab,
  onTabChange,
  agentCount = 0,
  protocolCount = 0,
  policyPackCount = 0,
}) => {
  const tabs = [
    { id: 'overview' as TabId, label: 'Overview', icon: LayoutDashboard },
    { id: 'protocols' as TabId, label: 'Tool Sources', icon: Network, badge: protocolCount },
    { id: 'agents' as TabId, label: 'Profiles', icon: Bot, badge: agentCount },
    { id: 'guardrails' as TabId, label: 'Security Guardrails', icon: ShieldCheck, badge: policyPackCount },
    { id: 'audit' as TabId, label: 'Audit Logs', icon: ScrollText },
  ]

  return (
    <nav
      role="navigation"
      aria-label="Primary Navigation"
      className="border-b border-gray-200 dark:border-white/10 bg-white/70 dark:bg-dark-bg/60 backdrop-blur-sm px-6 py-2 flex items-center gap-1 overflow-x-auto transition-colors"
    >
      {tabs.map((tab) => {
        const Icon = tab.icon
        const isActive = activeTab === tab.id

        return (
          <button
            key={tab.id}
            type="button"
            onClick={() => onTabChange(tab.id)}
            aria-current={isActive ? 'page' : undefined}
            className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs sm:text-sm font-medium transition-all whitespace-nowrap focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 ${
              isActive
                ? 'bg-cyan-50 text-cyan-800 border border-cyan-300 shadow-sm dark:bg-gradient-to-r dark:from-cyan-500/15 dark:to-indigo-500/15 dark:border-cyan-500/40 dark:text-cyan-300 dark:shadow-[0_0_15px_rgba(6,182,212,0.15)] font-semibold'
                : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100 dark:text-gray-400 dark:hover:text-gray-200 dark:hover:bg-white/5 border border-transparent'
            }`}
          >
            <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-600 dark:text-cyan-400' : 'text-gray-400 dark:text-gray-500'}`} />
            <span>{tab.label}</span>
            {tab.badge !== undefined && tab.badge > 0 && (
              <span
                className={`text-[10px] font-mono px-1.5 py-0.2 rounded-full font-bold ${
                  isActive
                    ? 'bg-cyan-100 text-cyan-800 border border-cyan-300 dark:bg-cyan-500/30 dark:text-cyan-200 dark:border-cyan-400/40'
                    : 'bg-gray-200/80 text-gray-700 border border-gray-300/60 dark:bg-gray-800 dark:text-gray-300 dark:border-white/5'
                }`}
              >
                {tab.badge}
              </span>
            )}
          </button>
        )
      })}
    </nav>
  )
}
