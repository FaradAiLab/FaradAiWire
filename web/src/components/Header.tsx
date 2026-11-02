import React from 'react'
import { Shield, Radio, Cpu, RefreshCw, Settings } from 'lucide-react'
import { GatewayStatus, ThemeMode } from '../types'
import { ThemeToggle } from './ui/ThemeToggle'

interface HeaderProps {
  status: GatewayStatus | null
  onReload: () => void
  isReloading: boolean
  themeMode: ThemeMode
  onThemeChange: (mode: ThemeMode) => void
  onOpenSettings?: () => void
}

export const Header: React.FC<HeaderProps> = ({
  status,
  onReload,
  isReloading,
  themeMode,
  onThemeChange,
  onOpenSettings,
}) => {
  const isOnline = status?.status === 'active' || status?.status === 'healthy' || status?.status?.toLowerCase() === 'ready'
  const isManaged = status?.runtime_mode === 'MANAGED'
  const slmActive = status?.slm_tier === 'neural_active' || status?.slm_status === 'active'

  return (
    <header className="border-b border-gray-200 dark:border-white/10 bg-white/90 dark:bg-dark-bg/80 backdrop-blur-md sticky top-0 z-50 px-6 py-3.5 flex flex-wrap items-center justify-between gap-4 transition-colors">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-xl bg-cyan-50 dark:bg-gradient-to-br dark:from-cyan-500/20 dark:to-indigo-500/20 border border-cyan-500/30 flex items-center justify-center text-cyan-600 dark:text-cyan-400 shadow-sm dark:shadow-[0_0_15px_rgba(6,182,212,0.15)]">
          <Shield className="w-5 h-5 text-cyan-600 dark:text-cyan-400" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="font-extrabold text-lg tracking-tight text-gray-900 dark:text-white">
              FaradAiWire
            </h1>
            <span className="text-xs px-2 py-0.5 rounded font-mono font-medium bg-cyan-100 text-cyan-800 dark:bg-cyan-950 dark:text-cyan-400 border border-cyan-300 dark:border-cyan-800/40">
              v1.0 Core
            </span>
          </div>
          <p className="text-xs text-gray-500 dark:text-gray-400">Standalone AI Gateway & Agent Studio</p>
        </div>
      </div>

      <div className="flex items-center gap-2.5 flex-wrap">
        {/* Gateway Ingress Status */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200 dark:bg-emerald-950/60 dark:border-emerald-500/30 dark:text-emerald-400">
          <Radio className={`w-3.5 h-3.5 ${isOnline ? 'animate-pulse text-emerald-600 dark:text-emerald-400' : 'text-rose-600 dark:text-rose-400'}`} />
          <span>{isOnline ? 'Gateway Active' : 'Gateway Offline'}</span>
        </div>

        {/* Runtime Architecture */}
        <div className="px-3 py-1.5 rounded-full text-xs font-semibold font-mono bg-indigo-50 text-indigo-700 border border-indigo-200 dark:bg-indigo-950/60 dark:border-indigo-500/30 dark:text-indigo-300">
          {isManaged ? 'Enterprise Managed' : 'Standalone Core (Zero-Egress)'}
        </div>

        {/* Semantic Security Guard Badge */}
        <div
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-semibold border ${
            slmActive
              ? 'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950/60 dark:border-emerald-500/30 dark:text-emerald-400'
              : 'bg-amber-50 text-amber-800 border-amber-200 dark:bg-amber-950/40 dark:border-amber-500/30 dark:text-amber-300'
          }`}
          title={status?.slm_endpoint || 'Local Semantic Security Guard'}
        >
          <Cpu className="w-3.5 h-3.5" />
          <span>{slmActive ? 'Semantic Guard Active' : 'Semantic Guard Standby'}</span>
        </div>

        {/* Hot Reload Trigger */}
        <button
          type="button"
          onClick={onReload}
          disabled={isReloading}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-medium bg-gray-100 hover:bg-gray-200 dark:bg-gray-800/80 dark:hover:bg-gray-700/80 border border-gray-300 dark:border-white/10 text-gray-700 dark:text-gray-200 transition-all disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500"
          title="Reload configuration & hot-swap policies"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isReloading ? 'animate-spin text-cyan-600 dark:text-cyan-400' : ''}`} />
          <span>Reload</span>
        </button>

        {/* 3-State Theme Toggle */}
        <ThemeToggle mode={themeMode} onChange={onThemeChange} />

        {/* Settings & Access Keys Trigger */}
        {onOpenSettings && (
          <button
            type="button"
            onClick={onOpenSettings}
            className="flex items-center justify-center p-2 rounded-xl text-gray-600 hover:text-gray-900 dark:text-gray-300 dark:hover:text-white bg-gray-100 hover:bg-gray-200 dark:bg-gray-800/80 dark:hover:bg-gray-700/80 border border-gray-300 dark:border-white/10 transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500"
            title="Settings & Access Keys"
            aria-label="Open Settings and Access Keys"
          >
            <Settings className="w-4 h-4" />
          </button>
        )}
      </div>
    </header>
  )
}

