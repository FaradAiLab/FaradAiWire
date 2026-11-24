import {
  Clock,
  Eye,
  Lock,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'

export interface VerdictStyle {
  badge: string
  stripe: string
  dot: string
  icon: LucideIcon
  label: string
}

export function getVerdictStyle(decision: string): VerdictStyle {
  switch (decision?.toUpperCase()) {
    case 'CRITICAL':
      return {
        badge:
          'bg-red-100 text-red-900 border-red-300 dark:bg-red-950/80 dark:text-red-200 dark:border-red-700/70',
        stripe: 'bg-red-600',
        dot: 'bg-red-600',
        icon: ShieldAlert,
        label: 'CRITICAL',
      }
    case 'ERROR':
      return {
        badge:
          'bg-orange-50 text-orange-800 border-orange-300 dark:bg-orange-950/70 dark:text-orange-200 dark:border-orange-700/60',
        stripe: 'bg-orange-500',
        dot: 'bg-orange-500',
        icon: ShieldAlert,
        label: 'ERROR',
      }
    case 'BLOCKED':
      return {
        badge:
          'bg-rose-50 text-rose-800 border-rose-300 dark:bg-rose-950/70 dark:text-rose-200 dark:border-rose-700/60',
        stripe: 'bg-rose-600',
        dot: 'bg-rose-600',
        icon: ShieldAlert,
        label: 'BLOCKED',
      }
    case 'MASKED':
      return {
        badge:
          'bg-amber-50 text-amber-900 border-amber-300 dark:bg-amber-950/70 dark:text-amber-200 dark:border-amber-700/60',
        stripe: 'bg-amber-500',
        dot: 'bg-amber-500',
        icon: Lock,
        label: 'MASKED',
      }
    case 'AUDIT':
      return {
        badge:
          'bg-purple-50 text-purple-800 border-purple-300 dark:bg-purple-950/70 dark:text-purple-200 dark:border-purple-700/60',
        stripe: 'bg-purple-600',
        dot: 'bg-purple-600',
        icon: Eye,
        label: 'AUDIT',
      }
    case 'PENDING':
      return {
        badge:
          'bg-sky-50 text-sky-800 border-sky-300 dark:bg-sky-950/70 dark:text-sky-200 dark:border-sky-700/60',
        stripe: 'bg-sky-500',
        dot: 'bg-sky-500',
        icon: Clock,
        label: 'PENDING',
      }
    case 'ALLOWED':
    default:
      return {
        badge:
          'bg-emerald-50 text-emerald-800 border-emerald-300 dark:bg-emerald-950/70 dark:text-emerald-200 dark:border-emerald-700/60',
        stripe: 'bg-emerald-500',
        dot: 'bg-emerald-500',
        icon: ShieldCheck,
        label: 'ALLOWED',
      }
  }
}
