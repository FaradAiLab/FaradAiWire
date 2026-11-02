import React from 'react'
import { Sun, Moon, Laptop } from 'lucide-react'
import { ThemeMode } from '../../types'

export interface ThemeToggleProps {
  mode: ThemeMode
  onChange: (mode: ThemeMode) => void
  className?: string
}

export const ThemeToggle: React.FC<ThemeToggleProps> = ({
  mode,
  onChange,
  className = '',
}) => {
  const options: { id: ThemeMode; label: string; icon: React.ReactNode }[] = [
    {
      id: 'light',
      label: 'Light theme',
      icon: <Sun className="w-3.5 h-3.5" />,
    },
    {
      id: 'system',
      label: 'System theme',
      icon: <Laptop className="w-3.5 h-3.5" />,
    },
    {
      id: 'dark',
      label: 'Dark theme',
      icon: <Moon className="w-3.5 h-3.5" />,
    },
  ]

  return (
    <div
      role="radiogroup"
      aria-label="Theme mode"
      className={`inline-flex items-center p-0.5 rounded-xl bg-gray-200/80 dark:bg-gray-800/80 border border-gray-300/80 dark:border-white/10 shadow-inner ${className}`}
    >
      {options.map((opt) => {
        const isSelected = mode === opt.id
        return (
          <button
            key={opt.id}
            type="button"
            role="radio"
            aria-checked={isSelected}
            aria-label={opt.label}
            title={opt.label}
            onClick={() => onChange(opt.id)}
            className={`p-1.5 rounded-lg transition-all text-xs flex items-center justify-center focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 ${
              isSelected
                ? 'bg-white dark:bg-gray-700 text-cyan-600 dark:text-cyan-400 shadow-sm font-semibold'
                : 'text-gray-500 hover:text-gray-900 dark:text-gray-400 dark:hover:text-gray-200'
            }`}
          >
            {opt.icon}
          </button>
        )
      })}
    </div>
  )
}
