import React, { useEffect } from 'react'
import { X } from 'lucide-react'

export interface DrawerProps {
  isOpen: boolean
  onClose: () => void
  title: string
  subtitle?: string
  icon?: React.ReactNode
  headerAction?: React.ReactNode
  subHeader?: React.ReactNode
  footer?: React.ReactNode
  maxWidth?: 'md' | 'lg' | 'xl' | '2xl' | '3xl' | '4xl' | '5xl'
  children: React.ReactNode
}

export const Drawer: React.FC<DrawerProps> = ({
  isOpen,
  onClose,
  title,
  subtitle,
  icon,
  headerAction,
  subHeader,
  footer,
  maxWidth = '5xl',
  children,
}) => {
  useEffect(() => {
    if (!isOpen) return

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose()
      }
    }

    // Lock body scroll while drawer is open
    const originalOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'

    window.addEventListener('keydown', handleKeyDown)
    return () => {
      document.body.style.overflow = originalOverflow
      window.removeEventListener('keydown', handleKeyDown)
    }
  }, [isOpen, onClose])

  if (!isOpen) return null

  const maxWidthStyles = {
    md: 'max-w-md',
    lg: 'max-w-lg',
    xl: 'max-w-xl',
    '2xl': 'max-w-2xl',
    '3xl': 'max-w-3xl',
    '4xl': 'max-w-4xl',
    '5xl': 'max-w-5xl',
  }[maxWidth]

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end bg-black/50 dark:bg-black/80 backdrop-blur-xs transition-opacity animate-in fade-in duration-150"
      role="dialog"
      aria-modal="true"
      aria-labelledby="drawer-title"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
    >
      <div
        className={`w-full ${maxWidthStyles} h-full bg-surface border-l border-subtle shadow-2xl relative flex flex-col animate-in slide-in-from-right duration-200`}
      >
        {/* Sticky Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-subtle shrink-0 bg-surface z-10">
          <div className="flex items-center gap-3 min-w-0">
            {icon && <div className="text-accent shrink-0">{icon}</div>}
            <div className="min-w-0">
              <h2 id="drawer-title" className="text-base font-bold text-primary font-sans truncate">
                {title}
              </h2>
              {subtitle && <p className="text-xs text-muted mt-0.5 truncate font-sans">{subtitle}</p>}
            </div>
          </div>

          <div className="flex items-center gap-2.5 shrink-0 ml-4">
            {headerAction}
            <button
              type="button"
              onClick={onClose}
              className="p-1.5 rounded-lg text-muted hover:text-primary hover:bg-subtle transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              aria-label="Close panel"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Sticky Sub-Header (Tabs remain pinned, never scroll away) */}
        {subHeader && (
          <div className="px-6 pt-3 pb-0 border-b border-subtle shrink-0 bg-surface z-10">
            {subHeader}
          </div>
        )}

        {/* Scrollable Body */}
        <div className="flex-1 overflow-y-auto px-6 py-5">{children}</div>

        {/* Sticky Footer */}
        {footer && (
          <div className="px-6 py-3.5 border-t border-subtle shrink-0 bg-surface/95 backdrop-blur-xs z-10">
            {footer}
          </div>
        )}
      </div>
    </div>
  )
}
