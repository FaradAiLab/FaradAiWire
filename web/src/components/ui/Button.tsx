import React from 'react'

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger' | 'ghost' | 'outline'
  size?: 'sm' | 'md' | 'lg'
  isLoading?: boolean
  icon?: React.ReactNode
}

export const Button: React.FC<ButtonProps> = ({
  children,
  variant = 'primary',
  size = 'md',
  isLoading = false,
  icon,
  className = '',
  disabled,
  ...props
}) => {
  const baseStyles =
    'inline-flex items-center justify-center gap-2 font-mono font-semibold rounded-xl transition-all select-none disabled:opacity-50 disabled:cursor-not-allowed focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 focus-visible:ring-offset-2 focus-visible:ring-offset-white dark:focus-visible:ring-offset-gray-900'

  const sizeStyles = {
    sm: 'text-[11px] px-2.5 py-1',
    md: 'text-xs px-4 py-2',
    lg: 'text-sm px-5 py-2.5',
  }[size]

  const variantStyles = {
    primary:
      'bg-cyan-600 hover:bg-cyan-700 text-white shadow-sm border border-cyan-700/20 dark:bg-cyan-600 dark:hover:bg-cyan-500 dark:text-white dark:shadow-[0_0_12px_rgba(6,182,212,0.3)] dark:border-cyan-400/30',
    secondary:
      'bg-gray-100 hover:bg-gray-200 text-gray-800 border border-gray-300/80 dark:bg-white/5 dark:hover:bg-white/10 dark:text-gray-200 dark:border-white/10 dark:hover:border-white/20',
    danger:
      'bg-rose-600 hover:bg-rose-700 text-white shadow-sm border border-rose-700/20 dark:bg-rose-600 dark:hover:bg-rose-500 dark:text-white dark:shadow-[0_0_12px_rgba(244,63,94,0.3)] dark:border-rose-400/30',
    ghost:
      'bg-transparent hover:bg-gray-100 text-gray-600 hover:text-gray-900 border border-transparent dark:hover:bg-white/5 dark:text-gray-400 dark:hover:text-gray-200',
    outline:
      'bg-transparent hover:bg-cyan-50 text-cyan-700 border border-cyan-300 dark:hover:bg-cyan-500/10 dark:text-cyan-400 dark:border-cyan-500/30',
  }[variant]

  return (
    <button
      className={`${baseStyles} ${sizeStyles} ${variantStyles} ${className}`}
      disabled={disabled || isLoading}
      {...props}
    >
      {isLoading ? (
        <span className="w-3.5 h-3.5 border-2 border-current border-t-transparent rounded-full animate-spin shrink-0" />
      ) : (
        icon && <span className="shrink-0">{icon}</span>
      )}
      <span>{children}</span>
    </button>
  )
}
