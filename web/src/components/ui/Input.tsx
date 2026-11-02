import React from 'react'

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string
  error?: string
  helperText?: string
  isMono?: boolean
}

export const Input: React.FC<InputProps> = ({
  label,
  error,
  helperText,
  isMono = false,
  className = '',
  id,
  ...props
}) => {
  const inputId = id || (label ? label.toLowerCase().replace(/\s+/g, '-') : undefined)

  return (
    <div className="space-y-1">
      {label && (
        <label htmlFor={inputId} className="block text-xs font-semibold text-gray-700 dark:text-gray-300">
          {label}
        </label>
      )}
      <input
        id={inputId}
        className={`w-full px-3 py-2 rounded-xl bg-white dark:bg-gray-950/80 border text-xs text-gray-900 dark:text-gray-100 placeholder:text-gray-400 dark:placeholder:text-gray-600 transition-all focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 focus-visible:ring-offset-1 focus-visible:ring-offset-white dark:focus-visible:ring-offset-gray-900 disabled:opacity-50 disabled:cursor-not-allowed ${
          isMono ? 'font-mono' : ''
        } ${
          error
            ? 'border-rose-500/50 focus-visible:ring-rose-500'
            : 'border-gray-300 dark:border-white/10 hover:border-gray-400 dark:hover:border-white/20 focus:border-cyan-500/60'
        } ${className}`}
        aria-invalid={!!error}
        aria-describedby={error ? `${inputId}-error` : helperText ? `${inputId}-helper` : undefined}
        {...props}
      />
      {error ? (
        <p id={`${inputId}-error`} className="text-[11px] text-rose-500 dark:text-rose-400 font-mono" role="alert">
          {error}
        </p>
      ) : helperText ? (
        <p id={`${inputId}-helper`} className="text-[10px] text-gray-500 dark:text-gray-400">
          {helperText}
        </p>
      ) : null}
    </div>
  )
}
