import React from 'react'
import { Lock } from 'lucide-react'
import { splitRedactionTokens } from './diff'

interface RedactedTextProps {
  text: string
  className?: string
}

export const RedactedText: React.FC<RedactedTextProps> = ({ text, className = '' }) => {
  const parts = splitRedactionTokens(text)

  return (
    <span className={`whitespace-pre-wrap leading-relaxed break-words ${className}`}>
      {parts.map((part, idx) =>
        part.isRedacted ? (
          <span
            key={idx}
            className="inline-flex items-center gap-1 px-1.5 py-0.5 mx-0.5 rounded text-[11px] font-mono font-bold bg-amber-100 text-amber-900 border border-amber-400 dark:bg-amber-500/20 dark:text-amber-300 dark:border-amber-500/40 shadow-xs"
            title="DLP Semantic Redaction"
          >
            <Lock className="w-2.5 h-2.5 text-amber-700 dark:text-amber-400 shrink-0" />
            <span>{part.text}</span>
          </span>
        ) : (
          <span key={idx}>{part.text}</span>
        )
      )}
    </span>
  )
}
