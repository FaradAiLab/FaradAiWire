import React, { useState, useMemo } from 'react'
import { DlpRule } from '../../types'
import { Badge } from '../ui/Badge'
import { Button } from '../ui/Button'
import {
  Play,
  Sparkles,
  AlertCircle,
  ShieldAlert,
  Target,
  RotateCcw,
  Copy,
  Check,
  Terminal,
} from 'lucide-react'

export interface RegexTesterCardProps {
  rules: DlpRule[]
  activeRule?: DlpRule | null
  onClearActiveRule?: () => void
}

const PRESET_SAMPLES = [
  {
    label: 'TR KVKK Sample',
    category: 'compliance',
    text: 'Müşteri Mehmet Yılmaz TC Kimlik No: 28472910384 ve telefon: 0532 555 1234 üzerinden teyit alındı.',
  },
  {
    label: 'Cloud Credential',
    category: 'cloud',
    text: 'Deploying with AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE and secret=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  },
  {
    label: 'Financial Card',
    category: 'financial',
    text: 'Payment received for card number 4532-1234-5678-9012 CVV 891 valid until 12/28.',
  },
  {
    label: 'Qatar QCB Sample',
    category: 'regional',
    text: 'National ID verification for resident with QID: 28463401928 at Doha branch.',
  },
]

export const RegexTesterCard: React.FC<RegexTesterCardProps> = ({
  rules,
  activeRule,
  onClearActiveRule,
}) => {
  const [testInput, setTestInput] = useState(PRESET_SAMPLES[1].text)
  const [isCopiedRegex, setIsCopiedRegex] = useState(false)

  // Copy active rule regex
  const handleCopyRegex = (regex: string) => {
    navigator.clipboard.writeText(regex)
    setIsCopiedRegex(true)
    setTimeout(() => setIsCopiedRegex(false), 1500)
  }

  // Test input against all rules or specific active rule
  const evaluation = useMemo(() => {
    if (!testInput) return { matches: [], maskedText: '', blocked: false }

    const targetRules = activeRule ? [activeRule] : rules
    const matches: Array<{ rule: DlpRule; matchText: string; index: number }> = []
    let masked = testInput
    let isBlocked = false

    for (const rule of targetRules) {
      try {
        const re = new RegExp(rule.regex, 'g')
        let m: RegExpExecArray | null
        while ((m = re.exec(testInput)) !== null) {
          matches.push({
            rule,
            matchText: m[0],
            index: m.index,
          })
          if (rule.default_action === 'block') {
            isBlocked = true
          }
        }

        // Simulate mask
        if (rule.default_action === 'mask') {
          masked = masked.replace(re, `[MASKED:${rule.id}]`)
        }
      } catch {
        // ignore invalid regex
      }
    }

    return { matches, maskedText: masked, blocked: isBlocked }
  }, [testInput, rules, activeRule])

  // In-payload highlighted segment preview
  const highlightedPayload = useMemo(() => {
    if (!testInput || evaluation.matches.length === 0) return null

    // Sort unique match segments by start index
    const sorted = [...evaluation.matches].sort((a, b) => a.index - b.index)
    const elements: React.ReactNode[] = []
    let cursor = 0

    sorted.forEach((m, idx) => {
      if (m.index > cursor) {
        elements.push(
          <span key={`txt-${idx}`}>{testInput.substring(cursor, m.index)}</span>
        )
      }
      const matchEnd = m.index + m.matchText.length
      if (matchEnd > cursor) {
        elements.push(
          <mark
            key={`mark-${idx}`}
            className="bg-amber-300 dark:bg-amber-400/30 text-amber-950 dark:text-amber-200 border-b-2 border-amber-600 dark:border-amber-400 font-bold px-1 rounded-sm"
            title={`Matched by rule: ${m.rule.name} (${m.rule.id})`}
          >
            {testInput.substring(Math.max(cursor, m.index), matchEnd)}
          </mark>
        )
        cursor = matchEnd
      }
    })

    if (cursor < testInput.length) {
      elements.push(<span key="tail">{testInput.substring(cursor)}</span>)
    }

    return elements
  }, [testInput, evaluation.matches])

  return (
    <div className="bg-surface border border-subtle rounded-2xl p-5 space-y-4 shadow-xs">
      {/* Sandbox Header */}
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-xl bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border border-cyan-500/20">
            <Sparkles className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold text-primary font-mono tracking-tight">
                Live DLP Diagnostics Sandbox
              </h3>
              {activeRule ? (
                <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyan-600 text-white dark:bg-cyan-500/20 dark:text-cyan-300 border border-cyan-500/30 uppercase">
                  Targeted Mode
                </span>
              ) : (
                <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-gray-100 dark:bg-white/5 text-muted border border-subtle uppercase">
                  Catalog Sweep ({rules.length} Rules)
                </span>
              )}
            </div>
            <p className="text-xs text-muted font-mono mt-0.5">
              Instant regex payload collision testing & enforcement simulation.
            </p>
          </div>
        </div>

        {activeRule && onClearActiveRule && (
          <Button
            variant="secondary"
            size="sm"
            onClick={onClearActiveRule}
            icon={<RotateCcw className="w-3.5 h-3.5" />}
            className="text-xs shrink-0"
          >
            Reset to All Rules
          </Button>
        )}
      </div>

      {/* Prominent Active Rule Target Banner */}
      {activeRule && (
        <div className="p-3.5 rounded-xl bg-cyan-50/80 dark:bg-cyan-950/30 border border-cyan-200 dark:border-cyan-500/30 shadow-xs flex flex-col gap-2.5 animate-fadeIn">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-mono font-bold uppercase bg-cyan-700 text-white dark:bg-cyan-500 dark:text-slate-950">
                <Target className="w-3 h-3" /> ACTIVE TEST TARGET
              </span>
              <span className="font-bold font-mono text-sm text-primary">
                {activeRule.name}
              </span>
              <Badge variant="indigo" size="sm">
                {activeRule.category}
              </Badge>
              <Badge
                variant={
                  activeRule.default_action === 'block'
                    ? 'rose'
                    : activeRule.default_action === 'mask'
                    ? 'amber'
                    : 'cyan'
                }
                size="sm"
              >
                DEFAULT: {activeRule.default_action}
              </Badge>
              {activeRule.severity && (
                <Badge
                  variant={
                    activeRule.severity === 'CRITICAL'
                      ? 'rose'
                      : activeRule.severity === 'HIGH' || activeRule.severity === 'MEDIUM'
                      ? 'amber'
                      : 'neutral'
                  }
                  size="sm"
                >
                  {activeRule.severity}
                </Badge>
              )}
            </div>

            <span className="text-[11px] font-mono text-muted">
              ID: <code className="text-primary font-semibold">{activeRule.id}</code>
            </span>
          </div>

          {/* Full Regex Pattern Display inside the Banner */}
          <div className="flex items-center gap-2 bg-white/90 dark:bg-black/50 p-2 rounded-lg border border-cyan-200 dark:border-cyan-500/30">
            <span className="text-[10px] font-mono uppercase font-bold text-muted shrink-0">
              Active Pattern:
            </span>
            <code className="text-xs font-mono text-sky-900 dark:text-cyan-300 break-all select-all flex-1 font-semibold">
              {activeRule.regex}
            </code>
            <button
              type="button"
              onClick={() => handleCopyRegex(activeRule.regex)}
              className="text-muted hover:text-primary p-1 transition-colors shrink-0"
              title="Copy active regex"
            >
              {isCopiedRegex ? (
                <Check className="w-3.5 h-3.5 text-emerald-500" />
              ) : (
                <Copy className="w-3.5 h-3.5" />
              )}
            </button>
          </div>
        </div>
      )}

      {/* Preset samples */}
      <div className="flex items-center gap-2 overflow-x-auto pb-1">
        <span className="text-[10px] uppercase font-mono text-muted font-bold shrink-0">
          Presets:
        </span>
        {PRESET_SAMPLES.map((preset) => {
          const isSuggested =
            activeRule &&
            (activeRule.category?.toLowerCase() === preset.category ||
              activeRule.name.toLowerCase().includes(preset.label.toLowerCase().split(' ')[0]))
          return (
            <button
              key={preset.label}
              type="button"
              onClick={() => setTestInput(preset.text)}
              className={`px-2.5 py-1 rounded-lg text-xs font-mono transition-colors border whitespace-nowrap ${
                isSuggested
                  ? 'bg-cyan-100 dark:bg-cyan-950/60 text-cyan-900 dark:text-cyan-200 border-cyan-400 font-bold shadow-xs'
                  : 'bg-surface hover:bg-surface-elevated text-muted hover:text-primary border-subtle'
              }`}
            >
              {preset.label}
              {isSuggested && ' (Suggested)'}
            </button>
          )
        })}
      </div>

      {/* Input payload */}
      <div>
        <div className="flex items-center justify-between mb-1">
          <label className="block text-xs font-semibold text-primary font-mono">
            Sample Payload Content
          </label>
          <span className="text-[10px] font-mono text-muted">
            {testInput.length} characters
          </span>
        </div>
        <textarea
          rows={3}
          value={testInput}
          onChange={(e) => setTestInput(e.target.value)}
          placeholder="Paste or type test prompt, LLM output, or tool payload here..."
          className="w-full px-3 py-2 rounded-xl bg-surface border border-subtle text-xs font-mono text-primary placeholder:text-muted focus:outline-none focus:ring-1 focus:ring-accent"
        />
      </div>

      {/* Real-time In-Payload Match Visualizer */}
      {highlightedPayload && (
        <div className="p-3 rounded-xl bg-surface-elevated border border-subtle space-y-1.5 animate-fadeIn">
          <div className="flex items-center justify-between text-[11px] font-mono text-muted">
            <span className="font-semibold text-primary flex items-center gap-1.5">
              <Sparkles className="w-3.5 h-3.5 text-cyan-500" />
              In-Payload Collision Highlight
            </span>
            <span>{evaluation.matches.length} collision(s) detected</span>
          </div>
          <div className="text-xs font-mono p-2.5 rounded-lg bg-surface border border-subtle break-all whitespace-pre-wrap leading-relaxed select-text">
            {highlightedPayload}
          </div>
        </div>
      )}

      {/* Results grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-1">
        {/* Detected Matches */}
        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 text-slate-100 shadow-inner space-y-2.5">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
            <span className="text-xs font-mono font-bold text-slate-200 flex items-center gap-1.5">
              <Play className="w-3.5 h-3.5 text-cyan-400" /> Matches Found
            </span>
            <span className="text-xs font-mono text-cyan-400 font-bold px-2 py-0.5 rounded bg-cyan-950/80 border border-cyan-800/50">
              {evaluation.matches.length}
            </span>
          </div>

          {evaluation.matches.length === 0 ? (
            <p className="text-xs text-slate-400 font-mono py-4 text-center">
              No DLP pattern collisions detected. Payload is clean.
            </p>
          ) : (
            <div className="space-y-1.5 max-h-36 overflow-y-auto pr-1">
              {evaluation.matches.map((m, idx) => (
                <div
                  key={idx}
                  className="flex items-center justify-between text-xs font-mono bg-slate-800/80 p-2 rounded-lg border border-slate-700/60"
                >
                  <div className="truncate mr-2">
                    <span className="font-bold text-cyan-300">{m.rule.name}</span>
                    <span className="text-[11px] text-amber-300 ml-1.5 font-mono">
                      "{m.matchText}"
                    </span>
                    <span className="text-[10px] text-slate-400 ml-1">
                      [@index {m.index}]
                    </span>
                  </div>
                  <Badge
                    variant={
                      m.rule.default_action === 'block'
                        ? 'rose'
                        : m.rule.default_action === 'mask'
                        ? 'amber'
                        : 'cyan'
                    }
                    size="sm"
                  >
                    {m.rule.default_action}
                  </Badge>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Runtime Enforcement Simulation */}
        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 text-slate-100 shadow-inner space-y-2.5">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
            <span className="text-xs font-mono font-bold text-slate-200 flex items-center gap-1.5">
              <ShieldAlert className="w-3.5 h-3.5 text-amber-400" /> Simulated Runtime Output
            </span>
            {evaluation.blocked ? (
              <Badge variant="rose" size="sm">
                BLOCKED (403)
              </Badge>
            ) : evaluation.matches.length > 0 ? (
              <Badge variant="amber" size="sm">
                SANITIZED
              </Badge>
            ) : (
              <Badge variant="emerald" size="sm">
                PASSED
              </Badge>
            )}
          </div>

          {evaluation.blocked ? (
            <div className="p-2.5 rounded-lg bg-rose-950/60 border border-rose-500/40 text-rose-300 text-xs font-mono flex items-start gap-2">
              <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <div>
                <span className="font-bold block">Request Blocked by Policy</span>
                <span className="text-[11px] text-rose-200/90">
                  Sensitive credential or restricted compliance pattern detected in payload.
                </span>
              </div>
            </div>
          ) : (
            <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800 text-xs font-mono text-emerald-400 break-all max-h-36 overflow-y-auto leading-relaxed">
              <div className="flex items-center gap-1.5 text-[10px] text-slate-400 uppercase font-mono pb-1 border-b border-slate-800/60 mb-1">
                <Terminal className="w-3 h-3" /> Transmitted Egress Payload
              </div>
              {evaluation.maskedText || <span className="text-slate-500">Waiting for input...</span>}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
