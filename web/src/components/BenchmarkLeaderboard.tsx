import React, { useState, useMemo } from 'react'
import {
  ShieldCheck,
  Zap,
  Cpu,
  Layers,
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  Info,
  CheckCircle2,
} from 'lucide-react'
import { GuardModel } from '../types'
import { calculateKVCacheMB } from './HostTelemetryBar'

interface BenchmarkLeaderboardProps {
  models: GuardModel[]
  activeModelId?: string
}

type SortField = 'name' | 'accuracy' | 'latency' | 'ram' | 'fp'

export const BenchmarkLeaderboard: React.FC<BenchmarkLeaderboardProps> = ({
  models,
  activeModelId,
}) => {
  const [sortField, setSortField] = useState<SortField>('accuracy')
  const [sortAsc, setSortAsc] = useState<boolean>(false)

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortAsc(!sortAsc)
    } else {
      setSortField(field)
      // Defaults: accuracy descending, latency ascending, ram ascending
      setSortAsc(field === 'latency' || field === 'fp')
    }
  }

  const sortedModels = useMemo(() => {
    return [...models].sort((a, b) => {
      let diff = 0
      switch (sortField) {
        case 'name':
          diff = a.name.localeCompare(b.name)
          break
        case 'accuracy':
          diff = a.benchmark_accuracy - b.benchmark_accuracy
          break
        case 'fp':
          diff = a.benchmark_fp_rate - b.benchmark_fp_rate
          break
        case 'latency':
          diff = a.benchmark_avg_latency_ms - b.benchmark_avg_latency_ms
          break
        case 'ram':
          diff = a.ram_required_mb - b.ram_required_mb
          break
      }
      return sortAsc ? diff : -diff
    })
  }, [models, sortField, sortAsc])

  const renderSortIcon = (field: SortField) => {
    if (sortField !== field) {
      return <ArrowUpDown className="w-3 h-3 text-muted/50 group-hover:text-muted" />
    }
    return sortAsc ? (
      <ArrowUp className="w-3 h-3 text-accent" />
    ) : (
      <ArrowDown className="w-3 h-3 text-accent" />
    )
  }

  return (
    <div className="bg-surface rounded-2xl border border-subtle shadow-sm overflow-hidden transition-all">
      {/* Table Header / Context */}
      <div className="p-5 border-b border-subtle flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-accent" />
            <h3 className="text-sm font-bold text-primary tracking-wide">
              FAB Benchmark Leaderboard & Hardware Matrix
            </h3>
          </div>
          <p className="text-xs text-muted mt-0.5">
            Empirical accuracy, false-positive rates, and latency percentiles measured across standardized agent tool-use workloads. Zero network egress.
          </p>
        </div>
        <div className="flex items-center gap-1.5 text-[11px] text-muted font-mono bg-canvas px-2.5 py-1 rounded-lg border border-subtle self-start sm:self-auto">
          <Info className="w-3.5 h-3.5 text-accent shrink-0" />
          <span>SLA Baseline: PEP Optimal (2,048 tokens)</span>
        </div>
      </div>

      {/* Table Container */}
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse" aria-label="Security Guard Models Benchmark Leaderboard">
          <thead>
            <tr className="border-b border-subtle bg-canvas/40 text-[11px] font-mono text-muted uppercase tracking-wider select-none">
              <th scope="col" className="py-3 px-4">
                <button
                  type="button"
                  onClick={() => handleSort('name')}
                  className="flex items-center gap-1 font-semibold hover:text-primary transition-colors group"
                >
                  <span>Model</span>
                  {renderSortIcon('name')}
                </button>
              </th>
              <th scope="col" className="py-3 px-4">Paradigm & Specs</th>
              <th scope="col" className="py-3 px-4">
                <button
                  type="button"
                  onClick={() => handleSort('accuracy')}
                  className="flex items-center gap-1 font-semibold hover:text-primary transition-colors group"
                >
                  <span>FAB Accuracy (FP Rate)</span>
                  {renderSortIcon('accuracy')}
                </button>
              </th>
              <th scope="col" className="py-3 px-4">
                <button
                  type="button"
                  onClick={() => handleSort('latency')}
                  className="flex items-center gap-1 font-semibold hover:text-primary transition-colors group"
                >
                  <span>Latency (Avg / P95)</span>
                  {renderSortIcon('latency')}
                </button>
              </th>
              <th scope="col" className="py-3 px-4">
                <button
                  type="button"
                  onClick={() => handleSort('ram')}
                  className="flex items-center gap-1 font-semibold hover:text-primary transition-colors group"
                >
                  <span>RAM Footprint</span>
                  {renderSortIcon('ram')}
                </button>
              </th>
              <th scope="col" className="py-3 px-4">Optimal Runtime</th>
              <th scope="col" className="py-3 px-4 text-right">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-subtle/60 text-xs">
            {sortedModels.map((model) => {
              const isActive = model.id === activeModelId || model.is_active
              const accuracyPct = (model.benchmark_accuracy * 100).toFixed(1)
              const fpPct = (model.benchmark_fp_rate * 100).toFixed(1)
              const kvCacheMB = calculateKVCacheMB(model, 2048)
              const totalRAM_GB = ((model.ram_required_mb + kvCacheMB) / 1024).toFixed(2)

              return (
                <tr
                  key={model.id}
                  className={`hover:bg-canvas/50 transition-colors ${
                    isActive ? 'bg-accent/5' : ''
                  }`}
                >
                  {/* Model Column */}
                  <td className="py-3.5 px-4">
                    <div className="font-semibold text-primary flex items-center gap-2">
                      <span>{model.name}</span>
                      {isActive && (
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                      )}
                    </div>
                    <div className="text-[11px] text-muted font-mono truncate max-w-xs mt-0.5">
                      {model.ollama_source || model.docker_image || model.id}
                    </div>
                  </td>

                  {/* Paradigm & Specs */}
                  <td className="py-3.5 px-4 font-mono">
                    <div className="flex items-center gap-1.5">
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-surface border border-subtle text-primary font-medium">
                        {model.parameter_size}
                      </span>
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/20 text-emerald-600 dark:text-emerald-400 font-semibold">
                        Q4_K_M
                      </span>
                    </div>
                    <div className="text-[11px] text-muted mt-1">
                      {model.paradigm === 'decision_model' ? (
                        <span className="text-cyan-600 dark:text-cyan-400 font-sans">Decision Model</span>
                      ) : (
                        <span className="text-purple-600 dark:text-purple-400 font-sans">Generative LLM</span>
                      )}
                    </div>
                  </td>

                  {/* FAB Accuracy */}
                  <td className="py-3.5 px-4 font-mono tabular-nums">
                    <div className="flex items-center gap-1.5">
                      <ShieldCheck className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400 shrink-0" />
                      <span className="font-bold text-emerald-700 dark:text-emerald-300">
                        {accuracyPct}%
                      </span>
                    </div>
                    <div className="text-[11px] text-muted mt-0.5 font-sans">
                      FP Rate: <span className="font-mono">{fpPct}%</span>
                    </div>
                  </td>

                  {/* Latency */}
                  <td className="py-3.5 px-4 font-mono tabular-nums">
                    <div className="flex items-center gap-1.5">
                      <Zap className="w-3.5 h-3.5 text-amber-500 shrink-0" />
                      <span className="font-semibold text-primary">
                        {Math.round(model.benchmark_avg_latency_ms)}ms
                      </span>
                      <span className="text-muted text-[11px]">avg</span>
                    </div>
                    <div className="text-[11px] text-muted mt-0.5">
                      P95: <span className="text-amber-700 dark:text-amber-400 font-semibold">{Math.round(model.benchmark_p95_latency_ms)}ms</span>
                    </div>
                  </td>

                  {/* RAM Footprint */}
                  <td className="py-3.5 px-4 font-mono tabular-nums">
                    <div className="flex items-center gap-1.5">
                      <Cpu className="w-3.5 h-3.5 text-accent shrink-0" />
                      <span className="font-bold text-primary">{totalRAM_GB} GB</span>
                    </div>
                    <div className="text-[11px] text-muted mt-0.5">
                      {(model.ram_required_mb / 1024).toFixed(1)} GB + {kvCacheMB} MB KV
                    </div>
                  </td>

                  {/* Recommended Runtime */}
                  <td className="py-3.5 px-4 text-[11px]">
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-canvas border border-subtle text-primary font-mono">
                      {model.family === 'liquid'
                        ? 'Docker Sidecar'
                        : 'Metal / Ollama Local'}
                    </span>
                  </td>

                  {/* Status */}
                  <td className="py-3.5 px-4 text-right">
                    {isActive ? (
                      <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[10px] font-mono font-bold uppercase bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30">
                        <CheckCircle2 className="w-3 h-3" />
                        Active
                      </span>
                    ) : (
                      <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-mono text-muted bg-canvas border border-subtle">
                        Standby
                      </span>
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

