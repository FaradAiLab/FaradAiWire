import { useState, useEffect, useRef, useMemo, useCallback } from 'react'
import type { AuditEvent, AuditLogsQueryParams, AuditQuerySummary } from '../../types.ts'
import { api } from '../../api'
import {
  MAX_STREAM_ROWS,
  PAGE_SIZE,
  getRowKey,
  normalizeAuditEvent,
  toRFC3339LocalInput,
} from './formatters.ts'
import {
  applyHydratedDetail,
  computeFallbackSummary,
  filterEventsClientSide,
  mergeAuditBatchDesc,
} from './streamLogic.ts'

export interface UseAuditStreamOptions {
  enabled: boolean
}

export function useAuditStream({ enabled }: UseAuditStreamOptions) {
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [serverSummary, setServerSummary] = useState<AuditQuerySummary | null>(null)
  const [totalCount, setTotalCount] = useState(0)
  const [offset, setOffset] = useState(0)
  const [isLoading, setIsLoading] = useState(true)
  const [queryError, setQueryError] = useState<string | null>(null)

  const [isConnected, setIsConnected] = useState(false)
  const [isPaused, setIsPaused] = useState(false)
  const [liveFollow, setLiveFollow] = useState(true)
  const [pendingEvents, setPendingEvents] = useState<AuditEvent[]>([])

  const [filterText, setFilterText] = useState('')
  const [matchedRuleFilter, setMatchedRuleFilter] = useState('')
  const [sinceInput, setSinceInput] = useState('')
  const [untilInput, setUntilInput] = useState('')
  const [selectedVerdict, setSelectedVerdict] = useState<string>('ALL')

  const [selectedRowKey, setSelectedRowKey] = useState<string | null>(null)
  const [detailLoadingIds, setDetailLoadingIds] = useState<Set<string>>(new Set())
  const [loadedDetailIds, setLoadedDetailIds] = useState<Set<string>>(new Set())
  const [detailErrors, setDetailErrors] = useState<Record<string, string>>({})

  const listContainerRef = useRef<HTMLDivElement>(null)
  const eventSourceRef = useRef<EventSource | null>(null)
  const isScrolledDownRef = useRef(false)
  const eventsRef = useRef<AuditEvent[]>(events)
  const pendingEventsRef = useRef<AuditEvent[]>(pendingEvents)
  const selectedRowKeyRef = useRef<string | null>(null)
  const liveFollowRef = useRef(liveFollow)
  const loadedDetailIdsRef = useRef(loadedDetailIds)
  const detailLoadingIdsRef = useRef(detailLoadingIds)

  eventsRef.current = events
  pendingEventsRef.current = pendingEvents
  selectedRowKeyRef.current = selectedRowKey
  liveFollowRef.current = liveFollow
  loadedDetailIdsRef.current = loadedDetailIds
  detailLoadingIdsRef.current = detailLoadingIds

  const isHistoricalMode = useMemo(() => {
    return offset > 0 || Boolean(sinceInput) || Boolean(untilInput)
  }, [offset, sinceInput, untilInput])

  const buildServerFilterParams = useCallback((): AuditLogsQueryParams => {
    return {
      summary: true,
      limit: PAGE_SIZE,
      offset,
      decision: selectedVerdict !== 'ALL' ? selectedVerdict : undefined,
      matched_rule: matchedRuleFilter.trim() || undefined,
      q: filterText.trim() || undefined,
      since: toRFC3339LocalInput(sinceInput),
      until: toRFC3339LocalInput(untilInput),
    }
  }, [offset, selectedVerdict, matchedRuleFilter, filterText, sinceInput, untilInput])

  const fetchDetail = useCallback((rowKey: string, ev: AuditEvent) => {
    const lookupId = ev.id || ev.trace_id
    if (!lookupId || detailLoadingIdsRef.current.has(rowKey)) return

    setDetailLoadingIds((prev) => new Set(prev).add(rowKey))
    setDetailErrors((prev) => {
      if (!prev[rowKey]) return prev
      const copy = { ...prev }
      delete copy[rowKey]
      return copy
    })

    api
      .getAuditLogDetail(lookupId)
      .then((res) => {
        if (res?.record) {
          const detailed = normalizeAuditEvent(res.record)
          setEvents((prev) => applyHydratedDetail(prev, rowKey, lookupId, detailed))
        }
        setLoadedDetailIds((prev) => new Set(prev).add(rowKey))
      })
      .catch((err: unknown) => {
        const msg = err instanceof Error ? err.message : 'Failed to load full invocation payload'
        setDetailErrors((prev) => ({ ...prev, [rowKey]: msg }))
      })
      .finally(() => {
        setDetailLoadingIds((prev) => {
          const copy = new Set(prev)
          copy.delete(rowKey)
          return copy
        })
      })
  }, [])

  const fetchHistoricalLogs = useCallback(
    (signal?: AbortSignal) => {
      setLoadedDetailIds(new Set())
      setDetailErrors({})
      setQueryError(null)
      setIsLoading(true)
      api
        .getAuditLogs(buildServerFilterParams(), signal)
        .then((res) => {
          if (signal?.aborted) return
          const list = res?.events || res?.logs || []
          if (Array.isArray(list)) {
            setEvents(list.map(normalizeAuditEvent))
          }
          setTotalCount(typeof res?.total === 'number' ? res.total : list.length)
          setServerSummary(res?.summary ?? null)
          setPendingEvents([])
        })
        .catch((err: unknown) => {
          if (signal?.aborted || (err instanceof Error && err.name === 'AbortError')) return
          setQueryError(err instanceof Error ? err.message : 'Failed to query audit logs')
        })
        .finally(() => {
          if (!signal?.aborted) setIsLoading(false)
        })
    },
    [buildServerFilterParams]
  )

  useEffect(() => {
    if (!enabled) return
    const abortController = new AbortController()
    const timer = window.setTimeout(() => {
      fetchHistoricalLogs(abortController.signal)
    }, 150)
    return () => {
      window.clearTimeout(timer)
      abortController.abort()
    }
  }, [enabled, fetchHistoricalLogs])

  useEffect(() => {
    if (!enabled || isPaused || isHistoricalMode) {
      if (eventSourceRef.current) {
        eventSourceRef.current.close()
        eventSourceRef.current = null
      }
      setIsConnected(false)
      return
    }

    const es = new EventSource('/admin/audit-logs/events')
    eventSourceRef.current = es

    const handleBatch = (rawBatch: unknown) => {
      try {
        const list = Array.isArray(rawBatch) ? rawBatch : [rawBatch]
        const shouldBufferNew =
          !liveFollowRef.current || isScrolledDownRef.current || selectedRowKeyRef.current !== null

        const merged = mergeAuditBatchDesc(eventsRef.current, list, MAX_STREAM_ROWS)

        if (shouldBufferNew && merged.newItems.length > 0) {
          const newIdSet = new Set(merged.newKeys)
          const updatedOnly = merged.nextEvents.filter((item, idx) => !newIdSet.has(getRowKey(item, idx)))
          eventsRef.current = updatedOnly
          setEvents(updatedOnly)

          const nextPending = mergeAuditBatchDesc(
            pendingEventsRef.current,
            merged.newItems,
            MAX_STREAM_ROWS
          ).nextEvents
          pendingEventsRef.current = nextPending
          setPendingEvents(nextPending)
        } else {
          eventsRef.current = merged.nextEvents
          setEvents(merged.nextEvents)
          if (merged.newKeys.length > 0) {
            setTotalCount((c) => c + merged.newKeys.length)
          }
        }

        if (merged.updatedKeys.length > 0) {
          setLoadedDetailIds((prev) => {
            const copy = new Set(prev)
            merged.updatedKeys.forEach((k) => copy.delete(k))
            return copy
          })
          const openKey = selectedRowKeyRef.current
          if (openKey && merged.updatedKeys.includes(openKey)) {
            const found = merged.nextEvents.find((ev, idx) => getRowKey(ev, idx) === openKey)
            if (found) {
              fetchDetail(openKey, found)
            }
          }
        }
      } catch (err) {
        console.error('Failed to parse audit batch', err)
      }
    }

    es.onopen = () => setIsConnected(true)
    es.onerror = () => setIsConnected(false)
    es.onmessage = (e) => {
      try {
        handleBatch(JSON.parse(e.data))
      } catch {
        // ignore heartbeat frames
      }
    }
    es.addEventListener('audit_batch', (e: MessageEvent) => {
      try {
        handleBatch(JSON.parse(e.data))
      } catch {
        // ignore malformed frames
      }
    })

    return () => {
      es.close()
      eventSourceRef.current = null
    }
  }, [enabled, isPaused, isHistoricalMode, fetchDetail])

  const selectRow = useCallback(
    (rowKey: string, ev: AuditEvent) => {
      setSelectedRowKey(rowKey)
      if (!loadedDetailIdsRef.current.has(rowKey)) {
        fetchDetail(rowKey, ev)
      }
    },
    [fetchDetail]
  )

  const clearSelection = useCallback(() => setSelectedRowKey(null), [])

  const onListScroll = useCallback((scrollTop: number) => {
    isScrolledDownRef.current = scrollTop > 24
  }, [])

  const jumpToTop = useCallback(() => {
    const queued = pendingEventsRef.current
    if (queued.length > 0) {
      const merged = mergeAuditBatchDesc(eventsRef.current, [...queued].reverse(), MAX_STREAM_ROWS)
      eventsRef.current = merged.nextEvents
      setEvents(merged.nextEvents)
      if (merged.newKeys.length > 0) {
        setTotalCount((c) => c + merged.newKeys.length)
      }
      pendingEventsRef.current = []
      setPendingEvents([])
    }
    isScrolledDownRef.current = false
    listContainerRef.current?.scrollTo({ top: 0, behavior: 'smooth' })
  }, [])

  const handleResumeLive = useCallback(() => {
    setOffset(0)
    setSinceInput('')
    setUntilInput('')
    setMatchedRuleFilter('')
    setIsPaused(false)
    setLiveFollow(true)
  }, [])

  const clearFilters = useCallback(() => {
    setOffset(0)
    setFilterText('')
    setMatchedRuleFilter('')
    setSinceInput('')
    setUntilInput('')
    setSelectedVerdict('ALL')
  }, [])

  const clearScreen = useCallback(() => {
    setEvents([])
    setPendingEvents([])
    setSelectedRowKey(null)
  }, [])

  const filteredEvents = useMemo(
    () => filterEventsClientSide(events, selectedVerdict, matchedRuleFilter, filterText),
    [events, selectedVerdict, matchedRuleFilter, filterText]
  )

  const summary = useMemo(
    () => serverSummary ?? computeFallbackSummary(events, totalCount),
    [serverSummary, events, totalCount]
  )

  const selectedEvent = useMemo(() => {
    if (!selectedRowKey) return null
    return filteredEvents.find((ev, idx) => getRowKey(ev, idx) === selectedRowKey) ??
      events.find((ev, idx) => getRowKey(ev, idx) === selectedRowKey) ??
      null
  }, [selectedRowKey, filteredEvents, events])

  return {
    events: filteredEvents,
    allLoadedCount: events.length,
    summary,
    totalCount,
    offset,
    setOffset,
    isLoading,
    queryError,
    setQueryError,
    isConnected,
    isPaused,
    setIsPaused,
    isHistoricalMode,
    liveFollow,
    setLiveFollow,
    pendingNewCount: pendingEvents.length,
    jumpToTop,
    onListScroll,
    listContainerRef,
    filterText,
    setFilterText: (v: string) => {
      setOffset(0)
      setFilterText(v)
    },
    matchedRuleFilter,
    setMatchedRuleFilter: (v: string) => {
      setOffset(0)
      setMatchedRuleFilter(v)
    },
    sinceInput,
    setSinceInput: (v: string) => {
      setOffset(0)
      setSinceInput(v)
    },
    untilInput,
    setUntilInput: (v: string) => {
      setOffset(0)
      setUntilInput(v)
    },
    selectedVerdict,
    setSelectedVerdict: (v: string) => {
      setOffset(0)
      setSelectedVerdict(v)
    },
    clearFilters,
    handleResumeLive,
    fetchHistoricalLogs,
    buildServerFilterParams,
    clearScreen,
    selectedRowKey,
    selectedEvent,
    selectRow,
    clearSelection,
    retryDetail: fetchDetail,
    isLoadingDetail: selectedRowKey ? detailLoadingIds.has(selectedRowKey) : false,
    detailError: selectedRowKey ? detailErrors[selectedRowKey] || null : null,
  }
}
