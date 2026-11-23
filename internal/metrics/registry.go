package metrics

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var defaultDurationBuckets = []float64{
	0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
}

var defaultRegistry = NewRegistry()

// Default returns the process-wide singleton OpenMetrics registry.
func Default() *Registry {
	return defaultRegistry
}

type requestLabels struct {
	decision string
	phase    string
	filter   string
	pathType string
}

func (l requestLabels) format() string {
	return fmt.Sprintf(`decision=%q,filter=%q,path_type=%q,phase=%q`, l.decision, l.filter, l.pathType, l.phase)
}

type filterDurLabels struct {
	phase    string
	pathType string
}

func (l filterDurLabels) format() string {
	return fmt.Sprintf(`path_type=%q,phase=%q`, l.pathType, l.phase)
}

type upstreamDurLabels struct {
	transport string
}

func (l upstreamDurLabels) format() string {
	return fmt.Sprintf(`transport=%q`, l.transport)
}

type phaseLabels struct {
	phase string
}

func (l phaseLabels) format() string {
	return fmt.Sprintf(`phase=%q`, l.phase)
}

type httpRespLabels struct {
	port      string
	codeClass string
}

func (l httpRespLabels) format() string {
	return fmt.Sprintf(`code_class=%q,port=%q`, l.codeClass, l.port)
}

type portLabels struct {
	port string
}

func (l portLabels) format() string {
	return fmt.Sprintf(`port=%q`, l.port)
}

type authFailLabels struct {
	port   string
	reason string
}

func (l authFailLabels) format() string {
	return fmt.Sprintf(`port=%q,reason=%q`, l.port, l.reason)
}

type counterMap[K comparable] struct {
	mu     sync.RWMutex
	series map[K]*atomic.Uint64
}

func newCounterMap[K comparable]() *counterMap[K] {
	return &counterMap[K]{series: make(map[K]*atomic.Uint64)}
}

func (m *counterMap[K]) add(k K, delta uint64) {
	if delta == 0 {
		return
	}
	m.mu.RLock()
	c, ok := m.series[k]
	m.mu.RUnlock()
	if ok {
		c.Add(delta)
		return
	}
	m.mu.Lock()
	c, ok = m.series[k]
	if !ok {
		c = &atomic.Uint64{}
		m.series[k] = c
	}
	m.mu.Unlock()
	c.Add(delta)
}

type labeledCounter struct {
	labels string
	value  uint64
}

func (m *counterMap[K]) snapshot(formatKey func(K) string) []labeledCounter {
	m.mu.RLock()
	out := make([]labeledCounter, 0, len(m.series))
	for k, c := range m.series {
		out = append(out, labeledCounter{
			labels: formatKey(k),
			value:  c.Load(),
		})
	}
	m.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		return out[i].labels < out[j].labels
	})
	return out
}

type histSeries struct {
	buckets []atomic.Uint64
	count   atomic.Uint64
	sumBits atomic.Uint64
}

func newHistSeries(numBounds int) *histSeries {
	return &histSeries{
		buckets: make([]atomic.Uint64, numBounds),
	}
}

func (s *histSeries) add(bounds []float64, val float64) {
	if math.IsNaN(val) || val < 0 {
		val = 0
	}
	for i, b := range bounds {
		if val <= b {
			s.buckets[i].Add(1)
			break
		}
	}
	s.count.Add(1)
	for {
		oldBits := s.sumBits.Load()
		nextBits := math.Float64bits(math.Float64frombits(oldBits) + val)
		if s.sumBits.CompareAndSwap(oldBits, nextBits) {
			break
		}
	}
}

type histMap[K comparable] struct {
	mu     sync.RWMutex
	bounds []float64
	series map[K]*histSeries
}

func newHistMap[K comparable](bounds []float64) *histMap[K] {
	return &histMap[K]{
		bounds: bounds,
		series: make(map[K]*histSeries),
	}
}

func (m *histMap[K]) observe(k K, seconds float64) {
	m.mu.RLock()
	s, ok := m.series[k]
	m.mu.RUnlock()
	if ok {
		s.add(m.bounds, seconds)
		return
	}
	m.mu.Lock()
	s, ok = m.series[k]
	if !ok {
		s = newHistSeries(len(m.bounds))
		m.series[k] = s
	}
	m.mu.Unlock()
	s.add(m.bounds, seconds)
}

type labeledHistogram struct {
	labels     string
	cumulative []uint64
	count      uint64
	sum        float64
}

func (m *histMap[K]) snapshot(formatKey func(K) string) []labeledHistogram {
	m.mu.RLock()
	out := make([]labeledHistogram, 0, len(m.series))
	for k, s := range m.series {
		cum := make([]uint64, len(m.bounds))
		var running uint64
		for i := range m.bounds {
			running += s.buckets[i].Load()
			cum[i] = running
		}
		out = append(out, labeledHistogram{
			labels:     formatKey(k),
			cumulative: cum,
			count:      s.count.Load(),
			sum:        math.Float64frombits(s.sumBits.Load()),
		})
	}
	m.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		return out[i].labels < out[j].labels
	})
	return out
}

// Registry maintains bounded-cardinality runtime metrics and renders OpenMetrics text exposition
// using only Go standard library primitives.
type Registry struct {
	startedAt time.Time

	requests       *counterMap[requestLabels]
	filterDuration *histMap[filterDurLabels]
	upstreamDur    *histMap[upstreamDurLabels]
	guardDuration  *histMap[phaseLabels]
	guardFallback  *counterMap[phaseLabels]
	guardLoadShed  *counterMap[phaseLabels]
	httpResponses  *counterMap[httpRespLabels]
	rateLimitRej   *counterMap[portLabels]
	authFailures   *counterMap[authFailLabels]

	droppedManualMu sync.RWMutex
	droppedManual   map[string]*atomic.Uint64

	providerMu          sync.RWMutex
	droppedProviders    map[string]func() uint64
	activeSessionsFn    func() int
	correlationEntryFn  func() int
	guardLatencyMSRatio func() float64
}

// NewRegistry creates an isolated OpenMetrics Registry.
func NewRegistry() *Registry {
	return &Registry{
		startedAt:        time.Now(),
		requests:         newCounterMap[requestLabels](),
		filterDuration:   newHistMap[filterDurLabels](defaultDurationBuckets),
		upstreamDur:      newHistMap[upstreamDurLabels](defaultDurationBuckets),
		guardDuration:    newHistMap[phaseLabels](defaultDurationBuckets),
		guardFallback:    newCounterMap[phaseLabels](),
		guardLoadShed:    newCounterMap[phaseLabels](),
		httpResponses:    newCounterMap[httpRespLabels](),
		rateLimitRej:     newCounterMap[portLabels](),
		authFailures:     newCounterMap[authFailLabels](),
		droppedManual:    make(map[string]*atomic.Uint64),
		droppedProviders: make(map[string]func() uint64),
	}
}

// ObserveRequest records a completed request/response security filter evaluation.
func (r *Registry) ObserveRequest(decision, phase, filterName, pathType string) {
	if r == nil {
		return
	}
	r.requests.add(requestLabels{
		decision: normalizeDecision(decision),
		phase:    normalizePhase(phase),
		filter:   normalizeFilter(filterName),
		pathType: normalizePathType(pathType),
	}, 1)
}

// ObserveFilterDuration records the duration of pipeline filter execution.
func (r *Registry) ObserveFilterDuration(phase, pathType string, d time.Duration) {
	if r == nil {
		return
	}
	r.filterDuration.observe(filterDurLabels{
		phase:    normalizePhase(phase),
		pathType: normalizePathType(pathType),
	}, d.Seconds())
}

// ObserveUpstreamDuration records upstream MCP call latency.
func (r *Registry) ObserveUpstreamDuration(transport string, d time.Duration) {
	if r == nil {
		return
	}
	r.upstreamDur.observe(upstreamDurLabels{
		transport: normalizeTransport(transport),
	}, d.Seconds())
}

// ObserveGuardDuration records L2 AI Guard inference latency.
func (r *Registry) ObserveGuardDuration(phase string, d time.Duration) {
	if r == nil {
		return
	}
	r.guardDuration.observe(phaseLabels{
		phase: normalizePhase(phase),
	}, d.Seconds())
}

// IncGuardFallback increments the L2->L1 guard degradation counter.
func (r *Registry) IncGuardFallback(phase string) {
	if r == nil {
		return
	}
	r.guardFallback.add(phaseLabels{phase: normalizePhase(phase)}, 1)
}

// IncGuardLoadShed increments the AI Guard concurrency queue load-shed counter.
func (r *Registry) IncGuardLoadShed(phase string) {
	if r == nil {
		return
	}
	r.guardLoadShed.add(phaseLabels{phase: normalizePhase(phase)}, 1)
}

// IncHTTPResponse records an HTTP response grouped by listener port role and code class.
func (r *Registry) IncHTTPResponse(port string, statusCode int) {
	if r == nil {
		return
	}
	r.httpResponses.add(httpRespLabels{
		port:      normalizePort(port),
		codeClass: normalizeCodeClass(statusCode),
	}, 1)
}

// IncRateLimitRejection records an HTTP 429 rate-limit rejection by port role.
func (r *Registry) IncRateLimitRejection(port string) {
	if r == nil {
		return
	}
	r.rateLimitRej.add(portLabels{port: normalizePort(port)}, 1)
}

// IncAuthFailure records an authentication or authorization failure with bounded reason enum.
func (r *Registry) IncAuthFailure(port, reason string) {
	if r == nil {
		return
	}
	r.authFailures.add(authFailLabels{
		port:   normalizePort(port),
		reason: normalizeAuthReason(reason),
	}, 1)
}

// AddDroppedEvents manually increments the dropped-event total for a sink ("duckdb", "broker", "jsonl").
func (r *Registry) AddDroppedEvents(sink string, n uint64) {
	if r == nil || n == 0 {
		return
	}
	norm := normalizeSink(sink)
	r.droppedManualMu.RLock()
	c, ok := r.droppedManual[norm]
	r.droppedManualMu.RUnlock()
	if !ok {
		r.droppedManualMu.Lock()
		c, ok = r.droppedManual[norm]
		if !ok {
			c = &atomic.Uint64{}
			r.droppedManual[norm] = c
		}
		r.droppedManualMu.Unlock()
	}
	c.Add(n)
}

// SetDroppedEventsProvider binds a dynamic callback returning dropped event counts for a sink.
func (r *Registry) SetDroppedEventsProvider(sink string, fn func() uint64) {
	if r == nil {
		return
	}
	r.providerMu.Lock()
	r.droppedProviders[normalizeSink(sink)] = fn
	r.providerMu.Unlock()
}

// SetActiveSessionsProvider binds a dynamic callback returning active MCP session count.
func (r *Registry) SetActiveSessionsProvider(fn func() int) {
	if r == nil {
		return
	}
	r.providerMu.Lock()
	r.activeSessionsFn = fn
	r.providerMu.Unlock()
}

// SetCorrelationEntriesProvider binds a dynamic callback returning pending correlation count.
func (r *Registry) SetCorrelationEntriesProvider(fn func() int) {
	if r == nil {
		return
	}
	r.providerMu.Lock()
	r.correlationEntryFn = fn
	r.providerMu.Unlock()
}

// RenderPrometheus renders all registered metrics in OpenMetrics / Prometheus text format v0.0.4.
func (r *Registry) RenderPrometheus() string {
	if r == nil {
		return ""
	}
	var b strings.Builder

	writeCounterMetric(&b,
		"faradaiwire_requests_total",
		"Total MCP requests processed through the security filter pipeline.",
		r.requests.snapshot(requestLabels.format),
	)

	writeHistogramMetric(&b,
		"faradaiwire_filter_duration_seconds",
		"Latency distribution of security filter pipeline execution in seconds.",
		defaultDurationBuckets,
		r.filterDuration.snapshot(filterDurLabels.format),
	)

	writeHistogramMetric(&b,
		"faradaiwire_upstream_duration_seconds",
		"Latency distribution of upstream MCP tool calls and forwarded requests in seconds.",
		defaultDurationBuckets,
		r.upstreamDur.snapshot(upstreamDurLabels.format),
	)

	writeHistogramMetric(&b,
		"faradaiwire_guard_duration_seconds",
		"Latency distribution of L2 AI Guard neural inference evaluations in seconds.",
		defaultDurationBuckets,
		r.guardDuration.snapshot(phaseLabels.format),
	)

	writeCounterMetric(&b,
		"faradaiwire_guard_fallback_total",
		"Total L2 AI Guard fallbacks to L1 static evaluation.",
		r.guardFallback.snapshot(phaseLabels.format),
	)

	writeCounterMetric(&b,
		"faradaiwire_guard_load_shed_total",
		"Total L2 AI Guard evaluations shed to L1 due to queue saturation.",
		r.guardLoadShed.snapshot(phaseLabels.format),
	)

	sinks := []string{"broker", "duckdb", "jsonl"}
	droppedSeries := make([]labeledCounter, 0, len(sinks))
	for _, sink := range sinks {
		droppedSeries = append(droppedSeries, labeledCounter{
			labels: fmt.Sprintf(`sink=%q`, sink),
			value:  r.droppedCount(sink),
		})
	}
	writeCounterMetric(&b,
		"faradaiwire_telemetry_dropped_events_total",
		"Total audit/telemetry events dropped due to bounded async queue saturation.",
		droppedSeries,
	)

	r.providerMu.RLock()
	activeFn := r.activeSessionsFn
	corrFn := r.correlationEntryFn
	r.providerMu.RUnlock()

	activeSessions := 0
	if activeFn != nil {
		activeSessions = activeFn()
	}
	correlationEntries := 0
	if corrFn != nil {
		correlationEntries = corrFn()
	}

	b.WriteString("# HELP faradaiwire_active_sessions Number of currently active managed MCP sessions.\n")
	b.WriteString("# TYPE faradaiwire_active_sessions gauge\n")
	b.WriteString("faradaiwire_active_sessions ")
	b.WriteString(strconv.Itoa(activeSessions))
	b.WriteByte('\n')

	b.WriteString("# HELP faradaiwire_correlation_entries Number of pending inbound-to-upstream correlation entries.\n")
	b.WriteString("# TYPE faradaiwire_correlation_entries gauge\n")
	b.WriteString("faradaiwire_correlation_entries ")
	b.WriteString(strconv.Itoa(correlationEntries))
	b.WriteByte('\n')

	writeCounterMetric(&b,
		"faradaiwire_http_responses_total",
		"Total HTTP responses served by listener port role and status code class.",
		r.httpResponses.snapshot(httpRespLabels.format),
	)

	writeCounterMetric(&b,
		"faradaiwire_rate_limit_rejections_total",
		"Total HTTP 429 rate-limit rejections by listener port role.",
		r.rateLimitRej.snapshot(portLabels.format),
	)

	writeCounterMetric(&b,
		"faradaiwire_auth_failures_total",
		"Total authentication or authorization failures by listener port role and reason.",
		r.authFailures.snapshot(authFailLabels.format),
	)

	b.WriteString("# HELP faradaiwire_process_uptime_seconds Process uptime in seconds.\n")
	b.WriteString("# TYPE faradaiwire_process_uptime_seconds gauge\n")
	b.WriteString("faradaiwire_process_uptime_seconds ")
	b.WriteString(strconv.FormatFloat(time.Since(r.startedAt).Seconds(), 'f', 3, 64))
	b.WriteByte('\n')

	return b.String()
}

func (r *Registry) droppedCount(sink string) uint64 {
	var total uint64
	r.droppedManualMu.RLock()
	if c, ok := r.droppedManual[sink]; ok {
		total += c.Load()
	}
	r.droppedManualMu.RUnlock()

	r.providerMu.RLock()
	fn := r.droppedProviders[sink]
	r.providerMu.RUnlock()
	if fn != nil {
		total += fn()
	}
	return total
}

func writeCounterMetric(b *strings.Builder, name, help string, series []labeledCounter) {
	b.WriteString("# HELP ")
	b.WriteString(name)
	b.WriteByte(' ')
	b.WriteString(help)
	b.WriteByte('\n')
	b.WriteString("# TYPE ")
	b.WriteString(name)
	b.WriteString(" counter\n")
	for _, s := range series {
		b.WriteString(name)
		if s.labels != "" {
			b.WriteByte('{')
			b.WriteString(s.labels)
			b.WriteByte('}')
		}
		b.WriteByte(' ')
		b.WriteString(strconv.FormatUint(s.value, 10))
		b.WriteByte('\n')
	}
}

func writeHistogramMetric(b *strings.Builder, name, help string, bounds []float64, series []labeledHistogram) {
	b.WriteString("# HELP ")
	b.WriteString(name)
	b.WriteByte(' ')
	b.WriteString(help)
	b.WriteByte('\n')
	b.WriteString("# TYPE ")
	b.WriteString(name)
	b.WriteString(" histogram\n")
	for _, s := range series {
		prefix := ""
		if s.labels != "" {
			prefix = s.labels + ","
		}
		for i, bound := range bounds {
			b.WriteString(name)
			b.WriteString("_bucket{")
			b.WriteString(prefix)
			b.WriteString(`le="`)
			b.WriteString(strconv.FormatFloat(bound, 'g', -1, 64))
			b.WriteString(`"} `)
			b.WriteString(strconv.FormatUint(s.cumulative[i], 10))
			b.WriteByte('\n')
		}
		b.WriteString(name)
		b.WriteString("_bucket{")
		b.WriteString(prefix)
		b.WriteString(`le="+Inf"} `)
		b.WriteString(strconv.FormatUint(s.count, 10))
		b.WriteByte('\n')

		b.WriteString(name)
		b.WriteString("_sum")
		if s.labels != "" {
			b.WriteByte('{')
			b.WriteString(s.labels)
			b.WriteByte('}')
		}
		b.WriteByte(' ')
		b.WriteString(strconv.FormatFloat(s.sum, 'g', -1, 64))
		b.WriteByte('\n')

		b.WriteString(name)
		b.WriteString("_count")
		if s.labels != "" {
			b.WriteByte('{')
			b.WriteString(s.labels)
			b.WriteByte('}')
		}
		b.WriteByte(' ')
		b.WriteString(strconv.FormatUint(s.count, 10))
		b.WriteByte('\n')
	}
}

func normalizeDecision(d string) string {
	switch strings.ToLower(strings.TrimSpace(d)) {
	case "allowed":
		return "allowed"
	case "blocked":
		return "blocked"
	case "masked":
		return "masked"
	case "audit":
		return "audit"
	case "pending":
		return "pending"
	case "error":
		return "error"
	case "critical":
		return "critical"
	case "":
		return "unknown"
	default:
		return "other"
	}
}

func normalizePhase(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "request":
		return "request"
	case "response":
		return "response"
	case "complete":
		return "complete"
	default:
		return "unknown"
	}
}

func normalizeFilter(f string) string {
	switch strings.ToLower(strings.TrimSpace(f)) {
	case "dlp", "dlp_filter":
		return "dlp"
	case "guard", "semantic_guard", "semantic_security_guard", "injection_scanner", "ai_guard":
		return "guard"
	case "loop", "loop_protection":
		return "loop"
	case "schema", "schema_pinning":
		return "schema"
	case "policy", "acl":
		return "policy"
	case "hitl", "hitl_gate":
		return "hitl"
	case "pipeline", "":
		return "pipeline"
	case "upstream":
		return "upstream"
	default:
		return "other"
	}
}

func normalizePathType(pt string) string {
	switch strings.ToLower(strings.TrimSpace(pt)) {
	case "fast":
		return "fast"
	case "deep":
		return "deep"
	default:
		return "unknown"
	}
}

func normalizeTransport(tr string) string {
	switch strings.ToLower(strings.TrimSpace(tr)) {
	case "http":
		return "http"
	case "sse":
		return "sse"
	case "stdio":
		return "stdio"
	default:
		return "other"
	}
}

func normalizePort(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "proxy":
		return "proxy"
	case "admin":
		return "admin"
	case "stdio":
		return "stdio"
	default:
		return "unknown"
	}
}

func normalizeCodeClass(status int) string {
	switch {
	case status >= 200 && status < 300:
		return "2xx"
	case status >= 300 && status < 400:
		return "3xx"
	case status >= 400 && status < 500:
		return "4xx"
	case status >= 500 && status < 600:
		return "5xx"
	default:
		return "other"
	}
}

func normalizeSink(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "duckdb":
		return "duckdb"
	case "broker":
		return "broker"
	case "jsonl":
		return "jsonl"
	default:
		return "other"
	}
}

func normalizeAuthReason(reason string) string {
	switch strings.ToLower(strings.TrimSpace(reason)) {
	case "invalid_bearer_token":
		return "invalid_bearer_token"
	case "missing_or_invalid_session":
		return "missing_or_invalid_session"
	case "admin_role_required":
		return "admin_role_required"
	case "too_many_attempts", "too_many_failed_attempts":
		return "too_many_attempts"
	case "invalid_api_key", "invalid_or_missing_credentials":
		return "invalid_api_key"
	case "agent_access_denied":
		return "agent_access_denied"
	case "invalid_session_cookie":
		return "invalid_session_cookie"
	default:
		return "other"
	}
}
