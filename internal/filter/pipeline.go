package filter

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/FaradAiLab/FaradAiWire/internal/filter/adaptive"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/types"
	"github.com/FaradAiLab/FaradAiWire/internal/settings"
	pkgfilter "github.com/FaradAiLab/FaradAiWire/pkg/filter"
)

// Canonical filter contracts re-exported from pkg/filter
type NamedFilter = pkgfilter.NamedFilter
type OrderedFilter = pkgfilter.OrderedFilter
type SecurityFilter = pkgfilter.SecurityFilter
type BaseSecurityFilter = pkgfilter.BaseSecurityFilter
type Filter = pkgfilter.Filter
type RequestFilter = pkgfilter.RequestFilter
type ResponseFilter = pkgfilter.ResponseFilter

// Re-export context types and keys from internal/filter/types for backward compatibility
type ContextKey = types.ContextKey
type UserContext = types.UserContext

const (
	// UserContextKey stores user metadata in the request context.
	UserContextKey ContextKey = types.UserContextKey
	// TraceIDContextKey stores the trace ID in the request context.
	TraceIDContextKey ContextKey = types.TraceIDContextKey
	// InvocationIDContextKey stores the unique invocation record ID across request and response phases.
	InvocationIDContextKey ContextKey = types.InvocationIDContextKey
	// ToolNameContextKey stores the tool name in request/response context.
	ToolNameContextKey ContextKey = types.ToolNameContextKey
	// PathTypeContextKey stores the execution path type (FAST_PATH / DEEP_PATH) in context.
	PathTypeContextKey ContextKey = types.PathTypeContextKey
	// AgentNameContextKey stores the resolved agent name for per-agent policy evaluation.
	AgentNameContextKey ContextKey = types.AgentNameContextKey
)

// Pipeline coordinates the sequential execution of filters.
type Pipeline struct {
	mu                      sync.RWMutex
	filters                 []NamedFilter
	externalFilters         []NamedFilter
	router                  *adaptive.Router
	logger                  AuditLogger
	debugRetainUnmaskedDiff bool
	settingsCache           *settings.Cache
}

// NewPipeline initializes a new filter pipeline.
func NewPipeline(logger AuditLogger) *Pipeline {
	return &Pipeline{
		logger: logger,
	}
}

// SetSettingsCache attaches a live atomic operational settings cache to the pipeline.
func (p *Pipeline) SetSettingsCache(cache *settings.Cache) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.settingsCache = cache
	p.mu.Unlock()
}

// SettingsCache returns the configured live operational settings cache, or nil.
func (p *Pipeline) SettingsCache() *settings.Cache {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.settingsCache
}

// SetDebugRetainUnmaskedDiff sets whether pre-filter payloads are recorded for local diffing.
func (p *Pipeline) SetDebugRetainUnmaskedDiff(enabled bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.debugRetainUnmaskedDiff = enabled
}

// DebugRetainUnmaskedDiff returns true if pre-filter payload capture is enabled.
func (p *Pipeline) DebugRetainUnmaskedDiff() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.debugRetainUnmaskedDiff
}

// AddAuditLogger attaches an additional audit logger to the pipeline thread-safely.
func (p *Pipeline) AddAuditLogger(l AuditLogger) {
	if l == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.logger == nil {
		p.logger = l
	} else {
		p.logger = NewMultiAuditLogger(p.logger, l)
	}
}

// GetAuditLogger returns the active audit logger.
func (p *Pipeline) GetAuditLogger() AuditLogger {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.logger
}

func getFilterOrder(f NamedFilter) int {
	if of, ok := f.(interface{ Order() int }); ok {
		return of.Order()
	}
	return 100 // default order for unordered filters
}

func sortFilters(filters []NamedFilter) []NamedFilter {
	if len(filters) == 0 {
		return nil
	}
	// Always copy into a fresh backing array so p.filters stays immutable for lock-free hot-path reads.
	sorted := make([]NamedFilter, len(filters))
	copy(sorted, filters)
	if len(sorted) > 1 {
		sort.SliceStable(sorted, func(i, j int) bool {
			return getFilterOrder(sorted[i]) < getFilterOrder(sorted[j])
		})
	}
	return sorted
}

// RegisterFilter adds a security filter to the pipeline, maintaining strict ascending Order() precedence.
// Dogfooded by Core built-in filters and dynamically toggled runtime filters.
func (p *Pipeline) RegisterFilter(f SecurityFilter) {
	if f == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	p.filters = upsertSortedFilter(p.filters, f)
}

// RegisterPinnedFilter adds an external security filter (such as FAWEE's OPAFilter) and pins it
// so it survives subsequent Swap calls during configuration reloads.
func (p *Pipeline) RegisterPinnedFilter(f SecurityFilter) {
	if f == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	p.externalFilters = upsertExternalFilter(p.externalFilters, f)
	p.filters = upsertSortedFilter(p.filters, f)
}

func sameFilterIdentity(a, b NamedFilter) bool {
	if a == nil || b == nil {
		return false
	}
	if a == b {
		return true
	}
	nameA := a.Name()
	return nameA != "" && nameA == b.Name()
}

func upsertExternalFilter(list []NamedFilter, f NamedFilter) []NamedFilter {
	for i, existing := range list {
		if sameFilterIdentity(existing, f) {
			next := make([]NamedFilter, len(list))
			copy(next, list)
			next[i] = f
			return next
		}
	}
	next := make([]NamedFilter, len(list)+1)
	copy(next, list)
	next[len(list)] = f
	return next
}

func upsertSortedFilter(list []NamedFilter, f NamedFilter) []NamedFilter {
	filtered := make([]NamedFilter, 0, len(list)+1)
	for _, existing := range list {
		if !sameFilterIdentity(existing, f) {
			filtered = append(filtered, existing)
		}
	}
	filtered = append(filtered, f)
	return sortFilters(filtered)
}

// SetFilters updates the active filters thread-safely, maintaining Order() sorting precedence.
func (p *Pipeline) SetFilters(filters []NamedFilter) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.filters = sortFilters(filters)
}

// Swap atomically updates the active filters and adaptive router under a single write lock,
// preserving externally registered pinned filters, and gracefully closes any displaced filters implementing io.Closer.
func (p *Pipeline) Swap(filters []NamedFilter, router *adaptive.Router) {
	p.mu.Lock()
	oldFilters := p.filters
	merged := make([]NamedFilter, 0, len(filters)+len(p.externalFilters))
	merged = append(merged, filters...)
	for _, ext := range p.externalFilters {
		present := false
		for _, newF := range merged {
			if sameFilterIdentity(ext, newF) {
				present = true
				break
			}
		}
		if !present {
			merged = append(merged, ext)
		}
	}
	sortedMerged := sortFilters(merged)
	p.filters = sortedMerged
	p.router = router
	p.mu.Unlock()

	for _, oldF := range oldFilters {
		retained := false
		for _, newF := range sortedMerged {
			if oldF == newF {
				retained = true
				break
			}
		}
		if !retained {
			if closer, ok := oldF.(io.Closer); ok {
				_ = closer.Close()
			}
		}
	}
}

// GetFilters returns a copy of the active list of filters.
func (p *Pipeline) GetFilters() []NamedFilter {
	p.mu.RLock()
	defer p.mu.RUnlock()
	res := make([]NamedFilter, len(p.filters))
	copy(res, p.filters)
	return res
}

// GetFilter returns the active filter with the given name, or nil if not present.
func (p *Pipeline) GetFilter(name string) NamedFilter {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, f := range p.filters {
		if f != nil && f.Name() == name {
			return f
		}
	}
	return nil
}

// SetAdaptiveRouter sets the adaptive fast-path router.
func (p *Pipeline) SetAdaptiveRouter(router *adaptive.Router) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.router = router
}

// GetAdaptiveRouter returns the current adaptive router.
func (p *Pipeline) GetAdaptiveRouter() *adaptive.Router {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.router
}

// ClearBaselines resets dynamic baselines across any filters in the pipeline that support it.
func (p *Pipeline) ClearBaselines() {
	p.mu.RLock()
	filters := make([]NamedFilter, len(p.filters))
	copy(filters, p.filters)
	p.mu.RUnlock()

	type baselineClearer interface {
		ClearBaselines()
	}

	for _, f := range filters {
		if bc, ok := f.(baselineClearer); ok {
			bc.ClearBaselines()
		}
	}
}

// Close gracefully closes all active filters implementing io.Closer.
func (p *Pipeline) Close() error {
	p.mu.Lock()
	filters := make([]NamedFilter, len(p.filters))
	copy(filters, p.filters)
	p.filters = nil
	p.mu.Unlock()

	var closeErrs []error
	for _, f := range filters {
		if closer, ok := f.(io.Closer); ok {
			if err := closer.Close(); err != nil {
				closeErrs = append(closeErrs, fmt.Errorf("closing filter %s: %w", f.Name(), err))
			}
		}
	}
	return errors.Join(closeErrs...)
}
