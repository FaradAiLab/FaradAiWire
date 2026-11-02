package guard

import (
	"context"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/settings"
	"github.com/FaradAiLab/FaradAiWire/pkg/filter"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
)

// Ensure GuardFilter implements filter.SecurityFilter and filter.RequestFilter.
var (
	_ filter.SecurityFilter = (*GuardFilter)(nil)
	_ filter.RequestFilter  = (*GuardFilter)(nil)
	_ filter.ResponseFilter = (*GuardFilter)(nil)
)

// L1CompiledRule holds a precompiled regular expression and its declarative action.
type L1CompiledRule struct {
	Name   string
	Regex  *regexp.Regexp
	Action string // "mask" or "block"
}

// FilterConfig holds runtime tuning parameters for the two-tiered cascade.
type FilterConfig struct {
	Enabled          bool
	L1Patterns       []config.DLPPattern
	FastPathTools    []string
	CriticalBlocks   []string
	MaxPayloadLength int // Threshold in characters, defaults to 128
	MinWordCount     int // Threshold in whitespace-separated words, defaults to 5
}

// GuardFilter coordinates the two-tiered fail-fast security cascade (Order 55).
type GuardFilter struct {
	cfg              FilterConfig
	compiledL1       []L1CompiledRule
	manager          Manager
	hitlDispatcher   *HITLDispatcher
	notificationSink NotificationSink
	catalog          CatalogStore
	agentRepo        agent.Resolver
	settingsCache    *settings.Cache
	mu               sync.RWMutex
}

// NewFilter constructs an initialized GuardFilter with precompiled L1 rules.
func NewFilter(cfg FilterConfig, mgr ...Manager) *GuardFilter {
	if cfg.MaxPayloadLength <= 0 {
		cfg.MaxPayloadLength = 128
	}
	if cfg.MinWordCount <= 0 {
		cfg.MinWordCount = 5
	}
	if len(cfg.FastPathTools) == 0 {
		cfg.FastPathTools = DefaultFastPathPatterns()
	}
	if len(cfg.CriticalBlocks) == 0 {
		cfg.CriticalBlocks = DefaultCriticalBlocks()
	}

	patterns := cfg.L1Patterns
	if len(patterns) == 0 {
		patterns = DefaultL1Patterns()
	}

	var compiled []L1CompiledRule
	for _, p := range patterns {
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			slog.Warn("Failed to compile Guard L1 rule, skipping", slog.String("rule", p.Name), slog.String("error", err.Error()))
			continue
		}
		action := strings.ToLower(p.Action)
		if action != "mask" && action != "block" {
			action = "block"
		}
		compiled = append(compiled, L1CompiledRule{
			Name:   p.Name,
			Regex:  re,
			Action: action,
		})
	}

	gf := &GuardFilter{
		cfg:        cfg,
		compiledL1: compiled,
	}
	if len(mgr) > 0 && mgr[0] != nil {
		gf.manager = mgr[0]
	}
	return gf
}

// Name returns the identifier of the filter.
func (f *GuardFilter) Name() string {
	return "guard"
}

// Order returns the pipeline execution precedence (OrderGuard = 55).
func (f *GuardFilter) Order() int {
	return filter.OrderGuard
}

// SetManager thread-safely binds or hot-swaps the underlying Manager provider.
func (f *GuardFilter) SetManager(mgr Manager) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.manager = mgr
}

// Manager returns the currently configured Manager provider.
func (f *GuardFilter) Manager() Manager {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.manager
}

// SetHITLDispatcher thread-safely binds the HITL dispatcher to the guard filter.
func (f *GuardFilter) SetHITLDispatcher(d *HITLDispatcher) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hitlDispatcher = d
}

// HITLDispatcher returns the currently configured HITL dispatcher.
func (f *GuardFilter) HITLDispatcher() *HITLDispatcher {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.hitlDispatcher
}

// SetCatalog thread-safely binds the DuckDB model catalog to the guard filter.
func (f *GuardFilter) SetCatalog(cat CatalogStore) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.catalog = cat
}

// Catalog returns the currently configured DuckDB model catalog.
func (f *GuardFilter) Catalog() CatalogStore {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.catalog
}

// SetAgentRepository thread-safely binds the agent configuration resolver.
func (f *GuardFilter) SetAgentRepository(repo agent.Resolver) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.agentRepo = repo
}

// AgentRepository returns the currently configured agent resolver.
func (f *GuardFilter) AgentRepository() agent.Resolver {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.agentRepo
}

// SetSettingsCache binds the dynamic atomic operational settings cache.
func (f *GuardFilter) SetSettingsCache(c *settings.Cache) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.settingsCache = c
}

// SettingsCache returns the currently configured operational settings cache.
func (f *GuardFilter) SettingsCache() *settings.Cache {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.settingsCache
}

func (f *GuardFilter) getThresholdScore() float64 {
	f.mu.RLock()
	c := f.settingsCache
	f.mu.RUnlock()
	if c != nil {
		if s := c.Get(); s != nil && s.Guard.ThresholdScore > 0 {
			return s.Guard.ThresholdScore
		}
	}
	return 0.50
}

func (f *GuardFilter) getHITLTimeout() time.Duration {
	f.mu.RLock()
	c := f.settingsCache
	f.mu.RUnlock()
	if c != nil {
		if s := c.Get(); s != nil && s.Guard.HITLTimeoutSec > 0 {
			return time.Duration(s.Guard.HITLTimeoutSec) * time.Second
		}
	}
	return 60 * time.Second
}

// SetNotificationSink thread-safely sets the MCP notification dispatcher.
func (f *GuardFilter) SetNotificationSink(sink NotificationSink) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.notificationSink = sink
}

// NotificationSink returns the currently configured notification sink.
func (f *GuardFilter) NotificationSink() NotificationSink {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.notificationSink
}

// ExecuteRequest satisfies filter.SecurityFilter for unified pipeline execution.
func (f *GuardFilter) ExecuteRequest(ctx context.Context, req *mcp.Request) (*mcp.Response, error) {
	_, err := f.FilterRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

// ExecuteResponse satisfies filter.SecurityFilter for unified pipeline execution.
func (f *GuardFilter) ExecuteResponse(ctx context.Context, resp *mcp.Response) (*mcp.Response, error) {
	filteredResp, mcpErr := f.FilterResponse(ctx, resp)
	if mcpErr != nil {
		return nil, mcpErr
	}
	return filteredResp, nil
}
