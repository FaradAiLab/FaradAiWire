package limit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/types"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
	"github.com/FaradAiLab/FaradAiWire/pkg/filter"
)

// Ensure filters implement filter.SecurityFilter, filter.RequestFilter, and io.Closer.
var (
	_ filter.SecurityFilter = (*LoopFilter)(nil)
	_ filter.RequestFilter  = (*LoopFilter)(nil)
	_ io.Closer             = (*LoopFilter)(nil)
	_ filter.SecurityFilter = (*RateLimitFilter)(nil)
	_ filter.RequestFilter  = (*RateLimitFilter)(nil)
	_ io.Closer             = (*RateLimitFilter)(nil)
)

// === Loop Protection Filter ===

// LoopFilter monitors consecutive tool execution and blocks infinite loops.
type LoopFilter struct {
	enabled       bool
	maxRepeat     int
	windowSeconds int
	excludeTools  []string
	overrides     []config.LoopToolOverride
	store         StateStore

	repoMu    sync.RWMutex
	agentRepo agent.Resolver
}

// NewLoopFilter creates a LoopFilter.
func NewLoopFilter(enabled bool, maxRepeat int, windowSeconds int, excludeTools []string, overrides []config.LoopToolOverride, store StateStore) *LoopFilter {
	if maxRepeat <= 0 {
		maxRepeat = 3
	}
	if windowSeconds <= 0 {
		windowSeconds = 10
	}
	if store == nil {
		store = NewInMemoryStateStore()
	}
	return &LoopFilter{
		enabled:       enabled,
		maxRepeat:     maxRepeat,
		windowSeconds: windowSeconds,
		excludeTools:  excludeTools,
		overrides:     overrides,
		store:         store,
	}
}

// SetAgentRepository sets the agent repository for per-agent loop protection overrides.
func (l *LoopFilter) SetAgentRepository(repo agent.Resolver) {
	l.repoMu.Lock()
	defer l.repoMu.Unlock()
	l.agentRepo = repo
}

// AgentRepository returns the currently configured agent repository.
func (l *LoopFilter) AgentRepository() agent.Resolver {
	l.repoMu.RLock()
	defer l.repoMu.RUnlock()
	return l.agentRepo
}

// Name returns the identifier of the filter.
func (l *LoopFilter) Name() string {
	return "loop_protection"
}

// Order returns the execution precedence in the security pipeline (OrderLoopProtection = 15).
func (l *LoopFilter) Order() int {
	return filter.OrderLoopProtection
}

func extractAgentName(ctx context.Context) string {
	if aVal := ctx.Value(types.AgentNameContextKey); aVal != nil {
		if a, ok := aVal.(string); ok && a != "" {
			return a
		}
	}
	if aVal := ctx.Value("agent_name"); aVal != nil {
		if a, ok := aVal.(string); ok && a != "" {
			return a
		}
	}
	return ""
}

func buildTrackingKey(ctx context.Context, toolName string) string {
	agentName := extractAgentName(ctx)
	if agentName == "" {
		agentName = "global"
	}

	userID := "anonymous"
	if uVal := ctx.Value(types.UserContextKey); uVal != nil {
		if u, ok := uVal.(*types.UserContext); ok && u.UserID != "" {
			userID = u.UserID
		}
	}

	if toolName != "" {
		return fmt.Sprintf("agent:%s:user:%s:tool:%s", agentName, userID, toolName)
	}
	return fmt.Sprintf("agent:%s:user:%s", agentName, userID)
}

// FilterRequest evaluates whether the incoming tool call violates loop constraints.
func (l *LoopFilter) FilterRequest(ctx context.Context, req *mcp.Request) (*mcp.Request, *mcp.Error) {
	if !l.enabled || req.Method != "tools/call" {
		return req, nil
	}

	var callParams struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &callParams); err != nil {
		return req, nil
	}

	maxRepeat := l.maxRepeat
	windowSeconds := l.windowSeconds
	excludeTools := l.excludeTools

	// Agent-specific overrides (ADR-0042)
	agentName := extractAgentName(ctx)
	if agentName != "" {
		l.repoMu.RLock()
		repo := l.agentRepo
		l.repoMu.RUnlock()

		if repo != nil {
			agentCfg, err := repo.GetAgentConfig(agentName)
			if err == nil && agentCfg != nil && agentCfg.LoopProtection != nil {
				if !agentCfg.LoopProtection.Enabled {
					// Loop protection is explicitly disabled for this agent
					return req, nil
				}
				if agentCfg.LoopProtection.MaxRepeat > 0 {
					maxRepeat = agentCfg.LoopProtection.MaxRepeat
				}
				if agentCfg.LoopProtection.WindowSeconds > 0 {
					windowSeconds = agentCfg.LoopProtection.WindowSeconds
				}
				if len(agentCfg.LoopProtection.ExcludeTools) > 0 {
					excludeTools = append(excludeTools, agentCfg.LoopProtection.ExcludeTools...)
				}
			}
		}
	}

	for _, ex := range excludeTools {
		if ex == callParams.Name {
			return req, nil
		}
	}

	for _, ov := range l.overrides {
		if ov.Tool == callParams.Name && ov.MaxRepeat > 0 {
			maxRepeat = ov.MaxRepeat
			break
		}
	}

	h := sha256.New()
	h.Write(callParams.Arguments)
	argsHash := hex.EncodeToString(h.Sum(nil))

	now := time.Now()
	call := ToolCall{
		Name:      callParams.Name,
		ArgsHash:  argsHash,
		Timestamp: now,
	}

	trackKey := buildTrackingKey(ctx, callParams.Name)
	window := time.Duration(windowSeconds) * time.Second
	activeCalls, err := l.store.AddAndGetToolCalls(ctx, trackKey, call, window)
	if err != nil {
		return nil, mcp.NewError(mcp.ErrInternalError, "Failed to check loop history: "+err.Error(), nil)
	}

	// Count occurrences of the same tool name with the same arguments hash in the window
	sameCallCount := 0
	for _, c := range activeCalls {
		if c.Name == call.Name && c.ArgsHash == call.ArgsHash {
			sameCallCount++
		}
	}

	if sameCallCount > maxRepeat {
		return nil, mcp.NewError(mcp.ErrLoopDetected, "Infinite loop detected: tool called repeatedly with identical parameters", nil)
	}

	return req, nil
}

// ExecuteRequest satisfies filter.SecurityFilter for unified pipeline execution.
func (l *LoopFilter) ExecuteRequest(ctx context.Context, req *mcp.Request) (*mcp.Response, error) {
	_, err := l.FilterRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

// ExecuteResponse satisfies filter.SecurityFilter for unified pipeline execution.
func (l *LoopFilter) ExecuteResponse(ctx context.Context, resp *mcp.Response) (*mcp.Response, error) {
	return resp, nil
}

// Close stops the background eviction worker on the underlying store if supported.
func (l *LoopFilter) Close() error {
	if closer, ok := l.store.(io.Closer); ok {
		return closer.Close()
	}
	if closer, ok := l.store.(interface{ Close() }); ok {
		closer.Close()
		return nil
	}
	return nil
}

// === Token-Bucket Rate Limiting Filter ===

// RateLimitFilter limits the rate of incoming tool calls per user/session.
type RateLimitFilter struct {
	enabled    bool
	maxBurst   int
	refillRate float64
	store      StateStore

	repoMu    sync.RWMutex
	agentRepo agent.Resolver
}

// NewRateLimitFilter creates a RateLimitFilter.
func NewRateLimitFilter(enabled bool, maxBurst int, refillRate float64, store StateStore) *RateLimitFilter {
	if maxBurst <= 0 {
		maxBurst = 5
	}
	if refillRate <= 0 {
		refillRate = 1.0 // 1 token per second
	}
	if store == nil {
		store = NewInMemoryStateStore()
	}
	return &RateLimitFilter{
		enabled:    enabled,
		maxBurst:   maxBurst,
		refillRate: refillRate,
		store:      store,
	}
}

// SetAgentRepository sets the agent repository for per-agent rate limit overrides.
func (r *RateLimitFilter) SetAgentRepository(repo agent.Resolver) {
	r.repoMu.Lock()
	defer r.repoMu.Unlock()
	r.agentRepo = repo
}

// AgentRepository returns the currently configured agent repository.
func (r *RateLimitFilter) AgentRepository() agent.Resolver {
	r.repoMu.RLock()
	defer r.repoMu.RUnlock()
	return r.agentRepo
}

// Name returns the identifier of the filter.
func (r *RateLimitFilter) Name() string {
	return "rate_limiting"
}

// Order returns the execution precedence in the security pipeline (OrderRateLimit = 10).
func (r *RateLimitFilter) Order() int {
	return filter.OrderRateLimit
}

// FilterRequest checks rate limits using the Token-Bucket algorithm.
func (r *RateLimitFilter) FilterRequest(ctx context.Context, req *mcp.Request) (*mcp.Request, *mcp.Error) {
	if !r.enabled || req.Method != "tools/call" {
		return req, nil
	}

	maxBurst := r.maxBurst
	refillRate := r.refillRate

	// Agent-specific overrides (ADR-0042)
	agentName := extractAgentName(ctx)
	if agentName != "" {
		r.repoMu.RLock()
		repo := r.agentRepo
		r.repoMu.RUnlock()

		if repo != nil {
			agentCfg, err := repo.GetAgentConfig(agentName)
			if err == nil && agentCfg != nil && agentCfg.RateLimit != nil {
				if agentCfg.RateLimit.MaxBurst > 0 {
					maxBurst = agentCfg.RateLimit.MaxBurst
				}
				if agentCfg.RateLimit.RefillRate > 0 {
					refillRate = agentCfg.RateLimit.RefillRate
				}
			}
		}
	}

	trackKey := buildTrackingKey(ctx, "")
	allowed, err := r.store.TakeToken(ctx, trackKey, maxBurst, refillRate)
	if err != nil {
		return nil, mcp.NewError(mcp.ErrInternalError, "Failed to check rate limit: "+err.Error(), nil)
	}

	if !allowed {
		return nil, mcp.NewError(mcp.ErrRateLimitExceeded, "Tool execution rate limit exceeded", nil)
	}

	return req, nil
}

// ExecuteRequest satisfies filter.SecurityFilter for unified pipeline execution.
func (r *RateLimitFilter) ExecuteRequest(ctx context.Context, req *mcp.Request) (*mcp.Response, error) {
	_, err := r.FilterRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

// ExecuteResponse satisfies filter.SecurityFilter for unified pipeline execution.
func (r *RateLimitFilter) ExecuteResponse(ctx context.Context, resp *mcp.Response) (*mcp.Response, error) {
	return resp, nil
}

// Close stops the background eviction worker on the underlying store if supported.
func (r *RateLimitFilter) Close() error {
	if closer, ok := r.store.(io.Closer); ok {
		return closer.Close()
	}
	if closer, ok := r.store.(interface{ Close() }); ok {
		closer.Close()
		return nil
	}
	return nil
}
