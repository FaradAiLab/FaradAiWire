package limit

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/types"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
)

func makeTestToolCallRequest(toolName string, args map[string]interface{}) *mcp.Request {
	params, _ := json.Marshal(map[string]interface{}{
		"name":      toolName,
		"arguments": args,
	})
	return &mcp.Request{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  params,
	}
}

func TestRateLimitFilter_BasicRateLimiting(t *testing.T) {
	store := NewInMemoryStateStore(WithDisableBackgroundWorker())
	defer store.Close()

	rateLimiter := NewRateLimitFilter(true, 2, 1.0, store)

	ctx := context.Background()
	req := makeTestToolCallRequest("query_db", map[string]interface{}{"q": "SELECT 1"})

	// Call 1: Allowed (1 token remaining)
	filtered, mcpErr := rateLimiter.FilterRequest(ctx, req)
	if mcpErr != nil || filtered == nil {
		t.Fatalf("expected request 1 to be allowed, got err: %v", mcpErr)
	}

	// Call 2: Allowed (0 tokens remaining)
	filtered, mcpErr = rateLimiter.FilterRequest(ctx, req)
	if mcpErr != nil || filtered == nil {
		t.Fatalf("expected request 2 to be allowed, got err: %v", mcpErr)
	}

	// Call 3: Blocked (Burst exceeded)
	filtered, mcpErr = rateLimiter.FilterRequest(ctx, req)
	if mcpErr == nil || mcpErr.Code != mcp.ErrRateLimitExceeded {
		t.Fatalf("expected ErrRateLimitExceeded (%d), got: %v", mcp.ErrRateLimitExceeded, mcpErr)
	}
	if filtered != nil {
		t.Fatalf("expected filtered request to be nil on rate limit block")
	}
}

func TestRateLimitFilter_UserIsolation(t *testing.T) {
	store := NewInMemoryStateStore(WithDisableBackgroundWorker())
	defer store.Close()

	rateLimiter := NewRateLimitFilter(true, 1, 1.0, store)

	ctxAlice := context.WithValue(context.Background(), types.UserContextKey, &types.UserContext{UserID: "alice"})
	ctxBob := context.WithValue(context.Background(), types.UserContextKey, &types.UserContext{UserID: "bob"})

	req := makeTestToolCallRequest("query_db", map[string]interface{}{"q": "SELECT 1"})

	// Alice consumes her 1 token
	_, mcpErr := rateLimiter.FilterRequest(ctxAlice, req)
	if mcpErr != nil {
		t.Fatalf("expected alice to succeed: %v", mcpErr)
	}

	// Alice second request is blocked
	_, mcpErr = rateLimiter.FilterRequest(ctxAlice, req)
	if mcpErr == nil || mcpErr.Code != mcp.ErrRateLimitExceeded {
		t.Fatalf("expected alice second request to be blocked")
	}

	// Bob's request should still succeed because buckets are isolated per user
	_, mcpErr = rateLimiter.FilterRequest(ctxBob, req)
	if mcpErr != nil {
		t.Fatalf("expected bob to succeed independently: %v", mcpErr)
	}
}

func TestRateLimitFilter_PassthroughNonToolCalls(t *testing.T) {
	rateLimiter := NewRateLimitFilter(true, 1, 1.0, nil)

	req := &mcp.Request{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/list",
	}

	filtered, mcpErr := rateLimiter.FilterRequest(context.Background(), req)
	if mcpErr != nil || filtered != req {
		t.Fatalf("expected tools/list to pass through untouched")
	}
}

func TestLoopFilter_RepetitiveCallDetection(t *testing.T) {
	store := NewInMemoryStateStore(WithDisableBackgroundWorker())
	defer store.Close()

	// maxRepeat = 2 calls allowed within 10s window (3rd identical call triggers loop detection)
	loopFilter := NewLoopFilter(true, 2, 10, nil, nil, store)

	ctx := context.Background()
	req := makeTestToolCallRequest("fetch_api", map[string]interface{}{"endpoint": "/users"})

	// Call 1: Allowed
	_, mcpErr := loopFilter.FilterRequest(ctx, req)
	if mcpErr != nil {
		t.Fatalf("call 1 should be allowed: %v", mcpErr)
	}

	// Call 2: Allowed
	_, mcpErr = loopFilter.FilterRequest(ctx, req)
	if mcpErr != nil {
		t.Fatalf("call 2 should be allowed: %v", mcpErr)
	}

	// Call 3: Blocked (exceeds maxRepeat 2)
	_, mcpErr = loopFilter.FilterRequest(ctx, req)
	if mcpErr == nil || mcpErr.Code != mcp.ErrLoopDetected {
		t.Fatalf("expected ErrLoopDetected (%d), got: %v", mcp.ErrLoopDetected, mcpErr)
	}
}

func TestLoopFilter_ExcludedToolsAndOverrides(t *testing.T) {
	store := NewInMemoryStateStore(WithDisableBackgroundWorker())
	defer store.Close()

	excludeTools := []string{"safe_poll"}
	overrides := []config.LoopToolOverride{
		{Tool: "custom_loop", MaxRepeat: 4},
	}

	loopFilter := NewLoopFilter(true, 2, 10, excludeTools, overrides, store)
	ctx := context.Background()

	// 1. Test Excluded Tool bypasses loop filter even when called 5 times
	for i := 0; i < 5; i++ {
		req := makeTestToolCallRequest("safe_poll", map[string]interface{}{"status": "ping"})
		_, mcpErr := loopFilter.FilterRequest(ctx, req)
		if mcpErr != nil {
			t.Fatalf("excluded tool should never be blocked at iteration %d: %v", i+1, mcpErr)
		}
	}

	// 2. Test Tool-Specific Override (allowed up to 4 times, 5th blocked)
	for i := 0; i < 4; i++ {
		// Same arguments to test loop detection:
		reqSameArgs := makeTestToolCallRequest("custom_loop", map[string]interface{}{"fixed": "val"})
		_, mcpErr := loopFilter.FilterRequest(ctx, reqSameArgs)
		if mcpErr != nil {
			t.Fatalf("override tool call %d should be allowed: %v", i+1, mcpErr)
		}
	}

	// 5th call to custom_loop with same args should be blocked (maxRepeat = 4)
	req5 := makeTestToolCallRequest("custom_loop", map[string]interface{}{"fixed": "val"})
	_, mcpErr := loopFilter.FilterRequest(ctx, req5)
	if mcpErr == nil || mcpErr.Code != mcp.ErrLoopDetected {
		t.Fatalf("expected 5th call to override tool to be blocked with ErrLoopDetected, got: %v", mcpErr)
	}
}

func TestRateLimitFilter_MultiAgentIsolation(t *testing.T) {
	store := NewInMemoryStateStore(WithDisableBackgroundWorker())
	defer store.Close()

	rateLimiter := NewRateLimitFilter(true, 1, 1.0, store)

	ctxAgentA := context.WithValue(context.Background(), types.UserContextKey, &types.UserContext{UserID: "alice"})
	ctxAgentA = context.WithValue(ctxAgentA, types.AgentNameContextKey, "agent-a")

	ctxAgentB := context.WithValue(context.Background(), types.UserContextKey, &types.UserContext{UserID: "alice"})
	ctxAgentB = context.WithValue(ctxAgentB, types.AgentNameContextKey, "agent-b")

	req := makeTestToolCallRequest("query_db", map[string]interface{}{"q": "SELECT 1"})

	// Alice on Agent A uses her 1 token
	_, errA1 := rateLimiter.FilterRequest(ctxAgentA, req)
	if errA1 != nil {
		t.Fatalf("expected alice on agent-a to succeed: %v", errA1)
	}

	// Alice second request on Agent A is blocked
	_, errA2 := rateLimiter.FilterRequest(ctxAgentA, req)
	if errA2 == nil || errA2.Code != mcp.ErrRateLimitExceeded {
		t.Fatalf("expected alice second request on agent-a to be blocked")
	}

	// Alice on Agent B should succeed because token bucket is isolated per agent
	_, errB1 := rateLimiter.FilterRequest(ctxAgentB, req)
	if errB1 != nil {
		t.Fatalf("expected alice on agent-b to succeed independently: %v", errB1)
	}
}

func TestLoopFilter_MultiAgentIsolation(t *testing.T) {
	store := NewInMemoryStateStore(WithDisableBackgroundWorker())
	defer store.Close()

	// maxRepeat = 2 calls allowed within 10s window
	loopFilter := NewLoopFilter(true, 2, 10, nil, nil, store)

	ctxAgentA := context.WithValue(context.Background(), types.UserContextKey, &types.UserContext{UserID: "alice"})
	ctxAgentA = context.WithValue(ctxAgentA, types.AgentNameContextKey, "agent-a")

	ctxAgentB := context.WithValue(context.Background(), types.UserContextKey, &types.UserContext{UserID: "alice"})
	ctxAgentB = context.WithValue(ctxAgentB, types.AgentNameContextKey, "agent-b")

	req := makeTestToolCallRequest("fetch_data", map[string]interface{}{"param": "123"})

	// Call 1 & 2 on Agent A: Allowed
	loopFilter.FilterRequest(ctxAgentA, req)
	loopFilter.FilterRequest(ctxAgentA, req)

	// Call 3 on Agent A: Blocked
	_, errA3 := loopFilter.FilterRequest(ctxAgentA, req)
	if errA3 == nil || errA3.Code != mcp.ErrLoopDetected {
		t.Fatalf("expected loop detection on agent-a")
	}

	// Call 1 on Agent B with same user & arguments: Allowed (independent history)
	_, errB1 := loopFilter.FilterRequest(ctxAgentB, req)
	if errB1 != nil {
		t.Fatalf("expected agent-b to succeed without being affected by agent-a: %v", errB1)
	}
}

type mockAgentRepo struct {
	agent.Repository
	configs map[string]*agent.RouteConfig
}

func (m *mockAgentRepo) GetAgentConfig(name string) (*agent.RouteConfig, error) {
	if cfg, ok := m.configs[name]; ok {
		return cfg, nil
	}
	return nil, nil
}

func TestLoopFilter_AlwaysEnforced_CannotBypassWithoutExclude(t *testing.T) {
	store := NewInMemoryStateStore(WithDisableBackgroundWorker())
	defer store.Close()

	loopFilter := NewLoopFilter(true, 2, 10, nil, nil, store)
	repo := &mockAgentRepo{
		configs: map[string]*agent.RouteConfig{
			"strict-agent": {
				AgentName: "strict-agent",
				LoopProtection: &agent.LoopProtectionOverride{
					MaxRepeat:     2,
					WindowSeconds: 10,
				},
			},
		},
	}
	loopFilter.SetAgentRepository(repo)

	ctx := context.WithValue(context.Background(), types.AgentNameContextKey, "strict-agent")
	req := makeTestToolCallRequest("batch_process", map[string]interface{}{"id": 100})

	// Calls 1 and 2 allowed
	_, err1 := loopFilter.FilterRequest(ctx, req)
	if err1 != nil {
		t.Fatalf("call 1 failed: %v", err1)
	}
	_, err2 := loopFilter.FilterRequest(ctx, req)
	if err2 != nil {
		t.Fatalf("call 2 failed: %v", err2)
	}

	// Call 3 MUST be blocked by loop protection (cannot be bypassed at agent level)
	_, err3 := loopFilter.FilterRequest(ctx, req)
	if err3 == nil || err3.Code != mcp.ErrLoopDetected {
		t.Fatalf("expected ErrLoopDetected on 3rd identical call, got: %v", err3)
	}
}

func TestLoopFilter_AgentOverride_CustomThresholds(t *testing.T) {
	store := NewInMemoryStateStore(WithDisableBackgroundWorker())
	defer store.Close()

	// Global maxRepeat is 2
	loopFilter := NewLoopFilter(true, 2, 10, nil, nil, store)
	repo := &mockAgentRepo{
		configs: map[string]*agent.RouteConfig{
			"custom-agent": {
				AgentName: "custom-agent",
				LoopProtection: &agent.LoopProtectionOverride{
					MaxRepeat:     4,
					WindowSeconds: 20,
				},
			},
		},
	}
	loopFilter.SetAgentRepository(repo)

	ctx := context.WithValue(context.Background(), types.AgentNameContextKey, "custom-agent")
	req := makeTestToolCallRequest("query_db", map[string]interface{}{"table": "users"})

	// Calls 1..4 should succeed (MaxRepeat: 4)
	for i := 1; i <= 4; i++ {
		_, err := loopFilter.FilterRequest(ctx, req)
		if err != nil {
			t.Fatalf("call %d should succeed under maxRepeat=4, got: %v", i, err)
		}
	}

	// Call 5 should be blocked
	_, err := loopFilter.FilterRequest(ctx, req)
	if err == nil || err.Code != mcp.ErrLoopDetected {
		t.Fatalf("expected call 5 to be blocked with ErrLoopDetected, got: %v", err)
	}
}

func TestLoopFilter_AgentOverride_ExcludeTools(t *testing.T) {
	store := NewInMemoryStateStore(WithDisableBackgroundWorker())
	defer store.Close()

	loopFilter := NewLoopFilter(true, 1, 10, nil, nil, store)
	repo := &mockAgentRepo{
		configs: map[string]*agent.RouteConfig{
			"excluded-agent": {
				AgentName: "excluded-agent",
				LoopProtection: &agent.LoopProtectionOverride{
					MaxRepeat:    1,
					ExcludeTools: []string{"ping_health"},
				},
			},
		},
	}
	loopFilter.SetAgentRepository(repo)

	ctx := context.WithValue(context.Background(), types.AgentNameContextKey, "excluded-agent")
	reqPing := makeTestToolCallRequest("ping_health", map[string]interface{}{"target": "all"})

	// Excluded tool should not be blocked even after 5 identical calls
	for i := 1; i <= 5; i++ {
		_, err := loopFilter.FilterRequest(ctx, reqPing)
		if err != nil {
			t.Fatalf("excluded tool ping_health failed on call %d: %v", i, err)
		}
	}

	// Non-excluded tool should be blocked on 2nd call
	reqNormal := makeTestToolCallRequest("delete_record", map[string]interface{}{"id": 42})
	_, err1 := loopFilter.FilterRequest(ctx, reqNormal)
	if err1 != nil {
		t.Fatalf("call 1 of delete_record should succeed: %v", err1)
	}
	_, err2 := loopFilter.FilterRequest(ctx, reqNormal)
	if err2 == nil || err2.Code != mcp.ErrLoopDetected {
		t.Fatalf("call 2 of delete_record should be blocked: %v", err2)
	}
}

func TestRateLimitFilter_AgentOverride(t *testing.T) {
	store := NewInMemoryStateStore(WithDisableBackgroundWorker())
	defer store.Close()

	// Default limiter has maxBurst = 1
	rateLimiter := NewRateLimitFilter(true, 1, 0.1, store)
	repo := &mockAgentRepo{
		configs: map[string]*agent.RouteConfig{
			"high-traffic-agent": {
				AgentName: "high-traffic-agent",
				RateLimit: &agent.RateLimitOverride{
					MaxBurst:   3,
					RefillRate: 1.0,
				},
			},
		},
	}
	rateLimiter.SetAgentRepository(repo)

	ctx := context.WithValue(context.Background(), types.AgentNameContextKey, "high-traffic-agent")
	req := makeTestToolCallRequest("query", map[string]interface{}{"q": "fast"})

	// Call 1, 2, 3 should succeed because agent has MaxBurst = 3
	for i := 1; i <= 3; i++ {
		_, err := rateLimiter.FilterRequest(ctx, req)
		if err != nil {
			t.Fatalf("call %d should succeed under MaxBurst=3, got: %v", i, err)
		}
	}

	// Call 4 should be rate limited
	_, err := rateLimiter.FilterRequest(ctx, req)
	if err == nil || err.Code != mcp.ErrRateLimitExceeded {
		t.Fatalf("expected call 4 to be rate limited, got: %v", err)
	}
}

func TestRateLimitFilter_AlwaysEnforced_CannotBypass(t *testing.T) {
	store := NewInMemoryStateStore(WithDisableBackgroundWorker())
	defer store.Close()

	// Global rate limiter has MaxBurst = 1
	rateLimiter := NewRateLimitFilter(true, 1, 0.1, store)
	repo := &mockAgentRepo{
		configs: map[string]*agent.RouteConfig{
			"custom-burst-agent": {
				AgentName: "custom-burst-agent",
				RateLimit: &agent.RateLimitOverride{
					MaxBurst:   2,
					RefillRate: 0.1,
				},
			},
		},
	}
	rateLimiter.SetAgentRepository(repo)

	ctx := context.WithValue(context.Background(), types.AgentNameContextKey, "custom-burst-agent")
	req := makeTestToolCallRequest("batch_task", map[string]interface{}{"idx": 42})

	// Calls 1 and 2 succeed (burst allowance: 2)
	for i := 1; i <= 2; i++ {
		_, err := rateLimiter.FilterRequest(ctx, req)
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
	}

	// Call 3 MUST be rate limited (rate limiting cannot be bypassed at agent level)
	_, err := rateLimiter.FilterRequest(ctx, req)
	if err == nil || err.Code != mcp.ErrRateLimitExceeded {
		t.Fatalf("expected call 3 to be rate limited with ErrRateLimitExceeded, got: %v", err)
	}
}

func BenchmarkLoopFilter_FilterRequest(b *testing.B) {
	store := NewInMemoryStateStore(WithDisableBackgroundWorker())
	defer store.Close()

	loopFilter := NewLoopFilter(true, 1000000, 60, nil, nil, store)
	ctx := context.WithValue(context.Background(), types.AgentNameContextKey, "bench-agent")
	req := makeTestToolCallRequest("calculate_metric", map[string]interface{}{"value": 42})

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = loopFilter.FilterRequest(ctx, req)
	}
}

func BenchmarkRateLimitFilter_FilterRequest(b *testing.B) {
	store := NewInMemoryStateStore(WithDisableBackgroundWorker())
	defer store.Close()

	rateLimiter := NewRateLimitFilter(true, 1000000, 1000000.0, store)
	ctx := context.WithValue(context.Background(), types.AgentNameContextKey, "bench-agent")
	req := makeTestToolCallRequest("calculate_metric", map[string]interface{}{"value": 42})

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = rateLimiter.FilterRequest(ctx, req)
	}
}

