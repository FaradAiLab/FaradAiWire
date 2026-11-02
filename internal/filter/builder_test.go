package filter_test

import (
	"context"
	"testing"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
)

type mockCustomFilter struct {
	filter.BaseSecurityFilter
	name  string
	order int
}

func (m *mockCustomFilter) Name() string { return m.name }
func (m *mockCustomFilter) Order() int  { return m.order }

func TestBuildPipeline_NilConfig(t *testing.T) {
	_, _, err := filter.BuildPipeline(nil, nil)
	if err == nil {
		t.Fatal("expected error when passing nil config, got nil")
	}
}

func TestBuildPipeline_EmptyConfig(t *testing.T) {
	cfg := &config.Config{}
	logger := &mockAuditLogger{}

	pipeline, router, err := filter.BuildPipeline(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error building empty pipeline: %v", err)
	}
	if pipeline == nil {
		t.Fatal("expected non-nil pipeline")
	}
	if router == nil {
		t.Fatal("expected non-nil router")
	}
	if len(pipeline.GetFilters()) != 0 {
		t.Errorf("expected 0 filters for empty config, got %d", len(pipeline.GetFilters()))
	}
}

func TestBuildPipeline_CanonicalOrdering(t *testing.T) {
	cfg := &config.Config{
		AgentsDir: t.TempDir(),
		Filters: config.FiltersConfig{
			Adaptive: config.AdaptiveConfig{
				Enabled:       true,
				DefaultPath:   "deep",
				FastPathTools: []string{"ping"},
			},
			PrefillBlock: config.PrefillBlockConfig{
				Enabled: true,
			},
			RateLimiting: config.RateLimitingConfig{
				Enabled:    true,
				MaxBurst:   10,
				RefillRate: 1.0,
			},
			LoopProtection: config.LoopProtectionConfig{
				Enabled:       true,
				MaxRepeat:     3,
				WindowSeconds: 10,
			},
			SchemaValidation: config.SchemaValidationConfig{
				Enabled: true,
			},
			DLP: config.DLPConfig{
				Enabled: true,
				Patterns: []config.DLPPattern{
					{Name: "email", Regex: `\w+@\w+\.\w+`, Action: "mask"},
				},
			},
			Guard: config.GuardConfig{
				Enabled: true,
			},
			HITL: config.HITLConfig{
				Enabled:          true,
				DestructiveTools: []string{"delete"},
				ApprovalMode:     "cli",
			},
		},
	}

	logger := &mockAuditLogger{}
	pipeline, router, err := filter.BuildPipeline(cfg, logger)
	if err != nil {
		t.Fatalf("failed to build full pipeline: %v", err)
	}

	if router == nil || !router.IsEnabled() {
		t.Error("expected router to be enabled")
	}

	filters := pipeline.GetFilters()
	expectedOrder := []string{
		"prefill_block",
		"rate_limiting",
		"loop_protection",
		"schema_validation",
		"dlp",
		"guard",
		"hitl",
	}

	if len(filters) != len(expectedOrder) {
		t.Fatalf("expected %d filters, got %d", len(expectedOrder), len(filters))
	}

	for i, expectedName := range expectedOrder {
		if filters[i].Name() != expectedName {
			t.Errorf("at index %d: expected filter '%s', got '%s'", i, expectedName, filters[i].Name())
		}
	}
}

func TestPipeline_RegisterFilter_StrictOrdering(t *testing.T) {
	p := filter.NewPipeline(nil)

	// Register filters out of order
	f50 := &mockCustomFilter{name: "dlp", order: 50}
	f10 := &mockCustomFilter{name: "rate_limiting", order: 10}
	f70 := &mockCustomFilter{name: "hitl", order: 70}
	f20 := &mockCustomFilter{name: "enterprise_opa", order: 20}
	f5 := &mockCustomFilter{name: "prefill", order: 5}

	p.RegisterFilter(f50)
	p.RegisterFilter(f10)
	p.RegisterFilter(f70)
	p.RegisterFilter(f20)
	p.RegisterFilter(f5)

	filters := p.GetFilters()
	expected := []string{"prefill", "rate_limiting", "enterprise_opa", "dlp", "hitl"}
	if len(filters) != len(expected) {
		t.Fatalf("expected %d filters, got %d", len(expected), len(filters))
	}

	for i, name := range expected {
		if filters[i].Name() != name {
			t.Errorf("at index %d: expected '%s', got '%s'", i, name, filters[i].Name())
		}
	}
}

func TestPipeline_SecurityFilterExecution(t *testing.T) {
	p := filter.NewPipeline(nil)

	// Filter that blocks
	blockingFilter := &customBlockFilter{name: "custom_block", order: 25}
	p.RegisterFilter(blockingFilter)

	req := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  []byte(`{"name":"forbidden_tool"}`),
	}

	_, err := p.ProcessRequest(context.Background(), req)
	if err == nil {
		t.Fatal("expected request to be blocked by custom SecurityFilter")
	}
}

type customBlockFilter struct {
	filter.BaseSecurityFilter
	name  string
	order int
}

func (c *customBlockFilter) Name() string { return c.name }
func (c *customBlockFilter) Order() int  { return c.order }
func (c *customBlockFilter) ExecuteRequest(ctx context.Context, req *mcp.Request) (*mcp.Response, error) {
	return nil, mcp.NewError(mcp.ErrPolicyDenied, "blocked by enterprise policy", nil)
}

func TestBuildPipeline_CanonicalOrdering_WithGuard(t *testing.T) {
	cfg := &config.Config{
		AgentsDir: t.TempDir(),
		Filters: config.FiltersConfig{
			DLP: config.DLPConfig{
				Enabled: true,
				Patterns: []config.DLPPattern{
					{Name: "test", Regex: `test`, Action: "mask"},
				},
			},
			Guard: config.GuardConfig{
				Enabled: true,
			},
		},
	}

	pipeline, _, err := filter.BuildPipeline(cfg, &mockAuditLogger{})
	if err != nil {
		t.Fatalf("failed to build pipeline: %v", err)
	}

	filters := pipeline.GetFilters()
	expected := []string{"dlp", "guard"}
	if len(filters) != len(expected) {
		t.Fatalf("expected %d filters, got %d", len(expected), len(filters))
	}

	for i, name := range expected {
		if filters[i].Name() != name {
			t.Errorf("at index %d: expected filter '%s', got '%s'", i, name, filters[i].Name())
		}
	}

	guardFilter := pipeline.GetFilter("guard")
	if guardFilter == nil {
		t.Fatal("expected pipeline.GetFilter(\"guard\") to return guard filter")
	}
	if of, ok := guardFilter.(filter.OrderedFilter); !ok || of.Order() != 55 {
		t.Errorf("expected guard filter order to be 55, got %v", guardFilter)
	}
}
