package adaptive_test

import (
	"testing"

	"github.com/FaradAiLab/FaradAiWire/internal/filter/adaptive"
)

func TestAdaptiveRouter_Classification(t *testing.T) {
	fastPatterns := []string{"get_*", "list_*", "read_*", "search_*", "exact_fast_tool", "*_query", "fetch_v[0-9]"}
	deepPatterns := []string{"delete_*", "execute_*", "write_*", "exact_deep_tool", "*_danger", "exec_v[0-9]"}

	router := adaptive.NewRouter(true, "deep", fastPatterns, deepPatterns)

	tests := []struct {
		name     string
		toolName string
		expected adaptive.PathType
	}{
		// Prefix matching (Fast Path)
		{"fast prefix get", "get_user", adaptive.PathFast},
		{"fast prefix list", "list_repositories", adaptive.PathFast},
		{"fast prefix read", "read_file", adaptive.PathFast},
		{"fast prefix search", "search_documents", adaptive.PathFast},

		// Prefix matching (Deep Path)
		{"deep prefix delete", "delete_user", adaptive.PathDeep},
		{"deep prefix execute", "execute_command", adaptive.PathDeep},
		{"deep prefix write", "write_database", adaptive.PathDeep},

		// Exact matching
		{"exact fast tool", "exact_fast_tool", adaptive.PathFast},
		{"exact deep tool", "exact_deep_tool", adaptive.PathDeep},

		// Suffix matching
		{"suffix fast query", "document_query", adaptive.PathFast},
		{"suffix deep danger", "nuclear_danger", adaptive.PathDeep},

		// Wildcard matching with character class
		{"wildcard fast v1", "fetch_v1", adaptive.PathFast},
		{"wildcard deep v2", "exec_v2", adaptive.PathDeep},

		// Case insensitivity
		{"case insensitive GET", "GET_USER", adaptive.PathFast},
		{"case insensitive DELETE", "DELETE_ACCOUNT", adaptive.PathDeep},

		// Cross-platform Windows-style backslash normalization
		{"windows path get", `github\get_issues`, adaptive.PathDeep}, // Not matching get_* directly due to namespace prefix unless namespaced
		{"posix namespaced delete", "db/delete_record", adaptive.PathDeep},

		// Safety precedence: deep patterns have priority over fast patterns if both match
		{"unknown fallback to default deep", "unknown_tool_xyz", adaptive.PathDeep},
		{"empty tool name defaults to deep", "", adaptive.PathDeep},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := router.Classify(tt.toolName)
			if got != tt.expected {
				t.Errorf("Classify(%q) = %v, want %v", tt.toolName, got, tt.expected)
			}
		})
	}
}

func TestAdaptiveRouter_SafetyPrecedence(t *testing.T) {
	// A tool matching both deep and fast pattern must ALWAYS classify as Deep-Path (Zero Trust)
	fastPatterns := []string{"dangerous_*"}
	deepPatterns := []string{"dangerous_delete_*"}

	router := adaptive.NewRouter(true, "fast", fastPatterns, deepPatterns)

	if got := router.Classify("dangerous_delete_database"); got != adaptive.PathDeep {
		t.Fatalf("expected Deep-Path precedence for dangerous tool, got %v", got)
	}
	if got := router.Classify("dangerous_read_only"); got != adaptive.PathFast {
		t.Fatalf("expected Fast-Path for non-deep tool, got %v", got)
	}
}

func TestAdaptiveRouter_NilAndDisabledSafety(t *testing.T) {
	var nilRouter *adaptive.Router
	if nilRouter.IsEnabled() {
		t.Errorf("nil router should not be enabled")
	}
	if nilRouter.Classify("get_user") != adaptive.PathDeep {
		t.Errorf("nil router must safely return PathDeep")
	}

	disabledRouter := adaptive.NewRouter(false, "fast", []string{"get_*"}, nil)
	if disabledRouter.IsEnabled() {
		t.Errorf("disabled router should return false for IsEnabled")
	}
	if disabledRouter.Classify("get_user") != adaptive.PathDeep {
		t.Errorf("disabled router must return PathDeep for safety")
	}
}

func TestAdaptiveRouter_DisabledFallback(t *testing.T) {
	router := adaptive.NewRouter(false, "deep", nil, nil)
	if router.Classify("get_user") != adaptive.PathDeep {
		t.Errorf("Expected disabled router to default to DEEP_PATH")
	}
}

func TestAdaptiveRouter_FilterExecutionSelection(t *testing.T) {
	router := adaptive.NewRouter(true, "deep", nil, nil)

	// Fast-path should skip heavy SLM injection scanner and HITL, but execute in-memory dlp (SEC-017 / DEC-05)
	if router.ShouldExecuteFilter("injection_scanner", adaptive.PathFast) {
		t.Errorf("Expected injection_scanner to be skipped in Fast-Path")
	}
	if !router.ShouldExecuteFilter("dlp", adaptive.PathFast) {
		t.Errorf("Expected dlp to run in Fast-Path")
	}
	if router.ShouldExecuteFilter("hitl", adaptive.PathFast) {
		t.Errorf("Expected hitl to be skipped in Fast-Path")
	}

	// Fast-path should run in-memory filters (Prefill, RateLimit, LoopProtection, Schema, DLP)
	for _, expectedFilter := range []string{"prefill_block", "rate_limiting", "loop_protection", "schema_validation", "dlp"} {
		if !router.ShouldExecuteFilter(expectedFilter, adaptive.PathFast) {
			t.Errorf("Expected %s to run in Fast-Path", expectedFilter)
		}
	}

	// Deep-path should run everything
	if !router.ShouldExecuteFilter("injection_scanner", adaptive.PathDeep) {
		t.Errorf("Expected injection_scanner to run in Deep-Path")
	}
	if !router.ShouldExecuteFilter("dlp", adaptive.PathDeep) {
		t.Errorf("Expected dlp to run in Deep-Path")
	}
	if !router.ShouldExecuteFilter("hitl", adaptive.PathDeep) {
		t.Errorf("Expected hitl to run in Deep-Path")
	}
}

func BenchmarkAdaptiveRouter_ClassificationAndFilterCheck(b *testing.B) {
	router := adaptive.NewRouter(true, "deep", nil, nil)
	tool := "get_user_profile"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		path := router.Classify(tool)
		_ = router.ShouldExecuteFilter("dlp", path)
		_ = router.ShouldExecuteFilter("injection_scanner", path)
	}
}

