package dlp

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/FaradAiLab/FaradAiWire/internal/filter/types"
)

func TestAgentFileProvider_CacheAndNegativeCache(t *testing.T) {
	tempDir := t.TempDir()
	agentDir := filepath.Join(tempDir, "AgentAlpha", "current")
	if err := os.MkdirAll(agentDir, 0755); err != nil {
		t.Fatalf("failed to create agent dir: %v", err)
	}

	dlpFile := filepath.Join(agentDir, "dlp.json")
	payload := `{"enabled": true, "patterns": [{"name": "secret", "regex": "API_KEY_[A-Z0-9]+", "action": "mask"}]}`
	if err := os.WriteFile(dlpFile, []byte(payload), 0644); err != nil {
		t.Fatalf("failed to write dlp file: %v", err)
	}

	baselinePattern := CompiledPattern{
		Name:   "baseline-secret",
		Regex:  regexp.MustCompile(`BASELINE_[0-9]+`),
		Action: ActionMask,
	}

	provider := NewAgentFileProvider(true, nil, []CompiledPattern{baselinePattern}, tempDir)

	ctxAlpha := context.WithValue(context.Background(), types.AgentNameContextKey, "AgentAlpha")
	ctxBeta := context.WithValue(context.Background(), types.AgentNameContextKey, "AgentBetaNoDLP")

	// 1. First resolution for AgentAlpha: cold-path loads from disk
	rulesAlpha1 := provider.ResolveRules(ctxAlpha)
	if !rulesAlpha1.Enabled || len(rulesAlpha1.Patterns) != 1 || rulesAlpha1.Patterns[0].Name != "secret" {
		t.Fatalf("expected AgentAlpha custom rules, got %+v", rulesAlpha1)
	}

	// 2. Second resolution for AgentAlpha: in-memory hot-path cache hit
	rulesAlpha2 := provider.ResolveRules(ctxAlpha)
	if !rulesAlpha2.Enabled || len(rulesAlpha2.Patterns) != 1 || rulesAlpha2.Patterns[0].Name != "secret" {
		t.Fatalf("expected cached AgentAlpha rules, got %+v", rulesAlpha2)
	}

	// 3. Resolution for AgentBeta (no dlp.json exists): falls back to baseline & populates negative cache
	rulesBeta1 := provider.ResolveRules(ctxBeta)
	if !rulesBeta1.Enabled || len(rulesBeta1.Patterns) != 1 || rulesBeta1.Patterns[0].Name != "baseline-secret" {
		t.Fatalf("expected baseline rules for AgentBeta, got %+v", rulesBeta1)
	}

	// 4. Second resolution for AgentBeta: hits negative cache immediately without file lookups
	rulesBeta2 := provider.ResolveRules(ctxBeta)
	if !rulesBeta2.Enabled || len(rulesBeta2.Patterns) != 1 || rulesBeta2.Patterns[0].Name != "baseline-secret" {
		t.Fatalf("expected cached negative baseline rules for AgentBeta, got %+v", rulesBeta2)
	}

	// 5. Update AgentAlpha dlp.json and test event-driven Reload
	newPayload := `{"enabled": true, "patterns": [{"name": "secret-v2", "regex": "SECRET_V2_[A-Z0-9]+", "action": "block"}]}`
	if err := os.WriteFile(dlpFile, []byte(newPayload), 0644); err != nil {
		t.Fatalf("failed to rewrite dlp file: %v", err)
	}

	// Before reload, hot path still returns cached V1 rules
	rulesAlphaPre := provider.ResolveRules(ctxAlpha)
	if rulesAlphaPre.Patterns[0].Name != "secret" {
		t.Fatalf("expected cached V1 rules prior to reload, got %s", rulesAlphaPre.Patterns[0].Name)
	}

	// Trigger event-driven reload
	provider.Reload("AgentAlpha")

	// After reload, returns V2 rules
	rulesAlphaPost := provider.ResolveRules(ctxAlpha)
	if len(rulesAlphaPost.Patterns) != 1 || rulesAlphaPost.Patterns[0].Name != "secret-v2" {
		t.Fatalf("expected reloaded V2 rules, got %+v", rulesAlphaPost)
	}
}

func TestAgentFileProvider_PathTraversalProtection(t *testing.T) {
	tempDir := t.TempDir()
	provider := NewAgentFileProvider(true, nil, nil, tempDir)

	traversalNames := []string{
		"../etc/passwd",
		"../../malicious",
		"/absolute/path",
		"agent/../../../root",
	}

	for _, name := range traversalNames {
		ctx := context.WithValue(context.Background(), types.AgentNameContextKey, name)
		rules := provider.ResolveRules(ctx)
		// Should safely fall back to baseline rules without panicking or traversing
		if len(rules.Patterns) != 0 {
			t.Errorf("expected empty baseline rules for traversal attempt %q", name)
		}
	}
}

func BenchmarkAgentFileProvider_ResolveRules(b *testing.B) {
	tempDir := b.TempDir()
	agentDir := filepath.Join(tempDir, "BenchAgent", "current")
	_ = os.MkdirAll(agentDir, 0755)

	dlpFile := filepath.Join(agentDir, "dlp.json")
	payload := `{"enabled": true, "patterns": [{"name": "secret", "regex": "KEY_[0-9]+", "action": "mask"}]}`
	_ = os.WriteFile(dlpFile, []byte(payload), 0644)

	provider := NewAgentFileProvider(true, nil, nil, tempDir)
	ctx := context.WithValue(context.Background(), types.AgentNameContextKey, "BenchAgent")

	// Prime the cache
	_ = provider.ResolveRules(ctx)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		rules := provider.ResolveRules(ctx)
		if !rules.Enabled {
			b.Fatal("unexpected disabled rules")
		}
	}
}
