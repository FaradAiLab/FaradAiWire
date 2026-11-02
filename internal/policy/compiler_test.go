package policy

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

type mockReloader struct {
	mu           sync.Mutex
	reloadedList []string
}

func (m *mockReloader) Reload(agentName string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reloadedList = append(m.reloadedList, agentName)
}

func (m *mockReloader) GetReloaded() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	copied := make([]string, len(m.reloadedList))
	copy(copied, m.reloadedList)
	return copied
}

func TestCompiler_MultiPackAndPrecedence(t *testing.T) {
	store := setupTestStore(t)
	ctx := context.Background()

	// 1. Create shared rule with different actions across two packs
	r1A := DlpPatternRule{
		ID:            "rule:conflict-1",
		Name:          "Conflict Rule 1",
		Category:      "test",
		Regex:         `\bCONF-1\b`,
		DefaultAction: ActionMask,
	}
	r2A := DlpPatternRule{
		ID:            "rule:conflict-2",
		Name:          "Conflict Rule 2",
		Category:      "test",
		Regex:         `\bCONF-2\b`,
		DefaultAction: ActionAudit,
	}
	r3A := DlpPatternRule{
		ID:            "rule:unique-a",
		Name:          "Unique A",
		Category:      "test",
		Regex:         `\bUNIQUE-A\b`,
		DefaultAction: ActionMask,
	}

	if err := store.CreateRule(ctx, &r1A); err != nil {
		t.Fatalf("create r1 failed: %v", err)
	}
	if err := store.CreateRule(ctx, &r2A); err != nil {
		t.Fatalf("create r2 failed: %v", err)
	}
	if err := store.CreateRule(ctx, &r3A); err != nil {
		t.Fatalf("create r3 failed: %v", err)
	}

	packA := PolicyPack{
		ID:       "pack:pack-a",
		Name:     "Pack A",
		Category: "test",
		RuleIDs:  []string{"rule:conflict-1", "rule:conflict-2", "rule:unique-a"},
	}
	if err := store.CreatePack(ctx, &packA); err != nil {
		t.Fatalf("create packA failed: %v", err)
	}

	r1B := DlpPatternRule{
		ID:            "rule:conflict-1b",
		Name:          "Conflict Rule 1",
		Category:      "test",
		Regex:         `\bCONF-1\b`,
		DefaultAction: ActionBlock,
	}
	r2B := DlpPatternRule{
		ID:            "rule:conflict-2b",
		Name:          "Conflict Rule 2",
		Category:      "test",
		Regex:         `\bCONF-2\b`,
		DefaultAction: ActionMask,
	}
	if err := store.CreateRule(ctx, &r1B); err != nil {
		t.Fatalf("create r1B failed: %v", err)
	}
	if err := store.CreateRule(ctx, &r2B); err != nil {
		t.Fatalf("create r2B failed: %v", err)
	}

	packB := PolicyPack{
		ID:       "pack:pack-b",
		Name:     "Pack B",
		Category: "test",
		RuleIDs:  []string{"rule:conflict-1b", "rule:conflict-2b"},
	}
	if err := store.CreatePack(ctx, &packB); err != nil {
		t.Fatalf("create packB failed: %v", err)
	}

	compiler := NewCompiler(store)

	cfg := AgentPolicyConfig{
		AgentName: "test-agent",
		PackIDs:   []string{"pack:pack-a", "pack:pack-b"},
	}

	compiled, err := compiler.Compile(ctx, &cfg)
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}

	if len(compiled.EffectiveRules) != 5 {
		t.Fatalf("expected 5 effective rules, got %d", len(compiled.EffectiveRules))
	}

	packC := PolicyPack{
		ID:       "pack:pack-c",
		Name:     "Pack C",
		Category: "test",
		RuleIDs:  []string{"rule:conflict-1"},
	}
	if err := store.CreatePack(ctx, &packC); err != nil {
		t.Fatalf("create packC failed: %v", err)
	}

	cfgCollide := AgentPolicyConfig{
		AgentName: "collision-agent",
		PackIDs:   []string{"pack:pack-a", "pack:pack-c"},
	}
	compiledCollide, err := compiler.Compile(ctx, &cfgCollide)
	if err != nil {
		t.Fatalf("compile collide failed: %v", err)
	}
	for _, r := range compiledCollide.EffectiveRules {
		if r.RuleID == "rule:conflict-1" {
			if len(r.SourcePackIDs) != 2 {
				t.Errorf("expected 2 source packs for rule:conflict-1, got %v", r.SourcePackIDs)
			}
		}
	}
}

func TestCompiler_AgentOverrides(t *testing.T) {
	store := setupTestStore(t)
	ctx := context.Background()

	if err := Seed(ctx, store); err != nil {
		t.Fatalf("Seed failed: %v", err)
	}

	compiler := NewCompiler(store)

	cfg := AgentPolicyConfig{
		AgentName: "finance-agent",
		PackIDs:   []string{"pack:tr-kvkk"},
		Overrides: []RuleOverride{
			{
				RuleID:  "rule:tr-phone",
				Enabled: false,
			},
			{
				RuleID:  "rule:tr-tckn",
				Action:  ActionBlock,
				Enabled: true,
			},
		},
		CustomPatterns: []CustomPattern{
			{
				Name:   "Internal Employee ID",
				Regex:  `\bEMP-[0-9]{5}\b`,
				Action: ActionMask,
			},
		},
		ToolExemptions: map[string]ToolExemption{
			"query_customer_db": {Request: true, Response: false},
		},
	}

	compiled, err := compiler.Compile(ctx, &cfg)
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}

	var phoneFound, tcknFound bool
	for _, r := range compiled.EffectiveRules {
		if r.RuleID == "rule:tr-phone" {
			phoneFound = true
			if !r.IsBypassed {
				t.Errorf("expected rule:tr-phone to be bypassed")
			}
		}
		if r.RuleID == "rule:tr-tckn" {
			tcknFound = true
			if r.EffectiveAction != ActionBlock {
				t.Errorf("expected rule:tr-tckn action to be BLOCK, got %v", r.EffectiveAction)
			}
			if !r.IsOverridden {
				t.Errorf("expected rule:tr-tckn to be marked IsOverridden")
			}
		}
	}
	if !phoneFound || !tcknFound {
		t.Fatalf("expected both phone and tckn rules in effective rules")
	}

	if len(compiled.ToolExemptions) != 1 || !compiled.ToolExemptions["query_customer_db"].Request || compiled.ToolExemptions["query_customer_db"].Response {
		t.Errorf("tool exemptions not compiled properly: %v", compiled.ToolExemptions)
	}

	payload, err := compiler.EmitPayload(compiled)
	if err != nil {
		t.Fatalf("EmitPayload failed: %v", err)
	}

	var emittedPhone, emittedTCKN, emittedCustom bool
	for _, p := range payload.Patterns {
		if p.Name == "Turkey Mobile Phone" {
			emittedPhone = true
		}
		if p.Name == "Turkey TCKN (Kimlik Numarası)" {
			emittedTCKN = true
			if p.Action != "block" {
				t.Errorf("expected emitted TCKN action to be block, got %s", p.Action)
			}
		}
		if p.Name == "Internal Employee ID" {
			emittedCustom = true
			if p.Regex != `\bEMP-[0-9]{5}\b` {
				t.Errorf("unexpected custom pattern regex: %s", p.Regex)
			}
		}
	}

	if emittedPhone {
		t.Errorf("bypassed rule 'Turkey Mobile Phone' should NOT be in emitted patterns")
	}
	if !emittedTCKN {
		t.Errorf("rule 'Turkey TCKN' must be present in emitted patterns")
	}
	if !emittedCustom {
		t.Errorf("custom pattern 'Internal Employee ID' must be present in emitted patterns")
	}

	jsonBytes, err := compiler.EmitJSON(compiled)
	if err != nil {
		t.Fatalf("EmitJSON failed: %v", err)
	}

	var parsedMap map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &parsedMap); err != nil {
		t.Fatalf("EmitJSON produced invalid JSON: %v", err)
	}
	if parsedMap["enabled"] != true {
		t.Errorf("expected enabled: true in JSON")
	}
}

func TestCompiler_AtomicWriteAndReload(t *testing.T) {
	store := setupTestStore(t)
	ctx := context.Background()

	if err := Seed(ctx, store); err != nil {
		t.Fatalf("Seed failed: %v", err)
	}

	tempAgentsDir := t.TempDir()
	reloader := &mockReloader{}

	compiler := NewCompiler(
		store,
		WithAgentsDir(tempAgentsDir),
		WithReloader(reloader),
	)

	cfg := AgentPolicyConfig{
		AgentName: "banking-bot",
		PackIDs:   []string{"pack:tr-kvkk"},
		Overrides: []RuleOverride{
			{
				RuleID:  "rule:tr-tckn",
				Action:  ActionBlock,
				Enabled: true,
			},
		},
		ToolExemptions: map[string]ToolExemption{
			"trusted_transfer": {Request: true, Response: true},
		},
	}

	// 1. Save and Compile
	if err := compiler.SaveConfigAndCompile(ctx, &cfg); err != nil {
		t.Fatalf("SaveConfigAndCompile failed: %v", err)
	}

	// 2. Verify target file exists
	expectedPath := filepath.Join(tempAgentsDir, "banking-bot", "current", "dlp.json")
	content, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatalf("failed to read emitted dlp.json: %v", err)
	}

	var payload CompiledDLPPayload
	if err := json.Unmarshal(content, &payload); err != nil {
		t.Fatalf("emitted file is not valid json: %v", err)
	}
	if !payload.Enabled || len(payload.Patterns) == 0 || len(payload.ToolExemptions) != 1 {
		t.Errorf("unexpected payload on disk: %+v", payload)
	}
	if !payload.ToolExemptions["trusted_transfer"].Request || !payload.ToolExemptions["trusted_transfer"].Response {
		t.Errorf("expected trusted_transfer exemption on disk: %+v", payload.ToolExemptions)
	}

	// 3. Verify reloader was invoked
	reloaded := reloader.GetReloaded()
	if len(reloaded) != 1 || reloaded[0] != "banking-bot" {
		t.Errorf("expected ['banking-bot'] reloaded, got %v", reloaded)
	}

	// 4. Test Path Traversal security validation
	if err := compiler.CompileAndSave(ctx, "../sneaky-agent"); err == nil {
		t.Fatalf("expected error for path traversal agent name, got nil")
	}
}

func TestCompiler_PropagatePackUpdate(t *testing.T) {
	store := setupTestStore(t)
	ctx := context.Background()

	if err := Seed(ctx, store); err != nil {
		t.Fatalf("Seed failed: %v", err)
	}

	tempAgentsDir := t.TempDir()
	reloader := &mockReloader{}

	compiler := NewCompiler(
		store,
		WithAgentsDir(tempAgentsDir),
		WithReloader(reloader),
	)

	// Set up two agents using pack:cloud-infra
	cfg1 := AgentPolicyConfig{
		AgentName: "cloud-agent-alpha",
		PackIDs:   []string{"pack:cloud-infra"},
	}
	cfg2 := AgentPolicyConfig{
		AgentName: "cloud-agent-beta",
		PackIDs:   []string{"pack:cloud-infra", "pack:tr-kvkk"},
	}

	if err := compiler.SaveConfigAndCompile(ctx, &cfg1); err != nil {
		t.Fatalf("save cfg1 failed: %v", err)
	}
	if err := compiler.SaveConfigAndCompile(ctx, &cfg2); err != nil {
		t.Fatalf("save cfg2 failed: %v", err)
	}

	// Reset reloader call log
	reloader.mu.Lock()
	reloader.reloadedList = nil
	reloader.mu.Unlock()

	// Trigger live propagation for pack:cloud-infra
	updatedAgents, err := compiler.PropagatePackUpdate(ctx, "pack:cloud-infra")
	if err != nil {
		t.Fatalf("PropagatePackUpdate failed: %v", err)
	}

	if len(updatedAgents) != 2 {
		t.Fatalf("expected 2 agents recompiled, got %d: %v", len(updatedAgents), updatedAgents)
	}

	reloaded := reloader.GetReloaded()
	if len(reloaded) != 2 {
		t.Errorf("expected 2 reloads, got %d: %v", len(reloaded), reloaded)
	}
}
