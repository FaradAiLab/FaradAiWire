package policy

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func setupTestStore(t *testing.T) *DuckDBStore {
	t.Helper()
	store, err := OpenDuckDBStore(":memory:")
	if err != nil {
		t.Fatalf("failed to open in-memory duckdb store: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	ctx := context.Background()
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("failed to migrate store: %v", err)
	}

	return store
}

func TestDuckDBStore_Rules(t *testing.T) {
	store := setupTestStore(t)
	ctx := context.Background()

	// 1. Create Rule
	rule := DlpPatternRule{
		ID:            "rule:test-ssn",
		Name:          "Social Security Number",
		Description:   "Matches US SSN pattern",
		Category:      "pii",
		Regex:         `\b\d{3}-\d{2}-\d{4}\b`,
		DefaultAction: ActionMask,
		CWE:           "CWE-359",
		Severity:      "HIGH",
		IsBuiltin:     false,
	}

	if err := store.CreateRule(ctx, &rule); err != nil {
		t.Fatalf("CreateRule failed: %v", err)
	}

	// 2. Duplicate Rule should fail
	if err := store.CreateRule(ctx, &rule); !errors.Is(err, ErrRuleAlreadyExists) {
		t.Fatalf("expected ErrRuleAlreadyExists, got %v", err)
	}

	// 3. Get Rule
	got, err := store.GetRule(ctx, "rule:test-ssn")
	if err != nil {
		t.Fatalf("GetRule failed: %v", err)
	}
	if got.Name != rule.Name || got.DefaultAction != ActionMask {
		t.Errorf("unexpected rule content: %+v", got)
	}
	if got.CWE != "CWE-359" || got.Severity != "HIGH" {
		t.Errorf("expected CWE CWE-359 and Severity HIGH, got CWE=%s, Severity=%s", got.CWE, got.Severity)
	}

	// 4. Update Rule
	got.Description = "Updated description"
	got.DefaultAction = ActionBlock
	if err := store.UpdateRule(ctx, got); err != nil {
		t.Fatalf("UpdateRule failed: %v", err)
	}

	updated, err := store.GetRule(ctx, "rule:test-ssn")
	if err != nil {
		t.Fatalf("GetRule after update failed: %v", err)
	}
	if updated.Description != "Updated description" || updated.DefaultAction != ActionBlock {
		t.Errorf("update was not persisted: %+v", updated)
	}

	// 5. List Rules
	rules, err := store.ListRules(ctx, "pii")
	if err != nil {
		t.Fatalf("ListRules failed: %v", err)
	}
	if len(rules) != 1 || rules[0].ID != "rule:test-ssn" {
		t.Errorf("unexpected list rules output: %+v", rules)
	}

	// 6. Delete Rule
	if err := store.DeleteRule(ctx, "rule:test-ssn"); err != nil {
		t.Fatalf("DeleteRule failed: %v", err)
	}
	_, err = store.GetRule(ctx, "rule:test-ssn")
	if !errors.Is(err, ErrRuleNotFound) {
		t.Fatalf("expected ErrRuleNotFound, got %v", err)
	}
}

func TestDuckDBStore_BuiltinImmutability(t *testing.T) {
	store := setupTestStore(t)
	ctx := context.Background()

	builtinRule := DlpPatternRule{
		ID:            "rule:builtin-tckn",
		Name:          "TCKN",
		Description:   "TC Kimlik No",
		Category:      "kvkk",
		Regex:         `\b[1-9][0-9]{10}\b`,
		DefaultAction: ActionMask,
		IsBuiltin:     true,
	}

	if err := store.CreateRule(ctx, &builtinRule); err != nil {
		t.Fatalf("failed to create builtin rule: %v", err)
	}

	// Attempt to update builtin rule must fail
	builtinRule.Name = "Malicious Modification"
	if err := store.UpdateRule(ctx, &builtinRule); !errors.Is(err, ErrImmutableBuiltin) {
		t.Fatalf("expected ErrImmutableBuiltin on update, got %v", err)
	}

	// Attempt to delete builtin rule must fail
	if err := store.DeleteRule(ctx, "rule:builtin-tckn"); !errors.Is(err, ErrImmutableBuiltin) {
		t.Fatalf("expected ErrImmutableBuiltin on delete, got %v", err)
	}

	// Builtin pack immutability
	builtinPack := PolicyPack{
		ID:          "pack:builtin-kvkk",
		Name:        "KVKK Pack",
		Description: "Official KVKK rules",
		Category:    "regional",
		RuleIDs:     []string{"rule:builtin-tckn"},
		IsBuiltin:   true,
	}
	if err := store.CreatePack(ctx, &builtinPack); err != nil {
		t.Fatalf("failed to create builtin pack: %v", err)
	}

	builtinPack.Name = "Tampered Pack"
	if err := store.UpdatePack(ctx, &builtinPack); !errors.Is(err, ErrImmutableBuiltin) {
		t.Fatalf("expected ErrImmutableBuiltin on pack update, got %v", err)
	}

	if err := store.DeletePack(ctx, "pack:builtin-kvkk"); !errors.Is(err, ErrImmutableBuiltin) {
		t.Fatalf("expected ErrImmutableBuiltin on pack delete, got %v", err)
	}
}

func TestDuckDBStore_Packs(t *testing.T) {
	store := setupTestStore(t)
	ctx := context.Background()

	// Seed two rules
	r1 := DlpPatternRule{
		ID:            "rule:r1",
		Name:          "Rule 1",
		Category:      "custom",
		Regex:         `\bABC\b`,
		DefaultAction: ActionMask,
	}
	r2 := DlpPatternRule{
		ID:            "rule:r2",
		Name:          "Rule 2",
		Category:      "custom",
		Regex:         `\bDEF\b`,
		DefaultAction: ActionBlock,
	}
	if err := store.CreateRule(ctx, &r1); err != nil {
		t.Fatalf("create r1 failed: %v", err)
	}
	if err := store.CreateRule(ctx, &r2); err != nil {
		t.Fatalf("create r2 failed: %v", err)
	}

	// 1. Create Pack
	pack := PolicyPack{
		ID:          "pack:custom-rules",
		Name:        "Custom Rules Pack",
		Description: "Pack with r1 and r2",
		Category:    "custom",
		RuleIDs:     []string{"rule:r1", "rule:r2"},
		IsBuiltin:   false,
	}
	if err := store.CreatePack(ctx, &pack); err != nil {
		t.Fatalf("CreatePack failed: %v", err)
	}

	// 2. Duplicate Pack should fail
	if err := store.CreatePack(ctx, &pack); !errors.Is(err, ErrPackAlreadyExists) {
		t.Fatalf("expected ErrPackAlreadyExists, got %v", err)
	}

	// 3. Get Pack
	got, err := store.GetPack(ctx, "pack:custom-rules")
	if err != nil {
		t.Fatalf("GetPack failed: %v", err)
	}
	if len(got.RuleIDs) != 2 || len(got.Rules) != 2 {
		t.Errorf("expected 2 rules in pack, got IDs=%d Rules=%d", len(got.RuleIDs), len(got.Rules))
	}

	// 4. Update Pack (remove r2)
	got.RuleIDs = []string{"rule:r1"}
	got.Description = "Single rule pack"
	if err := store.UpdatePack(ctx, got); err != nil {
		t.Fatalf("UpdatePack failed: %v", err)
	}

	updated, err := store.GetPack(ctx, "pack:custom-rules")
	if err != nil {
		t.Fatalf("GetPack after update failed: %v", err)
	}
	if len(updated.RuleIDs) != 1 || updated.RuleIDs[0] != "rule:r1" {
		t.Errorf("expected 1 rule (rule:r1), got %v", updated.RuleIDs)
	}

	// 5. Delete Pack
	if err := store.DeletePack(ctx, "pack:custom-rules"); err != nil {
		t.Fatalf("DeletePack failed: %v", err)
	}
	_, err = store.GetPack(ctx, "pack:custom-rules")
	if !errors.Is(err, ErrPackNotFound) {
		t.Fatalf("expected ErrPackNotFound, got %v", err)
	}
}

func TestDuckDBStore_AgentPolicyConfig(t *testing.T) {
	store := setupTestStore(t)
	ctx := context.Background()

	cfg := AgentPolicyConfig{
		AgentName: "banking-agent",
		PackIDs:   []string{"pack:tr-kvkk", "pack:cloud-infra"},
		Overrides: []RuleOverride{
			{
				RuleID:  "rule:tckn",
				Action:  ActionBlock,
				Enabled: true,
			},
			{
				RuleID:  "rule:phone",
				Action:  ActionMask,
				Enabled: false,
			},
		},
		CustomPatterns: []CustomPattern{
			{
				Name:   "Internal Branch Code",
				Regex:  `\bBR-[0-9]{4}\b`,
				Action: ActionMask,
			},
		},
		ToolExemptions: map[string]ToolExemption{
			"local_echo_tool": {Request: true, Response: true},
		},
	}

	// 1. Save Config
	if err := store.SaveAgentConfig(ctx, &cfg); err != nil {
		t.Fatalf("SaveAgentConfig failed: %v", err)
	}

	// 2. Get Config
	got, err := store.GetAgentConfig(ctx, "banking-agent")
	if err != nil {
		t.Fatalf("GetAgentConfig failed: %v", err)
	}
	if len(got.PackIDs) != 2 || len(got.Overrides) != 2 || len(got.CustomPatterns) != 1 || len(got.ToolExemptions) != 1 {
		t.Errorf("unexpected agent config payload: %+v", got)
	}
	if !got.ToolExemptions["local_echo_tool"].Request || !got.ToolExemptions["local_echo_tool"].Response {
		t.Errorf("expected local_echo_tool to have full directional exemptions: %+v", got.ToolExemptions)
	}

	// 3. Update Config (add another pack)
	got.PackIDs = append(got.PackIDs, "pack:db-sanitization")
	if err := store.SaveAgentConfig(ctx, got); err != nil {
		t.Fatalf("SaveAgentConfig update failed: %v", err)
	}

	updated, err := store.GetAgentConfig(ctx, "banking-agent")
	if err != nil {
		t.Fatalf("GetAgentConfig after update failed: %v", err)
	}
	if len(updated.PackIDs) != 3 {
		t.Errorf("expected 3 pack IDs, got %d", len(updated.PackIDs))
	}

	// 4. ListAgentsUsingPack
	agents, err := store.ListAgentsUsingPack(ctx, "pack:db-sanitization")
	if err != nil {
		t.Fatalf("ListAgentsUsingPack failed: %v", err)
	}
	if len(agents) != 1 || agents[0] != "banking-agent" {
		t.Errorf("expected ['banking-agent'], got %v", agents)
	}

	// Non-matching pack returns empty
	emptyAgents, err := store.ListAgentsUsingPack(ctx, "pack:non-existent")
	if err != nil {
		t.Fatalf("ListAgentsUsingPack failed: %v", err)
	}
	if len(emptyAgents) != 0 {
		t.Errorf("expected 0 agents, got %v", emptyAgents)
	}
}

func TestDuckDBStore_Concurrency(t *testing.T) {
	store := setupTestStore(t)
	ctx := context.Background()

	// Concurrently create rules and read them
	const workers = 10
	const iterations = 50

	var wg sync.WaitGroup
	wg.Add(workers)

	for w := 0; w < workers; w++ {
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				// Read rules
				_, _ = store.ListRules(ctx, "")
				// Read non-existent pack
				_, _ = store.GetPack(ctx, "pack:unknown")
				// Get agent config
				_, _ = store.GetAgentConfig(ctx, "agent")
				time.Sleep(100 * time.Microsecond)
			}
		}(w)
	}

	wg.Wait()
}
