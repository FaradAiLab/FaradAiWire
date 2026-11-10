package agent

import (
	"testing"
)

func TestRouteConfig_Clone_DeepCopy(t *testing.T) {
	orig := &RouteConfig{
		AgentID:     "agent-1",
		AgentName:   "Agent Alpha",
		Description: "Primary Agent",
		RoutingMode: "aggregated",
		Protocols: []ProtocolConfig{
			{
				ID:           "proto-1",
				Name:         "mcp-db",
				Type:         "stdio",
				URLOrCommand: "sqlite3",
				Args:         []string{"--json"},
				Env:          []string{"FOO=BAR"},
				Headers:      map[string]string{"X-Test": "val"},
				AllowedTools: []string{"query"},
			},
		},
		EnabledTools: []string{"mcp-db__query"},
		ToolOverrides: &ToolOverrides{
			EnabledTools: []string{"mcp-db__query"},
		},
		ToolGovernance: map[string]ToolGovernanceMode{
			"mcp-db__query": ModeGuardedHITL,
		},
		RetainedGovernance: map[string]map[string]ToolGovernanceMode{
			"proto-old": {
				"proto-old__drop": ModeStrictAlwaysHITL,
			},
		},
		RateLimit: &RateLimitOverride{
			MaxBurst:   50,
			RefillRate: 10.5,
		},
		LoopProtection: &LoopProtectionOverride{
			MaxRepeat:     5,
			WindowSeconds: 60,
			ExcludeTools:  []string{"ping"},
		},
	}

	clone := orig.Clone()
	if clone == nil {
		t.Fatalf("expected non-nil clone")
	}

	// 1. Verify equality of cloned values
	if clone.AgentID != orig.AgentID || clone.AgentName != orig.AgentName {
		t.Errorf("scalar fields did not match: got %s, %s", clone.AgentID, clone.AgentName)
	}
	if len(clone.Protocols) != 1 || clone.Protocols[0].ID != "proto-1" {
		t.Fatalf("protocols did not clone properly: %+v", clone.Protocols)
	}

	// 2. Mutate original slice/map fields and verify clone remains unchanged
	orig.Protocols[0].Args[0] = "--mutated"
	if clone.Protocols[0].Args[0] == "--mutated" {
		t.Errorf("protocol args leaked mutation to clone")
	}

	orig.Protocols[0].Headers["X-Test"] = "mutated-val"
	if clone.Protocols[0].Headers["X-Test"] == "mutated-val" {
		t.Errorf("protocol headers leaked mutation to clone")
	}

	orig.Protocols[0].AllowedTools[0] = "mutated-tool"
	if clone.Protocols[0].AllowedTools[0] == "mutated-tool" {
		t.Errorf("protocol allowed_tools leaked mutation to clone")
	}

	orig.EnabledTools[0] = "mutated-enabled"
	if clone.EnabledTools[0] == "mutated-enabled" {
		t.Errorf("enabled_tools leaked mutation to clone")
	}

	orig.ToolOverrides.EnabledTools[0] = "mutated-override"
	if clone.ToolOverrides.EnabledTools[0] == "mutated-override" {
		t.Errorf("tool_overrides leaked mutation to clone")
	}

	orig.ToolGovernance["mcp-db__query"] = ModeAutonomous
	if clone.ToolGovernance["mcp-db__query"] == ModeAutonomous {
		t.Errorf("tool_governance leaked mutation to clone")
	}

	orig.RetainedGovernance["proto-old"]["proto-old__drop"] = ModeAutonomous
	if clone.RetainedGovernance["proto-old"]["proto-old__drop"] == ModeAutonomous {
		t.Errorf("retained_governance leaked mutation to clone")
	}

	orig.LoopProtection.ExcludeTools[0] = "mutated-exclude"
	if clone.LoopProtection.ExcludeTools[0] == "mutated-exclude" {
		t.Errorf("loop_protection exclude_tools leaked mutation to clone")
	}
}

func TestRouteConfig_Clone_NilSafe(t *testing.T) {
	var nilCfg *RouteConfig
	if nilCfg.Clone() != nil {
		t.Errorf("expected nil for nil RouteConfig.Clone()")
	}

	emptyCfg := &RouteConfig{}
	emptyClone := emptyCfg.Clone()
	if emptyClone == nil {
		t.Fatalf("expected non-nil clone for empty RouteConfig")
	}
	if emptyClone.Protocols != nil || emptyClone.ToolGovernance != nil {
		t.Errorf("expected nil slices/maps on empty clone")
	}
}

func TestRouteConfig_GetToolGovernanceMode_CaseInsensitive(t *testing.T) {
	cfg := &RouteConfig{
		ToolGovernance: map[string]ToolGovernanceMode{
			"fs__delete_file": ModeStrictAlwaysHITL,
		},
	}

	for _, name := range []string{"fs__delete_file", "fs__DELETE_FILE", "FS__Delete_File"} {
		mode, ok := cfg.GetToolGovernanceMode(name)
		if !ok || mode != ModeStrictAlwaysHITL {
			t.Errorf("GetToolGovernanceMode(%q) = (%q, %v), want (%q, true)", name, mode, ok, ModeStrictAlwaysHITL)
		}
	}

	if mode, ok := cfg.GetToolGovernanceMode("fs__read_file"); ok || mode != "" {
		t.Errorf("GetToolGovernanceMode(unknown) = (%q, %v), want (\"\", false)", mode, ok)
	}
}
