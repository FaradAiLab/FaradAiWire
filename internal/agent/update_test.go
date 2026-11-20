package agent

import "testing"

func TestUpdateSpec_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		spec     UpdateSpec
		wantCode string
	}{
		{
			name: "valid empty spec",
			spec: UpdateSpec{},
		},
		{
			name: "invalid tool governance",
			spec: UpdateSpec{
				ToolGovernance: map[string]ToolGovernanceMode{"t1": "invalid_mode"},
			},
			wantCode: "INVALID_GOVERNANCE_MODE",
		},
		{
			name: "invalid retained governance",
			spec: UpdateSpec{
				RetainedGovernance: map[string]map[string]ToolGovernanceMode{
					"p1": {"p1__t1": "bogus"},
				},
			},
			wantCode: "INVALID_RETAINED_GOVERNANCE_MODE",
		},
		{
			name: "negative rate limit max_burst",
			spec: UpdateSpec{
				RateLimit: &RateLimitOverride{MaxBurst: -1, RefillRate: 1},
			},
			wantCode: "INVALID_RATE_LIMIT",
		},
		{
			name: "negative rate limit refill_rate",
			spec: UpdateSpec{
				RateLimit: &RateLimitOverride{MaxBurst: 1, RefillRate: -0.5},
			},
			wantCode: "INVALID_RATE_LIMIT",
		},
		{
			name: "negative loop protection max_repeat",
			spec: UpdateSpec{
				LoopProtection: &LoopProtectionOverride{MaxRepeat: -1},
			},
			wantCode: "INVALID_LOOP_PROTECTION",
		},
		{
			name: "negative loop protection window_seconds",
			spec: UpdateSpec{
				LoopProtection: &LoopProtectionOverride{WindowSeconds: -2},
			},
			wantCode: "INVALID_LOOP_PROTECTION",
		},
		{
			name: "invalid schema validation mode",
			spec: UpdateSpec{
				SchemaValidation: &SchemaValidationOverride{Mode: "strict"},
			},
			wantCode: "INVALID_SCHEMA_VALIDATION",
		},
		{
			name: "invalid guard override mode",
			spec: UpdateSpec{
				Guard: &GuardOverride{Mode: "block_all"},
			},
			wantCode: "INVALID_GUARD_OVERRIDE",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			vErr := tc.spec.Validate()
			if tc.wantCode == "" {
				if vErr != nil {
					t.Fatalf("expected nil error, got %+v", vErr)
				}
				return
			}
			if vErr == nil {
				t.Fatalf("expected validation error %q, got nil", tc.wantCode)
			}
			if vErr.Code != tc.wantCode {
				t.Fatalf("Code = %q, want %q (err: %v)", vErr.Code, tc.wantCode, vErr)
			}
		})
	}
}

func TestToolBelongsToProtocol(t *testing.T) {
	t.Parallel()

	manifest := []ToolMetadata{
		{Name: "custom_alias", CanonicalName: "custom_alias", ProtocolID: "legacy_id", ProtocolName: "Legacy Server"},
	}

	tests := []struct {
		name      string
		toolName  string
		protoID   string
		protoName string
		want      bool
	}{
		{name: "id prefix match", toolName: "git__status", protoID: "git", protoName: "Git", want: true},
		{name: "name prefix match", toolName: "Git__commit", protoID: "git_1234", protoName: "Git", want: true},
		{name: "manifest fallback match", toolName: "custom_alias", protoID: "legacy_id", protoName: "Legacy Server", want: true},
		{name: "unrelated tool", toolName: "other__tool", protoID: "git", protoName: "Git", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ToolBelongsToProtocol(tc.toolName, tc.protoID, tc.protoName, manifest); got != tc.want {
				t.Fatalf("ToolBelongsToProtocol() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRouteConfig_ApplyUpdate_RetainedGovernanceFlow(t *testing.T) {
	t.Parallel()

	t.Run("detaching protocol stashes its tool governance rules into RetainedGovernance", func(t *testing.T) {
		t.Parallel()
		cfg := &RouteConfig{
			AgentID:     "demo",
			AgentName:   "demo",
			Description: "Original",
			RoutingMode: "aggregated",
			Protocols: []ProtocolConfig{
				{ID: "p1", Name: "Proto One"},
				{ID: "p2", Name: "Proto Two"},
			},
			ToolGovernance: map[string]ToolGovernanceMode{
				"p1__delete": ModeStrictAlwaysHITL,
				"p2__read":   ModeAutonomous,
			},
		}

		cfg.ApplyUpdate(UpdateSpec{
			RoutingMode:      "DIRECT",
			Protocols:        []ProtocolConfig{{ID: "p2", Name: "Proto Two"}},
			ProtocolsUpdated: true,
		}, nil)

		if cfg.Description != "Original" || cfg.RoutingMode != "direct" {
			t.Fatalf("unexpected metadata: desc=%q mode=%q", cfg.Description, cfg.RoutingMode)
		}
		if _, stillActive := cfg.ToolGovernance["p1__delete"]; stillActive {
			t.Fatal("expected detached p1__delete to be removed from ToolGovernance")
		}
		if cfg.ToolGovernance["p2__read"] != ModeAutonomous {
			t.Fatalf("expected p2__read to remain active, got %+v", cfg.ToolGovernance)
		}
		if cfg.RetainedGovernance["p1"]["p1__delete"] != ModeStrictAlwaysHITL {
			t.Fatalf("expected p1__delete stashed in RetainedGovernance, got %+v", cfg.RetainedGovernance)
		}
	})

	t.Run("restoring retained protocol merges without overwriting explicit ToolGovernance", func(t *testing.T) {
		t.Parallel()
		cfg := &RouteConfig{
			AgentID:   "restore-agent",
			AgentName: "restore-agent",
			RetainedGovernance: map[string]map[string]ToolGovernanceMode{
				"p1": {
					"p1__delete": ModeStrictAlwaysHITL,
					"p1__read":   ModeGuardedBlock,
				},
			},
		}

		cfg.ApplyUpdate(UpdateSpec{
			Protocols:        []ProtocolConfig{{ID: "p1", Name: "p1"}},
			ProtocolsUpdated: true,
			ToolGovernance: map[string]ToolGovernanceMode{
				"p1__read": ModeAutonomous,
			},
			RestoreRetainedProtocols: []string{"p1"},
		}, nil)

		if cfg.ToolGovernance["p1__delete"] != ModeStrictAlwaysHITL {
			t.Fatalf("expected p1__delete restored, got %+v", cfg.ToolGovernance)
		}
		if cfg.ToolGovernance["p1__read"] != ModeAutonomous {
			t.Fatalf("expected explicit p1__read=autonomous to take precedence, got %+v", cfg.ToolGovernance)
		}
		if _, exists := cfg.RetainedGovernance["p1"]; exists {
			t.Fatalf("expected p1 entry cleared from RetainedGovernance after restore")
		}
	})
}
