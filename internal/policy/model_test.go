package policy

import (
	"testing"
	"time"
)

func TestActionPrecedence(t *testing.T) {
	tests := []struct {
		name     string
		actionA  Action
		actionB  Action
		expected Action
	}{
		{
			name:     "BLOCK overrides MASK",
			actionA:  ActionBlock,
			actionB:  ActionMask,
			expected: ActionBlock,
		},
		{
			name:     "MASK overrides AUDIT",
			actionA:  ActionMask,
			actionB:  ActionAudit,
			expected: ActionMask,
		},
		{
			name:     "BLOCK overrides AUDIT",
			actionA:  ActionAudit,
			actionB:  ActionBlock,
			expected: ActionBlock,
		},
		{
			name:     "BLOCK overrides HITL",
			actionA:  ActionBlock,
			actionB:  ActionHITL,
			expected: ActionBlock,
		},
		{
			name:     "HITL overrides MASK",
			actionA:  ActionHITL,
			actionB:  ActionMask,
			expected: ActionHITL,
		},
		{
			name:     "HITL overrides AUDIT",
			actionA:  ActionAudit,
			actionB:  ActionHITL,
			expected: ActionHITL,
		},
		{
			name:     "Equal actions preserve action",
			actionA:  ActionMask,
			actionB:  ActionMask,
			expected: ActionMask,
		},
		{
			name:     "Equal HITL actions preserve action",
			actionA:  ActionHITL,
			actionB:  ActionHITL,
			expected: ActionHITL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MostRestrictiveAction(tt.actionA, tt.actionB)
			if result != tt.expected {
				t.Errorf("MostRestrictiveAction(%q, %q) = %q; want %q", tt.actionA, tt.actionB, result, tt.expected)
			}
		})
	}
}

func TestValidateIdentifier(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{name: "valid simple id", id: "rule-123", wantErr: false},
		{name: "valid pack id with colon", id: "pack:tr-kvkk", wantErr: false},
		{name: "valid agent id with dot", id: "agent.finance_01", wantErr: false},
		{name: "empty id rejected", id: "", wantErr: true},
		{name: "whitespace only rejected", id: "   ", wantErr: true},
		{name: "path traversal rejected", id: "../etc/passwd", wantErr: true},
		{name: "windows path traversal rejected", id: "..\\windows\\system32", wantErr: true},
		{name: "slash rejected", id: "pack/kvkk", wantErr: true},
		{name: "backslash rejected", id: "pack\\kvkk", wantErr: true},
		{name: "null byte rejected", id: "pack\x00kvkk", wantErr: true},
		{name: "special characters rejected", id: "pack;rm -rf", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateIdentifier(tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateIdentifier(%q) error = %v, wantErr = %v", tt.id, err, tt.wantErr)
			}
		})
	}
}

func TestValidateRule(t *testing.T) {
	validRule := DlpPatternRule{
		ID:            "rule:tckn",
		Name:          "Turkish ID",
		Description:   "Validates 11-digit Turkish National ID Number",
		Category:      "kvkk",
		Regex:         `\b[1-9][0-9]{10}\b`,
		DefaultAction: ActionMask,
		IsBuiltin:     true,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	tests := []struct {
		name    string
		modify  func(r *DlpPatternRule)
		wantErr bool
	}{
		{
			name:    "valid rule passes",
			modify:  nil,
			wantErr: false,
		},
		{
			name: "valid hitl action rule passes",
			modify: func(r *DlpPatternRule) {
				r.DefaultAction = ActionHITL
			},
			wantErr: false,
		},
		{
			name: "nil rule fails",
			modify: func(r *DlpPatternRule) {
				*r = DlpPatternRule{}
			},
			wantErr: true,
		},
		{
			name: "empty name fails",
			modify: func(r *DlpPatternRule) {
				r.Name = ""
			},
			wantErr: true,
		},
		{
			name: "invalid action fails",
			modify: func(r *DlpPatternRule) {
				r.DefaultAction = "invalid_action"
			},
			wantErr: true,
		},
		{
			name: "empty regex fails",
			modify: func(r *DlpPatternRule) {
				r.Regex = ""
			},
			wantErr: true,
		},
		{
			name: "broken regex syntax fails",
			modify: func(r *DlpPatternRule) {
				r.Regex = `([a-z]+`
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := validRule
			if tt.modify != nil {
				tt.modify(&r)
			}
			err := ValidateRule(&r)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRule() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateAgentPolicyConfig(t *testing.T) {
	validCfg := AgentPolicyConfig{
		AgentName: "customer-support-agent",
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
				Name:   "Internal Account",
				Regex:  `\bACC-[0-9]{6}\b`,
				Action: ActionMask,
			},
		},
		ToolExemptions: map[string]ToolExemption{
			"trusted_internal_db_query": {Request: true, Response: false},
		},
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	t.Run("valid configuration passes", func(t *testing.T) {
		cfg := validCfg
		if err := ValidateAgentPolicyConfig(&cfg); err != nil {
			t.Fatalf("unexpected validation error: %v", err)
		}
	})

	t.Run("invalid agent name fails", func(t *testing.T) {
		cfg := validCfg
		cfg.AgentName = "../bad_name"
		if err := ValidateAgentPolicyConfig(&cfg); err == nil {
			t.Fatal("expected error for path traversal agent name, got nil")
		}
	})

	t.Run("invalid override action fails", func(t *testing.T) {
		cfg := validCfg
		cfg.Overrides = []RuleOverride{{RuleID: "rule:tckn", Action: "drop_table", Enabled: true}}
		if err := ValidateAgentPolicyConfig(&cfg); err == nil {
			t.Fatal("expected error for invalid override action, got nil")
		}
	})

	t.Run("invalid custom pattern regex fails", func(t *testing.T) {
		cfg := validCfg
		cfg.CustomPatterns = []CustomPattern{{Name: "test", Regex: "[unclosed", Action: ActionMask}}
		if err := ValidateAgentPolicyConfig(&cfg); err == nil {
			t.Fatal("expected error for invalid custom pattern regex, got nil")
		}
	})
}
