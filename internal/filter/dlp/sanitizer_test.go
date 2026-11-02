package dlp

import (
	"regexp"
	"testing"
)

func TestSanitize(t *testing.T) {
	emailRe := regexp.MustCompile(`[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+`)
	cardRe := regexp.MustCompile(`\b\d{4}-\d{4}-\d{4}-\d{4}\b`)
	tokenRe := regexp.MustCompile(`(?i)bearer\s+[a-z0-9_-]{16,}`)

	tests := []struct {
		name             string
		input            string
		patterns         []CompiledPattern
		wantBlocked      bool
		wantRule         string
		wantRequiresHITL bool
		wantHITLRule     string
		wantModified     bool
		wantOutput       string
	}{
		{
			name:         "empty input",
			input:        "",
			patterns:     []CompiledPattern{{Name: "email", Regex: emailRe, Action: ActionMask}},
			wantBlocked:  false,
			wantModified: false,
			wantOutput:   "",
		},
		{
			name:         "no patterns",
			input:        "user@test.com",
			patterns:     nil,
			wantBlocked:  false,
			wantModified: false,
			wantOutput:   "user@test.com",
		},
		{
			name:  "mask match with auto semantic placeholder",
			input: "Contact: alice@example.com",
			patterns: []CompiledPattern{
				{Name: "email", Regex: emailRe, Action: ActionMask},
			},
			wantBlocked:  false,
			wantModified: true,
			wantOutput:   "Contact: [REDACTED:EMAIL]",
		},
		{
			name:  "mask match with explicit custom placeholder",
			input: "Contact: alice@example.com",
			patterns: []CompiledPattern{
				{Name: "email", Regex: emailRe, Action: ActionMask, Placeholder: "[REDACTED]"},
			},
			wantBlocked:  false,
			wantModified: true,
			wantOutput:   "Contact: [REDACTED]",
		},
		{
			name:  "block match",
			input: "Authorization: bearer secret_token_1234567890",
			patterns: []CompiledPattern{
				{Name: "token", Regex: tokenRe, Action: ActionBlock},
			},
			wantBlocked:  true,
			wantRule:     "token",
			wantModified: false,
			wantOutput:   "Authorization: bearer secret_token_1234567890",
		},
		{
			name:  "audit match (zero payload modification)",
			input: "Contact: alice@example.com",
			patterns: []CompiledPattern{
				{Name: "email", Regex: emailRe, Action: ActionAudit},
			},
			wantBlocked:  false,
			wantModified: false,
			wantOutput:   "Contact: alice@example.com",
		},
		{
			name:  "collision: block takes absolute precedence over mask and audit",
			input: "User: alice@example.com, Token: bearer secret_token_1234567890, Card: 1234-5678-9012-3456",
			patterns: []CompiledPattern{
				{Name: "email", Regex: emailRe, Action: ActionAudit},
				{Name: "card", Regex: cardRe, Action: ActionMask},
				{Name: "token", Regex: tokenRe, Action: ActionBlock},
			},
			wantBlocked:  true,
			wantRule:     "token",
			wantModified: false,
			wantOutput:   "User: alice@example.com, Token: bearer secret_token_1234567890, Card: 1234-5678-9012-3456",
		},
		{
			name:  "multiple masks applied sequentially with semantic placeholders",
			input: "Email: alice@example.com, Card: 1234-5678-9012-3456",
			patterns: []CompiledPattern{
				{Name: "email", Regex: emailRe, Action: ActionMask},
				{Name: "card", Regex: cardRe, Action: ActionMask},
			},
			wantBlocked:  false,
			wantModified: true,
			wantOutput:   "Email: [REDACTED:EMAIL], Card: [REDACTED:CARD]",
		},
		{
			name:  "hitl match",
			input: "Execute: rm -rf /tmp/scratch",
			patterns: []CompiledPattern{
				{Name: "destructive_rm", Regex: regexp.MustCompile(`rm\s+-rf`), Action: ActionHITL},
			},
			wantBlocked:      false,
			wantRequiresHITL: true,
			wantHITLRule:     "destructive_rm",
			wantModified:     false,
			wantOutput:       "Execute: rm -rf /tmp/scratch",
		},
		{
			name:  "collision: block overrides hitl",
			input: "Execute: rm -rf /tmp/scratch with bearer secret_token_1234567890",
			patterns: []CompiledPattern{
				{Name: "destructive_rm", Regex: regexp.MustCompile(`rm\s+-rf`), Action: ActionHITL},
				{Name: "token", Regex: tokenRe, Action: ActionBlock},
			},
			wantBlocked:      true,
			wantRule:         "token",
			wantRequiresHITL: false,
			wantModified:     false,
			wantOutput:       "Execute: rm -rf /tmp/scratch with bearer secret_token_1234567890",
		},
		{
			name:  "collision: hitl overrides mask and audit",
			input: "Contact: alice@example.com, Execute: rm -rf /tmp/scratch",
			patterns: []CompiledPattern{
				{Name: "email", Regex: emailRe, Action: ActionMask},
				{Name: "destructive_rm", Regex: regexp.MustCompile(`rm\s+-rf`), Action: ActionHITL},
			},
			wantBlocked:      false,
			wantRequiresHITL: true,
			wantHITLRule:     "destructive_rm",
			wantModified:     false,
			wantOutput:       "Contact: alice@example.com, Execute: rm -rf /tmp/scratch",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := Sanitize(tc.input, tc.patterns)
			if res.Blocked != tc.wantBlocked {
				t.Errorf("Blocked = %v; want %v", res.Blocked, tc.wantBlocked)
			}
			if res.BlockingRule != tc.wantRule {
				t.Errorf("BlockingRule = %q; want %q", res.BlockingRule, tc.wantRule)
			}
			if res.RequiresHITL != tc.wantRequiresHITL {
				t.Errorf("RequiresHITL = %v; want %v", res.RequiresHITL, tc.wantRequiresHITL)
			}
			if res.HITLRule != tc.wantHITLRule {
				t.Errorf("HITLRule = %q; want %q", res.HITLRule, tc.wantHITLRule)
			}
			if res.Modified != tc.wantModified {
				t.Errorf("Modified = %v; want %v", res.Modified, tc.wantModified)
			}
			if res.Output != tc.wantOutput {
				t.Errorf("Output = %q; want %q", res.Output, tc.wantOutput)
			}
		})
	}
}

func TestSanitize_Canonicalization(t *testing.T) {
	dotDotRule := CompiledPattern{
		Name:   "rule:path-dot-dot",
		Regex:  regexp.MustCompile(`(?:\.\.[/\\])+`),
		Action: ActionBlock,
	}
	sensitiveUnixRule := CompiledPattern{
		Name:   "rule:path-sensitive-unix",
		Regex:  regexp.MustCompile(`(?i)/(?:etc/(?:[a-z0-9_.-]+/)*[a-z0-9_.-]+)`),
		Action: ActionBlock,
	}
	cmdChainRule := CompiledPattern{
		Name:   "rule:cmd-chaining-pipe",
		Regex:  regexp.MustCompile(`(?i)(?:[;&|` + "`" + `$]|\$\()\s*(?:cat|rm|nc|curl|wget|bash|sh)\b`),
		Action: ActionHITL,
	}

	patterns := []CompiledPattern{dotDotRule, sensitiveUnixRule, cmdChainRule}

	tests := []struct {
		name             string
		input            string
		wantBlocked      bool
		wantRule         string
		wantRequiresHITL bool
		wantHITLRule     string
	}{
		{
			name:        "clean path traversal detected directly",
			input:       "read_file ../../somefile.txt",
			wantBlocked: true,
			wantRule:    "rule:path-dot-dot",
		},
		{
			name:        "single percent-encoded dot-dot %2e%2e detected via canonicalization",
			input:       "read_file %2e%2e/%2e%2e/somefile.txt",
			wantBlocked: true,
			wantRule:    "rule:path-dot-dot",
		},
		{
			name:        "double percent-encoded dot-dot %252e%252e detected via double canonicalization",
			input:       "read_file %252e%252e%252f%252e%252e%252fsomefile.txt",
			wantBlocked: true,
			wantRule:    "rule:path-dot-dot",
		},
		{
			name:        "single percent-encoded sensitive path /etc/passwd detected",
			input:       "fetch %2fetc%2fpasswd",
			wantBlocked: true,
			wantRule:    "rule:path-sensitive-unix",
		},
		{
			name:        "double percent-encoded sensitive path /etc/passwd detected",
			input:       "fetch %252fetc%252fpasswd",
			wantBlocked: true,
			wantRule:    "rule:path-sensitive-unix",
		},
		{
			name:             "percent-encoded command chaining escalates to HITL",
			input:            "exec echo hello%3b%20cat%20/tmp/app.log",
			wantBlocked:      false,
			wantRequiresHITL: true,
			wantHITLRule:     "rule:cmd-chaining-pipe",
		},
		{
			name:             "query-encoded plus command chaining escalates to HITL",
			input:            "exec echo hello%3b+cat+/tmp/app.log",
			wantBlocked:      false,
			wantRequiresHITL: true,
			wantHITLRule:     "rule:cmd-chaining-pipe",
		},
		{
			name:             "harmless input with percent sign does not false-positive",
			input:            "progress: 50% complete",
			wantBlocked:      false,
			wantRequiresHITL: false,
		},
		{
			name:             "harmless clean input passes cleanly",
			input:            "read_file safe_document.txt",
			wantBlocked:      false,
			wantRequiresHITL: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := Sanitize(tc.input, patterns)
			if res.Blocked != tc.wantBlocked {
				t.Errorf("Blocked = %v; want %v", res.Blocked, tc.wantBlocked)
			}
			if res.BlockingRule != tc.wantRule {
				t.Errorf("BlockingRule = %q; want %q", res.BlockingRule, tc.wantRule)
			}
			if res.RequiresHITL != tc.wantRequiresHITL {
				t.Errorf("RequiresHITL = %v; want %v", res.RequiresHITL, tc.wantRequiresHITL)
			}
			if res.HITLRule != tc.wantHITLRule {
				t.Errorf("HITLRule = %q; want %q", res.HITLRule, tc.wantHITLRule)
			}
			// Invariant: original input must be preserved in Output
			if res.Output != tc.input {
				t.Errorf("Output = %q; want original input %q", res.Output, tc.input)
			}
		})
	}
}
