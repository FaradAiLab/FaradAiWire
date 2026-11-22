package filter

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestResolveCompositeDecision(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		reqDec   string
		respDec  string
		expected string
	}{
		{name: "both empty", reqDec: "", respDec: "", expected: ""},
		{name: "pending request only", reqDec: DecisionPending, respDec: "", expected: DecisionPending},
		{name: "allowed request and response", reqDec: DecisionAllowed, respDec: DecisionAllowed, expected: DecisionAllowed},
		{name: "allowed request and blocked response", reqDec: DecisionAllowed, respDec: DecisionBlocked, expected: DecisionBlocked},
		{name: "masked request and audit response", reqDec: DecisionMasked, respDec: DecisionAudit, expected: DecisionMasked},
		{name: "audit request and masked response", reqDec: DecisionAudit, respDec: DecisionMasked, expected: DecisionMasked},
		{name: "blocked request beats masked", reqDec: DecisionBlocked, respDec: DecisionMasked, expected: DecisionBlocked},
		{name: "critical beats blocked", reqDec: DecisionBlocked, respDec: DecisionCritical, expected: DecisionCritical},
		{name: "legacy aliases normalize cleanly", reqDec: "allow", respDec: "block", expected: DecisionBlocked},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := ResolveCompositeDecision(tc.reqDec, tc.respDec)
			if got != tc.expected {
				t.Fatalf("ResolveCompositeDecision(%q, %q) = %q, want %q", tc.reqDec, tc.respDec, got, tc.expected)
			}
		})
	}
}

func TestGenerateTraceID(t *testing.T) {
	t.Parallel()

	a := GenerateTraceID()
	b := GenerateTraceID()
	if a == "" || b == "" {
		t.Fatal("expected non-empty trace IDs")
	}
	if a == b {
		t.Fatalf("expected unique trace IDs, got identical %q", a)
	}
}

func TestAuditEvent_RedactedCopy(t *testing.T) {
	t.Parallel()

	var nilEv *AuditEvent
	if nilEv.RedactedCopy() != nil {
		t.Fatal("expected nil RedactedCopy for nil receiver")
	}

	ev := &AuditEvent{
		ID:               "id-1",
		Timestamp:        time.Now(),
		Decision:         DecisionBlocked,
		FilterName:       "guard",
		MatchedRule:      "guard",
		Message:          "prompt injection detected",
		OriginalRequest:  `{"query":"secret token"}`,
		Request:          `{"query":"secret token"}`,
		OriginalResponse: `{"result":"leak"}`,
		Response:         `{"error":"blocked"}`,
		OriginalPayload:  `{"secret":"raw"}`,
		RawPayload:       `{"raw":"leak"}`,
	}

	safe := ev.RedactedCopy()
	if safe.OriginalRequest != "" || safe.Request != "" || safe.OriginalResponse != "" || safe.Response != "" || safe.OriginalPayload != "" {
		t.Fatalf("expected all local-vault/unmasked fields cleared, got %+v", safe)
	}
	if !strings.HasPrefix(safe.RawPayload, "[REDACTED - Blocked by guard") {
		t.Fatalf("expected explicit blocked redaction notice, got %q", safe.RawPayload)
	}
	// Ensure caller's original event was not mutated
	if ev.OriginalRequest == "" || ev.OriginalResponse == "" {
		t.Fatal("expected original event to remain unmutated")
	}
}

func TestMakeBoundedPreview(t *testing.T) {
	t.Parallel()

	data := bytes.Repeat([]byte("X"), 1024)
	if got := MakeBoundedPreview(data, 512); !strings.Contains(got, "[TRUNCATED - Total Size: 1.00 KB]") {
		t.Fatalf("expected truncation trailer, got %q", got)
	}
	if got := MakeBoundedPreview(data, 2048); got != string(data) {
		t.Fatal("expected exact string when under limit")
	}
}

func TestAuditEvent_RedactedAndLightweightCopy_PreventSubstringBypass(t *testing.T) {
	t.Parallel()

	ev := &AuditEvent{
		Decision:    DecisionBlocked,
		MatchedRule: "dlp",
		Message:     "secret leaked",
		RawPayload:  `{"note":"[REDACTED fake marker","secret":"sk-live-999999"}`,
	}

	safe := ev.RedactedCopy()
	if strings.Contains(safe.RawPayload, "sk-live-999999") || !strings.HasPrefix(safe.RawPayload, "[REDACTED - Blocked by dlp") {
		t.Fatalf("RedactedCopy failed to block substring bypass: %q", safe.RawPayload)
	}

	sseCopy := ev.LightweightSummaryCopy(1024)
	if strings.Contains(sseCopy.RawPayload, "sk-live-999999") || !strings.HasPrefix(sseCopy.RawPayload, "[REDACTED - Blocked by dlp") {
		t.Fatalf("LightweightSummaryCopy leaked blocked payload: %q", sseCopy.RawPayload)
	}
}

type mockSecurityAuditLogger struct {
	events []*SecurityAuditEvent
}

func (m *mockSecurityAuditLogger) LogSecurityEvent(ev *SecurityAuditEvent) {
	if ev != nil {
		m.events = append(m.events, ev)
	}
}

func TestMultiSecurityAuditLogger_FanOutAndMetadata(t *testing.T) {
	t.Parallel()

	l1 := &mockSecurityAuditLogger{}
	l2 := &mockSecurityAuditLogger{}
	multi := NewMultiSecurityAuditLogger(nil, l1, l2)

	ev := &SecurityAuditEvent{
		ID:           "sec-1",
		Timestamp:    time.Now(),
		EventType:    "API_KEY_CREATE",
		ActorID:      "key-admin-1",
		ActorRole:    "Admin",
		ClientIP:     "127.0.0.1",
		ResourceType: "api_key",
		ResourceID:   "key-dev-9",
		Action:       "CREATE",
		Outcome:      "ALLOWED",
		Metadata:     map[string]any{"scope": "agent-a"},
	}
	multi.LogSecurityEvent(ev)

	if len(l1.events) != 1 || len(l2.events) != 1 {
		t.Fatalf("expected 1 event on both loggers, got l1=%d l2=%d", len(l1.events), len(l2.events))
	}

	auditEv := &AuditEvent{
		APIKeyID:        "key-1",
		ClientIP:        "10.0.0.5",
		HumanApproved:   true,
		ApprovedBy:      "key-admin-1",
		ApprovalChannel: "web_ws",
		HashVersion:     "v2",
	}
	if !auditEv.HumanApproved || auditEv.ApprovalChannel != "web_ws" {
		t.Fatalf("unexpected audit event HITL fields: %+v", auditEv)
	}
}
