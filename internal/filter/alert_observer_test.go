package filter

import (
	"sync"
	"testing"

	"github.com/FaradAiLab/FaradAiWire/internal/guard/hitltypes"
	"github.com/FaradAiLab/FaradAiWire/internal/notify"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
)

type recordingDesktopNotifier struct {
	mu     sync.Mutex
	events []notify.AlertEvent
}

func (r *recordingDesktopNotifier) Notify(event notify.AlertEvent) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
	return true
}

func (r *recordingDesktopNotifier) SetAdminBaseURL(_ string) {}

func (r *recordingDesktopNotifier) AdminBaseURL() string { return "" }

func (r *recordingDesktopNotifier) Events() []notify.AlertEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]notify.AlertEvent, len(r.events))
	copy(out, r.events)
	return out
}

func TestAlertAuditLogger_VerdictsAndOQ3Deduplication(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		event     *AuditEvent
		wantCount int
		wantCat   notify.AlertCategory
		wantFrag  string
	}{
		{
			name:      "nil_event_ignored",
			event:     nil,
			wantCount: 0,
		},
		{
			name: "allowed_ignored",
			event: &AuditEvent{
				Decision: DecisionAllowed,
				ToolName: "read_file",
			},
			wantCount: 0,
		},
		{
			name: "masked_ignored",
			event: &AuditEvent{
				Decision:   DecisionMasked,
				ToolName:   "read_file",
				FilterName: "dlp",
			},
			wantCount: 0,
		},
		{
			name: "pending_ignored",
			event: &AuditEvent{
				Decision: DecisionPending,
				ToolName: "exec_cmd",
			},
			wantCount: 0,
		},
		{
			name: "error_ignored",
			event: &AuditEvent{
				Decision: DecisionError,
				ToolName: "exec_cmd",
			},
			wantCount: 0,
		},
		{
			name: "dlp_block_emits_block_audit_route",
			event: &AuditEvent{
				Decision:    DecisionBlocked,
				ToolName:    "send_email",
				FilterName:  "dlp",
				MatchedRule: "aws_secret_key",
				ErrorCode:   mcp.ErrDLPViolation,
			},
			wantCount: 1,
			wantCat:   notify.CategoryBlock,
			wantFrag:  "audit",
		},
		{
			name: "critical_block_emits_block_audit_route",
			event: &AuditEvent{
				Decision:   DecisionCritical,
				ToolName:   "drop_table",
				FilterName: "guard",
				ErrorCode:  mcp.ErrDLPViolation,
			},
			wantCount: 1,
			wantCat:   notify.CategoryBlock,
			wantFrag:  "audit",
		},
		{
			name: "hitl_operator_denied_dedup_suppressed",
			event: &AuditEvent{
				Decision:     DecisionBlocked,
				ToolName:     "exec_cmd",
				FilterName:   "guard",
				ErrorCode:    mcp.ErrHITLDenied,
				ErrorMessage: "Human-in-the-loop approval denied for tool 'exec_cmd': " + hitltypes.ErrHITLDenied.Error(),
			},
			wantCount: 0,
		},
		{
			name: "hitl_timeout_dedup_suppressed",
			event: &AuditEvent{
				Decision:     DecisionBlocked,
				ToolName:     "exec_cmd",
				FilterName:   "guard",
				ErrorCode:    mcp.ErrHITLDenied,
				ErrorMessage: "Human-in-the-loop approval denied for tool 'exec_cmd': " + hitltypes.ErrHITLTimeout.Error(),
			},
			wantCount: 0,
		},
		{
			name: "hitl_headless_fail_closed_still_alerts_block",
			event: &AuditEvent{
				Decision:     DecisionBlocked,
				ToolName:     "exec_cmd",
				FilterName:   "guard",
				ErrorCode:    mcp.ErrHITLDenied,
				ErrorMessage: "Human-in-the-loop approval denied for tool 'exec_cmd': " + hitltypes.ErrHeadlessFailClosed.Error(),
			},
			wantCount: 1,
			wantCat:   notify.CategoryBlock,
			wantFrag:  "audit",
		},
		{
			name: "hitl_dispatcher_unavailable_still_alerts_block",
			event: &AuditEvent{
				Decision:     DecisionBlocked,
				ToolName:     "exec_cmd",
				FilterName:   "guard",
				ErrorCode:    mcp.ErrHITLDenied,
				ErrorMessage: "Human-in-the-loop approval denied for tool 'exec_cmd': safety dispatcher unavailable",
			},
			wantCount: 1,
			wantCat:   notify.CategoryBlock,
			wantFrag:  "audit",
		},
		{
			name: "audit_verdict_emits_audit_category",
			event: &AuditEvent{
				Decision:     DecisionAudit,
				ToolName:     "search_docs",
				FilterName:   "schema",
				AuditedRules: []string{"schema:missing_field"},
			},
			wantCount: 1,
			wantCat:   notify.CategoryAudit,
			wantFrag:  "audit",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			notifier := &recordingDesktopNotifier{}
			observer := NewAlertAuditLogger(notifier)

			observer.LogEvent(tc.event)

			events := notifier.Events()
			if len(events) != tc.wantCount {
				t.Fatalf("got %d alerts, want %d (%+v)", len(events), tc.wantCount, events)
			}
			if tc.wantCount > 0 {
				if events[0].Category != tc.wantCat {
					t.Errorf("got category %q, want %q", events[0].Category, tc.wantCat)
				}
				if events[0].TargetFragment != tc.wantFrag {
					t.Errorf("got fragment %q, want %q", events[0].TargetFragment, tc.wantFrag)
				}
			}
		})
	}
}
