package filter

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/guard"
	"github.com/FaradAiLab/FaradAiWire/internal/guard/hitltypes"
	"github.com/FaradAiLab/FaradAiWire/internal/notify"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
)

type recordingDesktopNotifier struct {
	mu       sync.Mutex
	events   []notify.AlertEvent
	onNotify func(notify.AlertEvent)
}

func (r *recordingDesktopNotifier) Notify(event notify.AlertEvent) bool {
	r.mu.Lock()
	r.events = append(r.events, event)
	cb := r.onNotify
	r.mu.Unlock()
	if cb != nil {
		cb(event)
	}
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

func TestAlertAuditLogger_SecretHygieneAndMetadataFallbacks(t *testing.T) {
	t.Parallel()

	secrets := []string{"sk-live-SUPERSECRET999", "AKIAIOSFODNN7EXAMPLE"}
	cases := []struct {
		name        string
		event       *AuditEvent
		wantCount   int
		wantCat     notify.AlertCategory
		wantContain string
	}{
		{
			name: "method_fallback_and_secret_scrubbing",
			event: &AuditEvent{
				Decision:         DecisionBlocked,
				Method:           "tools/call",
				FilterName:       "dlp",
				ErrorCode:        mcp.ErrDLPViolation,
				RawPayload:       secrets[0],
				OriginalRequest:  secrets[1],
				OriginalResponse: secrets[0],
				ErrorMessage:     "blocked secret " + secrets[0],
				Message:          "message secret " + secrets[1],
			},
			wantCount:   1,
			wantCat:     notify.CategoryBlock,
			wantContain: "method 'tools/call'",
		},
		{
			name: "empty_subject_and_empty_source_fallback",
			event: &AuditEvent{
				Decision: DecisionAudit,
				Message:  secrets[0],
			},
			wantCount:   1,
			wantCat:     notify.CategoryAudit,
			wantContain: "request (policy)",
		},
		{
			name: "hitl_denial_via_Message_field_suppressed",
			event: &AuditEvent{
				Decision:  DecisionBlocked,
				Method:    "tools/call",
				ErrorCode: mcp.ErrHITLDenied,
				Message:   "Human-in-the-loop approval denied by operator",
			},
			wantCount: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			notifier := &recordingDesktopNotifier{}
			observer := NewAlertAuditLogger(notifier)

			observer.LogEvent(tc.event)

			events := notifier.Events()
			if len(events) != tc.wantCount {
				t.Fatalf("got %d events, want %d: %+v", len(events), tc.wantCount, events)
			}
			if tc.wantCount == 0 {
				return
			}
			got := events[0]
			if got.Category != tc.wantCat {
				t.Errorf("got category %q, want %q", got.Category, tc.wantCat)
			}
			if !strings.Contains(got.Message, tc.wantContain) {
				t.Errorf("expected %q in message %q", tc.wantContain, got.Message)
			}
			for _, secret := range secrets {
				if strings.Contains(got.Title, secret) || strings.Contains(got.Message, secret) {
					t.Fatalf("desktop alert leaked sensitive payload %q: title=%q msg=%q", secret, got.Title, got.Message)
				}
			}
		})
	}
}

type stubAgentResolver struct {
	agent.Resolver
	configs map[string]*agent.RouteConfig
}

func (s *stubAgentResolver) GetAgentConfig(agentName string) (*agent.RouteConfig, error) {
	return s.configs[agentName], nil
}

type onlineGuardManager struct{}

func (onlineGuardManager) Start(context.Context, *guard.Model) error         { return nil }
func (onlineGuardManager) StartScript(context.Context, string, string) error { return nil }
func (onlineGuardManager) Stop(context.Context) error                        { return nil }
func (onlineGuardManager) CallInspect(context.Context, *guard.InspectionRequest) (*guard.InspectionResult, error) {
	return &guard.InspectionResult{Verdict: "BENIGN"}, nil
}
func (onlineGuardManager) Status() guard.ProcessStatus { return guard.ProcessStatus{Running: true} }
func (onlineGuardManager) IsRunning() bool             { return true }

func TestPipeline_EndToEnd_GuardHITLAndAlertAuditLogger(t *testing.T) {
	t.Parallel()

	resolver := &stubAgentResolver{
		configs: map[string]*agent.RouteConfig{
			"e2e-agent": {
				AgentName: "e2e-agent",
				ToolGovernance: map[string]agent.ToolGovernanceMode{
					"strict_tool":  agent.ModeStrictAlwaysHITL,
					"guarded_tool": agent.ModeGuardedBlock,
				},
			},
			"audit-agent": {
				AgentName: "audit-agent",
				Guard:     &agent.GuardOverride{Mode: agent.GuardModeAudit},
				ToolGovernance: map[string]agent.ToolGovernanceMode{
					"guarded_tool": agent.ModeGuardedBlock,
				},
			},
		},
	}

	runScenario := func(t *testing.T, agentName string, allowRESTOnly bool, approveOnNotify *bool, toolName, payload string) (*mcp.Error, []notify.AlertEvent) {
		t.Helper()
		notifier := &recordingDesktopNotifier{}

		hitlDisp := guard.NewHITLDispatcher(guard.HITLDispatcherConfig{
			Timeout:         2 * time.Second,
			DisableTTY:      true,
			AllowRESTOnly:   allowRESTOnly,
			DesktopNotifier: notifier,
		})
		if approveOnNotify != nil {
			wantApprove := *approveOnNotify
			notifier.onNotify = func(ev notify.AlertEvent) {
				if ev.Category == notify.CategoryHITLPending {
					for _, pending := range hitlDisp.ListPending() {
						hitlDisp.Resolve(pending.CallID, wantApprove)
					}
				}
			}
		}

		gf := guard.NewFilter(guard.FilterConfig{
			Enabled: true,
			L1Patterns: []config.DLPPattern{
				{Name: "drop_table_block", Regex: `DROP TABLE`, Action: "block"},
			},
		}, onlineGuardManager{})
		gf.SetHITLDispatcher(hitlDisp)
		gf.SetDesktopNotifier(notifier)
		gf.SetAgentRepository(resolver)

		pipe := NewPipeline(NewMultiAuditLogger(NewAlertAuditLogger(notifier)))
		pipe.RegisterFilter(gf)

		ctx := context.WithValue(context.Background(), AgentNameContextKey, agentName)
		req := &mcp.Request{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "tools/call",
			Params:  json.RawMessage(`{"name":"` + toolName + `","arguments":{"sql":"` + payload + `"}}`),
		}
		_, mcpErr := pipe.ProcessRequest(ctx, req)
		return mcpErr, notifier.Events()
	}

	t.Run("headless_hitl_fail_closed_emits_only_block", func(t *testing.T) {
		mcpErr, events := runScenario(t, "e2e-agent", false, nil, "strict_tool", "SELECT 1")
		if mcpErr == nil || mcpErr.Code != mcp.ErrHITLDenied {
			t.Fatalf("expected ErrHITLDenied (%d), got %+v", mcp.ErrHITLDenied, mcpErr)
		}
		if len(events) != 1 {
			t.Fatalf("expected exactly 1 alert (CategoryBlock only), got %d: %+v", len(events), events)
		}
		if events[0].Category != notify.CategoryBlock || events[0].TargetFragment != "audit" {
			t.Fatalf("unexpected alert: %+v", events[0])
		}
	})

	t.Run("interactive_hitl_deny_suppresses_duplicate_block_oq3", func(t *testing.T) {
		deny := false
		mcpErr, events := runScenario(t, "e2e-agent", true, &deny, "strict_tool", "SELECT 1")
		if mcpErr == nil || mcpErr.Code != mcp.ErrHITLDenied {
			t.Fatalf("expected ErrHITLDenied (%d), got %+v", mcp.ErrHITLDenied, mcpErr)
		}
		if len(events) != 1 {
			t.Fatalf("expected exactly 1 alert (HITL pending only, OQ-3 dedup), got %d: %+v", len(events), events)
		}
		if events[0].Category != notify.CategoryHITLPending || events[0].TargetFragment != "audit" {
			t.Fatalf("unexpected alert: %+v", events[0])
		}
	})

	t.Run("interactive_hitl_approve_emits_only_hitl_pending", func(t *testing.T) {
		approve := true
		mcpErr, events := runScenario(t, "e2e-agent", true, &approve, "strict_tool", "SELECT 1")
		if mcpErr != nil {
			t.Fatalf("expected nil error on approved HITL call, got %+v", mcpErr)
		}
		if len(events) != 1 {
			t.Fatalf("expected exactly 1 alert (HITL pending), got %d: %+v", len(events), events)
		}
		if events[0].Category != notify.CategoryHITLPending || events[0].TargetFragment != "audit" {
			t.Fatalf("unexpected alert: %+v", events[0])
		}
	})

	t.Run("l1_guard_block_emits_block_audit_route", func(t *testing.T) {
		mcpErr, events := runScenario(t, "e2e-agent", false, nil, "guarded_tool", "DROP TABLE users")
		if mcpErr == nil || mcpErr.Code != mcp.ErrDLPViolation {
			t.Fatalf("expected ErrDLPViolation (%d), got %+v", mcp.ErrDLPViolation, mcpErr)
		}
		if len(events) != 1 {
			t.Fatalf("expected exactly 1 alert (CategoryBlock), got %d: %+v", len(events), events)
		}
		if events[0].Category != notify.CategoryBlock || events[0].TargetFragment != "audit" {
			t.Fatalf("unexpected alert: %+v", events[0])
		}
	})

	t.Run("l1_guard_audit_mode_emits_audit_category", func(t *testing.T) {
		mcpErr, events := runScenario(t, "audit-agent", false, nil, "guarded_tool", "DROP TABLE users")
		if mcpErr != nil {
			t.Fatalf("expected nil error in guard audit mode, got %+v", mcpErr)
		}
		if len(events) != 1 {
			t.Fatalf("expected exactly 1 alert (CategoryAudit), got %d: %+v", len(events), events)
		}
		if events[0].Category != notify.CategoryAudit || events[0].TargetFragment != "audit" {
			t.Fatalf("unexpected alert: %+v", events[0])
		}
	})
}
