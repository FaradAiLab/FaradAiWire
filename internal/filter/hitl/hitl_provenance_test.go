package hitl_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/hitl"
	"github.com/FaradAiLab/FaradAiWire/internal/guard"
	"github.com/FaradAiLab/FaradAiWire/internal/guard/hitltypes"
	"github.com/FaradAiLab/FaradAiWire/internal/transport"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
)

type spyToolAuditLogger struct {
	mu     sync.Mutex
	events []*filter.AuditEvent
}

func (s *spyToolAuditLogger) LogEvent(ev *filter.AuditEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
}

func (s *spyToolAuditLogger) Events() []*filter.AuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*filter.AuditEvent, len(s.events))
	copy(out, s.events)
	return out
}

func TestPipeline_HITLProvenance_AllChannels(t *testing.T) {
	cases := []struct {
		name            string
		mode            string
		channel         string
		actorID         string
		wantApproved    bool
		wantChannel     string
		wantApprovedBy  string
		wantOutcome     string
		cliInput        string
		webhookResponse string
		timeout         int
	}{
		{
			name:           "web_rest approve",
			mode:           "dispatcher",
			channel:        "web_rest",
			actorID:        "key_rest_op",
			wantApproved:   true,
			wantChannel:    "web_rest",
			wantApprovedBy: "key_rest_op",
			wantOutcome:    "allowed",
			timeout:        2,
		},
		{
			name:           "web_ws deny",
			mode:           "dispatcher",
			channel:        "web_ws",
			actorID:        "key_ws_op",
			wantApproved:   false,
			wantChannel:    "web_ws",
			wantApprovedBy: "key_ws_op",
			wantOutcome:    "denied",
			timeout:        2,
		},
		{
			name:           "cli_tty approve",
			mode:           "cli_tty",
			cliInput:       "y\n",
			wantApproved:   true,
			wantChannel:    "cli_tty",
			wantApprovedBy: "local-operator",
			wantOutcome:    "allowed",
			timeout:        2,
		},
		{
			name:            "webhook approve with actor",
			mode:            "webhook",
			webhookResponse: `{"approved":true,"approved_by":"pagerduty:oncall-1"}`,
			wantApproved:    true,
			wantChannel:     "webhook",
			wantApprovedBy:  "pagerduty:oncall-1",
			wantOutcome:     "allowed",
			timeout:         2,
		},
		{
			name:            "webhook deny",
			mode:            "webhook",
			webhookResponse: `{"approved":false}`,
			wantApproved:    false,
			wantChannel:     "webhook",
			wantApprovedBy:  "webhook",
			wantOutcome:     "denied",
			timeout:         2,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var resolved []hitltypes.HITLResolutionInfo

			webhookURL := "http://127.0.0.1:0/unused"
			if tc.mode == "webhook" {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(tc.webhookResponse))
				}))
				defer srv.Close()
				webhookURL = srv.URL
			}

			modeStr := "cli"
			if tc.mode == "webhook" {
				modeStr = "webhook"
			}
			hf := hitl.NewHITLFilterWithSSRF(true, []string{"delete_db"}, modeStr, webhookURL, tc.timeout, transport.SafeTransportOptions{Enabled: false})
			hf.SetOnResolved(func(info hitltypes.HITLResolutionInfo) {
				mu.Lock()
				defer mu.Unlock()
				resolved = append(resolved, info)
			})

			switch tc.mode {
			case "dispatcher":
				d := guard.NewHITLDispatcher(guard.HITLDispatcherConfig{
					Timeout:       time.Duration(tc.timeout) * time.Second,
					DisableTTY:    true,
					AllowRESTOnly: true,
					OnResolved: func(info hitltypes.HITLResolutionInfo) {
						mu.Lock()
						defer mu.Unlock()
						resolved = append(resolved, info)
					},
				})
				hf.SetHITLDispatcher(d)
				go func() {
					deadline := time.Now().Add(time.Second)
					for time.Now().Before(deadline) {
						if pending := d.ListPending(); len(pending) > 0 {
							d.ResolveWithContext(pending[0].CallID, tc.wantApproved, tc.channel, tc.actorID, "10.0.0.5")
							return
						}
						time.Sleep(5 * time.Millisecond)
					}
				}()
			case "cli_tty":
				hf.SetCLIReaderWriter(strings.NewReader(tc.cliInput), &bytes.Buffer{})
			}

			auditLogger := &spyToolAuditLogger{}
			pipeline := filter.NewPipeline(auditLogger)
			pipeline.RegisterFilter(hf)

			ctx := context.WithValue(context.Background(), filter.UserContextKey, &filter.UserContext{
				Role:     "Developer",
				UserID:   "dev-1",
				APIKeyID: "key_dev_1",
				ClientIP: "192.0.2.10",
			})
			req := &mcp.Request{
				JSONRPC: "2.0",
				ID:      json.RawMessage(`1`),
				Method:  "tools/call",
				Params:  json.RawMessage(`{"name":"delete_db","arguments":{"target":"tmp"}}`),
			}

			_, mErr := pipeline.ProcessRequest(ctx, req)
			if tc.wantApproved && mErr != nil {
				t.Fatalf("expected approval passthrough, got error: %v", mErr)
			}
			if !tc.wantApproved && mErr == nil {
				t.Fatal("expected denial error, got nil")
			}

			events := auditLogger.Events()
			if len(events) == 0 {
				t.Fatal("expected at least 1 AuditEvent in pipeline")
			}
			ev := events[len(events)-1]
			if ev.HumanApproved != tc.wantApproved {
				t.Errorf("AuditEvent.HumanApproved = %v, want %v", ev.HumanApproved, tc.wantApproved)
			}
			if ev.ApprovedBy != tc.wantApprovedBy {
				t.Errorf("AuditEvent.ApprovedBy = %q, want %q", ev.ApprovedBy, tc.wantApprovedBy)
			}
			if ev.ApprovalChannel != tc.wantChannel {
				t.Errorf("AuditEvent.ApprovalChannel = %q, want %q", ev.ApprovalChannel, tc.wantChannel)
			}
			if ev.User == nil || ev.User.APIKeyID != "key_dev_1" || ev.User.ClientIP != "192.0.2.10" {
				t.Errorf("AuditEvent.User attribution lost: %+v", ev.User)
			}

			mu.Lock()
			defer mu.Unlock()
			if len(resolved) != 1 {
				t.Fatalf("expected 1 HITL resolution callback, got %d (%+v)", len(resolved), resolved)
			}
			if resolved[0].ApprovalChannel != tc.wantChannel || resolved[0].ApprovedBy != tc.wantApprovedBy || resolved[0].Outcome != tc.wantOutcome {
				t.Fatalf("unexpected HITL resolution info: %+v", resolved[0])
			}
		})
	}
}
