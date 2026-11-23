package guard

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/guard/hitltypes"
)

func TestHITLDispatcher_FourChannelAndOutcomeProvenance(t *testing.T) {
	t.Parallel()

	t.Run("ResolveWithContext records actor, IP, channel on request and callback", func(t *testing.T) {
		var mu sync.Mutex
		var resolved []hitltypes.HITLResolutionInfo

		d := NewHITLDispatcher(HITLDispatcherConfig{
			Timeout:       2 * time.Second,
			DisableTTY:    true,
			AllowRESTOnly: true,
			OnResolved: func(info hitltypes.HITLResolutionInfo) {
				mu.Lock()
				defer mu.Unlock()
				resolved = append(resolved, info)
			},
		})
		if !d.HasOnResolved() {
			t.Fatal("expected HasOnResolved() == true")
		}

		req := &HITLRequest{
			CallID:         "prov-rest-1",
			ToolName:       "exec_sql",
			DecisionEngine: "STRICT_HITL_GATE",
		}
		go func() {
			time.Sleep(15 * time.Millisecond)
			if !d.ResolveWithContext("prov-rest-1", true, "web_rest", "key_admin_42", "203.0.113.5") {
				t.Error("expected ResolveWithContext to return true")
			}
		}()

		approved, err := d.RequestApproval(context.Background(), req)
		if err != nil || !approved {
			t.Fatalf("RequestApproval = (%v, %v), want (true, nil)", approved, err)
		}
		if req.ApprovedBy != "key_admin_42" || req.ApprovalChannel != "web_rest" || req.ResolutionState != "approved" {
			t.Fatalf("unexpected HITLRequest provenance: %+v", req)
		}

		mu.Lock()
		defer mu.Unlock()
		if len(resolved) != 1 {
			t.Fatalf("expected 1 OnResolved call, got %d", len(resolved))
		}
		if resolved[0].ApprovedBy != "key_admin_42" || resolved[0].ApprovalChannel != "web_rest" || resolved[0].ActorIP != "203.0.113.5" || resolved[0].Outcome != "allowed" {
			t.Fatalf("unexpected resolution info: %+v", resolved[0])
		}
	})

	t.Run("cli_tty denial sets local-operator and cli_tty", func(t *testing.T) {
		var mu sync.Mutex
		var resolved []hitltypes.HITLResolutionInfo

		in := bytes.NewBufferString("n\n")
		out := &bytes.Buffer{}
		d := NewHITLDispatcher(HITLDispatcherConfig{
			Timeout: 2 * time.Second,
			TTYIn:   in,
			TTYOut:  out,
			OnResolved: func(info hitltypes.HITLResolutionInfo) {
				mu.Lock()
				defer mu.Unlock()
				resolved = append(resolved, info)
			},
		})

		req := &HITLRequest{
			CallID:         "prov-tty-1",
			ToolName:       "drop_table",
			DecisionEngine: "STRICT_HITL_GATE",
		}
		approved, err := d.RequestApproval(context.Background(), req)
		if approved || err != ErrHITLDenied {
			t.Fatalf("RequestApproval = (%v, %v), want (false, ErrHITLDenied)", approved, err)
		}
		if req.ApprovalChannel != "cli_tty" || req.ApprovedBy != "local-operator" || req.ResolutionState != "denied" {
			t.Fatalf("unexpected TTY HITLRequest provenance: %+v", req)
		}

		mu.Lock()
		defer mu.Unlock()
		if len(resolved) != 1 || resolved[0].ApprovalChannel != "cli_tty" || resolved[0].Outcome != "denied" {
			t.Fatalf("unexpected TTY resolution info: %+v", resolved)
		}
	})

	t.Run("timeout sets system:timeout and emits timeout outcome", func(t *testing.T) {
		var mu sync.Mutex
		var resolved []hitltypes.HITLResolutionInfo

		d := NewHITLDispatcher(HITLDispatcherConfig{
			Timeout:       40 * time.Millisecond,
			DisableTTY:    true,
			AllowRESTOnly: true,
			OnResolved: func(info hitltypes.HITLResolutionInfo) {
				mu.Lock()
				defer mu.Unlock()
				resolved = append(resolved, info)
			},
		})

		req := &HITLRequest{
			CallID:         "prov-timeout-1",
			ToolName:       "send_email",
			DecisionEngine: "DLP_HITL_GATE",
		}
		approved, err := d.RequestApproval(context.Background(), req)
		if approved || err != ErrHITLTimeout {
			t.Fatalf("RequestApproval = (%v, %v), want (false, ErrHITLTimeout)", approved, err)
		}
		if req.ApprovedBy != "system:timeout" || !strings.HasPrefix(req.ApprovalChannel, "web_") && req.ApprovalChannel != "cli_tty" {
			t.Fatalf("unexpected timeout provenance: %+v", req)
		}

		mu.Lock()
		defer mu.Unlock()
		if len(resolved) != 1 || resolved[0].Outcome != "timeout" || resolved[0].ApprovedBy != "system:timeout" {
			t.Fatalf("unexpected timeout resolution info: %+v", resolved)
		}
	})
}
