package hitl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/filter/types"
	"github.com/FaradAiLab/FaradAiWire/internal/guard/hitltypes"
	"github.com/FaradAiLab/FaradAiWire/internal/transport"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
)

func TestHITLFilter_WebhookSSRFProtection(t *testing.T) {
	blockedURLs := []struct {
		name string
		url  string
	}{
		{"Cloud Metadata", "http://169.254.169.254/webhook"},
		{"Localhost Loopback", "http://127.0.0.1:8080/webhook"},
		{"Private RFC1918 10.0.0.1", "http://10.0.0.1/webhook"},
		{"Private RFC1918 192.168.1.1", "http://192.168.1.1:3000/webhook"},
		{"Private RFC1918 172.16.0.1", "http://172.16.0.1/api/approve"},
		{"IPv6 Loopback", "http://[::1]:8080/webhook"},
	}

	for _, tt := range blockedURLs {
		t.Run(tt.name, func(t *testing.T) {
			filter := NewHITLFilter(true, []string{"delete_database"}, "webhook", tt.url, 2)

			req := &mcp.Request{
				Method: "tools/call",
				Params: json.RawMessage(`{"name":"delete_database","arguments":{"target":"prod-db"}}`),
			}

			_, mErr := filter.FilterRequest(context.Background(), req)
			if mErr == nil {
				t.Fatalf("Expected HITL request to %s to be blocked by SSRF defense, but it was allowed", tt.url)
			}

			if !strings.Contains(mErr.Message, "SSRF") && !strings.Contains(mErr.Message, "security violation") {
				t.Errorf("Expected SSRF security error message, got: %s", mErr.Message)
			}
		})
	}
}

func TestHITLFilter_NonDestructivePassthrough(t *testing.T) {
	filter := NewHITLFilter(true, []string{"delete_database"}, "webhook", "http://127.0.0.1:8080/webhook", 2)

	req := &mcp.Request{
		Method: "tools/call",
		Params: json.RawMessage(`{"name":"read_document","arguments":{"id":"doc-1"}}`),
	}

	resReq, mErr := filter.FilterRequest(context.Background(), req)
	if mErr != nil {
		t.Fatalf("Expected non-destructive tool to pass through without error, got: %v", mErr)
	}
	if resReq == nil {
		t.Fatal("Expected non-nil request returned")
	}
}

func TestHITLFilter_CLI_ContextCancellation(t *testing.T) {
	filter := NewHITLFilter(true, []string{"delete_database"}, "cli", "", 5)

	pr, pw := io.Pipe()
	defer pw.Close()
	var outBuf bytes.Buffer
	filter.SetCLIReaderWriter(pr, &outBuf)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()

	req := &mcp.Request{
		Method: "tools/call",
		Params: json.RawMessage(`{"name":"delete_database","arguments":{"target":"prod-db"}}`),
	}

	start := time.Now()
	_, mErr := filter.FilterRequest(ctx, req)
	elapsed := time.Since(start)

	if mErr == nil {
		t.Fatal("Expected error on context cancellation, got nil")
	}
	if !strings.Contains(mErr.Message, "context canceled") {
		t.Fatalf("Expected context canceled error, got: %s", mErr.Message)
	}
	if elapsed > 1*time.Second {
		t.Fatalf("Expected promptCLI to abort immediately on context cancellation, took %v", elapsed)
	}
}

func TestHITLFilter_CLI_ApprovalAndRejection(t *testing.T) {
	t.Run("Approve", func(t *testing.T) {
		filter := NewHITLFilter(true, []string{"delete_database"}, "cli", "", 5)
		filter.SetCLIReaderWriter(strings.NewReader("y\n"), &bytes.Buffer{})

		req := &mcp.Request{
			Method: "tools/call",
			Params: json.RawMessage(`{"name":"delete_database","arguments":{"target":"prod-db"}}`),
		}

		res, mErr := filter.FilterRequest(context.Background(), req)
		if mErr != nil {
			t.Fatalf("Expected approval, got error: %v", mErr)
		}
		if res == nil {
			t.Fatal("Expected non-nil request returned on approval")
		}
	})

	t.Run("Reject", func(t *testing.T) {
		filter := NewHITLFilter(true, []string{"delete_database"}, "cli", "", 5)
		filter.SetCLIReaderWriter(strings.NewReader("n\n"), &bytes.Buffer{})

		req := &mcp.Request{
			Method: "tools/call",
			Params: json.RawMessage(`{"name":"delete_database","arguments":{"target":"prod-db"}}`),
		}

		_, mErr := filter.FilterRequest(context.Background(), req)
		if mErr == nil {
			t.Fatal("Expected rejection error, got nil")
		}
		if !strings.Contains(mErr.Message, "rejected") {
			t.Fatalf("Expected rejection message, got: %s", mErr.Message)
		}
	})
}

type hangingRoundTripper struct{}

func (h *hangingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	<-req.Context().Done()
	return nil, req.Context().Err()
}

func TestHITLFilter_Webhook_ContextCancellation(t *testing.T) {
	filter := NewHITLFilter(true, []string{"delete_database"}, "webhook", "http://example.com/webhook", 5)
	filter.SetHTTPClient(&http.Client{
		Transport: &hangingRoundTripper{},
	})

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()

	req := &mcp.Request{
		Method: "tools/call",
		Params: json.RawMessage(`{"name":"delete_database","arguments":{"target":"prod-db"}}`),
	}

	start := time.Now()
	_, mErr := filter.FilterRequest(ctx, req)
	elapsed := time.Since(start)

	if mErr == nil {
		t.Fatal("Expected error on context cancellation, got nil")
	}
	if !strings.Contains(mErr.Message, "context canceled") {
		t.Fatalf("Expected context canceled error, got: %s", mErr.Message)
	}
	if elapsed > 1*time.Second {
		t.Fatalf("Expected promptWebhook to abort immediately on context cancellation, took %v", elapsed)
	}
}

type mockHITLApprover struct {
	called      bool
	lastReq     *hitltypes.HITLRequest
	hasDeadline bool
	approved    bool
	err         error
}

func (m *mockHITLApprover) RequestApproval(ctx context.Context, req *hitltypes.HITLRequest) (bool, error) {
	m.called = true
	m.lastReq = req
	_, m.hasDeadline = ctx.Deadline()
	return m.approved, m.err
}

func TestHITLFilter_DelegatesToHITLDispatcher(t *testing.T) {
	t.Run("ApprovedViaDispatcher", func(t *testing.T) {
		f := NewHITLFilter(true, []string{"delete_database"}, "cli", "", 60)
		approver := &mockHITLApprover{approved: true}
		f.SetHITLDispatcher(approver)

		req := &mcp.Request{
			Method: "tools/call",
			Params: json.RawMessage(`{"name":"delete_database","arguments":{"target":"prod"}}`),
		}

		res, mErr := f.FilterRequest(context.Background(), req)
		if mErr != nil {
			t.Fatalf("expected nil error on dispatcher approval, got %v", mErr)
		}
		if res == nil {
			t.Fatal("expected non-nil request")
		}
		if !approver.called || approver.lastReq == nil || approver.lastReq.ToolName != "delete_database" {
			t.Fatalf("expected HITLApprover to be called with delete_database, got called=%v req=%+v", approver.called, approver.lastReq)
		}
		if !approver.hasDeadline {
			t.Fatalf("expected FilterRequest to pass bounded timeout deadline to dispatcher")
		}
	})

	t.Run("DeniedViaDispatcher", func(t *testing.T) {
		f := NewHITLFilter(true, []string{"delete_database"}, "cli", "", 60)
		approver := &mockHITLApprover{approved: false, err: hitltypes.ErrHITLDenied}
		f.SetHITLDispatcher(approver)

		req := &mcp.Request{
			Method: "tools/call",
			Params: json.RawMessage(`{"name":"delete_database","arguments":{"target":"prod"}}`),
		}

		_, mErr := f.FilterRequest(context.Background(), req)
		if mErr == nil || mErr.Code != mcp.ErrHITLDenied {
			t.Fatalf("expected ErrHITLDenied, got %+v", mErr)
		}
	})

	t.Run("HeadlessFailClosed", func(t *testing.T) {
		f := NewHITLFilter(true, []string{"delete_database"}, "cli", "", 60)
		approver := &mockHITLApprover{approved: false, err: hitltypes.ErrHeadlessFailClosed}
		f.SetHITLDispatcher(approver)

		req := &mcp.Request{
			Method: "tools/call",
			Params: json.RawMessage(`{"name":"delete_database","arguments":{"target":"prod"}}`),
		}

		_, mErr := f.FilterRequest(context.Background(), req)
		if mErr == nil || mErr.Code != mcp.ErrHITLDenied {
			t.Fatalf("expected ErrHITLDenied on headless fail-closed, got %+v", mErr)
		}
		if !errors.Is(hitltypes.ErrHeadlessFailClosed, approver.err) || !strings.Contains(mErr.Message, "headless") {
			t.Fatalf("expected headless error detail, got %s", mErr.Message)
		}
	})

	t.Run("WebhookModeBypassesDispatcher", func(t *testing.T) {
		f := NewHITLFilter(true, []string{"delete_database"}, "webhook", "http://127.0.0.1:8080/hook", 5)
		approver := &mockHITLApprover{approved: true}
		f.SetHITLDispatcher(approver)

		req := &mcp.Request{
			Method: "tools/call",
			Params: json.RawMessage(`{"name":"delete_database","arguments":{"target":"prod"}}`),
		}

		_, _ = f.FilterRequest(context.Background(), req)
		if approver.called {
			t.Error("expected webhook mode not to delegate to interactive HITLDispatcher")
		}
	})
}

func TestHITLFilter_SafetyEdgeCases(t *testing.T) {
	t.Run("NilRequest", func(t *testing.T) {
		f := NewHITLFilter(true, []string{"delete_database"}, "cli", "", 5)
		res, mErr := f.FilterRequest(context.Background(), nil)
		if mErr != nil || res != nil {
			t.Fatalf("expected (nil, nil) for nil request, got (%v, %v)", res, mErr)
		}
	})

	t.Run("AlreadyHumanApproved_SkipsDoublePrompt", func(t *testing.T) {
		f := NewHITLFilter(true, []string{"delete_database"}, "cli", "", 5)
		approver := &mockHITLApprover{approved: false, err: errors.New("should not be called")}
		f.SetHITLDispatcher(approver)

		ctx := types.WithHumanApproved(context.Background(), true)
		req := &mcp.Request{
			Method: "tools/call",
			Params: json.RawMessage(`{"name":"delete_database","arguments":{"target":"prod"}}`),
		}
		res, mErr := f.FilterRequest(ctx, req)
		if mErr != nil || res == nil {
			t.Fatalf("expected pre-approved context to pass without re-prompting, got (%v, %v)", res, mErr)
		}
		if approver.called {
			t.Fatal("dispatcher should not be called when request is already human approved")
		}
	})

	t.Run("WebhookModeWithEmptyURL_FailsClosed", func(t *testing.T) {
		f := NewHITLFilter(true, []string{"delete_database"}, "WEBHOOK", "   ", 5)
		approver := &mockHITLApprover{approved: true}
		f.SetHITLDispatcher(approver)

		req := &mcp.Request{
			Method: "tools/call",
			Params: json.RawMessage(`{"name":"delete_database","arguments":{"target":"prod"}}`),
		}
		_, mErr := f.FilterRequest(context.Background(), req)
		if mErr == nil || mErr.Code != mcp.ErrHITLDenied {
			t.Fatalf("expected ErrHITLDenied when webhook URL is missing, got %+v", mErr)
		}
		if approver.called {
			t.Fatal("webhook mode without URL must fail-closed, not fall back to dispatcher")
		}
	})

	t.Run("WebhookSSRFError_StripsRawURLSecrets", func(t *testing.T) {
		f := NewHITLFilter(true, []string{"delete_database"}, "webhook", "https://user:secretpass@127.0.0.1:8080/hook?token=topsecret", 5)
		req := &mcp.Request{
			Method: "tools/call",
			Params: json.RawMessage(`{"name":"delete_database","arguments":{"target":"prod"}}`),
		}
		_, mErr := f.FilterRequest(context.Background(), req)
		if mErr == nil {
			t.Fatal("expected SSRF error")
		}
		if strings.Contains(mErr.Message, "secretpass") || strings.Contains(mErr.Message, "topsecret") {
			t.Fatalf("raw webhook URL credentials/query leaked in error message: %s", mErr.Message)
		}
	})

	t.Run("WebhookResponseSizeCapped", func(t *testing.T) {
		f := NewHITLFilterWithSSRF(true, []string{"delete_database"}, "webhook", "https://hooks.example.com/approve", 5, transport.SafeTransportOptions{Enabled: false})
		hugePadding := strings.Repeat(" ", (1<<20)+64)
		f.SetHTTPClient(&http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(hugePadding + `{"approved":true}`)),
				}, nil
			}),
		})

		req := &mcp.Request{
			Method: "tools/call",
			Params: json.RawMessage(`{"name":"delete_database","arguments":{"target":"prod"}}`),
		}
		_, mErr := f.FilterRequest(context.Background(), req)
		if mErr == nil {
			t.Fatal("expected decode failure when webhook response exceeds 1 MiB limit")
		}
	})

	t.Run("CLITimeout_ReturnsErrHITLTimeout", func(t *testing.T) {
		f := NewHITLFilter(true, []string{"delete_database"}, "cli", "", 1)
		f.timeout = 30 * time.Millisecond
		pr, pw := io.Pipe()
		defer pr.Close()
		defer pw.Close()
		f.SetCLIReaderWriter(pr, &bytes.Buffer{})

		req := &mcp.Request{
			Method: "tools/call",
			Params: json.RawMessage(`{"name":"delete_database","arguments":{"target":"prod"}}`),
		}
		_, mErr := f.FilterRequest(context.Background(), req)
		if mErr == nil || !strings.Contains(mErr.Message, hitltypes.ErrHITLTimeout.Error()) {
			t.Fatalf("expected ErrHITLTimeout message, got %+v", mErr)
		}
	})

	t.Run("MatchesAggregatedPrefixedDestructiveTool", func(t *testing.T) {
		f := NewHITLFilter(true, []string{"delete_file"}, "cli", "", 5)
		f.SetCLIReaderWriter(strings.NewReader("n\n"), &bytes.Buffer{})

		req := &mcp.Request{
			Method: "tools/call",
			Params: json.RawMessage(`{"name":"fs_abc123__delete_file","arguments":{"path":"/tmp/x"}}`),
		}
		_, mErr := f.FilterRequest(context.Background(), req)
		if mErr == nil || mErr.Code != mcp.ErrHITLDenied {
			t.Fatalf("expected aggregated prefixed tool to hit destructive_tools HITL gate, got %+v", mErr)
		}
	})

	t.Run("MatchesCaseInsensitiveDestructiveTool", func(t *testing.T) {
		f := NewHITLFilter(true, []string{"Delete_File"}, "cli", "", 5)
		f.SetCLIReaderWriter(strings.NewReader("n\n"), &bytes.Buffer{})

		for _, toolName := range []string{"DELETE_FILE", "fs__DELETE_FILE", "fs_abc123__Delete_File"} {
			req := &mcp.Request{
				Method: "tools/call",
				Params: json.RawMessage(`{"name":"` + toolName + `","arguments":{"path":"/tmp/x"}}`),
			}
			_, mErr := f.FilterRequest(context.Background(), req)
			if mErr == nil || mErr.Code != mcp.ErrHITLDenied {
				t.Fatalf("expected tool %q to hit case-insensitive destructive_tools HITL gate, got %+v", toolName, mErr)
			}
		}
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }
