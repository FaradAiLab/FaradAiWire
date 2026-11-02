package hitl

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

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
