package admin

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/internal/telemetry/broker"
)

func TestAdminServer_SSEConnection(t *testing.T) {
	cfg := &config.Config{}
	server := NewAdminServer(cfg, func() error { return nil }, func() {})
	b := broker.NewEventBroker(30 * time.Millisecond)
	defer b.Close()
	server.SetEventBroker(b)

	handler := server.Handler()

	// 1. Direct connection to /api/v1/logs/events -> 200 OK text/event-stream
	{
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		req := httptest.NewRequest("GET", "/api/v1/logs/events", nil).WithContext(ctx)
		rec := httptest.NewRecorder()

		done := make(chan struct{})
		go func() {
			handler.ServeHTTP(rec, req)
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(500 * time.Millisecond):
			cancel()
		}

		if rec.Header().Get("Content-Type") != "text/event-stream" {
			t.Fatalf("expected Content-Type text/event-stream, got %s", rec.Header().Get("Content-Type"))
		}
		body := rec.Body.String()
		if !strings.Contains(body, "event: ready") {
			t.Fatalf("expected initial 'event: ready' handshake, got: %s", body)
		}
	}

	// 2. Direct connection to /admin/audit-logs/events -> 200 OK text/event-stream
	{
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		req := httptest.NewRequest("GET", "/admin/audit-logs/events", nil).WithContext(ctx)
		rec := httptest.NewRecorder()

		done := make(chan struct{})
		go func() {
			handler.ServeHTTP(rec, req)
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(500 * time.Millisecond):
			cancel()
		}

		if rec.Header().Get("Content-Type") != "text/event-stream" {
			t.Fatalf("expected Content-Type text/event-stream, got %s", rec.Header().Get("Content-Type"))
		}
	}
}

type pipeResponseWriter struct {
	header     http.Header
	pw         *io.PipeWriter
	statusCode int
}

func (p *pipeResponseWriter) Header() http.Header {
	return p.header
}

func (p *pipeResponseWriter) Write(b []byte) (int, error) {
	return p.pw.Write(b)
}

func (p *pipeResponseWriter) WriteHeader(statusCode int) {
	p.statusCode = statusCode
}

func (p *pipeResponseWriter) Flush() {}

func TestAdminServer_SSEStreamingDelivery(t *testing.T) {
	cfg := &config.Config{}
	server := NewAdminServer(cfg, func() error { return nil }, func() {})
	b := broker.NewEventBroker(30 * time.Millisecond)
	defer b.Close()
	server.SetEventBroker(b)

	pr, pw := io.Pipe()
	defer pr.Close()

	pipeWriter := &pipeResponseWriter{
		header:     make(http.Header),
		pw:         pw,
		statusCode: http.StatusOK,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req := httptest.NewRequestWithContext(ctx, "GET", "/api/v1/logs/events", nil)

	go func() {
		defer pw.Close()
		server.Handler().ServeHTTP(pipeWriter, req)
	}()

	reader := bufio.NewReader(pr)

	// Read initial ready event
	line1, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read line 1: %v", err)
	}
	if !strings.HasPrefix(line1, "event: ready") {
		t.Fatalf("expected 'event: ready', got: %s", line1)
	}

	// Verify subscriber is registered in broker
	if b.SubscriberCount() != 1 {
		t.Fatalf("expected 1 active subscriber in broker, got %d", b.SubscriberCount())
	}

	// Dispatch 3 audit events via broker
	for i := 1; i <= 3; i++ {
		b.LogEvent(&filter.AuditEvent{
			ID:        fmt.Sprintf("live-sse-%d", i),
			ToolName:  "fetch_data",
			AgentName: "orchestrator",
			Decision:  "ALLOW",
		})
	}

	// Read stream until audit_batch event is received
	var receivedData string
	foundEvent := false
	timeout := time.After(2 * time.Second)

readLoop:
	for {
		select {
		case <-timeout:
			t.Fatalf("timed out waiting for audit_batch event")
		default:
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("error reading from stream: %v", err)
			}
			line = strings.TrimSpace(line)
			if line == "event: audit_batch" {
				foundEvent = true
			} else if foundEvent && strings.HasPrefix(line, "data: ") {
				receivedData = strings.TrimPrefix(line, "data: ")
				break readLoop
			}
		}
	}

	var batch []*filter.AuditEvent
	if err := json.Unmarshal([]byte(receivedData), &batch); err != nil {
		t.Fatalf("failed to decode audit_batch json: %v, raw data: %s", err, receivedData)
	}

	if len(batch) != 3 {
		t.Fatalf("expected batch of 3 events, got %d", len(batch))
	}
	if batch[0].ID != "live-sse-1" || batch[2].ID != "live-sse-3" {
		t.Errorf("unexpected event content in batch: %+v", batch)
	}

	// Test graceful disconnection & cleanup
	cancel()
	_ = pr.Close()

	// Wait for disconnection cleanup
	time.Sleep(50 * time.Millisecond)
	if b.SubscriberCount() != 0 {
		t.Fatalf("expected 0 subscribers after connection close, got %d", b.SubscriberCount())
	}
}
