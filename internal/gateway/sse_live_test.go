package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/filter"
)

type ssePipeResponseWriter struct {
	header http.Header
	pw     *io.PipeWriter
	code   int
}

func (p *ssePipeResponseWriter) Header() http.Header {
	return p.header
}

func (p *ssePipeResponseWriter) Write(b []byte) (int, error) {
	return p.pw.Write(b)
}

func (p *ssePipeResponseWriter) WriteHeader(code int) {
	p.code = code
}

func (p *ssePipeResponseWriter) Flush() {}

func TestGateway_SSELiveStreamingIntegration(t *testing.T) {
	cfg := &config.Config{
		Mode:       "sse",
		ListenPort: 8080,
		AdminPort:  8095,
		Filters:    config.FiltersConfig{},
		Telemetry: config.TelemetryConfig{
			DBPath: filepath.Join(t.TempDir(), "live_telemetry.duckdb"),
		},
	}

	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("failed to create gateway server: %v", err)
	}
	defer func() {
		_ = server.Shutdown(context.Background())
	}()

	if server.EventBroker() == nil {
		t.Fatalf("expected server.EventBroker to be initialized")
	}

	// 1. Establish SSE Client connection to /api/v1/logs/events
	pr, pw := io.Pipe()
	defer pr.Close()

	pipeWriter := &ssePipeResponseWriter{
		header: make(http.Header),
		pw:     pw,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req := httptest.NewRequestWithContext(ctx, "GET", "/api/v1/logs/events", nil)
	req.Header.Set("Authorization", "Bearer admin-live-key")

	go func() {
		defer pw.Close()
		server.AdminHandler().ServeHTTP(pipeWriter, req)
	}()

	reader := bufio.NewReader(pr)

	// Read initial handshake
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read handshake from SSE stream: %v", err)
	}
	if !strings.HasPrefix(line, "event: ready") {
		t.Fatalf("expected 'event: ready', got: %s", line)
	}

	// Verify subscriber registration
	if server.EventBroker().SubscriberCount() != 1 {
		t.Fatalf("expected 1 active subscriber, got %d", server.EventBroker().SubscriberCount())
	}

	// 2. Simulate 20 tool calls executed through the pipeline's combinedLogger
	const numEvents = 20
	for i := 1; i <= numEvents; i++ {
		server.combinedLogger.LogEvent(&filter.AuditEvent{
			ID:        fmt.Sprintf("e2e-tool-call-%d", i),
			ToolName:  fmt.Sprintf("tool_%d", i),
			AgentName: "claude-code",
			Decision:  "ALLOW",
			LatencyMs: 1.5,
		})
	}

	// 3. Read debounced batch from SSE stream
	var batchData string
	foundBatch := false
	timeout := time.After(2 * time.Second)

readLoop:
	for {
		select {
		case <-timeout:
			t.Fatalf("timed out waiting for debounced SSE audit_batch event")
		default:
			l, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("read error: %v", err)
			}
			l = strings.TrimSpace(l)
			if l == "event: audit_batch" {
				foundBatch = true
			} else if foundBatch && strings.HasPrefix(l, "data: ") {
				batchData = strings.TrimPrefix(l, "data: ")
				break readLoop
			}
		}
	}

	var events []*filter.AuditEvent
	if err := json.Unmarshal([]byte(batchData), &events); err != nil {
		t.Fatalf("failed to unmarshal SSE audit_batch: %v, raw data: %s", err, batchData)
	}

	if len(events) != numEvents {
		t.Fatalf("expected debounced batch of %d events, got %d", numEvents, len(events))
	}
	if events[0].ID != "e2e-tool-call-1" || events[numEvents-1].ID != fmt.Sprintf("e2e-tool-call-%d", numEvents) {
		t.Fatalf("unexpected events ordering in batch: first=%s, last=%s", events[0].ID, events[numEvents-1].ID)
	}

	// 4. Test client teardown
	cancel()
	_ = pr.Close()
	time.Sleep(50 * time.Millisecond)

	if server.EventBroker().SubscriberCount() != 0 {
		t.Fatalf("expected 0 subscribers after connection close, got %d", server.EventBroker().SubscriberCount())
	}
}
