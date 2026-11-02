package session

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
)

func newTestServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("skipping test requiring loopback socket: %v", err)
	}
	ts := httptest.NewUnstartedServer(h)
	ts.Listener = l
	ts.Start()
	return ts
}

func TestForwarder_ForwardMessage_Success(t *testing.T) {
	ts := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Trace-ID") != "trace-123" {
			t.Errorf("expected X-Trace-ID 'trace-123', got '%s'", r.Header.Get("X-Trace-ID"))
		}
		if r.Header.Get("Authorization") != "Bearer secret-token" {
			t.Errorf("expected Authorization 'Bearer secret-token', got '%s'", r.Header.Get("Authorization"))
		}

		resp := &mcp.Response{
			JSONRPC: "2.0",
			ID:      "req-1",
			Result:  json.RawMessage(`{"status":"ok"}`),
		}
		respBytes, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(respBytes)
	}))
	defer ts.Close()

	cStore := NewMemoryCorrelationStore()
	f := NewForwarder(nil, nil, cStore)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/message", bytes.NewBufferString(`{"jsonrpc":"2.0","method":"ping","id":"req-1"}`))
	userCtx := context.WithValue(context.Background(), filter.TraceIDContextKey, "trace-123")

	f.ForwardMessage(rec, req, userCtx, ts.URL, "target-sess", "client-sess", []byte(`{"jsonrpc":"2.0","method":"ping","id":"req-1"}`), "req-1", "secret-token")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var parsed mcp.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if parsed.ID != "req-1" {
		t.Errorf("expected ID 'req-1', got '%v'", parsed.ID)
	}
}

func TestForwarder_ForwardMessage_PayloadExceeds10MB(t *testing.T) {
	ts := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Write 10MB + 1 byte
		w.Write(make([]byte, (10<<20)+1))
	}))
	defer ts.Close()

	f := NewForwarder(nil, nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/message", bytes.NewBufferString(`{}`))

	f.ForwardMessage(rec, req, context.Background(), ts.URL, "", "cl-1", []byte(`{}`), "req-huge", "")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var parsed mcp.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if parsed.Error == nil || parsed.Error.Code != -32603 {
		t.Errorf("expected -32603 error, got %v", parsed.Error)
	}
}

func TestForwarder_ForwardMessage_Unreachable(t *testing.T) {
	f := NewForwarder(nil, nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/message", bytes.NewBufferString(`{}`))

	// Forward to non-existent port
	f.ForwardMessage(rec, req, context.Background(), "http://127.0.0.1:54321", "", "cl-1", []byte(`{}`), "req-fail", "")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var parsed mcp.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if parsed.Error == nil || parsed.Error.Code != -32001 {
		t.Errorf("expected -32001 error, got %v", parsed.Error)
	}
}

func TestForwarder_ForwardDirectSSE_AndEndpointCallback(t *testing.T) {
	ts := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)

		fmt.Fprintf(w, "event: endpoint\ndata: /backend/message?sessionId=upstream-sess-999\n\n")
		flusher.Flush()

		fmt.Fprintf(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":\"req-10\",\"result\":{\"val\":42}}\n\n")
		flusher.Flush()
	}))
	defer ts.Close()

	f := NewForwarder(nil, nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sse", nil)

	var recordedSessionID, recordedPath string
	f.ForwardDirectSSE(rec, req, ts.URL, func(sessionID, path string) {
		recordedSessionID = sessionID
		recordedPath = path
	})

	if recordedSessionID != "upstream-sess-999" {
		t.Errorf("expected recorded session ID 'upstream-sess-999', got '%s'", recordedSessionID)
	}
	if recordedPath != "/backend/message" {
		t.Errorf("expected recorded path '/backend/message', got '%s'", recordedPath)
	}

	bodyStr := rec.Body.String()
	if !strings.Contains(bodyStr, "event: endpoint") {
		t.Errorf("expected body to contain endpoint event: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, "/message?sessionId=upstream-sess-999") {
		t.Errorf("expected body to contain rewritten endpoint: %s", bodyStr)
	}
}

func TestForwarder_ProcessOutgoingMessage_CorrelationLookup(t *testing.T) {
	cStore := NewMemoryCorrelationStore()
	pipe := filter.NewPipeline(nil)
	f := NewForwarder(nil, pipe, cStore)

	cStore.Put(NewCorrelationKey("cl-1", "req-1"), &PendingRequest{
		ToolName:  "my_tool",
		AgentName: "my_agent",
		Timestamp: time.Now(),
	})

	msg := `{"jsonrpc":"2.0","id":"req-1","result":{"content":[{"type":"text","text":"hello"}]}}`
	processed := f.ProcessOutgoingMessage(msg, "cl-1", "")

	if !strings.Contains(processed, "hello") {
		t.Errorf("expected processed message to contain hello, got: %s", processed)
	}
	if cStore.Count() != 0 {
		t.Errorf("expected correlation store to be cleared, count is %d", cStore.Count())
	}
}
