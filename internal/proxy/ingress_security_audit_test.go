package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/auth"
	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/internal/logger"
)

type spyProxyToolAuditLogger struct {
	mu     sync.Mutex
	events []*filter.AuditEvent
}

func (s *spyProxyToolAuditLogger) LogEvent(ev *filter.AuditEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
}

func (s *spyProxyToolAuditLogger) Events() []*filter.AuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*filter.AuditEvent, len(s.events))
	copy(out, s.events)
	return out
}

type spyProxySecurityAuditLogger struct {
	mu     sync.Mutex
	events []*filter.SecurityAuditEvent
}

func (s *spyProxySecurityAuditLogger) LogSecurityEvent(ev *filter.SecurityAuditEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
}

func (s *spyProxySecurityAuditLogger) Events() []*filter.SecurityAuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*filter.SecurityAuditEvent, len(s.events))
	copy(out, s.events)
	return out
}

func TestContextExtractor_PopulatesAPIKeyIDAndClientIP(t *testing.T) {
	ks := auth.NewMemoryKeyStore()
	rawKey, keyRec, err := ks.GenerateKey("claude-desktop", "Developer", "alpha")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	extractor := NewContextExtractor(ks)

	req := httptest.NewRequest(http.MethodPost, "/message", nil)
	req.RemoteAddr = "198.51.100.42:55555"
	req.Header.Set("Authorization", "Bearer "+rawKey)
	// Even with X-User-ID header present, verified keyRec must always populate APIKeyID and UserID
	req.Header.Set("X-User-ID", "alice-workspace")

	uCtx, err := extractor.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}
	if uCtx.APIKeyID != keyRec.ID {
		t.Errorf("APIKeyID = %q, want %q", uCtx.APIKeyID, keyRec.ID)
	}
	if uCtx.ClientIP != "198.51.100.42" {
		t.Errorf("ClientIP = %q, want 198.51.100.42", uCtx.ClientIP)
	}
	if uCtx.UserID != "claude-desktop" {
		t.Errorf("UserID = %q, want claude-desktop (ignoring spoofed X-User-ID)", uCtx.UserID)
	}
}

func TestSSEProxy_Ingress401And403_EmitSecurityAuditWithoutSecretLeak(t *testing.T) {
	ks := auth.NewMemoryKeyStore()
	scopedRaw, scopedRec, err := ks.GenerateKey("scoped-agent-key", "Developer", "agent-allowed")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	toolSpy := &spyProxyToolAuditLogger{}
	secSpy := &spyProxySecurityAuditLogger{}
	pipeline := filter.NewPipeline(toolSpy)

	repo := agent.NewFSRepository(t.TempDir())
	_ = repo.SaveAgentConfig("agent-allowed", &agent.RouteConfig{
		AgentID:   "agent-allowed",
		AgentName: "agent-allowed",
	})
	_ = repo.SaveAgentConfig("agent-forbidden", &agent.RouteConfig{
		AgentID:   "agent-forbidden",
		AgentName: "agent-forbidden",
	})

	proxy := NewSSEProxy(0, "http://mock-backend/sse", pipeline, repo, nil)
	proxy.SetKeyValidator(ks)
	proxy.SetSecurityAuditLogger(secSpy)
	proxy.httpClient = &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","id":1,"result":{}}`)),
			}, nil
		}),
	}

	h := proxy.Handler()

	// 1. 401 Invalid API key on /sse and /message
	const invalidSecret = "faw_live_completely_invalid_secret_999"
	req401 := httptest.NewRequest(http.MethodGet, "/sse", nil)
	req401.RemoteAddr = "203.0.113.10:1234"
	req401.Header.Set("Authorization", "Bearer "+invalidSecret)
	rec401 := httptest.NewRecorder()
	h.ServeHTTP(rec401, req401)
	if rec401.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid key, got %d", rec401.Code)
	}

	// 2. 403 Scoped key accessing forbidden agent (/mcp/agent-forbidden/message)
	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"echo","arguments":{}},"id":1}`
	req403 := httptest.NewRequest(http.MethodPost, "/mcp/agent-forbidden/message", bytes.NewBufferString(body))
	req403.RemoteAddr = "203.0.113.11:5678"
	req403.Header.Set("Content-Type", "application/json")
	req403.Header.Set("Authorization", "Bearer "+scopedRaw)
	rec403 := httptest.NewRecorder()
	h.ServeHTTP(rec403, req403)
	if rec403.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for cross-agent access, got %d: %s", rec403.Code, rec403.Body.String())
	}

	if got := len(toolSpy.Events()); got != 0 {
		t.Fatalf("expected 0 tool_audit_logs for 401/403 rejections, got %d", got)
	}

	secEvents := secSpy.Events()
	if len(secEvents) < 2 {
		t.Fatalf("expected at least 2 security audit events (401 + 403), got %d", len(secEvents))
	}

	var saw401, saw403 bool
	for _, ev := range secEvents {
		blob, _ := json.Marshal(ev)
		if strings.Contains(string(blob), invalidSecret) || strings.Contains(string(blob), scopedRaw) {
			t.Fatalf("security audit event leaked raw API key: %s", string(blob))
		}
		if ev.EventType == "ingress_auth_failed" && ev.Outcome == "denied" && ev.ClientIP == "203.0.113.10" {
			saw401 = true
		}
		if ev.EventType == "ingress_auth_forbidden" && ev.Outcome == "denied" && ev.ActorID == scopedRec.ID && ev.ClientIP == "203.0.113.11" {
			saw403 = true
		}
	}
	if !saw401 {
		t.Errorf("missing expected ingress_auth_failed event: %+v", secEvents)
	}
	if !saw403 {
		t.Errorf("missing expected ingress_auth_forbidden event (actor=%q): %+v", scopedRec.ID, secEvents)
	}
}

func TestSSEProxy_PropagatesTraceAndAgentToContextLogger(t *testing.T) {
	var logBuf bytes.Buffer
	prevDefault := slog.Default()
	slog.SetDefault(slog.New(logger.NewContextHandler(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))))
	defer slog.SetDefault(prevDefault)

	repo := agent.NewFSRepository(t.TempDir())
	_ = repo.SaveAgentConfig("agent-alpha", &agent.RouteConfig{
		AgentID:   "agent-alpha",
		AgentName: "agent-alpha",
	})

	proxy := NewSSEProxy(0, "http://127.0.0.1:1/unreachable", filter.NewPipeline(nil), repo, nil)
	tok := attachTestBearerAuth(t, proxy)

	// Inject custom RoundTripper that records without external dialing; fails fast so Warn/Info logs emit with r.Context()
	proxy.SetHTTPClient(&http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`)),
			}, nil
		}),
	})

	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}},"id":1}`
	req := httptest.NewRequest(http.MethodPost, "/mcp/agent-alpha", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("X-Trace-ID", "trace-prop-777")

	rec := httptest.NewRecorder()
	proxy.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}

	logged := logBuf.String()
	if !strings.Contains(logged, `"trace_id":"trace-prop-777"`) {
		t.Errorf("expected propagated trace_id in structured logs, got:\n%s", logged)
	}
	if !strings.Contains(logged, `"agent_name":"agent-alpha"`) {
		t.Errorf("expected propagated agent_name in structured logs, got:\n%s", logged)
	}
}
