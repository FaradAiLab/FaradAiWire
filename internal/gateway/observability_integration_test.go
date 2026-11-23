package gateway_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/gateway"
)

func TestGateway_RealObservabilityWiringAndDrainingTransition(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("FARADAI_WIRE_HOME", tempDir)

	cfg := &config.Config{
		RuntimeMode:  config.RuntimeModeStandalone,
		ListenHost:   "127.0.0.1",
		ListenPort:   19490,
		AdminHost:    "127.0.0.1",
		AdminPort:    19495,
		Mode:         "sse",
		AgentsDir:    filepath.Join(tempDir, "agents"),
		ProtocolsDir: filepath.Join(tempDir, "protocols"),
		AuditLog: config.AuditLogConfig{
			Enabled: true,
			Path:    filepath.Join(tempDir, "logs", "audit.jsonl"),
		},
		Telemetry: config.TelemetryConfig{
			DBPath: filepath.Join(tempDir, "wire.duckdb"),
		},
	}

	provider := &mockConfigProvider{cfg: cfg}
	srv, err := gateway.NewServer(cfg, provider)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	proxyH := srv.ProxyHandler()
	adminH := srv.AdminHandler()

	// 1. Before draining: /health returns 200 and /admin/readyz returns 200 healthy
	recHealth := httptest.NewRecorder()
	proxyH.ServeHTTP(recHealth, httptest.NewRequest(http.MethodGet, "/health", nil))
	if recHealth.Code != http.StatusOK {
		t.Fatalf("expected /health 200 before shutdown, got %d (%s)", recHealth.Code, recHealth.Body.String())
	}

	recReady := httptest.NewRecorder()
	adminH.ServeHTTP(recReady, httptest.NewRequest(http.MethodGet, "/admin/readyz", nil))
	if recReady.Code != http.StatusOK {
		t.Fatalf("expected /admin/readyz 200 before shutdown, got %d (%s)", recReady.Code, recReady.Body.String())
	}

	// 2. /admin/analytics/summary, /admin/security-audit-logs, /admin/audit/verify, /admin/audit-logs/export
	for _, ep := range []struct {
		path string
		want string
	}{
		{"/admin/analytics/summary?window=1h", `"window":"1h"`},
		{"/admin/security-audit-logs", `"events":`},
		{"/admin/audit/verify", `"tool_audit_logs":{"checked":`},
		{"/admin/audit/verify", `"entries_checked":`},
		{"/admin/audit-logs/export?format=csv", "integrity_hash"},
	} {
		rec := httptest.NewRecorder()
		adminH.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, ep.path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 on %s, got %d (%s)", ep.path, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), ep.want) {
			t.Fatalf("expected %s body to contain %q, got %s", ep.path, ep.want, rec.Body.String())
		}
	}

	// 3. /admin/metrics emits wired gauges & HTTP counters from real AdminServer
	recMetrics := httptest.NewRecorder()
	adminH.ServeHTTP(recMetrics, httptest.NewRequest(http.MethodGet, "/admin/metrics", nil))
	if recMetrics.Code != http.StatusOK {
		t.Fatalf("expected 200 on /admin/metrics, got %d", recMetrics.Code)
	}
	metricsBody := recMetrics.Body.String()
	for _, metric := range []string{
		"faradaiwire_active_sessions ",
		"faradaiwire_correlation_entries ",
		`faradaiwire_telemetry_dropped_events_total{sink="duckdb"}`,
		`faradaiwire_telemetry_dropped_events_total{sink="broker"}`,
		`faradaiwire_telemetry_dropped_events_total{sink="jsonl"}`,
		`faradaiwire_http_responses_total{code_class="2xx",port="admin"}`,
		"faradaiwire_process_uptime_seconds ",
	} {
		if !strings.Contains(metricsBody, metric) {
			t.Errorf("expected /admin/metrics to contain %q\ngot:\n%s", metric, metricsBody)
		}
	}

	// 4. Trigger Shutdown: both /health and /admin/readyz transition to 503
	shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	recHealthDrain := httptest.NewRecorder()
	proxyH.ServeHTTP(recHealthDrain, httptest.NewRequest(http.MethodGet, "/health", nil))
	if recHealthDrain.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected /health 503 after draining, got %d", recHealthDrain.Code)
	}

	recReadyDrain := httptest.NewRecorder()
	adminH.ServeHTTP(recReadyDrain, httptest.NewRequest(http.MethodGet, "/admin/readyz", nil))
	if recReadyDrain.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected /admin/readyz 503 during draining, got %d (%s)", recReadyDrain.Code, recReadyDrain.Body.String())
	}
	var readyPayload map[string]interface{}
	if err := json.Unmarshal(recReadyDrain.Body.Bytes(), &readyPayload); err != nil {
		t.Fatalf("decode readyz draining JSON: %v", err)
	}
	if readyPayload["status"] != "draining" || readyPayload["draining"] != true {
		t.Fatalf("expected status=draining & draining=true, got %+v", readyPayload)
	}
}
