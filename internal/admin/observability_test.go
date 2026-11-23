package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/internal/guard"
	"github.com/FaradAiLab/FaradAiWire/internal/metrics"
	"github.com/FaradAiLab/FaradAiWire/internal/telemetry/broker"
	"github.com/FaradAiLab/FaradAiWire/internal/telemetry/duckdb"
)

type mockGuardWithLatency struct {
	running   bool
	modelID   string
	pid       int
	latencyMS float64
}

func (m *mockGuardWithLatency) Start(ctx context.Context, model *guard.Model) error { return nil }
func (m *mockGuardWithLatency) StartScript(ctx context.Context, scriptPath string, modelID string) error {
	return nil
}
func (m *mockGuardWithLatency) Stop(ctx context.Context) error { return nil }
func (m *mockGuardWithLatency) Status() guard.ProcessStatus {
	return guard.ProcessStatus{Running: m.running, ModelID: m.modelID, PID: m.pid}
}
func (m *mockGuardWithLatency) IsRunning() bool { return m.running }
func (m *mockGuardWithLatency) CallInspect(ctx context.Context, req *guard.InspectionRequest) (*guard.InspectionResult, error) {
	return &guard.InspectionResult{Verdict: "BENIGN"}, nil
}
func (m *mockGuardWithLatency) AverageLatencyMS() float64 { return m.latencyMS }

func TestAdminMetrics_EndpointAndAuth(t *testing.T) {
	reg := metrics.NewRegistry()
	reg.ObserveRequest("ALLOWED", "request", "dlp", "fast")

	// 1. Non-loopback host enforces admin auth (401 without bearer/session).
	srvAuth := newTestAdminServer(func(d *AdminDependencies) {
		d.Config = &config.Config{
			RuntimeMode: config.RuntimeModeStandalone,
			AdminHost:   "0.0.0.0",
			AdminPort:   19415,
		}
		d.Metrics = reg
	})
	t.Setenv("FARADAI_WIRE_ADMIN_TOKEN", "metrics-admin-secret")
	defer func() { _ = srvAuth.Shutdown(context.Background()) }()

	handler := srvAuth.Handler()

	reqUnauth := httptest.NewRequest(http.MethodGet, "/admin/metrics", nil)
	recUnauth := httptest.NewRecorder()
	handler.ServeHTTP(recUnauth, reqUnauth)
	if recUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on unauthenticated /admin/metrics on 0.0.0.0, got %d (%s)", recUnauth.Code, recUnauth.Body.String())
	}

	reqAuth := httptest.NewRequest(http.MethodGet, "/admin/metrics", nil)
	reqAuth.Header.Set("Authorization", "Bearer metrics-admin-secret")
	recAuth := httptest.NewRecorder()
	handler.ServeHTTP(recAuth, reqAuth)
	if recAuth.Code != http.StatusOK {
		t.Fatalf("expected 200 on authenticated /admin/metrics, got %d (%s)", recAuth.Code, recAuth.Body.String())
	}
	ct := recAuth.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") || !strings.Contains(ct, "0.0.4") {
		t.Errorf("expected Prometheus Content-Type text/plain; version=0.0.4, got %q", ct)
	}
	body := recAuth.Body.String()
	if !strings.Contains(body, `faradaiwire_requests_total{decision="allowed",filter="dlp",path_type="fast",phase="request"} 1`) {
		t.Errorf("expected OpenMetrics counter in body, got:\n%s", body)
	}
}

func TestAdminStatus_UsesRealGuardLatency(t *testing.T) {
	srv := newTestAdminServer(func(d *AdminDependencies) {
		d.Config = &config.Config{
			RuntimeMode: config.RuntimeModeStandalone,
			AdminHost:   "127.0.0.1",
			AdminPort:   19415,
		}
		d.GuardManager = &mockGuardWithLatency{
			running:   true,
			modelID:   "qwen3guard-test",
			pid:       4242,
			latencyMS: 7.3456,
		}
	})
	defer func() { _ = srv.Shutdown(context.Background()) }()

	req := httptest.NewRequest(http.MethodGet, "/admin/status", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	gotLatency, _ := payload["guard_latency_ms"].(float64)
	if gotLatency < 7.3 || gotLatency > 7.4 {
		t.Fatalf("expected measured guard_latency_ms ~7.35, got %v (should NOT be hardcoded 24.2)", gotLatency)
	}
}

func TestAdminReadyz_StatesAndDisabledTelemetry(t *testing.T) {
	t.Run("telemetry disabled returns 200 healthy", func(t *testing.T) {
		disabled := false
		eb := broker.NewEventBroker(10)
		defer eb.Close()

		srv := newTestAdminServer(func(d *AdminDependencies) {
			d.Config = &config.Config{
				RuntimeMode: config.RuntimeModeStandalone,
				AdminHost:   "127.0.0.1",
				Telemetry:   config.TelemetryConfig{Enabled: &disabled},
			}
			d.EventBroker = eb
		})
		defer func() { _ = srv.Shutdown(context.Background()) }()

		req := httptest.NewRequest(http.MethodGet, "/admin/readyz", nil)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 when telemetry disabled, got %d (%s)", rec.Code, rec.Body.String())
		}

		var body map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode readyz: %v", err)
		}
		if body["status"] != "healthy" {
			t.Fatalf("expected overall status healthy, got %v", body["status"])
		}
		comps, _ := body["components"].(map[string]interface{})
		duck, _ := comps["duckdb"].(map[string]interface{})
		if duck["status"] != "disabled" {
			t.Fatalf("expected duckdb component disabled, got %#v", duck)
		}
	})

	t.Run("telemetry enabled DB failure returns 503", func(t *testing.T) {
		enabled := true
		dbPath := filepath.Join(t.TempDir(), "readyz_fail.duckdb")
		eng, err := duckdb.New(duckdb.Config{DBPath: dbPath})
		if err != nil {
			t.Fatalf("NewEngine: %v", err)
		}
		// Close underlying engine/db so Ping fails while engine struct is still attached.
		_ = eng.Close()

		srv := newTestAdminServer(func(d *AdminDependencies) {
			d.Config = &config.Config{
				RuntimeMode: config.RuntimeModeStandalone,
				AdminHost:   "127.0.0.1",
				Telemetry:   config.TelemetryConfig{Enabled: &enabled},
			}
			d.TelemetryEngine = eng
		})
		defer func() { _ = srv.Shutdown(context.Background()) }()

		req := httptest.NewRequest(http.MethodGet, "/admin/readyz", nil)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503 when enabled DuckDB is closed/unhealthy, got %d (%s)", rec.Code, rec.Body.String())
		}
	})

	t.Run("draining returns 503", func(t *testing.T) {
		disabled := false
		srv := newTestAdminServer(func(d *AdminDependencies) {
			d.Config = &config.Config{
				RuntimeMode: config.RuntimeModeStandalone,
				AdminHost:   "127.0.0.1",
				Telemetry:   config.TelemetryConfig{Enabled: &disabled},
			}
			d.IsDrainingFn = func() bool { return true }
		})
		defer func() { _ = srv.Shutdown(context.Background()) }()

		req := httptest.NewRequest(http.MethodGet, "/admin/readyz", nil)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503 while draining, got %d (%s)", rec.Code, rec.Body.String())
		}
	})

	t.Run("dropped events triggers 503 degraded", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "readyz_drop.duckdb")
		enabled := true
		eng, err := duckdb.New(duckdb.Config{DBPath: dbPath})
		if err != nil {
			t.Fatalf("NewEngine: %v", err)
		}
		defer eng.Close()

		srv := newTestAdminServer(func(d *AdminDependencies) {
			d.Config = &config.Config{
				RuntimeMode: config.RuntimeModeStandalone,
				AdminHost:   "127.0.0.1",
				Telemetry:   config.TelemetryConfig{Enabled: &enabled},
			}
			d.TelemetryEngine = eng
			d.AuditLogDroppedFn = func() uint64 { return 4 }
		})
		defer func() { _ = srv.Shutdown(context.Background()) }()

		req := httptest.NewRequest(http.MethodGet, "/admin/readyz", nil)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503 when dropped_events > 0, got %d (%s)", rec.Code, rec.Body.String())
		}
	})

	t.Run("healthy duckdb passes 200", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "readyz_ok.duckdb")
		enabled := true
		eng, err := duckdb.New(duckdb.Config{DBPath: dbPath})
		if err != nil {
			t.Fatalf("NewEngine: %v", err)
		}
		defer eng.Close()

		// Ensure unused imports aren't introduced by accident
		var _ = (*sql.DB)(nil)
		var _ = (*filter.AuditEvent)(nil)

		srv := newTestAdminServer(func(d *AdminDependencies) {
			d.Config = &config.Config{
				RuntimeMode: config.RuntimeModeStandalone,
				AdminHost:   "127.0.0.1",
				Telemetry:   config.TelemetryConfig{Enabled: &enabled},
			}
			d.TelemetryEngine = eng
		})
		defer func() { _ = srv.Shutdown(context.Background()) }()

		req := httptest.NewRequest(http.MethodGet, "/admin/readyz", nil)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 when healthy, got %d (%s)", rec.Code, rec.Body.String())
		}
	})
}
