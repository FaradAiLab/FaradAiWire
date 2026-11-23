package admin

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/internal/guard"
	"github.com/FaradAiLab/FaradAiWire/internal/metrics"
	"github.com/FaradAiLab/FaradAiWire/internal/settings"
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

func TestAdminAnalyticsSecurityLogsAndRedactedExport(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "arch053.duckdb")
	enabled := true
	eng, err := duckdb.New(duckdb.Config{DBPath: dbPath, BufferSize: 100, BatchFlushMs: 10})
	if err != nil {
		t.Fatalf("duckdb.New: %v", err)
	}
	defer eng.Close()

	now := time.Now().UTC()
	eng.LogEvent(&filter.AuditEvent{
		ID:              "exp-1",
		TraceID:         "trace-exp-1",
		Timestamp:       now.Add(-5 * time.Minute),
		AgentName:       "alpha",
		ToolName:        "=cmd|'/C calc'!A0",
		Decision:        filter.DecisionBlocked,
		RequestDecision: filter.DecisionBlocked,
		MatchedRule:     "dlp_key",
		OriginalRequest: "RAW_UNMASKED_SECRET_MUST_NEVER_BLEED",
		OriginalPayload: "RAW_ORIG_PAYLOAD_MUST_NEVER_BLEED",
		Request:         "raw_blocked_request_body",
		RawPayload:      "UNMASKED_BAD_PREVIEW",
	})
	eng.LogEvent(&filter.AuditEvent{
		ID:               "exp-2",
		TraceID:          "trace-exp-2",
		Timestamp:        now.Add(-3 * time.Minute),
		AgentName:        "beta",
		ToolName:         "+malicious_plus",
		Decision:         filter.DecisionAllowed,
		RequestDecision:  filter.DecisionAllowed,
		MatchedRule:      "",
		OriginalRequest:  "LOCAL_VAULT_ORIG_REQUEST",
		OriginalResponse: "LOCAL_VAULT_ORIG_RESPONSE",
		Request:          `{"ok":true}`,
		RawPayload:       `{"ok":true}`,
	})
	eng.LogEvent(&filter.AuditEvent{
		ID:        "exp-3",
		TraceID:   "trace-exp-3",
		Timestamp: now.Add(-2 * time.Minute),
		AgentName: "gamma",
		ToolName:  "@formula_tool",
		Decision:  filter.DecisionAllowed,
	})
	eng.LogSecurityEvent(&filter.SecurityAuditEvent{
		ID:        "sec-a-1",
		Timestamp: now.Add(-1 * time.Minute),
		EventType: "API_KEY_CREATED",
		ActorID:   "local-operator",
		ActorRole: "admin",
		Action:    "create",
		Outcome:   "allowed",
	})
	if err := eng.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	opSettings := settings.DefaultOperationalSettings()
	opSettings.Maintenance.AuditExportMaxRows = 2
	sCache := settings.NewCache(opSettings)

	srv := newTestAdminServer(func(d *AdminDependencies) {
		d.Config = &config.Config{
			RuntimeMode: config.RuntimeModeStandalone,
			AdminHost:   "127.0.0.1",
			Telemetry:   config.TelemetryConfig{Enabled: &enabled},
		}
		d.TelemetryEngine = eng
		d.SettingsCache = sCache
		d.GuardManager = &mockGuardWithLatency{running: true, modelID: "qwen", latencyMS: 9.5}
	})
	defer func() { _ = srv.Shutdown(context.Background()) }()
	h := srv.Handler()

	// 1. /admin/audit-logs date + rule + metadata q
	sinceStr := now.Add(-10 * time.Minute).Format(time.RFC3339)
	reqLogs := httptest.NewRequest(http.MethodGet, "/admin/audit-logs?since="+sinceStr+"&matched_rule=dlp_key&q=alpha", nil)
	recLogs := httptest.NewRecorder()
	h.ServeHTTP(recLogs, reqLogs)
	if recLogs.Code != http.StatusOK {
		t.Fatalf("expected 200 on filtered /admin/audit-logs, got %d (%s)", recLogs.Code, recLogs.Body.String())
	}
	var logsBody struct {
		Total int64                `json:"total"`
		Logs  []duckdb.AuditRecord `json:"logs"`
	}
	if err := json.Unmarshal(recLogs.Body.Bytes(), &logsBody); err != nil {
		t.Fatalf("unmarshal /admin/audit-logs: %v", err)
	}
	if logsBody.Total != 1 || logsBody.Logs[0].ID != "exp-1" {
		t.Fatalf("expected filtered audit log exp-1, got total=%d logs=%+v", logsBody.Total, logsBody.Logs)
	}

	// 2. /admin/security-audit-logs
	reqSec := httptest.NewRequest(http.MethodGet, "/admin/security-audit-logs?event_type=API_KEY_CREATED&actor_id=local-operator", nil)
	recSec := httptest.NewRecorder()
	h.ServeHTTP(recSec, reqSec)
	if recSec.Code != http.StatusOK {
		t.Fatalf("expected 200 on /admin/security-audit-logs, got %d (%s)", recSec.Code, recSec.Body.String())
	}
	if !strings.Contains(recSec.Body.String(), "sec-a-1") {
		t.Fatalf("expected sec-a-1 in response, got %s", recSec.Body.String())
	}

	// 3. /admin/analytics/summary?window=1h
	reqSum := httptest.NewRequest(http.MethodGet, "/admin/analytics/summary?window=1h", nil)
	recSum := httptest.NewRecorder()
	h.ServeHTTP(recSum, reqSum)
	if recSum.Code != http.StatusOK {
		t.Fatalf("expected 200 on /admin/analytics/summary, got %d (%s)", recSum.Code, recSum.Body.String())
	}
	var sumBody map[string]interface{}
	if err := json.Unmarshal(recSum.Body.Bytes(), &sumBody); err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	if sumBody["total_calls"] != float64(3) {
		t.Fatalf("expected total_calls=3, got %v", sumBody["total_calls"])
	}
	if sumBody["guard_latency_ms"] != 9.5 {
		t.Fatalf("expected guard_latency_ms=9.5, got %v", sumBody["guard_latency_ms"])
	}

	// 4. /admin/audit-logs/export?format=jsonl (must NOT collide with {id}, must respect maxRows=2 and Zero-DLP Bleed)
	reqJSONL := httptest.NewRequest(http.MethodGet, "/admin/audit-logs/export?format=jsonl", nil)
	recJSONL := httptest.NewRecorder()
	h.ServeHTTP(recJSONL, reqJSONL)
	if recJSONL.Code != http.StatusOK {
		t.Fatalf("expected 200 on jsonl export (no {id} collision!), got %d (%s)", recJSONL.Code, recJSONL.Body.String())
	}
	jsonlOut := recJSONL.Body.String()
	for _, secret := range []string{
		"RAW_UNMASKED_SECRET_MUST_NEVER_BLEED",
		"RAW_ORIG_PAYLOAD_MUST_NEVER_BLEED",
		"UNMASKED_BAD_PREVIEW",
		"raw_blocked_request_body",
		"LOCAL_VAULT_ORIG_REQUEST",
		"LOCAL_VAULT_ORIG_RESPONSE",
	} {
		if strings.Contains(jsonlOut, secret) {
			t.Fatalf("ZERO-DLP BLEED VIOLATION: export leaked %q:\n%s", secret, jsonlOut)
		}
	}
	lines := strings.Split(strings.TrimSpace(jsonlOut), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected maintenance.audit_export_max_rows=2 to cap lines at 2, got %d", len(lines))
	}

	// 5. /admin/audit-logs/export?format=csv neutralizes =,+,-,@,\t,\r formula cells
	reqCSV := httptest.NewRequest(http.MethodGet, "/admin/audit-logs/export?format=csv", nil)
	recCSV := httptest.NewRecorder()
	h.ServeHTTP(recCSV, reqCSV)
	if recCSV.Code != http.StatusOK {
		t.Fatalf("expected 200 on csv export, got %d (%s)", recCSV.Code, recCSV.Body.String())
	}
	csvRows, err := csv.NewReader(strings.NewReader(recCSV.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("parse CSV: %v", err)
	}
	if len(csvRows) != 3 { // header + 2 capped rows (exp-3, exp-2 sorted DESC)
		t.Fatalf("expected 3 CSV rows (header + 2 capped data rows), got %d", len(csvRows))
	}
	csvText := recCSV.Body.String()
	if !strings.Contains(csvText, "'@formula_tool") || !strings.Contains(csvText, "'+malicious_plus") {
		t.Fatalf("expected formula-escaped @formula_tool and +malicious_plus in CSV:\n%s", csvText)
	}

	// 6. Export specifically targeting blocked row (exp-1) verifies ZERO-DLP BLEED redaction
	reqBlockedJSONL := httptest.NewRequest(http.MethodGet, "/admin/audit-logs/export?format=jsonl&matched_rule=dlp_key", nil)
	recBlockedJSONL := httptest.NewRecorder()
	h.ServeHTTP(recBlockedJSONL, reqBlockedJSONL)
	if recBlockedJSONL.Code != http.StatusOK {
		t.Fatalf("expected 200 on filtered blocked export, got %d", recBlockedJSONL.Code)
	}
	blockedBody := recBlockedJSONL.Body.String()
	if !strings.Contains(blockedBody, "[REDACTED - Blocked by dlp_key]") {
		t.Fatalf("expected blocked row raw_payload_preview to be replaced with redacted notice, got %s", blockedBody)
	}
	if strings.Contains(blockedBody, "raw_blocked_request_body") || strings.Contains(blockedBody, "UNMASKED_BAD_PREVIEW") {
		t.Fatalf("blocked row export leaked unredacted request/preview: %s", blockedBody)
	}
}

func TestSanitizeCSVCell_AllFormulaPrefixes(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty", in: "", want: ""},
		{name: "equals", in: "=SUM(A1:A2)", want: "'=SUM(A1:A2)"},
		{name: "plus", in: "+cmd|' /C calc'!A0", want: "'+cmd|' /C calc'!A0"},
		{name: "minus", in: "-1+1", want: "'-1+1"},
		{name: "at", in: "@SUM(1,2)", want: "'@SUM(1,2)"},
		{name: "tab", in: "\tcmd", want: "'\tcmd"},
		{name: "carriage_return", in: "\rcmd", want: "'\rcmd"},
		{name: "safe_text", in: "read_file", want: "read_file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeCSVCell(tc.in); got != tc.want {
				t.Fatalf("sanitizeCSVCell(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestAdminAuditLogsExport_InvalidParamsAndEmptyTelemetry(t *testing.T) {
	srv := newTestAdminServer(func(d *AdminDependencies) {
		d.Config = &config.Config{
			RuntimeMode: config.RuntimeModeStandalone,
			AdminHost:   "127.0.0.1",
		}
	})
	defer func() { _ = srv.Shutdown(context.Background()) }()
	h := srv.Handler()

	// Unsupported format -> 400
	reqBadFmt := httptest.NewRequest(http.MethodGet, "/admin/audit-logs/export?format=xml", nil)
	recBadFmt := httptest.NewRecorder()
	h.ServeHTTP(recBadFmt, reqBadFmt)
	if recBadFmt.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on unsupported export format, got %d", recBadFmt.Code)
	}

	// Malformed since timestamp -> 400
	reqBadSince := httptest.NewRequest(http.MethodGet, "/admin/audit-logs/export?format=csv&since=not-a-timestamp", nil)
	recBadSince := httptest.NewRecorder()
	h.ServeHTTP(recBadSince, reqBadSince)
	if recBadSince.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid since timestamp, got %d", recBadSince.Code)
	}

	// Nil telemetry engine still streams valid CSV header cleanly
	reqEmptyCSV := httptest.NewRequest(http.MethodGet, "/admin/audit-logs/export?format=csv", nil)
	recEmptyCSV := httptest.NewRecorder()
	h.ServeHTTP(recEmptyCSV, reqEmptyCSV)
	if recEmptyCSV.Code != http.StatusOK {
		t.Fatalf("expected 200 on empty telemetry CSV export, got %d", recEmptyCSV.Code)
	}
	rows, err := csv.NewReader(strings.NewReader(recEmptyCSV.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("parse empty CSV: %v", err)
	}
	if len(rows) != 1 || rows[0][0] != "id" {
		t.Fatalf("expected single CSV header row starting with 'id', got %+v", rows)
	}
}
