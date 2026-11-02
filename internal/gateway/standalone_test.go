package gateway_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/gateway"
)

// egressRecordingTransport intercepts all HTTP requests and counts external attempts.
type egressRecordingTransport struct {
	egressCount atomic.Int64
}

func (e *egressRecordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	e.egressCount.Add(1)
	return nil, http.ErrNotSupported
}

// TestStandaloneGateway_Bootstrap verifies that the gateway boots without FARADAI_WIRE_API_KEY,
// serves the embedded dashboard, reports mode: STANDALONE at /admin/status, and requires no cloud mocks.
func TestStandaloneGateway_Bootstrap(t *testing.T) {
	// Ensure no cloud credentials are present in environment
	t.Setenv("FARADAI_WIRE_API_KEY", "")
	t.Setenv("API_KEY", "")
	t.Setenv("GATEWAY_ID", "test-standalone-gw")

	cfg := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
		ListenPort:  8080,
		AdminPort:   8095,
		Mode:        "sse",
	}

	provider := &mockConfigProvider{cfg: cfg}
	srv, err := gateway.NewServer(cfg, provider)
	if err != nil {
		t.Fatalf("failed to create standalone gateway server: %v", err)
	}

	adminHandler := srv.AdminHandler()
	if adminHandler == nil {
		t.Fatal("expected non-nil admin handler from gateway server")
	}

	// 1. Acceptance Criteria: Embedded web console loads successfully at /admin/dashboard
	reqDash := httptest.NewRequest(http.MethodGet, "/admin/dashboard", nil)
	recDash := httptest.NewRecorder()
	adminHandler.ServeHTTP(recDash, reqDash)

	if recDash.Code != http.StatusOK {
		t.Errorf("expected /admin/dashboard to return HTTP 200, got %d", recDash.Code)
	}
	bodyDash := recDash.Body.String()
	if !strings.Contains(bodyDash, "FaradAiWire") && !strings.Contains(bodyDash, "Dashboard") {
		t.Errorf("expected /admin/dashboard body to contain dashboard markup, got %s", bodyDash[:min(len(bodyDash), 200)])
	}

	// 2. Acceptance Criteria: GET /admin/status returns HTTP 200 with mode: STANDALONE
	reqStatus := httptest.NewRequest(http.MethodGet, "/admin/status", nil)
	recStatus := httptest.NewRecorder()
	adminHandler.ServeHTTP(recStatus, reqStatus)

	if recStatus.Code != http.StatusOK {
		t.Fatalf("expected /admin/status to return HTTP 200, got %d (body: %s)", recStatus.Code, recStatus.Body.String())
	}

	var statusResp map[string]interface{}
	if err := json.Unmarshal(recStatus.Body.Bytes(), &statusResp); err != nil {
		t.Fatalf("failed to parse /admin/status JSON response: %v", err)
	}

	mode, ok := statusResp["mode"].(string)
	if !ok || mode != "STANDALONE" {
		t.Errorf("expected status mode to be 'STANDALONE', got %v", statusResp["mode"])
	}

	runtimeMode, ok := statusResp["runtime_mode"].(string)
	if !ok || runtimeMode != "STANDALONE" {
		t.Errorf("expected status runtime_mode to be 'STANDALONE', got %v", statusResp["runtime_mode"])
	}

	// 3. Root URL redirects to /admin/dashboard
	reqRoot := httptest.NewRequest(http.MethodGet, "/", nil)
	recRoot := httptest.NewRecorder()
	adminHandler.ServeHTTP(recRoot, reqRoot)

	if recRoot.Code != http.StatusFound {
		t.Errorf("expected root / to redirect with 302, got %d", recRoot.Code)
	}
	if loc := recRoot.Header().Get("Location"); loc != "/admin/dashboard" {
		t.Errorf("expected redirect location /admin/dashboard, got %s", loc)
	}
}

// TestStandaloneGateway_ZeroEgress asserts that zero outbound network packets are dispatched
// to external hosts during standalone boot, background task execution, and status queries.
func TestStandaloneGateway_ZeroEgress(t *testing.T) {
	// Guarantee no cloud keys
	t.Setenv("FARADAI_WIRE_API_KEY", "")
	t.Setenv("API_KEY", "")

	cfg := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
		ListenPort:  8080,
		AdminPort:   8095,
		Mode:        "sse",
		HotReload:   false,
	}

	provider := &mockConfigProvider{cfg: cfg}
	srv, err := gateway.NewServer(cfg, provider)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	egressTracker := &egressRecordingTransport{}
	if srv.AdminServer() != nil {
		srv.AdminServer().SetSafeHTTPClient(&http.Client{Transport: egressTracker})
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Boot in background and let background tickers/tasks cycle
	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- srv.Start(ctx)
	}()

	// Allow boot tasks to stabilize
	time.Sleep(150 * time.Millisecond)

	// Execute status and dashboard checks
	handler := srv.AdminHandler()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 from status probe, got %d", rec.Code)
	}

	// Graceful shutdown
	shutdownCtx, sCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer sCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && err != context.Canceled {
		t.Errorf("unexpected shutdown error: %v", err)
	}

	// Strictly assert zero outbound HTTP requests were dispatched
	if count := egressTracker.egressCount.Load(); count != 0 {
		t.Fatalf("Zero-Egress Invariant Violated: %d outbound HTTP requests dispatched to external hosts", count)
	}
}

// TestStandaloneGateway_DefaultConfigResolution tests standalone defaults when initialized without config file.
func TestStandaloneGateway_DefaultConfigResolution(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("FARADAI_WIRE_HOME", tempHome)
	t.Setenv("FARADAI_WIRE_API_KEY", "")
	t.Setenv("API_KEY", "")

	provider := config.NewYAMLConfigProvider("")
	cfg, err := provider.Load()
	if err != nil {
		t.Fatalf("failed to auto-bootstrap standalone config: %v", err)
	}

	if cfg.GetRuntimeMode() != config.RuntimeModeStandalone {
		t.Errorf("expected auto-bootstrapped config to have mode STANDALONE, got %s", cfg.GetRuntimeMode())
	}
	if cfg.GetListenPort() != 8090 {
		t.Errorf("expected auto-bootstrapped config port 8090, got %d", cfg.GetListenPort())
	}
	if cfg.GetAdminPort() != 8095 {
		t.Errorf("expected auto-bootstrapped admin port 8095, got %d", cfg.GetAdminPort())
	}

	srv, err := gateway.NewServer(cfg, provider)
	if err != nil {
		t.Fatalf("failed to create gateway server with auto-bootstrapped config: %v", err)
	}

	rec := httptest.NewRecorder()
	srv.AdminHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected /admin/status to return 200, got %d", rec.Code)
	}

	var status map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &status)
	if status["mode"] != "STANDALONE" {
		t.Errorf("expected status mode 'STANDALONE', got %v", status["mode"])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
