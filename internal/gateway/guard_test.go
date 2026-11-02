package gateway

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
	"github.com/FaradAiLab/FaradAiWire/internal/guard"
)

func TestGateway_GuardCatalog_BootAndAdminIntegration(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "telemetry_boot.duckdb")

	cfg := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
		ListenHost:  "127.0.0.1",
		ListenPort:  8090,
		AdminPort:   8095,
		Telemetry: config.TelemetryConfig{
			DBPath: dbPath,
		},
	}

	server, err := NewServer(cfg, config.NewYAMLConfigProvider(""))
	if err != nil {
		t.Fatalf("failed to create gateway server: %v", err)
	}
	defer server.Shutdown(context.Background())

	catalog := server.GuardCatalog()
	if catalog == nil {
		t.Fatalf("expected server.GuardCatalog() to be initialized on boot")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Verify 3 models are seeded automatically on boot
	models, err := catalog.List(ctx)
	if err != nil {
		t.Fatalf("failed to list models from booted gateway catalog: %v", err)
	}
	if len(models) != 6 {
		t.Fatalf("expected 6 seeded models, got %d", len(models))
	}

	// 2. Query Admin REST endpoint directly
	adminServer := server.AdminServer()
	if adminServer == nil {
		t.Fatalf("expected active AdminServer")
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/guards/models", nil)
	rec := httptest.NewRecorder()
	adminServer.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 from /admin/guards/models, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Models []*guard.Model `json:"models"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse models json from admin handler: %v", err)
	}

	if len(resp.Models) != 6 {
		t.Fatalf("expected 6 models in admin response, got %d", len(resp.Models))
	}

	// 3. Mutate runtime state and verify seed idempotency
	if err := catalog.UpdateStatus(ctx, "laya-mlx", guard.InstallStatusInstalled); err != nil {
		t.Fatalf("failed to update status: %v", err)
	}
	if err := catalog.SetActive(ctx, "laya-mlx", true); err != nil {
		t.Fatalf("failed to set active: %v", err)
	}

	// Re-run seed
	if err := catalog.Seed(ctx); err != nil {
		t.Fatalf("re-seeding catalog failed: %v", err)
	}

	m, err := catalog.Get(ctx, "laya-mlx")
	if err != nil {
		t.Fatalf("failed to get laya-mlx: %v", err)
	}
	if m.InstallStatus != guard.InstallStatusInstalled || !m.IsActive {
		t.Fatalf("expected runtime states to be preserved across seed, got status=%s active=%v", m.InstallStatus, m.IsActive)
	}

	// 4. Verify GuardManager is initialized and /admin/guards/status returns 200 OK
	guardMgr := server.GuardManager()
	if guardMgr == nil {
		t.Fatalf("expected server.GuardManager() to be initialized on boot")
	}

	statusReq := httptest.NewRequest(http.MethodGet, "/admin/guards/status", nil)
	statusRec := httptest.NewRecorder()
	adminServer.Handler().ServeHTTP(statusRec, statusReq)

	if statusRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /admin/guards/status, got %d: %s", statusRec.Code, statusRec.Body.String())
	}

	var statusResp guard.ProcessStatus
	if err := json.Unmarshal(statusRec.Body.Bytes(), &statusResp); err != nil {
		t.Fatalf("failed to parse status json: %v", err)
	}
	if statusResp.Running || statusResp.HealthStatus != "STOPPED" {
		t.Errorf("expected initial STOPPED status, got %+v", statusResp)
	}

	// 5. Verify GuardInstaller is initialized and routes respond
	guardInstaller := server.GuardInstaller()
	if guardInstaller == nil {
		t.Fatalf("expected server.GuardInstaller() to be initialized on boot")
	}

	installReq := httptest.NewRequest(http.MethodPost, "/admin/guards/models/non-existent/install", nil)
	installRec := httptest.NewRecorder()
	adminServer.Handler().ServeHTTP(installRec, installReq)
	if installRec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for non-existent model install, got %d: %s", installRec.Code, installRec.Body.String())
	}
}

type mockGatewayGuardManager struct {
	running     bool
	activeModel string
	stopCount   int
	startCount  int
}

func (m *mockGatewayGuardManager) Start(ctx context.Context, model *guard.Model) error {
	m.running = true
	m.activeModel = model.ID
	m.startCount++
	return nil
}
func (m *mockGatewayGuardManager) StartScript(ctx context.Context, scriptPath string, modelID string) error {
	return nil
}
func (m *mockGatewayGuardManager) Stop(ctx context.Context) error {
	m.running = false
	m.activeModel = ""
	m.stopCount++
	return nil
}
func (m *mockGatewayGuardManager) CallInspect(ctx context.Context, req *guard.InspectionRequest) (*guard.InspectionResult, error) {
	return nil, nil
}
func (m *mockGatewayGuardManager) Status() guard.ProcessStatus {
	return guard.ProcessStatus{Running: m.running, ModelID: m.activeModel}
}
func (m *mockGatewayGuardManager) IsRunning() bool {
	return m.running
}

func TestGateway_ZeroDowntimeHotSwap_Lifecycle(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "telemetry_hotswap.duckdb")

	cfg := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
		ListenHost:  "127.0.0.1",
		ListenPort:  8092,
		AdminPort:   8097,
		Telemetry: config.TelemetryConfig{
			DBPath: dbPath,
		},
	}

	server, err := NewServer(cfg, config.NewYAMLConfigProvider(""))
	if err != nil {
		t.Fatalf("failed to create gateway server: %v", err)
	}
	defer server.Shutdown(context.Background())

	mockMgr := &mockGatewayGuardManager{}
	server.AdminServer().SetGuardManager(mockMgr)

	adminHandler := server.AdminServer().Handler()
	catalog := server.GuardCatalog()
	ctx := context.Background()

	// 1. Verify Web Console SPA is served at /admin/dashboard
	dashReq := httptest.NewRequest(http.MethodGet, "/admin/dashboard", nil)
	dashRec := httptest.NewRecorder()
	adminHandler.ServeHTTP(dashRec, dashReq)
	if dashRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /admin/dashboard, got %d", dashRec.Code)
	}

	// 2. Verify all 3 models exist with benchmark KPIs
	listReq := httptest.NewRequest(http.MethodGet, "/admin/guards/models", nil)
	listRec := httptest.NewRecorder()
	adminHandler.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /admin/guards/models, got %d", listRec.Code)
	}

	var listResp struct {
		Models []*guard.Model `json:"models"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("failed to unmarshal models list: %v", err)
	}
	if len(listResp.Models) != 6 {
		t.Fatalf("expected 6 seeded models, got %d", len(listResp.Models))
	}

	expectedMetrics := map[string]struct {
		ramMB    int
		accuracy float64
	}{
		"laya-mlx":           {ramMB: 1800, accuracy: 0.862},
		"qwen3guard":         {ramMB: 1024, accuracy: 0.796},
		"granite-guardian":   {ramMB: 2500, accuracy: 0.783},
		"liquid-d1":          {ramMB: 2350, accuracy: 0.841},
		"pplx-decider-flash": {ramMB: 2050, accuracy: 0.855},
		"mica-v0.5":          {ramMB: 2950, accuracy: 0.871},
	}

	for _, m := range listResp.Models {
		exp, ok := expectedMetrics[m.ID]
		if !ok {
			t.Errorf("unexpected model id: %s", m.ID)
			continue
		}
		if m.RAMRequiredMB != exp.ramMB {
			t.Errorf("model %s: expected %d RAM MB, got %d", m.ID, exp.ramMB, m.RAMRequiredMB)
		}
		if m.BenchmarkAccuracy != exp.accuracy {
			t.Errorf("model %s: expected %f accuracy, got %f", m.ID, exp.accuracy, m.BenchmarkAccuracy)
		}
		if m.IsActive {
			t.Errorf("model %s should not be active initially", m.ID)
		}
	}

	// 3. Activating uninstalled model returns 400 Bad Request
	actReq1 := httptest.NewRequest(http.MethodPost, "/admin/guards/models/qwen3guard/activate", nil)
	actRec1 := httptest.NewRecorder()
	adminHandler.ServeHTTP(actRec1, actReq1)
	if actRec1.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for uninstalled model activation, got %d: %s", actRec1.Code, actRec1.Body.String())
	}

	// 4. Mark qwen3guard installed and activate it
	if err := catalog.UpdateStatus(ctx, "qwen3guard", guard.InstallStatusInstalled); err != nil {
		t.Fatalf("failed to update status: %v", err)
	}

	actReq2 := httptest.NewRequest(http.MethodPost, "/admin/guards/models/qwen3guard/activate", nil)
	actRec2 := httptest.NewRecorder()
	adminHandler.ServeHTTP(actRec2, actReq2)
	if actRec2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for qwen3guard activation, got %d: %s", actRec2.Code, actRec2.Body.String())
	}

	// Verify qwen3guard is the active model
	activeM, err := catalog.GetActive(ctx)
	if err != nil || activeM == nil || activeM.ID != "qwen3guard" {
		t.Fatalf("expected active model qwen3guard, got: %+v (err: %v)", activeM, err)
	}

	// 5. Configure Action Policy on qwen3guard (toggle to auto-block and critical tools)
	polReq := httptest.NewRequest(http.MethodPost, "/admin/guards/models/qwen3guard/policy", strings.NewReader(`{
		"default_action": "block",
		"critical_tools": ["execute_bash", "format_disk"]
	}`))
	polRec := httptest.NewRecorder()
	adminHandler.ServeHTTP(polRec, polReq)
	if polRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for policy update, got %d: %s", polRec.Code, polRec.Body.String())
	}

	mCheck, _ := catalog.Get(ctx, "qwen3guard")
	if mCheck.DefaultAction != guard.ThreatActionBlock {
		t.Errorf("expected default action block, got %s", mCheck.DefaultAction)
	}

	// 6. Zero-Downtime Hot-Swap: Mark laya-mlx installed and activate it
	if err := catalog.UpdateStatus(ctx, "laya-mlx", guard.InstallStatusInstalled); err != nil {
		t.Fatalf("failed to update status: %v", err)
	}

	hotSwapReq := httptest.NewRequest(http.MethodPost, "/admin/guards/models/laya-mlx/activate", nil)
	hotSwapRec := httptest.NewRecorder()
	adminHandler.ServeHTTP(hotSwapRec, hotSwapReq)
	if hotSwapRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for hot-swap to laya-mlx, got %d: %s", hotSwapRec.Code, hotSwapRec.Body.String())
	}

	// Verify single active model is now laya-mlx
	activeM2, err := catalog.GetActive(ctx)
	if err != nil || activeM2 == nil || activeM2.ID != "laya-mlx" {
		t.Fatalf("expected active model laya-mlx, got: %+v", activeM2)
	}
	m1AfterSwap, _ := catalog.Get(ctx, "qwen3guard")
	if m1AfterSwap.IsActive {
		t.Errorf("expected retiring model qwen3guard to be inactive")
	}

	// 7. Deactivate switches gateway to L1-Only mode
	deactReq := httptest.NewRequest(http.MethodPost, "/admin/guards/models/deactivate", nil)
	deactRec := httptest.NewRecorder()
	adminHandler.ServeHTTP(deactRec, deactReq)
	if deactRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for deactivation, got %d: %s", deactRec.Code, deactRec.Body.String())
	}

	activeM3, err := catalog.GetActive(ctx)
	if err != nil {
		t.Fatalf("error checking active model: %v", err)
	}
	if activeM3 != nil {
		t.Fatalf("expected no active model after deactivation, got %s", activeM3.ID)
	}
}

