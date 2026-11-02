package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/guard"
	_ "github.com/marcboeker/go-duckdb"
)

func setupTestAdminServerWithGuards(t *testing.T) (*AdminServer, guard.CatalogStore, func()) {
	t.Helper()
	db, err := sql.Open("duckdb", ":memory:")
	if err != nil {
		t.Fatalf("failed to open in-memory duckdb: %v", err)
	}

	cat := guard.NewCatalog(db)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := cat.Migrate(ctx); err != nil {
		db.Close()
		t.Fatalf("failed to migrate catalog: %v", err)
	}
	if err := cat.Seed(ctx); err != nil {
		db.Close()
		t.Fatalf("failed to seed catalog: %v", err)
	}

	cfg := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
	}

	server := NewAdminServer(cfg, func() error { return nil }, func() {})
	server.SetGuardCatalog(cat)

	cleanup := func() {
		db.Close()
	}
	return server, cat, cleanup
}

func TestGuardEndpoints_ListModels(t *testing.T) {
	server, _, cleanup := setupTestAdminServerWithGuards(t)
	defer cleanup()

	handler := server.Handler()

	// 1. GET /admin/guards/models returns 200 OK and models list
	req := httptest.NewRequest(http.MethodGet, "/admin/guards/models", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Models []*guard.Model `json:"models"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode models response: %v", err)
	}

	if len(resp.Models) != 6 {
		t.Fatalf("expected 6 models in catalog, got %d", len(resp.Models))
	}

	// Verify metrics on laya-mlx
	var foundLaya bool
	for _, m := range resp.Models {
		if m.ID == "laya-mlx" {
			foundLaya = true
			if m.RAMRequiredMB != 1800 {
				t.Errorf("expected 1800 RAM for laya-mlx, got %d", m.RAMRequiredMB)
			}
			if m.BenchmarkAccuracy != 0.862 {
				t.Errorf("expected 0.862 accuracy for laya-mlx, got %f", m.BenchmarkAccuracy)
			}
			if m.BenchmarkAvgLatencyMS != 24.2 {
				t.Errorf("expected 24.2ms avg latency for laya-mlx, got %f", m.BenchmarkAvgLatencyMS)
			}
			if m.BenchmarkP95LatencyMS != 38.5 {
				t.Errorf("expected 38.5ms p95 latency for laya-mlx, got %f", m.BenchmarkP95LatencyMS)
			}
			if m.InstallStatus != guard.InstallStatusNotInstalled {
				t.Errorf("expected NOT_INSTALLED status, got %s", m.InstallStatus)
			}
		}
	}
	if !foundLaya {
		t.Fatalf("laya-mlx not found in response")
	}

	// 2. format=array query param returns raw JSON array
	reqArray := httptest.NewRequest(http.MethodGet, "/admin/guards/models?format=array", nil)
	recArray := httptest.NewRecorder()
	handler.ServeHTTP(recArray, reqArray)

	if recArray.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", recArray.Code, recArray.Body.String())
	}
	var rawModels []*guard.Model
	if err := json.Unmarshal(recArray.Body.Bytes(), &rawModels); err != nil {
		t.Fatalf("failed to decode array response: %v", err)
	}
	if len(rawModels) != 6 {
		t.Fatalf("expected 6 models in array response, got %d", len(rawModels))
	}
}

func TestGuardEndpoints_GetSingleModel(t *testing.T) {
	server, _, cleanup := setupTestAdminServerWithGuards(t)
	defer cleanup()

	handler := server.Handler()

	// 1. GET existing model
	req := httptest.NewRequest(http.MethodGet, "/admin/guards/models/qwen3guard", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var m guard.Model
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("failed to decode single model: %v", err)
	}
	if m.ID != "qwen3guard" || m.RAMRequiredMB != 1024 {
		t.Errorf("unexpected model data for qwen3guard: %+v", m)
	}

	// 2. GET non-existent model returns 404
	req404 := httptest.NewRequest(http.MethodGet, "/admin/guards/models/unknown-model", nil)
	rec404 := httptest.NewRecorder()
	handler.ServeHTTP(rec404, req404)

	if rec404.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", rec404.Code)
	}

	// 3. Path traversal attack returns 400
	req400 := httptest.NewRequest(http.MethodGet, "/admin/guards/models/..%2F..%2Fetc", nil)
	rec400 := httptest.NewRecorder()
	handler.ServeHTTP(rec400, req400)

	if rec400.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec400.Code)
	}
}

func TestGuardEndpoints_MethodNotAllowed(t *testing.T) {
	server, _, cleanup := setupTestAdminServerWithGuards(t)
	defer cleanup()

	handler := server.Handler()

	req := httptest.NewRequest(http.MethodPost, "/admin/guards/models", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405 Method Not Allowed, got %d", rec.Code)
	}
	if rec.Header().Get("Allow") != "GET" {
		t.Errorf("expected Allow header to be GET, got %s", rec.Header().Get("Allow"))
	}
}

func TestGuardEndpoints_ServiceUnavailable(t *testing.T) {
	cfg := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
	}
	// Admin server with nil catalog
	server := NewAdminServer(cfg, func() error { return nil }, func() {})
	handler := server.Handler()

	req := httptest.NewRequest(http.MethodGet, "/admin/guards/models", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503 Service Unavailable, got %d", rec.Code)
	}
}

type mockGuardManager struct {
	status guard.ProcessStatus
}

func (m *mockGuardManager) Start(ctx context.Context, model *guard.Model) error                     { return nil }
func (m *mockGuardManager) StartScript(ctx context.Context, scriptPath string, modelID string) error { return nil }
func (m *mockGuardManager) Stop(ctx context.Context) error                                         { return nil }
func (m *mockGuardManager) CallInspect(ctx context.Context, req *guard.InspectionRequest) (*guard.InspectionResult, error) {
	return nil, nil
}
func (m *mockGuardManager) Status() guard.ProcessStatus { return m.status }
func (m *mockGuardManager) IsRunning() bool             { return m.status.Running }

func TestGuardEndpoints_Status(t *testing.T) {
	server, _, cleanup := setupTestAdminServerWithGuards(t)
	defer cleanup()

	handler := server.Handler()

	// 1. Initial state (nil manager) returns STOPPED status
	req := httptest.NewRequest(http.MethodGet, "/admin/guards/status", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from status endpoint, got %d", rec.Code)
	}

	var stoppedSt guard.ProcessStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &stoppedSt); err != nil {
		t.Fatalf("decode stopped status failed: %v", err)
	}
	if stoppedSt.Running || stoppedSt.HealthStatus != "STOPPED" {
		t.Errorf("expected STOPPED status when manager is nil, got %+v", stoppedSt)
	}

	// 2. Mock manager active state
	now := time.Now()
	server.SetGuardManager(&mockGuardManager{
		status: guard.ProcessStatus{
			Running:      true,
			ModelID:      "qwen3guard",
			PID:          4242,
			MemoryRSSMB:  48.5,
			HealthStatus: "HEALTHY",
			StartedAt:    &now,
		},
	})

	reqActive := httptest.NewRequest(http.MethodGet, "/admin/guards/status", nil)
	recActive := httptest.NewRecorder()
	handler.ServeHTTP(recActive, reqActive)

	if recActive.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", recActive.Code)
	}

	var activeSt guard.ProcessStatus
	if err := json.Unmarshal(recActive.Body.Bytes(), &activeSt); err != nil {
		t.Fatalf("decode active status failed: %v", err)
	}
	if !activeSt.Running || activeSt.PID != 4242 || activeSt.ModelID != "qwen3guard" || activeSt.MemoryRSSMB != 48.5 {
		t.Errorf("unexpected active status: %+v", activeSt)
	}

	// 3. Method Not Allowed on POST
	reqPost := httptest.NewRequest(http.MethodPost, "/admin/guards/status", nil)
	recPost := httptest.NewRecorder()
	handler.ServeHTTP(recPost, reqPost)

	if recPost.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 Method Not Allowed, got %d", recPost.Code)
	}
}

type mockGuardInstaller struct {
	installed   map[string]bool
	installing  map[string]bool
	uninstalled map[string]bool
}

func (m *mockGuardInstaller) DiscoverToolchain(ctx context.Context) (*guard.ToolchainInfo, error) {
	return &guard.ToolchainInfo{Type: guard.ToolchainNative, Version: "pure-go"}, nil
}
func (m *mockGuardInstaller) Install(ctx context.Context, modelID string) error {
	m.installed[modelID] = true
	return nil
}
func (m *mockGuardInstaller) InstallAsync(ctx context.Context, modelID string) error {
	if modelID == "unknown-model" {
		return guard.ErrModelNotFound
	}
	if m.installing[modelID] {
		return guard.ErrInstallInProgress
	}
	m.installing[modelID] = true
	return nil
}
func (m *mockGuardInstaller) Uninstall(ctx context.Context, modelID string) error {
	if modelID == "unknown-model" {
		return guard.ErrModelNotFound
	}
	m.uninstalled[modelID] = true
	delete(m.installed, modelID)
	return nil
}
func (m *mockGuardInstaller) GetProgress(modelID string) (guard.InstallProgress, bool) {
	if m.installing[modelID] {
		return guard.InstallProgress{
			ModelID:  modelID,
			Status:   guard.InstallStatusInstalling,
			Step:     guard.StepDownloadingWeights,
			Progress: 0.65,
		}, true
	}
	return guard.InstallProgress{}, false
}
func (m *mockGuardInstaller) SetOnProgress(cb func(guard.InstallProgress)) {}
func (m *mockGuardInstaller) VenvDir() string                               { return "/tmp/.venv" }
func (m *mockGuardInstaller) ModelsDir() string                             { return "/tmp/models" }

func TestGuardEndpoints_Install_And_Uninstall(t *testing.T) {
	server, _, cleanup := setupTestAdminServerWithGuards(t)
	defer cleanup()

	mockInst := &mockGuardInstaller{
		installed:   make(map[string]bool),
		installing:  make(map[string]bool),
		uninstalled: make(map[string]bool),
	}
	server.SetGuardInstaller(mockInst)
	handler := server.Handler()

	// 1. POST /admin/guards/models/qwen3guard/install returns 202 Accepted
	reqInstall := httptest.NewRequest(http.MethodPost, "/admin/guards/models/qwen3guard/install", nil)
	recInstall := httptest.NewRecorder()
	handler.ServeHTTP(recInstall, reqInstall)

	if recInstall.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted, got %d: %s", recInstall.Code, recInstall.Body.String())
	}

	// 2. GET /admin/guards/models/qwen3guard/progress returns progress JSON
	reqProg := httptest.NewRequest(http.MethodGet, "/admin/guards/models/qwen3guard/progress", nil)
	recProg := httptest.NewRecorder()
	handler.ServeHTTP(recProg, reqProg)

	if recProg.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for progress, got %d", recProg.Code)
	}

	var prog guard.InstallProgress
	if err := json.Unmarshal(recProg.Body.Bytes(), &prog); err != nil {
		t.Fatalf("unmarshal progress failed: %v", err)
	}
	if prog.Status != guard.InstallStatusInstalling || prog.Progress != 0.65 {
		t.Errorf("unexpected progress payload: %+v", prog)
	}

	// 3. Duplicate install returns 409 Conflict
	reqDup := httptest.NewRequest(http.MethodPost, "/admin/guards/models/qwen3guard/install", nil)
	recDup := httptest.NewRecorder()
	handler.ServeHTTP(recDup, reqDup)

	if recDup.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict for duplicate install, got %d", recDup.Code)
	}

	// 4. Unknown model returns 404
	reqUnknown := httptest.NewRequest(http.MethodPost, "/admin/guards/models/unknown-model/install", nil)
	recUnknown := httptest.NewRecorder()
	handler.ServeHTTP(recUnknown, reqUnknown)

	if recUnknown.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown model install, got %d", recUnknown.Code)
	}

	// 5. DELETE /admin/guards/models/qwen3guard returns 200 OK
	reqDelete := httptest.NewRequest(http.MethodDelete, "/admin/guards/models/qwen3guard", nil)
	recDelete := httptest.NewRecorder()
	handler.ServeHTTP(recDelete, reqDelete)

	if recDelete.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for delete, got %d: %s", recDelete.Code, recDelete.Body.String())
	}
	if !mockInst.uninstalled["qwen3guard"] {
		t.Errorf("expected mock installer to mark qwen3guard uninstalled")
	}
}

func TestGuardEndpoints_HITL_RespondAndPending(t *testing.T) {
	server, _, cleanup := setupTestAdminServerWithGuards(t)
	defer cleanup()

	dispatcher := guard.NewHITLDispatcher(guard.HITLDispatcherConfig{
		Timeout:       5 * time.Second,
		DisableTTY:    true,
		AllowRESTOnly: true,
		WSHub:         server.WSHub(),
	})
	server.SetGuardHITL(dispatcher)

	handler := server.Handler()

	// 1. Initial pending list is empty
	reqPending := httptest.NewRequest(http.MethodGet, "/admin/guards/hitl/pending", nil)
	recPending := httptest.NewRecorder()
	handler.ServeHTTP(recPending, reqPending)

	if recPending.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", recPending.Code)
	}

	var pendingResp struct {
		Pending []*guard.HITLRequest `json:"pending"`
	}
	if err := json.Unmarshal(recPending.Body.Bytes(), &pendingResp); err != nil {
		t.Fatalf("unmarshal pending failed: %v", err)
	}
	if len(pendingResp.Pending) != 0 {
		t.Fatalf("expected 0 pending, got %d", len(pendingResp.Pending))
	}

	// 2. Trigger asynchronous approval request
	hitlReq := &guard.HITLRequest{
		CallID:         "test-call-99",
		ToolName:       "send_email",
		Arguments:      map[string]interface{}{"to": "investor@example.com"},
		RiskScore:      0.82,
		ThreatDomain:   "UNVERIFIED_RECIPIENT",
		CWE:            "CWE-20",
		DecisionEngine: "L2_QWEN3GUARD",
	}

	respCh := make(chan bool, 1)
	errCh := make(chan error, 1)
	go func() {
		approved, err := dispatcher.RequestApproval(context.Background(), hitlReq)
		respCh <- approved
		errCh <- err
	}()

	time.Sleep(30 * time.Millisecond)

	// 3. Verify pending item appears in GET /admin/guards/hitl/pending
	recPending2 := httptest.NewRecorder()
	handler.ServeHTTP(recPending2, reqPending)
	if err := json.Unmarshal(recPending2.Body.Bytes(), &pendingResp); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if len(pendingResp.Pending) != 1 || pendingResp.Pending[0].CallID != "test-call-99" {
		t.Fatalf("expected 1 pending item with call_id test-call-99, got: %+v", pendingResp.Pending)
	}

	// 4. Bad request (missing call_id)
	badBody := strings.NewReader(`{"approved": true}`)
	reqBad := httptest.NewRequest(http.MethodPost, "/admin/guards/hitl/respond", badBody)
	recBad := httptest.NewRecorder()
	handler.ServeHTTP(recBad, reqBad)
	if recBad.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d", recBad.Code)
	}

	// 5. Unknown call_id returns 404
	unknownBody := strings.NewReader(`{"call_id": "non-existent", "approved": true}`)
	reqUnknown := httptest.NewRequest(http.MethodPost, "/admin/guards/hitl/respond", unknownBody)
	recUnknown := httptest.NewRecorder()
	handler.ServeHTTP(recUnknown, reqUnknown)
	if recUnknown.Code != http.StatusNotFound {
		t.Fatalf("expected 404 Not Found, got %d", recUnknown.Code)
	}

	// 6. Valid approval response: POST /admin/guards/hitl/respond
	validBody := strings.NewReader(`{"call_id": "test-call-99", "approved": true}`)
	reqValid := httptest.NewRequest(http.MethodPost, "/admin/guards/hitl/respond", validBody)
	recValid := httptest.NewRecorder()
	handler.ServeHTTP(recValid, reqValid)

	if recValid.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", recValid.Code, recValid.Body.String())
	}

	// Await goroutine resolution
	select {
	case approved := <-respCh:
		if !approved {
			t.Fatal("expected approval request to be resolved true")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for approval resolution")
	}

	// 7. Duplicate response now returns 404
	recDup := httptest.NewRecorder()
	reqDup := httptest.NewRequest(http.MethodPost, "/admin/guards/hitl/respond", strings.NewReader(`{"call_id": "test-call-99", "approved": true}`))
	handler.ServeHTTP(recDup, reqDup)
	if recDup.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for duplicate response, got %d", recDup.Code)
	}
}

type mockHotSwapManager struct {
	mu           sync.Mutex
	running      bool
	activeModel  string
	startedCount int
	stoppedCount int
}

func (m *mockHotSwapManager) Start(ctx context.Context, model *guard.Model) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.running = true
	m.activeModel = model.ID
	m.startedCount++
	return nil
}
func (m *mockHotSwapManager) StartScript(ctx context.Context, scriptPath string, modelID string) error {
	return nil
}
func (m *mockHotSwapManager) Stop(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.running = false
	m.activeModel = ""
	m.stoppedCount++
	return nil
}
func (m *mockHotSwapManager) CallInspect(ctx context.Context, req *guard.InspectionRequest) (*guard.InspectionResult, error) {
	return nil, nil
}
func (m *mockHotSwapManager) Status() guard.ProcessStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	return guard.ProcessStatus{Running: m.running, ModelID: m.activeModel}
}
func (m *mockHotSwapManager) IsRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

func TestGuardEndpoints_Activate_And_Deactivate(t *testing.T) {
	server, cat, cleanup := setupTestAdminServerWithGuards(t)
	defer cleanup()

	mgr := &mockHotSwapManager{}
	server.SetGuardManager(mgr)
	handler := server.Handler()

	ctx := context.Background()

	// 1. Attempting to activate an uninstalled model returns 400 Bad Request
	reqActNotInst := httptest.NewRequest(http.MethodPost, "/admin/guards/models/qwen3guard/activate", nil)
	recActNotInst := httptest.NewRecorder()
	handler.ServeHTTP(recActNotInst, reqActNotInst)

	if recActNotInst.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for uninstalled model activation, got %d: %s", recActNotInst.Code, recActNotInst.Body.String())
	}

	// 2. Mark qwen3guard as installed and activate it
	if err := cat.UpdateStatus(ctx, "qwen3guard", guard.InstallStatusInstalled); err != nil {
		t.Fatalf("failed to update status: %v", err)
	}

	reqAct1 := httptest.NewRequest(http.MethodPost, "/admin/guards/models/qwen3guard/activate", nil)
	recAct1 := httptest.NewRecorder()
	handler.ServeHTTP(recAct1, reqAct1)

	if recAct1.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for activation, got %d: %s", recAct1.Code, recAct1.Body.String())
	}

	if mgr.activeModel != "qwen3guard" || !mgr.running || mgr.startedCount != 1 {
		t.Errorf("expected qwen3guard to be active in manager, got: %+v", mgr)
	}

	// Verify catalog state
	m1, _ := cat.Get(ctx, "qwen3guard")
	if !m1.IsActive {
		t.Errorf("expected qwen3guard to be active in catalog")
	}

	// 3. Hot-Swap: Mark laya-mlx as installed and activate it (should terminate previous model first)
	if err := cat.UpdateStatus(ctx, "laya-mlx", guard.InstallStatusInstalled); err != nil {
		t.Fatalf("failed to update status: %v", err)
	}

	reqAct2 := httptest.NewRequest(http.MethodPost, "/admin/guards/models/laya-mlx/activate", nil)
	recAct2 := httptest.NewRecorder()
	handler.ServeHTTP(recAct2, reqAct2)

	if recAct2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for hot-swap activation, got %d: %s", recAct2.Code, recAct2.Body.String())
	}

	// Previous model should have been stopped, and new model started
	if mgr.stoppedCount != 1 {
		t.Errorf("expected previous model to be stopped (stoppedCount=1), got %d", mgr.stoppedCount)
	}
	if mgr.startedCount != 2 || mgr.activeModel != "laya-mlx" {
		t.Errorf("expected laya-mlx to be active (startedCount=2), got %+v", mgr)
	}

	// Verify single active model invariant in catalog
	m1Check, _ := cat.Get(ctx, "qwen3guard")
	m2Check, _ := cat.Get(ctx, "laya-mlx")
	if m1Check.IsActive {
		t.Errorf("expected previous model qwen3guard to be deactivated in catalog")
	}
	if !m2Check.IsActive {
		t.Errorf("expected laya-mlx to be active in catalog")
	}

	// 4. Global Deactivate switches to L1 Lightweight mode
	reqDeact := httptest.NewRequest(http.MethodPost, "/admin/guards/models/deactivate", nil)
	recDeact := httptest.NewRecorder()
	handler.ServeHTTP(recDeact, reqDeact)

	if recDeact.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for deactivation, got %d: %s", recDeact.Code, recDeact.Body.String())
	}

	if mgr.running {
		t.Errorf("expected manager to be stopped after deactivation")
	}
	m2AfterDeact, _ := cat.Get(ctx, "laya-mlx")
	if m2AfterDeact.IsActive {
		t.Errorf("expected laya-mlx to be deactivated in catalog")
	}
}

func TestGuardEndpoints_Policy(t *testing.T) {
	server, cat, cleanup := setupTestAdminServerWithGuards(t)
	defer cleanup()

	handler := server.Handler()
	ctx := context.Background()

	// 1. Update policy with POST /admin/guards/models/laya-mlx/policy
	body := strings.NewReader(`{
		"default_action": "block",
		"critical_tools": ["execute_bash", "run_command", "drop_db"]
	}`)
	req := httptest.NewRequest(http.MethodPost, "/admin/guards/models/laya-mlx/policy", body)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for policy update, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Status        string   `json:"status"`
		ModelID       string   `json:"model_id"`
		DefaultAction string   `json:"default_action"`
		CriticalTools []string `json:"critical_tools"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode policy response: %v", err)
	}

	if resp.DefaultAction != "block" || len(resp.CriticalTools) != 3 {
		t.Errorf("unexpected policy response: %+v", resp)
	}

	// Verify catalog state
	m, err := cat.Get(ctx, "laya-mlx")
	if err != nil {
		t.Fatalf("failed to get model: %v", err)
	}
	if m.DefaultAction != guard.ThreatActionBlock {
		t.Errorf("expected default action 'block', got %s", m.DefaultAction)
	}
	if !strings.Contains(m.CriticalToolsJSON, "execute_bash") {
		t.Errorf("expected critical tools to contain execute_bash: %s", m.CriticalToolsJSON)
	}

	// 2. Unknown model returns 404
	badReq := httptest.NewRequest(http.MethodPost, "/admin/guards/models/unknown-model/policy", strings.NewReader(`{"default_action":"hitl"}`))
	badRec := httptest.NewRecorder()
	handler.ServeHTTP(badRec, badReq)

	if badRec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown model policy, got %d", badRec.Code)
	}

	// 3. Bad JSON body returns 400
	invalidReq := httptest.NewRequest(http.MethodPost, "/admin/guards/models/laya-mlx/policy", strings.NewReader(`{bad json`))
	invalidRec := httptest.NewRecorder()
	handler.ServeHTTP(invalidRec, invalidReq)

	if invalidRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d", invalidRec.Code)
	}

	// 4. Oversized payload (>64KB) is rejected with 400 Bad Request
	oversizedString := strings.Repeat("A", 70*1024)
	oversizedBody := strings.NewReader(`{"default_action":"hitl","critical_tools":["` + oversizedString + `"]}`)
	oversizedReq := httptest.NewRequest(http.MethodPost, "/admin/guards/models/laya-mlx/policy", oversizedBody)
	oversizedRec := httptest.NewRecorder()
	handler.ServeHTTP(oversizedRec, oversizedReq)

	if oversizedRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for oversized payload, got %d", oversizedRec.Code)
	}
}

func TestGuardEndpoints_ConnectModel(t *testing.T) {
	server, cat, cleanup := setupTestAdminServerWithGuards(t)
	defer cleanup()

	handler := server.Handler()

	// 1. Missing endpoint_url returns 400
	req := httptest.NewRequest(http.MethodPost, "/admin/guards/models/laya-mlx/connect", strings.NewReader(`{"runtime_type":"docker"}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for missing endpoint_url, got %d: %s", rec.Code, rec.Body.String())
	}

	// 2. Non-existent model returns 404
	req = httptest.NewRequest(http.MethodPost, "/admin/guards/models/non-existent/connect", strings.NewReader(`{"endpoint_url":"http://127.0.0.1:8088"}`))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 Not Found for non-existent model, got %d: %s", rec.Code, rec.Body.String())
	}

	// 3. Unreachable endpoint returns 503
	req = httptest.NewRequest(http.MethodPost, "/admin/guards/models/laya-mlx/connect", strings.NewReader(`{"runtime_type":"docker","endpoint_url":"http://127.0.0.1:9999"}`))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 Service Unavailable for unreachable endpoint, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify model was not marked active
	active, err := cat.GetActive(context.Background())
	if err != nil {
		t.Fatalf("failed to query active model: %v", err)
	}
	if active != nil {
		t.Fatalf("expected active model to be nil after failed connection, got %s", active.ID)
	}

	// 4. Invalid HTTP method returns 405
	req = httptest.NewRequest(http.MethodGet, "/admin/guards/models/laya-mlx/connect", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 Method Not Allowed for GET, got %d", rec.Code)
	}
}

func TestGuardEndpoints_DeactivateNonActiveModel_PreservesActiveRunningModel(t *testing.T) {
	server, cat, cleanup := setupTestAdminServerWithGuards(t)
	defer cleanup()

	ctx := context.Background()
	// Set model-1 active in catalog
	if err := cat.SetActive(ctx, "laya-mlx", true); err != nil {
		t.Fatalf("failed to set laya-mlx active: %v", err)
	}

	// Fake manager running laya-mlx
	mockMgr := &mockGuardManager{
		status: guard.ProcessStatus{
			Running: true,
			ModelID: "laya-mlx",
		},
	}
	server.SetGuardManager(mockMgr)

	handler := server.Handler()

	// Deactivate another model (e.g. "laya-flash")
	req := httptest.NewRequest(http.MethodPost, "/admin/guards/models/laya-flash/deactivate", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on deactivating inactive model, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify laya-mlx is STILL active in catalog!
	active, err := cat.GetActive(ctx)
	if err != nil {
		t.Fatalf("failed to query active: %v", err)
	}
	if active == nil || active.ID != "laya-mlx" {
		t.Fatalf("expected laya-mlx to remain active, got %+v", active)
	}
}



