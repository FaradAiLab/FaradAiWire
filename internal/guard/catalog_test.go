package guard

import (
	"context"
	"database/sql"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/marcboeker/go-duckdb"
)

func setupTestCatalog(t *testing.T) (*Catalog, *sql.DB) {
	t.Helper()
	db, err := sql.Open("duckdb", ":memory:")
	if err != nil {
		t.Fatalf("failed to open in-memory duckdb: %v", err)
	}

	cat := NewCatalog(db)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := cat.Migrate(ctx); err != nil {
		db.Close()
		t.Fatalf("failed to migrate catalog: %v", err)
	}

	return cat, db
}

func TestCatalog_Migration(t *testing.T) {
	cat, db := setupTestCatalog(t)
	defer db.Close()

	ctx := context.Background()
	// Running Migrate again must be completely idempotent
	if err := cat.Migrate(ctx); err != nil {
		t.Fatalf("subsequent migration failed: %v", err)
	}

	// Verify table existence by querying it
	var count int
	err := db.QueryRowContext(ctx, "SELECT count(*) FROM guard_models").Scan(&count)
	if err != nil {
		t.Fatalf("failed to query guard_models table after migration: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 models in empty migrated table, got %d", count)
	}
}

func TestCatalog_Seed_And_List(t *testing.T) {
	cat, db := setupTestCatalog(t)
	defer db.Close()

	ctx := context.Background()
	if err := cat.Seed(ctx); err != nil {
		t.Fatalf("failed to seed models: %v", err)
	}

	models, err := cat.List(ctx)
	if err != nil {
		t.Fatalf("failed to list models: %v", err)
	}

	if len(models) != 6 {
		t.Fatalf("expected 6 seeded models, got %d", len(models))
	}

	expectedIDs := map[string]bool{
		"laya-mlx":           false,
		"qwen3guard":         false,
		"granite-guardian":   false,
		"liquid-d1":          false,
		"pplx-decider-flash": false,
		"mica-v0.5":          false,
	}

	for _, m := range models {
		expectedIDs[m.ID] = true
		if m.InstallStatus != InstallStatusNotInstalled {
			t.Errorf("expected initial status NOT_INSTALLED for %s, got %s", m.ID, m.InstallStatus)
		}
		if m.IsActive {
			t.Errorf("expected initial active state false for %s", m.ID)
		}
		if m.RAMRequiredMB <= 0 {
			t.Errorf("expected positive RAM requirement for %s, got %d", m.ID, m.RAMRequiredMB)
		}
		if m.BenchmarkAccuracy <= 0 || m.BenchmarkAccuracy > 1 {
			t.Errorf("expected valid benchmark accuracy for %s, got %f", m.ID, m.BenchmarkAccuracy)
		}
		if m.BenchmarkAvgLatencyMS <= 0 {
			t.Errorf("expected positive avg latency for %s, got %f", m.ID, m.BenchmarkAvgLatencyMS)
		}
		if m.OllamaSource == "" {
			t.Errorf("expected valid OllamaSource for %s", m.ID)
		}
		if m.DockerImage == "" || !strings.HasPrefix(m.DockerImage, "ghcr.io/faradailab/farad-ai-guard:") {
			t.Errorf("expected valid DockerImage prefixed with ghcr.io/faradailab/farad-ai-guard: for %s, got %s", m.ID, m.DockerImage)
		}
		if m.NumLayers <= 0 {
			t.Errorf("expected NumLayers > 0 for %s, got %d", m.ID, m.NumLayers)
		}
		if m.NumKVHeads <= 0 {
			t.Errorf("expected NumKVHeads > 0 for %s, got %d", m.ID, m.NumKVHeads)
		}
		if m.HeadDim <= 0 {
			t.Errorf("expected HeadDim > 0 for %s, got %d", m.ID, m.HeadDim)
		}
		if m.ContextWindow <= 0 {
			t.Errorf("expected ContextWindow > 0 for %s, got %d", m.ID, m.ContextWindow)
		}
	}

	for id, found := range expectedIDs {
		if !found {
			t.Errorf("expected seeded model %s not found in list", id)
		}
	}
}

func TestCatalog_Seed_Idempotency(t *testing.T) {
	cat, db := setupTestCatalog(t)
	defer db.Close()

	ctx := context.Background()
	if err := cat.Seed(ctx); err != nil {
		t.Fatalf("initial seed failed: %v", err)
	}

	// 1. Mutate runtime state for qwen3guard
	if err := cat.UpdateStatus(ctx, "qwen3guard", InstallStatusInstalled); err != nil {
		t.Fatalf("failed to update status: %v", err)
	}
	if err := cat.SetActive(ctx, "qwen3guard", true); err != nil {
		t.Fatalf("failed to activate model: %v", err)
	}

	qwenBefore, err := cat.Get(ctx, "qwen3guard")
	if err != nil {
		t.Fatalf("failed to get qwen3guard: %v", err)
	}
	if qwenBefore.InstallStatus != InstallStatusInstalled || !qwenBefore.IsActive {
		t.Fatalf("expected qwen3guard to be INSTALLED and active")
	}
	if qwenBefore.InstalledAt == nil {
		t.Fatalf("expected installed_at timestamp to be set")
	}

	// 2. Run Seed again (simulating gateway reboot / upgrade)
	if err := cat.Seed(ctx); err != nil {
		t.Fatalf("re-seeding failed: %v", err)
	}

	// 3. Verify runtime state was NOT overwritten
	qwenAfter, err := cat.Get(ctx, "qwen3guard")
	if err != nil {
		t.Fatalf("failed to get qwen3guard after re-seed: %v", err)
	}
	if qwenAfter.InstallStatus != InstallStatusInstalled {
		t.Errorf("expected install_status to remain INSTALLED, got %s", qwenAfter.InstallStatus)
	}
	if !qwenAfter.IsActive {
		t.Errorf("expected is_active to remain true, got %v", qwenAfter.IsActive)
	}
	if qwenAfter.InstalledAt == nil {
		t.Errorf("expected installed_at to be preserved")
	}
	// Verify static metadata still present
	if qwenAfter.RAMRequiredMB != 1024 {
		t.Errorf("expected RAM 1024, got %d", qwenAfter.RAMRequiredMB)
	}
	if qwenAfter.BenchmarkAccuracy != 0.796 {
		t.Errorf("expected accuracy 0.796, got %f", qwenAfter.BenchmarkAccuracy)
	}
}

func TestCatalog_Get_NotFound(t *testing.T) {
	cat, db := setupTestCatalog(t)
	defer db.Close()

	ctx := context.Background()
	_, err := cat.Get(ctx, "non-existent-model")
	if err != ErrModelNotFound {
		t.Fatalf("expected ErrModelNotFound, got %v", err)
	}
}

func TestCatalog_Single_Active_Model_Invariant(t *testing.T) {
	cat, db := setupTestCatalog(t)
	defer db.Close()

	ctx := context.Background()
	if err := cat.Seed(ctx); err != nil {
		t.Fatalf("seed failed: %v", err)
	}

	// Activate laya-mlx
	if err := cat.SetActive(ctx, "laya-mlx", true); err != nil {
		t.Fatalf("failed to activate laya-mlx: %v", err)
	}

	m1, _ := cat.Get(ctx, "laya-mlx")
	if !m1.IsActive {
		t.Fatalf("expected laya-mlx to be active")
	}

	// Activate granite-guardian
	if err := cat.SetActive(ctx, "granite-guardian", true); err != nil {
		t.Fatalf("failed to activate granite-guardian: %v", err)
	}

	m1After, _ := cat.Get(ctx, "laya-mlx")
	m2After, _ := cat.Get(ctx, "granite-guardian")

	if m1After.IsActive {
		t.Errorf("expected laya-mlx to be deactivated when granite-guardian was activated")
	}
	if !m2After.IsActive {
		t.Errorf("expected granite-guardian to be active")
	}

	// Deactivate granite-guardian
	if err := cat.SetActive(ctx, "granite-guardian", false); err != nil {
		t.Fatalf("failed to deactivate granite-guardian: %v", err)
	}
	m2Final, _ := cat.Get(ctx, "granite-guardian")
	if m2Final.IsActive {
		t.Errorf("expected granite-guardian to be inactive")
	}
}

func TestCatalog_GetActive(t *testing.T) {
	cat, db := setupTestCatalog(t)
	defer db.Close()

	ctx := context.Background()
	if err := cat.Seed(ctx); err != nil {
		t.Fatalf("seed failed: %v", err)
	}

	// Initially no model is active
	active, err := cat.GetActive(ctx)
	if err != nil {
		t.Fatalf("unexpected error querying active model: %v", err)
	}
	if active != nil {
		t.Fatalf("expected nil active model initially, got: %v", active.ID)
	}

	// Activate qwen3guard
	if err := cat.SetActive(ctx, "qwen3guard", true); err != nil {
		t.Fatalf("failed to activate qwen3guard: %v", err)
	}

	active, err = cat.GetActive(ctx)
	if err != nil {
		t.Fatalf("unexpected error querying active model: %v", err)
	}
	if active == nil || active.ID != "qwen3guard" {
		t.Fatalf("expected active model qwen3guard, got: %v", active)
	}
}

func TestCatalog_UpdatePolicy(t *testing.T) {
	cat, db := setupTestCatalog(t)
	defer db.Close()

	ctx := context.Background()
	if err := cat.Seed(ctx); err != nil {
		t.Fatalf("seed failed: %v", err)
	}

	// Update policy for laya-mlx
	err := cat.UpdatePolicy(ctx, "laya-mlx", ThreatActionBlock, `["execute_bash","drop_db"]`)
	if err != nil {
		t.Fatalf("failed to update policy: %v", err)
	}

	m, err := cat.Get(ctx, "laya-mlx")
	if err != nil {
		t.Fatalf("failed to get model: %v", err)
	}

	if m.DefaultAction != ThreatActionBlock {
		t.Errorf("expected default action 'block', got '%s'", m.DefaultAction)
	}
	if m.CriticalToolsJSON != `["execute_bash","drop_db"]` {
		t.Errorf("expected critical tools json, got '%s'", m.CriticalToolsJSON)
	}

	// Non-existent model should return ErrModelNotFound
	err = cat.UpdatePolicy(ctx, "non-existent", ThreatActionHITL, "[]")
	if err != ErrModelNotFound {
		t.Errorf("expected ErrModelNotFound, got %v", err)
	}
}

func TestCatalog_Migration_DeclarativeFields(t *testing.T) {
	db, err := sql.Open("duckdb", ":memory:")
	if err != nil {
		t.Fatalf("failed to open in-memory duckdb: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	// Create legacy table without ollama_source and docker_image
	legacyQuery := `
	CREATE TABLE guard_models (
		id VARCHAR PRIMARY KEY,
		name VARCHAR NOT NULL,
		family VARCHAR NOT NULL,
		parameter_size VARCHAR NOT NULL,
		ram_required_mb INTEGER NOT NULL,
		disk_size_mb INTEGER NOT NULL,
		description TEXT NOT NULL,
		recommended_for TEXT NOT NULL,
		benchmark_accuracy DOUBLE NOT NULL,
		benchmark_fp_rate DOUBLE NOT NULL,
		benchmark_avg_latency_ms DOUBLE NOT NULL,
		benchmark_p95_latency_ms DOUBLE NOT NULL,
		install_status VARCHAR NOT NULL,
		is_active BOOLEAN DEFAULT FALSE,
		default_action VARCHAR DEFAULT 'hitl',
		critical_tools_json TEXT DEFAULT '[]',
		source_url VARCHAR NOT NULL,
		entrypoint_script VARCHAR NOT NULL,
		installed_at TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	`
	if _, err := db.ExecContext(ctx, legacyQuery); err != nil {
		t.Fatalf("failed to create legacy table: %v", err)
	}

	cat := NewCatalog(db)
	if err := cat.Migrate(ctx); err != nil {
		t.Fatalf("migration on legacy table failed: %v", err)
	}

	// Verify columns were added by inserting a model with ollama_source and docker_image
	m := &Model{
		ID:                    "test-guard",
		Name:                  "Test Guard",
		Family:                "test",
		ParameterSize:         "0.1B",
		RAMRequiredMB:         512,
		DiskSizeMB:            256,
		Description:           "Test model",
		RecommendedFor:        "Unit testing",
		BenchmarkAccuracy:     0.9,
		BenchmarkFPRate:       0.01,
		BenchmarkAvgLatencyMS: 10,
		BenchmarkP95LatencyMS: 20,
		InstallStatus:         InstallStatusNotInstalled,
		IsActive:              false,
		DefaultAction:         ThreatActionHITL,
		CriticalToolsJSON:     "[]",
		SourceURL:             "test/source",
		EntrypointScript:      "test.py",
		OllamaSource:          "hf.co/faradailab/guard-test:latest",
		DockerImage:           "ghcr.io/faradailab/farad-ai-guard:test",
	}

	insertQuery := `
	INSERT INTO guard_models (
		id, name, family, parameter_size, ram_required_mb, disk_size_mb,
		description, recommended_for, benchmark_accuracy, benchmark_fp_rate,
		benchmark_avg_latency_ms, benchmark_p95_latency_ms, install_status,
		is_active, default_action, critical_tools_json, source_url,
		entrypoint_script, ollama_source, docker_image, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
	`
	_, err = db.ExecContext(ctx, insertQuery,
		m.ID, m.Name, m.Family, m.ParameterSize, m.RAMRequiredMB, m.DiskSizeMB,
		m.Description, m.RecommendedFor, m.BenchmarkAccuracy, m.BenchmarkFPRate,
		m.BenchmarkAvgLatencyMS, m.BenchmarkP95LatencyMS, m.InstallStatus,
		m.IsActive, m.DefaultAction, m.CriticalToolsJSON, m.SourceURL,
		m.EntrypointScript, m.OllamaSource, m.DockerImage,
	)
	if err != nil {
		t.Fatalf("failed to insert model into migrated table: %v", err)
	}

	retrieved, err := cat.Get(ctx, "test-guard")
	if err != nil {
		t.Fatalf("failed to get model from migrated table: %v", err)
	}
	if retrieved.OllamaSource != m.OllamaSource {
		t.Errorf("expected OllamaSource %s, got %s", m.OllamaSource, retrieved.OllamaSource)
	}
	if retrieved.DockerImage != m.DockerImage {
		t.Errorf("expected DockerImage %s, got %s", m.DockerImage, retrieved.DockerImage)
	}
}

func TestCatalog_UpdateConnection(t *testing.T) {
	cat, db := setupTestCatalog(t)
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := cat.Seed(ctx); err != nil {
		t.Fatalf("failed to seed models: %v", err)
	}

	modelID := "laya-mlx"
	targetURL := "http://127.0.0.1:8088"
	runtimeType := "docker"

	// Update connection
	if err := cat.UpdateConnection(ctx, modelID, runtimeType, targetURL); err != nil {
		t.Fatalf("UpdateConnection failed: %v", err)
	}

	// Retrieve via Get
	retrieved, err := cat.Get(ctx, modelID)
	if err != nil {
		t.Fatalf("failed to get model after UpdateConnection: %v", err)
	}
	if retrieved.EndpointURL != targetURL {
		t.Errorf("expected EndpointURL %q, got %q", targetURL, retrieved.EndpointURL)
	}
	if retrieved.RuntimeType != runtimeType {
		t.Errorf("expected RuntimeType %q, got %q", runtimeType, retrieved.RuntimeType)
	}

	// Activate and retrieve via GetActive
	if err := cat.SetActive(ctx, modelID, true); err != nil {
		t.Fatalf("failed to activate model: %v", err)
	}

	active, err := cat.GetActive(ctx)
	if err != nil {
		t.Fatalf("failed to get active model: %v", err)
	}
	if active == nil {
		t.Fatal("expected active model, got nil")
	}
	if active.ID != modelID {
		t.Errorf("expected active model ID %q, got %q", modelID, active.ID)
	}
	if active.EndpointURL != targetURL {
		t.Errorf("expected active EndpointURL %q, got %q", targetURL, active.EndpointURL)
	}
	if active.RuntimeType != runtimeType {
		t.Errorf("expected active RuntimeType %q, got %q", runtimeType, active.RuntimeType)
	}

	// Update connection to Ollama with different endpoint
	ollamaURL := "http://127.0.0.1:11434"
	if err := cat.UpdateConnection(ctx, modelID, "ollama", ollamaURL); err != nil {
		t.Fatalf("UpdateConnection to ollama failed: %v", err)
	}

	activeOllama, err := cat.GetActive(ctx)
	if err != nil {
		t.Fatalf("failed to get active model after ollama update: %v", err)
	}
	if activeOllama.EndpointURL != ollamaURL {
		t.Errorf("expected EndpointURL %q, got %q", ollamaURL, activeOllama.EndpointURL)
	}
	if activeOllama.RuntimeType != "ollama" {
		t.Errorf("expected RuntimeType %q, got %q", "ollama", activeOllama.RuntimeType)
	}
}

func TestCatalog_Paradigm(t *testing.T) {
	cat, db := setupTestCatalog(t)
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := cat.Seed(ctx); err != nil {
		t.Fatalf("failed to seed models: %v", err)
	}

	// 1. Verify Laya seeded as DecisionModel
	laya, err := cat.Get(ctx, "laya-mlx")
	if err != nil {
		t.Fatalf("failed to get laya-mlx: %v", err)
	}
	if laya.Paradigm != ModelParadigmDecisionModel {
		t.Errorf("expected laya-mlx paradigm %q, got %q", ModelParadigmDecisionModel, laya.Paradigm)
	}

	// 2. Verify Qwen and Granite seeded as GenerativeLLM
	qwen, err := cat.Get(ctx, "qwen3guard")
	if err != nil {
		t.Fatalf("failed to get qwen3guard: %v", err)
	}
	if qwen.Paradigm != ModelParadigmGenerativeLLM {
		t.Errorf("expected qwen3guard paradigm %q, got %q", ModelParadigmGenerativeLLM, qwen.Paradigm)
	}

	granite, err := cat.Get(ctx, "granite-guardian")
	if err != nil {
		t.Fatalf("failed to get granite-guardian: %v", err)
	}
	if granite.Paradigm != ModelParadigmGenerativeLLM {
		t.Errorf("expected granite-guardian paradigm %q, got %q", ModelParadigmGenerativeLLM, granite.Paradigm)
	}

	// 3. Verify newly seeded Q4 models are DecisionModel
	decisionModels := []string{"liquid-d1", "pplx-decider-flash", "mica-v0.5"}
	for _, id := range decisionModels {
		m, err := cat.Get(ctx, id)
		if err != nil {
			t.Fatalf("failed to get %s: %v", id, err)
		}
		if m.Paradigm != ModelParadigmDecisionModel {
			t.Errorf("expected %s paradigm %q, got %q", id, ModelParadigmDecisionModel, m.Paradigm)
		}
	}

	// 4. Test re-seed preserves paradigm
	if err := cat.Seed(ctx); err != nil {
		t.Fatalf("re-seeding failed: %v", err)
	}
	layaAfter, err := cat.Get(ctx, "laya-mlx")
	if err != nil {
		t.Fatalf("failed to get laya-mlx after re-seed: %v", err)
	}
	if layaAfter.Paradigm != ModelParadigmDecisionModel {
		t.Errorf("expected laya-mlx paradigm to remain %q, got %q", ModelParadigmDecisionModel, layaAfter.Paradigm)
	}
}

func TestCatalog_GQA_And_UpdateContextWindow(t *testing.T) {
	cat, db := setupTestCatalog(t)
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := cat.Seed(ctx); err != nil {
		t.Fatalf("failed to seed models: %v", err)
	}

	// Verify default context window for mica-v0.5 is 2048
	mica, err := cat.Get(ctx, "mica-v0.5")
	if err != nil {
		t.Fatalf("failed to get mica-v0.5: %v", err)
	}
	if mica.ContextWindow != 2048 {
		t.Errorf("expected default context window 2048, got %d", mica.ContextWindow)
	}
	if mica.NumLayers != 32 || mica.NumKVHeads != 4 || mica.HeadDim != 128 {
		t.Errorf("expected mica GQA 32/4/128, got %d/%d/%d", mica.NumLayers, mica.NumKVHeads, mica.HeadDim)
	}

	// Update context window to 4096
	if err := cat.UpdateContextWindow(ctx, "mica-v0.5", 4096); err != nil {
		t.Fatalf("failed to update context window: %v", err)
	}

	micaUpdated, err := cat.Get(ctx, "mica-v0.5")
	if err != nil {
		t.Fatalf("failed to get mica-v0.5 after update: %v", err)
	}
	if micaUpdated.ContextWindow != 4096 {
		t.Errorf("expected context window 4096, got %d", micaUpdated.ContextWindow)
	}

	// Non-existent model returns ErrModelNotFound
	if err := cat.UpdateContextWindow(ctx, "non-existent", 2048); err != ErrModelNotFound {
		t.Errorf("expected ErrModelNotFound for non-existent model, got %v", err)
	}
}

func TestCatalog_GetActive_ZeroIO_InMemoryCache(t *testing.T) {
	cat, db := setupTestCatalog(t)
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := cat.Seed(ctx); err != nil {
		t.Fatalf("failed to seed models: %v", err)
	}

	modelID := "laya-mlx"
	if err := cat.SetActive(ctx, modelID, true); err != nil {
		t.Fatalf("SetActive failed: %v", err)
	}

	// Update policy with critical tools JSON
	if err := cat.UpdatePolicy(ctx, modelID, ThreatActionBlock, `["filesystem__read_file", "bash__execute"]`); err != nil {
		t.Fatalf("UpdatePolicy failed: %v", err)
	}

	// 1. Initial retrieval populates and verifies cache
	active, err := cat.GetActive(ctx)
	if err != nil {
		t.Fatalf("GetActive failed: %v", err)
	}
	if active == nil || active.ID != modelID {
		t.Fatalf("expected active model %s, got: %+v", modelID, active)
	}
	if active.DefaultAction != ThreatActionBlock {
		t.Errorf("expected default action 'block', got: %s", active.DefaultAction)
	}
	tools := active.GetCriticalTools()
	if len(tools) != 2 || tools[0] != "filesystem__read_file" || tools[1] != "bash__execute" {
		t.Errorf("expected parsed critical tools, got: %v", tools)
	}

	// 2. High-volume parallel calls to GetActive to verify concurrent safety and zero-lock contention
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				m, err := cat.GetActive(ctx)
				if err != nil || m == nil || m.ID != modelID {
					t.Errorf("unexpected GetActive result: err=%v, m=%v", err, m)
					return
				}
				if len(m.GetCriticalTools()) != 2 {
					t.Errorf("unexpected critical tools length: %v", m.GetCriticalTools())
					return
				}
			}
		}()
	}
	wg.Wait()
}


