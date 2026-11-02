package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/guard"
	_ "github.com/marcboeker/go-duckdb"
)

func TestRenderModelsTable(t *testing.T) {
	models := guard.DefaultModels()
	models[1].InstallStatus = guard.InstallStatusInstalled
	models[1].IsActive = true

	// 1. Test with ANSI color enabled
	var bufColor bytes.Buffer
	RenderModelsTable(models, &bufColor, true)
	colorOutput := bufColor.String()

	if !strings.Contains(colorOutput, "\033[") {
		t.Fatalf("expected ANSI color codes in colored table output")
	}
	if !strings.Contains(colorOutput, "Laya MLX Guard (laya-mlx)") {
		t.Errorf("expected laya-mlx in output")
	}
	if !strings.Contains(colorOutput, "1800 MB") {
		t.Errorf("expected 1800 MB RAM requirement in output")
	}
	if !strings.Contains(colorOutput, "24.2ms / 38.5ms") {
		t.Errorf("expected latency metrics in output")
	}
	if !strings.Contains(colorOutput, "86.2% (4.4%)") {
		t.Errorf("expected accuracy metrics in output")
	}
	if !strings.Contains(colorOutput, "INSTALLED") {
		t.Errorf("expected INSTALLED status in output")
	}
	if !strings.Contains(colorOutput, "YES") {
		t.Errorf("expected active YES in output")
	}

	// 2. Test with ANSI color disabled
	var bufPlain bytes.Buffer
	RenderModelsTable(models, &bufPlain, false)
	plainOutput := bufPlain.String()

	if strings.Contains(plainOutput, "\033[") {
		t.Fatalf("expected NO ANSI color codes in plain table output")
	}
	if !strings.Contains(plainOutput, "MODEL") || !strings.Contains(plainOutput, "RAM REQ") {
		t.Errorf("expected headers in plain output")
	}
	if !strings.Contains(plainOutput, "Qwen3Guard-0.6B (qwen3guard)") {
		t.Errorf("expected qwen3guard in plain output")
	}
}

func TestExecuteGuardList_DuckDBFallback(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_guard.duckdb")
	cfgPath := filepath.Join(tmpDir, "config.yaml")

	// Pre-populate DB
	db, err := sql.Open("duckdb", dbPath)
	if err != nil {
		t.Fatalf("failed to open duckdb: %v", err)
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
	db.Close()

	// Write config referencing this DB
	cfgContent := "telemetry:\n  db_path: \"" + dbPath + "\"\nlisten_port: 65432\nadmin_port: 65433\n"
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	var buf bytes.Buffer
	code := executeGuardList(cfgPath, &buf)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, output: %s", code, buf.String())
	}

	output := buf.String()
	if !strings.Contains(output, "laya-mlx") {
		t.Errorf("expected laya-mlx in output: %s", output)
	}
	if !strings.Contains(output, "qwen3guard") {
		t.Errorf("expected qwen3guard in output: %s", output)
	}
	if !strings.Contains(output, "granite-guardian") {
		t.Errorf("expected granite-guardian in output: %s", output)
	}
}

type roundTripFunc func(req *http.Request) *http.Response

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

func TestFetchModelsFromGateway(t *testing.T) {
	models := guard.DefaultModels()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/guards/models" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"models": models,
		})
	})

	mockClient := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) *http.Response {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			return rec.Result()
		}),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	fetched, err := fetchModelsFromGateway(ctx, "127.0.0.1", 8095, mockClient)
	if err != nil {
		t.Fatalf("failed to fetch models: %v", err)
	}
	if len(fetched) != 6 {
		t.Fatalf("expected 6 models, got %d", len(fetched))
	}
	if fetched[0].ID != "laya-mlx" {
		t.Errorf("expected laya-mlx, got %s", fetched[0].ID)
	}
}

func TestRenderGuardStatus(t *testing.T) {
	var buf strings.Builder
	now := time.Now().Add(-45 * time.Second)

	// 1. Running state
	activeStatus := &guard.ProcessStatus{
		Running:      true,
		ModelID:      "qwen3guard",
		PID:          9876,
		MemoryRSSMB:  64.2,
		HealthStatus: "HEALTHY",
		StartedAt:    &now,
	}

	RenderGuardStatus(activeStatus, &buf, false)
	out := buf.String()

	if !strings.Contains(out, "Farad Ai SLM Security Guard Process Status") {
		t.Errorf("missing header in status output: %s", out)
	}
	if !strings.Contains(out, "qwen3guard") {
		t.Errorf("missing modelID in status output: %s", out)
	}
	if !strings.Contains(out, "9876") {
		t.Errorf("missing PID in status output: %s", out)
	}
	if !strings.Contains(out, "64.2 MB") {
		t.Errorf("missing RSS memory in status output: %s", out)
	}
	if !strings.Contains(out, "HEALTHY") {
		t.Errorf("missing HEALTHY status in status output: %s", out)
	}

	// 2. Stopped state
	buf.Reset()
	stoppedStatus := &guard.ProcessStatus{
		Running:      false,
		HealthStatus: "STOPPED",
	}

	RenderGuardStatus(stoppedStatus, &buf, false)
	stoppedOut := buf.String()

	if !strings.Contains(stoppedOut, "STOPPED") {
		t.Errorf("expected STOPPED in output: %s", stoppedOut)
	}
	if !strings.Contains(stoppedOut, "Inactive (No L2 SLM guard running)") {
		t.Errorf("expected inactive note in output: %s", stoppedOut)
	}
}

func TestExecuteGuardStatus(t *testing.T) {
	now := time.Now()
	statusPayload := guard.ProcessStatus{
		Running:      true,
		ModelID:      "laya-mlx",
		PID:          1234,
		MemoryRSSMB:  110.5,
		HealthStatus: "HEALTHY",
		StartedAt:    &now,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/guards/status" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(statusPayload)
	})

	mockClient := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) *http.Response {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			return rec.Result()
		}),
	}

	var buf strings.Builder
	code := executeGuardStatus("", &buf, mockClient)
	if code != 0 {
		t.Fatalf("expected return code 0, got %d", code)
	}

	out := buf.String()
	if !strings.Contains(out, "laya-mlx") || !strings.Contains(out, "1234") {
		t.Errorf("expected active guard output, got: %s", out)
	}
}

func TestExecuteGuardInstall_Gateway(t *testing.T) {
	callCount := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/guards/models/qwen3guard/install" && r.Method == http.MethodPost {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]string{"status": "ACCEPTED"})
			return
		}
		if r.URL.Path == "/admin/guards/models/qwen3guard/progress" && r.Method == http.MethodGet {
			callCount++
			step := guard.StepDownloadingWeights
			progStatus := guard.InstallStatusInstalling
			progress := 0.5
			if callCount >= 2 {
				step = guard.StepCompleted
				progStatus = guard.InstallStatusInstalled
				progress = 1.0
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(guard.InstallProgress{
				ModelID:  "qwen3guard",
				Status:   progStatus,
				Step:     step,
				Progress: progress,
				Message:  "Downloading test weights",
			})
			return
		}
		if r.URL.Path == "/admin/guards/models/not-found/install" {
			http.NotFound(w, r)
			return
		}
		http.NotFound(w, r)
	})

	mockClient := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) *http.Response {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			return rec.Result()
		}),
	}

	// 1. Successful install with progress polling
	var buf strings.Builder
	code := executeGuardInstall("", "qwen3guard", &buf, mockClient)
	if code != 0 {
		t.Fatalf("expected code 0, got %d, output: %s", code, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "Initiating installation for model 'qwen3guard'") {
		t.Errorf("missing initiation message: %s", out)
	}
	if !strings.Contains(out, "Successfully installed model 'qwen3guard'") {
		t.Errorf("missing completion message: %s", out)
	}

	// 2. Empty model ID
	buf.Reset()
	code = executeGuardInstall("", "", &buf, mockClient)
	if code != 1 {
		t.Fatalf("expected code 1 for empty model ID, got %d", code)
	}

	// 3. Model not found
	buf.Reset()
	code = executeGuardInstall("", "not-found", &buf, mockClient)
	if code != 1 {
		t.Fatalf("expected code 1 for not-found model, got %d", code)
	}
}

func TestExecuteGuardUninstall_Gateway(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/guards/models/qwen3guard" && r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"status": "DELETED"})
			return
		}
		if r.URL.Path == "/admin/guards/models/missing-model" && r.Method == http.MethodDelete {
			http.NotFound(w, r)
			return
		}
		http.NotFound(w, r)
	})

	mockClient := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) *http.Response {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			return rec.Result()
		}),
	}

	// 1. Successful uninstall
	var buf strings.Builder
	code := executeGuardUninstall("", "qwen3guard", &buf, mockClient)
	if code != 0 {
		t.Fatalf("expected code 0, got %d, output: %s", code, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "Successfully uninstalled model 'qwen3guard'") {
		t.Errorf("expected success uninstall output, got: %s", out)
	}

	// 2. Empty model ID
	buf.Reset()
	code = executeGuardUninstall("", "", &buf, mockClient)
	if code != 1 {
		t.Fatalf("expected code 1 for empty model ID, got %d", code)
	}

	// 3. 404 Not Found
	buf.Reset()
	code = executeGuardUninstall("", "missing-model", &buf, mockClient)
	if code != 1 {
		t.Fatalf("expected code 1 for missing model, got %d", code)
	}
}

func TestExecuteGuardInstall_Offline_And_Uninstall(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_guard_cli.duckdb")
	cfgPath := filepath.Join(tmpDir, "config.yaml")
	guardsDir := filepath.Join(tmpDir, "guards")

	t.Setenv("FARADAI_WIRE_GUARDS_DIR", guardsDir)

	// Pre-create mock venv to skip real network/pip
	venvDir := filepath.Join(guardsDir, ".venv")
	binDir := filepath.Join(venvDir, "bin")
	_ = os.MkdirAll(binDir, 0755)
	pythonPath := filepath.Join(binDir, "python")
	dummyScript := "#!/bin/sh\nexit 0\n"
	_ = os.WriteFile(pythonPath, []byte(dummyScript), 0755)

	// Write config referencing this DB and unreachable port
	cfgContent := "telemetry:\n  db_path: \"" + dbPath + "\"\nlisten_port: 59998\nadmin_port: 59999\n"
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	// Pre-populate DB
	db, err := sql.Open("duckdb", dbPath)
	if err != nil {
		t.Fatalf("failed to open duckdb: %v", err)
	}
	cat := guard.NewCatalog(db)
	ctx := context.Background()
	_ = cat.Migrate(ctx)
	_ = cat.Seed(ctx)
	db.Close()

	// 1. Direct offline installation
	var buf strings.Builder
	code := executeGuardInstall(cfgPath, "laya-mlx", &buf)
	if code != 0 {
		t.Fatalf("expected code 0 for offline install, got %d, output: %s", code, buf.String())
	}
	if !strings.Contains(buf.String(), "Successfully installed model 'laya-mlx'") {
		t.Errorf("missing success message in offline install: %s", buf.String())
	}

	// Verify model directory exists
	targetDir := filepath.Join(guardsDir, "models", "laya-mlx")
	if _, err := os.Stat(targetDir); os.IsNotExist(err) {
		t.Fatalf("expected target model dir %s to exist", targetDir)
	}

	// Verify DuckDB state is INSTALLED
	dbCheck, _ := sql.Open("duckdb", dbPath)
	catCheck := guard.NewCatalog(dbCheck)
	m, err := catCheck.Get(ctx, "laya-mlx")
	dbCheck.Close()
	if err != nil {
		t.Fatalf("failed to query model: %v", err)
	}
	if m.InstallStatus != guard.InstallStatusInstalled {
		t.Fatalf("expected status INSTALLED, got %s", m.InstallStatus)
	}

	// 2. Direct offline uninstallation
	buf.Reset()
	code = executeGuardUninstall(cfgPath, "laya-mlx", &buf)
	if code != 0 {
		t.Fatalf("expected code 0 for offline uninstall, got %d, output: %s", code, buf.String())
	}
	if !strings.Contains(buf.String(), "Successfully uninstalled model 'laya-mlx'") {
		t.Errorf("missing success message in offline uninstall: %s", buf.String())
	}

	// Verify model directory was purged
	if _, err := os.Stat(targetDir); !os.IsNotExist(err) {
		t.Fatalf("expected target model dir %s to be purged", targetDir)
	}

	// Verify DuckDB state reverted to NOT_INSTALLED
	dbCheck2, _ := sql.Open("duckdb", dbPath)
	catCheck2 := guard.NewCatalog(dbCheck2)
	m2, err := catCheck2.Get(ctx, "laya-mlx")
	dbCheck2.Close()
	if err != nil {
		t.Fatalf("failed to query model: %v", err)
	}
	if m2.InstallStatus != guard.InstallStatusNotInstalled {
		t.Fatalf("expected status NOT_INSTALLED, got %s", m2.InstallStatus)
	}
}
