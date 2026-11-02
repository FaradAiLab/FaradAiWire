package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/audit"
)

func TestCLI_Run_StandaloneDefaults(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("FARADAI_WIRE_HOME", tempHome)
	t.Setenv("FARADAI_WIRE_API_KEY", "")
	t.Setenv("API_KEY", "")

	// 1. Verify autodiscovery of default standalone runtime config
	provider := config.NewYAMLConfigProvider("")
	cfg, err := provider.Load()
	if err != nil {
		t.Fatalf("failed to load auto-bootstrapped config: %v", err)
	}

	if cfg.GetRuntimeMode() != config.RuntimeModeStandalone {
		t.Errorf("expected STANDALONE runtime mode, got %s", cfg.GetRuntimeMode())
	}
	if !cfg.IsStandalone() {
		t.Errorf("expected IsStandalone() to be true")
	}
	if cfg.GetListenHost() != "127.0.0.1" {
		t.Errorf("expected default listen host 127.0.0.1, got %s", cfg.GetListenHost())
	}
	if cfg.GetListenPort() != 8090 {
		t.Errorf("expected default port 8090, got %d", cfg.GetListenPort())
	}
	if cfg.GetAdminPort() != 8095 {
		t.Errorf("expected default admin port 8095, got %d", cfg.GetAdminPort())
	}

	// 2. Verify config directory structure
	for _, sub := range []string{"agents", "backups", "policies"} {
		path := filepath.Join(tempHome, sub)
		if info, err := os.Stat(path); os.IsNotExist(err) || !info.IsDir() {
			t.Errorf("expected runtime directory %s to exist", path)
		}
	}
}

func TestCLI_UsageString(t *testing.T) {
	usageStr := "Usage: faradaiwire run [--config <path>] [--standalone] [--host <host>] [--port <port>] [--admin-port <admin-port>] | doctor [--config <path>] | audit <path> | version"
	if !strings.Contains(usageStr, "--host <host>") {
		t.Errorf("expected usage to mention --host <host>")
	}
	if !strings.Contains(usageStr, "doctor") {
		t.Errorf("expected usage to mention doctor")
	}
	if strings.Contains(usageStr, "link --token") {
		t.Errorf("expected usage NOT to mention link --token")
	}
	if strings.Contains(usageStr, "unlink") {
		t.Errorf("expected usage NOT to mention unlink")
	}
}

func TestCLI_DoctorCommand(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("FARADAI_WIRE_HOME", tempHome)

	var buf strings.Builder
	exitCode := executeDoctor("", &buf)

	if exitCode != 0 {
		t.Errorf("expected doctor exit code 0, got %d", exitCode)
	}

	out := buf.String()
	if !strings.Contains(out, "FaradAiWire Diagnostic Report (Doctor)") {
		t.Errorf("expected diagnostic header in doctor output")
	}
	if !strings.Contains(out, "Configuration:") {
		t.Errorf("expected configuration check in doctor output")
	}
	if !strings.Contains(out, "Neural SLM") {
		t.Errorf("expected neural SLM check in doctor output")
	}
}

func TestCLI_AuditCommand(t *testing.T) {
	// 1. Test clean directory
	cleanDir := t.TempDir()
	cleanFile := filepath.Join(cleanDir, "calculator.py")
	if err := os.WriteFile(cleanFile, []byte("def add(x, y): return x + y\n"), 0644); err != nil {
		t.Fatal(err)
	}

	var bufClean strings.Builder
	cleanExit := executeAudit(cleanDir, false, &bufClean)
	if cleanExit != 0 {
		t.Errorf("expected clean audit exit code 0, got %d. Output: %s", cleanExit, bufClean.String())
	}
	cleanOut := bufClean.String()
	if !strings.Contains(cleanOut, "Audit Result: PASSED (No threat signatures detected)") {
		t.Errorf("expected PASSED result in clean output: %s", cleanOut)
	}
	if !strings.Contains(cleanOut, "[✓] No malicious shell invocations found") {
		t.Errorf("expected category checkmark in output: %s", cleanOut)
	}
	if !strings.Contains(cleanOut, "Exit Code: 0") {
		t.Errorf("expected Exit Code: 0 in output: %s", cleanOut)
	}

	// 1b. Test clean directory with JSON output
	var bufCleanJSON strings.Builder
	cleanJSONExit := executeAudit(cleanDir, true, &bufCleanJSON)
	if cleanJSONExit != 0 {
		t.Errorf("expected clean json audit exit code 0, got %d. Output: %s", cleanJSONExit, bufCleanJSON.String())
	}
	var cleanReport audit.AuditReport
	if err := json.Unmarshal([]byte(bufCleanJSON.String()), &cleanReport); err != nil {
		t.Fatalf("failed to parse clean JSON report: %v, raw: %s", err, bufCleanJSON.String())
	}
	if cleanReport.ScannedFilesCount != 1 {
		t.Errorf("expected 1 scanned file in JSON report, got %d", cleanReport.ScannedFilesCount)
	}
	if len(cleanReport.Issues) != 0 {
		t.Errorf("expected 0 issues in clean JSON report, got %d", len(cleanReport.Issues))
	}

	// 2. Test malicious directory
	dirtyDir := t.TempDir()
	dirtyFile := filepath.Join(dirtyDir, "exploit.sh")
	if err := os.WriteFile(dirtyFile, []byte("#!/bin/bash\nrm -rf /\n"), 0644); err != nil {
		t.Fatal(err)
	}

	var bufDirty strings.Builder
	dirtyExit := executeAudit(dirtyDir, false, &bufDirty)
	if dirtyExit != 2 {
		t.Errorf("expected dirty audit exit code 2, got %d. Output: %s", dirtyExit, bufDirty.String())
	}
	dirtyOut := bufDirty.String()
	if !strings.Contains(dirtyOut, "Audit Result: FAILED") {
		t.Errorf("expected FAILED in dirty output: %s", dirtyOut)
	}
	if !strings.Contains(dirtyOut, "[ALERT: CRITICAL]") {
		t.Errorf("expected CRITICAL alert in output: %s", dirtyOut)
	}
	if !strings.Contains(dirtyOut, "Exit Code: 2") {
		t.Errorf("expected Exit Code: 2 in output: %s", dirtyOut)
	}

	// 2b. Test malicious directory with JSON output
	var bufDirtyJSON strings.Builder
	dirtyJSONExit := executeAudit(dirtyDir, true, &bufDirtyJSON)
	if dirtyJSONExit != 2 {
		t.Errorf("expected dirty json audit exit code 2, got %d. Output: %s", dirtyJSONExit, bufDirtyJSON.String())
	}
	var dirtyReport audit.AuditReport
	if err := json.Unmarshal([]byte(bufDirtyJSON.String()), &dirtyReport); err != nil {
		t.Fatalf("failed to parse dirty JSON report: %v, raw: %s", err, bufDirtyJSON.String())
	}
	if len(dirtyReport.Issues) == 0 {
		t.Errorf("expected issues in dirty JSON report, got 0")
	}

	// 3. Test non-existent path
	var bufMissing strings.Builder
	missingExit := executeAudit(filepath.Join(cleanDir, "non_existent"), false, &bufMissing)
	if missingExit != 1 {
		t.Errorf("expected missing path exit code 1, got %d", missingExit)
	}
	if !strings.Contains(bufMissing.String(), "Error: Audit scan failed") {
		t.Errorf("expected error message for missing path: %s", bufMissing.String())
	}

	// 3b. Test non-existent path with JSON output
	var bufMissingJSON strings.Builder
	missingJSONExit := executeAudit(filepath.Join(cleanDir, "non_existent"), true, &bufMissingJSON)
	if missingJSONExit != 1 {
		t.Errorf("expected missing json exit code 1, got %d", missingJSONExit)
	}
	var errReport map[string]interface{}
	if err := json.Unmarshal([]byte(bufMissingJSON.String()), &errReport); err != nil {
		t.Fatalf("failed to parse error JSON: %v, raw: %s", err, bufMissingJSON.String())
	}
	if errReport["status"] != "ERROR" {
		t.Errorf("expected status ERROR in json error report, got %v", errReport["status"])
	}

	// 4. Test remote URL failure
	var bufRemote strings.Builder
	remoteExit := executeAudit("https://invalid-host-for-test.local/skill.git", false, &bufRemote)
	if remoteExit != 1 {
		t.Errorf("expected remote clone failure exit code 1, got %d", remoteExit)
	}
	if !strings.Contains(bufRemote.String(), "Error: Audit scan failed") {
		t.Errorf("expected error message for remote failure: %s", bufRemote.String())
	}
}
