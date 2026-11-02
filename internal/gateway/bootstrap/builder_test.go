package bootstrap

import (
	"path/filepath"
	"testing"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
)

func TestBuilder_Build_DefaultConfig(t *testing.T) {
	tempDir := t.TempDir()
	enabled := true
	cfg := &config.Config{
		Mode:       "sse",
		ListenPort: 8080,
		AdminPort:  9090,
		AgentsDir:  filepath.Join(tempDir, "agents"),
		Telemetry: config.TelemetryConfig{
			Enabled: &enabled,
			DBPath:  ":memory:",
		},
		SSE: config.SSEConfig{
			TargetURL: "http://localhost:8081/sse",
		},
	}

	deps, err := Build(cfg, nil)
	if err != nil {
		t.Fatalf("failed to build dependencies: %v", err)
	}
	defer deps.Cleanup()

	if deps.Pipeline == nil {
		t.Error("expected non-nil Pipeline")
	}
	if deps.DBManager == nil {
		t.Error("expected non-nil DBManager")
	}
	if deps.TelemetryEngine == nil {
		t.Error("expected non-nil TelemetryEngine")
	}
	if deps.GuardCatalog == nil {
		t.Error("expected non-nil GuardCatalog")
	}
	if deps.PolicyStore == nil {
		t.Error("expected non-nil PolicyStore")
	}
	if deps.SchemaStore == nil {
		t.Error("expected non-nil SchemaStore")
	}
	if deps.SettingsStore == nil {
		t.Error("expected non-nil SettingsStore")
	}
	if deps.SettingsCache == nil {
		t.Error("expected non-nil SettingsCache")
	} else if deps.SettingsCache.Get() == nil {
		t.Error("expected non-nil OperationalSettings in SettingsCache")
	}
	if deps.SSEProxy == nil {
		t.Error("expected non-nil SSEProxy")
	}
	if deps.AdminServer == nil {
		t.Error("expected non-nil AdminServer")
	}
	if deps.Coordinator == nil {
		t.Error("expected non-nil Coordinator")
	}
}

func TestBuilder_Build_SamePort_Rejection(t *testing.T) {
	cfg := &config.Config{
		ListenPort: 8080,
		AdminPort:  8080,
	}

	_, err := Build(cfg, nil)
	if err == nil {
		t.Fatal("expected error when listen_port and admin_port are identical, got nil")
	}
}
