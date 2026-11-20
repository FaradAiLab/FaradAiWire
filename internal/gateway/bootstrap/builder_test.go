package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/protocol"
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

func TestBuilder_Build_ProtocolStore_InUseIntegrity(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("FARADAI_WIRE_HOME", tempDir)

	enabled := false
	cfg := &config.Config{
		RuntimeMode:  config.RuntimeModeStandalone,
		Mode:         "sse",
		ListenPort:   8080,
		AdminPort:    9090,
		AgentsDir:    filepath.Join(tempDir, "agents"),
		ProtocolsDir: filepath.Join(tempDir, "protocols"),
		Telemetry: config.TelemetryConfig{
			Enabled: &enabled,
			DBPath:  filepath.Join(tempDir, "telemetry.duckdb"),
		},
		SSE: config.SSEConfig{
			TargetURL: "http://localhost:8081/sse",
		},
	}

	deps, err := Build(cfg, nil)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	defer deps.Cleanup()

	if deps.ProtocolStore == nil {
		t.Fatal("expected non-nil ProtocolStore wired by Build")
	}

	if err := deps.ProtocolStore.Save(&protocol.Protocol{
		ID:      "corp-proto",
		Name:    "corp-proto",
		Type:    "stdio",
		Command: "cat",
	}); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	if err := deps.AgentRepo.SaveAgentConfig("demo-agent", &agent.RouteConfig{
		AgentName: "demo-agent",
		Protocols: []agent.ProtocolConfig{
			{ID: "corp-proto", Name: "corp-proto", Type: "stdio", Command: "cat"},
		},
	}); err != nil {
		t.Fatalf("SaveAgentConfig failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/admin/protocols/corp-proto", nil)
	rec := httptest.NewRecorder()
	deps.AdminServer.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("DELETE /admin/protocols/corp-proto = %d, want 409 Conflict (body: %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "PROTOCOL_IN_USE") {
		t.Fatalf("expected PROTOCOL_IN_USE error code in body, got: %s", rec.Body.String())
	}
}
