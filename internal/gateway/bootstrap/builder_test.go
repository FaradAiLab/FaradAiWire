package bootstrap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/protocol"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
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

func TestBuilder_Build_ModeStdioRejectedWhenStdioDisabled(t *testing.T) {
	allowStdio := false
	cfg := &config.Config{
		AllowStdio: &allowStdio,
		Mode:       "stdio",
		Stdio: config.StdioConfig{
			Command: "cat",
		},
		ListenPort: 19490,
		AdminPort:  19495,
	}
	if _, err := Build(cfg, nil); err == nil {
		t.Fatal("expected Build to reject mode=stdio when allow_stdio=false")
	}
}

func TestBuilder_Build_BootstrapsAdminKeyAndDefaultProfile(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("FARADAI_WIRE_HOME", tempDir)
	t.Setenv("FARADAI_WIRE_API_KEY", "")

	allowStdio := false
	enabled := false
	cfg := &config.Config{
		AllowStdio:  &allowStdio,
		RuntimeMode: config.RuntimeModeStandalone,
		Mode:        "sse",
		ListenPort:  19491,
		AdminPort:   19496,
		Telemetry: config.TelemetryConfig{
			Enabled: &enabled,
			DBPath:  ":memory:",
		},
	}

	deps, err := Build(cfg, nil)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	defer deps.Cleanup()

	keys := deps.KeyStore.ListKeys()
	var foundAdmin bool
	for _, k := range keys {
		if !k.Revoked && k.Role == "Admin" && k.AgentName == "*" && strings.HasPrefix(k.RawKey, "faw_live_") {
			foundAdmin = true
		}
	}
	if !foundAdmin {
		t.Fatalf("expected auto-provisioned Bootstrap Master Key (Admin, *), got: %+v", keys)
	}

	if defaultCfg, err := deps.AgentRepo.GetAgentConfig("default"); err != nil || defaultCfg == nil {
		t.Fatalf("expected default Security Profile to be seeded in container mode, err=%v", err)
	}
}

func TestBuilder_Build_ToolDispatcherBlocksCloudMetadataSSRF(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("FARADAI_WIRE_HOME", tempDir)

	allowStdio := false
	enabled := false
	cfg := &config.Config{
		AllowStdio:  &allowStdio,
		RuntimeMode: config.RuntimeModeStandalone,
		Mode:        "sse",
		ListenPort:  19492,
		AdminPort:   19497,
		Telemetry: config.TelemetryConfig{
			Enabled: &enabled,
			DBPath:  ":memory:",
		},
	}

	deps, err := Build(cfg, nil)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	defer deps.Cleanup()

	if deps.ToolDispatcher == nil {
		t.Fatal("expected deps.ToolDispatcher to be wired")
	}

	if err := deps.AgentRepo.SaveAgentConfig("imds-agent", &agent.RouteConfig{
		AgentName:   "imds-agent",
		RoutingMode: "aggregated",
		Protocols: []agent.ProtocolConfig{
			{
				ID:           "imds",
				Name:         "imds",
				Type:         "http",
				URLOrCommand: "http://169.254.169.254/latest/meta-data",
			},
		},
	}); err != nil {
		t.Fatalf("SaveAgentConfig failed: %v", err)
	}
	if err := deps.AgentRepo.SaveAgentManifest("imds-agent", []agent.ToolMetadata{
		{
			Name:          "imds__probe",
			RawName:       "probe",
			CanonicalName: "imds__probe",
			ProtocolID:    "imds",
			ProtocolName:  "imds",
		},
	}); err != nil {
		t.Fatalf("SaveAgentManifest failed: %v", err)
	}

	ctx := context.Background()
	bridge, err := deps.SessionMgr.CreateBridge(ctx, "imds-agent", "sess-ssrf-test", nil)
	if err != nil {
		t.Fatalf("CreateBridge failed: %v", err)
	}
	defer bridge.Close()

	res, err := deps.ToolDispatcher.DispatchTool(ctx, "imds-agent", "imds__probe", &mcp.Request{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
	}, nil, bridge)
	if err != nil {
		t.Fatalf("DispatchTool returned unexpected error: %v", err)
	}
	if res == nil || res.Response == nil || res.Response.Error == nil {
		t.Fatalf("expected SSRF error response for cloud metadata IMDS, got %+v", res)
	}
	msg := strings.ToLower(res.Response.Error.Message)
	if !strings.Contains(msg, "metadata") && !strings.Contains(msg, "ssrf") && !strings.Contains(msg, "blocked") {
		t.Fatalf("expected cloud metadata/SSRF block error in Streamable HTTP tool call, got: %q", res.Response.Error.Message)
	}
}
