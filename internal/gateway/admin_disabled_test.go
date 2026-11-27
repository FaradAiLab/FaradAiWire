package gateway_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/gateway"
)

func TestServer_AdminDisabled_DisablesAdminServerAndSkipsPortCollision(t *testing.T) {
	tempDir := t.TempDir()
	// Deliberately use DefaultAdminPort (19415) for listen_port to verify collision check is bypassed when AdminDisabled=true.
	cfg := &config.Config{
		Mode:          "sse",
		ListenHost:    "127.0.0.1",
		ListenPort:    config.DefaultAdminPort,
		AdminDisabled: true,
		AgentsDir:     filepath.Join(tempDir, "agents"),
		ProtocolsDir:  filepath.Join(tempDir, "protocols"),
		Telemetry: config.TelemetryConfig{
			DBPath: filepath.Join(tempDir, "wire.duckdb"),
		},
		SSE: config.SSEConfig{
			TargetURL: "http://localhost:8080",
		},
	}

	provider := &mockConfigProvider{cfg: cfg}
	srv, err := gateway.NewServer(cfg, provider)
	if err != nil {
		t.Fatalf("NewServer with AdminDisabled=true failed: %v", err)
	}
	defer srv.Shutdown(context.Background())

	if srv.AdminServer() != nil {
		t.Fatalf("expected AdminServer() to be nil when AdminDisabled=true")
	}
	if srv.DesktopNotifier() != nil && srv.DesktopNotifier().AdminBaseURL() != "" {
		t.Fatalf("expected empty AdminBaseURL when AdminDisabled=true, got %q", srv.DesktopNotifier().AdminBaseURL())
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/status", nil)
	srv.AdminHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 from AdminHandler when AdminDisabled=true, got %d", rec.Code)
	}

	// ReloadWithConfig using a freshly unmarshaled Config (where AdminDisabled starts false) must preserve AdminDisabled=true.
	reloadedCfg := &config.Config{
		Mode:         "sse",
		ListenHost:   "127.0.0.1",
		ListenPort:   config.DefaultAdminPort,
		AgentsDir:    cfg.AgentsDir,
		ProtocolsDir: cfg.ProtocolsDir,
		Telemetry:    cfg.Telemetry,
		SSE:          cfg.SSE,
	}
	if err := srv.ReloadWithConfig(reloadedCfg); err != nil {
		t.Fatalf("ReloadWithConfig failed: %v", err)
	}
	if !reloadedCfg.AdminDisabled {
		t.Fatalf("expected ReloadWithConfig to preserve AdminDisabled=true")
	}
	if srv.DesktopNotifier() != nil && srv.DesktopNotifier().AdminBaseURL() != "" {
		t.Fatalf("expected AdminBaseURL to remain empty after reload, got %q", srv.DesktopNotifier().AdminBaseURL())
	}
}

func TestServer_AdminListenerDisabled_ConstructsHandlerWithoutBindingPort(t *testing.T) {
	tempDir := t.TempDir()
	listenPort := getFreePort(t)
	adminPort := getFreePort(t)

	cfg := &config.Config{
		Mode:                  "sse",
		ListenHost:            "127.0.0.1",
		ListenPort:            listenPort,
		AdminHost:             "127.0.0.1",
		AdminPort:             adminPort,
		AdminListenerDisabled: true,
		AgentsDir:             filepath.Join(tempDir, "agents"),
		ProtocolsDir:          filepath.Join(tempDir, "protocols"),
		Telemetry: config.TelemetryConfig{
			DBPath: filepath.Join(tempDir, "wire.duckdb"),
		},
		SSE: config.SSEConfig{
			TargetURL: "http://localhost:8080",
		},
	}

	provider := &mockConfigProvider{cfg: cfg}
	srv, err := gateway.NewServer(cfg, provider)
	if err != nil {
		t.Fatalf("NewServer with AdminListenerDisabled=true failed: %v", err)
	}

	if srv.AdminServer() == nil {
		t.Fatalf("expected AdminServer() to be non-nil when AdminListenerDisabled=true")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(ctx)
	}()

	// Wait for SSE proxy port to come up
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, dErr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", listenPort), 50*time.Millisecond)
		if dErr == nil {
			_ = conn.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Admin port MUST remain unbound because AdminListenerDisabled=true
	if conn, dErr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", adminPort), 100*time.Millisecond); dErr == nil {
		_ = conn.Close()
		t.Fatalf("expected admin port %d NOT to be bound when AdminListenerDisabled=true", adminPort)
	}

	// In-process AdminHandler must still serve requests
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/readyz", nil)
	srv.AdminHandler().ServeHTTP(rec, req)
	if rec.Code == http.StatusNotFound {
		t.Fatalf("expected in-process AdminHandler to serve /admin/readyz, got 404")
	}

	cancel()
	_ = srv.Shutdown(context.Background())
	select {
	case sErr := <-errCh:
		if sErr != nil {
			t.Fatalf("Server.Start returned unexpected error: %v", sErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for Server.Start to exit")
	}
}
