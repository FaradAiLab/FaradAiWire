package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/auth"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/db/duckdb"
	"github.com/FaradAiLab/FaradAiWire/internal/mcpconfig"
	"github.com/FaradAiLab/FaradAiWire/internal/settings"
)

type mockClientAdapter struct {
	id          mcpconfig.ClientID
	displayName string
	cfgPath     string
	detected    bool
	servers     []mcpconfig.DiscoveredServer
	readErr     error
	applyCalled bool
	applyErr    error
}

func (m *mockClientAdapter) ID() mcpconfig.ClientID {
	return m.id
}

func (m *mockClientAdapter) DisplayName() string {
	return m.displayName
}

func (m *mockClientAdapter) ConfigPath() (string, error) {
	return m.cfgPath, nil
}

func (m *mockClientAdapter) Detect() bool {
	return m.detected
}

func (m *mockClientAdapter) ReadServers() ([]mcpconfig.DiscoveredServer, error) {
	if m.readErr != nil {
		return nil, m.readErr
	}
	return m.servers, nil
}

func (m *mockClientAdapter) ApplyGatewayConfig(profileName string, adoptedServerNames []string) error {
	m.applyCalled = true
	return m.applyErr
}

func (m *mockClientAdapter) RestoreBackup(backupPath string) error {
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return err
	}
	return os.WriteFile(m.cfgPath, data, 0600)
}

func TestExecuteAdopt_NoServers(t *testing.T) {
	mockAdapter := &mockClientAdapter{
		id:          mcpconfig.ClientCursor,
		displayName: "Cursor",
		detected:    false,
	}

	var out bytes.Buffer
	code := executeAdoptWithAdapters(adoptOptions{yes: true}, strings.NewReader(""), &out, []mcpconfig.ClientAdapter{mockAdapter})

	if code != 0 {
		t.Fatalf("expected code 0, got %d", code)
	}
	if !strings.Contains(out.String(), "No MCP servers detected") {
		t.Errorf("expected 'No MCP servers detected' message, got:\n%s", out.String())
	}
}

func TestExecuteAdopt_DryRun(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "cursor.json")
	_ = os.WriteFile(cfgFile, []byte(`{"mcpServers":{}}`), 0600)

	mockAdapter := &mockClientAdapter{
		id:          mcpconfig.ClientCursor,
		displayName: "Cursor",
		cfgPath:     cfgFile,
		detected:    true,
		servers: []mcpconfig.DiscoveredServer{
			{
				ClientID:   mcpconfig.ClientCursor,
				ClientName: "Cursor",
				Name:       "github",
				Command:    "npx",
				Args:       []string{"-y", "@modelcontextprotocol/server-github"},
			},
		},
	}

	var out bytes.Buffer
	code := executeAdoptWithAdapters(adoptOptions{
		dryRun:       true,
		backupDir:    filepath.Join(tmpDir, "backups"),
		protocolsDir: filepath.Join(tmpDir, "protocols"),
		agentsDir:    filepath.Join(tmpDir, "agents"),
	}, strings.NewReader(""), &out, []mcpconfig.ClientAdapter{mockAdapter})

	if code != 0 {
		t.Fatalf("expected code 0, got %d", code)
	}
	output := out.String()
	if !strings.Contains(output, "[DRY-RUN] Planned changes:") {
		t.Errorf("expected dry-run header, got:\n%s", output)
	}
	if !strings.Contains(output, "[DRY-RUN] No files were modified on disk.") {
		t.Errorf("expected dry-run footer, got:\n%s", output)
	}
	if mockAdapter.applyCalled {
		t.Errorf("expected ApplyGatewayConfig NOT to be called in dry-run")
	}
}

func TestExecuteAdopt_InteractiveCancelled(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "cursor.json")
	_ = os.WriteFile(cfgFile, []byte(`{"mcpServers":{}}`), 0600)

	mockAdapter := &mockClientAdapter{
		id:          mcpconfig.ClientCursor,
		displayName: "Cursor",
		cfgPath:     cfgFile,
		detected:    true,
		servers: []mcpconfig.DiscoveredServer{
			{
				ClientID:   mcpconfig.ClientCursor,
				ClientName: "Cursor",
				Name:       "test-server",
				Command:    "echo",
				Args:       []string{"hello"},
			},
		},
	}

	var out bytes.Buffer
	code := executeAdoptWithAdapters(adoptOptions{
		yes:          false,
		backupDir:    filepath.Join(tmpDir, "backups"),
		protocolsDir: filepath.Join(tmpDir, "protocols"),
		agentsDir:    filepath.Join(tmpDir, "agents"),
	}, strings.NewReader("n\n"), &out, []mcpconfig.ClientAdapter{mockAdapter})

	if code != 0 {
		t.Fatalf("expected code 0, got %d", code)
	}
	if !strings.Contains(out.String(), "Adoption cancelled by user.") {
		t.Errorf("expected cancellation message, got:\n%s", out.String())
	}
	if mockAdapter.applyCalled {
		t.Errorf("expected ApplyGatewayConfig NOT to be called on cancellation")
	}
}

func TestExecuteAdopt_Success(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("USERPROFILE", tmpDir)
	cfgFile := filepath.Join(tmpDir, "cursor.json")
	originalJSON := `{"mcpServers":{"test-server":{"command":"echo","args":["hello"]}}}`
	if err := os.WriteFile(cfgFile, []byte(originalJSON), 0600); err != nil {
		t.Fatalf("write original cfg: %v", err)
	}

	mockAdapter := &mockClientAdapter{
		id:          mcpconfig.ClientCursor,
		displayName: "Cursor",
		cfgPath:     cfgFile,
		detected:    true,
		servers: []mcpconfig.DiscoveredServer{
			{
				ClientID:   mcpconfig.ClientCursor,
				ClientName: "Cursor",
				Name:       "test-server",
				Command:    "echo",
				Args:       []string{"hello"},
			},
		},
	}

	backupDir := filepath.Join(tmpDir, "backups")
	protocolsDir := filepath.Join(tmpDir, "protocols")
	agentsDir := filepath.Join(tmpDir, "agents")

	var out bytes.Buffer
	code := executeAdoptWithAdapters(adoptOptions{
		yes:          true,
		backupDir:    backupDir,
		protocolsDir: protocolsDir,
		agentsDir:    agentsDir,
	}, strings.NewReader(""), &out, []mcpconfig.ClientAdapter{mockAdapter})

	if code != 0 {
		t.Fatalf("expected code 0, got %d, out:\n%s", code, out.String())
	}
	if !mockAdapter.applyCalled {
		t.Errorf("expected ApplyGatewayConfig to be called")
	}

	// Verify backup was created (keyed by config path)
	bm, err := mcpconfig.NewBackupManager(backupDir)
	if err != nil {
		t.Fatalf("new backup manager: %v", err)
	}
	if !bm.HasBackupForConfig(mcpconfig.ClientCursor, cfgFile) {
		t.Errorf("expected backup file to exist for cursor config %s", cfgFile)
	}

	// Verify protocol file was written with collision-safe SHA-256 suffix
	matches, globErr := filepath.Glob(filepath.Join(protocolsDir, "cursor_test_server_*.json"))
	if globErr != nil || len(matches) != 1 {
		t.Errorf("expected 1 protocol file matching cursor_test_server_*.json, got %v (err=%v)", matches, globErr)
	}
	if _, err := os.Stat(filepath.Join(tmpDir, ".gitignore")); os.IsNotExist(err) {
		t.Errorf("expected .gitignore to be created alongside protocols directory")
	}

	// Verify agent config and DLP recommendation files were written
	agentConfigFile := filepath.Join(agentsDir, "cursor", "current", "config.json")
	if _, err := os.Stat(agentConfigFile); os.IsNotExist(err) {
		t.Errorf("expected agent config %s to exist", agentConfigFile)
	}
	dlpFile := filepath.Join(agentsDir, "cursor", "current", "dlp.json")
	if _, err := os.Stat(dlpFile); os.IsNotExist(err) {
		t.Errorf("expected recommendation dlp.json %s to exist", dlpFile)
	}

	// Verify scoped local API key was auto-provisioned for the adopted profile
	ks, ksErr := auth.NewFileKeyStore(filepath.Join(tmpDir, "keys", "api_keys.json"))
	if ksErr != nil {
		t.Fatalf("open api_keys.json: %v", ksErr)
	}
	foundKey := false
	for _, k := range ks.ListKeys() {
		if k.AgentName == "cursor" && strings.HasPrefix(k.RawKey, "faw_live_") && !k.Revoked {
			foundKey = true
		}
	}
	if !foundKey {
		t.Errorf("expected scoped local faw_live_ API key to be provisioned for 'cursor'")
	}
}

func TestExecuteAdopt_Rollback(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "cursor.json")
	originalJSON := `{"mcpServers":{"test-server":{"command":"echo"}}}`
	if err := os.WriteFile(cfgFile, []byte(originalJSON), 0600); err != nil {
		t.Fatalf("write original cfg: %v", err)
	}

	backupDir := filepath.Join(tmpDir, "backups")
	bm, err := mcpconfig.NewBackupManager(backupDir)
	if err != nil {
		t.Fatalf("new backup manager: %v", err)
	}

	if _, err := bm.CreateBackup(mcpconfig.ClientCursor, cfgFile); err != nil {
		t.Fatalf("create backup: %v", err)
	}

	// Now simulate post-adoption mutation on the same cfgFile path
	mutatedJSON := `{"mcpServers":{"farad-ai-wire":{"command":"faradaiwire","args":["connect"]}}}`
	if err := os.WriteFile(cfgFile, []byte(mutatedJSON), 0600); err != nil {
		t.Fatalf("write mutated cfg: %v", err)
	}

	mockAdapter := &mockClientAdapter{
		id:          mcpconfig.ClientCursor,
		displayName: "Cursor",
		cfgPath:     cfgFile,
		detected:    true,
	}

	var out bytes.Buffer
	code := executeAdoptWithAdapters(adoptOptions{
		rollback:  true,
		backupDir: backupDir,
	}, strings.NewReader(""), &out, []mcpconfig.ClientAdapter{mockAdapter})

	if code != 0 {
		t.Fatalf("expected code 0, got %d, out:\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "Restored Cursor configuration from backup") {
		t.Errorf("expected restore message, got:\n%s", out.String())
	}

	restoredContent, err := os.ReadFile(cfgFile)
	if err != nil {
		t.Fatalf("read restored cfg: %v", err)
	}
	if string(restoredContent) != originalJSON {
		t.Errorf("expected restored content %q, got %q", originalJSON, string(restoredContent))
	}
}

func TestExecuteAdopt_RollbackNoBackups(t *testing.T) {
	tmpDir := t.TempDir()
	backupDir := filepath.Join(tmpDir, "backups")

	mockAdapter := &mockClientAdapter{
		id:          mcpconfig.ClientWindsurf,
		displayName: "Windsurf",
		detected:    true,
	}

	var out bytes.Buffer
	code := executeAdoptWithAdapters(adoptOptions{
		rollback:  true,
		backupDir: backupDir,
	}, strings.NewReader(""), &out, []mcpconfig.ClientAdapter{mockAdapter})

	if code != 0 {
		t.Fatalf("expected code 0, got %d", code)
	}
	if !strings.Contains(out.String(), "No active client backups found to restore.") {
		t.Errorf("expected no backups message, got:\n%s", out.String())
	}
}

func TestExecuteAdopt_FailClosedOnInteractiveEOF(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("USERPROFILE", tmpDir)
	cfgFile := filepath.Join(tmpDir, "cursor.json")
	_ = os.WriteFile(cfgFile, []byte(`{"mcpServers":{}}`), 0600)

	mockAdapter := &mockClientAdapter{
		id:          mcpconfig.ClientCursor,
		displayName: "Cursor",
		cfgPath:     cfgFile,
		detected:    true,
		servers: []mcpconfig.DiscoveredServer{
			{
				ClientID:   mcpconfig.ClientCursor,
				ClientName: "Cursor",
				Name:       "test-server",
				Command:    "echo",
			},
		},
	}

	var out bytes.Buffer
	code := executeAdoptWithAdapters(adoptOptions{
		yes:          false,
		backupDir:    filepath.Join(tmpDir, "backups"),
		protocolsDir: filepath.Join(tmpDir, "protocols"),
		agentsDir:    filepath.Join(tmpDir, "agents"),
	}, strings.NewReader(""), &out, []mcpconfig.ClientAdapter{mockAdapter})

	if code != 1 {
		t.Fatalf("expected exit code 1 on empty stdin EOF without --yes, got %d; out:\n%s", code, out.String())
	}
	if mockAdapter.applyCalled {
		t.Fatalf("expected ApplyGatewayConfig NOT to be called on EOF")
	}
}

func TestExecuteAdopt_RemoteURLValidationAndExplicitConfirm(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("USERPROFILE", tmpDir)
	cfgFile := filepath.Join(tmpDir, "cursor.json")
	_ = os.WriteFile(cfgFile, []byte(`{"mcpServers":{}}`), 0600)

	// 1. Metadata IP SSRF URL must be blocked fail-closed
	ssrfAdapter := &mockClientAdapter{
		id:          mcpconfig.ClientCursor,
		displayName: "Cursor",
		cfgPath:     cfgFile,
		detected:    true,
		servers: []mcpconfig.DiscoveredServer{
			{
				ClientID:   mcpconfig.ClientCursor,
				ClientName: "Cursor",
				Name:       "evil-imds",
				URL:        "http://169.254.169.254/latest/meta-data",
			},
		},
	}
	var outSSRF bytes.Buffer
	codeSSRF := executeAdoptWithAdapters(adoptOptions{
		yes:          true,
		backupDir:    filepath.Join(tmpDir, "backups"),
		protocolsDir: filepath.Join(tmpDir, "protocols"),
		agentsDir:    filepath.Join(tmpDir, "agents"),
	}, strings.NewReader(""), &outSSRF, []mcpconfig.ClientAdapter{ssrfAdapter})
	if codeSSRF != 1 {
		t.Fatalf("expected exit code 1 for unsafe remote SSRF URL, got %d; out:\n%s", codeSSRF, outSSRF.String())
	}
	if ssrfAdapter.applyCalled {
		t.Fatalf("expected ApplyGatewayConfig NOT to be called when SSRF URL rejected")
	}

	// 2. Public HTTPS remote URL requires explicit 'y' (empty newline cancels [y/N])
	remoteAdapter := &mockClientAdapter{
		id:          mcpconfig.ClientCursor,
		displayName: "Cursor",
		cfgPath:     cfgFile,
		detected:    true,
		servers: []mcpconfig.DiscoveredServer{
			{
				ClientID:   mcpconfig.ClientCursor,
				ClientName: "Cursor",
				Name:       "remote-mcp",
				URL:        "https://mcp.example.com/sse",
			},
		},
	}
	var outEmptyEnter bytes.Buffer
	codeEnter := executeAdoptWithAdapters(adoptOptions{
		yes:          false,
		backupDir:    filepath.Join(tmpDir, "backups"),
		protocolsDir: filepath.Join(tmpDir, "protocols"),
		agentsDir:    filepath.Join(tmpDir, "agents"),
	}, strings.NewReader("\n"), &outEmptyEnter, []mcpconfig.ClientAdapter{remoteAdapter})
	if codeEnter != 0 {
		t.Fatalf("expected exit code 0 when user declines remote URL confirmation, got %d", codeEnter)
	}
	if remoteAdapter.applyCalled {
		t.Fatalf("expected empty Enter NOT to confirm remote URL adoption")
	}
}

func TestExecuteAdopt_ServersFilterAndProbeTimeoutFromDuckDB(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("USERPROFILE", tmpDir)
	dbPath := filepath.Join(tmpDir, "data", "wire.duckdb")
	mgr, err := duckdb.NewManager(duckdb.Config{DBPath: dbPath})
	if err != nil {
		t.Fatalf("open duckdb: %v", err)
	}
	sStore := settings.NewDuckDBStore(mgr.DB())
	ctx := context.Background()
	if err := sStore.Migrate(ctx); err != nil {
		_ = mgr.Close()
		t.Fatalf("migrate settings: %v", err)
	}
	if err := sStore.Set(ctx, "timeouts.probe_timeout_sec", "17"); err != nil {
		_ = mgr.Close()
		t.Fatalf("set probe timeout: %v", err)
	}
	_ = mgr.Close()

	// Offline DuckDB resolution
	if got := resolveAdoptProbeTimeout(0, nil, dbPath); got != 17*time.Second {
		t.Fatalf("expected 17s from DuckDB system_settings, got %v", got)
	}
	// Explicit override takes precedence
	if got := resolveAdoptProbeTimeout(9*time.Second, nil, dbPath); got != 9*time.Second {
		t.Fatalf("expected 9s explicit override, got %v", got)
	}

	// --servers filter selects only requested server
	cfgFile := filepath.Join(tmpDir, "cursor.json")
	_ = os.WriteFile(cfgFile, []byte(`{"mcpServers":{}}`), 0600)
	mockAdapter := &mockClientAdapter{
		id:          mcpconfig.ClientCursor,
		displayName: "Cursor",
		cfgPath:     cfgFile,
		detected:    true,
		servers: []mcpconfig.DiscoveredServer{
			{ClientID: mcpconfig.ClientCursor, ClientName: "Cursor", Name: "alpha", Command: "echo"},
			{ClientID: mcpconfig.ClientCursor, ClientName: "Cursor", Name: "beta", Command: "echo"},
		},
	}
	protocolsDir := filepath.Join(tmpDir, "protocols")
	agentsDir := filepath.Join(tmpDir, "agents")
	var out bytes.Buffer
	code := executeAdoptWithAdapters(adoptOptions{
		yes:          true,
		servers:      "alpha",
		backupDir:    filepath.Join(tmpDir, "backups"),
		protocolsDir: protocolsDir,
		agentsDir:    agentsDir,
	}, strings.NewReader(""), &out, []mcpconfig.ClientAdapter{mockAdapter})
	if code != 0 {
		t.Fatalf("expected code 0 with --servers filter, got %d; out:\n%s", code, out.String())
	}
	alphaMatches, _ := filepath.Glob(filepath.Join(protocolsDir, "cursor_alpha_*.json"))
	betaMatches, _ := filepath.Glob(filepath.Join(protocolsDir, "cursor_beta_*.json"))
	if len(alphaMatches) != 1 || len(betaMatches) != 0 {
		t.Fatalf("expected only alpha adopted, got alpha=%v beta=%v", alphaMatches, betaMatches)
	}
}

func TestExecuteAdopt_FailurePropagatesNonZeroExitCode(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("USERPROFILE", tmpDir)
	cfgFile := filepath.Join(tmpDir, "cursor.json")
	_ = os.WriteFile(cfgFile, []byte(`{"mcpServers":{}}`), 0600)

	mockAdapter := &mockClientAdapter{
		id:          mcpconfig.ClientCursor,
		displayName: "Cursor",
		cfgPath:     cfgFile,
		detected:    true,
		servers: []mcpconfig.DiscoveredServer{
			{ClientID: mcpconfig.ClientCursor, ClientName: "Cursor", Name: "test-server", Command: "echo"},
		},
		applyErr: errors.New("disk full"),
	}

	var out bytes.Buffer
	code := executeAdoptWithAdapters(adoptOptions{
		yes:          true,
		backupDir:    filepath.Join(tmpDir, "backups"),
		protocolsDir: filepath.Join(tmpDir, "protocols"),
		agentsDir:    filepath.Join(tmpDir, "agents"),
	}, strings.NewReader(""), &out, []mcpconfig.ClientAdapter{mockAdapter})

	if code != 1 {
		t.Fatalf("expected non-zero exit code when ApplyGatewayConfig fails, got %d", code)
	}
}

func TestExecuteAdopt_ExplicitMissingConfigReturnsError(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("USERPROFILE", tmpDir)

	var out bytes.Buffer
	code := executeAdoptWithAdapters(adoptOptions{
		configPath:   filepath.Join(tmpDir, "missing-config.yaml"),
		yes:          true,
		backupDir:    filepath.Join(tmpDir, "backups"),
		protocolsDir: filepath.Join(tmpDir, "protocols"),
		agentsDir:    filepath.Join(tmpDir, "agents"),
	}, strings.NewReader(""), &out, nil)

	if code != 1 {
		t.Fatalf("expected exit code 1 when explicit -config is missing, got %d (out=%s)", code, out.String())
	}
	if !strings.Contains(out.String(), "Failed to load config file") {
		t.Fatalf("expected explicit config load failure message, got:\n%s", out.String())
	}
}

func TestExecuteAdopt_RollbackIncludesCursorWorkspaceWithoutWarning(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	t.Setenv("USERPROFILE", tmpHome)

	workDir := t.TempDir()
	wsDir := filepath.Join(workDir, ".cursor")
	if err := os.MkdirAll(wsDir, 0700); err != nil {
		t.Fatalf("mkdir .cursor: %v", err)
	}
	wsCfg := filepath.Join(wsDir, "mcp.json")
	origWS := `{"mcpServers":{"repo":{"command":"echo"}}}`
	if err := os.WriteFile(wsCfg, []byte(origWS), 0600); err != nil {
		t.Fatalf("write wsCfg: %v", err)
	}

	origWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(workDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(origWD) })

	backupDir := filepath.Join(tmpHome, "backups")
	bm, err := mcpconfig.NewBackupManager(backupDir)
	if err != nil {
		t.Fatalf("NewBackupManager: %v", err)
	}
	if _, err := bm.CreateBackup(mcpconfig.ClientCursorWorkspace, wsCfg); err != nil {
		t.Fatalf("CreateBackup: %v", err)
	}
	if err := os.WriteFile(wsCfg, []byte(`{"mcpServers":{"faradaiwire":{"url":"http://127.0.0.1:8090/sse"}}}`), 0600); err != nil {
		t.Fatalf("mutate wsCfg: %v", err)
	}

	var out bytes.Buffer
	code := executeAdopt(adoptOptions{
		rollback:     true,
		backupDir:    backupDir,
		protocolsDir: filepath.Join(tmpHome, "protocols"),
		agentsDir:    filepath.Join(tmpHome, "agents"),
	}, strings.NewReader(""), &out)

	if code != 0 {
		t.Fatalf("expected rollback exit code 0, got %d; out:\n%s", code, out.String())
	}
	if strings.Contains(out.String(), "--workspace enabled") {
		t.Fatalf("expected rollback not to emit --workspace adoption warning, got:\n%s", out.String())
	}
	restored, _ := os.ReadFile(wsCfg)
	if string(restored) != origWS {
		t.Fatalf("expected workspace config restored to %s, got %s", origWS, restored)
	}
}

func TestResolveAdoptProbeTimeout_ReadsChunkedSettingsResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/settings" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"settings":[`))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		time.Sleep(25 * time.Millisecond)
		_, _ = w.Write([]byte(`{"key":"timeouts.probe_timeout_sec","value":12}]}`))
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("atoi port: %v", err)
	}

	cfg := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
		ListenHost:  host,
		AdminPort:   port,
	}
	if got := resolveAdoptProbeTimeout(0, cfg, ""); got != 12*time.Second {
		t.Fatalf("expected 12s from chunked /admin/settings response, got %v", got)
	}
}

func TestResolveAdminEndpointHost_UsesAdminHost(t *testing.T) {
	t.Setenv("FARADAI_WIRE_ADMIN_HOST", "")

	tests := []struct {
		name string
		cfg  *config.Config
		want string
	}{
		{
			name: "nil config defaults to loopback",
			cfg:  nil,
			want: "127.0.0.1",
		},
		{
			name: "standalone ignores public listen host and uses admin host",
			cfg: &config.Config{
				RuntimeMode: config.RuntimeModeStandalone,
				ListenHost:  "0.0.0.0",
				AdminHost:   "127.0.0.2",
			},
			want: "127.0.0.2",
		},
		{
			name: "standalone forces non-loopback admin host back to loopback",
			cfg: &config.Config{
				RuntimeMode: config.RuntimeModeStandalone,
				ListenHost:  "127.0.0.1",
				AdminHost:   "192.168.1.50",
			},
			want: "127.0.0.1",
		},
		{
			name: "managed mode uses configured admin host",
			cfg: &config.Config{
				RuntimeMode: config.RuntimeModeManaged,
				ListenHost:  "0.0.0.0",
				AdminHost:   "10.0.0.5",
			},
			want: "10.0.0.5",
		},
		{
			name: "wildcard admin host normalizes to loopback",
			cfg: &config.Config{
				RuntimeMode: config.RuntimeModeManaged,
				ListenHost:  "10.0.0.9",
				AdminHost:   "0.0.0.0",
			},
			want: "127.0.0.1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveAdminEndpointHost(tc.cfg); got != tc.want {
				t.Fatalf("resolveAdminEndpointHost() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAttachAdminBearerAuth(t *testing.T) {
	tests := []struct {
		name        string
		adminAPIKey string
		adminToken  string
		rawURL      string
		wantHeader  string
	}{
		{
			name:       "fallback token attached on loopback HTTP",
			adminToken: "fallback-token",
			rawURL:     "http://127.0.0.1:8095/admin/settings",
			wantHeader: "Bearer fallback-token",
		},
		{
			name:        "refuses cleartext token over remote HTTP even if token set",
			adminAPIKey: "primary-key",
			rawURL:      "http://10.0.0.5:8095/admin/settings",
			wantHeader:  "",
		},
		{
			name:        "allows token over remote HTTPS and prefers ADMIN_API_KEY",
			adminAPIKey: "primary-key",
			adminToken:  "fallback-token",
			rawURL:      "https://10.0.0.5:8095/admin/settings",
			wantHeader:  "Bearer primary-key",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("ADMIN_API_KEY", tc.adminAPIKey)
			t.Setenv("FARADAI_WIRE_ADMIN_TOKEN", tc.adminToken)

			req := httptest.NewRequest(http.MethodGet, tc.rawURL, nil)
			attachAdminBearerAuth(req)
			if got := req.Header.Get("Authorization"); got != tc.wantHeader {
				t.Fatalf("Authorization = %q, want %q", got, tc.wantHeader)
			}
		})
	}
}
