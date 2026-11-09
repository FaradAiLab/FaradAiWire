package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FaradAiLab/FaradAiWire/internal/mcpconfig"
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

	// Verify backup was created
	bm, err := mcpconfig.NewBackupManager(backupDir)
	if err != nil {
		t.Fatalf("new backup manager: %v", err)
	}
	if !bm.HasBackup(mcpconfig.ClientCursor) {
		t.Errorf("expected backup file to exist for cursor")
	}

	// Verify protocol file was written
	protoFile := filepath.Join(protocolsDir, "cursor_test_server.json")
	if _, err := os.Stat(protoFile); os.IsNotExist(err) {
		t.Errorf("expected protocol file %s to exist", protoFile)
	}

	// Verify agent config file was written
	agentConfigFile := filepath.Join(agentsDir, "cursor", "current", "config.json")
	if _, err := os.Stat(agentConfigFile); os.IsNotExist(err) {
		t.Errorf("expected agent config %s to exist", agentConfigFile)
	}
}

func TestExecuteAdopt_Rollback(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "cursor.json")
	mutatedJSON := `{"mcpServers":{"farad-ai-wire":{"command":"faradaiwire","args":["connect"]}}}`
	if err := os.WriteFile(cfgFile, []byte(mutatedJSON), 0600); err != nil {
		t.Fatalf("write mutated cfg: %v", err)
	}

	backupDir := filepath.Join(tmpDir, "backups")
	bm, err := mcpconfig.NewBackupManager(backupDir)
	if err != nil {
		t.Fatalf("new backup manager: %v", err)
	}

	// Save original backup
	originalJSON := `{"mcpServers":{"test-server":{"command":"echo"}}}`
	origFile := filepath.Join(tmpDir, "orig.json")
	_ = os.WriteFile(origFile, []byte(originalJSON), 0600)
	if _, err := bm.CreateBackup(mcpconfig.ClientCursor, origFile); err != nil {
		t.Fatalf("create backup: %v", err)
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
