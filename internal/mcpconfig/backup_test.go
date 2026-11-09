package mcpconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBackupManager(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	backupDir := filepath.Join(tempDir, "backups")
	bm, err := NewBackupManager(backupDir)
	if err != nil {
		t.Fatalf("failed to create BackupManager: %v", err)
	}

	configFile := filepath.Join(tempDir, "claude_config.json")
	initialContent := `{"mcpServers": {"test": {"command": "echo"}}}`
	if err := os.WriteFile(configFile, []byte(initialContent), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	if bm.HasBackup(ClientClaudeDesktop) {
		t.Errorf("expected HasBackup=false initially")
	}

	backupPath, err := bm.CreateBackup(ClientClaudeDesktop, configFile)
	if err != nil {
		t.Fatalf("CreateBackup failed: %v", err)
	}

	if !bm.HasBackup(ClientClaudeDesktop) {
		t.Errorf("expected HasBackup=true after backup")
	}

	// Verify 0600 permissions
	fi, err := os.Stat(backupPath)
	if err != nil {
		t.Fatalf("stat backup file: %v", err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Errorf("expected 0600 permissions, got %v", fi.Mode().Perm())
	}

	// Mutate config
	mutatedContent := `{"mcpServers": {"farad-ai-wire": {"command": "faradaiwire"}}}`
	if err := os.WriteFile(configFile, []byte(mutatedContent), 0644); err != nil {
		t.Fatalf("failed to write mutated config: %v", err)
	}

	// Restore backup
	if err := bm.RestoreBackup(ClientClaudeDesktop, configFile); err != nil {
		t.Fatalf("RestoreBackup failed: %v", err)
	}

	restoredData, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatalf("read restored file: %v", err)
	}

	if string(restoredData) != initialContent {
		t.Errorf("restored content does not match initial content")
	}
}

func TestPersistAdoptedProtocols(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	protoDir := filepath.Join(tempDir, "protocols")
	agentsDir := filepath.Join(tempDir, "agents")

	servers := []DiscoveredServer{
		{
			Name:       "filesystem",
			Command:    "npx",
			Args:       []string{"-y", "@modelcontextprotocol/server-filesystem"},
			Env:        map[string]string{"DEBUG": "1"},
			ClientName: "Claude Desktop",
		},
	}

	err := PersistAdoptedProtocols("claude-desktop", servers, nil, protoDir, agentsDir)
	if err != nil {
		t.Fatalf("PersistAdoptedProtocols failed: %v", err)
	}

	// Verify protocol file exists
	expectedProto := filepath.Join(protoDir, "claude_desktop_filesystem.json")
	if fi, err := os.Stat(expectedProto); err != nil || fi.Size() == 0 {
		t.Fatalf("protocol file %s was not written properly: %v", expectedProto, err)
	}

	// Verify agent config exists
	expectedAgentCfg := filepath.Join(agentsDir, "claude-desktop", "current", "config.json")
	if fi, err := os.Stat(expectedAgentCfg); err != nil || fi.Size() == 0 {
		t.Fatalf("agent config file %s was not written properly: %v", expectedAgentCfg, err)
	}
}
