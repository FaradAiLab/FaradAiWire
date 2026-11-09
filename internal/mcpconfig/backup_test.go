package mcpconfig

import (
	"os"
	"path/filepath"
	"strings"
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

	// Verify agent config exists and has 0600 permissions
	expectedAgentCfg := filepath.Join(agentsDir, "claude-desktop", "current", "config.json")
	if fi, err := os.Stat(expectedAgentCfg); err != nil || fi.Size() == 0 {
		t.Fatalf("agent config file %s was not written properly: %v", expectedAgentCfg, err)
	} else if fi.Mode().Perm() != 0600 {
		t.Errorf("expected agent config to have 0600 permissions, got %v", fi.Mode().Perm())
	}

	// 2nd run: Adopt a second server and ensure protocols are merged, not overwritten
	secondServer := []DiscoveredServer{
		{
			Name:       "github.com/upstash/context7-mcp",
			Command:    "npx",
			Args:       []string{"-y", "@upstash/context7-mcp"},
			ClientName: "Claude Desktop",
		},
	}
	if err := PersistAdoptedProtocols("claude-desktop", secondServer, nil, protoDir, agentsDir); err != nil {
		t.Fatalf("second PersistAdoptedProtocols failed: %v", err)
	}

	// Verify both protocols exist in config.json
	data, _ := os.ReadFile(expectedAgentCfg)
	if !strings.Contains(string(data), "claude_desktop_filesystem") || !strings.Contains(string(data), "claude_desktop_github_com_upstash_context7_mcp") {
		t.Errorf("expected both protocols merged in config.json, got:\n%s", string(data))
	}
}

func TestSanitizeIdentifier(t *testing.T) {
	tests := []struct {
		profile  string
		name     string
		expected string
	}{
		{
			profile:  "cline",
			name:     "github.com/upstash/context7-mcp",
			expected: "cline_github_com_upstash_context7_mcp",
		},
		{
			profile:  "cursor",
			name:     "../../../../etc/passwd",
			expected: "cursor_etc_passwd",
		},
		{
			profile:  "antigravity",
			name:     "@modelcontextprotocol/server-postgres",
			expected: "antigravity_modelcontextprotocol_server_postgres",
		},
	}

	for _, tc := range tests {
		got := sanitizeIdentifier(tc.profile, tc.name)
		if got != tc.expected {
			t.Errorf("sanitizeIdentifier(%q, %q) = %q; want %q", tc.profile, tc.name, got, tc.expected)
		}
	}
}

func TestBackupManager_PreservesPristineBackup(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	backupDir := filepath.Join(tempDir, "backups")
	bm, _ := NewBackupManager(backupDir)

	cfgPath := filepath.Join(tempDir, "orig.json")
	origContent := `{"original": true}`
	_ = os.WriteFile(cfgPath, []byte(origContent), 0600)

	// First backup
	dest1, err := bm.CreateBackup(ClientCursor, cfgPath)
	if err != nil {
		t.Fatalf("first CreateBackup failed: %v", err)
	}

	// Mutate the original config file
	mutatedContent := `{"mutated_by_faw": true}`
	_ = os.WriteFile(cfgPath, []byte(mutatedContent), 0600)

	// Second backup attempt should NOT overwrite the pristine backup
	dest2, err := bm.CreateBackup(ClientCursor, cfgPath)
	if err != nil {
		t.Fatalf("second CreateBackup failed: %v", err)
	}
	if dest1 != dest2 {
		t.Errorf("expected backup paths to match: %s vs %s", dest1, dest2)
	}

	// Backup file content must still be the original content
	backupData, _ := os.ReadFile(dest1)
	if string(backupData) != origContent {
		t.Errorf("pristine backup was overwritten! got %s, want %s", string(backupData), origContent)
	}
}
