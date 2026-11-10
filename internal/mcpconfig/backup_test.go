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

	// Verify protocol file exists (collision-safe prefix)
	expectedProtoID := sanitizeIdentifier("claude-desktop", "filesystem")
	expectedProto := filepath.Join(protoDir, expectedProtoID+".json")
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
	secondProtoID := sanitizeIdentifier("claude-desktop", "github.com/upstash/context7-mcp")
	if !strings.Contains(string(data), expectedProtoID) || !strings.Contains(string(data), secondProtoID) {
		t.Errorf("expected both protocols merged in config.json, got:\n%s", string(data))
	}
}

func TestSanitizeIdentifier(t *testing.T) {
	tests := []struct {
		profile string
		name    string
		prefix  string
	}{
		{
			profile: "cline",
			name:    "github.com/upstash/context7-mcp",
			prefix:  "cline_github_com_upstash_context7_mcp_",
		},
		{
			profile: "cursor",
			name:    "../../../../etc/passwd",
			prefix:  "cursor_etc_passwd_",
		},
		{
			profile: "antigravity",
			name:    "@modelcontextprotocol/server-postgres",
			prefix:  "antigravity_modelcontextprotocol_server_postgres_",
		},
	}

	for _, tc := range tests {
		got := sanitizeIdentifier(tc.profile, tc.name)
		if !strings.HasPrefix(got, tc.prefix) {
			t.Errorf("sanitizeIdentifier(%q, %q) = %q; want prefix %q", tc.profile, tc.name, got, tc.prefix)
		}
		if sanitizeIdentifier(tc.profile, tc.name) != got {
			t.Errorf("sanitizeIdentifier must be deterministic for (%q, %q)", tc.profile, tc.name)
		}
	}

	if sanitizeIdentifier("prof", "my-app") == sanitizeIdentifier("prof", "my_app") {
		t.Fatal("expected distinct identifiers for punctuation variants")
	}
	if sanitizeIdentifier("a_b", "c") == sanitizeIdentifier("a", "b_c") {
		t.Fatal("expected distinct identifiers for profile/name boundary split")
	}
}

func TestBackupManager_IsolationZeroByteAndLegacyFallback(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	bm, err := NewBackupManager(filepath.Join(tmp, "backups"))
	if err != nil {
		t.Fatalf("NewBackupManager: %v", err)
	}

	// 1. Two distinct config paths for ClientCursor must stay isolated
	globalCfg := filepath.Join(tmp, "global", "mcp.json")
	wsCfg := filepath.Join(tmp, "repo", ".cursor", "mcp.json")
	_ = os.MkdirAll(filepath.Dir(globalCfg), 0700)
	_ = os.MkdirAll(filepath.Dir(wsCfg), 0700)
	_ = os.WriteFile(globalCfg, []byte(`{"mcpServers":{"g":{}}}`), 0600)
	_ = os.WriteFile(wsCfg, []byte(`{"mcpServers":{"w":{}}}`), 0600)

	b1, err := bm.CreateBackup(ClientCursor, globalCfg)
	if err != nil {
		t.Fatalf("backup global: %v", err)
	}
	b2, err := bm.CreateBackup(ClientCursor, wsCfg)
	if err != nil {
		t.Fatalf("backup ws: %v", err)
	}
	if b1 == b2 {
		t.Fatalf("expected isolated backup paths for distinct config locations, got same %s", b1)
	}
	_ = os.WriteFile(globalCfg, []byte(`{}`), 0600)
	_ = os.WriteFile(wsCfg, []byte(`{}`), 0600)

	if err := bm.RestoreBackup(ClientCursor, globalCfg); err != nil {
		t.Fatalf("restore global: %v", err)
	}
	if err := bm.RestoreBackup(ClientCursor, wsCfg); err != nil {
		t.Fatalf("restore ws: %v", err)
	}
	if g, _ := os.ReadFile(globalCfg); !strings.Contains(string(g), `"g"`) {
		t.Fatalf("global config restored wrong content: %s", g)
	}
	if w, _ := os.ReadFile(wsCfg); !strings.Contains(string(w), `"w"`) {
		t.Fatalf("workspace config restored wrong content: %s", w)
	}

	// 2. 0-byte original file backup is valid and HasBackup/HasBackupForConfig return true
	emptyCfg := filepath.Join(tmp, "empty.json")
	_ = os.WriteFile(emptyCfg, []byte{}, 0600)
	if _, err := bm.CreateBackup(ClientWindsurf, emptyCfg); err != nil {
		t.Fatalf("backup empty file: %v", err)
	}
	if !bm.HasBackupForConfig(ClientWindsurf, emptyCfg) || !bm.HasBackup(ClientWindsurf) {
		t.Fatal("expected HasBackup and HasBackupForConfig to be true for 0-byte backup")
	}

	// 3. Legacy single-filename backup fallback works for RestoreBackup & HasBackupForConfig
	legacyTarget := filepath.Join(tmp, "cline.json")
	_ = os.WriteFile(legacyTarget, []byte(`{"mutated":true}`), 0600)
	_ = os.WriteFile(bm.BackupPath(ClientCline), []byte(`{"legacy_orig":true}`), 0600)
	if !bm.HasBackupForConfig(ClientCline, legacyTarget) {
		t.Fatal("expected legacy fallback to report HasBackupForConfig=true")
	}
	if err := bm.RestoreBackup(ClientCline, legacyTarget); err != nil {
		t.Fatalf("RestoreBackup legacy fallback failed: %v", err)
	}
	restoredLegacy, _ := os.ReadFile(legacyTarget)
	if string(restoredLegacy) != `{"legacy_orig":true}` {
		t.Fatalf("unexpected legacy restored content: %s", restoredLegacy)
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

func TestBackupManager_CursorWorkspaceDoesNotFallbackToLegacyGlobalBackup(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	bm, err := NewBackupManager(filepath.Join(tmp, "backups"))
	if err != nil {
		t.Fatalf("NewBackupManager: %v", err)
	}

	// Legacy global cursor backup exists
	if err := os.WriteFile(bm.BackupPath(ClientCursor), []byte(`{"global_legacy":true}`), 0600); err != nil {
		t.Fatalf("write legacy backup: %v", err)
	}

	wsDir := filepath.Join(tmp, ".cursor")
	if err := os.MkdirAll(wsDir, 0700); err != nil {
		t.Fatalf("mkdir .cursor: %v", err)
	}
	wsCfg := filepath.Join(wsDir, "mcp.json")
	if err := os.WriteFile(wsCfg, []byte(`{"workspace_current":true}`), 0600); err != nil {
		t.Fatalf("write workspace cfg: %v", err)
	}

	if bm.HasBackupForConfig(ClientCursorWorkspace, wsCfg) {
		t.Fatal("expected ClientCursorWorkspace not to match legacy global ClientCursor backup")
	}
	if err := bm.RestoreBackup(ClientCursorWorkspace, wsCfg); err == nil {
		t.Fatal("expected RestoreBackup for ClientCursorWorkspace without workspace backup to fail")
	}
	got, _ := os.ReadFile(wsCfg)
	if string(got) != `{"workspace_current":true}` {
		t.Fatalf("workspace config must remain intact, got %s", got)
	}
}
