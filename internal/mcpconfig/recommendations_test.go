package mcpconfig

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/marcboeker/go-duckdb"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/schema"
	"github.com/FaradAiLab/FaradAiWire/internal/protocol"
)

func TestMatchPreset_TokenAndURLBoundaries(t *testing.T) {
	t.Parallel()

	presets := protocol.GetPresets()

	// Must NOT false-match "git" inside "digital"
	resDigital := MatchPreset(DiscoveredServer{
		Name:    "my-digital-tool",
		Command: "node",
		Args:    []string{"server.js"},
	}, presets)
	if !resDigital.IsCustom || resDigital.Preset != nil {
		t.Fatalf("expected my-digital-tool to be custom (not false-match git), got %+v", resDigital.Preset)
	}

	// Must NOT false-match spoofing hostnames or query params
	resSpoofURL := MatchPreset(DiscoveredServer{
		Name: "custom-remote",
		URL:  "https://context7.com.attacker.example/mcp?ref=github.com",
	}, presets)
	if !resSpoofURL.IsCustom || resSpoofURL.Preset != nil {
		t.Fatalf("expected spoofed URL not to match preset, got %+v", resSpoofURL.Preset)
	}
}

func TestStripCommentsAndTrailingCommas_UTF8BOM(t *testing.T) {
	t.Parallel()

	input := append([]byte{0xEF, 0xBB, 0xBF}, []byte("// comment\n{\"a\": 1,}\n")...)
	cleaned, err := StripCommentsAndTrailingCommas(input)
	if err != nil {
		t.Fatalf("StripCommentsAndTrailingCommas failed on BOM input: %v", err)
	}
	var out map[string]int
	if err := json.Unmarshal(cleaned, &out); err != nil {
		t.Fatalf("failed to unmarshal BOM-stripped JSONC: %v (cleaned=%q)", err, cleaned)
	}
	if out["a"] != 1 {
		t.Fatalf("expected a=1, got %v", out["a"])
	}
}

func TestExpandPath_PercentVarsAndTilde(t *testing.T) {
	t.Setenv("FAW_TEST_APPDATA", "/custom/appdata")

	if got := expandPath("%FAW_TEST_APPDATA%/Claude"); !strings.Contains(got, filepath.Join("custom", "appdata", "Claude")) {
		t.Fatalf("expected %%FAW_TEST_APPDATA%% to expand, got %q", got)
	}

	home, err := os.UserHomeDir()
	if err == nil {
		if got := expandPath("~/sub/file.json"); got != filepath.Join(home, "sub", "file.json") {
			t.Fatalf("expected ~/ expansion to %q, got %q", filepath.Join(home, "sub", "file.json"), got)
		}
		if got := expandPath("~otheruser/sub"); strings.HasPrefix(got, home) {
			t.Fatalf("did not expect ~otheruser to expand to current user's home: %q", got)
		}
	}
}

func TestCursorAdapter_GlobalVsWorkspaceIsolation(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	t.Setenv("USERPROFILE", tmpHome)

	workDir := t.TempDir()
	wsConfig := filepath.Join(workDir, ".cursor", "mcp.json")
	if err := os.MkdirAll(filepath.Dir(wsConfig), 0700); err != nil {
		t.Fatalf("mkdir ws .cursor: %v", err)
	}
	if err := os.WriteFile(wsConfig, []byte(`{"mcpServers":{"repo-tool":{"command":"sh"}}}`), 0600); err != nil {
		t.Fatalf("write ws mcp.json: %v", err)
	}

	origWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(workDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(origWD) })

	// Default NewCursorAdapter MUST NOT read ./.cursor/mcp.json implicitly
	globalAdapter := NewCursorAdapter()
	globalPath, err := globalAdapter.ConfigPath()
	if err != nil {
		t.Fatalf("global ConfigPath: %v", err)
	}
	if globalPath == wsConfig || globalAdapter.Detect() {
		t.Fatalf("default CursorAdapter must ignore workspace %q, resolved %q (Detect=%v)", wsConfig, globalPath, globalAdapter.Detect())
	}

	// Explicit NewCursorWorkspaceAdapter MUST find ./.cursor/mcp.json
	wsAdapter := NewCursorWorkspaceAdapter(workDir)
	if !wsAdapter.Detect() {
		t.Fatal("expected NewCursorWorkspaceAdapter to detect workspace .cursor/mcp.json")
	}
	servers, err := wsAdapter.ReadServers()
	if err != nil || len(servers) != 1 || servers[0].Name != "repo-tool" {
		t.Fatalf("expected repo-tool from workspace adapter, got servers=%+v err=%v", servers, err)
	}
}

func TestPersistMatchRecommendations_And_SeedDiscoveredSchemas(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	protoDir := filepath.Join(tmpDir, "protocols")
	agentsDir := filepath.Join(tmpDir, "agents")
	cfgYAML := filepath.Join(tmpDir, "config.yaml")
	originalYAML := "# Preserved user comment\nruntime_mode: STANDALONE\nfilters:\n  hitl:\n    enabled: true\n"
	if err := os.WriteFile(cfgYAML, []byte(originalYAML), 0640); err != nil {
		t.Fatalf("write config.yaml: %v", err)
	}

	servers := []DiscoveredServer{
		{
			Name:       "fs",
			Command:    "npx",
			Args:       []string{"-y", "@modelcontextprotocol/server-filesystem", "/workspace"},
			ClientName: "Claude Desktop",
		},
	}

	if err := PersistAdoptedProtocols("claude-desktop", servers, nil, protoDir, agentsDir); err != nil {
		t.Fatalf("PersistAdoptedProtocols: %v", err)
	}

	summary, err := PersistMatchRecommendations("claude-desktop", servers, agentsDir, cfgYAML)
	if err != nil {
		t.Fatalf("PersistMatchRecommendations: %v", err)
	}
	if summary.DLPPatternsAdded == 0 || summary.HITLGovernanceAdded == 0 {
		t.Fatalf("expected DLP and HITL rules added, got %+v", summary)
	}

	// Verify dlp.json persisted with 0600
	dlpPath := filepath.Join(agentsDir, "claude-desktop", "current", "dlp.json")
	dlpData, err := os.ReadFile(dlpPath)
	if err != nil || !strings.Contains(string(dlpData), "sensitive_files") {
		t.Fatalf("expected sensitive_files in dlp.json, got %q (err=%v)", dlpData, err)
	}

	// Verify ToolGovernance persisted in config.json
	agentCfgData, _ := os.ReadFile(filepath.Join(agentsDir, "claude-desktop", "current", "config.json"))
	var routeCfg agent.RouteConfig
	if err := json.Unmarshal(agentCfgData, &routeCfg); err != nil {
		t.Fatalf("unmarshal config.json: %v", err)
	}
	fsSlug := sanitizeIdentifier("claude-desktop", "fs")
	if mode := routeCfg.ToolGovernance[fsSlug+"__delete_file"]; mode != agent.ModeStrictAlwaysHITL {
		t.Fatalf("expected %s__delete_file ModeStrictAlwaysHITL, got %q", fsSlug, mode)
	}

	// Verify config.yaml remains untouched with user comments preserved per ADR-0053
	yamlBytes, _ := os.ReadFile(cfgYAML)
	if string(yamlBytes) != originalYAML {
		t.Fatalf("expected config.yaml to remain unmodified per ADR-0053, got:\n%s", yamlBytes)
	}

	// Verify DuckDB mcp_tool_schemas seeding
	db, err := sql.Open("duckdb", ":memory:")
	if err != nil {
		t.Fatalf("open duckdb: %v", err)
	}
	defer db.Close()
	store := schema.NewDuckDBSchemaStore(db)

	probeResults := []ProbeResult{
		{
			ServerName: "fs",
			Success:    true,
			ToolCount:  1,
			Tools: []map[string]interface{}{
				{
					"name": "delete_file",
					"inputSchema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"path": map[string]interface{}{"type": "string"},
						},
					},
				},
			},
		},
	}
	seeded, err := SeedDiscoveredSchemas(context.Background(), "claude-desktop", servers, probeResults, store)
	if err != nil || seeded != 1 {
		t.Fatalf("expected 1 seeded schema, got %d (err=%v)", seeded, err)
	}
	rec, err := store.GetSchema(context.Background(), fsSlug+"__delete_file")
	if err != nil || rec.ProtocolID != fsSlug || rec.SHA256Hash == "" {
		t.Fatalf("unexpected seeded DuckDB schema record: rec=%+v err=%v", rec, err)
	}
}

func TestPersistAdoptedProtocols_RejectsTraversalAndCorruptConfig(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	if err := PersistAdoptedProtocols("../escape", nil, nil, filepath.Join(tmpDir, "p"), filepath.Join(tmpDir, "a")); err == nil {
		t.Fatal("expected path traversal profileName to fail")
	}

	agentsDir := filepath.Join(tmpDir, "agents")
	corruptDir := filepath.Join(agentsDir, "valid-prof", "current")
	_ = os.MkdirAll(corruptDir, 0700)
	_ = os.WriteFile(filepath.Join(corruptDir, "config.json"), []byte("{not valid json"), 0600)

	err := PersistAdoptedProtocols("valid-prof", nil, nil, filepath.Join(tmpDir, "p"), agentsDir)
	if err == nil || !strings.Contains(err.Error(), "parse existing profile config") {
		t.Fatalf("expected explicit error on corrupt existing config.json, got %v", err)
	}
}

func TestPersistMatchRecommendations_PreservesDisabledDLP_AndPropagatesConfigReadError(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	protoDir := filepath.Join(tmpDir, "protocols")
	agentsDir := filepath.Join(tmpDir, "agents")
	cfgYAML := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(cfgYAML, []byte("runtime_mode: STANDALONE\n"), 0640); err != nil {
		t.Fatalf("write config.yaml: %v", err)
	}

	servers := []DiscoveredServer{
		{
			Name:       "fs",
			Command:    "npx",
			Args:       []string{"-y", "@modelcontextprotocol/server-filesystem", "/workspace"},
			ClientName: "Claude Desktop",
		},
	}
	if err := PersistAdoptedProtocols("claude-desktop", servers, nil, protoDir, agentsDir); err != nil {
		t.Fatalf("PersistAdoptedProtocols: %v", err)
	}

	// Pre-seed dlp.json with enabled: false (clean bypass)
	dlpPath := filepath.Join(agentsDir, "claude-desktop", "current", "dlp.json")
	if err := os.WriteFile(dlpPath, []byte("{\n  \"enabled\": false,\n  \"patterns\": []\n}\n"), 0600); err != nil {
		t.Fatalf("write disabled dlp.json: %v", err)
	}

	if _, err := PersistMatchRecommendations("claude-desktop", servers, agentsDir, cfgYAML); err != nil {
		t.Fatalf("PersistMatchRecommendations: %v", err)
	}

	raw, err := os.ReadFile(dlpPath)
	if err != nil {
		t.Fatalf("read dlp.json: %v", err)
	}
	var payload struct {
		Enabled  bool             `json:"enabled"`
		Patterns []map[string]any `json:"patterns"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("unmarshal dlp.json: %v", err)
	}
	if payload.Enabled {
		t.Fatalf("expected PersistMatchRecommendations to preserve enabled=false on existing dlp.json")
	}
	if len(payload.Patterns) == 0 {
		t.Fatalf("expected recommended DLP patterns to be merged even when enabled=false")
	}

	// Non-os.ErrNotExist error reading profile config.json (directory instead of file) must fail closed
	agentCfgPath := filepath.Join(agentsDir, "claude-desktop", "current", "config.json")
	if err := os.Remove(agentCfgPath); err != nil {
		t.Fatalf("remove agent config.json: %v", err)
	}
	if err := os.Mkdir(agentCfgPath, 0700); err != nil {
		t.Fatalf("mkdir blocking config.json: %v", err)
	}
	if _, err := PersistMatchRecommendations("claude-desktop", servers, agentsDir, cfgYAML); err == nil {
		t.Fatal("expected error when profile config.json cannot be read as a file (non-ErrNotExist)")
	}
}
