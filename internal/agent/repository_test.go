package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func setupTestAgentsDir(t *testing.T) string {
	tmpDir, err := os.MkdirTemp("", "farad-ai-agent-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	// 1. Aggregated agent with multiple protocols & manifest
	aggDir := filepath.Join(tmpDir, "agent-finance", "current")
	if err := os.MkdirAll(aggDir, 0755); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}

	aggConfigJSON := `{
		"agent_id": "finance-01",
		"agent_name": "agent-finance",
		"routing_mode": "aggregated",
		"protocols": [
			{
				"protocol_id": "db-proto",
				"protocol_name": "db",
				"type": "sse",
				"url_or_command": "http://localhost:9001/sse"
			},
			{
				"protocol_id": "api-proto",
				"protocol_name": "api",
				"type": "sse",
				"url_or_command": "http://localhost:9002/sse"
			}
		]
	}`
	if err := os.WriteFile(filepath.Join(aggDir, "config.json"), []byte(aggConfigJSON), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	aggManifestJSON := `[
		{
			"name": "query_transactions",
			"canonical_name": "db__query_transactions",
			"protocol_name": "db",
			"description": "Query financial transactions"
		},
		{
			"name": "call_payment_gateway",
			"canonical_name": "api__call_payment_gateway",
			"protocol_name": "api",
			"description": "Trigger external payment API"
		}
	]`
	if err := os.WriteFile(filepath.Join(aggDir, "tools_manifest.json"), []byte(aggManifestJSON), 0644); err != nil {
		t.Fatalf("failed to write manifest: %v", err)
	}

	// 2. Direct agent with alternate JSON tags (id/name)
	dirDir := filepath.Join(tmpDir, "agent-direct", "current")
	if err := os.MkdirAll(dirDir, 0755); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}
	dirConfigJSON := `{
		"agent_id": "direct-01",
		"name": "agent-direct",
		"routing_mode": "direct",
		"protocols": [
			{
				"id": "direct-mcp",
				"name": "primary",
				"url_or_command": "http://localhost:9003/sse"
			}
		]
	}`
	if err := os.WriteFile(filepath.Join(dirDir, "config.json"), []byte(dirConfigJSON), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	return tmpDir
}

func TestFSRepository_GetAgentConfig(t *testing.T) {
	tmpDir := setupTestAgentsDir(t)
	defer os.RemoveAll(tmpDir)

	repo := NewFSRepository(tmpDir)

	// 1. Valid aggregated agent
	cfg, err := repo.GetAgentConfig("agent-finance")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.AgentID != "finance-01" || cfg.AgentName != "agent-finance" {
		t.Errorf("unexpected agent data: %+v", cfg)
	}
	if !cfg.IsAggregated() {
		t.Errorf("expected aggregated mode")
	}
	if len(cfg.Protocols) != 2 {
		t.Errorf("expected 2 protocols, got %d", len(cfg.Protocols))
	}

	// 2. Valid direct agent with alternate tags
	dirCfg, err := repo.GetAgentConfig("agent-direct")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dirCfg.AgentName != "agent-direct" || !dirCfg.IsDirect() {
		t.Errorf("unexpected direct agent data: %+v", dirCfg)
	}
	if len(dirCfg.Protocols) != 1 || dirCfg.Protocols[0].ID != "direct-mcp" || dirCfg.Protocols[0].Name != "primary" {
		t.Errorf("unexpected protocol unmarshaling: %+v", dirCfg.Protocols)
	}

	// 3. Non-existent agent
	_, errNotFound := repo.GetAgentConfig("non-existent")
	if !errors.Is(errNotFound, ErrAgentNotFound) {
		t.Errorf("expected ErrAgentNotFound, got: %v", errNotFound)
	}

	// 4. Path traversal injection
	_, errTraversal := repo.GetAgentConfig("../secret-agent")
	if !errors.Is(errTraversal, ErrInvalidIdentifier) {
		t.Errorf("expected ErrInvalidIdentifier, got: %v", errTraversal)
	}
}

func TestFSRepository_GetAgentManifest(t *testing.T) {
	tmpDir := setupTestAgentsDir(t)
	defer os.RemoveAll(tmpDir)

	repo := NewFSRepository(tmpDir)

	// 1. Valid manifest
	manifest, err := repo.GetAgentManifest("agent-finance")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(manifest) != 2 {
		t.Errorf("expected 2 tools, got %d", len(manifest))
	}
	if manifest[0].Name != "query_transactions" || manifest[0].ProtocolName != "db" {
		t.Errorf("unexpected tool 0: %+v", manifest[0])
	}

	// 2. Agent without manifest
	_, errMissing := repo.GetAgentManifest("agent-direct")
	if !errors.Is(errMissing, ErrManifestNotFound) {
		t.Errorf("expected ErrManifestNotFound, got: %v", errMissing)
	}
}

func TestFSRepository_ResolveToolProtocol(t *testing.T) {
	tmpDir := setupTestAgentsDir(t)
	defer os.RemoveAll(tmpDir)

	repo := NewFSRepository(tmpDir)

	// 1. Resolve tool matching manifest entry (db)
	info1, err1 := repo.ResolveToolProtocol("agent-finance", "query_transactions")
	if err1 != nil {
		t.Fatalf("unexpected error: %v", err1)
	}
	if info1.ProtocolName != "db" || info1.TargetURL != "http://localhost:9001/sse" {
		t.Errorf("unexpected resolved info: %+v", info1)
	}

	// 2. Resolve tool matching manifest entry (api)
	info2, err2 := repo.ResolveToolProtocol("agent-finance", "call_payment_gateway")
	if err2 != nil {
		t.Fatalf("unexpected error: %v", err2)
	}
	if info2.ProtocolName != "api" || info2.TargetURL != "http://localhost:9002/sse" {
		t.Errorf("unexpected resolved info: %+v", info2)
	}

	// 3. Resolve tool via prefix matching
	info3, err3 := repo.ResolveToolProtocol("agent-finance", "api__unknown_tool")
	if err3 != nil {
		t.Fatalf("unexpected error: %v", err3)
	}
	if info3.ProtocolName != "api" {
		t.Errorf("expected api protocol, got: %+v", info3)
	}

	// 4. Resolve single protocol agent shortcut
	infoDir, errDir := repo.ResolveToolProtocol("agent-direct", "any_random_tool")
	if errDir != nil {
		t.Fatalf("unexpected error: %v", errDir)
	}
	if infoDir.TargetURL != "http://localhost:9003/sse" {
		t.Errorf("unexpected target URL: %+v", infoDir)
	}
}

func TestFSRepository_ResolveTargetURLFromPath(t *testing.T) {
	tmpDir := setupTestAgentsDir(t)
	defer os.RemoveAll(tmpDir)

	repo := NewFSRepository(tmpDir)

	// 1. Aggregated agent on base path -> OK
	url1, err1 := repo.ResolveTargetURLFromPath("/sse/agent-finance", "http://default:8080")
	if err1 != nil || url1 != "http://localhost:9001/sse" {
		t.Errorf("expected url http://localhost:9001/sse, got %s, err: %v", url1, err1)
	}

	// 2. Aggregated agent with protocol path -> Routing Violation
	_, errAggViolation := repo.ResolveTargetURLFromPath("/sse/agent-finance/db", "http://default:8080")
	if !errors.Is(errAggViolation, ErrRoutingModeViolation) {
		t.Errorf("expected ErrRoutingModeViolation, got: %v", errAggViolation)
	}

	// 3. Direct agent on base path -> Routing Violation
	_, errDirViolation := repo.ResolveTargetURLFromPath("/sse/agent-direct", "http://default:8080")
	if !errors.Is(errDirViolation, ErrRoutingModeViolation) {
		t.Errorf("expected ErrRoutingModeViolation, got: %v", errDirViolation)
	}

	// 4. Direct agent with valid protocol -> OK
	urlDirect, errDirect := repo.ResolveTargetURLFromPath("/sse/agent-direct/primary", "http://default:8080")
	if errDirect != nil || urlDirect != "http://localhost:9003/sse" {
		t.Errorf("expected url http://localhost:9003/sse, got %s, err: %v", urlDirect, errDirect)
	}

	// 5. Direct agent with missing protocol -> ErrProtocolNotFound
	_, errProtoMissing := repo.ResolveTargetURLFromPath("/sse/agent-direct/non-attached", "http://default:8080")
	if !errors.Is(errProtoMissing, ErrProtocolNotFound) {
		t.Errorf("expected ErrProtocolNotFound, got: %v", errProtoMissing)
	}
}

func TestFSRepository_ListAgents(t *testing.T) {
	tmpDir := setupTestAgentsDir(t)
	defer os.RemoveAll(tmpDir)

	repo := NewFSRepository(tmpDir)
	agents, err := repo.ListAgents()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hasFinance := false
	hasDirect := false
	for _, a := range agents {
		if a == "agent-finance" {
			hasFinance = true
		}
		if a == "agent-direct" {
			hasDirect = true
		}
	}

	if !hasFinance || !hasDirect {
		t.Errorf("expected agent-finance and agent-direct, got: %v", agents)
	}
}

func TestFSRepository_SaveAgentManifest(t *testing.T) {
	tmpDir := setupTestAgentsDir(t)
	defer os.RemoveAll(tmpDir)

	repo := NewFSRepository(tmpDir)

	newTools := []ToolMetadata{
		{
			Name:          "new_tool",
			CanonicalName: "db__new_tool",
			ProtocolName:  "db",
			Description:   "Newly synced tool",
		},
	}

	if err := repo.SaveAgentManifest("agent-finance", newTools); err != nil {
		t.Fatalf("failed to save manifest: %v", err)
	}

	manifest, err := repo.GetAgentManifest("agent-finance")
	if err != nil {
		t.Fatalf("unexpected error reading back manifest: %v", err)
	}
	if len(manifest) != 1 || manifest[0].Name != "new_tool" {
		t.Errorf("expected saved tool 'new_tool', got: %+v", manifest)
	}
}

func TestFSRepository_ListAgentArchives_And_Rollback(t *testing.T) {
	tmpDir := setupTestAgentsDir(t)
	defer os.RemoveAll(tmpDir)

	archiveTime := "20260926-120000"
	archiveDir := filepath.Join(tmpDir, "agent-finance", "archive", archiveTime)
	if err := os.MkdirAll(archiveDir, 0755); err != nil {
		t.Fatalf("failed to create archive dir: %v", err)
	}

	archivedConfigJSON := `{
		"agent_id": "finance-archived",
		"agent_name": "agent-finance",
		"routing_mode": "aggregated"
	}`
	if err := os.WriteFile(filepath.Join(archiveDir, "config.json"), []byte(archivedConfigJSON), 0644); err != nil {
		t.Fatalf("failed to write archived config: %v", err)
	}

	repo := NewFSRepository(tmpDir)

	// List archives
	archives, err := repo.ListAgentArchives("agent-finance")
	if err != nil {
		t.Fatalf("unexpected error listing archives: %v", err)
	}
	if len(archives) != 1 || archives[0] != archiveTime {
		t.Fatalf("expected [%s], got %v", archiveTime, archives)
	}

	// Rollback
	if err := repo.RollbackAgent("agent-finance", archiveTime); err != nil {
		t.Fatalf("failed to rollback: %v", err)
	}

	cfg, err := repo.GetAgentConfig("agent-finance")
	if err != nil {
		t.Fatalf("failed to get config after rollback: %v", err)
	}
	if cfg.AgentID != "finance-archived" {
		t.Errorf("expected rolled back agent_id 'finance-archived', got '%s'", cfg.AgentID)
	}
}

func TestFSRepository_SaveAgentConfig_CreateAndArchive(t *testing.T) {
	tmpDir := t.TempDir()
	repo := NewFSRepository(tmpDir)

	cfg1 := &RouteConfig{
		AgentID:     "agent-lifecycle-01",
		AgentName:   "agent-lifecycle",
		Description: "Initial version",
		RoutingMode: "aggregated",
		Protocols: []ProtocolConfig{
			{
				ID:           "proto-1",
				Name:         "mcp-alpha",
				Type:         "sse",
				URLOrCommand: "http://localhost:8001/sse",
			},
		},
	}

	// 1. Initial creation
	if err := repo.SaveAgentConfig("agent-lifecycle", cfg1); err != nil {
		t.Fatalf("failed to save initial agent config: %v", err)
	}

	fetched1, err := repo.GetAgentConfig("agent-lifecycle")
	if err != nil {
		t.Fatalf("failed to get saved config: %v", err)
	}
	if fetched1.Description != "Initial version" {
		t.Errorf("expected 'Initial version', got '%s'", fetched1.Description)
	}

	// Verify no archives yet
	archives, err := repo.ListAgentArchives("agent-lifecycle")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(archives) != 0 {
		t.Errorf("expected 0 archives on initial save, got %d", len(archives))
	}

	// 2. Update configuration (triggers snapshot archive)
	cfg2 := &RouteConfig{
		AgentID:     "agent-lifecycle-01",
		AgentName:   "agent-lifecycle",
		Description: "Second version",
		RoutingMode: "aggregated",
		Protocols: []ProtocolConfig{
			{
				ID:           "proto-1",
				Name:         "mcp-alpha",
				Type:         "sse",
				URLOrCommand: "http://localhost:8001/sse",
			},
		},
	}

	if err := repo.SaveAgentConfig("agent-lifecycle", cfg2); err != nil {
		t.Fatalf("failed to update agent config: %v", err)
	}

	fetched2, err := repo.GetAgentConfig("agent-lifecycle")
	if err != nil {
		t.Fatalf("failed to get updated config: %v", err)
	}
	if fetched2.Description != "Second version" {
		t.Errorf("expected 'Second version', got '%s'", fetched2.Description)
	}

	// Verify 1 archive exists now
	archives2, err := repo.ListAgentArchives("agent-lifecycle")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(archives2) != 1 {
		t.Fatalf("expected 1 archive after update, got %d", len(archives2))
	}

	// 3. Rollback restores initial version
	if err := repo.RollbackAgent("agent-lifecycle", archives2[0]); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}

	rolledBack, err := repo.GetAgentConfig("agent-lifecycle")
	if err != nil {
		t.Fatalf("failed to get config after rollback: %v", err)
	}
	if rolledBack.Description != "Initial version" {
		t.Errorf("expected rolled back description 'Initial version', got '%s'", rolledBack.Description)
	}
}

func TestFSRepository_DeleteAgent(t *testing.T) {
	tmpDir := t.TempDir()
	repo := NewFSRepository(tmpDir)

	cfg := &RouteConfig{
		AgentID:     "agent-del",
		AgentName:   "agent-del",
		RoutingMode: "aggregated",
	}

	if err := repo.SaveAgentConfig("agent-del", cfg); err != nil {
		t.Fatalf("failed to save agent: %v", err)
	}

	// Verify it exists
	if _, err := repo.GetAgentConfig("agent-del"); err != nil {
		t.Fatalf("agent should exist: %v", err)
	}

	// Delete agent
	if err := repo.DeleteAgent("agent-del"); err != nil {
		t.Fatalf("failed to delete agent: %v", err)
	}

	// Verify deletion
	if _, err := repo.GetAgentConfig("agent-del"); !errors.Is(err, ErrAgentNotFound) {
		t.Fatalf("expected ErrAgentNotFound, got %v", err)
	}

	// Deleting again should return ErrAgentNotFound
	if err := repo.DeleteAgent("agent-del"); !errors.Is(err, ErrAgentNotFound) {
		t.Fatalf("expected ErrAgentNotFound on second delete, got %v", err)
	}
}

func TestRouteConfig_Layer2_ToolScoping(t *testing.T) {
	// Case 1: No restrictions
	cfgOpen := &RouteConfig{
		AgentName: "open-agent",
	}
	if !cfgOpen.IsToolAllowed("toolA") || !cfgOpen.IsToolAllowed("mcp__toolB") {
		t.Error("expected open agent to allow all tools")
	}

	// Case 2: EnabledTools whitelist
	cfgWhitelist := &RouteConfig{
		AgentName:    "whitelist-agent",
		EnabledTools: []string{"read_file", "search"},
	}
	if !cfgWhitelist.IsToolAllowed("read_file") {
		t.Error("expected 'read_file' to be allowed")
	}
	if !cfgWhitelist.IsToolAllowed("fs__read_file") {
		t.Error("expected prefixed 'fs__read_file' to be allowed")
	}
	if cfgWhitelist.IsToolAllowed("delete_file") {
		t.Error("expected 'delete_file' to be rejected")
	}

	// Case 3: ToolOverrides with EnabledTools scoping
	cfgOverrides := &RouteConfig{
		AgentName: "override-agent",
		ToolOverrides: &ToolOverrides{
			EnabledTools: []string{"toolA"},
		},
		ToolGovernance: map[string]ToolGovernanceMode{
			"toolA": ModeAutonomous,
			"toolB": ModeStrictAlwaysHITL,
		},
	}
	if !cfgOverrides.IsToolAllowed("toolA") {
		t.Error("expected toolA to be allowed by Layer 2 scoping")
	}
	if cfgOverrides.IsToolAllowed("toolB") {
		t.Error("expected toolB to be rejected because it is not in EnabledTools whitelist")
	}
	if mode, ok := cfgOverrides.GetToolGovernanceMode("toolA"); !ok || mode != ModeAutonomous {
		t.Errorf("expected toolA to have ModeAutonomous, got %v (found: %v)", mode, ok)
	}
	if mode, ok := cfgOverrides.GetToolGovernanceMode("toolB"); !ok || mode != ModeStrictAlwaysHITL {
		t.Errorf("expected toolB to have ModeStrictAlwaysHITL, got %v (found: %v)", mode, ok)
	}

	// Case 4: ComputeEffectiveTools intersection (Layer 1 ∩ Layer 2)
	cfgEffective := &RouteConfig{
		AgentName: "effective-agent",
		Protocols: []ProtocolConfig{
			{
				Name:         "github",
				AllowedTools: []string{"create_issue", "read_issue", "delete_issue"}, // Layer 1 allows these 3
			},
		},
		EnabledTools: []string{"read_issue", "list_repos"}, // Layer 2 allows read_issue and list_repos
	}

	manifest := []ToolMetadata{
		{Name: "create_issue", ProtocolName: "github"},
		{Name: "read_issue", ProtocolName: "github"},
		{Name: "delete_issue", ProtocolName: "github"},
		{Name: "unapproved_tool", ProtocolName: "github"},
	}

	effective := cfgEffective.ComputeEffectiveTools(manifest)
	if len(effective) != 1 {
		t.Fatalf("expected exactly 1 effective tool (intersection), got %d", len(effective))
	}
	if effective[0].Name != "read_issue" {
		t.Errorf("expected effective tool to be 'read_issue', got '%s'", effective[0].Name)
	}
}

func TestRouteConfig_ToolGovernance_LifecycleAndArchive(t *testing.T) {
	// 1. Table-driven validity checks
	testCases := []struct {
		mode  ToolGovernanceMode
		valid bool
	}{
		{ModeAutonomous, true},
		{ModeGuardedBlock, true},
		{ModeGuardedHITL, true},
		{ModeStrictAlwaysHITL, true},
		{"invalid_mode", false},
		{"", false},
	}
	for _, tc := range testCases {
		if tc.mode.IsValid() != tc.valid {
			t.Errorf("expected mode '%s' IsValid=%v, got %v", tc.mode, tc.valid, tc.mode.IsValid())
		}
	}

	// 2. Lookup resolution with namespaced prefixes
	cfg := &RouteConfig{
		AgentName: "governance-agent",
		ToolGovernance: map[string]ToolGovernanceMode{
			"read_data":    ModeAutonomous,
			"write_record": ModeGuardedHITL,
			"drop_table":   ModeGuardedBlock,
			"deploy_prod":  ModeStrictAlwaysHITL,
		},
	}

	// Direct match
	if mode, ok := cfg.GetToolGovernanceMode("read_data"); !ok || mode != ModeAutonomous {
		t.Errorf("expected read_data -> ModeAutonomous, got %v (%v)", mode, ok)
	}
	// Prefix match (db__write_record -> write_record)
	if mode, ok := cfg.GetToolGovernanceMode("db__write_record"); !ok || mode != ModeGuardedHITL {
		t.Errorf("expected db__write_record -> ModeGuardedHITL, got %v (%v)", mode, ok)
	}
	// Unconfigured tool
	if _, ok := cfg.GetToolGovernanceMode("unconfigured_tool"); ok {
		t.Error("expected unconfigured_tool to return ok=false")
	}

	// 3. Persistence and Snapshot Archiving
	tmpDir := t.TempDir()
	repo := NewFSRepository(tmpDir)

	err := repo.SaveAgentConfig("governance-agent", cfg)
	if err != nil {
		t.Fatalf("SaveAgentConfig failed: %v", err)
	}

	// Retrieve config from disk
	loaded, err := repo.GetAgentConfig("governance-agent")
	if err != nil {
		t.Fatalf("GetAgentConfig failed: %v", err)
	}
	if len(loaded.ToolGovernance) != 4 {
		t.Fatalf("expected 4 governance entries, got %d", len(loaded.ToolGovernance))
	}
	if loaded.ToolGovernance["deploy_prod"] != ModeStrictAlwaysHITL {
		t.Errorf("expected deploy_prod to be strict_always_hitl, got %v", loaded.ToolGovernance["deploy_prod"])
	}

	// Sleep briefly so timestamp archive is distinct
	time.Sleep(10 * time.Millisecond)

	// Update agent config: modify governance
	cfg.ToolGovernance["deploy_prod"] = ModeGuardedHITL
	if err := repo.SaveAgentConfig("governance-agent", cfg); err != nil {
		t.Fatalf("second SaveAgentConfig failed: %v", err)
	}

	// Verify archives exist
	archives, err := repo.ListAgentArchives("governance-agent")
	if err != nil {
		t.Fatalf("ListAgentArchives failed: %v", err)
	}
	if len(archives) == 0 {
		t.Fatal("expected at least 1 archive snapshot after second save")
	}

	// Rollback to prior snapshot
	if err := repo.RollbackAgent("governance-agent", archives[0]); err != nil {
		t.Fatalf("RollbackAgent failed: %v", err)
	}

	// Retrieve post-rollback config and verify strict_always_hitl was restored
	rolledBack, err := repo.GetAgentConfig("governance-agent")
	if err != nil {
		t.Fatalf("GetAgentConfig after rollback failed: %v", err)
	}
	if rolledBack.ToolGovernance["deploy_prod"] != ModeStrictAlwaysHITL {
		t.Errorf("expected rolled back config to have deploy_prod=strict_always_hitl, got %v", rolledBack.ToolGovernance["deploy_prod"])
	}
}

func TestFSRepository_ArchiveAgentCurrent(t *testing.T) {
	tempDir := t.TempDir()
	repo := NewFSRepository(tempDir)

	tests := []struct {
		name        string
		agentName   string
		setup       func(t *testing.T)
		wantErr     bool
		errCheck    func(error) bool
		checkResult func(t *testing.T)
	}{
		{
			name:      "invalid agent identifier",
			agentName: "../malicious",
			setup:     func(t *testing.T) {},
			wantErr:   true,
			errCheck: func(err error) bool {
				return errors.Is(err, ErrInvalidIdentifier)
			},
		},
		{
			name:      "nonexistent agent directory returns nil safely",
			agentName: "ghost-agent",
			setup:     func(t *testing.T) {},
			wantErr:   false,
		},
		{
			name:      "agent with current directory containing files archives cleanly",
			agentName: "active-agent",
			setup: func(t *testing.T) {
				currentDir := filepath.Join(tempDir, "active-agent", "current")
				if err := os.MkdirAll(currentDir, 0755); err != nil {
					t.Fatalf("failed to create currentDir: %v", err)
				}
				_ = os.WriteFile(filepath.Join(currentDir, "config.json"), []byte(`{"agent_name":"active-agent"}`), 0644)
				_ = os.WriteFile(filepath.Join(currentDir, "dlp.json"), []byte(`{"rules":[]}`), 0644)
			},
			wantErr: false,
			checkResult: func(t *testing.T) {
				archives, err := repo.ListAgentArchives("active-agent")
				if err != nil {
					t.Fatalf("ListAgentArchives failed: %v", err)
				}
				if len(archives) != 1 {
					t.Fatalf("expected 1 archive, got %d", len(archives))
				}
				// Verify archived files
				archivedConfig := filepath.Join(tempDir, "active-agent", "archive", archives[0], "config.json")
				if _, err := os.Stat(archivedConfig); err != nil {
					t.Errorf("expected archived config.json to exist at %s: %v", archivedConfig, err)
				}
				archivedDLP := filepath.Join(tempDir, "active-agent", "archive", archives[0], "dlp.json")
				if _, err := os.Stat(archivedDLP); err != nil {
					t.Errorf("expected archived dlp.json to exist at %s: %v", archivedDLP, err)
				}
			},
		},
		{
			name:      "subsequent archive call handles collision with unique timestamp suffix",
			agentName: "active-agent",
			setup:     func(t *testing.T) {},
			wantErr:   false,
			checkResult: func(t *testing.T) {
				archives, err := repo.ListAgentArchives("active-agent")
				if err != nil {
					t.Fatalf("ListAgentArchives failed: %v", err)
				}
				if len(archives) != 2 {
					t.Fatalf("expected 2 archives, got %d", len(archives))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup(t)
			err := repo.ArchiveAgentCurrent(tt.agentName)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ArchiveAgentCurrent() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.errCheck != nil && !tt.errCheck(err) {
				t.Fatalf("ArchiveAgentCurrent() error %v failed custom errCheck", err)
			}
			if tt.checkResult != nil {
				tt.checkResult(t)
			}
		})
	}
}

func TestFSRepository_ResolveToolProtocol_WireBudgetAndCompaction(t *testing.T) {
	tmpDir := t.TempDir()
	currentDir := filepath.Join(tmpDir, "wire-agent", "current")
	if err := os.MkdirAll(currentDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	cfg := RouteConfig{
		AgentID:     "wire-agent",
		AgentName:   "wire-agent",
		RoutingMode: "aggregated",
		Protocols: []ProtocolConfig{
			{ID: "codegraph_696c", Name: "codegraph (antigravity)", Type: "stdio", Command: "codegraph"},
			{ID: "sequential_516f", Name: "sequentialthinking (cline)", Type: "stdio", Command: "npx"},
		},
	}
	cfgBytes, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(filepath.Join(currentDir, "config.json"), cfgBytes, 0600); err != nil {
		t.Fatalf("write config.json: %v", err)
	}

	long34 := "create_pull_request_review_comment"
	extreme45 := "create_or_update_repository_dependabot_secret"
	manifest := []ToolMetadata{
		{
			Name:         FormatAggregatedToolName("sequential_516f", long34),
			RawName:      long34,
			ProtocolID:   "sequential_516f",
			ProtocolName: "sequentialthinking (cline)",
		},
		{
			Name:         FormatAggregatedToolName("sequential_516f", extreme45),
			RawName:      extreme45,
			ProtocolID:   "sequential_516f",
			ProtocolName: "sequentialthinking (cline)",
		},
		{
			Name:         FormatAggregatedToolName("codegraph_696c", "fs.read_file"),
			RawName:      "fs.read_file",
			ProtocolID:   "codegraph_696c",
			ProtocolName: "codegraph (antigravity)",
		},
		{
			Name:         FormatAggregatedToolName("codegraph_696c", "git/status"),
			RawName:      "git/status",
			ProtocolID:   "codegraph_696c",
			ProtocolName: "codegraph (antigravity)",
		},
	}
	mBytes, _ := json.MarshalIndent(manifest, "", "  ")
	if err := os.WriteFile(filepath.Join(currentDir, "tools_manifest.json"), mBytes, 0600); err != nil {
		t.Fatalf("write tools_manifest.json: %v", err)
	}

	repo := NewFSRepository(tmpDir)

	// Verify CompileToolsList emits <= 44 char wire-safe names matching ^[a-zA-Z0-9_-]{1,44}$
	agg := NewManifestAggregator(repo)
	listed, err := agg.CompileToolsList(context.Background(), "wire-agent")
	if err != nil {
		t.Fatalf("CompileToolsList: %v", err)
	}
	if len(listed) != 4 {
		t.Fatalf("expected 4 tools, got %d", len(listed))
	}
	for _, entry := range listed {
		name, _ := entry["name"].(string)
		if len(name) == 0 || len(name) > MaxWireToolNameLen {
			t.Errorf("tool name %q (len=%d) violates 1..%d budget", name, len(name), MaxWireToolNameLen)
		}
		for i := 0; i < len(name); i++ {
			c := name[i]
			valid := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-'
			if !valid {
				t.Errorf("tool name %q contains invalid char %q", name, c)
			}
		}
	}

	// Verify manifest-backed round-trip resolution for Tier 2, Tier 3, and punctuated tools
	tests := []struct {
		wireName string
		wantID   string
		wantRaw  string
	}{
		{wireName: FormatAggregatedToolName("sequential_516f", long34), wantID: "sequential_516f", wantRaw: long34},
		{wireName: FormatAggregatedToolName("sequential_516f", extreme45), wantID: "sequential_516f", wantRaw: extreme45},
		{wireName: FormatAggregatedToolName("codegraph_696c", "fs.read_file"), wantID: "codegraph_696c", wantRaw: "fs.read_file"},
		{wireName: FormatAggregatedToolName("codegraph_696c", "git/status"), wantID: "codegraph_696c", wantRaw: "git/status"},
		// Unmanifested Tier-2 narrowed prefix tool still resolves via FindProtocol("_696c")
		{wireName: "cod_696c__another_thirty_character_tool_ok", wantID: "codegraph_696c", wantRaw: "another_thirty_character_tool_ok"},
	}

	for _, tc := range tests {
		target, rErr := repo.ResolveToolProtocol("wire-agent", tc.wireName)
		if rErr != nil {
			t.Fatalf("ResolveToolProtocol(%q) error: %v", tc.wireName, rErr)
		}
		if target == nil || target.ProtocolID != tc.wantID || target.RawToolName != tc.wantRaw {
			t.Errorf("ResolveToolProtocol(%q) = %+v; want ProtocolID=%q RawToolName=%q", tc.wireName, target, tc.wantID, tc.wantRaw)
		}
	}
}
