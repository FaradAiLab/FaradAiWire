package mcpconfig

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/db/duckdb"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/schema"
	"github.com/FaradAiLab/FaradAiWire/internal/policy"
	"github.com/FaradAiLab/FaradAiWire/internal/protocol"
)

func TestMigrateLegacyProtocolIDs_EndToEndMultiStoreAndIdempotent(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	protocolsDir := filepath.Join(tmpDir, "protocols")
	agentsDir := filepath.Join(tmpDir, "agents")
	schemasDir := filepath.Join(tmpDir, "schemas")
	dbPath := filepath.Join(tmpDir, "telemetry.duckdb")

	if err := os.MkdirAll(protocolsDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(agentsDir, "antigravity", "current"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(schemasDir, 0700); err != nil {
		t.Fatal(err)
	}

	legacyCodegraphID := legacySanitizeIdentifier("antigravity", "codegraph")
	if legacyCodegraphID != "antigravity_codegraph_696cf8" {
		t.Fatalf("unexpected legacyCodegraphID: %s", legacyCodegraphID)
	}
	legacySeqID := legacySanitizeIdentifier("cline", "github.com/modelcontextprotocol/servers/tree/main/src/sequentialthinking")
	if legacySeqID != "cline_github_com_modelcontextprotocol_servers_tree_main_src_sequentialthinking_516fbc" {
		t.Fatalf("unexpected legacySeqID: %s", legacySeqID)
	}

	// 1. Seed legacy protocol files in protocols/
	cgProto := protocol.Protocol{
		ID:            legacyCodegraphID,
		Name:          "codegraph (antigravity)",
		Description:   "Imported from Google Antigravity MCP configuration",
		Type:          "http",
		TransportMode: "streamable_http",
		URLOrCommand:  "https://codegraph.internal/mcp",
		AuthToken:     "secret-bearer-token-123",
		AllowedTools:  []string{legacyCodegraphID + "__codegraph_explore"},
		CreatedAt:     time.Now().UTC().Add(-24 * time.Hour),
	}
	cgBytes, _ := json.MarshalIndent(cgProto, "", "  ")
	if err := os.WriteFile(filepath.Join(protocolsDir, legacyCodegraphID+".json"), cgBytes, 0600); err != nil {
		t.Fatal(err)
	}

	seqProto := protocol.Protocol{
		ID:           legacySeqID,
		Name:         "github.com/modelcontextprotocol/servers/tree/main/src/sequentialthinking (cline)",
		Type:         "stdio",
		Command:      "npx",
		URLOrCommand: "npx",
	}
	seqBytes, _ := json.MarshalIndent(seqProto, "", "  ")
	if err := os.WriteFile(filepath.Join(protocolsDir, legacySeqID+".json"), seqBytes, 0600); err != nil {
		t.Fatal(err)
	}

	// 2. Seed agents/antigravity/current/config.json with all governance & scoping fields
	routeCfg := agent.RouteConfig{
		AgentID:     "antigravity",
		AgentName:   "antigravity",
		RoutingMode: "aggregated",
		Protocols: []agent.ProtocolConfig{
			{
				ID:           legacyCodegraphID,
				Name:         "codegraph (antigravity)",
				Type:         "http",
				URLOrCommand: "https://codegraph.internal/mcp",
				AuthToken:    "secret-bearer-token-123",
				TargetScope:  "corporate",
				AllowedTools: []string{legacyCodegraphID + "__codegraph_explore"},
			},
		},
		EnabledTools: []string{legacyCodegraphID + "__codegraph_explore"},
		ToolOverrides: &agent.ToolOverrides{
			EnabledTools: []string{legacyCodegraphID + "__codegraph_explore"},
		},
		LoopProtection: &agent.LoopProtectionOverride{
			MaxRepeat:     3,
			WindowSeconds: 10,
			ExcludeTools:  []string{legacyCodegraphID + "__codegraph_explore"},
		},
		ToolGovernance: map[string]agent.ToolGovernanceMode{
			legacyCodegraphID + "__codegraph_explore": agent.ModeStrictAlwaysHITL,
		},
		RetainedGovernance: map[string]map[string]agent.ToolGovernanceMode{
			legacySeqID: {
				legacySeqID + "__sequentialthinking": agent.ModeStrictAlwaysHITL,
			},
		},
	}
	cfgBytes, _ := json.MarshalIndent(routeCfg, "", "  ")
	cfgPath := filepath.Join(agentsDir, "antigravity", "current", "config.json")
	if err := os.WriteFile(cfgPath, cfgBytes, 0600); err != nil {
		t.Fatal(err)
	}

	// 3. Seed tools_manifest.json and dlp.json
	manifest := []agent.ToolMetadata{
		{
			Name:          legacyCodegraphID + "__codegraph_explore",
			RawName:       "codegraph_explore",
			CanonicalName: legacyCodegraphID + "__codegraph_explore",
			ProtocolID:    legacyCodegraphID,
			ProtocolName:  "codegraph (antigravity)",
		},
	}
	mBytes, _ := json.MarshalIndent(manifest, "", "  ")
	manifestPath := filepath.Join(agentsDir, "antigravity", "current", "tools_manifest.json")
	if err := os.WriteFile(manifestPath, mBytes, 0600); err != nil {
		t.Fatal(err)
	}

	dlpDoc := map[string]interface{}{
		"enabled": true,
		"tool_exemptions": map[string]interface{}{
			legacyCodegraphID + "__codegraph_explore": map[string]bool{"request": true, "response": false},
		},
	}
	dlpBytes, _ := json.MarshalIndent(dlpDoc, "", "  ")
	dlpPath := filepath.Join(agentsDir, "antigravity", "current", "dlp.json")
	if err := os.WriteFile(dlpPath, dlpBytes, 0600); err != nil {
		t.Fatal(err)
	}

	// 4. Seed schemasDir files
	if err := os.WriteFile(filepath.Join(schemasDir, legacyCodegraphID+"__codegraph_explore.json"), []byte(`{"type":"object"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(schemasDir, "mcp_tools.json"), []byte(`{"`+legacyCodegraphID+`__codegraph_explore":{"type":"object"}}`), 0600); err != nil {
		t.Fatal(err)
	}

	// 5. Seed DuckDB SchemaStore (pinned baseline!) and PolicyStore
	ctx := context.Background()
	dbMgr, err := duckdb.NewManager(duckdb.Config{DBPath: dbPath, MaxOpenConns: 2, MaxIdleConns: 2})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer dbMgr.Close()

	schemaStore := schema.NewDuckDBSchemaStore(dbMgr.DB())
	if err := schemaStore.Migrate(ctx); err != nil {
		t.Fatalf("schemaStore.Migrate: %v", err)
	}
	if err := schemaStore.SaveSchema(ctx, &schema.ToolSchemaRecord{
		ToolName:   legacyCodegraphID + "__codegraph_explore",
		ProtocolID: legacyCodegraphID,
		SchemaJSON: json.RawMessage(`{"type":"object"}`),
		SHA256Hash: "abc123hash",
		IsPinned:   true,
	}); err != nil {
		t.Fatalf("SaveSchema: %v", err)
	}

	policyStore := policy.NewDuckDBStore(dbMgr.DB())
	if err := policyStore.Migrate(ctx); err != nil {
		t.Fatalf("policyStore.Migrate: %v", err)
	}
	if err := policyStore.SaveAgentConfig(ctx, &policy.AgentPolicyConfig{
		AgentName: "antigravity",
		ToolExemptions: map[string]policy.ToolExemption{
			legacyCodegraphID + "__codegraph_explore": {Request: true, Response: false},
		},
	}); err != nil {
		t.Fatalf("policyStore.SaveAgentConfig: %v", err)
	}

	// 6. Execute MigrateLegacyProtocolIDs
	opts := MigrateOptions{
		ProtocolsDir: protocolsDir,
		AgentsDir:    agentsDir,
		SchemasDir:   schemasDir,
		SchemaStore:  schemaStore,
		PolicyStore:  policyStore,
	}
	count, err := MigrateLegacyProtocolIDs(ctx, opts)
	if err != nil {
		t.Fatalf("MigrateLegacyProtocolIDs failed: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 migrated protocols, got %d", count)
	}

	// Verify new protocol files exist and old ones were cleaned up
	if _, err := os.Stat(filepath.Join(protocolsDir, "codegraph_696c.json")); err != nil {
		t.Fatalf("expected codegraph_696c.json to exist: %v", err)
	}
	if _, err := os.Stat(filepath.Join(protocolsDir, legacyCodegraphID+".json")); !os.IsNotExist(err) {
		t.Errorf("expected legacy protocol file %s.json to be removed", legacyCodegraphID)
	}

	// Verify migrated protocol preserved AuthToken, Type, TransportMode
	migratedProtoBytes, _ := os.ReadFile(filepath.Join(protocolsDir, "codegraph_696c.json"))
	var migratedProto protocol.Protocol
	if err := json.Unmarshal(migratedProtoBytes, &migratedProto); err != nil {
		t.Fatal(err)
	}
	if migratedProto.ID != "codegraph_696c" || migratedProto.AuthToken != "secret-bearer-token-123" || migratedProto.Type != "http" || migratedProto.TransportMode != "streamable_http" {
		t.Errorf("migrated protocol lost metadata: %+v", migratedProto)
	}

	// Verify agent config.json fields
	migratedCfgBytes, _ := os.ReadFile(cfgPath)
	var migratedCfg agent.RouteConfig
	if err := json.Unmarshal(migratedCfgBytes, &migratedCfg); err != nil {
		t.Fatal(err)
	}
	if len(migratedCfg.Protocols) != 1 || migratedCfg.Protocols[0].ID != "codegraph_696c" || migratedCfg.Protocols[0].AuthToken != "secret-bearer-token-123" {
		t.Errorf("unexpected migrated agent protocols: %+v", migratedCfg.Protocols)
	}
	wantTool := "codegraph_696c__codegraph_explore"
	if migratedCfg.ToolGovernance[wantTool] != agent.ModeStrictAlwaysHITL {
		t.Errorf("expected ToolGovernance[%q] = strict_always_hitl, got %+v", wantTool, migratedCfg.ToolGovernance)
	}
	if len(migratedCfg.EnabledTools) != 1 || migratedCfg.EnabledTools[0] != wantTool {
		t.Errorf("unexpected EnabledTools: %+v", migratedCfg.EnabledTools)
	}
	if len(migratedCfg.ToolOverrides.EnabledTools) != 1 || migratedCfg.ToolOverrides.EnabledTools[0] != wantTool {
		t.Errorf("unexpected ToolOverrides.EnabledTools: %+v", migratedCfg.ToolOverrides.EnabledTools)
	}
	if len(migratedCfg.LoopProtection.ExcludeTools) != 1 || migratedCfg.LoopProtection.ExcludeTools[0] != wantTool {
		t.Errorf("unexpected LoopProtection.ExcludeTools: %+v", migratedCfg.LoopProtection.ExcludeTools)
	}
	if migratedCfg.RetainedGovernance["sequential_516f"]["sequential_516f__sequentialthinking"] != agent.ModeStrictAlwaysHITL {
		t.Errorf("unexpected RetainedGovernance: %+v", migratedCfg.RetainedGovernance)
	}

	// Verify DuckDB pinned schema was migrated with IsPinned == true
	migratedSchema, err := schemaStore.GetSchema(ctx, wantTool)
	if err != nil || migratedSchema == nil {
		t.Fatalf("expected migrated schema %q in DuckDB, got err=%v", wantTool, err)
	}
	if !migratedSchema.IsPinned || migratedSchema.ProtocolID != "codegraph_696c" || migratedSchema.SHA256Hash != "abc123hash" {
		t.Errorf("migrated schema lost pinned status or metadata: %+v", migratedSchema)
	}
	if _, err := schemaStore.GetSchema(ctx, legacyCodegraphID+"__codegraph_explore"); err == nil {
		t.Errorf("expected old schema row to be deleted from DuckDB")
	}

	// Verify DuckDB PolicyStore ToolExemptions
	migratedPol, err := policyStore.GetAgentConfig(ctx, "antigravity")
	if err != nil || migratedPol == nil {
		t.Fatalf("GetAgentConfig: %v", err)
	}
	if ex, ok := migratedPol.ToolExemptions[wantTool]; !ok || !ex.Request {
		t.Errorf("expected migrated policy tool exemption for %q, got %+v", wantTool, migratedPol.ToolExemptions)
	}

	// 7. Second run must be a no-op (0 migrations)
	count2, err := MigrateLegacyProtocolIDs(ctx, opts)
	if err != nil {
		t.Fatalf("second MigrateLegacyProtocolIDs failed: %v", err)
	}
	if count2 != 0 {
		t.Errorf("expected 0 migrations on second idempotent run, got %d", count2)
	}
}

func TestMigrateLegacyProtocolIDs_PreservesFileReferencedByArchiveSnapshot(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	protocolsDir := filepath.Join(tmpDir, "protocols")
	agentsDir := filepath.Join(tmpDir, "agents")
	currentDir := filepath.Join(agentsDir, "antigravity", "current")
	archiveSnapDir := filepath.Join(agentsDir, "antigravity", "archive", "20261119-200000")

	for _, dir := range []string{protocolsDir, currentDir, archiveSnapDir} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}

	legacyID := legacySanitizeIdentifier("antigravity", "codegraph")
	protoJSON := `{"id":"` + legacyID + `","name":"codegraph (antigravity)","type":"stdio","command":"codegraph","url_or_command":"codegraph"}`
	if err := os.WriteFile(filepath.Join(protocolsDir, legacyID+".json"), []byte(protoJSON), 0600); err != nil {
		t.Fatal(err)
	}
	cfgJSON := `{"agent_id":"antigravity","agent_name":"antigravity","routing_mode":"aggregated","protocols":[{"protocol_id":"` + legacyID + `","protocol_name":"codegraph (antigravity)","type":"stdio","command":"codegraph","url_or_command":"codegraph"}]}`
	if err := os.WriteFile(filepath.Join(currentDir, "config.json"), []byte(cfgJSON), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(archiveSnapDir, "config.json"), []byte(cfgJSON), 0600); err != nil {
		t.Fatal(err)
	}

	count, err := MigrateLegacyProtocolIDs(context.Background(), MigrateOptions{
		ProtocolsDir: protocolsDir,
		AgentsDir:    agentsDir,
	})
	if err != nil {
		t.Fatalf("MigrateLegacyProtocolIDs: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 migration, got %d", count)
	}
	if _, err := os.Stat(filepath.Join(protocolsDir, "codegraph_696c.json")); err != nil {
		t.Fatalf("expected migrated codegraph_696c.json: %v", err)
	}
	if _, err := os.Stat(filepath.Join(protocolsDir, legacyID+".json")); err != nil {
		t.Fatalf("expected legacy protocol file referenced by archive snapshot to be preserved, got err=%v", err)
	}
}
