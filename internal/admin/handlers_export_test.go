package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/mcpexport"
	"github.com/FaradAiLab/FaradAiWire/internal/protocol"
)

func TestHandleExportAgentNativeMCP(t *testing.T) {
	agentsDir := t.TempDir()
	protocolsDir := t.TempDir()

	repo := agent.NewFSRepository(agentsDir)
	pStore, err := protocol.NewFSStore(protocolsDir)
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}

	if err := pStore.Save(&protocol.Protocol{
		ID:            "gh_remote",
		Name:          "github",
		Type:          "sse",
		TransportMode: "streamable_http",
		URLOrCommand:  "https://api.githubcopilot.com/mcp?token=topsecret",
		AuthToken:     "ghp_super_secret_token",
	}); err != nil {
		t.Fatalf("pStore.Save: %v", err)
	}

	route := &agent.RouteConfig{
		AgentID:   "dev-agent",
		AgentName: "dev-agent",
		Protocols: []agent.ProtocolConfig{
			{
				ID:           "gh_remote",
				Name:         "github (claude-code)",
				Type:         "sse",
				URLOrCommand: "https://api.githubcopilot.com/mcp?token=topsecret",
				AuthToken:    "ghp_super_secret_token",
				AllowedTools: []string{"get_issue"},
			},
		},
	}
	if err := repo.SaveAgentConfig("dev-agent", route); err != nil {
		t.Fatalf("SaveAgentConfig: %v", err)
	}
	if err := repo.SaveAgentManifest("dev-agent", []agent.ToolMetadata{
		{Name: "github__get_issue", RawName: "get_issue", ProtocolID: "gh_remote", ProtocolName: "github"},
		{Name: "github__delete_repo", RawName: "delete_repo", ProtocolID: "gh_remote", ProtocolName: "github"},
	}); err != nil {
		t.Fatalf("SaveAgentManifest: %v", err)
	}

	spy := &spySecurityAuditLogger{}
	srv := newTestAdminServer(func(d *AdminDependencies) {
		d.AgentRepo = repo
		d.ProtocolStore = pStore
		d.SecurityAuditLoggers = []SecurityAuditEventLogger{spy}
	})
	handler := srv.Handler()

	t.Run("200 exports native config with TransportMode enrichment and no secrets", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/admin/agents/dev-agent/export", bytes.NewBufferString(`{"client":"claude-code","scope":"project","client_os":"darwin"}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Fatalf("Cache-Control = %q, want no-store", got)
		}

		bodyStr := rec.Body.String()
		if strings.Contains(bodyStr, "topsecret") || strings.Contains(bodyStr, "ghp_super_secret_token") {
			t.Fatalf("raw secret leaked in response: %s", bodyStr)
		}

		var res mcpexport.ExportResult
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatalf("unmarshal response: %v", err)
		}
		if res.TargetPathHint != ".mcp.json" {
			t.Fatalf("target_path_hint = %q, want .mcp.json", res.TargetPathHint)
		}
		mcpServers := res.Config["mcpServers"].(map[string]any)
		gh := mcpServers["github"].(map[string]any)
		if gh["type"] != "http" {
			t.Fatalf("expected protocolStore TransportMode enrichment -> type=http, got %#v", gh)
		}
		if len(res.CompanionFiles) != 1 || res.CompanionFiles[0].PathHint != ".claude/settings.json" {
			t.Fatalf("expected companion .claude/settings.json, got %#v", res.CompanionFiles)
		}

		events := spy.Events()
		if len(events) == 0 || events[len(events)-1].EventType != "agent_native_export" {
			t.Fatalf("expected Control-Plane Security Audit event, got %#v", events)
		}
	})

	t.Run("400 rejects invalid target client", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/admin/agents/dev-agent/export", bytes.NewBufferString(`{"client":"invalid-ide"}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("404 returns not found for unknown profile", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/admin/agents/missing-agent/export", bytes.NewBufferString(`{"client":"cursor","client_os":"windows"}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})

	t.Run("400 rejects invalid profile identifier and unsupported scope/os", func(t *testing.T) {
		badNameReq := httptest.NewRequest(http.MethodPost, "/admin/agents/bad..agent/export", bytes.NewBufferString(`{"client":"generic"}`))
		badNameReq.Header.Set("Content-Type", "application/json")
		badNameRec := httptest.NewRecorder()
		handler.ServeHTTP(badNameRec, badNameReq)
		if badNameRec.Code != http.StatusBadRequest {
			t.Fatalf("invalid identifier status = %d, want 400", badNameRec.Code)
		}

		badScopeReq := httptest.NewRequest(http.MethodPost, "/admin/agents/dev-agent/export", bytes.NewBufferString(`{"client":"cursor","scope":"project","client_os":"plan9"}`))
		badScopeReq.Header.Set("Content-Type", "application/json")
		badScopeRec := httptest.NewRecorder()
		handler.ServeHTTP(badScopeRec, badScopeReq)
		if badScopeRec.Code != http.StatusBadRequest {
			t.Fatalf("invalid scope/os status = %d, want 400", badScopeRec.Code)
		}
	})
}
