package mcpexport

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/protocol"
)

func TestExport_AllNineTargetsAndTwoStoreEnrichment(t *testing.T) {
	route := &agent.RouteConfig{
		AgentID:   "dev-profile",
		AgentName: "dev-profile",
		Protocols: []agent.ProtocolConfig{
			{
				ID:           "fs_1",
				Name:         "filesystem (cursor)",
				Type:         "stdio",
				URLOrCommand: `npx -y @modelcontextprotocol/server-filesystem /tmp --token=supersecret123`,
				Env:          []string{"API_KEY=secret_env_val", "LOG_LEVEL=info"},
			},
			{
				ID:           "gh_1",
				Name:         "github",
				Type:         "sse", // Legacy persisted type; lookup resolves TransportMode="streamable_http"
				URLOrCommand: "https://user:pass@api.githubcopilot.com/mcp?api_key=querysecret",
				AuthToken:    "ghp_rawtokenvalue",
				AllowedTools: []string{"get_issue"},
			},
		},
	}
	manifest := []agent.ToolMetadata{
		{Name: "gh_1__get_issue", RawName: "get_issue", ProtocolID: "gh_1", ProtocolName: "github"},
		{Name: "gh_1__delete_repo", RawName: "delete_repo", ProtocolID: "gh_1", ProtocolName: "github"},
	}
	lookup := func(id string) (*protocol.Protocol, bool) {
		if id == "gh_1" {
			return &protocol.Protocol{ID: "gh_1", TransportMode: "streamable_http"}, true
		}
		return nil, false
	}

	clients := []string{
		ClientClaudeCode,
		ClientClaudeDesktop,
		ClientCursor,
		ClientCursorWorkspace,
		ClientWindsurf,
		ClientCline,
		ClientRooCode,
		ClientAntigravity,
		ClientGeneric,
	}

	for _, client := range clients {
		t.Run(client, func(t *testing.T) {
			res, err := Export(context.Background(), ExportRequest{
				Client:   client,
				ClientOS: OSDarwin,
				Route:    route,
				Manifest: manifest,
				Lookup:   lookup,
			})
			if err != nil {
				t.Fatalf("Export(%s) failed: %v", client, err)
			}

			rawBytes, _ := json.Marshal(res)
			raw := string(rawBytes)
			for _, secret := range []string{"supersecret123", "secret_env_val", "ghp_rawtokenvalue", "querysecret", "user:pass"} {
				if strings.Contains(raw, secret) {
					t.Fatalf("secret %q leaked in %s export: %s", secret, client, raw)
				}
			}

			mcpServers := res.Config["mcpServers"].(map[string]any)
			fsEntry := mcpServers["filesystem"].(map[string]any)
			if fsEntry["command"] != "npx" {
				t.Fatalf("unexpected stdio command: %#v", fsEntry)
			}

			if client == ClientClaudeDesktop {
				if _, ok := mcpServers["github"]; ok {
					t.Fatalf("claude-desktop must omit remote server")
				}
				return
			}

			ghEntry := mcpServers["github"].(map[string]any)
			switch client {
			case ClientClaudeCode, ClientGeneric:
				if ghEntry["type"] != "http" || ghEntry["url"] == nil {
					t.Fatalf("unexpected %s remote schema: %#v", client, ghEntry)
				}
			case ClientCline:
				if ghEntry["type"] != "streamableHttp" {
					t.Fatalf("unexpected cline type: %#v", ghEntry)
				}
			case ClientRooCode:
				if ghEntry["type"] != "streamable-http" {
					t.Fatalf("unexpected roo-code type: %#v", ghEntry)
				}
			case ClientWindsurf:
				if _, hasType := ghEntry["type"]; hasType || ghEntry["serverUrl"] == nil {
					t.Fatalf("unexpected windsurf schema: %#v", ghEntry)
				}
			case ClientAntigravity:
				if _, hasType := ghEntry["type"]; hasType || ghEntry["serverUrl"] == nil {
					t.Fatalf("antigravity must omit type and use serverUrl: %#v", ghEntry)
				}
				if _, hasDisabled := ghEntry["disabledTools"]; hasDisabled {
					t.Fatalf("antigravity must omit unverified disabledTools: %#v", ghEntry)
				}
			case ClientCursor, ClientCursorWorkspace:
				if _, hasType := ghEntry["type"]; hasType || ghEntry["url"] == nil {
					t.Fatalf("unexpected cursor schema: %#v", ghEntry)
				}
			}

			if client == ClientClaudeCode && len(res.CompanionFiles) != 1 {
				t.Fatalf("expected companion .claude/settings.json for claude-code")
			}
		})
	}
}

func TestExport_EmptyAndUnverifiedTransport(t *testing.T) {
	route := &agent.RouteConfig{
		AgentID: "unverified-sse",
		Protocols: []agent.ProtocolConfig{
			{
				ID:           "legacy_sse",
				Name:         "legacy-sse",
				Type:         "sse",
				URLOrCommand: "https://mcp.example.com/sse",
			},
		},
	}

	res, err := Export(context.Background(), ExportRequest{
		Client: ClientClaudeDesktop,
		Route:  route,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mcpServers := res.Config["mcpServers"].(map[string]any)
	if len(mcpServers) != 0 {
		t.Fatalf("expected empty mcpServers, got %#v", mcpServers)
	}

	hasOmitted := false
	for _, w := range res.Warnings {
		if w.Code == WarnUnsupportedTransportOmitted {
			hasOmitted = true
		}
	}
	if !hasOmitted {
		t.Fatalf("expected UNSUPPORTED_TRANSPORT_OMITTED warning, got %#v", res.Warnings)
	}

	rooRes, err := Export(context.Background(), ExportRequest{
		Client: ClientRooCode,
		Route:  route,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	hasUnverified := false
	for _, w := range rooRes.Warnings {
		if w.Code == WarnUnverifiedTransportMode {
			hasUnverified = true
		}
	}
	if !hasUnverified {
		t.Fatalf("expected UNVERIFIED_TRANSPORT_MODE warning on roo-code, got %#v", rooRes.Warnings)
	}
}
