package mcpexport

import (
	"slices"
	"testing"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
)

func TestEvaluateSelectedTools(t *testing.T) {
	proto := agent.ProtocolConfig{
		ID:           "github",
		Name:         "github",
		AllowedTools: []string{"read_file", "get__deep__item"},
	}
	route := &agent.RouteConfig{
		AgentID:      "dev",
		AgentName:    "dev",
		RoutingMode:  "direct",
		Protocols:    []agent.ProtocolConfig{proto},
		EnabledTools: []string{"github__read_file", "get__deep__item"},
	}
	manifest := []agent.ToolMetadata{
		{Name: "read_file", RawName: "read_file", ProtocolID: "github", ProtocolName: "github"},
		{Name: "get__deep__item", RawName: "get__deep__item", ProtocolID: "github", ProtocolName: "github"},
		{Name: "delete_repo", RawName: "delete_repo", ProtocolID: "github", ProtocolName: "github"},
		{Name: "orphan__tool", RawName: "orphan_tool", ProtocolID: "detached", ProtocolName: "detached"},
	}

	t.Run("windsurf emits inverted disabledTools", func(t *testing.T) {
		out := EvaluateSelectedTools(route, proto, "github", manifest, ClientWindsurf)
		if !slices.Equal(out.DisabledTools, []string{"delete_repo"}) {
			t.Fatalf("got disabledTools=%v, want [delete_repo]", out.DisabledTools)
		}
		if len(out.Warnings) != 1 || out.Warnings[0].Code != WarnDenylistUpstreamDrift {
			t.Fatalf("unexpected warnings: %#v", out.Warnings)
		}
	})

	t.Run("claude code emits companion permissions.deny", func(t *testing.T) {
		out := EvaluateSelectedTools(route, proto, "github", manifest, ClientClaudeCode)
		if !slices.Equal(out.ClaudeDenyPatterns, []string{"mcp__github__delete_repo"}) {
			t.Fatalf("got deny=%v", out.ClaudeDenyPatterns)
		}
	})

	t.Run("antigravity omits unverified disabledTools and warns", func(t *testing.T) {
		out := EvaluateSelectedTools(route, proto, "github", manifest, ClientAntigravity)
		if len(out.DisabledTools) != 0 {
			t.Fatalf("must not emit disabledTools for antigravity")
		}
		if len(out.Warnings) != 1 || out.Warnings[0].Code != WarnSelectedToolsUnsupported {
			t.Fatalf("unexpected warnings: %#v", out.Warnings)
		}
	})

	t.Run("uncataloged allowlisted server fails open with warning instead of omitting", func(t *testing.T) {
		out := EvaluateSelectedTools(route, proto, "github", nil, ClientWindsurf)
		if out.OmitServer || out.DisableServer {
			t.Fatalf("must not omit or disable uncataloged server")
		}
		if len(out.Warnings) != 1 || out.Warnings[0].Code != WarnUncatalogedAllowlistFailOpen {
			t.Fatalf("unexpected warnings: %#v", out.Warnings)
		}
	})

	t.Run("unrestricted unprobed server exports cleanly with zero warnings", func(t *testing.T) {
		unrestrictedProto := agent.ProtocolConfig{ID: "remote", Name: "remote"}
		unrestrictedRoute := &agent.RouteConfig{Protocols: []agent.ProtocolConfig{unrestrictedProto}}
		out := EvaluateSelectedTools(unrestrictedRoute, unrestrictedProto, "remote", nil, ClientCursor)
		if out.OmitServer || out.DisableServer || len(out.Warnings) != 0 {
			t.Fatalf("unexpected outcome for unrestricted server: %#v", out)
		}
	})

	t.Run("zero effective allowed tools disables on roo-code and omits on cursor", func(t *testing.T) {
		typoProto := agent.ProtocolConfig{ID: "github", Name: "github", AllowedTools: []string{"nonexistent"}}
		typoRoute := &agent.RouteConfig{Protocols: []agent.ProtocolConfig{typoProto}}

		rooOut := EvaluateSelectedTools(typoRoute, typoProto, "github", manifest, ClientRooCode)
		if !rooOut.DisableServer || len(rooOut.Warnings) != 1 || rooOut.Warnings[0].Code != WarnZeroEffectiveTools {
			t.Fatalf("unexpected roo zero-effective outcome: %#v", rooOut)
		}

		cursorOut := EvaluateSelectedTools(typoRoute, typoProto, "github", manifest, ClientCursor)
		if !cursorOut.OmitServer || len(cursorOut.Warnings) != 1 || cursorOut.Warnings[0].Code != WarnZeroEffectiveTools {
			t.Fatalf("unexpected cursor zero-effective outcome: %#v", cursorOut)
		}
	})
}
