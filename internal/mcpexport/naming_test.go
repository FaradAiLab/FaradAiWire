package mcpexport

import (
	"slices"
	"testing"
)

func TestResolveTargetMeta(t *testing.T) {
	tests := []struct {
		name        string
		client      string
		scope       string
		clientOS    string
		wantScope   string
		wantHint    string
		wantHazard  bool
		wantErr     bool
	}{
		{
			name:       "claude code default project",
			client:     ClientClaudeCode,
			clientOS:   OSDarwin,
			wantScope:  ScopeProject,
			wantHint:   ".mcp.json",
			wantHazard: false,
		},
		{
			name:       "claude code global windows",
			client:     ClientClaudeCode,
			scope:      ScopeGlobal,
			clientOS:   OSWindows,
			wantScope:  ScopeGlobal,
			wantHint:   `%USERPROFILE%\.claude.json`,
			wantHazard: true,
		},
		{
			name:       "claude desktop darwin",
			client:     ClientClaudeDesktop,
			clientOS:   OSDarwin,
			wantScope:  ScopeGlobal,
			wantHint:   "~/Library/Application Support/Claude/claude_desktop_config.json",
			wantHazard: true,
		},
		{
			name:     "claude desktop rejects project scope",
			client:   ClientClaudeDesktop,
			scope:    ScopeProject,
			clientOS: OSLinux,
			wantErr:  true,
		},
		{
			name:       "cursor global linux default",
			client:     ClientCursor,
			wantScope:  ScopeGlobal,
			wantHint:   "~/.cursor/mcp.json",
			wantHazard: false,
		},
		{
			name:       "cursor workspace",
			client:     ClientCursorWorkspace,
			clientOS:   OSLinux,
			wantScope:  ScopeProject,
			wantHint:   ".cursor/mcp.json",
			wantHazard: false,
		},
		{
			name:     "cursor workspace rejects global",
			client:   ClientCursorWorkspace,
			scope:    ScopeGlobal,
			clientOS: OSLinux,
			wantErr:  true,
		},
		{
			name:       "roo code project",
			client:     ClientRooCode,
			scope:      ScopeProject,
			clientOS:   OSDarwin,
			wantScope:  ScopeProject,
			wantHint:   ".roo/mcp.json",
			wantHazard: false,
		},
		{
			name:       "antigravity global darwin",
			client:     ClientAntigravity,
			clientOS:   OSDarwin,
			wantScope:  ScopeGlobal,
			wantHint:   "~/.gemini/antigravity/mcp_config.json",
			wantHazard: false,
		},
		{
			name:     "unknown client rejected",
			client:   "vscode",
			clientOS: OSLinux,
			wantErr:  true,
		},
		{
			name:     "unknown client os rejected",
			client:   ClientGeneric,
			clientOS: "plan9",
			wantErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			scope, hint, hazard, err := ResolveTargetMeta(tc.client, tc.scope, tc.clientOS)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if scope != tc.wantScope || hint != tc.wantHint || hazard != tc.wantHazard {
				t.Fatalf("got (%q, %q, %v), want (%q, %q, %v)", scope, hint, hazard, tc.wantScope, tc.wantHint, tc.wantHazard)
			}
		})
	}
}

func TestSanitizeAndAllocateServerKey(t *testing.T) {
	tests := []struct {
		name string
		in   string
		id   string
		want string
	}{
		{name: "adopted suffix stripped", in: "github (claude-code)", id: "github_a1b2", want: "github"},
		{name: "double underscores collapsed", in: "my__mcp__server", id: "id", want: "my_mcp_server"},
		{name: "spaces and symbols sanitized", in: "Corp MCP @ Prod!", id: "id", want: "Corp-MCP-Prod"},
		{name: "self reference prefixed", in: "faradaiwire-proxy", id: "id", want: "upstream-faradaiwire-proxy"},
		{name: "empty falls back", in: "   ", id: "!!!", want: "mcp-server"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := SanitizeServerKey(tc.in, tc.id); got != tc.want {
				t.Fatalf("SanitizeServerKey(%q, %q) = %q, want %q", tc.in, tc.id, got, tc.want)
			}
		})
	}

	used := make(map[string]int)
	if k := AllocateServerKey("github", used); k != "github" {
		t.Fatalf("first allocation = %q, want github", k)
	}
	if k := AllocateServerKey("github", used); k != "github-2" {
		t.Fatalf("second allocation = %q, want github-2", k)
	}
	if k := AllocateServerKey("github", used); k != "github-3" {
		t.Fatalf("third allocation = %q, want github-3", k)
	}
}

func TestSplitStdioCommand(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		wantCmd  string
		wantArgs []string
		wantErr  bool
	}{
		{
			name:     "quoted path with spaces",
			raw:      `"/Applications/My MCP/server" --port 8080 --token=secret`,
			wantCmd:  "/Applications/My MCP/server",
			wantArgs: []string{"--port", "8080", "--token=secret"},
		},
		{
			name:     "single quoted arg",
			raw:      `npx -y '@org/mcp server'`,
			wantCmd:  "npx",
			wantArgs: []string{"-y", "@org/mcp server"},
		},
		{
			name:    "unterminated quote",
			raw:     `"/Applications/My MCP/server --flag`,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd, args, err := SplitStdioCommand(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cmd != tc.wantCmd || !slices.Equal(args, tc.wantArgs) {
				t.Fatalf("got (%q, %v), want (%q, %v)", cmd, args, tc.wantCmd, tc.wantArgs)
			}
		})
	}
}
