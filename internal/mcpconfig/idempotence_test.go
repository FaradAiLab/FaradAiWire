package mcpconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestIsSelfReference(t *testing.T) {
	tests := []struct {
		name     string
		sName    string
		cmd      string
		args     []string
		url      string
		expected bool
	}{
		{
			name:     "Canonical name farad-ai-wire",
			sName:    "farad-ai-wire",
			expected: true,
		},
		{
			name:     "Name faradaimcp without hyphens",
			sName:    "faradaimcp",
			expected: true,
		},
		{
			name:     "Name faradaiwire",
			sName:    "faradaiwire",
			expected: true,
		},
		{
			name:     "Custom name with faradaiwire command binary",
			sName:    "custom-proxy",
			cmd:      "/opt/homebrew/bin/faradaiwire",
			expected: true,
		},
		{
			name:     "Wrapper script with connect and --profile args",
			sName:    "wrapper",
			cmd:      "bash",
			args:     []string{"./start.sh", "connect", "--profile", "cursor"},
			expected: true,
		},
		{
			name:     "URL pointing to loopback port 8090 sse",
			sName:    "remote-wire",
			url:      "http://127.0.0.1:8090/sse/claude",
			expected: true,
		},
		{
			name:     "URL pointing to localhost:8090",
			sName:    "localhost-wire",
			url:      "http://localhost:8090/mcp",
			expected: true,
		},
		{
			name:     "Standard third-party tool github",
			sName:    "github",
			cmd:      "npx",
			args:     []string{"-y", "@modelcontextprotocol/server-github"},
			expected: false,
		},
		{
			name:     "Standard third-party tool postgres",
			sName:    "postgres",
			cmd:      "npx",
			args:     []string{"-y", "@modelcontextprotocol/server-postgres"},
			expected: false,
		},
		{
			name:     "SSE remote tool on different port",
			sName:    "remote-context7",
			url:      "https://mcp.context7.com/mcp",
			expected: false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := isSelfReference(tc.sName, tc.cmd, tc.args, tc.url)
			if got != tc.expected {
				t.Errorf("isSelfReference(%q, %q, %v, %q) = %v; want %v",
					tc.sName, tc.cmd, tc.args, tc.url, got, tc.expected)
			}
		})
	}
}

func TestIdempotentAdoption_RepeatedRuns(t *testing.T) {
	tempDir := t.TempDir()
	cfgPath := filepath.Join(tempDir, "config.json")

	// 1. Initial state: user has a real tool ("github") and an existing "faradaimcp" definition
	initialJSON := `{
		"mcpServers": {
			"github": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-github"]
			},
			"faradaimcp": {
				"command": "faradaiwire",
				"args": ["connect", "--profile", "default"]
			}
		}
	}`
	if err := os.WriteFile(cfgPath, []byte(initialJSON), 0600); err != nil {
		t.Fatalf("failed to write initial config: %v", err)
	}

	// 2. First pass: readConfigFile should ONLY discover "github", completely ignoring "faradaimcp"
	_, servers, err := readConfigFile(cfgPath)
	if err != nil {
		t.Fatalf("readConfigFile failed: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected 1 server discovered, got %d", len(servers))
	}
	if servers[0].Name != "github" {
		t.Errorf("expected server 'github', got '%s'", servers[0].Name)
	}

	// 3. Mutate config: adopt "github"
	if err := mutateConfigFile(cfgPath, "test-profile", []string{"github"}); err != nil {
		t.Fatalf("mutateConfigFile failed: %v", err)
	}

	// Verify file content after first mutation:
	// "github" removed, "faradaimcp" cleaned up, only single "farad-ai-wire" remains
	mutatedBytes, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("failed to read mutated config: %v", err)
	}
	var rawMap map[string]interface{}
	if err := json.Unmarshal(mutatedBytes, &rawMap); err != nil {
		t.Fatalf("unmarshal mutated config: %v", err)
	}
	mcpServers := rawMap["mcpServers"].(map[string]interface{})
	if _, hasGithub := mcpServers["github"]; hasGithub {
		t.Errorf("adopted server 'github' still present in mcpServers")
	}
	if _, hasFaradaimcp := mcpServers["faradaimcp"]; hasFaradaimcp {
		t.Errorf("legacy 'faradaimcp' was not cleaned up from mcpServers")
	}
	if _, hasFaw := mcpServers["farad-ai-wire"]; !hasFaw {
		t.Errorf("canonical 'farad-ai-wire' was not injected into mcpServers")
	}

	// 4. Second pass (Repeated adopt on already-shielded config):
	// Should discover 0 servers because all active servers are already FaradAiWire!
	_, serversSecondPass, err := readConfigFile(cfgPath)
	if err != nil {
		t.Fatalf("second readConfigFile failed: %v", err)
	}
	if len(serversSecondPass) != 0 {
		t.Fatalf("expected 0 servers discovered on second run, got %d", len(serversSecondPass))
	}

	// 5. Third pass: user later adds a new tool ("slack") to the IDE config alongside farad-ai-wire
	mcpServers["slack"] = map[string]interface{}{
		"command": "npx",
		"args":    []interface{}{"-y", "@modelcontextprotocol/server-slack"},
	}
	updatedBytes, _ := json.MarshalIndent(rawMap, "", "  ")
	_ = os.WriteFile(cfgPath, updatedBytes, 0600)

	// Third read: should discover ONLY "slack", ignoring "farad-ai-wire"
	_, serversThirdPass, err := readConfigFile(cfgPath)
	if err != nil {
		t.Fatalf("third readConfigFile failed: %v", err)
	}
	if len(serversThirdPass) != 1 {
		t.Fatalf("expected 1 server discovered on third run, got %d", len(serversThirdPass))
	}
	if serversThirdPass[0].Name != "slack" {
		t.Errorf("expected discovered server to be 'slack', got '%s'", serversThirdPass[0].Name)
	}
}
