package mcpconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAdapters_ReadAndMutate(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()

	// 1. Setup Claude Desktop fixture
	claudePath := filepath.Join(tempDir, "claude_desktop_config.json")
	claudeContent := `{
		"mcpServers": {
			"filesystem": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/dev"],
				"env": {
					"DEBUG": "true"
				}
			},
			"github": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-github"],
				"env": {
					"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_secret123"
				}
			}
		}
	}`
	if err := os.WriteFile(claudePath, []byte(claudeContent), 0644); err != nil {
		t.Fatalf("failed to write claude fixture: %v", err)
	}

	// 2. Setup Cursor fixture with JSONC (comments & trailing comma)
	cursorPath := filepath.Join(tempDir, "cursor_mcp.json")
	cursorContent := `{
		// Database connection
		"mcpServers": {
			"postgres": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-postgres", "postgresql://localhost/db",],
				"env": {
					"PGPASSWORD": "secret",
				},
			},
		},
	}`
	if err := os.WriteFile(cursorPath, []byte(cursorContent), 0644); err != nil {
		t.Fatalf("failed to write cursor fixture: %v", err)
	}

	// 3. Setup Windsurf fixture
	windsurfPath := filepath.Join(tempDir, "windsurf_mcp.json")
	windsurfContent := `{
		"mcpServers": {
			"context7": {
				"serverUrl": "https://mcp.context7.com/mcp",
				"headers": {
					"Authorization": "Bearer ctx7_token"
				}
			}
		}
	}`
	if err := os.WriteFile(windsurfPath, []byte(windsurfContent), 0644); err != nil {
		t.Fatalf("failed to write windsurf fixture: %v", err)
	}

	// 4. Setup Google Antigravity fixture
	antigravityPath := filepath.Join(tempDir, "antigravity_mcp.json")
	antigravityContent := `{
		"mcpServers": {
			"codegraph": {
				"command": "codegraph",
				"args": ["serve", "--mcp"]
			}
		}
	}`
	if err := os.WriteFile(antigravityPath, []byte(antigravityContent), 0644); err != nil {
		t.Fatalf("failed to write antigravity fixture: %v", err)
	}

	// 5. Setup Claude Code fixture
	claudeCodePath := filepath.Join(tempDir, "claude_code.json")
	claudeCodeContent := `{
		"numApprovedRequests": 42,
		"mcpServers": {
			"memory": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-memory"]
			}
		}
	}`
	if err := os.WriteFile(claudeCodePath, []byte(claudeCodeContent), 0644); err != nil {
		t.Fatalf("failed to write claude code fixture: %v", err)
	}

	// 6. Setup Cline fixture
	clinePath := filepath.Join(tempDir, "cline_mcp_settings.json")
	clineContent := `{
		"mcpServers": {
			"brave-search": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-brave-search"],
				"env": {
					"BRAVE_API_KEY": "brave_secret_key"
				}
			}
		}
	}`
	if err := os.WriteFile(clinePath, []byte(clineContent), 0644); err != nil {
		t.Fatalf("failed to write cline fixture: %v", err)
	}

	// 7. Setup Roo Code fixture
	rooPath := filepath.Join(tempDir, "roo_mcp_settings.json")
	rooContent := `{
		"mcpServers": {
			"slack": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-slack"],
				"env": {
					"SLACK_BOT_TOKEN": "xoxb-secret"
				}
			}
		}
	}`
	if err := os.WriteFile(rooPath, []byte(rooContent), 0644); err != nil {
		t.Fatalf("failed to write roo code fixture: %v", err)
	}

	pathMap := map[ClientID]string{
		ClientClaudeDesktop: claudePath,
		ClientCursor:        cursorPath,
		ClientWindsurf:      windsurfPath,
		ClientAntigravity:   antigravityPath,
		ClientClaudeCode:    claudeCodePath,
		ClientCline:         clinePath,
		ClientRooCode:       rooPath,
	}

	adapters := []ClientAdapter{
		NewClaudeDesktopAdapter(claudePath),
		NewCursorAdapter(cursorPath),
		NewWindsurfAdapter(windsurfPath),
		NewAntigravityAdapter(antigravityPath),
		NewClaudeCodeAdapter(claudeCodePath),
		NewClineAdapter(clinePath),
		NewRooCodeAdapter(rooPath),
	}

	for _, adapter := range adapters {
		adapter := adapter
		t.Run(string(adapter.ID()), func(t *testing.T) {
			if !adapter.Detect() {
				t.Fatalf("adapter %s failed to detect file", adapter.ID())
			}

			servers, err := adapter.ReadServers()
			if err != nil {
				t.Fatalf("failed to read servers from %s: %v", adapter.ID(), err)
			}

			if len(servers) == 0 {
				t.Fatalf("expected at least 1 server in %s, got 0", adapter.ID())
			}

			// Verify fields
			for _, s := range servers {
				if s.Name == "" {
					t.Errorf("server name is empty")
				}
				if s.ClientID != adapter.ID() {
					t.Errorf("expected clientID %s, got %s", adapter.ID(), s.ClientID)
				}
			}

			// Test backup and mutation
			backupPath := filepath.Join(tempDir, string(adapter.ID())+".bak")
			origBytes, err := os.ReadFile(pathMap[adapter.ID()])
			if err != nil {
				t.Fatalf("failed to read original fixture for %s: %v", adapter.ID(), err)
			}
			if err := os.WriteFile(backupPath, origBytes, 0600); err != nil {
				t.Fatalf("failed to write backup: %v", err)
			}

			// Apply gateway config adopting first server
			if err := adapter.ApplyGatewayConfig(string(adapter.ID()), []string{servers[0].Name}); err != nil {
				t.Fatalf("failed to apply gateway config on %s: %v", adapter.ID(), err)
			}

			// Read back mutated file
			p, _ := adapter.ConfigPath()
			mutatedData, err := os.ReadFile(p)
			if err != nil {
				t.Fatalf("failed to read mutated file: %v", err)
			}

			var mutatedMap map[string]interface{}
			if err := json.Unmarshal(mutatedData, &mutatedMap); err != nil {
				t.Fatalf("failed to unmarshal mutated file: %v", err)
			}

			mcpServers := mutatedMap["mcpServers"].(map[string]interface{})
			if _, exists := mcpServers[servers[0].Name]; exists {
				t.Errorf("adopted server %s was not removed from mcpServers", servers[0].Name)
			}
			faw, exists := mcpServers["farad-ai-wire"]
			if !exists {
				t.Errorf("farad-ai-wire was not injected into mcpServers")
			}
			fawMap := faw.(map[string]interface{})
			if fawMap["command"] != "faradaiwire" {
				t.Errorf("expected command faradaiwire, got %v", fawMap["command"])
			}

			// Test rollback
			if err := adapter.RestoreBackup(backupPath); err != nil {
				t.Fatalf("failed to restore backup: %v", err)
			}

			restoredData, err := os.ReadFile(p)
			if err != nil {
				t.Fatalf("failed to read restored file: %v", err)
			}

			if string(restoredData) != string(origBytes) {
				t.Errorf("restored file does not match original bytes")
			}
		})
	}
}

func TestReadConfigFile_EmptyAndMalformed(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		content []byte
		isDir   bool
		wantErr bool
	}{
		{
			name:    "empty_file",
			content: []byte{},
			wantErr: false,
		},
		{
			name:    "whitespace_only",
			content: []byte("   \r\n\t  "),
			wantErr: false,
		},
		{
			name:    "bom_whitespace_and_comments_only",
			content: []byte("\xEF\xBB\xBF\r\n  // Google Antigravity MCP config\r\n  /* empty */\r\n"),
			wantErr: false,
		},
		{
			name:    "truncated_json_still_errors",
			content: []byte(`{"mcpServers": {`),
			wantErr: true,
		},
		{
			name:    "non_object_json_still_errors",
			content: []byte(`[]`),
			wantErr: true,
		},
		{
			name:    "non_regular_file_rejected",
			isDir:   true,
			wantErr: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tempDir := t.TempDir()
			p := filepath.Join(tempDir, "mcp_config.json")
			if tc.isDir {
				if err := os.Mkdir(p, 0700); err != nil {
					t.Fatalf("mkdir fixture: %v", err)
				}
			} else {
				if err := os.WriteFile(p, tc.content, 0600); err != nil {
					t.Fatalf("write fixture: %v", err)
				}
			}

			adapter := NewAntigravityAdapter(p)
			servers, err := adapter.ReadServers()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %s, got nil", tc.name)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected no error for %s, got: %v", tc.name, err)
			}
			if len(servers) != 0 {
				t.Fatalf("expected 0 servers for %s, got %d", tc.name, len(servers))
			}
		})
	}
}

func TestApplyGatewayConfig_EmptyFile(t *testing.T) {
	t.Parallel()

	p := filepath.Join(t.TempDir(), "empty_mcp_config.json")
	if err := os.WriteFile(p, []byte{}, 0600); err != nil {
		t.Fatalf("write empty file: %v", err)
	}

	adapter := NewAntigravityAdapter(p)
	if err := adapter.ApplyGatewayConfig("antigravity", nil); err != nil {
		t.Fatalf("ApplyGatewayConfig on empty file failed: %v", err)
	}

	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read mutated file: %v", err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal mutated file: %v", err)
	}
	mcpServers, ok := parsed["mcpServers"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected mcpServers map in mutated config")
	}
	if _, exists := mcpServers["farad-ai-wire"]; !exists {
		t.Fatalf("expected farad-ai-wire entry in mutated config")
	}
}

func TestReadBoundedRegularFile_ExceedsLimit(t *testing.T) {
	t.Parallel()

	p := filepath.Join(t.TempDir(), "oversized.json")
	if err := os.WriteFile(p, []byte(`{"mcpServers": {"a": {}}}`), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	if _, err := readBoundedRegularFile(p, 8); err == nil {
		t.Fatalf("expected error when file exceeds byte limit, got nil")
	}
}
