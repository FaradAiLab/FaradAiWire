package mcpconfig

import (
	"encoding/json"
	"testing"
)

func TestStripCommentsAndTrailingCommas(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		input       string
		wantErr     bool
		validateObj func(t *testing.T, data map[string]interface{})
	}{
		{
			name:  "Clean JSON without comments",
			input: `{"key": "value", "num": 42}`,
			validateObj: func(t *testing.T, data map[string]interface{}) {
				if data["key"] != "value" || data["num"] != float64(42) {
					t.Errorf("unexpected content: %v", data)
				}
			},
		},
		{
			name: "Single-line comments",
			input: `{
				// Primary server
				"server": "github",
				// Port setting
				"port": 8090
			}`,
			validateObj: func(t *testing.T, data map[string]interface{}) {
				if data["server"] != "github" {
					t.Errorf("expected server github, got %v", data["server"])
				}
			},
		},
		{
			name: "Block comments and trailing commas",
			input: `{
				/* Multi-line
				   configuration block */
				"mcpServers": {
					"filesystem": {
						"command": "npx",
						"args": ["-y", "mcp-filesystem",],
					},
				},
			}`,
			validateObj: func(t *testing.T, data map[string]interface{}) {
				servers, ok := data["mcpServers"].(map[string]interface{})
				if !ok {
					t.Fatalf("expected mcpServers map, got %T", data["mcpServers"])
				}
				fs, ok := servers["filesystem"].(map[string]interface{})
				if !ok {
					t.Fatalf("expected filesystem server, got %T", servers["filesystem"])
				}
				if fs["command"] != "npx" {
					t.Errorf("expected command npx, got %v", fs["command"])
				}
				args := fs["args"].([]interface{})
				if len(args) != 2 || args[1] != "mcp-filesystem" {
					t.Errorf("unexpected args: %v", args)
				}
			},
		},
		{
			name: "URLs with slashes inside string literals should not be stripped",
			input: `{
				"url": "http://localhost:8090/sse//test/*not_comment*/",
				"desc": "Contains // and /* inside quotes"
			}`,
			validateObj: func(t *testing.T, data map[string]interface{}) {
				if data["url"] != "http://localhost:8090/sse//test/*not_comment*/" {
					t.Errorf("url literal was corrupted: %v", data["url"])
				}
				if data["desc"] != "Contains // and /* inside quotes" {
					t.Errorf("desc literal was corrupted: %v", data["desc"])
				}
			},
		},
		{
			name:    "Unterminated string error",
			input:   `{"key": "unterminated`,
			wantErr: true,
		},
		{
			name:    "Unterminated block comment error",
			input:   `{"key": "val"} /* unfinished comment`,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			res, err := StripCommentsAndTrailingCommas([]byte(tc.input))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			var parsed map[string]interface{}
			if err := json.Unmarshal(res, &parsed); err != nil {
				t.Fatalf("failed to parse cleaned JSON: %v\nResult was:\n%s", err, string(res))
			}

			if tc.validateObj != nil {
				tc.validateObj(t, parsed)
			}
		})
	}
}

func BenchmarkStripCommentsAndTrailingCommas(b *testing.B) {
	input := []byte(`{
		// Primary development MCP
		"mcpServers": {
			"filesystem": {
				"command": "npx",
				/* multi-line comment */
				"args": ["-y", "@modelcontextprotocol/server-filesystem", "/path",],
				"env": {
					"DEBUG": "true",
				},
			},
		},
	}`)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := StripCommentsAndTrailingCommas(input)
		if err != nil {
			b.Fatal(err)
		}
	}
}
