package mcpconfig

import (
	"testing"
)

func TestMatchPreset(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		server           DiscoveredServer
		expectCustom     bool
		expectedPresetID string
	}{
		{
			name: "Direct name match github",
			server: DiscoveredServer{
				Name:    "github",
				Command: "npx",
				Args:    []string{"-y", "@modelcontextprotocol/server-github"},
			},
			expectCustom:     false,
			expectedPresetID: "github",
		},
		{
			name: "Company custom postgres server identified by args",
			server: DiscoveredServer{
				Name:    "internal-analytics-db",
				Command: "npx",
				Args:    []string{"-y", "@modelcontextprotocol/server-postgres", "postgresql://localhost/db"},
			},
			expectCustom:     false,
			expectedPresetID: "postgres",
		},
		{
			name: "Filesystem tool recommendation",
			server: DiscoveredServer{
				Name:    "local-files",
				Command: "npx",
				Args:    []string{"-y", "@modelcontextprotocol/server-filesystem", "/home"},
			},
			expectCustom:     false,
			expectedPresetID: "filesystem",
		},
		{
			name: "Unrecognized custom proprietary tool",
			server: DiscoveredServer{
				Name:    "my-corp-llm-service",
				Command: "python3",
				Args:    []string{"./scripts/mcp_server.py"},
			},
			expectCustom: true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			res := MatchPreset(tc.server, nil)
			if res.IsCustom != tc.expectCustom {
				t.Errorf("expected IsCustom=%v, got %v", tc.expectCustom, res.IsCustom)
			}

			if !tc.expectCustom {
				if res.Preset == nil || res.Preset.ID != tc.expectedPresetID {
					t.Errorf("expected preset ID=%s, got %v", tc.expectedPresetID, res.Preset)
				}
				if len(res.RecommendedDLP) == 0 {
					t.Errorf("expected recommended DLP policies, got none")
				}
			} else {
				if len(res.RecommendedDLP) == 0 {
					t.Errorf("expected default DLP recommendations for custom tool, got none")
				}
			}
		})
	}
}
