package mcpconfig

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
)

func TestProbeAndCompileManifest(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	agentsDir := filepath.Join(tempDir, "agents")

	servers := []DiscoveredServer{
		{
			Name:    "broken-tool",
			Command: "nonexistent-command-xyz",
			Args:    []string{},
		},
		{
			Name:    "remote-tool",
			URL:     "https://mcp.example.com/sse",
			Headers: map[string]string{"Authorization": "Bearer token"},
		},
	}

	ctx := context.Background()
	results, err := ProbeAndCompileManifest(ctx, "test-profile", servers, agentsDir, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("ProbeAndCompileManifest failed: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	// Verify broken tool handled gracefully with warning
	if results[0].Success {
		t.Errorf("expected broken tool to fail, got success")
	}
	if results[0].Warning == "" {
		t.Errorf("expected warning on broken tool, got empty")
	}

	// Verify manifest written on disk even with probe errors
	manifestPath := filepath.Join(agentsDir, "test-profile", "current", "tools_manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("failed to read tools_manifest.json: %v", err)
	}

	var tools []agent.ToolMetadata
	if err := json.Unmarshal(data, &tools); err != nil {
		t.Fatalf("failed to unmarshal tools_manifest.json: %v", err)
	}

	// Should be valid empty slice []
	if len(tools) != 0 {
		t.Errorf("expected 0 tools, got %d", len(tools))
	}
}
