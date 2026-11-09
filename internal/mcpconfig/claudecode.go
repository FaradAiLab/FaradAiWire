package mcpconfig

import (
	"fmt"
	"os"
	"path/filepath"
)

// ClaudeCodeAdapter handles configuration management for the Claude Code CLI tool.
type ClaudeCodeAdapter struct {
	baseClientAdapter
}

// NewClaudeCodeAdapter initializes a new adapter, optionally accepting a custom config file path.
func NewClaudeCodeAdapter(customPath ...string) *ClaudeCodeAdapter {
	var cp string
	if len(customPath) > 0 && customPath[0] != "" {
		cp = customPath[0]
	}
	return &ClaudeCodeAdapter{
		baseClientAdapter: newBaseClientAdapter(
			ClientClaudeCode,
			"Claude Code",
			func() (string, error) {
				if cp != "" {
					return expandPath(cp), nil
				}
				home, err := os.UserHomeDir()
				if err != nil {
					return "", fmt.Errorf("resolve user home directory: %w", err)
				}
				return filepath.Join(home, ".claude.json"), nil
			},
		),
	}
}
