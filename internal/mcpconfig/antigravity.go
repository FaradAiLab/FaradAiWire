package mcpconfig

import (
	"fmt"
	"os"
	"path/filepath"
)

// AntigravityAdapter handles configuration management for Google Antigravity.
type AntigravityAdapter struct {
	baseClientAdapter
}

// NewAntigravityAdapter initializes a new adapter, optionally accepting a custom config file path.
func NewAntigravityAdapter(customPath ...string) *AntigravityAdapter {
	var cp string
	if len(customPath) > 0 && customPath[0] != "" {
		cp = customPath[0]
	}
	return &AntigravityAdapter{
		baseClientAdapter: newBaseClientAdapter(
			ClientAntigravity,
			"Google Antigravity",
			func() (string, error) {
				if cp != "" {
					return expandPath(cp), nil
				}
				home, err := os.UserHomeDir()
				if err != nil {
					return "", fmt.Errorf("resolve user home directory: %w", err)
				}
				return filepath.Join(home, ".gemini", "config", "mcp_config.json"), nil
			},
		),
	}
}
