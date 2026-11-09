package mcpconfig

import (
	"os"
	"path/filepath"
	"runtime"
)

// WindsurfAdapter handles configuration management for the Windsurf AI code editor.
type WindsurfAdapter struct {
	baseClientAdapter
}

// NewWindsurfAdapter initializes a new adapter, optionally accepting a custom config file path.
func NewWindsurfAdapter(customPath ...string) *WindsurfAdapter {
	var cp string
	if len(customPath) > 0 && customPath[0] != "" {
		cp = customPath[0]
	}
	return &WindsurfAdapter{
		baseClientAdapter: newBaseClientAdapter(
			ClientWindsurf,
			"Windsurf",
			func() (string, error) {
				if cp != "" {
					return expandPath(cp), nil
				}

				home, err := os.UserHomeDir()
				if err != nil {
					return "", err
				}

				if runtime.GOOS == "windows" {
					userProfile := os.Getenv("USERPROFILE")
					if userProfile != "" {
						return filepath.Join(userProfile, ".codeium", "windsurf", "mcp_config.json"), nil
					}
				}

				return filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), nil
			},
		),
	}
}
