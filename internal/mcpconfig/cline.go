package mcpconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// ClineAdapter handles configuration management for the Cline extension and CLI.
type ClineAdapter struct {
	baseClientAdapter
}

// NewClineAdapter initializes a new adapter, optionally accepting a custom config file path.
func NewClineAdapter(customPath ...string) *ClineAdapter {
	var cp string
	if len(customPath) > 0 && customPath[0] != "" {
		cp = customPath[0]
	}
	return &ClineAdapter{
		baseClientAdapter: newBaseClientAdapter(
			ClientCline,
			"Cline",
			func() (string, error) {
				if cp != "" {
					return expandPath(cp), nil
				}

				primary, err := resolveClinePrimaryPath()
				if err != nil {
					return "", err
				}

				if fi, err := os.Stat(primary); err == nil && !fi.IsDir() {
					return primary, nil
				}

				// Check fallback CLI path: ~/.cline/data/settings/cline_mcp_settings.json
				home, err := os.UserHomeDir()
				if err == nil {
					cliPath := filepath.Join(home, ".cline", "data", "settings", "cline_mcp_settings.json")
					if fi, err := os.Stat(cliPath); err == nil && !fi.IsDir() {
						return cliPath, nil
					}
				}

				return primary, nil
			},
		),
	}
}

func resolveClinePrimaryPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user home directory: %w", err)
	}

	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"), nil
	case "windows":
		appData := os.Getenv("APPDATA")
		if appData == "" {
			appData = filepath.Join(home, "AppData", "Roaming")
		}
		return filepath.Join(appData, "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"), nil
	default: // linux / bsd
		return filepath.Join(home, ".config", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"), nil
	}
}
