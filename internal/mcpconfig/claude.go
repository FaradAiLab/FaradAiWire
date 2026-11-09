package mcpconfig

import (
	"os"
	"path/filepath"
	"runtime"
)

// ClaudeDesktopAdapter handles configuration management for the Anthropic Claude Desktop application.
type ClaudeDesktopAdapter struct {
	baseClientAdapter
}

// NewClaudeDesktopAdapter initializes a new adapter, optionally accepting a custom config file path.
func NewClaudeDesktopAdapter(customPath ...string) *ClaudeDesktopAdapter {
	var cp string
	if len(customPath) > 0 && customPath[0] != "" {
		cp = customPath[0]
	}
	return &ClaudeDesktopAdapter{
		baseClientAdapter: newBaseClientAdapter(
			ClientClaudeDesktop,
			"Claude Desktop",
			func() (string, error) {
				if cp != "" {
					return expandPath(cp), nil
				}
				switch runtime.GOOS {
				case "darwin":
					home, err := os.UserHomeDir()
					if err != nil {
						return "", err
					}
					return filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"), nil
				case "windows":
					appData := os.Getenv("APPDATA")
					if appData == "" {
						home, _ := os.UserHomeDir()
						appData = filepath.Join(home, "AppData", "Roaming")
					}
					return filepath.Join(appData, "Claude", "claude_desktop_config.json"), nil
				default: // linux / bsd
					home, err := os.UserHomeDir()
					if err != nil {
						return "", err
					}
					return filepath.Join(home, ".config", "Claude", "claude_desktop_config.json"), nil
				}
			},
		),
	}
}
