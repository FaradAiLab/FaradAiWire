package mcpconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// RooCodeAdapter handles configuration management for the Roo Code (Roo-Cline) extension.
type RooCodeAdapter struct {
	baseClientAdapter
}

// NewRooCodeAdapter initializes a new adapter, optionally accepting a custom config file path.
func NewRooCodeAdapter(customPath ...string) *RooCodeAdapter {
	var cp string
	if len(customPath) > 0 && customPath[0] != "" {
		cp = customPath[0]
	}
	return &RooCodeAdapter{
		baseClientAdapter: newBaseClientAdapter(
			ClientRooCode,
			"Roo Code",
			func() (string, error) {
				if cp != "" {
					return expandPath(cp), nil
				}

				home, err := os.UserHomeDir()
				if err != nil {
					return "", fmt.Errorf("resolve user home directory: %w", err)
				}

				switch runtime.GOOS {
				case "darwin":
					return filepath.Join(home, "Library", "Application Support", "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "mcp_settings.json"), nil
				case "windows":
					appData := os.Getenv("APPDATA")
					if appData == "" {
						appData = filepath.Join(home, "AppData", "Roaming")
					}
					return filepath.Join(appData, "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "mcp_settings.json"), nil
				default: // linux / bsd
					return filepath.Join(home, ".config", "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "mcp_settings.json"), nil
				}
			},
		),
	}
}
