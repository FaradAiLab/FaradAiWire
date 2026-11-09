package mcpconfig

import (
	"os"
	"path/filepath"
	"runtime"
)

// ClaudeDesktopAdapter handles configuration management for the Anthropic Claude Desktop application.
type ClaudeDesktopAdapter struct {
	customPath string
}

// NewClaudeDesktopAdapter initializes a new adapter, optionally accepting a custom config file path.
func NewClaudeDesktopAdapter(customPath ...string) *ClaudeDesktopAdapter {
	var cp string
	if len(customPath) > 0 && customPath[0] != "" {
		cp = customPath[0]
	}
	return &ClaudeDesktopAdapter{
		customPath: cp,
	}
}

func (a *ClaudeDesktopAdapter) ID() ClientID {
	return ClientClaudeDesktop
}

func (a *ClaudeDesktopAdapter) DisplayName() string {
	return "Claude Desktop"
}

func (a *ClaudeDesktopAdapter) ConfigPath() (string, error) {
	if a.customPath != "" {
		return expandPath(a.customPath), nil
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
}

func (a *ClaudeDesktopAdapter) Detect() bool {
	p, err := a.ConfigPath()
	if err != nil || p == "" {
		return false
	}
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

func (a *ClaudeDesktopAdapter) ReadServers() ([]DiscoveredServer, error) {
	p, err := a.ConfigPath()
	if err != nil {
		return nil, err
	}

	_, servers, _, _, err := readConfigFile(p)
	if err != nil {
		return nil, err
	}

	for i := range servers {
		servers[i].ClientID = ClientClaudeDesktop
		servers[i].ClientName = a.DisplayName()
	}

	return servers, nil
}

func (a *ClaudeDesktopAdapter) ApplyGatewayConfig(profileName string, adoptedServerNames []string) error {
	p, err := a.ConfigPath()
	if err != nil {
		return err
	}
	return mutateConfigFile(p, profileName, adoptedServerNames)
}

func (a *ClaudeDesktopAdapter) RestoreBackup(backupPath string) error {
	p, err := a.ConfigPath()
	if err != nil {
		return err
	}
	return restoreConfigFile(p, backupPath)
}
