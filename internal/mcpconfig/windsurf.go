package mcpconfig

import (
	"os"
	"path/filepath"
	"runtime"
)

// WindsurfAdapter handles configuration management for the Windsurf AI code editor.
type WindsurfAdapter struct {
	customPath string
}

// NewWindsurfAdapter initializes a new adapter, optionally accepting a custom config file path.
func NewWindsurfAdapter(customPath ...string) *WindsurfAdapter {
	var cp string
	if len(customPath) > 0 && customPath[0] != "" {
		cp = customPath[0]
	}
	return &WindsurfAdapter{
		customPath: cp,
	}
}

func (a *WindsurfAdapter) ID() ClientID {
	return ClientWindsurf
}

func (a *WindsurfAdapter) DisplayName() string {
	return "Windsurf"
}

func (a *WindsurfAdapter) ConfigPath() (string, error) {
	if a.customPath != "" {
		return expandPath(a.customPath), nil
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
}

func (a *WindsurfAdapter) Detect() bool {
	p, err := a.ConfigPath()
	if err != nil || p == "" {
		return false
	}
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

func (a *WindsurfAdapter) ReadServers() ([]DiscoveredServer, error) {
	p, err := a.ConfigPath()
	if err != nil {
		return nil, err
	}

	_, servers, _, _, err := readConfigFile(p)
	if err != nil {
		return nil, err
	}

	for i := range servers {
		servers[i].ClientID = ClientWindsurf
		servers[i].ClientName = a.DisplayName()
	}

	return servers, nil
}

func (a *WindsurfAdapter) ApplyGatewayConfig(profileName string, adoptedServerNames []string) error {
	p, err := a.ConfigPath()
	if err != nil {
		return err
	}
	return mutateConfigFile(p, profileName, adoptedServerNames)
}

func (a *WindsurfAdapter) RestoreBackup(backupPath string) error {
	p, err := a.ConfigPath()
	if err != nil {
		return err
	}
	return restoreConfigFile(p, backupPath)
}
