package mcpconfig

import (
	"os"
	"path/filepath"
	"runtime"
)

// CursorAdapter handles configuration management for the Cursor AI code editor.
type CursorAdapter struct {
	customPath string
}

// NewCursorAdapter initializes a new adapter, optionally accepting a custom config file path.
func NewCursorAdapter(customPath ...string) *CursorAdapter {
	var cp string
	if len(customPath) > 0 && customPath[0] != "" {
		cp = customPath[0]
	}
	return &CursorAdapter{
		customPath: cp,
	}
}

func (a *CursorAdapter) ID() ClientID {
	return ClientCursor
}

func (a *CursorAdapter) DisplayName() string {
	return "Cursor"
}

func (a *CursorAdapter) ConfigPath() (string, error) {
	if a.customPath != "" {
		return expandPath(a.customPath), nil
	}

	// 1. Check current directory workspace .cursor/mcp.json
	localPath := filepath.Join(".", ".cursor", "mcp.json")
	if fi, err := os.Stat(localPath); err == nil && !fi.IsDir() {
		return filepath.Abs(localPath)
	}

	// 2. Global user home ~/.cursor/mcp.json
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	if runtime.GOOS == "windows" {
		userProfile := os.Getenv("USERPROFILE")
		if userProfile != "" {
			return filepath.Join(userProfile, ".cursor", "mcp.json"), nil
		}
	}

	return filepath.Join(home, ".cursor", "mcp.json"), nil
}

func (a *CursorAdapter) Detect() bool {
	p, err := a.ConfigPath()
	if err != nil || p == "" {
		return false
	}
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

func (a *CursorAdapter) ReadServers() ([]DiscoveredServer, error) {
	p, err := a.ConfigPath()
	if err != nil {
		return nil, err
	}

	_, servers, _, _, err := readConfigFile(p)
	if err != nil {
		return nil, err
	}

	for i := range servers {
		servers[i].ClientID = ClientCursor
		servers[i].ClientName = a.DisplayName()
	}

	return servers, nil
}

func (a *CursorAdapter) ApplyGatewayConfig(profileName string, adoptedServerNames []string) error {
	p, err := a.ConfigPath()
	if err != nil {
		return err
	}
	return mutateConfigFile(p, profileName, adoptedServerNames)
}

func (a *CursorAdapter) RestoreBackup(backupPath string) error {
	p, err := a.ConfigPath()
	if err != nil {
		return err
	}
	return restoreConfigFile(p, backupPath)
}
