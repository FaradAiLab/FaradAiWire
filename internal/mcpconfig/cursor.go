package mcpconfig

import (
	"os"
	"path/filepath"
	"runtime"
)

// CursorAdapter handles configuration management for the Cursor AI code editor.
type CursorAdapter struct {
	baseClientAdapter
}

// NewCursorAdapter initializes a new adapter, optionally accepting a custom config file path.
func NewCursorAdapter(customPath ...string) *CursorAdapter {
	var cp string
	if len(customPath) > 0 && customPath[0] != "" {
		cp = customPath[0]
	}
	return &CursorAdapter{
		baseClientAdapter: newBaseClientAdapter(
			ClientCursor,
			"Cursor",
			func() (string, error) {
				if cp != "" {
					return expandPath(cp), nil
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
			},
		),
	}
}
