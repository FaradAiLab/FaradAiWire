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

// NewCursorAdapter initializes an adapter for Cursor's global user config (~/.cursor/mcp.json)
// or a custom explicit config path. Workspace .cursor/mcp.json files require NewCursorWorkspaceAdapter.
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

// NewCursorWorkspaceAdapter initializes a Cursor adapter explicitly scoped to a workspace's .cursor/mcp.json.
func NewCursorWorkspaceAdapter(workDir ...string) *CursorAdapter {
	var wd string
	if len(workDir) > 0 && workDir[0] != "" {
		wd = workDir[0]
	}
	return &CursorAdapter{
		baseClientAdapter: newBaseClientAdapter(
			ClientCursorWorkspace,
			"Cursor (Workspace)",
			func() (string, error) {
				if wd != "" {
					return filepath.Abs(filepath.Join(expandPath(wd), ".cursor", "mcp.json"))
				}
				return filepath.Abs(filepath.Join(".", ".cursor", "mcp.json"))
			},
		),
	}
}
