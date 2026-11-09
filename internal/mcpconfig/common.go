package mcpconfig

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// expandHome expands leading '~' or Windows environment variables into absolute path.
func expandPath(p string) string {
	if p == "" {
		return ""
	}

	if strings.HasPrefix(p, "~") {
		home, err := os.UserHomeDir()
		if err == nil {
			p = filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}

	if runtime.GOOS == "windows" {
		p = os.ExpandEnv(p)
	}

	return filepath.Clean(p)
}

// rawServerDef captures typical server fields found in client MCP JSON files.
type rawServerDef struct {
	Command   string            `json:"command,omitempty"`
	Args      []string          `json:"args,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
	URL       string            `json:"url,omitempty"`
	ServerURL string            `json:"serverUrl,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
}

// rawClientConfig represents the root JSON structure common to MCP IDEs.
type rawClientConfig struct {
	MCPServers map[string]rawServerDef `json:"mcpServers"`
	// Preserve other arbitrary top-level fields
	ExtraFields map[string]interface{} `json:"-"`
}

// readConfigFile reads and deserializes a client JSON/JSONC configuration file.
func readConfigFile(path string) (map[string]interface{}, []DiscoveredServer, ClientID, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("read config file '%s': %w", path, err)
	}

	cleaned, err := StripCommentsAndTrailingCommas(data)
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("strip comments in '%s': %w", path, err)
	}

	var rawMap map[string]interface{}
	if err := json.Unmarshal(cleaned, &rawMap); err != nil {
		return nil, nil, "", "", fmt.Errorf("unmarshal config '%s': %w", path, err)
	}

	var servers []DiscoveredServer
	mcpServersRaw, ok := rawMap["mcpServers"].(map[string]interface{})
	if ok {
		for name, serverVal := range mcpServersRaw {
			// Skip if it's already farad-ai-wire
			if strings.HasPrefix(name, "farad-ai") {
				continue
			}

			serverMap, sOk := serverVal.(map[string]interface{})
			if !sOk {
				continue
			}

			ds := DiscoveredServer{
				Name: name,
			}

			if cmd, cOk := serverMap["command"].(string); cOk {
				ds.Command = cmd
			}
			if argsRaw, aOk := serverMap["args"].([]interface{}); aOk {
				for _, arg := range argsRaw {
					if argStr, ok := arg.(string); ok {
						ds.Args = append(ds.Args, argStr)
					}
				}
			}
			if envRaw, eOk := serverMap["env"].(map[string]interface{}); eOk {
				ds.Env = make(map[string]string, len(envRaw))
				for k, v := range envRaw {
					if vStr, ok := v.(string); ok {
						ds.Env[k] = vStr
					}
				}
			}
			if urlStr, uOk := serverMap["url"].(string); uOk {
				ds.URL = urlStr
			} else if sUrlStr, suOk := serverMap["serverUrl"].(string); suOk {
				ds.URL = sUrlStr
			}
			if headersRaw, hOk := serverMap["headers"].(map[string]interface{}); hOk {
				ds.Headers = make(map[string]string, len(headersRaw))
				for k, v := range headersRaw {
					if vStr, ok := v.(string); ok {
						ds.Headers[k] = vStr
					}
				}
			}

			servers = append(servers, ds)
		}
	}

	return rawMap, servers, "", "", nil
}

// mutateConfigFile updates the target file by removing adoptedServerNames and injecting farad-ai-wire.
func mutateConfigFile(configPath string, profileName string, adoptedServerNames []string) error {
	rawMap, _, _, _, err := readConfigFile(configPath)
	if err != nil {
		return err
	}

	if rawMap == nil {
		rawMap = make(map[string]interface{})
	}

	mcpServers, ok := rawMap["mcpServers"].(map[string]interface{})
	if !ok {
		mcpServers = make(map[string]interface{})
		rawMap["mcpServers"] = mcpServers
	}

	adoptedSet := make(map[string]struct{}, len(adoptedServerNames))
	for _, name := range adoptedServerNames {
		adoptedSet[name] = struct{}{}
	}

	// Remove adopted servers from active mcpServers
	for name := range mcpServers {
		if _, shouldRemove := adoptedSet[name]; shouldRemove {
			delete(mcpServers, name)
		}
	}

	// Inject FaradAiWire single connection
	mcpServers["farad-ai-wire"] = map[string]interface{}{
		"command": "faradaiwire",
		"args":    []string{"connect", "--profile", profileName},
	}

	// Write formatted JSON back to file
	formatted, err := json.MarshalIndent(rawMap, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal mutated config: %w", err)
	}

	// Atomic write via temp file
	tmpPath := configPath + ".faw_tmp"
	if err := os.WriteFile(tmpPath, formatted, 0644); err != nil {
		return fmt.Errorf("write temp config: %w", err)
	}

	if err := os.Rename(tmpPath, configPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename temp config to '%s': %w", configPath, err)
	}

	return nil
}

// restoreConfigFile restores configPath directly from backupPath.
func restoreConfigFile(configPath, backupPath string) error {
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("read backup '%s': %w", backupPath, err)
	}

	tmpPath := configPath + ".faw_restore_tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("write restore tmp file: %w", err)
	}

	if err := os.Rename(tmpPath, configPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename restore file: %w", err)
	}

	return nil
}
