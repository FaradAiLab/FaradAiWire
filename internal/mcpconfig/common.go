package mcpconfig

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
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

// isSelfReference checks if an MCP server definition points to FaradAiWire itself,
// preventing infinite forwarding loops, circular recursion, and duplicate re-adoption cycles.
func isSelfReference(name string, cmd string, args []string, url string) bool {
	// 1. Check server name
	lowerName := strings.ToLower(name)
	if strings.HasPrefix(lowerName, "farad-ai") ||
		strings.HasPrefix(lowerName, "faradai") ||
		strings.Contains(lowerName, "faradaiwire") ||
		strings.Contains(lowerName, "faradaimcp") {
		return true
	}

	// 2. Check binary command
	if cmd != "" {
		lowerCmd := strings.ToLower(filepath.Base(cmd))
		if lowerCmd == "faradaiwire" || strings.HasPrefix(lowerCmd, "faradaiwire") {
			return true
		}
	}

	// 3. Check CLI arguments (e.g. wrapper script invoking connect subcommand)
	for _, arg := range args {
		if arg == "connect" {
			for _, a := range args {
				if a == "--profile" || a == "-profile" {
					return true
				}
			}
		}
	}

	// 4. Check URL / Ingress loopback port (default gateway port 8090)
	if url != "" {
		lowerURL := strings.ToLower(url)
		if strings.Contains(lowerURL, "127.0.0.1:8090") ||
			strings.Contains(lowerURL, "localhost:8090") ||
			strings.Contains(lowerURL, ":8090/sse") ||
			strings.Contains(lowerURL, ":8090/mcp") {
			return true
		}
	}

	return false
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

			// Skip self-references to FaradAiWire (by name, binary command, args, or port 8090)
			if isSelfReference(ds.Name, ds.Command, ds.Args, ds.URL) {
				continue
			}

			servers = append(servers, ds)
		}
	}

	// Sort servers deterministically by name
	sort.Slice(servers, func(i, j int) bool {
		return servers[i].Name < servers[j].Name
	})

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

	// Clean up any legacy, duplicate or alternate self-references (e.g. "faradaimcp")
	// to ensure only one clean canonical "farad-ai-wire" bridge remains.
	for name, val := range mcpServers {
		if name == "farad-ai-wire" {
			continue
		}
		if sMap, ok := val.(map[string]interface{}); ok {
			cmd, _ := sMap["command"].(string)
			url, _ := sMap["url"].(string)
			var args []string
			if aRaw, aOk := sMap["args"].([]interface{}); aOk {
				for _, a := range aRaw {
					if aStr, ok := a.(string); ok {
						args = append(args, aStr)
					}
				}
			}
			if isSelfReference(name, cmd, args, url) {
				delete(mcpServers, name)
			}
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

	// Preserve existing file permissions if present; fallback to 0600
	perm := os.FileMode(0600)
	if fi, err := os.Stat(configPath); err == nil {
		perm = fi.Mode().Perm()
	}

	// Atomic write via temp file
	tmpPath := configPath + ".faw_tmp"
	if err := os.WriteFile(tmpPath, formatted, perm); err != nil {
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

	// Preserve existing file permissions if present; fallback to 0600
	perm := os.FileMode(0600)
	if fi, err := os.Stat(configPath); err == nil {
		perm = fi.Mode().Perm()
	} else if fi, err := os.Stat(backupPath); err == nil {
		perm = fi.Mode().Perm()
	}

	tmpPath := configPath + ".faw_restore_tmp"
	if err := os.WriteFile(tmpPath, data, perm); err != nil {
		return fmt.Errorf("write restore tmp file: %w", err)
	}

	if err := os.Rename(tmpPath, configPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename restore file: %w", err)
	}

	return nil
}
