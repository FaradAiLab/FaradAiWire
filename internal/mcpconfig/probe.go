package mcpconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/admin"
	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/pathguard"
)

// ProbeResult holds the outcome of an individual MCP server probe attempt.
type ProbeResult struct {
	ServerName string                   `json:"server_name"`
	Success    bool                     `json:"success"`
	ToolCount  int                      `json:"tool_count"`
	Tools      []map[string]interface{} `json:"tools,omitempty"`
	Warning    string                   `json:"warning,omitempty"`
}

// ProbeAndCompileManifest attempts to introspect a slice of adopted servers
// with a strict per-server timeout (default 5s) and compiles agents/<profile>/current/tools_manifest.json.
// If any server fails or times out, it does NOT abort the adoption; it logs a warning
// and persists whatever tools were discovered (or an empty manifest ready for dynamic capture).
func ProbeAndCompileManifest(ctx context.Context, profileName string, servers []DiscoveredServer, agentsBaseDir string, timeoutPerServer time.Duration) ([]ProbeResult, error) {
	if err := pathguard.ValidateSafeIdentifier(profileName); err != nil {
		return nil, fmt.Errorf("invalid profile identifier %q: %w", profileName, err)
	}
	if timeoutPerServer <= 0 {
		timeoutPerServer = 5 * time.Second
	}
	if agentsBaseDir == "" {
		agentsBaseDir = filepath.Join(config.DefaultFaradAiWireDir(), "agents")
	}

	results := make([]ProbeResult, 0, len(servers))
	var allTools []agent.ToolMetadata

	for _, s := range servers {
		if err := ctx.Err(); err != nil {
			return results, err
		}
		pr := ProbeResult{
			ServerName: s.Name,
		}

		if s.Command == "" && s.URL == "" {
			pr.Warning = "Server has neither command nor URL specified"
			results = append(results, pr)
			continue
		}

		// Only stdio tools can be probed via local subprocess
		if s.Command != "" {
			// Convert env map to slice
			envSlice := make([]string, 0, len(s.Env))
			for k, v := range s.Env {
				envSlice = append(envSlice, k+"="+v)
			}
			sort.Strings(envSlice)

			probeCtx, cancel := context.WithTimeout(ctx, timeoutPerServer)
			rawTools, err := admin.ProbeAndDiscoverMCPToolsStdio(probeCtx, s.Command, s.Args, envSlice)
			cancel()

			if err != nil {
				pr.Warning = fmt.Sprintf("Probe failed or timed out: %v (will auto-capture on first live execution)", err)
			} else {
				pr.Success = true
				pr.ToolCount = len(rawTools)
				pr.Tools = rawTools

				// Transform to agent.ToolMetadata format matching PersistAdoptedProtocols slugs
				protoSlug := sanitizeIdentifier(profileName, s.Name)
				protoDisplayName := fmt.Sprintf("%s (%s)", s.Name, profileName)
				for _, rt := range rawTools {
					rawName, _ := rt["name"].(string)
					if strings.TrimSpace(rawName) == "" {
						continue
					}
					desc, _ := rt["description"].(string)
					schema, _ := rt["inputSchema"].(map[string]interface{})

					cleanRaw := strings.TrimPrefix(rawName, protoSlug+"__")
					canonical := fmt.Sprintf("%s__%s", protoSlug, cleanRaw)

					allTools = append(allTools, agent.ToolMetadata{
						Name:          canonical,
						RawName:       rawName,
						CanonicalName: canonical,
						ProtocolName:  protoDisplayName,
						ProtocolID:    protoSlug,
						Description:   desc,
						InputSchema:   schema,
					})
				}
			}
		} else {
			// Remote HTTP/SSE server: mark for runtime dynamic capture
			pr.Warning = "Remote HTTP/SSE server registered; schemas will be dynamically discovered at runtime"
		}

		results = append(results, pr)
	}

	// Persist tools_manifest.json to agents/<profileName>/current/
	agentDir, err := pathguard.ResolveSandboxedPath(agentsBaseDir, profileName)
	if err != nil {
		return results, fmt.Errorf("resolve profile directory '%s': %w", profileName, err)
	}
	targetDir, err := pathguard.ResolveSandboxedPath(agentDir, "current")
	if err != nil {
		return results, fmt.Errorf("resolve profile current directory: %w", err)
	}
	if err := os.MkdirAll(targetDir, 0700); err != nil {
		return results, fmt.Errorf("create profile directory '%s': %w", targetDir, err)
	}

	manifestPath := filepath.Join(targetDir, "tools_manifest.json")

	// Merge with existing tools_manifest.json if present (fail explicitly on corrupted JSON)
	toolMap := make(map[string]agent.ToolMetadata)
	if existingData, err := os.ReadFile(manifestPath); err == nil {
		if len(bytes.TrimSpace(existingData)) > 0 {
			var existingTools []agent.ToolMetadata
			if uErr := json.Unmarshal(existingData, &existingTools); uErr != nil {
				return results, fmt.Errorf("parse existing tools manifest '%s': %w", manifestPath, uErr)
			}
			for _, t := range existingTools {
				toolMap[t.Name] = t
			}
		}
	} else if !os.IsNotExist(err) {
		return results, fmt.Errorf("read existing tools manifest '%s': %w", manifestPath, err)
	}

	for _, t := range allTools {
		toolMap[t.Name] = t
	}

	mergedTools := make([]agent.ToolMetadata, 0, len(toolMap))
	for _, t := range toolMap {
		mergedTools = append(mergedTools, t)
	}
	sort.Slice(mergedTools, func(i, j int) bool {
		return mergedTools[i].Name < mergedTools[j].Name
	})

	manifestBytes, err := json.MarshalIndent(mergedTools, "", "  ")
	if err != nil {
		return results, fmt.Errorf("marshal tools manifest: %w", err)
	}

	if err := atomicWriteFile(manifestPath, manifestBytes, 0600); err != nil {
		return results, fmt.Errorf("commit tools manifest '%s': %w", manifestPath, err)
	}

	return results, nil
}
