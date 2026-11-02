package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/pathguard"
)

// Resolver defines the read-only contract for querying and routing agent configurations and tool manifests.
type Resolver interface {
	GetAgentConfig(agentName string) (*RouteConfig, error)
	GetAgentManifest(agentName string) ([]ToolMetadata, error)
	GetDefaultAgent() (*RouteConfig, error)
	ResolveToolProtocol(agentName, toolName string) (*ToolTargetInfo, error)
	ResolveTargetURLFromPath(path string, defaultTargetURL string) (string, error)
	ListAgents() ([]string, error)
}

// Manager defines the administrative mutator contract for managing agent configurations, manifests, and archives.
type Manager interface {
	SaveAgentConfig(agentName string, cfg *RouteConfig) error
	DeleteAgent(agentName string) error
	SaveAgentManifest(agentName string, tools interface{}) error
	ListAgentArchives(agentName string) ([]string, error)
	RollbackAgent(agentName, timestamp string) error
	ArchiveAgentCurrent(agentName string) error
	ClearCache()
}

// Repository combines Resolver and Manager contracts (Interface Segregation Principle).
type Repository interface {
	Resolver
	Manager
}

// FSRepository implements Repository with filesystem lookups, pathguard sandboxing, and in-memory caching.
type FSRepository struct {
	baseDirs      []string
	cacheMu       sync.RWMutex
	writeMu       sync.Mutex
	cfgCache      map[string]*RouteConfig
	manifestCache map[string][]ToolMetadata
}

// NewFSRepository initializes an FSRepository.
func NewFSRepository(baseDirs ...string) *FSRepository {
	var validDirs []string
	for _, d := range baseDirs {
		trimmed := strings.TrimSpace(d)
		if trimmed != "" {
			validDirs = append(validDirs, trimmed)
		}
	}
	// Always append standard default locations as fallbacks
	validDirs = append(validDirs, "/etc/faradaiwire/agents", "./agents")

	return &FSRepository{
		baseDirs:      validDirs,
		cfgCache:      make(map[string]*RouteConfig),
		manifestCache: make(map[string][]ToolMetadata),
	}
}

// ClearCache flushes in-memory caches.
func (r *FSRepository) ClearCache() {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	r.cfgCache = make(map[string]*RouteConfig)
	r.manifestCache = make(map[string][]ToolMetadata)
}

// GetAgentConfig retrieves the RouteConfig for a given agent.
func (r *FSRepository) GetAgentConfig(agentName string) (*RouteConfig, error) {
	if err := pathguard.ValidateSafeIdentifier(agentName); err != nil {
		return nil, fmt.Errorf("%w: invalid agent identifier '%s': %v", ErrInvalidIdentifier, agentName, err)
	}

	r.cacheMu.RLock()
	if cached, ok := r.cfgCache[agentName]; ok && cached != nil {
		r.cacheMu.RUnlock()
		return cached, nil
	}
	r.cacheMu.RUnlock()

	var data []byte
	var foundPath string

	for _, baseDir := range r.baseDirs {
		if _, statErr := os.Stat(baseDir); statErr != nil {
			continue
		}

		// Try 1: agents/{agent}/current/config.json
		p1, err1 := pathguard.ResolveSandboxedPath(baseDir, filepath.Join(agentName, "current", "config.json"))
		if err1 == nil {
			if d, readErr := os.ReadFile(p1); readErr == nil {
				data = d
				foundPath = p1
				break
			}
		}

		// Try 2: agents/{agent}/config.json
		p2, err2 := pathguard.ResolveSandboxedPath(baseDir, filepath.Join(agentName, "config.json"))
		if err2 == nil {
			if d, readErr := os.ReadFile(p2); readErr == nil {
				data = d
				foundPath = p2
				break
			}
		}
	}

	if len(data) == 0 {
		return nil, NewAgentNotFoundError(agentName)
	}

	var cfg RouteConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse agent config at '%s': %w", foundPath, err)
	}

	if cfg.AgentName == "" {
		cfg.AgentName = agentName
	}
	if cfg.RoutingMode == "" {
		cfg.RoutingMode = "aggregated"
	}

	r.cacheMu.Lock()
	r.cfgCache[agentName] = &cfg
	r.cacheMu.Unlock()

	return &cfg, nil
}

// GetAgentManifest retrieves the tool catalog for a given agent from tools_manifest.json.
func (r *FSRepository) GetAgentManifest(agentName string) ([]ToolMetadata, error) {
	if err := pathguard.ValidateSafeIdentifier(agentName); err != nil {
		return nil, fmt.Errorf("%w: invalid agent identifier '%s': %v", ErrInvalidIdentifier, agentName, err)
	}

	r.cacheMu.RLock()
	if cached, ok := r.manifestCache[agentName]; ok {
		r.cacheMu.RUnlock()
		return cached, nil
	}
	r.cacheMu.RUnlock()

	var data []byte

	for _, baseDir := range r.baseDirs {
		if _, statErr := os.Stat(baseDir); statErr != nil {
			continue
		}

		p1, err1 := pathguard.ResolveSandboxedPath(baseDir, filepath.Join(agentName, "current", "tools_manifest.json"))
		if err1 == nil {
			if d, readErr := os.ReadFile(p1); readErr == nil {
				data = d
				break
			}
		}

		p2, err2 := pathguard.ResolveSandboxedPath(baseDir, filepath.Join(agentName, "tools_manifest.json"))
		if err2 == nil {
			if d, readErr := os.ReadFile(p2); readErr == nil {
				data = d
				break
			}
		}
	}

	if len(data) == 0 {
		return nil, ErrManifestNotFound
	}

	var tools []ToolMetadata
	if err := json.Unmarshal(data, &tools); err != nil {
		return nil, fmt.Errorf("failed to parse tools manifest for agent '%s': %w", agentName, err)
	}

	r.cacheMu.Lock()
	r.manifestCache[agentName] = tools
	r.cacheMu.Unlock()

	return tools, nil
}

func buildToolTargetInfo(proto *ProtocolConfig, toolName string) *ToolTargetInfo {
	raw := toolName
	if strings.Contains(toolName, "__") {
		parts := strings.SplitN(toolName, "__", 2)
		raw = parts[1]
	}
	return &ToolTargetInfo{
		ProtocolID:   proto.ID,
		ProtocolName: proto.Name,
		TargetURL:    proto.URLOrCommand,
		ToolName:     toolName,
		RawToolName:  raw,
		Type:         proto.Type,
		Command:      proto.GetCommand(),
		Args:         proto.Args,
		Env:          proto.Env,
		AuthToken:    proto.AuthToken,
		Headers:      proto.Headers,
		TargetScope:  proto.TargetScope,
		AllowedTools: proto.AllowedTools,
	}
}

// GetDefaultAgent resolves the default agent route configuration.
// It checks FARADAI_WIRE_DEFAULT_AGENT environment variable, falls back to "default",
// or selects the first available agent alphabetically from the repository.
func (r *FSRepository) GetDefaultAgent() (*RouteConfig, error) {
	if defEnv := strings.TrimSpace(os.Getenv("FARADAI_WIRE_DEFAULT_AGENT")); defEnv != "" {
		cfg, err := r.GetAgentConfig(defEnv)
		if err == nil && cfg != nil {
			return cfg, nil
		}
	}

	// Try "default"
	if cfg, err := r.GetAgentConfig("default"); err == nil && cfg != nil {
		return cfg, nil
	}

	// Scan available agents
	agents, err := r.ListAgents()
	if err == nil && len(agents) > 0 {
		sort.Strings(agents)
		for _, name := range agents {
			if cfg, err := r.GetAgentConfig(name); err == nil && cfg != nil {
				return cfg, nil
			}
		}
	}

	return nil, NewAgentNotFoundError("default")
}

// ResolveToolProtocol finds the appropriate upstream target MCP endpoint for a given tool name.
func (r *FSRepository) ResolveToolProtocol(agentName, toolName string) (*ToolTargetInfo, error) {
	if toolName == "" {
		return nil, nil
	}

	agentCfg, err := r.GetAgentConfig(agentName)
	if err != nil {
		return nil, err
	}

	if len(agentCfg.Protocols) == 0 {
		return nil, NewProtocolNotFoundError(agentName, "default")
	}

	// Single protocol shortcut
	if len(agentCfg.Protocols) == 1 && (agentCfg.Protocols[0].URLOrCommand != "" || agentCfg.Protocols[0].Command != "") {
		return buildToolTargetInfo(&agentCfg.Protocols[0], toolName), nil
	}

	// Lookup via tools manifest
	tools, mErr := r.GetAgentManifest(agentName)
	if mErr == nil {
		for _, t := range tools {
			proto := agentCfg.FindProtocol(t.ProtocolID)
			if proto == nil {
				proto = agentCfg.FindProtocol(t.ProtocolName)
			}
			protoSlug := ""
			if proto != nil {
				protoSlug = GetProtocolSlug(proto)
			} else {
				if t.ProtocolID != "" && !strings.Contains(t.ProtocolID, " ") {
					protoSlug = strings.ToLower(t.ProtocolID)
				} else if t.ProtocolName != "" {
					protoSlug = strings.ToLower(strings.ReplaceAll(t.ProtocolName, " ", "_"))
				}
			}

			raw := t.RawName
			if raw == "" {
				if strings.Contains(t.Name, "__") {
					parts := strings.SplitN(t.Name, "__", 2)
					raw = parts[1]
				} else {
					raw = t.Name
				}
			}

			prefixedName := ""
			if protoSlug != "" && raw != "" {
				cleanRaw := strings.TrimPrefix(raw, protoSlug+"__")
				prefixedName = fmt.Sprintf("%s__%s", protoSlug, cleanRaw)
			}

			matches := strings.EqualFold(t.Name, toolName) ||
				strings.EqualFold(t.RawName, toolName) ||
				strings.EqualFold(t.CanonicalName, toolName) ||
				(prefixedName != "" && strings.EqualFold(prefixedName, toolName))

			if matches {
				if proto != nil && (proto.URLOrCommand != "" || proto.Command != "") {
					target := buildToolTargetInfo(proto, toolName)
					if raw != "" {
						target.RawToolName = raw
					}
					return target, nil
				}
			}
		}
	}

	// Prefix-based resolution (e.g. database__query_users -> database or context7__resolve-library-id -> context7)
	if strings.Contains(toolName, "__") {
		parts := strings.SplitN(toolName, "__", 2)
		protoPrefix := parts[0]
		rawTool := parts[1]
		proto := agentCfg.FindProtocol(protoPrefix)
		if proto != nil && (proto.URLOrCommand != "" || proto.Command != "") {
			target := buildToolTargetInfo(proto, toolName)
			target.RawToolName = rawTool
			return target, nil
		}
	}

	// Fallback to first configured protocol
	first := agentCfg.Protocols[0]
	if first.URLOrCommand != "" || first.Command != "" {
		return buildToolTargetInfo(&first, toolName), nil
	}

	return nil, NewProtocolNotFoundError(agentName, "first-protocol")
}

// ResolveTargetURLFromPath resolves the target MCP URL based on the request path and configured agent routing mode.
func (r *FSRepository) ResolveTargetURLFromPath(path string, defaultTargetURL string) (string, error) {
	p := strings.TrimPrefix(path, "/sse")
	p = strings.TrimPrefix(p, "/mcp")
	p = strings.Trim(p, "/")
	p = strings.TrimSuffix(p, "/message")
	p = strings.Trim(p, "/")

	if p == "" {
		return defaultTargetURL, nil
	}

	parts := strings.Split(p, "/")
	if len(parts) == 1 {
		agentName := parts[0]
		agentCfg, err := r.GetAgentConfig(agentName)
		if err != nil {
			return "", err
		}

		if agentCfg.IsDirect() {
			return "", NewRoutingModeViolationError(agentName, "DIRECT", fmt.Sprintf("Please specify target MCP in path: '/sse/%s/{mcp_name}'", agentName))
		}

		if len(agentCfg.Protocols) > 0 && agentCfg.Protocols[0].URLOrCommand != "" {
			return agentCfg.Protocols[0].URLOrCommand, nil
		}
		return defaultTargetURL, nil
	} else if len(parts) >= 2 {
		agentName := parts[0]
		mcpName := parts[1]

		agentCfg, err := r.GetAgentConfig(agentName)
		if err != nil {
			return "", err
		}

		if agentCfg.IsAggregated() {
			return "", NewRoutingModeViolationError(agentName, "AGGREGATED", fmt.Sprintf("Access using single path: '/sse/%s'", agentName))
		}

		proto := agentCfg.FindProtocol(mcpName)
		if proto != nil && proto.URLOrCommand != "" {
			return proto.URLOrCommand, nil
		}
		return "", NewProtocolNotFoundError(agentName, mcpName)
	}

	return defaultTargetURL, nil
}

// ListAgents scans configured base directories and returns a unique list of available agent names.
func (r *FSRepository) ListAgents() ([]string, error) {
	agentsSet := make(map[string]bool)

	for _, baseDir := range r.baseDirs {
		entries, err := os.ReadDir(baseDir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			if err := pathguard.ValidateSafeIdentifier(name); err == nil {
				agentsSet[name] = true
			}
		}
	}

	var res []string
	for k := range agentsSet {
		res = append(res, k)
	}
	return res, nil
}

// SaveAgentManifest writes the tools manifest for an agent and refreshes the manifest cache.
func (r *FSRepository) SaveAgentManifest(agentName string, tools interface{}) error {
	if err := pathguard.ValidateSafeIdentifier(agentName); err != nil {
		return fmt.Errorf("%w: invalid agent identifier '%s': %v", ErrInvalidIdentifier, agentName, err)
	}

	data, err := json.MarshalIndent(tools, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal tools manifest: %w", err)
	}

	var saved bool
	for _, baseDir := range r.baseDirs {
		if _, statErr := os.Stat(baseDir); statErr != nil {
			continue
		}

		currentDir, cErr := pathguard.ResolveSandboxedPath(baseDir, filepath.Join(agentName, "current"))
		if cErr == nil {
			if _, statErr := os.Stat(currentDir); statErr == nil {
				manifestPath, mErr := pathguard.ResolveSandboxedPath(currentDir, "tools_manifest.json")
				if mErr == nil {
					if writeErr := os.WriteFile(manifestPath, data, 0644); writeErr == nil {
						saved = true
						break
					}
				}
			}
		}

		agentDir, aErr := pathguard.ResolveSandboxedPath(baseDir, agentName)
		if aErr == nil {
			if _, statErr := os.Stat(agentDir); statErr == nil {
				manifestPath, mErr := pathguard.ResolveSandboxedPath(agentDir, "tools_manifest.json")
				if mErr == nil {
					if writeErr := os.WriteFile(manifestPath, data, 0644); writeErr == nil {
						saved = true
						break
					}
				}
			}
		}
	}

	if !saved {
		return fmt.Errorf("failed to save tools manifest for agent '%s': no writable directory found", agentName)
	}

	r.cacheMu.Lock()
	delete(r.manifestCache, agentName)
	r.cacheMu.Unlock()
	return nil
}

// ListAgentArchives returns the snapshot archive timestamps available for an agent.
func (r *FSRepository) ListAgentArchives(agentName string) ([]string, error) {
	if err := pathguard.ValidateSafeIdentifier(agentName); err != nil {
		return nil, fmt.Errorf("%w: invalid agent identifier '%s': %v", ErrInvalidIdentifier, agentName, err)
	}

	for _, baseDir := range r.baseDirs {
		if _, statErr := os.Stat(baseDir); statErr != nil {
			continue
		}

		archiveDir, err := pathguard.ResolveSandboxedPath(baseDir, filepath.Join(agentName, "archive"))
		if err != nil {
			continue
		}

		entries, readErr := os.ReadDir(archiveDir)
		if readErr != nil {
			continue
		}

		var archives []string
		for _, entry := range entries {
			if entry.IsDir() {
				if vErr := pathguard.ValidateSafeIdentifier(entry.Name()); vErr == nil {
					archives = append(archives, entry.Name())
				}
			}
		}
		sort.Slice(archives, func(i, j int) bool {
			return archives[i] > archives[j]
		})
		return archives, nil
	}
	return []string{}, nil
}

// RollbackAgent restores the configuration snapshot from archive/{timestamp} into current/.
func (r *FSRepository) RollbackAgent(agentName, timestamp string) error {
	if err := pathguard.ValidateSafeIdentifier(agentName); err != nil {
		return fmt.Errorf("%w: invalid agent identifier '%s': %v", ErrInvalidIdentifier, agentName, err)
	}
	if err := pathguard.ValidateSafeIdentifier(timestamp); err != nil {
		return fmt.Errorf("%w: invalid timestamp identifier '%s': %v", ErrInvalidIdentifier, timestamp, err)
	}

	r.writeMu.Lock()
	defer r.writeMu.Unlock()

	for _, baseDir := range r.baseDirs {
		if _, statErr := os.Stat(baseDir); statErr != nil {
			continue
		}

		archiveDir, aErr := pathguard.ResolveSandboxedPath(baseDir, filepath.Join(agentName, "archive", timestamp))
		if aErr != nil {
			continue
		}
		currentDir, cErr := pathguard.ResolveSandboxedPath(baseDir, filepath.Join(agentName, "current"))
		if cErr != nil {
			continue
		}

		entries, readErr := os.ReadDir(archiveDir)
		if readErr != nil {
			continue
		}

		for _, entry := range entries {
			if !entry.IsDir() {
				if fErr := pathguard.ValidateSafeIdentifier(entry.Name()); fErr != nil {
					continue
				}
				src, sErr := pathguard.ResolveSandboxedPath(archiveDir, entry.Name())
				dst, dErr := pathguard.ResolveSandboxedPath(currentDir, entry.Name())
				if sErr != nil || dErr != nil {
					continue
				}
				data, readErr := os.ReadFile(src)
				if readErr == nil {
					_ = os.WriteFile(dst, data, 0644)
				}
			}
		}

		r.cacheMu.Lock()
		delete(r.cfgCache, agentName)
		delete(r.manifestCache, agentName)
		r.cacheMu.Unlock()
		return nil
	}
	return fmt.Errorf("archive snapshot '%s' for agent '%s' not found", timestamp, agentName)
}

// ArchiveAgentCurrent snapshots all files in the agent's current/ directory into archive/<timestamp>/.
// If the current/ directory does not exist or has no files, it safely returns nil.
func (r *FSRepository) ArchiveAgentCurrent(agentName string) error {
	if err := pathguard.ValidateSafeIdentifier(agentName); err != nil {
		return fmt.Errorf("%w: invalid agent identifier '%s': %v", ErrInvalidIdentifier, agentName, err)
	}

	// Locate base directory containing agent
	var targetBaseDir string
	for _, baseDir := range r.baseDirs {
		if _, statErr := os.Stat(baseDir); statErr != nil {
			continue
		}
		candidate, err := pathguard.ResolveSandboxedPath(baseDir, agentName)
		if err == nil {
			if fi, err := os.Stat(candidate); err == nil && fi.IsDir() {
				targetBaseDir = baseDir
				break
			}
		}
	}
	if targetBaseDir == "" {
		return nil
	}

	agentDir, err := pathguard.ResolveSandboxedPath(targetBaseDir, agentName)
	if err != nil {
		return fmt.Errorf("failed to resolve agent directory: %w", err)
	}
	currentDir, err := pathguard.ResolveSandboxedPath(agentDir, "current")
	if err != nil {
		return fmt.Errorf("failed to resolve current directory: %w", err)
	}

	if _, err := os.Stat(currentDir); os.IsNotExist(err) {
		return nil
	}

	entries, err := os.ReadDir(currentDir)
	if err != nil || len(entries) == 0 {
		return nil
	}

	var filesToCopy []os.DirEntry
	for _, entry := range entries {
		if !entry.IsDir() {
			filesToCopy = append(filesToCopy, entry)
		}
	}
	if len(filesToCopy) == 0 {
		return nil
	}

	archiveBase, err := pathguard.ResolveSandboxedPath(agentDir, "archive")
	if err != nil {
		return fmt.Errorf("failed to resolve archive directory: %w", err)
	}

	timestamp := time.Now().UTC().Format("20060102T150405Z")
	snapshotDir := filepath.Join(archiveBase, timestamp)
	for i := 1; ; i++ {
		if _, statErr := os.Stat(snapshotDir); os.IsNotExist(statErr) {
			break
		}
		snapshotDir = filepath.Join(archiveBase, fmt.Sprintf("%s_%d", timestamp, i))
	}

	if err := os.MkdirAll(snapshotDir, 0755); err != nil {
		return fmt.Errorf("failed to create snapshot directory '%s': %w", snapshotDir, err)
	}

	for _, entry := range filesToCopy {
		srcPath := filepath.Join(currentDir, entry.Name())
		dstPath := filepath.Join(snapshotDir, entry.Name())
		data, readErr := os.ReadFile(srcPath)
		if readErr != nil {
			continue
		}
		if writeErr := os.WriteFile(dstPath, data, 0644); writeErr != nil {
			return fmt.Errorf("failed to write archive file '%s': %w", dstPath, writeErr)
		}
	}

	return nil
}

// SaveAgentConfig saves or updates the agent's route configuration in current/config.json.
// If an existing configuration is present, it archives a snapshot to archive/<timestamp>/
// and flushes all caches.
func (r *FSRepository) SaveAgentConfig(agentName string, cfg *RouteConfig) error {
	if err := pathguard.ValidateSafeIdentifier(agentName); err != nil {
		return fmt.Errorf("%w: invalid agent identifier '%s': %v", ErrInvalidIdentifier, agentName, err)
	}
	if cfg == nil {
		return errors.New("cannot save nil agent configuration")
	}

	r.writeMu.Lock()
	defer r.writeMu.Unlock()

	if cfg.AgentName == "" {
		cfg.AgentName = agentName
	}
	if cfg.AgentID == "" {
		cfg.AgentID = agentName
	}
	if cfg.RoutingMode == "" {
		cfg.RoutingMode = "aggregated"
	}

	// 1. Locate base directory (existing or first writable)
	var targetBaseDir string
	for _, baseDir := range r.baseDirs {
		if _, statErr := os.Stat(baseDir); statErr != nil {
			continue
		}
		candidate, err := pathguard.ResolveSandboxedPath(baseDir, agentName)
		if err == nil {
			if fi, err := os.Stat(candidate); err == nil && fi.IsDir() {
				targetBaseDir = baseDir
				break
			}
		}
	}
	if targetBaseDir == "" {
		for _, baseDir := range r.baseDirs {
			if err := os.MkdirAll(baseDir, 0755); err == nil {
				targetBaseDir = baseDir
				break
			}
		}
	}
	if targetBaseDir == "" {
		return fmt.Errorf("no writable base directory available to save agent '%s'", agentName)
	}

	// 2. Prepare paths
	agentDir, err := pathguard.ResolveSandboxedPath(targetBaseDir, agentName)
	if err != nil {
		return fmt.Errorf("failed to resolve agent directory: %w", err)
	}
	currentDir, err := pathguard.ResolveSandboxedPath(agentDir, "current")
	if err != nil {
		return fmt.Errorf("failed to resolve current directory: %w", err)
	}
	if err := os.MkdirAll(currentDir, 0755); err != nil {
		return fmt.Errorf("failed to create agent current directory '%s': %w", currentDir, err)
	}

	// 3. Snapshot archiving if previous current state exists
	_ = r.ArchiveAgentCurrent(agentName)

	configFile, err := pathguard.ResolveSandboxedPath(currentDir, "config.json")
	if err != nil {
		return fmt.Errorf("failed to resolve config.json path: %w", err)
	}

	// 4. Atomically commit config.json
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal agent config: %w", err)
	}

	tmpFile, err := os.CreateTemp(currentDir, "config.json.tmp.*")
	if err != nil {
		return fmt.Errorf("failed to create temporary agent config: %w", err)
	}
	tmpName := tmpFile.Name()
	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("failed to write temporary agent config: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("failed to close temporary agent config: %w", err)
	}
	if err := os.Rename(tmpName, configFile); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("failed to atomically commit agent config: %w", err)
	}

	// 5. Flush caches
	r.cacheMu.Lock()
	delete(r.cfgCache, agentName)
	delete(r.manifestCache, agentName)
	r.cacheMu.Unlock()

	return nil
}

// DeleteAgent removes the agent directory and flushes caches.
func (r *FSRepository) DeleteAgent(agentName string) error {
	if err := pathguard.ValidateSafeIdentifier(agentName); err != nil {
		return fmt.Errorf("%w: invalid agent identifier '%s': %v", ErrInvalidIdentifier, agentName, err)
	}

	r.writeMu.Lock()
	defer r.writeMu.Unlock()

	var deleted bool
	for _, baseDir := range r.baseDirs {
		agentDir, err := pathguard.ResolveSandboxedPath(baseDir, agentName)
		if err != nil {
			continue
		}
		if fi, err := os.Stat(agentDir); err == nil && fi.IsDir() {
			if err := os.RemoveAll(agentDir); err == nil {
				deleted = true
				break
			} else {
				return fmt.Errorf("failed to delete agent directory '%s': %w", agentDir, err)
			}
		}
	}

	if !deleted {
		return NewAgentNotFoundError(agentName)
	}

	r.cacheMu.Lock()
	delete(r.cfgCache, agentName)
	delete(r.manifestCache, agentName)
	r.cacheMu.Unlock()

	return nil
}

