package mcpconfig

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/pathguard"
	"github.com/FaradAiLab/FaradAiWire/internal/protocol"
)

// BackupManager orchestrates pristine client config backups and safe restoration.
type BackupManager struct {
	baseDir string
}

// NewBackupManager creates a BackupManager rooted at baseDir (defaults to ~/.faradaiwire/backups).
func NewBackupManager(baseDir ...string) (*BackupManager, error) {
	var dir string
	if len(baseDir) > 0 && baseDir[0] != "" {
		dir = baseDir[0]
	} else {
		dir = filepath.Join(config.DefaultFaradAiWireDir(), "backups")
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create backup directory '%s': %w", dir, err)
	}

	return &BackupManager{baseDir: dir}, nil
}

// BackupPath returns the legacy single-file backup path for client.
func (m *BackupManager) BackupPath(client ClientID) string {
	return filepath.Join(m.baseDir, fmt.Sprintf("%s_mcp_config.json.bak", client))
}

func canonicalBackupKey(configPath string) string {
	cleaned := filepath.Clean(configPath)
	if abs, err := filepath.Abs(cleaned); err == nil {
		cleaned = abs
	}
	if realPath, err := filepath.EvalSymlinks(cleaned); err == nil {
		cleaned = realPath
	}
	sum := sha256.Sum256([]byte(cleaned))
	return hex.EncodeToString(sum[:4])
}

// BackupPathForConfig returns an isolated backup path keyed by both client ID and canonical config path
// so global and workspace configs (or multiple repositories) never overwrite each other's pristine backup.
func (m *BackupManager) BackupPathForConfig(client ClientID, configPath string) string {
	if strings.TrimSpace(configPath) == "" {
		return m.BackupPath(client)
	}
	return filepath.Join(m.baseDir, fmt.Sprintf("%s_%s_mcp_config.json.bak", client, canonicalBackupKey(configPath)))
}

// HasBackup returns true if any valid backup (hashed or legacy single-file) exists for the client.
func (m *BackupManager) HasBackup(client ClientID) bool {
	if fi, err := os.Stat(m.BackupPath(client)); err == nil && !fi.IsDir() {
		return true
	}
	if err := pathguard.ValidateSafeIdentifier(string(client)); err != nil {
		return false
	}
	pattern := filepath.Join(m.baseDir, fmt.Sprintf("%s_*_mcp_config.json.bak", client))
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return false
	}
	for _, match := range matches {
		if fi, statErr := os.Stat(match); statErr == nil && !fi.IsDir() {
			return true
		}
	}
	return false
}

// HasBackupForConfig reports whether a backup exists for the exact configPath (or legacy fallback path).
func (m *BackupManager) HasBackupForConfig(client ClientID, configPath string) bool {
	if fi, err := os.Stat(m.BackupPathForConfig(client, configPath)); err == nil && !fi.IsDir() {
		return true
	}
	fi, err := os.Stat(m.BackupPath(client))
	return err == nil && !fi.IsDir()
}

// sanitizeIdentifier converts a profile and server name into a deterministic, collision-safe slug
// combining a human-readable prefix with a short SHA-256 discriminator so distinct punctuation/separators
// (e.g., "a_b"+"c" vs "a"+"b-c") never overwrite each other's protocol or schema records.
func sanitizeIdentifier(profile, name string) string {
	raw := fmt.Sprintf("%s_%s", profile, name)
	var b strings.Builder
	b.Grow(len(raw))
	lastWasUnderscore := false
	for _, r := range raw {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastWasUnderscore = false
		} else if !lastWasUnderscore {
			b.WriteRune('_')
			lastWasUnderscore = true
		}
	}
	res := strings.Trim(b.String(), "_")
	if res == "" {
		res = "mcp_tool"
	}
	sum := sha256.Sum256([]byte(profile + "\x00" + name))
	return filepath.Base(res) + "_" + hex.EncodeToString(sum[:3])
}

// CreateBackup copies the client's current configuration to the backup store with 0600 permissions.
// If a pristine backup already exists for this config path, it is preserved without overwrite so rollback always restores original state.
func (m *BackupManager) CreateBackup(client ClientID, configPath string) (string, error) {
	if err := pathguard.ValidateSafeIdentifier(string(client)); err != nil {
		return "", fmt.Errorf("invalid client identifier %q: %w", client, err)
	}
	dest := m.BackupPathForConfig(client, configPath)
	if _, err := pathguard.ResolveSandboxedPath(m.baseDir, filepath.Base(dest)); err != nil {
		return "", fmt.Errorf("invalid backup path: %w", err)
	}

	if fi, err := os.Stat(dest); err == nil && !fi.IsDir() {
		return dest, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("read source config '%s': %w", configPath, err)
	}

	// Enforce 0600 permissions and atomic rename to protect sensitive API keys/tokens
	if err := atomicWriteFile(dest, data, 0600); err != nil {
		return "", fmt.Errorf("commit backup file to '%s': %w", dest, err)
	}

	return dest, nil
}

// RestoreBackup restores the client's configuration file from its path-isolated backup (falling back to legacy backup filename).
func (m *BackupManager) RestoreBackup(client ClientID, configPath string) error {
	if err := pathguard.ValidateSafeIdentifier(string(client)); err != nil {
		return fmt.Errorf("invalid client identifier %q: %w", client, err)
	}
	backupPath := m.BackupPathForConfig(client, configPath)
	if _, err := pathguard.ResolveSandboxedPath(m.baseDir, filepath.Base(backupPath)); err != nil {
		return fmt.Errorf("invalid backup path: %w", err)
	}
	if fi, err := os.Stat(backupPath); err != nil || fi.IsDir() {
		legacy := m.BackupPath(client)
		if lfi, lErr := os.Stat(legacy); lErr == nil && !lfi.IsDir() {
			backupPath = legacy
		} else {
			return fmt.Errorf("no active backup found for client '%s' at '%s'", client, backupPath)
		}
	}

	return restoreConfigFile(configPath, backupPath)
}

// PersistAdoptedProtocols saves the adopted servers as Tool Sources in protocols/
// and registers them as attached protocols in the client's Security Profile (agents/{profile}/current/config.json).
func PersistAdoptedProtocols(
	profileName string,
	servers []DiscoveredServer,
	protoStore protocol.Store,
	protocolsDir string,
	agentsDir string,
) error {
	if err := pathguard.ValidateSafeIdentifier(profileName); err != nil {
		return fmt.Errorf("invalid profile identifier %q: %w", profileName, err)
	}
	if protocolsDir == "" {
		protocolsDir = filepath.Join(config.DefaultFaradAiWireDir(), "protocols")
	}
	if agentsDir == "" {
		agentsDir = filepath.Join(config.DefaultFaradAiWireDir(), "agents")
	}

	if err := os.MkdirAll(protocolsDir, 0700); err != nil {
		return fmt.Errorf("create protocols directory: %w", err)
	}

	attachedProtocols := make([]agent.ProtocolConfig, 0, len(servers))

	for _, s := range servers {
		protoID := sanitizeIdentifier(profileName, s.Name)

		// Convert env map to slice
		envSlice := make([]string, 0, len(s.Env))
		for k, v := range s.Env {
			envSlice = append(envSlice, k+"="+v)
		}
		sort.Strings(envSlice)

		protoType := "stdio"
		urlOrCmd := s.Command
		if s.URL != "" {
			protoType = "sse"
			urlOrCmd = s.URL
		}

		p := &protocol.Protocol{
			ID:           protoID,
			Name:         fmt.Sprintf("%s (%s)", s.Name, profileName),
			Description:  fmt.Sprintf("Imported from %s MCP configuration", s.ClientName),
			Type:         protoType,
			Command:      s.Command,
			Args:         s.Args,
			Env:          envSlice,
			URLOrCommand: urlOrCmd,
			Headers:      s.Headers,
		}

		if protoStore != nil {
			if err := protoStore.Save(p); err != nil {
				return fmt.Errorf("save protocol '%s' to store: %w", protoID, err)
			}
		} else {
			pPath, pErr := pathguard.ResolveSandboxedPath(protocolsDir, fmt.Sprintf("%s.json", protoID))
			if pErr != nil {
				return fmt.Errorf("resolve protocol path '%s': %w", protoID, pErr)
			}
			pData, err := json.MarshalIndent(p, "", "  ")
			if err != nil {
				return fmt.Errorf("marshal protocol '%s': %w", protoID, err)
			}
			if err := atomicWriteFile(pPath, pData, 0600); err != nil {
				return fmt.Errorf("commit protocol '%s': %w", pPath, err)
			}
		}

		attachedProtocols = append(attachedProtocols, agent.ProtocolConfig{
			ID:           protoID,
			Name:         p.Name,
			Type:         protoType,
			URLOrCommand: urlOrCmd,
			Command:      s.Command,
			Args:         s.Args,
			Env:          envSlice,
			Headers:      s.Headers,
		})
	}

	// Create/update agents/{profileName}/current/config.json
	agentDir, err := pathguard.ResolveSandboxedPath(agentsDir, profileName)
	if err != nil {
		return fmt.Errorf("resolve profile directory '%s': %w", profileName, err)
	}
	targetDir, err := pathguard.ResolveSandboxedPath(agentDir, "current")
	if err != nil {
		return fmt.Errorf("resolve profile current directory: %w", err)
	}
	if err := os.MkdirAll(targetDir, 0700); err != nil {
		return fmt.Errorf("create profile directory: %w", err)
	}

	cfgPath := filepath.Join(targetDir, "config.json")
	routeCfg := agent.RouteConfig{
		AgentID:     profileName,
		AgentName:   profileName,
		Description: fmt.Sprintf("Security Profile for %s", profileName),
		RoutingMode: "aggregated",
		RateLimit: &agent.RateLimitOverride{
			MaxBurst:   10,
			RefillRate: 2.0,
		},
		LoopProtection: &agent.LoopProtectionOverride{
			MaxRepeat:     3,
			WindowSeconds: 10,
		},
	}

	// Merge with existing configuration if present (fail explicitly on corrupted JSON)
	protocolMap := make(map[string]agent.ProtocolConfig)
	if existingData, err := os.ReadFile(cfgPath); err == nil {
		if len(bytes.TrimSpace(existingData)) > 0 {
			var existingCfg agent.RouteConfig
			if uErr := json.Unmarshal(existingData, &existingCfg); uErr != nil {
				return fmt.Errorf("parse existing profile config '%s': %w", cfgPath, uErr)
			}
			routeCfg = existingCfg
			for _, ep := range existingCfg.Protocols {
				protocolMap[ep.ID] = ep
			}
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read existing profile config '%s': %w", cfgPath, err)
	}

	// Add/update with newly attached protocols
	for _, ap := range attachedProtocols {
		protocolMap[ap.ID] = ap
	}

	mergedProtocols := make([]agent.ProtocolConfig, 0, len(protocolMap))
	for _, p := range protocolMap {
		mergedProtocols = append(mergedProtocols, p)
	}
	sort.Slice(mergedProtocols, func(i, j int) bool {
		return mergedProtocols[i].ID < mergedProtocols[j].ID
	})
	routeCfg.Protocols = mergedProtocols

	cfgBytes, err := json.MarshalIndent(routeCfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal profile config: %w", err)
	}

	if err := atomicWriteFile(cfgPath, cfgBytes, 0600); err != nil {
		return fmt.Errorf("commit profile config '%s': %w", cfgPath, err)
	}

	return nil
}
