package mcpconfig

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/protocol"
)

// BackupMetadata describes a persisted client configuration backup.
type BackupMetadata struct {
	ClientID   ClientID  `json:"client_id"`
	ConfigPath string    `json:"config_path"`
	BackupPath string    `json:"backup_path"`
	CreatedAt  time.Time `json:"created_at"`
	SizeBytes  int64     `json:"size_bytes"`
}

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
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("resolve user home directory: %w", err)
		}
		dir = filepath.Join(home, ".faradaiwire", "backups")
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create backup directory '%s': %w", dir, err)
	}

	return &BackupManager{baseDir: dir}, nil
}

// BackupPath returns the standard backup destination for a given client ID.
func (m *BackupManager) BackupPath(client ClientID) string {
	return filepath.Join(m.baseDir, fmt.Sprintf("%s_mcp_config.json.bak", client))
}

// HasBackup returns true if a valid backup exists for the client.
func (m *BackupManager) HasBackup(client ClientID) bool {
	fi, err := os.Stat(m.BackupPath(client))
	return err == nil && !fi.IsDir() && fi.Size() > 0
}

// CreateBackup copies the client's current configuration to the backup store with 0600 permissions.
func (m *BackupManager) CreateBackup(client ClientID, configPath string) (string, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("read source config '%s': %w", configPath, err)
	}

	dest := m.BackupPath(client)
	tmpDest := dest + ".tmp"

	// Enforce 0600 permissions to protect sensitive API keys/tokens inside configuration
	if err := os.WriteFile(tmpDest, data, 0600); err != nil {
		return "", fmt.Errorf("write backup file '%s': %w", tmpDest, err)
	}

	if err := os.Rename(tmpDest, dest); err != nil {
		_ = os.Remove(tmpDest)
		return "", fmt.Errorf("commit backup file to '%s': %w", dest, err)
	}

	return dest, nil
}

// RestoreBackup restores the client's configuration file from its backup.
func (m *BackupManager) RestoreBackup(client ClientID, configPath string) error {
	backupPath := m.BackupPath(client)
	if !m.HasBackup(client) {
		return fmt.Errorf("no active backup found for client '%s' at '%s'", client, backupPath)
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
	if protocolsDir == "" {
		protocolsDir = "./protocols"
	}
	if agentsDir == "" {
		agentsDir = "./agents"
	}

	if err := os.MkdirAll(protocolsDir, 0700); err != nil {
		return fmt.Errorf("create protocols directory: %w", err)
	}

	attachedProtocols := make([]agent.ProtocolConfig, 0, len(servers))

	for _, s := range servers {
		protoID := fmt.Sprintf("%s_%s", profileName, s.Name)
		protoID = strings.ReplaceAll(protoID, "-", "_")

		// Convert env map to slice
		envSlice := make([]string, 0, len(s.Env))
		for k, v := range s.Env {
			envSlice = append(envSlice, k+"="+v)
		}

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
			CreatedAt:    time.Now().UTC(),
			UpdatedAt:    time.Now().UTC(),
		}

		if protoStore != nil {
			if err := protoStore.Save(p); err != nil {
				return fmt.Errorf("save protocol '%s' to store: %w", protoID, err)
			}
		} else {
			// Direct file write fallback with 0600 permissions
			pPath := filepath.Join(protocolsDir, fmt.Sprintf("%s.json", protoID))
			pData, err := json.MarshalIndent(p, "", "  ")
			if err != nil {
				return fmt.Errorf("marshal protocol '%s': %w", protoID, err)
			}
			if err := os.WriteFile(pPath, pData, 0600); err != nil {
				return fmt.Errorf("write protocol '%s': %w", pPath, err)
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
	targetDir := filepath.Join(agentsDir, profileName, "current")
	if err := os.MkdirAll(targetDir, 0700); err != nil {
		return fmt.Errorf("create profile directory: %w", err)
	}

	cfgPath := filepath.Join(targetDir, "config.json")
	routeCfg := agent.RouteConfig{
		AgentID:     profileName,
		AgentName:   profileName,
		Description: fmt.Sprintf("Security Profile for %s", profileName),
		RoutingMode: "aggregated",
		Protocols:   attachedProtocols,
		RateLimit: &agent.RateLimitOverride{
			MaxBurst:   10,
			RefillRate: 2.0,
		},
		LoopProtection: &agent.LoopProtectionOverride{
			MaxRepeat:     3,
			WindowSeconds: 10,
		},
	}

	cfgBytes, err := json.MarshalIndent(routeCfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal profile config: %w", err)
	}

	if err := os.WriteFile(cfgPath, cfgBytes, 0644); err != nil {
		return fmt.Errorf("write profile config '%s': %w", cfgPath, err)
	}

	return nil
}
