package mcpconfig

import (
	"fmt"
	"os"
)

// baseClientAdapter provides reusable, standard implementations of ClientAdapter methods
// for MCP clients that use standard JSON/JSONC configuration files.
type baseClientAdapter struct {
	id           ClientID
	displayName  string
	pathResolver func() (string, error)
}

func newBaseClientAdapter(id ClientID, displayName string, pathResolver func() (string, error)) baseClientAdapter {
	return baseClientAdapter{
		id:           id,
		displayName:  displayName,
		pathResolver: pathResolver,
	}
}

func (b *baseClientAdapter) ID() ClientID {
	return b.id
}

func (b *baseClientAdapter) DisplayName() string {
	return b.displayName
}

func (b *baseClientAdapter) ConfigPath() (string, error) {
	return b.pathResolver()
}

func (b *baseClientAdapter) Detect() bool {
	p, err := b.ConfigPath()
	if err != nil || p == "" {
		return false
	}
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

func (b *baseClientAdapter) ReadServers() ([]DiscoveredServer, error) {
	p, err := b.ConfigPath()
	if err != nil {
		return nil, fmt.Errorf("resolve config path: %w", err)
	}

	_, servers, _, _, err := readConfigFile(p)
	if err != nil {
		return nil, fmt.Errorf("read %s config '%s': %w", b.displayName, p, err)
	}

	for i := range servers {
		servers[i].ClientID = b.id
		servers[i].ClientName = b.displayName
	}

	return servers, nil
}

func (b *baseClientAdapter) ApplyGatewayConfig(profileName string, adoptedServerNames []string) error {
	p, err := b.ConfigPath()
	if err != nil {
		return fmt.Errorf("resolve config path: %w", err)
	}
	if err := mutateConfigFile(p, profileName, adoptedServerNames); err != nil {
		return fmt.Errorf("mutate %s config '%s': %w", b.displayName, p, err)
	}
	return nil
}

func (b *baseClientAdapter) RestoreBackup(backupPath string) error {
	p, err := b.ConfigPath()
	if err != nil {
		return fmt.Errorf("resolve config path: %w", err)
	}
	if err := restoreConfigFile(p, backupPath); err != nil {
		return fmt.Errorf("restore %s config '%s' from '%s': %w", b.displayName, p, backupPath, err)
	}
	return nil
}
