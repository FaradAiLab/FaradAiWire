package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// YAMLConfigProvider implements Provider for local YAML files.
type YAMLConfigProvider struct {
	filePath string
}

// NewYAMLConfigProvider creates a new YAMLConfigProvider for the given file path.
// If filePath is empty, it attempts to discover ./config.yaml, then ~/.faradaiwire/config.yaml,
// or auto-initializes the default standalone configuration.
func NewYAMLConfigProvider(filePath string) *YAMLConfigProvider {
	if filePath == "" {
		if _, err := os.Stat("config.yaml"); err == nil {
			filePath = "config.yaml"
		} else {
			defaultPath := filepath.Join(DefaultFaradAiWireDir(), "config.yaml")
			if _, err := os.Stat(defaultPath); err == nil {
				filePath = defaultPath
			} else {
				if createdPath, err := EnsureDefaultRuntimeConfig(); err == nil {
					filePath = createdPath
				} else {
					filePath = "config.yaml"
				}
			}
		}
	}
	return &YAMLConfigProvider{filePath: filePath}
}

// Load reads and parses the YAML configuration file.
func (y *YAMLConfigProvider) Load() (*Config, error) {
	data, err := os.ReadFile(y.filePath)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	cfg.ConfigPath = y.filePath

	// Ensure runtime mode defaults to STANDALONE if unspecified
	if cfg.RuntimeMode == "" {
		cfg.RuntimeMode = RuntimeModeStandalone
	}

	return &cfg, nil
}

// Watch satisfies the Provider interface. Active filesystem monitoring is performed via ConfigWatcher.
func (y *YAMLConfigProvider) Watch(onChange func(*Config)) error {
	return nil
}

// Save writes the updated configuration back to the YAML file.
func (y *YAMLConfigProvider) Save(cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(y.filePath, data, 0644)
}

// GetFilePath returns the path to the active configuration file.
func (y *YAMLConfigProvider) GetFilePath() string {
	return y.filePath
}
