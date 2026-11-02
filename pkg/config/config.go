// Package config provides the public configuration types, loaders, and directory
// management helpers for FaradAiWire consumers.
package config

import (
	"github.com/FaradAiLab/FaradAiWire/internal/config"
)

// Config is the root configuration structure for the FaradAiWire security proxy engine.
type Config = config.Config

// Provider defines the retrieval interface for accessing active gateway configuration models.
type Provider = config.Provider

// YAMLConfigProvider manages loading, validating, and dynamic reloading of YAML configuration files.
type YAMLConfigProvider = config.YAMLConfigProvider

const (
	// Version is the current semantic release version of FaradAiWire.
	Version = config.Version
	// RuntimeModeManaged indicates the gateway is orchestrated by a central enterprise control plane.
	RuntimeModeManaged = config.RuntimeModeManaged
	// RuntimeModeStandalone indicates offline-first, zero-egress local operation.
	RuntimeModeStandalone = config.RuntimeModeStandalone
)

// NewYAMLConfigProvider creates a YAML config provider for the given file path.
func NewYAMLConfigProvider(path string) *config.YAMLConfigProvider {
	return config.NewYAMLConfigProvider(path)
}

// EnsureDefaultRuntimeConfig ensures the ~/.faradaiwire directory structure exists and returns the config path.
func EnsureDefaultRuntimeConfig() (string, error) {
	return config.EnsureDefaultRuntimeConfig()
}

// DefaultFaradAiWireDir returns the ~/.faradaiwire directory path.
func DefaultFaradAiWireDir() string {
	return config.DefaultFaradAiWireDir()
}
