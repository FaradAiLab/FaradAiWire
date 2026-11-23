package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestConfig_GetLogLevel_YAMLAndEnvOverride(t *testing.T) {
	t.Setenv("FARADAI_WIRE_LOG_LEVEL", "")

	// Default -> info
	var nilCfg *Config
	if nilCfg.GetLogLevel() != slog.LevelInfo {
		t.Fatalf("expected default LevelInfo on nil config, got %v", nilCfg.GetLogLevel())
	}

	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgFile, []byte("logging:\n  level: debug\n"), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	prov := NewYAMLConfigProvider(cfgFile)
	cfg, err := prov.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.GetLogLevel(); got != slog.LevelDebug {
		t.Fatalf("expected LevelDebug from YAML, got %v", got)
	}

	// Env override beats YAML
	t.Setenv("FARADAI_WIRE_LOG_LEVEL", "warn")
	if got := cfg.GetLogLevel(); got != slog.LevelWarn {
		t.Fatalf("expected LevelWarn from env override, got %v", got)
	}

	t.Setenv("FARADAI_WIRE_LOG_LEVEL", "ERROR")
	if got := cfg.GetLogLevel(); got != slog.LevelError {
		t.Fatalf("expected LevelError from uppercase env, got %v", got)
	}

	t.Setenv("FARADAI_WIRE_LOG_LEVEL", "not-a-valid-level")
	if got := cfg.GetLogLevel(); got != slog.LevelInfo {
		t.Fatalf("expected fallback LevelInfo for invalid env value, got %v", got)
	}
}
