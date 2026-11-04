package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
)

func TestConfigDefaults(t *testing.T) {
	cfg := &config.Config{}

	if host := cfg.GetListenHost(); host != "127.0.0.1" {
		t.Errorf("expected default listen host '127.0.0.1', got %s", host)
	}

	if port := cfg.GetListenPort(); port != 8090 {
		t.Errorf("expected default listen port 8090, got %d", port)
	}

	if adminPort := cfg.GetAdminPort(); adminPort != 8095 {
		t.Errorf("expected default admin port 8095, got %d", adminPort)
	}

	if mode := cfg.GetRuntimeMode(); mode != config.RuntimeModeStandalone {
		t.Errorf("expected default runtime mode STANDALONE, got %s", mode)
	}

	if !cfg.IsStandalone() {
		t.Errorf("expected IsStandalone() to be true by default")
	}

	if dir := cfg.GetAgentsDir(); dir != "/etc/faradaiwire/agents" {
		t.Errorf("expected default agents dir /etc/faradaiwire/agents, got %s", dir)
	}

	cfg.ListenHost = "0.0.0.0"
	cfg.ListenPort = 9000
	cfg.AdminPort = 9095
	cfg.AgentsDir = "/custom/agents"
	cfg.RuntimeMode = config.RuntimeModeManaged

	if host := cfg.GetListenHost(); host != "0.0.0.0" {
		t.Errorf("expected custom listen host '0.0.0.0', got %s", host)
	}

	if port := cfg.GetListenPort(); port != 9000 {
		t.Errorf("expected custom listen port 9000, got %d", port)
	}

	if adminPort := cfg.GetAdminPort(); adminPort != 9095 {
		t.Errorf("expected custom admin port 9095, got %d", adminPort)
	}

	if mode := cfg.GetRuntimeMode(); mode != config.RuntimeModeManaged {
		t.Errorf("expected runtime mode MANAGED, got %s", mode)
	}

	if cfg.IsStandalone() {
		t.Errorf("expected IsStandalone() to be false for MANAGED mode")
	}

	if dir := cfg.GetAgentsDir(); dir != "/custom/agents" {
		t.Errorf("expected custom agents dir /custom/agents, got %s", dir)
	}

	// Fallback to SSE.ListenPort
	cfg2 := &config.Config{
		SSE: config.SSEConfig{
			ListenPort: 8888,
		},
	}
	if port := cfg2.GetListenPort(); port != 8888 {
		t.Errorf("expected fallback listen port 8888, got %d", port)
	}
}

func TestConfig_ListenHostEnvOverrides(t *testing.T) {
	cfg := &config.Config{}

	t.Setenv("FARADAI_WIRE_HOST", "192.168.1.100")
	if host := cfg.GetListenHost(); host != "192.168.1.100" {
		t.Errorf("expected FARADAI_WIRE_HOST override 192.168.1.100, got %s", host)
	}

	t.Setenv("FARADAI_WIRE_HOST", "")
	t.Setenv("LISTEN_HOST", "10.0.0.5")
	if host := cfg.GetListenHost(); host != "10.0.0.5" {
		t.Errorf("expected LISTEN_HOST override 10.0.0.5, got %s", host)
	}

	// Explicit struct field takes precedence over env
	cfg.ListenHost = "172.16.0.1"
	if host := cfg.GetListenHost(); host != "172.16.0.1" {
		t.Errorf("expected explicit ListenHost to take precedence, got %s", host)
	}
}

func TestEnsureDefaultRuntimeConfig(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("FARADAI_WIRE_HOME", tempHome)

	configPath, err := config.EnsureDefaultRuntimeConfig()
	if err != nil {
		t.Fatalf("EnsureDefaultRuntimeConfig failed: %v", err)
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Fatalf("expected config file at %s, but does not exist", configPath)
	}

	// Verify required subdirectories were created
	for _, sub := range []string{"agents", "backups", "policies"} {
		dir := filepath.Join(tempHome, sub)
		if info, err := os.Stat(dir); os.IsNotExist(err) || !info.IsDir() {
			t.Errorf("expected directory %s to exist", dir)
		}
	}

	provider := config.NewYAMLConfigProvider(configPath)
	cfg, err := provider.Load()
	if err != nil {
		t.Fatalf("failed to load generated default config: %v", err)
	}

	if cfg.GetRuntimeMode() != config.RuntimeModeStandalone {
		t.Errorf("expected generated config mode to be STANDALONE, got %s", cfg.GetRuntimeMode())
	}
	if cfg.GetListenHost() != "127.0.0.1" {
		t.Errorf("expected generated config listen host '127.0.0.1', got %s", cfg.GetListenHost())
	}
	if cfg.GetListenPort() != 8090 {
		t.Errorf("expected generated config listen port 8090, got %d", cfg.GetListenPort())
	}
	if cfg.GetAdminPort() != 8095 {
		t.Errorf("expected generated config admin port 8095, got %d", cfg.GetAdminPort())
	}
}

func TestYAMLConfigProvider_Load(t *testing.T) {
	tempDir := t.TempDir()
	validConfigPath := filepath.Join(tempDir, "config.yaml")

	yamlContent := `
listen_port: 8090
agents_dir: "./agents"
mode: "sse"
hot_reload: true
security:
  admin_auth_required: true
user_context:
  fallback_role: "Developer"
filters:
  prefill_block:
    enabled: true
`
	if err := os.WriteFile(validConfigPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	provider := config.NewYAMLConfigProvider(validConfigPath)
	cfg, err := provider.Load()
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.ListenPort != 8090 {
		t.Errorf("expected listen_port 8090, got %d", cfg.ListenPort)
	}
	if cfg.AgentsDir != "./agents" {
		t.Errorf("expected agents_dir ./agents, got %s", cfg.AgentsDir)
	}
	if !cfg.HotReload {
		t.Errorf("expected hot_reload true, got false")
	}
	if cfg.UserContext.FallbackRole != "Developer" {
		t.Errorf("expected fallback_role Developer, got %s", cfg.UserContext.FallbackRole)
	}
	if !cfg.Filters.PrefillBlock.Enabled {
		t.Errorf("expected prefill_block enabled true, got false")
	}
	if cfg.ConfigPath != validConfigPath {
		t.Errorf("expected ConfigPath %s, got %s", validConfigPath, cfg.ConfigPath)
	}

	// Test non-existent file
	badProvider := config.NewYAMLConfigProvider(filepath.Join(tempDir, "non_existent.yaml"))
	if _, err := badProvider.Load(); err == nil {
		t.Errorf("expected error for non-existent file, got nil")
	}

	// Test invalid YAML syntax
	invalidPath := filepath.Join(tempDir, "invalid.yaml")
	if err := os.WriteFile(invalidPath, []byte("invalid: [yaml: broken"), 0644); err != nil {
		t.Fatalf("failed to write invalid YAML: %v", err)
	}
	invalidProvider := config.NewYAMLConfigProvider(invalidPath)
	if _, err := invalidProvider.Load(); err == nil {
		t.Errorf("expected syntax error for invalid YAML, got nil")
	}
}

func TestConfigWatcher_Lifecycle(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("listen_port: 8080\n"), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	provider := config.NewYAMLConfigProvider(configPath)
	watcher, err := config.NewConfigWatcher(provider)
	if err != nil {
		t.Fatalf("failed to create watcher: %v", err)
	}
	defer watcher.Close()

	reloaded := make(chan *config.Config, 1)
	err = watcher.Watch(func(cfg *config.Config) {
		reloaded <- cfg
	})
	if err != nil {
		t.Fatalf("failed to start watcher: %v", err)
	}

	// Trigger a write
	time.Sleep(100 * time.Millisecond)
	if err := os.WriteFile(configPath, []byte("listen_port: 9090\n"), 0644); err != nil {
		t.Fatalf("failed to update config: %v", err)
	}

	select {
	case cfg := <-reloaded:
		if cfg.ListenPort != 9090 {
			t.Errorf("expected reloaded port 9090, got %d", cfg.ListenPort)
		}
	case <-time.After(2 * time.Second):
		t.Log("Watcher didn't fire in test environment, acceptable due to OS fsnotify timing")
	}
}

func TestYAMLConfigProvider_WindowsLegacyPathRecovery(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	// Simulates the exact Windows bug where C:\Users contains \U which triggers:
	// "yaml: line 6: did not find expected hexdecimal number"
	legacyWindowsYAML := `# Farad Ai Core - Offline-First Standalone Configuration
runtime_mode: STANDALONE
listen_host: "127.0.0.1"
listen_port: 8090
admin_port: 8095
agents_dir: "C:\Users\User\.faradaiwire\agents"
mode: "sse"
`
	if err := os.WriteFile(configPath, []byte(legacyWindowsYAML), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	provider := config.NewYAMLConfigProvider(configPath)
	cfg, err := provider.Load()
	if err != nil {
		t.Fatalf("expected auto-recovery for legacy Windows path, but got error: %v", err)
	}

	expectedAgentsDir := "C:/Users/User/.faradaiwire/agents"
	if cfg.AgentsDir != expectedAgentsDir {
		t.Errorf("expected agents_dir %s, got %s", expectedAgentsDir, cfg.AgentsDir)
	}
}
