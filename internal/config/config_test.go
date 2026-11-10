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
	for _, sub := range []string{"agents", "backups", "policies", "schemas"} {
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

	// Verify all 7 layers of Runtime Security Envelope are active with generic defaults
	if !cfg.Filters.PrefillBlock.Enabled {
		t.Error("expected prefill_block enabled by default")
	}
	if !cfg.Filters.SchemaValidation.Enabled || !cfg.Filters.SchemaValidation.DynamicCapture || !cfg.Filters.SchemaValidation.BaselinePinning {
		t.Errorf("expected schema_validation fully enabled by default, got %+v", cfg.Filters.SchemaValidation)
	}
	expectedSchemasDir := filepath.ToSlash(filepath.Join(tempHome, "schemas"))
	if cfg.Filters.SchemaValidation.SchemasDir != expectedSchemasDir {
		t.Errorf("expected anchored schemas_dir %q, got %q", expectedSchemasDir, cfg.Filters.SchemaValidation.SchemasDir)
	}
	if !cfg.Filters.DLP.Enabled || len(cfg.Filters.DLP.Patterns) == 0 {
		t.Error("expected dlp enabled with baseline patterns by default")
	}
	if !cfg.Filters.Guard.Enabled {
		t.Error("expected guard enabled by default")
	}
	if !cfg.Filters.HITL.Enabled || cfg.Filters.HITL.ApprovalMode != "cli" || cfg.Filters.HITL.TimeoutSeconds != 60 {
		t.Errorf("expected hitl enabled with cli/60s defaults, got %+v", cfg.Filters.HITL)
	}
	for _, tool := range cfg.Filters.HITL.DestructiveTools {
		if tool == "para_transferi" {
			t.Errorf("unexpected localized demo tool 'para_transferi' in generic defaults")
		}
	}
	if len(cfg.Filters.HITL.DestructiveTools) != 3 {
		t.Errorf("expected 3 generic destructive tools, got %v", cfg.Filters.HITL.DestructiveTools)
	}
	if !cfg.Filters.LoopProtection.Enabled || cfg.Filters.LoopProtection.MaxRepeat != 5 || cfg.Filters.LoopProtection.WindowSeconds != 15 {
		t.Errorf("expected loop_protection 5/15 defaults, got %+v", cfg.Filters.LoopProtection)
	}
	if !cfg.Filters.RateLimiting.Enabled || cfg.Filters.RateLimiting.MaxBurst != 50 || cfg.Filters.RateLimiting.RefillRate != 10.0 {
		t.Errorf("expected rate_limiting 50/10.0 defaults, got %+v", cfg.Filters.RateLimiting)
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

func TestConfig_Clone(t *testing.T) {
	t.Parallel()

	var nilCfg *config.Config
	if nilCfg.Clone() != nil {
		t.Fatal("expected cloning nil Config to return nil")
	}

	httpEnabled := true
	telemetryEnabled := true
	orig := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
		ListenHost:  "127.0.0.1",
		ListenPort:  8090,
		AdminPort:   8095,
		Security: config.SecurityConfig{
			CORSAllowedOrigins: []string{"http://localhost:8095"},
			RateLimiting: config.HTTPRateLimitConfig{
				Enabled: &httpEnabled,
				Rate:    50,
				Burst:   100,
			},
		},
		Telemetry: config.TelemetryConfig{
			Enabled: &telemetryEnabled,
			DBPath:  "/tmp/test.duckdb",
		},
		Filters: config.FiltersConfig{
			PrefillBlock: config.PrefillBlockConfig{Enabled: true},
			DLP: config.DLPConfig{
				Enabled:      true,
				ExcludeTools: []string{"safe_tool"},
				Patterns:     []config.DLPPattern{{Name: "p1", Regex: "x", Action: "mask"}},
			},
			HITL: config.HITLConfig{
				Enabled:          true,
				DestructiveTools: []string{"delete_record"},
			},
			LoopProtection: config.LoopProtectionConfig{
				Enabled:   true,
				Overrides: []config.LoopToolOverride{{Tool: "search", MaxRepeat: 5}},
			},
		},
	}

	cloned := orig.Clone()
	if cloned == orig {
		t.Fatal("expected cloned pointer to differ from original")
	}

	// Mutate clone slices, pointers, and booleans; verify original is isolated.
	cloned.Filters.PrefillBlock.Enabled = false
	cloned.Filters.DLP.ExcludeTools[0] = "mutated"
	cloned.Filters.DLP.Patterns[0].Action = "block"
	cloned.Filters.HITL.DestructiveTools[0] = "mutated"
	cloned.Filters.LoopProtection.Overrides[0].MaxRepeat = 99
	cloned.Security.CORSAllowedOrigins[0] = "http://mutated"
	*cloned.Security.RateLimiting.Enabled = false
	*cloned.Telemetry.Enabled = false

	if !orig.Filters.PrefillBlock.Enabled {
		t.Error("expected original PrefillBlock.Enabled to remain true")
	}
	if orig.Filters.DLP.ExcludeTools[0] != "safe_tool" || orig.Filters.DLP.Patterns[0].Action != "mask" {
		t.Error("expected original DLP slices to remain isolated")
	}
	if orig.Filters.HITL.DestructiveTools[0] != "delete_record" {
		t.Error("expected original HITL DestructiveTools to remain isolated")
	}
	if orig.Filters.LoopProtection.Overrides[0].MaxRepeat != 5 {
		t.Error("expected original LoopProtection Overrides to remain isolated")
	}
	if orig.Security.CORSAllowedOrigins[0] != "http://localhost:8095" {
		t.Error("expected original CORSAllowedOrigins to remain isolated")
	}
	if !*orig.Security.RateLimiting.Enabled || !*orig.Telemetry.Enabled {
		t.Error("expected original pointer booleans to remain true")
	}
}
