package config

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultListenPort is the canonical gateway MCP ingress port (amendment to ADR-0025).
	DefaultListenPort = 19410
	// DefaultAdminPort is the canonical administrative console & API port (amendment to ADR-0025).
	DefaultAdminPort = 19415
	// DefaultWebDevPort is the canonical Vite dev server port for the standalone Web Studio.
	DefaultWebDevPort = 19418
)

// ErrNoConfigProvider is returned when Reload is invoked without a backing config.Provider.
var ErrNoConfigProvider = errors.New("no configuration provider configured for reload")

const (
	// RuntimeModeStandalone indicates offline-first zero-egress operation without SaaS dependencies.
	RuntimeModeStandalone = "STANDALONE"
	// RuntimeModeManaged indicates corporate managed mode linked to an upstream enterprise gateway/SaaS.
	RuntimeModeManaged = "MANAGED"
)

// Provider defines the abstract contract for loading configuration.
// It allows FaradAiWire to read configuration locally or pull from external/SaaS APIs.
type Provider interface {
	Load() (*Config, error)
	Watch(onChange func(*Config)) error
}

// Config is the top-level configuration structure for FaradAiWire.
type Config struct {
	mu                        sync.RWMutex      `yaml:"-" json:"-"`
	RuntimeMode               string            `yaml:"runtime_mode" json:"runtime_mode"`   // "STANDALONE" or "MANAGED"
	AllowStdio                *bool             `yaml:"allow_stdio,omitempty" json:"allow_stdio,omitempty"`
	ListenHost                string            `yaml:"listen_host" json:"listen_host"`     // Interface host to bind HTTP listeners (default 127.0.0.1)
	ListenPort                int               `yaml:"listen_port"`                        // Multi-agent gateway listen port
	AgentsDir                 string            `yaml:"agents_dir"`                         // Root directory containing agent subdirectories
	ProtocolsDir              string            `yaml:"protocols_dir" json:"protocols_dir"` // Root directory containing protocol definition files (defaults to ~/.faradaiwire/protocols)
	Mode                      string            `yaml:"mode"`                               // "stdio" or "sse"
	Stdio                     StdioConfig       `yaml:"stdio"`
	SSE                       SSEConfig         `yaml:"sse"`
	Filters                   FiltersConfig     `yaml:"filters"`
	AuditLog                  AuditLogConfig    `yaml:"audit_log"`
	Telemetry                 TelemetryConfig   `yaml:"telemetry" json:"telemetry"`
	HotReload                 bool              `yaml:"hot_reload"`
	PrivateKeyPath            string            `yaml:"private_key_path"`
	AdminHost                 string            `yaml:"admin_host" json:"admin_host"` // Interface host to bind Admin HTTP server (defaults to 127.0.0.1 per ADR-0028)
	AdminPort                 int               `yaml:"admin_port"`
	AdminTLS                  AdminTLSConfig    `yaml:"admin_tls"`
	UserContext               UserContextConfig `yaml:"user_context"`
	Security                  SecurityConfig    `yaml:"security"`
	AutoSyncMCP               bool              `yaml:"auto_sync_mcp"`
	AutoUpdatePolicies        bool              `yaml:"auto_update_policies"`
	PollIntervalSeconds       int               `yaml:"poll_interval_seconds" json:"poll_interval_seconds"`
	PolicyPollIntervalSeconds int               `yaml:"policy_poll_interval_seconds" json:"policy_poll_interval_seconds"`
	ToolSyncIntervalSeconds   int               `yaml:"tool_sync_interval_seconds" json:"tool_sync_interval_seconds"`
	ConfigPath                string            `yaml:"-"`
}

// GetRuntimeMode returns the active runtime mode (defaults to STANDALONE).
func (c *Config) GetRuntimeMode() string {
	if c == nil {
		return RuntimeModeStandalone
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if strings.EqualFold(strings.TrimSpace(c.RuntimeMode), RuntimeModeManaged) {
		return RuntimeModeManaged
	}
	if strings.EqualFold(strings.TrimSpace(c.RuntimeMode), RuntimeModeStandalone) {
		return RuntimeModeStandalone
	}
	return RuntimeModeStandalone
}

// SetRuntimeMode thread-safely updates the runtime mode.
func (c *Config) SetRuntimeMode(mode string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.RuntimeMode = mode
}

// ResetToStandalone thread-safely resets the configuration to standalone mode.
func (c *Config) ResetToStandalone() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.RuntimeMode = RuntimeModeStandalone
	c.PrivateKeyPath = ""
}

func cloneBoolPtr(p *bool) *bool {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// Clone returns a deep copy of Config with a fresh zero-value mutex so callers
// can safely update configuration snapshots and swap them atomically without races.
func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()

	cp := &Config{
		RuntimeMode:               c.RuntimeMode,
		AllowStdio:                cloneBoolPtr(c.AllowStdio),
		ListenHost:                c.ListenHost,
		ListenPort:                c.ListenPort,
		AgentsDir:                 c.AgentsDir,
		ProtocolsDir:              c.ProtocolsDir,
		Mode:                      c.Mode,
		Stdio:                     c.Stdio,
		SSE:                       c.SSE,
		Filters:                   c.Filters,
		AuditLog:                  c.AuditLog,
		Telemetry:                 c.Telemetry,
		HotReload:                 c.HotReload,
		PrivateKeyPath:            c.PrivateKeyPath,
		AdminHost:                 c.AdminHost,
		AdminPort:                 c.AdminPort,
		AdminTLS:                  c.AdminTLS,
		UserContext:               c.UserContext,
		Security:                  c.Security,
		AutoSyncMCP:               c.AutoSyncMCP,
		AutoUpdatePolicies:        c.AutoUpdatePolicies,
		PollIntervalSeconds:       c.PollIntervalSeconds,
		PolicyPollIntervalSeconds: c.PolicyPollIntervalSeconds,
		ToolSyncIntervalSeconds:   c.ToolSyncIntervalSeconds,
		ConfigPath:                c.ConfigPath,
	}

	cp.Stdio.Args = slices.Clone(c.Stdio.Args)
	cp.UserContext.TrustedProxies = slices.Clone(c.UserContext.TrustedProxies)
	cp.Security.TrustedProxies = slices.Clone(c.Security.TrustedProxies)
	cp.Security.CORSAllowedOrigins = slices.Clone(c.Security.CORSAllowedOrigins)
	cp.Security.SSRFProtection.AllowedDomains = slices.Clone(c.Security.SSRFProtection.AllowedDomains)
	cp.Security.SSRFProtection.Enabled = cloneBoolPtr(c.Security.SSRFProtection.Enabled)
	cp.Security.SSRFProtection.BlockPrivateIPs = cloneBoolPtr(c.Security.SSRFProtection.BlockPrivateIPs)
	cp.Security.RateLimiting.Enabled = cloneBoolPtr(c.Security.RateLimiting.Enabled)
	cp.Telemetry.Enabled = cloneBoolPtr(c.Telemetry.Enabled)

	cp.Filters.Adaptive.FastPathTools = slices.Clone(c.Filters.Adaptive.FastPathTools)
	cp.Filters.Adaptive.DeepPathTools = slices.Clone(c.Filters.Adaptive.DeepPathTools)
	cp.Filters.InjectionScanner.ExcludeTools = slices.Clone(c.Filters.InjectionScanner.ExcludeTools)
	cp.Filters.InjectionScanner.Patterns = slices.Clone(c.Filters.InjectionScanner.Patterns)
	cp.Filters.DLP.ExcludeTools = slices.Clone(c.Filters.DLP.ExcludeTools)
	cp.Filters.DLP.Patterns = slices.Clone(c.Filters.DLP.Patterns)
	cp.Filters.Guard.L1Patterns = slices.Clone(c.Filters.Guard.L1Patterns)
	cp.Filters.Guard.FastPathTools = slices.Clone(c.Filters.Guard.FastPathTools)
	cp.Filters.Guard.CriticalBlocks = slices.Clone(c.Filters.Guard.CriticalBlocks)
	cp.Filters.HITL.DestructiveTools = slices.Clone(c.Filters.HITL.DestructiveTools)
	cp.Filters.LoopProtection.ExcludeTools = slices.Clone(c.Filters.LoopProtection.ExcludeTools)
	cp.Filters.LoopProtection.Overrides = slices.Clone(c.Filters.LoopProtection.Overrides)

	return cp
}

// IsStandalone returns true if the gateway is running in offline-first standalone mode.
func (c *Config) IsStandalone() bool {
	return c.GetRuntimeMode() == RuntimeModeStandalone
}

// IsManaged returns true if the gateway is operating in corporate managed mode.
func (c *Config) IsManaged() bool {
	return c.GetRuntimeMode() == RuntimeModeManaged
}

// IsStdioAllowed returns whether local stdio MCP subprocess execution and IDE preset onboarding are permitted.
// FARADAI_WIRE_ALLOW_STDIO takes highest precedence over config.yaml, defaulting to true for native workstations.
func (c *Config) IsStdioAllowed() bool {
	if raw := strings.TrimSpace(os.Getenv("FARADAI_WIRE_ALLOW_STDIO")); raw != "" {
		switch strings.ToLower(raw) {
		case "false", "0", "no", "off":
			return false
		case "true", "1", "yes", "on":
			return true
		}
	}
	if c != nil {
		c.mu.RLock()
		allowPtr := c.AllowStdio
		c.mu.RUnlock()
		if allowPtr != nil {
			return *allowPtr
		}
	}
	return true
}

// GetListenHost resolves the host interface address to bind HTTP listeners to.
// Defaults strictly to "127.0.0.1" (safe loopback) to prevent unauthorized local network exposure (SEC-016 / SPEC-SEC-003).
// Can be overridden via CLI --host, config yaml listen_host, or FARADAI_WIRE_HOST / LISTEN_HOST environment variables.
func (c *Config) GetListenHost() string {
	if c != nil {
		c.mu.RLock()
		host := strings.TrimSpace(c.ListenHost)
		c.mu.RUnlock()
		if host != "" {
			return host
		}
	}
	if env := strings.TrimSpace(os.Getenv("FARADAI_WIRE_HOST")); env != "" {
		return env
	}
	if env := strings.TrimSpace(os.Getenv("LISTEN_HOST")); env != "" {
		return env
	}
	return "127.0.0.1"
}

// GetAdminHost resolves the host interface address to bind the Admin HTTP server to.
// Precedence: explicit config.AdminHost (or CLI --admin-host) > FARADAI_WIRE_ADMIN_HOST >
// (!IsStandalone() -> GetListenHost()) > "127.0.0.1" (preserving ADR-0028 loopback default).
func (c *Config) GetAdminHost() string {
	if c != nil {
		c.mu.RLock()
		host := strings.TrimSpace(c.AdminHost)
		c.mu.RUnlock()
		if host != "" {
			return host
		}
	}
	if env := strings.TrimSpace(os.Getenv("FARADAI_WIRE_ADMIN_HOST")); env != "" {
		return env
	}
	if c != nil && !c.IsStandalone() {
		if h := strings.TrimSpace(c.GetListenHost()); h != "" {
			return h
		}
	}
	return "127.0.0.1"
}

func resolvePositivePortEnv(envKeys ...string) int {
	for _, key := range envKeys {
		raw := strings.TrimSpace(os.Getenv(key))
		if raw == "" {
			continue
		}
		if p, err := strconv.Atoi(raw); err == nil && p > 0 && p <= 65535 {
			return p
		}
	}
	return 0
}

// GetListenPort resolves the gateway ingress port with backward compatibility.
// Precedence: explicit config.ListenPort (or CLI --port) > SSE.ListenPort >
// FARADAI_WIRE_PORT / LISTEN_PORT > DefaultListenPort (19410).
func (c *Config) GetListenPort() int {
	if c != nil {
		c.mu.RLock()
		listenPort := c.ListenPort
		ssePort := c.SSE.ListenPort
		c.mu.RUnlock()
		if listenPort > 0 {
			return listenPort
		}
		if ssePort > 0 {
			return ssePort
		}
	}
	if p := resolvePositivePortEnv("FARADAI_WIRE_PORT", "LISTEN_PORT"); p > 0 {
		return p
	}
	return DefaultListenPort
}

// GetAdminPort resolves the administrative console port.
// Precedence: explicit config.AdminPort (or CLI --admin-port) >
// FARADAI_WIRE_ADMIN_PORT / ADMIN_PORT > DefaultAdminPort (19415).
func (c *Config) GetAdminPort() int {
	if c != nil {
		c.mu.RLock()
		adminPort := c.AdminPort
		c.mu.RUnlock()
		if adminPort > 0 {
			return adminPort
		}
	}
	if p := resolvePositivePortEnv("FARADAI_WIRE_ADMIN_PORT", "ADMIN_PORT"); p > 0 {
		return p
	}
	return DefaultAdminPort
}

// GetAgentsDir resolves the active agents root directory.
// Defaults to ~/.faradaiwire/agents (or FARADAI_WIRE_HOME/agents) unless explicitly configured.
func (c *Config) GetAgentsDir() string {
	if c != nil {
		c.mu.RLock()
		dir := c.AgentsDir
		c.mu.RUnlock()
		if dir != "" {
			return dir
		}
	}
	return filepath.Join(DefaultFaradAiWireDir(), "agents")
}

// GetProtocolsDir resolves the active protocols root directory.
// Defaults to ~/.faradaiwire/protocols (or FARADAI_WIRE_HOME/protocols) unless explicitly configured.
func (c *Config) GetProtocolsDir() string {
	if c != nil && c.ProtocolsDir != "" {
		return c.ProtocolsDir
	}
	return filepath.Join(DefaultFaradAiWireDir(), "protocols")
}

// GetAPIKeysPath resolves the storage file path for hashed API keys.
// Defaults to ~/.faradaiwire/keys/api_keys.json (or FARADAI_WIRE_HOME/keys/api_keys.json).
func (c *Config) GetAPIKeysPath() string {
	if c != nil && c.Security.APIKeysPath != "" {
		return c.Security.APIKeysPath
	}
	return filepath.Join(DefaultFaradAiWireDir(), "keys", "api_keys.json")
}

// DefaultFaradAiWireDir returns the path to ~/.faradaiwire (or FARADAI_WIRE_HOME if set).
func DefaultFaradAiWireDir() string {
	if env := os.Getenv("FARADAI_WIRE_HOME"); env != "" {
		return env
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".faradaiwire")
	}
	return filepath.Join(home, ".faradaiwire")
}

// EnsureDefaultRuntimeConfig ensures the ~/.faradaiwire directory structure exists
// and generates a default offline-first standalone configuration if none exists.
func EnsureDefaultRuntimeConfig() (string, error) {
	wireDir := DefaultFaradAiWireDir()

	subdirs := []string{
		wireDir,
		filepath.Join(wireDir, "agents"),
		filepath.Join(wireDir, "backups"),
		filepath.Join(wireDir, "policies"),
		filepath.Join(wireDir, "keys"),
		filepath.Join(wireDir, "protocols"),
		filepath.Join(wireDir, "schemas"),
		filepath.Join(wireDir, "logs"),
	}
	for _, dir := range subdirs {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return "", fmt.Errorf("failed to create runtime directory %s: %w", dir, err)
		}
	}

	configPath := filepath.Join(wireDir, "config.yaml")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		agentsDir := strings.ReplaceAll(filepath.ToSlash(filepath.Join(wireDir, "agents")), `"`, `\"`)
		protocolsDir := strings.ReplaceAll(filepath.ToSlash(filepath.Join(wireDir, "protocols")), `"`, `\"`)
		schemasDir := strings.ReplaceAll(filepath.ToSlash(filepath.Join(wireDir, "schemas")), `"`, `\"`)
		auditLogPath := strings.ReplaceAll(filepath.ToSlash(filepath.Join(wireDir, "logs", "faradai_audit.jsonl")), `"`, `\"`)
		listenPortStr := strconv.Itoa(DefaultListenPort)
		adminPortStr := strconv.Itoa(DefaultAdminPort)
		defaultYAML := `# Farad Ai Core - Offline-First Standalone Configuration
runtime_mode: STANDALONE
# listen_host: "127.0.0.1" # Defaults to 127.0.0.1 (or FARADAI_WIRE_HOST / LISTEN_HOST)
listen_port: ` + listenPortStr + `
admin_port: ` + adminPortStr + `
agents_dir: "` + agentsDir + `"
protocols_dir: "` + protocolsDir + `"
mode: "sse"
security:
  admin_auth_required: false
  ssrf_protection:
    enabled: true
    block_private_ips: false
  cors_allowed_origins:
    - "http://localhost:` + listenPortStr + `"
    - "http://127.0.0.1:` + listenPortStr + `"
    - "http://localhost:` + adminPortStr + `"
    - "http://127.0.0.1:` + adminPortStr + `"
  rate_limiting:
    enabled: true
    rate: 50.0
    burst: 100
    login_max_attempts: 5
    login_lockout_sec: 900
filters:
  prefill_block:
    enabled: true
  schema_validation:
    enabled: true
    schemas_dir: "` + schemasDir + `"
    dynamic_capture: true
    baseline_pinning: true
  guard:
    enabled: true
    discovery:
      mode: "auto"
      ollama_url: "http://127.0.0.1:11434"
      docker_url: "http://127.0.0.1:8088"
      custom_url: ""
  hitl:
    enabled: true
    destructive_tools:
      - "write_to_db"
      - "delete_record"
      - "send_email"
    approval_mode: "cli"
    timeout_seconds: 60
  loop_protection:
    enabled: true
    max_repeat: 5
    window_seconds: 15
  rate_limiting:
    enabled: true
    max_burst: 50
    refill_rate: 10.0
  dlp:
    enabled: true
    patterns:
      - name: "private_keys"
        regex: '-----BEGIN (RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----'
        action: "block"
      - name: "sensitive_files"
        regex: '(?i)(\.env|\.aws/credentials|id_rsa|id_ed25519|/etc/shadow|/etc/passwd)'
        action: "block"
      - name: "aws_credentials"
        regex: '(?i)["'']?(aws_secret_access_key|aws_access_key_id)["'']?\s*[:=]?\s*["'']?[A-Za-z0-9/+=]{16,}["'']?'
        action: "mask"
      - name: "email"
        regex: '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        action: "mask"
      - name: "credit_card"
        regex: '\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'
        action: "mask"
audit_log:
  enabled: true
  path: "` + auditLogPath + `"
`
		if err := os.WriteFile(configPath, []byte(defaultYAML), 0640); err != nil {
			return "", fmt.Errorf("failed to write default runtime configuration: %w", err)
		}
	}

	return configPath, nil
}

// UserContextConfig defines custom header mapping and provenance rules for client context propagation.
type UserContextConfig struct {
	RoleHeader        string   `yaml:"role_header"`         // Header key for user role
	UserHeader        string   `yaml:"user_header"`         // Header key for user ID
	FallbackRole      string   `yaml:"fallback_role"`       // Default role if missing or untrusted
	FallbackUser      string   `yaml:"fallback_user"`       // Default user ID if missing or untrusted
	TrustedProxies    []string `yaml:"trusted_proxies"`     // List of CIDRs/IPs allowed to supply user context without HMAC signature
	ContextHMACSecret string   `yaml:"context_hmac_secret"` // Optional HMAC-SHA256 secret for cryptographic context attestation
}

// SecurityConfig defines top-level security parameters for FaradAiWire.
type SecurityConfig struct {
	TrustedProxies     []string             `yaml:"trusted_proxies"`
	ContextHMACSecret  string               `yaml:"context_hmac_secret"`
	CORSAllowedOrigins []string             `yaml:"cors_allowed_origins"`
	SSRFProtection     SSRFProtectionConfig `yaml:"ssrf_protection"`
	APIKeysPath        string               `yaml:"api_keys_path"`
	RateLimiting       HTTPRateLimitConfig  `yaml:"rate_limiting"`
}

// HTTPRateLimitConfig defines HTTP ingress rate limiting and brute force defense parameters.
type HTTPRateLimitConfig struct {
	Enabled          *bool   `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Rate             float64 `yaml:"rate"`               // Requests per second (e.g. 50.0)
	Burst            int     `yaml:"burst"`              // Max burst capacity (e.g. 100)
	LoginMaxAttempts int     `yaml:"login_max_attempts"` // Max failed attempts before lockout (e.g. 5)
	LoginLockoutSec  int     `yaml:"login_lockout_sec"`  // Lockout duration in seconds (e.g. 900 for 15 min)
}

// SSRFProtectionConfig defines egress sandbox settings.
type SSRFProtectionConfig struct {
	Enabled         *bool    `yaml:"enabled"`
	AllowedDomains  []string `yaml:"allowed_domains"`
	BlockPrivateIPs *bool    `yaml:"block_private_ips"`
}

// IsEnabled returns true unless SSRF protection is explicitly set to false in config.
func (s SSRFProtectionConfig) IsEnabled() bool {
	if s.Enabled != nil {
		return *s.Enabled
	}
	return true
}

func envBoolOverride(key string) (bool, bool) {
	raw, ok := os.LookupEnv(key)
	if !ok {
		return false, false
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true, true
	case "0", "false", "no", "off":
		return false, true
	default:
		return false, false
	}
}

// ShouldBlockPrivateIPs resolves private/loopback blocking with defaultVal when omitted.
// FARADAI_WIRE_ALLOW_LOCAL_TARGETS explicitly overrides configured YAML values.
func (s SSRFProtectionConfig) ShouldBlockPrivateIPs(defaultVal bool) bool {
	if allowLocal, ok := envBoolOverride("FARADAI_WIRE_ALLOW_LOCAL_TARGETS"); ok {
		return !allowLocal
	}
	if s.BlockPrivateIPs != nil {
		return *s.BlockPrivateIPs
	}
	if allowStdio, ok := envBoolOverride("FARADAI_WIRE_ALLOW_STDIO"); ok && !allowStdio {
		return false
	}
	return defaultVal
}

// AdminTLSConfig configures TLS/HTTPS for the Admin HTTP server.
type AdminTLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// StdioConfig configures the MCP server started as a subprocess.
type StdioConfig struct {
	Command     string   `yaml:"command"`
	Args        []string `yaml:"args"`
	AutoRestart bool     `yaml:"auto_restart"`
}

// SSEConfig configures the HTTP SSE reverse proxy.
type SSEConfig struct {
	ListenPort int    `yaml:"listen_port"`
	TargetURL  string `yaml:"target_url"`
}

// FiltersConfig toggles and configures the different filter types.
type FiltersConfig struct {
	Adaptive         AdaptiveConfig         `yaml:"adaptive" json:"adaptive"`
	PrefillBlock     PrefillBlockConfig     `yaml:"prefill_block"`
	SchemaValidation SchemaValidationConfig `yaml:"schema_validation"`
	InjectionScanner InjectionScannerConfig `yaml:"injection_scanner"`
	DLP              DLPConfig              `yaml:"dlp"`
	Guard            GuardConfig            `yaml:"guard" json:"guard"`
	HITL             HITLConfig             `yaml:"hitl"`
	LoopProtection   LoopProtectionConfig   `yaml:"loop_protection"`
	RateLimiting     RateLimitingConfig     `yaml:"rate_limiting"`
}

// AdaptiveConfig configures risk-tiered adaptive fast-path routing (ADR-0010 / TICK-002).
type AdaptiveConfig struct {
	Enabled       bool     `yaml:"enabled" json:"enabled"`
	DefaultPath   string   `yaml:"default_path" json:"default_path"` // "deep" (default) or "fast"
	FastPathTools []string `yaml:"fast_path_tools" json:"fast_path_tools"`
	DeepPathTools []string `yaml:"deep_path_tools" json:"deep_path_tools"`
}

// PrefillBlockConfig configures the sockpuppeting/assistant prefill defense.
type PrefillBlockConfig struct {
	Enabled bool `yaml:"enabled"`
}

// SchemaValidationConfig configures tool parameter schema validation and drift detection.
type SchemaValidationConfig struct {
	Enabled         bool   `yaml:"enabled"`
	SchemasDir      string `yaml:"schemas_dir"`
	DynamicCapture  bool   `yaml:"dynamic_capture"`
	BaselinePinning bool   `yaml:"baseline_pinning"`
}

// InjectionScannerConfig configures the indirect prompt injection scanner for tool outputs (ADR-0010 / TICK-003).
type InjectionScannerConfig struct {
	Enabled             bool     `yaml:"enabled"`
	ExcludeTools        []string `yaml:"exclude_tools"`
	Patterns            []string `yaml:"patterns"`
	CustomPatternsFile  string   `yaml:"custom_patterns_file"`
	ClassifierURL       string   `yaml:"classifier_url"`
	ClassifierThreshold float64  `yaml:"classifier_threshold"`
	TimeoutMs           int      `yaml:"timeout_ms" json:"timeout_ms"`     // Default 150ms per ADR-0010
	FailureMode         string   `yaml:"failure_mode" json:"failure_mode"` // "fail_closed" (default) or "fail_open_with_alert"
}

// DLPConfig configures PII regex-based masking, auditing, or blocking.
type DLPConfig struct {
	Enabled                 bool         `yaml:"enabled" json:"enabled"`
	ExcludeTools            []string     `yaml:"exclude_tools" json:"exclude_tools"`
	Patterns                []DLPPattern `yaml:"patterns" json:"patterns"`
	DebugRetainUnmaskedDiff bool         `yaml:"debug_retain_unmasked_diff" json:"debug_retain_unmasked_diff"`
}

// DLPPattern defines a single regex rule for sensitive data.
type DLPPattern struct {
	Name        string `yaml:"name" json:"name"`
	Regex       string `yaml:"regex" json:"regex"`
	Action      string `yaml:"action" json:"action"` // "mask", "block", or "audit"
	Placeholder string `yaml:"placeholder,omitempty" json:"placeholder,omitempty"`
}

// DiscoveryConfig configures AI Guard inference provider auto-detection and custom endpoints.
type DiscoveryConfig struct {
	Mode      string `yaml:"mode" json:"mode"`             // "auto" | "ollama" | "docker" | "custom"
	OllamaURL string `yaml:"ollama_url" json:"ollama_url"` // default "http://127.0.0.1:11434"
	DockerURL string `yaml:"docker_url" json:"docker_url"` // default "http://127.0.0.1:8088"
	CustomURL string `yaml:"custom_url" json:"custom_url"`
}

// GetEffectiveOllamaURL resolves the Ollama endpoint with environment precedence:
// FARADAI_WIRE_GUARD_OLLAMA_URL > OllamaURL > http://127.0.0.1:11434.
func (d DiscoveryConfig) GetEffectiveOllamaURL() string {
	if v := strings.TrimSpace(os.Getenv("FARADAI_WIRE_GUARD_OLLAMA_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	if v := strings.TrimSpace(d.OllamaURL); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "http://127.0.0.1:11434"
}

// GetEffectiveDockerURL resolves the Docker Prompt-Guard endpoint with environment precedence:
// FARADAI_WIRE_GUARD_DOCKER_URL > DockerURL > http://127.0.0.1:8088.
func (d DiscoveryConfig) GetEffectiveDockerURL() string {
	if v := strings.TrimSpace(os.Getenv("FARADAI_WIRE_GUARD_DOCKER_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	if v := strings.TrimSpace(d.DockerURL); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "http://127.0.0.1:8088"
}

// GuardConfig configures the extensible AI Guard security engine (GUARD-004).
type GuardConfig struct {
	Enabled          bool            `yaml:"enabled" json:"enabled"`
	L1Patterns       []DLPPattern    `yaml:"l1_patterns" json:"l1_patterns"`
	FastPathTools    []string        `yaml:"fast_path_tools" json:"fast_path_tools"`
	CriticalBlocks   []string        `yaml:"critical_blocks" json:"critical_blocks"`
	MaxPayloadLength int             `yaml:"max_payload_length" json:"max_payload_length"` // Defaults to 128
	MinWordCount     int             `yaml:"min_word_count" json:"min_word_count"`         // Defaults to 5
	Discovery        DiscoveryConfig `yaml:"discovery" json:"discovery"`
}

// HITLConfig configures human-in-the-loop approval hooks.
type HITLConfig struct {
	Enabled          bool     `yaml:"enabled"`
	DestructiveTools []string `yaml:"destructive_tools"`
	ApprovalMode     string   `yaml:"approval_mode"` // "cli" or "webhook"
	WebhookURL       string   `yaml:"webhook_url"`
	TimeoutSeconds   int      `yaml:"timeout_seconds"`
}

// AuditLogConfig configures the immutable audit trail log path.
type AuditLogConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
}

// LoopProtectionConfig configures the loop detection mechanism.
type LoopProtectionConfig struct {
	Enabled                bool               `yaml:"enabled"`
	MaxRepeat              int                `yaml:"max_repeat"`     // Max consecutive identical tool calls allowed
	WindowSeconds          int                `yaml:"window_seconds"` // Time window to monitor consecutive calls
	ExcludeTools           []string           `yaml:"exclude_tools"`
	Overrides              []LoopToolOverride `yaml:"overrides"`
	TTLSeconds             int                `yaml:"ttl_seconds"`              // TTL for inactive entries
	CleanupIntervalSeconds int                `yaml:"cleanup_interval_seconds"` // Cleanup background worker interval
	MaxKeys                int                `yaml:"max_keys"`                 // Max tracked keys (bounded memory)
}

// LoopToolOverride defines custom thresholds for specific tools.
type LoopToolOverride struct {
	Tool      string `yaml:"tool"`
	MaxRepeat int    `yaml:"max_repeat"`
}

// RateLimitingConfig configures the Token-Bucket rate limiter on tool calls.
type RateLimitingConfig struct {
	Enabled                bool    `yaml:"enabled"`
	MaxBurst               int     `yaml:"max_burst"`                // Maximum bucket capacity (tokens)
	RefillRate             float64 `yaml:"refill_rate"`              // Tokens refilled per second
	TTLSeconds             int     `yaml:"ttl_seconds"`              // TTL for inactive entries
	CleanupIntervalSeconds int     `yaml:"cleanup_interval_seconds"` // Cleanup background worker interval
	MaxKeys                int     `yaml:"max_keys"`                 // Max tracked keys (bounded memory)
}

// TelemetryConfig defines local DuckDB telemetry storage, retention, and truncation parameters.
type TelemetryConfig struct {
	Enabled         *bool  `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	DBPath          string `yaml:"db_path" json:"db_path"`
	RetentionDays   int    `yaml:"retention_days" json:"retention_days"`       // Default: 14 days
	MaxSizeBytes    int64  `yaml:"max_size_bytes" json:"max_size_bytes"`       // Default: 1 GB (1073741824)
	MaxPayloadBytes int    `yaml:"max_payload_bytes" json:"max_payload_bytes"` // Default: 64 KB (65536)
	BufferSize      int    `yaml:"buffer_size" json:"buffer_size"`             // Default: 4096 events
	BatchFlushMs    int    `yaml:"batch_flush_ms" json:"batch_flush_ms"`       // Default: 100 ms
}

// IsTelemetryEnabled returns whether the local DuckDB telemetry engine should be activated.
// In standalone mode, it defaults to true unless explicitly disabled.
func (c *Config) IsTelemetryEnabled() bool {
	if c.Telemetry.Enabled != nil {
		return *c.Telemetry.Enabled
	}
	// By default enabled in standalone mode
	return true
}

// GetTelemetryDBPath resolves the DuckDB database file path.
// Defaults to ~/.faradaiwire/wire.duckdb (or FARADAI_WIRE_HOME/wire.duckdb) per Open Core spec, ADR-0043, and ADR-0057.
// When running in automated test suites without an explicit FARADAI_WIRE_HOME override, it defaults to an isolated temporary path.
func (c *Config) GetTelemetryDBPath() string {
	if c != nil && strings.TrimSpace(c.Telemetry.DBPath) != "" {
		return c.Telemetry.DBPath
	}
	if strings.TrimSpace(os.Getenv("FARADAI_WIRE_HOME")) != "" {
		return filepath.Join(DefaultFaradAiWireDir(), "wire.duckdb")
	}
	if flag.Lookup("test.v") != nil {
		return filepath.Join(os.TempDir(), fmt.Sprintf("faradai_test_telemetry_%d_%d.duckdb", os.Getpid(), time.Now().UnixNano()))
	}
	return filepath.Join(DefaultFaradAiWireDir(), "wire.duckdb")
}

// GetDBPath returns the DuckDB database file path (alias for GetTelemetryDBPath).
func (c *Config) GetDBPath() string {
	return c.GetTelemetryDBPath()
}

// IsHTTPRateLimitEnabled checks if HTTP rate limiting is enabled.
func (c *Config) IsHTTPRateLimitEnabled() bool {
	if c == nil || c.Security.RateLimiting.Enabled == nil {
		return true
	}
	return *c.Security.RateLimiting.Enabled
}

// GetHTTPRateLimitConfig returns HTTP ingress rate limiting configuration with safe production defaults.
func (c *Config) GetHTTPRateLimitConfig() HTTPRateLimitConfig {
	if c == nil {
		return DefaultHTTPRateLimitConfig()
	}
	cfg := c.Security.RateLimiting
	if cfg.Rate <= 0 {
		cfg.Rate = 50.0 // 50 req/sec default ingress
	}
	if cfg.Burst <= 0 {
		cfg.Burst = 100
	}
	if cfg.LoginMaxAttempts <= 0 {
		cfg.LoginMaxAttempts = 5
	}
	if cfg.LoginLockoutSec <= 0 {
		cfg.LoginLockoutSec = 900 // 15 minutes lockout
	}
	return cfg
}

// DefaultHTTPRateLimitConfig returns production defaults for HTTP rate limiting.
func DefaultHTTPRateLimitConfig() HTTPRateLimitConfig {
	enabled := true
	return HTTPRateLimitConfig{
		Enabled:          &enabled,
		Rate:             50.0,
		Burst:            100,
		LoginMaxAttempts: 5,
		LoginLockoutSec:  900,
	}
}
