package settings

import (
	"errors"
	"net"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
)

var orderedFilterNames = []string{
	"prefill_block",
	"rate_limiting",
	"loop_protection",
	"schema_validation",
	"dlp",
	"hitl",
	"guard",
}

// FilterKeyPrefix is the canonical DuckDB system_settings key prefix for security filter toggles.
const FilterKeyPrefix = "filters."

// GuardDiscovery sparse overlay keys persisted in DuckDB system_settings (ADR-0053 / ADR-0060).
const (
	GuardDiscoveryModeKey      = "guard.discovery.mode"
	GuardDiscoveryOllamaURLKey = "guard.discovery.ollama_url"
	GuardDiscoveryDockerURLKey = "guard.discovery.docker_url"
	GuardDiscoveryCustomURLKey = "guard.discovery.custom_url"
)

// GuardDiscoveryRegistry catalogs sparse DuckDB overlay keys for AI Guard discovery settings.
// Kept separate from Registry so GET /admin/settings retains its 4 operational parameter categories.
var GuardDiscoveryRegistry = map[string]SettingMeta{
	GuardDiscoveryModeKey: {
		Key:         GuardDiscoveryModeKey,
		Label:       "Guard Discovery Mode",
		Description: "AI Guard provider discovery mode (auto, ollama, docker, custom)",
		Category:    "guard",
		Type:        TypeString,
		DefaultVal:  "auto",
	},
	GuardDiscoveryOllamaURLKey: {
		Key:         GuardDiscoveryOllamaURLKey,
		Label:       "Guard Ollama URL",
		Description: "Override Ollama endpoint URL for AI Guard discovery",
		Category:    "guard",
		Type:        TypeString,
		DefaultVal:  "http://127.0.0.1:11434",
	},
	GuardDiscoveryDockerURLKey: {
		Key:         GuardDiscoveryDockerURLKey,
		Label:       "Guard Docker URL",
		Description: "Override FaradAiGuard Docker sidecar endpoint URL",
		Category:    "guard",
		Type:        TypeString,
		DefaultVal:  "http://127.0.0.1:8088",
	},
	GuardDiscoveryCustomURLKey: {
		Key:         GuardDiscoveryCustomURLKey,
		Label:       "Guard Custom Endpoint URL",
		Description: "Explicit OpenAI-compatible or custom HTTP AI Guard classifier URL",
		Category:    "guard",
		Type:        TypeString,
		DefaultVal:  "",
	},
}

// FilterRegistry catalogs all runtime-toggleable security filters stored in the DuckDB
// system_settings sparse overlay. Kept separate from Registry so GET /admin/settings preserves
// the four Operational Parameters categories expected by the OperationalSettingsTab UI.
var FilterRegistry = map[string]SettingMeta{
	"filters.prefill_block": {
		Key:         "filters.prefill_block",
		Label:       "Prefill Attack Mitigation",
		Description: "Blocks unapproved assistant role prefilling injections designed to bypass guardrails",
		Category:    "filters",
		Type:        TypeBool,
		DefaultVal:  true,
	},
	"filters.dlp": {
		Key:         "filters.dlp",
		Label:       "Data Loss Prevention (DLP)",
		Description: "Zero-egress scanning that scrubs credentials, SSH keys, bearer tokens, and PII",
		Category:    "filters",
		Type:        TypeBool,
		DefaultVal:  true,
	},
	"filters.rate_limiting": {
		Key:         "filters.rate_limiting",
		Label:       "Ingress Rate Limiting",
		Description: "Token-bucket rate limiting per IP / client token",
		Category:    "filters",
		Type:        TypeBool,
		DefaultVal:  true,
	},
	"filters.loop_protection": {
		Key:         "filters.loop_protection",
		Label:       "Agent Loop Protection",
		Description: "Heuristic cycle detection that intercepts runaway recursive tool invocation loops",
		Category:    "filters",
		Type:        TypeBool,
		DefaultVal:  true,
	},
	"filters.guard": {
		Key:         "filters.guard",
		Label:       "Semantic Security Guard",
		Description: "Zero-egress offline neural guard with L1 cascade and Root Intent Isolation",
		Category:    "filters",
		Type:        TypeBool,
		DefaultVal:  true,
	},
	"filters.hitl": {
		Key:         "filters.hitl",
		Label:       "Human-in-the-Loop (HITL)",
		Description: "Requires explicit administrator confirmation before executing critical or destructive tools",
		Category:    "filters",
		Type:        TypeBool,
		DefaultVal:  true,
	},
	"filters.schema_validation": {
		Key:         "filters.schema_validation",
		Label:       "Dynamic Schema Validation",
		Description: "Enforces JSON schema adherence against learned baseline shapes for all tool calls",
		Category:    "filters",
		Type:        TypeBool,
		DefaultVal:  true,
	},
}

// IsFilterKey returns true if key identifies a registered security filter overlay entry (e.g. "filters.dlp").
func IsFilterKey(key string) bool {
	_, ok := FilterRegistry[key]
	return ok
}

// LookupMeta resolves metadata from Registry, FilterRegistry, or GuardDiscoveryRegistry.
func LookupMeta(key string) (SettingMeta, bool) {
	if meta, ok := Registry[key]; ok {
		return meta, true
	}
	if meta, ok := FilterRegistry[key]; ok {
		return meta, true
	}
	meta, ok := GuardDiscoveryRegistry[key]
	return meta, ok
}

// IsSupportedFilterName returns true if filterName (e.g. "dlp") maps to a registered filter overlay key.
func IsSupportedFilterName(filterName string) bool {
	return IsFilterKey(FilterKeyPrefix + filterName)
}

// ExtractFilterEnabled returns the current boolean state of filterName in cfg.
func ExtractFilterEnabled(cfg *config.Config, filterName string) (bool, bool) {
	if cfg == nil {
		return false, false
	}
	switch filterName {
	case "prefill_block":
		return cfg.Filters.PrefillBlock.Enabled, true
	case "schema_validation":
		return cfg.Filters.SchemaValidation.Enabled, true
	case "dlp":
		return cfg.Filters.DLP.Enabled, true
	case "hitl":
		return cfg.Filters.HITL.Enabled, true
	case "loop_protection":
		return cfg.Filters.LoopProtection.Enabled, true
	case "rate_limiting":
		return cfg.Filters.RateLimiting.Enabled, true
	case "guard":
		return cfg.Filters.Guard.Enabled, true
	default:
		return false, false
	}
}

// ApplyFilterToggleToConfig applies a filter enable/disable mutation to cfg and hydrates safe
// baseline defaults if a previously omitted filter block is enabled for the first time.
func ApplyFilterToggleToConfig(cfg *config.Config, filterName string, enabled bool) bool {
	if cfg == nil {
		return false
	}

	switch filterName {
	case "prefill_block":
		cfg.Filters.PrefillBlock.Enabled = enabled
	case "schema_validation":
		cfg.Filters.SchemaValidation.Enabled = enabled
		if enabled {
			uninitialized := cfg.Filters.SchemaValidation.SchemasDir == "" &&
				!cfg.Filters.SchemaValidation.DynamicCapture &&
				!cfg.Filters.SchemaValidation.BaselinePinning
			if cfg.Filters.SchemaValidation.SchemasDir == "" {
				cfg.Filters.SchemaValidation.SchemasDir = filepath.ToSlash(filepath.Join(config.DefaultFaradAiWireDir(), "schemas"))
			}
			if uninitialized {
				cfg.Filters.SchemaValidation.DynamicCapture = true
				cfg.Filters.SchemaValidation.BaselinePinning = true
			}
		}
	case "dlp":
		cfg.Filters.DLP.Enabled = enabled
	case "hitl":
		cfg.Filters.HITL.Enabled = enabled
		if enabled {
			if len(cfg.Filters.HITL.DestructiveTools) == 0 {
				cfg.Filters.HITL.DestructiveTools = []string{"write_to_db", "delete_record", "send_email"}
			}
			if strings.TrimSpace(cfg.Filters.HITL.ApprovalMode) == "" {
				cfg.Filters.HITL.ApprovalMode = "cli"
			}
			if cfg.Filters.HITL.TimeoutSeconds <= 0 {
				cfg.Filters.HITL.TimeoutSeconds = 60
			}
		}
	case "loop_protection":
		cfg.Filters.LoopProtection.Enabled = enabled
		if enabled {
			if cfg.Filters.LoopProtection.MaxRepeat <= 0 {
				cfg.Filters.LoopProtection.MaxRepeat = 5
			}
			if cfg.Filters.LoopProtection.WindowSeconds <= 0 {
				cfg.Filters.LoopProtection.WindowSeconds = 15
			}
		}
	case "rate_limiting":
		cfg.Filters.RateLimiting.Enabled = enabled
		if enabled {
			if cfg.Filters.RateLimiting.MaxBurst <= 0 {
				cfg.Filters.RateLimiting.MaxBurst = 50
			}
			if cfg.Filters.RateLimiting.RefillRate <= 0 {
				cfg.Filters.RateLimiting.RefillRate = 10.0
			}
		}
	case "guard":
		cfg.Filters.Guard.Enabled = enabled
	default:
		return false
	}

	return true
}

// ApplyFilterOverrides overlays persisted DuckDB "filters.*" boolean values onto cfg.
// Corrupted or unrecognized rows are safely skipped so boot and hot-reload remain resilient.
func ApplyFilterOverrides(cfg *config.Config, overrides map[string]string) {
	if cfg == nil || len(overrides) == 0 {
		return
	}

	for key, raw := range overrides {
		if !IsFilterKey(key) {
			continue
		}
		enabled, err := strconv.ParseBool(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		ApplyFilterToggleToConfig(cfg, strings.TrimPrefix(key, FilterKeyPrefix), enabled)
	}
}

// ValidateGuardDiscoveryURL enforces standalone AI Guard discovery URL safety constraints.
// Empty strings are permitted so callers can explicitly clear a persisted override.
func ValidateGuardDiscoveryURL(rawURL string) error {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil
	}
	if len(rawURL) > 2048 {
		return errors.New("URL exceeds maximum length of 2048 characters")
	}
	u, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return errors.New("invalid URL format: " + err.Error())
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("unsupported scheme: only http and https are allowed")
	}
	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if host == "" {
		return errors.New("missing host in URL")
	}
	if host == "169.254.169.254" || strings.HasPrefix(host, "169.254.") || host == "metadata.google.internal" {
		return errors.New("access to link-local cloud metadata is strictly prohibited")
	}
	if ip := net.ParseIP(host); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			ip = ipv4
		}
		if ip.Equal(net.ParseIP("169.254.169.254")) || ip.Equal(net.ParseIP("fd00:ec2::254")) {
			return errors.New("access to cloud metadata service is strictly prohibited")
		}
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return errors.New("access to link-local metadata is strictly prohibited")
		}
	}
	return nil
}

// ApplyGuardDiscoveryOverrides overlays persisted DuckDB "guard.discovery.*" values onto cfg.
// Corrupted or disallowed persisted URLs are skipped so startup and reload remain safe.
func ApplyGuardDiscoveryOverrides(cfg *config.Config, overrides map[string]string) {
	if cfg == nil || len(overrides) == 0 {
		return
	}
	if rawMode, ok := overrides[GuardDiscoveryModeKey]; ok {
		mode := strings.ToLower(strings.TrimSpace(rawMode))
		switch mode {
		case "auto", "ollama", "docker", "custom":
			cfg.Filters.Guard.Discovery.Mode = mode
		}
	}
	if rawOllama, ok := overrides[GuardDiscoveryOllamaURLKey]; ok {
		trimmed := strings.TrimSpace(rawOllama)
		if ValidateGuardDiscoveryURL(trimmed) == nil {
			cfg.Filters.Guard.Discovery.OllamaURL = trimmed
		}
	}
	if rawDocker, ok := overrides[GuardDiscoveryDockerURLKey]; ok {
		trimmed := strings.TrimSpace(rawDocker)
		if ValidateGuardDiscoveryURL(trimmed) == nil {
			cfg.Filters.Guard.Discovery.DockerURL = trimmed
		}
	}
	if rawCustom, ok := overrides[GuardDiscoveryCustomURLKey]; ok {
		trimmed := strings.TrimSpace(rawCustom)
		if ValidateGuardDiscoveryURL(trimmed) == nil {
			cfg.Filters.Guard.Discovery.CustomURL = trimmed
		}
	}
}

// OrderedFilterNames returns all registered security filter names in canonical display order.
func OrderedFilterNames() []string {
	return slices.Clone(orderedFilterNames)
}

// FilterStatusSummary summarizes active pipeline filters and per-filter enabled flags for status reporting.
type FilterStatusSummary struct {
	ActiveFilters []string
	ConfigStates  map[string]bool
}

// BuildFilterStatusSummary projects the active security filters and config booleans from cfg
// using the canonical ordered filter registry.
func BuildFilterStatusSummary(cfg *config.Config) FilterStatusSummary {
	summary := FilterStatusSummary{
		ActiveFilters: make([]string, 0, len(orderedFilterNames)),
		ConfigStates:  make(map[string]bool, len(orderedFilterNames)),
	}
	for _, name := range orderedFilterNames {
		enabled, _ := ExtractFilterEnabled(cfg, name)
		summary.ConfigStates[name] = enabled
		if enabled {
			summary.ActiveFilters = append(summary.ActiveFilters, name)
		}
	}
	return summary
}
