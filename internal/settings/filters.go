package settings

import (
	"path/filepath"
	"strconv"
	"strings"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
)

// FilterKeyPrefix is the canonical DuckDB system_settings key prefix for security filter toggles.
const FilterKeyPrefix = "filters."

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
	"filters.injection_scanner": {
		Key:         "filters.injection_scanner",
		Label:       "Indirect Injection Scanner",
		Description: "Scans tool outputs for indirect prompt injection payloads",
		Category:    "filters",
		Type:        TypeBool,
		DefaultVal:  false,
	},
}

// IsFilterKey returns true if key identifies a registered security filter overlay entry (e.g. "filters.dlp").
func IsFilterKey(key string) bool {
	_, ok := FilterRegistry[key]
	return ok
}

// LookupMeta resolves metadata from either the operational Registry or FilterRegistry.
func LookupMeta(key string) (SettingMeta, bool) {
	if meta, ok := Registry[key]; ok {
		return meta, true
	}
	meta, ok := FilterRegistry[key]
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
	case "injection_scanner":
		return cfg.Filters.InjectionScanner.Enabled, true
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
	case "injection_scanner":
		cfg.Filters.InjectionScanner.Enabled = enabled
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
