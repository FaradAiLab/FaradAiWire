package settings

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// SettingType identifies the primitive scalar data type for a configuration entry.
type SettingType string

const (
	TypeInt   SettingType = "int"
	TypeFloat SettingType = "float"
	TypeBool  SettingType = "bool"
)

// SettingMeta encapsulates the declarative schema, labels, constraints, and descriptions
// for a single operational setting.
type SettingMeta struct {
	Key         string      `json:"key"`
	Label       string      `json:"label"`
	Description string      `json:"description"`
	Category    string      `json:"category"` // "limits", "timeouts", "guard", "maintenance"
	Type        SettingType `json:"type"`
	DefaultVal  any         `json:"default_value"`
	Min         float64     `json:"min,omitempty"`
	Max         float64     `json:"max,omitempty"`
	Step        float64     `json:"step,omitempty"`
	Unit        string      `json:"unit,omitempty"`
}

// SettingItem is returned by the self-describing Settings API, merging static metadata
// with current runtime values and override status.
type SettingItem struct {
	SettingMeta
	Value        any  `json:"value"`
	IsOverridden bool `json:"is_overridden"`
}

// Registry defines all registered operational parameters across FaradAiWire.
// Modifying parameters not listed here is forbidden (fail-closed security boundary).
var Registry = map[string]SettingMeta{
	// Limits Category
	"limits.max_payload_bytes": {
		Key:         "limits.max_payload_bytes",
		Label:       "Maximum Payload Size",
		Description: "Maximum permissible size for MCP messages and tool execution responses",
		Category:    "limits",
		Type:        TypeInt,
		DefaultVal:  int64(10 * 1024 * 1024), // 10MB
		Min:         1024,                    // 1KB
		Max:         100 * 1024 * 1024,       // 100MB
		Unit:        "bytes",
	},
	"limits.max_scanner_buffer_mb": {
		Key:         "limits.max_scanner_buffer_mb",
		Label:       "Scanner Buffer Size",
		Description: "Maximum line scanning and token extraction buffer size in megabytes",
		Category:    "limits",
		Type:        TypeInt,
		DefaultVal:  10,
		Min:         1,
		Max:         64,
		Unit:        "MB",
	},
	"limits.max_preview_bytes": {
		Key:         "limits.max_preview_bytes",
		Label:       "Snippet Preview Limit",
		Description: "Maximum payload preview length stored in telemetry events and audit logs",
		Category:    "limits",
		Type:        TypeInt,
		DefaultVal:  4096,
		Min:         256,
		Max:         65536,
		Unit:        "bytes",
	},

	// Timeouts Category
	"timeouts.tool_execution_sec": {
		Key:         "timeouts.tool_execution_sec",
		Label:       "Tool Execution Timeout",
		Description: "Maximum permissible duration for Streamable HTTP MCP tool execution calls",
		Category:    "timeouts",
		Type:        TypeInt,
		DefaultVal:  60,
		Min:         1,
		Max:         600,
		Unit:        "seconds",
	},
	"timeouts.idle_timeout_sec": {
		Key:         "timeouts.idle_timeout_sec",
		Label:       "Connection Idle Timeout",
		Description: "Maximum duration an idle HTTP keep-alive connection remains open",
		Category:    "timeouts",
		Type:        TypeInt,
		DefaultVal:  90,
		Min:         5,
		Max:         600,
		Unit:        "seconds",
	},
	"timeouts.read_header_timeout_sec": {
		Key:         "timeouts.read_header_timeout_sec",
		Label:       "Read Header Timeout",
		Description: "Maximum duration allowed for reading incoming HTTP request headers",
		Category:    "timeouts",
		Type:        TypeInt,
		DefaultVal:  5,
		Min:         1,
		Max:         60,
		Unit:        "seconds",
	},
	"timeouts.probe_timeout_sec": {
		Key:         "timeouts.probe_timeout_sec",
		Label:       "MCP Probe Timeout",
		Description: "Maximum duration in seconds allowed when probing an MCP server endpoint",
		Category:    "timeouts",
		Type:        TypeInt,
		DefaultVal:  5,
		Min:         1,
		Max:         60,
		Unit:        "seconds",
	},

	// Guard Category
	"guard.threshold_score": {
		Key:         "guard.threshold_score",
		Label:       "Semantic Guard Risk Threshold",
		Description: "Minimum malicious probability score (0.0 to 1.0) to trigger a security block",
		Category:    "guard",
		Type:        TypeFloat,
		DefaultVal:  0.50,
		Min:         0.05,
		Max:         0.95,
		Step:        0.05,
		Unit:        "score",
	},
	"guard.timeout_ms": {
		Key:         "guard.timeout_ms",
		Label:       "Guard Warm Timeout SLA",
		Description: "Maximum execution SLA in milliseconds for warm SLM model inference",
		Category:    "guard",
		Type:        TypeInt,
		DefaultVal:  1000,
		Min:         100,
		Max:         10000,
		Unit:        "ms",
	},
	"guard.cold_timeout_ms": {
		Key:         "guard.cold_timeout_ms",
		Label:       "Guard Cold-Start Timeout SLA",
		Description: "Maximum execution SLA in milliseconds during initial SLM model runner loading",
		Category:    "guard",
		Type:        TypeInt,
		DefaultVal:  3000,
		Min:         500,
		Max:         30000,
		Unit:        "ms",
	},
	"guard.hitl_timeout_sec": {
		Key:         "guard.hitl_timeout_sec",
		Label:       "Human-in-the-Loop Timeout",
		Description: "Maximum window to wait for operator approval before failing closed",
		Category:    "guard",
		Type:        TypeInt,
		DefaultVal:  60,
		Min:         10,
		Max:         600,
		Unit:        "seconds",
	},

	// Maintenance Category
	"maintenance.session_idle_timeout_min": {
		Key:         "maintenance.session_idle_timeout_min",
		Label:       "Session Inactive Timeout",
		Description: "Inactive duration in minutes before an orphaned SSE/stdio session is evicted",
		Category:    "maintenance",
		Type:        TypeInt,
		DefaultVal:  30,
		Min:         5,
		Max:         1440,
		Unit:        "minutes",
	},
	"maintenance.correlation_ttl_min": {
		Key:         "maintenance.correlation_ttl_min",
		Label:       "Correlation Cache Retention",
		Description: "Time-to-live retention window in minutes for request correlation tracking",
		Category:    "maintenance",
		Type:        TypeInt,
		DefaultVal:  60,
		Min:         10,
		Max:         1440,
		Unit:        "minutes",
	},
}

// ErrUnknownSetting indicates an attempted mutation of an unregistered parameter key.
var ErrUnknownSetting = errors.New("unknown setting key")

// ErrInvalidValue indicates a parameter value that fails boundary or data type validation.
var ErrInvalidValue = errors.New("invalid setting value")

// Validate checks whether a given key exists in the operational settings registry and whether
// the provided value satisfies the type constraints and min/max boundaries.
func Validate(key string, val any) error {
	meta, exists := Registry[key]
	if !exists {
		return fmt.Errorf("%w: %q is not a recognized operational setting", ErrUnknownSetting, key)
	}
	return validateMeta(key, meta, val)
}

func validateMeta(key string, meta SettingMeta, val any) error {
	switch meta.Type {
	case TypeInt:
		var intVal int64
		switch v := val.(type) {
		case int:
			intVal = int64(v)
		case int32:
			intVal = int64(v)
		case int64:
			intVal = v
		case float64:
			if v != float64(int64(v)) {
				return fmt.Errorf("%w: key %q requires an integer value, got %v", ErrInvalidValue, key, v)
			}
			intVal = int64(v)
		default:
			return fmt.Errorf("%w: key %q expects an integer, got %T", ErrInvalidValue, key, val)
		}
		if meta.Min > 0 && float64(intVal) < meta.Min {
			return fmt.Errorf("%w: key %q value %d is below minimum allowed %v", ErrInvalidValue, key, intVal, meta.Min)
		}
		if meta.Max > 0 && float64(intVal) > meta.Max {
			return fmt.Errorf("%w: key %q value %d exceeds maximum allowed %v", ErrInvalidValue, key, intVal, meta.Max)
		}

	case TypeFloat:
		var floatVal float64
		switch v := val.(type) {
		case float64:
			floatVal = v
		case float32:
			floatVal = float64(v)
		case int:
			floatVal = float64(v)
		case int64:
			floatVal = float64(v)
		default:
			return fmt.Errorf("%w: key %q expects a float value, got %T", ErrInvalidValue, key, val)
		}
		if meta.Min > 0 && floatVal < meta.Min {
			return fmt.Errorf("%w: key %q value %v is below minimum allowed %v", ErrInvalidValue, key, floatVal, meta.Min)
		}
		if meta.Max > 0 && floatVal > meta.Max {
			return fmt.Errorf("%w: key %q value %v exceeds maximum allowed %v", ErrInvalidValue, key, floatVal, meta.Max)
		}

	case TypeBool:
		if _, ok := val.(bool); !ok {
			return fmt.Errorf("%w: key %q expects a boolean value, got %T", ErrInvalidValue, key, val)
		}

	default:
		return fmt.Errorf("%w: unhandled setting type %q for key %q", ErrInvalidValue, meta.Type, key)
	}

	return nil
}

// ParseAndValidate parses a raw string value according to the registered metadata schema
// and validates it against boundaries.
func ParseAndValidate(key string, strVal string) (any, error) {
	meta, exists := LookupMeta(key)
	if !exists {
		return nil, fmt.Errorf("%w: %q is not recognized", ErrUnknownSetting, key)
	}

	trimmed := strings.TrimSpace(strVal)
	var parsed any

	switch meta.Type {
	case TypeInt:
		v, err := strconv.ParseInt(trimmed, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: key %q cannot parse integer from %q: %v", ErrInvalidValue, key, strVal, err)
		}
		parsed = v
	case TypeFloat:
		v, err := strconv.ParseFloat(trimmed, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: key %q cannot parse float from %q: %v", ErrInvalidValue, key, strVal, err)
		}
		parsed = v
	case TypeBool:
		v, err := strconv.ParseBool(trimmed)
		if err != nil {
			return nil, fmt.Errorf("%w: key %q cannot parse bool from %q: %v", ErrInvalidValue, key, strVal, err)
		}
		parsed = v
	default:
		return nil, fmt.Errorf("%w: unsupported type %q for key %q", ErrInvalidValue, meta.Type, key)
	}

	if err := validateMeta(key, meta, parsed); err != nil {
		return nil, err
	}

	return parsed, nil
}

// ApplySetting mutates an OperationalSettings instance with the typed value for key.
// High-performance typed switch avoids reflection in the data-path setup.
func ApplySetting(s *OperationalSettings, key string, val any) error {
	if s == nil {
		return errors.New("cannot apply setting to nil OperationalSettings")
	}

	switch key {
	case "limits.max_payload_bytes":
		switch v := val.(type) {
		case int64:
			s.Limits.MaxPayloadBytes = v
		case int:
			s.Limits.MaxPayloadBytes = int64(v)
		case float64:
			s.Limits.MaxPayloadBytes = int64(v)
		default:
			return fmt.Errorf("%w: invalid type %T for %s", ErrInvalidValue, val, key)
		}
	case "limits.max_scanner_buffer_mb":
		switch v := val.(type) {
		case int:
			s.Limits.MaxScannerBufferMB = v
		case int64:
			s.Limits.MaxScannerBufferMB = int(v)
		case float64:
			s.Limits.MaxScannerBufferMB = int(v)
		default:
			return fmt.Errorf("%w: invalid type %T for %s", ErrInvalidValue, val, key)
		}
	case "limits.max_preview_bytes":
		switch v := val.(type) {
		case int:
			s.Limits.MaxPreviewBytes = v
		case int64:
			s.Limits.MaxPreviewBytes = int(v)
		case float64:
			s.Limits.MaxPreviewBytes = int(v)
		default:
			return fmt.Errorf("%w: invalid type %T for %s", ErrInvalidValue, val, key)
		}

	case "timeouts.tool_execution_sec":
		switch v := val.(type) {
		case int:
			s.Timeouts.ToolExecutionTimeoutSec = v
		case int64:
			s.Timeouts.ToolExecutionTimeoutSec = int(v)
		case float64:
			s.Timeouts.ToolExecutionTimeoutSec = int(v)
		default:
			return fmt.Errorf("%w: invalid type %T for %s", ErrInvalidValue, val, key)
		}
	case "timeouts.idle_timeout_sec":
		switch v := val.(type) {
		case int:
			s.Timeouts.IdleTimeoutSec = v
		case int64:
			s.Timeouts.IdleTimeoutSec = int(v)
		case float64:
			s.Timeouts.IdleTimeoutSec = int(v)
		default:
			return fmt.Errorf("%w: invalid type %T for %s", ErrInvalidValue, val, key)
		}
	case "timeouts.read_header_timeout_sec":
		switch v := val.(type) {
		case int:
			s.Timeouts.ReadHeaderTimeoutSec = v
		case int64:
			s.Timeouts.ReadHeaderTimeoutSec = int(v)
		case float64:
			s.Timeouts.ReadHeaderTimeoutSec = int(v)
		default:
			return fmt.Errorf("%w: invalid type %T for %s", ErrInvalidValue, val, key)
		}
	case "timeouts.probe_timeout_sec":
		switch v := val.(type) {
		case int:
			s.Timeouts.ProbeTimeoutSec = v
		case int64:
			s.Timeouts.ProbeTimeoutSec = int(v)
		case float64:
			s.Timeouts.ProbeTimeoutSec = int(v)
		default:
			return fmt.Errorf("%w: invalid type %T for %s", ErrInvalidValue, val, key)
		}

	case "guard.threshold_score":
		switch v := val.(type) {
		case float64:
			s.Guard.ThresholdScore = v
		case float32:
			s.Guard.ThresholdScore = float64(v)
		default:
			return fmt.Errorf("%w: invalid type %T for %s", ErrInvalidValue, val, key)
		}
	case "guard.timeout_ms":
		switch v := val.(type) {
		case int:
			s.Guard.TimeoutMS = v
		case int64:
			s.Guard.TimeoutMS = int(v)
		case float64:
			s.Guard.TimeoutMS = int(v)
		default:
			return fmt.Errorf("%w: invalid type %T for %s", ErrInvalidValue, val, key)
		}
	case "guard.cold_timeout_ms":
		switch v := val.(type) {
		case int:
			s.Guard.ColdTimeoutMS = v
		case int64:
			s.Guard.ColdTimeoutMS = int(v)
		case float64:
			s.Guard.ColdTimeoutMS = int(v)
		default:
			return fmt.Errorf("%w: invalid type %T for %s", ErrInvalidValue, val, key)
		}
	case "guard.hitl_timeout_sec":
		switch v := val.(type) {
		case int:
			s.Guard.HITLTimeoutSec = v
		case int64:
			s.Guard.HITLTimeoutSec = int(v)
		case float64:
			s.Guard.HITLTimeoutSec = int(v)
		default:
			return fmt.Errorf("%w: invalid type %T for %s", ErrInvalidValue, val, key)
		}

	case "maintenance.session_idle_timeout_min":
		switch v := val.(type) {
		case int:
			s.Maintenance.SessionIdleTimeoutMin = v
		case int64:
			s.Maintenance.SessionIdleTimeoutMin = int(v)
		case float64:
			s.Maintenance.SessionIdleTimeoutMin = int(v)
		default:
			return fmt.Errorf("%w: invalid type %T for %s", ErrInvalidValue, val, key)
		}
	case "maintenance.correlation_ttl_min":
		switch v := val.(type) {
		case int:
			s.Maintenance.CorrelationTTLMin = v
		case int64:
			s.Maintenance.CorrelationTTLMin = int(v)
		case float64:
			s.Maintenance.CorrelationTTLMin = int(v)
		default:
			return fmt.Errorf("%w: invalid type %T for %s", ErrInvalidValue, val, key)
		}

	default:
		return fmt.Errorf("%w: key %q has no mapping", ErrUnknownSetting, key)
	}

	return nil
}

// ExtractSetting extracts the current scalar value for a registered key from OperationalSettings.
func ExtractSetting(s *OperationalSettings, key string) (any, error) {
	if s == nil {
		return nil, errors.New("cannot extract setting from nil OperationalSettings")
	}

	switch key {
	case "limits.max_payload_bytes":
		return s.Limits.MaxPayloadBytes, nil
	case "limits.max_scanner_buffer_mb":
		return s.Limits.MaxScannerBufferMB, nil
	case "limits.max_preview_bytes":
		return s.Limits.MaxPreviewBytes, nil

	case "timeouts.tool_execution_sec":
		return s.Timeouts.ToolExecutionTimeoutSec, nil
	case "timeouts.idle_timeout_sec":
		return s.Timeouts.IdleTimeoutSec, nil
	case "timeouts.read_header_timeout_sec":
		return s.Timeouts.ReadHeaderTimeoutSec, nil
	case "timeouts.probe_timeout_sec":
		return s.Timeouts.ProbeTimeoutSec, nil

	case "guard.threshold_score":
		return s.Guard.ThresholdScore, nil
	case "guard.timeout_ms":
		return s.Guard.TimeoutMS, nil
	case "guard.cold_timeout_ms":
		return s.Guard.ColdTimeoutMS, nil
	case "guard.hitl_timeout_sec":
		return s.Guard.HITLTimeoutSec, nil

	case "maintenance.session_idle_timeout_min":
		return s.Maintenance.SessionIdleTimeoutMin, nil
	case "maintenance.correlation_ttl_min":
		return s.Maintenance.CorrelationTTLMin, nil

	default:
		return nil, fmt.Errorf("%w: key %q has no mapping", ErrUnknownSetting, key)
	}
}

// GetAllMetadata returns a slice of all registered settings metadata, sorted deterministically
// by Category and Key for predictable presentation in API responses.
func GetAllMetadata() []SettingMeta {
	items := make([]SettingMeta, 0, len(Registry))
	for _, meta := range Registry {
		items = append(items, meta)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Category == items[j].Category {
			return items[i].Key < items[j].Key
		}
		return items[i].Category < items[j].Category
	})
	return items
}
