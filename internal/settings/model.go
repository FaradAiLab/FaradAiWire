// Package settings provides domain models, type-safe registry catalogs,
// persistence stores, and zero-I/O in-memory atomic caches for FaradAiWire's
// operational settings overlay architecture.
package settings

// LimitsSettings defines payload, buffer, and preview ceiling thresholds.
type LimitsSettings struct {
	// MaxPayloadBytes is the maximum permissible payload size in bytes for MCP tool calls and responses.
	MaxPayloadBytes int64 `json:"max_payload_bytes"`
	// MaxScannerBufferMB is the maximum buffer size in megabytes for line/token scanning.
	MaxScannerBufferMB int `json:"max_scanner_buffer_mb"`
	// MaxPreviewBytes is the maximum preview snippet length in bytes.
	MaxPreviewBytes int `json:"max_preview_bytes"`
}

// TimeoutsSettings defines execution, keepalive, and idle deadlines.
type TimeoutsSettings struct {
	// ToolExecutionTimeoutSec is the maximum duration in seconds for MCP streamable tool execution.
	ToolExecutionTimeoutSec int `json:"tool_execution_timeout_sec"`
	// IdleTimeoutSec is the HTTP transport connection idle timeout in seconds.
	IdleTimeoutSec int `json:"idle_timeout_sec"`
	// ReadHeaderTimeoutSec is the HTTP server read header timeout in seconds.
	ReadHeaderTimeoutSec int `json:"read_header_timeout_sec"`
	// ProbeTimeoutSec is the maximum duration in seconds for active MCP server endpoint probing.
	ProbeTimeoutSec int `json:"probe_timeout_sec"`
}

// GuardSettings defines threat detection thresholds and SLA timings for the AI guard engine.
type GuardSettings struct {
	// ThresholdScore is the minimum malicious probability (0.0 to 1.0) to trigger a security block.
	ThresholdScore float64 `json:"threshold_score"`
	// TimeoutMS is the warm execution SLA in milliseconds for SLM guard inferences.
	TimeoutMS int `json:"timeout_ms"`
	// ColdTimeoutMS is the cold-start execution SLA in milliseconds for model loading.
	ColdTimeoutMS int `json:"cold_timeout_ms"`
	// HITLTimeoutSec is the maximum window in seconds to wait for human-in-the-loop confirmation.
	HITLTimeoutSec int `json:"hitl_timeout_sec"`
}

// MaintenanceSettings defines session retention and background cleanup intervals.
type MaintenanceSettings struct {
	// SessionIdleTimeoutMin is the inactive session lifetime in minutes before eviction.
	SessionIdleTimeoutMin int `json:"session_idle_timeout_min"`
	// CorrelationTTLMin is the retention TTL in minutes for request correlation tracking.
	CorrelationTTLMin int `json:"correlation_ttl_min"`
}

// OperationalSettings aggregates all runtime-tunable operational configuration parameters.
// Reads on proxy hot-paths access this model via an atomic pointer without lock contention.
type OperationalSettings struct {
	Limits      LimitsSettings      `json:"limits"`
	Timeouts    TimeoutsSettings    `json:"timeouts"`
	Guard       GuardSettings       `json:"guard"`
	Maintenance MaintenanceSettings `json:"maintenance"`
}

// DefaultOperationalSettings returns an OperationalSettings instance populated with
// production-hardened baseline defaults.
func DefaultOperationalSettings() *OperationalSettings {
	return &OperationalSettings{
		Limits: LimitsSettings{
			MaxPayloadBytes:    10 * 1024 * 1024, // 10MB
			MaxScannerBufferMB: 10,
			MaxPreviewBytes:    4096,
		},
		Timeouts: TimeoutsSettings{
			ToolExecutionTimeoutSec: 60,
			IdleTimeoutSec:          90,
			ReadHeaderTimeoutSec:    5,
			ProbeTimeoutSec:         5,
		},
		Guard: GuardSettings{
			ThresholdScore: 0.50,
			TimeoutMS:      1000,
			ColdTimeoutMS:  3000,
			HITLTimeoutSec: 60,
		},
		Maintenance: MaintenanceSettings{
			SessionIdleTimeoutMin: 30,
			CorrelationTTLMin:     60,
		},
	}
}

// Clone creates a deep copy of OperationalSettings for safe write-through mutation
// before atomic pointer exchange.
func (s *OperationalSettings) Clone() *OperationalSettings {
	if s == nil {
		return DefaultOperationalSettings()
	}
	return &OperationalSettings{
		Limits: LimitsSettings{
			MaxPayloadBytes:    s.Limits.MaxPayloadBytes,
			MaxScannerBufferMB: s.Limits.MaxScannerBufferMB,
			MaxPreviewBytes:    s.Limits.MaxPreviewBytes,
		},
		Timeouts: TimeoutsSettings{
			ToolExecutionTimeoutSec: s.Timeouts.ToolExecutionTimeoutSec,
			IdleTimeoutSec:          s.Timeouts.IdleTimeoutSec,
			ReadHeaderTimeoutSec:    s.Timeouts.ReadHeaderTimeoutSec,
			ProbeTimeoutSec:         s.Timeouts.ProbeTimeoutSec,
		},
		Guard: GuardSettings{
			ThresholdScore: s.Guard.ThresholdScore,
			TimeoutMS:      s.Guard.TimeoutMS,
			ColdTimeoutMS:  s.Guard.ColdTimeoutMS,
			HITLTimeoutSec: s.Guard.HITLTimeoutSec,
		},
		Maintenance: MaintenanceSettings{
			SessionIdleTimeoutMin: s.Maintenance.SessionIdleTimeoutMin,
			CorrelationTTLMin:     s.Maintenance.CorrelationTTLMin,
		},
	}
}
