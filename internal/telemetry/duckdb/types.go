package duckdb

import (
	"time"
)

// Config configures the embedded DuckDB telemetry engine.
type Config struct {
	DBPath          string
	RetentionDays   int
	MaxSizeBytes    int64
	MaxPayloadBytes int
	BufferSize      int
	BatchFlushMs    int
}

// DefaultConfig returns optimal production defaults for Farad Ai Core.
func DefaultConfig() Config {
	return Config{
		DBPath:          "", // Filled with ~/.faradaiwire/wire.duckdb or :memory: in tests
		RetentionDays:   14,
		MaxSizeBytes:    1024 * 1024 * 1024, // 1 GB ceiling
		MaxPayloadBytes: 64 * 1024,          // 64 KB truncation ceiling
		BufferSize:      4096,               // Event channel buffer
		BatchFlushMs:    100,                // Flush write-behind batch every 100ms
	}
}

// AuditRecord represents a persisted analytical audit record in DuckDB.
type AuditRecord struct {
	ID                string    `json:"id"`
	Timestamp         time.Time `json:"timestamp"`
	AgentName         string    `json:"agent_name"`
	ReleaseVersion    string    `json:"release_version"`
	ToolName          string    `json:"tool_name"`
	CallerRole        string    `json:"caller_role"`
	Decision          string    `json:"decision"` // ALLOW, BLOCK, MASK, RATE_LIMITED, etc.
	MatchedRule       string    `json:"matched_rule,omitempty"`
	LatencyMs         float64   `json:"latency_ms"`
	InputSizeBytes    int       `json:"input_size_bytes"`
	OutputSizeBytes   int       `json:"output_size_bytes"`
	RawPayloadPreview      string `json:"raw_payload_preview"`
	OriginalPayloadPreview string `json:"original_payload_preview,omitempty"`
	IntegrityHash          string `json:"integrity_hash"`

	// UI Compatibility Aliases for embedded console
	Method      string                 `json:"method,omitempty"`
	Filter      string                 `json:"filter,omitempty"`
	Reason      string                 `json:"reason,omitempty"`
	UserContext map[string]interface{} `json:"user_context,omitempty"`
}

// QueryFilter defines criteria for querying audit logs from DuckDB.
type QueryFilter struct {
	Limit     int
	Offset    int
	Decision  string
	AgentName string
	ToolName  string
	Since     *time.Time
	Until     *time.Time
}

// QueryResult represents the paginated result of an audit query.
type QueryResult struct {
	Logs   []AuditRecord `json:"logs"`
	Total  int64         `json:"total"`
	Limit  int           `json:"limit"`
	Offset int           `json:"offset"`
}
