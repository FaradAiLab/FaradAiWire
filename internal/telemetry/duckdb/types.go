package duckdb

import (
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/settings"
)

// Config configures the embedded DuckDB telemetry engine.
type Config struct {
	DBPath          string
	RetentionDays   int
	MaxSizeBytes    int64
	MaxPayloadBytes int
	BufferSize      int
	BatchFlushMs    int
	SettingsCache   *settings.Cache
}

// DefaultConfig returns optimal production defaults for Farad Ai Core.
func DefaultConfig() Config {
	return Config{
		DBPath:          "", // Filled with ~/.faradaiwire/wire.duckdb or :memory: in tests
		RetentionDays:   30,
		MaxSizeBytes:    1024 * 1024 * 1024, // 1 GB ceiling
		MaxPayloadBytes: 512 * 1024,         // 512 KB truncation ceiling
		BufferSize:      4096,               // Event channel buffer
		BatchFlushMs:    100,                // Flush write-behind batch every 100ms
	}
}

// AuditRecord represents a persisted analytical audit record in DuckDB.
type AuditRecord struct {
	ID                     string    `json:"id"`
	Timestamp              time.Time `json:"timestamp"`
	TraceID                string    `json:"trace_id,omitempty"`
	AgentName              string    `json:"agent_name"`
	ReleaseVersion         string    `json:"release_version"`
	ToolName               string    `json:"tool_name"`
	CallerRole             string    `json:"caller_role"`
	UserID                 string    `json:"user_id,omitempty"`
	ClientIP               string    `json:"client_ip,omitempty"`
	APIKeyID               string    `json:"api_key_id,omitempty"`
	PathType               string    `json:"path_type,omitempty"`
	Decision               string    `json:"decision"` // PENDING, ALLOWED, BLOCKED, MASKED, AUDIT, CRITICAL
	RequestDecision        string    `json:"request_decision,omitempty"`
	ResponseDecision       string    `json:"response_decision,omitempty"`
	MatchedRule            string    `json:"matched_rule,omitempty"`
	AuditedRules           []string  `json:"audited_rules,omitempty"`
	ErrorCode              int       `json:"error_code,omitempty"`
	ErrorMessage           string    `json:"error_message,omitempty"`
	HumanApproved          bool      `json:"human_approved,omitempty"`
	ApprovedBy             string    `json:"approved_by,omitempty"`
	ApprovalChannel        string    `json:"approval_channel,omitempty"`
	LatencyMs              float64   `json:"latency_ms"`
	InputSizeBytes         int       `json:"input_size_bytes"`
	OutputSizeBytes        int       `json:"output_size_bytes"`
	RawPayloadPreview      string    `json:"raw_payload_preview"`
	OriginalPayloadPreview string    `json:"original_payload_preview,omitempty"`
	OriginalRequest        string    `json:"original_request,omitempty"`
	Request                string    `json:"request,omitempty"`
	OriginalResponse       string    `json:"original_response,omitempty"`
	Response               string    `json:"response,omitempty"`
	HashVersion            string    `json:"hash_version,omitempty"`
	IntegrityHash          string    `json:"integrity_hash"`

	// UI Compatibility Aliases for embedded console
	Method      string                 `json:"method,omitempty"`
	Filter      string                 `json:"filter,omitempty"`
	Reason      string                 `json:"reason,omitempty"`
	UserContext map[string]interface{} `json:"user_context,omitempty"`
}

// QueryFilter defines criteria for querying audit logs from DuckDB.
type QueryFilter struct {
	Limit       int
	Offset      int
	Decision    string
	AgentName   string
	ToolName    string
	TraceID     string
	MatchedRule string
	Search      string
	SummaryOnly bool
	Since       *time.Time
	Until       *time.Time
}

// AuditQuerySummary contains server-computed aggregate counts across all audit records
// matching the active non-verdict query filters (independent of pagination LIMIT/OFFSET).
type AuditQuerySummary struct {
	Total        int64   `json:"total"`
	Allowed      int64   `json:"allowed"`
	Masked       int64   `json:"masked"`
	Audit        int64   `json:"audit"`
	Blocked      int64   `json:"blocked"` // Includes BLOCKED, ERROR, and CRITICAL
	AvgLatencyMs float64 `json:"avg_latency_ms"`
}

// QueryResult represents the paginated result of an audit query.
type QueryResult struct {
	Logs    []AuditRecord      `json:"logs"`
	Total   int64              `json:"total"`
	Limit   int                `json:"limit"`
	Offset  int                `json:"offset"`
	Summary *AuditQuerySummary `json:"summary,omitempty"`
}

// SecurityAuditRecord represents a persisted control-plane security audit record in DuckDB.
type SecurityAuditRecord struct {
	ID            string         `json:"id"`
	Timestamp     time.Time      `json:"timestamp"`
	TraceID       string         `json:"trace_id,omitempty"`
	EventType     string         `json:"event_type"`
	ActorID       string         `json:"actor_id"`
	ActorRole     string         `json:"actor_role"`
	ClientIP      string         `json:"client_ip,omitempty"`
	ResourceType  string         `json:"resource_type,omitempty"`
	ResourceID    string         `json:"resource_id,omitempty"`
	Action        string         `json:"action"`
	Outcome       string         `json:"outcome"`
	Reason        string         `json:"reason,omitempty"`
	Metadata      map[string]any `json:"metadata,omitempty"`
	HashVersion   string         `json:"hash_version,omitempty"`
	IntegrityHash string         `json:"integrity_hash"`
}

// SecurityQueryFilter defines criteria for querying control-plane security audit logs.
type SecurityQueryFilter struct {
	Limit     int
	Offset    int
	EventType string
	ActorID   string
	Outcome   string
	Since     *time.Time
	Until     *time.Time
}

// SecurityQueryResult represents the paginated result of a control-plane security audit query.
type SecurityQueryResult struct {
	Events []SecurityAuditRecord `json:"events"`
	Total  int64                 `json:"total"`
	Limit  int                   `json:"limit"`
	Offset int                   `json:"offset"`
}
