package filter

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
)

// AuditEvent represents a logged security decision.
type AuditEvent struct {
	ID              string       `json:"id,omitempty"`
	Timestamp       time.Time    `json:"timestamp"`
	AgentName       string       `json:"agent_name,omitempty"`
	ReleaseVersion  string       `json:"release_version,omitempty"`
	Method          string       `json:"method"`
	ToolName        string       `json:"tool_name,omitempty"`
	CallerRole      string       `json:"caller_role,omitempty"`
	PathType        string       `json:"path_type,omitempty"` // "FAST_PATH", "DEEP_PATH" (ADR-0010)
	FilterName      string       `json:"filter_name"`
	Decision        string       `json:"decision"` // "ALLOWED", "BLOCKED", "MASKED", "AUDIT"
	MatchedRule     string       `json:"matched_rule,omitempty"`
	ErrorCode       int          `json:"error_code,omitempty"`
	Message         string       `json:"message,omitempty"`
	User            *UserContext `json:"user_context,omitempty"`
	LatencyMs       float64      `json:"latency_ms"`
	TraceID         string       `json:"trace_id,omitempty"`
	InputBytes      int          `json:"input_size_bytes,omitempty"`
	OutputBytes     int          `json:"output_size_bytes,omitempty"`
	RawPayload      string       `json:"raw_payload_preview,omitempty"`
	OriginalPayload string       `json:"original_payload_preview,omitempty"`
	AuditedRules    []string     `json:"audited_rules,omitempty"`
	IntegrityHash   string       `json:"integrity_hash,omitempty"`
}

// maxPayloadPreviewBytes defines the maximum byte length of payload previews stored in AuditEvent (64 KB ceiling, NFR-MEM-2).
const maxPayloadPreviewBytes = 64 * 1024

func formatTruncatedTrailer(totalBytes int) string {
	if totalBytes >= 1024*1024 {
		return fmt.Sprintf("\n[TRUNCATED - Total Size: %.2f MB]", float64(totalBytes)/(1024*1024))
	}
	if totalBytes >= 1024 {
		return fmt.Sprintf("\n[TRUNCATED - Total Size: %.2f KB]", float64(totalBytes)/1024)
	}
	return fmt.Sprintf("\n[TRUNCATED - Total Size: %d bytes]", totalBytes)
}

// makePayloadPreview creates a bounded zero-copy-sliced string preview for audit logs.
func makePayloadPreview(data []byte) string {
	totalLen := len(data)
	if totalLen == 0 {
		return ""
	}
	if totalLen > maxPayloadPreviewBytes {
		return string(data[:maxPayloadPreviewBytes]) + formatTruncatedTrailer(totalLen)
	}
	return string(data)
}

// AuditLogger defines the interface for persisting audit events.
type AuditLogger interface {
	LogEvent(event *AuditEvent)
}

// MultiAuditLogger fans out audit events across multiple AuditLogger implementations.
type MultiAuditLogger struct {
	loggers []AuditLogger
}

// NewMultiAuditLogger creates a composite audit logger.
func NewMultiAuditLogger(loggers ...AuditLogger) *MultiAuditLogger {
	var valid []AuditLogger
	for _, l := range loggers {
		if l != nil {
			valid = append(valid, l)
		}
	}
	return &MultiAuditLogger{loggers: valid}
}

// LogEvent sends the audit event to all registered loggers.
func (m *MultiAuditLogger) LogEvent(event *AuditEvent) {
	if m == nil {
		return
	}
	for _, l := range m.loggers {
		l.LogEvent(event)
	}
}

func extractToolName(req *mcp.Request) string {
	if req == nil || req.Method != "tools/call" || len(req.Params) == 0 {
		return ""
	}
	var params struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(req.Params, &params); err == nil {
		return params.Name
	}
	return ""
}

