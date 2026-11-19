package filter

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
)

// Audit phase and composite decision constants for consolidated invocation telemetry.
const (
	AuditPhaseRequest  = "request"
	AuditPhaseResponse = "response"
	AuditPhaseComplete = "complete"

	DecisionPending  = "PENDING"
	DecisionAllowed  = "ALLOWED"
	DecisionAudit    = "AUDIT"
	DecisionMasked   = "MASKED"
	DecisionError    = "ERROR"
	DecisionBlocked  = "BLOCKED"
	DecisionCritical = "CRITICAL"
)

// AuditEvent represents a logged security decision or invocation lifecycle update.
type AuditEvent struct {
	ID               string       `json:"id,omitempty"`
	Timestamp        time.Time    `json:"timestamp"`
	AgentName        string       `json:"agent_name,omitempty"`
	ReleaseVersion   string       `json:"release_version,omitempty"`
	Method           string       `json:"method"`
	ToolName         string       `json:"tool_name,omitempty"`
	CallerRole       string       `json:"caller_role,omitempty"`
	PathType         string       `json:"path_type,omitempty"` // "FAST_PATH", "DEEP_PATH" (ADR-0010)
	FilterName       string       `json:"filter_name"`
	Decision         string       `json:"decision"` // "PENDING", "ALLOWED", "BLOCKED", "MASKED", "AUDIT", "CRITICAL"
	RequestDecision  string       `json:"request_decision,omitempty"`
	ResponseDecision string       `json:"response_decision,omitempty"`
	Phase            string       `json:"phase,omitempty"`
	MatchedRule      string       `json:"matched_rule,omitempty"`
	ErrorCode        int          `json:"error_code,omitempty"`
	Message          string       `json:"message,omitempty"`
	ErrorMessage     string       `json:"error_message,omitempty"`
	User             *UserContext `json:"user_context,omitempty"`
	LatencyMs        float64      `json:"latency_ms"`
	TraceID          string       `json:"trace_id,omitempty"`
	InputBytes       int          `json:"input_size_bytes,omitempty"`
	OutputBytes      int          `json:"output_size_bytes,omitempty"`
	RawPayload       string       `json:"raw_payload_preview,omitempty"`
	OriginalPayload  string       `json:"original_payload_preview,omitempty"`
	OriginalRequest  string       `json:"original_request,omitempty"`
	Request          string       `json:"request,omitempty"`
	OriginalResponse string       `json:"original_response,omitempty"`
	Response         string       `json:"response,omitempty"`
	AuditedRules     []string     `json:"audited_rules,omitempty"`
	IntegrityHash    string       `json:"integrity_hash,omitempty"`
}

var decisionSeverityRank = map[string]int{
	DecisionPending:  0,
	DecisionAllowed:  1,
	"ALLOW":          1,
	DecisionAudit:    2,
	DecisionMasked:   3,
	"MASK":           3,
	DecisionError:    4,
	DecisionBlocked:  5,
	"BLOCK":          5,
	"DENIED":         5,
	DecisionCritical: 6,
}

func normalizeDecisionName(d string) string {
	upper := strings.ToUpper(strings.TrimSpace(d))
	switch upper {
	case "ALLOW":
		return DecisionAllowed
	case "MASK":
		return DecisionMasked
	case "BLOCK", "DENIED":
		return DecisionBlocked
	default:
		return upper
	}
}

// ResolveCompositeDecision merges request and response verdicts using
// severity precedence: CRITICAL > BLOCKED > MASKED > AUDIT > ALLOWED.
func ResolveCompositeDecision(reqDecision, respDecision string) string {
	reqNorm := normalizeDecisionName(reqDecision)
	respNorm := normalizeDecisionName(respDecision)

	if reqNorm == "" && respNorm == "" {
		return ""
	}
	if respNorm == "" {
		return reqNorm
	}
	if reqNorm == "" {
		return respNorm
	}

	reqRank := decisionSeverityRank[reqNorm]
	respRank := decisionSeverityRank[respNorm]
	if respRank >= reqRank {
		return respNorm
	}
	return reqNorm
}

// GenerateTraceID generates a unique 128-bit hex identifier for correlating
// request and response invocation telemetry when the client omits a trace ID.
func GenerateTraceID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("tr-%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

func redactBlockedPayload(cp *AuditEvent) {
	normDecision := normalizeDecisionName(cp.Decision)
	if normDecision != DecisionBlocked && normDecision != DecisionCritical {
		return
	}
	if strings.HasPrefix(cp.RawPayload, "[REDACTED - Blocked by ") {
		return
	}
	rule := cp.MatchedRule
	if rule == "" {
		rule = cp.FilterName
	}
	if rule == "" {
		rule = "policy"
	}
	msg := cp.ErrorMessage
	if msg == "" {
		msg = cp.Message
	}
	if msg != "" {
		cp.RawPayload = fmt.Sprintf("[REDACTED - Blocked by %s: %s]", rule, msg)
	} else {
		cp.RawPayload = fmt.Sprintf("[REDACTED - Blocked by %s]", rule)
	}
}

// RedactedCopy returns a shallow copy of AuditEvent safe for flat text logs and
// external sinks (ZERO-DLP BLEED). Unmasked local-vault snapshots are stripped, and
// blocked/critical events retain only explicit redaction notices in RawPayload.
func (e *AuditEvent) RedactedCopy() *AuditEvent {
	if e == nil {
		return nil
	}
	cp := *e
	cp.OriginalRequest = ""
	cp.Request = ""
	cp.OriginalResponse = ""
	cp.Response = ""
	cp.OriginalPayload = ""
	redactBlockedPayload(&cp)
	return &cp
}

// LightweightSummaryCopy returns a shallow copy suitable for debounced SSE streaming:
// heavy 4-field local-vault blobs are omitted, blocked/critical payloads are redacted,
// and RawPayload is bounded so live dashboard broadcasts stay fast and safe.
func (e *AuditEvent) LightweightSummaryCopy(maxPreviewBytes int) *AuditEvent {
	if e == nil {
		return nil
	}
	cp := *e
	cp.OriginalRequest = ""
	cp.Request = ""
	cp.OriginalResponse = ""
	cp.Response = ""
	cp.OriginalPayload = ""
	redactBlockedPayload(&cp)
	if maxPreviewBytes > 0 && len(cp.RawPayload) > maxPreviewBytes {
		totalLen := len(cp.RawPayload)
		cp.RawPayload = cp.RawPayload[:maxPreviewBytes] + FormatTruncatedTrailer(totalLen)
	}
	return &cp
}

// maxPayloadPreviewBytes defines the default fallback byte length of payload previews when no settings cache is attached (64 KB, NFR-MEM-2).
const maxPayloadPreviewBytes = 64 * 1024

// FormatTruncatedTrailer produces a deterministic trailer indicating the total pre-truncation payload size.
func FormatTruncatedTrailer(totalBytes int) string {
	if totalBytes >= 1024*1024 {
		return fmt.Sprintf("\n[TRUNCATED - Total Size: %.2f MB]", float64(totalBytes)/(1024*1024))
	}
	if totalBytes >= 1024 {
		return fmt.Sprintf("\n[TRUNCATED - Total Size: %.2f KB]", float64(totalBytes)/1024)
	}
	return fmt.Sprintf("\n[TRUNCATED - Total Size: %d bytes]", totalBytes)
}

// MakeBoundedPreview creates a bounded string representation capped at limit bytes.
// When limit <= 0, it falls back to maxPayloadPreviewBytes (64 KB).
func MakeBoundedPreview(data []byte, limit int) string {
	totalLen := len(data)
	if totalLen == 0 {
		return ""
	}
	if limit <= 0 {
		limit = maxPayloadPreviewBytes
	}
	if totalLen > limit {
		return string(data[:limit]) + FormatTruncatedTrailer(totalLen)
	}
	return string(data)
}

// makePayloadPreview creates a bounded zero-copy-sliced string preview for audit logs.
func makePayloadPreview(data []byte) string {
	return MakeBoundedPreview(data, maxPayloadPreviewBytes)
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
