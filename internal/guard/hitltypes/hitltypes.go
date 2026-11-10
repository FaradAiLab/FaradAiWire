// Package hitltypes defines pure-Go human-in-the-loop approval contracts so
// cross-platform filter packages do not transitively pull CGO/DuckDB dependencies.
package hitltypes

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrHITLDenied indicates human-in-the-loop approval was denied by an operator.
	ErrHITLDenied = errors.New("human-in-the-loop approval denied")

	// ErrHITLTimeout indicates approval timed out without operator interaction.
	ErrHITLTimeout = errors.New("human-in-the-loop approval timed out after 60s without operator interaction")

	// ErrHeadlessFailClosed indicates approval failed-closed because no interactive channels are attached.
	ErrHeadlessFailClosed = errors.New("human-in-the-loop approval denied: headless environment with neither TTY nor Web Console attached")
)

// HITLRequest holds the payload and semantic risk metadata for human-in-the-loop review.
type HITLRequest struct {
	CallID         string                 `json:"call_id"`
	ToolName       string                 `json:"tool_name"`
	Arguments      map[string]interface{} `json:"arguments"`
	RiskScore      float64                `json:"risk_score"`
	ThreatDomain   string                 `json:"threat_domain"`
	CWE            string                 `json:"cwe"`
	DecisionEngine string                 `json:"decision_engine"`
	CreatedAt      time.Time              `json:"created_at"`
	ExpiresAt      time.Time              `json:"expires_at"`
}

// HITLApprover abstracts dual-channel or interactive human-in-the-loop approval escalation.
type HITLApprover interface {
	RequestApproval(ctx context.Context, req *HITLRequest) (bool, error)
}
