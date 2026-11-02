package guard

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrProcessNotRunning indicates a call was attempted while the guard provider is offline.
	ErrProcessNotRunning = errors.New("guard subprocess is not running")

	// ErrProcessAlreadyRunning indicates Start was called when a provider is already active.
	ErrProcessAlreadyRunning = errors.New("guard subprocess is already running")

	// ErrQueueFull indicates load shedding to L1 because the in-flight concurrency slots are saturated.
	ErrQueueFull = errors.New("guard queue depth exceeded: load shedding to L1")

	// ErrTimeout indicates execution timed out against the SLA budget.
	ErrTimeout = errors.New("guard execution timeout exceeded SLA budget")

	// ErrProcessTerminated indicates the provider terminated or connection closed unexpectedly.
	ErrProcessTerminated = errors.New("guard subprocess terminated unexpectedly")
)

// InspectionRequest represents the argument payload for inspecting a tool call.
type InspectionRequest struct {
	ToolName         string                 `json:"tool_name"`
	ToolArguments    map[string]interface{} `json:"tool_arguments"`
	ExecutionContext string                 `json:"execution_context,omitempty"`
	EnableL1Cascade  bool                   `json:"enable_l1_cascade,omitempty"`
}

// InspectionResult represents the threat verdict and telemetry scoring returned by the guard SLM.
type InspectionResult struct {
	Verdict              string  `json:"verdict"` // "BENIGN", "BLOCKED", "SUSPICIOUS"
	MaliciousProbability float64 `json:"malicious_probability"`
	AlignmentRisk        float64 `json:"alignment_risk"`
	ExploitRisk          float64 `json:"exploit_risk"`
	DecisionEngine       string  `json:"decision_engine"`
	ThreatDomain         string  `json:"threat_domain,omitempty"`
	CWE                  string  `json:"cwe,omitempty"`
	LatencyMS            float64 `json:"latency_ms"`
}

// ProcessStatus reports active provider state for CLI diagnostics and Web Console monitoring.
type ProcessStatus struct {
	Running      bool       `json:"running"`
	ModelID      string     `json:"model_id,omitempty"`
	PID          int        `json:"pid"`
	MemoryRSSMB  float64    `json:"memory_rss_mb"`
	HealthStatus string     `json:"health_status"` // "HEALTHY", "DEGRADED", "STOPPED", "FAILED"
	StartedAt    *time.Time `json:"started_at,omitempty"`
}

// Manager defines the operational lifecycle and execution contract for SLM guards.
type Manager interface {
	Start(ctx context.Context, model *Model) error
	StartScript(ctx context.Context, scriptPath string, modelID string) error
	Stop(ctx context.Context) error
	CallInspect(ctx context.Context, req *InspectionRequest) (*InspectionResult, error)
	Status() ProcessStatus
	IsRunning() bool
}
