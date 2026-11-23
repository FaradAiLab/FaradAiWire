package types

import (
	"context"

	"github.com/FaradAiLab/FaradAiWire/pkg/filter/types"
)

// ContextKey defines custom types for context variables re-exported from pkg/filter/types.
type ContextKey = types.ContextKey

const (
	// UserContextKey stores user metadata in the request context.
	UserContextKey = types.UserContextKey
	// TraceIDContextKey stores the trace ID in the request context.
	TraceIDContextKey = types.TraceIDContextKey
	// InvocationIDContextKey stores the unique per-call invocation record ID across request and response phases.
	InvocationIDContextKey ContextKey = "invocation_id"
	// ToolNameContextKey stores the tool name in request/response context.
	ToolNameContextKey = types.ToolNameContextKey
	// PathTypeContextKey stores the execution path type (FAST_PATH / DEEP_PATH) in context.
	PathTypeContextKey = types.PathTypeContextKey
	// AgentNameContextKey stores the resolved agent name for per-agent policy evaluation.
	AgentNameContextKey = types.AgentNameContextKey
	// HumanApprovedContextKey flags that a tool call was explicitly approved by a human operator.
	HumanApprovedContextKey = types.HumanApprovedContextKey
	// AuditMetadataKey stores live filter audit recordings in the request/response context.
	AuditMetadataKey ContextKey = "audit_metadata"
)

// UserContext represents the end-user metadata triggering the AI agent.
type UserContext = types.UserContext

// AuditMetadata records non-mutating audit observations and HITL resolution provenance across filter pipelines.
type AuditMetadata struct {
	AuditedRules    []string
	FilterName      string
	HumanApproved   bool
	ApprovedBy      string
	ApprovalChannel string
}

// WithAuditMetadata attaches an AuditMetadata pointer to context.
func WithAuditMetadata(ctx context.Context, meta *AuditMetadata) context.Context {
	return context.WithValue(ctx, AuditMetadataKey, meta)
}

// GetAuditMetadata retrieves the AuditMetadata pointer from context, or nil if not found.
func GetAuditMetadata(ctx context.Context) *AuditMetadata {
	if meta, ok := ctx.Value(AuditMetadataKey).(*AuditMetadata); ok {
		return meta
	}
	return nil
}

// WithHumanApproved attaches the human approval flag to context.
func WithHumanApproved(ctx context.Context, approved bool) context.Context {
	return context.WithValue(ctx, HumanApprovedContextKey, approved)
}

// SetHumanApproved marks the in-flight request context as approved by a human operator.
func SetHumanApproved(ctx context.Context, approved bool) {
	if meta := GetAuditMetadata(ctx); meta != nil {
		meta.HumanApproved = approved
	}
}

// SetHITLResolution records the full HITL decision provenance on the request's AuditMetadata.
func SetHITLResolution(ctx context.Context, approved bool, approvedBy, channel string) {
	if meta := GetAuditMetadata(ctx); meta != nil {
		meta.HumanApproved = approved
		meta.ApprovedBy = approvedBy
		meta.ApprovalChannel = channel
	}
}

// IsHumanApproved checks if human approval has been granted via context value or audit metadata.
func IsHumanApproved(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	if val := ctx.Value(HumanApprovedContextKey); val != nil {
		if b, ok := val.(bool); ok && b {
			return true
		}
	}
	if meta := GetAuditMetadata(ctx); meta != nil && meta.HumanApproved {
		return true
	}
	return false
}

// WithToolName binds the active MCP tool name to the context.
var WithToolName = types.WithToolName

// GetToolName extracts the active MCP tool name from context, returning "" if not set.
var GetToolName = types.GetToolName

// GetAgentName resolves the active agent profile name from context, supporting typed
// AgentNameContextKey and legacy string keys ("agent_name", "agent").
func GetAgentName(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if val := ctx.Value(AgentNameContextKey); val != nil {
		if s, ok := val.(string); ok && s != "" {
			return s
		}
	}
	if val := ctx.Value("agent_name"); val != nil {
		if s, ok := val.(string); ok && s != "" {
			return s
		}
	}
	if val := ctx.Value("agent"); val != nil {
		if s, ok := val.(string); ok && s != "" {
			return s
		}
	}
	return ""
}
