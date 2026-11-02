package types

import "context"

// ContextKey defines custom types for context variables.
type ContextKey string

const (
	// UserContextKey stores user metadata in the request context.
	UserContextKey ContextKey = "user"
	// TraceIDContextKey stores the trace ID in the request context.
	TraceIDContextKey ContextKey = "trace_id"
	// ToolNameContextKey stores the tool name in request/response context.
	ToolNameContextKey ContextKey = "tool_name"
	// PathTypeContextKey stores the execution path type (FAST_PATH / DEEP_PATH) in context.
	PathTypeContextKey ContextKey = "path_type"
	// AgentNameContextKey stores the resolved agent name for per-agent policy evaluation.
	AgentNameContextKey ContextKey = "agent_name"
	// HumanApprovedContextKey flags that a tool call was explicitly approved by a human operator,
	// establishing Human Supremacy over downstream SLM guards.
	HumanApprovedContextKey ContextKey = "human_approved"
)

// UserContext represents the end-user metadata triggering the AI agent.
type UserContext struct {
	UserID    string `json:"user_id"`
	Role      string `json:"role"`
	AgentName string `json:"agent_name,omitempty"`
}

// IsHumanApproved checks if human approval is present in context.
func IsHumanApproved(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	if val := ctx.Value(HumanApprovedContextKey); val != nil {
		if b, ok := val.(bool); ok && b {
			return true
		}
	}
	return false
}

// WithToolName binds the active MCP tool name to the context.
func WithToolName(ctx context.Context, toolName string) context.Context {
	return context.WithValue(ctx, ToolNameContextKey, toolName)
}

// GetToolName extracts the active MCP tool name from context, returning "" if not set.
func GetToolName(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if val := ctx.Value(ToolNameContextKey); val != nil {
		if s, ok := val.(string); ok {
			return s
		}
	}
	return ""
}

