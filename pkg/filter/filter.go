// Package filter defines the public interfaces, lifecycle methods, and execution
// precedence order for FaradAiWire security inspectors.
package filter

import (
	"context"

	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
)

// Canonical execution order precedence for security filters.
// Lower integer values execute earlier in the pipeline.
const (
	// OrderPrefill defines the pipeline precedence for assistant prefill injection detection.
	OrderPrefill = 5
	// OrderRateLimit defines the pipeline precedence for token-bucket rate limiting.
	OrderRateLimit = 10
	// OrderLoopProtection defines the pipeline precedence for infinite tool reasoning loop detection.
	OrderLoopProtection = 15
	// OrderPolicy defines the pipeline precedence for external or custom authorization policy evaluation.
	OrderPolicy = 20
	// OrderSchemaValidation defines the pipeline precedence for JSON schema parameter verification.
	OrderSchemaValidation = 30
	// OrderDLP defines the pipeline precedence for data loss prevention and sensitive PII redaction.
	OrderDLP = 50
	// OrderGuard defines the pipeline precedence for SLM extensible security guard (GUARD-004).
	OrderGuard = 55
	// OrderInjectionScanner defines the pipeline precedence for prompt injection scanning.
	OrderInjectionScanner = 60
	// OrderHITL defines the pipeline precedence for human-in-the-loop verification gates.
	OrderHITL = 70
)

// NamedFilter provides an identifier for the filter.
type NamedFilter interface {
	Name() string
}

// OrderedFilter provides pipeline execution precedence.
type OrderedFilter interface {
	NamedFilter
	Order() int
}

// RequestFilter inspects, validates, or modifies an incoming MCP request.
type RequestFilter interface {
	NamedFilter
	FilterRequest(ctx context.Context, req *mcp.Request) (*mcp.Request, *mcp.Error)
}

// ResponseFilter inspects, validates, or modifies an outgoing MCP response.
type ResponseFilter interface {
	NamedFilter
	FilterResponse(ctx context.Context, resp *mcp.Response) (*mcp.Response, *mcp.Error)
}

// SecurityFilter defines the canonical interface for all security pipeline inspectors (ADR-0022 / ARCH-027).
type SecurityFilter interface {
	Name() string
	Order() int
	ExecuteRequest(ctx context.Context, req *mcp.Request) (*mcp.Response, error)
	ExecuteResponse(ctx context.Context, resp *mcp.Response) (*mcp.Response, error)
}

// BaseSecurityFilter provides default implementations for ExecuteRequest and ExecuteResponse.
// Built-in and external filters can embed this struct to satisfy SecurityFilter.
type BaseSecurityFilter struct{}

// ExecuteRequest provides a default pass-through implementation.
func (BaseSecurityFilter) ExecuteRequest(ctx context.Context, req *mcp.Request) (*mcp.Response, error) {
	return nil, nil
}

// ExecuteResponse provides a default pass-through implementation.
func (BaseSecurityFilter) ExecuteResponse(ctx context.Context, resp *mcp.Response) (*mcp.Response, error) {
	return resp, nil
}

// Filter represents any pluggable filter component in the gateway.
type Filter = NamedFilter
