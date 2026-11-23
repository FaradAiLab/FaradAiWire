package logger

import (
	"context"
	"log/slog"
	"os"

	"github.com/FaradAiLab/FaradAiWire/internal/filter"
)

// ContextHandler wraps a slog.Handler and enriches every record with request-scoped
// trace/invocation/agent correlation identifiers present on ctx.
type ContextHandler struct {
	next slog.Handler
}

// NewContextHandler wraps next so slog.*Context records automatically attach
// trace_id, invocation_id, and agent_name when present in context.Context.
func NewContextHandler(next slog.Handler) *ContextHandler {
	if next == nil {
		next = slog.NewJSONHandler(os.Stderr, nil)
	}
	return &ContextHandler{next: next}
}

// Enabled delegates level filtering to the wrapped handler.
func (h *ContextHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

// Handle clones the record and appends trace_id, invocation_id, and agent_name from ctx
// if present and not already attached explicitly by the caller.
func (h *ContextHandler) Handle(ctx context.Context, r slog.Record) error {
	if ctx != nil {
		hasTrace := false
		hasInvocation := false
		hasAgent := false
		r.Attrs(func(a slog.Attr) bool {
			switch a.Key {
			case "trace_id":
				hasTrace = true
			case "invocation_id":
				hasInvocation = true
			case "agent_name":
				hasAgent = true
			}
			return true
		})

		cloned := r.Clone()
		added := false
		if !hasTrace {
			if traceID, _ := ctx.Value(filter.TraceIDContextKey).(string); traceID != "" {
				cloned.AddAttrs(slog.String("trace_id", traceID))
				added = true
			}
		}
		if !hasInvocation {
			if invID, _ := ctx.Value(filter.InvocationIDContextKey).(string); invID != "" {
				cloned.AddAttrs(slog.String("invocation_id", invID))
				added = true
			}
		}
		if !hasAgent {
			if agentName, _ := ctx.Value(filter.AgentNameContextKey).(string); agentName != "" {
				cloned.AddAttrs(slog.String("agent_name", agentName))
				added = true
			}
		}
		if added {
			r = cloned
		}
	}
	return h.next.Handle(ctx, r)
}

// WithAttrs returns a new ContextHandler wrapping next.WithAttrs(attrs).
func (h *ContextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &ContextHandler{next: h.next.WithAttrs(attrs)}
}

// WithGroup returns a new ContextHandler wrapping next.WithGroup(name).
func (h *ContextHandler) WithGroup(name string) slog.Handler {
	return &ContextHandler{next: h.next.WithGroup(name)}
}
