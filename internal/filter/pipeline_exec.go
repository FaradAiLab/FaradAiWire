package filter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"strings"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/filter/adaptive"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/types"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
)

// ProcessRequest runs the request through appropriate filters based on adaptive path routing.
// It wraps filter execution with a top-level panic boundary to isolate failures and protect gateway sessions.
func (p *Pipeline) ProcessRequest(ctx context.Context, req *mcp.Request) (finalReq *mcp.Request, finalErr *mcp.Error) {
	p.mu.RLock()
	filters := make([]NamedFilter, len(p.filters))
	copy(filters, p.filters)
	router := p.router
	debugRetainUnmaskedDiff := p.debugRetainUnmaskedDiff
	logger := p.logger
	p.mu.RUnlock()

	var currentFilterName string = "pipeline"
	startTime := time.Now()

	var user *UserContext
	if val := ctx.Value(UserContextKey); val != nil {
		if u, ok := val.(*UserContext); ok {
			user = u
		}
	}

	var traceID string
	if val := ctx.Value(TraceIDContextKey); val != nil {
		if t, ok := val.(string); ok {
			traceID = t
		}
	}

	var agentName string = "default"
	if val := ctx.Value(AgentNameContextKey); val != nil {
		if an, ok := val.(string); ok && an != "" {
			agentName = an
		}
	} else if val := ctx.Value("agent_name"); val != nil {
		if an, ok := val.(string); ok && an != "" {
			agentName = an
		}
	}

	var callerRole string = "default"
	if user != nil && user.Role != "" {
		callerRole = user.Role
	}

	inputBytes := 0
	if req != nil && len(req.Params) > 0 {
		inputBytes = len(req.Params)
	}

	toolName := extractToolName(req)
	pathType := adaptive.PathDeep
	if router != nil && router.IsEnabled() && toolName != "" {
		pathType = router.Classify(toolName)
	}

	reqMethod := "unknown"
	if req != nil {
		reqMethod = req.Method
	}

	defer func() {
		if r := recover(); r != nil {
			stack := string(debug.Stack())
			totalLatency := float64(time.Since(startTime).Microseconds()) / 1000.0

			slog.Error("Panic recovered in filter pipeline request execution",
				slog.String("filter", currentFilterName),
				slog.String("method", reqMethod),
				slog.String("tool", toolName),
				slog.Any("panic", r),
				slog.String("stack", stack),
			)

			if logger != nil {
				logger.LogEvent(&AuditEvent{
					Timestamp:   time.Now(),
					AgentName:   agentName,
					CallerRole:  callerRole,
					Method:      reqMethod,
					ToolName:    toolName,
					PathType:    string(pathType),
					FilterName:  currentFilterName,
					MatchedRule: currentFilterName,
					Decision:    "CRITICAL",
					ErrorCode:   mcp.ErrInternalError,
					Message:     fmt.Sprintf("Panic recovered in filter '%s': %v\nStack:\n%s", currentFilterName, r, stack),
					User:        user,
					LatencyMs:   totalLatency,
					TraceID:     traceID,
					InputBytes:  inputBytes,
					RawPayload:  fmt.Sprintf("[REDACTED - Panic in %s]", currentFilterName),
				})
			}

			finalReq = nil
			finalErr = mcp.NewError(mcp.ErrInternalError, fmt.Sprintf("Internal error in filter '%s': %v", currentFilterName, r), nil)
		}
	}()

	auditMeta := &types.AuditMetadata{}
	ctx = context.WithValue(ctx, types.AuditMetadataKey, auditMeta)

	var initialPayloadPreview string
	if debugRetainUnmaskedDiff && req != nil && len(req.Params) > 0 {
		initialPayloadPreview = makePayloadPreview(req.Params)
	}

	current := req
	var mcpErr *mcp.Error
	var modifiedFilter string

	for _, f := range filters {
		currentFilterName = f.Name()

		sf, isSecFilter := f.(SecurityFilter)
		rf, isReqFilter := f.(RequestFilter)
		if !isSecFilter && !isReqFilter {
			continue
		}

		// Adaptive Fast-Path Optimization: Skip heavy filters if in fast-path (TICK-002 / ADR-0010)
		if router != nil && router.IsEnabled() && !router.ShouldExecuteFilter(f.Name(), pathType) {
			continue
		}

		filterStart := time.Now()
		var prevParams []byte
		if current != nil && len(current.Params) > 0 {
			prevParams = bytes.Clone(current.Params)
		}

		if isSecFilter {
			resp, err := sf.ExecuteRequest(ctx, current)
			if err != nil {
				var codeErr *mcp.Error
				if errors.As(err, &codeErr) {
					mcpErr = codeErr
				} else {
					mcpErr = mcp.NewError(mcp.ErrInvalidRequest, err.Error(), nil)
				}
			} else if resp != nil && resp.Error != nil {
				mcpErr = resp.Error
			}
		} else if isReqFilter {
			nextReq, err := rf.FilterRequest(ctx, current)
			if err != nil {
				mcpErr = err
			} else if nextReq != nil {
				current = nextReq
			}
		}
		latency := float64(time.Since(filterStart).Microseconds()) / 1000.0

		if mcpErr != nil {
			// Log block decision with explicit redaction note / blocking rule metadata (SEC-008)
			blockedPayload := fmt.Sprintf("[REDACTED - Blocked by %s: %s]", f.Name(), mcpErr.Message)
			if logger != nil {
				logger.LogEvent(&AuditEvent{
					Timestamp:   time.Now(),
					AgentName:   agentName,
					CallerRole:  callerRole,
					Method:      reqMethod,
					ToolName:    toolName,
					PathType:    string(pathType),
					FilterName:  f.Name(),
					MatchedRule: f.Name(),
					Decision:    "BLOCKED",
					ErrorCode:   mcpErr.Code,
					Message:     mcpErr.Message,
					User:        user,
					LatencyMs:   latency,
					TraceID:     traceID,
					InputBytes:  inputBytes,
					RawPayload:  blockedPayload,
				})
			}
			return nil, mcpErr
		}

		if current != nil && !bytes.Equal(prevParams, current.Params) {
			modifiedFilter = f.Name()
		}
	}

	// Capture post-filtered payload preview strictly AFTER filter chain execution (SEC-008)
	rawPayload := ""
	if current != nil && len(current.Params) > 0 {
		inputBytes = len(current.Params)
		rawPayload = makePayloadPreview(current.Params)
	}

	decision := "ALLOWED"
	filterName := "pipeline"
	matchedRule := ""
	var auditedRules []string
	if modifiedFilter != "" {
		decision = "MASKED"
		filterName = modifiedFilter
		matchedRule = modifiedFilter
	} else if len(auditMeta.AuditedRules) > 0 {
		decision = "AUDIT"
		filterName = auditMeta.FilterName
		if filterName == "" {
			filterName = "dlp"
		}
		matchedRule = strings.Join(auditMeta.AuditedRules, ",")
		auditedRules = auditMeta.AuditedRules
	}

	var origPayload string
	if debugRetainUnmaskedDiff && (decision == "MASKED" || decision == "AUDIT") {
		origPayload = initialPayloadPreview
	}

	// Log allowed/masked/audited request if it passed all filters
	if logger != nil && reqMethod == "tools/call" {
		totalLatency := float64(time.Since(startTime).Microseconds()) / 1000.0
		logger.LogEvent(&AuditEvent{
			Timestamp:       time.Now(),
			AgentName:       agentName,
			CallerRole:      callerRole,
			Method:          reqMethod,
			ToolName:        toolName,
			PathType:        string(pathType),
			FilterName:      filterName,
			MatchedRule:     matchedRule,
			Decision:        decision,
			User:            user,
			LatencyMs:       totalLatency,
			TraceID:         traceID,
			InputBytes:      inputBytes,
			RawPayload:      rawPayload,
			OriginalPayload: origPayload,
			AuditedRules:    auditedRules,
		})
	}

	return current, nil
}

// ProcessResponse runs the response through all response-path filters.
// It wraps filter execution with a top-level panic boundary to isolate failures and protect gateway sessions.
func (p *Pipeline) ProcessResponse(ctx context.Context, resp *mcp.Response) (finalResp *mcp.Response, finalErr *mcp.Error) {
	p.mu.RLock()
	filters := make([]NamedFilter, len(p.filters))
	copy(filters, p.filters)
	router := p.router
	debugRetainUnmaskedDiff := p.debugRetainUnmaskedDiff
	logger := p.logger
	p.mu.RUnlock()

	var currentFilterName string = "pipeline"
	startTime := time.Now()

	var user *UserContext
	if val := ctx.Value(UserContextKey); val != nil {
		if u, ok := val.(*UserContext); ok {
			user = u
		}
	}

	var traceID string
	if val := ctx.Value(TraceIDContextKey); val != nil {
		if t, ok := val.(string); ok {
			traceID = t
		}
	}

	var agentName string = "default"
	if val := ctx.Value(AgentNameContextKey); val != nil {
		if an, ok := val.(string); ok && an != "" {
			agentName = an
		}
	} else if val := ctx.Value("agent_name"); val != nil {
		if an, ok := val.(string); ok && an != "" {
			agentName = an
		}
	}

	var callerRole string = "default"
	if user != nil && user.Role != "" {
		callerRole = user.Role
	}

	outputBytes := 0
	if resp != nil && len(resp.Result) > 0 {
		outputBytes = len(resp.Result)
	}

	toolName := types.GetToolName(ctx)

	pathType := adaptive.PathDeep
	if val := ctx.Value(PathTypeContextKey); val != nil {
		if pt, ok := val.(adaptive.PathType); ok {
			pathType = pt
		}
	} else if router != nil && router.IsEnabled() && toolName != "" {
		pathType = router.Classify(toolName)
	}

	defer func() {
		if r := recover(); r != nil {
			stack := string(debug.Stack())
			totalLatency := float64(time.Since(startTime).Microseconds()) / 1000.0

			slog.Error("Panic recovered in filter pipeline response execution",
				slog.String("filter", currentFilterName),
				slog.String("tool", toolName),
				slog.Any("panic", r),
				slog.String("stack", stack),
			)

			if logger != nil {
				logger.LogEvent(&AuditEvent{
					Timestamp:   time.Now(),
					AgentName:   agentName,
					CallerRole:  callerRole,
					Method:      "response",
					ToolName:    toolName,
					PathType:    string(pathType),
					FilterName:  currentFilterName,
					MatchedRule: currentFilterName,
					Decision:    "CRITICAL",
					ErrorCode:   mcp.ErrInternalError,
					Message:     fmt.Sprintf("Panic recovered in filter '%s': %v\nStack:\n%s", currentFilterName, r, stack),
					User:        user,
					LatencyMs:   totalLatency,
					TraceID:     traceID,
					OutputBytes: outputBytes,
					RawPayload:  fmt.Sprintf("[REDACTED - Panic in %s]", currentFilterName),
				})
			}

			finalResp = nil
			finalErr = mcp.NewError(mcp.ErrInternalError, fmt.Sprintf("Internal error in filter '%s': %v", currentFilterName, r), nil)
		}
	}()

	auditMeta := &types.AuditMetadata{}
	ctx = context.WithValue(ctx, types.AuditMetadataKey, auditMeta)

	var initialPayloadPreview string
	if debugRetainUnmaskedDiff && resp != nil && len(resp.Result) > 0 {
		initialPayloadPreview = makePayloadPreview(resp.Result)
	}

	current := resp
	var mcpErr *mcp.Error
	var modifiedFilter string

	for _, f := range filters {
		currentFilterName = f.Name()

		sf, isSecFilter := f.(SecurityFilter)
		respFilter, isRespFilter := f.(ResponseFilter)
		if !isSecFilter && !isRespFilter {
			continue
		}

		// Adaptive Fast-Path Optimization: Skip heavy filters if in fast-path (TICK-002 / ADR-0010)
		if router != nil && router.IsEnabled() && !router.ShouldExecuteFilter(f.Name(), pathType) {
			continue
		}

		filterStart := time.Now()
		var prevResult []byte
		if current != nil && len(current.Result) > 0 {
			prevResult = bytes.Clone(current.Result)
		}

		if isSecFilter {
			nextResp, err := sf.ExecuteResponse(ctx, current)
			if err != nil {
				var codeErr *mcp.Error
				if errors.As(err, &codeErr) {
					mcpErr = codeErr
				} else {
					mcpErr = mcp.NewError(mcp.ErrInternalError, err.Error(), nil)
				}
			} else if nextResp != nil {
				current = nextResp
				if current.Error != nil {
					mcpErr = current.Error
				}
			}
		} else if isRespFilter {
			nextResp, err := respFilter.FilterResponse(ctx, current)
			if err != nil {
				mcpErr = err
			} else if nextResp != nil {
				current = nextResp
			}
		}
		latency := float64(time.Since(filterStart).Microseconds()) / 1000.0

		if mcpErr != nil {
			// Log block decision with explicit redaction note / blocking rule metadata (SEC-008)
			blockedPayload := fmt.Sprintf("[REDACTED - Blocked by %s: %s]", f.Name(), mcpErr.Message)
			if logger != nil {
				logger.LogEvent(&AuditEvent{
					Timestamp:   time.Now(),
					AgentName:   agentName,
					CallerRole:  callerRole,
					Method:      "response",
					ToolName:    toolName,
					PathType:    string(pathType),
					FilterName:  f.Name(),
					MatchedRule: f.Name(),
					Decision:    "BLOCKED",
					ErrorCode:   mcpErr.Code,
					Message:     mcpErr.Message,
					User:        user,
					LatencyMs:   latency,
					TraceID:     traceID,
					OutputBytes: outputBytes,
					RawPayload:  blockedPayload,
				})
			}
			return nil, mcpErr
		}

		if current != nil && !bytes.Equal(prevResult, current.Result) {
			modifiedFilter = f.Name()
		}
	}

	// Capture post-filtered payload preview strictly AFTER filter chain execution (SEC-008)
	rawPayload := ""
	if current != nil && len(current.Result) > 0 {
		outputBytes = len(current.Result)
		rawPayload = makePayloadPreview(current.Result)
	}

	decision := "ALLOWED"
	filterName := "pipeline"
	matchedRule := ""
	var auditedRules []string
	if modifiedFilter != "" {
		decision = "MASKED"
		filterName = modifiedFilter
		matchedRule = modifiedFilter
	} else if len(auditMeta.AuditedRules) > 0 {
		decision = "AUDIT"
		filterName = auditMeta.FilterName
		if filterName == "" {
			filterName = "dlp"
		}
		matchedRule = strings.Join(auditMeta.AuditedRules, ",")
		auditedRules = auditMeta.AuditedRules
	}

	var origPayload string
	if debugRetainUnmaskedDiff && (decision == "MASKED" || decision == "AUDIT") {
		origPayload = initialPayloadPreview
	}

	// Log allowed/masked/audited response
	if logger != nil {
		totalLatency := float64(time.Since(startTime).Microseconds()) / 1000.0
		logger.LogEvent(&AuditEvent{
			Timestamp:       time.Now(),
			AgentName:       agentName,
			CallerRole:      callerRole,
			Method:          "response",
			ToolName:        toolName,
			PathType:        string(pathType),
			FilterName:      filterName,
			MatchedRule:     matchedRule,
			Decision:        decision,
			User:            user,
			LatencyMs:       totalLatency,
			TraceID:         traceID,
			OutputBytes:     outputBytes,
			RawPayload:      rawPayload,
			OriginalPayload: origPayload,
			AuditedRules:    auditedRules,
		})
	}

	return current, nil
}

