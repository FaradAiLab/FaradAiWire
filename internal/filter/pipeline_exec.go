package filter

import (
	"bytes"
	"context"
	"encoding/json"
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

func (p *Pipeline) captureConfig() (previewLimit int, retainLocalPayloads bool) {
	previewLimit = maxPayloadPreviewBytes
	retainLocalPayloads = true
	if p == nil {
		return previewLimit, retainLocalPayloads
	}
	p.mu.RLock()
	sc := p.settingsCache
	p.mu.RUnlock()
	if sc != nil {
		if s := sc.Get(); s != nil {
			if s.Limits.MaxPreviewBytes > 0 {
				previewLimit = s.Limits.MaxPreviewBytes
			}
			retainLocalPayloads = s.Maintenance.RetainLocalPayloads
		}
	}
	return previewLimit, retainLocalPayloads
}

func resolveContextCorrelation(ctx context.Context) (invocationID, traceID string, hasExplicitInvocation bool) {
	if ctx != nil {
		if tVal := ctx.Value(TraceIDContextKey); tVal != nil {
			if t, ok := tVal.(string); ok {
				traceID = t
			}
		}
		if iVal := ctx.Value(InvocationIDContextKey); iVal != nil {
			if id, ok := iVal.(string); ok && id != "" {
				invocationID = id
				hasExplicitInvocation = true
			}
		}
	}
	if invocationID == "" {
		if traceID != "" {
			invocationID = traceID
		} else {
			invocationID = GenerateTraceID()
		}
	}
	if traceID == "" {
		traceID = invocationID
	}
	return invocationID, traceID, hasExplicitInvocation
}

// EmitResponseFailure records an upstream dispatch/transport failure or post-filter policy block
// as a response completion event, respecting operational retention and preview-size limits.
func (p *Pipeline) EmitResponseFailure(
	ctx context.Context,
	invocationID, traceID, agentName, toolName, filterName, decision, errMsg string,
	respBytes []byte,
) {
	if p == nil || invocationID == "" {
		return
	}
	logger := p.GetAuditLogger()
	if logger == nil {
		return
	}
	if decision == "" {
		decision = DecisionError
	}
	if agentName == "" {
		agentName = types.GetAgentName(ctx)
		if agentName == "" {
			agentName = "default"
		}
	}
	previewLimit, retainLocalPayloads := p.captureConfig()
	var origResp string
	var finalResp string
	var rawPayload string
	if retainLocalPayloads && len(respBytes) > 0 {
		preview := MakeBoundedPreview(respBytes, previewLimit)
		if decision == DecisionBlocked {
			// Pre-upstream policy block: no upstream OriginalResponse exists; error JSON is final Response.
			finalResp = preview
			rawPayload = fmt.Sprintf("[REDACTED - Blocked by %s: %s]", filterName, errMsg)
		} else {
			origResp = preview
			rawPayload = preview
		}
	}
	logger.LogEvent(&AuditEvent{
		ID:               invocationID,
		TraceID:          traceID,
		Timestamp:        time.Now(),
		AgentName:        agentName,
		Method:           "response",
		ToolName:         toolName,
		FilterName:       filterName,
		Phase:            AuditPhaseResponse,
		Decision:         decision,
		ResponseDecision: decision,
		ErrorMessage:     errMsg,
		OutputBytes:      len(respBytes),
		RawPayload:       rawPayload,
		OriginalResponse: origResp,
		Response:         finalResp,
	})
}

func formatBlockedRPCResponse(reqID any, mcpErr *mcp.Error) string {
	if mcpErr == nil {
		return ""
	}
	errResp := mcp.NewErrorResponse(reqID, mcpErr.Code, mcpErr.Message, mcpErr.Data)
	b, err := json.Marshal(errResp)
	if err != nil {
		return ""
	}
	return string(b)
}

func extractResponseRawBytes(resp *mcp.Response) []byte {
	if resp == nil {
		return nil
	}
	if len(resp.Result) > 0 {
		return resp.Result
	}
	if resp.Error != nil {
		if b, err := json.Marshal(resp.Error); err == nil {
			return b
		}
	}
	return nil
}

// ProcessRequest runs the request through appropriate filters based on adaptive path routing.
// It wraps filter execution with a top-level panic boundary to isolate failures and protect gateway sessions.
func (p *Pipeline) ProcessRequest(ctx context.Context, req *mcp.Request) (finalReq *mcp.Request, finalErr *mcp.Error) {
	p.mu.RLock()
	filters := p.filters
	router := p.router
	debugRetainUnmaskedDiff := p.debugRetainUnmaskedDiff
	logger := p.logger
	p.mu.RUnlock()

	var currentFilterName string = "pipeline"
	startTime := time.Now()

	invocationID, traceID, hasExplicitInvocation := resolveContextCorrelation(ctx)
	previewLimit, retainLocalPayloads := p.captureConfig()

	var user *UserContext
	if val := ctx.Value(UserContextKey); val != nil {
		if u, ok := val.(*UserContext); ok {
			user = u
		}
	}

	agentName := types.GetAgentName(ctx)
	if agentName == "" {
		agentName = "default"
	}

	var callerRole string = "default"
	if user != nil && user.Role != "" {
		callerRole = user.Role
	}

	inputBytes := 0
	var rawReqBytes []byte
	if req != nil && len(req.Params) > 0 {
		inputBytes = len(req.Params)
		rawReqBytes = bytes.Clone(req.Params)
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

			slog.ErrorContext(ctx, "Panic recovered in filter pipeline request execution",
				slog.String("filter", currentFilterName),
				slog.String("method", reqMethod),
				slog.String("tool", toolName),
				slog.Any("panic", r),
				slog.String("stack", stack),
			)

			if logger != nil {
				errMsg := fmt.Sprintf("Panic recovered in filter '%s': %v\nStack:\n%s", currentFilterName, r, stack)
				var origReq string
				if retainLocalPayloads && len(rawReqBytes) > 0 {
					origReq = MakeBoundedPreview(rawReqBytes, previewLimit)
				}
				logger.LogEvent(&AuditEvent{
					ID:              invocationID,
					Timestamp:       time.Now(),
					AgentName:       agentName,
					CallerRole:      callerRole,
					Method:          reqMethod,
					ToolName:        toolName,
					PathType:        string(pathType),
					FilterName:      currentFilterName,
					MatchedRule:     currentFilterName,
					Phase:           AuditPhaseComplete,
					Decision:        DecisionCritical,
					RequestDecision: DecisionCritical,
					ErrorCode:       mcp.ErrInternalError,
					Message:         errMsg,
					ErrorMessage:    errMsg,
					User:            user,
					LatencyMs:       totalLatency,
					TraceID:         traceID,
					InputBytes:      inputBytes,
					RawPayload:      fmt.Sprintf("[REDACTED - Panic in %s]", currentFilterName),
					OriginalRequest: origReq,
				})
			}

			finalReq = nil
			finalErr = mcp.NewError(mcp.ErrInternalError, fmt.Sprintf("Internal error in filter '%s': %v", currentFilterName, r), nil)
		}
	}()

	auditMeta := &types.AuditMetadata{}
	ctx = context.WithValue(ctx, types.AuditMetadataKey, auditMeta)

	needBlockAudit := logger != nil
	needAllowAudit := logger != nil && reqMethod == "tools/call"

	var initialPayloadPreview string
	if needAllowAudit && debugRetainUnmaskedDiff && len(rawReqBytes) > 0 {
		initialPayloadPreview = MakeBoundedPreview(rawReqBytes, previewLimit)
	}
	var origReqCaptured string
	if retainLocalPayloads && len(rawReqBytes) > 0 {
		origReqCaptured = MakeBoundedPreview(rawReqBytes, previewLimit)
	}

	current := req
	var mcpErr *mcp.Error
	var modifiedFilter string
	lastSeenParams := rawReqBytes

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

		var filterStart time.Time
		if needBlockAudit {
			filterStart = time.Now()
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

		if mcpErr != nil {
			// Log block decision with explicit redaction note for RawPayload while
			// preserving local-vault OriginalRequest and error Response when enabled.
			if needBlockAudit {
				latency := float64(time.Since(filterStart).Microseconds()) / 1000.0
				blockedPayload := fmt.Sprintf("[REDACTED - Blocked by %s: %s]", f.Name(), mcpErr.Message)
				var errRespJSON string
				if retainLocalPayloads {
					var reqID any
					if req != nil {
						reqID = req.ID
					}
					errRespJSON = formatBlockedRPCResponse(reqID, mcpErr)
				}
				logger.LogEvent(&AuditEvent{
					ID:              invocationID,
					Timestamp:       time.Now(),
					AgentName:       agentName,
					CallerRole:      callerRole,
					Method:          reqMethod,
					ToolName:        toolName,
					PathType:        string(pathType),
					FilterName:      f.Name(),
					MatchedRule:     f.Name(),
					Phase:           AuditPhaseComplete,
					Decision:        DecisionBlocked,
					RequestDecision: DecisionBlocked,
					ErrorCode:       mcpErr.Code,
					Message:         mcpErr.Message,
					ErrorMessage:    mcpErr.Message,
					User:            user,
					LatencyMs:       latency,
					TraceID:         traceID,
					InputBytes:      inputBytes,
					RawPayload:      blockedPayload,
					OriginalRequest: origReqCaptured,
					Response:        errRespJSON,
				})
			}
			return nil, mcpErr
		}

		if needAllowAudit && current != nil && !bytes.Equal(lastSeenParams, current.Params) {
			modifiedFilter = f.Name()
			lastSeenParams = bytes.Clone(current.Params)
		}
	}

	if needAllowAudit {
		// Capture post-filtered payload preview strictly AFTER filter chain execution (SEC-008)
		rawPayload := ""
		var sentReqCaptured string
		if current != nil && len(current.Params) > 0 {
			inputBytes = len(current.Params)
			if retainLocalPayloads {
				rawPayload = MakeBoundedPreview(current.Params, previewLimit)
				if !bytes.Equal(rawReqBytes, current.Params) {
					sentReqCaptured = rawPayload
				}
			}
		}

		reqDecision := DecisionAllowed
		filterName := "pipeline"
		matchedRule := ""
		var auditedRules []string
		if modifiedFilter != "" {
			reqDecision = DecisionMasked
			filterName = modifiedFilter
			matchedRule = modifiedFilter
		} else if len(auditMeta.AuditedRules) > 0 {
			reqDecision = DecisionAudit
			filterName = auditMeta.FilterName
			if filterName == "" {
				filterName = "dlp"
			}
			matchedRule = strings.Join(auditMeta.AuditedRules, ",")
			auditedRules = auditMeta.AuditedRules
		}

		// Emit PENDING on orchestrated two-phase tools/call ingress when allowed (SPEC §1.2, SEC-022).
		decision := reqDecision
		if hasExplicitInvocation && reqMethod == "tools/call" && reqDecision == DecisionAllowed {
			decision = DecisionPending
		}

		var origPayload string
		if debugRetainUnmaskedDiff && retainLocalPayloads && (reqDecision == DecisionMasked || reqDecision == DecisionAudit) {
			origPayload = initialPayloadPreview
		}

		// Log allowed/masked/audited request if it passed all filters
		totalLatency := float64(time.Since(startTime).Microseconds()) / 1000.0
		logger.LogEvent(&AuditEvent{
			ID:              invocationID,
			Timestamp:       time.Now(),
			AgentName:       agentName,
			CallerRole:      callerRole,
			Method:          reqMethod,
			ToolName:        toolName,
			PathType:        string(pathType),
			FilterName:      filterName,
			MatchedRule:     matchedRule,
			Phase:           AuditPhaseRequest,
			Decision:        decision,
			RequestDecision: reqDecision,
			User:            user,
			LatencyMs:       totalLatency,
			TraceID:         traceID,
			InputBytes:      inputBytes,
			RawPayload:      rawPayload,
			OriginalPayload: origPayload,
			OriginalRequest: origReqCaptured,
			Request:         sentReqCaptured,
			AuditedRules:    auditedRules,
		})
	}

	return current, nil
}

// ProcessResponse runs the response through all response-path filters.
// It wraps filter execution with a top-level panic boundary to isolate failures and protect gateway sessions.
func (p *Pipeline) ProcessResponse(ctx context.Context, resp *mcp.Response) (finalResp *mcp.Response, finalErr *mcp.Error) {
	p.mu.RLock()
	filters := p.filters
	router := p.router
	debugRetainUnmaskedDiff := p.debugRetainUnmaskedDiff
	logger := p.logger
	p.mu.RUnlock()

	var currentFilterName string = "pipeline"
	startTime := time.Now()

	invocationID, traceID, _ := resolveContextCorrelation(ctx)
	previewLimit, retainLocalPayloads := p.captureConfig()

	var user *UserContext
	if val := ctx.Value(UserContextKey); val != nil {
		if u, ok := val.(*UserContext); ok {
			user = u
		}
	}

	agentName := types.GetAgentName(ctx)
	if agentName == "" {
		agentName = "default"
	}

	var callerRole string = "default"
	if user != nil && user.Role != "" {
		callerRole = user.Role
	}

	rawRespBytes := extractResponseRawBytes(resp)
	outputBytes := len(rawRespBytes)
	hadUpstreamError := resp != nil && resp.Error != nil

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

			slog.ErrorContext(ctx, "Panic recovered in filter pipeline response execution",
				slog.String("filter", currentFilterName),
				slog.String("tool", toolName),
				slog.Any("panic", r),
				slog.String("stack", stack),
			)

			if logger != nil {
				errMsg := fmt.Sprintf("Panic recovered in filter '%s': %v\nStack:\n%s", currentFilterName, r, stack)
				var origResp string
				if retainLocalPayloads && len(rawRespBytes) > 0 {
					origResp = MakeBoundedPreview(rawRespBytes, previewLimit)
				}
				logger.LogEvent(&AuditEvent{
					ID:               invocationID,
					Timestamp:        time.Now(),
					AgentName:        agentName,
					CallerRole:       callerRole,
					Method:           "response",
					ToolName:         toolName,
					PathType:         string(pathType),
					FilterName:       currentFilterName,
					MatchedRule:      currentFilterName,
					Phase:            AuditPhaseResponse,
					Decision:         DecisionCritical,
					ResponseDecision: DecisionCritical,
					ErrorCode:        mcp.ErrInternalError,
					Message:          errMsg,
					ErrorMessage:     errMsg,
					User:             user,
					LatencyMs:        totalLatency,
					TraceID:          traceID,
					OutputBytes:      outputBytes,
					RawPayload:       fmt.Sprintf("[REDACTED - Panic in %s]", currentFilterName),
					OriginalResponse: origResp,
				})
			}

			finalResp = nil
			finalErr = mcp.NewError(mcp.ErrInternalError, fmt.Sprintf("Internal error in filter '%s': %v", currentFilterName, r), nil)
		}
	}()

	auditMeta := &types.AuditMetadata{}
	ctx = context.WithValue(ctx, types.AuditMetadataKey, auditMeta)

	needAudit := logger != nil

	var initialPayloadPreview string
	if needAudit && debugRetainUnmaskedDiff && len(rawRespBytes) > 0 {
		initialPayloadPreview = MakeBoundedPreview(rawRespBytes, previewLimit)
	}
	var origRespCaptured string
	if retainLocalPayloads && len(rawRespBytes) > 0 {
		origRespCaptured = MakeBoundedPreview(rawRespBytes, previewLimit)
	}

	current := resp
	var mcpErr *mcp.Error
	var modifiedFilter string
	var lastSeenResult []byte
	if current != nil && len(current.Result) > 0 {
		lastSeenResult = bytes.Clone(current.Result)
	}

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

		var filterStart time.Time
		if needAudit {
			filterStart = time.Now()
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
				if !hadUpstreamError && current.Error != nil {
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

		if mcpErr != nil {
			// Log block decision with explicit redaction note for RawPayload while
			// retaining raw upstream OriginalResponse and error Response locally when enabled.
			if needAudit {
				latency := float64(time.Since(filterStart).Microseconds()) / 1000.0
				blockedPayload := fmt.Sprintf("[REDACTED - Blocked by %s: %s]", f.Name(), mcpErr.Message)
				var errRespJSON string
				if retainLocalPayloads {
					var respID any
					if resp != nil {
						respID = resp.ID
					}
					errRespJSON = formatBlockedRPCResponse(respID, mcpErr)
				}
				logger.LogEvent(&AuditEvent{
					ID:               invocationID,
					Timestamp:        time.Now(),
					AgentName:        agentName,
					CallerRole:       callerRole,
					Method:           "response",
					ToolName:         toolName,
					PathType:         string(pathType),
					FilterName:       f.Name(),
					MatchedRule:      f.Name(),
					Phase:            AuditPhaseResponse,
					Decision:         DecisionBlocked,
					ResponseDecision: DecisionBlocked,
					ErrorCode:        mcpErr.Code,
					Message:          mcpErr.Message,
					ErrorMessage:     mcpErr.Message,
					User:             user,
					LatencyMs:        latency,
					TraceID:          traceID,
					OutputBytes:      outputBytes,
					RawPayload:       blockedPayload,
					OriginalResponse: origRespCaptured,
					Response:         errRespJSON,
				})
			}
			return nil, mcpErr
		}

		if needAudit && current != nil && !bytes.Equal(lastSeenResult, current.Result) {
			modifiedFilter = f.Name()
			lastSeenResult = bytes.Clone(current.Result)
		}
	}

	if needAudit {
		// Capture post-filtered payload preview strictly AFTER filter chain execution (SEC-008)
		finalRespBytes := extractResponseRawBytes(current)
		rawPayload := ""
		var finalRespCaptured string
		if len(finalRespBytes) > 0 {
			outputBytes = len(finalRespBytes)
			if retainLocalPayloads {
				rawPayload = MakeBoundedPreview(finalRespBytes, previewLimit)
				if !bytes.Equal(rawRespBytes, finalRespBytes) {
					finalRespCaptured = rawPayload
				}
			}
		}

		decision := DecisionAllowed
		filterName := "pipeline"
		matchedRule := ""
		var auditedRules []string
		if hadUpstreamError {
			decision = DecisionError
			filterName = "upstream"
			if modifiedFilter != "" {
				matchedRule = modifiedFilter
			} else if len(auditMeta.AuditedRules) > 0 {
				matchedRule = strings.Join(auditMeta.AuditedRules, ",")
				auditedRules = auditMeta.AuditedRules
			}
		} else if modifiedFilter != "" {
			decision = DecisionMasked
			filterName = modifiedFilter
			matchedRule = modifiedFilter
		} else if len(auditMeta.AuditedRules) > 0 {
			decision = DecisionAudit
			filterName = auditMeta.FilterName
			if filterName == "" {
				filterName = "dlp"
			}
			matchedRule = strings.Join(auditMeta.AuditedRules, ",")
			auditedRules = auditMeta.AuditedRules
		}

		var origPayload string
		if debugRetainUnmaskedDiff && retainLocalPayloads && (decision == DecisionMasked || decision == DecisionAudit) {
			origPayload = initialPayloadPreview
		}

		var upstreamErrMsg string
		if hadUpstreamError && resp != nil && resp.Error != nil {
			upstreamErrMsg = resp.Error.Message
		}

		// Log allowed/masked/audited response
		totalLatency := float64(time.Since(startTime).Microseconds()) / 1000.0
		logger.LogEvent(&AuditEvent{
			ID:               invocationID,
			Timestamp:        time.Now(),
			AgentName:        agentName,
			CallerRole:       callerRole,
			Method:           "response",
			ToolName:         toolName,
			PathType:         string(pathType),
			FilterName:       filterName,
			MatchedRule:      matchedRule,
			Phase:            AuditPhaseResponse,
			Decision:         decision,
			ResponseDecision: decision,
			ErrorMessage:     upstreamErrMsg,
			User:             user,
			LatencyMs:        totalLatency,
			TraceID:          traceID,
			OutputBytes:      outputBytes,
			RawPayload:       rawPayload,
			OriginalPayload:  origPayload,
			OriginalResponse: origRespCaptured,
			Response:         finalRespCaptured,
			AuditedRules:     auditedRules,
		})
	}

	return current, nil
}
