package guard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/types"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
)

type profileGuardPolicy struct {
	guardMode      agent.GuardEnforcementMode
	toolMode       agent.ToolGovernanceMode
	toolConfigured bool
}

func (f *GuardFilter) resolveProfilePolicy(ctx context.Context, toolName string) profileGuardPolicy {
	policy := profileGuardPolicy{
		guardMode: agent.GuardModeEnforce,
	}
	agentName := types.GetAgentName(ctx)
	if agentName == "" {
		return policy
	}

	f.mu.RLock()
	repo := f.agentRepo
	f.mu.RUnlock()
	if repo == nil {
		return policy
	}

	agentCfg, err := repo.GetAgentConfig(agentName)
	if err != nil || agentCfg == nil {
		return policy
	}

	policy.guardMode = agentCfg.GetGuardMode()
	if m, ok := agentCfg.GetToolGovernanceMode(toolName); ok && m.IsValid() {
		policy.toolMode = m
		policy.toolConfigured = true
	}
	return policy
}

func recordGuardAudit(ctx context.Context, rule string) {
	if meta := types.GetAuditMetadata(ctx); meta != nil {
		meta.AuditedRules = append(meta.AuditedRules, rule)
		if meta.FilterName == "" {
			meta.FilterName = "guard"
		}
	}
}

// FilterResponse evaluates outgoing tool execution responses for indirect prompt injection and sensitive data leaks.
func (f *GuardFilter) FilterResponse(ctx context.Context, resp *mcp.Response) (*mcp.Response, *mcp.Error) {
	if resp == nil || resp.Result == nil || len(resp.Result) == 0 {
		return resp, nil
	}

	// 1. Fast-Path exemption: Skip scanning non-tool responses (static declarations like tools/list or ping)
	toolName := types.GetToolName(ctx)
	if toolName == "" {
		return resp, nil
	}

	policy := f.resolveProfilePolicy(ctx, toolName)
	if policy.guardMode == agent.GuardModeOff {
		return resp, nil
	}
	bypassAutonomous := policy.toolConfigured && policy.toolMode == agent.ModeAutonomous

	// -------------------------------------------------------------------------
	// TIER 1: L1 Static & DLP In-Memory Regex Engine (< 0.2ms)
	// -------------------------------------------------------------------------
	payloadStr := string(resp.Result)
	isMasked := false

	f.mu.RLock()
	rules := f.compiledL1
	cfg := f.cfg
	mgr := f.manager
	f.mu.RUnlock()

	// 1.1 Check block rules first to terminate early unless tool is explicitly Autonomous
	if !bypassAutonomous {
		for _, rule := range rules {
			if rule.Action == "block" && rule.Regex.MatchString(payloadStr) {
				slog.WarnContext(ctx, "Semantic Security Guard L1 Policy matched tool response",
					slog.String("rule", rule.Name),
					slog.String("tool", toolName),
					slog.String("guard_mode", string(policy.guardMode)),
				)
				if policy.guardMode == agent.GuardModeAudit {
					recordGuardAudit(ctx, "guard:response:l1:"+rule.Name)
					continue
				}
				return nil, mcp.NewError(
					mcp.ErrIndirectInjection,
					fmt.Sprintf("Security Alert: Indirect prompt injection detected in tool response by L1 rule '%s'", rule.Name),
					map[string]interface{}{
						"rule": rule.Name,
						"tool": toolName,
					},
				)
			}
		}
	}

	// 1.2 Evaluate mask rules and mutate payload if matches occur
	for _, rule := range rules {
		if rule.Action == "mask" && rule.Regex.MatchString(payloadStr) {
			payloadStr = rule.Regex.ReplaceAllString(payloadStr, "[REDACTED]")
			isMasked = true
		}
	}

	if isMasked {
		resp.Result = json.RawMessage(payloadStr)
	}

	if bypassAutonomous {
		return resp, nil
	}

	// -------------------------------------------------------------------------
	// TIER 2: Semantic Security Guard Deep Neural Inspection
	// -------------------------------------------------------------------------
	// Fault tolerance / Graceful Degradation: When engine is stopped, safely fallback to L1-Only
	if mgr == nil || !mgr.IsRunning() {
		slog.DebugContext(ctx, "Semantic Security Guard is stopped; degrading tool response safely to L1-Only fallback",
			slog.String("tool", toolName),
		)
		f.notifyDisconnection(ctx, toolName)
		return resp, nil
	}

	// Fast-path tool optimization: Skip neural scan for short structured responses
	isFast := f.isFastPath(toolName, cfg.FastPathTools)
	promoted := false
	if isFast {
		promoted = ShouldPromoteToL2(payloadStr, cfg.MaxPayloadLength, cfg.MinWordCount)
	}
	if isFast && !promoted && len(payloadStr) < 256 {
		return resp, nil
	}

	inspReq := &InspectionRequest{
		ToolName: toolName,
		ToolArguments: map[string]interface{}{
			"output": payloadStr,
		},
		ExecutionContext: "Response path: Tool output indirect prompt injection inspection",
		EnableL1Cascade:  false, // L1 already executed above in Go
	}

	result, err := mgr.CallInspect(ctx, inspReq)
	if err != nil {
		f.handleInspectError(ctx, toolName, "response", err)
		return resp, nil
	}

	if result != nil {
		isThreat := false
		if result.Verdict == "BLOCKED" || result.Verdict == "SUSPICIOUS" || result.Verdict == "THREAT" {
			isThreat = true
		} else if result.Verdict != "BENIGN" && result.Verdict != "SAFE" && result.MaliciousProbability >= f.getThresholdScore() {
			isThreat = true
		}

		if isThreat {
			engine := result.DecisionEngine
			if engine == "" {
				engine = "Semantic Security Guard"
			}

			slog.WarnContext(ctx, "Semantic Security Guard detected indirect prompt injection in tool response",
				slog.String("tool", toolName),
				slog.String("engine", engine),
				slog.String("threat_domain", result.ThreatDomain),
				slog.String("cwe", result.CWE),
				slog.Float64("score", result.MaliciousProbability),
				slog.String("guard_mode", string(policy.guardMode)),
			)

			if policy.guardMode == agent.GuardModeAudit {
				recordGuardAudit(ctx, fmt.Sprintf("guard:response:l2:%s:%s", engine, result.CWE))
				return resp, nil
			}

			return nil, mcp.NewError(
				mcp.ErrIndirectInjection,
				fmt.Sprintf("Security Alert: Indirect prompt injection detected in tool '%s' response by Semantic Security Guard (%s - %s)", toolName, result.ThreatDomain, result.CWE),
				map[string]interface{}{
					"tool":            toolName,
					"engine":          engine,
					"score":           result.MaliciousProbability,
					"threat_domain":   result.ThreatDomain,
					"cwe":             result.CWE,
					"decision_engine": engine,
				},
			)
		}
	}

	return resp, nil
}

// FilterRequest evaluates tools/call invocations through the two-tiered fail-fast cascade.
func (f *GuardFilter) FilterRequest(ctx context.Context, req *mcp.Request) (*mcp.Request, *mcp.Error) {
	if req == nil || req.Method != "tools/call" || len(req.Params) == 0 {
		return req, nil
	}

	var callParams struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &callParams); err != nil {
		return nil, mcp.NewError(mcp.ErrInvalidParams, "Invalid tools/call parameters: "+err.Error(), nil)
	}
	if callParams.Name == "" {
		return nil, mcp.NewError(mcp.ErrInvalidParams, "Missing required tool name in tools/call parameters", nil)
	}

	policy := f.resolveProfilePolicy(ctx, callParams.Name)
	if policy.guardMode == agent.GuardModeOff {
		return req, nil
	}
	bypassAutonomous := policy.toolConfigured && policy.toolMode == agent.ModeAutonomous

	// -------------------------------------------------------------------------
	// TIER 1: L1 Static & DLP In-Memory Regex Engine (< 0.2ms)
	// -------------------------------------------------------------------------
	payloadStr := string(req.Params)
	isMasked := false

	f.mu.RLock()
	rules := f.compiledL1
	cfg := f.cfg
	mgr := f.manager
	hitl := f.hitlDispatcher
	f.mu.RUnlock()

	// 1.1 Check block rules first to terminate early unless tool is explicitly Autonomous
	if !bypassAutonomous {
		for _, rule := range rules {
			if rule.Action == "block" && rule.Regex.MatchString(payloadStr) {
				if policy.guardMode == agent.GuardModeAudit {
					slog.WarnContext(ctx, "Semantic Security Guard L1 Policy audited tool request",
						slog.String("rule", rule.Name),
						slog.String("tool", callParams.Name),
					)
					recordGuardAudit(ctx, "guard:request:l1:"+rule.Name)
					continue
				}
				return nil, mcp.NewError(
					mcp.ErrDLPViolation,
					fmt.Sprintf("L1 Guard Policy Block: %s", rule.Name),
					nil,
				)
			}
		}
	}

	// 1.2 Evaluate mask rules and mutate payload if matches occur
	for _, rule := range rules {
		if rule.Action == "mask" && rule.Regex.MatchString(payloadStr) {
			payloadStr = rule.Regex.ReplaceAllString(payloadStr, "[REDACTED]")
			isMasked = true
		}
	}

	if isMasked {
		req.Params = json.RawMessage(payloadStr)
		// Re-sync arguments map for downstream L2 inspection; fail closed if masking broke JSON structure
		if err := json.Unmarshal(req.Params, &callParams); err != nil {
			return nil, mcp.NewError(mcp.ErrInvalidParams, "Post-redaction tools/call parameters invalid: "+err.Error(), nil)
		}
	}

	// -------------------------------------------------------------------------
	// TIER 1.5: Agent Tool Governance Mode Resolution
	// -------------------------------------------------------------------------
	var mode agent.ToolGovernanceMode
	if policy.toolConfigured {
		mode = policy.toolMode
	}

	// Boundary-aware smart default when unconfigured
	if mode == "" {
		isFast := f.isFastPath(callParams.Name, cfg.FastPathTools)
		argsText := ExtractArgumentsText(callParams.Arguments, req.Params)
		promoted := false
		if isFast {
			promoted = ShouldPromoteToL2(argsText, cfg.MaxPayloadLength, cfg.MinWordCount)
		}

		if f.isCriticalBlock(callParams.Name, cfg.CriticalBlocks) {
			mode = agent.ModeGuardedBlock
		} else if f.isExternalEgress(callParams.Name) {
			mode = agent.ModeGuardedHITL
		} else if isFast && !promoted {
			mode = agent.ModeAutonomous
		} else {
			if f.isDefaultActionBlock() {
				mode = agent.ModeGuardedBlock
			} else {
				mode = agent.ModeGuardedHITL
			}
		}
	}

	// -------------------------------------------------------------------------
	// TIER 2: Execution of Resolved Tool Governance Mode
	// -------------------------------------------------------------------------

	// 2.1 ModeAutonomous: Fast-Path bypass (<0.2ms latency)
	if mode == agent.ModeAutonomous {
		return req, nil
	}

	// 2.2 ModeStrictAlwaysHITL: Mandatory dual-channel HITL before tool execution
	if mode == agent.ModeStrictAlwaysHITL {
		// Human Supremacy Invariant: if already human-approved, do not prompt twice
		if types.IsHumanApproved(ctx) {
			slog.DebugContext(ctx, "Human Supremacy active: bypassing redundant HITL prompt for previously approved tool call",
				slog.String("tool", callParams.Name),
			)
			return req, nil
		}

		if hitl == nil {
			return nil, mcp.NewError(
				mcp.ErrHITLDenied,
				fmt.Sprintf("Human-in-the-loop approval denied for tool '%s': safety dispatcher unavailable", callParams.Name),
				nil,
			)
		}
		hitlCtx, cancel := context.WithTimeout(ctx, f.getHITLTimeout())
		defer cancel()

		hitlReq := &HITLRequest{
			ToolName:       callParams.Name,
			Arguments:      callParams.Arguments,
			RiskScore:      1.0,
			ThreatDomain:   "STRICT_POLICY",
			CWE:            "HITL-MANDATORY",
			DecisionEngine: "STRICT_HITL_GATE",
		}
		approved, err := hitl.RequestApproval(hitlCtx, hitlReq)
		types.SetHITLResolution(ctx, approved, hitlReq.ApprovedBy, hitlReq.ApprovalChannel)
		if err != nil || !approved {
			msg := fmt.Sprintf("Human-in-the-loop approval denied for tool '%s'", callParams.Name)
			if err != nil {
				msg = fmt.Sprintf("Human-in-the-loop approval denied for tool '%s': %s", callParams.Name, err.Error())
			}
			return nil, mcp.NewError(
				mcp.ErrHITLDenied,
				msg,
				nil,
			)
		}
		types.SetHumanApproved(ctx, true)
		return req, nil
	}

	// 2.3 ModeGuardedBlock and ModeGuardedHITL: Semantic Security Guard Deep Inspection
	// Fault tolerance / Graceful Degradation: When Semantic Security Guard is stopped, safely fallback to L1-Only mode
	if mgr == nil || !mgr.IsRunning() {
		slog.DebugContext(ctx, "Semantic Security Guard is stopped; degrading guarded tool safely to L1-Only fallback",
			slog.String("tool", callParams.Name),
			slog.String("mode", string(mode)),
		)
		f.notifyDisconnection(ctx, callParams.Name)
		return req, nil
	}

	inspReq := &InspectionRequest{
		ToolName:         callParams.Name,
		ToolArguments:    callParams.Arguments,
		ExecutionContext: "Gateway PEP inline evaluation",
		EnableL1Cascade:  false, // L1 already executed above in Go
	}

	result, err := mgr.CallInspect(ctx, inspReq)
	if err != nil {
		f.handleInspectError(ctx, callParams.Name, "request", err)
		return req, nil
	}

	if result != nil {
		isThreat := false
		if result.Verdict == "BLOCKED" || result.Verdict == "SUSPICIOUS" || result.Verdict == "THREAT" {
			isThreat = true
		} else if result.Verdict != "BENIGN" && result.Verdict != "SAFE" && result.MaliciousProbability >= f.getThresholdScore() {
			isThreat = true
		}

		if isThreat {
			engine := result.DecisionEngine
			if engine == "" {
				engine = "Semantic Security Guard"
			}

			// Human Supremacy Invariant (ADR-0040):
			// If a human operator has explicitly approved this execution (e.g. via DLP HITL gate or client),
			// downstream guards cannot veto or block the execution. We record shadow audit telemetry and pass through.
			if types.IsHumanApproved(ctx) {
				slog.InfoContext(ctx, "Human Supremacy active: bypassing Semantic Security Guard threat verdict for human-approved tool execution",
					slog.String("tool", callParams.Name),
					slog.String("engine", engine),
					slog.String("threat_domain", result.ThreatDomain),
					slog.String("cwe", result.CWE),
				)
				if meta := types.GetAuditMetadata(ctx); meta != nil {
					meta.AuditedRules = append(meta.AuditedRules, fmt.Sprintf("human_supremacy_override:%s:%s", engine, result.CWE))
				}
				return req, nil
			}

			if policy.guardMode == agent.GuardModeAudit {
				slog.WarnContext(ctx, "Semantic Security Guard audited threat verdict on tool request",
					slog.String("tool", callParams.Name),
					slog.String("engine", engine),
					slog.String("threat_domain", result.ThreatDomain),
					slog.String("cwe", result.CWE),
				)
				recordGuardAudit(ctx, fmt.Sprintf("guard:request:l2:%s:%s", engine, result.CWE))
				return req, nil
			}

			// Policy checks critical_tools: designated destructive tools are automatically hard-blocked with -32004
			if f.isCriticalBlock(callParams.Name, cfg.CriticalBlocks) {
				return nil, mcp.NewError(
					mcp.ErrDLPViolation,
					fmt.Sprintf("Guard Policy Hard-Block: Critical destructive tool '%s' blocked on threat verdict by %s (%s - %s)", callParams.Name, engine, result.ThreatDomain, result.CWE),
					nil,
				)
			}

			// Policy checks default_action: if configured as 'block', threats are auto-blocked with -32004
			if f.isDefaultActionBlock() {
				return nil, mcp.NewError(
					mcp.ErrDLPViolation,
					fmt.Sprintf("Guard Policy Auto-Block: Tool '%s' blocked on threat verdict by %s (%s - %s)", callParams.Name, engine, result.ThreatDomain, result.CWE),
					nil,
				)
			}

			// Explicit ModeGuardedBlock: hard-block with -32004 without prompting
			if mode == agent.ModeGuardedBlock {
				return nil, mcp.NewError(
					mcp.ErrDLPViolation,
					fmt.Sprintf("Guard Policy Hard-Block: Tool '%s' blocked on threat verdict by %s (%s - %s)", callParams.Name, engine, result.ThreatDomain, result.CWE),
					nil,
				)
			}

			// ModeGuardedHITL: Escalate to Dual-Channel HITL approval (60s fail-closed timeout)
			if hitl != nil {
				hitlCtx, cancel := context.WithTimeout(ctx, f.getHITLTimeout())
				defer cancel()

				hitlReq := &HITLRequest{
					ToolName:       callParams.Name,
					Arguments:      callParams.Arguments,
					RiskScore:      result.MaliciousProbability,
					ThreatDomain:   result.ThreatDomain,
					CWE:            result.CWE,
					DecisionEngine: engine,
				}
				approved, err := hitl.RequestApproval(hitlCtx, hitlReq)
				types.SetHITLResolution(ctx, approved, hitlReq.ApprovedBy, hitlReq.ApprovalChannel)
				if err != nil || !approved {
					msg := fmt.Sprintf("Human-in-the-loop approval denied for tool '%s'", callParams.Name)
					if err != nil {
						msg = fmt.Sprintf("Human-in-the-loop approval denied for tool '%s': %s", callParams.Name, err.Error())
					}
					return nil, mcp.NewError(
						mcp.ErrHITLDenied,
						msg,
						nil,
					)
				}
				types.SetHumanApproved(ctx, true)
				return req, nil
			}

			// Fail-closed if HITL dispatcher is not available
			return nil, mcp.NewError(
				mcp.ErrHITLDenied,
				fmt.Sprintf("Human-in-the-loop approval denied for tool '%s': safety dispatcher unavailable", callParams.Name),
				nil,
			)
		}
	}

	return req, nil
}

func (f *GuardFilter) handleInspectError(ctx context.Context, toolName, phase string, err error) {
	if errors.Is(err, context.Canceled) {
		return
	}
	if errors.Is(err, ErrQueueFull) {
		slog.WarnContext(ctx, "Semantic Security Guard queue depth exceeded; load shedding to L1",
			slog.String("tool", toolName),
			slog.String("phase", phase),
		)
		return
	}
	slog.WarnContext(ctx, "Semantic Security Guard inspection failed; degrading safely to L1-Only fallback",
		slog.String("tool", toolName),
		slog.String("phase", phase),
		slog.String("error", err.Error()),
	)
	f.notifyDisconnection(ctx, toolName)
}
