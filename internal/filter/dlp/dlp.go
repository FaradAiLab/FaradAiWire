package dlp

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/types"
	"github.com/FaradAiLab/FaradAiWire/internal/guard/hitltypes"
	"github.com/FaradAiLab/FaradAiWire/pkg/filter"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
)

// Ensure DLPFilter implements filter.SecurityFilter, filter.RequestFilter, and filter.ResponseFilter.
var (
	_ filter.SecurityFilter = (*DLPFilter)(nil)
	_ filter.RequestFilter  = (*DLPFilter)(nil)
	_ filter.ResponseFilter = (*DLPFilter)(nil)
)

// HITLApprover abstracts human-in-the-loop approval escalation.
type HITLApprover = hitltypes.HITLApprover

// DLPFilter coordinates DLP rule enforcement for incoming requests and outgoing responses.
// It delegates rule resolution to a RuleProvider (DIP) and sanitization to Sanitize (SRP).
type DLPFilter struct {
	provider       RuleProvider
	hitlDispatcher HITLApprover
	mu             sync.RWMutex
}

// SetHITLDispatcher thread-safely binds the HITL dispatcher to the DLP filter.
func (d *DLPFilter) SetHITLDispatcher(dispatcher HITLApprover) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.hitlDispatcher = dispatcher
}

// HITLDispatcher returns the currently configured HITL dispatcher.
func (d *DLPFilter) HITLDispatcher() HITLApprover {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.hitlDispatcher
}

// NewDLPFilterWithProvider constructs a DLPFilter with a custom RuleProvider.
func NewDLPFilterWithProvider(provider RuleProvider) *DLPFilter {
	return &DLPFilter{provider: provider}
}

// NewDLPFilter compiles baseline patterns and initializes a file-based AgentFileProvider.
func NewDLPFilter(enabled bool, excludeTools []string, patterns []config.DLPPattern, agentsDir ...string) (*DLPFilter, error) {
	compiled, err := compileBaselinePatterns(patterns)
	if err != nil {
		return nil, fmt.Errorf("compile baseline DLP patterns: %w", err)
	}

	targetDir := "/etc/faradaiwire/agents"
	if len(agentsDir) > 0 && agentsDir[0] != "" {
		targetDir = agentsDir[0]
	}

	provider := NewAgentFileProvider(enabled, excludeTools, compiled, targetDir)
	return NewDLPFilterWithProvider(provider), nil
}

// Name returns the identifier of the filter.
func (d *DLPFilter) Name() string {
	return "dlp"
}

// Order returns the pipeline execution precedence (OrderDLP = 50).
func (d *DLPFilter) Order() int {
	return filter.OrderDLP
}

// ExecuteRequest satisfies filter.SecurityFilter for unified pipeline execution.
func (d *DLPFilter) ExecuteRequest(ctx context.Context, req *mcp.Request) (*mcp.Response, error) {
	_, err := d.FilterRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

// ExecuteResponse satisfies filter.SecurityFilter for unified pipeline execution.
func (d *DLPFilter) ExecuteResponse(ctx context.Context, resp *mcp.Response) (*mcp.Response, error) {
	res, err := d.FilterResponse(ctx, resp)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// ReloadAgentDLP clears cached rules for an agent if the provider supports reloading.
func (d *DLPFilter) ReloadAgentDLP(agentName string) {
	if reloader, ok := d.provider.(Reloader); ok {
		reloader.Reload(agentName)
	}
}

// FilterRequest scans and filters incoming tool call arguments.
func (d *DLPFilter) FilterRequest(ctx context.Context, req *mcp.Request) (*mcp.Request, *mcp.Error) {
	if req.Method != "tools/call" || len(req.Params) == 0 {
		return req, nil
	}

	rules := d.provider.ResolveRules(ctx)
	if !rules.Enabled || len(rules.Patterns) == 0 {
		return req, nil
	}

	toolName := extractToolName(ctx, req.Params)
	if rules.IsExempt(toolName, FlagExemptRequest) {
		return req, nil
	}

	result := Sanitize(string(req.Params), rules.Patterns)
	if result.Blocked {
		return nil, mcp.NewError(
			mcp.ErrDLPViolation,
			fmt.Sprintf("DLP Policy Block: Sensitive data detected (Pattern: %s)", result.BlockingRule),
			nil,
		)
	}

	if result.RequiresHITL {
		d.mu.RLock()
		dispatcher := d.hitlDispatcher
		d.mu.RUnlock()

		if dispatcher == nil {
			return nil, mcp.NewError(
				mcp.ErrHITLDenied,
				fmt.Sprintf("Human-in-the-loop approval denied for tool '%s': safety dispatcher unavailable", toolName),
				nil,
			)
		}

		var callParams struct {
			Name      string                 `json:"name"`
			Arguments map[string]interface{} `json:"arguments"`
		}
		_ = json.Unmarshal(req.Params, &callParams)
		if callParams.Name == "" {
			callParams.Name = toolName
		}

		hitlCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		cwe := "CWE-UNKNOWN"
		if result.HITLRuleDetail != nil && result.HITLRuleDetail.CWE != "" {
			cwe = result.HITLRuleDetail.CWE
		} else if result.HITLRule != "" {
			cwe = result.HITLRule
		}

		approved, err := dispatcher.RequestApproval(hitlCtx, &hitltypes.HITLRequest{
			ToolName:       callParams.Name,
			Arguments:      callParams.Arguments,
			RiskScore:      1.0,
			ThreatDomain:   "DLP_POLICY",
			CWE:            cwe,
			DecisionEngine: "DLP_HITL_GATE",
		})
		if err != nil || !approved {
			msg := fmt.Sprintf("Human-in-the-loop approval denied for tool '%s'", callParams.Name)
			if err != nil {
				msg = fmt.Sprintf("Human-in-the-loop approval denied for tool '%s': %s", callParams.Name, err.Error())
			}
			return nil, mcp.NewError(mcp.ErrHITLDenied, msg, nil)
		}

		// The Human Supremacy Principle:
		// Mark human approval in the context so downstream SLM guards cannot veto.
		types.SetHumanApproved(ctx, true)
	}

	if result.Audited {
		if meta, ok := ctx.Value(types.AuditMetadataKey).(*types.AuditMetadata); ok && meta != nil {
			meta.AuditedRules = append(meta.AuditedRules, result.AuditedRules...)
			if meta.FilterName == "" {
				meta.FilterName = d.Name()
			}
		}
	}

	if result.Modified {
		req.Params = json.RawMessage(result.Output)
	}

	return req, nil
}

// FilterResponse scans and filters outgoing tool results.
func (d *DLPFilter) FilterResponse(ctx context.Context, resp *mcp.Response) (*mcp.Response, *mcp.Error) {
	if resp.Result == nil {
		return resp, nil
	}

	rules := d.provider.ResolveRules(ctx)
	if !rules.Enabled || len(rules.Patterns) == 0 {
		return resp, nil
	}

	toolName := extractToolName(ctx, nil)
	if rules.IsExempt(toolName, FlagExemptResponse) {
		return resp, nil
	}

	result := Sanitize(string(resp.Result), rules.Patterns)
	if result.Blocked {
		return nil, mcp.NewError(
			mcp.ErrDLPViolation,
			fmt.Sprintf("DLP Policy Block: Sensitive data detected in response (Pattern: %s)", result.BlockingRule),
			nil,
		)
	}

	if result.Audited {
		if meta, ok := ctx.Value(types.AuditMetadataKey).(*types.AuditMetadata); ok && meta != nil {
			meta.AuditedRules = append(meta.AuditedRules, result.AuditedRules...)
			if meta.FilterName == "" {
				meta.FilterName = d.Name()
			}
		}
	}

	if result.Modified {
		resp.Result = json.RawMessage(result.Output)
	}

	return resp, nil
}

func compileBaselinePatterns(patterns []config.DLPPattern) ([]CompiledPattern, error) {
	compiled := make([]CompiledPattern, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			return nil, err
		}
		act := Action(p.Action)
		if act == "" {
			act = ActionMask
		}
		compiled = append(compiled, CompiledPattern{
			Name:        p.Name,
			Regex:       re,
			Action:      act,
			Placeholder: p.Placeholder,
		})
	}
	return compiled, nil
}

func extractToolName(ctx context.Context, params json.RawMessage) string {
	if s := types.GetToolName(ctx); s != "" {
		return s
	}

	if len(params) > 0 {
		var callParams struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(params, &callParams); err == nil && callParams.Name != "" {
			return callParams.Name
		}
	}

	return ""
}

// DefaultBaselinePatterns returns the standard security DLP rules for credential and system file protection
// in accordance with SPEC-SEC-002 (Section 4.4) and SEC-011.
func DefaultBaselinePatterns() []config.DLPPattern {
	return []config.DLPPattern{
		{
			Name:   "private_keys",
			Regex:  `-----BEGIN (RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----`,
			Action: "block",
		},
		{
			Name:   "sensitive_files",
			Regex:  `(?i)(\.env|\.aws/credentials|id_rsa|id_ed25519|/etc/shadow|/etc/passwd)`,
			Action: "block",
		},
		{
			Name:   "aws_credentials",
			Regex:  `(?i)["']?(aws_secret_access_key|aws_access_key_id)["']?\s*[:=]?\s*["']?[A-Za-z0-9/+=]{16,}["']?`,
			Action: "mask",
		},
	}
}
