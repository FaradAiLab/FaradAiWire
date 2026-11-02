package dlp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/types"
	"github.com/FaradAiLab/FaradAiWire/internal/guard"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
)

func TestDLPFilter_GlobalBaseline(t *testing.T) {
	patterns := []config.DLPPattern{
		{Name: "card", Regex: `\b\d{4}-\d{4}-\d{4}-\d{4}\b`, Action: "mask"},
		{Name: "secret", Regex: `(?i)secret-password`, Action: "block"},
	}

	filter, err := NewDLPFilter(true, nil, patterns)
	if err != nil {
		t.Fatalf("Failed to create DLP filter: %v", err)
	}

	// 1. Test Masking Request params
	req := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"card": "1111-2222-3333-4444"}`),
	}

	filteredReq, mcpErr := filter.FilterRequest(context.Background(), req)
	if mcpErr != nil {
		t.Fatalf("FilterRequest returned unexpected error: %v", mcpErr)
	}

	if string(filteredReq.Params) != `{"card": "[REDACTED:CARD]"}` {
		t.Errorf("PII was not masked correctly. Got: %s", string(filteredReq.Params))
	}

	// 2. Test Blocking Request params
	reqBlock := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"pwd": "secret-password"}`),
	}

	_, mcpErrBlock := filter.FilterRequest(context.Background(), reqBlock)
	if mcpErrBlock == nil {
		t.Error("FilterRequest should have blocked secret password, but returned no error")
	} else if mcpErrBlock.Code != mcp.ErrDLPViolation {
		t.Errorf("Expected DLP violation error code, got %d", mcpErrBlock.Code)
	}
}

func TestDLPFilter_AgentOverride_EscalateToBlock(t *testing.T) {
	// Global baseline masks cards
	globalPatterns := []config.DLPPattern{
		{Name: "card", Regex: `\b\d{4}-\d{4}-\d{4}-\d{4}\b`, Action: "mask"},
	}

	tempDir := t.TempDir()
	agentDir := filepath.Join(tempDir, "Finance-Agent", "current")
	if err := os.MkdirAll(agentDir, 0755); err != nil {
		t.Fatalf("failed to create agent dir: %v", err)
	}

	// Agent-specific dlp.json escalates card to block
	agentDLP := `{
		"enabled": true,
		"patterns": [
			{ "name": "card", "regex": "\\b\\d{4}-\\d{4}-\\d{4}-\\d{4}\\b", "action": "block" }
		]
	}`
	if err := os.WriteFile(filepath.Join(agentDir, "dlp.json"), []byte(agentDLP), 0644); err != nil {
		t.Fatalf("failed to write agent dlp.json: %v", err)
	}

	filter, err := NewDLPFilter(true, nil, globalPatterns, tempDir)
	if err != nil {
		t.Fatalf("Failed to create DLP filter: %v", err)
	}

	// Request with agent context
	ctx := context.WithValue(context.Background(), types.AgentNameContextKey, "Finance-Agent")

	resp := &mcp.Response{
		JSONRPC: "2.0",
		ID:      1,
		Result:  json.RawMessage(`{"data": "Card: 4543-9821-2341-9872"}`),
	}

	_, mcpErr := filter.FilterResponse(ctx, resp)
	if mcpErr == nil {
		t.Fatal("Expected agent-level block for card, but got no error")
	}
	if mcpErr.Code != mcp.ErrDLPViolation {
		t.Fatalf("Expected ErrDLPViolation (-32004), got %d", mcpErr.Code)
	}
}

func TestDLPFilter_AgentOverride_Bypass(t *testing.T) {
	// Global baseline masks national ID
	globalPatterns := []config.DLPPattern{
		{Name: "national_id", Regex: `\b[1-9][0-9]{10}\b`, Action: "mask"},
	}

	tempDir := t.TempDir()
	agentDir := filepath.Join(tempDir, "HR-Agent", "current")
	if err := os.MkdirAll(agentDir, 0755); err != nil {
		t.Fatalf("failed to create agent dir: %v", err)
	}

	// Agent-specific dlp.json has enabled: false (Clean bypass per ADR-0022)
	agentDLP := `{
		"enabled": false,
		"patterns": []
	}`
	if err := os.WriteFile(filepath.Join(agentDir, "dlp.json"), []byte(agentDLP), 0644); err != nil {
		t.Fatalf("failed to write agent dlp.json: %v", err)
	}

	filter, err := NewDLPFilter(true, nil, globalPatterns, tempDir)
	if err != nil {
		t.Fatalf("Failed to create DLP filter: %v", err)
	}

	ctx := context.WithValue(context.Background(), types.AgentNameContextKey, "HR-Agent")

	resp := &mcp.Response{
		JSONRPC: "2.0",
		ID:      1,
		Result:  json.RawMessage(`{"identity": "28491823941"}`),
	}

	filteredResp, mcpErr := filter.FilterResponse(ctx, resp)
	if mcpErr != nil {
		t.Fatalf("Unexpected error for bypassed agent: %v", mcpErr)
	}

	// Should NOT be redacted!
	if string(filteredResp.Result) != `{"identity": "28491823941"}` {
		t.Fatalf("Expected unmasked identity due to bypass, got: %s", string(filteredResp.Result))
	}
}

func TestDLPFilter_Collision_BlockPriority(t *testing.T) {
	// Pattern 1: mask email
	// Pattern 2: block bearer token
	patterns := []config.DLPPattern{
		{Name: "email", Regex: `[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+`, Action: "mask"},
		{Name: "bearer", Regex: `(?i)bearer[ _]+[a-z0-9_-]{16,}`, Action: "block"},
	}

	filter, err := NewDLPFilter(true, nil, patterns)
	if err != nil {
		t.Fatalf("Failed to create DLP filter: %v", err)
	}

	// Payload with both email and bearer token
	resp := &mcp.Response{
		JSONRPC: "2.0",
		ID:      1,
		Result:  json.RawMessage(`{"user": "dev@corp.com", "token": "bearer secret_api_key_9988776655443322"}`),
	}

	_, mcpErr := filter.FilterResponse(context.Background(), resp)
	if mcpErr == nil {
		t.Fatal("Expected block priority on collision, but got no error")
	}
	if mcpErr.Code != mcp.ErrDLPViolation {
		t.Fatalf("Expected ErrDLPViolation, got code %d", mcpErr.Code)
	}
}

func TestDLPFilter_HotReloadOnMtime(t *testing.T) {
	tempDir := t.TempDir()
	agentDir := filepath.Join(tempDir, "Dynamic-Agent", "current")
	_ = os.MkdirAll(agentDir, 0755)

	dlpFile := filepath.Join(agentDir, "dlp.json")
	_ = os.WriteFile(dlpFile, []byte(`{"enabled": true, "patterns": [{"name": "p1", "regex": "FOO", "action": "mask"}]}`), 0644)

	filter, err := NewDLPFilter(true, nil, nil, tempDir)
	if err != nil {
		t.Fatalf("failed to create filter: %v", err)
	}

	ctx := context.WithValue(context.Background(), types.AgentNameContextKey, "Dynamic-Agent")

	// Phase 1: FOO is masked
	resp1 := &mcp.Response{Result: json.RawMessage(`{"text": "FOO and BAR"}`)}
	filtered1, _ := filter.FilterResponse(ctx, resp1)
	if string(filtered1.Result) != `{"text": "[REDACTED:P1] and BAR"}` {
		t.Fatalf("Phase 1 failed: %s", string(filtered1.Result))
	}

	// Phase 2: Update dlp.json to also mask BAR (event-driven reload per ADR-0048 Decision 3)
	_ = os.WriteFile(dlpFile, []byte(`{"enabled": true, "patterns": [{"name": "p1", "regex": "FOO", "action": "mask"}, {"name": "p2", "regex": "BAR", "action": "mask"}]}`), 0644)
	filter.ReloadAgentDLP("Dynamic-Agent")

	resp2 := &mcp.Response{Result: json.RawMessage(`{"text": "FOO and BAR"}`)}
	filtered2, _ := filter.FilterResponse(ctx, resp2)
	if string(filtered2.Result) != `{"text": "[REDACTED:P1] and [REDACTED:P2]"}` {
		t.Fatalf("Phase 2 hot-reload failed: %s", string(filtered2.Result))
	}
}

type mockRuleProvider struct {
	ruleSet RuleSet
}

func (m *mockRuleProvider) ResolveRules(ctx context.Context) RuleSet {
	return m.ruleSet
}

func TestDLPFilter_CustomRuleProvider_DependencyInversion(t *testing.T) {
	mockProvider := &mockRuleProvider{
		ruleSet: RuleSet{
			Enabled: true,
			Patterns: []CompiledPattern{
				{
					Name:   "in-memory-block",
					Regex:  regexp.MustCompile(`TOP_SECRET`),
					Action: ActionBlock,
				},
			},
		},
	}

	filter := NewDLPFilterWithProvider(mockProvider)

	req := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"data": "this is TOP_SECRET"}`),
	}

	_, err := filter.FilterRequest(context.Background(), req)
	if err == nil {
		t.Fatal("Expected error from mock rule provider, got nil")
	}
	if err.Code != mcp.ErrDLPViolation {
		t.Fatalf("Expected ErrDLPViolation, got %d", err.Code)
	}
}

func TestDLPFilter_ActionAudit(t *testing.T) {
	patterns := []config.DLPPattern{
		{Name: "tckn", Regex: `\b[1-9][0-9]{10}\b`, Action: "audit"},
	}

	filter, err := NewDLPFilter(true, nil, patterns)
	if err != nil {
		t.Fatalf("failed to create DLP filter: %v", err)
	}

	ctx := types.WithAuditMetadata(context.Background(), &types.AuditMetadata{})
	req := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"citizen_id": "12345678901"}`),
	}

	filteredReq, mcpErr := filter.FilterRequest(ctx, req)
	if mcpErr != nil {
		t.Fatalf("unexpected mcpErr on audit action: %v", mcpErr)
	}

	// Payload must NOT be modified in audit mode
	if string(filteredReq.Params) != `{"citizen_id": "12345678901"}` {
		t.Fatalf("payload should remain untouched in audit mode, got: %s", string(filteredReq.Params))
	}

	// Audit metadata must be recorded in context
	auditMeta := types.GetAuditMetadata(ctx)
	if auditMeta == nil {
		t.Fatal("expected AuditMetadata in context, got nil")
	}
	if len(auditMeta.AuditedRules) != 1 || auditMeta.AuditedRules[0] != "tckn" {
		t.Fatalf("expected AuditedRules ['tckn'], got: %v", auditMeta.AuditedRules)
	}
}

func TestDLPFilter_CustomPlaceholder(t *testing.T) {
	patterns := []config.DLPPattern{
		{
			Name:        "credit_card",
			Regex:       `\b\d{4}-\d{4}-\d{4}-\d{4}\b`,
			Action:      "mask",
			Placeholder: "[CARD_MASKED]",
		},
	}

	filter, err := NewDLPFilter(true, nil, patterns)
	if err != nil {
		t.Fatalf("failed to create DLP filter: %v", err)
	}

	req := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"payment": "1234-5678-9012-3456"}`),
	}

	filteredReq, mcpErr := filter.FilterRequest(context.Background(), req)
	if mcpErr != nil {
		t.Fatalf("unexpected error: %v", mcpErr)
	}

	expected := `{"payment": "[CARD_MASKED]"}`
	if string(filteredReq.Params) != expected {
		t.Fatalf("expected %s, got: %s", expected, string(filteredReq.Params))
	}
}

func TestDLPFilter_DirectionalToolExemptions(t *testing.T) {
	tempDir := t.TempDir()
	agentDir := filepath.Join(tempDir, "Directional-Agent", "current")
	if err := os.MkdirAll(agentDir, 0755); err != nil {
		t.Fatalf("failed to create agent dir: %v", err)
	}

	agentDLP := `{
		"enabled": true,
		"patterns": [
			{ "name": "phone", "regex": "\\b05[0-9]{9}\\b", "action": "mask" },
			{ "name": "secret", "regex": "SUPER_SECRET", "action": "block" }
		],
		"tool_exemptions": {
			"crm_lookup": { "request": true, "response": false },
			"analytics_dump": { "request": false, "response": true }
		}
	}`
	if err := os.WriteFile(filepath.Join(agentDir, "dlp.json"), []byte(agentDLP), 0644); err != nil {
		t.Fatalf("failed to write dlp.json: %v", err)
	}

	filter, err := NewDLPFilter(true, nil, nil, tempDir)
	if err != nil {
		t.Fatalf("failed to create DLP filter: %v", err)
	}

	ctx := context.WithValue(context.Background(), types.AgentNameContextKey, "Directional-Agent")

	// Case 1: crm_lookup (Request exempt, Response NOT exempt)
	// 1a: Request with phone should pass unmasked
	reqCRM := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name": "crm_lookup", "phone": "05321234567"}`),
	}
	fReqCRM, mcpErr := filter.FilterRequest(ctx, reqCRM)
	if mcpErr != nil {
		t.Fatalf("FilterRequest unexpected error for crm_lookup: %v", mcpErr)
	}
	if string(fReqCRM.Params) != `{"name": "crm_lookup", "phone": "05321234567"}` {
		t.Errorf("crm_lookup request should have bypassed masking, got: %s", string(fReqCRM.Params))
	}

	// 1b: Response from crm_lookup with phone SHOULD be masked
	ctxCRM := context.WithValue(ctx, types.ToolNameContextKey, "crm_lookup")
	respCRM := &mcp.Response{
		Result: json.RawMessage(`{"customer_phone": "05321234567"}`),
	}
	fRespCRM, mcpErr := filter.FilterResponse(ctxCRM, respCRM)
	if mcpErr != nil {
		t.Fatalf("FilterResponse unexpected error for crm_lookup: %v", mcpErr)
	}
	if string(fRespCRM.Result) != `{"customer_phone": "[REDACTED:PHONE]"}` {
		t.Errorf("crm_lookup response should have been masked, got: %s", string(fRespCRM.Result))
	}

	// Case 2: analytics_dump (Request NOT exempt, Response IS exempt)
	// 2a: Request with phone should be masked
	reqAnalytics := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name": "analytics_dump", "phone": "05321234567"}`),
	}
	fReqAnalytics, mcpErr := filter.FilterRequest(ctx, reqAnalytics)
	if mcpErr != nil {
		t.Fatalf("FilterRequest unexpected error for analytics_dump: %v", mcpErr)
	}
	if string(fReqAnalytics.Params) != `{"name": "analytics_dump", "phone": "[REDACTED:PHONE]"}` {
		t.Errorf("analytics_dump request should have been masked, got: %s", string(fReqAnalytics.Params))
	}

	// 2b: Response from analytics_dump with phone should pass unmasked
	ctxAnalytics := context.WithValue(ctx, types.ToolNameContextKey, "analytics_dump")
	respAnalytics := &mcp.Response{
		Result: json.RawMessage(`{"output": "05321234567"}`),
	}
	fRespAnalytics, mcpErr := filter.FilterResponse(ctxAnalytics, respAnalytics)
	if mcpErr != nil {
		t.Fatalf("FilterResponse unexpected error for analytics_dump: %v", mcpErr)
	}
	if string(fRespAnalytics.Result) != `{"output": "05321234567"}` {
		t.Errorf("analytics_dump response should have bypassed masking, got: %s", string(fRespAnalytics.Result))
	}
}

func TestDLPFilter_DirectionalToolExemptions_BlockAndEdgeCases(t *testing.T) {
	tempDir := t.TempDir()
	agentDir := filepath.Join(tempDir, "Edge-Agent", "current")
	if err := os.MkdirAll(agentDir, 0755); err != nil {
		t.Fatalf("failed to create agent dir: %v", err)
	}

	agentDLP := `{
		"enabled": true,
		"patterns": [
			{ "name": "critical_token", "regex": "SUPER_SECRET_TOKEN", "action": "block" },
			{ "name": "phone", "regex": "\\b05[0-9]{9}\\b", "action": "mask" }
		],
		"tool_exemptions": {
			"input_exempt_tool": { "request": true, "response": false },
			"output_exempt_tool": { "request": false, "response": true },
			"full_exempt_tool": { "request": true, "response": true },
			"full_enforced_tool": { "request": false, "response": false }
		}
	}`
	if err := os.WriteFile(filepath.Join(agentDir, "dlp.json"), []byte(agentDLP), 0644); err != nil {
		t.Fatalf("failed to write dlp.json: %v", err)
	}

	filter, err := NewDLPFilter(true, nil, nil, tempDir)
	if err != nil {
		t.Fatalf("failed to create DLP filter: %v", err)
	}

	ctx := context.WithValue(context.Background(), types.AgentNameContextKey, "Edge-Agent")

	// 1. input_exempt_tool: request contains SUPER_SECRET_TOKEN (action: block)
	// Since request is exempt, it MUST pass through without ErrDLPViolation!
	reqInputExempt := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name": "input_exempt_tool", "token": "SUPER_SECRET_TOKEN"}`),
	}
	fReq, mcpErr := filter.FilterRequest(ctx, reqInputExempt)
	if mcpErr != nil {
		t.Fatalf("expected input_exempt_tool request to bypass block rule, got error: %v", mcpErr)
	}
	if string(fReq.Params) != `{"name": "input_exempt_tool", "token": "SUPER_SECRET_TOKEN"}` {
		t.Errorf("expected verbatim params, got: %s", string(fReq.Params))
	}

	// 2. output_exempt_tool: request contains SUPER_SECRET_TOKEN (action: block)
	// Request is NOT exempt, so it MUST be blocked with ErrDLPViolation!
	reqOutputExempt := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name": "output_exempt_tool", "token": "SUPER_SECRET_TOKEN"}`),
	}
	_, mcpErr = filter.FilterRequest(ctx, reqOutputExempt)
	if mcpErr == nil {
		t.Fatalf("expected ErrDLPViolation for output_exempt_tool request, got nil")
	}
	if mcpErr.Code != mcp.ErrDLPViolation {
		t.Fatalf("expected error code %d, got %d", mcp.ErrDLPViolation, mcpErr.Code)
	}

	// 3. output_exempt_tool: response contains SUPER_SECRET_TOKEN (action: block)
	// Since response IS exempt, output MUST pass through without ErrDLPViolation!
	ctxOutputExempt := context.WithValue(ctx, types.ToolNameContextKey, "output_exempt_tool")
	respOutputExempt := &mcp.Response{
		Result: json.RawMessage(`{"token": "SUPER_SECRET_TOKEN"}`),
	}
	fResp, mcpErr := filter.FilterResponse(ctxOutputExempt, respOutputExempt)
	if mcpErr != nil {
		t.Fatalf("expected output_exempt_tool response to bypass block rule, got error: %v", mcpErr)
	}
	if string(fResp.Result) != `{"token": "SUPER_SECRET_TOKEN"}` {
		t.Errorf("expected verbatim response, got: %s", string(fResp.Result))
	}

	// 4. input_exempt_tool: response contains SUPER_SECRET_TOKEN (action: block)
	// Response is NOT exempt, so it MUST be blocked!
	ctxInputExempt := context.WithValue(ctx, types.ToolNameContextKey, "input_exempt_tool")
	respInputExempt := &mcp.Response{
		Result: json.RawMessage(`{"token": "SUPER_SECRET_TOKEN"}`),
	}
	_, mcpErr = filter.FilterResponse(ctxInputExempt, respInputExempt)
	if mcpErr == nil {
		t.Fatalf("expected ErrDLPViolation for input_exempt_tool response, got nil")
	}
	if mcpErr.Code != mcp.ErrDLPViolation {
		t.Fatalf("expected error code %d, got %d", mcp.ErrDLPViolation, mcpErr.Code)
	}

	// 5. full_exempt_tool: both directions bypass DLP
	reqFull := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name": "full_exempt_tool", "phone": "05321234567", "token": "SUPER_SECRET_TOKEN"}`),
	}
	fReqFull, errFullReq := filter.FilterRequest(ctx, reqFull)
	if errFullReq != nil {
		t.Fatalf("full_exempt_tool request failed: %v", errFullReq)
	}
	if string(fReqFull.Params) != string(reqFull.Params) {
		t.Errorf("expected verbatim params for full_exempt_tool, got: %s", string(fReqFull.Params))
	}

	ctxFull := context.WithValue(ctx, types.ToolNameContextKey, "full_exempt_tool")
	respFull := &mcp.Response{Result: json.RawMessage(`{"phone": "05321234567", "token": "SUPER_SECRET_TOKEN"}`)}
	fRespFull, errFullResp := filter.FilterResponse(ctxFull, respFull)
	if errFullResp != nil {
		t.Fatalf("full_exempt_tool response failed: %v", errFullResp)
	}
	if string(fRespFull.Result) != string(respFull.Result) {
		t.Errorf("expected verbatim result for full_exempt_tool, got: %s", string(fRespFull.Result))
	}

	// 6. full_enforced_tool: both directions enforce DLP
	reqEnforced := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name": "full_enforced_tool", "phone": "05321234567"}`),
	}
	fReqEnforced, errEnfReq := filter.FilterRequest(ctx, reqEnforced)
	if errEnfReq != nil {
		t.Fatalf("unexpected error for full_enforced_tool: %v", errEnfReq)
	}
	if string(fReqEnforced.Params) != `{"name": "full_enforced_tool", "phone": "[REDACTED:PHONE]"}` {
		t.Errorf("expected masked phone in full_enforced_tool request, got: %s", string(fReqEnforced.Params))
	}

	// 7. Malformed request JSON (resilience)
	reqMalformed := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{not a valid json`),
	}
	_, errMalformed := filter.FilterRequest(ctx, reqMalformed)
	// Should not panic, should fall through or return cleanly
	_ = errMalformed

	// 8. Request with empty params or missing "name" field
	reqNoName := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"phone": "05321234567"}`),
	}
	fReqNoName, errNoName := filter.FilterRequest(ctx, reqNoName)
	if errNoName != nil {
		t.Fatalf("unexpected error for request with no name: %v", errNoName)
	}
	if string(fReqNoName.Params) != `{"phone": "[REDACTED:PHONE]"}` {
		t.Errorf("expected default inspection when name is missing, got: %s", string(fReqNoName.Params))
	}
}

type mockHITLApprover struct {
	approveFn func(ctx context.Context, req *guard.HITLRequest) (bool, error)
	callCount int
}

func (m *mockHITLApprover) RequestApproval(ctx context.Context, req *guard.HITLRequest) (bool, error) {
	m.callCount++
	if m.approveFn != nil {
		return m.approveFn(ctx, req)
	}
	return false, nil
}

func TestDLPFilter_ActionHITL(t *testing.T) {
	patterns := []config.DLPPattern{
		{Name: "destructive_rm", Regex: `rm\s+-rf`, Action: "hitl"},
	}

	filter, err := NewDLPFilter(true, nil, patterns)
	if err != nil {
		t.Fatalf("Failed to create DLP filter: %v", err)
	}

	req := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"run_bash","arguments":{"command":"rm -rf /tmp/test"}}`),
	}

	t.Run("DispatcherUnavailable_FailsClosed", func(t *testing.T) {
		ctx := context.Background()
		_, mcpErr := filter.FilterRequest(ctx, req)
		if mcpErr == nil {
			t.Fatal("expected error when dispatcher is unavailable, got nil")
		}
		if mcpErr.Code != mcp.ErrHITLDenied {
			t.Errorf("expected error code %d (ErrHITLDenied), got %d", mcp.ErrHITLDenied, mcpErr.Code)
		}
	})

	t.Run("DispatcherApproved_SetsHumanApprovedContext", func(t *testing.T) {
		approver := &mockHITLApprover{
			approveFn: func(ctx context.Context, req *guard.HITLRequest) (bool, error) {
				return true, nil
			},
		}
		filter.SetHITLDispatcher(approver)

		auditMeta := &types.AuditMetadata{}
		ctx := types.WithAuditMetadata(context.Background(), auditMeta)

		filtered, mcpErr := filter.FilterRequest(ctx, req)
		if mcpErr != nil {
			t.Fatalf("expected approved HITL request to succeed, got error: %v", mcpErr)
		}
		if filtered == nil {
			t.Fatal("expected request to pass through")
		}
		if approver.callCount != 1 {
			t.Errorf("expected 1 approval request, got %d", approver.callCount)
		}

		// Verify Human Supremacy flag was set in context
		if !types.IsHumanApproved(ctx) {
			t.Errorf("expected Human Supremacy flag to be true in context after operator approval")
		}
	})

	t.Run("DispatcherDenied_ReturnsErrHITLDenied", func(t *testing.T) {
		approver := &mockHITLApprover{
			approveFn: func(ctx context.Context, req *guard.HITLRequest) (bool, error) {
				return false, nil
			},
		}
		filter.SetHITLDispatcher(approver)

		auditMeta := &types.AuditMetadata{}
		ctx := types.WithAuditMetadata(context.Background(), auditMeta)

		_, mcpErr := filter.FilterRequest(ctx, req)
		if mcpErr == nil {
			t.Fatal("expected error when operator rejects tool call, got nil")
		}
		if mcpErr.Code != mcp.ErrHITLDenied {
			t.Errorf("expected error code %d (ErrHITLDenied), got %d", mcp.ErrHITLDenied, mcpErr.Code)
		}
		if types.IsHumanApproved(ctx) {
			t.Errorf("expected Human Supremacy flag to remain false after rejection")
		}
	})
}


