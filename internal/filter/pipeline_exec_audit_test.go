package filter_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/dlp"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/types"
	"github.com/FaradAiLab/FaradAiWire/internal/logger"
	"github.com/FaradAiLab/FaradAiWire/internal/settings"
	"github.com/FaradAiLab/FaradAiWire/internal/telemetry/duckdb"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
)

func TestPipeline_FourFieldCapture_And_JSONLIsolation(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "four_field.duckdb")
	jsonlPath := filepath.Join(tempDir, "audit.jsonl")

	fileLogger, err := logger.NewFileAuditLogger(jsonlPath)
	if err != nil {
		t.Fatalf("NewFileAuditLogger failed: %v", err)
	}
	defer fileLogger.Close()

	engine, err := duckdb.New(duckdb.Config{
		DBPath:       dbPath,
		BufferSize:   100,
		BatchFlushMs: 10,
	})
	if err != nil {
		t.Fatalf("duckdb.New failed: %v", err)
	}
	defer engine.Close()

	op := settings.DefaultOperationalSettings()
	sCache := settings.NewCache(op)
	engine.SetSettingsCache(sCache)

	dlpFilter, err := dlp.NewDLPFilter(true, nil, []config.DLPPattern{
		{Name: "secret_token", Regex: `tok_secret_[0-9]+`, Action: "block"},
		{Name: "email", Regex: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`, Action: "mask"},
	})
	if err != nil {
		t.Fatalf("NewDLPFilter failed: %v", err)
	}

	p := filter.NewPipeline(filter.NewMultiAuditLogger(fileLogger, engine))
	p.SetSettingsCache(sCache)
	p.SetFilters([]filter.NamedFilter{dlpFilter})

	ctx := context.Background()
	ctx = context.WithValue(ctx, filter.AgentNameContextKey, "antigravity")

	// 1. Blocked ingress retains OriginalRequest in DuckDB only, NOT JSONL
	secret := "tok_secret_88881111"
	reqBlock := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"codegraph_explore","arguments":{"query":"` + secret + `"}}`),
		ID:      1,
	}
	ctxBlock := context.WithValue(ctx, filter.InvocationIDContextKey, "inv-block-1")
	ctxBlock = context.WithValue(ctxBlock, filter.TraceIDContextKey, "trace-block-1")
	if _, mcpErr := p.ProcessRequest(ctxBlock, reqBlock); mcpErr == nil {
		t.Fatal("expected blocked error on secret token")
	}

	// 2. Clean ALLOWED request + MASKED response collapses into 1 consolidated sparse row
	ctxMask := context.WithValue(ctx, filter.InvocationIDContextKey, "inv-mask-2")
	ctxMask = context.WithValue(ctxMask, filter.TraceIDContextKey, "trace-mask-2")
	ctxMask = context.WithValue(ctxMask, types.ToolNameContextKey, "codegraph_explore")
	reqAllow := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"codegraph_explore","arguments":{"query":"Builder","projectPath":"/repo"}}`),
		ID:      2,
	}
	if _, mcpErr := p.ProcessRequest(ctxMask, reqAllow); mcpErr != nil {
		t.Fatalf("unexpected request error: %v", mcpErr)
	}
	respMask := &mcp.Response{
		JSONRPC: "2.0",
		Result:  json.RawMessage(`{"email":"dev@farad.local"}`),
		ID:      2,
	}
	if _, mcpErr := p.ProcessResponse(ctxMask, respMask); mcpErr != nil {
		t.Fatalf("unexpected response error: %v", mcpErr)
	}

	// 3. Clean ALLOWED request + Upstream JSON-RPC error passes through and logs OriginalResponse
	ctxErr := context.WithValue(ctx, filter.InvocationIDContextKey, "inv-err-3")
	ctxErr = context.WithValue(ctxErr, filter.TraceIDContextKey, "trace-err-3")
	ctxErr = context.WithValue(ctxErr, types.ToolNameContextKey, "codegraph_explore")
	if _, mcpErr := p.ProcessRequest(ctxErr, reqAllow); mcpErr != nil {
		t.Fatalf("unexpected request error: %v", mcpErr)
	}
	upstreamErrResp := &mcp.Response{
		JSONRPC: "2.0",
		Error:   &mcp.Error{Code: -32602, Message: "projectPath is required"},
		ID:      3,
	}
	outErrResp, mcpErr := p.ProcessResponse(ctxErr, upstreamErrResp)
	if mcpErr != nil {
		t.Fatalf("expected upstream JSON-RPC error to pass through cleanly, got %v", mcpErr)
	}
	if outErrResp == nil || outErrResp.Error == nil || outErrResp.Error.Message != "projectPath is required" {
		t.Fatalf("expected upstream error preserved, got %+v", outErrResp)
	}

	if err := engine.Flush(); err != nil {
		t.Fatalf("engine.Flush failed: %v", err)
	}
	_ = fileLogger.Close()

	// Verify flat JSONL NEVER leaked the plaintext secret or email
	jsonlBytes, err := os.ReadFile(jsonlPath)
	if err != nil {
		t.Fatalf("ReadFile jsonl failed: %v", err)
	}
	jsonlStr := string(jsonlBytes)
	if strings.Contains(jsonlStr, secret) || strings.Contains(jsonlStr, "dev@farad.local") {
		t.Fatalf("ZERO-DLP BLEED in JSONL: %s", jsonlStr)
	}

	// Verify DuckDB records have full 4 fields
	recBlock, err := engine.GetAuditLogByID(ctx, "inv-block-1")
	if err != nil {
		t.Fatalf("GetAuditLogByID inv-block-1 failed: %v", err)
	}
	if !strings.Contains(recBlock.OriginalRequest, secret) || recBlock.Request != "" || recBlock.Response == "" {
		t.Fatalf("unexpected blocked record 4-field shape: %+v", recBlock)
	}

	recMask, err := engine.GetAuditLogByID(ctx, "inv-mask-2")
	if err != nil {
		t.Fatalf("GetAuditLogByID inv-mask-2 failed: %v", err)
	}
	if recMask.Decision != filter.DecisionMasked || recMask.RequestDecision != filter.DecisionAllowed || recMask.ResponseDecision != filter.DecisionMasked {
		t.Fatalf("unexpected composite/phase decisions: %+v", recMask)
	}
	if recMask.Request != "" {
		t.Fatalf("expected sparse NULL/empty Request when unchanged, got %q", recMask.Request)
	}
	if !strings.Contains(recMask.OriginalResponse, "dev@farad.local") || !strings.Contains(recMask.Response, "[REDACTED:EMAIL]") {
		t.Fatalf("expected unmasked OriginalResponse + redacted Response, got orig=%q resp=%q", recMask.OriginalResponse, recMask.Response)
	}

	recErr, err := engine.GetAuditLogByID(ctx, "inv-err-3")
	if err != nil {
		t.Fatalf("GetAuditLogByID inv-err-3 failed: %v", err)
	}
	if !strings.Contains(recErr.OriginalResponse, "projectPath is required") || recErr.ErrorMessage != "projectPath is required" {
		t.Fatalf("expected upstream JSON-RPC error captured in OriginalResponse, got %+v", recErr)
	}
	if recErr.Decision != filter.DecisionError {
		t.Fatalf("expected upstream JSON-RPC error decision ERROR, got %q", recErr.Decision)
	}
}

func TestPipeline_RetainLocalPayloadsDisabled_SuppressesVaultAndFailurePayloads(t *testing.T) {
	tempDir := t.TempDir()
	engine, err := duckdb.New(duckdb.Config{
		DBPath:       filepath.Join(tempDir, "no_retain.duckdb"),
		BufferSize:   100,
		BatchFlushMs: 10,
	})
	if err != nil {
		t.Fatalf("duckdb.New failed: %v", err)
	}
	defer engine.Close()

	op := settings.DefaultOperationalSettings()
	op.Maintenance.RetainLocalPayloads = false
	sCache := settings.NewCache(op)
	engine.SetSettingsCache(sCache)

	p := filter.NewPipeline(engine)
	p.SetSettingsCache(sCache)

	ctx := context.WithValue(context.Background(), filter.InvocationIDContextKey, "inv-no-retain")
	ctx = context.WithValue(ctx, filter.TraceIDContextKey, "trace-no-retain")
	req := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"fetch_secret","arguments":{"token":"super-secret-value"}}`),
		ID:      1,
	}
	if _, mcpErr := p.ProcessRequest(ctx, req); mcpErr != nil {
		t.Fatalf("unexpected request error: %v", mcpErr)
	}

	// Verify in-flight PENDING state before response completes
	if err := engine.Flush(); err != nil {
		t.Fatalf("flush pending failed: %v", err)
	}
	pendingRec, err := engine.GetAuditLogByID(ctx, "inv-no-retain")
	if err != nil {
		t.Fatalf("GetAuditLogByID pending failed: %v", err)
	}
	if pendingRec.Decision != filter.DecisionPending {
		t.Fatalf("expected PENDING decision before response, got %q", pendingRec.Decision)
	}
	if pendingRec.OriginalRequest != "" || pendingRec.RawPayloadPreview != "" {
		t.Fatalf("expected empty payloads when retain_local_payloads=false, got orig=%q raw=%q", pendingRec.OriginalRequest, pendingRec.RawPayloadPreview)
	}

	// Emit upstream failure and verify ERROR decision without storing raw response payload
	p.EmitResponseFailure(ctx, "inv-no-retain", "trace-no-retain", "antigravity", "fetch_secret", "forwarder", filter.DecisionError, "upstream 502", []byte(`{"error":"secret-upstream-detail"}`))
	if err := engine.Flush(); err != nil {
		t.Fatalf("flush failure failed: %v", err)
	}
	finalRec, err := engine.GetAuditLogByID(ctx, "inv-no-retain")
	if err != nil {
		t.Fatalf("GetAuditLogByID final failed: %v", err)
	}
	if finalRec.Decision != filter.DecisionError || finalRec.ResponseDecision != filter.DecisionError {
		t.Fatalf("expected ERROR decision after upstream failure, got %+v", finalRec)
	}
	if finalRec.OriginalResponse != "" || finalRec.RawPayloadPreview != "" {
		t.Fatalf("expected empty response payload when retain_local_payloads=false, got origResp=%q raw=%q", finalRec.OriginalResponse, finalRec.RawPayloadPreview)
	}
}

type inPlaceMutatingResponseFilter struct{}

func (f *inPlaceMutatingResponseFilter) Name() string { return "inplace_mutator" }
func (f *inPlaceMutatingResponseFilter) Order() int   { return 100 }
func (f *inPlaceMutatingResponseFilter) FilterResponse(ctx context.Context, resp *mcp.Response) (*mcp.Response, *mcp.Error) {
	if resp == nil || len(resp.Result) == 0 {
		return resp, nil
	}
	// Overwrite existing backing bytes in-place with equal-length token
	copy(resp.Result, bytes.ReplaceAll(resp.Result, []byte("secret-value"), []byte("REDACTED-VAL")))
	return resp, nil
}

func TestPipeline_ToolsListCorrelation_And_AllowedRetention(t *testing.T) {
	tempDir := t.TempDir()
	engine, err := duckdb.New(duckdb.Config{
		DBPath:       filepath.Join(tempDir, "tools_list.duckdb"),
		BufferSize:   100,
		BatchFlushMs: 10,
	})
	if err != nil {
		t.Fatalf("duckdb.New failed: %v", err)
	}
	defer engine.Close()

	p := filter.NewPipeline(engine)
	ctx := context.WithValue(context.Background(), filter.AgentNameContextKey, "antigravity")
	ctx = context.WithValue(ctx, filter.InvocationIDContextKey, "inv-tools-list-1")
	ctx = context.WithValue(ctx, filter.TraceIDContextKey, "trace-tools-list-1")

	req := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/list",
		ID:      10,
	}
	if _, mcpErr := p.ProcessRequest(ctx, req); mcpErr != nil {
		t.Fatalf("ProcessRequest failed: %v", mcpErr)
	}
	resp := &mcp.Response{
		JSONRPC: "2.0",
		Result:  json.RawMessage(`{"tools":[{"name":"demo_tool","description":"hello"}]}`),
		ID:      10,
	}
	if _, mcpErr := p.ProcessResponse(ctx, resp); mcpErr != nil {
		t.Fatalf("ProcessResponse failed: %v", mcpErr)
	}
	if err := engine.Flush(); err != nil {
		t.Fatalf("engine.Flush failed: %v", err)
	}

	rec, err := engine.GetAuditLogByID(ctx, "inv-tools-list-1")
	if err != nil {
		t.Fatalf("GetAuditLogByID failed: %v", err)
	}
	if rec.ToolName != "tools/list" {
		t.Fatalf("expected ToolName 'tools/list', got %q", rec.ToolName)
	}
	if rec.Decision != filter.DecisionAllowed || rec.RequestDecision != filter.DecisionAllowed || rec.ResponseDecision != filter.DecisionAllowed {
		t.Fatalf("expected ALLOWED lifecycle decisions, got composite=%q req=%q resp=%q", rec.Decision, rec.RequestDecision, rec.ResponseDecision)
	}
	if !strings.Contains(rec.OriginalRequest, "tools/list") {
		t.Fatalf("expected OriginalRequest to retain tools/list metadata, got %q", rec.OriginalRequest)
	}
	if !strings.Contains(rec.OriginalResponse, "demo_tool") {
		t.Fatalf("expected OriginalResponse to retain tool list payload, got %q", rec.OriginalResponse)
	}
}

func TestPipeline_ProcessResponse_InPlaceMutationDetected(t *testing.T) {
	tempDir := t.TempDir()
	engine, err := duckdb.New(duckdb.Config{
		DBPath:       filepath.Join(tempDir, "inplace_resp.duckdb"),
		BufferSize:   100,
		BatchFlushMs: 10,
	})
	if err != nil {
		t.Fatalf("duckdb.New failed: %v", err)
	}
	defer engine.Close()

	p := filter.NewPipeline(engine)
	p.SetFilters([]filter.NamedFilter{&inPlaceMutatingResponseFilter{}})

	ctx := context.WithValue(context.Background(), filter.InvocationIDContextKey, "inv-inplace-1")
	ctx = context.WithValue(ctx, filter.TraceIDContextKey, "trace-inplace-1")
	ctx = context.WithValue(ctx, types.ToolNameContextKey, "echo")

	req := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"echo","arguments":{}}`),
		ID:      11,
	}
	if _, mcpErr := p.ProcessRequest(ctx, req); mcpErr != nil {
		t.Fatalf("ProcessRequest failed: %v", mcpErr)
	}
	resp := &mcp.Response{
		JSONRPC: "2.0",
		Result:  json.RawMessage(`{"val":"secret-value"}`),
		ID:      11,
	}
	if _, mcpErr := p.ProcessResponse(ctx, resp); mcpErr != nil {
		t.Fatalf("ProcessResponse failed: %v", mcpErr)
	}
	if err := engine.Flush(); err != nil {
		t.Fatalf("engine.Flush failed: %v", err)
	}

	rec, err := engine.GetAuditLogByID(ctx, "inv-inplace-1")
	if err != nil {
		t.Fatalf("GetAuditLogByID failed: %v", err)
	}
	if rec.Decision != filter.DecisionMasked || rec.ResponseDecision != filter.DecisionMasked {
		t.Fatalf("expected MASKED decision on in-place response mutation, got decision=%q resp=%q", rec.Decision, rec.ResponseDecision)
	}
	if !strings.Contains(rec.OriginalResponse, "secret-value") || !strings.Contains(rec.Response, "REDACTED-VAL") {
		t.Fatalf("expected OriginalResponse vs mutated Response preserved, got orig=%q resp=%q", rec.OriginalResponse, rec.Response)
	}
}

func TestPipeline_ToolsList_RetainLocalPayloadsDisabled(t *testing.T) {
	tempDir := t.TempDir()
	engine, err := duckdb.New(duckdb.Config{
		DBPath:       filepath.Join(tempDir, "tools_list_noretain.duckdb"),
		BufferSize:   100,
		BatchFlushMs: 10,
	})
	if err != nil {
		t.Fatalf("duckdb.New failed: %v", err)
	}
	defer engine.Close()

	op := settings.DefaultOperationalSettings()
	op.Maintenance.RetainLocalPayloads = false
	sCache := settings.NewCache(op)
	engine.SetSettingsCache(sCache)

	p := filter.NewPipeline(engine)
	p.SetSettingsCache(sCache)

	ctx := context.WithValue(context.Background(), filter.AgentNameContextKey, "antigravity")
	ctx = context.WithValue(ctx, filter.InvocationIDContextKey, "inv-tl-noretain")
	ctx = context.WithValue(ctx, filter.TraceIDContextKey, "trace-tl-noretain")

	req := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/list",
		ID:      20,
	}
	if _, mcpErr := p.ProcessRequest(ctx, req); mcpErr != nil {
		t.Fatalf("ProcessRequest failed: %v", mcpErr)
	}
	resp := &mcp.Response{
		JSONRPC: "2.0",
		Result:  json.RawMessage(`{"tools":[{"name":"secret_tool","description":"classified"}]}`),
		ID:      20,
	}
	if _, mcpErr := p.ProcessResponse(ctx, resp); mcpErr != nil {
		t.Fatalf("ProcessResponse failed: %v", mcpErr)
	}
	if err := engine.Flush(); err != nil {
		t.Fatalf("engine.Flush failed: %v", err)
	}

	rec, err := engine.GetAuditLogByID(ctx, "inv-tl-noretain")
	if err != nil {
		t.Fatalf("GetAuditLogByID failed: %v", err)
	}
	if rec.ToolName != "tools/list" || rec.Decision != filter.DecisionAllowed {
		t.Fatalf("expected ALLOWED tools/list record, got tool=%q decision=%q", rec.ToolName, rec.Decision)
	}
	if rec.OriginalRequest != "" || rec.RawPayloadPreview != "" || rec.OriginalResponse != "" {
		t.Fatalf("expected zero retained payloads when retain_local_payloads=false, got origReq=%q raw=%q origResp=%q",
			rec.OriginalRequest, rec.RawPayloadPreview, rec.OriginalResponse)
	}
}

func TestPipeline_ToolsList_WithParams_And_ResponseMasked(t *testing.T) {
	tempDir := t.TempDir()
	engine, err := duckdb.New(duckdb.Config{
		DBPath:       filepath.Join(tempDir, "tools_list_masked.duckdb"),
		BufferSize:   100,
		BatchFlushMs: 10,
	})
	if err != nil {
		t.Fatalf("duckdb.New failed: %v", err)
	}
	defer engine.Close()

	dlpFilter, err := dlp.NewDLPFilter(true, nil, []config.DLPPattern{
		{Name: "email", Regex: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`, Action: "mask"},
	})
	if err != nil {
		t.Fatalf("NewDLPFilter failed: %v", err)
	}

	p := filter.NewPipeline(engine)
	p.SetFilters([]filter.NamedFilter{dlpFilter})

	ctx := context.WithValue(context.Background(), filter.AgentNameContextKey, "antigravity")
	ctx = context.WithValue(ctx, filter.InvocationIDContextKey, "inv-tl-masked")
	ctx = context.WithValue(ctx, filter.TraceIDContextKey, "trace-tl-masked")

	req := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/list",
		Params:  json.RawMessage(`{"cursor":"page-2"}`),
		ID:      21,
	}
	if _, mcpErr := p.ProcessRequest(ctx, req); mcpErr != nil {
		t.Fatalf("ProcessRequest failed: %v", mcpErr)
	}
	resp := &mcp.Response{
		JSONRPC: "2.0",
		Result:  json.RawMessage(`{"tools":[{"name":"mailer","description":"owner admin@farad.local"}]}`),
		ID:      21,
	}
	if _, mcpErr := p.ProcessResponse(ctx, resp); mcpErr != nil {
		t.Fatalf("ProcessResponse failed: %v", mcpErr)
	}
	if err := engine.Flush(); err != nil {
		t.Fatalf("engine.Flush failed: %v", err)
	}

	rec, err := engine.GetAuditLogByID(ctx, "inv-tl-masked")
	if err != nil {
		t.Fatalf("GetAuditLogByID failed: %v", err)
	}
	if rec.ToolName != "tools/list" || rec.Decision != filter.DecisionMasked {
		t.Fatalf("expected MASKED tools/list record, got tool=%q decision=%q", rec.ToolName, rec.Decision)
	}
	if !strings.Contains(rec.OriginalRequest, `"cursor":"page-2"`) {
		t.Fatalf("expected explicit tools/list params preserved, got %q", rec.OriginalRequest)
	}
	if !strings.Contains(rec.OriginalResponse, "admin@farad.local") || !strings.Contains(rec.Response, "[REDACTED:EMAIL]") {
		t.Fatalf("expected masked response diff preserved, got orig=%q resp=%q", rec.OriginalResponse, rec.Response)
	}
}
