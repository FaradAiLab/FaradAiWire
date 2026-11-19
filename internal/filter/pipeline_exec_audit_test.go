package filter_test

import (
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
