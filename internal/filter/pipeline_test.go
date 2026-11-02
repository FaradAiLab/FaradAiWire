package filter_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/adaptive"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/dlp"
	"github.com/FaradAiLab/FaradAiWire/internal/logger"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
	"github.com/FaradAiLab/FaradAiWire/internal/telemetry/duckdb"
)

type mockFilter struct {
	name        string
	execCount   int32
	shouldBlock bool
}

func (m *mockFilter) Name() string { return m.name }
func (m *mockFilter) FilterRequest(ctx context.Context, req *mcp.Request) (*mcp.Request, *mcp.Error) {
	atomic.AddInt32(&m.execCount, 1)
	if m.shouldBlock {
		return nil, mcp.NewError(mcp.ErrInvalidRequest, "blocked by mock", nil)
	}
	return req, nil
}
func (m *mockFilter) FilterResponse(ctx context.Context, resp *mcp.Response) (*mcp.Response, *mcp.Error) {
	atomic.AddInt32(&m.execCount, 1)
	if m.shouldBlock {
		return nil, mcp.NewError(mcp.ErrInvalidRequest, "blocked by mock", nil)
	}
	return resp, nil
}

type mockAuditLogger struct {
	events []*filter.AuditEvent
}

func (m *mockAuditLogger) LogEvent(event *filter.AuditEvent) {
	m.events = append(m.events, event)
}

type mockReqOnlyFilter struct {
	name      string
	execCount int32
}

func (m *mockReqOnlyFilter) Name() string { return m.name }
func (m *mockReqOnlyFilter) FilterRequest(ctx context.Context, req *mcp.Request) (*mcp.Request, *mcp.Error) {
	atomic.AddInt32(&m.execCount, 1)
	return req, nil
}

type mockRespOnlyFilter struct {
	name      string
	execCount int32
}

func (m *mockRespOnlyFilter) Name() string { return m.name }
func (m *mockRespOnlyFilter) FilterResponse(ctx context.Context, resp *mcp.Response) (*mcp.Response, *mcp.Error) {
	atomic.AddInt32(&m.execCount, 1)
	return resp, nil
}

type panickingReqFilter struct {
	name      string
	panicMsg  string
	execCount int32
}

func (m *panickingReqFilter) Name() string { return m.name }
func (m *panickingReqFilter) FilterRequest(ctx context.Context, req *mcp.Request) (*mcp.Request, *mcp.Error) {
	atomic.AddInt32(&m.execCount, 1)
	panic(m.panicMsg)
}

type panickingRespFilter struct {
	name      string
	panicMsg  string
	execCount int32
}

func (m *panickingRespFilter) Name() string { return m.name }
func (m *panickingRespFilter) FilterResponse(ctx context.Context, resp *mcp.Response) (*mcp.Response, *mcp.Error) {
	atomic.AddInt32(&m.execCount, 1)
	panic(m.panicMsg)
}

func TestPipeline_InterfaceSegregation(t *testing.T) {
	pipeline := filter.NewPipeline(nil)

	reqOnly := &mockReqOnlyFilter{name: "req_only"}
	respOnly := &mockRespOnlyFilter{name: "resp_only"}
	bidirectional := &mockFilter{name: "bidirectional"}

	pipeline.SetFilters([]filter.NamedFilter{reqOnly, respOnly, bidirectional})

	ctx := context.Background()

	// 1. ProcessRequest
	req := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name": "test_tool", "arguments": {}}`),
		ID:      1,
	}

	_, mcpErr := pipeline.ProcessRequest(ctx, req)
	if mcpErr != nil {
		t.Fatalf("unexpected request error: %v", mcpErr)
	}

	if atomic.LoadInt32(&reqOnly.execCount) != 1 {
		t.Errorf("expected req_only filter to be called in ProcessRequest, got %d", reqOnly.execCount)
	}
	if atomic.LoadInt32(&respOnly.execCount) != 0 {
		t.Errorf("expected resp_only filter to NOT be called in ProcessRequest, got %d", respOnly.execCount)
	}
	if atomic.LoadInt32(&bidirectional.execCount) != 1 {
		t.Errorf("expected bidirectional filter to be called in ProcessRequest, got %d", bidirectional.execCount)
	}

	// 2. ProcessResponse
	resp := &mcp.Response{
		JSONRPC: "2.0",
		ID:      1,
		Result:  json.RawMessage(`{"content": []}`),
	}

	_, mcpErr2 := pipeline.ProcessResponse(ctx, resp)
	if mcpErr2 != nil {
		t.Fatalf("unexpected response error: %v", mcpErr2)
	}

	if atomic.LoadInt32(&reqOnly.execCount) != 1 {
		t.Errorf("expected req_only filter to NOT be called in ProcessResponse, got %d", reqOnly.execCount)
	}
	if atomic.LoadInt32(&respOnly.execCount) != 1 {
		t.Errorf("expected resp_only filter to be called in ProcessResponse, got %d", respOnly.execCount)
	}
	if atomic.LoadInt32(&bidirectional.execCount) != 2 {
		t.Errorf("expected bidirectional filter to be called in ProcessResponse (total 2), got %d", bidirectional.execCount)
	}
}

func TestPipeline_AdaptiveFastPathVsDeepPath(t *testing.T) {
	logger := &mockAuditLogger{}
	pipeline := filter.NewPipeline(logger)

	prefillMock := &mockFilter{name: "prefill_block"}
	schemaMock := &mockFilter{name: "schema_validation"}
	injectionMock := &mockFilter{name: "injection_scanner"}
	dlpMock := &mockFilter{name: "dlp"}
	hitlMock := &mockFilter{name: "hitl"}

	pipeline.SetFilters([]filter.NamedFilter{prefillMock, schemaMock, injectionMock, dlpMock, hitlMock})

	// Configure Adaptive Router
	router := adaptive.NewRouter(true, "deep", []string{"get_*", "list_*"}, []string{"delete_*", "execute_*"})
	pipeline.SetAdaptiveRouter(router)

	ctx := context.Background()

	// 1. Fast-Path Request (e.g. get_user)
	fastReq := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name": "get_user", "arguments": {"user_id": "123"}}`),
		ID:      1,
	}

	_, err := pipeline.ProcessRequest(ctx, fastReq)
	if err != nil {
		t.Fatalf("Fast-Path request failed: %v", err)
	}

	// Fast-path should execute Prefill, Schema, and DLP (SEC-017 / DEC-05)
	if atomic.LoadInt32(&prefillMock.execCount) != 1 {
		t.Errorf("Expected prefill_block to be executed on Fast-Path")
	}
	if atomic.LoadInt32(&schemaMock.execCount) != 1 {
		t.Errorf("Expected schema_validation to be executed on Fast-Path")
	}
	if atomic.LoadInt32(&dlpMock.execCount) != 1 {
		t.Errorf("Expected dlp to be executed on Fast-Path, got %d", dlpMock.execCount)
	}
	if atomic.LoadInt32(&injectionMock.execCount) != 0 {
		t.Errorf("Expected injection_scanner to be SKIPPED on Fast-Path, got %d", injectionMock.execCount)
	}
	if atomic.LoadInt32(&hitlMock.execCount) != 0 {
		t.Errorf("Expected hitl to be SKIPPED on Fast-Path, got %d", hitlMock.execCount)
	}

	// 2. Deep-Path Request (e.g. delete_database)
	deepReq := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name": "delete_database", "arguments": {"db_id": "prod"}}`),
		ID:      2,
	}

	_, err = pipeline.ProcessRequest(ctx, deepReq)
	if err != nil {
		t.Fatalf("Deep-Path request failed: %v", err)
	}

	// Deep-path should execute ALL filters
	if atomic.LoadInt32(&prefillMock.execCount) != 2 {
		t.Errorf("Expected prefill_block to be executed on Deep-Path (total 2)")
	}
	if atomic.LoadInt32(&schemaMock.execCount) != 2 {
		t.Errorf("Expected schema_validation to be executed on Deep-Path (total 2)")
	}
	if atomic.LoadInt32(&dlpMock.execCount) != 2 {
		t.Errorf("Expected dlp to be executed on Deep-Path (total 2)")
	}
	if atomic.LoadInt32(&injectionMock.execCount) != 1 {
		t.Errorf("Expected injection_scanner to be executed on Deep-Path")
	}
	if atomic.LoadInt32(&hitlMock.execCount) != 1 {
		t.Errorf("Expected hitl to be executed on Deep-Path")
	}
}

func TestPipeline_ProcessRequest_PanicRecovery(t *testing.T) {
	logger := &mockAuditLogger{}
	pipeline := filter.NewPipeline(logger)

	goodFilter := &mockReqOnlyFilter{name: "good_filter"}
	panicFilter := &panickingReqFilter{name: "failing_filter", panicMsg: "simulated nil pointer crash"}

	pipeline.SetFilters([]filter.NamedFilter{goodFilter, panicFilter})

	req := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name": "query_db"}`),
		ID:      1,
	}

	ctx := context.WithValue(context.Background(), filter.UserContextKey, &filter.UserContext{UserID: "alice", Role: "Admin"})
	ctx = context.WithValue(ctx, filter.TraceIDContextKey, "trace-panic-123")

	resReq, mcpErr := pipeline.ProcessRequest(ctx, req)

	// Verify request failed gracefully without crashing the test process
	if resReq != nil {
		t.Fatal("expected nil request on filter panic")
	}
	if mcpErr == nil {
		t.Fatal("expected error on filter panic, got nil")
	}
	if mcpErr.Code != mcp.ErrInternalError {
		t.Errorf("expected error code %d (ErrInternalError), got %d", mcp.ErrInternalError, mcpErr.Code)
	}
	if !strings.Contains(mcpErr.Message, "failing_filter") || !strings.Contains(mcpErr.Message, "simulated nil pointer crash") {
		t.Errorf("expected error message to mention failing filter and panic message, got: %s", mcpErr.Message)
	}

	// Verify good filter was executed before panic
	if atomic.LoadInt32(&goodFilter.execCount) != 1 {
		t.Errorf("expected good filter to execute before panic")
	}

	// Verify audit log captured a CRITICAL event
	var criticalEvent *filter.AuditEvent
	for _, event := range logger.events {
		if event.Decision == "CRITICAL" {
			criticalEvent = event
			break
		}
	}

	if criticalEvent == nil {
		t.Fatal("expected a CRITICAL audit event to be logged, but found none")
	}
	if criticalEvent.FilterName != "failing_filter" {
		t.Errorf("expected critical event filter name 'failing_filter', got '%s'", criticalEvent.FilterName)
	}
	if criticalEvent.ErrorCode != mcp.ErrInternalError {
		t.Errorf("expected critical event error code %d, got %d", mcp.ErrInternalError, criticalEvent.ErrorCode)
	}
	if criticalEvent.TraceID != "trace-panic-123" {
		t.Errorf("expected trace ID 'trace-panic-123', got '%s'", criticalEvent.TraceID)
	}
	if criticalEvent.User == nil || criticalEvent.User.UserID != "alice" {
		t.Errorf("expected user context with alice, got: %+v", criticalEvent.User)
	}
	if !strings.Contains(criticalEvent.Message, "simulated nil pointer crash") {
		t.Errorf("expected audit message to contain panic message, got: %s", criticalEvent.Message)
	}
	if !strings.Contains(criticalEvent.Message, "Stack:") {
		t.Errorf("expected audit message to contain stack trace, got: %s", criticalEvent.Message)
	}
}

func TestPipeline_ProcessResponse_PanicRecovery(t *testing.T) {
	logger := &mockAuditLogger{}
	pipeline := filter.NewPipeline(logger)

	panicFilter := &panickingRespFilter{name: "failing_resp_filter", panicMsg: "array index out of range"}
	pipeline.SetFilters([]filter.NamedFilter{panicFilter})

	resp := &mcp.Response{
		JSONRPC: "2.0",
		ID:      1,
		Result:  json.RawMessage(`{"tools": []}`),
	}

	ctx := context.WithValue(context.Background(), filter.UserContextKey, &filter.UserContext{UserID: "bob", Role: "guest"})
	ctx = context.WithValue(ctx, filter.ToolNameContextKey, "fetch_records")

	resResp, mcpErr := pipeline.ProcessResponse(ctx, resp)

	// Verify response failed gracefully without crashing the test process
	if resResp != nil {
		t.Fatal("expected nil response on filter panic")
	}
	if mcpErr == nil {
		t.Fatal("expected error on filter panic, got nil")
	}
	if mcpErr.Code != mcp.ErrInternalError {
		t.Errorf("expected error code %d (ErrInternalError), got %d", mcp.ErrInternalError, mcpErr.Code)
	}

	// Verify audit log captured a CRITICAL event
	var criticalEvent *filter.AuditEvent
	for _, event := range logger.events {
		if event.Decision == "CRITICAL" {
			criticalEvent = event
			break
		}
	}

	if criticalEvent == nil {
		t.Fatal("expected a CRITICAL audit event to be logged, but found none")
	}
	if criticalEvent.FilterName != "failing_resp_filter" {
		t.Errorf("expected critical event filter name 'failing_resp_filter', got '%s'", criticalEvent.FilterName)
	}
	if criticalEvent.ToolName != "fetch_records" {
		t.Errorf("expected tool name 'fetch_records', got '%s'", criticalEvent.ToolName)
	}
	if !strings.Contains(criticalEvent.Message, "array index out of range") {
		t.Errorf("expected audit message to contain panic message, got: %s", criticalEvent.Message)
	}
	if !strings.Contains(criticalEvent.Message, "Stack:") {
		t.Errorf("expected audit message to contain stack trace, got: %s", criticalEvent.Message)
	}
}

func TestPipeline_AtomicSwap_ConcurrentRequests(t *testing.T) {
	pipeline := filter.NewPipeline(nil)

	f1 := &mockFilter{name: "filter_v1"}
	r1 := adaptive.NewRouter(true, "deep", []string{"fast_*"}, nil)
	pipeline.Swap([]filter.Filter{f1}, r1)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	var reqSuccessCount int64
	var respSuccessCount int64
	var swapCount int64
	var wg sync.WaitGroup

	// Start 20 concurrent readers processing requests
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := &mcp.Request{
				JSONRPC: "2.0",
				Method:  "tools/call",
				Params:  json.RawMessage(`{"name": "fast_tool", "arguments": {}}`),
				ID:      1,
			}
			for ctx.Err() == nil {
				out, err := pipeline.ProcessRequest(ctx, req)
				if err == nil && out != nil {
					atomic.AddInt64(&reqSuccessCount, 1)
				}
			}
		}()
	}

	// Start 20 concurrent readers processing responses
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp := &mcp.Response{
				JSONRPC: "2.0",
				Result:  json.RawMessage(`{"status": "ok"}`),
				ID:      1,
			}
			for ctx.Err() == nil {
				out, err := pipeline.ProcessResponse(ctx, resp)
				if err == nil && out != nil {
					atomic.AddInt64(&respSuccessCount, 1)
				}
			}
		}()
	}

	// Start 5 concurrent writers swapping filters and routers
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			filtersV1 := []filter.Filter{&mockFilter{name: "filter_v1"}}
			routerV1 := adaptive.NewRouter(true, "deep", []string{"fast_*"}, nil)

			filtersV2 := []filter.Filter{&mockFilter{name: "filter_v2"}, &mockFilter{name: "filter_v2_extra"}}
			routerV2 := adaptive.NewRouter(false, "deep", nil, nil)

			toggle := false
			for ctx.Err() == nil {
				if toggle {
					pipeline.Swap(filtersV1, routerV1)
				} else {
					pipeline.Swap(filtersV2, routerV2)
				}
				toggle = !toggle
				atomic.AddInt64(&swapCount, 1)
				time.Sleep(1 * time.Millisecond)
			}
		}(i)
	}

	<-ctx.Done()
	wg.Wait()

	reqs := atomic.LoadInt64(&reqSuccessCount)
	resps := atomic.LoadInt64(&respSuccessCount)
	swaps := atomic.LoadInt64(&swapCount)

	if reqs == 0 {
		t.Error("expected at least some request successes during concurrent swapping")
	}
	if resps == 0 {
		t.Error("expected at least some response successes during concurrent swapping")
	}
	if swaps == 0 {
		t.Error("expected at least some atomic swaps to occur")
	}
	t.Logf("Concurrent atomic swap test passed: reqs=%d, resps=%d, swaps=%d", reqs, resps, swaps)
}

func BenchmarkPipeline_FastPathLatency(b *testing.B) {
	pipeline := filter.NewPipeline(nil)
	prefillMock := &mockFilter{name: "prefill_block"}
	schemaMock := &mockFilter{name: "schema_validation"}
	injMock := &mockFilter{name: "injection_scanner"}

	pipeline.SetFilters([]filter.Filter{prefillMock, schemaMock, injMock})
	router := adaptive.NewRouter(true, "deep", []string{"get_*"}, nil)
	pipeline.SetAdaptiveRouter(router)

	req := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name": "get_user", "arguments": {}}`),
		ID:      1,
	}
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		_, _ = pipeline.ProcessRequest(ctx, req)
		elapsed := time.Since(start)
		if elapsed > 2*time.Millisecond {
			b.Errorf("Fast-path exceeded 2ms latency SLA: %v", elapsed)
		}
	}
}

func TestPipeline_PayloadPreviewCeiling64KB(t *testing.T) {
	logger := &mockAuditLogger{}
	pipeline := filter.NewPipeline(logger)

	// Create 128 KB payload
	largeBlob := strings.Repeat("A", 128*1024)
	largeParams := []byte(`{"name":"test_tool","arguments":{"blob":"` + largeBlob + `"}}`)
	req := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  largeParams,
		ID:      1,
	}

	ctx := context.Background()
	_, err := pipeline.ProcessRequest(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(logger.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(logger.events))
	}
	event := logger.events[0]
	if event.InputBytes != len(largeParams) {
		t.Errorf("expected InputBytes %d, got %d", len(largeParams), event.InputBytes)
	}
	if !strings.Contains(event.RawPayload, "[TRUNCATED - Total Size:") {
		t.Errorf("expected RawPayload preview to contain truncation trailer, got: %s", event.RawPayload[len(event.RawPayload)-50:])
	}
	if len(event.RawPayload) > 65*1024 {
		t.Errorf("expected RawPayload preview length <= 65536 + trailer, got %d", len(event.RawPayload))
	}
}

func TestPipeline_PostFilterAuditCapture_DLPMaskedRequest(t *testing.T) {
	patterns := []config.DLPPattern{
		{
			Name:   "credit_card",
			Regex:  `\b(?:\d{4}[ -]?){3}\d{4}\b`,
			Action: "mask",
		},
	}
	dlpFilter, err := dlp.NewDLPFilter(true, nil, patterns)
	if err != nil {
		t.Fatalf("failed to create DLP filter: %v", err)
	}

	logger := &mockAuditLogger{}
	p := filter.NewPipeline(logger)
	p.SetFilters([]filter.NamedFilter{dlpFilter})

	sensitiveCard := "4532-1234-5678-9012"
	req := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(fmt.Sprintf(`{"name":"charge_card","arguments":{"card":"%s","amount":100}}`, sensitiveCard)),
		ID:      1,
	}

	processedReq, mcpErr := p.ProcessRequest(context.Background(), req)
	if mcpErr != nil {
		t.Fatalf("unexpected mcpErr: %v", mcpErr)
	}

	// 1. Verify returned request is masked
	if strings.Contains(string(processedReq.Params), sensitiveCard) {
		t.Errorf("processed request still contains unmasked sensitive card")
	}
	if !strings.Contains(string(processedReq.Params), "[REDACTED") {
		t.Errorf("expected [REDACTED] in processed request params")
	}

	// 2. Verify AuditEvent captures strictly POST-FILTER masked payload
	if len(logger.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(logger.events))
	}
	event := logger.events[0]
	if strings.Contains(event.RawPayload, sensitiveCard) {
		t.Fatalf("CRITICAL LEAK: AuditEvent.RawPayload contains unmasked sensitive card: %s", event.RawPayload)
	}
	if !strings.Contains(event.RawPayload, "[REDACTED") {
		t.Errorf("expected AuditEvent.RawPayload to contain masked [REDACTED], got: %s", event.RawPayload)
	}
	if event.Decision != "MASKED" {
		t.Errorf("expected Decision MASKED, got %s", event.Decision)
	}
	if event.FilterName != "dlp" {
		t.Errorf("expected FilterName dlp, got %s", event.FilterName)
	}
}

func TestPipeline_PostFilterAuditCapture_DLPMaskedResponse(t *testing.T) {
	patterns := []config.DLPPattern{
		{
			Name:   "email",
			Regex:  `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`,
			Action: "mask",
		},
	}
	dlpFilter, err := dlp.NewDLPFilter(true, nil, patterns)
	if err != nil {
		t.Fatalf("failed to create DLP filter: %v", err)
	}

	logger := &mockAuditLogger{}
	p := filter.NewPipeline(logger)
	p.SetFilters([]filter.NamedFilter{dlpFilter})

	sensitiveEmail := "customer-alice@sensitivecorp.example"
	resp := &mcp.Response{
		JSONRPC: "2.0",
		Result:  json.RawMessage(fmt.Sprintf(`{"user":"alice","email":"%s"}`, sensitiveEmail)),
		ID:      1,
	}

	processedResp, mcpErr := p.ProcessResponse(context.Background(), resp)
	if mcpErr != nil {
		t.Fatalf("unexpected mcpErr: %v", mcpErr)
	}

	// 1. Verify returned response is masked
	if strings.Contains(string(processedResp.Result), sensitiveEmail) {
		t.Errorf("processed response still contains unmasked sensitive email")
	}
	if !strings.Contains(string(processedResp.Result), "[REDACTED") {
		t.Errorf("expected [REDACTED] in processed response result")
	}

	// 2. Verify AuditEvent captures strictly POST-FILTER masked payload
	if len(logger.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(logger.events))
	}
	event := logger.events[0]
	if strings.Contains(event.RawPayload, sensitiveEmail) {
		t.Fatalf("CRITICAL LEAK: AuditEvent.RawPayload contains unmasked sensitive email: %s", event.RawPayload)
	}
	if !strings.Contains(event.RawPayload, "[REDACTED") {
		t.Errorf("expected AuditEvent.RawPayload to contain masked [REDACTED], got: %s", event.RawPayload)
	}
	if event.Decision != "MASKED" {
		t.Errorf("expected Decision MASKED, got %s", event.Decision)
	}
}

func TestPipeline_PostFilterAuditCapture_DLPBlockedRequest(t *testing.T) {
	patterns := []config.DLPPattern{
		{
			Name:   "rsa_private_key",
			Regex:  `-----BEGIN (?:RSA|EC|OPENSSH) PRIVATE KEY-----`,
			Action: "block",
		},
	}
	dlpFilter, err := dlp.NewDLPFilter(true, nil, patterns)
	if err != nil {
		t.Fatalf("failed to create DLP filter: %v", err)
	}

	logger := &mockAuditLogger{}
	p := filter.NewPipeline(logger)
	p.SetFilters([]filter.NamedFilter{dlpFilter})

	forbiddenKey := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0..."
	req := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(fmt.Sprintf(`{"name":"upload_key","arguments":{"key":"%s"}}`, forbiddenKey)),
		ID:      2,
	}

	_, mcpErr := p.ProcessRequest(context.Background(), req)
	if mcpErr == nil {
		t.Fatalf("expected DLP violation block error, got nil")
	}

	if len(logger.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(logger.events))
	}
	event := logger.events[0]
	if strings.Contains(event.RawPayload, forbiddenKey) {
		t.Fatalf("CRITICAL LEAK: AuditEvent.RawPayload contains forbidden raw payload: %s", event.RawPayload)
	}
	if !strings.Contains(event.RawPayload, "[REDACTED - Blocked by dlp") {
		t.Errorf("expected AuditEvent.RawPayload to contain explicit redaction note, got: %s", event.RawPayload)
	}
	if event.Decision != "BLOCKED" {
		t.Errorf("expected Decision BLOCKED, got %s", event.Decision)
	}
	if event.FilterName != "dlp" {
		t.Errorf("expected FilterName dlp, got %s", event.FilterName)
	}
}

func TestPipeline_PostFilterAuditCapture_E2E_JSONL_And_DuckDB(t *testing.T) {
	tempDir := t.TempDir()
	jsonlPath := filepath.Join(tempDir, "faradai_audit.jsonl")
	duckdbPath := filepath.Join(tempDir, "audit_test.duckdb")

	fileLogger, err := logger.NewFileAuditLogger(jsonlPath)
	if err != nil {
		t.Fatalf("failed to create FileAuditLogger: %v", err)
	}
	defer fileLogger.Close()

	engine, err := duckdb.New(duckdb.Config{
		DBPath:          duckdbPath,
		RetentionDays:   14,
		MaxPayloadBytes: 64 * 1024,
		BatchFlushMs:    20,
		BufferSize:      100,
	})
	if err != nil {
		t.Fatalf("failed to create DuckDB engine: %v", err)
	}
	defer engine.Close()

	multiLogger := filter.NewMultiAuditLogger(fileLogger, engine)

	patterns := []config.DLPPattern{
		{
			Name:   "credit_card",
			Regex:  `\b(?:\d{4}[ -]?){3}\d{4}\b`,
			Action: "mask",
		},
		{
			Name:   "rsa_private_key",
			Regex:  `-----BEGIN (?:RSA|EC|OPENSSH) PRIVATE KEY-----`,
			Action: "block",
		},
	}
	dlpFilter, err := dlp.NewDLPFilter(true, nil, patterns)
	if err != nil {
		t.Fatalf("failed to create DLP filter: %v", err)
	}

	p := filter.NewPipeline(multiLogger)
	p.SetFilters([]filter.NamedFilter{dlpFilter})

	// 1. Normal allowed request
	reqAllowed := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"ping_tool","arguments":{"ping":"pong"}}`),
		ID:      101,
	}
	_, errAllowed := p.ProcessRequest(context.Background(), reqAllowed)
	if errAllowed != nil {
		t.Fatalf("unexpected error on allowed request: %v", errAllowed)
	}

	// 2. Sensitive request that gets masked
	sensitiveCard := "4111-2222-3333-4444"
	reqMasked := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(fmt.Sprintf(`{"name":"pay_tool","arguments":{"card":"%s"}}`, sensitiveCard)),
		ID:      102,
	}
	_, errMasked := p.ProcessRequest(context.Background(), reqMasked)
	if errMasked != nil {
		t.Fatalf("unexpected error on masked request: %v", errMasked)
	}

	// 3. Sensitive request that gets blocked
	forbiddenSecret := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA..."
	reqBlocked := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(fmt.Sprintf(`{"name":"key_tool","arguments":{"key":"%s"}}`, forbiddenSecret)),
		ID:      103,
	}
	_, errBlocked := p.ProcessRequest(context.Background(), reqBlocked)
	if errBlocked == nil {
		t.Fatalf("expected blocked error, got nil")
	}

	// Flush DuckDB and sync FileAuditLogger
	if err := engine.Flush(context.Background()); err != nil {
		t.Fatalf("failed to flush DuckDB: %v", err)
	}
	if err := fileLogger.Close(); err != nil {
		t.Fatalf("failed to close fileLogger: %v", err)
	}

	// 4. Verify JSONL audit log
	jsonlBytes, err := os.ReadFile(jsonlPath)
	if err != nil {
		t.Fatalf("failed to read JSONL audit log: %v", err)
	}
	jsonlContent := string(jsonlBytes)

	// Zero-DLP Bleed assertion for JSONL
	if strings.Contains(jsonlContent, sensitiveCard) {
		t.Fatalf("CRITICAL ZERO-DLP BLEED: JSONL audit log contains plaintext credit card: %s", sensitiveCard)
	}
	if strings.Contains(jsonlContent, forbiddenSecret) {
		t.Fatalf("CRITICAL ZERO-DLP BLEED: JSONL audit log contains forbidden private key secret: %s", forbiddenSecret)
	}
	if !strings.Contains(jsonlContent, "[REDACTED") {
		t.Errorf("expected JSONL audit log to contain [REDACTED]")
	}
	if !strings.Contains(jsonlContent, "[REDACTED - Blocked by dlp") {
		t.Errorf("expected JSONL audit log to contain blocked redaction note")
	}

	// 5. Verify DuckDB tool_audit_logs
	result, err := engine.QueryAuditLogs(context.Background(), duckdb.QueryFilter{Limit: 10})
	if err != nil {
		t.Fatalf("failed to query DuckDB audit logs: %v", err)
	}
	if result.Total < 3 {
		t.Fatalf("expected at least 3 logs in DuckDB, got %d", result.Total)
	}

	for _, l := range result.Logs {
		if strings.Contains(l.RawPayloadPreview, sensitiveCard) {
			t.Fatalf("CRITICAL ZERO-DLP BLEED: DuckDB tool_audit_logs contains plaintext credit card: %s", sensitiveCard)
		}
		if strings.Contains(l.RawPayloadPreview, forbiddenSecret) {
			t.Fatalf("CRITICAL ZERO-DLP BLEED: DuckDB tool_audit_logs contains forbidden secret: %s", forbiddenSecret)
		}
		if l.ToolName == "pay_tool" {
			if l.Decision != "MASKED" {
				t.Errorf("expected DuckDB pay_tool decision MASKED, got: %s", l.Decision)
			}
			if !strings.Contains(l.RawPayloadPreview, "[REDACTED") {
				t.Errorf("expected DuckDB pay_tool RawPayloadPreview to contain [REDACTED], got: %s", l.RawPayloadPreview)
			}
		}
		if l.ToolName == "key_tool" {
			if l.Decision != "BLOCKED" {
				t.Errorf("expected DuckDB key_tool decision BLOCKED, got: %s", l.Decision)
			}
			if !strings.Contains(l.RawPayloadPreview, "[REDACTED - Blocked by dlp") {
				t.Errorf("expected DuckDB key_tool RawPayloadPreview to contain [REDACTED - Blocked by dlp, got: %s", l.RawPayloadPreview)
			}
		}
	}
}

func TestPipeline_DefaultSensitiveDLP_Integration(t *testing.T) {
	// Configure gateway with DLP enabled and NO explicit patterns -> should fallback to DefaultBaselinePatterns()
	cfg := &config.Config{}
	cfg.Filters.DLP.Enabled = true

	logger := &mockAuditLogger{}
	p, _, err := filter.BuildPipeline(cfg, logger)
	if err != nil {
		t.Fatalf("BuildPipeline failed: %v", err)
	}

	// 1. Tool parameter targeting .env must be blocked
	reqEnv := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"read_file","arguments":{"path":"/var/app/.env.local"}}`),
		ID:      1,
	}
	_, errEnv := p.ProcessRequest(context.Background(), reqEnv)
	if errEnv == nil {
		t.Fatal("expected request for .env.local to be blocked, but was allowed")
	}
	if errEnv.Code != mcp.ErrDLPViolation {
		t.Errorf("expected ErrDLPViolation (-32004), got %d", errEnv.Code)
	}

	// 2. Tool parameter targeting /etc/shadow must be blocked
	reqShadow := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"read_file","arguments":{"path":"/etc/shadow"}}`),
		ID:      2,
	}
	_, errShadow := p.ProcessRequest(context.Background(), reqShadow)
	if errShadow == nil {
		t.Fatal("expected request for /etc/shadow to be blocked, but was allowed")
	}
	if errShadow.Code != mcp.ErrDLPViolation {
		t.Errorf("expected ErrDLPViolation (-32004), got %d", errShadow.Code)
	}

	// 3. Tool parameter containing private key must be blocked
	reqKey := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"ssh_connect","arguments":{"key":"-----BEGIN RSA PRIVATE KEY-----\nMIIE..."}}`),
		ID:      3,
	}
	_, errKey := p.ProcessRequest(context.Background(), reqKey)
	if errKey == nil {
		t.Fatal("expected request with RSA private key to be blocked, but was allowed")
	}
	if errKey.Code != mcp.ErrDLPViolation {
		t.Errorf("expected ErrDLPViolation (-32004), got %d", errKey.Code)
	}

	// 4. Tool response leaking AWS credential must be masked
	rawSecret := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	respAWS := &mcp.Response{
		JSONRPC: "2.0",
		ID:      4,
		Result:  json.RawMessage(fmt.Sprintf(`{"content":"aws_secret_access_key = %s"}`, rawSecret)),
	}
	processedResp, errResp := p.ProcessResponse(context.Background(), respAWS)
	if errResp != nil {
		t.Fatalf("unexpected error processing AWS response: %v", errResp)
	}
	if strings.Contains(string(processedResp.Result), rawSecret) {
		t.Fatalf("AWS secret access key was not masked in response result: %s", string(processedResp.Result))
	}
	if !strings.Contains(string(processedResp.Result), "[REDACTED") {
		t.Errorf("expected [REDACTED] placeholder in response, got: %s", string(processedResp.Result))
	}

	// 5. Verify zero-DLP bleed in audit events
	for _, evt := range logger.events {
		if strings.Contains(evt.RawPayload, rawSecret) {
			t.Fatalf("CRITICAL LEAK: Audit event contains raw AWS secret: %s", evt.RawPayload)
		}
	}
}

func TestPipeline_FastPath_DLPResponseRedaction(t *testing.T) {
	dlpFilter, err := dlp.NewDLPFilter(true, nil, dlp.DefaultBaselinePatterns())
	if err != nil {
		t.Fatalf("Failed to instantiate DLPFilter: %v", err)
	}

	injMock := &mockFilter{name: "injection_scanner"}
	hitlMock := &mockFilter{name: "hitl"}
	prefillMock := &mockFilter{name: "prefill_block"}

	pipeline := filter.NewPipeline(nil)
	pipeline.SetFilters([]filter.NamedFilter{prefillMock, injMock, dlpFilter, hitlMock})

	// Configure Adaptive Router: get_* and read_* are Fast-Path, delete_* is Deep-Path
	router := adaptive.NewRouter(true, "deep", []string{"get_*", "read_*", "fetch_*"}, []string{"delete_*", "write_*"})
	pipeline.SetAdaptiveRouter(router)

	// 1. Fast-Path tool invocation: response containing sensitive AWS credential
	ctxFast := context.WithValue(context.Background(), filter.ToolNameContextKey, "read_file")
	rawSecret := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	respAWS := &mcp.Response{
		JSONRPC: "2.0",
		ID:      1,
		Result:  json.RawMessage(fmt.Sprintf(`{"content":"aws_secret_access_key = %s"}`, rawSecret)),
	}

	processedResp, errResp := pipeline.ProcessResponse(ctxFast, respAWS)
	if errResp != nil {
		t.Fatalf("Unexpected error processing fast-path response: %v", errResp)
	}
	if strings.Contains(string(processedResp.Result), rawSecret) {
		t.Fatalf("Expected sensitive AWS secret to be redacted in fast-path response, but found: %s", string(processedResp.Result))
	}
	if !strings.Contains(string(processedResp.Result), "[REDACTED") {
		t.Errorf("Expected [REDACTED] in sanitized fast-path response, got: %s", string(processedResp.Result))
	}

	// Verify heavy SLM and HITL filters remain strictly bypassed on Fast-Path
	if atomic.LoadInt32(&injMock.execCount) != 0 {
		t.Errorf("Expected injection_scanner to remain bypassed on Fast-Path, got %d calls", injMock.execCount)
	}
	if atomic.LoadInt32(&hitlMock.execCount) != 0 {
		t.Errorf("Expected hitl to remain bypassed on Fast-Path, got %d calls", hitlMock.execCount)
	}

	// 2. Fast-Path tool invocation: response containing blocked private key
	respKey := &mcp.Response{
		JSONRPC: "2.0",
		ID:      2,
		Result:  json.RawMessage(`{"content":"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0tG..."}`),
	}
	_, errKey := pipeline.ProcessResponse(ctxFast, respKey)
	if errKey == nil {
		t.Fatalf("Expected fast-path response with private key to be blocked with DLP violation")
	}
	if errKey.Code != mcp.ErrDLPViolation {
		t.Errorf("Expected ErrDLPViolation (-32004), got %d", errKey.Code)
	}

	// 3. Deep-Path tool invocation: verify heavy filters DO execute on Deep-Path
	ctxDeep := context.WithValue(context.Background(), filter.ToolNameContextKey, "write_file")
	respDeep := &mcp.Response{
		JSONRPC: "2.0",
		ID:      3,
		Result:  json.RawMessage(`{"status":"ok"}`),
	}
	_, errDeep := pipeline.ProcessResponse(ctxDeep, respDeep)
	if errDeep != nil {
		t.Fatalf("Unexpected error in deep-path response: %v", errDeep)
	}
	if atomic.LoadInt32(&injMock.execCount) != 1 {
		t.Errorf("Expected injection_scanner to execute on Deep-Path, got %d", injMock.execCount)
	}
	if atomic.LoadInt32(&hitlMock.execCount) != 1 {
		t.Errorf("Expected hitl to execute on Deep-Path, got %d", hitlMock.execCount)
	}
}

func TestPipeline_FastPath_ExecutionLatencyBudget(t *testing.T) {
	dlpFilter, err := dlp.NewDLPFilter(true, nil, dlp.DefaultBaselinePatterns())
	if err != nil {
		t.Fatalf("Failed to instantiate DLPFilter: %v", err)
	}

	prefillMock := &mockFilter{name: "prefill_block"}
	schemaMock := &mockFilter{name: "schema_validation"}
	injMock := &mockFilter{name: "injection_scanner"}

	pipeline := filter.NewPipeline(nil)
	pipeline.SetFilters([]filter.NamedFilter{prefillMock, schemaMock, injMock, dlpFilter})

	router := adaptive.NewRouter(true, "deep", []string{"get_*", "read_*"}, nil)
	pipeline.SetAdaptiveRouter(router)

	req := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"get_user","arguments":{"id":"user_42"}}`),
		ID:      1,
	}
	resp := &mcp.Response{
		JSONRPC: "2.0",
		ID:      1,
		Result:  json.RawMessage(`{"status":"success","data":{"username":"alice","role":"engineer"}}`),
	}
	ctx := context.WithValue(context.Background(), filter.ToolNameContextKey, "get_user")

	// Warm up
	for i := 0; i < 50; i++ {
		_, _ = pipeline.ProcessRequest(ctx, req)
		_, _ = pipeline.ProcessResponse(ctx, resp)
	}

	iterations := 1000
	start := time.Now()
	for i := 0; i < iterations; i++ {
		_, errReq := pipeline.ProcessRequest(ctx, req)
		if errReq != nil {
			t.Fatalf("Unexpected ProcessRequest error: %v", errReq)
		}
		_, errResp := pipeline.ProcessResponse(ctx, resp)
		if errResp != nil {
			t.Fatalf("Unexpected ProcessResponse error: %v", errResp)
		}
	}
	totalElapsed := time.Since(start)
	avgPerCall := totalElapsed / time.Duration(iterations)

	// SPEC-SEC-003 and SEC-017 SLA budget: fast-path latency < 0.25 ms (250 µs)
	slaLimit := 250 * time.Microsecond
	if avgPerCall > slaLimit {
		t.Errorf("Fast-path average latency %v exceeded SLA budget of %v", avgPerCall, slaLimit)
	}
}

func BenchmarkPipeline_FastPathWithDLP_Latency(b *testing.B) {
	dlpFilter, err := dlp.NewDLPFilter(true, nil, dlp.DefaultBaselinePatterns())
	if err != nil {
		b.Fatalf("Failed to instantiate DLPFilter: %v", err)
	}

	prefillMock := &mockFilter{name: "prefill_block"}
	schemaMock := &mockFilter{name: "schema_validation"}
	injMock := &mockFilter{name: "injection_scanner"}

	pipeline := filter.NewPipeline(nil)
	pipeline.SetFilters([]filter.NamedFilter{prefillMock, schemaMock, injMock, dlpFilter})

	router := adaptive.NewRouter(true, "deep", []string{"get_*", "read_*"}, nil)
	pipeline.SetAdaptiveRouter(router)

	req := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"get_user","arguments":{"id":"user_42"}}`),
		ID:      1,
	}
	resp := &mcp.Response{
		JSONRPC: "2.0",
		ID:      1,
		Result:  json.RawMessage(`{"status":"success","data":{"username":"alice","role":"engineer"}}`),
	}
	ctx := context.WithValue(context.Background(), filter.ToolNameContextKey, "get_user")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = pipeline.ProcessRequest(ctx, req)
		_, _ = pipeline.ProcessResponse(ctx, resp)
	}
}

func TestPipeline_ActionAudit_Telemetry(t *testing.T) {
	patterns := []config.DLPPattern{
		{Name: "tckn", Regex: `\b[1-9][0-9]{10}\b`, Action: "audit"},
	}
	dlpFilter, err := dlp.NewDLPFilter(true, nil, patterns)
	if err != nil {
		t.Fatalf("failed to create DLP filter: %v", err)
	}

	logger := &mockAuditLogger{}
	p := filter.NewPipeline(logger)
	p.SetFilters([]filter.NamedFilter{dlpFilter})

	req := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"citizen_id": "12345678901"}`),
	}

	filteredReq, mcpErr := p.ProcessRequest(context.Background(), req)
	if mcpErr != nil {
		t.Fatalf("unexpected mcpErr: %v", mcpErr)
	}

	// Payload must NOT be altered
	if string(filteredReq.Params) != `{"citizen_id": "12345678901"}` {
		t.Fatalf("payload should remain untouched in audit mode, got: %s", string(filteredReq.Params))
	}

	// Verify AuditEvent emitted with decision = AUDIT and audited_rules
	if len(logger.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(logger.events))
	}
	event := logger.events[0]
	if event.Decision != "AUDIT" {
		t.Errorf("expected Decision AUDIT, got %s", event.Decision)
	}
	if len(event.AuditedRules) != 1 || event.AuditedRules[0] != "tckn" {
		t.Errorf("expected AuditedRules ['tckn'], got %v", event.AuditedRules)
	}
}

func TestPipeline_DebugRetainUnmaskedDiff(t *testing.T) {
	patterns := []config.DLPPattern{
		{Name: "email", Regex: `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`, Action: "mask"},
	}
	dlpFilter, err := dlp.NewDLPFilter(true, nil, patterns)
	if err != nil {
		t.Fatalf("failed to create DLP filter: %v", err)
	}

	t.Run("RetainUnmaskedDiff_Disabled", func(t *testing.T) {
		logger := &mockAuditLogger{}
		p := filter.NewPipeline(logger)
		p.SetDebugRetainUnmaskedDiff(false)
		p.SetFilters([]filter.NamedFilter{dlpFilter})

		resp := &mcp.Response{
			JSONRPC: "2.0",
			Result:  json.RawMessage(`{"email":"alice@secret.com"}`),
			ID:      1,
		}

		_, mcpErr := p.ProcessResponse(context.Background(), resp)
		if mcpErr != nil {
			t.Fatalf("unexpected error: %v", mcpErr)
		}

		if len(logger.events) != 1 {
			t.Fatalf("expected 1 audit event, got %d", len(logger.events))
		}
		event := logger.events[0]
		if event.OriginalPayload != "" {
			t.Errorf("expected empty OriginalPayload when retain diff disabled, got: %s", event.OriginalPayload)
		}
		if event.RawPayload != `{"email":"[REDACTED:EMAIL]"}` {
			t.Errorf("expected masked RawPayload, got: %s", event.RawPayload)
		}
	})

	t.Run("RetainUnmaskedDiff_Enabled", func(t *testing.T) {
		logger := &mockAuditLogger{}
		p := filter.NewPipeline(logger)
		p.SetDebugRetainUnmaskedDiff(true)
		p.SetFilters([]filter.NamedFilter{dlpFilter})

		resp := &mcp.Response{
			JSONRPC: "2.0",
			Result:  json.RawMessage(`{"email":"alice@secret.com"}`),
			ID:      1,
		}

		_, mcpErr := p.ProcessResponse(context.Background(), resp)
		if mcpErr != nil {
			t.Fatalf("unexpected error: %v", mcpErr)
		}

		if len(logger.events) != 1 {
			t.Fatalf("expected 1 audit event, got %d", len(logger.events))
		}
		event := logger.events[0]
		if event.OriginalPayload != `{"email":"alice@secret.com"}` {
			t.Errorf("expected unmasked OriginalPayload, got: %s", event.OriginalPayload)
		}
		if event.RawPayload != `{"email":"[REDACTED:EMAIL]"}` {
			t.Errorf("expected masked RawPayload, got: %s", event.RawPayload)
		}
	})
}

type mockNilReturningFilter struct {
	filter.BaseSecurityFilter
}

func (m *mockNilReturningFilter) Name() string { return "nil_returning" }
func (m *mockNilReturningFilter) Order() int   { return 10 }
func (m *mockNilReturningFilter) ExecuteResponse(ctx context.Context, resp *mcp.Response) (*mcp.Response, error) {
	return nil, nil // idiomatic pass-through
}

type mockSecondPassFilter struct {
	filter.BaseSecurityFilter
	called bool
}

func (m *mockSecondPassFilter) Name() string { return "second_pass" }
func (m *mockSecondPassFilter) Order() int   { return 20 }
func (m *mockSecondPassFilter) ExecuteResponse(ctx context.Context, resp *mcp.Response) (*mcp.Response, error) {
	m.called = true
	return resp, nil
}

func TestPipeline_ProcessResponse_NilSafeExecution(t *testing.T) {
	p := filter.NewPipeline(nil)
	nilFilter := &mockNilReturningFilter{}
	secondFilter := &mockSecondPassFilter{}

	p.SetFilters([]filter.NamedFilter{nilFilter, secondFilter})

	resp := &mcp.Response{
		JSONRPC: "2.0",
		Result:  json.RawMessage(`{"status":"ok"}`),
		ID:      1,
	}

	finalResp, mcpErr := p.ProcessResponse(context.Background(), resp)
	if mcpErr != nil {
		t.Fatalf("unexpected mcpErr: %v", mcpErr)
	}
	if finalResp == nil {
		t.Fatal("expected finalResp to not be nil")
	}
	if !secondFilter.called {
		t.Error("expected second filter to be called despite first filter returning nil, nil")
	}
}

type mockCloserFilter struct {
	filter.BaseSecurityFilter
	closed bool
}

func (m *mockCloserFilter) Name() string { return "closer_filter" }
func (m *mockCloserFilter) Order() int   { return 10 }
func (m *mockCloserFilter) Close() error {
	m.closed = true
	return nil
}

func TestPipeline_Swap_ClosesDisplacedFilters(t *testing.T) {
	p := filter.NewPipeline(nil)
	closerFilter := &mockCloserFilter{}
	p.SetFilters([]filter.NamedFilter{closerFilter})

	if closerFilter.closed {
		t.Fatal("filter should not be closed initially")
	}

	// Swap with an empty filter list
	p.Swap([]filter.NamedFilter{}, nil)

	if !closerFilter.closed {
		t.Fatal("expected displaced filter to be closed on Swap")
	}
}

type mockSlowFilter struct {
	filter.BaseSecurityFilter
	started chan struct{}
	release chan struct{}
}

func (m *mockSlowFilter) Name() string { return "slow_filter" }
func (m *mockSlowFilter) Order() int   { return 10 }
func (m *mockSlowFilter) ExecuteRequest(ctx context.Context, req *mcp.Request) (*mcp.Response, error) {
	close(m.started)
	<-m.release
	return nil, nil
}

func TestPipeline_LockFreeSnapshot_NonBlockingSwap(t *testing.T) {
	p := filter.NewPipeline(nil)
	slowFilter := &mockSlowFilter{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	p.RegisterFilter(slowFilter)

	req := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"test_tool"}`),
		ID:      1,
	}

	done := make(chan struct{})
	go func() {
		_, _ = p.ProcessRequest(context.Background(), req)
		close(done)
	}()

	// Wait until filter execution starts inside ProcessRequest
	<-slowFilter.started

	// Concurrently attempt Swap - must NOT block while slowFilter is executing
	swapDone := make(chan struct{})
	go func() {
		p.Swap([]filter.NamedFilter{}, nil)
		close(swapDone)
	}()

	select {
	case <-swapDone:
		// Success! Swap completed while request was in-flight inside filter
	case <-time.After(200 * time.Millisecond):
		t.Fatal("DEADLOCK/STARVATION: Pipeline.Swap blocked waiting for in-flight filter to release lock")
	}

	// Release slow filter to allow goroutine to finish cleanly
	close(slowFilter.release)
	<-done
}




