package schema_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/filter/schema"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
)

const sampleSchema = `{
  "type": "object",
  "properties": {
    "query": {"type": "string"},
    "limit": {"type": "integer", "minimum": 1}
  },
  "required": ["query"]
}`

const sampleSchemaV2 = `{
  "type": "object",
  "properties": {
    "query": {"type": "string"},
    "limit": {"type": "integer", "minimum": 1},
    "filter": {"type": "string"}
  },
  "required": ["query", "filter"]
}`

func TestSchemaFilter_FilterRequest_Validation(t *testing.T) {
	tmpDir := t.TempDir()
	f := schema.NewSchemaFilter(true, tmpDir, true, true)
	defer f.Close()

	// Register tool via FilterResponse
	listResp := &mcp.Response{
		JSONRPC: "2.0",
		ID:      1,
		Result: json.RawMessage(fmt.Sprintf(`{
			"tools": [
				{
					"name": "search_docs",
					"description": "Search documentation",
					"inputSchema": %s
				}
			]
		}`, sampleSchema)),
	}
	_, mErr := f.FilterResponse(context.Background(), listResp)
	if mErr != nil {
		t.Fatalf("unexpected FilterResponse error: %v", mErr)
	}

	ctx := context.Background()

	// Case 1: Valid params
	reqValid := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name": "search_docs", "arguments": {"query": "auth", "limit": 10}}`),
		ID:      1,
	}
	outReq, err := f.FilterRequest(ctx, reqValid)
	if err != nil {
		t.Fatalf("expected valid params to pass, got error: %v", err)
	}
	if outReq != reqValid {
		t.Errorf("expected original request returned")
	}

	// Case 2: Invalid params (missing required 'query')
	reqInvalid := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name": "search_docs", "arguments": {"limit": 5}}`),
		ID:      2,
	}
	_, err = f.FilterRequest(ctx, reqInvalid)
	if err == nil {
		t.Fatal("expected error for missing required parameter, got nil")
	}
	if err.Code != mcp.ErrSchemaValidation {
		t.Errorf("expected ErrSchemaValidation (%d), got %d", mcp.ErrSchemaValidation, err.Code)
	}

	// Case 3: Invalid param types (limit is string instead of int)
	reqTypeMismatch := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name": "search_docs", "arguments": {"query": "test", "limit": "invalid"}}`),
		ID:      3,
	}
	_, err = f.FilterRequest(ctx, reqTypeMismatch)
	if err == nil {
		t.Fatal("expected type mismatch error, got nil")
	}

	// Case 4: Unknown tool should pass with warning
	reqUnknown := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name": "unknown_tool", "arguments": {"any": "arg"}}`),
		ID:      4,
	}
	outUnknown, err := f.FilterRequest(ctx, reqUnknown)
	if err != nil {
		t.Errorf("expected unknown tool to bypass validation, got: %v", err)
	}
	if outUnknown == nil {
		t.Errorf("expected non-nil request")
	}

	// Case 5: Non-tools/call method
	reqNonTool := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/list",
		ID:      5,
	}
	outNonTool, err := f.FilterRequest(ctx, reqNonTool)
	if err != nil || outNonTool != reqNonTool {
		t.Errorf("expected non-tool request to pass unmodified")
	}
}

func TestSchemaFilter_FilterResponse_AsynchronousPersistence(t *testing.T) {
	tmpDir := t.TempDir()
	f := schema.NewSchemaFilter(true, tmpDir, true, true)
	defer f.Close()

	listResp := &mcp.Response{
		JSONRPC: "2.0",
		ID:      1,
		Result: json.RawMessage(fmt.Sprintf(`{
			"tools": [
				{
					"name": "tool_alpha",
					"description": "Alpha tool",
					"inputSchema": %s
				},
				{
					"name": "tool_beta",
					"description": "Beta tool",
					"inputSchema": {"type": "object", "properties": {"count": {"type": "number"}}}
				}
			]
		}`, sampleSchema)),
	}

	start := time.Now()
	_, mErr := f.FilterResponse(context.Background(), listResp)
	duration := time.Since(start)

	if mErr != nil {
		t.Fatalf("unexpected FilterResponse error: %v", mErr)
	}
	// FilterResponse should return in microseconds without waiting for disk I/O
	if duration > 10*time.Millisecond {
		t.Errorf("FilterResponse took too long (%v), expected non-blocking execution", duration)
	}

	// Flush write-behind queue to ensure all disk writes complete
	f.Flush()

	// 1. Verify individual schema files exist
	alphaFile := filepath.Join(tmpDir, "tool_alpha.json")
	if data, err := os.ReadFile(alphaFile); err != nil {
		t.Errorf("expected %s to exist: %v", alphaFile, err)
	} else if len(data) == 0 {
		t.Errorf("expected non-empty content in %s", alphaFile)
	}

	betaFile := filepath.Join(tmpDir, "tool_beta.json")
	if data, err := os.ReadFile(betaFile); err != nil {
		t.Errorf("expected %s to exist: %v", betaFile, err)
	} else if len(data) == 0 {
		t.Errorf("expected non-empty content in %s", betaFile)
	}

	// 2. Verify mcp_tools.json exists
	mcpToolsFile := filepath.Join(tmpDir, "mcp_tools.json")
	data, err := os.ReadFile(mcpToolsFile)
	if err != nil {
		t.Fatalf("expected mcp_tools.json to exist: %v", err)
	}
	var tools []map[string]interface{}
	if err := json.Unmarshal(data, &tools); err != nil {
		t.Fatalf("failed to parse mcp_tools.json: %v", err)
	}
	if len(tools) != 2 {
		t.Errorf("expected 2 tools in mcp_tools.json, got %d", len(tools))
	}

	// 3. Verify LoadSchemasFromDisk can reload them without panics or errors
	f2 := schema.NewSchemaFilter(true, tmpDir, true, true)
	defer f2.Close()

	reqAlpha := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name": "tool_alpha", "arguments": {"query": "reloaded"}}`),
		ID:      10,
	}
	if _, err := f2.FilterRequest(context.Background(), reqAlpha); err != nil {
		t.Errorf("expected reloaded schema to validate request, got: %v", err)
	}
}

func TestSchemaFilter_BaselineDriftDetection(t *testing.T) {
	tmpDir := t.TempDir()
	f := schema.NewSchemaFilter(true, tmpDir, true, true)
	defer f.Close()

	// 1. Send v1 schema
	respV1 := &mcp.Response{
		JSONRPC: "2.0",
		ID:      1,
		Result: json.RawMessage(fmt.Sprintf(`{
			"tools": [
				{"name": "drift_tool", "inputSchema": %s}
			]
		}`, sampleSchema)),
	}
	_, _ = f.FilterResponse(context.Background(), respV1)
	f.Flush()

	// Initial request with only 'query' is valid under v1
	req := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name": "drift_tool", "arguments": {"query": "version1"}}`),
		ID:      2,
	}
	if _, err := f.FilterRequest(context.Background(), req); err != nil {
		t.Fatalf("expected v1 request to pass, got: %v", err)
	}

	// 2. Send v2 schema (drift detected: requires 'filter' as well)
	respV2 := &mcp.Response{
		JSONRPC: "2.0",
		ID:      3,
		Result: json.RawMessage(fmt.Sprintf(`{
			"tools": [
				{"name": "drift_tool", "inputSchema": %s}
			]
		}`, sampleSchemaV2)),
	}
	_, _ = f.FilterResponse(context.Background(), respV2)
	f.Flush()

	// Under v2, request without 'filter' must now fail
	if _, err := f.FilterRequest(context.Background(), req); err == nil {
		t.Fatal("expected request without 'filter' to fail under v2 schema, got nil")
	}

	// Request with both 'query' and 'filter' must succeed
	reqV2 := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name": "drift_tool", "arguments": {"query": "v2", "filter": "active"}}`),
		ID:      4,
	}
	if _, err := f.FilterRequest(context.Background(), reqV2); err != nil {
		t.Fatalf("expected v2 request to pass, got: %v", err)
	}

	// 3. Verify disk file updated with v2
	schemaPath := filepath.Join(tmpDir, "drift_tool.json")
	content, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("failed to read updated schema: %v", err)
	}
	if !json.Valid(content) {
		t.Errorf("expected valid JSON schema on disk")
	}
}

func TestSchemaFilter_ClearBaselines(t *testing.T) {
	tmpDir := t.TempDir()
	f := schema.NewSchemaFilter(true, tmpDir, true, true)
	defer f.Close()

	resp := &mcp.Response{
		JSONRPC: "2.0",
		ID:      1,
		Result: json.RawMessage(fmt.Sprintf(`{
			"tools": [
				{"name": "temp_tool", "inputSchema": %s}
			]
		}`, sampleSchema)),
	}
	_, _ = f.FilterResponse(context.Background(), resp)
	f.Flush()

	schemaPath := filepath.Join(tmpDir, "temp_tool.json")
	if _, err := os.Stat(schemaPath); err != nil {
		t.Fatalf("expected schema file before clear: %v", err)
	}

	f.ClearBaselines()

	if _, err := os.Stat(schemaPath); !os.IsNotExist(err) {
		t.Errorf("expected schema file to be removed after ClearBaselines")
	}
}

func TestSchemaFilter_Concurrent_FilterRequest_During_Persistence(t *testing.T) {
	tmpDir := t.TempDir()
	f := schema.NewSchemaFilter(true, tmpDir, true, true)
	defer f.Close()

	// Pre-load tool schema
	initResp := &mcp.Response{
		JSONRPC: "2.0",
		ID:      1,
		Result: json.RawMessage(fmt.Sprintf(`{
			"tools": [
				{"name": "target_tool", "inputSchema": %s}
			]
		}`, sampleSchema)),
	}
	_, _ = f.FilterResponse(context.Background(), initResp)
	f.Flush()

	const workers = 50
	const requestsPerWorker = 200
	var totalRequests int64
	var maxLatencyNanos int64
	var totalLatencyNanos int64

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup

	// Background worker that continuously generates disk persistence load via FilterResponse
	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		counter := 0
		for {
			select {
			case <-ctx.Done():
				return
			default:
				counter++
				resp := &mcp.Response{
					JSONRPC: "2.0",
					ID:      counter,
					Result: json.RawMessage(fmt.Sprintf(`{
						"tools": [
							{"name": "bg_tool_%d", "inputSchema": %s}
						]
					}`, counter%20, sampleSchema)),
				}
				_, _ = f.FilterResponse(context.Background(), resp)
				time.Sleep(500 * time.Microsecond)
			}
		}
	}()

	// 50 concurrent validation workers
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < requestsPerWorker; i++ {
				req := &mcp.Request{
					JSONRPC: "2.0",
					Method:  "tools/call",
					Params:  json.RawMessage(`{"name": "target_tool", "arguments": {"query": "latency_test", "limit": 5}}`),
					ID:      fmt.Sprintf("w-%d-%d", workerID, i),
				}

				start := time.Now()
				out, err := f.FilterRequest(context.Background(), req)
				duration := time.Since(start)

				if err != nil || out == nil {
					t.Errorf("worker %d req %d failed: %v", workerID, i, err)
					return
				}

				nanos := duration.Nanoseconds()
				atomic.AddInt64(&totalRequests, 1)
				atomic.AddInt64(&totalLatencyNanos, nanos)

				for {
					currentMax := atomic.LoadInt64(&maxLatencyNanos)
					if nanos <= currentMax || atomic.CompareAndSwapInt64(&maxLatencyNanos, currentMax, nanos) {
						break
					}
				}
			}
		}(w)
	}

	wg.Wait()
	cancel()
	<-writeDone
	f.Flush()

	completed := atomic.LoadInt64(&totalRequests)
	avgLatency := time.Duration(atomic.LoadInt64(&totalLatencyNanos) / completed)
	maxLatency := time.Duration(atomic.LoadInt64(&maxLatencyNanos))

	t.Logf("Concurrent FilterRequest results under active disk write load:")
	t.Logf("  Total completed requests: %d", completed)
	t.Logf("  Average latency: %v", avgLatency)
	t.Logf("  Max latency: %v", maxLatency)

	// SLA Requirement: Parameter validation must resolve quickly (< 5ms average under race detector)
	if avgLatency > 5*time.Millisecond {
		t.Errorf("expected average latency < 5ms, got %v", avgLatency)
	}
}

func BenchmarkSchemaFilter_FilterRequest(b *testing.B) {
	tmpDir := b.TempDir()
	f := schema.NewSchemaFilter(true, tmpDir, true, true)
	defer f.Close()

	listResp := &mcp.Response{
		JSONRPC: "2.0",
		ID:      1,
		Result: json.RawMessage(fmt.Sprintf(`{
			"tools": [
				{"name": "bench_tool", "inputSchema": %s}
			]
		}`, sampleSchema)),
	}
	_, _ = f.FilterResponse(context.Background(), listResp)
	f.Flush()

	req := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name": "bench_tool", "arguments": {"query": "benchmark", "limit": 10}}`),
		ID:      1,
	}

	ctx := context.Background()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			out, err := f.FilterRequest(ctx, req)
			if err != nil || out == nil {
				b.Fatalf("FilterRequest error: %v", err)
			}
		}
	})
}

func BenchmarkSchemaFilter_FilterRequest_UnderWriteLoad(b *testing.B) {
	tmpDir := b.TempDir()
	f := schema.NewSchemaFilter(true, tmpDir, true, true)
	defer f.Close()

	listResp := &mcp.Response{
		JSONRPC: "2.0",
		ID:      1,
		Result: json.RawMessage(fmt.Sprintf(`{
			"tools": [
				{"name": "bench_tool", "inputSchema": %s}
			]
		}`, sampleSchema)),
	}
	_, _ = f.FilterResponse(context.Background(), listResp)
	f.Flush()

	stopWrite := make(chan struct{})
	go func() {
		counter := 0
		for {
			select {
			case <-stopWrite:
				return
			default:
				counter++
				resp := &mcp.Response{
					JSONRPC: "2.0",
					ID:      counter,
					Result: json.RawMessage(fmt.Sprintf(`{
						"tools": [
							{"name": "tool_dyn_%d", "inputSchema": %s}
						]
					}`, counter%30, sampleSchema)),
				}
				_, _ = f.FilterResponse(context.Background(), resp)
				time.Sleep(200 * time.Microsecond)
			}
		}
	}()
	defer close(stopWrite)

	req := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name": "bench_tool", "arguments": {"query": "benchmark", "limit": 10}}`),
		ID:      1,
	}

	ctx := context.Background()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			out, err := f.FilterRequest(ctx, req)
			if err != nil || out == nil {
				b.Fatalf("FilterRequest error: %v", err)
			}
		}
	})
}

func TestSchemaFilter_ConcurrentFlush_DuringAndAfterShutdown(t *testing.T) {
	tmpDir := t.TempDir()
	f := schema.NewSchemaFilter(true, tmpDir, true, true)

	// Send dynamic schemas to generate pending write tasks
	for i := 0; i < 50; i++ {
		resp := &mcp.Response{
			JSONRPC: "2.0",
			ID:      i,
			Result: json.RawMessage(fmt.Sprintf(`{
				"tools": [
					{"name": "tool_%d", "inputSchema": {"type": "object"}}
				]
			}`, i)),
		}
		_, _ = f.FilterResponse(context.Background(), resp)
	}

	const concurrentFlushes = 50
	var wg sync.WaitGroup

	// Launch concurrent flushes while Close is being called
	for i := 0; i < concurrentFlushes; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = f.Flush(ctx)
		}(i)
	}

	// Trigger Close concurrently with flushes
	time.Sleep(5 * time.Millisecond)
	if err := f.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	// Launch more concurrent flushes AFTER Close has completed
	for i := 0; i < concurrentFlushes; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = f.Flush(ctx)
		}(i)
	}

	// Wait with timeout to detect any deadlock
	doneCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneCh)
	}()

	select {
	case <-doneCh:
		// Succeeded with zero deadlocks
	case <-time.After(5 * time.Second):
		t.Fatal("DEADLOCK: Concurrent Flush during/after shutdown hung")
	}
}

func TestSchemaFilter_Flush_ContextCancellation(t *testing.T) {
	tmpDir := t.TempDir()
	f := schema.NewSchemaFilter(true, tmpDir, true, true)
	defer f.Close()

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	err := f.Flush(canceledCtx)
	if err != context.Canceled {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestSchemaFilter_CaseInsensitiveToolLookup(t *testing.T) {
	tmpDir := t.TempDir()
	f := schema.NewSchemaFilter(true, tmpDir, true, true)
	defer f.Close()

	listResp := &mcp.Response{
		JSONRPC: "2.0",
		ID:      1,
		Result: json.RawMessage(fmt.Sprintf(`{
			"tools": [
				{
					"name": "search_docs",
					"description": "Search documentation",
					"inputSchema": %s
				}
			]
		}`, sampleSchema)),
	}
	if _, mErr := f.FilterResponse(context.Background(), listResp); mErr != nil {
		t.Fatalf("unexpected FilterResponse error: %v", mErr)
	}

	ctx := context.Background()
	reqValid := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name": "SEARCH_DOCS", "arguments": {"query": "auth", "limit": 5}}`),
		ID:      10,
	}
	if _, err := f.FilterRequest(ctx, reqValid); err != nil {
		t.Fatalf("expected uppercase tool name with valid args to pass, got %v", err)
	}

	reqInvalid := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name": "Search_Docs", "arguments": {"limit": 5}}`),
		ID:      11,
	}
	_, err := f.FilterRequest(ctx, reqInvalid)
	if err == nil || err.Code != mcp.ErrSchemaValidation {
		t.Fatalf("expected ErrSchemaValidation for mixed-case tool missing required param, got %+v", err)
	}
}
