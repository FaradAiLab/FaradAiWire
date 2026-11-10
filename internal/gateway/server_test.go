package gateway_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/admin"
	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/auth"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/dlp"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/limit"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/schema"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/types"
	"github.com/FaradAiLab/FaradAiWire/internal/gateway"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
	"github.com/FaradAiLab/FaradAiWire/internal/proxy"
	"github.com/FaradAiLab/FaradAiWire/internal/session"
	"github.com/FaradAiLab/FaradAiWire/internal/telemetry/duckdb"
)

type mockConfigProvider struct {
	mu  sync.RWMutex
	cfg *config.Config
}

func (m *mockConfigProvider) Load() (*config.Config, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg, nil
}

func (m *mockConfigProvider) setConfig(cfg *config.Config) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg = cfg
}

func (m *mockConfigProvider) Watch(onChange func(*config.Config)) error {
	return nil
}

func TestNewServer_NilConfig(t *testing.T) {
	_, err := gateway.NewServer(nil, nil)
	if err == nil {
		t.Fatal("expected error when passing nil config, got nil")
	}
}

func TestServer_Lifecycle_StdioMode(t *testing.T) {
	cfg := &config.Config{
		Mode: "stdio",
		Stdio: config.StdioConfig{
			Command:     "cat",
			AutoRestart: false,
		},
		Telemetry: config.TelemetryConfig{
			DBPath: filepath.Join(t.TempDir(), "wire.duckdb"),
		},
	}

	provider := &mockConfigProvider{cfg: cfg}
	srv, err := gateway.NewServer(cfg, provider)
	if err != nil {
		t.Fatalf("failed to create gateway server: %v", err)
	}

	if srv.Pipeline() == nil {
		t.Fatal("expected non-nil pipeline")
	}
	if srv.Router() == nil {
		t.Fatal("expected non-nil adaptive router")
	}
	if srv.IsDraining() {
		t.Fatal("server should not be draining initially")
	}

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(ctx)
	}()

	// Allow server to boot
	time.Sleep(50 * time.Millisecond)

	// Trigger graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()

	cancel() // signal context cancel
	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}

	if !srv.IsDraining() {
		t.Error("expected server to be in draining state after shutdown")
	}

	select {
	case err := <-errCh:
		if err != nil && err != context.Canceled {
			t.Errorf("unexpected server exit error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server Start did not exit after shutdown")
	}
}

func TestServer_AtomicReload(t *testing.T) {
	initialCfg := &config.Config{
		Mode: "stdio",
		Stdio: config.StdioConfig{
			Command: "cat",
		},
		Filters: config.FiltersConfig{
			PrefillBlock: config.PrefillBlockConfig{
				Enabled: false,
			},
		},
	}

	updatedCfg := &config.Config{
		Mode: "stdio",
		Stdio: config.StdioConfig{
			Command: "cat",
		},
		Filters: config.FiltersConfig{
			PrefillBlock: config.PrefillBlockConfig{
				Enabled: true,
			},
		},
	}

	provider := &mockConfigProvider{cfg: initialCfg}
	srv, err := gateway.NewServer(initialCfg, provider)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	if len(srv.Pipeline().GetFilters()) != 0 {
		t.Fatalf("expected 0 filters initially, got %d", len(srv.Pipeline().GetFilters()))
	}

	// Update provider config and trigger reload
	provider.setConfig(updatedCfg)
	if err := srv.Reload(); err != nil {
		t.Fatalf("reload failed: %v", err)
	}

	if len(srv.Pipeline().GetFilters()) != 1 {
		t.Fatalf("expected 1 filter after reload, got %d", len(srv.Pipeline().GetFilters()))
	}
	if srv.Pipeline().GetFilters()[0].Name() != "prefill_block" {
		t.Errorf("expected 'prefill_block' filter, got '%s'", srv.Pipeline().GetFilters()[0].Name())
	}
}

func TestServer_Reload_InvalidConfigPreservesState(t *testing.T) {
	initialCfg := &config.Config{
		Mode: "stdio",
		Stdio: config.StdioConfig{
			Command: "cat",
		},
		Filters: config.FiltersConfig{
			PrefillBlock: config.PrefillBlockConfig{
				Enabled: true,
			},
		},
	}

	// Invalid config: malformed regex in DLP filter causes pipeline build to fail
	invalidCfg := &config.Config{
		Mode: "stdio",
		Filters: config.FiltersConfig{
			DLP: config.DLPConfig{
				Enabled: true,
				Patterns: []config.DLPPattern{
					{Name: "bad_regex", Regex: "[a-z"},
				},
			},
		},
	}

	provider := &mockConfigProvider{cfg: initialCfg}
	srv, err := gateway.NewServer(initialCfg, provider)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Verify initial state
	if len(srv.Pipeline().GetFilters()) != 1 {
		t.Fatalf("expected 1 filter initially, got %d", len(srv.Pipeline().GetFilters()))
	}

	// Attempt reload with invalid config
	provider.setConfig(invalidCfg)
	err = srv.Reload()
	if err == nil {
		t.Fatal("expected reload to fail with invalid config, got nil")
	}

	// Verify original pipeline is preserved without corruption
	if len(srv.Pipeline().GetFilters()) != 1 {
		t.Fatalf("expected 1 filter preserved after failed reload, got %d", len(srv.Pipeline().GetFilters()))
	}
	if srv.Pipeline().GetFilters()[0].Name() != "prefill_block" {
		t.Errorf("expected preserved filter 'prefill_block', got '%s'", srv.Pipeline().GetFilters()[0].Name())
	}
}

func TestServer_AtomicReload_ConcurrentRequests(t *testing.T) {
	cfg1 := &config.Config{
		Mode: "stdio",
		Stdio: config.StdioConfig{Command: "cat"},
		Filters: config.FiltersConfig{
			PrefillBlock: config.PrefillBlockConfig{Enabled: false},
		},
	}
	cfg2 := &config.Config{
		Mode: "stdio",
		Stdio: config.StdioConfig{Command: "cat"},
		Filters: config.FiltersConfig{
			PrefillBlock: config.PrefillBlockConfig{Enabled: true},
		},
	}

	provider := &mockConfigProvider{cfg: cfg1}
	srv, err := gateway.NewServer(cfg1, provider)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	var reqSuccessCount int64
	var respSuccessCount int64
	var reloadCount int64
	var wg sync.WaitGroup

	// 15 concurrent request workers
	for i := 0; i < 15; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := &mcp.Request{
				JSONRPC: "2.0",
				Method:  "tools/call",
				Params:  json.RawMessage(`{"name": "fetch_data", "arguments": {}}`),
				ID:      1,
			}
			for ctx.Err() == nil {
				out, err := srv.Pipeline().ProcessRequest(ctx, req)
				if err == nil && out != nil {
					atomic.AddInt64(&reqSuccessCount, 1)
				}
			}
		}()
	}

	// 15 concurrent response workers
	for i := 0; i < 15; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp := &mcp.Response{
				JSONRPC: "2.0",
				Result:  json.RawMessage(`{"status": "ok"}`),
				ID:      1,
			}
			for ctx.Err() == nil {
				out, err := srv.Pipeline().ProcessResponse(ctx, resp)
				if err == nil && out != nil {
					atomic.AddInt64(&respSuccessCount, 1)
				}
			}
		}()
	}

	// 3 concurrent reload workers
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			toggle := false
			for ctx.Err() == nil {
				if toggle {
					provider.setConfig(cfg1)
				} else {
					provider.setConfig(cfg2)
				}
				toggle = !toggle
				if err := srv.Reload(); err == nil {
					atomic.AddInt64(&reloadCount, 1)
				}
				time.Sleep(2 * time.Millisecond)
			}
		}()
	}

	<-ctx.Done()
	wg.Wait()

	reqs := atomic.LoadInt64(&reqSuccessCount)
	resps := atomic.LoadInt64(&respSuccessCount)
	reloads := atomic.LoadInt64(&reloadCount)

	if reqs == 0 {
		t.Error("expected successful requests during concurrent reload")
	}
	if resps == 0 {
		t.Error("expected successful responses during concurrent reload")
	}
	if reloads == 0 {
		t.Error("expected successful reloads during concurrent load")
	}
	t.Logf("Concurrent reload test passed: reqs=%d, resps=%d, reloads=%d", reqs, resps, reloads)
}

func TestServer_Reload_CompilationError_PreservesState(t *testing.T) {
	cfg := &config.Config{
		Mode:  "stdio",
		Stdio: config.StdioConfig{Command: "cat"},
		Filters: config.FiltersConfig{
			DLP: config.DLPConfig{
				Enabled: true,
				Patterns: []config.DLPPattern{
					{Name: "ssn", Regex: `\b\d{3}-\d{2}-\d{4}\b`, Action: "mask"},
				},
			},
		},
	}

	provider := &mockConfigProvider{cfg: cfg}
	srv, err := gateway.NewServer(cfg, provider)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	if len(srv.Pipeline().GetFilters()) != 1 {
		t.Fatalf("expected 1 filter initially, got %d", len(srv.Pipeline().GetFilters()))
	}
	if srv.Pipeline().GetFilters()[0].Name() != "dlp" {
		t.Errorf("expected 'dlp' filter, got '%s'", srv.Pipeline().GetFilters()[0].Name())
	}

	// Update config with invalid regex syntax error
	invalidCfg := &config.Config{
		Mode:  "stdio",
		Stdio: config.StdioConfig{Command: "cat"},
		Filters: config.FiltersConfig{
			DLP: config.DLPConfig{
				Enabled: true,
				Patterns: []config.DLPPattern{
					{Name: "broken", Regex: `[unclosed bracket`, Action: "mask"},
				},
			},
		},
	}
	provider.cfg = invalidCfg

	// Trigger reload: must return error and keep previous pipeline
	err = srv.Reload()
	if err == nil {
		t.Fatal("expected reload to fail with invalid regex syntax, got nil")
	}

	// Verify original pipeline is still intact and functional
	if len(srv.Pipeline().GetFilters()) != 1 {
		t.Fatalf("expected 1 filter preserved after failed reload, got %d", len(srv.Pipeline().GetFilters()))
	}
	if srv.Pipeline().GetFilters()[0].Name() != "dlp" {
		t.Errorf("expected preserved filter 'dlp', got '%s'", srv.Pipeline().GetFilters()[0].Name())
	}

	// Restore valid config and reload again
	provider.cfg = cfg
	if err := srv.Reload(); err != nil {
		t.Fatalf("expected reload to succeed after restoring valid config, got: %v", err)
	}
}

func TestServer_Reload_WiresFilterDependencies(t *testing.T) {
	cfg1 := &config.Config{
		Mode:  "stdio",
		Stdio: config.StdioConfig{Command: "cat"},
		Filters: config.FiltersConfig{
			SchemaValidation: config.SchemaValidationConfig{
				Enabled: true,
			},
			DLP: config.DLPConfig{
				Enabled:                 true,
				DebugRetainUnmaskedDiff: false,
			},
			LoopProtection: config.LoopProtectionConfig{
				Enabled: true,
			},
			RateLimiting: config.RateLimitingConfig{
				Enabled: true,
			},
		},
	}
	cfg2 := &config.Config{
		Mode:  "stdio",
		Stdio: config.StdioConfig{Command: "cat"},
		Filters: config.FiltersConfig{
			SchemaValidation: config.SchemaValidationConfig{
				Enabled: true,
			},
			DLP: config.DLPConfig{
				Enabled:                 true,
				DebugRetainUnmaskedDiff: true,
			},
			LoopProtection: config.LoopProtectionConfig{
				Enabled: true,
			},
			RateLimiting: config.RateLimitingConfig{
				Enabled: true,
			},
		},
	}

	provider := &mockConfigProvider{cfg: cfg1}
	srv, err := gateway.NewServer(cfg1, provider)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer srv.Shutdown(context.Background())

	// Before reload check
	if srv.Pipeline().DebugRetainUnmaskedDiff() != false {
		t.Errorf("expected debugRetainUnmaskedDiff to be false initially")
	}

	// Reload with cfg2
	provider.setConfig(cfg2)
	if err := srv.Reload(); err != nil {
		t.Fatalf("reload failed: %v", err)
	}

	// Check DebugRetainUnmaskedDiff
	if !srv.Pipeline().DebugRetainUnmaskedDiff() {
		t.Errorf("expected debugRetainUnmaskedDiff to be true after reload")
	}

	// Check SchemaFilter has DuckDBStore
	if sf, ok := srv.Pipeline().GetFilter("schema_validation").(*schema.SchemaFilter); ok {
		if sf.GetDuckDBStore() == nil {
			t.Errorf("expected schema filter to have duckdb store wired after reload")
		}
	} else {
		t.Errorf("schema_validation filter not found after reload")
	}

	// Check DLPFilter has HITLDispatcher
	if df, ok := srv.Pipeline().GetFilter("dlp").(*dlp.DLPFilter); ok {
		if df.HITLDispatcher() == nil {
			t.Errorf("expected dlp filter to have hitl dispatcher wired after reload")
		}
	} else {
		t.Errorf("dlp filter not found after reload")
	}

	// Check LoopFilter has AgentRepository
	if lf, ok := srv.Pipeline().GetFilter("loop_protection").(*limit.LoopFilter); ok {
		if lf.AgentRepository() == nil {
			t.Errorf("expected loop filter to have agent repository wired after reload")
		}
	} else {
		t.Errorf("loop_protection filter not found after reload")
	}

	// Check RateLimitFilter has AgentRepository
	if rf, ok := srv.Pipeline().GetFilter("rate_limiting").(*limit.RateLimitFilter); ok {
		if rf.AgentRepository() == nil {
			t.Errorf("expected rate limit filter to have agent repository wired after reload")
		}
	} else {
		t.Errorf("rate_limiting filter not found after reload")
	}
}

func TestServer_AdminReload_Integration(t *testing.T) {
	initialCfg := &config.Config{
		AdminPort: 9999,
		Mode:      "stdio",
		Stdio:     config.StdioConfig{Command: "cat"},
		Filters: config.FiltersConfig{
			PrefillBlock: config.PrefillBlockConfig{Enabled: false},
		},
	}

	provider := &mockConfigProvider{cfg: initialCfg}
	srv, err := gateway.NewServer(initialCfg, provider)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Create admin server with the server's Reload hook
	adminSrv := admin.NewAdminServer(initialCfg, func() error {
		return srv.Reload()
	}, func() {
		srv.Pipeline().ClearBaselines()
	})
	handler := adminSrv.Handler()

	// 1. Direct request to /api/reload -> 200 OK (Zero-Auth Open Core)
	req := httptest.NewRequest(http.MethodPost, "/api/reload", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200 for reload, got %d", rec.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["status"] != "success" {
		t.Errorf("expected status 'success', got '%v'", resp["status"])
	}

	// 2. Request with broken config -> 500 Internal Server Error
	brokenCfg := &config.Config{
		Mode: "stdio",
		Filters: config.FiltersConfig{
			DLP: config.DLPConfig{
				Enabled: true,
				Patterns: []config.DLPPattern{
					{Name: "bad_regex", Regex: "[a-z"},
				},
			},
		},
	}
	provider.setConfig(brokenCfg)

	failReq := httptest.NewRequest(http.MethodPost, "/api/reload", nil)
	failRec := httptest.NewRecorder()
	handler.ServeHTTP(failRec, failReq)
	if failRec.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500 for failed reload, got %d", failRec.Code)
	}
}

func TestServer_SynchronousShutdown_DrainingRejection(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		Mode: "stdio",
		Stdio: config.StdioConfig{
			Command:     "cat",
			AutoRestart: false,
		},
		Telemetry: config.TelemetryConfig{
			DBPath: filepath.Join(tempDir, "wire.duckdb"),
		},
	}

	provider := &mockConfigProvider{cfg: cfg}
	srv, err := gateway.NewServer(cfg, provider)
	if err != nil {
		t.Fatalf("failed to create gateway server: %v", err)
	}

	if srv.IsDraining() {
		t.Fatal("server should not be draining initially")
	}

	handler := srv.Handler()

	// Prior to shutdown, handler is reachable
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code == http.StatusServiceUnavailable {
		t.Fatalf("expected non-503 status prior to draining, got %d", rec.Code)
	}

	// Trigger shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}

	if !srv.IsDraining() {
		t.Fatal("expected server to be in draining state after shutdown")
	}

	// After shutdown begins, new incoming requests must receive HTTP 503 Service Unavailable
	recDraining := httptest.NewRecorder()
	reqDraining := httptest.NewRequest(http.MethodPost, "/message", strings.NewReader(`{"jsonrpc":"2.0","method":"tools/list","id":1}`))
	handler.ServeHTTP(recDraining, reqDraining)

	if recDraining.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503 during draining, got %d", recDraining.Code)
	}
	if recDraining.Header().Get("Connection") != "close" {
		t.Errorf("expected Connection: close header, got %q", recDraining.Header().Get("Connection"))
	}
	if !strings.Contains(recDraining.Body.String(), "Server is shutting down") {
		t.Errorf("expected JSON-RPC draining error message, got %q", recDraining.Body.String())
	}

	// Verify idempotency: calling Shutdown a second time must not hang or error
	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Errorf("expected subsequent Shutdown call to be idempotent, got error: %v", err)
	}
}

func TestServer_SynchronousShutdown_DuckDBAndAuditFlush(t *testing.T) {
	tempDir := t.TempDir()
	auditPath := filepath.Join(tempDir, "audit.jsonl")
	dbPath := filepath.Join(tempDir, "wire.duckdb")

	cfg := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
		Mode:        "stdio",
		Stdio: config.StdioConfig{
			Command:     "cat",
			AutoRestart: false,
		},
		AuditLog: config.AuditLogConfig{
			Enabled: true,
			Path:    auditPath,
		},
		Telemetry: config.TelemetryConfig{
			DBPath:          dbPath,
			RetentionDays:   7,
			MaxSizeBytes:    5 * 1024 * 1024,
			MaxPayloadBytes: 16 * 1024,
			BufferSize:      100,
			BatchFlushMs:    1000, // 1s flush timer, but Shutdown must flush immediately
		},
	}

	provider := &mockConfigProvider{cfg: cfg}
	srv, err := gateway.NewServer(cfg, provider)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Dispatch a tool call through the pipeline to generate audit and telemetry events
	ctx := context.WithValue(context.Background(), types.AgentNameContextKey, "agent-arch")
	req := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"test_tool","arguments":{"query":"arch013"}}`),
		ID:      "call-arch013-1",
	}
	_, _ = srv.Pipeline().ProcessRequest(ctx, req)

	// Shutdown synchronously
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}

	// 1. Verify file audit log flushed and committed to disk
	auditData, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("failed to read audit log file: %v", err)
	}
	if !strings.Contains(string(auditData), "test_tool") {
		t.Errorf("audit log file does not contain expected tool name, contents: %s", string(auditData))
	}

	// 2. Verify DuckDB engine closed cleanly and executed CHECKPOINT
	engine, err := duckdb.New(duckdb.Config{DBPath: dbPath})
	if err != nil {
		t.Fatalf("failed to open duckdb after server shutdown (checkpoint integrity check): %v", err)
	}
	_ = engine.Close()
}

type testPipeResponseWriter struct {
	header     http.Header
	w          *io.PipeWriter
	statusCode int
}

func (p *testPipeResponseWriter) Header() http.Header {
	return p.header
}

func (p *testPipeResponseWriter) Write(b []byte) (int, error) {
	return p.w.Write(b)
}

func (p *testPipeResponseWriter) WriteHeader(statusCode int) {
	p.statusCode = statusCode
}

func (p *testPipeResponseWriter) Flush() {}

func TestServer_Shutdown_ActiveSSEStreamEviction(t *testing.T) {
	tempDir := t.TempDir()
	agentDir := filepath.Join(tempDir, "agents")
	_ = os.MkdirAll(filepath.Join(agentDir, "active-agent", "current"), 0755)

	aggCfg := agent.RouteConfig{
		AgentName:   "active-agent",
		RoutingMode: "aggregated",
		Protocols:   []agent.ProtocolConfig{},
	}
	aggData, _ := json.Marshal(aggCfg)
	_ = os.WriteFile(filepath.Join(agentDir, "active-agent", "current", "config.json"), aggData, 0644)

	cfg := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
		Mode:        "sse",
		AgentsDir:   agentDir,
		SSE: config.SSEConfig{
			ListenPort: 0,
			TargetURL:  "http://localhost:8080",
		},
		Security: config.SecurityConfig{
			APIKeysPath: filepath.Join(tempDir, "keys", "api_keys.json"),
		},
	}

	provider := &mockConfigProvider{cfg: cfg}
	srv, err := gateway.NewServer(cfg, provider)
	if err != nil {
		t.Fatalf("failed to create gateway server: %v", err)
	}

	fsRepo := agent.NewFSRepository(agentDir, "")
	if sseProxy := srv.SSEProxy(); sseProxy != nil {
		sseProxy.SetAgentRepository(fsRepo)
	}

	pr, pw := io.Pipe()
	rw := &testPipeResponseWriter{
		header: make(http.Header),
		w:      pw,
	}

	rawToken, _, err := srv.KeyStore().GenerateKey("Dev Agent", "Developer")
	if err != nil {
		t.Fatalf("failed to generate dev key: %v", err)
	}

	req := httptest.NewRequest("GET", "/sse/active-agent", nil)
	req.Header.Set("Authorization", "Bearer "+rawToken)

	handlerDone := make(chan struct{})
	go func() {
		defer close(handlerDone)
		defer pw.Close()
		srv.Handler().ServeHTTP(rw, req)
	}()

	reader := bufio.NewReader(pr)

	// Wait for stream to establish (endpoint event)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("failed to read endpoint event: %v", err)
		}
		if strings.HasPrefix(line, "event: endpoint") {
			break
		}
	}

	// Active SSE stream is ongoing. Trigger server shutdown!
	shutdownStart := time.Now()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	readDone := make(chan struct{})
	var gotShutdownEvent bool
	go func() {
		defer close(readDone)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			if strings.HasPrefix(line, "event: shutdown") {
				gotShutdownEvent = true
			}
		}
	}()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("srv.Shutdown failed: %v", err)
	}
	shutdownDuration := time.Since(shutdownStart)

	// Verify handler finished promptly (< 500ms) without hitting 5s timeout
	select {
	case <-handlerDone:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("handler did not terminate promptly during server shutdown")
	}

	<-readDone
	if !gotShutdownEvent {
		t.Errorf("expected client to receive shutdown event frame")
	}

	if shutdownDuration > 500*time.Millisecond {
		t.Errorf("expected server shutdown to complete in <500ms, took %v", shutdownDuration)
	}
}

func getFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") || strings.Contains(err.Error(), "permission denied") {
			t.Skipf("skipping test requiring local TCP listener: socket listening not permitted in environment (%v)", err)
		}
		t.Fatalf("failed to listen on free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

func setupTestAgentDir(t *testing.T, agentName string) string {
	t.Helper()
	tempDir := t.TempDir()
	agentDir := filepath.Join(tempDir, "agents")
	_ = os.MkdirAll(filepath.Join(agentDir, agentName, "current"), 0755)

	aggCfg := agent.RouteConfig{
		AgentName:   agentName,
		RoutingMode: "aggregated",
		Protocols:   []agent.ProtocolConfig{},
	}
	aggData, _ := json.Marshal(aggCfg)
	_ = os.WriteFile(filepath.Join(agentDir, agentName, "current", "config.json"), aggData, 0644)
	return agentDir
}

func TestServer_MaintenanceCoordinator_RuntimeSessionEviction(t *testing.T) {
	agentDir := setupTestAgentDir(t, "agent-unified")
	listenPort := getFreePort(t)
	adminPort := getFreePort(t)

	cfg := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
		Mode:        "sse",
		ListenPort:  listenPort,
		AdminPort:   adminPort,
		AgentsDir:   agentDir,
		SSE: config.SSEConfig{
			TargetURL: "http://localhost:8080",
		},
	}

	provider := &mockConfigProvider{cfg: cfg}
	srv, err := gateway.NewServer(cfg, provider)
	if err != nil {
		t.Fatalf("failed to create gateway server: %v", err)
	}

	// Configure fast maintenance intervals: 15ms cleanup interval, 50ms session idle timeout, 50ms correlation max age
	srv.SetMaintenanceIntervals(15*time.Millisecond, 50*time.Millisecond, 50*time.Millisecond, 50*time.Millisecond)

	serverCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(serverCtx)
	}()

	// Wait for server to boot
	time.Sleep(30 * time.Millisecond)

	sessionMgr := srv.SessionManager()
	if sessionMgr == nil {
		t.Fatal("expected non-nil SessionManager in Unified Mode")
	}

	// 1. Create two session bridges: one idle and one active
	bridgeIdle, err := sessionMgr.CreateBridge(serverCtx, "agent-unified", "idle-bridge-1", nil)
	if err != nil {
		t.Fatalf("failed to create idle bridge: %v", err)
	}
	bridgeIdle.Touch()
	// Manually backdate LastActive to simulate 30+ minutes of inactivity
	bridgeIdle.SetLastActive(time.Now().Add(-1 * time.Hour))

	_, err = sessionMgr.CreateBridge(serverCtx, "agent-unified", "active-bridge-2", nil)
	if err != nil {
		t.Fatalf("failed to create active bridge: %v", err)
	}

	if sessionMgr.ActiveBridgesCount() != 2 {
		t.Fatalf("expected 2 active bridges initially, got %d", sessionMgr.ActiveBridgesCount())
	}

	// 2. Add two correlation entries: one expired and one fresh
	cStore := srv.CorrelationStore()
	if cStore == nil {
		t.Fatal("expected non-nil CorrelationStore in Unified Mode")
	}
	expiredKey := proxy.NewCorrelationKey("idle-bridge-1", "req-expired")
	cStore.Put(expiredKey, &proxy.PendingRequest{
		ToolName:  "tool_old",
		Timestamp: time.Now().Add(-10 * time.Minute),
	})
	freshKey := proxy.NewCorrelationKey("active-bridge-2", "req-fresh")
	cStore.Put(freshKey, &proxy.PendingRequest{
		ToolName:  "tool_new",
		Timestamp: time.Now(),
	})

	if cStore.Count() != 2 {
		t.Fatalf("expected 2 correlation entries initially, got %d", cStore.Count())
	}

	// 3. Add two session targets in SSEProxy: one expired and one fresh
	sseProxy := srv.SSEProxy()
	if sseProxy == nil {
		t.Fatal("expected non-nil SSEProxy in Unified Mode")
	}
	sseProxy.SetSessionTarget("idle-bridge-1", "http://localhost:8080", time.Now().Add(-3*time.Hour))
	sseProxy.SetSessionTarget("active-bridge-2", "http://localhost:8080", time.Now())

	if sseProxy.SessionTargetsCount() != 2 {
		t.Fatalf("expected 2 session targets initially, got %d", sseProxy.SessionTargetsCount())
	}

	// 4. Poll until the centralized maintenance coordinator evicts idle/expired resources
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if sessionMgr.ActiveBridgesCount() == 1 && cStore.Count() == 1 && sseProxy.SessionTargetsCount() == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Verify idle bridge was evicted
	if sessionMgr.ActiveBridgesCount() != 1 {
		t.Errorf("expected 1 active bridge after maintenance sweep, got %d", sessionMgr.ActiveBridgesCount())
	}
	if _, exists := sessionMgr.GetBridge("idle-bridge-1"); exists {
		t.Errorf("idle bridge should have been evicted")
	}
	if _, exists := sessionMgr.GetBridge("active-bridge-2"); !exists {
		t.Errorf("active bridge should have been retained")
	}

	// Verify expired correlation entry was purged
	if cStore.Count() != 1 {
		t.Errorf("expected 1 correlation record after maintenance sweep, got %d", cStore.Count())
	}
	if _, ok := cStore.GetAndRemove(expiredKey); ok {
		t.Errorf("expired correlation key should have been purged")
	}
	if _, ok := cStore.GetAndRemove(freshKey); !ok {
		t.Errorf("fresh correlation key should have been retained")
	}

	// Verify expired session target was purged
	if sseProxy.SessionTargetsCount() != 1 {
		t.Errorf("expected 1 session target after maintenance sweep, got %d", sseProxy.SessionTargetsCount())
	}

	// 5. Trigger graceful shutdown
	shutdownCtx, sCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer sCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}

	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed && err != context.Canceled {
			t.Errorf("unexpected error from srv.Start: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("srv.Start did not terminate after shutdown")
	}
}

func TestServer_MaintenanceCoordinator_GracefulTeardown(t *testing.T) {
	agentDir := setupTestAgentDir(t, "agent-teardown")
	listenPort := getFreePort(t)
	adminPort := getFreePort(t)

	cfg := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
		Mode:        "sse",
		ListenPort:  listenPort,
		AdminPort:   adminPort,
		AgentsDir:   agentDir,
		SSE: config.SSEConfig{
			TargetURL: "http://localhost:8080",
		},
	}

	provider := &mockConfigProvider{cfg: cfg}
	srv, err := gateway.NewServer(cfg, provider)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	srv.SetMaintenanceIntervals(5*time.Millisecond, 20*time.Millisecond, 20*time.Millisecond, 20*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(ctx)
	}()

	time.Sleep(30 * time.Millisecond)

	// Ensure shutdown completes promptly and clean up all tickers
	shutdownStart := time.Now()
	shutdownCtx, sCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer sCancel()

	cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}

	if duration := time.Since(shutdownStart); duration > 500*time.Millisecond {
		t.Errorf("expected shutdown to finish in < 500ms, took %v", duration)
	}

	select {
	case <-errCh:
	case <-time.After(1 * time.Second):
		t.Fatal("server start did not return after shutdown")
	}
}

func TestServer_MaintenanceCoordinator_StdioMode(t *testing.T) {
	cfg := &config.Config{
		Mode: "stdio",
		Stdio: config.StdioConfig{
			Command:     "cat",
			AutoRestart: false,
		},
	}

	provider := &mockConfigProvider{cfg: cfg}
	srv, err := gateway.NewServer(cfg, provider)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	srv.SetMaintenanceIntervals(5*time.Millisecond, 20*time.Millisecond, 20*time.Millisecond, 20*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(ctx)
	}()

	time.Sleep(30 * time.Millisecond)

	shutdownCtx, sCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer sCancel()

	cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("shutdown failed in stdio mode: %v", err)
	}

	select {
	case <-errCh:
	case <-time.After(1 * time.Second):
		t.Fatal("server start did not return after shutdown in stdio mode")
	}
}

func TestServer_SegregatedMode_MemoryLeakPrevention_ExtendedTraffic(t *testing.T) {
	agentDir := setupTestAgentDir(t, "agent-traffic")
	listenPort := getFreePort(t)
	adminPort := getFreePort(t)

	cfg := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
		Mode:        "sse",
		ListenPort:  listenPort,
		AdminPort:   adminPort,
		AgentsDir:   agentDir,
		SSE: config.SSEConfig{
			TargetURL: "http://localhost:8080",
		},
	}

	provider := &mockConfigProvider{cfg: cfg}
	srv, err := gateway.NewServer(cfg, provider)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	srv.SetMaintenanceIntervals(10*time.Millisecond, 30*time.Millisecond, 30*time.Millisecond, 30*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(ctx)
	}()

	time.Sleep(30 * time.Millisecond)

	sessionMgr := srv.SessionManager()
	cStore := srv.CorrelationStore()
	sseProxy := srv.SSEProxy()

	// Simulate repeated burst of sessions that become idle
	for round := 0; round < 3; round++ {
		for i := 0; i < 5; i++ {
			sid := fmt.Sprintf("burst-%d-%d", round, i)
			b, err := sessionMgr.CreateBridge(ctx, "agent-traffic", sid, nil)
			if err != nil {
				t.Fatalf("failed to create bridge: %v", err)
			}
			b.SetLastActive(time.Now().Add(-1 * time.Hour)) // abandoned
			cStore.Put(proxy.NewCorrelationKey(sid, "req-1"), &proxy.PendingRequest{
				ToolName:  "fetch",
				Timestamp: time.Now().Add(-10 * time.Minute),
			})
			sseProxy.SetSessionTarget(sid, "http://localhost:8080", time.Now().Add(-3*time.Hour))
		}

		// Wait for maintenance coordinator to sweep
		deadline := time.Now().Add(1 * time.Second)
		for time.Now().Before(deadline) {
			if sessionMgr.ActiveBridgesCount() == 0 && cStore.Count() == 0 && sseProxy.SessionTargetsCount() == 0 {
				break
			}
			time.Sleep(15 * time.Millisecond)
		}

		if count := sessionMgr.ActiveBridgesCount(); count != 0 {
			t.Errorf("round %d: expected 0 active bridges after sweep, got %d", round, count)
		}
		if count := cStore.Count(); count != 0 {
			t.Errorf("round %d: expected 0 correlations after sweep, got %d", round, count)
		}
		if count := sseProxy.SessionTargetsCount(); count != 0 {
			t.Errorf("round %d: expected 0 session targets after sweep, got %d", round, count)
		}
	}

	shutdownCtx, sCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer sCancel()
	_ = srv.Shutdown(shutdownCtx)
	<-errCh
}

func TestServer_StrictPhasedShutdown_InFlightExecution(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX process tests skipped on Windows")
	}

	agentDir := setupTestAgentDir(t, "test-agent")
	listenPort := getFreePort(t)
	adminPort := getFreePort(t)

	cfg := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
		Mode:        "sse",
		ListenPort:  listenPort,
		AdminPort:   adminPort,
		AgentsDir:   agentDir,
		SSE: config.SSEConfig{
			TargetURL: "http://localhost:8080",
		},
	}

	provider := &mockConfigProvider{cfg: cfg}
	srv, err := gateway.NewServer(cfg, provider)
	if err != nil {
		t.Fatalf("failed to create gateway server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startErrCh := make(chan error, 1)
	go func() {
		startErrCh <- srv.Start(ctx)
	}()

	for i := 0; i < 50; i++ {
		if srv.IsStarted() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	sm := srv.SessionManager()
	if sm == nil {
		t.Fatalf("expected non-nil SessionManager in Unified Mode")
	}

	bridge, err := sm.CreateBridge(ctx, "test-agent", "sess-inflight-1", nil)
	if err != nil {
		t.Fatalf("failed to create bridge: %v", err)
	}

	dialer := session.NewStdioDialer()
	proto := agent.ProtocolConfig{
		ID:           "sleeper-proto",
		Name:         "sleeper-tool",
		URLOrCommand: "sleep 30",
		Type:         "stdio",
	}
	upSess := dialer.Dial(ctx, proto, bridge.EventCh, "sess-inflight-1", nil)
	bridge.SetUpstream("sleeper-tool", upSess)

	if upSess.GetStatus() != "READY" {
		t.Fatalf("expected upSess to be READY, got %s", upSess.GetStatus())
	}

	// Track an in-flight tool call
	inFlightStarted := make(chan struct{})
	inFlightDone := make(chan struct{})
	go func() {
		srv.InFlightAdd(1)
		close(inFlightStarted)
		time.Sleep(200 * time.Millisecond)
		srv.InFlightDone()
		close(inFlightDone)
	}()

	<-inFlightStarted

	// Trigger shutdown while the in-flight tool call is executing
	shutdownStart := time.Now()
	shutdownDone := make(chan struct{})
	shutdownCtx, sCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer sCancel()

	go func() {
		defer close(shutdownDone)
		if sErr := srv.Shutdown(shutdownCtx); sErr != nil {
			t.Errorf("srv.Shutdown failed: %v", sErr)
		}
	}()

	// Wait briefly for Phase 1 to activate isDraining
	time.Sleep(30 * time.Millisecond)
	if !srv.IsDraining() {
		t.Errorf("expected server to be draining in Phase 1")
	}

	// New inbound request arriving during shutdown must receive HTTP 503 Service Unavailable
	handler := srv.Handler()
	recNew := httptest.NewRecorder()
	reqNew := httptest.NewRequest(http.MethodPost, "/message?sessionId=sess-inflight-1", strings.NewReader(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"test"},"id":100}`))
	handler.ServeHTTP(recNew, reqNew)

	if recNew.Code != http.StatusServiceUnavailable {
		t.Errorf("expected HTTP 503 for new request during draining, got %d", recNew.Code)
	}
	if !strings.Contains(recNew.Body.String(), "-32000") {
		t.Errorf("expected JSON-RPC error -32000, got %s", recNew.Body.String())
	}

	// Verify that while in-flight is still active, child stdio process has NOT been terminated yet (Phase 2)
	select {
	case <-inFlightDone:
		t.Fatal("in-flight completed prematurely")
	default:
		// In-flight still executing
		if upSess.GetStatus() != "READY" {
			t.Errorf("expected upSess to remain READY during in-flight execution, got %s", upSess.GetStatus())
		}
	}

	// Await in-flight completion
	<-inFlightDone

	// Await shutdown completion
	<-shutdownDone
	shutdownDuration := time.Since(shutdownStart)

	// After shutdown completion, child stdio process must now be CLOSED and reaped (Phase 3)
	if upSess.GetStatus() != "CLOSED" {
		t.Errorf("expected upSess to be CLOSED after shutdown, got %s", upSess.GetStatus())
	}

	t.Logf("Strict phased shutdown completed in %v with in-flight drain", shutdownDuration)
	cancel()
	<-startErrCh
}

func TestServer_StrictPhasedShutdown_TimingUnder1_5s(t *testing.T) {
	agentDir := setupTestAgentDir(t, "test-timing")
	listenPort := getFreePort(t)
	adminPort := getFreePort(t)

	cfg := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
		Mode:        "sse",
		ListenPort:  listenPort,
		AdminPort:   adminPort,
		AgentsDir:   agentDir,
		SSE: config.SSEConfig{
			TargetURL: "http://localhost:8080",
		},
	}

	provider := &mockConfigProvider{cfg: cfg}
	srv, err := gateway.NewServer(cfg, provider)
	if err != nil {
		t.Fatalf("failed to create gateway server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startErrCh := make(chan error, 1)
	go func() {
		startErrCh <- srv.Start(ctx)
	}()

	// Wait for server to start
	for i := 0; i < 50; i++ {
		if srv.IsStarted() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	shutdownStart := time.Now()
	shutdownCtx, sCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer sCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("srv.Shutdown failed: %v", err)
	}
	shutdownDuration := time.Since(shutdownStart)

	if shutdownDuration >= 1500*time.Millisecond {
		t.Errorf("expected graceful shutdown in < 1.5s, took %v", shutdownDuration)
	}
	t.Logf("Graceful shutdown without in-flight calls completed in %v", shutdownDuration)

	cancel()
	<-startErrCh
}

func TestServer_StrictPhasedShutdown_DoubleShutdownRaceFree(t *testing.T) {
	agentDir := setupTestAgentDir(t, "test-race")
	listenPort := getFreePort(t)
	adminPort := getFreePort(t)

	cfg := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
		Mode:        "sse",
		ListenPort:  listenPort,
		AdminPort:   adminPort,
		AgentsDir:   agentDir,
		SSE: config.SSEConfig{
			TargetURL: "http://localhost:8080",
		},
	}

	provider := &mockConfigProvider{cfg: cfg}
	srv, err := gateway.NewServer(cfg, provider)
	if err != nil {
		t.Fatalf("failed to create gateway server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startErrCh := make(chan error, 1)
	go func() {
		startErrCh <- srv.Start(ctx)
	}()

	// Wait for server to start
	for i := 0; i < 50; i++ {
		if srv.IsStarted() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Concurrently call Shutdown and cancel context from 10 parallel goroutines
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if idx%2 == 0 {
				cancel()
			}
			shutdownCtx, sCancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer sCancel()
			_ = srv.Shutdown(shutdownCtx)
		}(i)
	}
	wg.Wait()

	if !srv.IsDraining() {
		t.Errorf("expected server to be draining")
	}

	<-startErrCh
}

func TestServer_PortCollision_Rejected(t *testing.T) {
	// Startup validation fails fast with an explicit error when listen_port == admin_port
	port := getFreePort(t)
	cfg := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
		Mode:        "sse",
		ListenPort:  port,
		AdminPort:   port,
		AgentsDir:   setupTestAgentDir(t, "test-collision"),
		SSE: config.SSEConfig{
			TargetURL: "http://localhost:8080",
		},
	}

	provider := &mockConfigProvider{cfg: cfg}
	srv, err := gateway.NewServer(cfg, provider)
	if err == nil {
		if srv != nil {
			_ = srv.Shutdown(context.Background())
		}
		t.Fatalf("expected error when listen_port == admin_port, got nil")
	}

	expectedSub := "must be distinct"
	if !strings.Contains(err.Error(), expectedSub) {
		t.Errorf("expected error message to contain %q, got: %v", expectedSub, err)
	}
}

func TestServer_StrictPortSegregation(t *testing.T) {
	listenPort := getFreePort(t)
	adminPort := getFreePort(t)
	agentDir := setupTestAgentDir(t, "test-segregation")

	cfg := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
		Mode:        "sse",
		ListenPort:  listenPort,
		AdminPort:   adminPort,
		AgentsDir:   agentDir,
		SSE: config.SSEConfig{
			TargetURL: "http://localhost:8080",
		},
	}

	provider := &mockConfigProvider{cfg: cfg}
	srv, err := gateway.NewServer(cfg, provider)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startErrCh := make(chan error, 1)
	go func() {
		startErrCh <- srv.Start(ctx)
	}()

	// Wait for server to start
	for i := 0; i < 50; i++ {
		if srv.IsStarted() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Allow listeners to bind and start accepting traffic
	time.Sleep(50 * time.Millisecond)

	client := &http.Client{Timeout: 2 * time.Second}

	// 1. Proxy listener on listen_port serves strictly MCP protocols.
	// Admin routes on listen_port must return 404 Not Found.
	respAdminOnProxy, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/admin/dashboard", listenPort))
	if err != nil {
		t.Fatalf("failed to connect to proxy port: %v", err)
	}
	defer respAdminOnProxy.Body.Close()
	if respAdminOnProxy.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 Not Found for /admin/dashboard on proxy port, got %d", respAdminOnProxy.StatusCode)
	}

	respStatusOnProxy, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/admin/status", listenPort))
	if err != nil {
		t.Fatalf("failed to connect to proxy port: %v", err)
	}
	defer respStatusOnProxy.Body.Close()
	if respStatusOnProxy.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 Not Found for /admin/status on proxy port, got %d", respStatusOnProxy.StatusCode)
	}

	// 2. Admin listener on admin_port serves strictly administrative routes.
	// Status endpoint must return 200 OK on admin_port.
	respStatusOnAdmin, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/admin/status", adminPort))
	if err != nil {
		t.Fatalf("failed to connect to admin port: %v", err)
	}
	defer respStatusOnAdmin.Body.Close()
	if respStatusOnAdmin.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK for /admin/status on admin port, got %d", respStatusOnAdmin.StatusCode)
	}

	// MCP routes on admin_port must return 404 Not Found.
	respSSEOnAdmin, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/sse", adminPort))
	if err != nil {
		t.Fatalf("failed to connect to admin port: %v", err)
	}
	defer respSSEOnAdmin.Body.Close()
	if respSSEOnAdmin.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 Not Found for /sse on admin port, got %d", respSSEOnAdmin.StatusCode)
	}

	respMsgOnAdmin, err := client.Post(fmt.Sprintf("http://127.0.0.1:%d/message", adminPort), "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("failed to connect to admin port: %v", err)
	}
	defer respMsgOnAdmin.Body.Close()
	if respMsgOnAdmin.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 Not Found for /message on admin port, got %d", respMsgOnAdmin.StatusCode)
	}

	// Clean shutdown
	shutdownCtx, sCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer sCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}
	cancel()
	<-startErrCh
}

func TestServer_SlowlorisTransportTimeouts(t *testing.T) {
	listenPort := getFreePort(t)
	adminPort := getFreePort(t)
	agentDir := setupTestAgentDir(t, "test-timeouts")

	cfg := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
		Mode:        "sse",
		ListenPort:  listenPort,
		AdminPort:   adminPort,
		AgentsDir:   agentDir,
		SSE: config.SSEConfig{
			TargetURL: "http://localhost:8080",
		},
	}

	provider := &mockConfigProvider{cfg: cfg}
	srv, err := gateway.NewServer(cfg, provider)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startErrCh := make(chan error, 1)
	go func() {
		startErrCh <- srv.Start(ctx)
	}()

	// Wait for server to start
	for i := 0; i < 50; i++ {
		if srv.IsStarted() && srv.SSEProxy() != nil && srv.SSEProxy().Server() != nil && srv.AdminServer() != nil && srv.AdminServer().Server() != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	sseSrv := srv.SSEProxy().Server()
	if sseSrv == nil {
		t.Fatal("expected non-nil http.Server in SSEProxy")
	}
	if sseSrv.ReadHeaderTimeout != 5*time.Second {
		t.Errorf("expected SSE proxy ReadHeaderTimeout 5s, got %v", sseSrv.ReadHeaderTimeout)
	}
	if sseSrv.IdleTimeout != 120*time.Second {
		t.Errorf("expected SSE proxy IdleTimeout 120s, got %v", sseSrv.IdleTimeout)
	}
	if sseSrv.WriteTimeout != 0 {
		t.Errorf("expected SSE proxy WriteTimeout 0 (unbounded for persistent event streams), got %v", sseSrv.WriteTimeout)
	}

	admSrv := srv.AdminServer().Server()
	if admSrv == nil {
		t.Fatal("expected non-nil http.Server in AdminServer")
	}
	if admSrv.ReadHeaderTimeout != 5*time.Second {
		t.Errorf("expected AdminServer ReadHeaderTimeout 5s, got %v", admSrv.ReadHeaderTimeout)
	}
	if admSrv.IdleTimeout != 120*time.Second {
		t.Errorf("expected AdminServer IdleTimeout 120s, got %v", admSrv.IdleTimeout)
	}

	shutdownCtx, sCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer sCancel()
	_ = srv.Shutdown(shutdownCtx)
	cancel()
	<-startErrCh
}

func TestServer_CleanIndependentListenerDraining(t *testing.T) {
	listenPort := getFreePort(t)
	adminPort := getFreePort(t)
	agentDir := setupTestAgentDir(t, "test-draining")

	cfg := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
		Mode:        "sse",
		ListenPort:  listenPort,
		AdminPort:   adminPort,
		AgentsDir:   agentDir,
		SSE: config.SSEConfig{
			TargetURL: "http://localhost:8080",
		},
	}

	provider := &mockConfigProvider{cfg: cfg}
	srv, err := gateway.NewServer(cfg, provider)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startErrCh := make(chan error, 1)
	go func() {
		startErrCh <- srv.Start(ctx)
	}()

	for i := 0; i < 50; i++ {
		if srv.IsStarted() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)

	// Simulate in-flight tool call
	srv.InFlightAdd(1)
	inFlightCompleted := make(chan struct{})
	go func() {
		time.Sleep(80 * time.Millisecond)
		srv.InFlightDone()
		close(inFlightCompleted)
	}()

	shutdownStart := time.Now()
	shutdownCtx, sCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer sCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}
	elapsed := time.Since(shutdownStart)

	// Shutdown must have waited for the in-flight request to finish (> 80ms)
	if elapsed < 70*time.Millisecond {
		t.Errorf("Shutdown exited prematurely without waiting for in-flight request: took %v", elapsed)
	}

	select {
	case <-inFlightCompleted:
	default:
		t.Errorf("in-flight request was not completed prior to shutdown completion")
	}

	// Verify both servers are closed
	client := &http.Client{Timeout: 200 * time.Millisecond}
	_, errProxy := client.Get(fmt.Sprintf("http://127.0.0.1:%d/sse", listenPort))
	if errProxy == nil {
		t.Errorf("expected connection error to proxy port after shutdown, but succeeded")
	}

	_, errAdmin := client.Get(fmt.Sprintf("http://127.0.0.1:%d/admin/status", adminPort))
	if errAdmin == nil {
		t.Errorf("expected connection error to admin port after shutdown, but succeeded")
	}

	cancel()
	<-startErrCh
}

func TestServer_LoopbackBindingDefault(t *testing.T) {
	agentDir := setupTestAgentDir(t, "test-loopback-default")
	listenPort := getFreePort(t)
	adminPort := getFreePort(t)

	cfg := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
		Mode:        "sse",
		ListenPort:  listenPort,
		AdminPort:   adminPort,
		AgentsDir:   agentDir,
	}

	provider := &mockConfigProvider{cfg: cfg}
	srv, err := gateway.NewServer(cfg, provider)
	if err != nil {
		t.Fatalf("failed to create gateway server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startErrCh := make(chan error, 1)
	go func() {
		startErrCh <- srv.Start(ctx)
	}()

	for i := 0; i < 50; i++ {
		if srv.IsStarted() && srv.SSEProxy() != nil && srv.SSEProxy().Server() != nil && srv.AdminServer() != nil && srv.AdminServer().Server() != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)

	// Verify that the underlying http.Server Addr strings bind explicitly to 127.0.0.1
	if srv.SSEProxy() != nil && srv.SSEProxy().Server() != nil {
		expectedAddr := fmt.Sprintf("127.0.0.1:%d", listenPort)
		if srv.SSEProxy().Server().Addr != expectedAddr {
			t.Errorf("expected sseProxy Addr %q, got %q", expectedAddr, srv.SSEProxy().Server().Addr)
		}
	} else {
		t.Fatal("expected non-nil sseProxy http.Server")
	}

	if srv.AdminServer() != nil && srv.AdminServer().Server() != nil {
		expectedAdminAddr := fmt.Sprintf("127.0.0.1:%d", adminPort)
		if srv.AdminServer().Server().Addr != expectedAdminAddr {
			t.Errorf("expected adminServer Addr %q, got %q", expectedAdminAddr, srv.AdminServer().Server().Addr)
		}
	} else {
		t.Fatal("expected non-nil adminServer http.Server")
	}

	// Verify local HTTP connectivity to 127.0.0.1
	client := &http.Client{Timeout: 500 * time.Millisecond}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/admin/dashboard", adminPort))
	if err != nil {
		t.Fatalf("failed to reach admin console on 127.0.0.1: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected HTTP 200 from admin console, got %d", resp.StatusCode)
	}

	shutdownCtx, sCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer sCancel()
	_ = srv.Shutdown(shutdownCtx)
	cancel()
	<-startErrCh
}

func TestServer_CustomHostBinding(t *testing.T) {
	agentDir := setupTestAgentDir(t, "test-custom-host")
	listenPort := getFreePort(t)
	adminPort := getFreePort(t)

	cfg := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
		Mode:        "sse",
		ListenHost:  "0.0.0.0",
		ListenPort:  listenPort,
		AdminPort:   adminPort,
		AgentsDir:   agentDir,
	}

	provider := &mockConfigProvider{cfg: cfg}
	srv, err := gateway.NewServer(cfg, provider)
	if err != nil {
		t.Fatalf("failed to create gateway server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startErrCh := make(chan error, 1)
	go func() {
		startErrCh <- srv.Start(ctx)
	}()

	for i := 0; i < 50; i++ {
		if srv.IsStarted() && srv.SSEProxy() != nil && srv.SSEProxy().Server() != nil && srv.AdminServer() != nil && srv.AdminServer().Server() != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)

	// Verify that the ingress proxy binds to custom host (0.0.0.0) while Admin Server enforces strict loopback (127.0.0.1) per ADR-0028
	if srv.SSEProxy() != nil && srv.SSEProxy().Server() != nil {
		expectedAddr := fmt.Sprintf("0.0.0.0:%d", listenPort)
		if srv.SSEProxy().Server().Addr != expectedAddr {
			t.Errorf("expected sseProxy Addr %q, got %q", expectedAddr, srv.SSEProxy().Server().Addr)
		}
	} else {
		t.Fatal("expected non-nil sseProxy http.Server")
	}

	if srv.AdminServer() != nil && srv.AdminServer().Server() != nil {
		// ADR-0028: In standalone mode, admin server is strictly isolated to 127.0.0.1 even if ListenHost is 0.0.0.0
		expectedAdminAddr := fmt.Sprintf("127.0.0.1:%d", adminPort)
		if srv.AdminServer().Server().Addr != expectedAdminAddr {
			t.Errorf("expected adminServer Addr %q (strict loopback), got %q", expectedAdminAddr, srv.AdminServer().Server().Addr)
		}
	} else {
		t.Fatal("expected non-nil adminServer http.Server")
	}

	shutdownCtx, sCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer sCancel()
	_ = srv.Shutdown(shutdownCtx)
	cancel()
	<-startErrCh
}

func TestServer_Shutdown_KeystoreDirtyFlush(t *testing.T) {
	tempDir := t.TempDir()
	keyStorePath := filepath.Join(tempDir, "keys", "api_keys.json")
	agentDir := filepath.Join(tempDir, "agents")
	_ = os.MkdirAll(agentDir, 0755)

	// Pre-populate keystore on disk with a valid key
	keyStore, err := auth.NewFileKeyStore(keyStorePath)
	if err != nil {
		t.Fatalf("failed to initialize test keystore: %v", err)
	}
	rawToken, record, err := keyStore.GenerateKey("Shutdown Test Agent", "Developer")
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	listenPort, adminPort := getFreePort(t), getFreePort(t)
	cfg := &config.Config{
		Mode:        "stdio",
		Stdio:       config.StdioConfig{Command: "cat"},
		Security:    config.SecurityConfig{APIKeysPath: keyStorePath},
		ListenHost:  "127.0.0.1",
		ListenPort:  listenPort,
		AdminPort:   adminPort,
		AgentsDir:   agentDir,
	}

	provider := &mockConfigProvider{cfg: cfg}
	srv, err := gateway.NewServer(cfg, provider)
	if err != nil {
		t.Fatalf("failed to create gateway server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startErrCh := make(chan error, 1)
	go func() {
		startErrCh <- srv.Start(ctx)
	}()

	for i := 0; i < 50; i++ {
		if srv.IsStarted() && srv.KeyStore() != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Validate key against live server's keystore: updates LastUsedAt in RAM and marks dirty
	time.Sleep(5 * time.Millisecond)
	validateTime := time.Now().UTC()
	key, ok := srv.KeyStore().ValidateKey(rawToken)
	if !ok || key == nil {
		t.Fatalf("ValidateKey failed against server keystore")
	}

	// Shutdown the server gracefully: Phase 4 must flush dirty keystore to disk
	shutdownCtx, sCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer sCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Server shutdown failed: %v", err)
	}
	cancel()
	<-startErrCh

	// Re-read keystore from disk and verify LastUsedAt was persisted on shutdown
	reloadedStore, err := auth.NewFileKeyStore(keyStorePath)
	if err != nil {
		t.Fatalf("Failed to reload keystore from disk: %v", err)
	}

	reloadedKey, err := reloadedStore.GetKey(record.ID)
	if err != nil {
		t.Fatalf("Failed to get key metadata from reloaded store: %v", err)
	}
	if reloadedKey.LastUsedAt.Before(validateTime) {
		t.Errorf("Keystore flush on shutdown failed: persisted LastUsedAt (%v) is older than validation time (%v)", reloadedKey.LastUsedAt, validateTime)
	}
}

func TestServer_FilterToggle_PersistsAcrossReloadAndRestart(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("FARADAI_WIRE_HOME", tmpDir)
	configPath := filepath.Join(tmpDir, "config.yaml")
	dbPath := filepath.Join(tmpDir, "telemetry.duckdb")

	originalYAML := fmt.Sprintf(`# Preserved user comment
runtime_mode: STANDALONE
listen_host: "127.0.0.1"
listen_port: 8090
admin_port: 8095
agents_dir: %q
telemetry:
  db_path: %q
filters:
  prefill_block:
    enabled: true
  dlp:
    enabled: true
  rate_limiting:
    enabled: false
`, filepath.ToSlash(filepath.Join(tmpDir, "agents")), filepath.ToSlash(dbPath))

	if err := os.WriteFile(configPath, []byte(originalYAML), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	provider := config.NewYAMLConfigProvider(configPath)
	cfg, err := provider.Load()
	if err != nil {
		t.Fatalf("failed to load initial config: %v", err)
	}

	srv, err := gateway.NewServer(cfg, provider)
	if err != nil {
		t.Fatalf("failed to create gateway server: %v", err)
	}
	adminH := srv.AdminHandler()

	// 1. Toggle DLP off and Rate Limiting on
	for _, body := range []string{
		`{"filter":"dlp","enabled":false}`,
		`{"filter":"rate_limiting","enabled":true}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/admin/config/toggle", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		adminH.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("toggle %s failed with %d: %s", body, rec.Code, rec.Body.String())
		}
	}

	assertFilters := func(label string, h http.Handler, srvInstance *gateway.Server, wantDLP, wantRL bool) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/admin/status", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: /admin/status returned %d", label, rec.Code)
		}
		var st struct {
			ActiveFilters []string `json:"active_filters"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
			t.Fatalf("%s: decode status: %v", label, err)
		}
		if got := slices.Contains(st.ActiveFilters, "dlp"); got != wantDLP {
			t.Errorf("%s: status dlp=%v, want %v (active_filters=%v)", label, got, wantDLP, st.ActiveFilters)
		}
		if got := slices.Contains(st.ActiveFilters, "rate_limiting"); got != wantRL {
			t.Errorf("%s: status rate_limiting=%v, want %v (active_filters=%v)", label, got, wantRL, st.ActiveFilters)
		}
		if got := srvInstance.Pipeline().GetFilter("dlp") != nil; got != wantDLP {
			t.Errorf("%s: pipeline dlp=%v, want %v", label, got, wantDLP)
		}
		if got := srvInstance.Pipeline().GetFilter("rate_limiting") != nil; got != wantRL {
			t.Errorf("%s: pipeline rate_limiting=%v, want %v", label, got, wantRL)
		}
	}

	assertFilters("after toggle", adminH, srv, false, true)

	// 2. Manual disk reload must NOT revert DuckDB filter overrides
	if err := srv.Reload(); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}
	assertFilters("after Reload()", adminH, srv, false, true)

	// 3. Verify config.yaml on disk is untouched
	afterBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config after toggle: %v", err)
	}
	if string(afterBytes) != originalYAML {
		t.Fatalf("config.yaml on disk was mutated")
	}

	// 4. Simulate full gateway restart against same config.yaml and DuckDB
	_ = srv.Shutdown(context.Background())

	cfg2, err := provider.Load()
	if err != nil {
		t.Fatalf("reload config for restart: %v", err)
	}
	srv2, err := gateway.NewServer(cfg2, provider)
	if err != nil {
		t.Fatalf("failed to boot restarted gateway server: %v", err)
	}
	defer srv2.Shutdown(context.Background())
	adminH2 := srv2.AdminHandler()

	assertFilters("after restart", adminH2, srv2, false, true)

	// 5. Reset filters.dlp restores YAML baseline (true) while preserving rate_limiting=true
	resetReq := httptest.NewRequest(http.MethodPost, "/admin/settings/reset", strings.NewReader(`{"key":"filters.dlp"}`))
	resetReq.Header.Set("Content-Type", "application/json")
	resetRec := httptest.NewRecorder()
	adminH2.ServeHTTP(resetRec, resetReq)
	if resetRec.Code != http.StatusOK {
		t.Fatalf("reset failed with %d: %s", resetRec.Code, resetRec.Body.String())
	}

	assertFilters("after reset filters.dlp", adminH2, srv2, true, true)
}



