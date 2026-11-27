package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/auth"
	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/types"
	"github.com/FaradAiLab/FaradAiWire/internal/session"
	"github.com/FaradAiLab/FaradAiWire/internal/settings"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
)

type testRoleAuthFilter struct {
	allowedRole string
}

func (f *testRoleAuthFilter) Name() string { return "test_role_auth" }
func (f *testRoleAuthFilter) FilterRequest(ctx context.Context, req *mcp.Request) (*mcp.Request, *mcp.Error) {
	if u, ok := ctx.Value(types.UserContextKey).(*types.UserContext); ok {
		if u.Role == f.allowedRole {
			return req, nil
		}
	}
	return nil, mcp.NewError(mcp.ErrPolicyDenied, "Access denied by policy rules", nil)
}

func newTestIPv4Server(t *testing.T, handler http.Handler) *httptest.Server {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("skipping test requiring loopback socket: %v", err)
		return nil
	}
	ts := &httptest.Server{
		Listener: l,
		Config:   &http.Server{Handler: handler},
	}
	ts.Start()
	return ts
}

func attachTestBearerAuth(t *testing.T, p *SSEProxy, scope ...string) string {
	t.Helper()
	ks := auth.NewMemoryKeyStore()
	agentScope := "*"
	if len(scope) > 0 && scope[0] != "" {
		agentScope = scope[0]
	}
	raw, _, err := ks.GenerateKey("test-client", "Developer", agentScope)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	p.SetKeyValidator(ks)
	return raw
}

func closeTestServer(ts *httptest.Server) {
	if ts != nil {
		ts.CloseClientConnections()
		ts.Close()
	}
}

func TestRoutingModeStrictValidation(t *testing.T) {
	// Create mock agent dirs
	agentDir := "./agents"
	_ = os.MkdirAll(filepath.Join(agentDir, "agg-agent", "current"), 0755)
	_ = os.MkdirAll(filepath.Join(agentDir, "dir-agent", "current"), 0755)

	defer func() {
		_ = os.RemoveAll(agentDir)
	}()

	// 1. Write Aggregated Agent Config
	aggCfg := agent.RouteConfig{
		AgentName:   "agg-agent",
		RoutingMode: "aggregated",
		Protocols: []agent.ProtocolConfig{
			{ID: "proto-1", Name: "triage-core", URLOrCommand: "http://localhost:8081/sse"},
		},
	}
	aggData, _ := json.Marshal(aggCfg)
	_ = os.WriteFile(filepath.Join(agentDir, "agg-agent", "current", "config.json"), aggData, 0644)

	// 2. Write Direct Agent Config
	dirCfg := agent.RouteConfig{
		AgentName:   "dir-agent",
		RoutingMode: "direct",
		Protocols: []agent.ProtocolConfig{
			{ID: "proto-1", Name: "triage-core", URLOrCommand: "http://localhost:8081/sse"},
			{ID: "proto-2", Name: "attack-sim", URLOrCommand: "http://localhost:8082/sse"},
		},
	}
	dirData, _ := json.Marshal(dirCfg)
	_ = os.WriteFile(filepath.Join(agentDir, "dir-agent", "current", "config.json"), dirData, 0644)

	proxy := NewSSEProxy(0, "http://localhost:9090/sse", nil, agent.NewFSRepository(agentDir, ""), nil)

	// Test Case A: Aggregated Mode valid request (/sse/agg-agent)
	reqA := httptest.NewRequest("GET", "/sse/agg-agent", nil)
	urlA, errA := proxy.resolveTargetURL(reqA)
	if errA != nil {
		t.Fatalf("expected valid resolution for aggregated mode, got error: %v", errA)
	}
	if urlA != "http://localhost:8081/sse" {
		t.Errorf("expected target URL 'http://localhost:8081/sse', got '%s'", urlA)
	}

	// Test Case B: Aggregated Mode invalid request (/sse/agg-agent/triage-core) -> should reject
	reqB := httptest.NewRequest("GET", "/sse/agg-agent/triage-core", nil)
	_, errB := proxy.resolveTargetURL(reqB)
	if errB == nil {
		t.Fatalf("expected error when making 2-segment request to aggregated agent")
	}

	// Test Case C: Direct Mode valid request (/sse/dir-agent/triage-core)
	reqC := httptest.NewRequest("GET", "/sse/dir-agent/triage-core", nil)
	urlC, errC := proxy.resolveTargetURL(reqC)
	if errC != nil {
		t.Fatalf("expected valid resolution for direct mode target, got error: %v", errC)
	}
	if urlC != "http://localhost:8081/sse" {
		t.Errorf("expected target URL 'http://localhost:8081/sse', got '%s'", urlC)
	}

	// Test Case D: Direct Mode invalid request (/sse/dir-agent) -> should reject
	reqD := httptest.NewRequest("GET", "/sse/dir-agent", nil)
	_, errD := proxy.resolveTargetURL(reqD)
	if errD == nil {
		t.Fatalf("expected error when making 1-segment request to direct mode agent")
	}

	// Test Case E: Direct Mode invalid protocol (/sse/dir-agent/non-existent) -> should reject
	reqE := httptest.NewRequest("GET", "/sse/dir-agent/non-existent", nil)
	_, errE := proxy.resolveTargetURL(reqE)
	if errE == nil {
		t.Fatalf("expected error when requesting non-existent protocol in direct mode")
	}
}

func TestSSEProxy_AgentScopingAndImplicitRouting(t *testing.T) {
	agentDir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(agentDir, "claude", "current"), 0755)
	_ = os.MkdirAll(filepath.Join(agentDir, "coder", "current"), 0755)

	claudeCfg := agent.RouteConfig{
		AgentName:   "claude",
		RoutingMode: "aggregated",
		Protocols: []agent.ProtocolConfig{
			{ID: "proto-1", Name: "tavily", URLOrCommand: "http://localhost:8081/sse"},
		},
	}
	coderCfg := agent.RouteConfig{
		AgentName:   "coder",
		RoutingMode: "aggregated",
		Protocols: []agent.ProtocolConfig{
			{ID: "proto-2", Name: "github", URLOrCommand: "http://localhost:8082/sse"},
		},
	}
	cData, _ := json.Marshal(claudeCfg)
	_ = os.WriteFile(filepath.Join(agentDir, "claude", "current", "config.json"), cData, 0644)
	cdData, _ := json.Marshal(coderCfg)
	_ = os.WriteFile(filepath.Join(agentDir, "coder", "current", "config.json"), cdData, 0644)

	proxy := NewSSEProxy(0, "", nil, agent.NewFSRepository(agentDir, ""), nil)

	// 1. Implicit routing: Request to /sse with UserContext AgentName="claude"
	req1 := httptest.NewRequest("GET", "/sse", nil)
	req1 = req1.WithContext(context.WithValue(req1.Context(), filter.UserContextKey, &filter.UserContext{
		UserID:    "dev-user",
		Role:      "Developer",
		AgentName: "claude",
	}))
	resolvedAgent, isAgg, err := proxy.checkAggregatedAgent(req1)
	if err != nil {
		t.Fatalf("expected implicit routing to succeed, got: %v", err)
	}
	if !isAgg || resolvedAgent != "claude" {
		t.Errorf("expected auto-routed agent 'claude', got '%s'", resolvedAgent)
	}

	// 2. Explicit matching: Request to /sse/claude with AgentName="claude"
	req2 := httptest.NewRequest("GET", "/sse/claude", nil)
	req2 = req2.WithContext(context.WithValue(req2.Context(), filter.UserContextKey, &filter.UserContext{
		UserID:    "dev-user",
		Role:      "Developer",
		AgentName: "claude",
	}))
	resolvedAgent2, isAgg2, err := proxy.checkAggregatedAgent(req2)
	if err != nil {
		t.Fatalf("expected explicit routing to succeed, got: %v", err)
	}
	if !isAgg2 || resolvedAgent2 != "claude" {
		t.Errorf("expected agent 'claude', got '%s'", resolvedAgent2)
	}

	// 3. Fail-closed: Request to /sse/coder with AgentName="claude" -> should reject with AGENT_ACCESS_DENIED
	req3 := httptest.NewRequest("GET", "/sse/coder", nil)
	req3 = req3.WithContext(context.WithValue(req3.Context(), filter.UserContextKey, &filter.UserContext{
		UserID:    "dev-user",
		Role:      "Developer",
		AgentName: "claude",
	}))
	_, _, err3 := proxy.checkAggregatedAgent(req3)
	if err3 == nil {
		t.Fatalf("expected AGENT_ACCESS_DENIED when accessing /sse/coder with claude key")
	}
	if !strings.Contains(err3.Error(), "AGENT_ACCESS_DENIED") {
		t.Errorf("expected AGENT_ACCESS_DENIED error, got: %v", err3)
	}

	// 4. Wildcard key: Request to /sse/coder with AgentName="*" -> allowed
	req4 := httptest.NewRequest("GET", "/sse/coder", nil)
	req4 = req4.WithContext(context.WithValue(req4.Context(), filter.UserContextKey, &filter.UserContext{
		UserID:    "dev-user",
		Role:      "Developer",
		AgentName: "*",
	}))
	resolvedAgent4, isAgg4, err := proxy.checkAggregatedAgent(req4)
	if err != nil {
		t.Fatalf("expected wildcard access to succeed, got: %v", err)
	}
	if !isAgg4 || resolvedAgent4 != "coder" {
		t.Errorf("expected agent 'coder', got '%s'", resolvedAgent4)
	}
}

func TestSSEProxy_POST_Delegation_And_SimulationHeaders(t *testing.T) {
	// Setup filter with a rule that allows Developer but blocks guest/Customer
	authFilter := &testRoleAuthFilter{allowedRole: "Developer"}

	pipeline := filter.NewPipeline(nil)
	pipeline.SetFilters([]filter.Filter{authFilter})

	// Mock downstream backend server
	mockBackend := newTestIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"sim-1","result":{"content":[{"type":"text","text":"success"}]}}`))
	}))
	defer closeTestServer(mockBackend)

	ks := auth.NewMemoryKeyStore()
	custToken, _, err := ks.GenerateKey("guest-key", "Customer", "*")
	if err != nil {
		t.Fatalf("GenerateKey(Customer): %v", err)
	}
	devToken, _, err := ks.GenerateKey("dev-key", "Developer", "*")
	if err != nil {
		t.Fatalf("GenerateKey(Developer): %v", err)
	}

	proxy := NewSSEProxy(0, mockBackend.URL, pipeline, nil, nil)
	proxy.SetKeyValidator(ks)

	// Test 1: POST to /sse (delegation to handleMessage) with blocked role (Customer key)
	mcpBody := []byte(`{"jsonrpc":"2.0","id":"sim-1","method":"tools/call","params":{"name":"exec_cmd","arguments":{}}}`)
	reqBlocked := httptest.NewRequest("POST", "/sse", bytes.NewReader(mcpBody))
	reqBlocked.Header.Set("Content-Type", "application/json")
	reqBlocked.Header.Set("Authorization", "Bearer "+custToken)
	reqBlocked.RemoteAddr = "127.0.0.1:12345"

	wBlocked := httptest.NewRecorder()
	proxy.Handler().ServeHTTP(wBlocked, reqBlocked)

	var errResp struct {
		JSONRPC string
		ID      string
		Error   struct {
			Code    int
			Message string
		}
	}
	if err := json.Unmarshal(wBlocked.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to parse JSON-RPC error response: %v", err)
	}
	if errResp.Error.Code != mcp.ErrPolicyDenied {
		t.Errorf("expected JSON-RPC error code %d (ErrPolicyDenied), got %d (%s)", mcp.ErrPolicyDenied, errResp.Error.Code, errResp.Error.Message)
	}

	// Test 2: POST to /sse/my-agent (delegation to handleMessage) with allowed role (Developer key)
	reqAllowed := httptest.NewRequest("POST", "/sse/my-agent", bytes.NewReader(mcpBody))
	reqAllowed.Header.Set("Content-Type", "application/json")
	reqAllowed.Header.Set("Authorization", "Bearer "+devToken)
	reqAllowed.RemoteAddr = "127.0.0.1:12345"

	wAllowed := httptest.NewRecorder()
	proxy.Handler().ServeHTTP(wAllowed, reqAllowed)

	if wAllowed.Code != http.StatusOK {
		t.Errorf("expected HTTP 200 OK for allowed simulation, got %d: %s", wAllowed.Code, wAllowed.Body.String())
	}
	var okResp struct {
		JSONRPC string
		ID      string
		Result  interface{}
	}
	if err := json.Unmarshal(wAllowed.Body.Bytes(), &okResp); err != nil {
		t.Fatalf("failed to parse JSON-RPC success response: %v", err)
	}
	if okResp.Result == nil {
		t.Errorf("expected non-nil result for allowed tool call")
	}
}

func TestFlexibleUnmarshalAgentConfig(t *testing.T) {
	// SaaS format with protocol_name, protocol_id, agent_name
	saasJSON := `{
		"agent_id": "agent-123",
		"agent_name": "support-agent",
		"routing_mode": "direct",
		"protocols": [
			{
				"protocol_id": "proto-uuid-1",
				"protocol_name": "dummy-mcp-general",
				"type": "mcp",
				"url_or_command": "http://localhost:9094/sse"
			}
		]
	}`

	var cfg agent.RouteConfig
	if err := json.Unmarshal([]byte(saasJSON), &cfg); err != nil {
		t.Fatalf("failed to unmarshal SaaS config: %v", err)
	}

	if cfg.AgentName != "support-agent" {
		t.Errorf("expected agent name 'support-agent', got '%s'", cfg.AgentName)
	}
	if len(cfg.Protocols) != 1 {
		t.Fatalf("expected 1 protocol, got %d", len(cfg.Protocols))
	}
	if cfg.Protocols[0].Name != "dummy-mcp-general" {
		t.Errorf("expected protocol name 'dummy-mcp-general', got '%s'", cfg.Protocols[0].Name)
	}
	if cfg.Protocols[0].ID != "proto-uuid-1" {
		t.Errorf("expected protocol ID 'proto-uuid-1', got '%s'", cfg.Protocols[0].ID)
	}
	if cfg.Protocols[0].URLOrCommand != "http://localhost:9094/sse" {
		t.Errorf("expected URL 'http://localhost:9094/sse', got '%s'", cfg.Protocols[0].URLOrCommand)
	}
}

func TestSSE_PathPreservingEndpointRewriting(t *testing.T) {
	// Mock backend that returns standard SSE endpoint event
	mockBackend := newTestIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		_, _ = w.Write([]byte("event: endpoint\ndata: /message?sessionId=sess-xyz-999\n\n"))
		if flusher != nil {
			flusher.Flush()
		}
	}))
	defer closeTestServer(mockBackend)

	agentDir := "./agents"
	_ = os.MkdirAll(filepath.Join(agentDir, "qa-agent", "current"), 0755)
	defer os.RemoveAll(agentDir)

	cfg := agent.RouteConfig{
		AgentName:   "qa-agent",
		RoutingMode: "direct",
		Protocols: []agent.ProtocolConfig{
			{ID: "p1", Name: "dummy-mcp", URLOrCommand: mockBackend.URL},
		},
	}
	cfgBytes, _ := json.Marshal(cfg)
	_ = os.WriteFile(filepath.Join(agentDir, "qa-agent", "current", "config.json"), cfgBytes, 0644)
	proxy := NewSSEProxy(0, mockBackend.URL, filter.NewPipeline(nil), agent.NewFSRepository(agentDir, ""), nil)
	tok := attachTestBearerAuth(t, proxy)

	// Connect via /sse/qa-agent/dummy-mcp
	reqCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest("GET", "/sse/qa-agent/dummy-mcp", nil).WithContext(reqCtx)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()

	proxy.handleSSE(rec, req)

	respBody := rec.Body.String()
	expectedEndpoint := "data: /sse/qa-agent/dummy-mcp/message?sessionId=sess-xyz-999"
	if !bytes.Contains([]byte(respBody), []byte(expectedEndpoint)) {
		t.Errorf("expected rewritten SSE endpoint to contain '%s', got '%s'", expectedEndpoint, respBody)
	}

	// Verify sessionTargets mapping in proxy
	proxy.mu.RLock()
	mappedBinding, ok := proxy.sessionTargets["sess-xyz-999"]
	proxy.mu.RUnlock()
	if !ok || mappedBinding.targetURL != mockBackend.URL {
		t.Errorf("expected sessionTargets to contain session 'sess-xyz-999' -> '%s', got '%s'", mockBackend.URL, mappedBinding.targetURL)
	}
}

func TestSSE_DirectAndAggregatedMessageRouting(t *testing.T) {
	var receivedPath string
	mockBackend := newTestIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`))
	}))
	defer closeTestServer(mockBackend)

	agentDir := "./agents"
	_ = os.MkdirAll(filepath.Join(agentDir, "routing-agent", "current"), 0755)
	defer os.RemoveAll(agentDir)

	cfg := agent.RouteConfig{
		AgentName:   "routing-agent",
		RoutingMode: "direct",
		Protocols: []agent.ProtocolConfig{
			{ID: "p1", Name: "backend-mcp", URLOrCommand: mockBackend.URL},
		},
	}
	cfgBytes, _ := json.Marshal(cfg)
	_ = os.WriteFile(filepath.Join(agentDir, "routing-agent", "current", "config.json"), cfgBytes, 0644)

	proxy := NewSSEProxy(0, "http://fallback-8081:8081", filter.NewPipeline(nil), agent.NewFSRepository(agentDir, ""), nil)
	tok := attachTestBearerAuth(t, proxy)

	// POST to /sse/routing-agent/backend-mcp/message
	mcpBody := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test_tool","arguments":{}}}`)
	req := httptest.NewRequest("POST", "/sse/routing-agent/backend-mcp/message", bytes.NewReader(mcpBody))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()

	proxy.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}
	if receivedPath != "/message" {
		t.Errorf("expected backend request path to be '/message', got '%s'", receivedPath)
	}
}

func TestSSE_SessionTargetFallback(t *testing.T) {
	var receivedOnMock bool
	mockBackend := newTestIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedOnMock = true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"session-routed"}]}}`))
	}))
	defer closeTestServer(mockBackend)

	proxy := NewSSEProxy(0, "http://fallback-8081:8081", filter.NewPipeline(nil), nil, nil)
	tok := attachTestBearerAuth(t, proxy)

	// Register session in proxy's sessionTargets map
	proxy.mu.Lock()
	proxy.sessionTargets["active-sess-456"] = sessionBinding{targetURL: mockBackend.URL, timestamp: time.Now()}
	proxy.mu.Unlock()

	// Client sends bare /message?sessionId=active-sess-456
	mcpBody := []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_db","arguments":{}}}`)
	req := httptest.NewRequest("POST", "/message?sessionId=active-sess-456", bytes.NewReader(mcpBody))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()

	proxy.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}
	if !receivedOnMock {
		t.Errorf("expected request to be routed to mock backend via session target fallback")
	}
}

func TestSSE_MaxBytesReader_RejectsHugePayload(t *testing.T) {
	proxy := NewSSEProxy(0, "http://fallback-8081:8081", filter.NewPipeline(nil), nil, nil)
	tok := attachTestBearerAuth(t, proxy)

	// Create a payload larger than 10MB (11MB)
	hugePayload := make([]byte, 11*1024*1024)
	req := httptest.NewRequest("POST", "/message?sessionId=test-huge", bytes.NewReader(hugePayload))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()

	proxy.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected HTTP 400 Bad Request for body exceeding 10MB, got HTTP %d", rec.Code)
	}
}

type pipeResponseWriter struct {
	header     http.Header
	w          *io.PipeWriter
	statusCode int
}

func (p *pipeResponseWriter) Header() http.Header {
	return p.header
}

func (p *pipeResponseWriter) Write(b []byte) (int, error) {
	return p.w.Write(b)
}

func (p *pipeResponseWriter) WriteHeader(statusCode int) {
	p.statusCode = statusCode
}

func (p *pipeResponseWriter) Flush() {}

func TestSSEProxy_ActiveStreamEvictionOnDrain(t *testing.T) {
	agentDir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(agentDir, "drain-agent", "current"), 0755)

	aggCfg := agent.RouteConfig{
		AgentName:   "drain-agent",
		RoutingMode: "aggregated",
		Protocols:   []agent.ProtocolConfig{},
	}
	aggData, _ := json.Marshal(aggCfg)
	_ = os.WriteFile(filepath.Join(agentDir, "drain-agent", "current", "config.json"), aggData, 0644)

	fsRepo := agent.NewFSRepository(agentDir, "")
	proxy := NewSSEProxy(0, "http://localhost:8080", filter.NewPipeline(nil), fsRepo, nil)
	tok := attachTestBearerAuth(t, proxy)

	pr, pw := io.Pipe()
	rw := &pipeResponseWriter{
		header: make(http.Header),
		w:      pw,
	}

	req := httptest.NewRequest("GET", "/sse/drain-agent", nil)
	req.Header.Set("Authorization", "Bearer "+tok)

	handlerDone := make(chan struct{})
	go func() {
		defer close(handlerDone)
		defer pw.Close()
		proxy.Handler().ServeHTTP(rw, req)
	}()

	reader := bufio.NewReader(pr)

	// Read initial endpoint event
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("failed reading endpoint event: %v", err)
		}
		if strings.HasPrefix(line, "event: endpoint") {
			break
		}
	}

	// Active stream is connected. Now trigger DrainActiveStreams!
	drainStart := time.Now()
	proxy.DrainActiveStreams()

	// Read until shutdown event or EOF
	var gotShutdownEvent bool
	var shutdownData string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		if strings.HasPrefix(line, "event: shutdown") {
			gotShutdownEvent = true
		}
		if strings.HasPrefix(line, "data:") && gotShutdownEvent {
			shutdownData = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			break
		}
	}

	select {
	case <-handlerDone:
		// Handler terminated cleanly
	case <-time.After(500 * time.Millisecond):
		t.Fatal("handler did not terminate within 500ms after DrainActiveStreams")
	}

	drainDuration := time.Since(drainStart)
	if drainDuration > 500*time.Millisecond {
		t.Errorf("expected drain duration < 500ms, took %v", drainDuration)
	}

	if !gotShutdownEvent {
		t.Errorf("expected to receive 'event: shutdown'")
	}
	if !strings.Contains(shutdownData, "GATEWAY_DRAINING") {
		t.Errorf("expected shutdown data to contain GATEWAY_DRAINING, got: %s", shutdownData)
	}
}

type mockContextCapturingFilter struct {
	capturedCtx context.Context
}

func (m *mockContextCapturingFilter) Name() string { return "context-capturer" }

func (m *mockContextCapturingFilter) FilterResponse(ctx context.Context, resp *mcp.Response) (*mcp.Response, *mcp.Error) {
	m.capturedCtx = ctx
	return resp, nil
}

func TestSSEProxy_ContextCancellationPropagation(t *testing.T) {
	capFilter := &mockContextCapturingFilter{}
	pipeline := filter.NewPipeline(nil)
	pipeline.SetFilters([]filter.Filter{capFilter})

	proxy := NewSSEProxy(0, "http://localhost:8080", pipeline, nil, nil)

	// 1. Canceled context test:
	// A request whose context has been canceled should abort outgoing SSE message processing early.
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	proxy.CorrelationStore().Put(NewCorrelationKey("sess-canceled", "req-1"), &PendingRequest{
		Context:   cancelCtx,
		Timestamp: time.Now(),
	})

	sseData := `{"jsonrpc":"2.0","id":"req-1","result":{"status":"ok"}}`
	result := proxy.processOutgoingSSEMessage(sseData, "sess-canceled", "")
	if result != "" {
		t.Errorf("expected empty result when context is canceled, got: %s", result)
	}
	if capFilter.capturedCtx != nil {
		t.Errorf("expected filter not to be executed when context is canceled")
	}

	// 2. Active context test:
	// An active request context should propagate to filters and the message should be processed.
	type testCtxKey struct{}
	activeCtx := context.WithValue(context.Background(), testCtxKey{}, "custom-value-xyz")

	proxy.CorrelationStore().Put(NewCorrelationKey("sess-active", "req-2"), &PendingRequest{
		Context:   activeCtx,
		Timestamp: time.Now(),
	})

	sseData2 := `{"jsonrpc":"2.0","id":"req-2","result":{"status":"ok"}}`
	result2 := proxy.processOutgoingSSEMessage(sseData2, "sess-active", "")
	if result2 == "" {
		t.Errorf("expected non-empty processed result for active context")
	}
	if capFilter.capturedCtx == nil {
		t.Fatalf("expected filter to have captured context")
	}
	if val := capFilter.capturedCtx.Value(testCtxKey{}); val != "custom-value-xyz" {
		t.Errorf("expected context value 'custom-value-xyz', got %v", val)
	}
}

func TestSSEProxy_UpstreamPayloadExceeds10MB_Rejected(t *testing.T) {
	// Mock backend that returns an 11 MB response
	backend := newTestIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Write 11 MB of data in chunks
		chunk := bytes.Repeat([]byte("A"), 1024*1024) // 1 MB chunk
		for i := 0; i < 11; i++ {
			_, _ = w.Write(chunk)
		}
	}))
	defer closeTestServer(backend)

	proxy := NewSSEProxy(0, backend.URL, filter.NewPipeline(nil), nil, nil)

	// 1. JSON-RPC request with reqID: must receive JSON-RPC error -32603
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/message", bytes.NewBufferString(`{"jsonrpc":"2.0","method":"tools/call","id":1}`))
	req.Header.Set("Content-Type", "application/json")

	proxy.forwardMessageToBackend(rec, req, context.Background(), backend.URL, "target-sess", "client-sess", []byte(`{"id":1}`), 1, "")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 with JSON-RPC error, got %d", rec.Code)
	}

	var jsonErrResp mcp.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &jsonErrResp); err != nil {
		t.Fatalf("failed to parse response JSON: %v", err)
	}

	if jsonErrResp.Error == nil {
		t.Fatalf("expected non-nil error for payload exceeding 10MB")
	}
	if jsonErrResp.Error.Code != -32603 {
		t.Errorf("expected error code -32603, got %d", jsonErrResp.Error.Code)
	}
	if !strings.Contains(jsonErrResp.Error.Message, "upstream response exceeds 10MB limit") {
		t.Errorf("expected error message to contain 'upstream response exceeds 10MB limit', got '%s'", jsonErrResp.Error.Message)
	}

	// 2. Non-JSON-RPC request (reqID == nil): must receive HTTP 500
	rec500 := httptest.NewRecorder()
	req500 := httptest.NewRequest("POST", "/message", bytes.NewBufferString(`notification`))
	proxy.forwardMessageToBackend(rec500, req500, context.Background(), backend.URL, "target-sess", "client-sess", []byte(`notification`), nil, "")

	if rec500.Code != http.StatusInternalServerError {
		t.Fatalf("expected HTTP 500 for non-JSON-RPC payload exceeding 10MB, got %d", rec500.Code)
	}
	if !strings.Contains(rec500.Body.String(), "upstream response exceeds 10MB limit") {
		t.Errorf("expected response body to contain limit message, got '%s'", rec500.Body.String())
	}
}

func TestSSE_AgentScopedKey_EnforcesAgentTargeting(t *testing.T) {
	keyStore := auth.NewMemoryKeyStore()
	rawKey, _, err := keyStore.GenerateKey("agent-alpha-client", "Developer", "agent-alpha")
	if err != nil {
		t.Fatalf("failed to generate scoped key: %v", err)
	}

	tempDir := t.TempDir()
	repo := agent.NewFSRepository(tempDir, "")

	proxy := NewSSEProxy(0, "http://127.0.0.1:9999", filter.NewPipeline(nil), repo, nil)
	proxy.SetKeyValidator(keyStore)

	// 1. Target different agent via canonical URL path -> 403 AGENT_ACCESS_DENIED
	req := httptest.NewRequest("POST", "/mcp/agent-beta", bytes.NewBufferString(`{"jsonrpc":"2.0","method":"tools/list","id":1}`))
	req.Header.Set("Authorization", "Bearer "+rawKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	proxy.handleMessage(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected HTTP 403 Forbidden for cross-agent key usage, got %d. Body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "AGENT_ACCESS_DENIED") {
		t.Errorf("expected AGENT_ACCESS_DENIED in response body, got: %s", rec.Body.String())
	}

	// 1b. Legacy ?profile= query parameter -> 400 INVALID_ROUTING_PARAMETER
	reqQuery := httptest.NewRequest("POST", "/message?profile=agent-beta", bytes.NewBufferString(`{"jsonrpc":"2.0","method":"tools/list","id":1}`))
	reqQuery.Header.Set("Authorization", "Bearer "+rawKey)
	reqQuery.Header.Set("Content-Type", "application/json")
	recQuery := httptest.NewRecorder()
	proxy.handleMessage(recQuery, reqQuery)
	if recQuery.Code != http.StatusBadRequest || !strings.Contains(recQuery.Body.String(), "INVALID_ROUTING_PARAMETER") {
		t.Fatalf("expected 400 INVALID_ROUTING_PARAMETER for ?profile= query, got %d: %s", recQuery.Code, recQuery.Body.String())
	}

	// 2. Target different agent via SSE endpoint -> 403 AGENT_ACCESS_DENIED
	reqSSE := httptest.NewRequest("GET", "/sse/agent-beta", nil)
	reqSSE.Header.Set("Authorization", "Bearer "+rawKey)
	recSSE := httptest.NewRecorder()

	proxy.handleSSE(recSSE, reqSSE)

	if recSSE.Code != http.StatusForbidden {
		t.Fatalf("expected HTTP 403 Forbidden for cross-agent SSE connection, got %d. Body: %s", recSSE.Code, recSSE.Body.String())
	}
	if !strings.Contains(recSSE.Body.String(), "AGENT_ACCESS_DENIED") {
		t.Errorf("expected AGENT_ACCESS_DENIED in response body, got: %s", recSSE.Body.String())
	}
}

func TestSSE_UnknownAgent_Returns404NotFound(t *testing.T) {
	tempDir := t.TempDir()
	repo := agent.NewFSRepository(tempDir, "")

	proxy := NewSSEProxy(0, "http://127.0.0.1:9999", filter.NewPipeline(nil), repo, nil)
	tok := attachTestBearerAuth(t, proxy)

	// 1. GET /sse/non-existent-agent -> 404 Not Found
	reqSSE := httptest.NewRequest("GET", "/sse/non-existent-agent", nil)
	reqSSE.Header.Set("Authorization", "Bearer "+tok)
	recSSE := httptest.NewRecorder()
	proxy.handleSSE(recSSE, reqSSE)

	if recSSE.Code != http.StatusNotFound {
		t.Fatalf("expected HTTP 404 for unknown agent on SSE, got %d. Body: %s", recSSE.Code, recSSE.Body.String())
	}

	// 2. POST /mcp/non-existent-agent -> 404 Not Found
	reqMsg := httptest.NewRequest("POST", "/mcp/non-existent-agent", bytes.NewBufferString(`{"jsonrpc":"2.0","method":"tools/list","id":1}`))
	reqMsg.Header.Set("Content-Type", "application/json")
	reqMsg.Header.Set("Authorization", "Bearer "+tok)
	recMsg := httptest.NewRecorder()
	proxy.handleMessage(recMsg, reqMsg)

	if recMsg.Code != http.StatusNotFound {
		t.Fatalf("expected HTTP 404 for unknown agent on /message, got %d. Body: %s", recMsg.Code, recMsg.Body.String())
	}
}

func TestSSEProxy_HealthEndpoint(t *testing.T) {
	proxy := NewSSEProxy(0, "http://127.0.0.1:9999", filter.NewPipeline(nil), nil, nil)
	handler := proxy.Handler()

	// 1. GET /health -> 200 OK
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d. Body: %s", rec.Code, rec.Body.String())
	}

	contentType := rec.Header().Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Errorf("expected application/json Content-Type, got %s", contentType)
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to parse health response JSON: %v", err)
	}

	if body["status"] != "ok" {
		t.Errorf("expected status 'ok', got '%s'", body["status"])
	}
	if body["version"] == "" {
		t.Errorf("expected non-empty version")
	}

	// 2. POST /health -> 405 Method Not Allowed with Allow header
	reqPost := httptest.NewRequest(http.MethodPost, "/health", nil)
	recPost := httptest.NewRecorder()
	handler.ServeHTTP(recPost, reqPost)

	if recPost.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected HTTP 405 for POST /health, got %d", recPost.Code)
	}
	if allow := recPost.Header().Get("Allow"); allow != "GET, HEAD" {
		t.Errorf("expected Allow: GET, HEAD on POST /health, got %q", allow)
	}
}

func TestSSEProxy_NewWithCoordinatorPreservesForwarderHTTPClient(t *testing.T) {
	calledCustomTransport := false
	customClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			calledCustomTransport = true
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","id":1,"result":{}}`)),
			}, nil
		}),
	}
	cStore := NewMemoryCorrelationStore()
	fwd := session.NewForwarder(customClient, nil, cStore)
	coord := session.NewInboundCoordinator(nil, nil, nil, nil, nil, cStore, fwd, "http://upstream.example/sse")

	p := NewSSEProxyWithCoordinator(0, "http://upstream.example/sse", coord)
	tok := attachTestBearerAuth(t, p)
	if p.httpClient != nil {
		t.Fatalf("expected p.httpClient to remain nil when custom coordinator is injected")
	}

	req := httptest.NewRequest(http.MethodPost, "/message", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	p.Handler().ServeHTTP(rec, req)

	if !calledCustomTransport {
		t.Fatalf("expected injected coordinator HTTP client transport to be preserved and invoked")
	}
}

func TestSSEProxy_MethodValidationAndHEAD(t *testing.T) {
	agentDir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(agentDir, "agg-head", "current"), 0755)
	cfg := agent.RouteConfig{
		AgentName:   "agg-head",
		RoutingMode: "aggregated",
		Protocols:   []agent.ProtocolConfig{},
	}
	cfgData, _ := json.Marshal(cfg)
	_ = os.WriteFile(filepath.Join(agentDir, "agg-head", "current", "config.json"), cfgData, 0644)

	repo := agent.NewFSRepository(agentDir, "")
	p := NewSSEProxy(0, "http://127.0.0.1:9999", filter.NewPipeline(nil), repo, nil)
	tok := attachTestBearerAuth(t, p)
	h := p.Handler()

	// PUT /sse -> 405 Method Not Allowed with Allow header
	reqPut := httptest.NewRequest(http.MethodPut, "/sse", nil)
	recPut := httptest.NewRecorder()
	h.ServeHTTP(recPut, reqPut)
	if recPut.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for PUT /sse, got %d", recPut.Code)
	}
	if allow := recPut.Header().Get("Allow"); allow != "GET, HEAD, POST" {
		t.Errorf("expected Allow: GET, HEAD, POST on PUT /sse, got %q", allow)
	}

	// DELETE /message -> 405 Method Not Allowed with Allow header
	reqDel := httptest.NewRequest(http.MethodDelete, "/message", nil)
	recDel := httptest.NewRecorder()
	h.ServeHTTP(recDel, reqDel)
	if recDel.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for DELETE /message, got %d", recDel.Code)
	}
	if allow := recDel.Header().Get("Allow"); allow != "POST" {
		t.Errorf("expected Allow: POST on DELETE /message, got %q", allow)
	}

	// HEAD /sse/agg-head -> 200 OK immediately without streaming
	done := make(chan int, 1)
	go func() {
		reqHead := httptest.NewRequest(http.MethodHead, "/sse/agg-head", nil)
		reqHead.Header.Set("Authorization", "Bearer "+tok)
		recHead := httptest.NewRecorder()
		h.ServeHTTP(recHead, reqHead)
		done <- recHead.Code
	}()
	select {
	case code := <-done:
		if code != http.StatusOK {
			t.Fatalf("expected 200 for HEAD /sse/agg-head, got %d", code)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("HEAD /sse/agg-head blocked instead of returning headers")
	}
}

func TestSSEProxy_RejectsCRLFInjectionInSessionOrAgent(t *testing.T) {
	agentDir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(agentDir, "agg-safe", "current"), 0755)
	cfg := agent.RouteConfig{
		AgentName:   "agg-safe",
		RoutingMode: "aggregated",
		Protocols:   []agent.ProtocolConfig{},
	}
	cfgData, _ := json.Marshal(cfg)
	_ = os.WriteFile(filepath.Join(agentDir, "agg-safe", "current", "config.json"), cfgData, 0644)

	repo := agent.NewFSRepository(agentDir, "")
	p := NewSSEProxy(0, "http://127.0.0.1:9999", filter.NewPipeline(nil), repo, nil)
	tok := attachTestBearerAuth(t, p)
	h := p.Handler()

	// 1. CRLF in query sessionId on GET /sse
	reqSSE := httptest.NewRequest(http.MethodGet, "/sse/agg-safe?sessionId=abc%0aevent:%20evil", nil)
	reqSSE.Header.Set("Authorization", "Bearer "+tok)
	recSSE := httptest.NewRecorder()
	h.ServeHTTP(recSSE, reqSSE)
	if recSSE.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for CRLF sessionId on GET /sse, got %d", recSSE.Code)
	}

	// 2. CRLF in Mcp-Session-Id header on POST /mcp/{profile}
	reqMsg := httptest.NewRequest(http.MethodPost, "/mcp/agg-safe", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	reqMsg.Header.Set("Content-Type", "application/json")
	reqMsg.Header.Set("Authorization", "Bearer "+tok)
	reqMsg.Header.Set("Mcp-Session-Id", "sess\r\nevil")
	recMsg := httptest.NewRecorder()
	h.ServeHTTP(recMsg, reqMsg)
	if recMsg.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for CRLF Mcp-Session-Id on POST /mcp, got %d", recMsg.Code)
	}
}

func TestSSEProxy_HandleMessageBridgeSurvivesRequestCompletion(t *testing.T) {
	agentDir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(agentDir, "agg-persist", "current"), 0755)
	cfg := agent.RouteConfig{
		AgentName:   "agg-persist",
		RoutingMode: "aggregated",
		Protocols:   []agent.ProtocolConfig{},
	}
	cfgData, _ := json.Marshal(cfg)
	_ = os.WriteFile(filepath.Join(agentDir, "agg-persist", "current", "config.json"), cfgData, 0644)

	repo := agent.NewFSRepository(agentDir, "")
	mgr := session.NewManager(repo, nil)
	p := NewSSEProxy(0, "http://127.0.0.1:9999", filter.NewPipeline(nil), repo, mgr)
	tok := attachTestBearerAuth(t, p)
	defer func() { _ = p.Shutdown(context.Background()) }()

	reqCtx, cancelReq := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodPost, "/mcp/agg-persist", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)).WithContext(reqCtx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Mcp-Session-Id", "persist-sess-1")
	rec := httptest.NewRecorder()
	p.Handler().ServeHTTP(rec, req)

	// Simulate HTTP POST request completion canceling r.Context()
	cancelReq()

	bridge, ok := mgr.GetBridge("persist-sess-1")
	if !ok || bridge == nil {
		t.Fatalf("expected bridge persist-sess-1 to be created")
	}
	if bridge.BridgeCtx.Err() != nil {
		t.Fatalf("expected bridge context to outlive POST request context, got %v", bridge.BridgeCtx.Err())
	}

	// Shutting down proxy cancels lifecycleCtx and tears down detached bridges
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("unexpected Shutdown error: %v", err)
	}
	if bridge.BridgeCtx.Err() == nil {
		t.Fatalf("expected bridge context to cancel on SSEProxy.Shutdown")
	}
}

func TestSSEProxy_DirectMode_EnforcesScopedAPIKey(t *testing.T) {
	tempAgents := t.TempDir()
	_ = os.MkdirAll(filepath.Join(tempAgents, "alice", "current"), 0755)
	_ = os.WriteFile(filepath.Join(tempAgents, "alice", "current", "config.json"), []byte(`{"agent_name":"alice","routing_mode":"direct","protocols":[{"id":"github","name":"github","type":"http","url_or_command":"http://127.0.0.1:9999/mcp"}]}`), 0600)

	repo := agent.NewFSRepository(tempAgents, "")
	p := NewSSEProxy(0, "http://127.0.0.1:9999", filter.NewPipeline(nil), repo, nil)

	req := httptest.NewRequest(http.MethodGet, "/sse/alice/github", nil)
	req = req.WithContext(context.WithValue(req.Context(), filter.UserContextKey, &filter.UserContext{
		UserID:    "dev",
		Role:      "Developer",
		AgentName: "bob",
	}))
	if _, _, err := p.checkAggregatedAgent(req); err == nil || !strings.Contains(err.Error(), "AGENT_ACCESS_DENIED") {
		t.Fatalf("expected AGENT_ACCESS_DENIED on direct mode path with bob-scoped key, got %v", err)
	}
}

func TestSSEProxy_CanonicalRouting_WildcardGuards_And_DirectMCP(t *testing.T) {
	backendCalls := 0
	mockBackend := newTestIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalls++
		if r.URL.Query().Get("profile") != "" || r.URL.Query().Get("agent") != "" {
			t.Errorf("legacy routing query leaked to upstream: %s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`))
	}))
	defer closeTestServer(mockBackend)

	tempAgents := t.TempDir()
	for _, name := range []string{"alpha", "mcp", "message"} {
		_ = os.MkdirAll(filepath.Join(tempAgents, name, "current"), 0755)
		mode := "direct"
		if name == "mcp" || name == "message" {
			mode = "aggregated"
		}
		cfg := fmt.Sprintf(`{"agent_name":%q,"routing_mode":%q,"protocols":[{"id":"github","name":"github","type":"http","url_or_command":%q}]}`, name, mode, mockBackend.URL+"/mcp")
		_ = os.WriteFile(filepath.Join(tempAgents, name, "current", "config.json"), []byte(cfg), 0600)
	}

	repo := agent.NewFSRepository(tempAgents, "")
	p := NewSSEProxy(0, "", filter.NewPipeline(nil), repo, nil)
	tok := attachTestBearerAuth(t, p) // wildcard "*" key
	h := p.Handler()

	// 1. Legacy ?profile= or ?agent= (including empty values) rejected with 400 INVALID_ROUTING_PARAMETER
	for _, path := range []string{"/sse/alpha/github?profile=alpha", "/mcp/alpha/github?agent=alpha", "/sse/alpha/github?profile=", "/mcp/alpha/github?agent="} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "INVALID_ROUTING_PARAMETER") {
			t.Fatalf("expected 400 INVALID_ROUTING_PARAMETER for %s, got %d: %s", path, rec.Code, rec.Body.String())
		}
	}

	// 2. Wildcard (*) key on root /sse and /mcp -> 400 PROFILE_REQUIRED (even with legacy X-FaradAiWire-Profile header)
	reqRootSSE := httptest.NewRequest(http.MethodGet, "/sse", nil)
	reqRootSSE.Header.Set("Authorization", "Bearer "+tok)
	reqRootSSE.Header.Set("X-FaradAiWire-Profile", "mcp")
	recRootSSE := httptest.NewRecorder()
	h.ServeHTTP(recRootSSE, reqRootSSE)
	if recRootSSE.Code != http.StatusBadRequest || !strings.Contains(recRootSSE.Body.String(), "PROFILE_REQUIRED") {
		t.Fatalf("expected 400 PROFILE_REQUIRED on root GET /sse, got %d: %s", recRootSSE.Code, recRootSSE.Body.String())
	}

	reqRootMCP := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	reqRootMCP.Header.Set("Content-Type", "application/json")
	reqRootMCP.Header.Set("Authorization", "Bearer "+tok)
	reqRootMCP.Header.Set("X-FaradAiWire-Profile", "mcp")
	recRootMCP := httptest.NewRecorder()
	h.ServeHTTP(recRootMCP, reqRootMCP)
	if recRootMCP.Code != http.StatusBadRequest || !strings.Contains(recRootMCP.Body.String(), "PROFILE_REQUIRED") {
		t.Fatalf("expected 400 PROFILE_REQUIRED on root POST /mcp, got %d: %s", recRootMCP.Code, recRootMCP.Body.String())
	}

	// 3. Direct-mode single-segment POST /mcp/{direct_profile} -> 400 ROUTING_VIOLATION_DIRECT
	reqDirBad := httptest.NewRequest(http.MethodPost, "/mcp/alpha", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	reqDirBad.Header.Set("Content-Type", "application/json")
	reqDirBad.Header.Set("Authorization", "Bearer "+tok)
	recDirBad := httptest.NewRecorder()
	h.ServeHTTP(recDirBad, reqDirBad)
	if recDirBad.Code != http.StatusBadRequest || !strings.Contains(recDirBad.Body.String(), "ROUTING_VIOLATION_DIRECT") {
		t.Fatalf("expected 400 ROUTING_VIOLATION_DIRECT on POST /mcp/alpha, got %d: %s", recDirBad.Code, recDirBad.Body.String())
	}

	// 4. Direct-mode two-segment POST /mcp/{profile}/{tool_source} -> 200 OK
	reqDirOK := httptest.NewRequest(http.MethodPost, "/mcp/alpha/github", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}`))
	reqDirOK.Header.Set("Content-Type", "application/json")
	reqDirOK.Header.Set("Authorization", "Bearer "+tok)
	recDirOK := httptest.NewRecorder()
	h.ServeHTTP(recDirOK, reqDirOK)
	if recDirOK.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on POST /mcp/alpha/github, got %d: %s", recDirOK.Code, recDirOK.Body.String())
	}

	// 5. Wildcard (*) key on Direct SSE POST /message?sessionId=<bound> stays intact
	p.SetSessionTarget("direct-sess-77", mockBackend.URL, time.Now())
	reqDirectSess := httptest.NewRequest(http.MethodPost, "/message?sessionId=direct-sess-77", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}`))
	reqDirectSess.Header.Set("Content-Type", "application/json")
	reqDirectSess.Header.Set("Authorization", "Bearer "+tok)
	recDirectSess := httptest.NewRecorder()
	h.ServeHTTP(recDirectSess, reqDirectSess)
	if recDirectSess.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for bound Direct SSE /message?sessionId=..., got %d: %s", recDirectSess.Code, recDirectSess.Body.String())
	}

	// 6. Profiles literally named "mcp" and "message" resolve cleanly without suffix-trimming bugs
	for _, literalName := range []string{"mcp", "message"} {
		reqLit := httptest.NewRequest(http.MethodPost, "/mcp/"+literalName, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}`))
		reqLit.Header.Set("Content-Type", "application/json")
		reqLit.Header.Set("Authorization", "Bearer "+tok)
		recLit := httptest.NewRecorder()
		h.ServeHTTP(recLit, reqLit)
		if recLit.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for profile named %q at /mcp/%s, got %d: %s", literalName, literalName, recLit.Code, recLit.Body.String())
		}
	}

	if backendCalls < 4 {
		t.Errorf("expected at least 4 backend calls, got %d", backendCalls)
	}
}

func TestDirectMode_ScopedKey_MessageCallbackPreserved(t *testing.T) {
	var backendCalls int
	mockBackend := newTestIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalls++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`))
	}))
	defer closeTestServer(mockBackend)

	tempAgents := t.TempDir()
	_ = os.MkdirAll(filepath.Join(tempAgents, "alpha", "current"), 0755)
	cfg := fmt.Sprintf(`{"agent_name":"alpha","routing_mode":"direct","protocols":[{"id":"github","name":"github","type":"http","url_or_command":%q}]}`, mockBackend.URL+"/mcp")
	_ = os.WriteFile(filepath.Join(tempAgents, "alpha", "current", "config.json"), []byte(cfg), 0600)

	repo := agent.NewFSRepository(tempAgents, "")
	p := NewSSEProxy(0, "", filter.NewPipeline(nil), repo, nil)
	scopedTok := attachTestBearerAuth(t, p, "alpha")
	h := p.Handler()

	// 1. Registered Direct-mode session callback POST /message?sessionId=<sid> succeeds even with scoped key
	p.SetSessionTarget("direct-scoped-1", mockBackend.URL+"/mcp", time.Now())
	reqCallback := httptest.NewRequest(http.MethodPost, "/message?sessionId=direct-scoped-1", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}`))
	reqCallback.Header.Set("Content-Type", "application/json")
	reqCallback.Header.Set("Authorization", "Bearer "+scopedTok)
	recCallback := httptest.NewRecorder()
	h.ServeHTTP(recCallback, reqCallback)
	if recCallback.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for bound Direct SSE /message?sessionId=... with scoped key, got %d: %s", recCallback.Code, recCallback.Body.String())
	}

	// 2. Unbound POST /message?sessionId=unknown fails closed with 400 ROUTING_VIOLATION_DIRECT
	reqUnknown := httptest.NewRequest(http.MethodPost, "/message?sessionId=unknown", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	reqUnknown.Header.Set("Content-Type", "application/json")
	reqUnknown.Header.Set("Authorization", "Bearer "+scopedTok)
	recUnknown := httptest.NewRecorder()
	h.ServeHTTP(recUnknown, reqUnknown)
	if recUnknown.Code != http.StatusBadRequest || !strings.Contains(recUnknown.Body.String(), "ROUTING_VIOLATION_DIRECT") {
		t.Fatalf("expected 400 ROUTING_VIOLATION_DIRECT for unbound /message with Direct scoped key, got %d: %s", recUnknown.Code, recUnknown.Body.String())
	}

	// 3. Single-segment POST /mcp/alpha still rejects with 400 ROUTING_VIOLATION_DIRECT
	reqSingleMCP := httptest.NewRequest(http.MethodPost, "/mcp/alpha", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	reqSingleMCP.Header.Set("Content-Type", "application/json")
	reqSingleMCP.Header.Set("Authorization", "Bearer "+scopedTok)
	recSingleMCP := httptest.NewRecorder()
	h.ServeHTTP(recSingleMCP, reqSingleMCP)
	if recSingleMCP.Code != http.StatusBadRequest || !strings.Contains(recSingleMCP.Body.String(), "ROUTING_VIOLATION_DIRECT") {
		t.Fatalf("expected 400 ROUTING_VIOLATION_DIRECT for single-segment POST /mcp/alpha, got %d: %s", recSingleMCP.Code, recSingleMCP.Body.String())
	}

	if backendCalls != 1 {
		t.Errorf("expected 1 backend call, got %d", backendCalls)
	}
}

func TestSSEProxy_ReadRequestBody_HonorsLiveMaxPayloadBytes(t *testing.T) {
	t.Parallel()

	sCache := settings.NewCache(nil)
	eff := sCache.Get().Clone()
	eff.Limits.MaxPayloadBytes = 1024
	sCache.Update(eff)

	p := NewSSEProxyWithCoordinator(0, "", nil)
	p.SetSettingsCache(sCache)

	// 2048-byte body exceeds 1024-byte limit
	oversizeReq := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(strings.Repeat("a", 2048)))
	oversizeRec := httptest.NewRecorder()
	if _, ok := p.readRequestBody(oversizeRec, oversizeReq); ok {
		t.Fatal("expected readRequestBody to reject 2048-byte body when MaxPayloadBytes=1024")
	}
	if oversizeRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d", oversizeRec.Code)
	}

	// Updating settingsCache live allows the 2048-byte body without restart
	eff2 := eff.Clone()
	eff2.Limits.MaxPayloadBytes = 4096
	sCache.Update(eff2)

	okReq := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(strings.Repeat("a", 2048)))
	okRec := httptest.NewRecorder()
	body, ok := p.readRequestBody(okRec, okReq)
	if !ok || len(body) != 2048 {
		t.Fatalf("expected readRequestBody to accept 2048-byte body after live limit bump, got ok=%v len=%d", ok, len(body))
	}
}
