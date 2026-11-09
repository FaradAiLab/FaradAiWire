package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
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
	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/types"
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

	proxy := NewSSEProxy(0, "http://localhost:9090/sse", nil, agent.NewFSRepository(agentDir, ""), nil, config.UserContextConfig{})

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

	proxy := NewSSEProxy(0, "", nil, agent.NewFSRepository(agentDir, ""), nil, config.UserContextConfig{})

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

	uCtxCfg := config.UserContextConfig{
		FallbackRole:   "Customer",
		FallbackUser:   "guest",
		TrustedProxies: []string{"127.0.0.1/32", "10.0.0.0/8"},
	}

	proxy := NewSSEProxy(0, mockBackend.URL, pipeline, nil, nil, uCtxCfg)

	// Test 1: POST to /sse (delegation to handleMessage) with blocked role (Customer)
	mcpBody := []byte(`{"jsonrpc":"2.0","id":"sim-1","method":"tools/call","params":{"name":"exec_cmd","arguments":{}}}`)
	reqBlocked := httptest.NewRequest("POST", "/sse", bytes.NewReader(mcpBody))
	reqBlocked.Header.Set("Content-Type", "application/json")
	reqBlocked.Header.Set("X-User-Role", "Customer")
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

	// Test 2: POST to /sse/my-agent (delegation to handleMessage) with allowed role (Developer)
	reqAllowed := httptest.NewRequest("POST", "/sse/my-agent", bytes.NewReader(mcpBody))
	reqAllowed.Header.Set("Content-Type", "application/json")
	reqAllowed.Header.Set("X-User-Role", "Developer")
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
	proxy := NewSSEProxy(0, mockBackend.URL, filter.NewPipeline(nil), agent.NewFSRepository(agentDir, ""), nil, config.UserContextConfig{})

	// Connect via /sse/qa-agent/dummy-mcp
	reqCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest("GET", "/sse/qa-agent/dummy-mcp", nil).WithContext(reqCtx)
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

	proxy := NewSSEProxy(0, "http://fallback-8081:8081", filter.NewPipeline(nil), agent.NewFSRepository(agentDir, ""), nil, config.UserContextConfig{})

	// POST to /sse/routing-agent/backend-mcp/message
	mcpBody := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test_tool","arguments":{}}}`)
	req := httptest.NewRequest("POST", "/sse/routing-agent/backend-mcp/message", bytes.NewReader(mcpBody))
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

	proxy := NewSSEProxy(0, "http://fallback-8081:8081", filter.NewPipeline(nil), nil, nil, config.UserContextConfig{})

	// Register session in proxy's sessionTargets map
	proxy.mu.Lock()
	proxy.sessionTargets["active-sess-456"] = sessionBinding{targetURL: mockBackend.URL, timestamp: time.Now()}
	proxy.mu.Unlock()

	// Client sends bare /message?sessionId=active-sess-456
	mcpBody := []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_db","arguments":{}}}`)
	req := httptest.NewRequest("POST", "/message?sessionId=active-sess-456", bytes.NewReader(mcpBody))
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
	proxy := NewSSEProxy(0, "http://fallback-8081:8081", filter.NewPipeline(nil), nil, nil, config.UserContextConfig{})

	// Create a payload larger than 10MB (11MB)
	hugePayload := make([]byte, 11*1024*1024)
	req := httptest.NewRequest("POST", "/message?sessionId=test-huge", bytes.NewReader(hugePayload))
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
	proxy := NewSSEProxy(0, "http://localhost:8080", filter.NewPipeline(nil), fsRepo, nil, config.UserContextConfig{})

	pr, pw := io.Pipe()
	rw := &pipeResponseWriter{
		header: make(http.Header),
		w:      pw,
	}

	req := httptest.NewRequest("GET", "/sse/drain-agent", nil)

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

	proxy := NewSSEProxy(0, "http://localhost:8080", pipeline, nil, nil, config.UserContextConfig{})

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

	proxy := NewSSEProxy(0, backend.URL, filter.NewPipeline(nil), nil, nil, config.UserContextConfig{})

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

	proxy := NewSSEProxy(0, "http://127.0.0.1:9999", filter.NewPipeline(nil), repo, nil, config.UserContextConfig{})
	proxy.SetKeyValidator(keyStore)

	// 1. Target different agent via query param -> 403 AGENT_ACCESS_DENIED
	req := httptest.NewRequest("POST", "/message?profile=agent-beta", bytes.NewBufferString(`{"jsonrpc":"2.0","method":"tools/list","id":1}`))
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

	proxy := NewSSEProxy(0, "http://127.0.0.1:9999", filter.NewPipeline(nil), repo, nil, config.UserContextConfig{})

	// 1. GET /sse/non-existent-agent -> 404 Not Found
	reqSSE := httptest.NewRequest("GET", "/sse/non-existent-agent", nil)
	recSSE := httptest.NewRecorder()
	proxy.handleSSE(recSSE, reqSSE)

	if recSSE.Code != http.StatusNotFound {
		t.Fatalf("expected HTTP 404 for unknown agent on SSE, got %d. Body: %s", recSSE.Code, recSSE.Body.String())
	}

	// 2. POST /message?profile=non-existent-agent -> 404 Not Found
	reqMsg := httptest.NewRequest("POST", "/message?profile=non-existent-agent", bytes.NewBufferString(`{"jsonrpc":"2.0","method":"tools/list","id":1}`))
	reqMsg.Header.Set("Content-Type", "application/json")
	recMsg := httptest.NewRecorder()
	proxy.handleMessage(recMsg, reqMsg)

	if recMsg.Code != http.StatusNotFound {
		t.Fatalf("expected HTTP 404 for unknown agent on /message, got %d. Body: %s", recMsg.Code, recMsg.Body.String())
	}
}

func TestSSEProxy_HealthEndpoint(t *testing.T) {
	proxy := NewSSEProxy(0, "http://127.0.0.1:9999", filter.NewPipeline(nil), nil, nil, config.UserContextConfig{})
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

	// 2. POST /health -> 405 Method Not Allowed
	reqPost := httptest.NewRequest(http.MethodPost, "/health", nil)
	recPost := httptest.NewRecorder()
	handler.ServeHTTP(recPost, reqPost)

	if recPost.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected HTTP 405 for POST /health, got %d", recPost.Code)
	}
}




