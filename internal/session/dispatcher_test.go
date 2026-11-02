package session

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
)

// newMockStreamableHTTPServer creates a mock Streamable HTTP JSON-RPC server for testing.
func newMockStreamableHTTPServer(t *testing.T) *httptest.Server {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("skipping test requiring loopback socket: %v", err)
	}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		var rpc struct {
			JSONRPC string          `json:"jsonrpc"`
			Method  string          `json:"method"`
			ID      interface{}     `json:"id"`
			Params  json.RawMessage `json:"params"`
		}
		json.NewDecoder(r.Body).Decode(&rpc)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      rpc.ID,
			"result": map[string]interface{}{
				"content": []map[string]interface{}{
					{"type": "text", "text": "Mock tool result"},
				},
			},
		})
	}))
	ts.Listener = l
	ts.Start()
	return ts
}

// newMockStreamableHTTPServerWithHeaderCapture creates a mock server that captures auth and custom headers.
func newMockStreamableHTTPServerWithHeaderCapture(t *testing.T, receivedAuth, receivedCustom *string) *httptest.Server {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("skipping test requiring loopback socket: %v", err)
	}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*receivedAuth = r.Header.Get("Authorization")
		*receivedCustom = r.Header.Get("X-Custom-Api-Key")

		var rpc struct {
			ID interface{} `json:"id"`
		}
		json.NewDecoder(r.Body).Decode(&rpc)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      rpc.ID,
			"result":  map[string]interface{}{"content": []map[string]interface{}{{"type": "text", "text": "ok"}}},
		})
	}))
	ts.Listener = l
	ts.Start()
	return ts
}

type mockDispatcherRepo struct {
	configs   map[string]*agent.RouteConfig
	manifests map[string][]agent.ToolMetadata
	tools     map[string]*agent.ToolTargetInfo
}

func (m *mockDispatcherRepo) GetAgentConfig(agentName string) (*agent.RouteConfig, error) {
	if cfg, ok := m.configs[agentName]; ok {
		return cfg, nil
	}
	return nil, agent.NewAgentNotFoundError(agentName)
}

func (m *mockDispatcherRepo) GetAgentManifest(agentName string) ([]agent.ToolMetadata, error) {
	if man, ok := m.manifests[agentName]; ok {
		return man, nil
	}
	return nil, agent.ErrManifestNotFound
}

func (m *mockDispatcherRepo) ResolveToolProtocol(agentName, toolName string) (*agent.ToolTargetInfo, error) {
	key := agentName + ":" + toolName
	if t, ok := m.tools[key]; ok {
		return t, nil
	}
	return nil, nil
}

func (m *mockDispatcherRepo) ResolveTargetURLFromPath(path string, defaultTargetURL string) (string, error) {
	return defaultTargetURL, nil
}

func (m *mockDispatcherRepo) ListAgents() ([]string, error) {
	return nil, nil
}

func (m *mockDispatcherRepo) GetDefaultAgent() (*agent.RouteConfig, error) {
	return nil, nil
}

func (m *mockDispatcherRepo) ClearCache() {}
func (m *mockDispatcherRepo) SaveAgentConfig(agentName string, cfg *agent.RouteConfig) error { return nil }
func (m *mockDispatcherRepo) DeleteAgent(agentName string) error { return nil }
func (m *mockDispatcherRepo) SaveAgentManifest(agentName string, tools interface{}) error { return nil }
func (m *mockDispatcherRepo) ListAgentArchives(agentName string) ([]string, error) { return nil, nil }
func (m *mockDispatcherRepo) RollbackAgent(agentName, timestamp string) error { return nil }
func (m *mockDispatcherRepo) ArchiveAgentCurrent(agentName string) error { return nil }

func TestSessionToolDispatcher_RemoteToolRouting(t *testing.T) {
	repo := &mockDispatcherRepo{
		configs: map[string]*agent.RouteConfig{
			"agent-remote": {
				AgentName: "agent-remote",
				Protocols: []agent.ProtocolConfig{
					{ID: "proto-corp", Name: "corp-mcp", URLOrCommand: "http://corp-gw/sse"},
				},
			},
		},
		tools: map[string]*agent.ToolTargetInfo{
			"agent-remote:query_db": {
				ProtocolID:   "proto-corp",
				ProtocolName: "corp-mcp",
				TargetURL:    "http://corp-gw/sse",
				ToolName:     "query_db",
				Type:         "sse",
				AuthToken:    "secret-corp-token",
			},
		},
	}

	dispatcher := NewToolDispatcher(repo, nil)

	bridge := &AgentSessionBridge{
		ClientSessionID: "cl-1",
		AgentName:       "agent-remote",
		Upstreams:       make(map[string]*UpstreamSession),
	}
	bridge.SetUpstream("proto-corp", &UpstreamSession{
		ProtocolID:       "proto-corp",
		ProtocolName:     "corp-mcp",
		URLOrCommand:     "http://corp-gw/sse",
		BackendSessionID: "sess-corp-999",
		Status:           "READY",
		LastPing:         time.Now(),
	})

	req := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"query_db","arguments":{}}`),
		ID:      "req-1",
	}

	result, err := dispatcher.DispatchTool(context.Background(), "agent-remote", "query_db", req, nil, bridge)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.ExecutedLocally {
		t.Errorf("expected remote tool, got ExecutedLocally == true")
	}
	if result.TargetURL != "http://corp-gw/sse" {
		t.Errorf("expected TargetURL 'http://corp-gw/sse', got '%s'", result.TargetURL)
	}
	if result.TargetSessionID != "sess-corp-999" {
		t.Errorf("expected TargetSessionID 'sess-corp-999', got '%s'", result.TargetSessionID)
	}
	if result.AuthToken != "secret-corp-token" {
		t.Errorf("expected AuthToken 'secret-corp-token', got '%s'", result.AuthToken)
	}
}

func TestSessionToolDispatcher_UnresolvedTool(t *testing.T) {
	repo := &mockDispatcherRepo{
		configs: map[string]*agent.RouteConfig{},
		tools:   map[string]*agent.ToolTargetInfo{},
	}

	dispatcher := NewToolDispatcher(repo, nil)
	result, err := dispatcher.DispatchTool(context.Background(), "any", "unknown", nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ExecutedLocally {
		t.Errorf("expected ExecutedLocally == false for unresolved tool")
	}
}

func TestSessionToolDispatcher_AllowedTools_ZeroTrustRejection(t *testing.T) {
	repo := &mockDispatcherRepo{
		configs: map[string]*agent.RouteConfig{
			"agent-secure": {
				AgentName: "agent-secure",
				Protocols: []agent.ProtocolConfig{
					{
						ID:           "sec-proto",
						Name:         "sec",
						AllowedTools: []string{"safe_read"},
					},
				},
			},
		},
		tools: map[string]*agent.ToolTargetInfo{
			"agent-secure:sec__dangerous_delete": {
				ProtocolName: "sec",
				ToolName:     "dangerous_delete",
				AllowedTools: []string{"safe_read"},
			},
			"agent-secure:sec__safe_read": {
				ProtocolName: "sec",
				ToolName:     "safe_read",
				AllowedTools: []string{"safe_read"},
				TargetURL:    "http://mock-gw/sse",
			},
		},
	}

	dispatcher := NewToolDispatcher(repo, nil)

	// 1. Invoking forbidden tool returns ExecutedLocally == true with -32004 security error
	badReq := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"sec__dangerous_delete"}`),
		ID:      "bad-1",
	}

	res, err := dispatcher.DispatchTool(context.Background(), "agent-secure", "sec__dangerous_delete", badReq, nil, nil)
	if err != nil {
		t.Fatalf("unexpected dispatch error: %v", err)
	}
	if !res.ExecutedLocally {
		t.Fatalf("expected ExecutedLocally == true for security interception")
	}
	if res.Response == nil || res.Response.Error == nil {
		t.Fatalf("expected Error response, got nil")
	}
	if res.Response.Error.Code != -32004 {
		t.Errorf("expected error code -32004, got %d", res.Response.Error.Code)
	}

	// 2. Invoking allowed tool proceeds normally
	goodReq := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"sec__safe_read"}`),
		ID:      "good-1",
	}
	goodRes, err := dispatcher.DispatchTool(context.Background(), "agent-secure", "sec__safe_read", goodReq, nil, nil)
	if err != nil {
		t.Fatalf("unexpected dispatch error: %v", err)
	}
	if goodRes.Response != nil && goodRes.Response.Error != nil && goodRes.Response.Error.Code == -32004 {
		t.Errorf("allowed tool was incorrectly blocked")
	}
}

func TestSessionToolDispatcher_Layer2_AgentToolScopingRejection(t *testing.T) {
	repo := &mockDispatcherRepo{
		configs: map[string]*agent.RouteConfig{
			"agent-scoped": {
				AgentName:    "agent-scoped",
				EnabledTools: []string{"read_query"}, // Layer 2 allows read_query, blocks write_query
				Protocols: []agent.ProtocolConfig{
					{
						Name:         "db",
						AllowedTools: []string{"read_query", "write_query"}, // Layer 1 allows both
					},
				},
			},
		},
		tools: map[string]*agent.ToolTargetInfo{
			"agent-scoped:db__write_query": {
				ProtocolName: "db",
				ToolName:     "write_query",
				AllowedTools: []string{"read_query", "write_query"}, // Allowed by protocol
			},
			"agent-scoped:db__read_query": {
				ProtocolName: "db",
				ToolName:     "read_query",
				AllowedTools: []string{"read_query", "write_query"}, // Allowed by protocol
				TargetURL:    "http://mock-gw/sse",
			},
		},
	}

	dispatcher := NewToolDispatcher(repo, nil)

	// write_query is allowed by protocol (Layer 1) but forbidden by agent EnabledTools (Layer 2)
	badReq := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"db__write_query"}`),
		ID:      "bad-layer2",
	}

	res, err := dispatcher.DispatchTool(context.Background(), "agent-scoped", "db__write_query", badReq, nil, nil)
	if err != nil {
		t.Fatalf("unexpected dispatch error: %v", err)
	}
	if !res.ExecutedLocally {
		t.Fatalf("expected ExecutedLocally == true for Layer 2 security interception")
	}
	if res.Response == nil || res.Response.Error == nil {
		t.Fatalf("expected Error response, got nil")
	}
	if res.Response.Error.Code != -32004 {
		t.Errorf("expected error code -32004, got %d", res.Response.Error.Code)
	}

	// read_query is allowed by both Layer 1 and Layer 2
	goodReq := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"db__read_query"}`),
		ID:      "good-layer2",
	}

	goodRes, err := dispatcher.DispatchTool(context.Background(), "agent-scoped", "db__read_query", goodReq, nil, nil)
	if err != nil {
		t.Fatalf("unexpected dispatch error: %v", err)
	}
	if goodRes.Response != nil && goodRes.Response.Error != nil && goodRes.Response.Error.Code == -32004 {
		t.Errorf("allowed tool was incorrectly blocked: %v", goodRes.Response.Error)
	}
}

// ========== STUDIO-010: Unified Upstream Session Bridge for Streamable HTTP ==========

func TestStreamableHTTPDialer_Dial(t *testing.T) {
	dialer := NewStreamableHTTPDialer()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proto := agent.ProtocolConfig{
		ID:           "context7",
		Name:         "Context7",
		Type:         "http",
		URLOrCommand: "https://mcp.context7.com/mcp",
		AuthToken:    "test-token-123",
		Headers:      map[string]string{"X-Custom": "value"},
	}

	eventCh := make(chan SSEEvent, 10)
	upSess := dialer.Dial(ctx, proto, eventCh, "test-session", nil)

	if upSess == nil {
		t.Fatal("expected non-nil upstream session")
	}
	if upSess.GetStatus() != "READY" {
		t.Errorf("expected READY status, got %s", upSess.GetStatus())
	}
	if !upSess.IsStreamableHTTP() {
		t.Error("expected IsStreamableHTTP() to return true")
	}
	if upSess.IsStdio() {
		t.Error("expected IsStdio() to return false")
	}
	if upSess.AuthToken != "test-token-123" {
		t.Errorf("expected auth token, got %s", upSess.AuthToken)
	}
	if upSess.Headers["X-Custom"] != "value" {
		t.Errorf("expected custom header, got %v", upSess.Headers)
	}
}

func TestStreamableHTTPDialer_DialInvalidURL(t *testing.T) {
	dialer := NewStreamableHTTPDialer()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	testCases := []struct {
		name string
		url  string
	}{
		{"MalformedSyntax", "://invalid-url"},
		{"UnsupportedScheme", "ftp://example.com/mcp"},
		{"SchemelessURL", "example.com/mcp"},
		{"EmptyHost", "http://"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			proto := agent.ProtocolConfig{
				ID:           "bad",
				Name:         "BadURL",
				Type:         "http",
				URLOrCommand: tc.url,
			}

			upSess := dialer.Dial(ctx, proto, nil, "test-session", nil)
			if upSess.GetStatus() != "DEGRADED" {
				t.Errorf("[%s] expected DEGRADED for URL '%s', got %s", tc.name, tc.url, upSess.GetStatus())
			}
		})
	}
}

func TestCallToolHTTP_NilClientFailFast(t *testing.T) {
	upSess := &UpstreamSession{
		ProtocolID:   "test-nil",
		ProtocolName: "TestNil",
		URLOrCommand: "http://example.com/mcp",
		Type:         "http",
		Status:       "READY",
	}

	req := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		ID:      "nil-call",
	}

	// Must fail-fast with error and NOT panic
	resp, err := upSess.CallToolHTTP(context.Background(), nil, req)
	if err == nil {
		t.Fatal("expected error when passing nil http.Client, got nil")
	}
	if resp != nil {
		t.Errorf("expected nil response on nil client error, got %v", resp)
	}
}

func TestCallToolHTTP_MultiLineSSEResponse(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("skipping test requiring loopback socket: %v", err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		// Multi-line data stream
		_, _ = w.Write([]byte("event: message\n"))
		_, _ = w.Write([]byte("data: {\n"))
		_, _ = w.Write([]byte("data:   \"jsonrpc\": \"2.0\",\n"))
		_, _ = w.Write([]byte("data:   \"id\": \"multi-1\",\n"))
		_, _ = w.Write([]byte("data:   \"result\": {\"content\": [{\"type\": \"text\", \"text\": \"multiline-success\"}]}\n"))
		_, _ = w.Write([]byte("data: }\n\n"))
	}))
	server.Listener = l
	server.Start()
	defer server.Close()

	upSess := &UpstreamSession{
		ProtocolID:   "multi-sse",
		ProtocolName: "MultiSSE",
		URLOrCommand: server.URL,
		Type:         "http",
		Status:       "READY",
	}

	req := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		ID:      "multi-1",
	}

	resp, err := upSess.CallToolHTTP(context.Background(), server.Client(), req)
	if err != nil {
		t.Fatalf("unexpected error parsing multi-line SSE response: %v", err)
	}
	if resp == nil || resp.Result == nil {
		t.Fatal("expected non-nil result from multi-line SSE")
	}
	if !strings.Contains(string(resp.Result), "multiline-success") {
		t.Errorf("expected 'multiline-success' in result, got: %s", string(resp.Result))
	}
}

func TestCallToolHTTP_Success(t *testing.T) {
	// Mock Streamable HTTP server
	upstream := newMockStreamableHTTPServer(t)
	defer upstream.Close()

	upSess := &UpstreamSession{
		ProtocolID:   "test-http",
		ProtocolName: "TestHTTP",
		URLOrCommand: upstream.URL + "/mcp",
		Type:         "http",
		AuthToken:    "test-bearer-token",
		Headers:      map[string]string{"X-Api-Key": "secret123"},
		Status:       "READY",
		LastPing:     time.Now(),
	}

	req := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"resolve","arguments":{"libraryName":"react"}}`),
		ID:      "call-1",
	}

	resp, err := upSess.CallToolHTTP(context.Background(), upstream.Client(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Error != nil {
		t.Fatalf("unexpected JSON-RPC error: %v", resp.Error)
	}
}

func TestCallToolHTTP_CredentialInjection(t *testing.T) {
	var receivedAuth string
	var receivedCustom string

	upstream := newMockStreamableHTTPServerWithHeaderCapture(t, &receivedAuth, &receivedCustom)
	defer upstream.Close()

	upSess := &UpstreamSession{
		ProtocolID:   "cred-test",
		ProtocolName: "CredTest",
		URLOrCommand: upstream.URL + "/mcp",
		Type:         "http",
		AuthToken:    "Bearer my-secret-token",
		Headers:      map[string]string{"X-Custom-Api-Key": "custom-secret"},
		Status:       "READY",
		LastPing:     time.Now(),
	}

	req := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"test_tool"}`),
		ID:      "cred-call",
	}

	_, err := upSess.CallToolHTTP(context.Background(), upstream.Client(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedAuth != "Bearer my-secret-token" {
		t.Errorf("expected 'Bearer my-secret-token', got '%s'", receivedAuth)
	}
	if receivedCustom != "custom-secret" {
		t.Errorf("expected 'custom-secret', got '%s'", receivedCustom)
	}
}

func TestDispatchTool_StreamableHTTP(t *testing.T) {
	upstream := newMockStreamableHTTPServer(t)
	defer upstream.Close()

	repo := &mockDispatcherRepo{
		configs: map[string]*agent.RouteConfig{
			"test-agent": {
				AgentName: "test-agent",
				Protocols: []agent.ProtocolConfig{
					{
						ID:           "context7",
						Name:         "Context7",
						Type:         "http",
						URLOrCommand: upstream.URL + "/mcp",
						AuthToken:    "test-token",
					},
				},
			},
		},
		tools: map[string]*agent.ToolTargetInfo{
			"test-agent:resolve": {
				ProtocolID:   "context7",
				ProtocolName: "Context7",
				TargetURL:    upstream.URL + "/mcp",
				ToolName:     "resolve",
				Type:         "http",
				AuthToken:    "test-token",
			},
		},
	}

	dispatcher := NewToolDispatcher(repo, nil)
	dispatcher.SetHTTPClient(upstream.Client())

	// Pre-build bridge with Streamable HTTP session
	bridge := &AgentSessionBridge{
		ClientSessionID: "test-session",
		AgentName:       "test-agent",
		Upstreams:       make(map[string]*UpstreamSession),
		CreatedAt:       time.Now(),
		LastActive:      time.Now(),
	}

	upSess := &UpstreamSession{
		ProtocolID:   "context7",
		ProtocolName: "Context7",
		URLOrCommand: upstream.URL + "/mcp",
		Type:         "http",
		AuthToken:    "test-token",
		Status:       "READY",
		LastPing:     time.Now(),
	}
	bridge.SetUpstream("context7", upSess)

	req := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"resolve","arguments":{"libraryName":"react"}}`),
		ID:      "dispatch-1",
	}

	result, err := dispatcher.DispatchTool(context.Background(), "test-agent", "resolve", req, nil, bridge)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Streamable HTTP should be executed locally (like stdio)
	if !result.ExecutedLocally {
		t.Error("expected ExecutedLocally=true for Streamable HTTP dispatch")
	}
	if result.Response == nil {
		t.Fatal("expected non-nil response")
	}
	if result.Response.Error != nil {
		t.Fatalf("unexpected error response: %v", result.Response.Error)
	}
}

func TestCompositeDialer_RoutesStreamableHTTP(t *testing.T) {
	dialer := NewCompositeDialer(nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proto := agent.ProtocolConfig{
		ID:           "streamable-test",
		Name:         "StreamableTest",
		Type:         "http",
		URLOrCommand: "https://example.com/mcp",
	}

	upSess := dialer.Dial(ctx, proto, nil, "test-session", nil)
	if upSess.GetStatus() != "READY" {
		t.Errorf("expected READY for Streamable HTTP dial, got %s", upSess.GetStatus())
	}
	if !upSess.IsStreamableHTTP() {
		t.Error("expected IsStreamableHTTP() true after CompositeDialer routes to StreamableHTTPDialer")
	}
}

type mockDialerFunc func(ctx context.Context, proto agent.ProtocolConfig, eventCh chan<- SSEEvent, clientSessionID string, headers http.Header) *UpstreamSession

func (m mockDialerFunc) Dial(ctx context.Context, proto agent.ProtocolConfig, eventCh chan<- SSEEvent, clientSessionID string, headers http.Header) *UpstreamSession {
	return m(ctx, proto, eventCh, clientSessionID, headers)
}

func TestCompositeDialer_AdaptiveFallbackToStreamableHTTP(t *testing.T) {
	// mockHTTPDialer simulates an SSE dial that returns DEGRADED (e.g. 405 Method Not Allowed)
	mockHTTP := mockDialerFunc(func(ctx context.Context, proto agent.ProtocolConfig, eventCh chan<- SSEEvent, clientSessionID string, headers http.Header) *UpstreamSession {
		return &UpstreamSession{
			ProtocolID:         proto.ID,
			ProtocolName:       proto.Name,
			Status:             "DEGRADED",
			lastDialStatusCode: http.StatusMethodNotAllowed,
		}
	})

	// mockStreamableDialer simulates a successful Streamable HTTP fallback that returns READY
	mockStreamable := mockDialerFunc(func(ctx context.Context, proto agent.ProtocolConfig, eventCh chan<- SSEEvent, clientSessionID string, headers http.Header) *UpstreamSession {
		return &UpstreamSession{
			ProtocolID:   proto.ID,
			ProtocolName: proto.Name,
			Type:         "http",
			Status:       "READY",
		}
	})

	dialer := NewCompositeDialerWithStreamable(mockHTTP, nil, mockStreamable)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Configured as "sse" (triggers HTTPDialer first, then falls back to StreamableHTTPDialer)
	proto := agent.ProtocolConfig{
		ID:           "adaptive-test",
		Name:         "AdaptiveTest",
		Type:         "sse",
		URLOrCommand: "https://example.com/mcp",
	}

	upSess := dialer.Dial(ctx, proto, nil, "adaptive-session", nil)
	if upSess.GetStatus() != "READY" {
		t.Fatalf("expected READY after adaptive fallback to Streamable HTTP, got %s", upSess.GetStatus())
	}
	if !upSess.IsStreamableHTTP() {
		t.Error("expected IsStreamableHTTP() true after adaptive fallback")
	}
}
