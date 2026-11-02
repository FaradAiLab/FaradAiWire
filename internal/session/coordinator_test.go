package session

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
)

type mockDispatcher struct {
	result *ToolExecutionResult
	err    error
}

func (m *mockDispatcher) DispatchTool(ctx context.Context, agentName, toolName string, req *mcp.Request, headers http.Header, bridge *AgentSessionBridge) (*ToolExecutionResult, error) {
	return m.result, m.err
}

type mockForwarder struct {
	forwardedTargetURL string
	forwardedReqID     interface{}
	forwardedBody      []byte
}

func (m *mockForwarder) ForwardMessage(w http.ResponseWriter, r *http.Request, userCtx context.Context, targetURL, targetSessionID, clientSessionID string, body []byte, reqID interface{}, authToken string) {
	m.forwardedTargetURL = targetURL
	m.forwardedReqID = reqID
	m.forwardedBody = body
	resp := &mcp.Response{
		JSONRPC: "2.0",
		ID:      reqID,
		Result:  json.RawMessage(`{"forwarded":true}`),
	}
	respBytes, _ := json.Marshal(resp)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(respBytes)
}

func (m *mockForwarder) ForwardDirectSSE(w http.ResponseWriter, r *http.Request, targetURLStr string, onEndpoint func(sessionID, path string)) {
}

func (m *mockForwarder) ProcessOutgoingMessage(data, clientSessionID, targetURL string) string {
	return data
}

func (m *mockForwarder) SetBackendPath(path string)                 {}
func (m *mockForwarder) BackendPath() string                        { return "/message" }
func (m *mockForwarder) SetSessionBackendPath(sessionID, path string) {}
func (m *mockForwarder) SessionBackendPath(sessionID string) string { return "/message" }
func (m *mockForwarder) SetPipeline(p *filter.Pipeline)             {}
func (m *mockForwarder) SetCorrelationStore(store CorrelationStore) {}
func (m *mockForwarder) SetHTTPClient(client *http.Client)          {}

func TestInboundCoordinator_LocalToolExecution(t *testing.T) {
	cStore := NewMemoryCorrelationStore()
	dispatcher := &mockDispatcher{
		result: &ToolExecutionResult{
			ExecutedLocally: true,
			Response: &mcp.Response{
				JSONRPC: "2.0",
				ID:      "call-1",
				Result:  json.RawMessage(`{"content":[{"type":"text","text":"local result"}]}`),
			},
		},
	}
	forwarder := &mockForwarder{}

	coord := NewInboundCoordinator(nil, nil, nil, nil, dispatcher, cStore, forwarder, "http://default-target")

	rec := httptest.NewRecorder()
	reqBody := []byte(`{"jsonrpc":"2.0","method":"tools/call","id":"call-1","params":{"name":"local_tool"}}`)
	r := httptest.NewRequest(http.MethodPost, "/message", bytes.NewBuffer(reqBody))
	parsedReq, _, _, _ := mcp.ParseMessage(reqBody)

	mgr := NewManager(nil, nil)
	mgr.bridgesMu.Lock()
	mgr.bridges["cl-test"] = &AgentSessionBridge{
		ClientSessionID: "cl-test",
		AgentName:       "agent-a",
		Upstreams:       make(map[string]*UpstreamSession),
	}
	mgr.bridgesMu.Unlock()
	coord.SetSessionManager(mgr)

	coord.ExecuteMessage(rec, r, context.Background(), "cl-test", "agent-a", reqBody, parsedReq, nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "local result") {
		t.Errorf("expected local result in response, got: %s", rec.Body.String())
	}
}

func TestInboundCoordinator_RemoteForwardingFallbackToSessionTargets(t *testing.T) {
	forwarder := &mockForwarder{}
	coord := NewInboundCoordinator(nil, nil, nil, nil, nil, nil, forwarder, "http://default-target")

	rec := httptest.NewRecorder()
	reqBody := []byte(`{"jsonrpc":"2.0","method":"ping","id":"ping-99"}`)
	r := httptest.NewRequest(http.MethodPost, "/message?sessionId=bound-sess-123", bytes.NewBuffer(reqBody))
	parsedReq, _, _, _ := mcp.ParseMessage(reqBody)

	coord.ExecuteMessage(rec, r, context.Background(), "bound-sess-123", "", reqBody, parsedReq, func(sid string) (string, bool) {
		if sid == "bound-sess-123" {
			return "http://resolved-target:9090", true
		}
		return "", false
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	if forwarder.forwardedTargetURL != "http://resolved-target:9090" {
		t.Errorf("expected forwarded target URL 'http://resolved-target:9090', got '%s'", forwarder.forwardedTargetURL)
	}
}

func TestInboundCoordinator_StreamableHTTPToolExecution(t *testing.T) {
	var receivedAuth string
	var receivedCustom string
	upstream := newMockStreamableHTTPServerWithHeaderCapture(t, &receivedAuth, &receivedCustom)
	defer upstream.Close()

	agentCfg := &agent.RouteConfig{
		AgentName:   "agent-streamable",
		RoutingMode: "aggregated",
		Protocols: []agent.ProtocolConfig{
			{
				ID:           "context7",
				Name:         "Context7",
				Type:         "http",
				URLOrCommand: upstream.URL + "/mcp",
				AuthToken:    "context7-upstream-key",
				Headers:      map[string]string{"X-Custom-Api-Key": "custom-val"},
			},
		},
	}

	repo := &mockDispatcherRepo{
		configs: map[string]*agent.RouteConfig{
			"agent-streamable": agentCfg,
		},
		tools: map[string]*agent.ToolTargetInfo{
			"agent-streamable:context7__resolve": {
				ProtocolID:   "context7",
				ProtocolName: "Context7",
				TargetURL:    upstream.URL + "/mcp",
				ToolName:     "context7__resolve",
				Type:         "http",
				AuthToken:    "context7-upstream-key",
			},
		},
	}

	mgr := NewManager(repo, nil)
	dispatcher := NewToolDispatcher(repo, mgr)
	dispatcher.SetHTTPClient(upstream.Client())

	cStore := NewMemoryCorrelationStore()
	forwarder := &mockForwarder{}
	coord := NewInboundCoordinator(nil, repo, mgr, nil, dispatcher, cStore, forwarder, "http://default-target")

	// Initialize bridge for this client session
	_, err := mgr.CreateBridge(context.Background(), "agent-streamable", "cl-sess-streamable", nil)
	if err != nil {
		t.Fatalf("failed to create bridge: %v", err)
	}

	// Simulate incoming client tool call with client's own Authorization header
	rec := httptest.NewRecorder()
	reqBody := []byte(`{"jsonrpc":"2.0","method":"tools/call","id":"client-req-42","params":{"name":"context7__resolve","arguments":{"query":"test"}}}`)
	r := httptest.NewRequest(http.MethodPost, "/message?sessionId=cl-sess-streamable", bytes.NewBuffer(reqBody))
	r.Header.Set("Authorization", "Bearer client-sensitive-token")
	parsedReq, _, _, _ := mcp.ParseMessage(reqBody)

	coord.ExecuteMessage(rec, r, context.Background(), "cl-sess-streamable", "agent-streamable", reqBody, parsedReq, nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp mcp.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal JSON response: %v", err)
	}

	if resp.Error != nil {
		t.Fatalf("unexpected error response: %v", resp.Error)
	}

	if resp.ID != "client-req-42" {
		t.Errorf("expected ID 'client-req-42', got %v", resp.ID)
	}

	// Verify Upstream Credential Stripping: client token was stripped, upstream token and header were injected
	if receivedAuth != "Bearer context7-upstream-key" {
		t.Errorf("expected upstream Authorization 'Bearer context7-upstream-key', got '%s'", receivedAuth)
	}
	if receivedCustom != "custom-val" {
		t.Errorf("expected custom header 'custom-val', got '%s'", receivedCustom)
	}

	// Verify session bridge state
	bridge, ok := mgr.GetBridge("cl-sess-streamable")
	if !ok || bridge == nil {
		t.Fatal("expected bridge to be registered in manager")
	}
	upSess := bridge.GetUpstream("context7")
	if upSess == nil {
		t.Fatal("expected upstream session 'context7' in bridge")
	}
	if !upSess.IsStreamableHTTP() {
		t.Error("expected upstream session to be Streamable HTTP")
	}
	if upSess.GetStatus() != "READY" {
		t.Errorf("expected status READY, got %s", upSess.GetStatus())
	}
}

func TestInboundCoordinator_Initialize(t *testing.T) {
	coord := NewInboundCoordinator(nil, nil, nil, nil, nil, nil, nil, "http://default-target")

	rec := httptest.NewRecorder()
	reqBody := []byte(`{"jsonrpc":"2.0","method":"initialize","id":1,"params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test-client","version":"1.0"}}}`)
	r := httptest.NewRequest(http.MethodPost, "/sse/Claude/message?sessionId=cl-init-test", bytes.NewBuffer(reqBody))
	parsedReq, _, _, err := mcp.ParseMessage(reqBody)
	if err != nil {
		t.Fatalf("failed to parse message: %v", err)
	}

	coord.ExecuteMessage(rec, r, context.Background(), "cl-init-test", "Claude", reqBody, parsedReq, nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	if sessHeader := rec.Header().Get("Mcp-Session-Id"); sessHeader != "cl-init-test" {
		t.Errorf("expected Mcp-Session-Id header 'cl-init-test', got '%s'", sessHeader)
	}

	var resp mcp.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp.ID != float64(1) {
		t.Errorf("expected id 1, got %v", resp.ID)
	}

	var result struct {
		ProtocolVersion string `json:"protocolVersion"`
		Capabilities    struct {
			Tools struct {
				ListChanged bool `json:"listChanged"`
			} `json:"tools"`
		} `json:"capabilities"`
		ServerInfo struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
	}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	if result.ProtocolVersion != "2024-11-05" {
		t.Errorf("expected protocolVersion '2024-11-05', got '%s'", result.ProtocolVersion)
	}
	if result.ServerInfo.Name != "farad-ai-Claude" {
		t.Errorf("expected server name 'farad-ai-Claude', got '%s'", result.ServerInfo.Name)
	}
}

func TestInboundCoordinator_NotificationsInitialized(t *testing.T) {
	coord := NewInboundCoordinator(nil, nil, nil, nil, nil, nil, nil, "http://default-target")

	rec := httptest.NewRecorder()
	reqBody := []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	r := httptest.NewRequest(http.MethodPost, "/sse/Claude/message?sessionId=cl-init-test", bytes.NewBuffer(reqBody))
	parsedReq, _, _, err := mcp.ParseMessage(reqBody)
	if err != nil {
		t.Fatalf("failed to parse message: %v", err)
	}

	coord.ExecuteMessage(rec, r, context.Background(), "cl-init-test", "Claude", reqBody, parsedReq, nil)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected status 202 Accepted, got %d", rec.Code)
	}
}

func TestInboundCoordinator_Ping(t *testing.T) {
	coord := NewInboundCoordinator(nil, nil, nil, nil, nil, nil, nil, "http://default-target")

	rec := httptest.NewRecorder()
	reqBody := []byte(`{"jsonrpc":"2.0","method":"ping","id":"ping-1"}`)
	r := httptest.NewRequest(http.MethodPost, "/sse/Claude/message?sessionId=cl-init-test", bytes.NewBuffer(reqBody))
	parsedReq, _, _, err := mcp.ParseMessage(reqBody)
	if err != nil {
		t.Fatalf("failed to parse message: %v", err)
	}

	coord.ExecuteMessage(rec, r, context.Background(), "cl-init-test", "Claude", reqBody, parsedReq, nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp mcp.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp.ID != "ping-1" {
		t.Errorf("expected id 'ping-1', got %v", resp.ID)
	}
}

type testMaskingFilter struct {
	filter.BaseSecurityFilter
}

func (f *testMaskingFilter) Name() string { return "test_masker" }
func (f *testMaskingFilter) Order() int   { return 10 }
func (f *testMaskingFilter) ExecuteRequest(ctx context.Context, req *mcp.Request) (*mcp.Response, error) {
	req.Params = []byte(`{"name":"remote_tool","arguments":{"token":"[REDACTED]"}}`)
	return nil, nil
}
func (f *testMaskingFilter) FilterRequest(ctx context.Context, req *mcp.Request) (*mcp.Request, *mcp.Error) {
	req.Params = []byte(`{"name":"remote_tool","arguments":{"token":"[REDACTED]"}}`)
	return req, nil
}

func TestInboundCoordinator_MaskedPayloadReSerialization(t *testing.T) {
	p := filter.NewPipeline(nil)
	p.RegisterFilter(&testMaskingFilter{})

	forwarder := &mockForwarder{}
	coord := NewInboundCoordinator(p, nil, nil, nil, nil, nil, forwarder, "http://default-target")

	rec := httptest.NewRecorder()
	originalBody := []byte(`{"jsonrpc":"2.0","method":"tools/call","id":"call-secret-1","params":{"name":"remote_tool","arguments":{"token":"sk-secret-12345"}}}`)
	r := httptest.NewRequest(http.MethodPost, "/message?sessionId=cl-mask-test", bytes.NewBuffer(originalBody))
	parsedReq, _, _, err := mcp.ParseMessage(originalBody)
	if err != nil {
		t.Fatalf("failed to parse message: %v", err)
	}

	coord.ExecuteMessage(rec, r, context.Background(), "cl-mask-test", "", originalBody, parsedReq, nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	if forwarder.forwardedBody == nil {
		t.Fatal("expected forwarder to receive forwardedBody, got nil")
	}

	forwardedStr := string(forwarder.forwardedBody)
	if strings.Contains(forwardedStr, "sk-secret-12345") {
		t.Fatalf("SECURITY VIOLATION: forwarded body still contains unmasked secret: %s", forwardedStr)
	}
	if !strings.Contains(forwardedStr, "[REDACTED]") {
		t.Fatalf("expected forwarded body to contain '[REDACTED]', got: %s", forwardedStr)
	}
}


