package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"github.com/FaradAiLab/FaradAiWire/internal/auth"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/types"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
)

type ingressAuthFilter struct{}

func (f *ingressAuthFilter) Name() string { return "ingress_auth" }
func (f *ingressAuthFilter) FilterRequest(ctx context.Context, req *mcp.Request) (*mcp.Request, *mcp.Error) {
	if req.Method == "tools/list" {
		return req, nil
	}
	role := "unknown"
	if u, ok := ctx.Value(types.UserContextKey).(*types.UserContext); ok {
		role = u.Role
	}
	if role == "Developer" || role == "Admin" {
		return req, nil
	}
	return nil, mcp.NewError(mcp.ErrPolicyDenied, "Access denied by ingress auth policy", nil)
}

func setupTestIngressWithPolicyAuth(t *testing.T) (*SSEProxy, auth.KeyStore) {
	pipeline := filter.NewPipeline(nil)
	pipeline.SetFilters([]filter.Filter{&ingressAuthFilter{}})

	keyStore := auth.NewMemoryKeyStore()

	userCtxCfg := config.UserContextConfig{
		RoleHeader:   "X-User-Role",
		UserHeader:   "X-User-ID",
		FallbackRole: "Customer",
		FallbackUser: "guest-customer",
	}

	proxy := NewSSEProxy(0, "http://mock-backend/sse", pipeline, nil, nil, userCtxCfg)
	proxy.SetKeyValidator(keyStore)

	// Mock backend HTTP transport so tests don't bind sockets
	proxy.httpClient = &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			body, _ := io.ReadAll(r.Body)
			var req mcp.Request
			_ = json.Unmarshal(body, &req)

			resultBytes, _ := json.Marshal(map[string]interface{}{
				"status": "success",
				"output": "tool execution completed",
			})
			resp := &mcp.Response{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result:  resultBytes,
			}
			respBytes, _ := json.Marshal(resp)

			header := make(http.Header)
			header.Set("Content-Type", "application/json")
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     header,
				Body:       io.NopCloser(bytes.NewReader(respBytes)),
			}, nil
		}),
	}

	return proxy, keyStore
}

func TestIngressAuth_Unauthenticated_CannotExecuteDeveloperTool(t *testing.T) {
	proxy, _ := setupTestIngressWithPolicyAuth(t)

	// Call developer-restricted tool without credentials, trying to spoof X-User-Role: Developer
	toolCallBody := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"execute_privileged_task","arguments":{"action":"deploy"}},"id":1001}`
	req := httptest.NewRequest("POST", "/message?sessionId=sess-1", bytes.NewBufferString(toolCallBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-User-Role", "Developer") // Unauthenticated role spoofing attempt!
	req.Header.Set("X-User-ID", "attacker")

	rec := httptest.NewRecorder()
	proxy.handleMessage(rec, req)

	res := rec.Result()
	body, _ := io.ReadAll(res.Body)
	defer res.Body.Close()

	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected HTTP 401 Unauthorized for unauthenticated caller, got %d. Body: %s", res.StatusCode, string(body))
	}

	authHeader := res.Header.Get("WWW-Authenticate")
	if authHeader != `Bearer realm="FaradAiWire"` {
		t.Errorf("expected WWW-Authenticate header, got %q", authHeader)
	}

	var errResp map[string]string
	if err := json.Unmarshal(body, &errResp); err != nil {
		t.Fatalf("failed to parse response JSON: %v, raw: %s", err, string(body))
	}
	if errResp["error"] != "UNAUTHORIZED" {
		t.Errorf("expected error code 'UNAUTHORIZED', got %q", errResp["error"])
	}
}

func TestIngressAuth_ValidBearerToken_CanExecuteDeveloperTool(t *testing.T) {
	proxy, keyStore := setupTestIngressWithPolicyAuth(t)

	// Generate a valid Developer API key
	rawToken, _, err := keyStore.GenerateKey("Cursor Dev Agent", "Developer")
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	toolCallBody := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"execute_privileged_task","arguments":{"action":"deploy"}},"id":1002}`
	req := httptest.NewRequest("POST", "/message?sessionId=sess-2", bytes.NewBufferString(toolCallBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+rawToken)

	rec := httptest.NewRecorder()
	proxy.handleMessage(rec, req)

	res := rec.Result()
	body, _ := io.ReadAll(res.Body)
	defer res.Body.Close()

	var resp mcp.Response
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("failed to parse response JSON: %v, raw: %s", err, string(body))
	}

	if resp.Error != nil {
		t.Fatalf("expected successful tool call for valid Developer key, got error: %s", resp.Error.Message)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}
	if result["status"] != "success" {
		t.Errorf("expected status 'success', got %v", result["status"])
	}
}

func TestIngressAuth_ValidXAPIKeyHeader_CanExecuteDeveloperTool(t *testing.T) {
	proxy, keyStore := setupTestIngressWithPolicyAuth(t)

	rawToken, _, err := keyStore.GenerateKey("CI Runner", "Developer")
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	toolCallBody := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"execute_privileged_task","arguments":{"action":"deploy"}},"id":1003}`
	req := httptest.NewRequest("POST", "/message?sessionId=sess-3", bytes.NewBufferString(toolCallBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", rawToken)

	rec := httptest.NewRecorder()
	proxy.handleMessage(rec, req)

	res := rec.Result()
	body, _ := io.ReadAll(res.Body)
	defer res.Body.Close()

	var resp mcp.Response
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("failed to parse response JSON: %v", err)
	}

	if resp.Error != nil {
		t.Fatalf("expected successful execution with X-API-Key header, got error: %s", resp.Error.Message)
	}
}

func TestIngressAuth_RevokedKey_CannotExecuteDeveloperTool(t *testing.T) {
	proxy, keyStore := setupTestIngressWithPolicyAuth(t)

	rawToken, record, err := keyStore.GenerateKey("Compromised Key", "Developer")
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Revoke the key
	if err := keyStore.RevokeKey(record.ID); err != nil {
		t.Fatalf("failed to revoke key: %v", err)
	}

	toolCallBody := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"execute_privileged_task","arguments":{"action":"deploy"}},"id":1004}`
	req := httptest.NewRequest("POST", "/message?sessionId=sess-4", bytes.NewBufferString(toolCallBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+rawToken)

	rec := httptest.NewRecorder()
	proxy.handleMessage(rec, req)

	res := rec.Result()
	body, _ := io.ReadAll(res.Body)
	defer res.Body.Close()

	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected HTTP 401 Unauthorized for revoked key, got %d. Body: %s", res.StatusCode, string(body))
	}

	var errResp map[string]string
	if err := json.Unmarshal(body, &errResp); err != nil {
		t.Fatalf("failed to parse response JSON: %v, raw: %s", err, string(body))
	}
	if errResp["error"] != "UNAUTHORIZED" {
		t.Errorf("expected error code 'UNAUTHORIZED', got %q", errResp["error"])
	}
}

func TestIngressAuth_EliminationOfDefaultSessionFallback(t *testing.T) {
	proxy, keyStore := setupTestIngressWithPolicyAuth(t)

	rawToken, _, err := keyStore.GenerateKey("Session Tester", "Developer")
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Send two requests without sessionId: verify both succeed independently and do NOT share state
	toolCallBody := `{"jsonrpc":"2.0","method":"tools/list","id":2001}`

	req1 := httptest.NewRequest("POST", "/message", bytes.NewBufferString(toolCallBody))
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("Authorization", "Bearer "+rawToken)
	rec1 := httptest.NewRecorder()
	proxy.handleMessage(rec1, req1)

	if rec1.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 for req1, got %d, body: %s", rec1.Code, rec1.Body.String())
	}

	req2 := httptest.NewRequest("POST", "/message", bytes.NewBufferString(toolCallBody))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", "Bearer "+rawToken)
	rec2 := httptest.NewRecorder()
	proxy.handleMessage(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 for req2, got %d, body: %s", rec2.Code, rec2.Body.String())
	}

	// Verify correlation store has no "default-session" keys
	cStore := proxy.CorrelationStore()
	if cStore != nil {
		_, ok := cStore.GetAndRemove(NewCorrelationKey("default-session", "2001"))
		if ok {
			t.Errorf("unexpected entry under 'default-session' correlation key!")
		}
	}
}

func TestIngressAuth_SSEEndpoint_ContextExtraction(t *testing.T) {
	proxy, keyStore := setupTestIngressWithPolicyAuth(t)

	rawToken, _, err := keyStore.GenerateKey("SSE Client Agent", "Developer")
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// 1. Valid Bearer token on /sse
	reqValid := httptest.NewRequest("GET", "/sse/agent-dev", nil)
	reqValid.Header.Set("Authorization", "Bearer "+rawToken)
	uCtxValid := proxy.extractUserContext(reqValid)
	if uCtxValid == nil || uCtxValid.Role != "Developer" || uCtxValid.UserID != "SSE Client Agent" {
		t.Errorf("expected Developer / SSE Client Agent, got %+v", uCtxValid)
	}

	// 2. Unauthenticated request attempting to spoof Developer on /sse -> immediate 401
	reqSpoof := httptest.NewRequest("GET", "/sse/agent-dev", nil)
	reqSpoof.Header.Set("X-User-Role", "Developer")
	reqSpoof.Header.Set("X-User-ID", "imposter")

	uCtxSpoof := proxy.extractUserContext(reqSpoof)
	if uCtxSpoof != nil {
		t.Errorf("expected nil UserContext for unauthenticated /sse request, got %+v", uCtxSpoof)
	}

	recSpoof := httptest.NewRecorder()
	proxy.handleSSE(recSpoof, reqSpoof)
	if recSpoof.Code != http.StatusUnauthorized {
		t.Errorf("expected HTTP 401 for unauthenticated /sse, got %d", recSpoof.Code)
	}
	if recSpoof.Header().Get("WWW-Authenticate") != `Bearer realm="FaradAiWire"` {
		t.Errorf("expected WWW-Authenticate header on 401, got %q", recSpoof.Header().Get("WWW-Authenticate"))
	}

	// 3. Corrupted Bearer token on /sse -> immediate 401
	reqInvalid := httptest.NewRequest("GET", "/sse/agent-dev", nil)
	reqInvalid.Header.Set("Authorization", "Bearer invalid-token-12345")

	uCtxInvalid := proxy.extractUserContext(reqInvalid)
	if uCtxInvalid != nil {
		t.Errorf("expected nil UserContext for invalid Bearer token on /sse, got %+v", uCtxInvalid)
	}

	recInvalid := httptest.NewRecorder()
	proxy.handleSSE(recInvalid, reqInvalid)
	if recInvalid.Code != http.StatusUnauthorized {
		t.Errorf("expected HTTP 401 for invalid Bearer token on /sse, got %d", recInvalid.Code)
	}

	// 4. MCPEndpoint (/mcp) fail-closed check
	reqMCPUnauth := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","method":"tools/list","id":1}`))
	reqMCPUnauth.Header.Set("Content-Type", "application/json")
	recMCPUnauth := httptest.NewRecorder()
	proxy.handleMessage(recMCPUnauth, reqMCPUnauth)
	if recMCPUnauth.Code != http.StatusUnauthorized {
		t.Errorf("expected HTTP 401 for unauthenticated /mcp, got %d", recMCPUnauth.Code)
	}
}
