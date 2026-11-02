package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"context"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/types"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
)

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type provenanceAuthFilter struct{}

func (f *provenanceAuthFilter) Name() string { return "provenance_auth" }
func (f *provenanceAuthFilter) FilterRequest(ctx context.Context, req *mcp.Request) (*mcp.Request, *mcp.Error) {
	if req.Method == "tools/list" {
		return req, nil
	}
	role := "unknown"
	if u, ok := ctx.Value(types.UserContextKey).(*types.UserContext); ok {
		role = u.Role
	}
	if role == "SOC_Lead" || role == "Developer" {
		return req, nil
	}
	if role == "Customer" && req.Method == "tools/call" {
		var p struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(req.Params, &p)
		if p.Name == "read_data" {
			return req, nil
		}
	}
	return nil, mcp.NewError(mcp.ErrPolicyDenied, "Access denied by provenance auth policy", nil)
}

func TestContextProvenance_AntiSpoofing_Policy_Integration(t *testing.T) {
	pipeline := filter.NewPipeline(nil)
	pipeline.SetFilters([]filter.Filter{&provenanceAuthFilter{}})

	// 3. Initialize Proxy with User Context & Provenance Config
	secretKey := "enterprise-farad-ai-secret-key-99"
	userCtxCfg := config.UserContextConfig{
		RoleHeader:        "X-User-Role",
		UserHeader:        "X-User-ID",
		FallbackRole:      "Customer",
		FallbackUser:      "guest-customer",
		TrustedProxies:    []string{"10.244.0.0/16"},
		ContextHMACSecret: secretKey,
	}

	proxy := NewSSEProxy(0, "http://mock-backend/sse", pipeline, nil, nil, userCtxCfg)

	// Mock backend HTTP transport without requiring network binding
	proxy.httpClient = &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			body, _ := io.ReadAll(r.Body)
			var req mcp.Request
			_ = json.Unmarshal(body, &req)

			resultBytes, _ := json.Marshal(map[string]interface{}{
				"status": "success",
				"tool":   "executed",
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

	// Helper function to send simulated requests
	executeProxyRequest := func(remoteAddr, roleHeader, userHeader, sigHeader, tsHeader string, queryParam string, jsonRPCBody string) (*http.Response, []byte) {
		urlPath := "/message"
		if queryParam != "" {
			urlPath += "?" + queryParam
		}
		req := httptest.NewRequest("POST", urlPath, bytes.NewBufferString(jsonRPCBody))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = remoteAddr

		if roleHeader != "" {
			req.Header.Set("X-User-Role", roleHeader)
		}
		if userHeader != "" {
			req.Header.Set("X-User-ID", userHeader)
		}
		if sigHeader != "" {
			req.Header.Set("X-FaradAiWire-Signature", sigHeader)
		}
		if tsHeader != "" {
			req.Header.Set("X-FaradAiWire-Timestamp", tsHeader)
		}

		rec := httptest.NewRecorder()
		proxy.handleMessage(rec, req)

		res := rec.Result()
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		return res, body
	}

	callRestrictedTool := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"trigger_attack_simulation","arguments":{"target":"all"}},"id":101}`

	// Scenario 1: Untrusted External Client Spoofing X-User-Role: SOC_Lead
	// Expected: Role is downgraded to Customer, policy blocks tool call with -32003
	t.Run("Untrusted_Spoofing_Elevated_Role_Blocked_By_Policy", func(t *testing.T) {
		_, respBody := executeProxyRequest(
			"198.51.100.50:43210", // Untrusted public IP
			"SOC_Lead",            // Spoofed role
			"attacker-user",
			"", "", "",
			callRestrictedTool,
		)

		var resp mcp.Response
		if err := json.Unmarshal(respBody, &resp); err != nil {
			t.Fatalf("failed to parse response JSON: %v", err)
		}

		if resp.Error == nil {
			t.Fatalf("expected policy denial error for untrusted spoofing attempt, got success: %s", string(respBody))
		}
		if resp.Error.Code != mcp.ErrPolicyDenied {
			t.Errorf("expected error code %d (ErrPolicyDenied), got %d: %s", mcp.ErrPolicyDenied, resp.Error.Code, resp.Error.Message)
		}
	})

	// Scenario 2: Untrusted Client attempting URL query parameter injection (?role=SOC_Lead)
	// Expected: Query parameter is ignored, context downgraded, policy blocks call
	t.Run("Query_Parameter_Role_Override_Ignored_And_Blocked", func(t *testing.T) {
		_, respBody := executeProxyRequest(
			"198.51.100.50:43210",
			"", "", "", "",
			"role=SOC_Lead&user_id=attacker", // Injected in URL query
			callRestrictedTool,
		)

		var resp mcp.Response
		if err := json.Unmarshal(respBody, &resp); err != nil {
			t.Fatalf("failed to parse response JSON: %v", err)
		}

		if resp.Error == nil || resp.Error.Code != mcp.ErrPolicyDenied {
			t.Fatalf("expected policy block for query param role injection, got: %s", string(respBody))
		}
	})

	// Scenario 3: Trusted Upstream Proxy IP (10.244.1.50 in 10.244.0.0/16)
	// Expected: Context is trusted, X-User-Role: SOC_Lead is accepted, policy allows call
	t.Run("Trusted_Proxy_CIDR_Allowed_By_Policy", func(t *testing.T) {
		_, respBody := executeProxyRequest(
			"10.244.1.50:54321", // Inside trusted CIDR 10.244.0.0/16
			"SOC_Lead",
			"sec-ops-lead",
			"", "", "",
			callRestrictedTool,
		)

		var resp mcp.Response
		if err := json.Unmarshal(respBody, &resp); err != nil {
			t.Fatalf("failed to parse response JSON: %v", err)
		}

		if resp.Error != nil {
			t.Fatalf("expected trusted proxy request to succeed, got policy error: %s", resp.Error.Message)
		}
		if resp.Result == nil {
			t.Fatalf("expected successful result from backend MCP server")
		}
	})

	// Scenario 4: Cryptographic HMAC Attestation from Untrusted IP
	// Expected: Valid HMAC signature verifies identity, X-User-Role: SOC_Lead accepted, policy allows call
	t.Run("Valid_HMAC_Signature_Allowed_By_Policy", func(t *testing.T) {
		tsStr := strconv.FormatInt(time.Now().Unix(), 10)
		userID := "alice-lead"
		role := "SOC_Lead"
		sig := ComputeHMACSignature([]byte(secretKey), tsStr, userID, role)

		_, respBody := executeProxyRequest(
			"198.51.100.50:43210", // Untrusted IP
			role,
			userID,
			sig,
			tsStr,
			"",
			callRestrictedTool,
		)

		var resp mcp.Response
		if err := json.Unmarshal(respBody, &resp); err != nil {
			t.Fatalf("failed to parse response JSON: %v", err)
		}

		if resp.Error != nil {
			t.Fatalf("expected signed request to succeed, got policy error: %s", resp.Error.Message)
		}
		if resp.Result == nil {
			t.Fatalf("expected successful result from backend MCP server")
		}
	})

	// Scenario 5: Tampered HMAC Signature from Untrusted IP
	// Expected: Signature check fails, role downgraded to Customer, policy blocks call
	t.Run("Tampered_HMAC_Signature_Blocked_By_Policy", func(t *testing.T) {
		tsStr := strconv.FormatInt(time.Now().Unix(), 10)
		// Sign for Customer, but request sends SOC_Lead
		sig := ComputeHMACSignature([]byte(secretKey), tsStr, "alice-lead", "Customer")

		_, respBody := executeProxyRequest(
			"198.51.100.50:43210",
			"SOC_Lead", // Tampered role!
			"alice-lead",
			sig,
			tsStr,
			"",
			callRestrictedTool,
		)

		var resp mcp.Response
		if err := json.Unmarshal(respBody, &resp); err != nil {
			t.Fatalf("failed to parse response JSON: %v", err)
		}

		if resp.Error == nil || resp.Error.Code != mcp.ErrPolicyDenied {
			t.Fatalf("expected policy block for tampered HMAC signature, got: %s", string(respBody))
		}
	})
}
