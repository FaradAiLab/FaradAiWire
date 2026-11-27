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
	if role == "Developer" || role == "SOC_Lead" {
		return req, nil
	}
	return nil, mcp.NewError(mcp.ErrPolicyDenied, "Access denied by provenance auth policy", nil)
}

func TestContextProvenance_BearerOnly_Policy_Integration(t *testing.T) {
	pipeline := filter.NewPipeline(nil)
	pipeline.SetFilters([]filter.Filter{&provenanceAuthFilter{}})

	ks := auth.NewMemoryKeyStore()
	devToken, _, err := ks.GenerateKey("dev-operator", "Developer", "*")
	if err != nil {
		t.Fatalf("GenerateKey(Developer): %v", err)
	}
	guestToken, _, err := ks.GenerateKey("guest-operator", "Customer", "*")
	if err != nil {
		t.Fatalf("GenerateKey(Customer): %v", err)
	}

	proxy := NewSSEProxy(0, "http://mock-backend/sse", pipeline, nil, nil)
	proxy.SetKeyValidator(ks)
	proxy.httpClient = &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			body, _ := io.ReadAll(r.Body)
			var req mcp.Request
			_ = json.Unmarshal(body, &req)

			resultBytes, _ := json.Marshal(map[string]interface{}{
				"status": "success",
				"tool":   "executed",
			})
			respBytes, _ := json.Marshal(&mcp.Response{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result:  resultBytes,
			})
			header := make(http.Header)
			header.Set("Content-Type", "application/json")
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     header,
				Body:       io.NopCloser(bytes.NewReader(respBytes)),
			}, nil
		}),
	}

	callRestrictedTool := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"trigger_attack_simulation","arguments":{"target":"all"}},"id":101}`

	t.Run("Legacy_Trusted_IP_And_Spoofed_Headers_Rejected_401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/message", bytes.NewBufferString(callRestrictedTool))
		req.RemoteAddr = "127.0.0.1:43210"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-User-Role", "SOC_Lead")
		req.Header.Set("X-User-ID", "attacker")
		rec := httptest.NewRecorder()
		proxy.handleMessage(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 without Bearer token, got %d (%s)", rec.Code, rec.Body.String())
		}
	})

	t.Run("X_API_Key_Header_Only_Rejected_401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/message", bytes.NewBufferString(callRestrictedTool))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", devToken)
		rec := httptest.NewRecorder()
		proxy.handleMessage(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for X-API-Key without Authorization: Bearer, got %d (%s)", rec.Code, rec.Body.String())
		}
	})

	t.Run("Customer_Key_With_Spoofed_Role_Header_Blocked_By_Policy", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/message", bytes.NewBufferString(callRestrictedTool))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+guestToken)
		req.Header.Set("X-User-Role", "Developer")
		rec := httptest.NewRecorder()
		proxy.handleMessage(rec, req)

		var resp mcp.Response
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if resp.Error == nil || resp.Error.Code != mcp.ErrPolicyDenied {
			t.Fatalf("expected policy denial when Customer key spoofs X-User-Role, got %s", rec.Body.String())
		}
	})

	t.Run("Valid_Developer_Bearer_Allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/message", bytes.NewBufferString(callRestrictedTool))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+devToken)
		rec := httptest.NewRecorder()
		proxy.handleMessage(rec, req)

		var resp mcp.Response
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if resp.Error != nil {
			t.Fatalf("expected Developer Bearer call allowed, got error: %s", resp.Error.Message)
		}
	})
}
