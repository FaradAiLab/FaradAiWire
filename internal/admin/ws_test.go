package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/guard"
)

func TestWSHub_Lifecycle_And_Broadcast(t *testing.T) {
	hub := NewWSHub()

	if hub.ClientCount() != 0 {
		t.Fatalf("expected 0 clients initially, got %d", hub.ClientCount())
	}

	// Verify broadcast on empty hub doesn't panic
	hub.Broadcast(map[string]interface{}{
		"type":    "HITL_APPROVAL_REQUIRED",
		"call_id": "test-123",
	})

	// Test invalid upgrade request rejected
	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	rec := httptest.NewRecorder()
	hub.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for bad upgrade, got %d", rec.Code)
	}
}

func TestAdminServer_HITL_WSHub_Integration(t *testing.T) {
	server, _, cleanup := setupTestAdminServerWithGuards(t)
	defer cleanup()

	hub := server.WSHub()
	if hub == nil {
		t.Fatal("expected non-nil WSHub on AdminServer")
	}

	dispatcher := guard.NewHITLDispatcher(guard.HITLDispatcherConfig{
		Timeout:       2 * time.Second,
		DisableTTY:    true,
		AllowRESTOnly: true,
		WSHub:         hub,
	})
	server.SetGuardHITL(dispatcher)

	// Broadcast an approval event via dispatcher
	hitlReq := &guard.HITLRequest{
		CallID:         "ws-call-1",
		ToolName:       "execute_query",
		Arguments:      map[string]interface{}{"q": "SELECT 1"},
		RiskScore:      0.88,
		ThreatDomain:   "INJECTION",
		CWE:            "CWE-89",
		DecisionEngine: "L2_QWEN3GUARD",
	}

	go func() {
		time.Sleep(20 * time.Millisecond)
		dispatcher.Resolve("ws-call-1", true)
	}()

	approved, err := dispatcher.RequestApproval(context.Background(), hitlReq)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !approved {
		t.Fatal("expected approved to be true")
	}
}

func TestWSHub_CSWSH_Origin_Validation(t *testing.T) {
	hub := NewWSHub()
	hub.SetAllowedOrigins([]string{"https://app.trusted.com"})

	// Case 1: Unauthorized Origin rejected with 403 Forbidden
	reqEvil := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8095/ws", nil)
	reqEvil.Header.Set("Upgrade", "websocket")
	reqEvil.Header.Set("Connection", "Upgrade")
	reqEvil.Header.Set("Origin", "http://evil.com")
	recEvil := httptest.NewRecorder()
	hub.ServeHTTP(recEvil, reqEvil)

	if recEvil.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for evil.com origin, got %d", recEvil.Code)
	}

	// Case 2: Configured trusted origin allowed past origin check
	reqTrusted := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8095/ws", nil)
	reqTrusted.Header.Set("Origin", "https://app.trusted.com")
	recTrusted := httptest.NewRecorder()
	hub.ServeHTTP(recTrusted, reqTrusted)
	// Won't be 403 (will be 400 Bad Request because upgrade headers missing)
	if recTrusted.Code == http.StatusForbidden {
		t.Fatalf("did not expect 403 for configured trusted origin, got %d", recTrusted.Code)
	}

	// Case 3: Same-Host loopback origin allowed past origin check
	reqLoopback := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8095/ws", nil)
	reqLoopback.Header.Set("Origin", "http://localhost:8095")
	recLoopback := httptest.NewRecorder()
	hub.ServeHTTP(recLoopback, reqLoopback)
	if recLoopback.Code == http.StatusForbidden {
		t.Fatalf("did not expect 403 for loopback origin, got %d", recLoopback.Code)
	}
}

func TestWSHub_SendDirect_Safety(t *testing.T) {
	hub := NewWSHub()

	// Calling SendDirect with nil client should not panic
	hub.SendDirect(nil, map[string]string{"type": "TEST"})

	// Calling SendDirect with unregistered/closed client should safely return without panic
	dummyClient := &wsClient{
		send: make(chan []byte, 1),
	}
	close(dummyClient.send) // simulate unregister where channel is closed
	hub.SendDirect(dummyClient, map[string]string{"type": "TEST"})
}

