package admin

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
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

func TestWSHub_CSWSH_DNSRebindingBlocked(t *testing.T) {
	hub := NewWSHub()

	tests := []struct {
		name     string
		reqURL   string
		origin   string
		wantCode int
	}{
		{
			name:     "arbitrary matching Host and Origin rejected",
			reqURL:   "http://evil.com:8095/ws",
			origin:   "http://evil.com:8095",
			wantCode: http.StatusForbidden,
		},
		{
			name:     "non-http scheme rejected",
			reqURL:   "http://127.0.0.1:8095/ws",
			origin:   "file://localhost:8095",
			wantCode: http.StatusForbidden,
		},
		{
			name:     "loopback cross-port rejected",
			reqURL:   "http://127.0.0.1:8095/ws",
			origin:   "http://localhost:9999",
			wantCode: http.StatusForbidden,
		},
		{
			name:     "loopback matching port allowed past origin check",
			reqURL:   "http://127.0.0.1:8095/ws",
			origin:   "http://localhost:8095",
			wantCode: http.StatusBadRequest, // missing Upgrade headers
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.reqURL, nil)
			req.Header.Set("Origin", tc.origin)
			rec := httptest.NewRecorder()
			hub.ServeHTTP(rec, req)
			if rec.Code != tc.wantCode {
				t.Fatalf("expected HTTP %d, got %d", tc.wantCode, rec.Code)
			}
		})
	}
}

func TestWSHub_ConcurrentPingBroadcastUnregister(t *testing.T) {
	hub := NewWSHub()
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	// Drain peer side so writes don't stall
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := clientConn.Read(buf); err != nil {
				return
			}
		}
	}()

	c := &wsClient{
		conn: serverConn,
		send: make(chan []byte, 16),
		done: make(chan struct{}),
		hub:  hub,
	}
	hub.register(c)

	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		defer hub.unregister(c)
		for {
			select {
			case <-c.done:
				return
			case msg := <-c.send:
				if _, err := serverConn.Write(msg); err != nil {
					return
				}
			}
		}
	}()

	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func(id int) {
			defer workers.Done()
			for j := 0; j < 50; j++ {
				c.trySend(encodePongFrame([]byte("ping")))
				hub.Broadcast(map[string]int{"worker": id, "iter": j})
				hub.SendDirect(c, map[string]int{"direct": j})
			}
		}(i)
	}

	time.Sleep(10 * time.Millisecond)
	hub.unregister(c)
	hub.unregister(c) // idempotent

	workers.Wait()
	select {
	case <-writerDone:
	case <-time.After(time.Second):
		t.Fatal("writer goroutine did not exit after unregister")
	}
}

func TestWSHub_CSWSH_WildcardCORSStillRejectsUntrustedOrigin(t *testing.T) {
	hub := NewWSHub()
	hub.SetAllowedOrigins([]string{"*", " * ", " https://trusted.example.com "})

	cases := []struct {
		name         string
		origin       string
		secFetchSite string
		wantBlocked  bool
	}{
		{
			name:        "untrusted origin rejected even when wildcard present",
			origin:      "http://evil.com",
			wantBlocked: true,
		},
		{
			name:         "cross-site origin rejected even when wildcard present",
			origin:       "https://evil.com",
			secFetchSite: "cross-site",
			wantBlocked:  true,
		},
		{
			name:        "whitespace-only origin rejected",
			origin:      "   ",
			wantBlocked: true,
		},
		{
			name:        "explicit allowlisted origin allowed with whitespace and case normalization",
			origin:      " https://TRUSTED.example.com ",
			wantBlocked: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8095/ws", nil)
			req.Header.Set("Origin", tc.origin)
			if tc.secFetchSite != "" {
				req.Header.Set("Sec-Fetch-Site", tc.secFetchSite)
			}
			rec := httptest.NewRecorder()
			hub.ServeHTTP(rec, req)

			if tc.wantBlocked && rec.Code != http.StatusForbidden {
				t.Fatalf("expected 403 Forbidden, got %d", rec.Code)
			}
			if !tc.wantBlocked && rec.Code == http.StatusForbidden {
				t.Fatalf("did not expect 403 Forbidden for allowlisted origin, got %d", rec.Code)
			}
		})
	}
}
