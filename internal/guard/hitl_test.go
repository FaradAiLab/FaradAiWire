package guard

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type mockWSHub struct {
	mu          sync.Mutex
	clientCount int
	events      []interface{}
}

func (m *mockWSHub) Broadcast(event interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
}

func (m *mockWSHub) ClientCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.clientCount
}

func (m *mockWSHub) Events() []interface{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	copied := make([]interface{}, len(m.events))
	copy(copied, m.events)
	return copied
}

func TestHITLDispatcher_HeadlessFailClosed(t *testing.T) {
	// Headless environment: TTY disabled, zero WebSocket clients
	hub := &mockWSHub{clientCount: 0}
	dispatcher := NewHITLDispatcher(HITLDispatcherConfig{
		Timeout:    1 * time.Second,
		DisableTTY: true,
		WSHub:      hub,
	})

	req := &HITLRequest{
		ToolName:  "delete_file",
		Arguments: map[string]interface{}{"path": "/data/test.txt"},
		RiskScore: 0.85,
	}

	approved, err := dispatcher.RequestApproval(context.Background(), req)
	if approved {
		t.Fatal("expected approval to be denied in headless environment")
	}
	if !errors.Is(err, ErrHeadlessFailClosed) {
		t.Fatalf("expected ErrHeadlessFailClosed, got: %v", err)
	}
}

func TestHITLDispatcher_TTY_Approved(t *testing.T) {
	in := strings.NewReader("y\n")
	var out bytes.Buffer

	dispatcher := NewHITLDispatcher(HITLDispatcherConfig{
		Timeout: 2 * time.Second,
		TTYIn:   in,
		TTYOut:  &out,
	})

	req := &HITLRequest{
		ToolName:     "send_email",
		Arguments:    map[string]interface{}{"to": "boss@company.com"},
		RiskScore:    0.72,
		ThreatDomain: "PHISHING_RISK",
		CWE:          "CWE-20",
	}

	approved, err := dispatcher.RequestApproval(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !approved {
		t.Fatal("expected tool execution to be approved via TTY")
	}

	promptOutput := out.String()
	if !strings.Contains(promptOutput, "SUSPICIOUS TOOL CALL DETECTED") {
		t.Errorf("expected prompt output to contain alert header, got: %s", promptOutput)
	}
	if !strings.Contains(promptOutput, "Approve execution? (y/N)") {
		t.Errorf("expected prompt output to contain question, got: %s", promptOutput)
	}
}

func TestHITLDispatcher_TTY_Denied(t *testing.T) {
	in := strings.NewReader("N\n")
	var out bytes.Buffer

	dispatcher := NewHITLDispatcher(HITLDispatcherConfig{
		Timeout: 2 * time.Second,
		TTYIn:   in,
		TTYOut:  &out,
	})

	req := &HITLRequest{
		ToolName:  "execute_script",
		Arguments: map[string]interface{}{"code": "print(1)"},
		RiskScore: 0.90,
	}

	approved, err := dispatcher.RequestApproval(context.Background(), req)
	if approved {
		t.Fatal("expected tool execution to be denied via TTY")
	}
	if !errors.Is(err, ErrHITLDenied) {
		t.Fatalf("expected ErrHITLDenied, got: %v", err)
	}
}

func TestHITLDispatcher_REST_Resolve(t *testing.T) {
	hub := &mockWSHub{clientCount: 1}
	dispatcher := NewHITLDispatcher(HITLDispatcherConfig{
		Timeout:    2 * time.Second,
		DisableTTY: true,
		WSHub:      hub,
	})

	req := &HITLRequest{
		CallID:    "test-call-42",
		ToolName:  "custom_api_call",
		Arguments: map[string]interface{}{"endpoint": "https://api.internal/data"},
		RiskScore: 0.65,
	}

	// Resolve asynchronously via REST simulated call
	go func() {
		time.Sleep(30 * time.Millisecond)
		// Verify pending presence
		pending := dispatcher.ListPending()
		if len(pending) != 1 || pending[0].CallID != "test-call-42" {
			t.Errorf("expected 1 pending item, got %d", len(pending))
		}
		// Resolve approval
		resolved := dispatcher.Resolve("test-call-42", true)
		if !resolved {
			t.Errorf("expected Resolve to return true")
		}
	}()

	approved, err := dispatcher.RequestApproval(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !approved {
		t.Fatal("expected request to be approved via REST")
	}

	// Verify WebSocket events
	events := hub.Events()
	if len(events) < 2 {
		t.Fatalf("expected at least 2 WS events (REQUIRED and RESOLVED), got %d", len(events))
	}
}

func TestHITLDispatcher_TimeoutFailClosed(t *testing.T) {
	hub := &mockWSHub{clientCount: 1}
	dispatcher := NewHITLDispatcher(HITLDispatcherConfig{
		Timeout:    50 * time.Millisecond,
		DisableTTY: true,
		WSHub:      hub,
	})

	req := &HITLRequest{
		ToolName:  "read_private_key",
		Arguments: map[string]interface{}{"key": "cert.pem"},
		RiskScore: 0.99,
	}

	start := time.Now()
	approved, err := dispatcher.RequestApproval(context.Background(), req)
	duration := time.Since(start)

	if approved {
		t.Fatal("expected request to fail-closed on timeout")
	}
	if !errors.Is(err, ErrHITLTimeout) {
		t.Fatalf("expected ErrHITLTimeout, got: %v", err)
	}
	if duration < 40*time.Millisecond {
		t.Fatalf("expected timeout to wait for configured duration, took: %v", duration)
	}

	// Verify pending request was cleanly removed
	if len(dispatcher.ListPending()) != 0 {
		t.Fatalf("expected 0 pending requests after timeout, got %d", len(dispatcher.ListPending()))
	}
}

func TestHITLDispatcher_ConcurrentResolution_RaceFree(t *testing.T) {
	hub := &mockWSHub{clientCount: 2}
	dispatcher := NewHITLDispatcher(HITLDispatcherConfig{
		Timeout:    1 * time.Second,
		DisableTTY: true,
		WSHub:      hub,
	})

	req := &HITLRequest{
		CallID:    "race-call-1",
		ToolName:  "update_config",
		Arguments: map[string]interface{}{"k": "v"},
		RiskScore: 0.8,
	}

	var wg sync.WaitGroup
	// 5 concurrent attempts to resolve
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			time.Sleep(10 * time.Millisecond)
			dispatcher.Resolve("race-call-1", idx%2 == 0)
		}(i)
	}

	approved, err := dispatcher.RequestApproval(context.Background(), req)
	if err != nil && !errors.Is(err, ErrHITLDenied) {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = approved
	wg.Wait()
}
