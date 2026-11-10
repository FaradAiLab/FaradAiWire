package guard

import (
	"bytes"
	"context"
	"errors"
	"io"
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

type syncSafeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncSafeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncSafeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestHITLDispatcher_DualChannel_WebWinsRaceCleanly(t *testing.T) {
	t.Parallel()

	pr, pw := io.Pipe()
	defer pr.Close()
	defer pw.Close()

	var out syncSafeBuffer
	hub := &mockWSHub{clientCount: 1}
	dispatcher := NewHITLDispatcher(HITLDispatcherConfig{
		Timeout: 2 * time.Second,
		TTYIn:   pr,
		TTYOut:  &out,
		WSHub:   hub,
	})

	req := &HITLRequest{
		CallID:    "dual-race-1",
		ToolName:  "delete_record",
		Arguments: map[string]interface{}{"id": 42},
		RiskScore: 0.91,
	}

	go func() {
		time.Sleep(30 * time.Millisecond)
		if !dispatcher.Resolve("dual-race-1", true) {
			t.Errorf("expected Web Console Resolve to succeed")
		}
	}()

	start := time.Now()
	approved, err := dispatcher.RequestApproval(context.Background(), req)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("expected nil error when resolved via Web Console, got %v", err)
	}
	if !approved {
		t.Fatal("expected request to be approved")
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("expected immediate return after Web Console resolve, took %v", elapsed)
	}
	if !strings.Contains(out.String(), "Approve execution? (y/N)") {
		t.Errorf("expected TTY prompt to have been rendered, got %q", out.String())
	}
}

func TestHITLDispatcher_ExternalRejectVsTimeoutNotice(t *testing.T) {
	t.Parallel()

	t.Run("ExternalWebRejectNotice", func(t *testing.T) {
		t.Parallel()
		pr, pw := io.Pipe()
		defer pr.Close()
		defer pw.Close()

		var out syncSafeBuffer
		hub := &mockWSHub{clientCount: 1}
		dispatcher := NewHITLDispatcher(HITLDispatcherConfig{
			Timeout: 2 * time.Second,
			TTYIn:   pr,
			TTYOut:  &out,
			WSHub:   hub,
		})

		go func() {
			time.Sleep(25 * time.Millisecond)
			dispatcher.Resolve("ext-reject-1", false)
		}()

		approved, err := dispatcher.RequestApproval(context.Background(), &HITLRequest{
			CallID:   "ext-reject-1",
			ToolName: "delete_table",
		})
		if approved || !errors.Is(err, ErrHITLDenied) {
			t.Fatalf("expected ErrHITLDenied, got approved=%v err=%v", approved, err)
		}
		if !strings.Contains(out.String(), "rejected via Web Console") {
			t.Fatalf("expected Web Console rejection notice, got %q", out.String())
		}
	})

	t.Run("TimeoutNoticeDistinctFromWebReject", func(t *testing.T) {
		t.Parallel()
		pr, pw := io.Pipe()
		defer pr.Close()
		defer pw.Close()

		var out syncSafeBuffer
		dispatcher := NewHITLDispatcher(HITLDispatcherConfig{
			Timeout: 50 * time.Millisecond,
			TTYIn:   pr,
			TTYOut:  &out,
		})

		approved, err := dispatcher.RequestApproval(context.Background(), &HITLRequest{
			CallID:   "timeout-notice-1",
			ToolName: "drop_schema",
		})
		if approved || !errors.Is(err, ErrHITLTimeout) {
			t.Fatalf("expected ErrHITLTimeout, got approved=%v err=%v", approved, err)
		}
		rendered := out.String()
		if strings.Contains(rendered, "rejected via Web Console") {
			t.Fatalf("timeout notice must not masquerade as Web Console rejection: %q", rendered)
		}
		if !strings.Contains(rendered, "timed out") {
			t.Fatalf("expected timeout notice in TTY output, got %q", rendered)
		}
	})
}

func TestHITLDispatcher_ConcurrentPrompts_SerializedTTY(t *testing.T) {
	t.Parallel()

	pr, pw := io.Pipe()
	defer pr.Close()
	defer pw.Close()

	var out syncSafeBuffer
	dispatcher := NewHITLDispatcher(HITLDispatcherConfig{
		Timeout: 2 * time.Second,
		TTYIn:   pr,
		TTYOut:  &out,
	})

	type outcome struct {
		approved bool
		err      error
	}
	resCh := make(chan outcome, 2)
	for _, callID := range []string{"conc-1", "conc-2"} {
		id := callID
		go func() {
			ok, err := dispatcher.RequestApproval(context.Background(), &HITLRequest{
				CallID:   id,
				ToolName: "exec_cmd",
			})
			resCh <- outcome{approved: ok, err: err}
		}()
	}

	// Wait for first serialized prompt, answer it, wait for second prompt, answer it.
	deadline := time.Now().Add(1 * time.Second)
	for strings.Count(out.String(), "Approve execution? (y/N): ") < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := pw.Write([]byte("y\n")); err != nil {
		t.Fatalf("pipe write 1 failed: %v", err)
	}

	for strings.Count(out.String(), "Approve execution? (y/N): ") < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := pw.Write([]byte("n\n")); err != nil {
		t.Fatalf("pipe write 2 failed: %v", err)
	}

	o1 := <-resCh
	o2 := <-resCh
	if (o1.approved == o2.approved) || strings.Count(out.String(), "Approve execution? (y/N): ") != 2 {
		t.Fatalf("expected one approval and one denial cleanly serialized, got o1=%+v o2=%+v out=%q", o1, o2, out.String())
	}
}

func TestHITLDispatcher_TTYSemaphore_NoHeadOfLineTimeoutStall(t *testing.T) {
	t.Parallel()

	pr, pw := io.Pipe()
	defer pr.Close()
	defer pw.Close()

	var out syncSafeBuffer
	dispatcher := NewHITLDispatcher(HITLDispatcherConfig{
		Timeout: 5 * time.Second,
		TTYIn:   pr,
		TTYOut:  &out,
	})

	// Request A holds the TTY lock indefinitely
	ctxA, cancelA := context.WithCancel(context.Background())
	doneA := make(chan struct{})
	go func() {
		defer close(doneA)
		_, _ = dispatcher.RequestApproval(ctxA, &HITLRequest{
			CallID:   "hol-a",
			ToolName: "exec_cmd",
		})
	}()

	deadline := time.Now().Add(500 * time.Millisecond)
	for !strings.Contains(out.String(), "Approve execution? (y/N): ") && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	// Request B cancels quickly and MUST NOT block waiting on Request A's TTY lock
	start := time.Now()
	ctxB, cancelB := context.WithTimeout(context.Background(), 35*time.Millisecond)
	defer cancelB()
	approvedB, errB := dispatcher.RequestApproval(ctxB, &HITLRequest{
		CallID:   "hol-b",
		ToolName: "exec_cmd",
	})
	elapsed := time.Since(start)

	if approvedB || !errors.Is(errB, context.DeadlineExceeded) {
		t.Fatalf("expected Request B to fail closed on deadline, got approved=%v err=%v", approvedB, errB)
	}
	if elapsed > 250*time.Millisecond {
		t.Fatalf("head-of-line TTY stall detected: Request B took %v", elapsed)
	}

	cancelA()
	_, _ = pw.Write([]byte("n\n"))
	<-doneA
}
