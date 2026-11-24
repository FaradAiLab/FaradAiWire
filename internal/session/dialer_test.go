package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
)

func TestAgentSessionBridge_BroadcastShutdown(t *testing.T) {
	parentCtx := context.Background()
	bridgeCtx, bridgeCancel := context.WithCancel(parentCtx)

	eventCh := make(chan SSEEvent, 5)
	bridge := &AgentSessionBridge{
		ClientSessionID: "test-client-drain",
		AgentName:       "test-agent",
		Upstreams:       make(map[string]*UpstreamSession),
		EventCh:         eventCh,
		Cancel:          bridgeCancel,
		BridgeCtx:       bridgeCtx,
		CreatedAt:       time.Now(),
		LastActive:      time.Now(),
	}

	// Attach a dummy upstream
	dummyCmd := exec.Command("sleep", "10")
	setProcessGroup(dummyCmd)
	_ = dummyCmd.Start()

	upSess := &UpstreamSession{
		ProtocolID:   "p1",
		ProtocolName: "sleepy",
		Status:       "READY",
		cmd:          dummyCmd,
	}
	bridge.SetUpstream("p1", upSess)

	// Broadcast shutdown
	bridge.BroadcastShutdown()

	// 1. Verify shutdown frame received
	select {
	case ev := <-eventCh:
		if ev.Event != "shutdown" {
			t.Errorf("expected event 'shutdown', got '%s'", ev.Event)
		}
		if ev.Data == "" {
			t.Errorf("expected non-empty shutdown data")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timed out waiting for shutdown event on bridge.EventCh")
	}

	// 2. Verify bridge context canceled
	if bridge.BridgeCtx.Err() == nil {
		t.Errorf("expected bridge.BridgeCtx to be canceled")
	}

	// 3. Verify upstream closed
	if upSess.GetStatus() != "CLOSED" {
		t.Errorf("expected upstream status CLOSED, got '%s'", upSess.GetStatus())
	}
}

func TestManager_DrainAllBridges(t *testing.T) {
	mockRepo := &MockRepo{
		configs: map[string]*agent.RouteConfig{
			"agent-drain": {
				AgentID:     "drain-id",
				AgentName:   "agent-drain",
				RoutingMode: "aggregated",
				Protocols:   []agent.ProtocolConfig{},
			},
		},
	}

	dialer := &MockDialer{}
	mgr := NewManager(mockRepo, nil)
	mgr.SetDialer(dialer)

	ctx := context.Background()

	b1, err := mgr.CreateBridge(ctx, "agent-drain", "client-d1", nil)
	if err != nil {
		t.Fatalf("failed to create bridge 1: %v", err)
	}

	b2, err := mgr.CreateBridge(ctx, "agent-drain", "client-d2", nil)
	if err != nil {
		t.Fatalf("failed to create bridge 2: %v", err)
	}

	// Drain all bridges
	mgr.DrainAllBridges()

	// Verify both bridges received shutdown event
	select {
	case ev := <-b1.EventCh:
		if ev.Event != "shutdown" {
			t.Errorf("b1: expected shutdown event, got %s", ev.Event)
		}
	default:
		t.Errorf("b1 did not receive shutdown event")
	}

	select {
	case ev := <-b2.EventCh:
		if ev.Event != "shutdown" {
			t.Errorf("b2: expected shutdown event, got %s", ev.Event)
		}
	default:
		t.Errorf("b2 did not receive shutdown event")
	}

	// Verify manager has 0 bridges left
	if _, ok := mgr.GetBridge("client-d1"); ok {
		t.Errorf("expected client-d1 to be removed from manager")
	}
	if _, ok := mgr.GetBridge("client-d2"); ok {
		t.Errorf("expected client-d2 to be removed from manager")
	}
}

func TestBuildSafeSubprocessEnv_Unit(t *testing.T) {
	// Set parent environment variables, including sensitive secrets and standard vars
	t.Setenv("API_KEY", "secret-gateway-api-key")
	t.Setenv("ADMIN_API_KEY", "secret-gateway-admin-key")
	t.Setenv("AGENT_API_KEY", "secret-gateway-agent-key")
	t.Setenv("FARADAI_WIRE_HMAC_SECRET", "secret-farad-ai-hmac")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret-aws-access-key")
	t.Setenv("CUSTOM_PARENT_SECRET", "do-not-leak")
	t.Setenv("USER", "test-gateway-user")
	t.Setenv("HOME", "/Users/test-gateway-user")
	t.Setenv("PATH", "/usr/bin:/bin")

	// 1. Calling with empty/nil protoEnv
	safeEnv := BuildSafeSubprocessEnv(nil, false)
	if safeEnv == nil {
		t.Fatalf("expected non-nil safeEnv slice")
	}

	hasKey := func(envSlice []string, key string) bool {
		prefix := key + "="
		for _, e := range envSlice {
			if strings.HasPrefix(e, prefix) {
				return true
			}
		}
		return false
	}

	getKeyVal := func(envSlice []string, key string) string {
		prefix := key + "="
		for _, e := range envSlice {
			if strings.HasPrefix(e, prefix) {
				return strings.TrimPrefix(e, prefix)
			}
		}
		return ""
	}

	// Verify secrets are strictly absent
	forbiddenKeys := []string{"API_KEY", "ADMIN_API_KEY", "AGENT_API_KEY", "FARADAI_WIRE_HMAC_SECRET", "AWS_SECRET_ACCESS_KEY", "CUSTOM_PARENT_SECRET"}
	for _, k := range forbiddenKeys {
		if hasKey(safeEnv, k) {
			t.Errorf("expected secret %q to be absent from safeEnv, but found: %s", k, getKeyVal(safeEnv, k))
		}
	}

	// Verify baseline variables are present
	if runtime.GOOS != "windows" {
		if !hasKey(safeEnv, "PATH") {
			t.Errorf("expected PATH to be present in safeEnv")
		}
		if !hasKey(safeEnv, "HOME") {
			t.Errorf("expected HOME to be present in safeEnv")
		}
		if !hasKey(safeEnv, "USER") {
			t.Errorf("expected USER to be present in safeEnv")
		}
		if !hasKey(safeEnv, "TMPDIR") {
			t.Errorf("expected TMPDIR to be present in safeEnv")
		}
	} else {
		if !hasKey(safeEnv, "PATH") && !hasKey(safeEnv, "Path") {
			t.Errorf("expected PATH to be present in safeEnv on Windows")
		}
	}

	// 2. Calling with caller-specified protoEnv
	protoEnv := []string{
		"ALLOWED_TOOL_KEY=tool_val_1",
		"PYTHONUNBUFFERED=1",
	}
	mergedEnv := BuildSafeSubprocessEnv(protoEnv, false)
	for _, k := range forbiddenKeys {
		if hasKey(mergedEnv, k) {
			t.Errorf("expected secret %q to be absent from mergedEnv", k)
		}
	}
	if getKeyVal(mergedEnv, "ALLOWED_TOOL_KEY") != "tool_val_1" {
		t.Errorf("expected ALLOWED_TOOL_KEY=tool_val_1 in mergedEnv, got: %q", getKeyVal(mergedEnv, "ALLOWED_TOOL_KEY"))
	}
	if getKeyVal(mergedEnv, "PYTHONUNBUFFERED") != "1" {
		t.Errorf("expected PYTHONUNBUFFERED=1 in mergedEnv, got: %q", getKeyVal(mergedEnv, "PYTHONUNBUFFERED"))
	}

	// 3. Explicit host ref expansion only happens when expandHostRefs=true
	t.Setenv("EXPLICIT_MCP_TOKEN", "expanded-secret-token")
	rawEnv := BuildSafeSubprocessEnv([]string{"TOKEN=${EXPLICIT_MCP_TOKEN}", "LITERAL=p@ss$123"}, false)
	if getKeyVal(rawEnv, "TOKEN") != "${EXPLICIT_MCP_TOKEN}" {
		t.Errorf("expected unexpanded TOKEN when expandHostRefs=false, got: %q", getKeyVal(rawEnv, "TOKEN"))
	}
	expandedEnv := BuildSafeSubprocessEnv([]string{"TOKEN=Bearer ${EXPLICIT_MCP_TOKEN}", "LITERAL=p@ss$123"}, true)
	if getKeyVal(expandedEnv, "TOKEN") != "Bearer expanded-secret-token" {
		t.Errorf("expected expanded TOKEN, got: %q", getKeyVal(expandedEnv, "TOKEN"))
	}
	if getKeyVal(expandedEnv, "LITERAL") != "p@ss$123" {
		t.Errorf("expected bare $ literal preserved, got: %q", getKeyVal(expandedEnv, "LITERAL"))
	}

	// 4. Sensitive gateway secrets must NOT be expanded even when expandHostRefs=true
	t.Setenv("ADMIN_API_KEY", "secret-gateway-admin-key")
	t.Setenv("AGENT_API_KEY", "secret-gateway-agent-key")
	blockedEnv := BuildSafeSubprocessEnv([]string{"LEAK=${ADMIN_API_KEY}", "LEAK_AGENT=${AGENT_API_KEY}"}, true)
	if strings.Contains(getKeyVal(blockedEnv, "LEAK"), "secret-gateway-admin-key") {
		t.Fatalf("CRITICAL LEAK: expandBracedHostRefs must block gateway secret ADMIN_API_KEY")
	}
	if strings.Contains(getKeyVal(blockedEnv, "LEAK_AGENT"), "secret-gateway-agent-key") {
		t.Fatalf("CRITICAL LEAK: expandBracedHostRefs must block gateway secret AGENT_API_KEY")
	}
}

func TestHTTPDialer_UpstreamHeaderStripping(t *testing.T) {
	// Capture the headers that actually arrive at the mock upstream MCP server.
	var receivedHeaders http.Header
	var receivedMu sync.Mutex
	endpointReceived := make(chan struct{})

	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("skipping test requiring loopback socket: %v", err)
	}
	mockUpstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMu.Lock()
		receivedHeaders = r.Header.Clone()
		receivedMu.Unlock()

		// Respond with a minimal SSE endpoint event, then close.
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		fmt.Fprintf(w, "event: endpoint\ndata: /message?sessionId=test-sess-001\n\n")
		if flusher != nil {
			flusher.Flush()
		}
		close(endpointReceived)
		// Keep the connection open briefly so the dialer can read the endpoint event.
		<-r.Context().Done()
	}))
	mockUpstream.Listener = l
	mockUpstream.Start()
	defer mockUpstream.Close()

	// Build inbound client headers that simulate a real ingress request
	clientHeaders := make(http.Header)
	clientHeaders.Set("Authorization", "Bearer faw_live_client_secret_token_12345")
	clientHeaders.Set("X-API-Key", "faw_live_api_key_67890")
	clientHeaders.Set("Cookie", "session=super-secret-user-cookie; jwt=abc123")
	clientHeaders.Set("X-FaradAiWire-Signature", "t=1700000000,v1=abcdef")
	clientHeaders.Set("X-FaradAiWire-Timestamp", "1700000000")
	clientHeaders.Set("X-FaradAiWire-User-Role", "Admin")
	clientHeaders.Set("Connection", "keep-alive")
	clientHeaders.Set("Proxy-Authorization", "Basic eW91bmdibG9vZA==")
	// These must pass through:
	clientHeaders.Set("Content-Type", "application/json")
	clientHeaders.Set("X-Request-ID", "req-dial-strip-777")
	clientHeaders.Set("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")

	upstreamToken := "upstream-mcp-target-token-xyz"
	proto := agent.ProtocolConfig{
		ID:           "test-header-strip-proto",
		Name:         "test-header-strip",
		URLOrCommand: mockUpstream.URL,
		Type:         "sse",
		AuthToken:    upstreamToken,
	}

	dialer := NewHTTPDialer(nil, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	eventCh := make(chan SSEEvent, 10)
	upSess := dialer.Dial(ctx, proto, eventCh, "client-strip-test", clientHeaders)
	if upSess == nil {
		t.Fatalf("expected non-nil UpstreamSession")
	}
	defer func() {
		cancel()
		upSess.Close()
	}()

	// Wait for the mock upstream to receive and capture headers.
	select {
	case <-endpointReceived:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for mock upstream to receive request")
	}

	receivedMu.Lock()
	hdrs := receivedHeaders
	receivedMu.Unlock()

	if hdrs == nil {
		t.Fatalf("received headers were nil")
	}

	// 1. Client credentials MUST be stripped
	blockedHeaders := []string{
		"X-Api-Key",
		"Cookie",
		"X-FaradAiWire-Signature",
		"X-FaradAiWire-Timestamp",
		"X-FaradAiWire-User-Role",
		"Proxy-Authorization",
	}
	for _, h := range blockedHeaders {
		if v := hdrs.Get(h); v != "" {
			t.Errorf("CREDENTIAL LEAK: expected %q to be stripped from upstream request, got %q", h, v)
		}
	}

	// 2. Client Authorization must be REPLACED with the upstream target token, not the client token
	authVal := hdrs.Get("Authorization")
	expectedAuth := "Bearer " + upstreamToken
	if authVal != expectedAuth {
		t.Errorf("expected Authorization %q, got %q", expectedAuth, authVal)
	}
	if strings.Contains(authVal, "faw_live_client_secret") {
		t.Fatalf("CRITICAL LEAK: client auth token leaked to upstream as Authorization header")
	}

	// 3. Safe transport headers MUST be preserved
	if hdrs.Get("Content-Type") != "application/json" {
		t.Errorf("expected Content-Type application/json preserved, got %q", hdrs.Get("Content-Type"))
	}
	if hdrs.Get("X-Request-Id") != "req-dial-strip-777" {
		t.Errorf("expected X-Request-ID req-dial-strip-777 preserved, got %q", hdrs.Get("X-Request-Id"))
	}
	if hdrs.Get("Traceparent") == "" {
		t.Errorf("expected Traceparent header preserved")
	}
}

func TestHTTPDialer_UpstreamHeaderStripping_NoToken(t *testing.T) {
	// When no upstream AuthToken is configured, Authorization must be completely absent.
	var receivedHeaders http.Header
	var receivedMu sync.Mutex
	endpointReceived := make(chan struct{})

	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("skipping test requiring loopback socket: %v", err)
	}
	mockUpstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMu.Lock()
		receivedHeaders = r.Header.Clone()
		receivedMu.Unlock()

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		fmt.Fprintf(w, "event: endpoint\ndata: /message?sessionId=test-sess-notoken\n\n")
		if flusher != nil {
			flusher.Flush()
		}
		close(endpointReceived)
		<-r.Context().Done()
	}))
	mockUpstream.Listener = l
	mockUpstream.Start()
	defer mockUpstream.Close()

	clientHeaders := make(http.Header)
	clientHeaders.Set("Authorization", "Bearer faw_live_client_secret_token_99999")
	clientHeaders.Set("X-API-Key", "faw_live_api_key_99999")
	clientHeaders.Set("Cookie", "session=victim-cookie")

	proto := agent.ProtocolConfig{
		ID:           "test-header-strip-notoken",
		Name:         "test-strip-notoken",
		URLOrCommand: mockUpstream.URL,
		Type:         "sse",
		AuthToken:    "", // No upstream token configured
	}

	dialer := NewHTTPDialer(nil, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	eventCh := make(chan SSEEvent, 10)
	upSess := dialer.Dial(ctx, proto, eventCh, "client-strip-notoken", clientHeaders)
	if upSess == nil {
		t.Fatalf("expected non-nil UpstreamSession")
	}
	defer func() {
		cancel()
		upSess.Close()
	}()

	select {
	case <-endpointReceived:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for mock upstream to receive request")
	}

	receivedMu.Lock()
	hdrs := receivedHeaders
	receivedMu.Unlock()

	// Client Authorization must NOT leak when no upstream token is set
	if v := hdrs.Get("Authorization"); v != "" {
		t.Errorf("expected Authorization to be empty when no upstream token, got %q", v)
	}
	if v := hdrs.Get("X-Api-Key"); v != "" {
		t.Errorf("expected X-API-Key to be stripped, got %q", v)
	}
	if v := hdrs.Get("Cookie"); v != "" {
		t.Errorf("expected Cookie to be stripped, got %q", v)
	}
}

type blockingWriteCloser struct {
	writing chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func (b *blockingWriteCloser) Write(p []byte) (int, error) {
	select {
	case b.writing <- struct{}{}:
	default:
	}
	<-b.closed
	return 0, io.ErrClosedPipe
}

func (b *blockingWriteCloser) Close() error {
	b.once.Do(func() {
		close(b.closed)
	})
	return nil
}

func TestUpstreamSession_CloseDoesNotDeadlockOnBlockedStdin(t *testing.T) {
	bwc := &blockingWriteCloser{
		writing: make(chan struct{}, 1),
		closed:  make(chan struct{}),
	}
	sess := &UpstreamSession{
		ProtocolName: "blocked-stdin-test",
		Type:         "stdio",
		Status:       "READY",
		stdin:        bwc,
	}

	writeErrCh := make(chan error, 1)
	go func() {
		writeErrCh <- sess.SendNotification([]byte(`{"jsonrpc":"2.0","method":"notify"}`))
	}()

	select {
	case <-bwc.writing:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for SendNotification to enter stdin.Write")
	}

	closeDone := make(chan struct{})
	go func() {
		sess.Close()
		close(closeDone)
	}()

	select {
	case <-closeDone:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("UpstreamSession.Close deadlocked while stdin.Write was blocked")
	}

	select {
	case err := <-writeErrCh:
		if !errors.Is(err, ErrSubprocessTerminated) {
			t.Fatalf("expected ErrSubprocessTerminated after Close, got %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("SendNotification did not unblock after Close closed stdin")
	}
}

func TestCompositeDialer_StdioDisabledReturnsNonNilDegradedSession(t *testing.T) {
	cd := NewCompositeDialer(nil, nil)
	cd.SetStdioAllowed(false)

	sess := cd.Dial(context.Background(), agent.ProtocolConfig{
		ID:           "legacy-stdio",
		Name:         "legacy-stdio",
		Type:         "stdio",
		Command:      "sleep",
		URLOrCommand: "sleep 60",
	}, nil, "client-1", nil)
	if sess == nil {
		t.Fatal("expected non-nil UpstreamSession when stdio is disabled")
	}
	if sess.GetStatus() != "DEGRADED" {
		t.Fatalf("expected DEGRADED status, got %q", sess.GetStatus())
	}
	if sess.cmd != nil {
		t.Fatal("expected no subprocess spawned when stdio is disabled")
	}
}
