package session

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
)

// MockRepo implements agent.Repository for session tests.
type MockRepo struct {
	configs   map[string]*agent.RouteConfig
	manifests map[string][]agent.ToolMetadata
}

func (m *MockRepo) GetAgentConfig(agentName string) (*agent.RouteConfig, error) {
	if cfg, ok := m.configs[agentName]; ok {
		return cfg, nil
	}
	return nil, agent.NewAgentNotFoundError(agentName)
}

func (m *MockRepo) GetAgentManifest(agentName string) ([]agent.ToolMetadata, error) {
	if man, ok := m.manifests[agentName]; ok {
		return man, nil
	}
	return nil, agent.ErrManifestNotFound
}

func (m *MockRepo) ResolveToolProtocol(agentName, toolName string) (*agent.ToolTargetInfo, error) {
	return nil, nil
}

func (m *MockRepo) ResolveTargetURLFromPath(path string, defaultTargetURL string) (string, error) {
	return defaultTargetURL, nil
}

func (m *MockRepo) ListAgents() ([]string, error) {
	var list []string
	for k := range m.configs {
		list = append(list, k)
	}
	return list, nil
}

func (m *MockRepo) GetDefaultAgent() (*agent.RouteConfig, error) {
	for _, cfg := range m.configs {
		return cfg, nil
	}
	return nil, agent.NewAgentNotFoundError("default")
}

func (m *MockRepo) ClearCache() {}
func (m *MockRepo) SaveAgentConfig(agentName string, cfg *agent.RouteConfig) error { return nil }
func (m *MockRepo) DeleteAgent(agentName string) error { return nil }
func (m *MockRepo) SaveAgentManifest(agentName string, tools interface{}) error { return nil }
func (m *MockRepo) ListAgentArchives(agentName string) ([]string, error) { return nil, nil }
func (m *MockRepo) RollbackAgent(agentName, timestamp string) error { return nil }
func (m *MockRepo) ArchiveAgentCurrent(agentName string) error { return nil }

// MockDialer implements Dialer for testing.
type MockDialer struct {
	mu        sync.Mutex
	dialCalls []string
}

func (d *MockDialer) Dial(ctx context.Context, proto agent.ProtocolConfig, eventCh chan<- SSEEvent, clientSessionID string, headers http.Header) *UpstreamSession {
	d.mu.Lock()
	d.dialCalls = append(d.dialCalls, proto.Name)
	d.mu.Unlock()

	upSess := &UpstreamSession{
		ProtocolID:        proto.ID,
		ProtocolName:      proto.Name,
		URLOrCommand:      proto.URLOrCommand,
		BackendSessionID:  "backend-sess-" + proto.Name,
		BackendMessageURL: proto.URLOrCommand + "/messages?sessionId=backend-sess-" + proto.Name,
		Status:            "READY",
		LastPing:          time.Now(),
	}

	// Emit initial test event
	go func() {
		eventCh <- SSEEvent{
			Event:        "init",
			Data:         "connected to " + proto.Name,
			ProtocolName: proto.Name,
		}
	}()

	return upSess
}

func TestSessionManager_CreateBridgeAndParallelDial(t *testing.T) {
	mockRepo := &MockRepo{
		configs: map[string]*agent.RouteConfig{
			"agent-multi": {
				AgentID:     "agent-multi-id",
				AgentName:   "agent-multi",
				RoutingMode: "aggregated",
				Protocols: []agent.ProtocolConfig{
					{ID: "proto-1", Name: "db", URLOrCommand: "http://localhost:8001/sse"},
					{ID: "proto-2", Name: "api", URLOrCommand: "http://localhost:8002/sse"},
				},
			},
		},
	}

	dialer := &MockDialer{}
	mgr := NewManager(mockRepo, nil)
	mgr.SetDialer(dialer)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bridge, err := mgr.CreateBridge(ctx, "agent-multi", "client-123", nil)
	if err != nil {
		t.Fatalf("failed to create bridge: %v", err)
	}

	if bridge.ClientSessionID != "client-123" {
		t.Errorf("unexpected client session ID: %s", bridge.ClientSessionID)
	}

	// Verify both upstreams dialed
	if len(dialer.dialCalls) != 2 {
		t.Errorf("expected 2 dial calls, got %d", len(dialer.dialCalls))
	}

	dbUp := bridge.GetUpstream("db")
	if dbUp == nil || !dbUp.IsHealthy() {
		t.Errorf("expected healthy db upstream, got: %+v", dbUp)
	}
	if dbUp.GetBackendSessionID() != "backend-sess-db" {
		t.Errorf("unexpected backend session ID: %s", dbUp.GetBackendSessionID())
	}

	apiUp := bridge.GetUpstream("api")
	if apiUp == nil || !apiUp.IsHealthy() {
		t.Errorf("expected healthy api upstream, got: %+v", apiUp)
	}

	// Verify event multiplexing channel
	select {
	case ev := <-bridge.EventCh:
		if ev.Event != "init" {
			t.Errorf("unexpected event: %+v", ev)
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("timeout waiting for bridge event")
	}

	// Retrieve bridge from manager
	retrieved, ok := mgr.GetBridge("client-123")
	if !ok || retrieved != bridge {
		t.Errorf("failed to retrieve bridge from manager")
	}

	// Remove bridge
	mgr.RemoveBridge("client-123")
	_, existsAfterRemove := mgr.GetBridge("client-123")
	if existsAfterRemove {
		t.Error("bridge should have been removed")
	}
}

func TestSessionManager_JITReconnect(t *testing.T) {
	mockRepo := &MockRepo{
		configs: map[string]*agent.RouteConfig{
			"agent-jit": {
				AgentID:     "jit-id",
				AgentName:   "agent-jit",
				RoutingMode: "aggregated",
				Protocols:   []agent.ProtocolConfig{},
			},
		},
	}

	dialer := &MockDialer{}
	mgr := NewManager(mockRepo, nil)
	mgr.SetDialer(dialer)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bridge, err := mgr.CreateBridge(ctx, "agent-jit", "client-jit", nil)
	if err != nil {
		t.Fatalf("failed to create bridge: %v", err)
	}

	// JIT dial a new protocol
	proto := agent.ProtocolConfig{
		ID:           "jit-proto",
		Name:         "analytics",
		URLOrCommand: "http://localhost:8003/sse",
	}

	upSess, err := mgr.GetOrDialUpstream(ctx, bridge, proto, nil)
	if err != nil {
		t.Fatalf("unexpected JIT dial error: %v", err)
	}
	if upSess == nil || !upSess.IsHealthy() {
		t.Errorf("expected healthy JIT upstream, got: %+v", upSess)
	}

	// Calling again should return cached upstream without redialing
	dialer.dialCalls = nil
	cachedUp, errCached := mgr.GetOrDialUpstream(ctx, bridge, proto, nil)
	if errCached != nil || cachedUp != upSess {
		t.Errorf("expected cached upstream, got: %+v, err: %v", cachedUp, errCached)
	}
	if len(dialer.dialCalls) != 0 {
		t.Errorf("expected 0 new dial calls for cached upstream, got %d", len(dialer.dialCalls))
	}
}

func TestBuildTargetMessageURL(t *testing.T) {
	tests := []struct {
		name        string
		protoURL    string
		msgPath     string
		expected    string
		expectError bool
	}{
		{
			name:     "Relative path resolution",
			protoURL: "http://localhost:8001/sse",
			msgPath:  "/messages?sessionId=abc",
			expected: "http://localhost:8001/messages?sessionId=abc",
		},
		{
			name:     "Absolute message URL",
			protoURL: "http://localhost:8001/sse",
			msgPath:  "http://remote-backend:9000/custom/msg?id=xyz",
			expected: "http://remote-backend:9000/custom/msg?id=xyz",
		},
		{
			name:     "Empty message path default",
			protoURL: "http://localhost:8001/base/sse",
			msgPath:  "",
			expected: "http://localhost:8001/message",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := BuildTargetMessageURL(tc.protoURL, tc.msgPath)
			if tc.expectError && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.expectError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res != tc.expected {
				t.Errorf("expected '%s', got '%s'", tc.expected, res)
			}
		})
	}
}

func TestSessionManager_StartCleanupLoop(t *testing.T) {
	mockRepo := &MockRepo{
		configs: map[string]*agent.RouteConfig{
			"agent-test": {
				AgentName: "agent-test",
				Protocols: []agent.ProtocolConfig{},
			},
		},
	}
	mgr := NewManager(mockRepo, nil)
	mgr.SetDialer(&MockDialer{})

	ctx, cancel := context.WithCancel(context.Background())

	// Create bridge 1 (stale/idle)
	bridge1, err := mgr.CreateBridge(ctx, "agent-test", "client-stale", nil)
	if err != nil {
		t.Fatalf("failed to create bridge1: %v", err)
	}
	bridge1.SetLastActive(time.Now().Add(-10 * time.Minute))

	// Create bridge 2 (fresh/active)
	_, err = mgr.CreateBridge(ctx, "agent-test", "client-active", nil)
	if err != nil {
		t.Fatalf("failed to create bridge2: %v", err)
	}

	if mgr.ActiveBridgesCount() != 2 {
		t.Fatalf("expected 2 active bridges initially, got %d", mgr.ActiveBridgesCount())
	}

	// Start cleanup loop with 10ms interval and 50ms max idle timeout
	mgr.StartCleanupLoop(ctx, 10*time.Millisecond, 50*time.Millisecond)

	// Poll until stale bridge is purged
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if mgr.ActiveBridgesCount() == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if mgr.ActiveBridgesCount() != 1 {
		t.Fatalf("expected 1 active bridge after eviction, got %d", mgr.ActiveBridgesCount())
	}

	if _, exists := mgr.GetBridge("client-stale"); exists {
		t.Errorf("expected client-stale to be purged")
	}
	if _, exists := mgr.GetBridge("client-active"); !exists {
		t.Errorf("expected client-active to be retained")
	}

	// Terminate cleanup loop cleanly
	cancel()
	mgr.WaitForCleanup()
}

func TestAgentSessionBridge_CanonicalIndexingAndSingleClose(t *testing.T) {
	mockRepo := &MockRepo{
		configs: map[string]*agent.RouteConfig{
			"agent-canon": {
				Protocols: []agent.ProtocolConfig{
					{
						ID:           "proto-uuid-1",
						Name:         "github-mcp",
						URLOrCommand: "http://localhost:8001/mcp",
					},
					{
						ID:           "proto-uuid-2",
						Name:         "slack-mcp",
						URLOrCommand: "http://localhost:8002/mcp",
					},
				},
			},
		},
	}

	closeCounts := make(map[string]int)
	var countsMu sync.Mutex

	dialer := &MockDialer{}
	mgr := NewManager(mockRepo, nil)
	mgr.SetDialer(dialer)

	ctx := context.Background()
	bridge, err := mgr.CreateBridge(ctx, "agent-canon", "client-test-canon", nil)
	if err != nil {
		t.Fatalf("failed to create bridge: %v", err)
	}

	// Verify Upstreams map only contains canonical IDs (length == 2, NOT 4)
	if len(bridge.Upstreams) != 2 {
		t.Fatalf("expected exactly 2 canonical entries in Upstreams, got %d", len(bridge.Upstreams))
	}
	if _, ok := bridge.Upstreams["proto-uuid-1"]; !ok {
		t.Errorf("expected Upstreams to contain proto-uuid-1")
	}
	if _, ok := bridge.Upstreams["proto-uuid-2"]; !ok {
		t.Errorf("expected Upstreams to contain proto-uuid-2")
	}

	// Verify NameToID has name aliases
	if bridge.NameToID["github-mcp"] != "proto-uuid-1" {
		t.Errorf("expected NameToID[github-mcp] == proto-uuid-1, got %q", bridge.NameToID["github-mcp"])
	}
	if bridge.NameToID["slack-mcp"] != "proto-uuid-2" {
		t.Errorf("expected NameToID[slack-mcp] == proto-uuid-2, got %q", bridge.NameToID["slack-mcp"])
	}

	// Verify GetUpstream works by both ID and Name
	byID := bridge.GetUpstream("proto-uuid-1")
	byName := bridge.GetUpstream("github-mcp")
	if byID == nil || byName == nil || byID != byName {
		t.Fatalf("expected GetUpstream to return identical UpstreamSession for ID and Name")
	}

	// Attach cancel callbacks to verify single close execution
	for id, up := range bridge.Upstreams {
		capturedID := id
		up.Cancel = func() {
			countsMu.Lock()
			closeCounts[capturedID]++
			countsMu.Unlock()
		}
	}

	// Also simulate artificial pointer aliasing to rigorously test deduplication
	bridge.SetUpstream("aliased-key-1", bridge.Upstreams["proto-uuid-1"])
	bridge.SetUpstream("aliased-key-2", bridge.Upstreams["proto-uuid-1"])

	// Close the bridge
	bridge.Close()

	// Verify each upstream was closed exactly once
	countsMu.Lock()
	defer countsMu.Unlock()

	if closeCounts["proto-uuid-1"] != 1 {
		t.Errorf("expected proto-uuid-1 to be closed exactly once, got %d", closeCounts["proto-uuid-1"])
	}
	if closeCounts["proto-uuid-2"] != 1 {
		t.Errorf("expected proto-uuid-2 to be closed exactly once, got %d", closeCounts["proto-uuid-2"])
	}
}

