package session

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/settings"
)

// ErrBridgeAlreadyExists is returned by CreateBridge when an active bridge already exists for the given clientSessionID.
var ErrBridgeAlreadyExists = errors.New("session bridge already exists")

// ErrBridgeAgentMismatch is returned when an existing clientSessionID is reused for a different target agent.
var ErrBridgeAgentMismatch = errors.New("session bridge belongs to a different agent")

// Manager orchestrates multi-agent client session bridges and upstream connections.
type Manager struct {
	repo          agent.Resolver
	dialer        Dialer
	bridges       map[string]*AgentSessionBridge
	bridgesMu     sync.RWMutex
	dialTimeout   time.Duration
	cleanupWg     sync.WaitGroup
	isDraining    atomic.Bool
	bridgeSeq     atomic.Uint64
	settingsCache *settings.Cache
	mu            sync.RWMutex
}

// NewManager creates a new session Manager.
func NewManager(repo agent.Resolver, client *http.Client, dialTimeout ...time.Duration) *Manager {
	timeout := 500 * time.Millisecond
	if len(dialTimeout) > 0 && dialTimeout[0] > 0 {
		timeout = dialTimeout[0]
	}
	return &Manager{
		repo:        repo,
		dialer:      NewCompositeDialer(NewHTTPDialer(client, timeout), NewStdioDialer()),
		bridges:     make(map[string]*AgentSessionBridge),
		dialTimeout: timeout,
	}
}

// SetDialer allows swapping the Dialer implementation (useful for mocking in unit tests).
func (m *Manager) SetDialer(dialer Dialer) {
	m.dialer = dialer
}

// SetSettingsCache binds the dynamic atomic operational settings cache.
func (m *Manager) SetSettingsCache(c *settings.Cache) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.settingsCache = c
}

func (m *Manager) getMaxIdleTimeout() (time.Duration, bool) {
	m.mu.RLock()
	c := m.settingsCache
	m.mu.RUnlock()
	if c != nil {
		if s := c.Get(); s != nil && s.Maintenance.SessionIdleTimeoutMin > 0 {
			return time.Duration(s.Maintenance.SessionIdleTimeoutMin) * time.Minute, true
		}
	}
	return 0, false
}

// GetBridge retrieves an existing bridge by clientSessionID.
func (m *Manager) GetBridge(clientSessionID string) (*AgentSessionBridge, bool) {
	m.bridgesMu.RLock()
	bridge, ok := m.bridges[clientSessionID]
	m.bridgesMu.RUnlock()
	if ok && bridge != nil {
		bridge.Touch()
		return bridge, true
	}
	return nil, false
}

// HasActiveSessions checks if there are any active client session bridges associated with agentName.
func (m *Manager) HasActiveSessions(agentName string) bool {
	m.bridgesMu.RLock()
	defer m.bridgesMu.RUnlock()
	for _, b := range m.bridges {
		if b != nil && b.AgentName == agentName {
			return true
		}
	}
	return false
}

// CreateBridge initializes a multi-protocol bridge for the given agent and dials attached upstreams in parallel.
// It fails closed with ErrBridgeAlreadyExists if clientSessionID already maps to an active bridge.
func (m *Manager) CreateBridge(parentCtx context.Context, agentName, clientSessionID string, headers http.Header) (*AgentSessionBridge, error) {
	if clientSessionID == "" {
		seq := m.bridgeSeq.Add(1)
		clientSessionID = fmt.Sprintf("cl-%d-%x", time.Now().UnixNano(), seq&0xFFFF)
	} else {
		m.bridgesMu.RLock()
		_, exists := m.bridges[clientSessionID]
		m.bridgesMu.RUnlock()
		if exists {
			return nil, fmt.Errorf("%w: %s", ErrBridgeAlreadyExists, clientSessionID)
		}
	}

	bridge, err := m.dialBridge(parentCtx, agentName, clientSessionID, headers)
	if err != nil {
		return nil, err
	}

	m.bridgesMu.Lock()
	if _, exists := m.bridges[clientSessionID]; exists {
		m.bridgesMu.Unlock()
		bridge.Close()
		return nil, fmt.Errorf("%w: %s", ErrBridgeAlreadyExists, clientSessionID)
	}
	m.bridges[clientSessionID] = bridge
	m.bridgesMu.Unlock()

	return bridge, nil
}

// GetOrCreateBridge atomically retrieves an active bridge for clientSessionID or creates and stores a new one.
func (m *Manager) GetOrCreateBridge(parentCtx context.Context, agentName, clientSessionID string, headers http.Header) (*AgentSessionBridge, error) {
	if clientSessionID != "" {
		if existing, ok := m.GetBridge(clientSessionID); ok {
			if !strings.EqualFold(existing.AgentName, agentName) {
				return nil, fmt.Errorf("%w: session %q bound to %q cannot access %q", ErrBridgeAgentMismatch, clientSessionID, existing.AgentName, agentName)
			}
			return existing, nil
		}
	} else {
		seq := m.bridgeSeq.Add(1)
		clientSessionID = fmt.Sprintf("cl-%d-%x", time.Now().UnixNano(), seq&0xFFFF)
	}

	bridge, err := m.dialBridge(parentCtx, agentName, clientSessionID, headers)
	if err != nil {
		return nil, err
	}

	m.bridgesMu.Lock()
	if existing, exists := m.bridges[clientSessionID]; exists && existing != nil {
		m.bridgesMu.Unlock()
		bridge.Close()
		if !strings.EqualFold(existing.AgentName, agentName) {
			return nil, fmt.Errorf("%w: session %q bound to %q cannot access %q", ErrBridgeAgentMismatch, clientSessionID, existing.AgentName, agentName)
		}
		existing.Touch()
		return existing, nil
	}
	m.bridges[clientSessionID] = bridge
	m.bridgesMu.Unlock()

	return bridge, nil
}

func (m *Manager) dialBridge(parentCtx context.Context, agentName, clientSessionID string, headers http.Header) (*AgentSessionBridge, error) {
	if parentCtx == nil {
		parentCtx = context.Background()
	}

	agentCfg, err := m.repo.GetAgentConfig(agentName)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve agent config for '%s': %w", agentName, err)
	}

	bridgeCtx, bridgeCancel := context.WithCancel(parentCtx)

	bridge := &AgentSessionBridge{
		ClientSessionID: clientSessionID,
		AgentName:       agentName,
		Upstreams:       make(map[string]*UpstreamSession),
		NameToID:        make(map[string]string),
		EventCh:         make(chan SSEEvent, 128),
		Cancel:          bridgeCancel,
		BridgeCtx:       bridgeCtx,
		CreatedAt:       time.Now(),
		LastActive:      time.Now(),
	}

	// Parallel dial to all attached protocols
	var dialWg sync.WaitGroup
	var dialMu sync.Mutex

	for _, proto := range agentCfg.Protocols {
		if proto.URLOrCommand == "" {
			continue
		}
		protoCopy := proto
		dialWg.Add(1)
		go func(p agent.ProtocolConfig) {
			defer dialWg.Done()
			upSess := m.dialer.Dial(bridgeCtx, p, bridge.EventCh, clientSessionID, headers)
			dialMu.Lock()
			canonicalKey := p.ID
			if canonicalKey == "" {
				canonicalKey = p.Name
			}
			if canonicalKey != "" {
				bridge.Upstreams[canonicalKey] = upSess
			}
			if p.Name != "" && p.ID != "" {
				bridge.NameToID[p.Name] = p.ID
			}
			dialMu.Unlock()
		}(protoCopy)
	}
	dialWg.Wait()

	return bridge, nil
}

// GetOrDialUpstream provides Just-In-Time (JIT) connection acquisition or lazy reconnection.
func (m *Manager) GetOrDialUpstream(ctx context.Context, bridge *AgentSessionBridge, proto agent.ProtocolConfig, headers http.Header) (*UpstreamSession, error) {
	if bridge == nil {
		return nil, fmt.Errorf("bridge cannot be nil")
	}
	bridge.Touch()

	// Check existing upstream in bridge
	if existing := bridge.GetUpstream(proto.Name); existing != nil && existing.IsHealthy() {
		return existing, nil
	}
	if proto.ID != "" {
		if existing := bridge.GetUpstream(proto.ID); existing != nil && existing.IsHealthy() {
			return existing, nil
		}
	}

	// Redial JIT
	upSess := m.dialer.Dial(bridge.BridgeCtx, proto, bridge.EventCh, bridge.ClientSessionID, headers)
	bridge.SetUpstreamWithAlias(proto.ID, proto.Name, upSess)

	return upSess, nil
}

// SetDraining marks the session manager as draining during gateway shutdown.
func (m *Manager) SetDraining(draining bool) {
	m.isDraining.Store(draining)
}

// IsDraining reports whether the session manager is in draining mode.
func (m *Manager) IsDraining() bool {
	return m.isDraining.Load()
}

// BroadcastShutdownEvent notifies all active bridges with a shutdown event frame without closing upstreams.
func (m *Manager) BroadcastShutdownEvent() {
	m.bridgesMu.RLock()
	defer m.bridgesMu.RUnlock()
	for _, b := range m.bridges {
		if b != nil {
			b.BroadcastShutdownEvent()
		}
	}
}

// RemoveBridge closes and deletes an active session bridge.
// When the manager is in draining mode, bridges and upstreams are preserved until Phase 3 DrainAllBridges.
func (m *Manager) RemoveBridge(clientSessionID string) {
	if m.isDraining.Load() {
		return
	}

	m.bridgesMu.Lock()
	bridge, ok := m.bridges[clientSessionID]
	if ok {
		delete(m.bridges, clientSessionID)
	}
	m.bridgesMu.Unlock()

	if ok && bridge != nil {
		bridge.Close()
	}
}

// DrainAllBridges broadcasts a shutdown event to all active bridges, terminates upstreams, and clears the registry.
func (m *Manager) DrainAllBridges() {
	m.bridgesMu.Lock()
	bridges := make([]*AgentSessionBridge, 0, len(m.bridges))
	for sid, b := range m.bridges {
		bridges = append(bridges, b)
		delete(m.bridges, sid)
	}
	m.bridgesMu.Unlock()

	for _, b := range bridges {
		if b != nil {
			b.BroadcastShutdown()
		}
	}
}

// ActiveBridgesCount returns the number of currently active session bridges.
func (m *Manager) ActiveBridgesCount() int {
	m.bridgesMu.RLock()
	defer m.bridgesMu.RUnlock()
	return len(m.bridges)
}

// WaitForCleanup blocks until the active cleanup worker completes.
func (m *Manager) WaitForCleanup() {
	m.cleanupWg.Wait()
}

// StartCleanupLoop launches background worker to evict inactive session bridges safely.
func (m *Manager) StartCleanupLoop(ctx context.Context, interval, maxIdle time.Duration) {
	if interval <= 0 {
		interval = 1 * time.Minute
	}
	if maxIdle <= 0 {
		maxIdle = 30 * time.Minute
	}

	m.cleanupWg.Add(1)
	go func() {
		defer m.cleanupWg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				var staleBridges []*AgentSessionBridge
				now := time.Now()

				effectiveMaxIdle := maxIdle
				if dynamic, ok := m.getMaxIdleTimeout(); ok {
					effectiveMaxIdle = dynamic
				}

				m.bridgesMu.Lock()
				for sid, b := range m.bridges {
					b.mu.RLock()
					idleTime := now.Sub(b.LastActive)
					b.mu.RUnlock()

					if idleTime > effectiveMaxIdle {
						staleBridges = append(staleBridges, b)
						delete(m.bridges, sid)
					}
				}
				m.bridgesMu.Unlock()

				// Execute callbacks outside global manager lock to prevent lock convoys
				for _, b := range staleBridges {
					slog.Info("Evicting idle session bridge",
						slog.String("client_session_id", b.ClientSessionID),
						slog.String("agent", b.AgentName),
					)
					b.Close()
				}
			}
		}
	}()
}
