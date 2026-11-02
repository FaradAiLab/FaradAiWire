package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/auth"
	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
	"github.com/FaradAiLab/FaradAiWire/internal/session"
)

// SetAgentRepository sets the agent resolver and updates corresponding aggregator, dispatcher, and coordinator.
func (s *SSEProxy) SetAgentRepository(repo agent.Resolver) {
	s.getCoordinator().SetAgentRepository(repo)
}

// SetSessionManager sets the session manager and updates dispatcher and coordinator.
func (s *SSEProxy) SetSessionManager(mgr *session.Manager) {
	s.getCoordinator().SetSessionManager(mgr)
}

// SetToolDispatcher allows injecting a custom MCP tool dispatcher.
func (s *SSEProxy) SetToolDispatcher(dispatcher session.ToolDispatcher) {
	s.getCoordinator().SetToolDispatcher(dispatcher)
}

// SetManifestAggregator allows injecting a custom manifest aggregator.
func (s *SSEProxy) SetManifestAggregator(agg agent.ManifestAggregator) {
	s.getCoordinator().SetManifestAggregator(agg)
}

// SetCorrelationStore allows injecting a custom correlation store.
func (s *SSEProxy) SetCorrelationStore(store CorrelationStore) {
	coord := s.getCoordinator()
	coord.SetCorrelationStore(store)
	if forwarder := coord.Forwarder(); forwarder != nil {
		forwarder.SetCorrelationStore(store)
	}
}

// SetKeyValidator updates or injects a KeyValidator for client authentication.
func (s *SSEProxy) SetKeyValidator(v auth.KeyValidator) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keyValidator = v
	if s.contextExtractor != nil {
		s.contextExtractor.SetKeyValidator(v)
	} else {
		s.contextExtractor = NewContextExtractor(s.userCtxCfg, v)
	}
}

// SessionManager returns the underlying session manager instance from coordinator.
func (s *SSEProxy) SessionManager() *session.Manager {
	return s.getCoordinator().SessionManager()
}

// CorrelationStore returns the underlying correlation store from coordinator.
func (s *SSEProxy) CorrelationStore() CorrelationStore {
	return s.getCoordinator().CorrelationStore()
}

// CleanupStaleSessions purges expired entries from the correlation store and stale session target mappings.
func (s *SSEProxy) CleanupStaleSessions(correlationMaxAge, targetMaxAge time.Duration) {
	if s == nil {
		return
	}
	cStore := s.CorrelationStore()
	if cStore != nil {
		cStore.Cleanup(correlationMaxAge)
	}

	s.mu.Lock()
	now := time.Now()
	for k, v := range s.sessionTargets {
		if now.Sub(v.timestamp) > targetMaxAge {
			delete(s.sessionTargets, k)
		}
	}
	s.mu.Unlock()
}

// SessionTargetsCount returns the current count of active session target bindings.
func (s *SSEProxy) SessionTargetsCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessionTargets)
}

// SetSessionTarget registers or updates a target URL binding for a given session ID.
func (s *SSEProxy) SetSessionTarget(sessionID, targetURL string, ts time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ts.IsZero() {
		ts = time.Now()
	}
	s.sessionTargets[sessionID] = sessionBinding{
		targetURL: targetURL,
		timestamp: ts,
	}
}

func (s *SSEProxy) resolveTargetURL(r *http.Request) (string, error) {
	repo := s.getCoordinator().AgentRepository()
	if repo == nil {
		return s.targetURL, nil
	}
	return repo.ResolveTargetURLFromPath(r.URL.Path, s.targetURL)
}

const unauthorizedPayload = `{"error":"UNAUTHORIZED","message":"Missing, invalid, or revoked API key. Provide Authorization: Bearer <key> or X-API-Key."}`

func (s *SSEProxy) writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", `Bearer realm="FaradAiWire"`)
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(unauthorizedPayload))
}

func (s *SSEProxy) authenticate(r *http.Request) (*filter.UserContext, error) {
	s.mu.RLock()
	extractor := s.contextExtractor
	keyVal := s.keyValidator
	s.mu.RUnlock()

	if extractor != nil {
		return extractor.Authenticate(r)
	}
	if keyVal != nil {
		return NewContextExtractor(s.userCtxCfg, keyVal).Authenticate(r)
	}
	return NewContextExtractor(s.userCtxCfg).Authenticate(r)
}

func (s *SSEProxy) extractUserContext(r *http.Request) *filter.UserContext {
	uCtx, err := s.authenticate(r)
	if err != nil {
		return nil
	}
	return uCtx
}

func (s *SSEProxy) checkAggregatedAgent(r *http.Request) (string, bool, error) {
	p := strings.TrimPrefix(r.URL.Path, "/sse")
	p = strings.Trim(p, "/")
	p = strings.TrimSuffix(p, "/message")
	p = strings.Trim(p, "/")

	var keyAgent string
	if uVal := r.Context().Value(filter.UserContextKey); uVal != nil {
		if uc, ok := uVal.(*filter.UserContext); ok && uc != nil {
			keyAgent = strings.TrimSpace(uc.AgentName)
		}
	}

	repo := s.getCoordinator().AgentRepository()
	parts := strings.Split(p, "/")
	if len(parts) == 1 && parts[0] != "" {
		agentName := parts[0]
		// Fail-closed authorization: If key is strictly scoped to another agent, reject with 403
		if keyAgent != "" && keyAgent != "*" && !strings.EqualFold(keyAgent, agentName) {
			return "", false, fmt.Errorf("AGENT_ACCESS_DENIED: API key is scoped to agent '%s', access to '%s' is forbidden", keyAgent, agentName)
		}

		if repo != nil {
			agentCfg, err := repo.GetAgentConfig(agentName)
			if err != nil {
				return "", false, err
			}
			if agentCfg.IsDirect() {
				return "", false, fmt.Errorf("ROUTING_VIOLATION_DIRECT: Agent '%s' is configured in DIRECT mode. Please specify target MCP in path: '/sse/%s/{mcp_name}'", agentName, agentName)
			}
			return agentName, true, nil
		}
	} else if p == "" || len(parts) == 0 || parts[0] == "" {
		// 1. Check if an explicit profile / agent name was passed via header or query param
		explicitAgent := ""
		if r != nil {
			if prof := strings.TrimSpace(r.Header.Get("X-FaradAiWire-Profile")); prof != "" {
				explicitAgent = prof
			} else if r.URL != nil && strings.TrimSpace(r.URL.Query().Get("profile")) != "" {
				explicitAgent = strings.TrimSpace(r.URL.Query().Get("profile"))
			} else if ag := strings.TrimSpace(r.Header.Get("X-FaradAiWire-Agent-Name")); ag != "" {
				explicitAgent = ag
			} else if r.URL != nil && strings.TrimSpace(r.URL.Query().Get("agent")) != "" {
				explicitAgent = strings.TrimSpace(r.URL.Query().Get("agent"))
			}
		}

		if explicitAgent != "" {
			if keyAgent != "" && keyAgent != "*" && !strings.EqualFold(keyAgent, explicitAgent) {
				return "", false, fmt.Errorf("AGENT_ACCESS_DENIED: API key is scoped to agent '%s', access to '%s' is forbidden", keyAgent, explicitAgent)
			}
			if repo != nil {
				agentCfg, err := repo.GetAgentConfig(explicitAgent)
				if err != nil {
					return "", false, err
				}
				if agentCfg.IsDirect() {
					return "", false, fmt.Errorf("ROUTING_VIOLATION_DIRECT: Agent '%s' is configured in DIRECT mode. Please specify target MCP in path: '/sse/%s/{mcp_name}'", explicitAgent, explicitAgent)
				}
				return explicitAgent, true, nil
			}
		}

		// 2. Implicit Agent Resolution: If key is scoped to a specific agent, auto-route to that agent
		if keyAgent != "" && keyAgent != "*" && repo != nil {
			if agentCfg, err := repo.GetAgentConfig(keyAgent); err == nil && agentCfg != nil {
				if agentCfg.IsDirect() {
					return "", false, fmt.Errorf("ROUTING_VIOLATION_DIRECT: Scoped Agent '%s' is configured in DIRECT mode.", keyAgent)
				}
				return agentCfg.AgentName, true, nil
			}
		}

		// 3. Default Agent Resolution
		if repo != nil {
			if defAgent, err := repo.GetDefaultAgent(); err == nil && defAgent != nil {
				if defAgent.IsDirect() {
					return "", false, fmt.Errorf("ROUTING_VIOLATION_DIRECT: Default Agent '%s' is configured in DIRECT mode.", defAgent.AgentName)
				}
				return defAgent.AgentName, true, nil
			}
		}
	}
	return "", false, nil
}

func (s *SSEProxy) writeRoutingError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	if strings.Contains(err.Error(), "AGENT_ACCESS_DENIED") {
		w.WriteHeader(http.StatusForbidden)
	} else if errors.Is(err, agent.ErrAgentNotFound) || errors.Is(err, agent.ErrProtocolNotFound) || strings.Contains(err.Error(), "MCP_NOT_FOUND") || strings.Contains(err.Error(), "AGENT_NOT_FOUND") {
		w.WriteHeader(http.StatusNotFound)
	} else if errors.Is(err, agent.ErrRoutingModeViolation) || strings.Contains(err.Error(), "ROUTING_VIOLATION") {
		w.WriteHeader(http.StatusBadRequest)
	} else {
		w.WriteHeader(http.StatusBadRequest)
	}
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   "Routing Error",
		"message": err.Error(),
	})
}

func (s *SSEProxy) onDirectEndpoint(targetURLStr string) func(string, string) {
	return func(realSessionID, cleanData string) {
		s.mu.Lock()
		if targetURLStr != "" {
			s.sessionTargets[realSessionID] = sessionBinding{
				targetURL:   targetURLStr,
				backendPath: cleanData,
				timestamp:   time.Now(),
			}
		}
		s.mu.Unlock()

		if cleanData != "" {
			if coord := s.getCoordinator(); coord != nil {
				if fwd := coord.Forwarder(); fwd != nil {
					fwd.SetSessionBackendPath(realSessionID, cleanData)
				}
			}
		}
	}
}

func (s *SSEProxy) readRequestBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Request body too large or unreadable: "+err.Error(), http.StatusBadRequest)
		return nil, false
	}
	return body, true
}

func (s *SSEProxy) writeParseError(w http.ResponseWriter, parseErr error) {
	resp := mcp.NewErrorResponse(nil, mcp.ErrParseError, "Parse error: "+parseErr.Error(), nil)
	respBytes, _ := json.Marshal(resp)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(respBytes)
}

func (s *SSEProxy) resolveSessionTarget(sid string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if binding, ok := s.sessionTargets[sid]; ok && binding.targetURL != "" {
		return binding.targetURL, true
	}
	return "", false
}

func (s *SSEProxy) getCoordinator() *session.InboundCoordinator {
	s.mu.RLock()
	coord := s.coordinator
	s.mu.RUnlock()

	if coord != nil {
		return coord
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.coordinator == nil {
		cStore := NewMemoryCorrelationStore()
		fwd := session.NewForwarder(s.httpClient, nil, cStore)
		s.coordinator = session.NewInboundCoordinator(nil, nil, nil, nil, nil, cStore, fwd, s.targetURL)
	}
	return s.coordinator
}

func (s *SSEProxy) streamBridgeEvents(bridge *session.AgentSessionBridge, w io.Writer, flusher http.Flusher, clientSessionID string) {
	pingTicker := time.NewTicker(15 * time.Second)
	defer pingTicker.Stop()

	for {
		select {
		case <-bridge.BridgeCtx.Done():
			select {
			case ev, ok := <-bridge.EventCh:
				if ok {
					_, _ = w.Write([]byte(fmt.Sprintf("event: %s\ndata: %s\n\n", ev.Event, ev.Data)))
					flusher.Flush()
				}
			default:
			}
			return
		case <-pingTicker.C:
			_, _ = w.Write([]byte(": ping\n\n"))
			flusher.Flush()
		case ev, ok := <-bridge.EventCh:
			if !ok {
				return
			}
			data := ev.Data
			if ev.Event == "message" {
				if fwd := s.getCoordinator().Forwarder(); fwd != nil {
					data = fwd.ProcessOutgoingMessage(data, clientSessionID, "")
				}
			}
			_, _ = w.Write([]byte(fmt.Sprintf("event: %s\ndata: %s\n\n", ev.Event, data)))
			flusher.Flush()
			if ev.Event == "shutdown" {
				return
			}
		}
	}
}

func extractSessionID(r *http.Request) string {
	clientSessionID := r.URL.Query().Get("sessionId")
	if clientSessionID == "" {
		clientSessionID = r.URL.Query().Get("session_id")
	}
	if clientSessionID == "" {
		clientSessionID = r.Header.Get("Mcp-Session-Id")
	}
	if clientSessionID == "" {
		clientSessionID = r.Header.Get("mcp-session-id")
	}
	if clientSessionID == "" {
		clientSessionID = fmt.Sprintf("cl-%d-%x", time.Now().UnixNano(), time.Now().Nanosecond()%0xFFFF)
	}
	return clientSessionID
}

func extractTraceIDFromHeader(r *http.Request) string {
	if val := r.Header.Get("X-Trace-ID"); val != "" {
		return val
	}
	if val := r.Header.Get("Traceparent"); val != "" {
		return val
	}
	return ""
}

func extractAgentNameFromPath(reqPath string) string {
	reqPath = strings.TrimRight(reqPath, "/")
	if strings.HasPrefix(reqPath, "/sse/") || strings.HasPrefix(reqPath, "/mcp/") {
		trimmed := strings.TrimPrefix(reqPath, "/sse/")
		trimmed = strings.TrimPrefix(trimmed, "/mcp/")
		trimmed = strings.TrimSuffix(trimmed, "/message")
		parts := strings.Split(trimmed, "/")
		if len(parts) > 0 && parts[0] != "" {
			return parts[0]
		}
	}
	return ""
}

// extractAgentName inspects request headers, query parameters, and URL path for agent/profile identity:
// 1. Header: X-FaradAiWire-Profile
// 2. Query param: profile
// 3. Header: X-FaradAiWire-Agent-Name
// 4. Query param: agent
// 5. URL Path: /sse/{agent}/... or /mcp/{agent}/...
func extractAgentName(r *http.Request) string {
	if r == nil {
		return ""
	}
	if p := strings.TrimSpace(r.Header.Get("X-FaradAiWire-Profile")); p != "" {
		return p
	}
	if r.URL != nil {
		if q := strings.TrimSpace(r.URL.Query().Get("profile")); q != "" {
			return q
		}
	}
	if a := strings.TrimSpace(r.Header.Get("X-FaradAiWire-Agent-Name")); a != "" {
		return a
	}
	if r.URL != nil {
		if q := strings.TrimSpace(r.URL.Query().Get("agent")); q != "" {
			return q
		}
		return extractAgentNameFromPath(r.URL.Path)
	}
	return ""
}

func (s *SSEProxy) processOutgoingSSEMessage(data, clientSessionID, targetURL string) string {
	fwd := s.getCoordinator().Forwarder()
	if fwd != nil {
		return fwd.ProcessOutgoingMessage(data, clientSessionID, targetURL)
	}
	return data
}

func (s *SSEProxy) forwardMessageToBackend(w http.ResponseWriter, r *http.Request, userCtx context.Context, targetURL, targetSessionID, clientSessionID string, body []byte, reqID interface{}, authToken string) {
	fwd := s.getCoordinator().Forwarder()
	if fwd != nil {
		s.mu.RLock()
		hc := s.httpClient
		s.mu.RUnlock()
		if hc != nil {
			fwd.SetHTTPClient(hc)
		}
		fwd.ForwardMessage(w, r, userCtx, targetURL, targetSessionID, clientSessionID, body, reqID, authToken)
	}
}

