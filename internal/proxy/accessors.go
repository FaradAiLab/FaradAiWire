package proxy

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/auth"
	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/internal/metrics"
	"github.com/FaradAiLab/FaradAiWire/internal/session"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
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
		s.contextExtractor = NewContextExtractor(v)
	}
}

// SetSecurityAuditLogger binds the non-blocking control-plane/ingress security audit logger.
func (s *SSEProxy) SetSecurityAuditLogger(l filter.SecurityAuditLogger) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.securityAuditLogger = l
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

const (
	unauthorizedPayload         = `{"error":"UNAUTHORIZED","message":"Missing, invalid, or revoked API key. Provide Authorization: Bearer <key>."}`
	forbiddenIngressRolePayload = `{"error":"INGRESS_ROLE_REQUIRED","message":"Forbidden: admin keys are restricted to the Admin Console; use an Agent ingress key"}`
)

var ingressSecSeq atomic.Uint64

func nextIngressSecEventID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err == nil {
		return "sec-" + hex.EncodeToString(b[:])
	}
	return fmt.Sprintf("sec-%d-%d", time.Now().UnixNano(), ingressSecSeq.Add(1))
}

func (s *SSEProxy) logIngressSecurityRejection(r *http.Request, eventType, action, resourceType, resourceID, reason string) {
	s.logIngressSecurityRejectionAs(r, "", "", eventType, action, resourceType, resourceID, reason)
}

func (s *SSEProxy) logIngressSecurityRejectionAs(r *http.Request, explicitActorID, explicitActorRole, eventType, action, resourceType, resourceID, reason string) {
	s.mu.RLock()
	logger := s.securityAuditLogger
	s.mu.RUnlock()
	if logger == nil {
		return
	}

	var clientIP, traceID string
	actorID := cmp.Or(explicitActorID, "anonymous")
	actorRole := cmp.Or(explicitActorRole, "unknown")
	if r != nil {
		if ip := extractClientIP(r); ip != nil {
			clientIP = ip.String()
		}
		traceID = strings.TrimSpace(r.Header.Get("X-Request-ID"))
		if explicitActorID == "" {
			if uCtx, ok := r.Context().Value(filter.UserContextKey).(*filter.UserContext); ok && uCtx != nil {
				actorID = cmp.Or(uCtx.APIKeyID, uCtx.UserID, "anonymous")
				actorRole = cmp.Or(uCtx.Role, "unknown")
			}
		}
	}

	logger.LogSecurityEvent(&filter.SecurityAuditEvent{
		ID:           nextIngressSecEventID(),
		TraceID:      traceID,
		Timestamp:    time.Now().UTC(),
		EventType:    eventType,
		ActorID:      actorID,
		ActorRole:    actorRole,
		ClientIP:     clientIP,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Action:       action,
		Outcome:      "denied",
		Reason:       reason,
	})
}

func (s *SSEProxy) writeUnauthorized(w http.ResponseWriter, r *http.Request) {
	path := ""
	method := ""
	if r != nil {
		path = r.URL.Path
		method = r.Method
	}
	s.logIngressSecurityRejection(r, "ingress_auth_failed", method, "ingress_mcp", path, "invalid_or_missing_credentials")
	metrics.Default().IncAuthFailure("proxy", "invalid_api_key")

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", `Bearer realm="FaradAiWire"`)
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(unauthorizedPayload))
}

func (s *SSEProxy) writeForbiddenIngressRole(w http.ResponseWriter, r *http.Request, authErr error) {
	path := ""
	method := ""
	if r != nil {
		path = r.URL.Path
		method = r.Method
	}
	var actorID, actorRole string
	var forbiddenErr *forbiddenAdminKeyError
	if errors.As(authErr, &forbiddenErr) && forbiddenErr.keyID != "" {
		actorID = forbiddenErr.keyID
		actorRole = auth.DefaultAdminRole
	}
	s.logIngressSecurityRejectionAs(r, actorID, actorRole, "ingress_auth_forbidden", method, "ingress_mcp", path, "ingress_role_required")
	metrics.Default().IncAuthFailure("proxy", "ingress_role_required")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(forbiddenIngressRolePayload))
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
		return NewContextExtractor(keyVal).Authenticate(r)
	}
	return NewContextExtractor().Authenticate(r)
}

func (s *SSEProxy) extractUserContext(r *http.Request) *filter.UserContext {
	uCtx, err := s.authenticate(r)
	if err != nil {
		return nil
	}
	return uCtx
}

func (s *SSEProxy) checkAggregatedAgent(r *http.Request) (string, bool, error) {
	_, profile, toolSource, _ := parseIngressPath(r.URL.Path)

	var keyAgent string
	if uVal := r.Context().Value(filter.UserContextKey); uVal != nil {
		if uc, ok := uVal.(*filter.UserContext); ok && uc != nil {
			keyAgent = strings.TrimSpace(uc.AgentName)
		}
	}

	repo := s.getCoordinator().AgentRepository()
	if toolSource != "" && profile != "" {
		// Fail-closed authorization for Direct Mode paths (/sse/{profile}/{tool_source}):
		// Enforce scoped API key boundaries before delegating to direct-mode path resolution.
		if keyAgent != "" && keyAgent != "*" && !strings.EqualFold(keyAgent, profile) {
			return "", false, fmt.Errorf("AGENT_ACCESS_DENIED: API key is scoped to agent '%s', access to '%s' is forbidden", keyAgent, profile)
		}
		return "", false, nil
	}
	if profile != "" {
		// Fail-closed authorization: If key is strictly scoped to another agent, reject with 403
		if keyAgent != "" && keyAgent != "*" && !strings.EqualFold(keyAgent, profile) {
			return "", false, fmt.Errorf("AGENT_ACCESS_DENIED: API key is scoped to agent '%s', access to '%s' is forbidden", keyAgent, profile)
		}

		if repo != nil {
			agentCfg, err := repo.GetAgentConfig(profile)
			if err != nil {
				return "", false, err
			}
			if agentCfg.IsDirect() {
				return "", false, fmt.Errorf("ROUTING_VIOLATION_DIRECT: Agent '%s' is configured in DIRECT mode. Please specify target MCP in path: '/sse/%s/{mcp_name}'", profile, profile)
			}
			return profile, true, nil
		}
		return "", false, nil
	}

	// Root /sse without profile path segment:
	// 1. Scoped API key auto-routes to its bound profile.
	if keyAgent != "" && keyAgent != "*" && repo != nil {
		agentCfg, err := repo.GetAgentConfig(keyAgent)
		if err != nil {
			return "", false, err
		}
		if agentCfg.IsDirect() {
			return "", false, fmt.Errorf("ROUTING_VIOLATION_DIRECT: Scoped Agent '%s' is configured in DIRECT mode. Please specify target MCP in path: '/sse/%s/{mcp_name}'", keyAgent, keyAgent)
		}
		return agentCfg.AgentName, true, nil
	}

	// 2. Wildcard (*) keys require an explicit profile segment when AgentRepository is configured.
	if repo != nil {
		return "", false, fmt.Errorf("PROFILE_REQUIRED: wildcard API key requires an explicit profile in URL path: '/sse/{profile}' or '/mcp/{profile}'")
	}
	return "", false, nil
}

func (s *SSEProxy) writeRoutingError(w http.ResponseWriter, r *http.Request, err error) {
	w.Header().Set("Content-Type", "application/json")
	path := ""
	method := ""
	ctx := context.Background()
	if r != nil {
		path = r.URL.Path
		method = r.Method
		ctx = r.Context()
	}

	status := http.StatusBadRequest
	if strings.Contains(err.Error(), "AGENT_ACCESS_DENIED") {
		status = http.StatusForbidden
		s.logIngressSecurityRejection(r, "ingress_auth_forbidden", method, "agent", path, "agent_access_denied")
		metrics.Default().IncAuthFailure("proxy", "agent_access_denied")
	} else {
		if errors.Is(err, agent.ErrAgentNotFound) || errors.Is(err, agent.ErrProtocolNotFound) || strings.Contains(err.Error(), "MCP_NOT_FOUND") || strings.Contains(err.Error(), "AGENT_NOT_FOUND") {
			status = http.StatusNotFound
		}
		slog.WarnContext(ctx, "MCP ingress routing rejected",
			slog.String("method", method),
			slog.String("path", path),
			slog.Int("status", status),
			slog.String("error", err.Error()),
		)
	}
	w.WriteHeader(status)
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
		if s.httpClient == nil {
			s.httpClient = &http.Client{Timeout: 0}
		}
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
					_, _ = io.WriteString(w, session.FormatSSEFrame(ev.Event, ev.Data))
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
			_, _ = io.WriteString(w, session.FormatSSEFrame(ev.Event, data))
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

// parseIngressPath extracts canonical transport, Security Profile, and Tool Source segments
// from an MCP ingress path without conflating profiles literally named "mcp" or "message".
func parseIngressPath(reqPath string) (transport, profile, toolSource string, isMessage bool) {
	trimmed := strings.TrimRight(reqPath, "/")
	var rest string
	switch {
	case trimmed == "/sse":
		return "sse", "", "", false
	case trimmed == "/mcp":
		return "mcp", "", "", false
	case trimmed == "/message":
		return "message", "", "", true
	case strings.HasPrefix(trimmed, "/sse/"):
		transport = "sse"
		rest = strings.TrimPrefix(trimmed, "/sse/")
	case strings.HasPrefix(trimmed, "/mcp/"):
		transport = "mcp"
		rest = strings.TrimPrefix(trimmed, "/mcp/")
	default:
		return "", "", "", false
	}

	segs := strings.Split(rest, "/")
	if len(segs) >= 2 && segs[len(segs)-1] == "message" {
		isMessage = true
		segs = segs[:len(segs)-1]
	}
	if len(segs) >= 1 && segs[0] != "" {
		profile = segs[0]
	}
	if len(segs) >= 2 && segs[1] != "" {
		toolSource = segs[1]
	}
	return transport, profile, toolSource, isMessage
}

// validateNoLegacyRoutingQuery rejects deprecated ?profile= and ?agent= query parameters
// on MCP ingress to avoid silent misrouting or query-string leakage to upstream servers.
func validateNoLegacyRoutingQuery(r *http.Request) error {
	if r == nil || r.URL == nil || r.URL.RawQuery == "" {
		return nil
	}
	q := r.URL.Query()
	if q.Has("profile") || q.Has("agent") {
		return fmt.Errorf("INVALID_ROUTING_PARAMETER: query parameters 'profile' and 'agent' are unsupported; specify profile in URL path '/sse/{profile}' or '/mcp/{profile}'")
	}
	return nil
}

// isSafeControlFree rejects ASCII control characters (including CR/LF and NUL)
// to prevent SSE frame / header injection from untrusted session IDs or agent names.
func isSafeControlFree(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return false
		}
	}
	return true
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
