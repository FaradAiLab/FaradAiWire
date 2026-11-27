package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/auth"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/internal/middleware"
	"github.com/FaradAiLab/FaradAiWire/internal/session"
	"github.com/FaradAiLab/FaradAiWire/internal/settings"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
)

type sessionBinding struct {
	targetURL   string
	backendPath string
	timestamp   time.Time
}

// SSEProxy acts as a thin HTTP Reverse Proxy for SSE and MCP JSON-RPC messages.
type SSEProxy struct {
	host                string
	port                int
	targetURL           string
	server              *http.Server
	httpClient          *http.Client
	mu                  sync.RWMutex
	sessionTargets      map[string]sessionBinding // sessionId -> sessionBinding
	contextExtractor    *ContextExtractor
	secCfg              config.SecurityConfig
	keyValidator        auth.KeyValidator
	securityAuditLogger filter.SecurityAuditLogger
	drainingMiddleware  func(http.Handler) http.Handler
	settingsCache       atomic.Pointer[settings.Cache]
	shutdownOnce        sync.Once
	closed              bool
	baseCtx             context.Context
	baseCancel          context.CancelFunc

	coordinator *session.InboundCoordinator
}

// SetSettingsCache binds the dynamic atomic operational settings cache to SSEProxy.
func (s *SSEProxy) SetSettingsCache(c *settings.Cache) {
	s.settingsCache.Store(c)
}

// SetHTTPClient updates the underlying HTTP transport client.
func (s *SSEProxy) SetHTTPClient(client *http.Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.httpClient = client
	if s.coordinator != nil {
		if fwd := s.coordinator.Forwarder(); fwd != nil {
			fwd.SetHTTPClient(client)
		}
	}
}

// NewSSEProxyWithCoordinator creates an SSEProxy with an injected InboundCoordinator (Composition Root pattern).
func NewSSEProxyWithCoordinator(
	port int,
	targetURL string,
	coordinator *session.InboundCoordinator,
	secCfg ...config.SecurityConfig,
) *SSEProxy {
	var sc config.SecurityConfig
	if len(secCfg) > 0 {
		sc = secCfg[0]
	}
	var httpClient *http.Client
	if coordinator == nil {
		httpClient = &http.Client{Timeout: 0}
		cStore := NewMemoryCorrelationStore()
		fwd := session.NewForwarder(httpClient, nil, cStore)
		coordinator = session.NewInboundCoordinator(nil, nil, nil, nil, nil, cStore, fwd, targetURL)
	}

	return &SSEProxy{
		port:             port,
		targetURL:        targetURL,
		httpClient:       httpClient,
		sessionTargets:   make(map[string]sessionBinding),
		contextExtractor: NewContextExtractor(),
		secCfg:           sc,
		coordinator:      coordinator,
	}
}

// NewSSEProxy initializes a new SSEProxy with constructor dependency injection (convenience / legacy).
func NewSSEProxy(
	port int,
	targetURL string,
	pipeline *filter.Pipeline,
	agentRepo agent.Resolver,
	sessionMgr *session.Manager,
	secCfg ...config.SecurityConfig,
) *SSEProxy {
	var sc config.SecurityConfig
	if len(secCfg) > 0 {
		sc = secCfg[0]
	}
	httpClient := &http.Client{Timeout: 0}
	if sessionMgr == nil && agentRepo != nil {
		sessionMgr = session.NewManager(agentRepo, nil)
	}

	var aggregator agent.ManifestAggregator
	if agentRepo != nil {
		aggregator = agent.NewManifestAggregator(agentRepo)
	}

	var dispatcher session.ToolDispatcher
	if agentRepo != nil && sessionMgr != nil {
		dispatcher = session.NewToolDispatcher(agentRepo, sessionMgr)
	}

	cStore := NewMemoryCorrelationStore()
	fwd := session.NewForwarder(httpClient, pipeline, cStore)
	coord := session.NewInboundCoordinator(pipeline, agentRepo, sessionMgr, aggregator, dispatcher, cStore, fwd, targetURL)

	return NewSSEProxyWithCoordinator(port, targetURL, coord, sc)
}

// Handler builds and returns the configured HTTP handler with security headers and rate limiting applied.
func (s *SSEProxy) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/sse", s.handleSSE)
	mux.HandleFunc("/sse/", s.handleSSE)
	mux.HandleFunc("/message", s.handleMessage)
	mux.HandleFunc("/mcp", s.handleMessage)
	mux.HandleFunc("/mcp/", s.handleMessage)

	var h http.Handler = mux
	if s.secCfg.RateLimiting.Enabled != nil && *s.secCfg.RateLimiting.Enabled {
		rate := s.secCfg.RateLimiting.Rate
		if rate <= 0 {
			rate = 50.0
		}
		burst := s.secCfg.RateLimiting.Burst
		if burst <= 0 {
			burst = 100
		}
		h = middleware.HTTPRateLimitWithOptions(rate, burst, middleware.RateLimitOptions{
			Port: "proxy",
		})(h)
	}

	secMiddleware := middleware.SecurityHeaders(middleware.SecurityHeadersConfig{
		AllowedOrigins: s.secCfg.CORSAllowedOrigins,
	})
	h = secMiddleware(h)
	h = middleware.AccessLog("proxy")(h)

	s.mu.RLock()
	drainMW := s.drainingMiddleware
	s.mu.RUnlock()
	if drainMW != nil {
		h = drainMW(h)
	}
	return h
}

var healthResponseBytes = []byte(fmt.Sprintf(`{"status":"ok","version":"%s"}`, config.Version))

func (s *SSEProxy) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(healthResponseBytes)
	}
}

func (s *SSEProxy) handleSSE(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.handleMessage(w, r)
		return
	case http.MethodGet, http.MethodHead:
	default:
		w.Header().Set("Allow", "GET, HEAD, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	uCtx, err := s.authenticate(r)
	if err != nil {
		if errors.Is(err, ErrForbiddenAdminKeyOnIngress) {
			s.writeForbiddenIngressRole(w, r, err)
			return
		}
		s.writeUnauthorized(w, r)
		return
	}
	if uCtx != nil {
		r = r.WithContext(context.WithValue(r.Context(), filter.UserContextKey, uCtx))
	}
	if err := validateNoLegacyRoutingQuery(r); err != nil {
		s.writeRoutingError(w, r, err)
		return
	}
	if traceID := extractTraceIDFromHeader(r); traceID != "" {
		r = r.WithContext(context.WithValue(r.Context(), filter.TraceIDContextKey, traceID))
	}

	if agentName, isAgg, err := s.checkAggregatedAgent(r); err != nil {
		s.writeRoutingError(w, r, err)
		return
	} else if isAgg {
		if agentName != "" {
			r = r.WithContext(context.WithValue(r.Context(), filter.AgentNameContextKey, agentName))
		}
		s.handleAggregatedSSE(w, r, agentName)
		return
	}

	targetURLStr, err := s.resolveTargetURL(r)
	if err != nil {
		s.writeRoutingError(w, r, err)
		return
	}

	if r.Method == http.MethodHead {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		return
	}

	fwd := s.getCoordinator().Forwarder()
	if fwd != nil {
		fwd.ForwardDirectSSE(w, r, targetURLStr, s.onDirectEndpoint(targetURLStr))
	}
}

func (s *SSEProxy) handleAggregatedSSE(w http.ResponseWriter, r *http.Request, agentName string) {
	clientSessionID := extractSessionID(r)
	if !isSafeControlFree(agentName) || !isSafeControlFree(clientSessionID) {
		http.Error(w, "Invalid agent or session identifier", http.StatusBadRequest)
		return
	}

	if r.Method == http.MethodHead {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}
	mgr := s.getCoordinator().SessionManager()
	if mgr == nil {
		http.Error(w, "session manager not initialized", http.StatusInternalServerError)
		return
	}

	bridge, err := mgr.CreateBridge(r.Context(), agentName, clientSessionID, r.Header)
	if err != nil {
		if errors.Is(err, session.ErrBridgeAlreadyExists) {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer mgr.RemoveBridge(clientSessionID)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	endpointData := fmt.Sprintf("/sse/%s/message?sessionId=%s", url.PathEscape(agentName), url.QueryEscape(clientSessionID))
	_, _ = w.Write([]byte(fmt.Sprintf("event: endpoint\ndata: %s\n\n", endpointData)))
	flusher.Flush()

	s.streamBridgeEvents(bridge, w, flusher, clientSessionID)
}

func (s *SSEProxy) handleMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	uCtx, err := s.authenticate(r)
	if err != nil {
		if errors.Is(err, ErrForbiddenAdminKeyOnIngress) {
			s.writeForbiddenIngressRole(w, r, err)
			return
		}
		s.writeUnauthorized(w, r)
		return
	}
	if uCtx != nil {
		r = r.WithContext(context.WithValue(r.Context(), filter.UserContextKey, uCtx))
	}
	if err := validateNoLegacyRoutingQuery(r); err != nil {
		s.writeRoutingError(w, r, err)
		return
	}

	body, ok := s.readRequestBody(w, r)
	if !ok {
		return
	}

	req, _, _, parseErr := mcp.ParseMessage(body)
	if parseErr != nil {
		s.writeParseError(w, parseErr)
		return
	}

	clientSessionID := extractSessionID(r)
	traceID := extractTraceIDFromHeader(r)
	if traceID == "" && req != nil {
		traceID = req.ExtractTraceID()
	}

	userCtx := r.Context()
	if traceID != "" {
		userCtx = context.WithValue(userCtx, filter.TraceIDContextKey, traceID)
	}
	r = r.WithContext(userCtx)

	keyAgent := ""
	if uCtx != nil && uCtx.AgentName != "" && uCtx.AgentName != "*" {
		keyAgent = strings.TrimSpace(uCtx.AgentName)
	}

	transport, pathAgent, pathToolSource, _ := parseIngressPath(r.URL.Path)
	if pathAgent != "" && keyAgent != "" && !strings.EqualFold(keyAgent, pathAgent) {
		s.writeRoutingError(w, r, fmt.Errorf("AGENT_ACCESS_DENIED: API key is scoped to agent '%s', access to '%s' is forbidden", keyAgent, pathAgent))
		return
	}
	agentName := pathAgent
	if agentName == "" && keyAgent != "" {
		agentName = keyAgent
	}

	if !isSafeControlFree(clientSessionID) || !isSafeControlFree(agentName) || !isSafeControlFree(pathToolSource) {
		http.Error(w, "Invalid agent or session identifier", http.StatusBadRequest)
		return
	}

	coord := s.getCoordinator()
	s.mu.RLock()
	hc := s.httpClient
	s.mu.RUnlock()
	if hc != nil {
		if fwd := coord.Forwarder(); fwd != nil {
			fwd.SetHTTPClient(hc)
		}
	}

	_, hasDirectSession := s.resolveSessionTarget(clientSessionID)
	mgr := coord.SessionManager()
	repo := coord.AgentRepository()
	if agentName == "" && repo != nil {
		hasBridge := false
		if mgr != nil {
			if br, ok := mgr.GetBridge(clientSessionID); ok && br != nil {
				hasBridge = true
			}
		}
		if !hasDirectSession && !hasBridge {
			s.writeRoutingError(w, r, fmt.Errorf("PROFILE_REQUIRED: wildcard API key requires an explicit profile in URL path: '/sse/{profile}' or '/mcp/{profile}'"))
			return
		}
	}

	var agentCfg *agent.RouteConfig
	if repo != nil && agentName != "" {
		agentCfg, err = repo.GetAgentConfig(agentName)
		if err != nil {
			s.writeRoutingError(w, r, err)
			return
		}
		if agentCfg != nil {
			if agentCfg.IsDirect() {
				if pathToolSource == "" && !(pathAgent == "" && hasDirectSession) {
					prefix := "mcp"
					if transport == "sse" {
						prefix = "sse"
					}
					s.writeRoutingError(w, r, fmt.Errorf("ROUTING_VIOLATION_DIRECT: Agent '%s' is configured in DIRECT mode. Please specify target MCP in path: '/%s/%s/{mcp_name}'", agentName, prefix, agentName))
					return
				}
				if pathToolSource != "" && agentCfg.FindProtocol(pathToolSource) == nil {
					s.writeRoutingError(w, r, agent.NewProtocolNotFoundError(agentName, pathToolSource))
					return
				}
			} else if pathToolSource != "" {
				s.writeRoutingError(w, r, agent.NewRoutingModeViolationError(agentName, "AGGREGATED", fmt.Sprintf("Access using single path: '/%s/%s'", transport, agentName)))
				return
			}
		}
	}

	if agentName != "" {
		userCtx = context.WithValue(userCtx, filter.AgentNameContextKey, agentName)
		r = r.WithContext(userCtx)
	}

	if mgr != nil && agentName != "" {
		isDirect := agentCfg != nil && agentCfg.IsDirect()
		if !isDirect {
			if _, bErr := mgr.GetOrCreateBridge(s.lifecycleCtx(), agentName, clientSessionID, r.Header); bErr != nil {
				if errors.Is(bErr, session.ErrBridgeAgentMismatch) {
					s.writeRoutingError(w, r, fmt.Errorf("AGENT_ACCESS_DENIED: %w", bErr))
					return
				}
				slog.WarnContext(r.Context(), "Failed to prepare session bridge for incoming message",
					slog.String("agent", agentName),
					slog.String("session_id", clientSessionID),
					slog.String("error", bErr.Error()),
				)
			}
		}
	}

	coord.ExecuteMessage(w, r, userCtx, clientSessionID, agentName, body, req, s.resolveSessionTarget)
}
