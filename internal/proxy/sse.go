package proxy

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/auth"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
	"github.com/FaradAiLab/FaradAiWire/internal/middleware"
	"github.com/FaradAiLab/FaradAiWire/internal/session"
)

type sessionBinding struct {
	targetURL   string
	backendPath string
	timestamp   time.Time
}

// SSEProxy acts as a thin HTTP Reverse Proxy for SSE and MCP JSON-RPC messages.
type SSEProxy struct {
	host               string
	port               int
	targetURL          string
	server             *http.Server
	httpClient         *http.Client
	mu                 sync.RWMutex
	sessionTargets     map[string]sessionBinding // sessionId -> sessionBinding
	userCtxCfg         config.UserContextConfig
	contextExtractor   *ContextExtractor
	secCfg             config.SecurityConfig
	keyValidator       auth.KeyValidator
	drainingMiddleware func(http.Handler) http.Handler
	shutdownOnce       sync.Once

	coordinator *session.InboundCoordinator
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
	userCtxCfg config.UserContextConfig,
	secCfg ...config.SecurityConfig,
) *SSEProxy {
	var sc config.SecurityConfig
	if len(secCfg) > 0 {
		sc = secCfg[0]
	}
	httpClient := &http.Client{Timeout: 0}
	if coordinator == nil {
		cStore := NewMemoryCorrelationStore()
		fwd := session.NewForwarder(httpClient, nil, cStore)
		coordinator = session.NewInboundCoordinator(nil, nil, nil, nil, nil, cStore, fwd, targetURL)
	} else if fwd := coordinator.Forwarder(); fwd != nil {
		fwd.SetHTTPClient(httpClient)
	}

	return &SSEProxy{
		port:             port,
		targetURL:        targetURL,
		httpClient:       httpClient,
		sessionTargets:   make(map[string]sessionBinding),
		userCtxCfg:       userCtxCfg,
		contextExtractor: NewContextExtractor(userCtxCfg),
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
	userCtxCfg config.UserContextConfig,
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

	return NewSSEProxyWithCoordinator(port, targetURL, coord, userCtxCfg, sc)
}

// Handler builds and returns the configured HTTP handler with security headers and rate limiting applied.
func (s *SSEProxy) Handler() http.Handler {
	mux := http.NewServeMux()
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
		h = middleware.HTTPRateLimit(rate, burst)(h)
	}

	secMiddleware := middleware.SecurityHeaders(middleware.SecurityHeadersConfig{
		AllowedOrigins: s.secCfg.CORSAllowedOrigins,
	})
	h = secMiddleware(h)

	s.mu.RLock()
	drainMW := s.drainingMiddleware
	s.mu.RUnlock()
	if drainMW != nil {
		h = drainMW(h)
	}
	return h
}

func (s *SSEProxy) handleSSE(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.handleMessage(w, r)
		return
	}
	uCtx, err := s.authenticate(r)
	if err != nil {
		s.writeUnauthorized(w)
		return
	}
	if uCtx != nil {
		r = r.WithContext(context.WithValue(r.Context(), filter.UserContextKey, uCtx))
	}

	if agentName, isAgg, err := s.checkAggregatedAgent(r); err != nil {
		s.writeRoutingError(w, err)
		return
	} else if isAgg {
		s.handleAggregatedSSE(w, r, agentName)
		return
	}

	targetURLStr, err := s.resolveTargetURL(r)
	if err != nil {
		s.writeRoutingError(w, err)
		return
	}

	fwd := s.getCoordinator().Forwarder()
	if fwd != nil {
		fwd.ForwardDirectSSE(w, r, targetURLStr, s.onDirectEndpoint(targetURLStr))
	}
}

func (s *SSEProxy) handleAggregatedSSE(w http.ResponseWriter, r *http.Request, agentName string) {
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

	clientSessionID := extractSessionID(r)
	bridge, err := mgr.CreateBridge(r.Context(), agentName, clientSessionID, r.Header)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer mgr.RemoveBridge(clientSessionID)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	endpointData := fmt.Sprintf("/sse/%s/message?sessionId=%s", agentName, clientSessionID)
	_, _ = w.Write([]byte(fmt.Sprintf("event: endpoint\ndata: %s\n\n", endpointData)))
	flusher.Flush()

	s.streamBridgeEvents(bridge, w, flusher, clientSessionID)
}

func (s *SSEProxy) handleMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	uCtx, err := s.authenticate(r)
	if err != nil {
		s.writeUnauthorized(w)
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

	userCtx := context.WithValue(r.Context(), filter.UserContextKey, uCtx)
	if traceID != "" {
		userCtx = context.WithValue(userCtx, filter.TraceIDContextKey, traceID)
	}

	keyAgent := ""
	if uCtx != nil && uCtx.AgentName != "" && uCtx.AgentName != "*" {
		keyAgent = strings.TrimSpace(uCtx.AgentName)
	}

	agentName := extractAgentName(r)
	if agentName != "" && keyAgent != "" && !strings.EqualFold(keyAgent, agentName) {
		s.writeRoutingError(w, fmt.Errorf("AGENT_ACCESS_DENIED: API key is scoped to agent '%s', access to '%s' is forbidden", keyAgent, agentName))
		return
	}
	if agentName == "" && keyAgent != "" {
		agentName = keyAgent
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

	repo := coord.AgentRepository()
	if repo != nil && agentName != "" {
		if _, err := repo.GetAgentConfig(agentName); err != nil {
			s.writeRoutingError(w, err)
			return
		}
	}

	if agentName != "" {
		userCtx = context.WithValue(userCtx, filter.AgentNameContextKey, agentName)
	}

	mgr := coord.SessionManager()
	if mgr != nil && agentName != "" {
		isDirect := false
		if repo != nil {
			if cfg, err := repo.GetAgentConfig(agentName); err == nil && cfg != nil && cfg.IsDirect() {
				isDirect = true
			}
		}
		if !isDirect {
			if _, ok := mgr.GetBridge(clientSessionID); !ok {
				_, _ = mgr.CreateBridge(r.Context(), agentName, clientSessionID, r.Header)
			}
		}
	}

	coord.ExecuteMessage(w, r, userCtx, clientSessionID, agentName, body, req, s.resolveSessionTarget)
}
