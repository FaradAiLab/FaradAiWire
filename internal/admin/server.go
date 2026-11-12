package admin

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/auth"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/schema"
	"github.com/FaradAiLab/FaradAiWire/internal/guard"
	"github.com/FaradAiLab/FaradAiWire/internal/middleware"
	"github.com/FaradAiLab/FaradAiWire/internal/policy"
	"github.com/FaradAiLab/FaradAiWire/internal/protocol"
	"github.com/FaradAiLab/FaradAiWire/internal/settings"
	"github.com/FaradAiLab/FaradAiWire/internal/telemetry/duckdb"
	"github.com/FaradAiLab/FaradAiWire/internal/transport"
	"github.com/FaradAiLab/FaradAiWire/web"
)

// TelemetryReader defines the analytical audit log query interface for the admin server.
type TelemetryReader interface {
	QueryAuditLogs(ctx context.Context, filter duckdb.QueryFilter) (*duckdb.QueryResult, error)
}

// EventBroadcaster defines the multi-client live event stream interface for SSE endpoints.
type EventBroadcaster interface {
	Subscribe() (chan []*filter.AuditEvent, func())
	SubscriberCount() int
	DroppedCount() uint64
}

// AdminServer manages gateway configuration, inspection, diff previews, approval, and live telemetry.
type AdminServer struct {
	cfg                  *config.Config
	cfgProvider          *config.YAMLConfigProvider
	agentRepo            agent.Repository
	reloadFunc           func() error
	reloadConfigFunc     func(*config.Config) error
	schemaClear          func()
	telemetryEngine      TelemetryReader
	eventBroker          EventBroadcaster
	server               *http.Server
	safeHTTPClient       *http.Client
	safeHTTPClientCustom bool
	safeHTTPClientOpts   transport.SafeTransportOptions
	mu                   sync.RWMutex
	configMutMu          sync.Mutex
	keyStore             auth.KeyStore
	protocolStore        protocol.Store
	guardCatalog         guard.CatalogStore
	guardManager         guard.Manager
	guardInstaller       guard.ModelInstaller
	guardHITL            *guard.HITLDispatcher
	policyStore          policy.Store
	policyCompiler       *policy.Compiler
	schemaStore          schema.Store
	pipeline             *filter.Pipeline
	settingsStore        settings.Store
	settingsCache        *settings.Cache
	wsHub                *WSHub
	activeSessionChecker func(agentName string) bool
	shutdownOnce         sync.Once
}

// NewAdminServer creates a new AdminServer instance.
func NewAdminServer(cfg *config.Config, reloadFunc func() error, schemaClear func()) *AdminServer {
	hub := NewWSHub()
	if cfg != nil && len(cfg.Security.CORSAllowedOrigins) > 0 {
		hub.SetAllowedOrigins(cfg.Security.CORSAllowedOrigins)
	}
	s := &AdminServer{
		cfg:         cfg,
		reloadFunc:  reloadFunc,
		schemaClear: schemaClear,
		wsHub:       hub,
	}

	hub.SetOnConnect(func(client *wsClient) {
		s.mu.RLock()
		hitl := s.guardHITL
		s.mu.RUnlock()
		if hitl != nil {
			for _, req := range hitl.ListPending() {
				hub.SendDirect(client, map[string]interface{}{
					"type":            "HITL_APPROVAL_REQUIRED",
					"call_id":         req.CallID,
					"tool_name":       req.ToolName,
					"arguments":       req.Arguments,
					"risk_score":      req.RiskScore,
					"threat_domain":   req.ThreatDomain,
					"cwe":             req.CWE,
					"decision_engine": req.DecisionEngine,
					"created_at":      req.CreatedAt.Format(time.RFC3339),
					"expires_at":      req.ExpiresAt.Format(time.RFC3339),
				})
			}
		}
	})

	hub.SetOnMessage(func(client *wsClient, payload []byte) {
		var msg struct {
			Type     string `json:"type"`
			CallID   string `json:"call_id"`
			Approved bool   `json:"approved"`
		}
		if err := json.Unmarshal(payload, &msg); err == nil && msg.Type == "HITL_RESPOND" && msg.CallID != "" {
			s.mu.RLock()
			hitl := s.guardHITL
			s.mu.RUnlock()
			if hitl != nil {
				hitl.Resolve(msg.CallID, msg.Approved)
			}
		}
	})

	return s
}

// SetTelemetryEngine sets the embedded DuckDB telemetry engine for querying audit records.
func (a *AdminServer) SetTelemetryEngine(engine TelemetryReader) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.telemetryEngine = engine
}

// SetEventBroker sets the event broker for streaming audit events via SSE.
func (a *AdminServer) SetEventBroker(broker EventBroadcaster) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.eventBroker = broker
}

// SetConfigProvider sets the configuration provider for saving runtime config.
func (a *AdminServer) SetConfigProvider(p *config.YAMLConfigProvider) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cfgProvider = p
}

// SetAgentRepository sets the agent repository for caching and manifest lookups.
func (a *AdminServer) SetAgentRepository(repo agent.Repository) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.agentRepo = repo
}

// SetKeyStore sets the API Key storage manager.
func (a *AdminServer) SetKeyStore(store auth.KeyStore) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.keyStore = store
}

// SetProtocolStore sets the protocol catalog store.
func (a *AdminServer) SetProtocolStore(store protocol.Store) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.protocolStore = store
}

// SetGuardCatalog sets the DuckDB guard model catalog store.
func (a *AdminServer) SetGuardCatalog(catalog guard.CatalogStore) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.guardCatalog = catalog
}

// SetSettingsStore sets the persistent DuckDB settings store.
func (a *AdminServer) SetSettingsStore(store settings.Store) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.settingsStore = store
}

// SetSettingsCache sets the active atomic operational settings cache.
func (a *AdminServer) SetSettingsCache(cache *settings.Cache) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.settingsCache = cache
}

// SetReloadConfigFunc registers an in-memory pipeline reload hook that accepts
// an updated Config snapshot without re-reading config.yaml from disk.
func (a *AdminServer) SetReloadConfigFunc(fn func(*config.Config) error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.reloadConfigFunc = fn
}

// SetGuardManager sets the active SLM Stdio guard process manager.
func (a *AdminServer) SetGuardManager(mgr guard.Manager) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.guardManager = mgr
}

// SetGuardInstaller sets the environment and model installer.
func (a *AdminServer) SetGuardInstaller(installer guard.ModelInstaller) {
	a.mu.Lock()
	a.guardInstaller = installer
	hub := a.wsHub
	a.mu.Unlock()

	if installer != nil && hub != nil {
		installer.SetOnProgress(func(p guard.InstallProgress) {
			hub.Broadcast(map[string]interface{}{
				"type":       "GUARD_INSTALL_PROGRESS",
				"model_id":   p.ModelID,
				"status":     string(p.Status),
				"step":       string(p.Step),
				"progress":   p.Progress,
				"message":    p.Message,
				"error":      p.Error,
				"updated_at": p.UpdatedAt.Format(time.RFC3339),
			})
		})
	}
}

// SetGuardHITL sets the HITL dispatcher for resolving interactive approvals.
func (a *AdminServer) SetGuardHITL(d *guard.HITLDispatcher) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.guardHITL = d
}

// SetConfig updates the active configuration safely on the AdminServer.
func (a *AdminServer) SetConfig(cfg *config.Config) {
	a.mu.Lock()
	a.cfg = cfg
	var stale *http.Client
	if !a.safeHTTPClientCustom {
		stale = a.safeHTTPClient
		a.safeHTTPClient = nil
	}
	a.mu.Unlock()
	if stale != nil {
		stale.CloseIdleConnections()
	}
}

func safeTransportOptsEqual(a, b transport.SafeTransportOptions) bool {
	return a.Enabled == b.Enabled &&
		a.BlockPrivateIPs == b.BlockPrivateIPs &&
		slices.Equal(a.AllowedDomains, b.AllowedDomains)
}

func (a *AdminServer) invalidateSafeHTTPClient() {
	a.mu.Lock()
	var stale *http.Client
	if !a.safeHTTPClientCustom {
		stale = a.safeHTTPClient
		a.safeHTTPClient = nil
	}
	a.mu.Unlock()
	if stale != nil {
		stale.CloseIdleConnections()
	}
}

// SafeHTTPClient returns the cached SSRF-safe HTTP client with connection pooling,
// kept synchronized with active cfg.Security.SSRFProtection and timeouts.probe_timeout_sec.
func (a *AdminServer) SafeHTTPClient() *http.Client {
	timeout := a.probeTimeout()

	a.mu.RLock()
	custom := a.safeHTTPClientCustom
	client := a.safeHTTPClient
	cfg := a.cfg
	curOpts := a.safeHTTPClientOpts
	a.mu.RUnlock()

	if custom && client != nil {
		return client
	}

	wantOpts := transport.DefaultSafeOptions()
	if cfg != nil {
		wantOpts = transport.OptionsFromConfig(cfg.Security.SSRFProtection)
	}

	if client != nil && client.Timeout == timeout && safeTransportOptsEqual(curOpts, wantOpts) {
		return client
	}

	a.mu.Lock()
	if a.safeHTTPClientCustom && a.safeHTTPClient != nil {
		c := a.safeHTTPClient
		a.mu.Unlock()
		return c
	}
	wantOpts = transport.DefaultSafeOptions()
	if a.cfg != nil {
		wantOpts = transport.OptionsFromConfig(a.cfg.Security.SSRFProtection)
	}
	if a.safeHTTPClient != nil && a.safeHTTPClient.Timeout == timeout && safeTransportOptsEqual(a.safeHTTPClientOpts, wantOpts) {
		c := a.safeHTTPClient
		a.mu.Unlock()
		return c
	}
	stale := a.safeHTTPClient
	a.safeHTTPClient = transport.NewSafeHTTPClient(wantOpts, timeout)
	a.safeHTTPClientOpts = wantOpts
	c := a.safeHTTPClient
	a.mu.Unlock()

	if stale != nil {
		stale.CloseIdleConnections()
	}
	return c
}

// SetSafeHTTPClient sets the safe HTTP client for probing and egress.
func (a *AdminServer) SetSafeHTTPClient(client *http.Client) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.safeHTTPClient = client
	a.safeHTTPClientCustom = client != nil
}

// SetPipeline sets the security filter pipeline for dynamic filter injection and rewiring.
func (a *AdminServer) SetPipeline(p *filter.Pipeline) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pipeline = p
}

// GetPipeline returns the active security filter pipeline.
func (a *AdminServer) GetPipeline() *filter.Pipeline {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.pipeline
}

// WSHub returns the WebSocket hub.
func (a *AdminServer) WSHub() *WSHub {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.wsHub
}

// SetActiveSessionChecker sets the callback for checking whether an agent has active client sessions.
func (a *AdminServer) SetActiveSessionChecker(checker func(agentName string) bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.activeSessionChecker = checker
}

// probeTimeout resolves the active MCP probe timeout from settings cache, defaulting to 5s.
func (a *AdminServer) probeTimeout() time.Duration {
	a.mu.RLock()
	sCache := a.settingsCache
	a.mu.RUnlock()
	if sCache != nil {
		if active := sCache.Get(); active != nil && active.Timeouts.ProbeTimeoutSec > 0 {
			return time.Duration(active.Timeouts.ProbeTimeoutSec) * time.Second
		}
	}
	return 5 * time.Second
}

// withMutationGuard enforces read-only access to policies and agents when running in MANAGED mode.
// Any attempt to toggle configuration, clear schemas, sync tools, approve/discard diffs, or rollback
// returns HTTP 403 Forbidden with {"error": "FORBIDDEN_MANAGED_MODE", "message": "Policy editing is locked: Gateway is managed by organization."}.
func (a *AdminServer) withMutationGuard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a.mu.RLock()
		cfg := a.cfg
		a.mu.RUnlock()
		if cfg != nil && cfg.IsManaged() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "FORBIDDEN_MANAGED_MODE",
				"message": "Policy editing is locked: Gateway is managed by organization.",
			})
			return
		}
		next(w, r)
	}
}

// withWriteMutationGuard enforces MANAGED-mode lockouts only on mutating HTTP methods
// so read-only GET/HEAD queries (such as GET /admin/settings) remain accessible.
func (a *AdminServer) withWriteMutationGuard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next(w, r)
			return
		}
		a.withMutationGuard(next)(w, r)
	}
}

// Handler builds and returns the configured HTTP handler with security headers and CORS middleware applied.
func (a *AdminServer) Handler() http.Handler {
	mux := http.NewServeMux()

	// blockedOnAdmin lists MCP protocol paths that must never be served on the admin port.
	// These are strictly proxy-only endpoints; serving them here would violate port segregation.
	blockedOnAdmin := []string{"/sse", "/message", "/mcp"}

	// Root handler redirects to embedded admin dashboard, or serves static Vite assets and SPA routes
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/admin/dashboard", http.StatusFound)
			return
		}
		// Block MCP protocol endpoints on the admin port (strict port segregation)
		for _, blocked := range blockedOnAdmin {
			if r.URL.Path == blocked || strings.HasPrefix(r.URL.Path, blocked+"/") {
				http.NotFound(w, r)
				return
			}
		}
		// Vite assets & client-side routes fallback (non-admin, non-api)
		if !strings.HasPrefix(r.URL.Path, "/admin") && !strings.HasPrefix(r.URL.Path, "/api") {
			web.Handler().ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})

	// Public static dashboard UI (React SPA)
	mux.HandleFunc("/admin/dashboard", a.handleDashboard)
	// Embedded static assets (Vite bundle)
	mux.Handle("/assets/", web.Handler())
	mux.Handle("/admin/assets/", http.StripPrefix("/admin", web.Handler()))

	// Runtime inspection and local telemetry endpoints (zero-auth localhost access)
	mux.HandleFunc("/admin/status", a.handleStatus)
	mux.HandleFunc("/admin/host/resources", a.handleHostResources)
	mux.HandleFunc("/admin/slm/probe", a.handleSLMProbe)
	mux.HandleFunc("/admin/audit-logs", a.handleAuditLogs)
	mux.HandleFunc("/api/v1/logs/events", a.handleLogEventsStream)
	mux.HandleFunc("/admin/audit-logs/events", a.handleLogEventsStream)
	mux.HandleFunc("/admin/mcp/tools", a.handleMCPTools)
	mux.HandleFunc("/admin/agents", a.handleAgents)
	mux.HandleFunc("/admin/agents/", a.handleAgents)
	mux.HandleFunc("/admin/agents/archives", a.handleAgentArchives)
	mux.HandleFunc("/admin/settings", a.withWriteMutationGuard(a.handleSettings))
	mux.HandleFunc("/admin/settings/reset", a.withMutationGuard(a.handleSettingsReset))
	mux.HandleFunc("/admin/api-keys", a.handleAPIKeys)
	mux.HandleFunc("/admin/api-keys/", a.handleAPIKeys)
	mux.HandleFunc("/admin/protocols", a.handleProtocols)
	mux.HandleFunc("/admin/protocols/", a.handleProtocols)
	mux.HandleFunc("/admin/protocols/presets", a.handleProtocolPresets)
	mux.HandleFunc("/admin/protocols/probe", a.handleProtocolProbe)
	mux.HandleFunc("/admin/guards/models", a.handleGuardModels)
	mux.HandleFunc("/admin/guards/models/", a.handleGuardModels)
	mux.HandleFunc("/admin/guards/status", a.handleGuardStatus)
	mux.HandleFunc("/admin/guards/hitl/respond", a.handleHITLRespond)
	mux.HandleFunc("/admin/guards/hitl/pending", a.handleHITLPending)
	mux.HandleFunc("/admin/dlp/rules", a.handleDlpRules)
	mux.HandleFunc("/admin/dlp/rules/", a.handleDlpRules)
	mux.HandleFunc("/admin/policy-packs", a.handlePolicyPacks)
	mux.HandleFunc("/admin/policy-packs/", a.handlePolicyPacks)
	mux.HandleFunc("/admin/policy-packs/recommend", a.handlePolicyRecommend)
	mux.HandleFunc("/admin/policies/preview", a.handlePolicyPreview)
	mux.HandleFunc("/admin/policy-packs/preview", a.handlePolicyPreview)
	mux.HandleFunc("/ws", a.handleWebSocket)
	mux.HandleFunc("/api/reload", a.handleReload)
	mux.HandleFunc("/admin/reload", a.handleReload)
	mux.HandleFunc("/admin/schemas", a.handleSchemas)
	mux.HandleFunc("/admin/schemas/", a.handleSchemas)

	// Mutating endpoints (guarded by withMutationGuard against managed enterprise mode modifications)
	mux.HandleFunc("/admin/slm/configure", a.withMutationGuard(a.handleSLMConfigure))
	mux.HandleFunc("/admin/schemas/clear", a.withMutationGuard(a.handleClearSchemas))
	mux.HandleFunc("/admin/config/toggle", a.withMutationGuard(a.handleConfigToggle))
	mux.HandleFunc("/admin/agents/sync-tools", a.withMutationGuard(a.handleAgentSyncTools))
	mux.HandleFunc("/admin/agents/rollback", a.withMutationGuard(a.handleAgentRollback))

	var h http.Handler = mux

	if a.cfg != nil && a.cfg.Security.RateLimiting.Enabled != nil && *a.cfg.Security.RateLimiting.Enabled {
		rlCfg := a.cfg.GetHTTPRateLimitConfig()
		h = middleware.HTTPRateLimit(rlCfg.Rate, rlCfg.Burst)(h)
	}

	var allowedOrigins []string
	var enableHSTS bool
	if a.cfg != nil {
		allowedOrigins = a.cfg.Security.CORSAllowedOrigins
		enableHSTS = a.cfg.AdminTLS.Enabled
	}

	adminCSP := "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: https:; connect-src 'self' ws: wss:; frame-ancestors 'none';"
	secMiddleware := middleware.SecurityHeaders(middleware.SecurityHeadersConfig{
		AllowedOrigins:        allowedOrigins,
		EnableHSTS:            enableHSTS,
		ContentSecurityPolicy: adminCSP,
	})

	return secMiddleware(h)
}

// StartTasks is a no-op in standalone mode.
func (a *AdminServer) StartTasks(ctx context.Context) {
}

// ListenAddr resolves the bind address for the admin server.
// Explicit admin_host / FARADAI_WIRE_ADMIN_HOST opts into custom interfaces;
// otherwise standalone mode enforces loopback ("127.0.0.1") per ADR-0028.
func (a *AdminServer) ListenAddr() string {
	adminPort := 8095
	if a.cfg != nil {
		adminPort = a.cfg.GetAdminPort()
	}
	adminHost := a.cfg.GetAdminHost()
	return net.JoinHostPort(adminHost, strconv.Itoa(adminPort))
}

// Start boots the HTTP/HTTPS server in a background goroutine.
func (a *AdminServer) Start(ctx context.Context) error {
	addr := a.ListenAddr()
	adminHost, portStr, _ := net.SplitHostPort(addr)
	adminPort, _ := strconv.Atoi(portStr)

	handler := a.Handler()
	a.mu.Lock()
	a.server = &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	server := a.server
	a.mu.Unlock()

	errCh := make(chan error, 1)
	if a.cfg.AdminTLS.Enabled {
		slog.Info("Admin UI listening on HTTPS", slog.String("host", adminHost), slog.Int("port", adminPort))
		go func() {
			if err := server.ListenAndServeTLS(a.cfg.AdminTLS.CertFile, a.cfg.AdminTLS.KeyFile); err != nil && err != http.ErrServerClosed {
				slog.Error("HTTPS Server error", slog.String("error", err.Error()))
				errCh <- err
			} else {
				errCh <- nil
			}
		}()
	} else {
		slog.Info("Admin UI listening on HTTP", slog.String("host", adminHost), slog.Int("port", adminPort))
		go func() {
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("HTTP Server error", slog.String("error", err.Error()))
				errCh <- err
			} else {
				errCh <- nil
			}
		}()
	}

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return a.Shutdown(shutdownCtx)
	}
}

// Shutdown initiates graceful termination of the admin server.
func (a *AdminServer) Shutdown(ctx context.Context) error {
	a.mu.RLock()
	server := a.server
	a.mu.RUnlock()

	if server == nil {
		return nil
	}

	var shutdownErr error
	a.shutdownOnce.Do(func() {
		slog.Info("Shutting down admin server")
		shutdownErr = server.Shutdown(ctx)
	})
	return shutdownErr
}

// Server returns the underlying active http.Server instance if started (useful for timeout assertions).
func (a *AdminServer) Server() *http.Server {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.server
}
