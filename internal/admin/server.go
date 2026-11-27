package admin

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/auth"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/schema"
	"github.com/FaradAiLab/FaradAiWire/internal/guard"
	"github.com/FaradAiLab/FaradAiWire/internal/mcpprobe"
	"github.com/FaradAiLab/FaradAiWire/internal/metrics"
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

// TelemetryDetailReader defines optional single-invocation full payload lookup for expanded console views.
type TelemetryDetailReader interface {
	GetAuditLogByID(ctx context.Context, id string) (*duckdb.AuditRecord, error)
}

// TelemetrySecurityReader queries control-plane security audit logs in DuckDB.
type TelemetrySecurityReader interface {
	QuerySecurityAuditLogs(ctx context.Context, filter duckdb.SecurityQueryFilter) (*duckdb.SecurityQueryResult, error)
}

// TelemetryAnalyticsReader provides cached traffic analytics summaries from DuckDB.
type TelemetryAnalyticsReader interface {
	GetAnalyticsSummary(ctx context.Context, window string) (*duckdb.AnalyticsSummary, error)
}

// EventBroadcaster defines the multi-client live event stream interface for SSE endpoints.
type EventBroadcaster interface {
	Subscribe() (chan []*filter.AuditEvent, func())
	SubscriberCount() int
	DroppedCount() uint64
}

// AuditEventLogger records administrative configuration mutation audit events.
type AuditEventLogger interface {
	LogEvent(event *filter.AuditEvent)
}

// AdminDependencies groups all runtime dependencies injected into AdminServer at startup.
type AdminDependencies struct {
	Config               *config.Config
	ConfigProvider       *config.YAMLConfigProvider
	AgentRepo            agent.Repository
	ProtocolStore        protocol.Store
	KeyStore             auth.KeyStore
	GuardCatalog         guard.CatalogStore
	GuardManager         guard.Manager
	GuardInstaller       guard.ModelInstaller
	GuardHITL            *guard.HITLDispatcher
	PolicyStore          policy.Store
	PolicyCompiler       *policy.Compiler
	SchemaStore          schema.Store
	SettingsStore        settings.Store
	SettingsCache        *settings.Cache
	TelemetryEngine      TelemetryReader
	EventBroker          EventBroadcaster
	AuditLoggers         []AuditEventLogger
	SecurityAuditLoggers []SecurityAuditEventLogger
	Pipeline             *filter.Pipeline
	SafeHTTPClient       *http.Client
	ReloadFunc           func() error
	ReloadConfigFunc     func(*config.Config) error
	SchemaClearFunc      func()
	ActiveSessionChecker func(agentName string) bool
	Metrics              *metrics.Registry
	AuditLogDroppedFn    func() uint64
	IsDrainingFn         func() bool
}

// AdminServer manages gateway configuration, inspection, diff previews, approval, and live telemetry.
type AdminServer struct {
	cfgPtr               atomic.Pointer[config.Config]
	pipelinePtr          atomic.Pointer[filter.Pipeline]
	cfgProvider          *config.YAMLConfigProvider
	agentRepo            agent.Repository
	reloadFunc           func() error
	reloadConfigFunc     func(*config.Config) error
	schemaClear          func()
	telemetryEngine      TelemetryReader
	eventBroker          EventBroadcaster
	auditLoggers         []AuditEventLogger
	securityAuditLoggers []filter.SecurityAuditLogger
	serverMu             sync.Mutex
	server               *http.Server
	safeClientMu         sync.Mutex
	safeHTTPClient       *http.Client
	safeHTTPClientCustom bool
	safeHTTPClientOpts   transport.SafeTransportOptions
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
	settingsStore        settings.Store
	settingsCache        *settings.Cache
	wsHub                *WSHub
	loginLimiter         *adminLoginLimiter
	activeSessionChecker func(agentName string) bool
	metrics              *metrics.Registry
	auditLogDroppedFn    func() uint64
	drainingMu           sync.RWMutex
	isDrainingFn         func() bool
	dbPingMu             sync.Mutex
	dbPingAt             time.Time
	dbPingErr            error
	shutdownOnce         sync.Once
	closed               bool
}

// NewAdminServer creates a configured AdminServer pre-wired with explicit runtime dependencies.
func NewAdminServer(deps AdminDependencies) *AdminServer {
	hub := NewWSHub()
	if deps.Config != nil && len(deps.Config.Security.CORSAllowedOrigins) > 0 {
		hub.SetAllowedOrigins(deps.Config.Security.CORSAllowedOrigins)
	}
	if deps.Config != nil && !isLoopbackHost(deps.Config.GetAdminHost()) {
		hub.SetAllowSameHostNonLoopback(true)
	}
	s := &AdminServer{
		cfgProvider:          deps.ConfigProvider,
		agentRepo:            deps.AgentRepo,
		protocolStore:        deps.ProtocolStore,
		keyStore:             deps.KeyStore,
		guardCatalog:         deps.GuardCatalog,
		guardManager:         deps.GuardManager,
		guardInstaller:       deps.GuardInstaller,
		guardHITL:            deps.GuardHITL,
		policyStore:          deps.PolicyStore,
		policyCompiler:       deps.PolicyCompiler,
		schemaStore:          deps.SchemaStore,
		settingsStore:        deps.SettingsStore,
		settingsCache:        deps.SettingsCache,
		telemetryEngine:      deps.TelemetryEngine,
		eventBroker:          deps.EventBroker,
		auditLoggers:         slices.Clone(deps.AuditLoggers),
		securityAuditLoggers: slices.Clone(deps.SecurityAuditLoggers),
		reloadFunc:           deps.ReloadFunc,
		reloadConfigFunc:     deps.ReloadConfigFunc,
		schemaClear:          deps.SchemaClearFunc,
		activeSessionChecker: deps.ActiveSessionChecker,
		metrics:              deps.Metrics,
		auditLogDroppedFn:    deps.AuditLogDroppedFn,
		isDrainingFn:         deps.IsDrainingFn,
		wsHub:                hub,
		loginLimiter:         newAdminLoginLimiter(),
	}
	s.cfgPtr.Store(deps.Config)
	s.pipelinePtr.Store(deps.Pipeline)
	if deps.SafeHTTPClient != nil {
		s.safeHTTPClient = deps.SafeHTTPClient
		s.safeHTTPClientCustom = true
	}

	if deps.GuardInstaller != nil && hub != nil {
		wireGuardInstallerProgress(deps.GuardInstaller, hub)
	}

	hub.SetOnConnect(func(client *wsClient) {
		hitl := s.getGuardHITL()
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
			if hitl := s.getGuardHITL(); hitl != nil {
				actorID := client.actorID
				if actorID == "" {
					actorID = "local-operator"
				}
				resolved := hitl.ResolveWithContext(msg.CallID, msg.Approved, "web_ws", actorID, client.clientIP)
				if resolved && !hitl.HasOnResolved() {
					outcome := "denied"
					if msg.Approved {
						outcome = "allowed"
					}
					s.logSecurityAuditAs(nil, actorID, "admin", "HITL_RESOLVED", "hitl_resolve", "hitl_request", msg.CallID, outcome, "web_ws", map[string]any{
						"approval_channel": "web_ws",
						"approved":         msg.Approved,
						"client_ip":        client.clientIP,
					})
				}
			}
		}
	})

	return s
}

func wireGuardInstallerProgress(installer guard.ModelInstaller, hub *WSHub) {
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

func (a *AdminServer) getGuardHITL() *guard.HITLDispatcher {
	return a.guardHITL
}

func (a *AdminServer) getSettingsCache() *settings.Cache {
	return a.settingsCache
}

func (a *AdminServer) getAuditLoggers() []AuditEventLogger {
	return a.auditLoggers
}

func (a *AdminServer) getSecurityAuditLoggers() []filter.SecurityAuditLogger {
	return a.securityAuditLoggers
}

// SetConfig updates the active configuration atomically on the AdminServer.
func (a *AdminServer) SetConfig(cfg *config.Config) {
	a.cfgPtr.Store(cfg)
	a.invalidateSafeHTTPClient()
	if a.wsHub != nil && cfg != nil {
		a.wsHub.SetAllowedOrigins(cfg.Security.CORSAllowedOrigins)
		a.wsHub.SetAllowSameHostNonLoopback(!isLoopbackHost(cfg.GetAdminHost()))
	}
}

// Config returns the active configuration snapshot safely.
func (a *AdminServer) Config() *config.Config {
	return a.cfgPtr.Load()
}

func safeTransportOptsEqual(a, b transport.SafeTransportOptions) bool {
	return a.Enabled == b.Enabled &&
		a.BlockPrivateIPs == b.BlockPrivateIPs &&
		a.IdleConnTimeout == b.IdleConnTimeout &&
		slices.Equal(a.AllowedDomains, b.AllowedDomains)
}

func (a *AdminServer) invalidateSafeHTTPClient() {
	a.safeClientMu.Lock()
	var stale *http.Client
	if !a.safeHTTPClientCustom {
		stale = a.safeHTTPClient
		a.safeHTTPClient = nil
	}
	a.safeClientMu.Unlock()
	if stale != nil {
		stale.CloseIdleConnections()
	}
}

// SafeHTTPClient returns the cached SSRF-safe HTTP client with connection pooling,
// kept synchronized with active cfg.Security.SSRFProtection and timeouts.probe_timeout_sec.
func (a *AdminServer) SafeHTTPClient() *http.Client {
	timeout := a.probeTimeout()
	cfg := a.Config()

	a.safeClientMu.Lock()
	if a.safeHTTPClientCustom && a.safeHTTPClient != nil {
		c := a.safeHTTPClient
		a.safeClientMu.Unlock()
		return c
	}

	wantOpts := transport.DefaultSafeOptions()
	if cfg != nil {
		wantOpts = transport.OptionsFromConfig(cfg.Security.SSRFProtection)
	}
	if sCache := a.settingsCache; sCache != nil {
		if active := sCache.Get(); active != nil && active.Timeouts.IdleTimeoutSec > 0 {
			wantOpts.IdleConnTimeout = time.Duration(active.Timeouts.IdleTimeoutSec) * time.Second
		}
	}
	if a.safeHTTPClient != nil && a.safeHTTPClient.Timeout == timeout && safeTransportOptsEqual(a.safeHTTPClientOpts, wantOpts) {
		c := a.safeHTTPClient
		a.safeClientMu.Unlock()
		return c
	}

	stale := a.safeHTTPClient
	a.safeHTTPClient = transport.NewSafeHTTPClient(wantOpts, timeout)
	a.safeHTTPClientOpts = wantOpts
	c := a.safeHTTPClient
	a.safeClientMu.Unlock()

	if stale != nil {
		stale.CloseIdleConnections()
	}
	return c
}

// SetPipeline sets the security filter pipeline atomically for dynamic filter injection and rewiring.
func (a *AdminServer) SetPipeline(p *filter.Pipeline) {
	a.pipelinePtr.Store(p)
}

// GetPipeline returns the active security filter pipeline atomically.
func (a *AdminServer) GetPipeline() *filter.Pipeline {
	return a.pipelinePtr.Load()
}

// WSHub returns the WebSocket hub.
func (a *AdminServer) WSHub() *WSHub {
	return a.wsHub
}

// SetIsDrainingFn binds the gateway draining status check for /admin/readyz.
func (a *AdminServer) SetIsDrainingFn(fn func() bool) {
	a.drainingMu.Lock()
	a.isDrainingFn = fn
	a.drainingMu.Unlock()
}

func (a *AdminServer) isDraining() bool {
	a.drainingMu.RLock()
	fn := a.isDrainingFn
	a.drainingMu.RUnlock()
	return fn != nil && fn()
}

// probeTimeout resolves the active MCP probe timeout from settings cache, defaulting to 5s.
func (a *AdminServer) probeTimeout() time.Duration {
	if sCache := a.settingsCache; sCache != nil {
		if active := sCache.Get(); active != nil && active.Timeouts.ProbeTimeoutSec > 0 {
			return time.Duration(active.Timeouts.ProbeTimeoutSec) * time.Second
		}
	}
	return 5 * time.Second
}

const (
	defaultStdioProbeTimeout        = 30 * time.Second
	defaultPackageStdioProbeTimeout = 120 * time.Second
)

// stdioProbeTimeout resolves the timeout for local stdio MCP probes.
// Subprocess package launchers (uvx, npx, pipx, docker) can exceed 30s on
// cold-start runtime/package downloads (e.g. fetching CPython + wheels), so
// they floor at 120s while other stdio probes floor at 30s.
func (a *AdminServer) stdioProbeTimeout(command string) time.Duration {
	floor := defaultStdioProbeTimeout
	if mcpprobe.IsPackageRunnerCommand(command) {
		floor = defaultPackageStdioProbeTimeout
	}
	if t := a.probeTimeout(); t > floor {
		return t
	}
	return floor
}

// Handler builds and returns the configured HTTP handler with security headers and CORS middleware applied.
func (a *AdminServer) Handler() http.Handler {
	apiMux := http.NewServeMux()

	// Embedded static dashboard UI & assets under /admin/*
	apiMux.Handle("GET /admin/assets/", http.StripPrefix("/admin", web.Handler()))
	registerExactMethods(apiMux, "/admin/dashboard", a.handleDashboard, http.MethodGet)
	registerExactMethods(apiMux, "/admin/auth/session", a.handleAdminSessionCreate, http.MethodPost)
	registerExactMethods(apiMux, "/admin/auth/logout", a.handleAdminSessionLogout, http.MethodPost)

	// Runtime inspection and local telemetry endpoints (zero-auth localhost access)
	registerExactMethods(apiMux, "/admin/status", a.handleStatus, http.MethodGet)
	registerExactMethods(apiMux, "/admin/metrics", a.handleMetrics, http.MethodGet)
	registerExactMethods(apiMux, "/admin/readyz", a.handleReadyz, http.MethodGet)
	registerExactMethods(apiMux, "/admin/host/resources", a.handleHostResources, http.MethodGet)
	registerExactMethods(apiMux, "/admin/guards/probe", a.handleGuardProbe, http.MethodGet, http.MethodPost)
	registerExactMethods(apiMux, "/admin/audit-logs", a.handleAuditLogs, http.MethodGet)
	registerExactMethods(apiMux, "/admin/audit-logs/events", a.handleLogEventsStream, http.MethodGet)
	registerExactMethods(apiMux, "/admin/audit-logs/export", a.handleAuditLogsExport, http.MethodGet)
	registerExactMethods(apiMux, "/admin/audit-logs/{id}", a.handleAuditLogDetail, http.MethodGet)
	registerExactMethods(apiMux, "/admin/security-audit-logs", a.handleSecurityAuditLogs, http.MethodGet)
	registerExactMethods(apiMux, "/admin/analytics/summary", a.handleAnalyticsSummary, http.MethodGet)
	registerExactMethods(apiMux, "/admin/audit/verify", a.handleAuditVerify, http.MethodGet)
	registerExactMethods(apiMux, "/api/v1/logs/events", a.handleLogEventsStream, http.MethodGet)
	registerExactMethods(apiMux, "/admin/mcp/tools", a.handleMCPTools, http.MethodGet)

	// Agent lifecycle & DLP governance routes (Go 1.22+ ServeMux method + path routing)
	apiMux.HandleFunc("GET /admin/agents", a.handleListAgents)
	apiMux.HandleFunc("POST /admin/agents", a.handleCreateAgent)
	apiMux.HandleFunc("DELETE /admin/agents", a.handleDeleteAgent)
	registerExactMethods(apiMux, "/admin/agents/archives", a.handleAgentArchives, http.MethodGet)
	registerExactMethods(apiMux, "/admin/agents/sync-tools", a.handleAgentSyncTools, http.MethodPost)
	registerExactMethods(apiMux, "/admin/agents/rollback", a.handleAgentRollback, http.MethodPost)
	apiMux.HandleFunc("GET /admin/agents/{name}", a.handleGetAgent)
	apiMux.HandleFunc("PUT /admin/agents/{name}", a.handleUpdateAgent)
	apiMux.HandleFunc("DELETE /admin/agents/{name}", a.handleDeleteAgent)
	apiMux.HandleFunc("GET /admin/agents/{name}/dlp", a.handleGetAgentDLP)
	apiMux.HandleFunc("PUT /admin/agents/{name}/dlp", a.handleUpdateAgentDLP)
	apiMux.HandleFunc("POST /admin/agents/{name}/export", a.handleExportAgentNativeMCP)

	// Protocol catalog & probing routes
	apiMux.HandleFunc("GET /admin/protocols", a.handleListProtocols)
	apiMux.HandleFunc("POST /admin/protocols", a.handleCreateProtocol)
	apiMux.HandleFunc("DELETE /admin/protocols", a.handleDeleteProtocol)
	registerExactMethods(apiMux, "/admin/protocols/presets", a.handleProtocolPresets, http.MethodGet)
	registerExactMethods(apiMux, "/admin/protocols/probe", a.handleProtocolProbe, http.MethodPost)
	apiMux.HandleFunc("GET /admin/protocols/{id}", a.handleGetProtocol)
	apiMux.HandleFunc("PUT /admin/protocols/{id}", a.handleUpdateProtocol)
	apiMux.HandleFunc("DELETE /admin/protocols/{id}", a.handleDeleteProtocol)

	// Operational settings, configuration toggles & runtime reload routes
	apiMux.HandleFunc("GET /admin/settings", a.getSettings)
	apiMux.HandleFunc("POST /admin/settings", a.updateSettings)
	apiMux.HandleFunc("PUT /admin/settings", a.updateSettings)
	registerExactMethods(apiMux, "/admin/settings/reset", a.handleSettingsReset, http.MethodPost)
	registerExactMethods(apiMux, "/admin/config/toggle", a.handleConfigToggle, http.MethodPost)
	registerExactMethods(apiMux, "/admin/guards/configure", a.handleGuardConfigure, http.MethodPost)
	registerExactMethods(apiMux, "/api/reload", a.handleReload, http.MethodPost)
	registerExactMethods(apiMux, "/admin/reload", a.handleReload, http.MethodPost)

	// Self-service API keys
	apiMux.HandleFunc("GET /admin/api-keys", a.handleListAPIKeys)
	apiMux.HandleFunc("POST /admin/api-keys", a.handleCreateAPIKey)
	apiMux.HandleFunc("DELETE /admin/api-keys", a.handleRevokeAPIKey)
	apiMux.HandleFunc("GET /admin/api-keys/{id}", a.handleGetAPIKey)
	apiMux.HandleFunc("DELETE /admin/api-keys/{id}", a.handleRevokeAPIKey)

	// Guard catalog, lifecycle & HITL routes
	registerExactMethods(apiMux, "/admin/guards/status", a.handleGuardStatus, http.MethodGet)
	registerExactMethods(apiMux, "/admin/guards/hitl/pending", a.handleHITLPending, http.MethodGet)
	registerExactMethods(apiMux, "/admin/guards/hitl/respond", a.handleHITLRespond, http.MethodPost)
	registerExactMethods(apiMux, "/admin/guards/models", a.handleListGuardModels, http.MethodGet)
	registerExactMethods(apiMux, "/admin/guards/models/deactivate", a.handleGuardDeactivateGlobal, http.MethodPost)
	apiMux.HandleFunc("GET /admin/guards/models/{id}", a.handleGetGuardModel)
	apiMux.HandleFunc("DELETE /admin/guards/models/{id}", a.handleDeleteGuardModel)
	registerExactMethods(apiMux, "/admin/guards/models/{id}/connect", a.handleGuardConnect, http.MethodPost)
	registerExactMethods(apiMux, "/admin/guards/models/{id}/activate", a.handleGuardActivate, http.MethodPost)
	registerExactMethods(apiMux, "/admin/guards/models/{id}/deactivate", a.handleGuardDeactivateModel, http.MethodPost)
	registerExactMethods(apiMux, "/admin/guards/models/{id}/policy", a.handleGuardPolicyUpdate, http.MethodPost, http.MethodPut)
	registerExactMethods(apiMux, "/admin/guards/models/{id}/install", a.handleGuardInstall, http.MethodPost)
	registerExactMethods(apiMux, "/admin/guards/models/{id}/progress", a.handleGuardInstallProgress, http.MethodGet)

	// DLP pattern rules, policy packs, recommendation & dry-run preview routes
	apiMux.HandleFunc("GET /admin/dlp/rules", a.handleListDlpRules)
	apiMux.HandleFunc("POST /admin/dlp/rules", a.handleCreateDlpRule)
	apiMux.HandleFunc("GET /admin/dlp/rules/{id}", a.handleGetDlpRule)
	apiMux.HandleFunc("PUT /admin/dlp/rules/{id}", a.handleUpdateDlpRule)
	apiMux.HandleFunc("DELETE /admin/dlp/rules/{id}", a.handleDeleteDlpRule)
	apiMux.HandleFunc("GET /admin/policy-packs", a.handleListPolicyPacks)
	apiMux.HandleFunc("POST /admin/policy-packs", a.handleCreatePolicyPack)
	registerExactMethods(apiMux, "/admin/policy-packs/recommend", a.handlePolicyRecommend, http.MethodPost)
	registerExactMethods(apiMux, "/admin/policy-packs/preview", a.handlePolicyPreview, http.MethodPost)
	registerExactMethods(apiMux, "/admin/policies/preview", a.handlePolicyPreview, http.MethodPost)
	apiMux.HandleFunc("GET /admin/policy-packs/{id}", a.handleGetPolicyPack)
	apiMux.HandleFunc("PUT /admin/policy-packs/{id}", a.handleUpdatePolicyPack)
	apiMux.HandleFunc("DELETE /admin/policy-packs/{id}", a.handleDeletePolicyPack)

	// Captured tool schema baselines
	registerExactMethods(apiMux, "/admin/schemas", a.handleListSchemas, http.MethodGet)
	registerExactMethods(apiMux, "/admin/schemas/clear", a.handleClearSchemas, http.MethodPost)
	registerExactMethods(apiMux, "/admin/schemas/{tool}", a.handleGetSchema, http.MethodGet)
	registerExactMethods(apiMux, "/admin/schemas/{tool}/pin", a.handlePinSchema, http.MethodPost)

	// blockedOnAdmin lists MCP protocol paths that must never be served on the admin port.
	// These are strictly proxy-only endpoints; serving them here would violate port segregation.
	blockedOnAdmin := []string{"/sse", "/message", "/mcp"}
	apiHandler := withJSONMethodNotAllowed(apiMux)

	rootHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/admin/dashboard", http.StatusFound)
			return
		}
		for _, blocked := range blockedOnAdmin {
			if r.URL.Path == blocked || strings.HasPrefix(r.URL.Path, blocked+"/") {
				http.NotFound(w, r)
				return
			}
		}
		if r.URL.Path == "/ws" {
			a.handleWebSocket(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/admin") || strings.HasPrefix(r.URL.Path, "/api") {
			apiHandler.ServeHTTP(w, r)
			return
		}
		// Vite assets & client-side SPA routes fallback
		web.Handler().ServeHTTP(w, r)
	})

	var h http.Handler = a.withAdminSecurity(rootHandler)

	cfg := a.Config()

	if cfg != nil && cfg.Security.RateLimiting.Enabled != nil && *cfg.Security.RateLimiting.Enabled {
		rlCfg := cfg.GetHTTPRateLimitConfig()
		h = middleware.HTTPRateLimitWithOptions(rlCfg.Rate, rlCfg.Burst, middleware.RateLimitOptions{
			Port: "admin",
		})(h)
	}

	var allowedOrigins []string
	var enableHSTS bool
	if cfg != nil {
		allowedOrigins = cfg.Security.CORSAllowedOrigins
		enableHSTS = cfg.AdminTLS.Enabled
	}

	adminCSP := "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: https:; connect-src 'self' ws: wss:; frame-ancestors 'none';"
	secMiddleware := middleware.SecurityHeaders(middleware.SecurityHeadersConfig{
		AllowedOrigins:        allowedOrigins,
		EnableHSTS:            enableHSTS,
		ContentSecurityPolicy: adminCSP,
	})

	return middleware.AccessLog("admin")(secMiddleware(h))
}

func isLoopbackHost(host string) bool {
	h := strings.TrimSpace(host)
	h = strings.TrimPrefix(strings.TrimSuffix(h, "]"), "[")
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func isExplicitlyAllowedOrigin(origin string, allowedOrigins []string) bool {
	trimmedOrigin := strings.TrimSpace(origin)
	if trimmedOrigin == "" {
		return false
	}
	for _, candidate := range allowedOrigins {
		trimmedCandidate := strings.TrimSpace(candidate)
		if trimmedCandidate == "" || trimmedCandidate == "*" {
			continue
		}
		if strings.EqualFold(trimmedCandidate, trimmedOrigin) {
			return true
		}
	}
	return false
}

func isLoopbackSameHostOrigin(origin string, reqHost string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	if !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") {
		return false
	}
	reqHostname, reqPort, err := net.SplitHostPort(reqHost)
	if err != nil {
		reqHostname = reqHost
	}
	return isLoopbackHost(reqHostname) && isLoopbackHost(u.Hostname()) && reqPort == u.Port()
}

func requiresAdminAuthForPath(path string) bool {
	if path == "/admin/dashboard" || path == "/admin/dashboard/" ||
		strings.HasPrefix(path, "/admin/assets/") ||
		path == "/admin/auth/session" || path == "/admin/auth/logout" {
		return false
	}
	return strings.HasPrefix(path, "/admin") || strings.HasPrefix(path, "/api") || path == "/ws"
}

func isMutatingMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func isDisallowedCSRFContentType(mediaType string) bool {
	switch mediaType {
	case "text/plain", "application/x-www-form-urlencoded", "multipart/form-data":
		return true
	default:
		return false
	}
}

func (a *AdminServer) withAdminSecurity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := a.Config()

		var allowedOrigins []string
		adminHost := "127.0.0.1"
		if cfg != nil {
			allowedOrigins = cfg.Security.CORSAllowedOrigins
			adminHost = cfg.GetAdminHost()
		}

		isProtectedPath := requiresAdminAuthForPath(r.URL.Path)
		mutating := isMutatingMethod(r.Method)

		// 1. Enforce cross-site / Origin / DNS-rebinding protections on Admin/API/WS paths and mutations.
		if isProtectedPath || mutating {
			origin := strings.TrimSpace(r.Header.Get("Origin"))
			explicitOriginAllowed := origin != "" && isExplicitlyAllowedOrigin(origin, allowedOrigins)
			sameHostNonLoopbackAllowed := origin != "" && !isLoopbackHost(adminHost) && isExactSameHostOrigin(origin, r.Host)

			if strings.EqualFold(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")), "cross-site") && !explicitOriginAllowed {
				http.Error(w, "Forbidden: cross-site admin request blocked", http.StatusForbidden)
				return
			}
			if origin != "" && !explicitOriginAllowed && !isLoopbackSameHostOrigin(origin, r.Host) && !sameHostNonLoopbackAllowed {
				http.Error(w, "Forbidden: unauthorized request origin", http.StatusForbidden)
				return
			}
		}

		if mutating {
			if ct := strings.TrimSpace(r.Header.Get("Content-Type")); ct != "" {
				mediaType := strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
				if isDisallowedCSRFContentType(mediaType) {
					http.Error(w, "Unsupported Media Type: JSON required for admin mutations", http.StatusUnsupportedMediaType)
					return
				}
			}
		}

		// 2. Enforce Admin-role authentication:
		//    - Explicit Authorization: Bearer headers are ALWAYS validated (even on loopback) so Agent keys receive 403 ADMIN_ROLE_REQUIRED.
		//    - Unauthenticated requests on non-loopback require a valid HttpOnly HMAC session cookie (or Bearer token).
		//    - Unauthenticated requests on loopback remain open for zero-auth localhost access.
		clientIP := clientIPFromRequest(r)
		if isProtectedPath {
			authHeader := r.Header.Get("Authorization")
			const bearerPrefix = "Bearer "
			if len(authHeader) > len(bearerPrefix) && strings.EqualFold(authHeader[:len(bearerPrefix)], bearerPrefix) {
				now := time.Now()
				if a.loginLimiter != nil && a.loginLimiter.isLocked(clientIP, now) {
					a.logSecurityAuditAs(r, "anonymous", "unknown", "admin_auth_lockout", "bearer_auth", "admin_auth", r.URL.Path, "locked", "too_many_failed_attempts", nil)
					metrics.Default().IncAuthFailure("admin", "too_many_attempts")
					writeError(w, http.StatusTooManyRequests, "TOO_MANY_ATTEMPTS", "Too many failed authentication attempts; try again later")
					return
				}

				providedToken := strings.TrimSpace(authHeader[len(bearerPrefix):])
				valid, isAdmin, actorID := a.validateAdminCredential(providedToken)
				if !valid {
					if a.loginLimiter != nil {
						rlCfg := a.Config().GetHTTPRateLimitConfig()
						a.loginLimiter.recordFailure(clientIP, now, rlCfg.LoginMaxAttempts, rlCfg.LoginLockoutSec)
					}
					a.logSecurityAuditAs(r, "anonymous", "unknown", "admin_auth_failed", "bearer_auth", "admin_auth", r.URL.Path, "denied", "invalid_bearer_token", nil)
					metrics.Default().IncAuthFailure("admin", "invalid_bearer_token")
					w.Header().Set("WWW-Authenticate", `Bearer realm="FaradAiWire Admin"`)
					http.Error(w, "Unauthorized: invalid admin bearer token", http.StatusUnauthorized)
					return
				}
				if !isAdmin {
					a.logSecurityAuditAs(r, actorID, "non_admin", "admin_auth_forbidden", "bearer_auth", "admin_auth", r.URL.Path, "denied", "admin_role_required", nil)
					metrics.Default().IncAuthFailure("admin", "admin_role_required")
					writeError(w, http.StatusForbidden, "ADMIN_ROLE_REQUIRED", "Forbidden: admin role required; scoped agent keys are restricted to ingress")
					return
				}
				if a.loginLimiter != nil {
					a.loginLimiter.reset(clientIP)
				}
				r = withVerifiedAdminActor(r, verifiedAdminActor{
					ActorID:   actorID,
					ActorRole: "admin",
					ClientIP:  clientIP,
				})
			} else if a.isAdminAuthRequired() {
				if actorID, ok := a.extractValidAdminSessionCookie(r); ok {
					r = withVerifiedAdminActor(r, verifiedAdminActor{
						ActorID:   actorID,
						ActorRole: "admin",
						ClientIP:  clientIP,
					})
				} else {
					a.logSecurityAuditAs(r, "anonymous", "unknown", "admin_auth_failed", "session_auth", "admin_auth", r.URL.Path, "denied", "missing_or_invalid_session", nil)
					metrics.Default().IncAuthFailure("admin", "missing_or_invalid_session")
					w.Header().Set("WWW-Authenticate", `Bearer realm="FaradAiWire Admin"`)
					http.Error(w, "Unauthorized: admin bearer token or session required", http.StatusUnauthorized)
					return
				}
			} else {
				r = withVerifiedAdminActor(r, verifiedAdminActor{
					ActorID:   "local-operator",
					ActorRole: "admin",
					ClientIP:  clientIP,
				})
			}
		}

		next.ServeHTTP(w, r)
	})
}

// StartTasks is a no-op in standalone mode.
func (a *AdminServer) StartTasks(ctx context.Context) {
}

// ListenAddr resolves the bind address for the admin server.
// Explicit admin_host / FARADAI_WIRE_ADMIN_HOST opts into custom interfaces;
// otherwise standalone mode enforces loopback ("127.0.0.1") per ADR-0028.
func (a *AdminServer) ListenAddr() string {
	cfg := a.Config()

	adminPort := config.DefaultAdminPort
	if cfg != nil {
		adminPort = cfg.GetAdminPort()
	}
	adminHost := cfg.GetAdminHost()
	return net.JoinHostPort(adminHost, strconv.Itoa(adminPort))
}

// Start boots the HTTP/HTTPS server in a background goroutine.
func (a *AdminServer) Start(ctx context.Context) error {
	addr := a.ListenAddr()
	adminHost, portStr, _ := net.SplitHostPort(addr)
	adminPort, _ := strconv.Atoi(portStr)

	cfg := a.Config()

	if err := a.validateAdminStartCredentials(adminHost); err != nil {
		return err
	}
	if !isLoopbackHost(adminHost) && (cfg == nil || !cfg.AdminTLS.Enabled) {
		slog.Warn("Admin Server exposed on non-loopback interface without TLS; configure admin_tls or terminate TLS upstream",
			slog.String("host", adminHost),
			slog.Int("port", adminPort),
		)
	}

	handler := a.Handler()
	a.serverMu.Lock()
	if a.closed {
		a.serverMu.Unlock()
		return nil
	}
	readHeaderTimeout := 5 * time.Second
	if sCache := a.settingsCache; sCache != nil {
		if active := sCache.Get(); active != nil && active.Timeouts.ReadHeaderTimeoutSec > 0 {
			readHeaderTimeout = time.Duration(active.Timeouts.ReadHeaderTimeoutSec) * time.Second
		}
	}
	a.server = &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       120 * time.Second,
	}
	server := a.server
	a.serverMu.Unlock()

	errCh := make(chan error, 1)
	if cfg != nil && cfg.AdminTLS.Enabled {
		slog.Info("Admin UI listening on HTTPS", slog.String("host", adminHost), slog.Int("port", adminPort))
		go func() {
			if err := server.ListenAndServeTLS(cfg.GetAdminTLSCertFile(), cfg.GetAdminTLSKeyFile()); err != nil && err != http.ErrServerClosed {
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
	var shutdownErr error
	a.shutdownOnce.Do(func() {
		a.serverMu.Lock()
		a.closed = true
		server := a.server
		a.serverMu.Unlock()

		if server != nil {
			slog.Info("Shutting down admin server")
			shutdownErr = server.Shutdown(ctx)
		}
	})
	return shutdownErr
}

// Server returns the underlying active http.Server instance if started (useful for timeout assertions).
func (a *AdminServer) Server() *http.Server {
	a.serverMu.Lock()
	defer a.serverMu.Unlock()
	return a.server
}
