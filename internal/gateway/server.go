package gateway

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

	"github.com/FaradAiLab/FaradAiWire/internal/admin"
	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/auth"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
	dbduckdb "github.com/FaradAiLab/FaradAiWire/internal/db/duckdb"
	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/adaptive"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/schema"
	"github.com/FaradAiLab/FaradAiWire/internal/gateway/bootstrap"
	"github.com/FaradAiLab/FaradAiWire/internal/guard"
	"github.com/FaradAiLab/FaradAiWire/internal/logger"
	"github.com/FaradAiLab/FaradAiWire/internal/policy"
	"github.com/FaradAiLab/FaradAiWire/internal/proxy"
	"github.com/FaradAiLab/FaradAiWire/internal/session"
	"github.com/FaradAiLab/FaradAiWire/internal/settings"
	"github.com/FaradAiLab/FaradAiWire/internal/telemetry/broker"
	"github.com/FaradAiLab/FaradAiWire/internal/telemetry/duckdb"
)

type maintenanceConfig struct {
	cleanupInterval    time.Duration
	sessionIdleTimeout time.Duration
	correlationMaxAge  time.Duration
	targetMaxAge       time.Duration
}

// Server coordinates the entire FaradAiWire runtime lifecycle:
// proxies (SSE / Stdio), administrative console, dynamic filter pipelines, and graceful ingress draining.
type Server struct {
	cfg             *config.Config
	provider        config.Provider
	pipeline        *filter.Pipeline
	router          *adaptive.Router
	auditLog        *logger.FileAuditLogger
	telemetryEngine *duckdb.Engine
	eventBroker     *broker.EventBroker
	combinedLogger  filter.AuditLogger
	sseProxy        *proxy.SSEProxy
	stdioProxy      *proxy.StdioProxy
	adminServer     *admin.AdminServer
	watcher         *config.ConfigWatcher
	sessionMgr      *session.Manager
	maintenanceCfg  maintenanceConfig
	keyStore        auth.KeyStore
	guardCatalog    guard.CatalogStore
	guardManager    guard.Manager
	guardInstaller  guard.ModelInstaller
	guardHITL       *guard.HITLDispatcher
	agentRepo       agent.Repository
	dbManager       *dbduckdb.Manager
	schemaStore     schema.Store
	policyStore     policy.Store
	settingsCache   *settings.Cache
	settingsStore   settings.Store

	mu                  sync.RWMutex
	reloadMu            sync.Mutex
	runningWg           sync.WaitGroup
	inFlightWg          sync.WaitGroup
	inFlightGracePeriod time.Duration
	drainMu             sync.RWMutex
	cancel              context.CancelFunc
	isDraining          atomic.Bool
	isStarted           atomic.Bool
	shutdownOnce        sync.Once
}

// NewServer initializes a configured Gateway Server instance using the bootstrap composition root.
func NewServer(cfg *config.Config, provider config.Provider) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration cannot be nil")
	}

	s := &Server{
		cfg:                 cfg,
		provider:            provider,
		inFlightGracePeriod: 10 * time.Second,
	}

	deps, err := bootstrap.Build(cfg, provider, bootstrap.Callbacks{
		OnReload: func() error {
			slog.Info("Admin manual reload triggered")
			return s.Reload()
		},
		OnReloadConfig: func(nextCfg *config.Config) error {
			slog.Info("Admin in-memory config swap triggered")
			return s.ReloadWithConfig(nextCfg)
		},
		OnClearBaselines: func() {
			slog.Info("Admin manual schema baselines clear triggered")
			if s.pipeline != nil {
				s.pipeline.ClearBaselines()
			}
		},
	})
	if err != nil {
		return nil, err
	}

	s.applyDependencies(deps)

	if s.sseProxy != nil {
		s.sseProxy.SetDrainingMiddleware(s.drainingMiddleware)
	}

	// Initialize background watcher for hot-reloads if configured
	if cfg.HotReload && provider != nil {
		if yamlProv, ok := provider.(*config.YAMLConfigProvider); ok {
			watcher, err := config.NewConfigWatcher(yamlProv)
			if err != nil {
				slog.Warn("Failed to initialize config watcher", slog.String("error", err.Error()))
			} else {
				s.watcher = watcher
			}
		}
	}

	return s, nil
}

// NewServerWithDependencies creates a Server from pre-constructed dependencies.
func NewServerWithDependencies(deps *bootstrap.Dependencies) (*Server, error) {
	if deps == nil {
		return nil, fmt.Errorf("dependencies cannot be nil")
	}
	s := &Server{
		cfg:                 deps.Config,
		provider:            deps.Provider,
		inFlightGracePeriod: 10 * time.Second,
	}
	s.applyDependencies(deps)
	if s.adminServer != nil {
		s.adminServer.SetReloadConfigFunc(s.ReloadWithConfig)
	}
	if s.sseProxy != nil {
		s.sseProxy.SetDrainingMiddleware(s.drainingMiddleware)
	}
	return s, nil
}

func (s *Server) applyDependencies(deps *bootstrap.Dependencies) {
	s.pipeline = deps.Pipeline
	s.router = deps.Router
	s.auditLog = deps.AuditLog
	s.telemetryEngine = deps.TelemetryEngine
	s.eventBroker = deps.EventBroker
	s.combinedLogger = deps.CombinedLogger
	s.sseProxy = deps.SSEProxy
	s.stdioProxy = deps.StdioProxy
	s.adminServer = deps.AdminServer
	s.sessionMgr = deps.SessionMgr
	s.keyStore = deps.KeyStore
	s.guardCatalog = deps.GuardCatalog
	s.guardManager = deps.GuardManager
	s.guardInstaller = deps.GuardInstaller
	s.guardHITL = deps.GuardHITL
	s.agentRepo = deps.AgentRepo
	s.dbManager = deps.DBManager
	s.schemaStore = deps.SchemaStore
	s.policyStore = deps.PolicyStore
	s.settingsCache = deps.SettingsCache
	s.settingsStore = deps.SettingsStore
}

// ProxyHandler returns the HTTP handler for the Gateway Proxy Ingress on listen_port.
// It serves strictly MCP protocols (/sse, /message, /mcp) with security headers, rate limiting, and graceful draining.
func (s *Server) ProxyHandler() http.Handler {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.sseProxy != nil {
		return s.sseProxy.Handler()
	}
	return s.drainingMiddleware(http.NotFoundHandler())
}

// AdminHandler returns the HTTP handler for the Administrative Console on admin_port.
// It serves strictly administrative and governance routes (/admin/*, /api/*).
func (s *Server) AdminHandler() http.Handler {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.adminServer != nil {
		return s.adminServer.Handler()
	}
	return http.NotFoundHandler()
}

// Handler returns the primary MCP proxy ingress handler (served on listen_port).
func (s *Server) Handler() http.Handler {
	return s.ProxyHandler()
}

// InFlightWg returns the waitgroup tracking in-flight tool call executions.
func (s *Server) InFlightWg() *sync.WaitGroup {
	return &s.inFlightWg
}

// InFlightAdd increments the in-flight tool call count.
func (s *Server) InFlightAdd(delta int) {
	s.inFlightWg.Add(delta)
}

// InFlightDone decrements the in-flight tool call count.
func (s *Server) InFlightDone() {
	s.inFlightWg.Done()
}

// SetInFlightGracePeriod overrides the default in-flight grace timeout (useful for tests).
func (s *Server) SetInFlightGracePeriod(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inFlightGracePeriod = d
}

func (s *Server) drainingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isStream := r.Method == http.MethodGet && (strings.HasPrefix(r.URL.Path, "/sse") || strings.Contains(r.Header.Get("Accept"), "text/event-stream"))

		s.drainMu.RLock()
		if s.isDraining.Load() {
			s.drainMu.RUnlock()
			w.Header().Set("Connection", "close")
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "5")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","error":{"code":-32000,"message":"Server is shutting down (draining)"},"id":null}`))
			return
		}

		if !isStream {
			s.inFlightWg.Add(1)
		}
		s.drainMu.RUnlock()

		if !isStream {
			defer s.inFlightWg.Done()
		}

		next.ServeHTTP(w, r)
	})
}

// SessionManager returns the active session manager instance, or nil if none is configured.
func (s *Server) SessionManager() *session.Manager {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.sseProxy != nil && s.sseProxy.SessionManager() != nil {
		return s.sseProxy.SessionManager()
	}
	return s.sessionMgr
}

// CorrelationStore returns the active correlation store, or nil if none is configured.
func (s *Server) CorrelationStore() proxy.CorrelationStore {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.sseProxy != nil {
		return s.sseProxy.CorrelationStore()
	}
	return nil
}

// SetMaintenanceIntervals overrides default intervals for background maintenance sweeps (useful for tests).
func (s *Server) SetMaintenanceIntervals(cleanupInterval, sessionIdleTimeout, correlationMaxAge, targetMaxAge time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maintenanceCfg = maintenanceConfig{
		cleanupInterval:    cleanupInterval,
		sessionIdleTimeout: sessionIdleTimeout,
		correlationMaxAge:  correlationMaxAge,
		targetMaxAge:       targetMaxAge,
	}
}

// startMaintenanceCoordinator starts centralized background loops for session eviction and correlation cleanup.
// It executes identically across Unified Mode, Separate Ports, and Stdio modes.
func (s *Server) startMaintenanceCoordinator(ctx context.Context) {
	s.mu.RLock()
	cfg := s.maintenanceCfg
	sseProxy := s.sseProxy
	s.mu.RUnlock()

	cleanupInterval := cfg.cleanupInterval
	if cleanupInterval <= 0 {
		cleanupInterval = 1 * time.Minute
	}
	sessionIdleTimeout := cfg.sessionIdleTimeout
	if sessionIdleTimeout <= 0 {
		sessionIdleTimeout = 30 * time.Minute
	}
	correlationMaxAge := cfg.correlationMaxAge
	if correlationMaxAge <= 0 {
		correlationMaxAge = 5 * time.Minute
	}
	targetMaxAge := cfg.targetMaxAge
	if targetMaxAge <= 0 {
		targetMaxAge = 2 * time.Hour
	}

	// 1. Evict idle session bridges via sessionMgr
	if sm := s.SessionManager(); sm != nil {
		sm.StartCleanupLoop(ctx, cleanupInterval, sessionIdleTimeout)
	}

	// 2. Periodic correlation store and stale session targets cleanup loop
	if sseProxy != nil {
		s.runningWg.Add(1)
		go func() {
			defer s.runningWg.Done()
			ticker := time.NewTicker(cleanupInterval)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					sseProxy.CleanupStaleSessions(correlationMaxAge, targetMaxAge)
				}
			}
		}()
	}

	// 3. Periodic keystore dirty usage flush loop (SEC-018 / DEC-06)
	if s.keyStore != nil {
		s.runningWg.Add(1)
		go func() {
			defer s.runningWg.Done()
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if err := s.keyStore.FlushDirty(); err != nil {
						slog.Warn("Failed periodic keystore flush", slog.String("error", err.Error()))
					}
				}
			}
		}()
	}
}

// Start boots the proxy listeners, admin server, and file watcher.
// It blocks until ctx is canceled or a fatal runtime error occurs.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	serverCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.runningWg.Add(1)
	s.isStarted.Store(true)
	s.mu.Unlock()

	defer func() {
		cancel()
		s.runningWg.Done()
	}()

	// Establish centralized runtime maintenance coordinator
	s.startMaintenanceCoordinator(serverCtx)

	// Start file watcher loop if configured
	if s.watcher != nil {
		err := s.watcher.Watch(func(_ *config.Config) {
			slog.Info("Hot-reload triggered by file watcher...")
			if err := s.Reload(); err != nil {
				slog.Warn("Hot-reload failed (keeping current pipeline)", slog.String("error", err.Error()))
			} else {
				slog.Info("Gateway pipeline successfully hot-reloaded.")
			}
		})
		if err != nil {
			slog.Warn("Failed to start config watch loop", slog.String("error", err.Error()))
		}
	}

	// Start Admin Console HTTP listener on admin_port
	if s.adminServer != nil {
		go func() {
			if err := s.adminServer.Start(serverCtx); err != nil && err != context.Canceled && err != http.ErrServerClosed {
				slog.Error("Admin server encountered an error", slog.String("error", err.Error()))
			}
		}()
	}

	// Start primary proxy transport (SSE on listen_port or Stdio)
	var runErr error
	if s.cfg.Mode == "stdio" && s.stdioProxy != nil {
		runErr = s.stdioProxy.Start(serverCtx)
	} else if s.sseProxy != nil {
		runErr = s.sseProxy.Start(serverCtx)
	}

	if runErr != nil && runErr != context.Canceled && runErr != http.ErrServerClosed {
		return runErr
	}

	return nil
}

// Shutdown gracefully drains active connections, closes listeners, flushes telemetry WAL, and terminates background workers.
// It executes synchronously and guarantees DuckDB and file audit logs are completely flushed prior to return.
func (s *Server) Shutdown(ctx context.Context) error {
	s.isDraining.Store(true)

	var shutdownErr error
	s.shutdownOnce.Do(func() {
		shutdownErr = s.doShutdown(ctx)
	})
	return shutdownErr
}

func (s *Server) doShutdown(ctx context.Context) error {
	s.mu.Lock()
	cancel := s.cancel
	sseProxy := s.sseProxy
	adminServer := s.adminServer
	gracePeriod := s.inFlightGracePeriod
	s.mu.Unlock()

	if gracePeriod <= 0 {
		gracePeriod = 5 * time.Second
	}

	var shutdownErrs []error

	// =========================================================================
	// Phase 1: Ingress Rejection & Client Eviction
	// =========================================================================
	s.drainMu.Lock()
	s.isDraining.Store(true)
	s.drainMu.Unlock()

	// Set session manager to draining mode so active bridges and upstreams are preserved during Phase 2
	if sm := s.SessionManager(); sm != nil {
		sm.SetDraining(true)
	}

	// Broadcast SSE shutdown event frame to active clients
	if sseProxy != nil {
		sseProxy.BroadcastShutdownEvent()
	}

	// Initiate independent listener shutdowns asynchronously to immediately close listener sockets
	// and unblock ListenAndServe while allowing in-flight requests on active connections to finish.
	var proxyShutdownDone chan struct{}
	if sseProxy != nil {
		proxyShutdownDone = make(chan struct{})
		go func() {
			defer close(proxyShutdownDone)
			if err := sseProxy.Shutdown(ctx); err != nil && err != http.ErrServerClosed {
				slog.Debug("SSE proxy shutdown error", slog.String("error", err.Error()))
			}
		}()
	}

	var adminShutdownDone chan struct{}
	if adminServer != nil {
		adminShutdownDone = make(chan struct{})
		go func() {
			defer close(adminShutdownDone)
			if err := adminServer.Shutdown(ctx); err != nil && err != http.ErrServerClosed {
				slog.Debug("Admin server shutdown error", slog.String("error", err.Error()))
			}
		}()
	}

	// =========================================================================
	// Phase 2: In-Flight Request Drain
	// =========================================================================
	inFlightDone := make(chan struct{})
	go func() {
		s.inFlightWg.Wait()
		close(inFlightDone)
	}()

	select {
	case <-inFlightDone:
		// All in-flight tool calls and HTTP requests completed cleanly
	case <-time.After(gracePeriod):
		shutdownErrs = append(shutdownErrs, fmt.Errorf("in-flight requests failed to drain within %v grace window", gracePeriod))
	case <-ctx.Done():
		shutdownErrs = append(shutdownErrs, fmt.Errorf("in-flight drain canceled: %w", ctx.Err()))
	}

	// Wait for listener shutdowns to complete their connection draining
	if proxyShutdownDone != nil {
		select {
		case <-proxyShutdownDone:
		case <-time.After(1 * time.Second):
		case <-ctx.Done():
		}
	}
	if adminShutdownDone != nil {
		select {
		case <-adminShutdownDone:
		case <-time.After(1 * time.Second):
		case <-ctx.Done():
		}
	}

	// =========================================================================
	// Phase 3: Subprocess & Upstream Teardown
	// =========================================================================
	// Terminate child stdio process groups and upstream sessions only after in-flight requests finish
	if sm := s.SessionManager(); sm != nil {
		sm.DrainAllBridges()
	} else if sseProxy != nil {
		sseProxy.DrainActiveStreams()
	}

	// Terminate stdio proxy subprocess if running in stdio mode
	if s.stdioProxy != nil {
		s.stdioProxy.Stop()
	}

	// Terminate active SLM Stdio guard subprocess if running
	if s.guardManager != nil {
		if err := s.guardManager.Stop(ctx); err != nil {
			shutdownErrs = append(shutdownErrs, fmt.Errorf("guard manager stop: %w", err))
		}
	}

	// =========================================================================
	// Phase 4: Storage & Telemetry Flush
	// =========================================================================
	// 1. Cancel server context to terminate background tasks and tickers
	if cancel != nil {
		cancel()
	}

	// 2. Wait for Start goroutine and maintenance workers to finish draining within provided context
	runnersDone := make(chan struct{})
	go func() {
		s.runningWg.Wait()
		if sm := s.SessionManager(); sm != nil {
			sm.WaitForCleanup()
		}
		close(runnersDone)
	}()

	select {
	case <-runnersDone:
	case <-ctx.Done():
		shutdownErrs = append(shutdownErrs, fmt.Errorf("wait for runners: %w", ctx.Err()))
	}

	// 3. Close config file watcher if active
	if s.watcher != nil {
		_ = s.watcher.Close()
	}

	// 4. Close pipeline filters and flush write-behind workers
	if s.pipeline != nil {
		if err := s.pipeline.Close(); err != nil {
			shutdownErrs = append(shutdownErrs, fmt.Errorf("pipeline filter close: %w", err))
		}
	}

	// 5. Close DuckDB telemetry engine, flush write-behind buffer, and execute CHECKPOINT;
	if s.telemetryEngine != nil {
		if err := s.telemetryEngine.Close(); err != nil {
			shutdownErrs = append(shutdownErrs, fmt.Errorf("telemetry engine close: %w", err))
		}
	}

	// 5.b. Close centralized DuckDB connection pool manager and release file locks
	if s.dbManager != nil {
		if err := s.dbManager.Close(); err != nil {
			shutdownErrs = append(shutdownErrs, fmt.Errorf("duckdb manager close: %w", err))
		}
	}

	// 6. Close live telemetry event broker
	if s.eventBroker != nil {
		if err := s.eventBroker.Close(); err != nil {
			shutdownErrs = append(shutdownErrs, fmt.Errorf("event broker close: %w", err))
		}
	}

	// 7. Flush and close audit log file only after all in-flight requests have drained and logged
	if s.auditLog != nil {
		if err := s.auditLog.Close(); err != nil {
			shutdownErrs = append(shutdownErrs, fmt.Errorf("audit log close: %w", err))
		}
	}

	// 8. Flush buffered keystore usage metadata to disk (SEC-018 / DEC-06)
	if s.keyStore != nil {
		if err := s.keyStore.FlushDirty(); err != nil {
			shutdownErrs = append(shutdownErrs, fmt.Errorf("keystore flush dirty: %w", err))
		}
	}

	return errors.Join(shutdownErrs...)
}

// Reload reloads configuration from the provider and updates pipeline filters atomically.
func (s *Server) Reload() error {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()

	if s.provider == nil {
		return config.ErrNoConfigProvider
	}
	newCfg, err := s.provider.Load()
	if err != nil {
		return fmt.Errorf("failed to reload configuration: %w", err)
	}

	s.mu.RLock()
	sStore := s.settingsStore
	sCache := s.settingsCache
	s.mu.RUnlock()

	if sStore != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		overrides, oErr := sStore.GetAll(ctx)
		cancel()
		if oErr != nil {
			slog.Error("Aborting reload: failed to load DuckDB settings overrides (retaining LKG configuration)", slog.String("error", oErr.Error()))
			return fmt.Errorf("failed to load settings overrides: %w", oErr)
		}
		settings.ApplyFilterOverrides(newCfg, overrides)
		if sCache != nil {
			sCache.Update(settings.ResolveEffectiveSettings(newCfg, overrides))
		}
	}

	return s.reloadWithConfigLocked(newCfg)
}

// ReloadWithConfig applies a new configuration by building new filters and atomically swapping them.
func (s *Server) ReloadWithConfig(newCfg *config.Config) error {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	return s.reloadWithConfigLocked(newCfg)
}

func (s *Server) reloadWithConfigLocked(newCfg *config.Config) error {
	if newCfg == nil {
		return fmt.Errorf("new configuration cannot be nil")
	}

	newPipeline, newRouter, err := filter.BuildPipeline(newCfg, s.combinedLogger)
	if err != nil {
		return fmt.Errorf("failed to build reloaded pipeline: %w", err)
	}

	s.mu.Lock()
	s.cfg = newCfg
	s.router = newRouter

	bootstrap.WireFilterDependencies(newPipeline, newCfg, bootstrap.FilterWiringDependencies{
		SchemaStore:   s.schemaStore,
		SettingsCache: s.settingsCache,
		GuardCatalog:  s.guardCatalog,
		GuardManager:  s.guardManager,
		GuardHITL:     s.guardHITL,
		AgentRepo:     s.agentRepo,
	})
	s.mu.Unlock()

	s.pipeline.Swap(newPipeline.GetFilters(), newRouter)
	s.pipeline.SetDebugRetainUnmaskedDiff(newCfg.Filters.DLP.DebugRetainUnmaskedDiff)
	if s.adminServer != nil {
		s.adminServer.SetConfig(newCfg)
		s.adminServer.SetPipeline(s.pipeline)
	}
	return nil
}

// TelemetryEngine returns the active embedded DuckDB telemetry engine, or nil if inactive.
func (s *Server) TelemetryEngine() *duckdb.Engine {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.telemetryEngine
}

// Pipeline returns the active security filter pipeline.
func (s *Server) Pipeline() *filter.Pipeline {
	return s.pipeline
}

// Router returns the active adaptive router.
func (s *Server) Router() *adaptive.Router {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.router
}

// EventBroker returns the active event broadcast broker, or nil if inactive.
func (s *Server) EventBroker() *broker.EventBroker {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.eventBroker
}

// SSEProxy returns the underlying SSEProxy instance if running in SSE mode.
func (s *Server) SSEProxy() *proxy.SSEProxy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sseProxy
}

// AdminServer returns the admin console server instance if active.
func (s *Server) AdminServer() *admin.AdminServer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.adminServer
}

// KeyStore returns the active API key store instance.
func (s *Server) KeyStore() auth.KeyStore {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.keyStore
}

// IsDraining returns true if the server is in the process of shutting down.
func (s *Server) IsDraining() bool {
	return s.isDraining.Load()
}

// IsStarted returns true if the server has initiated its Start routine.
func (s *Server) IsStarted() bool {
	return s.isStarted.Load()
}

// GuardCatalog returns the persistent SLM guard model catalog.
func (s *Server) GuardCatalog() guard.CatalogStore {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.guardCatalog
}

// GuardManager returns the active SLM Stdio subprocess manager.
func (s *Server) GuardManager() guard.Manager {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.guardManager
}

// GuardInstaller returns the active SLM guard model installer.
func (s *Server) GuardInstaller() guard.ModelInstaller {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.guardInstaller
}
