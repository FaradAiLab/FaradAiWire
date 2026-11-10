package bootstrap

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/admin"
	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/auth"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/db/duckdb"
	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/adaptive"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/dlp"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/hitl"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/limit"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/schema"
	"github.com/FaradAiLab/FaradAiWire/internal/guard"
	"github.com/FaradAiLab/FaradAiWire/internal/logger"
	"github.com/FaradAiLab/FaradAiWire/internal/policy"
	"github.com/FaradAiLab/FaradAiWire/internal/proxy"
	"github.com/FaradAiLab/FaradAiWire/internal/session"
	"github.com/FaradAiLab/FaradAiWire/internal/settings"
	"github.com/FaradAiLab/FaradAiWire/internal/telemetry/broker"
	duckdbTelemetry "github.com/FaradAiLab/FaradAiWire/internal/telemetry/duckdb"
)

// Dependencies contains the fully wired, immutable runtime components of FaradAiWire.
type Dependencies struct {
	Config          *config.Config
	Provider        config.Provider
	DBManager       *duckdb.Manager
	AuditLog        *logger.FileAuditLogger
	TelemetryEngine *duckdbTelemetry.Engine
	EventBroker     *broker.EventBroker
	CombinedLogger  filter.AuditLogger
	GuardCatalog    guard.CatalogStore
	PolicyStore     policy.Store
	SchemaStore     schema.Store
	SettingsStore   settings.Store
	SettingsCache   *settings.Cache
	Pipeline        *filter.Pipeline
	Router          *adaptive.Router
	AgentRepo       agent.Repository
	SessionMgr      *session.Manager
	KeyStore        auth.KeyStore
	GuardManager    guard.Manager
	GuardInstaller  guard.ModelInstaller
	GuardHITL       *guard.HITLDispatcher
	SSEProxy        *proxy.SSEProxy
	StdioProxy      *proxy.StdioProxy
	AdminServer     *admin.AdminServer
	Coordinator     *session.InboundCoordinator
}

// FilterWiringDependencies holds all shared stores and services needed to wire runtime filter instances.
type FilterWiringDependencies struct {
	SchemaStore   schema.Store
	SettingsCache *settings.Cache
	GuardCatalog  guard.CatalogStore
	GuardManager  guard.Manager
	GuardHITL     *guard.HITLDispatcher
	AgentRepo     agent.Resolver
}

// WireFilterDependencies binds all shared runtime stores and managers to pipeline filters.
func WireFilterDependencies(pipe *filter.Pipeline, cfg *config.Config, deps FilterWiringDependencies) {
	if pipe == nil {
		return
	}

	// 1. Schema Validation Store
	if deps.SchemaStore != nil {
		if sf, ok := pipe.GetFilter("schema_validation").(*schema.SchemaFilter); ok && sf != nil {
			sf.SetDuckDBStore(deps.SchemaStore)
		}
	}

	// 2. DLP & HITL Safety Dispatcher
	if deps.GuardHITL != nil {
		if dlpFilter, ok := pipe.GetFilter("dlp").(*dlp.DLPFilter); ok && dlpFilter != nil {
			dlpFilter.SetHITLDispatcher(deps.GuardHITL)
		}
		if hitlFilter, ok := pipe.GetFilter("hitl").(*hitl.HITLFilter); ok && hitlFilter != nil {
			hitlFilter.SetHITLDispatcher(deps.GuardHITL)
		}
	}

	// 3. Agent Repo for Loop and Rate Limit filters
	if deps.AgentRepo != nil {
		if lf, ok := pipe.GetFilter("loop_protection").(*limit.LoopFilter); ok && lf != nil {
			lf.SetAgentRepository(deps.AgentRepo)
		}
		if rf, ok := pipe.GetFilter("rate_limiting").(*limit.RateLimitFilter); ok && rf != nil {
			rf.SetAgentRepository(deps.AgentRepo)
		}
	}

	// 4. Semantic Guard Filter registration & wiring
	gf, ok := pipe.GetFilter("guard").(*guard.GuardFilter)
	if (!ok || gf == nil) && cfg != nil && cfg.Filters.Guard.Enabled {
		gf = guard.NewFilter(guard.FilterConfig{
			Enabled:          true,
			L1Patterns:       cfg.Filters.Guard.L1Patterns,
			FastPathTools:    cfg.Filters.Guard.FastPathTools,
			CriticalBlocks:   cfg.Filters.Guard.CriticalBlocks,
			MaxPayloadLength: cfg.Filters.Guard.MaxPayloadLength,
			MinWordCount:     cfg.Filters.Guard.MinWordCount,
		})
		pipe.RegisterFilter(gf)
	}
	if gf != nil {
		if deps.GuardManager != nil {
			gf.SetManager(deps.GuardManager)
		}
		if deps.GuardHITL != nil {
			gf.SetHITLDispatcher(deps.GuardHITL)
		}
		if deps.SettingsCache != nil {
			gf.SetSettingsCache(deps.SettingsCache)
		}
		if deps.GuardCatalog != nil {
			gf.SetCatalog(deps.GuardCatalog)
		}
		if deps.AgentRepo != nil {
			gf.SetAgentRepository(deps.AgentRepo)
		}
	}
}

// Callbacks holds runtime hooks for administrative triggers (reload, in-memory config swap, baseline clearing).
type Callbacks struct {
	OnReload         func() error
	OnReloadConfig   func(*config.Config) error
	OnClearBaselines func()
}

// Build constructs and wires all Gateway subsystems according to the provided configuration.
func Build(cfg *config.Config, provider config.Provider, cb ...Callbacks) (*Dependencies, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration cannot be nil")
	}

	listenPort := cfg.GetListenPort()
	adminPort := cfg.GetAdminPort()
	if listenPort == adminPort {
		return nil, fmt.Errorf("configuration error: listen_port (%d) and admin_port (%d) must be distinct; unified single-port mode has been removed", listenPort, adminPort)
	}

	// Synchronize security and user context configurations
	if len(cfg.UserContext.TrustedProxies) == 0 && len(cfg.Security.TrustedProxies) > 0 {
		cfg.UserContext.TrustedProxies = cfg.Security.TrustedProxies
	}
	if cfg.UserContext.ContextHMACSecret == "" && cfg.Security.ContextHMACSecret != "" {
		cfg.UserContext.ContextHMACSecret = cfg.Security.ContextHMACSecret
	}
	if strings.HasPrefix(cfg.UserContext.ContextHMACSecret, "${") && strings.HasSuffix(cfg.UserContext.ContextHMACSecret, "}") {
		cfg.UserContext.ContextHMACSecret = os.ExpandEnv(cfg.UserContext.ContextHMACSecret)
	}

	deps := &Dependencies{
		Config:   cfg,
		Provider: provider,
	}

	// 1. Initialize append-only audit trail logger if enabled
	if cfg.AuditLog.Enabled && cfg.AuditLog.Path != "" {
		auditLog, err := logger.NewFileAuditLogger(cfg.AuditLog.Path)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize audit logger: %w", err)
		}
		deps.AuditLog = auditLog
	}

	// 2. Initialize Centralized DuckDB Connection Pool Manager (Slice 3, ADR-0048)
	dbMgr, err := duckdb.NewManager(duckdb.Config{
		DBPath:       cfg.GetTelemetryDBPath(),
		MaxOpenConns: 4,
		MaxIdleConns: 4,
	})
	if err != nil {
		slog.Warn("Failed to initialize centralized DuckDB connection manager", slog.String("error", err.Error()))
	} else {
		deps.DBManager = dbMgr
	}

	// 3. Initialize analytical DuckDB telemetry engine if enabled
	if cfg.IsTelemetryEnabled() && dbMgr != nil {
		telemetryCfg := duckdbTelemetry.Config{
			DBPath:          cfg.GetTelemetryDBPath(),
			RetentionDays:   cfg.Telemetry.RetentionDays,
			MaxSizeBytes:    cfg.Telemetry.MaxSizeBytes,
			MaxPayloadBytes: cfg.Telemetry.MaxPayloadBytes,
			BufferSize:      cfg.Telemetry.BufferSize,
			BatchFlushMs:    cfg.Telemetry.BatchFlushMs,
		}
		tEngine, tErr := duckdbTelemetry.NewWithDB(dbMgr.DB(), telemetryCfg)
		if tErr != nil {
			slog.Warn("Failed to initialize DuckDB telemetry engine, proceeding without local analytics", slog.String("error", tErr.Error()))
		} else {
			deps.TelemetryEngine = tEngine
		}
	}

	// 4. Initialize and seed DuckDB Model Catalog (GUARD-001)
	if dbMgr != nil && dbMgr.DB() != nil {
		cat := guard.NewCatalog(dbMgr.DB())
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := cat.Migrate(ctx); err != nil {
			slog.Warn("Failed to migrate guard models table in DuckDB", slog.String("error", err.Error()))
		}
		if err := cat.Seed(ctx); err != nil {
			slog.Warn("Failed to seed official guard models into DuckDB", slog.String("error", err.Error()))
		}
		cancel()
		deps.GuardCatalog = cat
	}

	// 5. Initialize and seed DuckDB Policy Store & Canonical Packs (POL-001)
	if dbMgr != nil && dbMgr.DB() != nil {
		ps := policy.NewDuckDBStore(dbMgr.DB())
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := ps.Migrate(ctx); err != nil {
			slog.Warn("Failed to migrate policy tables in DuckDB", slog.String("error", err.Error()))
		}
		if err := policy.Seed(ctx, ps); err != nil {
			slog.Warn("Failed to seed canonical policy packs into DuckDB", slog.String("error", err.Error()))
		}

		ss := schema.NewDuckDBSchemaStore(dbMgr.DB())
		if err := ss.Migrate(ctx); err != nil {
			slog.Warn("Failed to migrate mcp_tool_schemas table in DuckDB", slog.String("error", err.Error()))
		}
		cancel()
		deps.PolicyStore = ps
		deps.SchemaStore = ss
	}

	// 5.b. Initialize DuckDB Settings Store & Zero-I/O Overlay Cache (ADR-0053)
	var settingsStore settings.Store
	var settingsCache *settings.Cache

	if dbMgr != nil && dbMgr.DB() != nil {
		sStore := settings.NewDuckDBStore(dbMgr.DB())
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := sStore.Migrate(ctx); err != nil {
			slog.Warn("Failed to migrate system_settings table in DuckDB", slog.String("error", err.Error()))
		}
		overrides, err := sStore.GetAll(ctx)
		if err != nil {
			slog.Warn("Failed to load settings overrides from DuckDB", slog.String("error", err.Error()))
		}
		cancel()

		settings.ApplyFilterOverrides(cfg, overrides)
		effective := settings.ResolveEffectiveSettings(cfg, overrides)
		settingsCache = settings.NewCache(effective)
		settingsStore = sStore
	} else {
		effective := settings.ResolveEffectiveSettings(cfg, nil)
		settingsCache = settings.NewCache(effective)
	}

	deps.SettingsStore = settingsStore
	deps.SettingsCache = settingsCache

	// 6. Compose audit loggers into a single unified logger
	var loggers []filter.AuditLogger
	if deps.AuditLog != nil {
		loggers = append(loggers, deps.AuditLog)
	}
	if deps.TelemetryEngine != nil {
		loggers = append(loggers, deps.TelemetryEngine)
	}

	eventBroker := broker.NewEventBroker(150 * time.Millisecond)
	deps.EventBroker = eventBroker
	loggers = append(loggers, eventBroker)

	if len(loggers) == 1 {
		deps.CombinedLogger = loggers[0]
	} else if len(loggers) > 1 {
		deps.CombinedLogger = filter.NewMultiAuditLogger(loggers...)
	}

	// 7. Assemble core filter pipeline and adaptive fast-path router
	pipe, rtr, err := filter.BuildPipeline(cfg, deps.CombinedLogger)
	if err != nil {
		deps.Cleanup()
		return nil, fmt.Errorf("failed to build security pipeline: %w", err)
	}
	deps.Pipeline = pipe
	deps.Router = rtr

	// 8. Agent Repository and Session Manager
	agentsDir := cfg.GetAgentsDir()
	agentRepo := agent.NewFSRepository(agentsDir, "/etc/faradaiwire/agents")
	deps.AgentRepo = agentRepo
	sessionMgr := session.NewManager(agentRepo, &http.Client{Timeout: 0})
	if deps.SettingsCache != nil {
		sessionMgr.SetSettingsCache(deps.SettingsCache)
	}
	deps.SessionMgr = sessionMgr

	// 9. KeyStore
	keyStorePath := cfg.GetAPIKeysPath()
	keyStore, kErr := auth.NewFileKeyStore(keyStorePath)
	if kErr != nil {
		slog.Warn("Failed to initialize file keystore, falling back to memory keystore", slog.String("error", kErr.Error()))
		keyStore = auth.NewMemoryKeyStore()
	}
	deps.KeyStore = keyStore

	// 10. Decoupled SLM HTTP Inference Provider Client (ADR 0041)
	httpCfg := guard.DefaultHTTPProviderConfig()
	if cfg.Filters.Guard.Discovery.CustomURL != "" {
		httpCfg.BaseURL = cfg.Filters.Guard.Discovery.CustomURL
	} else if cfg.Filters.Guard.Discovery.Mode == "docker" && cfg.Filters.Guard.Discovery.DockerURL != "" {
		httpCfg.BaseURL = cfg.Filters.Guard.Discovery.DockerURL
	} else if cfg.Filters.Guard.Discovery.OllamaURL != "" {
		httpCfg.BaseURL = cfg.Filters.Guard.Discovery.OllamaURL
	}
	guardManager := guard.NewHTTPProvider(httpCfg)
	deps.GuardManager = guardManager

	// 11. Dual-Channel HITL Safety Dispatcher (GUARD-005)
	hitlCfg := guard.DefaultHITLDispatcherConfig()
	hitlDispatcher := guard.NewHITLDispatcher(hitlCfg)
	deps.GuardHITL = hitlDispatcher

	// Auto-restore active guard model if configured in DuckDB catalog (DEC-01, ADR-0045)
	if deps.GuardCatalog != nil {
		bootCtx, bootCancel := context.WithTimeout(context.Background(), 10*time.Second)
		if activeModel, aErr := deps.GuardCatalog.GetActive(bootCtx); aErr == nil && activeModel != nil && (activeModel.EndpointURL != "" || activeModel.InstallStatus == guard.InstallStatusInstalled) {
			if startErr := guardManager.Start(bootCtx, activeModel); startErr != nil {
				slog.Warn("Failed to auto-start active guard model at boot", slog.String("model", activeModel.ID), slog.String("error", startErr.Error()))
			} else {
				slog.Info("Successfully booted active Semantic Security Guard model",
					slog.String("model", activeModel.ID),
					slog.String("endpoint", activeModel.EndpointURL),
					slog.String("runtime", activeModel.RuntimeType),
				)
			}
		}
		bootCancel()
	}

	// 12. Wire all pipeline filters with shared runtime dependencies
	WireFilterDependencies(pipe, cfg, FilterWiringDependencies{
		SchemaStore:   deps.SchemaStore,
		SettingsCache: deps.SettingsCache,
		GuardCatalog:  deps.GuardCatalog,
		GuardManager:  guardManager,
		GuardHITL:     hitlDispatcher,
		AgentRepo:     agentRepo,
	})

	// 13. SLM Guard Model Installer
	guardInstaller := guard.NewInstaller(guard.InstallerConfig{
		Catalog: deps.GuardCatalog,
	})
	deps.GuardInstaller = guardInstaller

	// 14. Inbound Coordinator and Proxy Transports
	cStore := proxy.NewMemoryCorrelationStore()
	fwd := session.NewForwarder(&http.Client{Timeout: 0}, pipe, cStore)
	if deps.SettingsCache != nil {
		fwd.SetSettingsCache(deps.SettingsCache)
	}
	aggregator := agent.NewManifestAggregator(agentRepo)
	dispatcher := session.NewToolDispatcher(agentRepo, sessionMgr)
	if deps.SettingsCache != nil {
		dispatcher.SetSettingsCache(deps.SettingsCache)
	}
	coordinator := session.NewInboundCoordinator(pipe, agentRepo, sessionMgr, aggregator, dispatcher, cStore, fwd, cfg.SSE.TargetURL)
	deps.Coordinator = coordinator

	if cfg.Mode == "stdio" {
		deps.StdioProxy = proxy.NewStdioProxy(cfg.Stdio.Command, cfg.Stdio.Args, cfg.Stdio.AutoRestart, pipe, cfg.UserContext)
	} else {
		listenHost := cfg.GetListenHost()
		secCfg := cfg.Security
		if secCfg.RateLimiting.Enabled == nil {
			secCfg.RateLimiting = cfg.GetHTTPRateLimitConfig()
		}
		sseP := proxy.NewSSEProxyWithCoordinator(listenPort, cfg.SSE.TargetURL, coordinator, cfg.UserContext, secCfg)
		sseP.SetHost(listenHost)
		sseP.SetKeyValidator(keyStore)
		deps.SSEProxy = sseP
	}

	// 15. Admin HTTP Server
	var reloadHook func() error
	var reloadConfigHook func(*config.Config) error
	var clearBaselinesHook func()
	if len(cb) > 0 {
		reloadHook = cb[0].OnReload
		reloadConfigHook = cb[0].OnReloadConfig
		clearBaselinesHook = cb[0].OnClearBaselines
	}
	if reloadHook == nil {
		reloadHook = func() error { return nil }
	}
	if clearBaselinesHook == nil {
		clearBaselinesHook = func() {
			if pipe != nil {
				pipe.ClearBaselines()
			}
		}
	}

	if cfg.AdminPort > 0 || cfg.IsStandalone() || adminPort > 0 {
		adminSrv := admin.NewAdminServer(cfg, reloadHook, clearBaselinesHook)
		adminSrv.SetKeyStore(keyStore)
		adminSrv.SetAgentRepository(agentRepo)
		adminSrv.SetActiveSessionChecker(sessionMgr.HasActiveSessions)
		if deps.TelemetryEngine != nil {
			adminSrv.SetTelemetryEngine(deps.TelemetryEngine)
		}
		if deps.EventBroker != nil {
			adminSrv.SetEventBroker(deps.EventBroker)
		}
		if deps.GuardCatalog != nil {
			adminSrv.SetGuardCatalog(deps.GuardCatalog)
		}
		if deps.PolicyStore != nil {
			adminSrv.SetPolicyStore(deps.PolicyStore)
			reloader := dlp.ReloaderFunc(func(agentName string) {
				if activePipe := adminSrv.GetPipeline(); activePipe != nil {
					if dlpFilter, ok := activePipe.GetFilter("dlp").(*dlp.DLPFilter); ok && dlpFilter != nil {
						dlpFilter.ReloadAgentDLP(agentName)
					}
				}
			})
			adminSrv.SetPolicyCompiler(policy.NewCompiler(deps.PolicyStore, policy.WithReloader(reloader)))
		}
		if deps.SchemaStore != nil {
			adminSrv.SetSchemaStore(deps.SchemaStore)
		}
		if deps.SettingsStore != nil {
			adminSrv.SetSettingsStore(deps.SettingsStore)
		}
		if deps.SettingsCache != nil {
			adminSrv.SetSettingsCache(deps.SettingsCache)
		}
		if yamlProv, ok := provider.(*config.YAMLConfigProvider); ok {
			adminSrv.SetConfigProvider(yamlProv)
		}
		adminSrv.SetGuardManager(guardManager)
		adminSrv.SetGuardHITL(hitlDispatcher)
		if reloadConfigHook != nil {
			adminSrv.SetReloadConfigFunc(reloadConfigHook)
		}
		adminSrv.SetPipeline(pipe)
		adminSrv.SetGuardInstaller(guardInstaller)

		if adminSrv.WSHub() != nil {
			hitlDispatcher.SetWSHub(adminSrv.WSHub())
		}
		deps.AdminServer = adminSrv
	}

	return deps, nil
}

// Cleanup releases all held resources if bootstrap fails midway.
func (d *Dependencies) Cleanup() {
	if d.AuditLog != nil {
		_ = d.AuditLog.Close()
	}
	if d.TelemetryEngine != nil {
		_ = d.TelemetryEngine.Close()
	}
	if d.EventBroker != nil {
		_ = d.EventBroker.Close()
	}
	if d.DBManager != nil {
		_ = d.DBManager.Close()
	}
}
