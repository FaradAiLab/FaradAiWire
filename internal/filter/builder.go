package filter

import (
	"fmt"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/adaptive"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/dlp"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/hitl"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/limit"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/prefill"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/schema"
	"github.com/FaradAiLab/FaradAiWire/internal/guard"
	"github.com/FaradAiLab/FaradAiWire/internal/transport"
)

// BuildPipeline constructs and wires the entire security filter pipeline and adaptive router based on configuration.
// Core dogfoods pipeline.RegisterFilter(f) for all built-in filters to maintain strict Order() precedence.
func BuildPipeline(cfg *config.Config, auditLog AuditLogger) (*Pipeline, *adaptive.Router, error) {
	if cfg == nil {
		return nil, nil, fmt.Errorf("configuration cannot be nil")
	}

	filters, err := BuildFilters(cfg, auditLog)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build security filters: %w", err)
	}

	pipeline := NewPipeline(auditLog)
	if cfg.Filters.DLP.DebugRetainUnmaskedDiff {
		pipeline.SetDebugRetainUnmaskedDiff(true)
	}
	for _, f := range filters {
		pipeline.RegisterFilter(f)
	}

	router := adaptive.NewRouter(
		cfg.Filters.Adaptive.Enabled,
		cfg.Filters.Adaptive.DefaultPath,
		cfg.Filters.Adaptive.FastPathTools,
		cfg.Filters.Adaptive.DeepPathTools,
	)
	pipeline.SetAdaptiveRouter(router)

	return pipeline, router, nil
}

// BuildFilters instantiates all enabled filters in the canonical security execution sequence.
func BuildFilters(cfg *config.Config, auditLog AuditLogger) ([]SecurityFilter, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration cannot be nil")
	}

	var filters []SecurityFilter
	agentsDir := cfg.GetAgentsDir()

	// 1. Prefill/Sockpuppeting filter (Request path) - Order: 5
	if cfg.Filters.PrefillBlock.Enabled {
		filters = append(filters, prefill.NewPrefillFilter(true))
	}

	// 2. Rate Limiting filter (Request path) - Order: 10
	if cfg.Filters.RateLimiting.Enabled {
		var opts []limit.StoreOption
		if cfg.Filters.RateLimiting.TTLSeconds > 0 {
			opts = append(opts, limit.WithTTL(time.Duration(cfg.Filters.RateLimiting.TTLSeconds)*time.Second))
		}
		if cfg.Filters.RateLimiting.CleanupIntervalSeconds > 0 {
			opts = append(opts, limit.WithCleanupInterval(time.Duration(cfg.Filters.RateLimiting.CleanupIntervalSeconds)*time.Second))
		}
		if cfg.Filters.RateLimiting.MaxKeys > 0 {
			opts = append(opts, limit.WithMaxKeys(cfg.Filters.RateLimiting.MaxKeys))
		}
		rateStore := limit.NewInMemoryStateStore(opts...)
		filters = append(filters, limit.NewRateLimitFilter(
			true,
			cfg.Filters.RateLimiting.MaxBurst,
			cfg.Filters.RateLimiting.RefillRate,
			rateStore,
		))
	}

	// 3. Loop Protection filter (Request path) - Order: 15
	if cfg.Filters.LoopProtection.Enabled {
		var opts []limit.StoreOption
		if cfg.Filters.LoopProtection.TTLSeconds > 0 {
			opts = append(opts, limit.WithTTL(time.Duration(cfg.Filters.LoopProtection.TTLSeconds)*time.Second))
		}
		if cfg.Filters.LoopProtection.CleanupIntervalSeconds > 0 {
			opts = append(opts, limit.WithCleanupInterval(time.Duration(cfg.Filters.LoopProtection.CleanupIntervalSeconds)*time.Second))
		}
		if cfg.Filters.LoopProtection.MaxKeys > 0 {
			opts = append(opts, limit.WithMaxKeys(cfg.Filters.LoopProtection.MaxKeys))
		}
		loopStore := limit.NewInMemoryStateStore(opts...)
		filters = append(filters, limit.NewLoopFilter(
			true,
			cfg.Filters.LoopProtection.MaxRepeat,
			cfg.Filters.LoopProtection.WindowSeconds,
			cfg.Filters.LoopProtection.ExcludeTools,
			cfg.Filters.LoopProtection.Overrides,
			loopStore,
		))
	}

	// 4. Schema validation filter (Request/Response paths) - Order: 30
	if cfg.Filters.SchemaValidation.Enabled {
		filters = append(filters, schema.NewSchemaFilter(
			true,
			cfg.Filters.SchemaValidation.SchemasDir,
			cfg.Filters.SchemaValidation.DynamicCapture,
			cfg.Filters.SchemaValidation.BaselinePinning,
		))
	}

	// 5. DLP/PII filter (Request/Response paths) - Order: 50
	if cfg.Filters.DLP.Enabled {
		patterns := cfg.Filters.DLP.Patterns
		if len(patterns) == 0 {
			patterns = dlp.DefaultBaselinePatterns()
		}
		dlpFilter, err := dlp.NewDLPFilter(true, cfg.Filters.DLP.ExcludeTools, patterns, agentsDir)
		if err != nil {
			return nil, fmt.Errorf("failed to load DLP patterns: %w", err)
		}
		filters = append(filters, dlpFilter)
	}

	// 5.5. Semantic Security Guard filter (Request & Response paths) - Order: 55 (GUARD-004 / ADR-0042)
	if cfg.Filters.Guard.Enabled {
		guardFilter := guard.NewFilter(guard.FilterConfig{
			Enabled:          cfg.Filters.Guard.Enabled,
			L1Patterns:       cfg.Filters.Guard.L1Patterns,
			FastPathTools:    cfg.Filters.Guard.FastPathTools,
			CriticalBlocks:   cfg.Filters.Guard.CriticalBlocks,
			MaxPayloadLength: cfg.Filters.Guard.MaxPayloadLength,
			MinWordCount:     cfg.Filters.Guard.MinWordCount,
		})
		filters = append(filters, guardFilter)
	}

	// 6. HITL confirmation filter (Request path) - Order: 70
	if cfg.Filters.HITL.Enabled {
		filters = append(filters, hitl.NewHITLFilterWithSSRF(
			true,
			cfg.Filters.HITL.DestructiveTools,
			cfg.Filters.HITL.ApprovalMode,
			cfg.Filters.HITL.WebhookURL,
			cfg.Filters.HITL.TimeoutSeconds,
			transport.OptionsFromConfig(cfg.Security.SSRFProtection),
		))
	}

	return filters, nil
}
