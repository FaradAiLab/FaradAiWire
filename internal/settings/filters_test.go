package settings

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/marcboeker/go-duckdb"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
)

func TestFilterRegistry_AllExpectedFiltersPresent(t *testing.T) {
	t.Parallel()

	expectedKeys := []string{
		"filters.prefill_block",
		"filters.schema_validation",
		"filters.dlp",
		"filters.guard",
		"filters.hitl",
		"filters.loop_protection",
		"filters.rate_limiting",
		"filters.injection_scanner",
	}

	for _, key := range expectedKeys {
		meta, ok := FilterRegistry[key]
		if !ok {
			t.Errorf("expected FilterRegistry to contain %q", key)
			continue
		}
		if meta.Type != TypeBool {
			t.Errorf("expected %q to have TypeBool, got %q", key, meta.Type)
		}
		if meta.Category != "filters" {
			t.Errorf("expected %q to have category 'filters', got %q", key, meta.Category)
		}
		if !IsFilterKey(key) {
			t.Errorf("expected IsFilterKey(%q) to return true", key)
		}
	}

	if IsFilterKey("guard.threshold_score") {
		t.Error("expected IsFilterKey('guard.threshold_score') to return false")
	}
}

func TestApplyFilterToggleToConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		filterName string
		enabled    bool
		wantOK     bool
		check      func(t *testing.T, cfg *config.Config)
	}{
		{
			name:       "enable prefill_block",
			filterName: "prefill_block",
			enabled:    true,
			wantOK:     true,
			check: func(t *testing.T, cfg *config.Config) {
				if !cfg.Filters.PrefillBlock.Enabled {
					t.Error("expected prefill_block enabled")
				}
			},
		},
		{
			name:       "enable schema_validation hydrates unconfigured block",
			filterName: "schema_validation",
			enabled:    true,
			wantOK:     true,
			check: func(t *testing.T, cfg *config.Config) {
				if !cfg.Filters.SchemaValidation.Enabled {
					t.Error("expected schema_validation enabled")
				}
				if cfg.Filters.SchemaValidation.SchemasDir == "" {
					t.Error("expected unconfigured SchemasDir to be hydrated")
				}
				if !cfg.Filters.SchemaValidation.DynamicCapture || !cfg.Filters.SchemaValidation.BaselinePinning {
					t.Error("expected DynamicCapture and BaselinePinning defaults to be hydrated")
				}
			},
		},
		{
			name:       "enable dlp",
			filterName: "dlp",
			enabled:    true,
			wantOK:     true,
			check: func(t *testing.T, cfg *config.Config) {
				if !cfg.Filters.DLP.Enabled {
					t.Error("expected dlp enabled")
				}
			},
		},
		{
			name:       "enable guard",
			filterName: "guard",
			enabled:    true,
			wantOK:     true,
			check: func(t *testing.T, cfg *config.Config) {
				if !cfg.Filters.Guard.Enabled {
					t.Error("expected guard enabled")
				}
			},
		},
		{
			name:       "enable hitl hydrates unconfigured block",
			filterName: "hitl",
			enabled:    true,
			wantOK:     true,
			check: func(t *testing.T, cfg *config.Config) {
				if !cfg.Filters.HITL.Enabled {
					t.Error("expected hitl enabled")
				}
				if len(cfg.Filters.HITL.DestructiveTools) == 0 {
					t.Error("expected unconfigured DestructiveTools to be hydrated")
				}
				if cfg.Filters.HITL.TimeoutSeconds <= 0 {
					t.Error("expected TimeoutSeconds default to be hydrated")
				}
			},
		},
		{
			name:       "enable loop_protection hydrates unconfigured block",
			filterName: "loop_protection",
			enabled:    true,
			wantOK:     true,
			check: func(t *testing.T, cfg *config.Config) {
				if !cfg.Filters.LoopProtection.Enabled {
					t.Error("expected loop_protection enabled")
				}
				if cfg.Filters.LoopProtection.MaxRepeat <= 0 || cfg.Filters.LoopProtection.WindowSeconds <= 0 {
					t.Error("expected loop_protection thresholds to be hydrated")
				}
			},
		},
		{
			name:       "enable rate_limiting hydrates unconfigured block",
			filterName: "rate_limiting",
			enabled:    true,
			wantOK:     true,
			check: func(t *testing.T, cfg *config.Config) {
				if !cfg.Filters.RateLimiting.Enabled {
					t.Error("expected rate_limiting enabled")
				}
				if cfg.Filters.RateLimiting.MaxBurst <= 0 || cfg.Filters.RateLimiting.RefillRate <= 0 {
					t.Error("expected rate_limiting thresholds to be hydrated")
				}
			},
		},
		{
			name:       "enable injection_scanner",
			filterName: "injection_scanner",
			enabled:    true,
			wantOK:     true,
			check: func(t *testing.T, cfg *config.Config) {
				if !cfg.Filters.InjectionScanner.Enabled {
					t.Error("expected injection_scanner enabled")
				}
			},
		},
		{
			name:       "unknown filter returns false",
			filterName: "unknown_filter",
			enabled:    true,
			wantOK:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := &config.Config{}
			ok := ApplyFilterToggleToConfig(cfg, tc.filterName, tc.enabled)
			if ok != tc.wantOK {
				t.Fatalf("ApplyFilterToggleToConfig(%q) = %v, want %v", tc.filterName, ok, tc.wantOK)
			}
			if tc.check != nil {
				tc.check(t, cfg)
			}
		})
	}
}

func TestApplyFilterOverrides(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		Filters: config.FiltersConfig{
			PrefillBlock: config.PrefillBlockConfig{Enabled: true},
			DLP:          config.DLPConfig{Enabled: true},
			RateLimiting: config.RateLimitingConfig{Enabled: false, MaxBurst: 25, RefillRate: 5.0},
		},
	}

	overrides := map[string]string{
		"filters.prefill_block": "false",
		"filters.rate_limiting": "true",
		"filters.hitl":          "invalid_bool", // skipped gracefully
		"filters.unknown":       "true",         // skipped gracefully
		"guard.threshold_score": "0.75",         // ignored (non-filter operational setting)
	}

	ApplyFilterOverrides(cfg, overrides)

	if cfg.Filters.PrefillBlock.Enabled {
		t.Error("expected prefill_block to be overridden to false")
	}
	if !cfg.Filters.DLP.Enabled {
		t.Error("expected unmodified dlp to retain YAML value true")
	}
	if !cfg.Filters.RateLimiting.Enabled {
		t.Error("expected rate_limiting to be overridden to true")
	}
	// Existing configured MaxBurst/RefillRate must be preserved rather than clobbered
	if cfg.Filters.RateLimiting.MaxBurst != 25 || cfg.Filters.RateLimiting.RefillRate != 5.0 {
		t.Errorf("expected configured rate limit params preserved, got burst=%d rate=%v",
			cfg.Filters.RateLimiting.MaxBurst, cfg.Filters.RateLimiting.RefillRate)
	}
	if cfg.Filters.HITL.Enabled {
		t.Error("expected corrupted boolean override for hitl to be ignored")
	}
}

func TestDuckDBStore_FilterTogglePersistence(t *testing.T) {
	t.Parallel()

	db, err := sql.Open("duckdb", ":memory:")
	if err != nil {
		t.Fatalf("failed to open duckdb: %v", err)
	}
	store := NewDuckDBStore(db)
	ctx := context.Background()
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("failed to migrate store: %v", err)
	}

	if err := store.Set(ctx, "filters.dlp", "false"); err != nil {
		t.Fatalf("expected DuckDBStore.Set to accept filters.dlp, got: %v", err)
	}
	if err := store.Set(ctx, "filters.schema_validation", "true"); err != nil {
		t.Fatalf("expected DuckDBStore.Set to accept filters.schema_validation, got: %v", err)
	}

	overrides, err := store.GetAll(ctx)
	if err != nil {
		t.Fatalf("GetAll failed: %v", err)
	}
	cfg := &config.Config{
		Filters: config.FiltersConfig{
			DLP: config.DLPConfig{Enabled: true},
		},
	}
	ApplyFilterOverrides(cfg, overrides)

	if cfg.Filters.DLP.Enabled {
		t.Error("expected DLP to be disabled via DuckDB override")
	}
	if !cfg.Filters.SchemaValidation.Enabled {
		t.Error("expected SchemaValidation to be enabled via DuckDB override")
	}
}
