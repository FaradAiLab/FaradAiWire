package settings

import (
	"context"
	"database/sql"
	"slices"
	"strings"
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

func TestApplyGuardDiscoveryOverrides(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		overrides map[string]string
		wantMode  string
		wantOll   string
		wantDoc   string
		wantCust  string
	}{
		{
			name: "applies valid discovery keys",
			overrides: map[string]string{
				GuardDiscoveryModeKey:      "custom",
				GuardDiscoveryOllamaURLKey: "http://127.0.0.1:21434",
				GuardDiscoveryDockerURLKey: "http://127.0.0.1:18088",
				GuardDiscoveryCustomURLKey: "http://127.0.0.1:9000/v1",
			},
			wantMode: "custom",
			wantOll:  "http://127.0.0.1:21434",
			wantDoc:  "http://127.0.0.1:18088",
			wantCust: "http://127.0.0.1:9000/v1",
		},
		{
			name: "ignores invalid mode and preserves existing URLs",
			overrides: map[string]string{
				GuardDiscoveryModeKey:      "bogus_mode",
				GuardDiscoveryCustomURLKey: "http://127.0.0.1:9999/v1",
			},
			wantMode: "auto",
			wantOll:  "http://127.0.0.1:11434",
			wantDoc:  "http://127.0.0.1:8088",
			wantCust: "http://127.0.0.1:9999/v1",
		},
		{
			name: "skips invalid discovery URLs and allows empty clear override",
			overrides: map[string]string{
				GuardDiscoveryModeKey:      "auto",
				GuardDiscoveryOllamaURLKey: "ftp://invalid.local",
				GuardDiscoveryDockerURLKey: "http://169.254.169.254/latest",
				GuardDiscoveryCustomURLKey: "",
			},
			wantMode: "auto",
			wantOll:  "http://127.0.0.1:11434",
			wantDoc:  "http://127.0.0.1:8088",
			wantCust: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := &config.Config{
				Filters: config.FiltersConfig{
					Guard: config.GuardConfig{
						Discovery: config.DiscoveryConfig{
							Mode:      "auto",
							OllamaURL: "http://127.0.0.1:11434",
							DockerURL: "http://127.0.0.1:8088",
							CustomURL: "http://127.0.0.1:9000/v1",
						},
					},
				},
			}
			ApplyGuardDiscoveryOverrides(cfg, tc.overrides)
			if cfg.Filters.Guard.Discovery.Mode != tc.wantMode {
				t.Errorf("Mode = %q, want %q", cfg.Filters.Guard.Discovery.Mode, tc.wantMode)
			}
			if cfg.Filters.Guard.Discovery.OllamaURL != tc.wantOll {
				t.Errorf("OllamaURL = %q, want %q", cfg.Filters.Guard.Discovery.OllamaURL, tc.wantOll)
			}
			if cfg.Filters.Guard.Discovery.DockerURL != tc.wantDoc {
				t.Errorf("DockerURL = %q, want %q", cfg.Filters.Guard.Discovery.DockerURL, tc.wantDoc)
			}
			if cfg.Filters.Guard.Discovery.CustomURL != tc.wantCust {
				t.Errorf("CustomURL = %q, want %q", cfg.Filters.Guard.Discovery.CustomURL, tc.wantCust)
			}
		})
	}
}

func TestValidateGuardDiscoveryURL_AndDuckDBPersistence(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"empty clear allowed", "", false},
		{"localhost http allowed", "http://127.0.0.1:11434", false},
		{"https remote allowed", "https://guard.internal:8443/v1", false},
		{"file scheme rejected", "file:///etc/passwd", true},
		{"imds v4 rejected", "http://169.254.169.254/latest/meta-data", true},
		{"metadata google rejected", "http://metadata.google.internal/computeMetadata/v1", true},
		{"link-local ipv6 rejected", "http://[fe80::1]:8080/v1", true},
		{"oversized rejected", "http://127.0.0.1/" + strings.Repeat("a", 2050), true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateGuardDiscoveryURL(tc.url)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateGuardDiscoveryURL(%q) err=%v, wantErr=%v", tc.url, err, tc.wantErr)
			}
		})
	}

	db, err := sql.Open("duckdb", ":memory:")
	if err != nil {
		t.Fatalf("open duckdb: %v", err)
	}
	defer db.Close()
	store := NewDuckDBStore(db)
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	if err := store.Set(context.Background(), GuardDiscoveryCustomURLKey, "http://169.254.169.254/latest"); err == nil {
		t.Fatal("expected DuckDBStore.Set to reject link-local metadata URL")
	}
	if err := store.Set(context.Background(), GuardDiscoveryCustomURLKey, ""); err != nil {
		t.Fatalf("expected DuckDBStore.Set to accept empty string clear override, got: %v", err)
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

func TestApplyFilterToggleToConfig_SchemaDirIndependentHydration(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		Filters: config.FiltersConfig{
			SchemaValidation: config.SchemaValidationConfig{
				DynamicCapture: true,
				SchemasDir:     "",
			},
		},
	}

	if ok := ApplyFilterToggleToConfig(cfg, "schema_validation", true); !ok {
		t.Fatal("expected ApplyFilterToggleToConfig to return true")
	}
	if cfg.Filters.SchemaValidation.SchemasDir == "" {
		t.Fatal("expected SchemasDir to be hydrated even when DynamicCapture was already true")
	}
	if cfg.Filters.SchemaValidation.BaselinePinning {
		t.Fatal("expected BaselinePinning not to be forced on when already partially initialized")
	}
}

func TestOrderedFilterNames_MatchesFilterRegistry(t *testing.T) {
	t.Parallel()

	names := OrderedFilterNames()
	if len(names) != len(FilterRegistry) {
		t.Fatalf("OrderedFilterNames len=%d != FilterRegistry len=%d", len(names), len(FilterRegistry))
	}
	seen := make(map[string]bool, len(names))
	for _, n := range names {
		if seen[n] {
			t.Fatalf("duplicate name %q in OrderedFilterNames", n)
		}
		seen[n] = true
		if !IsSupportedFilterName(n) {
			t.Fatalf("OrderedFilterNames entry %q missing from FilterRegistry", n)
		}
	}
	// Returned slice must be safe from caller mutation.
	names[0] = "mutated"
	if OrderedFilterNames()[0] == "mutated" {
		t.Fatal("expected OrderedFilterNames to return a cloned slice")
	}
}

func TestBuildFilterStatusSummary(t *testing.T) {
	t.Parallel()

	t.Run("nil config returns all false and empty active filters", func(t *testing.T) {
		t.Parallel()
		summary := BuildFilterStatusSummary(nil)
		if len(summary.ActiveFilters) != 0 {
			t.Fatalf("expected 0 active filters for nil cfg, got %v", summary.ActiveFilters)
		}
		if len(summary.ConfigStates) != len(FilterRegistry) {
			t.Fatalf("expected %d config states, got %d", len(FilterRegistry), len(summary.ConfigStates))
		}
		for _, v := range summary.ConfigStates {
			if v {
				t.Fatal("expected all ConfigStates false for nil cfg")
			}
		}
	})

	t.Run("tracks pipeline filters in active_filters and config_states", func(t *testing.T) {
		t.Parallel()
		cfg := &config.Config{
			Filters: config.FiltersConfig{
				PrefillBlock: config.PrefillBlockConfig{Enabled: true},
				DLP:          config.DLPConfig{Enabled: true},
				Guard:        config.GuardConfig{Enabled: true},
			},
		}
		summary := BuildFilterStatusSummary(cfg)
		wantActive := []string{"prefill_block", "dlp", "guard"}
		if !slices.Equal(summary.ActiveFilters, wantActive) {
			t.Fatalf("ActiveFilters = %v, want %v", summary.ActiveFilters, wantActive)
		}
		for _, f := range wantActive {
			if !summary.ConfigStates[f] {
				t.Fatalf("expected ConfigStates[%s] = true", f)
			}
		}
	})
}

func BenchmarkApplyFilterOverrides(b *testing.B) {
	overrides := map[string]string{
		"filters.prefill_block":     "false",
		"filters.rate_limiting":     "true",
		"filters.dlp":               "true",
		"filters.schema_validation": "true",
		"filters.hitl":              "false",
		"filters.guard":             "true",
		"guard.threshold_score":     "0.75",
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		cfg := config.Config{
			Filters: config.FiltersConfig{
				PrefillBlock: config.PrefillBlockConfig{Enabled: true},
				RateLimiting: config.RateLimitingConfig{MaxBurst: 25, RefillRate: 5.0},
			},
		}
		ApplyFilterOverrides(&cfg, overrides)
	}
}
