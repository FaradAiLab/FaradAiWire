package gateway_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/hitl"
	"github.com/FaradAiLab/FaradAiWire/internal/gateway"
	"github.com/FaradAiLab/FaradAiWire/internal/gateway/bootstrap"
	"github.com/FaradAiLab/FaradAiWire/internal/settings"
)

func TestFilterPersistence_FreshInstall7LayersAndToggleLifecycle(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("FARADAI_WIRE_HOME", tmpHome)

	configPath, err := config.EnsureDefaultRuntimeConfig()
	if err != nil {
		t.Fatalf("EnsureDefaultRuntimeConfig failed: %v", err)
	}

	originalYAMLBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed to read generated config.yaml: %v", err)
	}

	provider := config.NewYAMLConfigProvider(configPath)
	cfg, err := provider.Load()
	if err != nil {
		t.Fatalf("failed to load default config: %v", err)
	}
	cfg.Telemetry.DBPath = filepath.Join(tmpHome, "wire.duckdb")

	srv, err := gateway.NewServer(cfg, provider)
	if err != nil {
		t.Fatalf("failed to boot gateway server: %v", err)
	}

	adminH := srv.AdminHandler()

	// 1. Fresh install must expose all 7 security layers active
	allLayers := []string{
		"prefill_block",
		"dlp",
		"rate_limiting",
		"loop_protection",
		"guard",
		"hitl",
		"schema_validation",
	}

	statusFilters := fetchActiveFilters(t, adminH)
	for _, layer := range allLayers {
		if !slices.Contains(statusFilters, layer) {
			t.Fatalf("expected fresh install to activate %q, got active_filters=%v", layer, statusFilters)
		}
	}
	if len(statusFilters) != 7 {
		t.Fatalf("expected 7 active filters on fresh install, got %d (%v)", len(statusFilters), statusFilters)
	}

	// Verify Layer 6 HITLFilter is wired to unified dual-channel HITLDispatcher
	hf, ok := srv.Pipeline().GetFilter("hitl").(*hitl.HITLFilter)
	if !ok || hf == nil || hf.HITLDispatcher() == nil {
		t.Fatal("expected booted HITLFilter to have unified HITLDispatcher wired")
	}

	// 2. Toggle all 7 filters OFF sequentially
	for _, layer := range allLayers {
		postFilterToggle(t, adminH, layer, false)
	}
	if got := fetchActiveFilters(t, adminH); len(got) != 0 {
		t.Fatalf("expected 0 active filters after disabling all, got %v", got)
	}

	// 3. Toggle 3 filters back ON (guard, hitl, schema_validation)
	wantActive := []string{"guard", "hitl", "schema_validation"}
	for _, layer := range wantActive {
		postFilterToggle(t, adminH, layer, true)
	}

	// Reload from disk must preserve DuckDB overrides
	if err := srv.Reload(); err != nil {
		t.Fatalf("srv.Reload() failed: %v", err)
	}
	afterReload := fetchActiveFilters(t, adminH)
	if len(afterReload) != len(wantActive) {
		t.Fatalf("expected %v after Reload(), got %v", wantActive, afterReload)
	}
	for _, layer := range wantActive {
		if !slices.Contains(afterReload, layer) {
			t.Errorf("expected %q active after Reload(), got %v", layer, afterReload)
		}
	}

	// Re-check unified HITLDispatcher after reload
	hfReloaded, ok := srv.Pipeline().GetFilter("hitl").(*hitl.HITLFilter)
	if !ok || hfReloaded == nil || hfReloaded.HITLDispatcher() == nil {
		t.Fatal("expected HITLFilter to remain wired to HITLDispatcher after Reload()")
	}

	// Shut down and reboot a brand-new Server instance against the same DuckDB and config.yaml
	_ = srv.Shutdown(context.Background())

	cfg2, err := provider.Load()
	if err != nil {
		t.Fatalf("failed to reload config for restarted server: %v", err)
	}
	cfg2.Telemetry.DBPath = filepath.Join(tmpHome, "wire.duckdb")

	srv2, err := gateway.NewServer(cfg2, provider)
	if err != nil {
		t.Fatalf("failed to boot restarted gateway server: %v", err)
	}
	defer srv2.Shutdown(context.Background())

	afterRestart := fetchActiveFilters(t, srv2.AdminHandler())
	if len(afterRestart) != len(wantActive) {
		t.Fatalf("expected %v after restart, got %v", wantActive, afterRestart)
	}
	for _, layer := range wantActive {
		if !slices.Contains(afterRestart, layer) {
			t.Errorf("expected %q active after restart, got %v", layer, afterRestart)
		}
	}

	// Verify config.yaml on disk was never modified
	afterYAMLBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed to read config.yaml after test: %v", err)
	}
	if string(afterYAMLBytes) != string(originalYAMLBytes) {
		t.Fatal("config.yaml on disk was unexpectedly mutated")
	}
}

func TestFilterPersistence_Legacy3FilterConfigHydratesOnToggle(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("FARADAI_WIRE_HOME", tmpHome)
	configPath := filepath.Join(tmpHome, "config.yaml")
	dbPath := filepath.Join(tmpHome, "wire.duckdb")

	// Simulate pre-fix Windows config.yaml with only 3 filters
	legacyYAML := `runtime_mode: STANDALONE
listen_host: "127.0.0.1"
listen_port: 8090
admin_port: 8095
filters:
  prefill_block:
    enabled: true
  guard:
    enabled: true
  dlp:
    enabled: true
`
	if err := os.WriteFile(configPath, []byte(legacyYAML), 0644); err != nil {
		t.Fatalf("failed to write legacy config: %v", err)
	}

	provider := config.NewYAMLConfigProvider(configPath)
	cfg, err := provider.Load()
	if err != nil {
		t.Fatalf("load legacy config: %v", err)
	}
	cfg.Telemetry.DBPath = dbPath

	srv, err := gateway.NewServer(cfg, provider)
	if err != nil {
		t.Fatalf("boot gateway: %v", err)
	}
	defer srv.Shutdown(context.Background())

	adminH := srv.AdminHandler()
	if initial := fetchActiveFilters(t, adminH); len(initial) != 3 {
		t.Fatalf("expected 3 initial filters in legacy config, got %v", initial)
	}

	// Enable the 4 previously missing filters from UI
	for _, missing := range []string{"rate_limiting", "loop_protection", "hitl", "schema_validation"} {
		postFilterToggle(t, adminH, missing, true)
	}

	active := fetchActiveFilters(t, adminH)
	if len(active) != 7 {
		t.Fatalf("expected all 7 filters active after toggling missing ones ON, got %v", active)
	}

	// Hydrated HITLFilter must have HITLDispatcher wired
	hf, ok := srv.Pipeline().GetFilter("hitl").(*hitl.HITLFilter)
	if !ok || hf == nil || hf.HITLDispatcher() == nil {
		t.Fatal("expected newly enabled HITLFilter from legacy config to have HITLDispatcher wired")
	}
}

func TestFilterPersistence_ConcurrentToggleReloadAndReset(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("FARADAI_WIRE_HOME", tmpHome)

	configPath, err := config.EnsureDefaultRuntimeConfig()
	if err != nil {
		t.Fatalf("EnsureDefaultRuntimeConfig failed: %v", err)
	}
	provider := config.NewYAMLConfigProvider(configPath)
	cfg, err := provider.Load()
	if err != nil {
		t.Fatalf("provider.Load failed: %v", err)
	}
	cfg.Telemetry.DBPath = filepath.Join(tmpHome, "wire.duckdb")

	srv, err := gateway.NewServer(cfg, provider)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	defer srv.Shutdown(context.Background())

	adminH := srv.AdminHandler()
	filters := []string{"dlp", "hitl", "rate_limiting", "loop_protection", "guard", "schema_validation"}

	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		filterName := filters[i%len(filters)]
		wg.Add(1)
		go func(name string, idx int) {
			defer wg.Done()
			postFilterToggle(t, adminH, name, idx%2 == 0)
			_ = srv.Reload()
			if idx%3 == 0 {
				rReq := httptest.NewRequest(http.MethodPost, "/admin/settings/reset", strings.NewReader(`{"key":"filters.`+name+`"}`))
				rReq.Header.Set("Content-Type", "application/json")
				rRec := httptest.NewRecorder()
				adminH.ServeHTTP(rRec, rReq)
				if rRec.Code != http.StatusOK {
					t.Errorf("concurrent reset failed with %d: %s", rRec.Code, rRec.Body.String())
				}
			}
			_ = fetchActiveFilters(t, adminH)
		}(filterName, i)
	}
	wg.Wait()
}

func postFilterToggle(t *testing.T, handler http.Handler, filterName string, enabled bool) {
	t.Helper()
	body := `{"filter":"` + filterName + `","enabled":`
	if enabled {
		body += "true}"
	} else {
		body += "false}"
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/config/toggle", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("toggle %s=%v failed with %d: %s", filterName, enabled, rec.Code, rec.Body.String())
	}
}

func fetchActiveFilters(t *testing.T, handler http.Handler) []string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/admin/status", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/status failed with %d: %s", rec.Code, rec.Body.String())
	}
	var st struct {
		ActiveFilters []string `json:"active_filters"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatalf("decode /admin/status: %v", err)
	}
	return st.ActiveFilters
}

type errGetAllSettingsStore struct {
	settings.Store
}

func (e *errGetAllSettingsStore) GetAll(context.Context) (map[string]string, error) {
	return nil, errors.New("duckdb read error")
}

func TestServer_Reload_AbortsOnSettingsStoreError_PreservesLKG(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("FARADAI_WIRE_HOME", tmpHome)

	configPath, err := config.EnsureDefaultRuntimeConfig()
	if err != nil {
		t.Fatalf("EnsureDefaultRuntimeConfig failed: %v", err)
	}
	provider := config.NewYAMLConfigProvider(configPath)
	lkgCfg, err := provider.Load()
	if err != nil {
		t.Fatalf("provider.Load failed: %v", err)
	}
	lkgCfg.Filters.DLP.Enabled = false

	pipe := filter.NewPipeline(nil)
	initialFilters := pipe.GetFilters()

	srv, err := gateway.NewServerWithDependencies(&bootstrap.Dependencies{
		Config:        lkgCfg,
		Provider:      provider,
		Pipeline:      pipe,
		SettingsStore: &errGetAllSettingsStore{},
		SettingsCache: settings.NewCache(settings.DefaultOperationalSettings()),
	})
	if err != nil {
		t.Fatalf("NewServerWithDependencies failed: %v", err)
	}

	if err := srv.Reload(); err == nil {
		t.Fatal("expected Reload() to fail when SettingsStore.GetAll errors")
	}

	if len(srv.Pipeline().GetFilters()) != len(initialFilters) {
		t.Fatalf("expected LKG pipeline filters preserved on failed reload")
	}
}
