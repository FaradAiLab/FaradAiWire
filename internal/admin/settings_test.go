package admin

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/marcboeker/go-duckdb"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/internal/guard"
	"github.com/FaradAiLab/FaradAiWire/internal/protocol"
	"github.com/FaradAiLab/FaradAiWire/internal/settings"
)

type mockAuditLogger struct {
	mu     sync.Mutex
	events []*filter.AuditEvent
}

func (m *mockAuditLogger) LogEvent(event *filter.AuditEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
}

func (m *mockAuditLogger) GetEvents() []*filter.AuditEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	copied := make([]*filter.AuditEvent, len(m.events))
	copy(copied, m.events)
	return copied
}

func setupTestAdminSettings(t *testing.T) (*AdminServer, *settings.DuckDBStore, *settings.Cache, *mockAuditLogger) {
	t.Helper()

	db, err := sql.Open("duckdb", ":memory:")
	if err != nil {
		t.Fatalf("failed to open duckdb: %v", err)
	}

	store := settings.NewDuckDBStore(db)
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatalf("failed to migrate system_settings: %v", err)
	}

	cache := settings.NewCache(settings.DefaultOperationalSettings())
	cfg := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
	}

	server := NewAdminServer(cfg, func() error { return nil }, func() {})
	server.SetSettingsStore(store)
	server.SetSettingsCache(cache)

	logger := &mockAuditLogger{}
	server.mu.Lock()
	server.telemetryEngine = &mockTelemetryWithLogger{mockAuditLogger: logger}
	server.mu.Unlock()

	return server, store, cache, logger
}

type mockTelemetryWithLogger struct {
	mockTelemetryReader
	*mockAuditLogger
}

func TestSettingsAPI_GetSelfDescribing(t *testing.T) {
	t.Parallel()

	server, _, _, _ := setupTestAdminSettings(t)
	handler := server.Handler()

	req := httptest.NewRequest(http.MethodGet, "/admin/settings", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Status     string                 `json:"status"`
		Categories []string               `json:"categories"`
		Settings   []settings.SettingItem `json:"settings"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse json response: %v", err)
	}

	if resp.Status != "success" {
		t.Errorf("expected status 'success', got %q", resp.Status)
	}
	if len(resp.Categories) != 4 {
		t.Errorf("expected 4 categories, got %v", resp.Categories)
	}
	if len(resp.Settings) != len(settings.Registry) {
		t.Errorf("expected %d settings items, got %d", len(settings.Registry), len(resp.Settings))
	}

	// Verify all initially have is_overridden = false
	for _, item := range resp.Settings {
		if item.IsOverridden {
			t.Errorf("setting %q should not be overridden initially", item.Key)
		}
	}
}

func TestSettingsAPI_MutateAndReset(t *testing.T) {
	t.Parallel()

	server, store, cache, logger := setupTestAdminSettings(t)
	handler := server.Handler()

	// 1. Mutate setting
	payload := []byte(`{"key": "guard.threshold_score", "value": 0.35}`)
	req := httptest.NewRequest(http.MethodPost, "/admin/settings", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on update, got %d: %s", w.Code, w.Body.String())
	}

	// Verify in-memory cache updated atomically
	if cache.Get().Guard.ThresholdScore != 0.35 {
		t.Errorf("expected threshold 0.35 in cache, got %v", cache.Get().Guard.ThresholdScore)
	}

	// Verify DuckDB store persisted override
	dbVal, exists, err := store.Get(context.Background(), "guard.threshold_score")
	if err != nil || !exists || dbVal != "0.35" {
		t.Errorf("expected DuckDB override 0.35, got exists=%v, val=%q, err=%v", exists, dbVal, err)
	}

	// Verify GET shows is_overridden = true
	getReq := httptest.NewRequest(http.MethodGet, "/admin/settings", nil)
	getW := httptest.NewRecorder()
	handler.ServeHTTP(getW, getReq)

	var getResp struct {
		Settings []settings.SettingItem `json:"settings"`
	}
	_ = json.Unmarshal(getW.Body.Bytes(), &getResp)
	var found bool
	for _, item := range getResp.Settings {
		if item.Key == "guard.threshold_score" {
			found = true
			if !item.IsOverridden {
				t.Errorf("expected is_overridden=true for mutated setting")
			}
			if item.Value != 0.35 {
				t.Errorf("expected current value 0.35, got %v", item.Value)
			}
		}
	}
	if !found {
		t.Errorf("guard.threshold_score not found in settings list")
	}

	// 2. Reset setting back to default
	resetPayload := []byte(`{"key": "guard.threshold_score"}`)
	resetReq := httptest.NewRequest(http.MethodPost, "/admin/settings/reset", bytes.NewReader(resetPayload))
	resetReq.Header.Set("Content-Type", "application/json")
	resetW := httptest.NewRecorder()
	handler.ServeHTTP(resetW, resetReq)

	if resetW.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on reset, got %d: %s", resetW.Code, resetW.Body.String())
	}

	// Verify in-memory cache reverted to baseline default 0.50
	if cache.Get().Guard.ThresholdScore != 0.50 {
		t.Errorf("expected threshold to revert to default 0.50, got %v", cache.Get().Guard.ThresholdScore)
	}

	// Verify DuckDB row was deleted
	_, exists, _ = store.Get(context.Background(), "guard.threshold_score")
	if exists {
		t.Errorf("expected override row to be deleted from DuckDB after reset")
	}

	// Verify audit logs were captured
	events := logger.GetEvents()
	if len(events) < 2 {
		t.Fatalf("expected at least 2 audit events, got %d", len(events))
	}
	if events[0].Method != "SETTINGS_MUTATE" {
		t.Errorf("expected SETTINGS_MUTATE, got %s", events[0].Method)
	}
	if events[1].Method != "SETTINGS_RESET" {
		t.Errorf("expected SETTINGS_RESET, got %s", events[1].Method)
	}
}

func TestSettingsAPI_ValidationFailClosed(t *testing.T) {
	t.Parallel()

	server, _, _, _ := setupTestAdminSettings(t)
	handler := server.Handler()

	tests := []struct {
		name         string
		payload      string
		expectedCode int
	}{
		{
			name:         "threshold score above maximum (1.5)",
			payload:      `{"key": "guard.threshold_score", "value": 1.5}`,
			expectedCode: http.StatusBadRequest,
		},
		{
			name:         "payload size below minimum (500 bytes)",
			payload:      `{"key": "limits.max_payload_bytes", "value": 500}`,
			expectedCode: http.StatusBadRequest,
		},
		{
			name:         "unknown setting key",
			payload:      `{"key": "system.arbitrary_key", "value": 42}`,
			expectedCode: http.StatusBadRequest,
		},
		{
			name:         "malformed json body",
			payload:      `{invalid_json`,
			expectedCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodPost, "/admin/settings", bytes.NewReader([]byte(tt.payload)))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != tt.expectedCode {
				t.Errorf("expected HTTP %d, got %d: %s", tt.expectedCode, w.Code, w.Body.String())
			}
		})
	}
}

func TestConfigToggle_NoFileWrite(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	originalYAML := `# FaradAiWire Human-Crafted Configuration
# NOTE: DO NOT DELETE THESE COMMENTS
runtime_mode: STANDALONE
listen_port: 8090
admin_port: 8095
filters:
  prefill_block:
    enabled: true
  guard:
    enabled: true
`
	if err := os.WriteFile(configPath, []byte(originalYAML), 0644); err != nil {
		t.Fatalf("failed to write original config: %v", err)
	}

	statBefore, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("failed to stat config before test: %v", err)
	}

	cfg := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
		ConfigPath:  configPath,
	}
	server := NewAdminServer(cfg, func() error { return nil }, func() {})
	handler := server.Handler()

	// Toggle prefill_block to false
	togglePayload := []byte(`{"filter_name": "prefill_block", "enabled": false}`)
	req := httptest.NewRequest(http.MethodPost, "/admin/config/toggle", bytes.NewReader(togglePayload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from toggle, got %d: %s", w.Code, w.Body.String())
	}

	// Verify memory config was updated
	if cfg.Filters.PrefillBlock.Enabled != false {
		t.Errorf("expected memory prefill_block to be false")
	}

	// Check config file on disk: it must be completely untouched!
	fileBytesAfter, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed to read config file after toggle: %v", err)
	}
	if string(fileBytesAfter) != originalYAML {
		t.Fatalf("CRITICAL: config.yaml on disk was modified! Comments or formatting lost!")
	}

	statAfter, _ := os.Stat(configPath)
	if statAfter.ModTime() != statBefore.ModTime() {
		t.Errorf("config.yaml file modification time changed: was %v, now %v", statBefore.ModTime(), statAfter.ModTime())
	}
}

type failingFilterStore struct {
	settings.Store
}

func (f *failingFilterStore) Get(ctx context.Context, key string) (string, bool, error) {
	return "", false, nil
}

func (f *failingFilterStore) Set(ctx context.Context, key string, value string) error {
	return errors.New("simulated duckdb write error")
}

func (f *failingFilterStore) Delete(ctx context.Context, key string) error {
	return nil
}

func TestConfigToggle_PersistsToDuckDBAndUsesReloadConfig(t *testing.T) {
	t.Parallel()

	db, err := sql.Open("duckdb", ":memory:")
	if err != nil {
		t.Fatalf("failed to open duckdb: %v", err)
	}
	store := settings.NewDuckDBStore(db)
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatalf("failed to migrate store: %v", err)
	}

	cfg := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
	}
	cfg.Filters.PrefillBlock.Enabled = true
	cfg.Filters.DLP.Enabled = true

	var diskReloadCalled int
	var inMemoryReloadCalled int

	var server *AdminServer
	server = NewAdminServer(cfg, func() error {
		diskReloadCalled++
		// Simulate disk load that would revert if invoked by toggle
		reloaded := &config.Config{RuntimeMode: config.RuntimeModeStandalone}
		reloaded.Filters.PrefillBlock.Enabled = true
		reloaded.Filters.DLP.Enabled = true
		server.SetConfig(reloaded)
		return nil
	}, func() {})
	server.SetSettingsStore(store)
	server.SetReloadConfigFunc(func(nextCfg *config.Config) error {
		inMemoryReloadCalled++
		server.SetConfig(nextCfg)
		return nil
	})

	handler := server.Handler()

	// Toggle DLP off
	req := httptest.NewRequest(http.MethodPost, "/admin/config/toggle", bytes.NewReader([]byte(`{"filter":"dlp","enabled":false}`)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}
	if diskReloadCalled != 0 {
		t.Errorf("expected disk reloadFunc not to be called on toggle, got %d", diskReloadCalled)
	}
	if inMemoryReloadCalled != 1 {
		t.Errorf("expected in-memory reloadConfigFunc to be called once, got %d", inMemoryReloadCalled)
	}

	// Verify DuckDB persisted filters.dlp = "false"
	val, exists, err := store.Get(context.Background(), "filters.dlp")
	if err != nil || !exists || val != "false" {
		t.Fatalf("expected DuckDB filters.dlp='false', got exists=%v val=%q err=%v", exists, val, err)
	}

	// Verify /admin/status reflects disabled DLP (no snap-back)
	stReq := httptest.NewRequest(http.MethodGet, "/admin/status", nil)
	stRec := httptest.NewRecorder()
	handler.ServeHTTP(stRec, stReq)
	var stResp struct {
		ActiveFilters []string `json:"active_filters"`
	}
	if err := json.Unmarshal(stRec.Body.Bytes(), &stResp); err != nil {
		t.Fatalf("decode status failed: %v", err)
	}
	for _, f := range stResp.ActiveFilters {
		if f == "dlp" {
			t.Errorf("expected 'dlp' to be removed from active_filters, got %v", stResp.ActiveFilters)
		}
	}
}

func TestConfigToggle_StoreErrorFailsClosed(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{RuntimeMode: config.RuntimeModeStandalone}
	cfg.Filters.DLP.Enabled = true

	server := NewAdminServer(cfg, nil, nil)
	server.SetSettingsStore(&failingFilterStore{})

	req := httptest.NewRequest(http.MethodPost, "/admin/config/toggle", bytes.NewReader([]byte(`{"filter":"dlp","enabled":false}`)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 Internal Server Error on store failure, got %d: %s", rec.Code, rec.Body.String())
	}
	if !cfg.Filters.DLP.Enabled {
		t.Error("expected DLP config not to be mutated when persistence fails")
	}
}

func TestConfigToggle_ResetFilterToBaseline(t *testing.T) {
	t.Parallel()

	db, err := sql.Open("duckdb", ":memory:")
	if err != nil {
		t.Fatalf("failed to open duckdb: %v", err)
	}
	store := settings.NewDuckDBStore(db)
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatalf("failed to migrate store: %v", err)
	}

	cfg := &config.Config{RuntimeMode: config.RuntimeModeStandalone}
	cfg.Filters.DLP.Enabled = true

	var server *AdminServer
	var reloadCalled int
	server = NewAdminServer(cfg, func() error {
		reloadCalled++
		// Simulate disk load with dlp=true
		base := &config.Config{RuntimeMode: config.RuntimeModeStandalone}
		base.Filters.DLP.Enabled = true
		server.SetConfig(base)
		return nil
	}, func() {})
	server.SetSettingsStore(store)
	server.SetReloadConfigFunc(func(nextCfg *config.Config) error {
		server.SetConfig(nextCfg)
		return nil
	})
	handler := server.Handler()

	// 1. Toggle DLP off
	tReq := httptest.NewRequest(http.MethodPost, "/admin/config/toggle", bytes.NewReader([]byte(`{"filter":"dlp","enabled":false}`)))
	tReq.Header.Set("Content-Type", "application/json")
	tRec := httptest.NewRecorder()
	handler.ServeHTTP(tRec, tReq)
	if tRec.Code != http.StatusOK {
		t.Fatalf("toggle failed: %d", tRec.Code)
	}

	// 2. Reset filters.dlp via /admin/settings/reset
	rReq := httptest.NewRequest(http.MethodPost, "/admin/settings/reset", bytes.NewReader([]byte(`{"key":"filters.dlp"}`)))
	rReq.Header.Set("Content-Type", "application/json")
	rRec := httptest.NewRecorder()
	handler.ServeHTTP(rRec, rReq)
	if rRec.Code != http.StatusOK {
		t.Fatalf("reset failed: %d: %s", rRec.Code, rRec.Body.String())
	}

	_, exists, _ := store.Get(context.Background(), "filters.dlp")
	if exists {
		t.Error("expected filters.dlp row to be deleted from DuckDB on reset")
	}
	if reloadCalled != 1 {
		t.Errorf("expected reloadFunc to be called once on filter reset, got %d", reloadCalled)
	}
}

func TestStatus_GuardRespectsConfigFlagEvenWhenRunnerWarm(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{RuntimeMode: config.RuntimeModeStandalone}
	cfg.Filters.Guard.Enabled = false

	server := NewAdminServer(cfg, nil, nil)
	server.SetGuardManager(&mockGuardManager{
		status: guard.ProcessStatus{
			Running: true,
			ModelID: "qwen3guard",
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/status", nil)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	var resp struct {
		ActiveFilters []string       `json:"active_filters"`
		Config        map[string]any `json:"config"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode status: %v", err)
	}
	for _, f := range resp.ActiveFilters {
		if f == "guard" {
			t.Errorf("expected guard NOT in active_filters when Filters.Guard.Enabled=false, got %v", resp.ActiveFilters)
		}
	}
	if guardCfg, ok := resp.Config["guard"].(bool); ok && guardCfg {
		t.Error("expected config.guard to reflect false when Filters.Guard.Enabled=false")
	}
}

func TestSettingsAPI_UpdateRejectsFilterKeys(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{RuntimeMode: config.RuntimeModeStandalone}
	server := NewAdminServer(cfg, nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/admin/settings", bytes.NewReader([]byte(`{"key":"filters.dlp","value":false}`)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request when passing filters.* key to /admin/settings, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestConfigToggle_MissingEnabledAndReloadError(t *testing.T) {
	t.Parallel()

	t.Run("MissingEnabledReturns400", func(t *testing.T) {
		t.Parallel()
		cfg := &config.Config{RuntimeMode: config.RuntimeModeStandalone}
		server := NewAdminServer(cfg, nil, nil)

		req := httptest.NewRequest(http.MethodPost, "/admin/config/toggle", bytes.NewReader([]byte(`{"filter":"dlp"}`)))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request when enabled is omitted, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("ReloadFailureReturns500AndRollsBackDuckDB", func(t *testing.T) {
		t.Parallel()
		db, err := sql.Open("duckdb", ":memory:")
		if err != nil {
			t.Fatalf("open duckdb: %v", err)
		}
		defer db.Close()
		store := settings.NewDuckDBStore(db)
		if err := store.Migrate(context.Background()); err != nil {
			t.Fatalf("migrate: %v", err)
		}
		if err := store.Set(context.Background(), "filters.dlp", "true"); err != nil {
			t.Fatalf("seed dlp: %v", err)
		}

		cfg := &config.Config{RuntimeMode: config.RuntimeModeStandalone}
		cfg.Filters.DLP.Enabled = true
		server := NewAdminServer(cfg, nil, nil)
		server.SetSettingsStore(store)
		server.SetReloadConfigFunc(func(*config.Config) error {
			return errors.New("simulated pipeline failure")
		})

		req := httptest.NewRequest(http.MethodPost, "/admin/config/toggle", bytes.NewReader([]byte(`{"filter":"dlp","enabled":false}`)))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 on reload error, got %d: %s", rec.Code, rec.Body.String())
		}
		val, ok, _ := store.Get(context.Background(), "filters.dlp")
		if !ok || val != "true" {
			t.Fatalf("expected DuckDB filters.dlp to roll back to true, got exists=%v val=%q", ok, val)
		}
	})
}

func TestConfigToggle_ConcurrentRequests_RaceFree(t *testing.T) {
	t.Parallel()

	db, err := sql.Open("duckdb", ":memory:")
	if err != nil {
		t.Fatalf("open duckdb: %v", err)
	}
	defer db.Close()
	store := settings.NewDuckDBStore(db)
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	cfg := &config.Config{RuntimeMode: config.RuntimeModeStandalone}
	server := NewAdminServer(cfg, nil, nil)
	server.SetSettingsStore(store)
	server.SetSettingsCache(settings.NewCache(nil))
	server.SetReloadConfigFunc(func(next *config.Config) error {
		server.SetConfig(next)
		return nil
	})

	handler := server.Handler()
	filters := []string{"dlp", "hitl", "guard", "rate_limiting"}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		idx := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			f := filters[idx%len(filters)]
			body := `{"filter":"` + f + `","enabled":true}`
			if idx%2 == 1 {
				body = `{"filter":"` + f + `","enabled":false}`
			}
			tReq := httptest.NewRequest(http.MethodPost, "/admin/config/toggle", strings.NewReader(body))
			tRec := httptest.NewRecorder()
			handler.ServeHTTP(tRec, tReq)
			if tRec.Code != http.StatusOK {
				t.Errorf("concurrent toggle failed: %d %s", tRec.Code, tRec.Body.String())
			}

			sReq := httptest.NewRequest(http.MethodGet, "/admin/status", nil)
			sRec := httptest.NewRecorder()
			handler.ServeHTTP(sRec, sReq)
			if sRec.Code != http.StatusOK {
				t.Errorf("concurrent status failed: %d", sRec.Code)
			}
		}()
	}
	wg.Wait()
}

func TestSettings_ManagedMode_AllowsGET_BlocksMutations(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{RuntimeMode: config.RuntimeModeManaged}
	server := NewAdminServer(cfg, nil, nil)
	server.SetSettingsCache(settings.NewCache(nil))
	handler := server.Handler()

	getReq := httptest.NewRequest(http.MethodGet, "/admin/settings", nil)
	getRec := httptest.NewRecorder()
	handler.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("expected GET /admin/settings to succeed in MANAGED mode, got %d: %s", getRec.Code, getRec.Body.String())
	}

	for _, method := range []string{http.MethodPost, http.MethodPut} {
		mutReq := httptest.NewRequest(method, "/admin/settings", strings.NewReader(`{"key":"timeouts.probe_timeout_sec","value":12}`))
		mutReq.Header.Set("Content-Type", "application/json")
		mutRec := httptest.NewRecorder()
		handler.ServeHTTP(mutRec, mutReq)
		if mutRec.Code != http.StatusForbidden {
			t.Fatalf("expected %s /admin/settings to return 403 in MANAGED mode, got %d", method, mutRec.Code)
		}
	}
}

func TestSettings_LegacyValidationAndProbeTimeoutSec(t *testing.T) {
	t.Parallel()

	db, err := sql.Open("duckdb", ":memory:")
	if err != nil {
		t.Fatalf("open duckdb: %v", err)
	}
	defer db.Close()
	store := settings.NewDuckDBStore(db)
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	cfg := &config.Config{RuntimeMode: config.RuntimeModeStandalone, PollIntervalSeconds: 30}
	server := NewAdminServer(cfg, nil, nil)
	server.SetSettingsStore(store)
	cache := settings.NewCache(settings.DefaultOperationalSettings())
	server.SetSettingsCache(cache)
	server.SetReloadConfigFunc(func(next *config.Config) error {
		server.SetConfig(next)
		return nil
	})
	handler := server.Handler()

	// Invalid poll_interval_seconds returns 400 without mutating cfg
	badReq := httptest.NewRequest(http.MethodPost, "/admin/settings", strings.NewReader(`{"poll_interval_seconds":0}`))
	badRec := httptest.NewRecorder()
	handler.ServeHTTP(badRec, badReq)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid poll_interval_seconds, got %d", badRec.Code)
	}

	// Valid PUT updates timeouts.probe_timeout_sec + poll_interval_seconds cleanly
	putReq := httptest.NewRequest(http.MethodPut, "/admin/settings", strings.NewReader(`{"timeouts.probe_timeout_sec":12,"poll_interval_seconds":45}`))
	putRec := httptest.NewRecorder()
	handler.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on PUT /admin/settings, got %d: %s", putRec.Code, putRec.Body.String())
	}
	if got := server.probeTimeout(); got != 12*time.Second {
		t.Fatalf("expected probeTimeout=12s, got %v", got)
	}
}

func TestAgents_MaskSecrets_HydrateEnvOnPUT_AndArchivePerms(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	agentsDir := filepath.Join(tmpDir, "agents")
	protosDir := filepath.Join(tmpDir, "protocols")
	repo := agent.NewFSRepository(agentsDir)
	pStore, err := protocol.NewFSStore(protosDir)
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}

	rawToken := "tok_live_supersecret_9988"
	rawEnvSecret := "sk-live-secret-abcdef123456"
	rawHeader := "Bearer hdr_secret_xyz987"
	initialCfg := &agent.RouteConfig{
		AgentName:   "secret-agent",
		RoutingMode: "aggregated",
		Protocols: []agent.ProtocolConfig{{
			ID:        "my-mcp",
			Name:      "my-mcp",
			Type:      "http",
			AuthToken: rawToken,
			Env:       []string{"OPENAI_API_KEY=" + rawEnvSecret, "LOG_LEVEL=info"},
			Headers:   map[string]string{"Authorization": rawHeader},
		}},
	}
	if err := repo.SaveAgentConfig("secret-agent", initialCfg); err != nil {
		t.Fatalf("SaveAgentConfig: %v", err)
	}

	cfg := &config.Config{
		RuntimeMode:  config.RuntimeModeStandalone,
		AgentsDir:    agentsDir,
		ProtocolsDir: protosDir,
	}
	server := NewAdminServer(cfg, nil, nil)
	server.SetAgentRepository(repo)
	server.SetProtocolStore(pStore)
	handler := server.Handler()

	// 1. GET masks secrets in response while keeping disk unmasked
	getReq := httptest.NewRequest(http.MethodGet, "/admin/agents/secret-agent", nil)
	getRec := httptest.NewRecorder()
	handler.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET /admin/agents/secret-agent failed: %d %s", getRec.Code, getRec.Body.String())
	}
	bodyStr := getRec.Body.String()
	for _, leaked := range []string{rawToken, rawEnvSecret, rawHeader} {
		if strings.Contains(bodyStr, leaked) {
			t.Fatalf("raw secret %q leaked in GET /admin/agents response", leaked)
		}
	}
	if !strings.Contains(bodyStr, "••••••") {
		t.Fatalf("expected masked placeholders in GET response, got: %s", bodyStr)
	}

	// 2. PUT with masked placeholders hydrates existing unmasked secrets on disk and archives with 0700/0600
	var getResp struct {
		Config *agent.RouteConfig `json:"config"`
	}
	if err := json.Unmarshal(getRec.Body.Bytes(), &getResp); err != nil {
		t.Fatalf("unmarshal GET: %v", err)
	}
	putPayload, _ := json.Marshal(map[string]any{
		"description":  "updated safely",
		"routing_mode": "aggregated",
		"protocols":    getResp.Config.Protocols,
	})
	putReq := httptest.NewRequest(http.MethodPut, "/admin/agents/secret-agent", bytes.NewReader(putPayload))
	putRec := httptest.NewRecorder()
	handler.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("PUT /admin/agents/secret-agent failed: %d %s", putRec.Code, putRec.Body.String())
	}
	if strings.Contains(putRec.Body.String(), rawEnvSecret) || strings.Contains(putRec.Body.String(), rawToken) {
		t.Fatalf("raw secret leaked in PUT response: %s", putRec.Body.String())
	}

	onDisk, err := repo.GetAgentConfig("secret-agent")
	if err != nil {
		t.Fatalf("GetAgentConfig after PUT: %v", err)
	}
	if len(onDisk.Protocols) != 1 || onDisk.Protocols[0].AuthToken != rawToken {
		t.Fatalf("expected AuthToken hydrated on disk, got %+v", onDisk.Protocols)
	}
	if onDisk.Protocols[0].Env[0] != "OPENAI_API_KEY="+rawEnvSecret {
		t.Fatalf("expected masked Env hydrated on disk, got %v", onDisk.Protocols[0].Env)
	}
	if onDisk.Protocols[0].Headers["Authorization"] != rawHeader {
		t.Fatalf("expected masked Header hydrated on disk, got %v", onDisk.Protocols[0].Headers)
	}

	// 3. Verify ArchiveAgentCurrent permissions are 0700 / 0600
	archives, err := repo.ListAgentArchives("secret-agent")
	if err != nil || len(archives) == 0 {
		t.Fatalf("expected archive snapshot after PUT, got archives=%v err=%v", archives, err)
	}
	archiveDir := filepath.Join(agentsDir, "secret-agent", "archive", archives[0])
	dirInfo, err := os.Stat(archiveDir)
	if err != nil {
		t.Fatalf("stat archive dir: %v", err)
	}
	if dirInfo.Mode().Perm()&0077 != 0 {
		t.Fatalf("expected archive dir perms 0700 (no group/other), got %o", dirInfo.Mode().Perm())
	}
	cfgInfo, err := os.Stat(filepath.Join(archiveDir, "config.json"))
	if err != nil {
		t.Fatalf("stat archive config.json: %v", err)
	}
	if cfgInfo.Mode().Perm()&0077 != 0 {
		t.Fatalf("expected archive config.json perms 0600 (no group/other), got %o", cfgInfo.Mode().Perm())
	}
}

func BenchmarkHandleStatus(b *testing.B) {
	cfg := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
		ListenHost:  "127.0.0.1",
		ListenPort:  8090,
		AdminPort:   8095,
	}
	server := NewAdminServer(cfg, nil, nil)
	handler := server.Handler()
	req := httptest.NewRequest(http.MethodGet, "/admin/status", nil)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("expected HTTP 200, got %d", rec.Code)
		}
	}
}

func TestSettingsAPI_LargeIntNoScientificNotation_And_SafeHTTPClientSync(t *testing.T) {
	t.Parallel()

	server, store, cache, _ := setupTestAdminSettings(t)
	handler := server.Handler()

	// 1. JSON float64 >= 1_000_000 (10 MiB) must persist cleanly as base-10 integer string
	payload := []byte(`{"key": "limits.max_payload_bytes", "value": 10485760}`)
	req := httptest.NewRequest(http.MethodPost, "/admin/settings", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for 10485760 integer setting, got %d: %s", w.Code, w.Body.String())
	}

	dbVal, exists, err := store.Get(context.Background(), "limits.max_payload_bytes")
	if err != nil || !exists || dbVal != "10485760" {
		t.Fatalf("expected DuckDB string '10485760', got val=%q exists=%v err=%v", dbVal, exists, err)
	}
	if cache.Get().Limits.MaxPayloadBytes != 10485760 {
		t.Fatalf("expected cache MaxPayloadBytes=10485760, got %d", cache.Get().Limits.MaxPayloadBytes)
	}

	// 2. Updating timeouts.probe_timeout_sec > 10s updates SafeHTTPClient timeout dynamically
	tPayload := []byte(`{"key": "timeouts.probe_timeout_sec", "value": 15}`)
	tReq := httptest.NewRequest(http.MethodPost, "/admin/settings", bytes.NewReader(tPayload))
	tReq.Header.Set("Content-Type", "application/json")
	tW := httptest.NewRecorder()
	handler.ServeHTTP(tW, tReq)

	if tW.Code != http.StatusOK {
		t.Fatalf("expected 200 OK updating probe_timeout_sec, got %d: %s", tW.Code, tW.Body.String())
	}

	c1 := server.SafeHTTPClient()
	c2 := server.SafeHTTPClient()
	if c1 == nil || c1.Timeout != 15*time.Second {
		t.Fatalf("expected SafeHTTPClient timeout 15s, got %v", c1)
	}
	if c1 != c2 {
		t.Fatal("expected SafeHTTPClient pointer reuse while timeout unchanged")
	}
}

func TestSettingsResetAndToggle_RollbackDuckDBOnReloadFailure(t *testing.T) {
	t.Parallel()

	// 1. Toggle without prior DuckDB override deletes the newly inserted row on reload failure
	t.Run("ToggleDeletesNewRowOnReloadError", func(t *testing.T) {
		t.Parallel()
		db, err := sql.Open("duckdb", ":memory:")
		if err != nil {
			t.Fatalf("open duckdb: %v", err)
		}
		defer db.Close()
		store := settings.NewDuckDBStore(db)
		if err := store.Migrate(context.Background()); err != nil {
			t.Fatalf("migrate: %v", err)
		}

		cfg := &config.Config{RuntimeMode: config.RuntimeModeStandalone}
		cfg.Filters.DLP.Enabled = true
		server := NewAdminServer(cfg, nil, nil)
		server.SetSettingsStore(store)
		server.SetReloadConfigFunc(func(*config.Config) error {
			return errors.New("reload failed")
		})

		req := httptest.NewRequest(http.MethodPost, "/admin/config/toggle", bytes.NewReader([]byte(`{"filter":"dlp","enabled":false}`)))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 on reload error, got %d: %s", rec.Code, rec.Body.String())
		}
		if _, ok, _ := store.Get(context.Background(), "filters.dlp"); ok {
			t.Fatal("expected newly written filters.dlp row to be deleted on reload failure")
		}
	})

	// 2. Settings reset restores previous DuckDB override if reload fails
	t.Run("SettingsResetRestoresOverrideOnReloadError", func(t *testing.T) {
		t.Parallel()
		db, err := sql.Open("duckdb", ":memory:")
		if err != nil {
			t.Fatalf("open duckdb: %v", err)
		}
		defer db.Close()
		store := settings.NewDuckDBStore(db)
		if err := store.Migrate(context.Background()); err != nil {
			t.Fatalf("migrate: %v", err)
		}
		if err := store.Set(context.Background(), "filters.dlp", "false"); err != nil {
			t.Fatalf("seed dlp: %v", err)
		}

		cfg := &config.Config{RuntimeMode: config.RuntimeModeStandalone}
		cfg.Filters.DLP.Enabled = false
		server := NewAdminServer(cfg, nil, nil)
		server.SetSettingsStore(store)
		server.SetReloadConfigFunc(func(*config.Config) error {
			return errors.New("reload failed")
		})

		req := httptest.NewRequest(http.MethodPost, "/admin/settings/reset", bytes.NewReader([]byte(`{"key":"filters.dlp"}`)))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 on reset reload failure, got %d: %s", rec.Code, rec.Body.String())
		}
		val, ok, _ := store.Get(context.Background(), "filters.dlp")
		if !ok || val != "false" {
			t.Fatalf("expected DuckDB filters.dlp='false' restored after reset failure, got exists=%v val=%q", ok, val)
		}
	})
}
