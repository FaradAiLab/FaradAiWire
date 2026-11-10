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
	"sync"
	"testing"

	_ "github.com/marcboeker/go-duckdb"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/internal/guard"
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

func (f *failingFilterStore) Set(ctx context.Context, key string, value string) error {
	return errors.New("simulated duckdb write error")
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
		ActiveFilters []string        `json:"active_filters"`
		Config        map[string]any  `json:"config"`
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
