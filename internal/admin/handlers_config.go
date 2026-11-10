package admin

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/internal/settings"
)

func (a *AdminServer) handleClearSchemas(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if a.schemaClear != nil {
		a.schemaClear()
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Pinned schema baselines successfully cleared",
	})
}

func (a *AdminServer) handleMCPTools(w http.ResponseWriter, r *http.Request) {
	schemasDir := a.cfg.Filters.SchemaValidation.SchemasDir
	if schemasDir == "" {
		schemasDir = "./schemas/"
	}
	mcpToolsPath := filepath.Join(schemasDir, "mcp_tools.json")

	content, err := os.ReadFile(mcpToolsPath)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(content)
}

func (a *AdminServer) handleConfigToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req struct {
		FilterName string `json:"filter_name"`
		Filter     string `json:"filter"`
		Enabled    bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if req.FilterName == "" && req.Filter != "" {
		req.FilterName = req.Filter
	}

	isFilter := settings.IsSupportedFilterName(req.FilterName)
	isLegacyToggle := req.FilterName == "auto_sync_mcp" || req.FilterName == "auto_update_policies"
	if !isFilter && !isLegacyToggle {
		http.Error(w, "Unknown setting/filter: "+req.FilterName, http.StatusBadRequest)
		return
	}

	a.mu.RLock()
	sStore := a.settingsStore
	a.mu.RUnlock()

	// Persist filter enablement to DuckDB system_settings sparse overlay (ADR-0053 / ADR-0054)
	// before mutating runtime configuration so persistence failures fail closed.
	if isFilter && sStore != nil {
		if err := sStore.Set(r.Context(), settings.FilterKeyPrefix+req.FilterName, strconv.FormatBool(req.Enabled)); err != nil {
			slog.ErrorContext(r.Context(), "Failed to persist filter toggle to DuckDB", slog.String("filter", req.FilterName), slog.String("error", err.Error()))
			http.Error(w, fmt.Sprintf("Failed to persist filter toggle %q", req.FilterName), http.StatusInternalServerError)
			return
		}
	}

	nextCfg := a.cloneAndMutateConfig(func(c *config.Config) {
		if isFilter {
			settings.ApplyFilterToggleToConfig(c, req.FilterName, req.Enabled)
		} else if req.FilterName == "auto_sync_mcp" {
			c.AutoSyncMCP = req.Enabled
		} else if req.FilterName == "auto_update_policies" {
			c.AutoUpdatePolicies = req.Enabled
		}
	})

	// Trigger runtime reload in memory without touching config.yaml on disk (ADR-0053 / ADR-0054)
	if err := a.applyConfigReload(nextCfg); err != nil {
		slog.ErrorContext(r.Context(), "Failed to reload after config toggle", slog.String("filter", req.FilterName), slog.String("error", err.Error()))
	}

	// Emit configuration audit trail event (Task 7)
	a.logAuditEvent(&filter.AuditEvent{
		Timestamp:  time.Now(),
		Method:     "CONFIG_TOGGLE",
		ToolName:   req.FilterName,
		FilterName: "admin_config",
		Decision:   "ALLOWED",
		Message:    fmt.Sprintf("Filter %s toggled to %v", req.FilterName, req.Enabled),
		User:       a.extractUserContext(r),
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "success",
		"filter":      req.FilterName,
		"filter_name": req.FilterName,
		"enabled":     req.Enabled,
		"message":     fmt.Sprintf("Setting '%s' successfully set to %v", req.FilterName, req.Enabled),
	})
}

// handleSettings handles self-describing metadata retrieval and validated updates for operational settings.
func (a *AdminServer) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.getSettings(w, r)
	case http.MethodPost, http.MethodPut:
		a.updateSettings(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// getSettings returns self-describing operational settings metadata, active values, and override status.
func (a *AdminServer) getSettings(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	sStore := a.settingsStore
	sCache := a.settingsCache
	var pollInterval int
	var autoSyncMCP, autoUpdatePolicies bool
	if a.cfg != nil {
		pollInterval = a.cfg.PollIntervalSeconds
		autoSyncMCP = a.cfg.AutoSyncMCP
		autoUpdatePolicies = a.cfg.AutoUpdatePolicies
	}
	a.mu.RUnlock()

	var overrides map[string]string
	if sStore != nil {
		var err error
		overrides, err = sStore.GetAll(r.Context())
		if err != nil {
			slog.WarnContext(r.Context(), "Failed to read settings overrides from DuckDB", slog.String("error", err.Error()))
		}
	}
	if overrides == nil {
		overrides = make(map[string]string)
	}

	var activeSettings *settings.OperationalSettings
	if sCache != nil {
		activeSettings = sCache.Get()
	}
	if activeSettings == nil {
		activeSettings = settings.DefaultOperationalSettings()
	}

	allMeta := settings.GetAllMetadata()
	items := make([]settings.SettingItem, 0, len(allMeta))
	categorySet := make(map[string]struct{})

	for _, meta := range allMeta {
		categorySet[meta.Category] = struct{}{}
		val, _ := settings.ExtractSetting(activeSettings, meta.Key)
		_, isOverridden := overrides[meta.Key]

		items = append(items, settings.SettingItem{
			SettingMeta:  meta,
			Value:        val,
			IsOverridden: isOverridden,
		})
	}

	categories := make([]string, 0, len(categorySet))
	for cat := range categorySet {
		categories = append(categories, cat)
	}
	sort.Strings(categories)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":                "success",
		"categories":            categories,
		"settings":              items,
		"poll_interval_seconds": pollInterval,
		"auto_sync_mcp":         autoSyncMCP,
		"auto_update_policies":  autoUpdatePolicies,
	})
}

// updateSettings validates inputs against the registry and persists overrides into DuckDB and cache.
func (a *AdminServer) updateSettings(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var payload map[string]any
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	a.mu.Lock()
	sStore := a.settingsStore
	sCache := a.settingsCache
	a.mu.Unlock()

	toUpdate := make(map[string]any)

	// Format A: Nested map `{"settings": {"guard.threshold_score": 0.40}}`
	if rawSettings, ok := payload["settings"].(map[string]any); ok {
		for k, v := range rawSettings {
			toUpdate[k] = v
		}
	} else if key, ok := payload["key"].(string); ok && key != "" {
		// Format B: Single key-value `{"key": "guard.threshold_score", "value": 0.40}`
		toUpdate[key] = payload["value"]
	}

	// Format C: Top-level registered operational keys
	for k, v := range payload {
		if _, exists := settings.Registry[k]; exists {
			toUpdate[k] = v
		}
	}

	// Support legacy fields
	hasLegacy := false
	if poll, ok := payload["poll_interval_seconds"].(float64); ok && int(poll) > 0 {
		a.mu.Lock()
		if a.cfg != nil {
			a.cfg.PollIntervalSeconds = int(poll)
		}
		a.mu.Unlock()
		hasLegacy = true
	}
	if syncMCP, ok := payload["auto_sync_mcp"].(bool); ok {
		a.mu.Lock()
		if a.cfg != nil {
			a.cfg.AutoSyncMCP = syncMCP
		}
		a.mu.Unlock()
		hasLegacy = true
	}
	if updatePol, ok := payload["auto_update_policies"].(bool); ok {
		a.mu.Lock()
		if a.cfg != nil {
			a.cfg.AutoUpdatePolicies = updatePol
		}
		a.mu.Unlock()
		hasLegacy = true
	}

	if len(toUpdate) == 0 && !hasLegacy {
		http.Error(w, "No valid setting keys found in request payload", http.StatusBadRequest)
		return
	}

	// Fail-closed validation against registry schema and bounds
	for k, v := range toUpdate {
		if err := settings.Validate(k, v); err != nil {
			http.Error(w, fmt.Sprintf("Validation failed for %q: %v", k, err), http.StatusBadRequest)
			return
		}
	}

	ctx := r.Context()
	var currentSettings *settings.OperationalSettings
	if sCache != nil {
		currentSettings = sCache.Get().Clone()
	} else {
		currentSettings = settings.DefaultOperationalSettings()
	}

	for k, v := range toUpdate {
		strVal := fmt.Sprintf("%v", v)
		if sStore != nil {
			if err := sStore.Set(ctx, k, strVal); err != nil {
				slog.ErrorContext(ctx, "Failed to persist setting to DuckDB", slog.String("key", k), slog.String("error", err.Error()))
				http.Error(w, fmt.Sprintf("Database error updating %q: %v", k, err), http.StatusInternalServerError)
				return
			}
		}

		oldVal, _ := settings.ExtractSetting(currentSettings, k)
		_ = settings.ApplySetting(currentSettings, k, v)

		// Emit Audit Event (Task 7)
		a.logAuditEvent(&filter.AuditEvent{
			Timestamp:  time.Now(),
			Method:     "SETTINGS_MUTATE",
			ToolName:   k,
			FilterName: "admin_settings",
			Decision:   "ALLOWED",
			Message:    fmt.Sprintf("Setting %q updated from %v to %v", k, oldVal, v),
			User:       a.extractUserContext(r),
		})
	}

	if sCache != nil {
		sCache.Update(currentSettings)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":   "success",
		"message":  "Settings updated successfully",
		"updated":  toUpdate,
		"settings": currentSettings,
	})
}

// handleSettingsReset removes an override from DuckDB and reverts to the config.yaml baseline default.
func (a *AdminServer) handleSettingsReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.Key == "" {
		http.Error(w, "Setting key is required", http.StatusBadRequest)
		return
	}

	meta, exists := settings.LookupMeta(req.Key)
	if !exists {
		http.Error(w, fmt.Sprintf("Unknown setting key: %q", req.Key), http.StatusBadRequest)
		return
	}

	a.mu.Lock()
	sStore := a.settingsStore
	sCache := a.settingsCache
	cfg := a.cfg
	cfgProv := a.cfgProvider
	reloadFn := a.reloadFunc
	a.mu.Unlock()

	ctx := r.Context()
	if sStore != nil {
		if err := sStore.Delete(ctx, req.Key); err != nil {
			slog.ErrorContext(ctx, "Failed to delete setting override from DuckDB", slog.String("key", req.Key), slog.String("error", err.Error()))
			http.Error(w, fmt.Sprintf("Failed to reset setting %q", req.Key), http.StatusInternalServerError)
			return
		}
	}

	if settings.IsFilterKey(req.Key) {
		if reloadFn != nil {
			if err := reloadFn(); err != nil {
				slog.ErrorContext(ctx, "Failed to reload baseline config after filter reset", slog.String("key", req.Key), slog.String("error", err.Error()))
			}
		} else if cfg != nil {
			filterName := req.Key[len(settings.FilterKeyPrefix):]
			baselineVal, _ := meta.DefaultVal.(bool)
			if cfgProv != nil {
				if baseCfg, err := cfgProv.Load(); err == nil {
					if v, ok := settings.ExtractFilterEnabled(baseCfg, filterName); ok {
						baselineVal = v
					}
				}
			}
			nextCfg := a.cloneAndMutateConfig(func(c *config.Config) {
				settings.ApplyFilterToggleToConfig(c, filterName, baselineVal)
			})
			if err := a.applyConfigReload(nextCfg); err != nil {
				slog.ErrorContext(ctx, "Failed to apply fallback filter reset", slog.String("key", req.Key), slog.String("error", err.Error()))
			}
		}
	} else {
		// Recompute effective operational settings from YAML baseline + remaining DuckDB overrides
		var overrides map[string]string
		if sStore != nil {
			overrides, _ = sStore.GetAll(ctx)
		}
		effective := settings.ResolveEffectiveSettings(cfg, overrides)
		if sCache != nil {
			sCache.Update(effective)
		}
	}

	// Emit Audit Event (Task 7)
	a.logAuditEvent(&filter.AuditEvent{
		Timestamp:  time.Now(),
		Method:     "SETTINGS_RESET",
		ToolName:   req.Key,
		FilterName: "admin_settings",
		Decision:   "ALLOWED",
		Message:    fmt.Sprintf("Setting %q reset to baseline default", req.Key),
		User:       a.extractUserContext(r),
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":  "success",
		"message": fmt.Sprintf("Setting %q reset to baseline default successfully", req.Key),
		"key":     req.Key,
	})
}

// extractUserContext parses caller provenance headers or falls back to admin defaults.
func (a *AdminServer) extractUserContext(r *http.Request) *filter.UserContext {
	role := r.Header.Get("X-User-Role")
	if role == "" {
		role = "admin"
	}
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "local-operator"
	}

	return &filter.UserContext{
		Role:      role,
		UserID:    userID,
		AgentName: "admin-console",
	}
}

// logAuditEvent delivers an AuditEvent to the DuckDB telemetry engine and event broker.
func (a *AdminServer) logAuditEvent(event *filter.AuditEvent) {
	if event == nil {
		return
	}
	a.mu.RLock()
	te := a.telemetryEngine
	eb := a.eventBroker
	a.mu.RUnlock()

	type eventLogger interface {
		LogEvent(event *filter.AuditEvent)
	}

	if el, ok := te.(eventLogger); ok && el != nil {
		el.LogEvent(event)
	}
	if el, ok := eb.(eventLogger); ok && el != nil {
		el.LogEvent(event)
	}
}

// handleReload triggers an atomic hot-reload of configuration and filter pipeline.
func (a *AdminServer) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	}

	if a.reloadFunc != nil {
		if err := a.reloadFunc(); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "error",
				"message": "Reload failed: " + err.Error(),
			})
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Gateway successfully reloaded",
	})
}
