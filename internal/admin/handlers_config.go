package admin

import (
	"context"
	"encoding/json"
	"errors"
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
	a.mu.RLock()
	var schemasDir string
	if a.cfg != nil {
		schemasDir = a.cfg.Filters.SchemaValidation.SchemasDir
	}
	a.mu.RUnlock()
	if schemasDir == "" {
		schemasDir = filepath.Join(config.DefaultFaradAiWireDir(), "schemas")
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
		Enabled    *bool  `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if req.FilterName == "" && req.Filter != "" {
		req.FilterName = req.Filter
	}
	if req.Enabled == nil {
		http.Error(w, "Missing required boolean field: enabled", http.StatusBadRequest)
		return
	}
	enabled := *req.Enabled

	isFilter := settings.IsSupportedFilterName(req.FilterName)
	isLegacyToggle := req.FilterName == "auto_sync_mcp" || req.FilterName == "auto_update_policies"
	if !isFilter && !isLegacyToggle {
		http.Error(w, "Unknown setting/filter: "+req.FilterName, http.StatusBadRequest)
		return
	}

	a.configMutMu.Lock()
	defer a.configMutMu.Unlock()

	a.mu.RLock()
	sStore := a.settingsStore
	a.mu.RUnlock()

	filterKey := settings.FilterKeyPrefix + req.FilterName
	ctx := r.Context()

	var (
		prevOverride string
		hadOverride  bool
	)
	if isFilter && sStore != nil {
		var getErr error
		prevOverride, hadOverride, getErr = sStore.Get(ctx, filterKey)
		if getErr != nil {
			slog.ErrorContext(ctx, "Failed to read prior filter toggle from DuckDB", slog.String("filter", req.FilterName), slog.String("error", getErr.Error()))
			http.Error(w, fmt.Sprintf("Failed to read current state for filter %q", req.FilterName), http.StatusInternalServerError)
			return
		}
		if err := sStore.Set(ctx, filterKey, strconv.FormatBool(enabled)); err != nil {
			slog.ErrorContext(ctx, "Failed to persist filter toggle to DuckDB", slog.String("filter", req.FilterName), slog.String("error", err.Error()))
			http.Error(w, fmt.Sprintf("Failed to persist filter toggle %q", req.FilterName), http.StatusInternalServerError)
			return
		}
	}

	nextCfg := a.cloneAndMutateConfig(func(c *config.Config) {
		if isFilter {
			settings.ApplyFilterToggleToConfig(c, req.FilterName, enabled)
		} else if req.FilterName == "auto_sync_mcp" {
			c.AutoSyncMCP = enabled
		} else if req.FilterName == "auto_update_policies" {
			c.AutoUpdatePolicies = enabled
		}
	})

	// Trigger runtime reload in memory without touching config.yaml on disk (ADR-0053 / ADR-0054)
	if err := a.applyConfigReload(nextCfg); err != nil {
		slog.ErrorContext(ctx, "Failed to reload after config toggle", slog.String("filter", req.FilterName), slog.String("error", err.Error()))
		if isFilter && sStore != nil {
			rbCtx, rbCancel := context.WithTimeout(context.Background(), 3*time.Second)
			var rbErr error
			if hadOverride {
				rbErr = sStore.Set(rbCtx, filterKey, prevOverride)
			} else {
				rbErr = sStore.Delete(rbCtx, filterKey)
			}
			rbCancel()
			if rbErr != nil {
				slog.ErrorContext(ctx, "Failed to roll back DuckDB filter override after reload error", slog.String("key", filterKey), slog.String("error", rbErr.Error()))
			}
		}
		http.Error(w, fmt.Sprintf("Failed to reload configuration after toggling %q: %v", req.FilterName, err), http.StatusInternalServerError)
		return
	}

	// Emit configuration audit trail event (Task 7)
	a.logAuditEvent(&filter.AuditEvent{
		Timestamp:  time.Now(),
		Method:     "CONFIG_TOGGLE",
		ToolName:   req.FilterName,
		FilterName: "admin_config",
		Decision:   "ALLOWED",
		Message:    fmt.Sprintf("Filter %s toggled to %v", req.FilterName, enabled),
		User:       a.extractUserContext(r),
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "success",
		"filter":      req.FilterName,
		"filter_name": req.FilterName,
		"enabled":     enabled,
		"message":     fmt.Sprintf("Setting '%s' successfully set to %v", req.FilterName, enabled),
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

	a.configMutMu.Lock()
	defer a.configMutMu.Unlock()

	a.mu.RLock()
	sStore := a.settingsStore
	sCache := a.settingsCache
	a.mu.RUnlock()

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

	// Validate legacy fields upfront before mutating DuckDB or runtime config.
	var (
		hasLegacy        bool
		setPollInterval  bool
		pollIntervalVal  int
		setAutoSyncMCP   bool
		autoSyncMCPVal   bool
		setAutoUpdatePol bool
		autoUpdatePolVal bool
	)
	if rawPoll, present := payload["poll_interval_seconds"]; present {
		pollFloat, ok := rawPoll.(float64)
		pollInt := int(pollFloat)
		if !ok || float64(pollInt) != pollFloat || pollInt < 1 || pollInt > 86400 {
			http.Error(w, "Invalid poll_interval_seconds: must be an integer between 1 and 86400", http.StatusBadRequest)
			return
		}
		setPollInterval = true
		pollIntervalVal = pollInt
		hasLegacy = true
	}
	if rawSync, present := payload["auto_sync_mcp"]; present {
		b, ok := rawSync.(bool)
		if !ok {
			http.Error(w, "Invalid auto_sync_mcp: must be a boolean", http.StatusBadRequest)
			return
		}
		setAutoSyncMCP = true
		autoSyncMCPVal = b
		hasLegacy = true
	}
	if rawUpdatePol, present := payload["auto_update_policies"]; present {
		b, ok := rawUpdatePol.(bool)
		if !ok {
			http.Error(w, "Invalid auto_update_policies: must be a boolean", http.StatusBadRequest)
			return
		}
		setAutoUpdatePol = true
		autoUpdatePolVal = b
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

	keys := make([]string, 0, len(toUpdate))
	for k := range toUpdate {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var prevOverrides map[string]string
	if sStore != nil && len(keys) > 0 {
		var getErr error
		prevOverrides, getErr = sStore.GetAll(ctx)
		if getErr != nil {
			slog.ErrorContext(ctx, "Failed to read prior settings from DuckDB", slog.String("error", getErr.Error()))
			http.Error(w, fmt.Sprintf("Database error reading current settings: %v", getErr), http.StatusInternalServerError)
			return
		}
	}

	appliedKeys := make([]string, 0, len(keys))
	rollbackPersisted := func() {
		rollbackDuckDBSettings(ctx, sStore, appliedKeys, prevOverrides)
	}

	type pendingAudit struct {
		key    string
		oldVal any
		newVal any
	}
	audits := make([]pendingAudit, 0, len(keys))

	for _, k := range keys {
		v := toUpdate[k]
		strVal := formatSettingString(k, v)
		if sStore != nil {
			if err := sStore.Set(ctx, k, strVal); err != nil {
				slog.ErrorContext(ctx, "Failed to persist setting to DuckDB", slog.String("key", k), slog.String("error", err.Error()))
				rollbackPersisted()
				http.Error(w, fmt.Sprintf("Database error updating %q: %v", k, err), http.StatusInternalServerError)
				return
			}
			appliedKeys = append(appliedKeys, k)
		}

		oldVal, _ := settings.ExtractSetting(currentSettings, k)
		_ = settings.ApplySetting(currentSettings, k, v)
		audits = append(audits, pendingAudit{key: k, oldVal: oldVal, newVal: v})
	}

	if hasLegacy {
		nextCfg := a.cloneAndMutateConfig(func(c *config.Config) {
			if setPollInterval {
				c.PollIntervalSeconds = pollIntervalVal
			}
			if setAutoSyncMCP {
				c.AutoSyncMCP = autoSyncMCPVal
			}
			if setAutoUpdatePol {
				c.AutoUpdatePolicies = autoUpdatePolVal
			}
		})
		if setPollInterval {
			toUpdate["poll_interval_seconds"] = pollIntervalVal
		}
		if setAutoSyncMCP {
			toUpdate["auto_sync_mcp"] = autoSyncMCPVal
		}
		if setAutoUpdatePol {
			toUpdate["auto_update_policies"] = autoUpdatePolVal
		}
		if err := a.applyConfigReload(nextCfg); err != nil {
			slog.ErrorContext(ctx, "Failed to reload config after legacy settings update", slog.String("error", err.Error()))
			rollbackPersisted()
			http.Error(w, fmt.Sprintf("Failed to reload configuration after settings update: %v", err), http.StatusInternalServerError)
			return
		}
	}

	for _, aEv := range audits {
		a.logAuditEvent(&filter.AuditEvent{
			Timestamp:  time.Now(),
			Method:     "SETTINGS_MUTATE",
			ToolName:   aEv.key,
			FilterName: "admin_settings",
			Decision:   "ALLOWED",
			Message:    fmt.Sprintf("Setting %q updated from %v to %v", aEv.key, aEv.oldVal, aEv.newVal),
			User:       a.extractUserContext(r),
		})
	}

	if sCache != nil {
		sCache.Update(currentSettings)
	}
	if _, timeoutUpdated := toUpdate["timeouts.probe_timeout_sec"]; timeoutUpdated {
		a.invalidateSafeHTTPClient()
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":   "success",
		"message":  "Settings updated successfully",
		"updated":  toUpdate,
		"settings": currentSettings,
	})
}

func formatSettingString(key string, val any) string {
	meta, exists := settings.LookupMeta(key)
	if !exists {
		return fmt.Sprintf("%v", val)
	}
	switch meta.Type {
	case settings.TypeInt:
		switch v := val.(type) {
		case int:
			return strconv.FormatInt(int64(v), 10)
		case int64:
			return strconv.FormatInt(v, 10)
		case float64:
			return strconv.FormatInt(int64(v), 10)
		case float32:
			return strconv.FormatInt(int64(v), 10)
		}
	case settings.TypeFloat:
		switch v := val.(type) {
		case float64:
			return strconv.FormatFloat(v, 'f', -1, 64)
		case float32:
			return strconv.FormatFloat(float64(v), 'f', -1, 32)
		case int:
			return strconv.FormatInt(int64(v), 10)
		case int64:
			return strconv.FormatInt(v, 10)
		}
	case settings.TypeBool:
		if b, ok := val.(bool); ok {
			return strconv.FormatBool(b)
		}
	}
	return fmt.Sprintf("%v", val)
}

func rollbackDuckDBSettings(reqCtx context.Context, sStore settings.Store, appliedKeys []string, prev map[string]string) {
	if sStore == nil || len(appliedKeys) == 0 {
		return
	}
	rbCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for i := len(appliedKeys) - 1; i >= 0; i-- {
		k := appliedKeys[i]
		var err error
		if oldVal, existed := prev[k]; existed {
			err = sStore.Set(rbCtx, k, oldVal)
		} else {
			err = sStore.Delete(rbCtx, k)
		}
		if err != nil {
			slog.ErrorContext(reqCtx, "Failed to roll back DuckDB setting override", slog.String("key", k), slog.String("error", err.Error()))
		}
	}
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

	a.configMutMu.Lock()
	defer a.configMutMu.Unlock()

	a.mu.RLock()
	sStore := a.settingsStore
	sCache := a.settingsCache
	cfg := a.cfg
	cfgProv := a.cfgProvider
	reloadFn := a.reloadFunc
	a.mu.RUnlock()

	ctx := r.Context()
	var (
		prevVal     string
		hadOverride bool
	)
	if sStore != nil {
		var getErr error
		prevVal, hadOverride, getErr = sStore.Get(ctx, req.Key)
		if getErr != nil {
			slog.ErrorContext(ctx, "Failed to read setting override before reset", slog.String("key", req.Key), slog.String("error", getErr.Error()))
			http.Error(w, fmt.Sprintf("Failed to read current state for %q", req.Key), http.StatusInternalServerError)
			return
		}
		if err := sStore.Delete(ctx, req.Key); err != nil {
			slog.ErrorContext(ctx, "Failed to delete setting override from DuckDB", slog.String("key", req.Key), slog.String("error", err.Error()))
			http.Error(w, fmt.Sprintf("Failed to reset setting %q", req.Key), http.StatusInternalServerError)
			return
		}
	}

	if settings.IsFilterKey(req.Key) {
		var reloadErr error
		if reloadFn != nil {
			reloadErr = reloadFn()
		}
		if (reloadFn == nil || errors.Is(reloadErr, config.ErrNoConfigProvider)) && cfg != nil {
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
			reloadErr = a.applyConfigReload(nextCfg)
		}
		if reloadErr != nil {
			slog.ErrorContext(ctx, "Failed to reload configuration after filter reset", slog.String("key", req.Key), slog.String("error", reloadErr.Error()))
			if sStore != nil && hadOverride {
				rbCtx, rbCancel := context.WithTimeout(context.Background(), 3*time.Second)
				if rbErr := sStore.Set(rbCtx, req.Key, prevVal); rbErr != nil {
					slog.ErrorContext(ctx, "Failed to restore DuckDB setting override after reset failure", slog.String("key", req.Key), slog.String("error", rbErr.Error()))
				}
				rbCancel()
			}
			http.Error(w, fmt.Sprintf("Failed to reload configuration after resetting %q: %v", req.Key, reloadErr), http.StatusInternalServerError)
			return
		}
	} else {
		// Recompute effective operational settings from YAML baseline + remaining DuckDB overrides
		var overrides map[string]string
		if sStore != nil {
			var gErr error
			overrides, gErr = sStore.GetAll(ctx)
			if gErr != nil {
				slog.ErrorContext(ctx, "Failed to reload remaining overrides from DuckDB after reset", slog.String("key", req.Key), slog.String("error", gErr.Error()))
				http.Error(w, fmt.Sprintf("Failed to recompute settings after resetting %q: %v", req.Key, gErr), http.StatusInternalServerError)
				return
			}
		}
		effective := settings.ResolveEffectiveSettings(cfg, overrides)
		if sCache != nil {
			sCache.Update(effective)
		}
		if req.Key == "timeouts.probe_timeout_sec" {
			a.invalidateSafeHTTPClient()
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

	a.configMutMu.Lock()
	defer a.configMutMu.Unlock()

	a.mu.RLock()
	reloadFn := a.reloadFunc
	a.mu.RUnlock()

	if reloadFn != nil {
		if err := reloadFn(); err != nil {
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
