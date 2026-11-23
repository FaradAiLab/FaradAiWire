package admin

import (
	"context"
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
	if a.schemaClear != nil {
		a.schemaClear()
	}

	a.logSecurityAudit(r, "schemas_cleared", "schemas_clear", "schemas", "*", "allowed", "Pinned schema baselines cleared", nil)

	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "success",
		"message": "Pinned schema baselines successfully cleared",
	})
}

func (a *AdminServer) handleMCPTools(w http.ResponseWriter, r *http.Request) {
	var schemasDir string
	if cfg := a.Config(); cfg != nil {
		schemasDir = cfg.Filters.SchemaValidation.SchemasDir
	}
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
	var req struct {
		FilterName string `json:"filter_name"`
		Filter     string `json:"filter"`
		Enabled    *bool  `json:"enabled"`
	}
	if err := decodeJSON(w, r, maxSmallAdminBodyBytes, &req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid request body")
		return
	}
	if req.FilterName == "" && req.Filter != "" {
		req.FilterName = req.Filter
	}
	if req.Enabled == nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Missing required boolean field: enabled")
		return
	}
	enabled := *req.Enabled

	isFilter := settings.IsSupportedFilterName(req.FilterName)
	isLegacyToggle := settings.IsLegacyToggleName(req.FilterName)
	if !isFilter && !isLegacyToggle {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Unknown setting/filter: "+req.FilterName)
		return
	}

	a.configMutMu.Lock()
	defer a.configMutMu.Unlock()

	sStore := a.settingsStore

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
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", fmt.Sprintf("Failed to read current state for filter %q", req.FilterName))
			return
		}
		if err := sStore.Set(ctx, filterKey, strconv.FormatBool(enabled)); err != nil {
			slog.ErrorContext(ctx, "Failed to persist filter toggle to DuckDB", slog.String("filter", req.FilterName), slog.String("error", err.Error()))
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", fmt.Sprintf("Failed to persist filter toggle %q", req.FilterName))
			return
		}
	}

	nextCfg := a.cloneAndMutateConfig(func(c *config.Config) {
		settings.ApplyRuntimeToggle(c, req.FilterName, enabled)
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
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", fmt.Sprintf("Failed to reload configuration after toggling %q: %v", req.FilterName, err))
		return
	}

	// Emit control-plane security audit event (segregated from tool_audit_logs)
	a.logSecurityAudit(
		r,
		"config_mutated",
		"config_toggle",
		"filter_toggle",
		req.FilterName,
		"allowed",
		fmt.Sprintf("Filter %s toggled to %v", req.FilterName, enabled),
		map[string]any{"enabled": enabled},
	)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":      "success",
		"filter":      req.FilterName,
		"filter_name": req.FilterName,
		"enabled":     enabled,
		"message":     fmt.Sprintf("Setting '%s' successfully set to %v", req.FilterName, enabled),
	})
}

// getSettings returns self-describing operational settings metadata, active values, and override status.
func (a *AdminServer) getSettings(w http.ResponseWriter, r *http.Request) {
	sStore := a.settingsStore
	sCache := a.settingsCache

	var pollInterval int
	var autoSyncMCP, autoUpdatePolicies bool
	if cfg := a.Config(); cfg != nil {
		pollInterval = cfg.PollIntervalSeconds
		autoSyncMCP = cfg.AutoSyncMCP
		autoUpdatePolicies = cfg.AutoUpdatePolicies
	}

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

	writeJSON(w, http.StatusOK, map[string]any{
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
	var payload map[string]any
	if err := decodeJSON(w, r, maxAdminBodyBytes, &payload); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid JSON payload: "+err.Error())
		return
	}

	a.configMutMu.Lock()
	defer a.configMutMu.Unlock()

	sStore := a.settingsStore
	sCache := a.settingsCache

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
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid poll_interval_seconds: must be an integer between 1 and 86400")
			return
		}
		setPollInterval = true
		pollIntervalVal = pollInt
		hasLegacy = true
	}
	if rawSync, present := payload["auto_sync_mcp"]; present {
		b, ok := rawSync.(bool)
		if !ok {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid auto_sync_mcp: must be a boolean")
			return
		}
		setAutoSyncMCP = true
		autoSyncMCPVal = b
		hasLegacy = true
	}
	if rawUpdatePol, present := payload["auto_update_policies"]; present {
		b, ok := rawUpdatePol.(bool)
		if !ok {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid auto_update_policies: must be a boolean")
			return
		}
		setAutoUpdatePol = true
		autoUpdatePolVal = b
		hasLegacy = true
	}

	if len(toUpdate) == 0 && !hasLegacy {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "No valid setting keys found in request payload")
		return
	}

	// Fail-closed validation against registry schema and bounds
	for k, v := range toUpdate {
		if err := settings.Validate(k, v); err != nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", fmt.Sprintf("Validation failed for %q: %v", k, err))
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
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", fmt.Sprintf("Database error reading current settings: %v", getErr))
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
				writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", fmt.Sprintf("Database error updating %q: %v", k, err))
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
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", fmt.Sprintf("Failed to reload configuration after settings update: %v", err))
			return
		}
	}

	for _, aEv := range audits {
		a.logSecurityAudit(
			r,
			"settings_mutated",
			"settings_mutate",
			"settings",
			aEv.key,
			"allowed",
			fmt.Sprintf("Setting %q updated from %v to %v", aEv.key, aEv.oldVal, aEv.newVal),
			map[string]any{"old_value": aEv.oldVal, "new_value": aEv.newVal},
		)
	}

	if sCache != nil {
		sCache.Update(currentSettings)
	}
	if _, timeoutUpdated := toUpdate["timeouts.probe_timeout_sec"]; timeoutUpdated {
		a.invalidateSafeHTTPClient()
	}

	writeJSON(w, http.StatusOK, map[string]any{
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
	var req struct {
		Key string `json:"key"`
	}
	if err := decodeJSON(w, r, maxSmallAdminBodyBytes, &req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid JSON payload: "+err.Error())
		return
	}

	if req.Key == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Setting key is required")
		return
	}

	meta, exists := settings.LookupMeta(req.Key)
	if !exists {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", fmt.Sprintf("Unknown setting key: %q", req.Key))
		return
	}

	a.configMutMu.Lock()
	defer a.configMutMu.Unlock()

	sStore := a.settingsStore
	sCache := a.settingsCache
	cfgProv := a.cfgProvider
	reloadFn := a.reloadFunc
	cfg := a.Config()

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
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", fmt.Sprintf("Failed to read current state for %q", req.Key))
			return
		}
		if err := sStore.Delete(ctx, req.Key); err != nil {
			slog.ErrorContext(ctx, "Failed to delete setting override from DuckDB", slog.String("key", req.Key), slog.String("error", err.Error()))
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", fmt.Sprintf("Failed to reset setting %q", req.Key))
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
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", fmt.Sprintf("Failed to reload configuration after resetting %q: %v", req.Key, reloadErr))
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
				writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", fmt.Sprintf("Failed to recompute settings after resetting %q: %v", req.Key, gErr))
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

	// Emit control-plane security audit event (segregated from tool_audit_logs)
	a.logSecurityAudit(
		r,
		"settings_reset",
		"settings_reset",
		"settings",
		req.Key,
		"allowed",
		fmt.Sprintf("Setting %q reset to baseline default", req.Key),
		nil,
	)

	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "success",
		"message": fmt.Sprintf("Setting %q reset to baseline default successfully", req.Key),
		"key":     req.Key,
	})
}

// extractUserContext resolves the verified actor identity established by admin middleware.
func (a *AdminServer) extractUserContext(r *http.Request) *filter.UserContext {
	actor := adminActorFromRequest(r)
	return &filter.UserContext{
		Role:      actor.ActorRole,
		UserID:    actor.ActorID,
		APIKeyID:  apiKeyIDFromActor(actor.ActorID),
		ClientIP:  actor.ClientIP,
		AgentName: "admin-console",
	}
}

// logAuditEvent delivers an AuditEvent to registered audit event loggers.
func (a *AdminServer) logAuditEvent(event *filter.AuditEvent) {
	if event == nil {
		return
	}
	for _, logger := range a.getAuditLoggers() {
		if logger != nil {
			logger.LogEvent(event)
		}
	}
}

// handleReload triggers an atomic hot-reload of configuration and filter pipeline.
func (a *AdminServer) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, maxAdminBodyBytes)
	}

	a.configMutMu.Lock()
	defer a.configMutMu.Unlock()

	if a.reloadFunc != nil {
		if err := a.reloadFunc(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"status":  "error",
				"message": "Reload failed: " + err.Error(),
			})
			return
		}
	}

	a.logSecurityAudit(r, "config_reloaded", "config_reload", "config", "runtime", "allowed", "Configuration hot-reloaded", nil)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"message": "Gateway successfully reloaded",
	})
}
