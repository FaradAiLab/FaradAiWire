package admin

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/internal/guard"
	"github.com/FaradAiLab/FaradAiWire/internal/settings"
)

func applyGuardFilterDependencies(
	gf *guard.GuardFilter,
	hitl *guard.HITLDispatcher,
	cat guard.CatalogStore,
	sc *settings.Cache,
	repo agent.Repository,
) {
	if hitl != nil {
		gf.SetHITLDispatcher(hitl)
	}
	if cat != nil {
		gf.SetCatalog(cat)
	}
	if sc != nil {
		gf.SetSettingsCache(sc)
	}
	if repo != nil {
		gf.SetAgentRepository(repo)
	}
}

// ensureGuardFilterRegistered registers or updates the GuardFilter in the admin pipeline.
func (a *AdminServer) ensureGuardFilterRegistered(mgr guard.Manager) {
	a.configMutMu.Lock()
	if nextCfg := a.cloneAndMutateConfig(func(c *config.Config) {
		c.Filters.Guard.Enabled = true
	}); nextCfg != nil {
		a.SetConfig(nextCfg)
	}
	cfg := a.Config()
	a.configMutMu.Unlock()

	guardCfg := guard.FilterConfig{Enabled: true}
	if cfg != nil {
		guardCfg.L1Patterns = cfg.Filters.Guard.L1Patterns
		guardCfg.FastPathTools = cfg.Filters.Guard.FastPathTools
		guardCfg.CriticalBlocks = cfg.Filters.Guard.CriticalBlocks
		guardCfg.MaxPayloadLength = cfg.Filters.Guard.MaxPayloadLength
		guardCfg.MinWordCount = cfg.Filters.Guard.MinWordCount
	}

	pl := a.GetPipeline()
	if pl == nil || mgr == nil {
		return
	}
	hitl := a.getGuardHITL()
	cat := a.getGuardCatalog()
	sc := a.getSettingsCache()
	repo := a.getAgentRepository()
	if gf, ok := pl.GetFilter("guard").(*guard.GuardFilter); ok && gf != nil {
		gf.SetManager(mgr)
		applyGuardFilterDependencies(gf, hitl, cat, sc, repo)
		return
	}
	gf := guard.NewFilter(guardCfg, mgr)
	applyGuardFilterDependencies(gf, hitl, cat, sc, repo)
	registerFilter(pl, gf)
}

func registerFilter(pl *filter.Pipeline, gf *guard.GuardFilter) {
	pl.RegisterFilter(gf)
}

func (a *AdminServer) broadcastGuardStatus(activeModelID string, running bool, extras map[string]interface{}) {
	hub := a.WSHub()
	if hub == nil {
		return
	}
	payload := map[string]interface{}{
		"type":            "GUARD_STATUS_CHANGED",
		"active_model_id": activeModelID,
		"running":         running,
	}
	for k, v := range extras {
		payload[k] = v
	}
	hub.Broadcast(payload)
}

func (a *AdminServer) broadcastGuardModelUpdated(modelID string) {
	hub := a.WSHub()
	if hub == nil {
		return
	}
	hub.Broadcast(map[string]interface{}{
		"type":     "GUARD_MODEL_UPDATED",
		"model_id": modelID,
	})
}

func (a *AdminServer) setGuardEnabled(enabled bool) {
	a.configMutMu.Lock()
	defer a.configMutMu.Unlock()
	if nextCfg := a.cloneAndMutateConfig(func(c *config.Config) {
		c.Filters.Guard.Enabled = enabled
	}); nextCfg != nil {
		a.SetConfig(nextCfg)
	}
}

// handleGuardDeactivateGlobal deactivates any active guard model and falls back to L1-Only mode (POST /admin/guards/models/deactivate).
func (a *AdminServer) handleGuardDeactivateGlobal(w http.ResponseWriter, r *http.Request) {
	catalog := a.requireGuardCatalog(w)
	if catalog == nil {
		return
	}

	active, _ := catalog.GetActive(r.Context())
	if active != nil {
		_ = catalog.SetActive(r.Context(), active.ID, false)
	}

	stopRunningGuardManager(a.getGuardManager())
	a.setGuardEnabled(false)
	a.broadcastGuardStatus("", false, nil)
	if active != nil {
		a.broadcastGuardModelUpdated(active.ID)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "INACTIVE",
		"message": "Gateway switched to L1 Static Rules Only (Lightweight Mode)",
	})
}

// handleGuardDeactivateModel deactivates a specific guard model (POST /admin/guards/models/{id}/deactivate).
func (a *AdminServer) handleGuardDeactivateModel(w http.ResponseWriter, r *http.Request) {
	catalog := a.requireGuardCatalog(w)
	if catalog == nil {
		return
	}
	modelID, ok := requireValidGuardModelID(w, r)
	if !ok {
		return
	}

	active, _ := catalog.GetActive(r.Context())
	isActiveTarget := active != nil && active.ID == modelID

	_ = catalog.SetActive(r.Context(), modelID, false)

	if isActiveTarget {
		stopRunningGuardManager(a.getGuardManager())
		a.setGuardEnabled(false)
		a.broadcastGuardStatus("", false, nil)
	}
	a.broadcastGuardModelUpdated(modelID)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "INACTIVE",
		"model_id": modelID,
		"message":  fmt.Sprintf("Model '%s' deactivated; gateway switched to L1 Static Rules Only", modelID),
	})
}

// handleGuardConnect connects and activates a guard model with an external endpoint (POST /admin/guards/models/{id}/connect).
func (a *AdminServer) handleGuardConnect(w http.ResponseWriter, r *http.Request) {
	catalog := a.requireGuardCatalog(w)
	if catalog == nil {
		return
	}
	modelID, ok := requireValidGuardModelID(w, r)
	if !ok {
		return
	}

	model, err := catalog.Get(r.Context(), modelID)
	if err != nil {
		writeCatalogGetError(w, modelID, err)
		return
	}

	var reqPayload struct {
		RuntimeType   string `json:"runtime_type"`
		EndpointURL   string `json:"endpoint_url"`
		ContextWindow int    `json:"context_window,omitempty"`
		Force         bool   `json:"force,omitempty"`
	}
	if err := decodeJSON(w, r, maxSmallAdminBodyBytes, &reqPayload); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_PAYLOAD", "Invalid JSON request payload: "+err.Error())
		return
	}

	reqPayload.EndpointURL = strings.TrimSpace(reqPayload.EndpointURL)
	if reqPayload.EndpointURL == "" {
		writeError(w, http.StatusBadRequest, "MISSING_ENDPOINT_URL", "endpoint_url is required")
		return
	}

	reqPayload.RuntimeType = cmp.Or(reqPayload.RuntimeType, "docker")
	if reqPayload.ContextWindow <= 0 {
		if model.ContextWindow > 0 {
			reqPayload.ContextWindow = model.ContextWindow
		} else {
			reqPayload.ContextWindow = 2048
		}
	}

	expectedModelRef := model.ID
	if model.OllamaSource != "" && reqPayload.RuntimeType == "ollama" {
		expectedModelRef = model.OllamaSource
	} else if model.DockerImage != "" && reqPayload.RuntimeType == "docker" {
		expectedModelRef = model.DockerImage
	}

	probeResult, probeErr := guard.ProbeAndVerify(r.Context(), reqPayload.EndpointURL, reqPayload.RuntimeType, expectedModelRef)
	if probeErr != nil || probeResult == nil || !probeResult.Alive {
		errMsg := "Endpoint probe failed"
		if probeErr != nil {
			errMsg = probeErr.Error()
		}
		writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error":        "ENDPOINT_UNREACHABLE",
			"message":      errMsg,
			"endpoint_url": reqPayload.EndpointURL,
			"probe":        probeResult,
		})
		return
	}

	if !probeResult.ModelMatched && !reqPayload.Force {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":         "WARNING_MISMATCH",
			"model_mismatch": true,
			"expected_model": expectedModelRef,
			"detected_model": probeResult.DetectedModel,
			"endpoint_url":   reqPayload.EndpointURL,
			"message":        fmt.Sprintf("Endpoint is running %q, which does not match expected model %q. Pass force=true to activate anyway.", probeResult.DetectedModel, expectedModelRef),
			"probe":          probeResult,
		})
		return
	}

	if err := catalog.UpdateConnection(r.Context(), modelID, reqPayload.RuntimeType, reqPayload.EndpointURL); err != nil {
		writeError(w, http.StatusInternalServerError, "CATALOG_UPDATE_FAILED", err.Error())
		return
	}
	if err := catalog.UpdateContextWindow(r.Context(), modelID, reqPayload.ContextWindow); err != nil {
		writeError(w, http.StatusInternalServerError, "CATALOG_UPDATE_FAILED", err.Error())
		return
	}
	if err := catalog.SetActive(r.Context(), modelID, true); err != nil {
		writeError(w, http.StatusInternalServerError, "CATALOG_ACTIVATE_FAILED", err.Error())
		return
	}

	model.EndpointURL = reqPayload.EndpointURL
	model.RuntimeType = reqPayload.RuntimeType
	model.ContextWindow = reqPayload.ContextWindow
	model.IsActive = true

	mgr := a.getGuardManager()
	if mgr != nil {
		stopRunningGuardManager(mgr)
		startCtx, startCancel := context.WithTimeout(context.Background(), 5*time.Second)
		startErr := mgr.Start(startCtx, model)
		startCancel()
		if startErr != nil {
			_ = catalog.SetActive(context.Background(), modelID, false)
			writeError(w, http.StatusInternalServerError, "MODEL_START_FAILED", fmt.Sprintf("Failed to start guard process for '%s': %v", modelID, startErr))
			return
		}
	}

	a.ensureGuardFilterRegistered(mgr)
	a.broadcastGuardStatus(modelID, true, map[string]interface{}{
		"endpoint_url":   reqPayload.EndpointURL,
		"runtime_type":   reqPayload.RuntimeType,
		"context_window": reqPayload.ContextWindow,
	})
	a.broadcastGuardModelUpdated(modelID)

	slog.InfoContext(r.Context(), "Semantic Security Guard connected and activated",
		slog.String("model_id", modelID),
		slog.String("endpoint_url", reqPayload.EndpointURL),
		slog.String("runtime_type", reqPayload.RuntimeType),
		slog.Int("context_window", reqPayload.ContextWindow),
		slog.Float64("latency_ms", probeResult.LatencyMS),
	)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":         "ACTIVE",
		"model_id":       modelID,
		"endpoint_url":   reqPayload.EndpointURL,
		"runtime_type":   reqPayload.RuntimeType,
		"context_window": reqPayload.ContextWindow,
		"model_mismatch": !probeResult.ModelMatched,
		"detected_model": probeResult.DetectedModel,
		"latency_ms":     probeResult.LatencyMS,
		"message":        fmt.Sprintf("Guard model '%s' connected and activated successfully", model.Name),
		"probe":          probeResult,
	})
}

// handleGuardActivate handles activating an installed guard model (POST /admin/guards/models/{id}/activate).
func (a *AdminServer) handleGuardActivate(w http.ResponseWriter, r *http.Request) {
	catalog := a.requireGuardCatalog(w)
	if catalog == nil {
		return
	}
	modelID, ok := requireValidGuardModelID(w, r)
	if !ok {
		return
	}

	model, err := catalog.Get(r.Context(), modelID)
	if err != nil {
		writeCatalogGetError(w, modelID, err)
		return
	}
	if model.InstallStatus != guard.InstallStatusInstalled {
		writeError(w, http.StatusBadRequest, "MODEL_NOT_INSTALLED", fmt.Sprintf("Guard model '%s' must be installed before activation (current status: %s)", modelID, model.InstallStatus))
		return
	}

	mgr := a.getGuardManager()
	if mgr != nil {
		// Zero-Downtime Hot-Swap:
		// 1. Gracefully terminate retiring subprocess via SIGTERM -> SIGKILL to reclaim VRAM.
		// 2. In-flight agent traffic flows across L1-Only fallback during the restart window without dropped requests.
		stopRunningGuardManager(mgr)

		// 3. Mark newly activated model in DuckDB catalog
		if err := catalog.SetActive(r.Context(), modelID, true); err != nil {
			writeError(w, http.StatusInternalServerError, "CATALOG_UPDATE_FAILED", err.Error())
			return
		}

		// 4. Boot successor process
		startCtx, startCancel := context.WithTimeout(context.Background(), 10*time.Second)
		startErr := mgr.Start(startCtx, model)
		startCancel()

		if startErr != nil {
			// Startup failure: record FAILED in DuckDB, gateway remains safe under L1 protection
			_ = catalog.SetActive(context.Background(), modelID, false)
			_ = catalog.UpdateStatus(context.Background(), modelID, guard.InstallStatusFailed)
			a.broadcastGuardStatus("", false, nil)
			a.broadcastGuardModelUpdated(modelID)
			writeError(w, http.StatusInternalServerError, "ACTIVATION_FAILED", fmt.Sprintf("Failed to start guard process for '%s': %v", modelID, startErr))
			return
		}
	} else {
		if err := catalog.SetActive(r.Context(), modelID, true); err != nil {
			writeError(w, http.StatusInternalServerError, "CATALOG_UPDATE_FAILED", err.Error())
			return
		}
	}

	a.ensureGuardFilterRegistered(mgr)
	a.broadcastGuardStatus(modelID, true, nil)
	a.broadcastGuardModelUpdated(modelID)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "ACTIVE",
		"model_id": modelID,
		"message":  fmt.Sprintf("Guard model '%s' activated successfully", model.Name),
	})
}

// handleGuardInstall triggers asynchronous model installation (POST /admin/guards/models/{id}/install).
func (a *AdminServer) handleGuardInstall(w http.ResponseWriter, r *http.Request) {
	if a.requireGuardCatalog(w) == nil {
		return
	}
	modelID, ok := requireValidGuardModelID(w, r)
	if !ok {
		return
	}
	installer := a.getGuardInstaller()
	if installer == nil {
		writeError(w, http.StatusServiceUnavailable, "INSTALLER_UNAVAILABLE", "Guard model installer is not initialized")
		return
	}

	if err := installer.InstallAsync(r.Context(), modelID); err != nil {
		if errors.Is(err, guard.ErrModelNotFound) {
			writeError(w, http.StatusNotFound, "NOT_FOUND", fmt.Sprintf("Guard model '%s' not found", modelID))
			return
		}
		if errors.Is(err, guard.ErrInstallInProgress) {
			writeError(w, http.StatusConflict, "INSTALL_IN_PROGRESS", fmt.Sprintf("Installation for model '%s' is already in progress", modelID))
			return
		}
		writeError(w, http.StatusInternalServerError, "INSTALL_FAILED", err.Error())
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"status":   "INSTALLING",
		"model_id": modelID,
		"message":  fmt.Sprintf("Installation started for %s", modelID),
	})
}

// handleGuardInstallProgress reports async guard model installation progress (GET /admin/guards/models/{id}/progress).
func (a *AdminServer) handleGuardInstallProgress(w http.ResponseWriter, r *http.Request) {
	catalog := a.requireGuardCatalog(w)
	if catalog == nil {
		return
	}
	modelID, ok := requireValidGuardModelID(w, r)
	if !ok {
		return
	}
	installer := a.getGuardInstaller()
	if installer == nil {
		writeError(w, http.StatusServiceUnavailable, "INSTALLER_UNAVAILABLE", "Guard model installer is not initialized")
		return
	}

	prog, exists := installer.GetProgress(modelID)
	if !exists {
		m, err := catalog.Get(r.Context(), modelID)
		if err != nil {
			writeError(w, http.StatusNotFound, "NOT_FOUND", fmt.Sprintf("Guard model '%s' not found", modelID))
			return
		}
		writeJSON(w, http.StatusOK, guard.InstallProgress{
			ModelID:   modelID,
			Status:    m.InstallStatus,
			Step:      guard.StepCompleted,
			Progress:  1.0,
			UpdatedAt: m.UpdatedAt,
		})
		return
	}
	writeJSON(w, http.StatusOK, prog)
}
