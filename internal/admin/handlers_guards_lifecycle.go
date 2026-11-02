package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/guard"
	"github.com/FaradAiLab/FaradAiWire/internal/pathguard"
)

// ensureGuardFilterRegistered registers or updates the GuardFilter in the admin pipeline.
func (a *AdminServer) ensureGuardFilterRegistered(mgr guard.Manager) {
	a.mu.Lock()
	guardCfg := guard.FilterConfig{Enabled: true}
	if a.cfg != nil {
		a.cfg.Filters.Guard.Enabled = true
		guardCfg.L1Patterns = a.cfg.Filters.Guard.L1Patterns
		guardCfg.FastPathTools = a.cfg.Filters.Guard.FastPathTools
		guardCfg.CriticalBlocks = a.cfg.Filters.Guard.CriticalBlocks
		guardCfg.MaxPayloadLength = a.cfg.Filters.Guard.MaxPayloadLength
		guardCfg.MinWordCount = a.cfg.Filters.Guard.MinWordCount
	}
	pl := a.pipeline
	hitl := a.guardHITL
	cat := a.guardCatalog
	sc := a.settingsCache
	a.mu.Unlock()

	if pl != nil && mgr != nil {
		gf, ok := pl.GetFilter("guard").(*guard.GuardFilter)
		if !ok || gf == nil {
			gf = guard.NewFilter(guardCfg, mgr)
			if hitl != nil {
				gf.SetHITLDispatcher(hitl)
			}
			if cat != nil {
				gf.SetCatalog(cat)
			}
			if sc != nil {
				gf.SetSettingsCache(sc)
			}
			if repo := a.getAgentRepository(); repo != nil {
				gf.SetAgentRepository(repo)
			}
			pl.RegisterFilter(gf)
		} else {
			gf.SetManager(mgr)
			if hitl != nil {
				gf.SetHITLDispatcher(hitl)
			}
			if cat != nil {
				gf.SetCatalog(cat)
			}
			if sc != nil {
				gf.SetSettingsCache(sc)
			}
			if repo := a.getAgentRepository(); repo != nil {
				gf.SetAgentRepository(repo)
			}
		}
	}
}

// handleGuardDeactivateGlobal deactivates any active guard model and falls back to L1-Only mode.
// POST /admin/guards/models/deactivate
func (a *AdminServer) handleGuardDeactivateGlobal(w http.ResponseWriter, r *http.Request, catalog guard.CatalogStore) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "METHOD_NOT_ALLOWED",
			"message": "Only POST method is supported for deactivation",
		})
		return
	}

	active, _ := catalog.GetActive(r.Context())
	if active != nil {
		_ = catalog.SetActive(r.Context(), active.ID, false)
	}

	mgr := a.getGuardManager()
	if mgr != nil && mgr.IsRunning() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = mgr.Stop(stopCtx)
		cancel()
	}

	a.mu.Lock()
	if a.cfg != nil {
		a.cfg.Filters.Guard.Enabled = false
	}
	a.mu.Unlock()

	hub := a.WSHub()
	if hub != nil {
		hub.Broadcast(map[string]interface{}{
			"type":            "GUARD_STATUS_CHANGED",
			"active_model_id": "",
			"running":         false,
		})
		if active != nil {
			hub.Broadcast(map[string]interface{}{
				"type":     "GUARD_MODEL_UPDATED",
				"model_id": active.ID,
			})
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "INACTIVE",
		"message": "Gateway switched to L1 Static Rules Only (Lightweight Mode)",
	})
}

// handleGuardDeactivateModel deactivates a specific guard model.
// POST /admin/guards/models/{id}/deactivate
func (a *AdminServer) handleGuardDeactivateModel(w http.ResponseWriter, r *http.Request, catalog guard.CatalogStore, modelID string) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "METHOD_NOT_ALLOWED",
			"message": "Only POST method is supported for deactivation",
		})
		return
	}

	if err := pathguard.ValidateSafeIdentifier(modelID); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "INVALID_MODEL_ID",
			"message": "Invalid model ID format: " + err.Error(),
		})
		return
	}

	active, _ := catalog.GetActive(r.Context())
	isActiveTarget := (active != nil && active.ID == modelID)

	_ = catalog.SetActive(r.Context(), modelID, false)

	if isActiveTarget {
		mgr := a.getGuardManager()
		if mgr != nil && mgr.IsRunning() {
			stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = mgr.Stop(stopCtx)
			cancel()
		}

		a.mu.Lock()
		if a.cfg != nil {
			a.cfg.Filters.Guard.Enabled = false
		}
		a.mu.Unlock()

		hub := a.WSHub()
		if hub != nil {
			hub.Broadcast(map[string]interface{}{
				"type":            "GUARD_STATUS_CHANGED",
				"active_model_id": "",
				"running":         false,
			})
		}
	}

	hub := a.WSHub()
	if hub != nil {
		hub.Broadcast(map[string]interface{}{
			"type":     "GUARD_MODEL_UPDATED",
			"model_id": modelID,
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "INACTIVE",
		"model_id": modelID,
		"message":  fmt.Sprintf("Model '%s' deactivated; gateway switched to L1 Static Rules Only", modelID),
	})
}

// handleGuardConnect connects and activates a guard model with an external endpoint (Ollama/Docker/vLLM).
// POST /admin/guards/models/{id}/connect
func (a *AdminServer) handleGuardConnect(w http.ResponseWriter, r *http.Request, catalog guard.CatalogStore, modelID string) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "METHOD_NOT_ALLOWED",
			"message": "Only POST method is supported for model connection",
		})
		return
	}

	if err := pathguard.ValidateSafeIdentifier(modelID); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "INVALID_MODEL_ID",
			"message": "Invalid model ID format: " + err.Error(),
		})
		return
	}

	model, err := catalog.Get(r.Context(), modelID)
	if err != nil {
		if errors.Is(err, guard.ErrModelNotFound) {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "NOT_FOUND",
				"message": fmt.Sprintf("Guard model '%s' not found", modelID),
			})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "CATALOG_GET_FAILED",
			"message": err.Error(),
		})
		return
	}

	var reqPayload struct {
		RuntimeType   string `json:"runtime_type"`
		EndpointURL   string `json:"endpoint_url"`
		ContextWindow int    `json:"context_window,omitempty"`
		Force         bool   `json:"force,omitempty"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	if err := json.NewDecoder(r.Body).Decode(&reqPayload); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "INVALID_PAYLOAD",
			"message": "Invalid JSON request payload: " + err.Error(),
		})
		return
	}

	reqPayload.EndpointURL = strings.TrimSpace(reqPayload.EndpointURL)
	if reqPayload.EndpointURL == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "MISSING_ENDPOINT_URL",
			"message": "endpoint_url is required",
		})
		return
	}

	if reqPayload.RuntimeType == "" {
		reqPayload.RuntimeType = "docker"
	}

	if reqPayload.ContextWindow <= 0 {
		if model.ContextWindow > 0 {
			reqPayload.ContextWindow = model.ContextWindow
		} else {
			reqPayload.ContextWindow = 2048
		}
	}

	// 1. Probe & Verify target endpoint
	expectedModelRef := model.ID
	if model.OllamaSource != "" && reqPayload.RuntimeType == "ollama" {
		expectedModelRef = model.OllamaSource
	} else if model.DockerImage != "" && reqPayload.RuntimeType == "docker" {
		expectedModelRef = model.DockerImage
	}

	probeResult, probeErr := guard.ProbeAndVerify(r.Context(), reqPayload.EndpointURL, reqPayload.RuntimeType, expectedModelRef)
	if probeErr != nil || probeResult == nil || !probeResult.Alive {
		w.WriteHeader(http.StatusServiceUnavailable)
		errMsg := "Endpoint probe failed"
		if probeErr != nil {
			errMsg = probeErr.Error()
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":        "ENDPOINT_UNREACHABLE",
			"message":      errMsg,
			"endpoint_url": reqPayload.EndpointURL,
			"probe":        probeResult,
		})
		return
	}

	// Check for mismatch: If model does not match and not forced, return mismatch warning
	if !probeResult.ModelMatched && !reqPayload.Force {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
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

	// 2. Commit connection metadata & activate in DuckDB
	if err := catalog.UpdateConnection(r.Context(), modelID, reqPayload.RuntimeType, reqPayload.EndpointURL); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "CATALOG_UPDATE_FAILED",
			"message": err.Error(),
		})
		return
	}
	if err := catalog.UpdateContextWindow(r.Context(), modelID, reqPayload.ContextWindow); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "CATALOG_UPDATE_FAILED",
			"message": err.Error(),
		})
		return
	}
	if err := catalog.SetActive(r.Context(), modelID, true); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "CATALOG_ACTIVATE_FAILED",
			"message": err.Error(),
		})
		return
	}

	// 3. Update Model in memory
	model.EndpointURL = reqPayload.EndpointURL
	model.RuntimeType = reqPayload.RuntimeType
	model.ContextWindow = reqPayload.ContextWindow
	model.IsActive = true

	// 4. Update Manager
	mgr := a.getGuardManager()
	if mgr != nil {
		if mgr.IsRunning() {
			stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = mgr.Stop(stopCtx)
			stopCancel()
		}
		startCtx, startCancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := mgr.Start(startCtx, model)
		startCancel()
		if err != nil {
			_ = catalog.SetActive(context.Background(), modelID, false)
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":   "MODEL_START_FAILED",
				"message": fmt.Sprintf("Failed to start guard process for '%s': %v", modelID, err),
			})
			return
		}
	}

	// 5. Ensure filter is registered in pipeline
	a.ensureGuardFilterRegistered(mgr)

	// 6. Broadcast via WebSocket
	hub := a.WSHub()
	if hub != nil {
		hub.Broadcast(map[string]interface{}{
			"type":            "GUARD_STATUS_CHANGED",
			"active_model_id": modelID,
			"running":         true,
			"endpoint_url":    reqPayload.EndpointURL,
			"runtime_type":    reqPayload.RuntimeType,
			"context_window":  reqPayload.ContextWindow,
		})
		hub.Broadcast(map[string]interface{}{
			"type":     "GUARD_MODEL_UPDATED",
			"model_id": modelID,
		})
	}

	slog.InfoContext(r.Context(), "Semantic Security Guard connected and activated",
		slog.String("model_id", modelID),
		slog.String("endpoint_url", reqPayload.EndpointURL),
		slog.String("runtime_type", reqPayload.RuntimeType),
		slog.Int("context_window", reqPayload.ContextWindow),
		slog.Float64("latency_ms", probeResult.LatencyMS),
	)

	json.NewEncoder(w).Encode(map[string]interface{}{
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

// handleGuardActivate handles activating an installed guard model.
// POST /admin/guards/models/{id}/activate
func (a *AdminServer) handleGuardActivate(w http.ResponseWriter, r *http.Request, catalog guard.CatalogStore, modelID string) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "METHOD_NOT_ALLOWED",
			"message": "Only POST method is supported for model activation",
		})
		return
	}

	if err := pathguard.ValidateSafeIdentifier(modelID); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "INVALID_MODEL_ID",
			"message": "Invalid model ID format: " + err.Error(),
		})
		return
	}

	model, err := catalog.Get(r.Context(), modelID)
	if err != nil {
		if errors.Is(err, guard.ErrModelNotFound) {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "NOT_FOUND",
				"message": fmt.Sprintf("Guard model '%s' not found", modelID),
			})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "CATALOG_GET_FAILED",
			"message": err.Error(),
		})
		return
	}

	if model.InstallStatus != guard.InstallStatusInstalled {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "MODEL_NOT_INSTALLED",
			"message": fmt.Sprintf("Guard model '%s' must be installed before activation (current status: %s)", modelID, model.InstallStatus),
		})
		return
	}

	mgr := a.getGuardManager()
	if mgr != nil {
		// Zero-Downtime Hot-Swap:
		// 1. Gracefully terminate retiring subprocess via SIGTERM -> SIGKILL to reclaim VRAM.
		// 2. In-flight agent traffic flows across L1-Only fallback during the restart window without dropped requests.
		if mgr.IsRunning() {
			stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = mgr.Stop(stopCtx)
			stopCancel()
		}

		// 3. Mark newly activated model in DuckDB catalog
		if err := catalog.SetActive(r.Context(), modelID, true); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "CATALOG_UPDATE_FAILED",
				"message": err.Error(),
			})
			return
		}

		// 4. Boot successor process
		startCtx, startCancel := context.WithTimeout(context.Background(), 10*time.Second)
		err = mgr.Start(startCtx, model)
		startCancel()

		if err != nil {
			// Startup failure: record FAILED in DuckDB, gateway remains safe under L1 protection
			_ = catalog.SetActive(context.Background(), modelID, false)
			_ = catalog.UpdateStatus(context.Background(), modelID, guard.InstallStatusFailed)

			hub := a.WSHub()
			if hub != nil {
				hub.Broadcast(map[string]interface{}{
					"type":            "GUARD_STATUS_CHANGED",
					"active_model_id": "",
					"running":         false,
				})
				hub.Broadcast(map[string]interface{}{
					"type":     "GUARD_MODEL_UPDATED",
					"model_id": modelID,
				})
			}

			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "ACTIVATION_FAILED",
				"message": fmt.Sprintf("Failed to start guard process for '%s': %v", modelID, err),
			})
			return
		}
	} else {
		if err := catalog.SetActive(r.Context(), modelID, true); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "CATALOG_UPDATE_FAILED",
				"message": err.Error(),
			})
			return
		}
	}

	a.ensureGuardFilterRegistered(mgr)

	hub := a.WSHub()
	if hub != nil {
		hub.Broadcast(map[string]interface{}{
			"type":            "GUARD_STATUS_CHANGED",
			"active_model_id": modelID,
			"running":         true,
		})
		hub.Broadcast(map[string]interface{}{
			"type":     "GUARD_MODEL_UPDATED",
			"model_id": modelID,
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "ACTIVE",
		"model_id": modelID,
		"message":  fmt.Sprintf("Guard model '%s' activated successfully", model.Name),
	})
}

// handleGuardInstallOrProgress handles async model installation triggers and progress polling.
// POST /admin/guards/models/{id}/install
// GET  /admin/guards/models/{id}/progress
func (a *AdminServer) handleGuardInstallOrProgress(w http.ResponseWriter, r *http.Request, catalog guard.CatalogStore, relPath string) {
	var modelID string
	var isProgress bool
	if strings.HasSuffix(relPath, "/install") {
		modelID = strings.TrimSuffix(relPath, "/install")
	} else {
		modelID = strings.TrimSuffix(relPath, "/progress")
		isProgress = true
	}
	modelID = strings.Trim(modelID, "/")

	if err := pathguard.ValidateSafeIdentifier(modelID); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "INVALID_MODEL_ID",
			"message": "Invalid model ID format: " + err.Error(),
		})
		return
	}

	installer := a.getGuardInstaller()
	if installer == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "INSTALLER_UNAVAILABLE",
			"message": "Guard model installer is not initialized",
		})
		return
	}

	if r.Method == http.MethodPost && !isProgress {
		err := installer.InstallAsync(r.Context(), modelID)
		if err != nil {
			if errors.Is(err, guard.ErrModelNotFound) {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "NOT_FOUND",
					"message": fmt.Sprintf("Guard model '%s' not found", modelID),
				})
				return
			}
			if errors.Is(err, guard.ErrInstallInProgress) {
				w.WriteHeader(http.StatusConflict)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "INSTALL_IN_PROGRESS",
					"message": fmt.Sprintf("Installation for model '%s' is already in progress", modelID),
				})
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "INSTALL_FAILED",
				"message": err.Error(),
			})
			return
		}

		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "INSTALLING",
			"model_id": modelID,
			"message":  fmt.Sprintf("Installation started for %s", modelID),
		})
		return
	}

	if r.Method == http.MethodGet {
		prog, exists := installer.GetProgress(modelID)
		if !exists {
			// Fallback to checking catalog status directly
			m, err := catalog.Get(r.Context(), modelID)
			if err != nil {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "NOT_FOUND",
					"message": fmt.Sprintf("Guard model '%s' not found", modelID),
				})
				return
			}
			json.NewEncoder(w).Encode(guard.InstallProgress{
				ModelID:   modelID,
				Status:    m.InstallStatus,
				Step:      guard.StepCompleted,
				Progress:  1.0,
				UpdatedAt: m.UpdatedAt,
			})
			return
		}
		json.NewEncoder(w).Encode(prog)
		return
	}

	w.Header().Set("Allow", "GET, POST")
	w.WriteHeader(http.StatusMethodNotAllowed)
	json.NewEncoder(w).Encode(map[string]string{
		"error":   "METHOD_NOT_ALLOWED",
		"message": "Only GET and POST methods are supported on install route",
	})
}

