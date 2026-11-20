package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/guard"
	"github.com/FaradAiLab/FaradAiWire/internal/pathguard"
)

func (a *AdminServer) getGuardCatalog() guard.CatalogStore {
	return a.guardCatalog
}

func (a *AdminServer) getGuardManager() guard.Manager {
	return a.guardManager
}

func (a *AdminServer) getGuardInstaller() guard.ModelInstaller {
	return a.guardInstaller
}

func (a *AdminServer) requireGuardCatalog(w http.ResponseWriter) guard.CatalogStore {
	catalog := a.getGuardCatalog()
	if catalog == nil {
		writeError(w, http.StatusServiceUnavailable, "GUARD_CATALOG_UNAVAILABLE", "Guard model catalog is not initialized or database is unavailable")
		return nil
	}
	return catalog
}

func requireValidGuardModelID(w http.ResponseWriter, r *http.Request) (string, bool) {
	modelID := strings.TrimSpace(r.PathValue("id"))
	if err := pathguard.ValidateSafeIdentifier(modelID); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_MODEL_ID", "Invalid model ID format: "+err.Error())
		return "", false
	}
	return modelID, true
}

func writeCatalogGetError(w http.ResponseWriter, modelID string, err error) {
	if errors.Is(err, guard.ErrModelNotFound) {
		writeError(w, http.StatusNotFound, "NOT_FOUND", fmt.Sprintf("Guard model '%s' not found", modelID))
		return
	}
	writeError(w, http.StatusInternalServerError, "CATALOG_GET_FAILED", err.Error())
}

// handleGuardStatus reports the runtime status of the child AI Guard stdio subprocess (GET /admin/guards/status).
func (a *AdminServer) handleGuardStatus(w http.ResponseWriter, r *http.Request) {
	mgr := a.getGuardManager()
	if mgr == nil {
		writeJSON(w, http.StatusOK, guard.ProcessStatus{
			Running:      false,
			HealthStatus: "STOPPED",
		})
		return
	}

	writeJSON(w, http.StatusOK, mgr.Status())
}

// handleListGuardModels lists all catalog guard models with runtime metrics (GET /admin/guards/models).
func (a *AdminServer) handleListGuardModels(w http.ResponseWriter, r *http.Request) {
	catalog := a.requireGuardCatalog(w)
	if catalog == nil {
		return
	}

	models, err := catalog.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "CATALOG_QUERY_FAILED", err.Error())
		return
	}
	if models == nil {
		models = make([]*guard.Model, 0)
	}

	if r.URL.Query().Get("format") == "array" {
		writeJSON(w, http.StatusOK, models)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"models": models})
}

// handleGetGuardModel retrieves a single guard model specification (GET /admin/guards/models/{id}).
func (a *AdminServer) handleGetGuardModel(w http.ResponseWriter, r *http.Request) {
	catalog := a.requireGuardCatalog(w)
	if catalog == nil {
		return
	}
	modelID, ok := requireValidGuardModelID(w, r)
	if !ok {
		return
	}

	m, err := catalog.Get(r.Context(), modelID)
	if err != nil {
		writeCatalogGetError(w, modelID, err)
		return
	}
	writeJSON(w, http.StatusOK, m)
}

// handleDeleteGuardModel purges guard model weights and reverts state to NOT_INSTALLED (DELETE /admin/guards/models/{id}).
func (a *AdminServer) handleDeleteGuardModel(w http.ResponseWriter, r *http.Request) {
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

	mgr := a.getGuardManager()
	if mgr != nil && mgr.Status().ModelID == modelID {
		stopRunningGuardManager(mgr)
	}

	if err := installer.Uninstall(r.Context(), modelID); err != nil {
		if errors.Is(err, guard.ErrModelNotFound) {
			writeError(w, http.StatusNotFound, "NOT_FOUND", fmt.Sprintf("Guard model '%s' not found", modelID))
			return
		}
		writeError(w, http.StatusInternalServerError, "UNINSTALL_FAILED", err.Error())
		return
	}

	a.broadcastGuardStatus("", false, nil)
	a.broadcastGuardModelUpdated(modelID)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "NOT_INSTALLED",
		"model_id": modelID,
		"message":  fmt.Sprintf("Model '%s' uninstalled and weights purged", modelID),
	})
}

// handleGuardPolicyUpdate configures threat enforcement policy and critical tools (POST/PUT /admin/guards/models/{id}/policy).
func (a *AdminServer) handleGuardPolicyUpdate(w http.ResponseWriter, r *http.Request) {
	catalog := a.requireGuardCatalog(w)
	if catalog == nil {
		return
	}
	modelID, ok := requireValidGuardModelID(w, r)
	if !ok {
		return
	}

	if _, err := catalog.Get(r.Context(), modelID); err != nil {
		writeCatalogGetError(w, modelID, err)
		return
	}

	var polReq struct {
		DefaultAction string   `json:"default_action"`
		CriticalTools []string `json:"critical_tools"`
	}
	if err := decodeJSON(w, r, maxSmallAdminBodyBytes, &polReq); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "Failed to parse action policy JSON payload: "+err.Error())
		return
	}

	if polReq.DefaultAction != string(guard.ThreatActionHITL) && polReq.DefaultAction != string(guard.ThreatActionBlock) {
		polReq.DefaultAction = string(guard.ThreatActionHITL)
	}

	sanitizedTools := make([]string, 0, len(polReq.CriticalTools))
	for _, tool := range polReq.CriticalTools {
		trimmed := strings.TrimSpace(tool)
		if trimmed != "" && len(trimmed) <= 128 {
			sanitizedTools = append(sanitizedTools, trimmed)
		}
	}

	critJSON, err := json.Marshal(sanitizedTools)
	if err != nil {
		critJSON = []byte("[]")
	}

	if err := catalog.UpdatePolicy(r.Context(), modelID, guard.ThreatAction(polReq.DefaultAction), string(critJSON)); err != nil {
		writeError(w, http.StatusInternalServerError, "POLICY_UPDATE_FAILED", err.Error())
		return
	}

	a.broadcastGuardModelUpdated(modelID)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":         "updated",
		"model_id":       modelID,
		"default_action": polReq.DefaultAction,
		"critical_tools": sanitizedTools,
	})
}

func stopRunningGuardManager(mgr guard.Manager) {
	if mgr == nil || !mgr.IsRunning() {
		return
	}
	stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = mgr.Stop(stopCtx)
}
