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
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.guardCatalog
}

func (a *AdminServer) getGuardManager() guard.Manager {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.guardManager
}

func (a *AdminServer) getGuardInstaller() guard.ModelInstaller {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.guardInstaller
}

// handleGuardStatus reports the runtime status of the child SLM Stdio guard subprocess.
// Endpoint:
//   GET /admin/guards/status
func (a *AdminServer) handleGuardStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "METHOD_NOT_ALLOWED",
			"message": "Only GET method is supported for guard status",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	mgr := a.getGuardManager()
	if mgr == nil {
		json.NewEncoder(w).Encode(guard.ProcessStatus{
			Running:      false,
			HealthStatus: "STOPPED",
		})
		return
	}

	status := mgr.Status()
	json.NewEncoder(w).Encode(status)
}

// handleGuardModels manages administrative query and lifecycle endpoints for Guard Models.
// Endpoints:
//   GET    /admin/guards/models               -> List all catalog models with metrics
//   GET    /admin/guards/models/{id}          -> Retrieve single model specification
//   POST   /admin/guards/models/{id}/install  -> Trigger asynchronous runtime bootstrap and model staging
//   GET    /admin/guards/models/{id}/progress -> Check installation progress
//   POST   /admin/guards/models/{id}/activate -> Zero-downtime hot-swap and process activation
//   POST   /admin/guards/models/deactivate    -> Deactivate active model; switch to L1-Only mode
//   POST   /admin/guards/models/{id}/deactivate -> Deactivate specific model
//   POST   /admin/guards/models/{id}/policy   -> Configure threat enforcement policy and critical tools
//   DELETE /admin/guards/models/{id}          -> Purge model weights and revert state to NOT_INSTALLED
func (a *AdminServer) handleGuardModels(w http.ResponseWriter, r *http.Request) {
	catalog := a.getGuardCatalog()
	if catalog == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "GUARD_CATALOG_UNAVAILABLE",
			"message": "Guard model catalog is not initialized or database is unavailable",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	relPath := strings.TrimPrefix(r.URL.Path, "/admin/guards/models")
	relPath = strings.Trim(relPath, "/")

	// 1. List all models: GET /admin/guards/models
	if relPath == "" {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "METHOD_NOT_ALLOWED",
				"message": "Only GET method is supported for catalog browsing",
			})
			return
		}

		models, err := catalog.List(r.Context())
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "CATALOG_QUERY_FAILED",
				"message": err.Error(),
			})
			return
		}
		if models == nil {
			models = make([]*guard.Model, 0)
		}

		if r.URL.Query().Get("format") == "array" {
			json.NewEncoder(w).Encode(models)
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"models": models,
		})
		return
	}

	// 2. Global deactivate route: POST /admin/guards/models/deactivate
	if relPath == "deactivate" {
		a.handleGuardDeactivateGlobal(w, r, catalog)
		return
	}

	// 3. Model connect route: POST /admin/guards/models/{id}/connect
	if strings.HasSuffix(relPath, "/connect") {
		modelID := strings.TrimSuffix(relPath, "/connect")
		modelID = strings.Trim(modelID, "/")
		a.handleGuardConnect(w, r, catalog, modelID)
		return
	}

	// 4. Model activate route: POST /admin/guards/models/{id}/activate
	if strings.HasSuffix(relPath, "/activate") {
		modelID := strings.TrimSuffix(relPath, "/activate")
		modelID = strings.Trim(modelID, "/")
		a.handleGuardActivate(w, r, catalog, modelID)
		return
	}

	// 5. Specific model deactivate route: POST /admin/guards/models/{id}/deactivate
	if strings.HasSuffix(relPath, "/deactivate") {
		modelID := strings.TrimSuffix(relPath, "/deactivate")
		modelID = strings.Trim(modelID, "/")
		a.handleGuardDeactivateModel(w, r, catalog, modelID)
		return
	}

	// 6. Action Policy Drawer route: POST/PUT /admin/guards/models/{id}/policy
	if strings.HasSuffix(relPath, "/policy") {
		a.handleGuardPolicyUpdate(w, r, catalog, relPath)
		return
	}

	// 7. Handle /install and /progress sub-routes
	if strings.HasSuffix(relPath, "/install") || strings.HasSuffix(relPath, "/progress") {
		a.handleGuardInstallOrProgress(w, r, catalog, relPath)
		return
	}

	// 8. Direct model endpoints: GET /admin/guards/models/{id} or DELETE /admin/guards/models/{id}
	if err := pathguard.ValidateSafeIdentifier(relPath); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "INVALID_MODEL_ID",
			"message": "Invalid model ID format: " + err.Error(),
		})
		return
	}

	switch r.Method {
	case http.MethodGet:
		m, err := catalog.Get(r.Context(), relPath)
		if err != nil {
			if errors.Is(err, guard.ErrModelNotFound) {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "NOT_FOUND",
					"message": fmt.Sprintf("Guard model '%s' not found in catalog", relPath),
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
		json.NewEncoder(w).Encode(m)
		return

	case http.MethodDelete:
		installer := a.getGuardInstaller()
		if installer == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "INSTALLER_UNAVAILABLE",
				"message": "Guard model installer is not initialized",
			})
			return
		}

		mgr := a.getGuardManager()
		if mgr != nil && mgr.Status().ModelID == relPath && mgr.IsRunning() {
			stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = mgr.Stop(stopCtx)
			cancel()
		}

		if err := installer.Uninstall(r.Context(), relPath); err != nil {
			if errors.Is(err, guard.ErrModelNotFound) {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "NOT_FOUND",
					"message": fmt.Sprintf("Guard model '%s' not found", relPath),
				})
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "UNINSTALL_FAILED",
				"message": err.Error(),
			})
			return
		}

		hub := a.WSHub()
		if hub != nil {
			hub.Broadcast(map[string]interface{}{
				"type":            "GUARD_STATUS_CHANGED",
				"active_model_id": "",
				"running":         false,
			})
			hub.Broadcast(map[string]interface{}{
				"type":     "GUARD_MODEL_UPDATED",
				"model_id": relPath,
			})
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "NOT_INSTALLED",
			"model_id": relPath,
			"message":  fmt.Sprintf("Model '%s' uninstalled and weights purged", relPath),
		})
		return

	default:
		w.Header().Set("Allow", "GET, DELETE")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "METHOD_NOT_ALLOWED",
			"message": "Only GET and DELETE methods are supported for model details",
		})
		return
	}
}

// handleGuardPolicyUpdate handles threat policy configuration for a model.
// POST/PUT /admin/guards/models/{id}/policy
func (a *AdminServer) handleGuardPolicyUpdate(w http.ResponseWriter, r *http.Request, catalog guard.CatalogStore, relPath string) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		w.Header().Set("Allow", "POST, PUT")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "METHOD_NOT_ALLOWED",
			"message": "Only POST and PUT methods are supported for policy configuration",
		})
		return
	}

	modelID := strings.TrimSuffix(relPath, "/policy")
	modelID = strings.Trim(modelID, "/")
	if err := pathguard.ValidateSafeIdentifier(modelID); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "INVALID_MODEL_ID",
			"message": "Invalid model ID format: " + err.Error(),
		})
		return
	}

	_, err := catalog.Get(r.Context(), modelID)
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

	var polReq struct {
		DefaultAction string   `json:"default_action"`
		CriticalTools []string `json:"critical_tools"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	if err := json.NewDecoder(r.Body).Decode(&polReq); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "INVALID_JSON",
			"message": "Failed to parse action policy JSON payload: " + err.Error(),
		})
		return
	}

	if polReq.DefaultAction != string(guard.ThreatActionHITL) && polReq.DefaultAction != string(guard.ThreatActionBlock) {
		polReq.DefaultAction = string(guard.ThreatActionHITL)
	}

	var sanitizedTools []string
	for _, tool := range polReq.CriticalTools {
		trimmed := strings.TrimSpace(tool)
		if trimmed != "" && len(trimmed) <= 128 {
			sanitizedTools = append(sanitizedTools, trimmed)
		}
	}
	if sanitizedTools == nil {
		sanitizedTools = []string{}
	}

	critJSON, err := json.Marshal(sanitizedTools)
	if err != nil {
		critJSON = []byte("[]")
	}

	if err := catalog.UpdatePolicy(r.Context(), modelID, guard.ThreatAction(polReq.DefaultAction), string(critJSON)); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "POLICY_UPDATE_FAILED",
			"message": err.Error(),
		})
		return
	}

	hub := a.WSHub()
	if hub != nil {
		hub.Broadcast(map[string]interface{}{
			"type":     "GUARD_MODEL_UPDATED",
			"model_id": modelID,
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         "updated",
		"model_id":       modelID,
		"default_action": polReq.DefaultAction,
		"critical_tools": sanitizedTools,
	})
}
