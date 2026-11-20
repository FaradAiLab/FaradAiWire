package admin

import (
	"fmt"
	"net/http"

	"github.com/FaradAiLab/FaradAiWire/internal/pathguard"
)

func (a *AdminServer) handleAgentArchives(w http.ResponseWriter, r *http.Request) {
	agentName := r.URL.Query().Get("agent")
	if agentName == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "agent query parameter is required")
		return
	}

	if err := pathguard.ValidateSafeIdentifier(agentName); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_IDENTIFIER", "Security violation: invalid agent identifier: "+err.Error())
		return
	}

	repo := a.requireAgentRepository(w)
	if repo == nil {
		return
	}
	archives, err := repo.ListAgentArchives(agentName)
	if err != nil {
		writeError(w, http.StatusBadRequest, "ARCHIVE_LOOKUP_FAILED", "Security violation or lookup error: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"agent":    agentName,
		"archives": archives,
	})
}

func (a *AdminServer) handleAgentRollback(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AgentName string `json:"agent"`
		Timestamp string `json:"timestamp"`
	}
	if err := decodeJSON(w, r, maxAdminBodyBytes, &req); err != nil || req.AgentName == "" || req.Timestamp == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid payload. 'agent' and 'timestamp' required")
		return
	}

	if err := pathguard.ValidateSafeIdentifier(req.AgentName); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_IDENTIFIER", "Security violation: invalid agent identifier: "+err.Error())
		return
	}
	if err := pathguard.ValidateSafeIdentifier(req.Timestamp); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_IDENTIFIER", "Security violation: invalid timestamp identifier: "+err.Error())
		return
	}

	repo := a.requireAgentRepository(w)
	if repo == nil {
		return
	}
	if err := repo.RollbackAgent(req.AgentName, req.Timestamp); err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "Archive snapshot not found: "+err.Error())
		return
	}

	if a.reloadFunc != nil {
		if err := a.reloadFunc(); err != nil {
			writeError(w, http.StatusInternalServerError, "RELOAD_FAILED", "Rollback successful on disk but hot-reload failed: "+err.Error())
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"message": fmt.Sprintf("Agent '%s' successfully rolled back to %s", req.AgentName, req.Timestamp),
	})
}
