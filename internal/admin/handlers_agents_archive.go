package admin

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/FaradAiLab/FaradAiWire/internal/pathguard"
)

func (a *AdminServer) handleAgentArchives(w http.ResponseWriter, r *http.Request) {
	agentName := r.URL.Query().Get("agent")
	if agentName == "" {
		http.Error(w, "agent query parameter is required", http.StatusBadRequest)
		return
	}

	if err := pathguard.ValidateSafeIdentifier(agentName); err != nil {
		http.Error(w, "Security violation: invalid agent identifier: "+err.Error(), http.StatusBadRequest)
		return
	}

	repo := a.getAgentRepository()
	archives, err := repo.ListAgentArchives(agentName)
	if err != nil {
		http.Error(w, "Security violation or lookup error: "+err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"agent":    agentName,
		"archives": archives,
	})
}

func (a *AdminServer) handleAgentRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req struct {
		AgentName string `json:"agent"`
		Timestamp string `json:"timestamp"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AgentName == "" || req.Timestamp == "" {
		http.Error(w, "Invalid payload. 'agent' and 'timestamp' required", http.StatusBadRequest)
		return
	}

	if err := pathguard.ValidateSafeIdentifier(req.AgentName); err != nil {
		http.Error(w, "Security violation: invalid agent identifier: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := pathguard.ValidateSafeIdentifier(req.Timestamp); err != nil {
		http.Error(w, "Security violation: invalid timestamp identifier: "+err.Error(), http.StatusBadRequest)
		return
	}

	repo := a.getAgentRepository()
	if err := repo.RollbackAgent(req.AgentName, req.Timestamp); err != nil {
		http.Error(w, "Archive snapshot not found: "+err.Error(), http.StatusNotFound)
		return
	}

	a.mu.Lock()
	reloadFn := a.reloadFunc
	a.mu.Unlock()

	if reloadFn != nil {
		if err := reloadFn(); err != nil {
			http.Error(w, "Rollback successful on disk but hot-reload failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": fmt.Sprintf("Agent '%s' successfully rolled back to %s", req.AgentName, req.Timestamp),
	})
}

