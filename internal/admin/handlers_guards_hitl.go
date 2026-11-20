package admin

import (
	"fmt"
	"net/http"

	"github.com/FaradAiLab/FaradAiWire/internal/guard"
)

// handleHITLRespond handles REST responses to pending HITL safety approvals.
// Endpoint: POST /admin/guards/hitl/respond
// Body: {"call_id": "...", "approved": true|false}
func (a *AdminServer) handleHITLRespond(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CallID   string `json:"call_id"`
		Approved bool   `json:"approved"`
	}
	if err := decodeJSON(w, r, maxSmallAdminBodyBytes, &req); err != nil || req.CallID == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Request body must contain 'call_id' and 'approved' boolean")
		return
	}

	hitl := a.guardHITL
	if hitl == nil {
		writeError(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "HITL safety dispatcher is not initialized")
		return
	}

	if !hitl.Resolve(req.CallID, req.Approved) {
		writeError(w, http.StatusNotFound, "NOT_FOUND", fmt.Sprintf("Pending HITL approval request '%s' not found or already resolved", req.CallID))
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "resolved",
		"call_id":  req.CallID,
		"approved": req.Approved,
	})
}

// handleHITLPending lists all currently unresolved HITL safety approvals.
// Endpoint: GET /admin/guards/hitl/pending
func (a *AdminServer) handleHITLPending(w http.ResponseWriter, r *http.Request) {
	hitl := a.guardHITL
	if hitl == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"pending": []*guard.HITLRequest{},
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"pending": hitl.ListPending(),
	})
}

// handleWebSocket handles WebSocket connections for the Web Console modal.
func (a *AdminServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	hub := a.wsHub
	if hub == nil {
		http.Error(w, "WebSocket hub unavailable", http.StatusServiceUnavailable)
		return
	}
	hub.ServeHTTP(w, r)
}
