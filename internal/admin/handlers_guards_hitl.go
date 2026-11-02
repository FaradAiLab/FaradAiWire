package admin

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/FaradAiLab/FaradAiWire/internal/guard"
)

// handleHITLRespond handles REST responses to pending HITL safety approvals.
// Endpoint: POST /admin/guards/hitl/respond
// Body: {"call_id": "...", "approved": true|false}
func (a *AdminServer) handleHITLRespond(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "METHOD_NOT_ALLOWED",
			"message": "Only POST method is supported for HITL response",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	var req struct {
		CallID   string `json:"call_id"`
		Approved bool   `json:"approved"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.CallID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "INVALID_REQUEST",
			"message": "Request body must contain 'call_id' and 'approved' boolean",
		})
		return
	}

	a.mu.RLock()
	hitl := a.guardHITL
	a.mu.RUnlock()

	if hitl == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "SERVICE_UNAVAILABLE",
			"message": "HITL safety dispatcher is not initialized",
		})
		return
	}

	resolved := hitl.Resolve(req.CallID, req.Approved)
	if !resolved {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "NOT_FOUND",
			"message": fmt.Sprintf("Pending HITL approval request '%s' not found or already resolved", req.CallID),
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "resolved",
		"call_id":  req.CallID,
		"approved": req.Approved,
	})
}

// handleHITLPending lists all currently unresolved HITL safety approvals.
// Endpoint: GET /admin/guards/hitl/pending
func (a *AdminServer) handleHITLPending(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "METHOD_NOT_ALLOWED",
			"message": "Only GET method is supported for pending approvals",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	a.mu.RLock()
	hitl := a.guardHITL
	a.mu.RUnlock()

	if hitl == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"pending": []*guard.HITLRequest{},
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"pending": hitl.ListPending(),
	})
}

// handleWebSocket handles WebSocket connections for the Web Console modal.
func (a *AdminServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	hub := a.wsHub
	a.mu.RUnlock()

	if hub == nil {
		http.Error(w, "WebSocket hub unavailable", http.StatusServiceUnavailable)
		return
	}
	hub.ServeHTTP(w, r)
}

