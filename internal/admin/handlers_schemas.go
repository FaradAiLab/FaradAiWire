package admin

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/FaradAiLab/FaradAiWire/internal/filter/schema"
	"github.com/FaradAiLab/FaradAiWire/internal/pathguard"
)

// getSchemaStore retrieves the configured DuckDB schema store.
func (a *AdminServer) getSchemaStore() schema.Store {
	return a.schemaStore
}

func requireValidSchemaTool(w http.ResponseWriter, r *http.Request) (string, bool) {
	toolName := strings.TrimSpace(r.PathValue("tool"))
	if err := pathguard.ValidateSafeIdentifier(toolName); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_IDENTIFIER", "Invalid tool name identifier: "+err.Error())
		return "", false
	}
	return toolName, true
}

// handleListSchemas lists all captured tool schemas (GET /admin/schemas).
func (a *AdminServer) handleListSchemas(w http.ResponseWriter, r *http.Request) {
	store := a.getSchemaStore()
	if store == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"schemas": []schema.ToolSchemaRecord{}})
		return
	}

	records, err := store.ListSchemas(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", fmt.Sprintf("Failed to list schemas: %v", err))
		return
	}
	if records == nil {
		records = make([]schema.ToolSchemaRecord, 0)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"schemas": records})
}

// handleGetSchema retrieves a single tool schema record by tool name (GET /admin/schemas/{tool}).
func (a *AdminServer) handleGetSchema(w http.ResponseWriter, r *http.Request) {
	toolName, ok := requireValidSchemaTool(w, r)
	if !ok {
		return
	}

	store := a.getSchemaStore()
	if store == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", fmt.Sprintf("Tool schema '%s' not found", toolName))
		return
	}

	record, err := store.GetSchema(r.Context(), toolName)
	if err != nil {
		if errors.Is(err, schema.ErrSchemaNotFound) {
			writeError(w, http.StatusNotFound, "NOT_FOUND", fmt.Sprintf("Tool schema '%s' not found", toolName))
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", fmt.Sprintf("Failed to query schema for tool '%s': %v", toolName, err))
		return
	}

	writeJSON(w, http.StatusOK, record)
}

// handlePinSchema toggles the pinned state for a tool schema (POST /admin/schemas/{tool}/pin).
func (a *AdminServer) handlePinSchema(w http.ResponseWriter, r *http.Request) {
	toolName, ok := requireValidSchemaTool(w, r)
	if !ok {
		return
	}

	store := a.getSchemaStore()
	if store == nil {
		writeError(w, http.StatusServiceUnavailable, "STORE_UNAVAILABLE", "DuckDB schema store is not configured")
		return
	}

	var payload struct {
		Pinned *bool `json:"pinned"`
	}
	if err := decodeJSON(w, r, maxSmallAdminBodyBytes, &payload); err != nil || payload.Pinned == nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Request body must contain 'pinned' boolean")
		return
	}

	if err := store.PinSchema(r.Context(), toolName, *payload.Pinned); err != nil {
		if errors.Is(err, schema.ErrSchemaNotFound) {
			writeError(w, http.StatusNotFound, "NOT_FOUND", fmt.Sprintf("Tool schema '%s' not found to pin", toolName))
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", fmt.Sprintf("Failed to update pinning for tool '%s': %v", toolName, err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "ok",
		"tool_name": toolName,
		"is_pinned": *payload.Pinned,
	})
}
