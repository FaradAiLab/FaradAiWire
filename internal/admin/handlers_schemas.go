package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/FaradAiLab/FaradAiWire/internal/filter/schema"
	"github.com/FaradAiLab/FaradAiWire/internal/pathguard"
)

// SetSchemaStore assigns the DuckDB schema persistence store to the AdminServer.
func (a *AdminServer) SetSchemaStore(store schema.Store) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.schemaStore = store
}

// getSchemaStore retrieves the configured DuckDB schema store.
func (a *AdminServer) getSchemaStore() schema.Store {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.schemaStore
}

// handleSchemas manages GET /admin/schemas and GET/POST /admin/schemas/{tool_name}[/pin].
func (a *AdminServer) handleSchemas(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	store := a.getSchemaStore()
	relPath := strings.TrimPrefix(r.URL.Path, "/admin/schemas")
	relPath = strings.TrimPrefix(relPath, "/")

	switch r.Method {
	case http.MethodGet:
		if relPath == "" {
			// GET /admin/schemas - list all captured schemas
			if store == nil {
				json.NewEncoder(w).Encode(map[string]interface{}{"schemas": []schema.ToolSchemaRecord{}})
				return
			}
			records, err := store.ListSchemas(r.Context())
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "INTERNAL_ERROR",
					"message": fmt.Sprintf("Failed to list schemas: %v", err),
				})
				return
			}
			if records == nil {
				records = make([]schema.ToolSchemaRecord, 0)
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"schemas": records})
			return
		}

		// GET /admin/schemas/{tool_name}
		toolName := strings.TrimSpace(relPath)
		if err := pathguard.ValidateSafeIdentifier(toolName); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "INVALID_IDENTIFIER",
				"message": "Invalid tool name identifier: " + err.Error(),
			})
			return
		}

		if store == nil {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "NOT_FOUND",
				"message": fmt.Sprintf("Tool schema '%s' not found", toolName),
			})
			return
		}

		record, err := store.GetSchema(r.Context(), toolName)
		if err != nil {
			if errors.Is(err, schema.ErrSchemaNotFound) {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "NOT_FOUND",
					"message": fmt.Sprintf("Tool schema '%s' not found", toolName),
				})
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "INTERNAL_ERROR",
				"message": fmt.Sprintf("Failed to query schema for tool '%s': %v", toolName, err),
			})
			return
		}

		json.NewEncoder(w).Encode(record)
		return

	case http.MethodPost:
		// POST /admin/schemas/{tool_name}/pin
		if !strings.HasSuffix(relPath, "/pin") {
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "METHOD_NOT_ALLOWED",
				"message": "Only /pin sub-endpoint accepts POST",
			})
			return
		}

		toolName := strings.TrimSuffix(relPath, "/pin")
		toolName = strings.TrimSpace(toolName)
		if err := pathguard.ValidateSafeIdentifier(toolName); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "INVALID_IDENTIFIER",
				"message": "Invalid tool name identifier: " + err.Error(),
			})
			return
		}

		if store == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "STORE_UNAVAILABLE",
				"message": "DuckDB schema store is not configured",
			})
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
		var payload struct {
			Pinned *bool `json:"pinned"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.Pinned == nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "BAD_REQUEST",
				"message": "Request body must contain 'pinned' boolean",
			})
			return
		}

		if err := store.PinSchema(r.Context(), toolName, *payload.Pinned); err != nil {
			if errors.Is(err, schema.ErrSchemaNotFound) {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "NOT_FOUND",
					"message": fmt.Sprintf("Tool schema '%s' not found to pin", toolName),
				})
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "INTERNAL_ERROR",
				"message": fmt.Sprintf("Failed to update pinning for tool '%s': %v", toolName, err),
			})
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "ok",
			"tool_name": toolName,
			"is_pinned": *payload.Pinned,
		})
		return

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "METHOD_NOT_ALLOWED",
			"message": "Method not allowed on /admin/schemas",
		})
	}
}
