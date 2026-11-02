package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/FaradAiLab/FaradAiWire/internal/auth"
)

// handleAPIKeys manages self-service API key listing, generation, and revocation (SEC-010).
// Endpoints:
//   GET    /admin/api-keys         -> List all keys (metadata only)
//   GET    /admin/api-keys/{id}    -> Get single key metadata
//   POST   /admin/api-keys         -> Generate new key (plaintext returned exactly once)
//   DELETE /admin/api-keys/{id}    -> Revoke key immediately
func (a *AdminServer) handleAPIKeys(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	ks := a.keyStore
	a.mu.RUnlock()

	if ks == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "KEYSTORE_UNAVAILABLE",
			"message": "API key storage is not initialized",
		})
		return
	}

	relPath := strings.TrimPrefix(r.URL.Path, "/admin/api-keys")
	relPath = strings.Trim(relPath, "/")

	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		if relPath == "" {
			keys := ks.ListKeys()
			if keys == nil {
				keys = make([]*auth.KeyMetadata, 0)
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"keys": keys,
			})
			return
		}

		keyMeta, err := ks.GetKey(relPath)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "NOT_FOUND",
				"message": "API key not found",
			})
			return
		}
		json.NewEncoder(w).Encode(keyMeta)
		return

	case http.MethodPost:
		w.Header().Set("Content-Type", "application/json")
		var req struct {
			Name      string `json:"name"`
			Role      string `json:"role"`
			AgentName string `json:"agent_name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "BAD_REQUEST",
				"message": "Invalid request body: " + err.Error(),
			})
			return
		}

		req.Name = strings.TrimSpace(req.Name)
		if req.Name == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "BAD_REQUEST",
				"message": "Key name is required",
			})
			return
		}

		req.Role = strings.TrimSpace(req.Role)
		if req.Role == "" || strings.EqualFold(req.Role, "Admin") {
			req.Role = "Developer"
		}

		rawToken, record, err := ks.GenerateKey(req.Name, req.Role, req.AgentName)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "GENERATE_FAILED",
				"message": err.Error(),
			})
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":         record.ID,
			"name":       record.Name,
			"agent_name": record.AgentName,
			"prefix":     record.Prefix,
			"role":       record.Role,
			"raw_key":    record.RawKey,
			"api_key":    rawToken,
			"key":        rawToken, // Backward-compatible alias for frontend
			"message":    "API key generated successfully",
		})
		return

	case http.MethodDelete:
		w.Header().Set("Content-Type", "application/json")
		keyID := relPath
		if keyID == "" {
			keyID = r.URL.Query().Get("id")
		}
		if keyID == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "BAD_REQUEST",
				"message": "Missing required API key ID parameter",
			})
			return
		}

		if err := ks.RevokeKey(keyID); err != nil {
			if errors.Is(err, auth.ErrKeyNotFound) {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "NOT_FOUND",
					"message": "API key not found",
				})
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "REVOKE_FAILED",
				"message": err.Error(),
			})
			return
		}

		json.NewEncoder(w).Encode(map[string]string{
			"status":  "success",
			"message": "API key successfully revoked",
		})
		return

	default:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "METHOD_NOT_ALLOWED",
			"message": "Method not allowed",
		})
	}
}
