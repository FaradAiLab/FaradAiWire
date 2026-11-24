package admin

import (
	"cmp"
	"errors"
	"net/http"
	"strings"

	"github.com/FaradAiLab/FaradAiWire/internal/auth"
)

func (a *AdminServer) requireKeyStore(w http.ResponseWriter) auth.KeyStore {
	ks := a.keyStore
	if ks == nil {
		writeError(w, http.StatusServiceUnavailable, "KEYSTORE_UNAVAILABLE", "API key storage is not initialized")
		return nil
	}
	return ks
}

func redactAdminKeyMetadata(meta *auth.KeyMetadata) *auth.KeyMetadata {
	if meta == nil {
		return nil
	}
	cp := *meta
	if auth.IsAdminRole(cp.Role) {
		cp.RawKey = ""
	}
	return &cp
}

// handleListAPIKeys returns metadata for all registered API keys (GET /admin/api-keys).
func (a *AdminServer) handleListAPIKeys(w http.ResponseWriter, _ *http.Request) {
	ks := a.requireKeyStore(w)
	if ks == nil {
		return
	}

	rawKeys := ks.ListKeys()
	keys := make([]*auth.KeyMetadata, 0, len(rawKeys))
	for _, k := range rawKeys {
		if k != nil {
			keys = append(keys, redactAdminKeyMetadata(k))
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"keys": keys})
}

// handleGetAPIKey returns metadata for a single API key (GET /admin/api-keys/{id}).
func (a *AdminServer) handleGetAPIKey(w http.ResponseWriter, r *http.Request) {
	ks := a.requireKeyStore(w)
	if ks == nil {
		return
	}

	keyMeta, err := ks.GetKey(strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "API key not found")
		return
	}
	writeJSON(w, http.StatusOK, redactAdminKeyMetadata(keyMeta))
}

// handleCreateAPIKey generates a new scoped Agent ingress API key (POST /admin/api-keys).
func (a *AdminServer) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	ks := a.requireKeyStore(w)
	if ks == nil {
		return
	}

	var req struct {
		Name      string `json:"name"`
		Role      string `json:"role"`
		AgentName string `json:"agent_name"`
	}
	if err := decodeJSON(w, r, maxAdminBodyBytes, &req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid request body: "+err.Error())
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Key name is required")
		return
	}

	// All API keys minted over HTTP are strictly scoped to the Agent ingress role.
	req.Role = auth.DefaultIngressRole

	rawToken, record, err := ks.GenerateKey(req.Name, req.Role, req.AgentName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "GENERATE_FAILED", err.Error())
		return
	}

	a.logSecurityAudit(r, "api_key_created", "create", "api_key", record.ID, "allowed", "API key generated", map[string]any{
		"name":       record.Name,
		"role":       record.Role,
		"agent_name": record.AgentName,
		"prefix":     record.Prefix,
	})

	writeJSON(w, http.StatusCreated, map[string]interface{}{
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
}

// handleRevokeAPIKey revokes an existing non-Admin API key immediately (DELETE /admin/api-keys/{id} or ?id=...).
func (a *AdminServer) handleRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	ks := a.requireKeyStore(w)
	if ks == nil {
		return
	}

	keyID := cmp.Or(strings.TrimSpace(r.PathValue("id")), strings.TrimSpace(r.URL.Query().Get("id")))
	if keyID == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Missing required API key ID parameter")
		return
	}

	keyMeta, err := ks.GetKey(keyID)
	if err != nil {
		if errors.Is(err, auth.ErrKeyNotFound) {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "API key not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "REVOKE_FAILED", err.Error())
		return
	}
	if auth.IsAdminRole(keyMeta.Role) {
		a.logSecurityAudit(r, "api_key_revoke_denied", "revoke", "api_key", keyID, "denied", "admin_key_cli_only", nil)
		writeError(w, http.StatusForbidden, "ADMIN_KEY_CLI_ONLY", "Admin keys can only be rotated via CLI: faradaiwire token --rotate")
		return
	}

	if err := ks.RevokeKey(keyID); err != nil {
		if errors.Is(err, auth.ErrKeyNotFound) {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "API key not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "REVOKE_FAILED", err.Error())
		return
	}

	a.logSecurityAudit(r, "api_key_revoked", "revoke", "api_key", keyID, "allowed", "API key revoked", nil)

	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "success",
		"message": "API key successfully revoked",
	})
}
