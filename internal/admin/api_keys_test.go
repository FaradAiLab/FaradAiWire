package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/FaradAiLab/FaradAiWire/internal/auth"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
)

func setupTestAdminServerWithKeyStore() (*AdminServer, auth.KeyStore) {
	cfg := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
		AdminPort:   8090,
	}
	keyStore := auth.NewMemoryKeyStore()
	server := NewAdminServer(AdminDependencies{
		Config:          cfg,
		ReloadFunc:      func() error { return nil },
		SchemaClearFunc: func() {},
		KeyStore:        keyStore,
	})
	return server, keyStore
}

func TestAdminAPIKeys_Lifecycle(t *testing.T) {
	server, keyStore := setupTestAdminServerWithKeyStore()
	handler := server.Handler()

	// 1. Initial GET /admin/api-keys: should return empty list (Zero-Auth Open Core)
	req := httptest.NewRequest(http.MethodGet, "/admin/api-keys", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var listResp struct {
		Keys []*auth.KeyMetadata `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("failed to decode GET /admin/api-keys response: %v", err)
	}
	if len(listResp.Keys) != 0 {
		t.Fatalf("expected 0 keys, got %d", len(listResp.Keys))
	}

	// 2. POST /admin/api-keys: Generate a new Developer API Key scoped to agent "Claude"
	genPayload := `{"name": "Cursor Local Agent", "role": "Developer", "agent_name": "Claude"}`
	req = httptest.NewRequest(http.MethodPost, "/admin/api-keys", bytes.NewBufferString(genPayload))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status 201 Created, got %d: %s", rec.Code, rec.Body.String())
	}

	var genResp struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		AgentName string `json:"agent_name"`
		Prefix    string `json:"prefix"`
		Role      string `json:"role"`
		RawKey    string `json:"raw_key"`
		APIKey    string `json:"api_key"`
		Key       string `json:"key"`
		Message   string `json:"message"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &genResp); err != nil {
		t.Fatalf("failed to decode POST /admin/api-keys response: %v", err)
	}

	if genResp.ID == "" {
		t.Errorf("expected non-empty key ID")
	}
	if genResp.Name != "Cursor Local Agent" {
		t.Errorf("expected name 'Cursor Local Agent', got '%s'", genResp.Name)
	}
	if genResp.AgentName != "Claude" {
		t.Errorf("expected agent_name 'Claude', got '%s'", genResp.AgentName)
	}
	if genResp.Role != auth.DefaultIngressRole {
		t.Errorf("expected role %q, got %q", auth.DefaultIngressRole, genResp.Role)
	}
	if !strings.HasPrefix(genResp.APIKey, "faw_live_") {
		t.Errorf("expected raw api_key to start with 'faw_live_', got '%s'", genResp.APIKey)
	}
	if genResp.RawKey != genResp.APIKey {
		t.Errorf("expected raw_key '%s', got '%s'", genResp.APIKey, genResp.RawKey)
	}
	if genResp.Key != genResp.APIKey {
		t.Errorf("expected key alias '%s', got '%s'", genResp.APIKey, genResp.Key)
	}
	if genResp.Prefix != genResp.APIKey[:12] {
		t.Errorf("expected prefix '%s', got '%s'", genResp.APIKey[:12], genResp.Prefix)
	}

	// Verify the key can authenticate against keyStore immediately
	validated, ok := keyStore.ValidateKey(genResp.APIKey)
	if !ok || validated == nil {
		t.Fatalf("expected ValidateKey to succeed for freshly generated key")
	}
	if validated.Role != auth.DefaultIngressRole {
		t.Errorf("expected validated role %q, got %q", auth.DefaultIngressRole, validated.Role)
	}
	if validated.AgentName != "Claude" {
		t.Errorf("expected validated agent_name 'Claude', got '%s'", validated.AgentName)
	}

	// 3. GET /admin/api-keys: Subsequent request must expose raw_key for local developer reveal (ADR-0031), but NEVER hash or salt
	req = httptest.NewRequest(http.MethodGet, "/admin/api-keys", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	bodyStr := rec.Body.String()
	if strings.Contains(bodyStr, "hash") || strings.Contains(bodyStr, "salt") {
		t.Fatalf("CRITICAL SECURITY VIOLATION: Cryptographic hash or salt leaked in GET /admin/api-keys response: %s", bodyStr)
	}

	var listAfterGen struct {
		Keys []*auth.KeyMetadata `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listAfterGen); err != nil {
		t.Fatalf("failed to decode GET /admin/api-keys response: %v", err)
	}
	if len(listAfterGen.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(listAfterGen.Keys))
	}
	if listAfterGen.Keys[0].ID != genResp.ID {
		t.Errorf("expected key ID '%s', got '%s'", genResp.ID, listAfterGen.Keys[0].ID)
	}
	if listAfterGen.Keys[0].AgentName != "Claude" {
		t.Errorf("expected agent_name 'Claude', got '%s'", listAfterGen.Keys[0].AgentName)
	}
	if listAfterGen.Keys[0].RawKey != genResp.APIKey {
		t.Errorf("expected raw_key '%s', got '%s'", genResp.APIKey, listAfterGen.Keys[0].RawKey)
	}
	if listAfterGen.Keys[0].Revoked {
		t.Errorf("expected key to not be revoked")
	}

	// 4. GET /admin/api-keys/{id}: Inspect single key metadata
	req = httptest.NewRequest(http.MethodGet, "/admin/api-keys/"+genResp.ID, nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 for single key query, got %d", rec.Code)
	}
	var singleKey auth.KeyMetadata
	if err := json.Unmarshal(rec.Body.Bytes(), &singleKey); err != nil {
		t.Fatalf("failed to decode single key metadata: %v", err)
	}
	if singleKey.ID != genResp.ID || singleKey.Name != "Cursor Local Agent" {
		t.Errorf("unexpected single key metadata: %+v", singleKey)
	}

	// 5. DELETE /admin/api-keys/{id}: Revoke the key immediately
	req = httptest.NewRequest(http.MethodDelete, "/admin/api-keys/"+genResp.ID, nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 on DELETE, got %d: %s", rec.Code, rec.Body.String())
	}
	var delResp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &delResp); err != nil {
		t.Fatalf("failed to decode DELETE response: %v", err)
	}
	if delResp["status"] != "success" {
		t.Errorf("expected status 'success', got '%s'", delResp["status"])
	}

	// 6. Ingress enforcement: Revoked key MUST immediately fail validation
	_, ok = keyStore.ValidateKey(genResp.APIKey)
	if ok {
		t.Fatalf("CRITICAL: Revoked API key was still validated as active!")
	}

	// 7. Verify GET /admin/api-keys reflects revoked status
	req = httptest.NewRequest(http.MethodGet, "/admin/api-keys", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var listAfterRevoke struct {
		Keys []*auth.KeyMetadata `json:"keys"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &listAfterRevoke)
	if len(listAfterRevoke.Keys) != 1 || !listAfterRevoke.Keys[0].Revoked {
		t.Errorf("expected key to be marked as revoked: %+v", listAfterRevoke.Keys)
	}

	// 8. DELETE on non-existent key returns 404
	req = httptest.NewRequest(http.MethodDelete, "/admin/api-keys/key_non_existent", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for non-existent key revocation, got %d", rec.Code)
	}
}

func TestAdminAPIKeys_RoleSanitization(t *testing.T) {
	server, keyStore := setupTestAdminServerWithKeyStore()
	handler := server.Handler()

	roles := []string{"", "Admin", "admin", "Developer", "SuperUser"}
	for _, requested := range roles {
		t.Run("role_"+requested, func(t *testing.T) {
			payload, _ := json.Marshal(map[string]string{
				"name": "Key " + requested,
				"role": requested,
			})
			req := httptest.NewRequest(http.MethodPost, "/admin/api-keys", bytes.NewReader(payload))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusCreated {
				t.Fatalf("expected status 201 Created, got %d: %s", rec.Code, rec.Body.String())
			}

			var genResp struct {
				Role   string `json:"role"`
				APIKey string `json:"api_key"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &genResp); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}

			if genResp.Role != auth.DefaultIngressRole {
				t.Errorf("requested role %q -> got %q, want %q", requested, genResp.Role, auth.DefaultIngressRole)
			}

			validated, ok := keyStore.ValidateKey(genResp.APIKey)
			if !ok || validated.Role != auth.DefaultIngressRole {
				t.Errorf("keyStore validated role = %q (ok=%v), want %q", validated.Role, ok, auth.DefaultIngressRole)
			}
		})
	}
}

func TestAdminAPIKeys_AdminRawKeyRedactedOnGet(t *testing.T) {
	server, keyStore := setupTestAdminServerWithKeyStore()
	handler := server.Handler()

	adminRaw, adminRec, err := keyStore.GenerateKey("bootstrap-admin", auth.DefaultAdminRole, "*")
	if err != nil {
		t.Fatalf("GenerateKey(Admin): %v", err)
	}
	agentRaw, agentRec, err := keyStore.GenerateKey("cursor-agent", auth.DefaultIngressRole, "cursor")
	if err != nil {
		t.Fatalf("GenerateKey(Agent): %v", err)
	}

	// 1. GET /admin/api-keys must strip raw_key from Admin key but keep prefix and keep Agent raw_key.
	req := httptest.NewRequest(http.MethodGet, "/admin/api-keys", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/api-keys = %d, want 200", rec.Code)
	}
	if strings.Contains(rec.Body.String(), adminRaw) {
		t.Fatal("CRITICAL: raw Admin secret leaked in GET /admin/api-keys response")
	}

	var listResp struct {
		Keys []*auth.KeyMetadata `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	var foundAdmin, foundAgent *auth.KeyMetadata
	for _, k := range listResp.Keys {
		switch k.ID {
		case adminRec.ID:
			foundAdmin = k
		case agentRec.ID:
			foundAgent = k
		}
	}
	if foundAdmin == nil || foundAgent == nil {
		t.Fatalf("expected both Admin and Agent keys in list, got %+v", listResp.Keys)
	}
	if foundAdmin.RawKey != "" {
		t.Errorf("expected Admin key raw_key to be redacted, got %q", foundAdmin.RawKey)
	}
	if foundAdmin.Prefix != adminRaw[:12] {
		t.Errorf("expected Admin key prefix %q, got %q", adminRaw[:12], foundAdmin.Prefix)
	}
	if foundAgent.RawKey != agentRaw {
		t.Errorf("expected Agent key raw_key preserved, got %q", foundAgent.RawKey)
	}

	// 2. GET /admin/api-keys/{adminID} must also redact raw_key.
	singleReq := httptest.NewRequest(http.MethodGet, "/admin/api-keys/"+adminRec.ID, nil)
	singleRec := httptest.NewRecorder()
	handler.ServeHTTP(singleRec, singleReq)
	if singleRec.Code != http.StatusOK {
		t.Fatalf("GET /admin/api-keys/{adminID} = %d, want 200", singleRec.Code)
	}
	if strings.Contains(singleRec.Body.String(), adminRaw) {
		t.Fatal("CRITICAL: raw Admin secret leaked in GET /admin/api-keys/{id}")
	}
	var singleAdmin auth.KeyMetadata
	if err := json.Unmarshal(singleRec.Body.Bytes(), &singleAdmin); err != nil {
		t.Fatalf("decode single admin: %v", err)
	}
	if singleAdmin.RawKey != "" || singleAdmin.Prefix != adminRaw[:12] {
		t.Errorf("unexpected single admin metadata: raw_key=%q prefix=%q", singleAdmin.RawKey, singleAdmin.Prefix)
	}
}

func TestAdminAPIKeys_AdminRevokeCLIOnly(t *testing.T) {
	server, keyStore := setupTestAdminServerWithKeyStore()
	handler := server.Handler()

	adminRaw, adminRec, err := keyStore.GenerateKey("bootstrap-admin", auth.DefaultAdminRole, "*")
	if err != nil {
		t.Fatalf("GenerateKey(Admin): %v", err)
	}
	_, agentRec, err := keyStore.GenerateKey("cursor-agent", auth.DefaultIngressRole, "cursor")
	if err != nil {
		t.Fatalf("GenerateKey(Agent): %v", err)
	}

	for _, target := range []string{"/admin/api-keys/" + adminRec.ID, "/admin/api-keys?id=" + adminRec.ID} {
		t.Run("DELETE_"+target, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodDelete, target, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("DELETE %s = %d, want 403 (%s)", target, rec.Code, rec.Body.String())
			}
			var errResp map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
				t.Fatalf("decode error JSON: %v", err)
			}
			if errResp["error"] != "ADMIN_KEY_CLI_ONLY" {
				t.Errorf("error = %q, want ADMIN_KEY_CLI_ONLY", errResp["error"])
			}
		})
	}

	// Admin key must remain active.
	if _, ok := keyStore.ValidateKey(adminRaw); !ok {
		t.Fatal("Admin key should remain active after rejected HTTP DELETE")
	}

	// Agent key revocation must still succeed.
	delAgentReq := httptest.NewRequest(http.MethodDelete, "/admin/api-keys/"+agentRec.ID, nil)
	delAgentRec := httptest.NewRecorder()
	handler.ServeHTTP(delAgentRec, delAgentReq)
	if delAgentRec.Code != http.StatusOK {
		t.Fatalf("DELETE agent key = %d, want 200 (%s)", delAgentRec.Code, delAgentRec.Body.String())
	}
}
