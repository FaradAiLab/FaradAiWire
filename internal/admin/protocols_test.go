package admin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/auth"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/protocol"
	"github.com/FaradAiLab/FaradAiWire/internal/transport"
)

func newTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("skipping test requiring loopback socket: %v", err)
		return nil
	}
	ts := httptest.NewUnstartedServer(handler)
	ts.Listener = l
	ts.Start()
	return ts
}

func setupTestAdminServerWithProtocols(t *testing.T, runtimeMode string) (*AdminServer, string, string) {
	tmpProtocolsDir := t.TempDir()
	tmpAgentsDir := t.TempDir()

	cfg := &config.Config{
		RuntimeMode:  runtimeMode,
		ProtocolsDir: tmpProtocolsDir,
		AgentsDir:    tmpAgentsDir,
	}

	server := NewAdminServer(cfg, func() error { return nil }, func() {})
	server.SetKeyStore(auth.NewMemoryKeyStore())

	store, err := protocol.NewFSStore(tmpProtocolsDir)
	if err != nil {
		t.Fatalf("failed to create protocol store: %v", err)
	}

	repo := agent.NewFSRepository(tmpAgentsDir)
	server.SetAgentRepository(repo)

	// Wire referential integrity
	store.SetAgentUsageChecker(func(protocolID string) ([]string, error) {
		agentNames, err := repo.ListAgents()
		if err != nil {
			return nil, err
		}
		var inUse []string
		for _, name := range agentNames {
			if name == "archive" || name == "agents" || name == "temp" {
				continue
			}
			agentCfg, err := repo.GetAgentConfig(name)
			if err != nil || agentCfg == nil {
				continue
			}
			for _, p := range agentCfg.Protocols {
				if strings.EqualFold(p.ID, protocolID) || strings.EqualFold(p.Name, protocolID) {
					inUse = append(inUse, name)
					break
				}
			}
		}
		return inUse, nil
	})

	server.SetProtocolStore(store)
	return server, tmpProtocolsDir, tmpAgentsDir
}

func TestProtocolEndpoints_Presets(t *testing.T) {
	server, _, _ := setupTestAdminServerWithProtocols(t, config.RuntimeModeStandalone)
	handler := server.Handler()

	// 1. GET /admin/protocols/presets returns 200 OK and presets list
	req := httptest.NewRequest(http.MethodGet, "/admin/protocols/presets", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Presets []protocol.PresetMetadata `json:"presets"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode presets: %v", err)
	}

	if len(resp.Presets) < 20 {
		t.Errorf("expected at least 20 presets, got %d", len(resp.Presets))
	}

	// Verify Context7 is prominently featured
	var foundContext7 bool
	for _, p := range resp.Presets {
		if p.ID == "context7" {
			foundContext7 = true
			if p.Type != "http" || p.URL != "https://mcp.context7.com/mcp" {
				t.Errorf("unexpected Context7 preset definition: %+v", p)
			}
		}
	}
	if !foundContext7 {
		t.Errorf("expected Context7 to be included in presets catalog")
	}

	// 2. POST /admin/protocols/presets should return 405 Method Not Allowed
	postReq := httptest.NewRequest(http.MethodPost, "/admin/protocols/presets", bytes.NewBufferString("{}"))
	postRec := httptest.NewRecorder()
	handler.ServeHTTP(postRec, postReq)

	if postRec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for POST to presets, got %d", postRec.Code)
	}
}

func TestProtocolEndpoints_CRUD_Lifecycle(t *testing.T) {
	server, protoDir, _ := setupTestAdminServerWithProtocols(t, config.RuntimeModeStandalone)
	handler := server.Handler()

	// 1. GET /admin/protocols initially empty
	req := httptest.NewRequest(http.MethodGet, "/admin/protocols", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var listResp struct {
		Protocols []*protocol.Protocol `json:"protocols"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if len(listResp.Protocols) != 0 {
		t.Errorf("expected 0 protocols, got %d", len(listResp.Protocols))
	}

	// 2. POST /admin/protocols - Create valid protocol with secret
	createPayload := `{
		"id": "github",
		"name": "GitHub Workspace",
		"description": "Access GitHub repos",
		"type": "stdio",
		"command": "npx",
		"args": ["-y", "@modelcontextprotocol/server-github"],
		"env": ["GITHUB_TOKEN=ghp_live_secret_token_1234567890"],
		"allowed_tools": ["create_issue", "get_repo"]
	}`
	postReq := httptest.NewRequest(http.MethodPost, "/admin/protocols", bytes.NewBufferString(createPayload))
	postReq.Header.Set("Content-Type", "application/json")
	postRec := httptest.NewRecorder()
	handler.ServeHTTP(postRec, postReq)

	if postRec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", postRec.Code, postRec.Body.String())
	}

	var createResp struct {
		Status   string             `json:"status"`
		Protocol *protocol.Protocol `json:"protocol"`
	}
	if err := json.Unmarshal(postRec.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Secret in response must be masked
	if len(createResp.Protocol.Env) != 1 || !strings.Contains(createResp.Protocol.Env[0], "••••••") {
		t.Errorf("expected secret to be masked in response, got %v", createResp.Protocol.Env)
	}

	// Check file on disk: 0600 permissions and unmasked original token
	filePath := filepath.Join(protoDir, "github.json")
	info, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("expected protocol file to exist: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("expected 0600 file permissions, got %o", perm)
	}
	diskData, _ := os.ReadFile(filePath)
	if !strings.Contains(string(diskData), "ghp_live_secret_token_1234567890") {
		t.Errorf("expected disk file to store unmasked raw secret")
	}

	// 3. POST duplicate ID -> 409 Conflict
	dupReq := httptest.NewRequest(http.MethodPost, "/admin/protocols", bytes.NewBufferString(createPayload))
	dupReq.Header.Set("Content-Type", "application/json")
	dupRec := httptest.NewRecorder()
	handler.ServeHTTP(dupRec, dupReq)

	if dupRec.Code != http.StatusConflict {
		t.Errorf("expected 409 Conflict on duplicate ID, got %d", dupRec.Code)
	}

	// 4. POST invalid ID -> 400 Bad Request
	badPayload := `{"id": "../invalid-name", "name": "Bad", "type": "stdio", "command": "ls"}`
	badReq := httptest.NewRequest(http.MethodPost, "/admin/protocols", bytes.NewBufferString(badPayload))
	badReq.Header.Set("Content-Type", "application/json")
	badRec := httptest.NewRecorder()
	handler.ServeHTTP(badRec, badReq)

	if badRec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request on invalid ID, got %d", badRec.Code)
	}

	// 5. GET /admin/protocols/github - Single retrieval with masked secret
	getSingleReq := httptest.NewRequest(http.MethodGet, "/admin/protocols/github", nil)
	getSingleRec := httptest.NewRecorder()
	handler.ServeHTTP(getSingleRec, getSingleReq)

	if getSingleRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", getSingleRec.Code)
	}
	var singleProto protocol.Protocol
	if err := json.Unmarshal(getSingleRec.Body.Bytes(), &singleProto); err != nil {
		t.Fatalf("failed to decode single protocol: %v", err)
	}
	if singleProto.ID != "github" || !strings.Contains(singleProto.Env[0], "••••••") {
		t.Errorf("unexpected single protocol response: %+v", singleProto)
	}

	// 6. PUT /admin/protocols/github - Update description, preserve secret when sending masked value
	updatePayload := `{
		"name": "GitHub Workspace (Updated)",
		"description": "Updated description",
		"type": "stdio",
		"command": "npx",
		"args": ["-y", "@modelcontextprotocol/server-github"],
		"env": ["GITHUB_TOKEN=ghp_••••••"],
		"allowed_tools": ["create_issue"]
	}`
	putReq := httptest.NewRequest(http.MethodPut, "/admin/protocols/github", bytes.NewBufferString(updatePayload))
	putReq.Header.Set("Content-Type", "application/json")
	putRec := httptest.NewRecorder()
	handler.ServeHTTP(putRec, putReq)

	if putRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on PUT, got %d: %s", putRec.Code, putRec.Body.String())
	}

	// Verify that the disk still holds the original unmasked token
	diskDataAfterPut, _ := os.ReadFile(filePath)
	if !strings.Contains(string(diskDataAfterPut), "ghp_live_secret_token_1234567890") {
		t.Errorf("original secret was overwritten by masked placeholder!")
	}
	if !strings.Contains(string(diskDataAfterPut), "GitHub Workspace (Updated)") {
		t.Errorf("expected updated name on disk")
	}

	// 7. DELETE /admin/protocols/github
	delReq := httptest.NewRequest(http.MethodDelete, "/admin/protocols/github", nil)
	delRec := httptest.NewRecorder()
	handler.ServeHTTP(delRec, delReq)

	if delRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on DELETE, got %d: %s", delRec.Code, delRec.Body.String())
	}

	// Check file is removed
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Errorf("expected protocol file to be removed")
	}

	// 8. GET /admin/protocols/github now returns 404
	getGoneReq := httptest.NewRequest(http.MethodGet, "/admin/protocols/github", nil)
	getGoneRec := httptest.NewRecorder()
	handler.ServeHTTP(getGoneRec, getGoneReq)

	if getGoneRec.Code != http.StatusNotFound {
		t.Errorf("expected 404 Not Found, got %d", getGoneRec.Code)
	}
}

func TestProtocolEndpoints_ReferentialIntegrity(t *testing.T) {
	server, protoDir, agentsDir := setupTestAdminServerWithProtocols(t, config.RuntimeModeStandalone)
	handler := server.Handler()

	// 1. Create a protocol directly on disk
	proto := &protocol.Protocol{
		ID:      "db-proto",
		Name:    "Database Protocol",
		Type:    "stdio",
		Command: "sqlite3",
	}
	if err := server.getProtocolStore().Save(proto); err != nil {
		t.Fatalf("failed to save proto: %v", err)
	}

	// 2. Create an agent referencing "db-proto"
	agentDir := filepath.Join(agentsDir, "agent-finance", "current")
	if err := os.MkdirAll(agentDir, 0755); err != nil {
		t.Fatalf("failed to create agent dir: %v", err)
	}
	agentConfigJSON := `{
		"agent_id": "finance-01",
		"agent_name": "agent-finance",
		"routing_mode": "aggregated",
		"protocols": [
			{
				"protocol_id": "db-proto",
				"protocol_name": "db",
				"type": "stdio",
				"command": "sqlite3"
			}
		]
	}`
	if err := os.WriteFile(filepath.Join(agentDir, "config.json"), []byte(agentConfigJSON), 0644); err != nil {
		t.Fatalf("failed to write agent config: %v", err)
	}

	// 3. Attempt to DELETE protocol "db-proto"
	delReq := httptest.NewRequest(http.MethodDelete, "/admin/protocols/db-proto", nil)
	delRec := httptest.NewRecorder()
	handler.ServeHTTP(delRec, delReq)

	// Must be blocked with 409 Conflict
	if delRec.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict due to referential integrity, got %d: %s", delRec.Code, delRec.Body.String())
	}

	var errResp map[string]string
	if err := json.Unmarshal(delRec.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to decode error JSON: %v", err)
	}
	if errResp["error"] != "PROTOCOL_IN_USE" || !strings.Contains(errResp["message"], "agent-finance") {
		t.Errorf("unexpected error payload: %+v", errResp)
	}

	// File must still exist
	filePath := filepath.Join(protoDir, "db-proto.json")
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		t.Errorf("file should not have been deleted")
	}
}

func TestProtocolEndpoints_ManagedMode(t *testing.T) {
	server, _, _ := setupTestAdminServerWithProtocols(t, config.RuntimeModeManaged)
	handler := server.Handler()

	// 1. GET /admin/protocols is allowed (read-only)
	getReq := httptest.NewRequest(http.MethodGet, "/admin/protocols", nil)
	getRec := httptest.NewRecorder()
	handler.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Errorf("expected 200 OK for GET in managed mode, got %d", getRec.Code)
	}

	// 2. GET /admin/protocols/presets is allowed
	presetReq := httptest.NewRequest(http.MethodGet, "/admin/protocols/presets", nil)
	presetRec := httptest.NewRecorder()
	handler.ServeHTTP(presetRec, presetReq)
	if presetRec.Code != http.StatusOK {
		t.Errorf("expected 200 OK for presets in managed mode, got %d", presetRec.Code)
	}

	// 3. POST /admin/protocols is blocked (403 Forbidden)
	postReq := httptest.NewRequest(http.MethodPost, "/admin/protocols", bytes.NewBufferString(`{"id":"p1","name":"P1","type":"stdio","command":"ls"}`))
	postRec := httptest.NewRecorder()
	handler.ServeHTTP(postRec, postReq)
	if postRec.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for POST in managed mode, got %d", postRec.Code)
	}

	// 4. PUT /admin/protocols/p1 is blocked (403 Forbidden)
	putReq := httptest.NewRequest(http.MethodPut, "/admin/protocols/p1", bytes.NewBufferString(`{"name":"P1 Updated","type":"stdio","command":"ls"}`))
	putRec := httptest.NewRecorder()
	handler.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for PUT in managed mode, got %d", putRec.Code)
	}

	// 5. DELETE /admin/protocols/p1 is blocked (403 Forbidden)
	delReq := httptest.NewRequest(http.MethodDelete, "/admin/protocols/p1", nil)
	delRec := httptest.NewRecorder()
	handler.ServeHTTP(delRec, delReq)
	if delRec.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for DELETE in managed mode, got %d", delRec.Code)
	}
}

func TestProtocolEndpoints_Probe_SSRF_Protection(t *testing.T) {
	server, _, _ := setupTestAdminServerWithProtocols(t, config.RuntimeModeStandalone)
	handler := server.Handler()

	blockedURLs := []string{
		"http://10.0.0.1/sse",
		"http://192.168.1.1/mcp",
		"http://172.16.0.1/sse",
		"http://127.0.0.1:8080/sse",
		"http://localhost:8080/sse",
		"file:///etc/passwd",
		"gopher://127.0.0.1:6379",
	}

	for _, u := range blockedURLs {
		t.Run("Blocked_"+u, func(t *testing.T) {
			payload := map[string]string{
				"type": "sse",
				"url":  u,
			}
			body, _ := json.Marshal(payload)
			req := httptest.NewRequest(http.MethodPost, "/admin/protocols/probe", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 Bad Request for SSRF target '%s', got %d: %s", u, rec.Code, rec.Body.String())
			}

			var resp map[string]interface{}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}
			if resp["error"] != "SSRF_VIOLATION" {
				t.Errorf("expected error SSRF_VIOLATION, got %v", resp["error"])
			}
		})
	}
}

func TestProtocolEndpoints_Probe_Validation(t *testing.T) {
	server, _, _ := setupTestAdminServerWithProtocols(t, config.RuntimeModeStandalone)
	handler := server.Handler()

	tests := []struct {
		name         string
		method       string
		body         string
		expectedCode int
		expectedErr  string
	}{
		{
			name:         "Method Not Allowed (GET)",
			method:       http.MethodGet,
			body:         "",
			expectedCode: http.StatusMethodNotAllowed,
			expectedErr:  "METHOD_NOT_ALLOWED",
		},
		{
			name:         "Malformed JSON",
			method:       http.MethodPost,
			body:         "{invalid",
			expectedCode: http.StatusBadRequest,
			expectedErr:  "BAD_REQUEST",
		},
		{
			name:         "Missing command for stdio",
			method:       http.MethodPost,
			body:         `{"type": "stdio"}`,
			expectedCode: http.StatusBadRequest,
			expectedErr:  "BAD_REQUEST",
		},
		{
			name:         "Missing URL for sse",
			method:       http.MethodPost,
			body:         `{"type": "sse"}`,
			expectedCode: http.StatusBadRequest,
			expectedErr:  "BAD_REQUEST",
		},
		{
			name:         "Unsupported protocol type",
			method:       http.MethodPost,
			body:         `{"type": "grpc"}`,
			expectedCode: http.StatusBadRequest,
			expectedErr:  "BAD_REQUEST",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/admin/protocols/probe", bytes.NewBufferString(tc.body))
			if tc.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tc.expectedCode {
				t.Errorf("expected status %d, got %d: %s", tc.expectedCode, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestProtocolEndpoints_Probe_Stdio_Live(t *testing.T) {
	server, _, _ := setupTestAdminServerWithProtocols(t, config.RuntimeModeStandalone)
	handler := server.Handler()

	// A mock MCP server script running via sh that handles initialize and tools/list
	mockScript := `
read -r line1
echo '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{}}}'
read -r line2
read -r line3
echo '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"probed_tool","description":"Discovered tool description","inputSchema":{"type":"object","properties":{"param":{"type":"string"}}}}]}}'
`

	payload := map[string]interface{}{
		"type":    "stdio",
		"command": "sh",
		"args":    []string{"-c", mockScript},
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/admin/protocols/probe", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for stdio probe, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Status string                   `json:"status"`
		Count  int                      `json:"count"`
		Tools  []map[string]interface{} `json:"tools"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Status != "success" || resp.Count != 1 || len(resp.Tools) != 1 {
		t.Fatalf("unexpected probe response: %+v", resp)
	}

	tool := resp.Tools[0]
	if tool["name"] != "probed_tool" {
		t.Errorf("expected tool name 'probed_tool', got '%v'", tool["name"])
	}
	if tool["description"] != "Discovered tool description" {
		t.Errorf("expected description 'Discovered tool description', got '%v'", tool["description"])
	}
	if tool["inputSchema"] == nil {
		t.Errorf("expected inputSchema to be populated")
	}
}

func TestAdminServer_ProtocolsCRUD_AuthTokenAndHeaders(t *testing.T) {
	server, protocolsDir, _ := setupTestAdminServerWithProtocols(t, "standalone")
	handler := server.Handler()

	// 1. Create a remote protocol with AuthToken and custom Headers
	createPayload := map[string]interface{}{
		"id":             "remote-context7",
		"name":           "Context7 Live Docs",
		"type":           "sse",
		"url_or_command": "https://mcp.context7.com/mcp",
		"auth_token":     "ctx7_live_secret_key_99999",
		"headers": map[string]string{
			"X-API-Key":      "api_secret_key_88888",
			"X-Workspace-Id": "ws-12345",
			"Authorization":  "Bearer live_bearer_token_77777",
		},
	}
	body, _ := json.Marshal(createPayload)

	req := httptest.NewRequest(http.MethodPost, "/admin/protocols", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", rec.Code, rec.Body.String())
	}

	var createResp struct {
		Status   string             `json:"status"`
		Protocol *protocol.Protocol `json:"protocol"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Verify secrets are masked in API response
	if !strings.Contains(createResp.Protocol.AuthToken, "••••••") {
		t.Errorf("expected masked AuthToken, got: %s", createResp.Protocol.AuthToken)
	}
	if !strings.Contains(createResp.Protocol.Headers["X-API-Key"], "••••••") {
		t.Errorf("expected masked X-API-Key, got: %s", createResp.Protocol.Headers["X-API-Key"])
	}
	if createResp.Protocol.Headers["X-Workspace-Id"] != "ws-12345" {
		t.Errorf("non-sensitive header should not be masked, got: %s", createResp.Protocol.Headers["X-Workspace-Id"])
	}

	// 2. Verify file on disk has 0600 permissions and contains real secrets
	protoFile := filepath.Join(protocolsDir, "remote-context7.json")
	info, err := os.Stat(protoFile)
	if err != nil {
		t.Fatalf("file not found on disk: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected 0600 permissions, got: %o", info.Mode().Perm())
	}
	fileBytes, _ := os.ReadFile(protoFile)
	if !strings.Contains(string(fileBytes), "ctx7_live_secret_key_99999") {
		t.Errorf("file on disk should contain raw AuthToken")
	}

	// 3. GET /admin/protocols/remote-context7
	getReq := httptest.NewRequest(http.MethodGet, "/admin/protocols/remote-context7", nil)
	getRec := httptest.NewRecorder()
	handler.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", getRec.Code)
	}

	var getProto protocol.Protocol
	json.Unmarshal(getRec.Body.Bytes(), &getProto)
	if !strings.Contains(getProto.AuthToken, "••••••") {
		t.Errorf("GET returned unmasked token: %s", getProto.AuthToken)
	}

	// 4. PUT /admin/protocols/remote-context7 with masked token sent back -> preserves original
	updatePayload := map[string]interface{}{
		"id":             "remote-context7",
		"name":           "Context7 Live Docs Renamed",
		"type":           "sse",
		"url_or_command": "https://mcp.context7.com/mcp",
		"auth_token":     getProto.AuthToken, // masked value sent back
		"headers":        getProto.Headers,   // masked headers sent back
	}
	upBody, _ := json.Marshal(updatePayload)
	putReq := httptest.NewRequest(http.MethodPut, "/admin/protocols/remote-context7", bytes.NewReader(upBody))
	putReq.Header.Set("Content-Type", "application/json")
	putRec := httptest.NewRecorder()
	handler.ServeHTTP(putRec, putReq)

	if putRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for PUT, got %d: %s", putRec.Code, putRec.Body.String())
	}

	// Check disk to verify raw secret was preserved
	fileBytesAfterPut, _ := os.ReadFile(protoFile)
	if !strings.Contains(string(fileBytesAfterPut), "ctx7_live_secret_key_99999") {
		t.Errorf("file on disk should preserve raw secret when masked token was sent on PUT")
	}
}

func TestAdminServer_ProtocolProbe_WithAuthTokenAndCustomHeaders(t *testing.T) {
	var receivedGETAuth, receivedGETKey, receivedGETTenant string
	var receivedPOSTAuth, receivedPOSTKey, receivedPOSTTenant string

	upstream := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			receivedGETAuth = r.Header.Get("Authorization")
			receivedGETKey = r.Header.Get("X-API-Key")
			receivedGETTenant = r.Header.Get("X-Tenant-ID")

			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("event: endpoint\ndata: /messages\n\n"))
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			return
		}

		if r.Method == http.MethodPost {
			receivedPOSTAuth = r.Header.Get("Authorization")
			receivedPOSTKey = r.Header.Get("X-API-Key")
			receivedPOSTTenant = r.Header.Get("X-Tenant-ID")

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      2,
				"result": map[string]interface{}{
					"tools": []map[string]interface{}{
						{"name": "fetch_docs", "description": "Fetches documentation"},
					},
				},
			})
			return
		}
	}))
	defer upstream.Close()

	server, _, _ := setupTestAdminServerWithProtocols(t, config.RuntimeModeStandalone)
	server.cfg.Security.SSRFProtection.Enabled = false
	server.SetSafeHTTPClient(transport.NewSafeHTTPClient(transport.SafeTransportOptions{Enabled: false}, 5*time.Second))
	handler := server.Handler()

	probeReq := ProbeProtocolRequest{
		Type:      "sse",
		URL:       upstream.URL + "/sse",
		AuthToken: "my-secret-upstream-token",
		Headers: map[string]string{
			"X-API-Key":   "api-key-test-value",
			"X-Tenant-ID": "tenant-abc",
		},
	}
	body, _ := json.Marshal(probeReq)

	req := httptest.NewRequest(http.MethodPost, "/admin/protocols/probe", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from probe, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Tools []map[string]interface{} `json:"tools"`
		Count int                      `json:"count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode probe response: %v", err)
	}

	if resp.Count != 1 || len(resp.Tools) != 1 {
		t.Errorf("expected 1 discovered tool, got count=%d len=%d", resp.Count, len(resp.Tools))
	}

	// Verify upstream server received custom headers and bearer token on both GET and POST
	if receivedGETAuth != "Bearer my-secret-upstream-token" {
		t.Errorf("expected GET Authorization 'Bearer my-secret-upstream-token', got %q", receivedGETAuth)
	}
	if receivedGETKey != "api-key-test-value" {
		t.Errorf("expected GET X-API-Key 'api-key-test-value', got %q", receivedGETKey)
	}
	if receivedGETTenant != "tenant-abc" {
		t.Errorf("expected GET X-Tenant-ID 'tenant-abc', got %q", receivedGETTenant)
	}

	if receivedPOSTAuth != "Bearer my-secret-upstream-token" {
		t.Errorf("expected POST Authorization 'Bearer my-secret-upstream-token', got %q", receivedPOSTAuth)
	}
	if receivedPOSTKey != "api-key-test-value" {
		t.Errorf("expected POST X-API-Key 'api-key-test-value', got %q", receivedPOSTKey)
	}
	if receivedPOSTTenant != "tenant-abc" {
		t.Errorf("expected POST X-Tenant-ID 'tenant-abc', got %q", receivedPOSTTenant)
	}
}

// ========== STUDIO-008: Diagnostic Transparency & HTTP Status Probing ==========

func TestAdminServer_Probe_UpstreamHTTPError_StatusCodes(t *testing.T) {
	statusCodes := []int{
		http.StatusUnauthorized,        // 401
		http.StatusForbidden,           // 403
		http.StatusNotFound,            // 404
		http.StatusInternalServerError, // 500
		http.StatusBadGateway,          // 502
		http.StatusServiceUnavailable,  // 503
	}

	for _, code := range statusCodes {
		t.Run(fmt.Sprintf("HTTP_%d", code), func(t *testing.T) {
			upstream := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(code)
				w.Write([]byte("error"))
			}))
			defer upstream.Close()

			server, _, _ := setupTestAdminServerWithProtocols(t, config.RuntimeModeStandalone)
			server.cfg.Security.SSRFProtection.Enabled = false
			server.SetSafeHTTPClient(transport.NewSafeHTTPClient(transport.SafeTransportOptions{Enabled: false}, 5*time.Second))
			handler := server.Handler()

			probeReq := ProbeProtocolRequest{
				Type: "sse",
				URL:  upstream.URL + "/sse",
			}
			body, _ := json.Marshal(probeReq)
			req := httptest.NewRequest(http.MethodPost, "/admin/protocols/probe", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			// All upstream HTTP errors should return 502 Bad Gateway from our probe handler
			if rec.Code != http.StatusBadGateway {
				t.Fatalf("expected 502 Bad Gateway, got %d: %s", rec.Code, rec.Body.String())
			}

			var resp map[string]interface{}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}

			// Verify structured error payload
			if resp["error"] != "UPSTREAM_HTTP_ERROR" {
				t.Errorf("expected error=UPSTREAM_HTTP_ERROR, got %v", resp["error"])
			}
			if int(resp["status_code"].(float64)) != code {
				t.Errorf("expected status_code=%d, got %v", code, resp["status_code"])
			}
			remediation, ok := resp["remediation"].(string)
			if !ok || remediation == "" {
				t.Errorf("expected non-empty remediation string, got %v", resp["remediation"])
			}
			msg, ok := resp["message"].(string)
			if !ok || !strings.Contains(msg, fmt.Sprintf("HTTP %d", code)) {
				t.Errorf("expected message to contain 'HTTP %d', got %q", code, msg)
			}
		})
	}
}

func TestAdminServer_Probe_UpstreamHTTPError_WithCredentials(t *testing.T) {
	// Upstream server returns 401 Unauthorized
	var receivedAuth string
	var receivedAPIKey string
	upstream := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		receivedAPIKey = r.Header.Get("X-API-Key")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error": "invalid_token"}`))
	}))
	defer upstream.Close()

	server, _, _ := setupTestAdminServerWithProtocols(t, config.RuntimeModeStandalone)
	server.cfg.Security.SSRFProtection.Enabled = false
	server.SetSafeHTTPClient(transport.NewSafeHTTPClient(transport.SafeTransportOptions{Enabled: false}, 5*time.Second))
	handler := server.Handler()

	probeReq := ProbeProtocolRequest{
		Type:      "sse",
		URL:       upstream.URL + "/mcp",
		AuthToken: "bad-token-value",
		Headers: map[string]string{
			"X-API-Key": "wrong-key",
		},
	}
	body, _ := json.Marshal(probeReq)
	req := httptest.NewRequest(http.MethodPost, "/admin/protocols/probe", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)

	if resp["error"] != "UPSTREAM_HTTP_ERROR" {
		t.Errorf("expected UPSTREAM_HTTP_ERROR, got %v", resp["error"])
	}
	if int(resp["status_code"].(float64)) != 401 {
		t.Errorf("expected status_code=401, got %v", resp["status_code"])
	}

	// Verify credentials were actually forwarded to upstream
	if receivedAuth != "Bearer bad-token-value" {
		t.Errorf("expected auth token to be forwarded, got %q", receivedAuth)
	}
	if receivedAPIKey != "wrong-key" {
		t.Errorf("expected X-API-Key to be forwarded, got %q", receivedAPIKey)
	}
}

func TestUpstreamHTTPError_ErrorMethod(t *testing.T) {
	err := &UpstreamHTTPError{
		StatusCode:  403,
		Category:    "UPSTREAM_HTTP_ERROR",
		Remediation: "Access denied by remote server.",
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "HTTP 403") {
		t.Errorf("Error() should contain 'HTTP 403', got: %s", errStr)
	}
	if !strings.Contains(errStr, "Forbidden") {
		t.Errorf("Error() should contain 'Forbidden', got: %s", errStr)
	}
	if !strings.Contains(errStr, "Access denied") {
		t.Errorf("Error() should contain remediation text, got: %s", errStr)
	}
}

func TestUpstreamHTTPRemediation(t *testing.T) {
	tests := []struct {
		code     int
		contains string
	}{
		{401, "credentials"},
		{403, "Access denied"},
		{404, "Endpoint not found"},
		{405, "HTTP method"},
		{429, "Rate limited"},
		{500, "internal error"},
		{502, "Bad gateway"},
		{503, "temporarily unavailable"},
		{504, "timed out"},
		{418, "unexpected HTTP 418"},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("HTTP_%d", tc.code), func(t *testing.T) {
			msg := upstreamHTTPRemediation(tc.code)
			if !strings.Contains(msg, tc.contains) {
				t.Errorf("expected remediation for %d to contain %q, got: %s", tc.code, tc.contains, msg)
			}
		})
	}
}

// ========== STUDIO-009: Probe-Time Streamable HTTP Auto-Negotiation ==========

func TestAutoNegotiation_SSE_Success(t *testing.T) {
	// Mock legacy SSE server: GET returns event:endpoint, POST returns tools
	upstream := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("event: endpoint\ndata: /messages\n\n"))
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			return
		}
		if r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      2,
				"result": map[string]interface{}{
					"tools": []map[string]interface{}{
						{"name": "sse_tool", "description": "Discovered via SSE"},
					},
				},
			})
			return
		}
	}))
	defer upstream.Close()

	server, _, _ := setupTestAdminServerWithProtocols(t, config.RuntimeModeStandalone)
	server.cfg.Security.SSRFProtection.Enabled = false
	server.SetSafeHTTPClient(transport.NewSafeHTTPClient(transport.SafeTransportOptions{Enabled: false}, 5*time.Second))
	handler := server.Handler()

	probeReq := ProbeProtocolRequest{Type: "sse", URL: upstream.URL + "/sse"}
	body, _ := json.Marshal(probeReq)
	req := httptest.NewRequest(http.MethodPost, "/admin/protocols/probe", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)

	if resp["transport_mode"] != "sse" {
		t.Errorf("expected transport_mode=sse, got %v", resp["transport_mode"])
	}
	if resp["status"] != "success" {
		t.Errorf("expected status=success, got %v", resp["status"])
	}
	if int(resp["count"].(float64)) != 1 {
		t.Errorf("expected count=1, got %v", resp["count"])
	}
}

func TestAutoNegotiation_StreamableHTTP_Success(t *testing.T) {
	// Mock Streamable HTTP server: GET returns 405, POST accepts JSON-RPC
	var requestCount int
	upstream := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.Method == http.MethodPost {
			requestCount++
			var rpc struct {
				Method string `json:"method"`
				ID     int    `json:"id"`
			}
			json.NewDecoder(r.Body).Decode(&rpc)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)

			switch rpc.Method {
			case "initialize":
				json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0", "id": rpc.ID,
					"result": map[string]interface{}{
						"protocolVersion": "2024-11-05",
						"capabilities":    map[string]interface{}{},
					},
				})
			case "tools/list":
				json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0", "id": rpc.ID,
					"result": map[string]interface{}{
						"tools": []map[string]interface{}{
							{"name": "streamable_tool_1", "description": "Tool from Streamable HTTP"},
							{"name": "streamable_tool_2", "description": "Another tool"},
						},
					},
				})
			case "notifications/initialized":
				w.WriteHeader(http.StatusOK)
			}
			return
		}
	}))
	defer upstream.Close()

	server, _, _ := setupTestAdminServerWithProtocols(t, config.RuntimeModeStandalone)
	server.cfg.Security.SSRFProtection.Enabled = false
	server.SetSafeHTTPClient(transport.NewSafeHTTPClient(transport.SafeTransportOptions{Enabled: false}, 5*time.Second))
	handler := server.Handler()

	probeReq := ProbeProtocolRequest{Type: "http", URL: upstream.URL + "/mcp"}
	body, _ := json.Marshal(probeReq)
	req := httptest.NewRequest(http.MethodPost, "/admin/protocols/probe", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)

	if resp["transport_mode"] != "streamable_http" {
		t.Errorf("expected transport_mode=streamable_http, got %v", resp["transport_mode"])
	}
	if int(resp["count"].(float64)) != 2 {
		t.Errorf("expected count=2, got %v", resp["count"])
	}
}

func TestAutoNegotiation_SSE_NoEndpoint_FallbackToStreamableHTTP(t *testing.T) {
	// Server responds 200 to GET but never emits "event: endpoint" — then accepts POST for Streamable HTTP
	upstream := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			// Return 200 with non-SSE content (HTML or similar)
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html>Not an SSE endpoint</html>"))
			return
		}
		if r.Method == http.MethodPost {
			var rpc struct {
				Method string `json:"method"`
				ID     int    `json:"id"`
			}
			json.NewDecoder(r.Body).Decode(&rpc)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)

			switch rpc.Method {
			case "initialize":
				json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0", "id": rpc.ID,
					"result": map[string]interface{}{
						"protocolVersion": "2024-11-05",
						"capabilities":    map[string]interface{}{},
					},
				})
			case "tools/list":
				json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0", "id": rpc.ID,
					"result": map[string]interface{}{
						"tools": []map[string]interface{}{
							{"name": "fallback_tool", "description": "Found via fallback"},
						},
					},
				})
			case "notifications/initialized":
				// no-op
			}
			return
		}
	}))
	defer upstream.Close()

	server, _, _ := setupTestAdminServerWithProtocols(t, config.RuntimeModeStandalone)
	server.cfg.Security.SSRFProtection.Enabled = false
	server.SetSafeHTTPClient(transport.NewSafeHTTPClient(transport.SafeTransportOptions{Enabled: false}, 5*time.Second))
	handler := server.Handler()

	probeReq := ProbeProtocolRequest{Type: "sse", URL: upstream.URL + "/mcp"}
	body, _ := json.Marshal(probeReq)
	req := httptest.NewRequest(http.MethodPost, "/admin/protocols/probe", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)

	if resp["transport_mode"] != "streamable_http" {
		t.Errorf("expected transport_mode=streamable_http after fallback, got %v", resp["transport_mode"])
	}

	tools := resp["tools"].([]interface{})
	if len(tools) != 1 {
		t.Errorf("expected 1 tool from fallback, got %d", len(tools))
	}
}

func TestAutoNegotiation_FatalHTTPError_NoFallback(t *testing.T) {
	// 401 from SSE should NOT trigger Streamable HTTP fallback
	upstream := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer upstream.Close()

	server, _, _ := setupTestAdminServerWithProtocols(t, config.RuntimeModeStandalone)
	server.cfg.Security.SSRFProtection.Enabled = false
	server.SetSafeHTTPClient(transport.NewSafeHTTPClient(transport.SafeTransportOptions{Enabled: false}, 5*time.Second))
	handler := server.Handler()

	probeReq := ProbeProtocolRequest{Type: "sse", URL: upstream.URL + "/mcp"}
	body, _ := json.Marshal(probeReq)
	req := httptest.NewRequest(http.MethodPost, "/admin/protocols/probe", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// 401 should be returned as a fatal error without any POST attempt
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["error"] != "UPSTREAM_HTTP_ERROR" {
		t.Errorf("expected UPSTREAM_HTTP_ERROR, got %v", resp["error"])
	}
	if int(resp["status_code"].(float64)) != 401 {
		t.Errorf("expected status_code=401, got %v", resp["status_code"])
	}
}

func TestExtractJSONFromSSEOrDirect(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "direct JSON",
			input:    `{"jsonrpc":"2.0","id":1,"result":{}}`,
			expected: `{"jsonrpc":"2.0","id":1,"result":{}}`,
		},
		{
			name:     "SSE wrapped",
			input:    "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n",
			expected: `{"jsonrpc":"2.0","id":1,"result":{}}`,
		},
		{
			name:     "SSE with multiple lines",
			input:    "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}\n\nevent: done\ndata: {}\n\n",
			expected: `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := string(extractJSONFromSSEOrDirect([]byte(tc.input)))
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}
