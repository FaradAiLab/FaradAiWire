package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FaradAiLab/FaradAiWire/internal/auth"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/telemetry/duckdb"
	"github.com/FaradAiLab/FaradAiWire/internal/transport"
	"github.com/FaradAiLab/FaradAiWire/web"
)

func TestAdminEndpoints_ZeroAuth_Standalone(t *testing.T) {
	cfg := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
		Filters: config.FiltersConfig{
			SchemaValidation: config.SchemaValidationConfig{
				SchemasDir: t.TempDir(),
			},
		},
	}
	server := NewAdminServer(cfg, func() error { return nil }, func() {})
	server.SetKeyStore(auth.NewMemoryKeyStore())
	handler := server.Handler()

	endpoints := []struct {
		name         string
		method       string
		path         string
		body         string
		expectedCode int
	}{
		{name: "Dashboard UI", method: http.MethodGet, path: "/admin/dashboard", expectedCode: http.StatusOK},
		{name: "Status Endpoint", method: http.MethodGet, path: "/admin/status", expectedCode: http.StatusOK},
		{name: "Audit Logs", method: http.MethodGet, path: "/admin/audit-logs", expectedCode: http.StatusOK},
		{name: "MCP Tools", method: http.MethodGet, path: "/admin/mcp/tools", expectedCode: http.StatusOK},
		{name: "Agents List", method: http.MethodGet, path: "/admin/agents", expectedCode: http.StatusOK},
		{name: "Settings", method: http.MethodGet, path: "/admin/settings", expectedCode: http.StatusOK},
		{name: "API Keys List", method: http.MethodGet, path: "/admin/api-keys", expectedCode: http.StatusOK},
		{name: "API Reload", method: http.MethodPost, path: "/api/reload", expectedCode: http.StatusOK},
		{name: "Admin Reload", method: http.MethodPost, path: "/admin/reload", expectedCode: http.StatusOK},
		{name: "Purged Login Endpoint", method: http.MethodPost, path: "/admin/login", expectedCode: http.StatusNotFound},
	}

	for _, ep := range endpoints {
		t.Run(ep.name, func(t *testing.T) {
			req := httptest.NewRequest(ep.method, ep.path, bytes.NewBufferString(ep.body))
			if ep.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != ep.expectedCode {
				t.Fatalf("expected status %d for %s %s without auth, got %d (body: %s)",
					ep.expectedCode, ep.method, ep.path, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestAdminServer_StrictLoopbackBinding(t *testing.T) {
	t.Run("Default standalone binds strictly to 127.0.0.1", func(t *testing.T) {
		cfg := &config.Config{
			AdminPort: 8095,
		}
		server := NewAdminServer(cfg, nil, nil)
		addr := server.ListenAddr()
		if addr != "127.0.0.1:8095" {
			t.Fatalf("expected listen addr 127.0.0.1:8095, got %s", addr)
		}
	})

	t.Run("Standalone ignores ListenHost 0.0.0.0 and enforces 127.0.0.1", func(t *testing.T) {
		cfg := &config.Config{
			AdminPort:   8095,
			ListenHost:  "0.0.0.0",
			RuntimeMode: config.RuntimeModeStandalone,
		}
		server := NewAdminServer(cfg, nil, nil)
		addr := server.ListenAddr()
		if addr != "127.0.0.1:8095" {
			t.Fatalf("expected standalone mode to enforce 127.0.0.1:8095 even with 0.0.0.0 configured, got %s", addr)
		}
	})

	t.Run("Managed mode allows configured host", func(t *testing.T) {
		cfg := &config.Config{
			AdminPort:   8095,
			ListenHost:  "192.168.1.100",
			RuntimeMode: config.RuntimeModeManaged,
		}
		server := NewAdminServer(cfg, nil, nil)
		addr := server.ListenAddr()
		if addr != "192.168.1.100:8095" {
			t.Fatalf("expected managed mode to allow configured host 192.168.1.100:8095, got %s", addr)
		}
	})
}

func TestAdminServer_MutationGuard_ManagedMode(t *testing.T) {
	mutatingEndpoints := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{
			name:   "Config toggle",
			method: http.MethodPost,
			path:   "/admin/config/toggle",
			body:   `{"filter_name":"sql_injection","enabled":false}`,
		},
		{
			name:   "Clear schemas",
			method: http.MethodPost,
			path:   "/admin/schemas/clear",
			body:   `{}`,
		},
		{
			name:   "Configure SLM",
			method: http.MethodPost,
			path:   "/admin/slm/configure",
			body:   `{"primary_endpoint":"http://localhost:11434"}`,
		},
		{
			name:   "Sync tools",
			method: http.MethodPost,
			path:   "/admin/agents/sync-tools",
			body:   `{"tools":[]}`,
		},
		{
			name:   "Rollback agent",
			method: http.MethodPost,
			path:   "/admin/agents/rollback",
			body:   `{"agent":"default","timestamp":"20260101"}`,
		},
	}

	t.Run("Managed mode blocks mutations with 403 Forbidden", func(t *testing.T) {
		cfg := &config.Config{
			RuntimeMode: config.RuntimeModeManaged,
		}
		server := NewAdminServer(cfg, nil, nil)
		handler := server.Handler()

		for _, ep := range mutatingEndpoints {
			t.Run(ep.name, func(t *testing.T) {
				req := httptest.NewRequest(ep.method, ep.path, bytes.NewBufferString(ep.body))
				req.Header.Set("Content-Type", "application/json")
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)

				if rec.Code != http.StatusForbidden {
					t.Fatalf("expected 403 Forbidden for mutating endpoint %s in managed mode, got %d", ep.path, rec.Code)
				}

				var resp map[string]string
				if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if resp["error"] != "FORBIDDEN_MANAGED_MODE" {
					t.Fatalf("expected error FORBIDDEN_MANAGED_MODE, got %s", resp["error"])
				}
			})
		}
	})

	t.Run("Standalone mode allows mutating endpoints past mutation guard", func(t *testing.T) {
		cfg := &config.Config{
			RuntimeMode: config.RuntimeModeStandalone,
		}
		server := NewAdminServer(cfg, nil, func() {})
		handler := server.Handler()

		// Testing schemas/clear in standalone should return 200 OK
		req := httptest.NewRequest(http.MethodPost, "/admin/schemas/clear", bytes.NewBufferString(`{}`))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK in standalone mode, got %d (body: %s)", rec.Code, rec.Body.String())
		}
	})
}


func TestPathGuard_AgentEndpoints_RejectsTraversal(t *testing.T) {
	tempBase := t.TempDir()
	agentsDir := filepath.Join(tempBase, "agents")
	_ = os.MkdirAll(filepath.Join(agentsDir, "valid-agent", "current"), 0750)
	_ = os.MkdirAll(filepath.Join(agentsDir, "valid-agent", "archive", "20260101"), 0750)
	_ = os.WriteFile(filepath.Join(agentsDir, "valid-agent", "current", "config.json"), []byte(`{"agent_id":"valid","agent_name":"valid-agent"}`), 0644)
	_ = os.WriteFile(filepath.Join(agentsDir, "valid-agent", "archive", "20260101", "config.json"), []byte(`{"agent_id":"valid","agent_name":"valid-agent"}`), 0644)

	cfg := &config.Config{}
	server := NewAdminServer(cfg, func() error { return nil }, nil)

	t.Run("Agent Archives rejects directory traversal in query parameter", func(t *testing.T) {
		traversalQueries := []string{
			"../../etc",
			"../",
			"%2e%2e%2f",
			"valid-agent/sub",
			"valid-agent%00evil",
			"..",
			".",
		}

		for _, query := range traversalQueries {
			req := httptest.NewRequest(http.MethodGet, "/admin/agents/archives?agent="+query, nil)
			rec := httptest.NewRecorder()

			server.handleAgentArchives(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected HTTP 400 Bad Request for agent query %q, got HTTP %d", query, rec.Code)
			}
		}
	})

	t.Run("Agent Rollback rejects directory traversal in agent and timestamp payloads", func(t *testing.T) {
		maliciousPayloads := []struct {
			name      string
			agent     string
			timestamp string
		}{
			{name: "Traversal in agent", agent: "../../etc", timestamp: "20260101"},
			{name: "Traversal in timestamp", agent: "valid-agent", timestamp: "../../etc"},
			{name: "Slash in timestamp", agent: "valid-agent", timestamp: "2026/01/01"},
			{name: "URL-encoded traversal in agent", agent: "%2e%2e%2f", timestamp: "20260101"},
			{name: "Null byte in agent", agent: "valid\x00agent", timestamp: "20260101"},
			{name: "Null byte in timestamp", agent: "valid-agent", timestamp: "20260101\x00"},
			{name: "Double dot in timestamp", agent: "valid-agent", timestamp: ".."},
		}

		for _, tc := range maliciousPayloads {
			body, _ := json.Marshal(map[string]string{
				"agent":     tc.agent,
				"timestamp": tc.timestamp,
			})
			req := httptest.NewRequest(http.MethodPost, "/admin/agents/rollback", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			server.handleAgentRollback(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected HTTP 400 Bad Request for %s (%q, %q), got HTTP %d. Body: %s",
					tc.name, tc.agent, tc.timestamp, rec.Code, rec.Body.String())
			}
		}
	})

	t.Run("Agent Sync Tools rejects directory traversal in agent_name", func(t *testing.T) {
		maliciousAgents := []string{
			"../../etc",
			"../",
			"%2e%2e",
			"agent/sub",
			"agent\\sub",
			"agent\x00name",
		}

		for _, agentName := range maliciousAgents {
			body, _ := json.Marshal(map[string]string{"agent_name": agentName})
			req := httptest.NewRequest(http.MethodPost, "/admin/agents/sync-tools", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			server.handleAgentSyncTools(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected HTTP 400 Bad Request for agent_name %q, got HTTP %d", agentName, rec.Code)
			}
		}
	})
}


func TestSSRF_ProbeAndDiscoverMCPTools_BlocksRestrictedDestinations(t *testing.T) {
	blockedURLs := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://127.0.0.1:8080/sse",
		"http://10.0.0.1/mcp",
		"http://172.16.0.10:8000/sse",
		"http://192.168.1.100/sse",
		"http://[::1]:8080/sse",
		"http://localhost:8080/sse",
		"file:///etc/passwd",
		"gopher://127.0.0.1:6379",
	}

	for _, u := range blockedURLs {
		t.Run(u, func(t *testing.T) {
			_, err := ProbeAndDiscoverMCPTools(u)
			if err == nil {
				t.Fatalf("Expected ProbeAndDiscoverMCPTools to fail for %s due to SSRF protection, but succeeded", u)
			}
			t.Logf("ProbeAndDiscoverMCPTools safely blocked %s: %v", u, err)
		})
	}
}

func TestAdminServer_SecurityHeaders(t *testing.T) {
	cfg := &config.Config{
		AdminPort: 8095,
		Security: config.SecurityConfig{
			CORSAllowedOrigins: []string{"https://admin.faradai.security"},
		},
	}
	server := NewAdminServer(cfg, nil, nil)
	handler := server.Handler()

	testPaths := []struct {
		method string
		path   string
	}{
		{method: "GET", path: "/admin/dashboard"},
		{method: "GET", path: "/admin/status"},
		{method: "POST", path: "/admin/schemas/clear"},
	}

	for _, tc := range testPaths {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			res := rec.Result()
			defer res.Body.Close()

			if got := res.Header.Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("expected X-Content-Type-Options: nosniff, got %q", got)
			}
			if got := res.Header.Get("X-Frame-Options"); got != "DENY" {
				t.Errorf("expected X-Frame-Options: DENY, got %q", got)
			}
			if got := res.Header.Get("Referrer-Policy"); got != "strict-origin-when-cross-origin" {
				t.Errorf("expected Referrer-Policy: strict-origin-when-cross-origin, got %q", got)
			}
			if got := res.Header.Get("Content-Security-Policy"); got == "" {
				t.Errorf("expected non-empty Content-Security-Policy header")
			}
		})
	}
}

func TestAdminServer_CORSOriginAllowlist(t *testing.T) {
	cfg := &config.Config{
		AdminPort: 8095,
		Security: config.SecurityConfig{
			CORSAllowedOrigins: []string{"https://admin.faradai.security"},
		},
	}
	server := NewAdminServer(cfg, nil, nil)
	handler := server.Handler()

	// Case 1: Allowed Origin
	reqAllowed := httptest.NewRequest("GET", "/admin/dashboard", nil)
	reqAllowed.Header.Set("Origin", "https://admin.faradai.security")
	recAllowed := httptest.NewRecorder()
	handler.ServeHTTP(recAllowed, reqAllowed)

	if got := recAllowed.Result().Header.Get("Access-Control-Allow-Origin"); got != "https://admin.faradai.security" {
		t.Errorf("expected Access-Control-Allow-Origin %q, got %q", "https://admin.faradai.security", got)
	}

	// Case 2: Disallowed Origin
	reqDisallowed := httptest.NewRequest("GET", "/admin/dashboard", nil)
	reqDisallowed.Header.Set("Origin", "https://attacker.evil")
	recDisallowed := httptest.NewRecorder()
	handler.ServeHTTP(recDisallowed, reqDisallowed)

	if got := recDisallowed.Result().Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("expected no Access-Control-Allow-Origin for unauthorized origin, got %q", got)
	}
}



type mockTelemetryReader struct {
	lastFilter duckdb.QueryFilter
	result     *duckdb.QueryResult
	err        error
}

func (m *mockTelemetryReader) QueryAuditLogs(ctx context.Context, f duckdb.QueryFilter) (*duckdb.QueryResult, error) {
	m.lastFilter = f
	return m.result, m.err
}

func TestAdminServer_AuditLogs_DuckDB(t *testing.T) {
	cfg := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
	}
	server := NewAdminServer(cfg, nil, nil)

	mockReader := &mockTelemetryReader{
		result: &duckdb.QueryResult{
			Total:  10,
			Limit:  25,
			Offset: 5,
			Logs: []duckdb.AuditRecord{
				{
					ID:         "rec-1",
					AgentName:  "researcher",
					ToolName:   "web_search",
					Decision:   "ALLOW",
					LatencyMs:  1.2,
					CallerRole: "engineer",
				},
			},
		},
	}
	server.SetTelemetryEngine(mockReader)

	req := httptest.NewRequest("GET", "/admin/audit-logs?limit=25&offset=5&decision=ALLOW&agent_name=researcher&tool_name=web_search", nil)
	rec := httptest.NewRecorder()

	server.handleAuditLogs(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	if mockReader.lastFilter.Limit != 25 {
		t.Errorf("expected filter limit 25, got %d", mockReader.lastFilter.Limit)
	}
	if mockReader.lastFilter.Offset != 5 {
		t.Errorf("expected filter offset 5, got %d", mockReader.lastFilter.Offset)
	}
	if mockReader.lastFilter.Decision != "ALLOW" {
		t.Errorf("expected filter decision ALLOW, got %s", mockReader.lastFilter.Decision)
	}
	if mockReader.lastFilter.AgentName != "researcher" {
		t.Errorf("expected filter agent_name researcher, got %s", mockReader.lastFilter.AgentName)
	}
	if mockReader.lastFilter.ToolName != "web_search" {
		t.Errorf("expected filter tool_name web_search, got %s", mockReader.lastFilter.ToolName)
	}

	var resp struct {
		Enabled bool                 `json:"enabled"`
		Total   int64                `json:"total"`
		Limit   int                  `json:"limit"`
		Offset  int                  `json:"offset"`
		Logs    []duckdb.AuditRecord `json:"logs"`
	}

	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !resp.Enabled {
		t.Errorf("expected enabled=true")
	}
	if resp.Total != 10 {
		t.Errorf("expected total 10, got %d", resp.Total)
	}
	if len(resp.Logs) != 1 || resp.Logs[0].ToolName != "web_search" {
		t.Errorf("unexpected logs in response: %+v", resp.Logs)
	}
}

type testHangingTransport struct{}

func (t *testHangingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	<-req.Context().Done()
	return nil, req.Context().Err()
}

func TestProbeAndDiscoverMCPToolsWithContext_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	client := &http.Client{
		Transport: &testHangingTransport{},
	}

	opts := transport.DefaultSafeOptions()
	opts.AllowedDomains = []string{"example.com"}

	_, err := ProbeAndDiscoverMCPToolsWithContext(ctx, client, "http://example.com/sse", opts)
	if err == nil {
		t.Fatal("Expected error on canceled context, got nil")
	}
	if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("Expected context.Canceled error, got: %v", err)
	}
}

func TestAdminServer_SafeHTTPClient_Reused(t *testing.T) {
	cfg := &config.Config{}
	srv := NewAdminServer(cfg, nil, nil)
	c1 := srv.SafeHTTPClient()
	c2 := srv.SafeHTTPClient()
	if c1 == nil || c2 == nil {
		t.Fatal("Expected non-nil SafeHTTPClient")
	}
	if c1 != c2 {
		t.Fatal("Expected SafeHTTPClient to be reused across calls")
	}
}

func TestAdminServer_AgentEndpoints_RepositoryMediation(t *testing.T) {
	tempBase := t.TempDir()
	agentsDir := filepath.Join(tempBase, "agents")
	agentDir := filepath.Join(agentsDir, "demo-agent", "current")
	archiveDir := filepath.Join(agentsDir, "demo-agent", "archive", "20260926-000000")

	if err := os.MkdirAll(agentDir, 0750); err != nil {
		t.Fatalf("failed to create agent current dir: %v", err)
	}
	if err := os.MkdirAll(archiveDir, 0750); err != nil {
		t.Fatalf("failed to create agent archive dir: %v", err)
	}

	cfgContent := `{"agent_id":"demo-01","agent_name":"demo-agent","routing_mode":"aggregated"}`
	if err := os.WriteFile(filepath.Join(agentDir, "config.json"), []byte(cfgContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	manifestContent := `[{"name":"demo_tool","canonical_name":"db__demo_tool","description":"test tool"}]`
	if err := os.WriteFile(filepath.Join(agentDir, "tools_manifest.json"), []byte(manifestContent), 0644); err != nil {
		t.Fatalf("failed to write manifest: %v", err)
	}
	archivedCfgContent := `{"agent_id":"demo-archived","agent_name":"demo-agent","routing_mode":"aggregated"}`
	if err := os.WriteFile(filepath.Join(archiveDir, "config.json"), []byte(archivedCfgContent), 0644); err != nil {
		t.Fatalf("failed to write archived config: %v", err)
	}

	cfg := &config.Config{
		AgentsDir: agentsDir,
	}
	reloaded := false
	server := NewAdminServer(cfg, func() error {
		reloaded = true
		return nil
	}, nil)

	// 1. Test handleAgents
	req := httptest.NewRequest(http.MethodGet, "/admin/agents", nil)
	rec := httptest.NewRecorder()
	server.handleAgents(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var agentsResp struct {
		Agents []struct {
			Name        string                   `json:"name"`
			RoutingMode string                   `json:"routing_mode"`
			Status      string                   `json:"status"`
			Tools       []map[string]interface{} `json:"tools"`
		} `json:"agents"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &agentsResp); err != nil {
		t.Fatalf("failed to parse agents response: %v", err)
	}
	if len(agentsResp.Agents) != 1 || agentsResp.Agents[0].Name != "demo-agent" {
		t.Fatalf("expected 1 agent 'demo-agent', got: %+v", agentsResp.Agents)
	}
	if agentsResp.Agents[0].RoutingMode != "aggregated" {
		t.Errorf("expected routing_mode 'aggregated', got %s", agentsResp.Agents[0].RoutingMode)
	}
	if len(agentsResp.Agents[0].Tools) != 1 {
		t.Errorf("expected 1 tool in manifest, got %d", len(agentsResp.Agents[0].Tools))
	}

	// 2. Test handleAgentArchives
	reqArchives := httptest.NewRequest(http.MethodGet, "/admin/agents/archives?agent=demo-agent", nil)
	recArchives := httptest.NewRecorder()
	server.handleAgentArchives(recArchives, reqArchives)

	if recArchives.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d: %s", recArchives.Code, recArchives.Body.String())
	}
	var archivesResp struct {
		Agent    string   `json:"agent"`
		Archives []string `json:"archives"`
	}
	if err := json.Unmarshal(recArchives.Body.Bytes(), &archivesResp); err != nil {
		t.Fatalf("failed to parse archives response: %v", err)
	}
	if archivesResp.Agent != "demo-agent" || len(archivesResp.Archives) != 1 || archivesResp.Archives[0] != "20260926-000000" {
		t.Fatalf("expected ['20260926-000000'], got: %+v", archivesResp.Archives)
	}

	// 3. Test handleAgentRollback
	rollbackBody, _ := json.Marshal(map[string]string{
		"agent":     "demo-agent",
		"timestamp": "20260926-000000",
	})
	reqRollback := httptest.NewRequest(http.MethodPost, "/admin/agents/rollback", bytes.NewReader(rollbackBody))
	recRollback := httptest.NewRecorder()
	server.handleAgentRollback(recRollback, reqRollback)

	if recRollback.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 for rollback, got %d: %s", recRollback.Code, recRollback.Body.String())
	}
	if !reloaded {
		t.Error("expected hot-reload function to be triggered on rollback")
	}

	// Verify restored config via repository
	repo := server.getAgentRepository()
	restoredCfg, err := repo.GetAgentConfig("demo-agent")
	if err != nil {
		t.Fatalf("failed to retrieve restored config: %v", err)
	}
	if restoredCfg.AgentID != "demo-archived" {
		t.Errorf("expected restored agent_id 'demo-archived', got '%s'", restoredCfg.AgentID)
	}
}

func TestAdmin_SLMProbe_And_Configure(t *testing.T) {
	cfg := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
	}
	cfg.Filters.InjectionScanner.Enabled = true
	cfg.Filters.InjectionScanner.ClassifierURL = ""

	reloaded := false
	server := NewAdminServer(cfg, func() error {
		reloaded = true
		return nil
	}, nil)

	handler := server.Handler()

	// 1. Verify GET /admin/status includes slm_status (regex_standby initially)
	reqStatus := httptest.NewRequest(http.MethodGet, "/admin/status", nil)
	recStatus := httptest.NewRecorder()
	handler.ServeHTTP(recStatus, reqStatus)

	if recStatus.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /admin/status, got %d", recStatus.Code)
	}

	var statusResp map[string]interface{}
	if err := json.NewDecoder(recStatus.Body).Decode(&statusResp); err != nil {
		t.Fatalf("failed to decode /admin/status response: %v", err)
	}

	slmStatus, ok := statusResp["slm_status"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected slm_status object in status response, got %v", statusResp)
	}
	if slmStatus["tier"] != "regex_standby" {
		t.Errorf("expected tier=regex_standby, got %v", slmStatus["tier"])
	}

	// 2. Verify GET /admin/slm/probe returns 200 and ProbeResult
	reqProbe := httptest.NewRequest(http.MethodGet, "/admin/slm/probe", nil)
	recProbe := httptest.NewRecorder()
	handler.ServeHTTP(recProbe, reqProbe)

	if recProbe.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /admin/slm/probe, got %d", recProbe.Code)
	}

	var probeResp map[string]interface{}
	if err := json.NewDecoder(recProbe.Body).Decode(&probeResp); err != nil {
		t.Fatalf("failed to decode /admin/slm/probe response: %v", err)
	}
	if _, hasDetected := probeResp["detected"]; !hasDetected {
		t.Errorf("expected 'detected' field in probe response")
	}

	// 3. Verify POST /admin/slm/configure updates config and triggers reload
	cfgBody, _ := json.Marshal(map[string]interface{}{
		"classifier_url": "http://localhost:8088/predict",
		"mode":           "docker",
		"docker_url":     "http://localhost:8088",
		"ollama_url":     "http://localhost:11434",
	})
	reqCfg := httptest.NewRequest(http.MethodPost, "/admin/slm/configure", bytes.NewReader(cfgBody))
	recCfg := httptest.NewRecorder()
	handler.ServeHTTP(recCfg, reqCfg)

	if recCfg.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /admin/slm/configure, got %d: %s", recCfg.Code, recCfg.Body.String())
	}
	if !reloaded {
		t.Errorf("expected reloadFunc to be triggered on slm configure")
	}
	if cfg.Filters.InjectionScanner.ClassifierURL != "http://localhost:8088/predict" {
		t.Errorf("expected classifier_url updated in cfg, got %s", cfg.Filters.InjectionScanner.ClassifierURL)
	}
	if cfg.Filters.Guard.Discovery.Mode != "docker" {
		t.Errorf("expected discovery mode 'docker', got %s", cfg.Filters.Guard.Discovery.Mode)
	}
	if cfg.Filters.Guard.Discovery.DockerURL != "http://localhost:8088" {
		t.Errorf("expected discovery docker_url updated, got %s", cfg.Filters.Guard.Discovery.DockerURL)
	}

	// 4. Verify /admin/status reflects neural_active tier after configuration
	reqStatus2 := httptest.NewRequest(http.MethodGet, "/admin/status", nil)
	recStatus2 := httptest.NewRecorder()
	handler.ServeHTTP(recStatus2, reqStatus2)

	var statusResp2 map[string]interface{}
	json.NewDecoder(recStatus2.Body).Decode(&statusResp2)
	slmStatus2 := statusResp2["slm_status"].(map[string]interface{})
	if slmStatus2["tier"] != "neural_active" {
		t.Errorf("expected tier=neural_active, got %v", slmStatus2["tier"])
	}
	if slmStatus2["classifier_url"] != "http://localhost:8088/predict" {
		t.Errorf("expected classifier_url in status, got %v", slmStatus2["classifier_url"])
	}
}

func TestAdmin_SLM_SecurityGuardrails(t *testing.T) {
	cfg := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
	}
	cfg.Filters.InjectionScanner.Enabled = true
	server := NewAdminServer(cfg, func() error { return nil }, nil)
	handler := server.Handler()

	// 1. Rejection of Cloud Metadata (169.254.169.254) in configure
	metaBody, _ := json.Marshal(map[string]interface{}{
		"classifier_url": "http://169.254.169.254/latest/meta-data/",
	})
	reqMeta := httptest.NewRequest(http.MethodPost, "/admin/slm/configure", bytes.NewReader(metaBody))
	recMeta := httptest.NewRecorder()
	handler.ServeHTTP(recMeta, reqMeta)
	if recMeta.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for cloud metadata URL, got %d", recMeta.Code)
	}

	// 2. Rejection of invalid scheme (file://) in probe
	reqFile := httptest.NewRequest(http.MethodGet, "/admin/slm/probe?url=file:///etc/passwd", nil)
	recFile := httptest.NewRecorder()
	handler.ServeHTTP(recFile, reqFile)
	if recFile.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for file:// scheme probe, got %d", recFile.Code)
	}

	// 3. Acceptance of loopback and LAN endpoints in configure
	lanBody, _ := json.Marshal(map[string]interface{}{
		"classifier_url": "http://192.168.1.150:11434",
	})
	reqLan := httptest.NewRequest(http.MethodPost, "/admin/slm/configure", bytes.NewReader(lanBody))
	recLan := httptest.NewRecorder()
	handler.ServeHTTP(recLan, reqLan)
	if recLan.Code != http.StatusOK {
		t.Errorf("expected 200 OK for LAN SLM configure, got %d", recLan.Code)
	}

	// 4. Verification of credential redaction in /admin/status
	authBody, _ := json.Marshal(map[string]interface{}{
		"classifier_url": "http://admin:secretPass123@127.0.0.1:8088/predict",
	})
	reqAuth := httptest.NewRequest(http.MethodPost, "/admin/slm/configure", bytes.NewReader(authBody))
	recAuth := httptest.NewRecorder()
	handler.ServeHTTP(recAuth, reqAuth)
	if recAuth.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for authenticated SLM configure, got %d", recAuth.Code)
	}

	reqStatus := httptest.NewRequest(http.MethodGet, "/admin/status", nil)
	recStatus := httptest.NewRecorder()
	handler.ServeHTTP(recStatus, reqStatus)
	var statusMap map[string]interface{}
	json.NewDecoder(recStatus.Body).Decode(&statusMap)
	slmMap := statusMap["slm_status"].(map[string]interface{})
	maskedURL, _ := slmMap["classifier_url"].(string)

	if strings.Contains(maskedURL, "secretPass123") {
		t.Errorf("expected password to be redacted in status output, got %s", maskedURL)
	}
	if !strings.Contains(maskedURL, "admin:") {
		t.Errorf("expected username preserved in redacted output, got %s", maskedURL)
	}
}

func TestAdminServer_StaticAssetsAndCSP(t *testing.T) {
	cfg := &config.Config{
		AdminPort: 8095,
	}
	server := NewAdminServer(cfg, nil, nil)
	handler := server.Handler()

	// 1. Verify CSP on /admin/dashboard
	req := httptest.NewRequest("GET", "/admin/dashboard", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "fonts.googleapis.com") {
		t.Errorf("CSP missing fonts.googleapis.com: %s", csp)
	}
	if !strings.Contains(csp, "fonts.gstatic.com") {
		t.Errorf("CSP missing fonts.gstatic.com: %s", csp)
	}
	if !strings.Contains(csp, "data:") {
		t.Errorf("CSP missing data: scheme for inline SVGs: %s", csp)
	}

	// 2. Verify /admin/dashboard returns 200 HTML
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for /admin/dashboard, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("expected text/html for /admin/dashboard, got %s", ct)
	}

	// 3. Verify static asset serving through /assets/ and /admin/assets/
	dist, err := web.DistFS()
	if err != nil {
		t.Fatalf("failed to open DistFS: %v", err)
	}
	entries, err := fs.ReadDir(dist, "assets")
	if err != nil {
		t.Fatalf("failed to read dist/assets: %v", err)
	}
	var cssName string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".css") {
			cssName = entry.Name()
			break
		}
	}
	if cssName == "" {
		t.Fatalf("no .css file found in dist/assets")
	}

	cssReq1 := httptest.NewRequest("GET", "/assets/"+cssName, nil)
	cssRec1 := httptest.NewRecorder()
	handler.ServeHTTP(cssRec1, cssReq1)
	if cssRec1.Code != http.StatusOK {
		t.Errorf("expected 200 for /assets/%s, got %d", cssName, cssRec1.Code)
	}
	if ct := cssRec1.Header().Get("Content-Type"); !strings.Contains(ct, "text/css") {
		t.Errorf("expected text/css for stylesheet, got %s", ct)
	}

	cssReq2 := httptest.NewRequest("GET", "/admin/assets/"+cssName, nil)
	cssRec2 := httptest.NewRecorder()
	handler.ServeHTTP(cssRec2, cssReq2)
	if cssRec2.Code != http.StatusOK {
		t.Errorf("expected 200 for /admin/assets/%s, got %d", cssName, cssRec2.Code)
	}
	if ct := cssRec2.Header().Get("Content-Type"); !strings.Contains(ct, "text/css") {
		t.Errorf("expected text/css for /admin/assets stylesheet, got %s", ct)
	}
}

func TestAdminServer_ConfigToggle_AllFilters(t *testing.T) {
	cfg := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
	}
	server := NewAdminServer(cfg, nil, nil)
	handler := server.Handler()

	filters := []string{
		"prefill_block",
		"dlp",
		"rate_limiting",
		"loop_protection",
		"guard",
		"hitl",
		"schema_validation",
	}

	for _, f := range filters {
		t.Run("Toggle_"+f, func(t *testing.T) {
			// Test using "filter" field (React SPA format)
			body := fmt.Sprintf(`{"filter":"%s","enabled":true}`, f)
			req := httptest.NewRequest(http.MethodPost, "/admin/config/toggle", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("expected 200 OK for filter '%s', got %d: %s", f, rec.Code, rec.Body.String())
			}

			var resp map[string]interface{}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}
			if resp["status"] != "success" {
				t.Errorf("expected status 'success', got %v", resp["status"])
			}
			if resp["enabled"] != true {
				t.Errorf("expected enabled true, got %v", resp["enabled"])
			}

			// Test toggling off
			bodyOff := fmt.Sprintf(`{"filter_name":"%s","enabled":false}`, f)
			reqOff := httptest.NewRequest(http.MethodPost, "/admin/config/toggle", strings.NewReader(bodyOff))
			reqOff.Header.Set("Content-Type", "application/json")
			recOff := httptest.NewRecorder()
			handler.ServeHTTP(recOff, reqOff)

			if recOff.Code != http.StatusOK {
				t.Fatalf("expected 200 OK for disabling filter '%s', got %d: %s", f, recOff.Code, recOff.Body.String())
			}
		})
	}
}

func TestAdminServer_Status_ActiveFilters_ExactCountAndNoDuplicates(t *testing.T) {
	cfg := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
	}
	cfg.Filters.PrefillBlock.Enabled = true
	cfg.Filters.RateLimiting.Enabled = true
	cfg.Filters.LoopProtection.Enabled = true
	cfg.Filters.SchemaValidation.Enabled = true
	cfg.Filters.DLP.Enabled = true
	cfg.Filters.HITL.Enabled = true
	cfg.Filters.Guard.Enabled = true

	server := NewAdminServer(cfg, nil, nil)
	handler := server.Handler()

	req := httptest.NewRequest(http.MethodGet, "/admin/status", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var statusResp struct {
		ActiveFilters []string `json:"active_filters"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &statusResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(statusResp.ActiveFilters) != 7 {
		t.Errorf("expected exactly 7 active filters, got %d: %v", len(statusResp.ActiveFilters), statusResp.ActiveFilters)
	}

	seen := make(map[string]bool)
	for _, f := range statusResp.ActiveFilters {
		if seen[f] {
			t.Errorf("duplicate filter in active_filters: %s (all: %v)", f, statusResp.ActiveFilters)
		}
		seen[f] = true
	}
}
