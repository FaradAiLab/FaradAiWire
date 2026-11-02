package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
)

// TestHelperProcess runs as a mock stdio MCP subprocess when GO_WANT_HELPER_PROCESS=1.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	defer os.Exit(0)

	mode := os.Getenv("MOCK_MODE")
	if mode == "crash_immediate" {
		os.Exit(42)
	}

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if mode == "crash_on_first_request" {
			os.Exit(1)
		}

		var req mcp.Request
		if err := json.Unmarshal([]byte(line), &req); err == nil {
			if mode == "notify_before_response" {
				fmt.Println(`{"jsonrpc":"2.0","method":"notifications/test","params":{"msg":"server-event"}}`)
			}
			resp := mcp.Response{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result:  json.RawMessage(`{"content":[{"type":"text","text":"local stdio execution output"}]}`),
			}
			data, _ := json.Marshal(resp)
			fmt.Println(string(data))
		}
	}
}

func TestHierarchicalGatewayMultiplexer(t *testing.T) {
	var corpReqCount int32
	var receivedAuthHeader string

	// 1. Mock upstream corporate enterprise gateway (simulating FaradAiWireEE)
	corpServer := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/sse") {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)
			w.Write([]byte("event: endpoint\ndata: /message?sessionId=corp-upstream-session-999\n\n"))
			flusher.Flush()
			<-r.Context().Done()
			return
		}

		if strings.HasPrefix(r.URL.Path, "/message") {
			atomic.AddInt32(&corpReqCount, 1)
			receivedAuthHeader = r.Header.Get("Authorization")

			// Invariant: Token must be in Authorization header, never in query string
			if r.URL.Query().Get("token") != "" || r.URL.Query().Get("auth") != "" {
				t.Errorf("Security Violation: Auth token found in URL query parameters!")
			}

			body, _ := io.ReadAll(r.Body)
			var req mcp.Request
			_ = json.Unmarshal(body, &req)

			resp := mcp.Response{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result:  json.RawMessage(`{"content":[{"type":"text","text":"corporate enterprise data result"}]}`),
			}
			respBytes, _ := json.Marshal(resp)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(respBytes)
			return
		}

		http.NotFound(w, r)
	}))
	defer closeServer(corpServer)

	// 2. Set up agent configuration in a temp directory
	tmpDir := t.TempDir()
	agentCurrentDir := filepath.Join(tmpDir, "default", "current")
	if err := os.MkdirAll(agentCurrentDir, 0755); err != nil {
		t.Fatalf("Failed to create temp agent dir: %v", err)
	}

	agentCfg := agent.RouteConfig{
		AgentID:     "agent-default-1",
		AgentName:   "default",
		RoutingMode: "aggregated",
		Protocols: []agent.ProtocolConfig{
			{
				ID:          "proto-local-stdio",
				Name:        "local-stdio",
				Type:        "stdio",
				Command:     os.Args[0],
				Args:        []string{"-test.run=TestHelperProcess", "--"},
				Env:         []string{"GO_WANT_HELPER_PROCESS=1"},
				TargetScope: "local",
			},
			{
				ID:           "proto-corporate",
				Name:         "corporate-upstream",
				Type:         "sse",
				URLOrCommand: corpServer.URL + "/sse",
				AuthToken:    "corp-secret-bearer-token-12345",
				TargetScope:  "corporate",
			},
		},
	}
	cfgBytes, _ := json.Marshal(agentCfg)
	if err := os.WriteFile(filepath.Join(agentCurrentDir, "config.json"), cfgBytes, 0644); err != nil {
		t.Fatalf("Failed to write config.json: %v", err)
	}

	manifest := []agent.ToolMetadata{
		{
			Name:         "local_read_file",
			ProtocolName: "local-stdio",
			Description:  "Read local filesystem file",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"path": map[string]interface{}{"type": "string"},
				},
			},
		},
		{
			Name:         "corporate_database_query",
			ProtocolName: "corporate-upstream",
			Description:  "Query enterprise data warehouse",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"sql": map[string]interface{}{"type": "string"},
				},
			},
		},
	}
	manBytes, _ := json.Marshal(manifest)
	if err := os.WriteFile(filepath.Join(agentCurrentDir, "tools_manifest.json"), manBytes, 0644); err != nil {
		t.Fatalf("Failed to write tools_manifest.json: %v", err)
	}

	// 3. Initialize Gateway with agent repository pointing to tmpDir
	agentRepo := agent.NewFSRepository(tmpDir)
	proxy := NewSSEProxy(0, corpServer.URL, filter.NewPipeline(nil), agentRepo, nil, config.UserContextConfig{})

	gwServer := newIPv4Server(t, proxy.Handler())
	defer closeServer(gwServer)

	// Phase 1: Client connects to single unified gateway endpoint: http://localhost:8090/sse (Acceptance Criteria 1)
	sseReq, _ := http.NewRequest(http.MethodGet, gwServer.URL+"/sse", nil)
	sseResp, err := http.DefaultClient.Do(sseReq)
	if err != nil {
		t.Fatalf("Failed to connect to unified /sse endpoint: %v", err)
	}
	defer sseResp.Body.Close()

	if sseResp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK from /sse, got %d", sseResp.StatusCode)
	}

	// Read endpoint event
	scanner := bufio.NewScanner(sseResp.Body)
	var endpointURL string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data:") {
			data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if strings.Contains(data, "message?sessionId=") {
				endpointURL = gwServer.URL + data
				break
			}
		}
	}
	if endpointURL == "" {
		t.Fatalf("Did not receive endpoint event from /sse")
	}

	u, err := url.Parse(endpointURL)
	if err != nil {
		t.Fatalf("Failed to parse endpoint URL '%s': %v", endpointURL, err)
	}
	sessionID := u.Query().Get("sessionId")
	if sessionID == "" {
		t.Fatalf("Missing sessionId in endpoint event URL '%s'", endpointURL)
	}

	// Phase 2: Client calls tools/list on single session
	listReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/list",
	}
	listReqBytes, _ := json.Marshal(listReq)
	postResp, err := http.Post(endpointURL, "application/json", bytes.NewBuffer(listReqBytes))
	if err != nil {
		t.Fatalf("Failed to send tools/list: %v", err)
	}
	defer postResp.Body.Close()

	body, _ := io.ReadAll(postResp.Body)
	var listResp struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &listResp); err != nil {
		t.Fatalf("Failed to unmarshal tools/list response: %v, raw: %s", err, string(body))
	}

	foundLocal := false
	foundCorp := false
	for _, tName := range listResp.Result.Tools {
		if tName.Name == "local_read_file" || strings.HasSuffix(tName.Name, "local_read_file") {
			foundLocal = true
		}
		if tName.Name == "corporate_database_query" || strings.HasSuffix(tName.Name, "corporate_database_query") {
			foundCorp = true
		}
	}
	if !foundLocal || !foundCorp {
		t.Fatalf("Expected both local and corporate tools in tools/list. Found local: %v, found corp: %v, tools: %+v", foundLocal, foundCorp, listResp.Result.Tools)
	}

	// Phase 3: Zero-Egress Local Tool Execution via stdio (Acceptance Criteria 2)
	initialCorpReqs := atomic.LoadInt32(&corpReqCount)

	localCallReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "local_read_file",
			"arguments": map[string]interface{}{
				"path": "/etc/hosts",
			},
		},
	}
	localCallBytes, _ := json.Marshal(localCallReq)
	localResp, err := http.Post(endpointURL, "application/json", bytes.NewBuffer(localCallBytes))
	if err != nil {
		t.Fatalf("Failed to call local tool: %v", err)
	}
	defer localResp.Body.Close()

	localBody, _ := io.ReadAll(localResp.Body)
	var localResult struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
		Error *mcp.Error `json:"error"`
	}
	if err := json.Unmarshal(localBody, &localResult); err != nil {
		t.Fatalf("Failed to unmarshal local tool response: %v, raw: %s", err, string(localBody))
	}
	if localResult.Error != nil {
		t.Fatalf("Unexpected error from local tool: %v", localResult.Error)
	}
	if len(localResult.Result.Content) == 0 || !strings.Contains(localResult.Result.Content[0].Text, "local stdio execution output") {
		t.Fatalf("Unexpected local tool output: %s", string(localBody))
	}

	// Zero-egress verification: Ensure corporate server received 0 new requests!
	if atomic.LoadInt32(&corpReqCount) != initialCorpReqs {
		t.Fatalf("Zero-Egress Invariant Violated! Corporate upstream received %d requests during local tool call", atomic.LoadInt32(&corpReqCount)-initialCorpReqs)
	}

	// Phase 4: Corporate Tool Proxying with Bearer Authentication (Acceptance Criteria 3)
	corpCallReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "corporate_database_query",
			"arguments": map[string]interface{}{
				"sql": "SELECT COUNT(*) FROM users",
			},
		},
	}
	corpCallBytes, _ := json.Marshal(corpCallReq)
	corpCallResp, err := http.Post(endpointURL, "application/json", bytes.NewBuffer(corpCallBytes))
	if err != nil {
		t.Fatalf("Failed to call corporate tool: %v", err)
	}
	defer corpCallResp.Body.Close()

	corpBody, _ := io.ReadAll(corpCallResp.Body)
	var corpResult struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
		Error *mcp.Error `json:"error"`
	}
	if err := json.Unmarshal(corpBody, &corpResult); err != nil {
		t.Fatalf("Failed to unmarshal corporate tool response: %v, raw: %s", err, string(corpBody))
	}
	if corpResult.Error != nil {
		t.Fatalf("Unexpected error from corporate tool: %v", corpResult.Error)
	}
	if len(corpResult.Result.Content) == 0 || !strings.Contains(corpResult.Result.Content[0].Text, "corporate enterprise data result") {
		t.Fatalf("Unexpected corporate tool output: %s", string(corpBody))
	}

	// Invariant: Verify corporate request was forwarded with Bearer token
	if atomic.LoadInt32(&corpReqCount) <= initialCorpReqs {
		t.Fatalf("Corporate tool request was not forwarded to upstream corporate gateway")
	}
	expectedAuth := "Bearer corp-secret-bearer-token-12345"
	if receivedAuthHeader != expectedAuth {
		t.Fatalf("Expected Authorization '%s', got '%s'", expectedAuth, receivedAuthHeader)
	}

	// Phase 5: Network Timeout / Unreachable Upstream Resilience (Acceptance Criteria 4)
	// Terminate corporate server
	closeServer(corpServer)

	failCallReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      4,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "corporate_database_query",
			"arguments": map[string]interface{}{
				"sql": "SELECT * FROM orders",
			},
		},
	}
	failCallBytes, _ := json.Marshal(failCallReq)
	failResp, err := http.Post(endpointURL, "application/json", bytes.NewBuffer(failCallBytes))
	if err != nil {
		t.Fatalf("Failed to execute request during upstream outage: %v", err)
	}
	defer failResp.Body.Close()

	failBody, _ := io.ReadAll(failResp.Body)
	var rpcErrResp struct {
		JSONRPC string     `json:"jsonrpc"`
		ID      int        `json:"id"`
		Error   *mcp.Error `json:"error"`
	}
	if err := json.Unmarshal(failBody, &rpcErrResp); err != nil {
		t.Fatalf("Expected valid JSON-RPC error during upstream outage, got unparseable response: %s", string(failBody))
	}

	if rpcErrResp.Error == nil {
		t.Fatalf("Expected JSON-RPC error, got nil: %s", string(failBody))
	}
	if rpcErrResp.Error.Code != -32001 {
		t.Errorf("Expected JSON-RPC error code -32001, got %d", rpcErrResp.Error.Code)
	}
	if !strings.Contains(rpcErrResp.Error.Message, "Upstream corporate gateway unreachable") {
		t.Errorf("Expected message to contain 'Upstream corporate gateway unreachable', got '%s'", rpcErrResp.Error.Message)
	}

	// Invariant: Gateway daemon did not crash, local tools still function properly
	localRetryResp, err := http.Post(endpointURL, "application/json", bytes.NewBuffer(localCallBytes))
	if err != nil {
		t.Fatalf("Local tool execution failed after upstream outage: %v", err)
	}
	defer localRetryResp.Body.Close()
	retryBody, _ := io.ReadAll(localRetryResp.Body)
	if !strings.Contains(string(retryBody), "local stdio execution output") {
		t.Fatalf("Local tool failed after upstream outage: %s", string(retryBody))
	}
}
